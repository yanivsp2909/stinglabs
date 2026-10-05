#!/usr/bin/env python3
"""
hook_entry.py — the single process every agent's hook config invokes.

    stdin (agent's payload) -> adapter.parse -> engine.decide -> adapter.render -> stdout

One entry point, one engine, N adapters. Adding an agent means adding a module
to ADAPTERS and nothing else.

Wiring, per agent:

  Claude Code   .claude/settings.json
      {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
        {"type": "command", "command": "python3 /path/to/hook_entry.py"}]}]}}

  Cursor        .cursor/hooks.json          --agent cursor
  Copilot       VS Code hook config          --agent copilot
  Codex         hooks.json                   --agent codex
  Antigravity   .agents/hooks.json           --agent antigravity

The agent may also be selected with STING_AGENT, for hook configs that make it
awkward to pass arguments.

EXIT CODES — these are the contract, and the runner depends on them:
    0   a verdict was produced (stdout carries it; empty stdout means allow)
    2   the guard could not decide. NOT an allow. Fail closed.

Treating a crashed guard as an allow is the instrumentation bug that lets a
fully broken guard report a clean-looking score. See
the design notes on inspection points (L3).
"""
from __future__ import annotations

import json
import time
from dataclasses import replace
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ⚠ THE FLOOR, CHECKED BEFORE THE IMPORT THAT WOULD OTHERWISE TRACEBACK.
#
# DERIVED, not assumed: the only 3.11+ feature in the tree is `StrEnum`
# (core/types.py:29). There is no `match`, no `tomllib`, no dataclass `slots=` or
# `kw_only=`, no `datetime.UTC`. `X | Y` annotations are lazy everywhere via
# `from __future__ import annotations`.
#
# On 3.10 the failure without this is `ImportError: cannot import name
# 'StrEnum'` raised from inside core/types.py — a traceback from inside a hook,
# which the agent may swallow whole, leaving a guard that silently never runs.
# One line, on stderr, naming the version, and a non-zero exit the caller can
# see. This block must stay ABOVE the `core` import and must not use any syntax
# newer than the oldest interpreter that could reach it.
if sys.version_info < (3, 11):
    sys.stderr.write(
        "sting: needs Python 3.11 or newer (StrEnum); this is %d.%d at %s\n"
        % (sys.version_info[0], sys.version_info[1], sys.executable))
    raise SystemExit(2)

from adapters import ADAPTERS_BY_NAME                                  # noqa: E402
from adapters import antigravity, claude_code, codex, copilot, cursor  # noqa: E402,F401
from core import allow_once, audit_log, engine, locking, policy, probes, title  # noqa: E402
from core import why as why_facts                                     # noqa: E402
from core.display import visible                                       # noqa: E402
from core.session import capture_preexisting_remotes, open_session     # noqa: E402
from core.types import Decision, Verdict                               # noqa: E402

# ⚠ THE REGISTRY MOVED TO `adapters/__init__.py` AND IS IMPORTED, NOT RESTATED.
# Adding an agent must not mean editing the process every hook invokes, and two
# lists of adapters is one list that can be missing an entry — the entry whose
# semantic probe would then never run.
ADAPTERS = ADAPTERS_BY_NAME

# ⚠ THESE TWO CONSTANTS ANSWER TWO DIFFERENT QUESTIONS AND MUST NEVER BE ONE
# VALUE AGAIN. `DEFAULT_AGENT = "claude-code"` used to answer both, and that is
# the whole of the defect: the agent name is (a) the LABEL stamped on the record
# and (b) the KEY that selects the adapter which parses the payload. Collapsing
# them meant an invocation that named no agent got Claude Code's parser — which
# is the correct fallback — and Claude Code's LABEL, which is a lie. Every
# record a Cursor install produced before `--agent` was always passed says
# `claude-code`.
#
# The failure mode is a WRONG name, never a missing one, and wrong is worse: a
# missing label makes a reader ask, a wrong one makes them investigate the wrong
# tool. This repo has now found "one value answering two questions" four times.
#
# So: `UNKNOWN_AGENT` is the LABEL for "nobody said" — the same three-state
# discipline `core/purpose.py` holds for `purpose`, where absence stays absent
# all the way to the reader and is never coerced into the common case.
# `FALLBACK_ADAPTER` is the PARSER for the same state, and it is a fallback
# rather than a default because a hook with no parser has no verdict at all.
UNKNOWN_AGENT = "unknown"
"""The label when the invocation declared no agent. NOT a parser key."""

FALLBACK_ADAPTER = "claude-code"
"""The parser used when nothing was declared — the reference implementation.

Choosing it labels NOTHING. It is the shape four of the five adapters are
modelled on, so it is the least-wrong guess at a payload of unknown origin, and
guessing a PARSER is recoverable in a way that guessing a NAME is not: a
mis-parsed payload yields an action the engine judges conservatively, while a
mis-labelled record is wrong evidence that reads as right.
"""

# ⚠ `DEFAULT_AGENT` IS DELETED RATHER THAN ALIASED. An alias would keep one
# spelling that answers both questions available to the next caller, which is
# exactly how the two got welded together in the first place.


def observing() -> bool:
    """STING_OBSERVE: log every verdict, block nothing.

    For a live RECORDING run. The agent has to reach the end of an attack chain
    for the recording to be worth anything, and a guard that blocks at the first
    sink gives you a truncated trace you paid for.

    Read here and not in core/engine.py deliberately: mode is a deployment
    concern, not a policy one, and tests/test_hook_entry.py forbids the engine
    from importing `os` at all. The engine decides exactly as it always does —
    only the rendering changes.

    Labelling is untouched, which is the point: mark_sources and propagate run
    inside the session lock during decide(), so the recording carries the real
    session state even though nothing was blocked.
    """
    return os.environ.get("STING_OBSERVE", "").strip() not in ("", "0", "false", "no")


def pick_agent(argv: list[str]) -> str:
    """--agent <name>, else STING_AGENT, else `unknown` — NEVER a guess.

    ⚠ IT USED TO RETURN `claude-code` HERE, AND THAT WAS THE BUG. Returning a
    real agent's name for an invocation that named none is not a default, it is
    a fabricated observation: the record then asserts which tool ran, with no
    evidence, and it asserts it wrongly for every tool that is not Claude Code.

    `unknown` is a label, not a parser key — `run()` resolves the parser
    separately. See FALLBACK_ADAPTER.
    """
    for i, arg in enumerate(argv):
        if arg == "--agent" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--agent="):
            return arg.split("=", 1)[1]
    return os.environ.get("STING_AGENT") or UNKNOWN_AGENT


def _decide(action, hook_env: dict | None = None
            ) -> tuple[object, str, int | None, float | None, object, str]:
    """Decide, degrading rather than crashing if state cannot be reached.

    Returns (verdict, warning, seq, elapsed_ms, action, title). The warning goes to
    stderr; it is a note, not an error, so the exit code stays 0 and the verdict
    still applies. seq is None when the session was unreachable and there is no
    sequence to report.

    ⚠ THE ACTION IS RETURNED, AND THAT IS LOAD-BEARING FOR THE LOG. This
    function is where `action.workspace_roots` is replaced with the roots
    resolved for this session (the cwd fallback the adapter filled in cannot
    know them). Every caller that LOGS — `_canary`, `_log` — must record the
    roots the decision was actually made against, or the record misrepresents
    its own inputs: a book-app session judged against the four declared roots
    logged `["…/book-app"]`, which made a correct `write_outside` read as a
    containment bug. So the resolved action goes back out, and `run()` logs THAT
    one, not the original. On the degraded paths the action returned is whatever
    was resolved so far — the original on a lock/open failure (before resolution
    runs), possibly the resolved one if the state write-back failed after the
    verdict. It is always the same binding the fallback verdict was built from,
    so the two never disagree — and the more-resolved value is the more honest.

    Only the session layer can raise OSError here that this must attribute to the
    state file. `engine.decide()` does ONE bounded local read of its own — the
    memoised org-policy cache (`core/org_policy.load_cached`, step 3a) — but that
    is contained: it catches its own errors and always returns the empty policy,
    never raising (a `stat` and, on change, a size-bounded parse; no network). So
    an OSError reaching here still means the state file, not the policy, and
    RealWorld swallows its own OSErrors as before.

    `hook_env` is the environment the hook was started with, before
    `~/.sting/env` was loaded (item B, docs/110 §B): the only values an
    environment read may fingerprint. None means nobody handed one over.
    """
    try:
        # The only wiring point: session lifecycle and the real machine are
        # supplied here so engine.decide() stays a pure function of its inputs.
        world = probes.RealWorld(hook_env)
        with open_session(action.session_id) as state:
            state.seq = state.next_seq(action.seq)
            state.cwd = action.cwd or state.cwd

            # PROJECT ROOTS, resolved once per session and cached in state.
            # The PreToolUse payload carries no workspace field at all — only
            # cwd — so the adapter cannot know this and fills in cwd alone.
            # That is why a sibling repository looked "outside the project" and
            # 44 ordinary writes were denied in one real session.
            #
            # Resolving here rather than in the adapter keeps engine.decide a
            # pure function and keeps git off the per-action path.
            note = ""
            env_roots = os.environ.get("STING_ROOTS") or ""
            # `None` means UNKNOWN provenance — a session that resolved its
            # roots before this field existed. Treated as stale so it re-checks
            # once and self-heals, rather than carrying a guess forever.
            stale = state.roots_env != env_roots
            announce = stale and state.roots_env is not None and bool(state.workspace_roots)
            if not state.workspace_roots or stale:
                roots, why = world.project_roots(state.cwd)
                if announce:
                    # A CONFIG CHANGE MID-SESSION. Re-resolving is the easy
                    # half; saying so is the point. Without this the developer
                    # sets STING_ROOTS, sees nothing happen, and has no way to
                    # tell the variable was ignored from the variable being
                    # wrong.
                    why = (f"sting: STING_ROOTS changed since this session "
                           f"resolved its project roots; re-resolved to "
                           f"{list(roots)}" + (f" — {why}" if why else ""))
                state.workspace_roots = list(roots)
                state.roots_note = why
                state.roots_env = env_roots
                note = why or ""        # said when it is DECIDED, not repeated

                # FREEZE each root's pre-existing remote URLs, HERE — piggybacked
                # on the once-per-session root resolution so git stays OFF the
                # per-action path, and (this being PreToolUse) BEFORE the first
                # action's command has run, so a remote the session itself adds
                # or `set-url`s is never in the frozen set. A later push to a
                # pre-existing remote then resolves to ASK instead of the "could
                # not resolve the remote" DENY; see engine._preexisting_remote_
                # host. Per repo, never flat: a repo first entered mid-session
                # that is not a resolved root is simply not exempted (today's
                # DENY) — the fail-safe direction. capture_* no-ops on failure.
                for root in state.workspace_roots:
                    capture_preexisting_remotes(state, root, world)

            # THE TITLE, ONCE PER SESSION, FROM WHAT THIS ACTION ALREADY CARRIES.
            # A pure derivation — no file is read, and the transcript never is;
            # core/title.py and docs/79 say why. Cached in state so every later
            # record carries the same label, whatever the later command was.
            if not state.title:
                state.title = title.session_title(
                    state.workspace_roots, state.cwd, action.command,
                    action.tool_name, action.paths)

            # STING_ROOTS SET BUT NOT HONOURED. Distinct from the note above:
            # the variable parsed to real directories and the session is still
            # using something else, which can only mean the cache won. Loud
            # every time, because a trust boundary the developer believes they
            # widened and did not is exactly the case that must not be quiet.
            if env_roots and not set(state.workspace_roots) & {
                    str(Path(r).resolve()) for r in probes.split_roots(env_roots)
                    if Path(r).is_dir()}:
                note = ((note + "\n") if note else "") + (
                    f"sting: STING_ROOTS is set but the project roots in use are "
                    f"{state.workspace_roots} — it did not take effect")
            # Declared, never inferred. The per-session directory sits BELOW
            # this, so one stable value covers every session — and guessing a
            # harness-specific path shape is the mistake this project has made
            # four times already.
            state.scratch_roots = [
                str(Path(d).resolve()) for d in
                probes.split_roots(os.environ.get("STING_SCRATCH") or "")
                if Path(d).is_dir()]

            # ⚠ SCHEMA SKEW IS REPORTED ON EVERY ACTION OF THE SESSION, NOT
            # ONCE. `state.schema_skew` is persisted, so it survives into every
            # later record — which is the point: a session that ran under the
            # maximal-labelling fallback must be identifiable AFTERWARDS. Without
            # it the log shows a session untrusted and holding secrets from its
            # first action with no cause, and a reader would reasonably conclude
            # the developer did something.
            if state.schema_skew:
                note = ((note + "\n") if note else "") + (
                    f"sting: degraded — {state.schema_skew}; "
                    f"failing closed at sinks, open elsewhere")

            action = replace(action,
                              workspace_roots=tuple(state.workspace_roots))

            # Timed here and nowhere else: this brackets decide() alone, so the
            # number in the log is the verdict cost — not interpreter startup,
            # not the session lock, not the log write.
            started = time.perf_counter()
            verdict = engine.decide(action, state, world)
            elapsed = (time.perf_counter() - started) * 1000

            # ⚠ THE UNDECLARED-PROJECT SIGNAL — said once, and only when it bites.
            # A write judged `write_outside` while the cwd is inside no declared
            # root IS the book-app case: a project never added to STING_ROOTS,
            # where the verdict is otherwise silent in observe and a prompt on
            # every write in enforce, with no hint that the fix is one line of
            # config. Gated on the verdict, not on the cwd alone, so a read-only
            # session in an odd directory is not nagged; latched in state so the
            # 200th write of the same session does not repeat it. `is_inside_project`
            # separates this from a write to a genuinely external path (e.g. /etc)
            # from inside the project, where 'add your cwd to STING_ROOTS' is the
            # wrong advice.
            if (not state.warned_undeclared_root
                    and isinstance(verdict.rule_id, str)
                    and verdict.rule_id.endswith(":write_outside")
                    and state.workspace_roots
                    and not engine.is_inside_project(
                        state.cwd, tuple(state.workspace_roots), world)):
                state.warned_undeclared_root = True
                note = ((note + "\n") if note else "") + (
                    f"sting: this working directory ({state.cwd}) is not inside "
                    f"any declared project root {list(state.workspace_roots)} — "
                    f"which is why this write is judged write_outside. Add it to "
                    f"STING_ROOTS to treat it as your project.")
            return verdict, note, state.seq, elapsed, action, state.title
    except OSError as exc:
        verdict = engine.fallback_verdict(action)
        return verdict, (f"sting: degraded — session state unavailable ({exc}); "
                          f"failing closed at sinks, open elsewhere"), None, None, action, ""
    except locking.LockUnavailable as exc:
        # ⚠ THE THIRD ANSWER, AND IT IS NEITHER OF THE TWO THE QUESTION OFFERS.
        #
        # "Proceed without the lock and risk the chain" and "refuse to write and
        # lose the record" are both wrong here, and both are avoidable, because
        # THE TWO LOCKS ARE ON DIFFERENT FILES:
        #
        #     the session state   <root>/<id>.json      — this timeout
        #     the audit chain     <root>/<id>.log.jsonl — a separate lock, taken
        #                                                 later, by `_log`
        #
        # So the chain is never written unserialised: we do not write it here at
        # all, and `_log` takes its own lock afterwards. And the RECORD is not
        # lost: `_log` still runs and still appends. What is lost is narrower
        # and must be named exactly —
        #
        # ⚠ THIS ACTION'S LABELLING DOES NOT PERSIST. `mark_secret` and
        # `mark_untrusted` run inside `decide()`, which runs inside the lock we
        # could not take, so a `.env` read during the wedge is not remembered.
        # That is a real security cost: session memory is the product, and this
        # is the product forgetting. It is bounded to the actions that occur
        # while the lock is stuck, it is LOUD on every one of them, and the
        # verdict itself still fails closed at every sink.
        #
        # ⚠ WHY NOT REFUSE THE ACTION OUTRIGHT. Exit 2 on every action until the
        # wedge clears stops the developer working entirely, and observe mode —
        # which promises to block nothing — would have to suppress it, so on an
        # observing machine the two choices are identical anyway. Degrading
        # matches the precedent directly above: an unreachable state file has
        # meant "fail closed at sinks, open elsewhere" since that path was
        # written.
        verdict = engine.fallback_verdict(action)
        return verdict, (f"sting: degraded — {exc} THIS ACTION'S LABELLING WAS "
                          f"NOT RECORDED, so a secret read now will not be "
                          f"remembered later; failing closed at sinks, open "
                          f"elsewhere"), None, None, action, ""


def _canary(action, title: str = "") -> str:
    """One `session_start` record, the first time this session writes anything.

    ⚠ THE PROBLEM IT SOLVES. A hook that never fires and a hook that fires and
    allows everything produce byte-identical evidence: none. Every record until
    now was written BY a decision, so a session with nothing to say wrote
    nothing — and an empty log directory could equally mean the guard was never
    installed, the settings file was reset, or the interpreter moved.

    INSIDE THE HASH CHAIN, and that is the whole point. Outside it a canary can
    be deleted or forged with no trace, so its presence would prove nothing. In
    the chain, removing it breaks every subsequent hash AND leaves a hole in the
    record count — two independent signals, the same argument that put every
    decision in the log rather than only the denials.

    WHY HERE AND NOT IN `open_session`. `core/session.py` imports only
    `core.types`; `core/audit_log.py` imports `core.session`. Writing it from
    the session module would make that a cycle. The entry point already holds
    both, and "the engine decides, hook_entry records" is the existing rule.

    COST, measured: append() is p99 0.29 ms on a fresh log, and this runs ONCE
    PER SESSION, not per action — 2.4% of the 12 ms A6a budget, paid once.

    ⚠ Benign race: two hooks starting at the same instant can both observe an
    empty log and both write one. `append` serialises them, and `seq=None` skips
    the duplicate check by design, so the result is two markers rather than a
    corrupt chain. A duplicate canary misleads nobody; a missing one does.
    """
    try:
        path = audit_log.default_log_path(action.session_id)
        if path.exists() and path.stat().st_size > 0:
            return ""
        audit_log.append(action.session_id, audit_log.build_body(
            action.session_id, seq=None, event="session_start", decision=None,
            cwd=action.cwd, agent=action.agent,
            workspace_roots=action.workspace_roots, title=title or None))
        return ""
    except Exception as exc:                      # noqa: BLE001 — deliberate
        # Same rule as _log: an observability failure never changes a verdict.
        return f"sting: liveness record not written ({type(exc).__name__}: {exc})"


def _log(action, verdict, seq: int | None, event: str = "decision",
          duration_ms: float | None = None, relaxed=(),
          granted_by: str | None = None, title: str = "",
          enforced: Decision | None = None) -> str:
    """Chain this decision onto the tamper-evident log. Returns a note, or "".

    The note is also how a chain break is ANNOUNCED: when the log's final line
    could not be parsed, `append` records this decision chained from
    UNREADABLE — the contractual, permanent, visible-in-the-file break — and
    until this note existed that was the whole of the visibility. Now the hook
    says it on stderr, at the moment it happens, naming the seq.

    NEVER raises. A log that cannot be written is an observability failure, not
    a policy one — turning it into a crash would fail closed on every action for
    a full disk, which is a far worse outcome than an unrecorded allow. The note
    goes to stderr so the failure is still visible.
    """
    try:
        body = audit_log.build_body(
            action.session_id, seq=seq, event=event, relaxed=relaxed,
            decision=str(verdict.decision), reason=verdict.reason,
            rule_id=verdict.rule_id, kind=str(action.kind),
            paths=action.paths, command=action.command, url=action.url,
            cwd=action.cwd, tool_name=action.tool_name,
            workspace_roots=action.workspace_roots,
            # Set by every adapter since they were written, recorded by nobody.
            # Two developers on two different agents writing into one log
            # directory produced records that were indistinguishable.
            agent=action.agent,
            action_hash=allow_once.fingerprint(action),
            # WHAT FIRED THE RULE — read off the verdict, never re-derived.
            # This used to call engine.sink_evidence(), which re-matched a
            # parallel pattern table: it covered 15 of 19 sinks and, for
            # secret_in_argv, consulted a different predicate than the one that
            # decided, so the log could name text that never fired the rule. The
            # engine now carries the span it matched on, which is the same
            # objection as the extension recomputing action_hash: one decision,
            # one implementation.
            evidence=verdict.evidence,
            duration_ms=duration_ms,
            # ⚠ ONLY EVER SET FOR event="allow_once_used". `build_body` drops the
            # key when this is None, so every ordinary record — including an
            # engine-decided ALLOW — is byte-identical to before.
            granted_by=granted_by,
            # THE SESSION'S TITLE, derived once in _decide; `None` keeps a body
            # that has no title byte-identical to before (clean absence).
            title=title or None,
            # WHY A DENY OR AN ASK (docs/108), read off the verdict: None for
            # an ALLOW, so an ALLOW record is byte-identical to before.
            why=why_facts.record_fields(verdict),
            # WHAT THE AGENT WAS TOLD (docs/113 §1), beside the verdict above.
            enforced=enforced)
        entry = audit_log.append(action.session_id, body)
        # OPTION D. The record's `command` is clipped, so a verdict on a long
        # command cannot be RE-RUN from the log alone. The full text goes beside
        # the log, content-addressed by the `command_sha256` already inside the
        # hashed body — the chain supplies the authority, the file supplies only
        # bytes. Written AFTER the append on purpose: the record is the evidence
        # and the sidecar is a convenience, so if this fails the decision is
        # still recorded. store_full_command never raises.
        audit_log.store_full_command(
            audit_log.default_log_path(action.session_id), action.command)
        if entry["prev"] == audit_log.UNREADABLE:
            # ⚠ THE SENTINEL IS CONTRACTUAL; THE SILENCE AROUND IT WAS NOT.
            # The record is written, the decision is enforced, verify_chain
            # will report the break — and nobody would have been told. Said
            # here, once, where it happened; the caller puts notes on stderr.
            return (f"sting: the decision log's last line could not be read; "
                    f"seq {body.get('seq')} is recorded but chains from "
                    f"UNREADABLE — the hash chain is broken here, and "
                    f"verify_chain will say so")
        return ""
    except Exception as exc:                      # noqa: BLE001 — deliberate
        return f"sting: decision not logged ({type(exc).__name__}: {exc})"


def _enforced_answer(overlay: policy.Overlay, verdict: Verdict) -> Decision | None:
    """What the relaxations make of the engine's verdict, for its record
    (docs/113 §1), or None when the overlay cannot say: an answer the record
    leaves out is never a reason not to write the record."""
    try:
        return overlay.enforce(verdict)[0].decision
    except Exception:                             # noqa: BLE001 — the record comes first
        return None


def _apply_allow_once(action, verdict, seq: int | None) -> tuple[object, str, object]:
    """Spend a one-shot grant, if the developer armed one for THIS action.

    Returns (verdict, note). Only a DENY is overridable — there is nothing to
    override on an allow, and asking the engine twice would be a second policy
    decision made outside the engine.

    Labelling is untouched: engine.decide() already marked the session inside
    the lock before this runs, so an overridden action still taints exactly as
    it would have. The override changes the answer, not the memory.
    """
    if verdict.decision is not Decision.DENY:
        return verdict, "", None
    try:
        grant = allow_once.consume(action.session_id, action)
    except Exception as exc:                      # noqa: BLE001 — deliberate
        # A broken grant is not permission. Keep the denial.
        return verdict, f"sting: allow-once not readable ({type(exc).__name__}: {exc})", None
    if grant is None:
        return verdict, "", None

    allowed = Verdict(Decision.ALLOW,
                      f"allowed once by the developer; the engine denied this: "
                      f"{verdict.reason}", verdict.rule_id)
    # ⚠ WHO IS RETURNED SEPARATELY, NOT PUT ON THE VERDICT. A Verdict is what the
    # engine produced (decision, reason, rule_id) and this override is not the
    # engine's — threading `granted_by` through the verdict would blur that. It
    # goes onto the `allow_once_used` RECORD, and only that record. `granted_by`
    # is a grant field with its own default of "unknown", so it is never None
    # for a real grant; None here means no override happened.
    granted_by = grant.get("granted_by")
    return allowed, (f"sting: one-shot override spent for rule "
                     f"{verdict.rule_id!r} (granted by {granted_by})"), granted_by


def _normalise_payload(text: str) -> str:
    r"""Strip a leading BOM and trim to the first `{` or `[`. DEFENCE IN DEPTH.

    ⚠ THIS IS THE ENGINE'S HALF OF THE CURSOR-ON-WINDOWS FIX, AND IT IS
    MEASURED. On the first native Windows Cursor install the hook received the
    payload via `Get-Content '<temp>.json' -Raw`, which prepends a UTF-8 BOM, so
    `json.loads` died on the first character with the exact error the developer
    saw: "Unexpected UTF-8 BOM (decode using utf-8-sig)". A leading BOM, a stray
    banner line, or PowerShell's own decoration all vanish once the text is
    trimmed to where JSON actually begins.

    ⚠ IT DOES NOT REPLACE THE BRIDGE. RC2 is two faults stacked — the BOM AND
    unreliable stdin delivery via `$input | native.exe`. This fixes the first on
    EVERY platform, so a BOM never breaks a payload again; the bridge
    (`installer/cursor_bridge.ps1`) fixes the second by writing to the child's
    stdin through .NET ProcessStartInfo. Neither alone is sufficient, which is
    why both exist.

    Conservative: it only strips before the first structural character, so a
    valid payload is untouched and a genuinely malformed one still fails to
    parse — an unparseable payload is never treated as permission.
    """
    if not text:
        return text
    stripped = text.lstrip("\ufeff\r\n\t ")
    starts = [stripped.find(c) for c in "{[" if stripped.find(c) >= 0]
    return stripped[min(starts):] if starts else stripped


def resolve_agent(agent: str):
    """(adapter, label) — the PARSER and the NAME, resolved separately.

    ⚠ THE TRAP THIS EXISTS TO AVOID. One string was answering two questions:
    which module parses the payload, and what name goes on the record. They
    have different right answers for the same input, and there are exactly
    THREE states, not two:

        declared and known    ("--agent cursor")   cursor's parser, "cursor"
        declared and UNKNOWN  ("--agent cursur")   REFUSED — see below
        not declared at all   (no flag, no env)    the fallback parser,
                                                   labelled "unknown"

    ⚠ THE MIDDLE STATE IS NOT FOLDED INTO THE THIRD, AND THAT MATTERS. A typo'd
    or unsupported `--agent` is somebody ASSERTING an agent this build cannot
    parse. Accepting it as "unknown" would parse the payload with the wrong
    adapter and record a shrug, hiding a broken install behind a plausible
    label; refusing says so. Returning `None` for the adapter keeps the existing
    exit-2 path exactly as it was.

    Returns (None, agent) for the refusal so the caller can report the name.
    """
    if agent == UNKNOWN_AGENT:
        # ⚠ A PARSER IS STILL REQUIRED. "Record `unknown`" must not become "have
        # no adapter", because a hook with no adapter produces no verdict at
        # all — an unlabelled invocation would stop being guarded, which trades
        # a wrong label for no guard. The label is what goes unknown; the
        # parsing falls back.
        return ADAPTERS[FALLBACK_ADAPTER], UNKNOWN_AGENT
    return ADAPTERS.get(agent), agent


def run(stdin_text: str, agent: str = UNKNOWN_AGENT,
        hook_env: dict | None = None) -> tuple[str, str, int]:
    """The whole pipeline, as a pure function of its input — see `_run`.

    ⚠ ITS NOTES ARE SHOWN, SO VISIBLE (item C, docs/110 §C): stderr quotes a
    cwd, a path or an exception's text, and the agent reads it."""
    out, err, code = _run(stdin_text, agent, hook_env)
    return _told_to(agent, out, visible(err, multiline=True), code)


def _told_to(agent: str, out: str, err: str, code: int) -> tuple[str, str, int]:
    """⚠ A GUARD THAT COULD NOT DECIDE, TOLD IN THE SHAPE ITS AGENT BLOCKS ON
    (docs/110 §A). Exit 2 blocks on every agent but Antigravity, which reads it
    as a hook error and, on one of its two paths, runs the call; an adapter
    with `render_failure` answers a deny instead, with exit 0. `run()` and
    `main()`'s last resort both answer through here."""
    if code != 2:
        return out, err, code
    try:
        adapter, _label = resolve_agent(agent)
    except Exception:                                 # noqa: BLE001 — exit 2 stands
        return out, err, code
    failed = getattr(adapter, "render_failure", None)
    return (failed(err), err, 0) if failed is not None else (out, err, code)


def _run(stdin_text: str, agent: str = UNKNOWN_AGENT,
         hook_env: dict | None = None) -> tuple[str, str, int]:
    """The whole pipeline, as a pure function of its input.

    Returns (stdout, stderr, exit_code) so tests can exercise it without a
    subprocess. main() is the only part that touches the real streams.

    `hook_env`: the environment the hook process was started with, as its
    caller saw it BEFORE loading `~/.sting/env` (item B, docs/110 §B) — what
    `main` takes, or what the daemon's caller sent. Never read from here.
    """
    adapter, label = resolve_agent(agent)
    if adapter is None:
        known = ", ".join(sorted(ADAPTERS))
        return "", f"sting: unknown agent {agent!r} (known: {known})", 2

    # ⚠ AN EMPTY PAYLOAD USED TO BECOME `{}` AND THEN AN ALLOW, three lines
    # above a comment saying "Unparseable input is not permission to proceed."
    # Measured through the real hook as a subprocess:
    #
    #     stdin ''              -> exit 0, permissionDecision "allow"
    #     stdin 'null' / '[]'   -> exit 0, permissionDecision "allow"
    #
    # Harmless while ALLOW rendered as empty output — Claude Code saw no opinion
    # and applied its own rules. It stopped being harmless the moment ALLOW
    # became explicit: the guard now actively PERMITS an action on a payload it
    # never received. "I was sent nothing" is not "go ahead".
    if not stdin_text.strip():
        return "", ("sting: the guard failed to decide — it received an EMPTY "
                     "payload on stdin. This is NOT a policy refusal: no rule "
                     "ran and nothing was judged."), 2

    try:
        raw = json.loads(_normalise_payload(stdin_text))
    except json.JSONDecodeError as exc:
        # Unparseable input is not permission to proceed.
        return "", f"sting: could not parse hook payload: {exc}", 2

    if not isinstance(raw, dict):
        # `null`, `[]`, `"a string"` — parseable JSON that describes no call.
        return "", (f"sting: the guard failed to decide — the payload is a "
                     f"{type(raw).__name__}, not an object describing a tool "
                     f"call. This is NOT a policy refusal."), 2

    # ⚠ LOADED ONCE PER INVOCATION AND BEFORE THE DECISION, so a broken policy
    # file is reported even on a call that then fails for another reason. It is
    # one small file read; `load` never raises and a missing file is the
    # ordinary case, which costs a single failed `open`.
    overlay = policy.load()

    try:
        action = adapter.parse(raw)
        # ⚠ THE ADAPTER STAMPS ITS OWN NAME, SO THE LABEL IS OVERRIDDEN HERE
        # AND ONLY HERE. `claude_code.parse` sets `agent="claude-code"` because
        # from inside the adapter that is simply true — it is the Claude Code
        # adapter. It is the CALLER that knows the adapter was a fallback rather
        # than a declaration, so the caller is the only place that can say so.
        #
        # Not pushed into the adapters: five adapters each learning "unless you
        # were picked by default" is five copies of one fact, and the four that
        # are never the fallback would carry dead code that looked live.
        if label != action.agent:
            action = replace(action, agent=label)

        # ⚠ A SHELL TOOL WHOSE COMMAND IS NOT A COMMAND IS UNPARSEABLE INPUT (H1),
        # and takes the same exit as the empty and non-object payloads above.
        # `{"command": 7}` or `null` used to parse to "EXEC, no command" and the
        # engine, with nothing to object to, allowed it. An argv LIST never gets
        # here — `_common.shell_command` joins it and it is judged as a string.
        if action.malformed:
            return "", (f"sting: the guard failed to decide — the payload names a "
                         f"shell tool but {action.malformed}. This is NOT a "
                         f"policy refusal: no rule ran and nothing was judged."), 2

        # ⚠ A PAYLOAD NAMING NO TOOL DESCRIBES NO ACTION, AND THE HONEST ANSWER
        # IS SILENCE, NOT PERMISSION. It used to parse into "a TOOL call with
        # tool=None, command=None" — an action about nothing — which the engine
        # allowed because there was nothing to object to. Rendering that as an
        # explicit `allow` tells Claude Code to proceed on a payload we did not
        # understand.
        #
        # ⚠ ABSTAINING RATHER THAN REFUSING, DELIBERATELY. Exit 2 here would
        # block every tool call the day Claude Code ships a payload shape this
        # adapter does not read yet. Empty stdout is "no opinion": Claude Code
        # applies its own rules, which is what it did for every verdict before
        # this pass — a known-safe state, and loudly reported on stderr.
        # ⚠ EVERY FIELD THAT CAN NAME AN ACTION, NOT JUST THE TOOL NAME. The
        # first version of this gate checked `tool_name` and `command` only —
        # and `codex._kind_for` / `cursor._kind_for` DELIBERATELY infer READ,
        # WRITE, EDIT and FETCH from `paths`, `url` and `content` when the
        # vendor sends no tool name. Measured: a Codex payload
        # `{"tool_input": {"file_path": ".env"}}` parses to kind=READ with a
        # real path, and this gate dropped it — no verdict, and because the
        # return happens BEFORE `_canary` and `_log`, NO RECORD AT ALL. A sink
        # action leaving no evidence it happened is worse than the confident
        # allow this gate was added to remove.
        if (action.tool_name is None and not action.command
                and not action.paths and not action.url and not action.content):
            return "", (f"sting: NO OPINION — the payload named no tool, so "
                         f"there was no action to judge and nothing was "
                         f"permitted. Falling back to {label}'s own rules. "
                         f"This is NOT a policy refusal."), 0

        # ⚠ REBIND `action` TO THE ONE `_decide` JUDGED. Root resolution happens
        # inside `_decide`, which replaces action.workspace_roots with the roots
        # resolved for this session; everything below LOGS, and the log must
        # name the roots the decision used, not the cwd fallback the adapter
        # filled in. The fingerprint (allow-once) does not read workspace_roots,
        # so this does not move any action_hash.
        verdict, degraded, seq, took_ms, action, session_title = _decide(action, hook_env)
        # The canary FIRST, so a session that is about to be judged has already
        # proved the hook was alive — even if the decision record then fails.
        notes = [_canary(action, session_title), degraded]

        if observing():
            # The REAL verdict goes on the record; nothing is enforced, so the
            # answer beside it is ALLOW (docs/113 §1). Render nothing.
            #
            # Allow-once is skipped: there is nothing to override when nothing
            # is being blocked, and consuming a grant here would silently spend
            # it on an action that was never going to be stopped.
            #
            # Loud on every call, deliberately. A guard in observe mode protects
            # nothing, and nobody should ever be in it by accident and believe
            # otherwise.
            notes.append(_log(action, verdict, seq, duration_ms=took_ms,
                              relaxed=overlay.relaxed, title=session_title,
                              enforced=Decision.ALLOW))
            notes.append(
                f"sting: OBSERVE — blocking nothing. Engine said "
                f"{verdict.decision} ({verdict.rule_id or 'no rule'}).")
            return "", "\n".join(n for n in notes if n), 0

        # The engine's own verdict is recorded FIRST and always. An override
        # then appends its own record, so the log shows both what the policy
        # decided and that a human overruled it — never just the outcome.
        # ⚠ BESIDE IT, WHAT THE RELAXATIONS TELL THE AGENT (`enforced`, docs/113
        # §1), settled with no side effect so the record still comes first. A
        # one-shot grant spent below is its own record's answer: the
        # `allow_once_used` that follows at the same seq, ALLOW.
        notes.append(_log(action, verdict, seq, duration_ms=took_ms,
                          relaxed=overlay.relaxed, title=session_title,
                          enforced=_enforced_answer(overlay, verdict)))

        final, override, granted_by = _apply_allow_once(action, verdict, seq)
        if override and final is not verdict:
            notes.append(_log(action, final, seq, event="allow_once_used",
                               duration_ms=took_ms, relaxed=overlay.relaxed,
                               granted_by=granted_by, title=session_title))
        notes.append(override)

        # ⚠ THE OFF-SWITCH IS APPLIED HERE, AFTER THE ENGINE'S OWN VERDICT HAS
        # ALREADY BEEN RECORDED, AND IT NEVER TOUCHES THE ENGINE.
        #
        # `core/engine.decide()` performs no IO and reads nothing about the
        # machine — two tests enforce that — so a relaxation cannot live inside
        # it. What this changes is what is DONE with a decision, never the
        # decision: the record above still says what the policy actually
        # concluded, which is what keeps the standing replay comparable and what
        # lets a reader see that a rule fired even though nothing was stopped.
        #
        # ⚠ AND IT ONLY EVER WEAKENS. `Overlay.apply` refuses anything that
        # would strengthen, so this line cannot be the reason an action was
        # refused — only ever the reason one was not. See core/policy.py.
        # A relaxed installed-guard floor enforces the verdict it replaced
        # (`Overlay.enforce`), never a blanket ALLOW.
        final, relaxed_note = overlay.enforce(final)
        notes.append(relaxed_note)
        # The action says which event this answers, where an agent's answer
        # differs by event (Cursor: docs/110 §A).
        return adapter.render(final, action), "\n".join(n for n in notes if n), 0
    except Exception as exc:                      # noqa: BLE001 — deliberate
        # ⚠ THE GUARD BROKE, AND IN ENFORCE MODE THAT BLOCKS — SO IT MUST NOT
        # READ LIKE A POLICY REFUSAL. This is TASK 1.2's second half.
        #
        # A rule refusing and the guard crashing are BOTH a stopped tool call,
        # and until now both said `sting: <Error>: <msg>`. A developer facing a
        # blocked command has to know which, because the two have opposite next
        # steps: a refusal is a decision to argue with or relax, a crash is a
        # bug to report and a reason to fall back to observe.
        #
        # ⚠ AND IT NAMES NO SWITCH (item 2). This is stderr on exit 2, which every
        # agent reads and Claude Code gives to the model, so "`python3 install.py
        # --observe` records and blocks nothing" told the model how to turn the
        # guard off. The person has it from their own terminal (`install.py
        # --help`), where the hook does not run.
        return "", (
            f"sting: ⚠ THE GUARD FAILED TO DECIDE — this is NOT a policy "
            f"refusal.\n"
            f"  what     {type(exc).__name__}: {exc}\n"
            f"  meaning  no rule stopped this. The guard could not reach a "
            f"verdict at all, and enforce mode refuses rather than permitting "
            f"what it did not judge.\n"
            f"  next     stop and tell the user the guard failed. "
            f"`python3 tools/preflight.py` names which part is broken.\n"
            f"  ⚠ NOT a rule anyone can relax — no rule ran, so there is none "
            f"to name."), 2


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # ⚠ THE AGENT'S ENVIRONMENT, TAKEN BEFORE STING ADDS ITS OWN (item B,
    # docs/110 §B): an environment read fingerprints values from this, and
    # what `~/.sting/env` loads below was never the agent's.
    hook_env = dict(os.environ)
    # ⚠ ~/.sting/env, NOT THE COMMAND LINE — see envfile.py. Also loaded here so
    # a direct `python hook_entry.py` (install pointing straight at it, or the
    # daemon booting it) gets the same environment sting_hook gives it. The
    # environment already wins over the file, so re-loading when sting_hook
    # already did is a harmless no-op.
    import envfile
    envfile.load()
    agent = UNKNOWN_AGENT
    try:
        agent = pick_agent(argv)
        out, err, code = run(sys.stdin.read(), agent, hook_env)
    except Exception as exc:                          # noqa: BLE001 — deliberate
        # Nothing above this line may take the process down. Reading stdin or
        # picking the agent can fail too, and in observe mode a traceback would
        # become a non-zero exit, which blocks.
        out, err, code = _told_to(agent, "", visible(f"sting: {type(exc).__name__}: {exc}"), 2)

    if observing():
        # THE OBSERVE GUARANTEE, enforced at one choke point rather than trusted
        # to every path above it.
        #
        # `run()` fails CLOSED by design — exit 2 on unparseable input, an
        # unknown agent, or any engine exception, because a guard that cannot
        # decide must not wave an exit through. Correct when enforcing. WRONG
        # here: exit 2 blocks the tool call, so a parse bug or an engine crash
        # would stop the developer's real work while claiming to observe only.
        # Measured before this existed: unparseable stdin, unknown agent and a
        # forced engine crash all exited 2 and would have blocked.
        #
        # Observe means observe. Every failure is reported on stderr and none of
        # them blocks.
        if out or code:
            note = f"sting: OBSERVE suppressed a blocking result (exit={code})"
            err = f"{err}\n{note}" if err else note
        out, code = "", 0

    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
