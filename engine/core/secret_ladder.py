"""The secret ladder, and the reasons it gives: how exactly an exit carries a
secret the session holds (`_secret_level`), and the sentences that say where
that secret was seen.

Moved out of core/engine.py; docs/ENGINE_LAYOUT.md.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from core import known_formats
from core import why as why_facts
from core.types import Action, ActionKind, SessionState, Why, World
from core.command_text import (_EVIDENCE_CONTEXT, _structure_text, executed_text,
                               mentions_path, span_evidence)
from core.credentials import (CREDENTIAL_PATHS, _matches_fingerprinted_value,
                              carries_canary, carries_secret, sends_the_environment)
from core.sources import _paths_mentioned_in

STAGED = "the staged changes"
"""What `_exact_source` was given when it read `git diff --cached`."""


def _exact_source(text: str | None, state: SessionState,
                  command: bool = False, within: str = "") -> dict:
    """The `source` dict for an EXACT level found in `text`.

    Provenance's answer is the session's — which file, which step — and that is
    what the ladder has always reported. When the value was recognised by its
    documented FORMAT (core/known_formats.py), the source also carries the
    format's NAME, so the reason can say "an AWS access key ID" in a session
    that never read a credential file, and its EVIDENCE points at the key
    rather than at the sink. Never the value: a `Hit` has no value field, and
    the span is the engine's usual window with every key in it replaced by its
    name and length (`_masked_span`), reduced to an offset on the wire.

    ⚠ THE LEFTMOST VALUE, WHEN THERE ARE SEVERAL. The reason names it and the
    evidence points at it; every value in the window is masked.

    `command=True` mirrors `carries_secret`'s: on a command, the exact level can
    also come from shipping the environment, which no read precedes. That is
    named as the `basis` only when neither a format nor a fingerprint explains
    the hit, so a real provenance reason is never replaced.

    `within` names what `text` is ("the command", "the staged changes"), so
    the record can say where the value sits (docs/108); a staged hit also
    carries its file and line (`staged_at`).
    """
    source = {"level": "exact", "from_seq": state.holds_secret_since_seq}
    first = known_formats.find_known_secret(text)
    if first is not None:
        source["format_id"] = first.format_id
        source["format"] = first.name
        source["evidence"] = _masked_span(
            text, known_formats.masked_spans(text, first, _EVIDENCE_CONTEXT),
            known_formats.hidden_before(text, first, _EVIDENCE_CONTEXT))
        source["within"] = within
        source["offset"] = first.start
        if within == STAGED:
            source["staged_at"] = why_facts.diff_position(text, first.start)
    elif (command and not _matches_fingerprinted_value(text, state)
          and sends_the_environment(text)):
        source["basis"] = "environment"
    return source


def _masked_span(text: str, spans: list[tuple[int, int, str]],
                 before: list[tuple[int, int, str]] = ()) -> str:
    """`span_evidence` around the FIRST value, with EVERY value replaced by
    what it is. `spans` are `known_formats.masked_spans`: `(start, end, name)`,
    the first one the reason's value. `before` are
    `known_formats.hidden_before`, masked at their own length so that nothing
    after them moves and the offset stays the raw one.

    ⚠ A FORMAT HIT KNOWS THE EXACT SPAN, WHICH NO OTHER RULE DOES — so it can
    redact precisely instead of shipping the raw window and relying on the
    wire tier. The window keeps its offset (the first value's, in the raw
    text) and its surroundings, which is the judgeable part, and
    `<an AWS access key ID, 20 chars>` stands where each key sat.

    ⚠ EVERY VALUE, NOT ONE. Masking only the one the matcher returned left a
    second value within the window raw in the local record's `evidence`, which
    ships at `full`. Below `full` evidence travels as its offset alone
    (REASONED too, since #74), so the value reaches a collector only in the
    `command` field, at the tier that ships it on purpose.
    """
    for start, end, name in before:
        text = text[:start] + _fitted(known_formats.stand_in(name, end - start),
                                      end - start) + text[end:]
    stand_ins = [known_formats.stand_in(name, end - start) for start, end, name in spans]
    pieces, cursor = [], 0
    for (start, end, _name), stand_in in zip(spans, stand_ins):
        pieces += [text[cursor:start], stand_in]
        cursor = end
    masked = "".join(pieces) + text[cursor:]
    start = spans[0][0]
    return span_evidence(masked, start, start + len(stand_ins[0]))


def _fitted(stand_in: str, length: int) -> str:
    """`stand_in` at exactly `length` characters: cut, or padded with `*`."""
    return stand_in[:length].ljust(length, "*")


def _staged_secret_level(
        action: Action, state: SessionState, world: World,
        newest: Callable[[Iterable[str]], tuple[str | None, dict | None]],
) -> tuple[str | None, dict | None, bool]:
    """What is really in the commit about to be pushed: (level, source, whether
    git's index was read).

    CLAUDE.md rule #7: inspect `git diff --cached`, not a staged-file list we
    maintained ourselves. Ours is wrong in both directions —

      too broad   we recorded a `git add` of a path that .gitignore then
                  dropped, so we would deny a push carrying nothing
      too narrow  `git add -f` forced in an ignored file, or an edit made
                  outside the agent's tool calls, and we never saw either

    Three checks, in descending confidence:
      1. a staged path we already know is tainted
      2. a staged path that is itself credential-shaped, while holding secrets
      3. the staged CONTENT carrying a known fingerprint — the only one that
         can see a file we never watched being written

    If git cannot be inspected at all (not a repo, git missing, timeout) we
    fall back to our own list. A successful-but-empty index is NOT a fallback
    case: an empty commit genuinely carries nothing, and treating it as
    "use the stale list" would deny a push that carries no secret.
    """
    staged = world.staged_files(action.cwd)
    inspected = staged is not None
    if staged is None:
        staged = tuple(state.staged_secret_files)      # could not look

    # ⚠ THE STRICTEST FINDING, NOT THE FIRST (docs/110 §B.3). A staged file
    # written while holding the secret is "derived"; the staged CONTENT can
    # still carry the exact value, and that is what leaves. `exact` ends the
    # search; `derived` is kept while a stricter finding is sought.
    level, src = newest(staged)
    if level == "exact":
        return level, src, inspected
    derived = src if level == "derived" else None

    if state.holds_secret:
        for path in staged:
            if CREDENTIAL_PATHS.search(path):
                return "exact", {"level": "exact", "path": path,
                                 "from_seq": state.holds_secret_since_seq}, inspected

    if inspected and not staged:
        # THE INDEX WAS READ AND IS EMPTY, so the staged diff is necessarily
        # empty too — asking git for it again costs ~12 ms to be told nothing.
        # `inspected` is what makes this safe: a None from staged_files means
        # "could not look", which is NOT the same as "nothing staged", and that
        # case still falls through to the real call below.
        #
        # Rule #7 is untouched. This does not cache or assume anything about
        # the index; it derives one fresh fact from another fresh fact read
        # microseconds earlier.
        return None, None, inspected

    content = world.staged_content(action.cwd)
    # ⚠ THE CANARY, ON THE SAME staged CONTENT — checked first, and reusing the
    # content already read (no extra git spawn). A decoy value `git add`ed and about
    # to be committed/pushed is exfiltration the command text cannot show; this is
    # the one path that sees it. Routed to the `canary_exfil` rung by the ladder.
    if carries_canary(content, state):
        return "canary", {"level": "canary"}, inspected
    if carries_secret(content, state):
        return "exact", _exact_source(content, state, within=STAGED), inspected

    if derived is not None:
        return "derived", derived, inspected
    return None, None, inspected


def _secret_level(action: Action, state: SessionState, world: World,
                   sink: str) -> tuple[str | None, dict | None, bool]:
    """Is the data THIS action moves labelled? Returns (level, source, enumerated).

    Not "is the session holding secrets" — that is a different question, and
    conflating them is what would block a bare `.env` read.

    `enumerated` says whether the payload could be LISTED at all. A push whose
    index we successfully read is a positive finding of "carries nothing"; a
    push we could not inspect, or a curl whose body we cannot see, is an absence
    of information. Those are different facts and the ladder must not conflate
    them — doing so is what would deny N09's clean-index push.

    Only git_push can ever be enumerated: it is the one sink whose payload the
    engine can list and fingerprint. Everything else is False by construction.
    """
    # ⚠ EVERY EXACT SOURCE CARRIES A `basis` — what this branch SAW — so the
    # reason can say it (`_exact_reason`). Without it the reason fell back to
    # "traced from a credential file read earlier in this session" for a session
    # that had read nothing (item A, docs/96). A NEW dict each time: the stored
    # taint entry is session state and is never written from here.
    def tainted(path, entry):
        return {**entry, "basis": "tainted_path", "path": path}

    def newest(paths):
        best, best_src = None, None
        for path in paths:
            entry = state.tainted_paths.get(path)
            if not entry:
                continue
            if entry["level"] == "exact":
                return "exact", tainted(path, entry)
            best, best_src = "derived", entry
        return best, best_src

    exact_now = {"level": "exact", "from_seq": state.holds_secret_since_seq}

    # A push carries whatever is ACTUALLY in the commit — step 10.
    enumerated = False
    # ⚠ THE STRICTEST FINDING, NOT THE FIRST (docs/110 §B.3). Every check below
    # used to return what it found. A command naming a file written while the
    # session held a secret ("derived") and carrying the secret's exact value
    # answered "derived": the tainted-path loop met the file first. `exact`
    # (or a canary) ends the search; the first `derived` is kept, and answered
    # only when nothing stricter turns up.
    derived: dict | None = None

    def settle(level, src) -> bool:
        nonlocal derived
        if level == "derived":
            derived = src if derived is None else derived
            return False
        return bool(level)

    if sink in ("git_push", "git_commit"):
        # A commit carries whatever is ACTUALLY in the index, the same question
        # a push asks. Inspecting it here is what keeps an ordinary commit in a
        # secret-holding session quiet: a clean index is `enumerated`, so it
        # skips bucket 1's escalation and lands on ALLOW.
        level, src, enumerated = _staged_secret_level(action, state, world, newest)
        if settle(level, src):
            return level, src, enumerated

    level, src = newest(action.paths)
    if settle(level, src):
        return level, src, enumerated

    if action.kind is ActionKind.EXEC and action.command:
        cmd = action.command
        for path, entry in state.tainted_paths.items():
            if mentions_path(cmd, path) and settle(entry["level"], tainted(path, entry)):
                return entry["level"], tainted(path, entry), enumerated
        # STRUCTURE, despite living in a payload function. "Does this command
        # OPERATE ON a credential file" is a question about the command, not
        # about what it carries — a commit message that MENTIONS `.env` is
        # discussing it, not sending it. The payload question is asked two
        # branches below by carries_secret(), which keeps reading `cmd` raw.
        #
        # Measured, not assumed, because I02 is A1 and its decisive command
        # mentions `.env` only inside a commit message. With and without this
        # change I02 denies at seq 4 (secret_exact:git_commit) and seq 5
        # (secret_exact:git_push), byte-identical — as do A01 and I06. I02's
        # block comes from inspecting the staged index, which is CLAUDE.md
        # rule #7 working correctly, not from the text of the message.
        #
        # On one real session this branch fired on 78 of 645 commands, every one
        # of them a `.env` mentioned inside a heredoc body.
        #
        # ⚠ AND NOT A `.env`, OR A `cd .aws`, WRITTEN INSIDE A GREP PATTERN
        # (item B, docs/100): the structure view, as `_sink_hit` reads it.
        for path in _paths_mentioned_in(
                _structure_text(executed_text(cmd), state), action.cwd):
            if CREDENTIAL_PATHS.search(path):
                return "exact", {**exact_now, "basis": "credential_path",
                                 "path": path}, enumerated
        for name, var_seq in state.tainted_vars.items():
            if re.search(rf"\${{?{re.escape(name)}\b", cmd):
                return "exact", {**exact_now, "basis": "tainted_var",
                                 "var": name, "var_seq": var_seq}, enumerated
        # THE COMMAND TEXT ITSELF. Until now no branch checked it, so a secret
        # pasted verbatim into a command was invisible even with its exact value
        # already fingerprinted — `curl -d "AKIA…"` returned ASK ("could not be
        # inspected") while the engine held the matching hash. Nothing in the
        # corpus exercises this; it closes a hole the corpus cannot see.
        if carries_secret(cmd, state, command=True):
            return "exact", _exact_source(cmd, state, command=True,
                                          within="the command"), enumerated

    if action.kind is ActionKind.FETCH:
        # ⚠ THE URL AND THE QUERY, WHICH NO BRANCH FINGERPRINTED. A WebFetch of
        # `https://x/?leak=<secret>` returned ASK ("could not be inspected")
        # while the curl of the same URL was DENY — the same secret, the same
        # direction, a different tool. WebSearch arrives as a FETCH with no
        # url and the query as content; a secret typed into a search box
        # leaves the machine exactly as one typed into a URL does. docs/83.
        for text, within in ((action.url, "the URL"), (action.content, "the query")):
            if carries_secret(text, state):
                return "exact", _exact_source(text, state, within=within), enumerated
    if action.kind is ActionKind.TOOL:
        # The arguments, flattened by the adapter. Fingerprints only — NO
        # `derived` fallback: an MCP call made while holding secrets is not
        # inherently carrying them, and treating it as such would flag every
        # tool call after any credential read.
        if carries_secret(action.content, state):
            return "exact", _exact_source(action.content, state,
                                          within="the tool's arguments"), enumerated
        return ("derived", derived, enumerated) if derived is not None else (
            None, None, enumerated)

    if action.kind in (ActionKind.WRITE, ActionKind.EDIT):
        if carries_secret(action.content, state):
            return "exact", _exact_source(action.content, state,
                                          within="the written content"), enumerated
        # The PROSPECTIVE level. propagate() will mark this destination derived
        # under rule set B, but that runs after the verdict for this same
        # action (deliberately — see the module docstring). Reading the label
        # here would always miss by one step. What the action carries is what
        # the session holds.
        if state.holds_secret and derived is None:
            derived = {"level": "derived", "from_seq": state.holds_secret_since_seq}

    if derived is not None:
        return "derived", derived, enumerated
    return None, None, enumerated


def _secret_origin(state: SessionState) -> str:
    """Where the secret ENTERED the session — the fact a developer can act on.

    A path the engine already knows is a propagation DESTINATION is never the
    origin of anything: its bytes are there because we copied them, so naming it
    sends the developer to a consequence instead of a cause. A live run
    (session 4c5247e9) reported `debug/.env` for exactly that reason.

    This is the REPORTING half. mark_sources() no longer records copy
    destinations at all, which is the recording half; this filter also catches
    routes that one cannot — the live heredoc commit put `debug/.env` into the
    list via a `cat` that read no file, and its message mentioned the path in
    prose, so no amount of command segmentation would have helped.

    The most recent SURVIVING source still wins: a session that genuinely reads
    two different credentials should name the later one, not always the first.
    """
    genuine = [src for src in state.secret_sources
               if src["path"] not in state.tainted_paths]
    # Pathological case — every recorded source is also a destination. Naming
    # the least-bad path beats naming nothing; a reason with no origin is not
    # actionable, and being actionable is the whole purpose of the string.
    candidates = genuine or state.secret_sources
    if candidates:
        return _read_label(candidates[-1])
    # ⚠ NO READ IS RECORDED, SO NONE IS CLAIMED. This used to say "a credential
    # file read earlier in this session" — a read that never happened (item A,
    # docs/96). Callers that can say what they SAW do so before reaching here.
    return "a secret the session holds, with no credential read recorded"


_path_display = why_facts.path_display
"""A path as the developer spelled it (`core/why.py`, one definition)."""


def _what_was_seen(source: dict) -> str | None:
    """The one-clause answer to "what did this branch see?", or None when the
    source is provenance (a fingerprinted value traced to a recorded read)."""
    basis = source.get("basis")
    if basis == "credential_path":
        return f"this command names a credential path ({_path_display(source['path'])})"
    if basis == "tainted_path":
        return (f"this uses {_path_display(source['path'])}, which holds data copied "
                f"from a credential (labelled at step {source.get('from_seq')})")
    if basis == "tainted_var":
        return (f"this expands ${source['var']}, which was filled from a credential "
                f"file at step {source.get('var_seq')}")
    if basis == "environment":
        return "this sends the process environment, which can hold credentials"
    return None


# A home directory's own spelling, for matching the `/HOME` sentinel lexically.
_HOME_DIR = re.compile(r"/(?:Users|home)/[^/]+|/root|[A-Za-z]:/Users/[^/]+")


def _same_file(named: str, recorded: str) -> bool:
    """Do two spellings name the same file? Exact (a backslash and a slash are
    one separator, on either side), or `~` against its absolute form:
    `/HOME/<rest>` (the engine's sentinel) is the same file as
    `<a home directory>/<rest>`, and only that — `~/.env` is NOT
    `/work/repo/.env`. Lexical, no IO.

    ⚠ KNOWN LIMIT, ACCEPTED: any home-directory-SHAPED prefix matches
    (`/Users/<anyone>`, `/home/<anyone>`, `/root`, `<drive>:/Users/<anyone>`).
    The engine may not read `$HOME`, so it cannot check the prefix is THIS
    session's own home. Reason text only; no verdict depends on it.

    ⚠ CASE-SENSITIVE ON PURPOSE. `CREDENTIAL_PATHS` ignores case because it asks
    "is this credential-SHAPED?", where an under-match opens an exit. This asks
    "is it the SAME file?", where an under-match only falls back to the reason
    saying what was seen — true either way — and folding case would call two
    files one on a case-sensitive filesystem."""
    named, recorded = named.replace("\\", "/"), recorded.replace("\\", "/")
    if named == recorded:
        return True
    for sentinel, other in ((named, recorded), (recorded, named)):
        if not sentinel.startswith("/HOME/"):
            continue
        rest = sentinel[len("/HOME"):]
        if other.endswith(rest) and _HOME_DIR.fullmatch(other[:-len(rest)]):
            return True
    return False


def _read_label(src: dict) -> str:
    """One recorded read, as a reason names it. ⚠ Through `_path_display`: a read
    spelled with `~` is recorded under the internal `/HOME` sentinel, which must
    never reach a developer (see `_root_display`)."""
    return f"{_path_display(src['path'])} (read at step {src['seq']})"


def _shown_provenance(state: SessionState, source: dict) -> str | None:
    """The recorded read the engine can SHOW this finding came from, labelled,
    or None. Only then does the reason name a read (#63 review, docs/96):
      credential_path  the read OF THAT PATH — the matched one, never merely
                       the latest (a session can read two credentials)
      tainted_path     the i02 rule: a copy's reason names the ORIGINAL read,
                       never the copy, and `_secret_origin` picks it
      tainted_var      none — which file filled the variable is not recorded
      environment      none — the environment is not read from a file
    """
    if not state.secret_sources:
        return None
    basis = source.get("basis")
    if basis == "credential_path":
        matched = [src for src in state.secret_sources
                   if _same_file(source["path"], src["path"])]
        return _read_label(matched[-1]) if matched else None
    if basis == "tainted_path":
        return _secret_origin(state)
    return None


def _exact_reason(state: SessionState, source: dict | None) -> str:
    """Provenance names where the secret CAME FROM; a format hit names WHAT IT
    IS. Both can be true at once, and then the reason says both. Neither ever
    contains the value: one is a path and a step, the other a vendor's name
    for a shape (core/known_formats.py `Format.name`).

    ⚠ NEVER INVENT OR BORROW A READ (item A and its #63-review follow-up, docs/96). A
    branch that fired on something else — a credential path in the command, a
    tainted path or variable, the environment — says WHAT IT SAW (`basis`),
    unless a recorded read is shown to be its source; then the provenance
    reason is byte-identical to before, naming the ORIGINAL read, never a copy
    (the i02 and heredoc tests guard that)."""
    source = source or {}
    fmt = source.get("format")
    if not fmt:
        seen = _what_was_seen(source)
        if not seen:
            return f"this carries data traced from {_secret_origin(state)}"
        origin = _shown_provenance(state, source)
        return f"this carries data traced from {origin}" if origin else seen
    reason = f"this carries {fmt}, recognised by its documented format"
    if state.secret_sources:
        reason += f"; the session also read {_secret_origin(state)}"
    return reason


def _held_secret_clause(state: SessionState) -> str:
    """Why this session counts as holding a secret, for an ASK reason."""
    if state.secret_sources:
        return f"this session read {_secret_origin(state)}"
    if state.schema_skew:
        return ("this session's saved state could not be read completely, so it "
                "is treated as holding a secret")
    return "this session is marked as holding a secret, with no credential read recorded"


def _untrusted_origin(state: SessionState) -> str:
    if state.untrusted_sources:
        src = state.untrusted_sources[-1]
        if src.get("kind") == "git-history-unreadable":
            # ⚠ SAY THAT THE EVIDENCE IS WEAK RATHER THAN STATING IT AS FACT.
            # The command could not be parsed, so "git log ran" is the safe
            # assumption and not an observation — and a sticky mark made on an
            # assumption should say so every time it is cited.
            return (f"{src['ref']} (step {src['seq']}) — the command could not "
                     f"be parsed, so this may be quoted text rather than a "
                     f"history read")
        return f"{src['ref']} (step {src['seq']})"
    return f"untrusted content (step {state.untrusted_since_seq})"


# ──────────────────────────────────────── the facts only this ladder knows
#
# docs/108 §4. Each field is set only where the ladder KNOWS it; the gaps that
# table lists stay None: which read a fingerprint came from when the session
# made more than one, which file filled a variable, the position of anything but
# a known-format hit.

_BASIS_TYPES = {"tainted_path": why_facts.COPIED,
                "credential_path": why_facts.CREDENTIAL_FILE,
                "tainted_var": why_facts.FILLED,
                "environment": why_facts.ENVIRONMENT}


def _read_step(state: SessionState, path: str) -> int | None:
    """The step a recorded read of exactly this file happened at, or None."""
    matched = [src for src in state.secret_sources if _same_file(path, src["path"])]
    return matched[-1]["seq"] if matched else None


def _only(sources: list[dict]) -> tuple[str | None, int | None]:
    """The source when there is exactly one; which of several is not recorded."""
    return (sources[0]["path"], sources[0]["seq"]) if len(sources) == 1 else (None, None)


def _why_source(state: SessionState, source: dict) -> tuple[str | None, int | None]:
    basis = source.get("basis")
    if source.get("format") or basis == "environment":
        return None, None                  # recognised by shape, or no read at all
    if basis == "tainted_path":            # a copy: its original read, if one
        return _only([src for src in state.secret_sources
                      if src["path"] not in state.tainted_paths])
    if basis == "tainted_var":             # the step is kept; the file is not
        return None, source.get("var_seq")
    if source.get("path"):                 # a credential path, named or staged
        return source["path"], _read_step(state, source["path"])
    return _only([src for src in state.secret_sources if src.get("how") == "content"])


def _why_location(source: dict) -> str | None:
    if source.get("offset") is not None:
        staged_at = source.get("staged_at")
        if staged_at:
            return f"the staged file {staged_at[0]}, line {staged_at[1]}"
        if source.get("within"):
            return f"offset {source['offset']} in {source['within']}"
        return None
    if source.get("basis") in ("tainted_path", "credential_path"):
        return f"the file {_path_display(source['path'])}"
    if source.get("path") and not source.get("basis"):
        return f"the staged file {_path_display(source['path'])}"
    return None


def why_of_secret(state: SessionState, source: dict | None, action: Action) -> Why:
    """What a `secret_exact` verdict knows: the value's type, where it came from
    and where it sits. A known-format key written into a command also carries
    the environment remedy, which `why.completed` keeps only for a host the
    guard recognises."""
    source = source or {}
    value_type = (source.get("format") or _BASIS_TYPES.get(source.get("basis"))
                  or (why_facts.CREDENTIAL_FILE if source.get("path") else why_facts.READ_VALUE))
    source_file, source_step = _why_source(state, source)
    remedy = ("environment" if source.get("format") and source.get("within") == "the command"
              and action.kind is ActionKind.EXEC else None)
    return Why(source_file=source_file, source_step=source_step,
               location=_why_location(source), value_type=value_type, remedy=remedy)


def why_of_derived(state: SessionState) -> Why:
    """What a write made while holding a secret knows: the step the session
    first held one, and the file read at that step."""
    step = state.holds_secret_since_seq
    at_step = [src for src in state.secret_sources if src["seq"] == step]
    return Why(source_file=at_step[0]["path"] if len(at_step) == 1 else None,
               source_step=step, value_type=why_facts.DERIVED)


def why_of_held(state: SessionState) -> Why:
    """What `secret_session_unverified` turned on: the read its reason names
    (`_held_secret_clause` → `_secret_origin`). Not a traced value: the rule
    asks precisely because it could not see what is sent."""
    genuine = [src for src in state.secret_sources if src["path"] not in state.tainted_paths]
    candidates = genuine or state.secret_sources
    if not candidates:
        return Why()
    return Why(source_file=candidates[-1]["path"], source_step=candidates[-1]["seq"])
