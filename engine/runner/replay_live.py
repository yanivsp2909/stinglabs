#!/usr/bin/env python3
"""Differential replay of real decision logs. $0, no agent, no network.

    python3 runner/replay_live.py                # $STING_SESSION_ROOT
    python3 runner/replay_live.py --root logs/live-fixture
    python3 runner/replay_live.py --update-baseline         # accept differences

WHAT THIS ASSERTS, AND WHAT IT CANNOT.

**Not "was the verdict right".** The recorded verdict came from an older engine,
so treating it as ground truth would pin today's engine to yesterday's bugs,
including the ones since fixed. A decision log contains no oracle.

The property is a DIFFERENTIAL:

    For every recorded action whose inputs are fully recoverable, the current
    engine reaches the same (decision, rule_id) it reached when the action was
    recorded — or the difference is listed in runner/live_baseline.json with a
    written reason.

Its value is not correctness. It is that **a verdict change on a real,
structurally-rich action becomes visible**, which the synthetic corpus
structurally cannot produce: 0% of corpus commands contain any shell structure
against 100% of live ones, and the corpus median trace is 2 actions against 120.

SESSION ORDER IS MANDATORY. A verdict depends on session history, so each session
replays in `seq` order with mark_sources and propagate rebuilding state between
actions. Judging actions independently would evaluate every action after the
first against the wrong state — which would make every difference meaningless.

WHAT THE LOG CANNOT REPRODUCE. Only REPLAYABLE actions are compared; the rest are
counted and reported, never silently passed. A differential that quietly skips
what it cannot do is how a green suite comes to mean nothing.

    REPLAYABLE       EXEC/READ/TOOL with its command or paths intact
    NO_CONTENT       WRITE/EDIT — `content` is not in the record, so
                     carries_secret() and weakens_security() cannot be re-run.
                     INHERENT, not a defect: content can be large and can BE the
                     secret, so logging it is not the fix.
    TRUNCATED        command clipped and the sidecar cannot recover it
    ASSUMED_CWD      pre-dates `cwd` in the record. COMPARED, but counted
                     separately, because a relative path resolves against a cwd
                     that is assumed rather than recorded. Excluding these would
                     answer nothing — they are 213 of 271 records — and 92.8% of
                     live commands begin `cd <root> &&`, so the supplied --cwd is
                     almost certainly the right one. The caveat travels with the
                     number instead of hiding it.

DETERMINISM. The default world answers nothing, so a run does not depend on the
machine's current git index or filesystem. `--world real` is available for
investigation and makes the run non-reproducible by design.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import audit_log, engine                                   # noqa: E402
from core.types import Action, ActionKind, SessionState              # noqa: E402
# ONE definition of "identity" in this repo, deliberately imported rather than
# restated. The baseline is written from the SAME real logs the fixture is built
# from, so any second copy of the substitution list would drift and the drift
# would be invisible until it shipped. See `_redact_excerpt`.
from tools.redact_logs import leaks_in, redact                       # noqa: E402

ROOT = Path(__file__).parent.parent
BASELINE = ROOT / "runner" / "live_baseline.json"
# ⚠ THE REAL SESSION ROOT, AND IT USED TO BE `~/.sting/dogfood`. That directory
# emptied when the logs moved to `~/.sting/sessions`, and this tool went on
# printing "No unexplained differences" over ZERO records — a gate that could
# not fail, pinned as "standing replay green" in every checkpoint since.
# Working rule 13 aimed at the checkpoint itself.
#
# STING_SESSION_ROOT first: that is the variable the hook writes to and the one
# an installed machine sets, so this follows the logs instead of guessing at a
# path that was true once.
DEFAULT_LOG_ROOT = Path(
    os.environ.get("STING_SESSION_ROOT") or "~/.sting/sessions").expanduser()

# The smallest population this tool will report a verdict over. One is enough
# to make the result non-vacuous; the number exists so the check is a stated
# threshold rather than an implicit `> 0` somebody can argue with.
MIN_COMPARISONS = 1

REPLAYABLE = "REPLAYABLE"
NO_CONTENT = "NO_CONTENT"
TRUNCATED = "TRUNCATED"
ASSUMED_CWD = "ASSUMED_CWD"
STATE_DIVERGED = "STATE_DIVERGED"


def state_implied_by(rule_id: str | None) -> tuple[bool, bool]:
    """(untrusted, holds_secret) that the recorded rule_id PROVES were set.

    THE KEY TRICK, and it is what makes the differential mean anything. The log
    does not record session state — only the verdict. But a rule id names the
    branch that fired, and those branches are gated: `untrusted_*` cannot fire
    unless `state.untrusted` was True, and `secret_*` cannot fire unless the
    session held secrets. So the recorded rule is a WITNESS to the state at record
    time.

    That lets a difference be attributed. If the recorded rule proves the session
    was untrusted and the replay did not reconstruct that, the divergence is a
    REPLAY FIDELITY gap — missing content, an unrecorded tool name, a file the
    NeutralWorld cannot read — and not a policy change. Reporting those as
    regressions would bury the handful of real ones.
    """
    if not rule_id:
        return False, False
    head, _, sink = rule_id.partition(":")
    untrusted = head.startswith("untrusted")
    # THE SINK IS A WITNESS TOO, and leaving it out mis-attributed 13 differences.
    # These three sinks are gated on holds_secret inside check_sinks, so their
    # presence in a rule id proves the session held secrets — regardless of what
    # the ladder branch was called. Without this, an MCP call recorded as
    # `untrusted_unexpected:mcp_tool_call` looked like a policy change when the
    # replay simply never reconstructed the secret.
    secret = head.startswith("secret") or sink in (
        "mcp_tool_call", "unknown_tool_call", "security_critical")
    return untrusted, secret


class NeutralWorld:
    """Answers nothing, so a replay is reproducible on any machine.

    `staged_files` returning None is "could not inspect" rather than "inspected
    and empty" — the distinction core/engine.py depends on. That means
    index-inspecting verdicts resolve through the unverified branch, which is the
    honest answer when the index of that moment is gone.
    """

    def read_text(self, path): return None
    def staged_files(self, cwd): return None
    def staged_content(self, cwd): return None
    def is_dirty(self, cwd): return True
    def remotes(self, cwd): return ()
    def branch(self, cwd): return "main"
    def project_roots(self, cwd): return (cwd,), ""


def load_records(root: Path) -> dict[str, list[dict]]:
    """Every decision record, grouped by session, in seq order."""
    sessions: dict[str, list[dict]] = {}
    for path in sorted(root.rglob("*.jsonl")) + sorted(root.rglob("*.log")):
        for line in path.open(errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event") != "decision":
                continue
            record["_log_path"] = str(path)
            sessions.setdefault(record.get("session_id") or path.name, []).append(record)
    for records in sessions.values():
        records.sort(key=lambda r: (r.get("seq") or 0, r.get("ts") or 0))
    return sessions


def classify(record: dict, log_path: Path) -> tuple[str, str | None]:
    """(class, command). The command is recovered from the sidecar when clipped."""
    kind = record.get("kind")
    if kind in ("WRITE", "EDIT"):
        return NO_CONTENT, record.get("command")
    command = record.get("command")
    # WHOLENESS IS `audit_log.stored_command_is_whole`, AND NOWHERE ELSE. This
    # used to carry its own three-branch ladder — flag, then marker, then bare
    # length — while `load_full_command` tested only the flag. The two disagreed
    # about nine real records, and the other one answered WRONGLY rather than not
    # at all. One predicate, two callers; the order lives in that function.
    #
    # WHY THIS MATTERS FAR MORE THAN IT LOOKS. A clipped command loses its
    # heredoc terminator, `shell_scan` cannot close the heredoc, and it fails SAFE
    # to all-code — so every `git push` and `curl … | bash` written INTO a test
    # file reads as a command being run. Ten of seventeen untrusted denials in the
    # enforce measurement were exactly that, and 92 of the 93 parse failures
    # across the fixture are this and nothing else. They are artifacts of the
    # RECORD, not of the engine: clipping happens when the log body is built, and
    # the verdict was already made — live, the engine saw the whole command.
    #
    # Without this the differential compares records whose input it does not have,
    # and reports the resulting nonsense as policy behaviour.
    # ⚠ ONE READER, IN audit_log. Restoration is a property of READING THE LOG,
    # not of this analysis — an audit that re-implemented it read the raw field
    # and concluded 15.4% of real commands are unparseable, when the true figure
    # on complete text is 0. `command_for` is the only sanctioned way to ask a
    # record what command it was judged on.
    command, whole = audit_log.command_for(record, log_path)
    if isinstance(command, str) and not whole:
        return TRUNCATED, command
    if not record.get("cwd"):
        return ASSUMED_CWD, command
    return REPLAYABLE, command


def action_from(record: dict, command: str | None, cwd: str) -> Action:
    kind = record.get("kind") or "EXEC"
    try:
        action_kind = ActionKind[kind]
    except KeyError:
        action_kind = ActionKind.TOOL
    return Action(
        session_id=record.get("session_id") or "replay",
        seq=record.get("seq") or 0,
        kind=action_kind,
        paths=tuple(record.get("paths") or ()),
        command=command,
        url=record.get("url"),
        tool_name=record.get("tool_name"),
        content=None,                       # never in the record; see NO_CONTENT
        cwd=record.get("cwd") or cwd,
        # RECORDED ROOTS WIN. Deriving them from cwd is what made 4 in-project
        # writes look like `write_outside` — the record's cwd is the shell's
        # directory, which is not necessarily the project.
        workspace_roots=(tuple(record.get("workspace_roots") or ())
                          or (record.get("cwd") or cwd,)),
        # RECORDED, then the old assumption as a fallback. This was hardcoded
        # `"claude-code"` because the record could not say — which was true of
        # every record written before the field existed and false the moment a
        # second agent appears. It cannot change a verdict either way (no rule
        # reads `agent`); what it changes is whether a replay of a Cursor session
        # can honestly say whose session it was.
        agent=record.get("agent") or "claude-code")


def replay(roots: list[Path], cwd: str,
            scratch: list[str] | None = None) -> dict:
    """Returns {'compared', 'same', 'diffs', 'skipped', 'sessions'}."""
    world = NeutralWorld()
    # DE-DUPLICATE ACROSS ROOTS, BY (session, seq).
    #
    # A session can appear in more than one root — a live log in ~/.sting/dogfood
    # and an archived copy of the SAME session under sting-logs-archive. Merging
    # them naively replays the overlapping actions twice, which does not merely
    # inflate the counts: `mark_sources` and `propagate` run again, so the session
    # carries taint from actions that happened once, and every later verdict is
    # judged against a session that never existed.
    #
    # Measured when this was found: 1f089cfa had 22 records in one root and 485 in
    # the other, 22 seqs overlapping — and the duplicate replay turned 10 recorded
    # denials into 82. The longer record wins, since an archived copy is usually
    # the complete one and the live file the truncated tail.
    sessions: dict[str, dict[tuple, dict]] = {}
    for one in roots:
        for sid, recs in load_records(one).items():
            bucket = sessions.setdefault(sid, {})
            for record in recs:
                key = (record.get("seq"), record.get("event"))
                previous = bucket.get(key)
                if previous is None or len(str(record.get("command") or "")) > len(
                        str(previous.get("command") or "")):
                    bucket[key] = record
    sessions = {sid: sorted(b.values(), key=lambda r: (r.get("seq") or 0,
                                                        r.get("ts") or 0))
                 for sid, b in sessions.items()}
    out = {"compared": 0, "same": 0, "diffs": [], "skipped": Counter(),
            "sessions": len(sessions), "records": 0,
            "assumed": 0, "assumed_same": 0,
            # ⚠ WHICH SESSIONS THIS RUN ACTUALLY OPENED, AND WHICH RECORDS
            # REACHED A COMPARISON. Without these, a baseline entry for a
            # session the run never scanned is indistinguishable from one whose
            # difference has genuinely been fixed — and the report called both
            # "no longer differ". See `main`, and the note on `--prune-stale`.
            "session_ids": set(sessions),
            "compared_keys": set()}

    for session_id, records in sessions.items():
        state = SessionState(session_id=session_id)
        state.cwd = cwd
        state.workspace_roots = [cwd]
        state.scratch_roots = list(scratch or [])
        for record in records:
            out["records"] += 1
            log_path = Path(record["_log_path"])
            klass, command = classify(record, log_path)
            action = action_from(record, command, cwd)
            state.seq = record.get("seq") or (state.seq + 1)
            if not state.workspace_roots:
                state.workspace_roots = [action.cwd]

            # The verdict is computed for EVERY record, replayable or not, because
            # labelling must still advance the session state — skipping an action
            # entirely would leave every later verdict judged against a session
            # that never happened.
            # ⚠ A RECORD THE DIFFERENTIAL REFUSES TO JUDGE STILL SHAPES EVERY
            # LATER ONE. `decide()` runs on every record, TRUNCATED included,
            # because skipping it would judge later verdicts against a session
            # that never happened. But a truncated command is a PREFIX, and
            # letting the engine derive structure from it does not preserve
            # fidelity — it manufactures state the live engine never had.
            #
            # Measured on 83aea8bb:117, a clipped record with no sidecar whose
            # commit message describes `_copy_pairs` test cases: with it
            # advancing state, 0 of the 6 records it poisons matched the live
            # recording; with its structure suppressed, 4 of 6 did. `command`
            # here may already be a sidecar or transcript recovery, so wholeness
            # is asked of the RECORD, and only a still-truncated one is capped.
            verdict = engine.decide(action, state, world,
                                     text_complete=(klass != TRUNCATED))

            if klass in (NO_CONTENT, TRUNCATED):
                out["skipped"][klass] += 1
                continue
            # STATE WITNESS. Checked before comparing, because a verdict reached
            # from a different session state is not evidence about policy.
            want_untrusted, want_secret = state_implied_by(record.get("rule_id"))
            if ((want_untrusted and not state.untrusted)
                    or (want_secret and not state.holds_secret)):
                out["skipped"][STATE_DIVERGED] += 1
                continue
            assumed = klass == ASSUMED_CWD
            if assumed:
                out["assumed"] += 1
            else:
                out["compared"] += 1
            out["compared_keys"].add(f"{session_id}:{record.get('seq')}")
            recorded = (str(record.get("decision") or "").upper(),
                        record.get("rule_id"))
            current = (str(verdict.decision).upper(), verdict.rule_id)
            if recorded == current:
                out["assumed_same" if assumed else "same"] += 1
            else:
                out["diffs"].append({
                    "key": f"{session_id}:{record.get('seq')}",
                    "kind": record.get("kind"),
                    "assumed_cwd": assumed,
                    # ⚠ REDACT BEFORE TRUNCATING, NOT AFTER. This excerpt is
                    # written verbatim into runner/live_baseline.json, which is
                    # TRACKED — it held the developer's home directory, name and
                    # email in 32 of 43 entries because it was built straight
                    # from the real logs and never passed through the redaction
                    # the fixture beside it gets.
                    #
                    # The order is the load-bearing part: truncating first can
                    # cut a token in half at byte 160 (`…/Users/ali`), and a
                    # half token matches no pattern while still identifying the
                    # person. Redacting the whole command first means the slice
                    # can only ever contain already-redacted text.
                    "command": redact(command or "")[:160],
                    "recorded": {"decision": recorded[0], "rule_id": recorded[1]},
                    "current": {"decision": current[0], "rule_id": current[1]}})
    return out


def _is_loosening(diff: dict) -> bool:
    """Was DENY or ASK, is now ALLOW. The one direction that is never a
    judgement call — see the refusal in main()."""
    # ⚠ `.get`, BECAUSE 15 COMMITTED ENTRIES HAVE NO `recorded` FIELD AT ALL —
    # an older baseline format that stored only the CURRENT verdict. Their
    # direction is unknowable, and unknowable is not the same as safe: they are
    # reported separately by `undirected()` rather than silently counted clean.
    was = str((diff.get("recorded") or {}).get("decision") or "").upper()
    now = str((diff.get("current") or {}).get("decision") or "").upper()
    return was in ("DENY", "ASK") and now == "ALLOW"


def undirected(entry: dict) -> bool:
    """No `recorded` verdict, so nothing can be said about the direction."""
    return not (entry.get("recorded") or {}).get("decision")


def load_baseline() -> dict:
    if not BASELINE.exists():
        return {"accepted": {}}
    return json.loads(BASELINE.read_text())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, action="append", default=None,
                     help="log directory; repeatable")
    # ⚠ DEFAULTS FROM THE ENVIRONMENT, for the same reason --root does. The
    # scratch roots are declared via STING_SCRATCH at RECORD time and are NOT in
    # the record, so a scratchpad exemption cannot be reproduced without them —
    # and every unsupplied one shows up as an UNEXPLAINED difference that is
    # really just a missing input. Measured: 2 false alarms on this developer's
    # own session within an hour of the gate starting to work.
    ap.add_argument("--scratch", default=os.environ.get("STING_SCRATCH", ""),
                     help="colon-separated scratch roots; "
                     "declared via STING_SCRATCH at record time and NOT in the "
                     "record, so a scratchpad exemption cannot be reproduced "
                     "without being supplied here")
    ap.add_argument("--cwd", default=str(ROOT),
                     help="cwd for records that pre-date the cwd field")
    ap.add_argument("--update-baseline", action="store_true",
                     help="write the current differences as accepted (write a "
                          "reason for each afterwards — an unexplained baseline "
                          "entry is a regression nobody looked at)")
    ap.add_argument("--accept-loosening", action="store_true",
                     help="allow --update-baseline to record a NEW DENY/ASK -> "
                          "ALLOW difference. Deliberate false-positive fixes are "
                          "legitimate; drift you did not intend is a regression, "
                          "and only one of them is worth typing this flag for")
    ap.add_argument("--prune-stale", action="store_true",
                     help="with --update-baseline, DROP entries not seen in "
                          "this run AND compared by it. Off by default: this "
                          "file serves more than one log root, and one root's "
                          "run cannot tell a resolved difference from an "
                          "unscanned population. It will NOT drop an entry "
                          "whose session this run never opened.")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    roots = args.root or [DEFAULT_LOG_ROOT]
    roots = [r for r in roots if r.is_dir()]
    if not roots:
        print(f"No logs under {args.root or DEFAULT_LOG_ROOT}", file=sys.stderr)
        return 2

    scratch_roots = [d for d in args.scratch.split(':') if d]
    result = replay(roots, args.cwd, scratch_roots)
    baseline = load_baseline()
    accepted = baseline.get("accepted", {})

    unexplained = [d for d in result["diffs"] if d["key"] not in accepted]
    explained = [d for d in result["diffs"] if d["key"] in accepted]
    stale = [k for k in accepted if k not in {d["key"] for d in result["diffs"]}]

    # ⚠ NAME THE CONFIGURATION NEXT TO THE COUNT, OR THE COUNT IS A TRAP.
    # This is the A4 shape: two roots, two numbers, nothing saying which is
    # which. The committed baseline is AUTHORED AGAINST ONE POPULATION
    # (logs/live-fixture); pointed at a different root, its accepted-set does
    # not cover those sessions, and a session recorded AFTER the baseline was
    # written — the currently-running one, say — CANNOT be in it, so every one
    # of its differences prints as UNEXPLAINED. That is not a regression signal;
    # it is a run against a root the baseline never reviewed.
    #
    # So partition the unexplained by whether the baseline has EVER seen the
    # session: a difference in a reviewed session is a candidate regression a
    # human must judge; a difference in a session with no baseline entry at all
    # is un-reviewed drift on a foreign root. Reporting only — the exit code
    # still fails on ANY unexplained, so this cannot hide a real regression, it
    # only stops a legible count from masquerading as a finding.
    baseline_session_ids = {k.rsplit(":", 1)[0] for k in accepted}
    unexplained_reviewed = [d for d in unexplained
                            if d["key"].rsplit(":", 1)[0] in baseline_session_ids]
    unexplained_unseen = [d for d in unexplained
                          if d["key"].rsplit(":", 1)[0] not in baseline_session_ids]
    run_sessions_unbaselined = sorted(result["session_ids"] - baseline_session_ids)

    print(f"=== LIVE DIFFERENTIAL REPLAY — {', '.join(str(r) for r in roots)}")
    print(f"    {result['sessions']} sessions, {result['records']} records, $0.00\n")
    print(f"  compared, cwd RECORDED  {result['compared']}")
    print(f"    decided the same      {result['same']}")
    print(f"  compared, cwd ASSUMED   {result['assumed']}   "
          f"(pre-date the cwd field; --cwd {args.cwd})")
    print(f"    decided the same      {result['assumed_same']}")
    print(f"  decided DIFFERENTLY     {len(result['diffs'])}")
    print(f"      explained in baseline {len(explained)}")
    print(f"      UNEXPLAINED           {len(unexplained)}")
    if unexplained:
        print(f"        in a baseline-reviewed session  {len(unexplained_reviewed)}"
              f"  (candidate regressions — judge each)")
        print(f"        in a session the baseline never saw  {len(unexplained_unseen)}"
              f"  (un-reviewed drift, not a regression signal)")
    print(f"  not comparable          {sum(result['skipped'].values())}")
    print(f"  baseline: {BASELINE.name}, {len(accepted)} accepted entries over "
          f"{len(baseline_session_ids)} session(s)")
    if run_sessions_unbaselined:
        shown = ', '.join(s[:8] for s in run_sessions_unbaselined[:6])
        print(f"  ⚠ {len(run_sessions_unbaselined)} of this run's sessions have NO "
              f"baseline entry — this root is not the one the baseline was authored "
              f"against.\n    {shown}{' …' if len(run_sessions_unbaselined) > 6 else ''}")
    for klass, count in sorted(result["skipped"].items()):
        print(f"    {klass:<14} {count}")

    # ⚠ AN EMPTY POPULATION IS A FAILURE, NOT A PASS. "No unexplained
    # differences" over zero comparisons is not a green gate, it is an absent
    # one — and this tool printed exactly that for as long as the default root
    # was empty. The check is on COMPARISONS rather than on sessions or files,
    # because a root full of logs none of which are replayable is the same
    # vacuum wearing a better disguise.
    population = result["compared"] + result["assumed"]
    if population < MIN_COMPARISONS:
        print(f"\n⚠ REFUSING TO REPORT: {population} comparable action(s) in "
              f"{', '.join(str(r) for r in roots)} (need >= {MIN_COMPARISONS}).\n"
              f"  A green result over an empty population is a gate that cannot "
              f"fail.\n  Point --root at a directory with real decision logs, or "
              f"set STING_SESSION_ROOT.", file=sys.stderr)
        return 2

    if not args.quiet and result["diffs"]:
        print(f"\n  differences:")
        for d in result["diffs"]:
            mark = "expected" if d["key"] in accepted else "UNEXPLAINED"
            mark += ", assumed cwd" if d.get("assumed_cwd") else ""
            print(f"    [{mark}] {d['key']}  "
                  f"{d['recorded']['decision']}/{d['recorded']['rule_id']} -> "
                  f"{d['current']['decision']}/{d['current']['rule_id']}")
            print(f"       {d['command'][:120]!r}")
            if d["key"] in accepted:
                print(f"       reason: {accepted[d['key']].get('reason', '(none given)')}")

    # ⚠ "STALE" WAS THREE DIFFERENT THINGS WEARING ONE WORD, AND ONLY ONE OF
    # THEM IS A RESOLVED DIFFERENCE.
    #
    # This line used to print "N baseline entries no longer differ" for every
    # accepted key absent from this run's diffs. Measured against the committed
    # baseline on this machine: of 84 such keys, **ZERO** had been resolved by a
    # change to the engine.
    #
    #   77  UNSCANNED   two session ids the run never opened — they were
    #                   recorded on another machine, under /Users/dev. A key
    #                   whose log was not read has not been judged.
    #    7  RESOLVED    compared, and agreeing — but ⚠ ONLY BECAUSE OF AN
    #                   ARGUMENT, NOT BECAUSE OF A CODE CHANGE. All seven are
    #                   `irreversible_action` ASKs under `/private/tmp/claude-000`.
    #                   With STING_SCRATCH set they agree and 0 are unexplained;
    #                   with it UNSET the same run reports 77 stale, 28
    #                   differences and 11 UNEXPLAINED. "Resolved" here is a
    #                   property of how the tool was invoked.
    #
    # So the honest count of entries fixed by a change to the engine is ZERO,
    # and nothing in this baseline should be dropped.
    #
    # Printing 84 under a word that means "fixed" is an invitation to prune, and
    # a bulk prune is how this file lost 77 entries once already. The three are
    # now counted separately and named for what they are.
    unscanned = [k for k in stale
                 if k.rsplit(":", 1)[0] not in result["session_ids"]]
    resolved = [k for k in stale if k in result["compared_keys"]]
    unjudged = [k for k in stale
                if k not in unscanned and k not in resolved]

    if stale:
        print(f"\n  baseline entries not among this run's differences: {len(stale)}")
        print(f"    RESOLVED   {len(resolved):4}  compared, and now agree — "
              f"these are the only ones a prune may drop")
        print(f"    UNSCANNED  {len(unscanned):4}  their session was never "
              f"opened by this run. NOT resolved.")
        print(f"    UNJUDGED   {len(unjudged):4}  their session was scanned but "
              f"the record reached no comparison")
        if unjudged and not scratch_roots:
            print(f"    ⚠ STING_SCRATCH is unset, which moves this count on its "
                  f"own. Set it before reading these.")
        for label, keys in (("RESOLVED", resolved), ("UNSCANNED", unscanned),
                            ("UNJUDGED", unjudged)):
            if keys:
                print(f"    {label}: {', '.join(sorted(keys)[:4])}"
                      f"{' …' if len(keys) > 4 else ''}")

    # ⚠ A LOOSENING MUST BE ACKNOWLEDGED, NOT FORBIDDEN — and the first version
    # of this code forbade it, which was wrong. Measured against the committed
    # baseline: 42 of 86 accepted entries ARE loosenings, and every one is a
    # deliberate false-positive fix citing the commit that made it. `fb071e3`
    # narrowed _GUARD_SELFMOD from a bare `sting` substring that matched 188 of
    # 190 real paths; refusing that would have pinned the engine to a bug.
    #
    # What is true is the weaker, useful claim: a loosening is the direction in
    # which a REGRESSION hides, so it may not be accepted by accident. Writing
    # a new one takes --accept-loosening, and the existing count is pinned by a
    # test so it cannot grow quietly.
    loosened = [d for d in result["diffs"] if _is_loosening(d)]
    if loosened and not args.quiet:
        print(f"\n  ⚠ {len(loosened)} difference(s) are a LOOSENING "
              f"(was DENY/ASK, now ALLOW) — these may not be baselined:")
        for d in loosened:
            print(f"    {d['key']}  {d['recorded']['decision']} -> "
                  f"{d['current']['decision']}")

    if args.update_baseline:
        new_loosenings = [d for d in loosened if d["key"] not in accepted]
        if new_loosenings and not args.accept_loosening:
            print(f"\n  REFUSING TO WRITE {BASELINE.name} — "
                  f"{len(new_loosenings)} NEW difference(s) are a loosening "
                  f"(was DENY/ASK, now ALLOW). That is the direction a "
                  f"regression hides in.\n  If each is a deliberate "
                  f"false-positive fix, re-run with --accept-loosening and "
                  f"write the commit that made it into every reason.",
                  file=sys.stderr)
            return 1
        # ⚠ MERGE, NEVER REPLACE — AND THIS COST 77 ENTRIES ONCE. This file
        # serves MORE THAN ONE population: the vendored `logs/live-fixture`
        # that gates CI, and whatever live root a developer points at. A run
        # against one root sees the other's entries as "stale", and replacing
        # the dict deleted every fixture entry — turning the CI gate red for a
        # reason that had nothing to do with the engine.
        #
        # Stale entries are REPORTED and kept. Removing one is a deliberate act
        # (`--prune-stale`), because "I did not scan that root today" and "that
        # difference is gone" are different facts and only one of them is a
        # reason to forget an explanation somebody wrote.
        # ⚠ AND `--prune-stale` USED TO BE THAT REPLACEMENT WEARING A FLAG.
        # It set `accepted = {}` and rebuilt from this run's diffs, so it
        # dropped UNSCANNED entries — the exact 77 the paragraph above is about
        # — while its help text promised only to drop entries "not seen in this
        # run". Those are different sets, and the difference is the whole bug.
        #
        # It now removes ONLY entries this run actually compared and found
        # agreeing. An entry whose session was never opened cannot be pruned by
        # a run that did not look at it, whatever flag is passed.
        accepted = dict(accepted)
        if args.prune_stale:
            for key in resolved:
                accepted.pop(key, None)
            print(f"\n  --prune-stale: dropped {len(resolved)} RESOLVED "
                  f"entr{'y' if len(resolved) == 1 else 'ies'}; kept "
                  f"{len(unscanned)} UNSCANNED and {len(unjudged)} UNJUDGED, "
                  f"which this run is not entitled to judge.")
        for d in result["diffs"]:
            accepted.setdefault(d["key"], {
                "recorded": d["recorded"], "current": d["current"],
                "command": d["command"], "reason": "TODO: explain"})
        payload = json.dumps({"accepted": accepted}, indent=2, sort_keys=True) + "\n"
        # THE SAME CHECK THE FIXTURE GETS, ON THE SAME PATTERNS. Redaction above
        # is the fix; this is the proof it worked. A tracked artifact built from
        # real logs must never be written on the strength of "the substitution
        # should have caught it" — that assumption is exactly what put 115
        # occurrences of the username into the fixture and 32 entries' worth
        # into this file.
        survived = leaks_in(payload)
        if survived:
            print(f"\n  REFUSING TO WRITE {BASELINE.name} — identity survived "
                  f"redaction: {', '.join(survived)}", file=sys.stderr)
            return 1
        BASELINE.write_text(payload)
        print(f"\n  wrote {len(accepted)} entries to {BASELINE} (redacted, checked)")
        print( "  ⚠ every reason says TODO. An unexplained baseline entry is a "
               "regression nobody looked at.")
        return 0

    if unexplained:
        print(f"\n{len(unexplained)} unexplained difference(s) against {BASELINE.name}"
              f" — {len(unexplained_reviewed)} in baseline-reviewed session(s), "
              f"{len(unexplained_unseen)} in session(s) the baseline never saw.")
        if unexplained_reviewed:
            print(f"  The {len(unexplained_reviewed)} in a reviewed session is each "
                  f"either a regression or needs a reason in {BASELINE.name}.")
        if unexplained_unseen and not unexplained_reviewed:
            print(f"  All {len(unexplained_unseen)} are on a root the baseline was "
                  f"not authored against — an un-reviewed queue, not a regression "
                  f"verdict. Run against logs/live-fixture for the standing gate.")
        return 1
    print(f"\nNo unexplained differences.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
