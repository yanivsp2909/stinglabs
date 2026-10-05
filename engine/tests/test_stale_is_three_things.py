"""A baseline entry missing from a run's differences is not "resolved".

⚠ THE REPORT SAID "84 baseline entries no longer differ (stale)". Measured on
this machine, the honest count of entries a code change had resolved was ZERO:

    77  UNSCANNED  two session ids the run never opened — recorded on another
                   machine, under /Users/dev. A key whose log was not read has
                   not been judged.
     7  RESOLVED   compared and agreeing — but only because STING_SCRATCH was
                   set. The same run with it UNSET reports 77 stale, 28
                   differences and 11 UNEXPLAINED. Every one is an
                   `irreversible_action` ASK under `/private/tmp/claude-000`.
     0              fixed by a change to the engine.

"Stale" invites a prune, and `--prune-stale` rebuilt the dict from this run's
diffs — so it dropped UNSCANNED entries, which is how this file lost 77 once
already. Its help text promised to drop entries "not seen in this run"; those
are different sets, and the difference was the bug.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _log(path, session, records):
    with open(path, "w", encoding="utf-8") as handle:
        for seq, (command, decision, rule) in enumerate(records, start=1):
            handle.write(json.dumps({
                "event": "decision", "session_id": session, "seq": seq,
                "kind": "EXEC", "command": command, "decision": decision,
                "rule_id": rule, "cwd": ROOT, "command_clipped": False,
            }) + "\n")


def _run(root, baseline, *extra):
    env = dict(os.environ, STING_SESSION_ROOT=str(root))
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "runner", "replay_live.py"),
         "--root", str(root), "--quiet", *extra],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=ROOT)


def test_an_unscanned_session_is_not_reported_as_resolved(tmp_path, monkeypatch):
    """The distinction, end to end through the real tool."""
    root = tmp_path / "logs"
    root.mkdir()
    _log(root / "seen.jsonl", "seen",
         [("git status", "ALLOW", None), ("ls -la", "ALLOW", None)])

    baseline = {"accepted": {
        # A session that IS in the root, and agrees -> RESOLVED
        "seen:1": {"recorded": {"decision": "DENY", "rule_id": "x"},
                   "current": {"decision": "ALLOW", "rule_id": None},
                   "command": "git status", "reason": "an old difference"},
        # A session that is NOT in the root at all -> UNSCANNED
        "absent:9": {"recorded": {"decision": "DENY", "rule_id": "y"},
                     "current": {"decision": "ALLOW", "rule_id": None},
                     "command": "whatever", "reason": "from another root"},
    }}
    target = tmp_path / "live_baseline.json"
    target.write_text(json.dumps(baseline), encoding="utf-8")
    monkeypatch.setenv("STING_BASELINE", str(target))

    import importlib
    from runner import replay_live
    importlib.reload(replay_live)
    replay_live.BASELINE = target
    result = replay_live.replay([root], ROOT, [])

    stale = [k for k in baseline["accepted"]
             if k not in {d["key"] for d in result["diffs"]}]
    unscanned = [k for k in stale
                 if k.rsplit(":", 1)[0] not in result["session_ids"]]
    resolved = [k for k in stale if k in result["compared_keys"]]

    assert "absent:9" in unscanned, "a session never opened cannot be resolved"
    assert "absent:9" not in resolved
    assert "seen:1" in resolved, "a compared, agreeing record IS resolved"
    assert "seen:1" not in unscanned


def test_the_run_reports_which_sessions_it_opened(tmp_path):
    """⚠ THE FIELD THE DISTINCTION RESTS ON. Without `session_ids` the caller
    cannot tell "not in the diffs" from "not in the population", and the report
    called both the same thing for as long as it existed."""
    from runner import replay_live

    root = tmp_path / "logs"
    root.mkdir()
    _log(root / "a.jsonl", "alpha", [("git status", "ALLOW", None)])
    _log(root / "b.jsonl", "beta", [("ls", "ALLOW", None)])

    result = replay_live.replay([root], ROOT, [])

    assert result["session_ids"] == {"alpha", "beta"}
    assert result["compared_keys"], "the run must have compared something"
    assert all(":" in k for k in result["compared_keys"])


def test_prune_stale_cannot_drop_an_unscanned_entry(tmp_path):
    """⚠ THE 77-ENTRY BUG, AS A TEST.

    `--prune-stale` rebuilt `accepted` from this run's diffs, so an entry whose
    session lived in another log root was deleted by a run that never read it.
    Now it removes only what this run compared.
    """
    source = open(os.path.join(ROOT, "runner", "replay_live.py"),
                  encoding="utf-8").read()

    assert "accepted = dict(accepted) if not args.prune_stale else {}" not in source, \
        "prune-stale must not rebuild the dict from one run's diffs"
    assert "for key in resolved:" in source, \
        "prune-stale must drop only entries this run compared and found agreeing"


def test_the_reporter_names_all_three_populations():
    """The words matter here: "stale" is what invited the prune."""
    source = open(os.path.join(ROOT, "runner", "replay_live.py"),
                  encoding="utf-8").read()

    for word in ("RESOLVED", "UNSCANNED", "UNJUDGED"):
        assert word in source, f"{word} must be reported separately"
    assert "no longer differ (stale)" not in source, \
        "the single-word report is what made 84 look like 84 fixes"
