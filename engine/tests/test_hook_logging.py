"""hook_entry records every decision onto the chained log — docs/15 step 16.

The engine decides; the entry point records. These tests pin that the recording
happens, that it carries the reason string the panel will display, and — most
importantly — that a broken log never changes a verdict.
"""
import json

import pytest

import hook_entry
from core import engine
from core.audit_log import default_log_path, read_records, verify_chain
from core.types import Decision, Verdict


def payload(tool="Bash", tool_input=None, session="s1"):
    return json.dumps({"session_id": session, "cwd": "/tmp",
                       "hook_event_name": "PreToolUse", "tool_name": tool,
                       "tool_input": tool_input or {"command": "ls"}})


def records(session="s1"):
    """Only DECISION records — the log now opens with a `session_start` canary,
    so the Nth decision is no longer the Nth record. Every production reader
    filters the same way (replay_live.py:143, and any viewer that reads the log)."""
    return [r for r in read_records(default_log_path(session))
            if r.get("event") == "decision"]


def test_an_allow_is_logged():
    out, err, code = hook_entry.run(payload())
    assert (out, err, code) == ('{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": "Sting: allowed"}}', "", 0)
    recs = records()
    assert len(recs) == 1
    assert recs[0]["decision"] == "ALLOW"
    assert recs[0]["kind"] == "EXEC"
    assert recs[0]["command"] == "ls"


def test_a_deny_is_logged_with_its_reason_and_rule_id(monkeypatch):
    """The panel displays the engine's reason string verbatim. If it is not in
    the log, the extension would have to reconstruct it — which is policy logic
    in TypeScript, the exact thing Part C forbids."""
    reason = "this carries data traced from .env (read at step 2)"
    monkeypatch.setattr(engine, "decide",
                        lambda a, s, w: Verdict(Decision.DENY, reason, "secret_egress"))
    hook_entry.run(payload())
    rec = records()[0]
    assert rec["decision"] == "DENY"
    assert rec["reason"] == reason
    assert rec["rule_id"] == "secret_egress"


def test_successive_calls_chain_into_one_verifiable_log():
    for _ in range(4):
        hook_entry.run(payload())
    ok, bad, detail = verify_chain(default_log_path("s1"))
    assert ok, detail
    assert len(records()) == 4


def test_seq_is_recorded_and_advances():
    for _ in range(3):
        hook_entry.run(payload())
    assert [r["seq"] for r in records()] == [1, 2, 3]


def test_separate_sessions_get_separate_logs():
    hook_entry.run(payload(session="s1"))
    hook_entry.run(payload(session="s2"))
    assert len(records("s1")) == 1 and len(records("s2")) == 1


def test_a_read_logs_its_resolved_path(tmp_path):
    """The RESOLVED path, the same one the engine reasoned about. On macOS /tmp
    is a symlink to /private/tmp; logging the raw string would show the viewer a
    path the policy never actually considered."""
    target = tmp_path / "x.txt"
    target.write_text("x")
    hook_entry.run(payload(tool="Read", tool_input={"file_path": str(target)}))
    assert records()[0]["paths"] == [str(target.resolve())]


def test_a_fetch_logs_its_url():
    hook_entry.run(payload(tool="WebFetch", tool_input={"url": "https://example.com/a"}))
    rec = records()[0]
    assert rec["kind"] == "FETCH" and rec["url"] == "https://example.com/a"


# ------------------------------------------------------------ failure modes
def test_an_unwritable_log_does_not_change_the_verdict(tmp_path, monkeypatch):
    """Full disk, bad permissions, whatever. Failing closed on every action
    because the log is broken would be far worse than an unrecorded allow."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    monkeypatch.setenv("STING_LOG", str(blocker / "sub" / "x.jsonl"))

    out, err, code = hook_entry.run(payload())
    # ⚠ ALLOW is an explicit decision now, not empty stdout.
    assert (out, code) == ('{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": "Sting: allowed"}}', 0), "the allow must survive a log failure"
    assert "not logged" in err, "but it must say so on stderr"


def test_an_unwritable_log_does_not_suppress_a_deny(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    monkeypatch.setenv("STING_LOG", str(blocker / "sub" / "x.jsonl"))
    monkeypatch.setattr(engine, "decide",
                        lambda a, s, w: Verdict(Decision.DENY, "nope", "r"))

    out, err, code = hook_entry.run(payload())
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert code == 0 and "not logged" in err


def test_a_guard_crash_is_not_logged_as_an_allow(monkeypatch):
    """Exit 2 means no verdict was produced. Writing an ALLOW record here would
    put a decision in the audit log that the guard never actually made."""
    monkeypatch.setattr(engine, "decide",
                        lambda a, s, w: (_ for _ in ()).throw(RuntimeError("boom")))
    out, err, code = hook_entry.run(payload())
    assert code == 2 and out == ""
    assert records() == []
