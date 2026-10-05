"""The record says what the agent was TOLD, beside what the rule decided.

`decision` is the engine's own verdict, and it stays so: the standing replay
compares against it. But the agent is answered after the shipped default and a
person's `~/.sting/policy.json` relax it, after a one-shot grant, and not at all
in observe mode — so a DENY record was often an ASK or an ALLOW to the agent,
and anything counting DENY records (the panel, an audit) overstated what was
stopped. `enforced` is what the relaxations make of the engine's verdict (ALLOW
in observe mode): one of ALLOW, ASK, DENY, never stricter than `decision`, on
every DENY and ASK record (an ALLOW can only have been answered ALLOW, and its
record stays byte-identical). A one-shot grant is its `allow_once_used`
record's answer. docs/108 §6 and docs/113 §1.
"""
from __future__ import annotations

import json

import pytest

import hook_entry
from core import allow_once, audit_log, engine, policy, wire
from core.allow_once import fingerprint, grant_path, write_grant
from core.audit_log import default_log_path, read_records
from core.types import Action, ActionKind, Decision, Verdict

_STRENGTH = {"ALLOW": 0, "ASK": 1, "DENY": 2}


def _payload(command: str = "git push origin main", session: str = "enf") -> str:
    return json.dumps({"session_id": session, "cwd": "/tmp",
                       "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": command}})


def _engine_says(monkeypatch, verdict: Verdict) -> None:
    monkeypatch.setattr(engine, "decide", lambda a, s, w: verdict)


def _policy(tmp_path, monkeypatch, rules: dict) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": rules}), encoding="utf-8")
    monkeypatch.setenv("STING_POLICY", str(path))


def _records(session: str = "enf") -> list[dict]:
    return [r for r in read_records(default_log_path(session))
            if r.get("event") != "session_start"]


def _told(out: str) -> str:
    """What Claude Code was told: an empty stdout is no opinion (observe)."""
    if not out:
        return ""
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"].upper()


# ── the relaxations: the record keeps the rule's verdict and adds the answer
def test_a_deny_the_shipped_default_relaxes_records_the_ask_the_agent_was_given(monkeypatch):
    # Arrange
    _engine_says(monkeypatch, Verdict(Decision.DENY, "a push after outside content",
                                      "untrusted_unexpected:git_push"))
    # Act
    out, _err, code = hook_entry.run(_payload(), agent="claude-code")
    # Assert
    record = _records()[0]
    assert code == 0 and _told(out) == "ASK"
    assert record["decision"] == "DENY", "the rule's own verdict stays on the record"
    assert record["enforced"] == "ASK"
    assert "untrusted_unexpected:git_push" in record["relaxed"]


def test_a_deny_a_person_relaxes_to_allow_records_allow(tmp_path, monkeypatch):
    _policy(tmp_path, monkeypatch, {"test_rule": "allow"})
    _engine_says(monkeypatch, Verdict(Decision.DENY, "nope", "test_rule"))
    out, _err, _code = hook_entry.run(_payload(), agent="claude-code")
    record = _records()[0]
    assert (record["decision"], record["enforced"], _told(out)) == ("DENY", "ALLOW", "ALLOW")


def test_an_unrelaxed_deny_is_enforced_as_decided(monkeypatch):
    _engine_says(monkeypatch, Verdict(Decision.DENY, "a secret leaves",
                                      "secret_exact:network_egress"))
    out, _err, _code = hook_entry.run(_payload(), agent="claude-code")
    record = _records()[0]
    assert (record["decision"], record["enforced"], _told(out)) == ("DENY", "DENY", "DENY")


def test_an_allow_record_carries_no_answer_because_it_can_only_be_allow(monkeypatch):
    """An ALLOW cannot be relaxed further, so its record stays byte-identical
    (`test_an_allow_record_is_byte_for_byte_what_it_was`)."""
    _engine_says(monkeypatch, Verdict(Decision.ALLOW, None, None))
    out, _err, _code = hook_entry.run(_payload("ls"), agent="claude-code")
    record = _records()[0]
    assert (record["decision"], _told(out)) == ("ALLOW", "ALLOW")
    assert "enforced" not in record


def test_a_relaxed_floor_records_the_verdict_it_gave_back(tmp_path, monkeypatch):
    """`installed_guard:guard_selfmod` relaxed to allow enforces what the
    engine decided beneath the floor (`Overlay.enforce`): here an ASK."""
    _policy(tmp_path, monkeypatch, {"installed_guard:guard_selfmod": "allow"})
    beneath = Verdict(Decision.ASK, "a recursive delete", "irreversible_action")
    _engine_says(monkeypatch, Verdict(Decision.DENY, "the installed guard",
                                      "installed_guard:guard_selfmod", beneath=beneath))
    out, _err, _code = hook_entry.run(_payload("rm -rf x"), agent="claude-code")
    record = _records()[0]
    assert (record["decision"], record["rule_id"]) == ("DENY", "installed_guard:guard_selfmod")
    assert record["enforced"] == "ASK" == _told(out)


# ── observe and the one-shot grant
def test_observe_mode_records_allow_because_it_enforces_nothing(monkeypatch):
    monkeypatch.setenv("STING_OBSERVE", "1")
    _engine_says(monkeypatch, Verdict(Decision.DENY, "a secret leaves",
                                      "secret_exact:network_egress"))
    out, _err, code = hook_entry.run(_payload(), agent="claude-code")
    record = _records()[0]
    assert (out, code) == ("", 0), "observe blocks nothing"
    assert (record["decision"], record["enforced"]) == ("DENY", "ALLOW")


def _grant_for_the_payload() -> None:
    act = Action("enf", 0, ActionKind.EXEC, (), "git push origin main", None, "Bash",
                 None, "/tmp", ("/tmp",), "x")
    write_grant("enf", fingerprint(act), granted_by="test")


def test_a_spent_grant_is_the_override_records_answer(monkeypatch):
    """The decision record is written FIRST, as on main (both round-1 reviews:
    spending the grant first left a window with a spent grant and no record).
    It carries the answer before any grant; the `allow_once_used` record that
    follows at the same seq is the answer the agent got, ALLOW."""
    _engine_says(monkeypatch, Verdict(Decision.DENY, "a secret leaves",
                                      "secret_exact:network_egress"))
    _grant_for_the_payload()
    out, _err, _code = hook_entry.run(_payload(), agent="claude-code")
    decision, override = _records()
    assert _told(out) == "ALLOW"
    assert (decision["event"], decision["decision"], decision["enforced"]) == (
        "decision", "DENY", "DENY")
    assert (override["event"], override["decision"], override["seq"]) == (
        "allow_once_used", "ALLOW", decision["seq"])


def test_the_decision_is_recorded_before_the_grant_is_spent(monkeypatch):
    _engine_says(monkeypatch, Verdict(Decision.DENY, "a secret leaves",
                                      "secret_exact:network_egress"))
    _grant_for_the_payload()
    seen: list[list[str]] = []
    real = allow_once.consume

    def consume(session_id, action, root=None):
        seen.append([r["event"] for r in _records()])
        return real(session_id, action, root)

    monkeypatch.setattr(allow_once, "consume", consume)
    hook_entry.run(_payload(), agent="claude-code")
    assert seen == [["decision"]], seen


def test_a_failing_overlay_leaves_the_decision_on_the_record(monkeypatch):
    """The guard fails closed (exit 2) — and the engine's verdict is still on
    the record, as on main, with no answer said."""
    _engine_says(monkeypatch, Verdict(Decision.DENY, "a secret leaves",
                                      "secret_exact:network_egress"))

    def broken(self, verdict):
        raise RuntimeError("overlay")

    monkeypatch.setattr(policy.Overlay, "enforce", broken)
    _out, _err, code = hook_entry.run(_payload(), agent="claude-code")
    records = _records()
    assert code == 2
    assert [r["decision"] for r in records] == ["DENY"]
    assert "enforced" not in records[0]


def test_a_grant_is_not_spent_in_observe_mode(monkeypatch):
    monkeypatch.setenv("STING_OBSERVE", "1")
    _engine_says(monkeypatch, Verdict(Decision.DENY, "a secret leaves",
                                      "secret_exact:network_egress"))
    act = Action("enf", 0, ActionKind.EXEC, (), "git push origin main", None, "Bash",
                 None, "/tmp", ("/tmp",), "x")
    write_grant("enf", fingerprint(act), granted_by="test")
    hook_entry.run(_payload(), agent="claude-code")
    assert [r["event"] for r in _records()] == ["decision"]
    assert grant_path("enf").exists(), (
        "observe must not spend a grant on an action it never blocks")


# ── the bound: never stricter than the rule, and only the three answers
@pytest.mark.parametrize("decided", list(Decision))
@pytest.mark.parametrize("relaxed_to", [None, "ask", "allow"])
def test_enforced_is_never_stricter_than_the_rules_own_decision(tmp_path, monkeypatch,
                                                                decided, relaxed_to):
    if relaxed_to:
        _policy(tmp_path, monkeypatch, {"test_rule": relaxed_to})
    _engine_says(monkeypatch, Verdict(decided, "r", "test_rule"))
    out, _err, _code = hook_entry.run(_payload(), agent="claude-code")
    record = _records()[0]
    answer = record.get("enforced", "ALLOW" if record["decision"] == "ALLOW" else None)
    assert answer in _STRENGTH, record
    assert _STRENGTH[answer] <= _STRENGTH[record["decision"]]
    assert _told(out) == answer


@pytest.mark.parametrize("decision,enforced,kept", [
    ("DENY", "maybe", False), ("DENY", None, False), ("ALLOW", "ALLOW", False),
    ("ASK", "DENY", False),             # never stricter than the rule (round-1 review)
    ("DENY", "ASK", True), ("ASK", "ASK", True), ("DENY", "DENY", True),
    ("ASK", "ALLOW", True)])
def test_only_an_answer_on_a_deny_or_an_ask_is_recorded(decision, enforced, kept):
    body = audit_log.build_body("s", seq=1, event="decision", decision=decision,
                                enforced=enforced)
    assert ("enforced" in body) is kept
    if kept:
        assert body["enforced"] == enforced


def test_a_body_given_no_answer_carries_none():
    """The session_start canary decides nothing, and an older engine never
    wrote the field: absence means "not said", never "same as decision"."""
    body = audit_log.build_body("s", seq=None, event="session_start", decision=None)
    assert "enforced" not in body


def test_the_answer_ships_unmasked_at_every_tier():
    """Our own enum, no user-authored bytes: in the spine with `decision`."""
    assert "enforced" in wire._SPINE
    assert "enforced" in wire.UNMASKED
