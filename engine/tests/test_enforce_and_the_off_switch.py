"""Enforce mode, and the one thing that must ship with it.

⚠ THE OFF-SWITCH IS NOT A FEATURE BESIDE ENFORCE — IT IS THE OTHER HALF OF IT.
The rehearsal measured ~28 stops a day catching zero attacks, and this machine's
own store confirms the shape: 185 stops, 146 of them DENY, and reading the
actual commands not one was an attack. 59 were the developer pushing their own
branch. Enforce without a way to turn ONE rule down is a product uninstalled on
day two, and the uninstall takes the whole guard with it.

The properties pinned here:

    1  enforce is what a machine is BORN in; observe is what somebody asks for
    2  `failClosed` tracks the mode, so a hook that cannot run cannot permit
    3  a crash is distinguishable from a refusal, in the message itself
    4  the overlay RELAXES and can never tighten
    5  it lives where the agent cannot quietly write it
    6  the engine's verdict is on the record UNCHANGED, and the record says
       which rules were relaxed when it was decided
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import hook_entry
import install
from core import policy
from core.types import Decision, Verdict

ROOT = Path(__file__).resolve().parent.parent


# ══════════════════════════════════════ 1 · enforce is the default ══

def test_a_machine_is_born_enforcing():
    """⚠ THE FALLBACK IS `"0"`. A guard whose first state is "decides
    everything, stops nothing" is one the collector cannot tell from a working
    one — same heartbeat, same records, and nothing ever refused."""
    from installer import recorded

    value, source = recorded.resolve(None, None, "0", key="STING_OBSERVE")
    assert value == "0" and source == "the default"

    source_text = (ROOT / "install.py").read_text(encoding="utf-8")
    assert '"0", key="STING_OBSERVE")' in source_text, (
        "install.py no longer defaults to enforce")


def test_a_machine_that_chose_observe_is_not_flipped_by_an_upgrade():
    """⚠ THE REVERSE OF THIS BLOCK'S OWN RULE WOULD BE A GUARD THAT TURNS ITSELF
    ON. A carried value still wins over the default, both ways."""
    from installer import recorded

    assert recorded.resolve(None, "1", "0", key="STING_OBSERVE")[0] == "1"
    assert recorded.resolve(None, "0", "0", key="STING_OBSERVE")[0] == "0"


# ═══════════════════════════════ 2 · failClosed tracks the mode ══

@pytest.mark.parametrize("observe,expected", [(True, False), (False, True)])
def test_failclosed_flips_with_the_mode(observe, expected, monkeypatch):
    """⚠ IN ENFORCE, A HOOK THAT CANNOT RUN MUST NOT SILENTLY PERMIT. This
    project has shipped a guard that reported success and permitted everything
    twice; `failClosed:false` under enforce would be the third."""
    monkeypatch.setattr(install, "_is_windows", lambda: False)
    written = install.write_hook_config(
        "cursor", Path("/tmp/never/hooks.json"),
        Path("/opt/sting/v1/sting_hook.py"), {}, dry_run=True, observe=observe)
    # dry_run returns the command; the entry shape is what carries failClosed
    entry = install._cursor_entry(written["command"], observe)
    assert entry["failClosed"] is expected


# ═════════════════ 3 · a crash is not a refusal, and says so ══

def test_a_guard_crash_is_unmistakable_and_offers_a_way_out(monkeypatch):
    """Both a refusal and a crash stop the tool call. They have opposite next
    steps, so a developer must be able to tell them apart at a glance."""
    def boom(action, state, world):
        raise RuntimeError("engine exploded")
    monkeypatch.setattr(hook_entry.engine, "decide", boom)

    out, err, code = hook_entry.run(json.dumps(
        {"session_id": "crash-1", "cwd": "/tmp", "tool_name": "Bash",
         "tool_input": {"command": "ls"}}), agent="claude-code")

    assert code == 2 and out == "", "a crashed guard must never read as an allow"
    assert "NOT a policy refusal" in err
    assert "RuntimeError" in err and "engine exploded" in err
    # ⚠ RE-PINNED BY ITEM 2: this asserted "--observe" in err. Every agent
    # reads this message (Claude Code gives it to the model), so it no longer
    # names a switch; the person has `install.py --help` in their own terminal
    # (tests/test_an_agent_cannot_change_the_install.py).
    assert "--observe" not in err
    assert "tell the user" in err
    assert "preflight" in err


def test_a_refusal_names_its_rule_and_how_to_turn_it_down():
    """⚠ THE RULE ID IS WHAT MAKES A REFUSAL ACTIONABLE. It is the key of
    `~/.sting/policy.json`, so the string in the message is the string to
    paste. A refusal with no way forward is how enforce becomes an uninstall."""
    from adapters import claude_code

    rendered = json.loads(claude_code.render(
        Verdict(Decision.DENY, "a credential is leaving", "secret_exact:egress")))
    reason = rendered["hookSpecificOutput"]["permissionDecisionReason"]

    # ⚠ PREFIXED so the refusal is obviously Sting's; the engine's words follow.
    assert "STING BLOCKED" in reason.upper()
    assert "a credential is leaving" in reason
    # ⚠ RE-PINNED (docs/108): the rule id and the way out go where only the
    # person reads them, Claude Code's `systemMessage`. An agent handed the
    # allow-once command could run it (docs/108 §3), so the model reads neither.
    human = rendered["systemMessage"]
    assert "secret_exact:egress" in human and "secret_exact:egress" not in reason
    assert "policy.json" in human and "policy.json" not in reason
    assert "allow_once" in human and "allow_once" not in reason


def test_an_ASK_is_not_told_how_to_switch_the_guard_off():
    """⚠ APPENDING "here is how to turn this off" TO EVERY PROMPT IS HOW A GUARD
    TRAINS PEOPLE TO TURN IT OFF. An ASK already lets the developer proceed."""
    from adapters import claude_code

    rendered = json.loads(claude_code.render(
        Verdict(Decision.ASK, "unusual", "irreversible_action")))
    reason = rendered["hookSpecificOutput"]["permissionDecisionReason"]

    assert "irreversible_action" in reason, "an ASK should still name its rule"
    assert "policy.json" not in reason


# ═══════════════════════════ 4 · the overlay relaxes, never tightens ══

@pytest.mark.parametrize("wanted,decision,expected", [
    (Decision.ASK, Decision.DENY, Decision.ASK),
    (Decision.ALLOW, Decision.DENY, Decision.ALLOW),
    (Decision.ALLOW, Decision.ASK, Decision.ALLOW),
    (Decision.ASK, Decision.ALLOW, Decision.ALLOW),      # would tighten: refused
    (Decision.ASK, Decision.ASK, Decision.ASK),          # no movement
])
def test_it_only_ever_weakens(wanted, decision, expected):
    """⚠ A FILE THAT COULD TIGHTEN IS A FILE NOBODY LOOKS IN when something is
    unexpectedly refused. Because it can only weaken, this overlay can never be
    the reason an action was stopped — only ever the reason one was not."""
    overlay = policy.Overlay({"r": wanted}, [], "/x")
    assert overlay.apply(decision, "r")[0] == expected


def test_deny_is_not_a_value_the_file_can_hold(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": {"r:a": "deny"}}), encoding="utf-8")

    overlay = policy.load(str(path))

    assert "r:a" not in overlay.rules
    assert any("can only RELAX" in p for p in overlay.problems), overlay.problems


def test_a_broken_policy_file_is_reported_and_never_raises(tmp_path):
    """⚠ A JSON SYNTAX ERROR IN A CONFIG MUST NOT BECOME A HOOK THAT CANNOT RUN.
    But it must not be silent either: a relaxation somebody wrote and which is
    not in force is exactly as bad as one they did not write."""
    path = tmp_path / "policy.json"
    path.write_text("{not json", encoding="utf-8")

    overlay = policy.load(str(path))

    assert overlay.problems, "a broken policy file was accepted silently"
    assert policy.describe(overlay), "nothing would reach the developer"


# ═════════════════════ 5 · where it lives, and why that is safe ══

def test_it_lives_outside_every_repository_the_agent_can_write(monkeypatch):
    """⚠ TASK 2.2. A settings file inside the project is a file the agent edits
    all day, so "turn this rule off" becomes something an attacker's session
    does. `~/.sting/` is outside every project root, so a write to it from an
    agent session is a `write_outside` the guard itself can see."""
    # ⚠ THE OVERRIDE IS CLEARED, because this asserts the DEFAULT location and
    # `STING_POLICY` is exactly what replaces it. Without this the test passed
    # alone and failed in the suite — another test's override leaking in, which
    # is a test measuring the harness rather than the product.
    monkeypatch.delenv(policy.PATH_ENV, raising=False)
    assert policy.default_path().endswith(os.path.join(".sting", "policy.json"))
    assert ".sting" in policy.default_path()

    source = (ROOT / "core" / "policy.py").read_text(encoding="utf-8")
    assert "not a boundary against a determined local" in source.lower(), (
        "the limit of this protection must be stated rather than implied")


# ══════════════ 6 · the engine's verdict survives, and is labelled ══

def test_the_record_keeps_the_ENGINE_verdict_and_names_the_relaxation(tmp_path,
                                                                       monkeypatch):
    """⚠ THE WHOLE REASON THE STANDING REPLAY STILL WORKS. If the overlay wrote
    its own decision into the record, every relaxed action would read as a
    verdict the engine never reached — and the differential replay would compare
    a fresh DENY against a recorded ASK and call it a regression."""
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    monkeypatch.setenv("STING_OBSERVE", "0")
    monkeypatch.setenv("STING_POLICY", str(tmp_path / "policy.json"))
    (tmp_path / "policy.json").write_text(
        json.dumps({"rules": {"test_rule": "ask"}}), encoding="utf-8")
    monkeypatch.setattr(hook_entry.engine, "decide",
                        lambda a, s, w: Verdict(Decision.DENY, "nope", "test_rule"))

    out, err, code = hook_entry.run(json.dumps(
        {"session_id": "rel-1", "cwd": "/tmp", "tool_name": "Bash",
         "tool_input": {"command": "x"}}), agent="claude-code")

    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask", (
        "the relaxation did not reach the agent")
    assert "relaxed by policy" in err

    records = [json.loads(l) for l in
               (tmp_path / "rel-1.log.jsonl").read_text().splitlines() if l.strip()]
    decisions = [r for r in records if r["event"] == "decision"]
    assert decisions and decisions[0]["decision"] == "DENY", (
        "the record no longer holds the ENGINE's verdict — the differential "
        "replay compares against this")
    assert "test_rule" in decisions[0]["relaxed"]


def test_the_relaxed_set_is_the_whole_overlay_not_just_the_rule_that_fired():
    """⚠ WHAT A READER NEEDS TO JUDGE A SESSION IS WHICH POLICY IT RAN UNDER.
    A record saying "nothing was relaxed for me" is worth nothing if three other
    rules were off at the time."""
    from core import audit_log

    body = audit_log.build_body("s", seq=1, event="decision", decision="ALLOW",
                                 rule_id=None, relaxed=["r:b", "r:a"])
    assert body["relaxed"] == ["r:a", "r:b"]


def test_relaxed_is_absent_when_nothing_is_relaxed():
    """An unrelaxed machine pays no bytes for it, at any tier."""
    from core import audit_log

    assert "relaxed" not in audit_log.build_body(
        "s", seq=1, event="decision", decision="ALLOW")


def test_the_relaxation_travels_at_every_tier():
    """⚠ SAME REASON AS `guard_version`: a verdict that arrives without the
    policy that made it cannot be judged at any tier, and which rules were
    turned down is part of that policy."""
    from core import wire

    assert "relaxed" in wire._SPINE


# ═══════════════════════════ the shipped default, and its argument ══

def test_the_shipped_default_relaxes_only_the_untrusted_unexpected_family():
    """⚠ TASK 3.2, AND THE LIST IS THE PRODUCT. What is NOT relaxed is the
    argument: `secret_*` stays DENY because a false positive costs one prompt
    and a miss costs the credential."""
    relaxed = set(policy.SHIPPED_DEFAULT)

    assert relaxed, "the shipped default relaxes nothing — a guard that blocks 28 times a day is not a default"
    assert all(r.startswith("untrusted_unexpected:") for r in relaxed), relaxed
    assert all(v is Decision.ASK for v in policy.SHIPPED_DEFAULT.values()), (
        "the shipped default ALLOWS something — every relaxation here must "
        "still stop the action and ask a human")
    for kept in ("catastrophic_delete", "untrusted_destructive"):
        assert kept not in relaxed
    assert not any(r.startswith("secret") for r in relaxed), (
        "a secret rule was relaxed by default — a miss there is the credential")


def test_a_users_file_starts_from_the_shipped_default(tmp_path):
    """⚠ "my file has three rules in it" MUST NOT SILENTLY MEAN "and the other
    six are now enforced"."""
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": {"my_rule": "allow"}}), encoding="utf-8")

    overlay = policy.load(str(path))

    assert "my_rule" in overlay.rules
    for shipped in policy.SHIPPED_DEFAULT:
        assert shipped in overlay.rules, f"{shipped} was dropped by a user file"


# ═══════════ guard_selfmod: the temporary relaxation is gone (item C) ══
#
# `untrusted_unexpected:guard_selfmod` was relaxed to ASK with its removal
# trigger written beside it, and a test here kept the note alive. The trigger
# fired: nothing in the shipped default relaxes it now, and an agent acting on
# the installed guard is `installed_guard:guard_selfmod`, DENY in every
# session. tests/test_the_installed_guard_is_protected.py pins both.


def test_the_secret_family_keeps_guard_selfmod_at_DENY():
    """⚠ THE FLOOR THE RELAXATION DOES NOT TOUCH, asserted so a future widening
    has to argue with a test.

    A session that has actually read a credential and then disables the guard
    is the cover-your-tracks shape, and it is the one case where refusing costs
    a prompt and permitting costs the evidence. Two of this machine's DENYs were
    `secret_exact:guard_selfmod`; both stay DENY.
    """
    from core.types import Decision

    overlay = policy.Overlay(dict(policy.SHIPPED_DEFAULT), [], "shipped")
    for rule in ("secret_exact:guard_selfmod", "secret_derived:guard_selfmod",
                 "secret_session_unverified:guard_selfmod"):
        decided, relaxed = overlay.apply(Decision.DENY, rule)
        assert decided is Decision.DENY and relaxed is None, (
            f"{rule} is relaxed by the shipped default — a session that has "
            f"read a credential can now stop the guard with one prompt")
