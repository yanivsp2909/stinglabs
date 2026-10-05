"""Which agent produced a record — and the guarantee that it stays telemetry.

`Action.agent` has been set by all five adapters since they were written and was
never written to the log, so a decision log could not answer "was this Claude
Code or Cursor?" at all. That was harmless while one developer used one agent.
It stopped being harmless the day a second developer started on Cursor and both
began writing into the same log directory.

TWO PROPERTIES, AND THE SECOND IS THE LOAD-BEARING ONE:

  1. the field is recorded, inside the hashed body, for every adapter;
  2. **no verdict depends on it.** `Action.agent`'s docstring says the engine
     must never branch on it. That is what makes the field safe to record at
     all: a forged `agent` misattributes a record, it does not change a
     decision. `test_the_engine_never_branches_on_the_agent` is the enforcement
     — it decides the same action under all five agent ids and requires one
     answer, so a rule that starts reading `agent` fails here rather than in
     production.

CLEAN ABSENCE, the same shape as `duration_ms`. Records written before this
field simply do not have the key. They still verify — each record hashes its own
body, so a key added today cannot invalidate one written yesterday — and the
1181-record vendored fixture is the proof, since not one of its records has it.
"""
from __future__ import annotations

import json

import pytest

import hook_entry
from core import audit_log, engine
from core.audit_log import default_log_path, read_records
from core.probes import NullWorld
from core.types import Action, ActionKind, SessionState
# The five native payload shapes already exist, one per agent. Rebuilding them
# here would be a second set of five, free to drift from the ones the
# conformance contract actually checks.
from tests.test_adapter_conformance import NATIVE_EXEC_PAYLOAD

AGENTS = ["claude-code", "cursor", "codex", "copilot", "antigravity"]


# ------------------------------------------------------------ 1 · it is there

@pytest.mark.parametrize("agent", AGENTS)
def test_every_adapter_records_which_agent_it_was(agent):
    """Driven through each agent's OWN payload shape, not a Claude Code one
    relabelled — otherwise this proves the env var works and nothing about the
    adapters."""
    out, err, code = hook_entry.run(json.dumps(NATIVE_EXEC_PAYLOAD[agent]),
                                    agent=agent)
    assert code == 0, err
    session = hook_entry.ADAPTERS[agent].parse(NATIVE_EXEC_PAYLOAD[agent]).session_id
    recs = read_records(default_log_path(session))
    assert recs, "no record written"
    assert recs[0]["agent"] == agent


def test_the_agent_is_inside_the_hashed_body():
    """An attribution that can be edited afterwards attributes nothing.

    Same argument as cwd, tool_name and workspace_roots: the field is only worth
    having if changing it is detectable.
    """
    body = audit_log.build_body("s", seq=1, event="decision", decision="ALLOW",
                                agent="cursor")
    assert body["agent"] == "cursor"
    assert "agent" not in ("prev", "hash"), "sanity"

    first = audit_log.record_hash(audit_log.GENESIS, body)
    forged = dict(body, agent="claude-code")
    assert audit_log.record_hash(audit_log.GENESIS, forged) != first, (
        "the agent is outside the hash — it could be rewritten after the fact")


def test_a_long_agent_string_is_bounded_like_every_other_field():
    body = audit_log.build_body("s", seq=1, event="decision", decision="ALLOW",
                                agent="x" * 500)
    # _clip appends CLIP_MARKER, so the bound is on the retained text.
    assert body["agent"].endswith(audit_log.CLIP_MARKER)
    assert len(body["agent"]) <= audit_log._MAX_AGENT + len(audit_log.CLIP_MARKER)


def test_an_absent_agent_is_null_not_a_guess():
    """`None`, never a default of "claude-code".

    A record that does not know which agent wrote it must say so. Defaulting
    would make every pre-existing record claim an agent nobody verified, which
    is the failure this whole field exists to remove.
    """
    body = audit_log.build_body("s", seq=1, event="decision", decision="ALLOW")
    assert body["agent"] is None


# --------------------------------------------------- 2 · it changes no verdict

def _action(agent: str) -> Action:
    return Action(session_id="s", seq=1, kind=ActionKind.EXEC,
                  paths=(), command="git push origin main", url=None,
                  tool_name=None, content=None, cwd="/tmp",
                  workspace_roots=("/tmp",), agent=agent)


@pytest.mark.parametrize("state_kind", ["clean", "untrusted", "secret"])
def test_the_engine_never_branches_on_the_agent(state_kind):
    """THE PROPERTY THAT MAKES RECORDING IT SAFE.

    Checked under three session states rather than one, because a rule that read
    `agent` would most plausibly do it inside an untrusted or secret-holding
    branch — the branches with the most conditions in them — and a clean-session
    check alone would walk straight past that.
    """
    def fresh() -> SessionState:
        s = SessionState(session_id="s")
        if state_kind == "untrusted":
            s.mark_untrusted(seq=1, kind="read", ref="README.md")
        elif state_kind == "secret":
            s.mark_secret(seq=1, path="/tmp/.env", how="credential path")
        return s

    verdicts = {}
    for agent in AGENTS:
        # A FRESH STATE PER AGENT. SessionState mutates in place, so sharing one
        # would let the first decision's side effects decide the rest and the
        # comparison would be between different sessions, not different agents.
        v = engine.decide(_action(agent), fresh(), NullWorld())
        verdicts[agent] = (str(v.decision), v.rule_id, v.reason)

    distinct = set(verdicts.values())
    assert len(distinct) == 1, (
        f"the engine branched on `agent` under a {state_kind} session: {verdicts}")


def test_the_recorded_agent_does_not_move_the_replayed_verdict():
    """The reader side of the same property.

    `replay_live` used to hardcode `agent="claude-code"` because the record could
    not say. It now reads the field — and this pins that switching the recorded
    value cannot change what the differential concludes, so the fix is an
    attribution fix and not a silent policy change.
    """
    from runner import replay_live
    command = "git push origin main"
    base = {"kind": "EXEC", "command": command, "cwd": "/tmp",
            "session_id": "s", "seq": 1, "workspace_roots": ["/tmp"]}
    seen = set()
    for agent in AGENTS + [None]:
        record = dict(base, agent=agent) if agent else dict(base)
        action = replay_live.action_from(record, command, "/tmp")
        assert action.agent == (agent or "claude-code")
        v = engine.decide(action, SessionState(session_id="s"), NullWorld())
        seen.add((str(v.decision), v.rule_id))
    assert len(seen) == 1, seen
