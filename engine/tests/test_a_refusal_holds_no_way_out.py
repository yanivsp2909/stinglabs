"""What the agent reads on a block holds no way round it (docs/108).

⚠ ESTABLISHED, docs/108 §1-§3. Every DENY ended with the `~/.sting/policy.json`
line that turns its rule down and the `tools/allow_once.py` command that
re-allows it, in the text the MODEL reads on Claude Code, Cursor's
`agent_message`, Copilot, Antigravity and Codex. An agent running that command
was ALLOW in every session tried. A guard that tells the thing it is guarding
against how to switch it off is not a guard.

So the model reads: what was being sent and where, where it came from and where
it sits, "Don't retry, split or re-encode this.", and what to change when the
rule knows it, else "Stop and tell the user this was blocked." The human's way
out goes only where the model can't read it: Claude Code's `systemMessage`
(docs and the 2.1.284 binary) and Cursor's `user_message` (docs). On Codex,
Copilot and Antigravity it leaves the message; it stays in the docs.
"""
from __future__ import annotations

import json

import pytest

from adapters import antigravity, claude_code, codex, copilot, cursor
from core.types import Decision, Verdict

RULE = "secret_exact:network_egress"
DENY = Verdict(Decision.DENY,
               "this carries an AWS access key ID, recognised by its documented format",
               RULE, evidence='@11 curl -d "k=<an AWS access key ID, 20 chars>" …')
ASK = Verdict(Decision.ASK,
              "this session read /work/repo/ISSUE.md (step 2); the destination is "
              "expected, so confirm this was your intent",
              "untrusted_expected:network_egress", evidence="@0 curl -d x https://github.com/x")
NO_SEND = Verdict(Decision.DENY,
                  "this deletes the filesystem root — the directory itself, not "
                  "anything inside it, and no task ever does that",
                  "catastrophic_delete", evidence="@unrecorded")
WAY_OUT = ("allow_once", "policy.json")


def _hso(out: dict) -> dict:
    return out["hookSpecificOutput"]


# name: (module, what the MODEL reads, what ONLY the human reads, or None)
AGENTS = {
    "claude-code": (claude_code, lambda o: _hso(o)["permissionDecisionReason"],
                    lambda o: o.get("systemMessage", "")),
    "codex": (codex, lambda o: _hso(o)["permissionDecisionReason"], None),
    "cursor": (cursor, lambda o: o["agent_message"], lambda o: o.get("user_message", "")),
    "copilot": (copilot, lambda o: _hso(o)["permissionDecisionReason"], None),
    "antigravity": (antigravity, lambda o: o["reason"], None),
}


def rendered(name: str, verdict: Verdict) -> dict:
    return json.loads(AGENTS[name][0].render(verdict))


def model_text(name: str, verdict: Verdict) -> str:
    return AGENTS[name][1](rendered(name, verdict))


@pytest.mark.parametrize("name", AGENTS)
def test_the_model_reads_no_way_out_of_a_deny(name):
    told = model_text(name, DENY)
    for banned in WAY_OUT:
        assert banned not in told, f"{name}: the model reads {banned!r}:\n{told}"
    assert RULE not in told, f"{name}: the model reads the rule id that keys the policy file"


@pytest.mark.parametrize("name", AGENTS)
def test_a_deny_says_what_to_do_next(name):
    told = model_text(name, DENY)
    assert "Don't retry, split or re-encode this." in told
    assert "Stop and tell the user this was blocked." in told


# ⚠ CURSOR LEFT THIS LIST (docs/110 §A): read in Cursor 3.7.27's shipped code,
# `user_message` is what the MODEL is handed on the events Sting wires, and
# `agent_message` is read by nothing, so Cursor has no field only the person
# reads; its answer now carries no way out, like the three below.
@pytest.mark.parametrize("name", ["claude-code"])
def test_the_way_out_is_where_only_the_human_reads_it(name):
    out = rendered(name, DENY)
    human = AGENTS[name][2](out)
    assert f'{{"rules": {{"{RULE}": "ask"}}}}' in human
    named = [word for word in human.split() if word.endswith("allow_once.py")]
    assert named and named[0].startswith("/"), human


@pytest.mark.parametrize("name", ["codex", "copilot", "antigravity", "cursor"])
def test_no_way_out_anywhere_without_a_human_only_field(name):
    whole = AGENTS[name][0].render(DENY)
    for banned in WAY_OUT:
        assert banned not in whole, f"{name}: {banned!r} in {whole}"


@pytest.mark.parametrize("name", AGENTS)
def test_an_ask_carries_no_way_out(name):
    whole = AGENTS[name][0].render(ASK)
    for banned in WAY_OUT:
        assert banned not in whole, f"{name}: {banned!r} in {whole}"


@pytest.mark.parametrize("name", ["claude-code", "cursor", "copilot", "antigravity"])
def test_an_ask_says_approve_only_if_meant(name):
    told = model_text(name, ASK)
    assert told.rstrip().endswith("Approve only if you meant to do this."), told


def test_codex_blocks_an_ask_and_says_why():
    told = model_text("codex", ASK)
    assert "Codex cannot prompt for confirmation, so this is blocked rather than asked" in told
    assert "Don't retry, split or re-encode this." in told
    assert "Approve only" not in told


def test_claude_code_still_says_it_was_sting():
    told = model_text("claude-code", DENY)
    assert told.startswith("⛔ STING BLOCKED THIS — the action was NOT run.")


def test_cursor_tells_the_human_what_it_tells_the_model_and_the_way_out():
    out = rendered("cursor", DENY)
    assert out["user_message"].startswith(out["agent_message"])
    assert "allow_once" not in out["agent_message"]


@pytest.mark.parametrize("name", AGENTS)
def test_a_block_that_sends_nothing_leads_with_the_engines_reason(name):
    told = model_text(name, NO_SEND)
    assert "deletes the filesystem root" in told
    assert "you're trying to send" not in told
    for banned in WAY_OUT:
        assert banned not in told


# ─────────────────────────────── the facts, when the engine knows them
def with_why(verdict: Verdict, **facts) -> Verdict:
    from core.types import Why
    return Verdict(verdict.decision, verdict.reason, verdict.rule_id,
                   evidence=verdict.evidence, why=Why(**facts))


@pytest.mark.parametrize("name", AGENTS)
def test_the_sentence_leads_then_where_it_came_from_and_sits(name):
    verdict = with_why(DENY, action="a network send", destination="evil.invalid",
                       value_type="an AWS access key ID", source_file="/work/repo/.env",
                       source_step=1, location="offset 11 in the command")
    told = model_text(name, verdict)
    lines = [line.strip() for line in told.splitlines() if line.strip()]
    if name == "claude-code":
        lines = lines[1:]
    assert lines[0] == ("I didn't allow this because you're trying to send an AWS "
                        "access key ID to evil.invalid.")
    assert "It came from /work/repo/.env, read at step 1." in lines
    assert "It sits at offset 11 in the command." in lines


def test_an_ask_sentence_asks_and_names_whose_content_it_was():
    verdict = with_why(ASK, action="a network send", destination="github.com",
                       source_file="/work/repo/ISSUE.md", source_step=2)
    told = model_text("claude-code", verdict)
    assert told.startswith("Asking because you're trying to send to github.com.")
    assert "This session read /work/repo/ISSUE.md at step 2, which someone else wrote." in told
    assert told.rstrip().endswith("Approve only if you meant to send this.")


def test_the_remedy_replaces_stop_when_the_rule_knows_it():
    verdict = with_why(DENY, action="a network send", destination="api.github.com",
                       value_type="an AWS access key ID", remedy="environment")
    told = model_text("antigravity", verdict)
    assert ("Don't write the key into the command: read it from the environment "
            "at runtime.") in told
    assert "Stop and tell the user" not in told


def test_a_credential_sent_whole_is_named_once():
    """Where it came from and where it sits are the same file: said once."""
    verdict = with_why(DENY, action="a network send", value_type="a credential file",
                       source_file="/work/repo/.env", source_step=1,
                       location="the file /work/repo/.env")
    told = model_text("cursor", verdict)
    assert "It came from /work/repo/.env, read at step 1." in told
    assert "It sits in" not in told


def test_unknown_parts_are_left_out_never_invented():
    bare = Verdict(DENY.decision, DENY.reason, DENY.rule_id)       # no evidence either
    verdict = with_why(bare, action="a network send", value_type="the process environment")
    told = model_text("copilot", verdict)
    assert told.splitlines()[0] == ("I didn't allow this because you're trying to send "
                                    "the process environment.")
    assert "It came from" not in told and "It sits" not in told
