"""⚠ A GUARD WHOSE DECISION DOES NOT REPLACE THE AGENT'S PROMPT IS A LOG FILE
WITH EXTRA STEPS.

The operator's words: "When I run Claude Code in manual mode, IT asks me yes or
no. I want STING to say yes or no. And when Sting denies something I want to SEE
a message from Sting saying it was denied and stopped."

Both symptoms were one cause. `render()` returned the EMPTY STRING on ALLOW, on
the belief that Claude Code reads "no output, exit 0" as allow. Read against the
shipped binary — `@anthropic-ai/claude-code` 2.1.231, `bin/claude.exe`, the same
way `failClosed` was settled for Cursor — the hook result is consumed by:

    if (p.permissionBehavior !== void 0) { … yield hookPermissionResult … }

No output means no `permissionDecision`, so no `permissionBehavior`, so that
branch never runs and **Claude Code falls through to its own permission flow.**
In manual mode it prompts. The same binary documents the field it honours:

    `permissionDecision` - "allow", "deny", or "ask" (PreToolUse only)

⚠ PROVEN IN A REAL SESSION, not only here. `claude -p --permission-mode manual`
with a settings file pointing at this hook:

    before   "The write was blocked — permission to create `touched.txt`
              hasn't been granted yet."          (file NOT created)
    after    "Created `touched.txt` containing `hi`."   (no prompt)

and, feeding the real DENY bytes through the same path, Claude Code answered:

    "The command was blocked by Sting, not by git — it never ran."

⚠ AND THIS REPLACES THE AGENT'S PERMISSION SYSTEM RATHER THAN ADDING TO IT.
That is the product, and it means a DEFECT IN STING NOW LETS AN AGENT RUN
UNPROMPTED, where before the agent would still have asked. Everything below the
first section is about that.
"""
from __future__ import annotations

import json

import pytest

from adapters import claude_code
from core.types import Decision, Verdict


def _rendered(decision, reason="r", rule="some_rule:sink"):
    # ⚠ Verdict is (decision, reason, rule_id) — NOT (…, evidence, rule_id).
    # Getting that wrong silently drops the rule id and the way out, which is
    # exactly what a hand-built Verdict did while probing this by hand.
    out = claude_code.render(Verdict(decision, reason, rule))
    return json.loads(out)["hookSpecificOutput"]


# ════════════════════ 2.1 · ALLOW suppresses the prompt ══

def test_allow_is_an_explicit_decision_not_an_empty_string():
    """⚠ THE WHOLE BUG. Empty output is not 'allow', it is NO OPINION — and no
    opinion means Claude Code decides, which in manual mode means it prompts."""
    out = claude_code.render(Verdict(Decision.ALLOW, None, None, None))
    assert out.strip(), "ALLOW rendered as empty output — the agent will prompt"
    assert _rendered(Decision.ALLOW)["permissionDecision"] == "allow"


def test_the_three_decisions_map_to_the_three_values_the_binary_documents():
    """`permissionDecision` - "allow", "deny", or "ask" (PreToolUse only),
    read from bin/claude.exe in the installed package."""
    assert _rendered(Decision.ALLOW)["permissionDecision"] == "allow"
    assert _rendered(Decision.DENY)["permissionDecision"] == "deny"
    assert _rendered(Decision.ASK)["permissionDecision"] == "ask"


def test_ask_still_falls_through_to_the_agents_own_prompt():
    """ASK means a human decides, so handing Claude Code `ask` is correct —
    it is the one verdict that SHOULD produce the dialog."""
    assert _rendered(Decision.ASK)["permissionDecision"] == "ask"


def test_every_reply_names_the_event_claude_code_requires():
    for decision in (Decision.ALLOW, Decision.DENY, Decision.ASK):
        assert _rendered(decision)["hookEventName"] == "PreToolUse"


# ════════════════════ 2.2 · a DENY is obviously Sting's ══

def test_a_denial_says_sting_stopped_it():
    """⚠ WITHOUT A NAME IN THE TEXT IT READS AS THE AGENT'S OWN REFUSAL.
    Claude Code prints this string verbatim when a reason is supplied — its
    own fallback (`Hook PreToolUse:<tool> … this tool`) is used only when the
    reason is EMPTY — so the name has to be in our text or nowhere.
    """
    reason = _rendered(Decision.DENY, "this carries data traced from .env")["permissionDecisionReason"]
    assert "STING" in reason.upper()
    assert "NOT run" in reason or "not run" in reason.lower()


def test_a_denial_carries_the_rule_and_the_way_out_for_the_human():
    """⚠ RE-PINNED (docs/108): in `systemMessage`, which the model does not
    read; the reason the model reads names neither."""
    out = json.loads(claude_code.render(
        Verdict(Decision.DENY, "why", "secret_exact:network_egress")))
    human = out["systemMessage"]
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "secret_exact:network_egress" in human
    assert "policy.json" in human and "allow_once" in human
    assert "policy.json" not in reason and "allow_once" not in reason


def test_an_ask_is_not_dressed_up_as_a_block():
    """An ASK interrupts with a prompt; telling somebody it was BLOCKED when it
    was not is the same lie in the other direction."""
    reason = _rendered(Decision.ASK, "why", "some_rule:sink")["permissionDecisionReason"]
    assert "STING BLOCKED" not in reason.upper()


# ════════════════════ 2.4 · failClosed, the failure this makes catastrophic ══

# ⚠ MEASURED AGAINST A REAL `claude -p --permission-mode manual` SESSION, with a
# stub hook in place of Sting:
#
#     hook exits 2 with stderr   -> "The command never ran — a PreToolUse hook
#                                    blocked it by crashing"        BLOCKED
#     hook prints "{not json"    -> the command RAN                 ⚠ ALLOWED
#     hook prints nothing        -> the command RAN                 ⚠ ALLOWED
#
# So Claude Code fails OPEN on malformed or absent output and fails CLOSED only
# on a non-zero exit. Sting's safety therefore rests entirely on `sting_hook`
# exiting non-zero when anything goes wrong — never on what it writes.

def test_the_hook_exits_non_zero_when_the_decision_path_raises(monkeypatch):
    """⚠ THE ONE THING BETWEEN A DEFECT AND A SILENT ALLOW."""
    import sting_hook

    def explode(_payload, _agent):
        raise RuntimeError("engine blew up")

    monkeypatch.setattr(sting_hook, "decide", explode)
    monkeypatch.setattr(sting_hook, "observing", lambda: False)
    monkeypatch.setattr("sys.stdin", _Stdin("{}"))

    code = sting_hook.main(["--agent", "claude-code"])

    assert code != 0, (
        "a crashing hook exited 0 — Claude Code runs the tool on a zero exit "
        "with no usable output, so this is a silent allow")


def test_a_refused_interpreter_also_exits_non_zero(monkeypatch):
    import sting_hook

    def bail(_payload, _agent):
        raise SystemExit("python 3.10 is below the floor")

    monkeypatch.setattr(sting_hook, "decide", bail)
    monkeypatch.setattr(sting_hook, "observing", lambda: False)
    monkeypatch.setattr("sys.stdin", _Stdin("{}"))

    assert sting_hook.main(["--agent", "claude-code"]) != 0


def test_render_never_emits_anything_but_one_json_object():
    """⚠ MALFORMED OUTPUT WITH EXIT 0 IS A SILENT ALLOW, measured above. The
    only defence is that this function cannot produce it: `json.dumps` of a
    dict, and nothing else on stdout."""
    for decision in (Decision.ALLOW, Decision.DENY, Decision.ASK):
        out = claude_code.render(Verdict(decision, "r\nwith\nnewlines", "x:y"))
        parsed = json.loads(out)                      # raises if malformed
        # ⚠ RE-PINNED (docs/108): a DENY also carries `systemMessage`, the
        # human's way out, in a field the model does not read.
        assert set(parsed) == ({"hookSpecificOutput", "systemMessage"}
                               if decision is Decision.DENY else {"hookSpecificOutput"})
        assert "\n" not in out, (
            "a newline in the payload would let a second line be read as "
            "separate output")


class _Stdin:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text
