"""A Sting DENY blocks on Codex: the adapter answers in the shape Codex reads.

⚠ CONFIRMED LIVE, 29 SEP 2026, Codex 0.156.1. In a scratch repo Codex ran
`mkdir -p .github/hooks && echo '{}' > .github/hooks/hooks.json`; Sting logged
`codex DENY installed_guard:guard_selfmod`; the file was created. The adapter
answered FLAT, `{"permissionDecision": "deny", …}`, as its docstring guessed
from third-party write-ups, and Codex reads no such key (docs/108 §5). (The
same machine's `~/.sting/policy.json` also relaxes that rule to `allow`, which
alone let the second probe, at 13:52 under 0.158.0, through: docs/110 §A.)

`codex_pre_tool_use` below is Codex's own reading of a PreToolUse hook's
stdout, rebuilt from its source at `rust-v0.156.1` (b412ff3). The three files
are identical at `rust-v0.158.0` (064c6b8):

    codex-rs/hooks/src/schema.rs
      87-99    HookUniversalOutputWire: continue, stopReason, suppressOutput,
               systemMessage; camelCase, deny_unknown_fields
      101-126  HookEventNameWire: the eleven event names
      127-140  PreToolUseCommandOutputWire: the universal fields flattened, then
               decision, reason, hookSpecificOutput; deny_unknown_fields
      241-255  PreToolUseHookSpecificOutputWire: hookEventName (required),
               permissionDecision, permissionDecisionReason, updatedInput,
               additionalContext; deny_unknown_fields
      258-273  permissionDecision allow|deny|ask; decision approve|block
    codex-rs/hooks/src/engine/output_parser.rs
      121-182  parse_pre_tool_use     345-358  parse_json (an object, or None)
      360-363  looks_like_json        369-379  continue:false, stopReason and
      441-482  the hookSpecificOutput          suppressOutput are unsupported
               decision's rules       484-507  the legacy decision's rules
      514-521  trimmed_reason         531-546  a test: `{"unexpectedField":
                                               true}` is refused
    codex-rs/hooks/src/events/pre_tool_use.rs
      214-259  exit 0: a parse with a block reason is Blocked (should_block);
               an invalid one, or JSON that does not parse, is Failed and does
               NOT block; empty stdout is nothing
    codex-rs/core/src/hook_runtime.rs
      222-236  a block reaches the model as "Command blocked by PreToolUse
               hook: {reason}. Command: {command}"

It is checked first against Codex's own expectations (pre_tool_use.rs, the
tests at 362, 393, 443, 490, 521, 561, 590, 621, 677), then applied to what the
adapter writes.
"""
from __future__ import annotations

import json

import pytest

from adapters import codex
from core.types import Decision, Verdict

EVENTS = {"PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact",
          "SessionStart", "UserPromptSubmit", "SubagentStart", "SubagentStop", "Stop",
          "Interrupt"}
_TOP = {"continue", "stopReason", "suppressOutput", "systemMessage", "decision", "reason",
        "hookSpecificOutput"}
_SPECIFIC = {"hookEventName", "permissionDecision", "permissionDecisionReason",
             "updatedInput", "additionalContext"}


class _Refused(Exception):
    """serde refused the JSON: `parse_json` returns None."""


def _optional(value, kind, allowed=None):
    if value is None:
        return None
    if not isinstance(value, kind) or (allowed is not None and value not in allowed):
        raise _Refused
    return value


def _wire(text: str) -> dict:
    """`parse_json` into the wire structs, or _Refused (schema.rs 87-140, 241-273)."""
    try:
        value = json.loads(text)
    except ValueError:
        raise _Refused from None
    if not isinstance(value, dict) or set(value) - _TOP:
        raise _Refused                                   # deny_unknown_fields
    for key in ("continue", "suppressOutput"):
        if key in value and not isinstance(value[key], bool):
            raise _Refused
    _optional(value.get("stopReason"), str)
    _optional(value.get("systemMessage"), str)
    _optional(value.get("reason"), str)
    _optional(value.get("decision"), str, {"approve", "block"})
    specific = value.get("hookSpecificOutput")
    if specific is not None:
        if (not isinstance(specific, dict) or set(specific) - _SPECIFIC
                or specific.get("hookEventName") not in EVENTS):
            raise _Refused
        _optional(specific.get("permissionDecision"), str, {"allow", "deny", "ask"})
        _optional(specific.get("permissionDecisionReason"), str)
        _optional(specific.get("additionalContext"), str)
    return value


def _trimmed(reason):
    return reason.strip() or None if isinstance(reason, str) else None


def _invalid(value: dict, specific: dict | None, use_specific: bool) -> bool:
    """output_parser.rs 137-143 with 369-379, 441-482 and 484-507."""
    if value.get("continue") is False or value.get("stopReason") is not None \
            or value.get("suppressOutput") is True:
        return True
    if use_specific:
        decision = specific.get("permissionDecision")
        if specific.get("updatedInput") is not None and decision != "allow":
            return True
        if decision == "allow":
            return specific.get("updatedInput") is None
        if decision == "ask":
            return True
        if decision == "deny":
            return _trimmed(specific.get("permissionDecisionReason")) is None
        return specific.get("permissionDecisionReason") is not None
    decision = value.get("decision")
    if decision == "approve":
        return True
    if decision == "block":
        return _trimmed(value.get("reason")) is None
    return value.get("reason") is not None


def codex_pre_tool_use(stdout: str) -> tuple[str, str | None]:
    """(status, block_reason) for an exit-0 PreToolUse hook: "Blocked" (the
    call does not run), "Failed" (it does), or "Completed" (it does)."""
    if not stdout.strip():
        return "Completed", None
    try:
        value = _wire(stdout.strip())
    except _Refused:
        return ("Failed", None) if stdout.lstrip()[:1] in ("{", "[") else ("Completed", None)
    specific = value.get("hookSpecificOutput")
    use_specific = specific is not None and any(
        specific.get(k) is not None for k in ("permissionDecision",
                                               "permissionDecisionReason", "updatedInput"))
    if _invalid(value, specific, use_specific):
        return "Failed", None
    if use_specific:
        reason = (_trimmed(specific.get("permissionDecisionReason"))
                  if specific.get("permissionDecision") == "deny" else None)
    else:
        reason = _trimmed(value.get("reason")) if value.get("decision") == "block" else None
    return ("Blocked", reason) if reason else ("Completed", None)


# ──────────────────────────────── the fixture reads as Codex's own tests say
CODEX_OWN = [
    (362, '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'
          '"permissionDecisionReason":"do not run that"}}', "Blocked"),
    (393, '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow",'
          '"updatedInput":{"command":"echo rewritten"}}}', "Completed"),
    (443, '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow",'
          '"additionalContext":"preserved"}}', "Failed"),
    (490, '{"decision":"block","reason":"do not run that"}', "Blocked"),
    (521, '{"decision":"block","reason":"do not run that","hookSpecificOutput":'
          '{"hookEventName":"PreToolUse","additionalContext":"remember this"}}', "Blocked"),
    (561, '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask",'
          '"permissionDecisionReason":"please confirm"}}', "Failed"),
    (590, '{"decision":"approve"}', "Failed"),
    (621, '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'
          '"permissionDecisionReason":"do not run that","additionalContext":"nope"}}', "Blocked"),
    (677, '{"decision":\n', "Failed"),
    ("output_parser 539", '{"unexpectedField":true}', "Failed"),
]


@pytest.mark.parametrize("line,stdout,status", CODEX_OWN, ids=[str(c[0]) for c in CODEX_OWN])
def test_the_fixture_reads_as_codex_says_it_does(line, stdout, status):
    assert codex_pre_tool_use(stdout)[0] == status


# ─────────────────────────────────────────────── what the adapter writes
DENY = Verdict(Decision.DENY, "this writes the project's .github/hooks/hooks.json",
               "installed_guard:guard_selfmod", evidence="@27 …")
ASK = Verdict(Decision.ASK, "this cannot be undone — `git reset --hard` discards work",
              "irreversible_action")


def test_a_deny_blocks_on_codex():
    status, reason = codex_pre_tool_use(codex.render(DENY))
    assert status == "Blocked"
    assert "Don't retry, split or re-encode this." in reason


def test_an_ask_blocks_on_codex_which_cannot_ask():
    """Codex marks `permissionDecision: "ask"` unsupported and runs the call
    (output_parser.rs 458-460; pre_tool_use.rs test 561). A guard that wanted a
    person must not fall through, so an ASK is a block, and says so."""
    status, reason = codex_pre_tool_use(codex.render(ASK))
    assert status == "Blocked"
    assert "Codex cannot prompt for confirmation" in reason


def test_a_deny_with_no_reason_still_blocks():
    """A deny whose reason trims to nothing is invalid, and invalid runs the
    call (output_parser.rs 461-468)."""
    assert codex_pre_tool_use(codex.render(Verdict(Decision.DENY, None, None)))[0] == "Blocked"


def test_an_allow_is_no_opinion():
    assert codex_pre_tool_use(codex.render(Verdict(Decision.ALLOW, None, None))) == (
        "Completed", None)


def test_the_live_probe_blocks_through_the_hook(tmp_path):
    """The command the maintainer's probe ran, through the real pipeline with the codex
    adapter, in a temp home (conftest): the engine's DENY now blocks."""
    import hook_entry
    payload = {"session_id": "codex-probe", "cwd": str(tmp_path), "tool_name": "Bash",
               "tool_input": {"command": "mkdir -p .github/hooks && echo '{}' > "
                                         ".github/hooks/hooks.json"}}
    out, _err, code = hook_entry.run(json.dumps(payload), agent="codex")
    assert code == 0
    status, reason = codex_pre_tool_use(out)
    assert status == "Blocked", out
    assert "allow_once" not in reason and "policy.json" not in reason
