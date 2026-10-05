"""GitHub Copilot does what Sting's verdict means, on each surface that reads
Sting's `.github/hooks/hooks.json`.

Item A of fix/agents-block-and-env-reads (docs/110 §A). The functions below
are how each surface reads a PreToolUse hook's (stdout, stderr, exit code),
rebuilt from its code and docs:

    VS Code 1.138.0 "Local" (microsoft/vscode, commit 7debcd0e)
        src/vs/workbench/contrib/chat/…/hookExecutor.ts 141-157: exit 2 blocks
            (stderr is the reason), another non-zero exit fails OPEN, empty
            stdout is no decision, JSON is parsed
        chatHookService.ts 291-332, 384-419: `continue:false`/`stopReason` stop
            the turn; ONLY `hookSpecificOutput` is read — flat keys never are;
            a nested `hookEventName` must be "PreToolUse"; `deny` blocks,
            `ask` asks, anything else is no decision
    Copilot CLI (docs, hooks-reference.md 168-173, 452, 685-695, 846-855;
        source read at 1.0.63 and 1.0.70 — 1.0.89 compiles it)
        exit 2 blocks (since 1.0.70), another non-zero exit or a crash is
        "Denied by preToolUse hook (hook errored)", a timeout fails open;
        the DOCUMENTED answer is FLAT, `permissionDecision` at the top level;
        1.0.63 reads `hookSpecificOutput.permissionDecision` first, and only for
        an entry configured as `PreToolUse`; `ask` asks when it can prompt,
        else denies
    the cloud agent: the CLI's rules, and `ask` is a deny (no one to answer)

What was missing: Sting answered ONLY nested — VS Code's shape. The CLI's
documented contract is flat, so under a `preToolUse` config, or any CLI that
reads what its docs say, a Sting deny said nothing. The answer now carries the
same decision in both places; VS Code reads the nested one and ignores the rest.
"""
from __future__ import annotations

import json

import pytest

from adapters import copilot
from core.types import Decision, Verdict

BLOCKED, ASKED, ALLOWED, FAILED_OPEN, FAILED_CLOSED, STOPPED = (
    "blocked", "asked", "allowed", "failed-open", "failed-closed", "stopped")


def vscode_local(stdout: str, code: int) -> str:
    if code == 2:
        return BLOCKED
    if code != 0:
        return FAILED_OPEN
    if not stdout.strip():
        return ALLOWED
    try:
        obj = json.loads(stdout)
    except ValueError:
        return FAILED_OPEN
    if not isinstance(obj, dict):
        return FAILED_OPEN
    if isinstance(obj.get("hookEventName"), str) and obj["hookEventName"] != "PreToolUse":
        return ALLOWED
    if isinstance(obj.get("stopReason"), str) or obj.get("continue") is False:
        return STOPPED
    nested = obj.get("hookSpecificOutput")
    if not isinstance(nested, dict):
        return ALLOWED
    if isinstance(nested.get("hookEventName"), str) and nested["hookEventName"] != "PreToolUse":
        return ALLOWED
    decision = nested.get("permissionDecision")
    return {"deny": BLOCKED, "ask": ASKED}.get(decision, ALLOWED)


def copilot_cli(stdout: str, code: int, *, pascal_case: bool,
                can_prompt: bool = True) -> str:
    if code == 2:
        return BLOCKED
    if code != 0:
        return FAILED_CLOSED
    if not stdout.strip():
        return ALLOWED
    try:
        obj = json.loads(stdout)
    except ValueError:
        return FAILED_OPEN
    if not isinstance(obj, dict):
        return FAILED_OPEN
    nested = obj.get("hookSpecificOutput") if pascal_case else None
    decision = nested.get("permissionDecision") if isinstance(nested, dict) else None
    if decision is None:
        decision = obj.get("permissionDecision")
    if decision == "deny":
        return BLOCKED
    if decision == "ask":
        return ASKED if can_prompt else BLOCKED
    return ALLOWED


# ─────────────────────────── the fixture reads as the sources say
@pytest.mark.parametrize("stdout,code,expect", [
    ('{"hookSpecificOutput":{"permissionDecision":"deny"}}', 0, BLOCKED),
    ('{"permissionDecision":"deny"}', 0, ALLOWED),                 # flat is never read
    ('{"continue":false}', 0, STOPPED),
    ("", 2, BLOCKED), ("", 1, FAILED_OPEN), ("", 0, ALLOWED),
])
def test_vscode_reads_as_its_source_says(stdout, code, expect):
    assert vscode_local(stdout, code) == expect


@pytest.mark.parametrize("stdout,code,pascal,expect", [
    ('{"permissionDecision":"deny"}', 0, False, BLOCKED),
    ('{"hookSpecificOutput":{"permissionDecision":"deny"}}', 0, False, ALLOWED),
    ('{"hookSpecificOutput":{"permissionDecision":"deny"}}', 0, True, BLOCKED),
    ("", 1, True, FAILED_CLOSED), ("", 2, True, BLOCKED),
])
def test_the_cli_reads_as_its_docs_and_source_say(stdout, code, pascal, expect):
    assert copilot_cli(stdout, code, pascal_case=pascal) == expect


# ─────────────────────────── what the adapter writes
DENY = Verdict(Decision.DENY, "this sends the file off the machine",
               "untrusted_unexpected:network_egress")
ASK = Verdict(Decision.ASK, "this cannot be undone", "irreversible_action")


@pytest.mark.parametrize("verdict,expect", [(DENY, BLOCKED), (ASK, ASKED)],
                         ids=["deny", "ask"])
def test_every_surface_honours_the_answer(verdict, expect):
    out = copilot.render(verdict)
    assert vscode_local(out, 0) == expect
    assert copilot_cli(out, 0, pascal_case=True) == expect
    assert copilot_cli(out, 0, pascal_case=False) == expect          # the documented shape
    cloud = copilot_cli(out, 0, pascal_case=True, can_prompt=False)
    assert cloud == BLOCKED


def test_an_allow_is_allowed_everywhere():
    out = copilot.render(Verdict(Decision.ALLOW, None, None))
    assert vscode_local(out, 0) == ALLOWED
    assert copilot_cli(out, 0, pascal_case=False) == ALLOWED


def test_the_two_places_say_the_same_thing():
    rendered = json.loads(copilot.render(DENY))
    nested = rendered["hookSpecificOutput"]
    assert nested["hookEventName"] == "PreToolUse"
    assert rendered["permissionDecision"] == nested["permissionDecision"] == "deny"
    assert rendered["permissionDecisionReason"] == nested["permissionDecisionReason"]
    assert "allow_once" not in rendered["permissionDecisionReason"]
