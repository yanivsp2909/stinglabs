"""Cursor does what Sting's verdict means, on every event Sting wires.

Item A of fix/agents-block-and-env-reads (docs/110 §A, docs/probe-agents.md).

`cursor_outcome` below is how Cursor turns a hook's (stdout, stderr, exit code)
into a decision on `beforeShellExecution`, `beforeReadFile` and
`beforeMCPExecution`, rebuilt from its shipped code — Cursor 3.7.27 (IDE,
commit e48ee61) and cursor-agent 2026.08.04 (CLI) — byte offsets into
`/Applications/Cursor.app/Contents/Resources/app/`:

    R1  timeout 60 s → deny if failClosed, else fail open
            out/vs/workbench/workbench.desktop.main.js (WB) @23147249 `Wth=60`
    R3  exit 2 blocks whatever failClosed says; stdout is read as TEXT
            WB @38276205, @23146363
    R4  another non-zero exit, or EMPTY stdout on exit 0 → deny if failClosed,
        else fail open                  WB @38276462, @38276915 ("returned no output.")
    R5  strict JSON.parse of the trimmed stdout (IDE)      WB @38240470
    R6  invalid JSON or a failed schema check → deny, failClosed or not
            WB @23145742, @38277298, @38278040
    R7  permission ∈ {allow, deny, ask} on shell and MCP, {allow, deny} on read
            WB @23138316 beforeCommandExecutionHookResponse.ts,
               @23139446 beforeReadFileResponse.ts
    R8  deny blocks; `user_message` goes into the result the AGENT reads,
        `agent_message` is never read  extensions/cursor-agent-exec/dist/main.js
            (AX) @3378708, @3395771, @3388928, @3371506 ("… was blocked by a
            hook: <user_message> … Agent note: Do not suggest workarounds …")
    R10 ask forces the approval prompt on shell; after beforeMCPExecution only
        `deny` is tested, so an ask RUNS the MCP call   AX @3379016, @3388928

What was wrong (docs/110 §A): an ALLOW was empty stdout, which Cursor reads as
a failed hook and, with the `failClosed: true` the installer writes in enforce
mode, BLOCKS; an ASK on an MCP call ran it; the way out (the `policy.json`
line, the allow-once command) sat in `user_message`, which the model reads.
"""
from __future__ import annotations

import json

import pytest

import hook_entry
from adapters import cursor
from core.types import Action, ActionKind, Decision, Verdict

ALLOWED_PERMISSIONS = {"beforeShellExecution": ("allow", "deny", "ask"),
                       "beforeMCPExecution": ("allow", "deny", "ask"),
                       "beforeReadFile": ("allow", "deny")}
STRING_FIELDS = {"beforeShellExecution": ("user_message", "agent_message"),
                 "beforeMCPExecution": ("user_message", "agent_message"),
                 "beforeReadFile": ("user_message",)}
LABEL = {"beforeShellExecution": "Command execution", "beforeReadFile": "File read",
         "beforeMCPExecution": "MCP tool execution"}


def cursor_outcome(event: str, stdout: str, exit_code: int, *,
                   fail_closed: bool) -> tuple[str, str | None]:
    """(blocked | asked | allowed | failed-open | failed-closed, the text the
    agent is handed or the approval prompt's reason)."""
    if exit_code == 2:                                                   # R3
        return "blocked", f"{LABEL[event]} was blocked by a hook: {stdout.strip()}"
    if exit_code != 0:                                                   # R4
        return ("failed-closed", None) if fail_closed else ("failed-open", None)
    text = stdout.strip()
    if not text:                                                         # R4
        return ("failed-closed", None) if fail_closed else ("failed-open", None)
    try:
        response = json.loads(text)                                      # R5
    except ValueError:
        return "failed-closed", None                                     # R6
    if not isinstance(response, dict) or (                               # R7
            "permission" in response
            and response["permission"] not in ALLOWED_PERMISSIONS[event]) or not all(
            isinstance(response[k], str) for k in STRING_FIELDS[event] if k in response):
        return "failed-closed", None                                     # R6
    message = response.get("user_message")
    if response.get("permission") == "deny":                             # R8
        return "blocked", f"{LABEL[event]} was blocked by a hook: {message}"
    if response.get("permission") == "ask" and event == "beforeShellExecution":
        return "asked", f"Hook requested approval: {message}"            # R10
    return "allowed", None                                               # R10: MCP ask runs


# ───────────────────────────── the fixture reads as Cursor's own code says
@pytest.mark.parametrize("event,stdout,code,fail_closed,outcome", [
    ("beforeShellExecution", '{"permission":"deny","user_message":"no"}', 0, True, "blocked"),
    ("beforeShellExecution", '{"permission":"ask","user_message":"sure?"}', 0, True, "asked"),
    ("beforeShellExecution", "", 0, True, "failed-closed"),
    ("beforeShellExecution", "", 0, False, "failed-open"),
    ("beforeShellExecution", "", 2, False, "blocked"),
    ("beforeShellExecution", "{}", 0, True, "allowed"),
    ("beforeShellExecution", '{"permission":"allow"}', 0, True, "allowed"),
    ("beforeShellExecution", "not json", 0, False, "failed-closed"),
    ("beforeReadFile", '{"permission":"ask"}', 0, False, "failed-closed"),
    ("beforeReadFile", '{"permission":"deny","user_message":null}', 0, False, "failed-closed"),
    ("beforeMCPExecution", '{"permission":"ask"}', 0, True, "allowed"),
])
def test_the_fixture_reads_as_cursors_code_says(event, stdout, code, fail_closed, outcome):
    assert cursor_outcome(event, stdout, code, fail_closed=fail_closed)[0] == outcome


# ───────────────────────────── what the adapter writes, event by event
def _action(kind: ActionKind, tool: str) -> Action:
    return Action("c", 1, kind, (), "ls" if kind is ActionKind.EXEC else None, None,
                  tool, None, "/w", ("/w",), "cursor")


EVENTS = {"beforeShellExecution": _action(ActionKind.EXEC, "beforeShellExecution"),
          "beforeReadFile": _action(ActionKind.READ, "beforeReadFile"),
          "beforeMCPExecution": _action(ActionKind.TOOL, "mcp__github__create_issue")}
DENY = Verdict(Decision.DENY, "this sends the file off the machine",
               "untrusted_unexpected:network_egress")
ASK = Verdict(Decision.ASK, "this cannot be undone", "irreversible_action")
ALLOW = Verdict(Decision.ALLOW, None, None)


@pytest.mark.parametrize("event", list(EVENTS))
@pytest.mark.parametrize("fail_closed", [True, False], ids=["enforce", "observe-shaped"])
def test_an_allow_is_allowed(event, fail_closed):
    outcome, _ = cursor_outcome(event, cursor.render(ALLOW, EVENTS[event]), 0,
                                fail_closed=fail_closed)
    assert outcome == "allowed"


@pytest.mark.parametrize("event", list(EVENTS))
def test_a_deny_blocks_and_names_no_way_out(event):
    outcome, text = cursor_outcome(event, cursor.render(DENY, EVENTS[event]), 0,
                                   fail_closed=True)
    assert outcome == "blocked"
    assert "sends the file off the machine" in text
    for way_out in ("allow_once", "policy.json", "untrusted_unexpected:network_egress"):
        assert way_out not in text, text


def test_an_ask_on_a_shell_command_asks():
    outcome, text = cursor_outcome("beforeShellExecution",
                                   cursor.render(ASK, EVENTS["beforeShellExecution"]), 0,
                                   fail_closed=True)
    assert outcome == "asked" and "cannot be undone" in text


@pytest.mark.parametrize("event", ["beforeReadFile", "beforeMCPExecution"])
def test_an_ask_where_cursor_cannot_ask_is_a_block_that_says_why(event):
    """MCP: Cursor ignores `ask` and runs the call. Read: `ask` fails Cursor's
    schema and Cursor blocks with its own words. Both are told as the block
    they are, in Sting's words — as Codex's are."""
    outcome, text = cursor_outcome(event, cursor.render(ASK, EVENTS[event]), 0,
                                   fail_closed=True)
    assert outcome == "blocked"
    assert "cannot be undone" in text and "Cursor cannot ask" in text


def test_the_verdict_reaches_cursor_through_the_real_hook(tmp_path, monkeypatch):
    """hook_entry → the adapter, with the event's own payload: an allowed
    command is allowed in enforce mode."""
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path / "s"))
    monkeypatch.setenv("STING_LOG", str(tmp_path / "s" / "decisions.jsonl"))
    policy = tmp_path / "p.json"
    policy.write_text('{"shipped_default": false}')
    monkeypatch.setenv("STING_POLICY", str(policy))
    payload = json.dumps({"conversation_id": "c9", "hook_event_name": "beforeShellExecution",
                          "command": "ls", "cwd": str(tmp_path),
                          "workspace_roots": [str(tmp_path)]})
    out, _err, code = hook_entry.run(payload, "cursor")
    assert cursor_outcome("beforeShellExecution", out, code, fail_closed=True)[0] == "allowed"
