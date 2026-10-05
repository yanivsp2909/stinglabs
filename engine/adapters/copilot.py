"""
GitHub Copilot / VS Code adapter.

Verified against https://code.visualstudio.com/docs/agent-customization/hooks
on 7 Aug 2026. This is the closest of the four to Claude Code — deliberately so,
VS Code documents its hook format as compatible with Claude Code and Copilot CLI.

Events (PascalCase): SessionStart, UserPromptSubmit, PreToolUse, PostToolUse,
PreCompact, SubagentStart, SubagentStop, Stop. We wire PreToolUse.

Input (stdin):
    {"timestamp": "...", "session_id": "...", "cwd": "...",
     "hook_event_name": "PreToolUse",
     "tool_name": "bash", "tool_input": {...}}

Output (stdout) — the decision FLAT and NESTED, the same in both (render()):
    {"continue": true,
     "permissionDecision": "deny|ask", "permissionDecisionReason": "...",
     "hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "deny|ask",
                            "permissionDecisionReason": "..."}}
VS Code reads the nested object; the CLI and the cloud agent document the flat
fields (docs/110 §A, tests/test_copilot_honours_the_answer.py).

Config: .github/hooks/*.json — VS Code also reads .claude/settings.json, which
is why the tool-name map below accepts both VS Code's lowercase names and
Claude Code's capitalised ones. The same install can arrive either way.
"""
from __future__ import annotations

import json

from adapters import _common
from core.types import Action, ActionKind, Decision, Verdict

AGENT = "copilot"

# Looked up case-insensitively. Covers VS Code's own tool names and the Claude
# Code names, since a Copilot install may be configured through either file.
_KIND_BY_TOOL = {
    # VS Code / Copilot
    "bash": ActionKind.EXEC,
    "shell": ActionKind.EXEC,
    "run_in_terminal": ActionKind.EXEC,
    "view": ActionKind.READ,
    "read_file": ActionKind.READ,
    "create_file": ActionKind.WRITE,
    "str_replace_editor": ActionKind.EDIT,
    "replace_string_in_file": ActionKind.EDIT,
    "apply_patch": ActionKind.EDIT,
    "insert_edit_into_file": ActionKind.EDIT,
    "fetch_webpage": ActionKind.FETCH,
    # Claude Code spellings
    "read": ActionKind.READ,
    "write": ActionKind.WRITE,
    "edit": ActionKind.EDIT,
    "multiedit": ActionKind.EDIT,
    "notebookedit": ActionKind.EDIT,
    "webfetch": ActionKind.FETCH,
}

_PATH_FIELDS = ("file_path", "filePath", "path", "notebook_path", "uri")
_CONTENT_FIELDS = ("content", "new_string", "newString", "code", "patch")
_COMMAND_FIELDS = ("command", "commandLine")
_URL_FIELDS = ("url", "urls")


def parse(raw: dict) -> Action:
    """Copilot's PreToolUse payload -> Action. Never raises."""
    raw = _common.as_dict(raw)
    tool_name = _common.as_str(raw.get("tool_name") or raw.get("toolName"))
    tool_input = _common.as_dict(raw.get("tool_input") or raw.get("toolInput"))
    cwd = _common.resolve_cwd(_common.first_str(raw, "cwd", "workspaceRoot"))
    session_id = _common.first_str(raw, "session_id", "sessionId") or "unknown"

    command, unreadable = _common.shell_command(tool_input, keys=_COMMAND_FIELDS)
    url = _common.first_str(tool_input, *_URL_FIELDS)
    if tool_name.startswith("mcp__"):
        kind = ActionKind.TOOL
    else:
        # An UNRECOGNISED tool carrying a command is a shell (M1) — the same
        # inference the other four adapters make, from the one shared helper.
        kind = (_KIND_BY_TOOL.get(tool_name.lower())
                or _common.inferred_kind(command, url) or ActionKind.TOOL)

    content_parts = [tool_input.get(f) for f in _CONTENT_FIELDS]
    content = "\n".join(p for p in content_parts if isinstance(p, str)) or None

    return Action(
        session_id=session_id,
        seq=0,                      # not supplied; the session layer assigns it
        kind=kind,
        paths=_common.resolve_paths([tool_input.get(f) for f in _PATH_FIELDS], cwd),
        command=command,
        url=url,
        tool_name=tool_name or None,
        content=_common.with_tool_arguments(content, tool_name, tool_input),
        cwd=cwd,
        # This agent exposes a single directory, so the project is one
        # root. Cursor and Antigravity send arrays; see their adapters.
        workspace_roots=_common.workspace_roots(None, cwd),
        agent=AGENT,
        # The adapter knows its own agent's naming; the engine must not.
        tool_origin="mcp" if (tool_name or "").startswith(("mcp__", "mcp.")) else ("builtin" if kind is ActionKind.TOOL else ""),
        malformed=unreadable if kind is ActionKind.EXEC and command is None else "",
    )


def render(verdict: Verdict, action: Action | None = None) -> str:
    """Verdict -> Copilot's response. ALLOW is the empty string (no decision,
    on every surface).

    ⚠ THE SAME DECISION IN BOTH PLACES (docs/110 §A). VS Code reads ONLY
    `hookSpecificOutput` (chatHookService.ts 388-419); the Copilot CLI and the
    cloud agent document a FLAT top-level `permissionDecision`
    (hooks-reference.md 685-695), and the CLI read the nested one first only
    for a `PreToolUse`-spelled entry (1.0.63). Answering nested only was
    VS Code's shape alone. Each surface reads its own place and passes the
    other through. `continue` stays true: false stops the whole agent turn.
    """
    if verdict.decision is Decision.ALLOW:
        return ""

    decision = "deny" if verdict.decision is Decision.DENY else "ask"
    # No way out: every surface hands this reason to the model (docs/108 §1).
    reason = _common.told(verdict)
    return json.dumps({
        "continue": True,
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })


# ─────────────────────────────────────────────────────── the semantic probe
#
# ⚠ REQUIRED OF EVERY ADAPTER. `tools/preflight.py` drives the I02 sequence —
# read a credential, copy it, commit it, push — through the REAL hook process
# and requires a DENY. Before this existed the check ran for claude-code only
# and printed "skipped" everywhere else, so on the first machine that was not
# Claude Code, the guard against a blind guard did not run.
#
# It returns ONE EXEC action in this vendor's own shape. It is not a fixture:
# it is the adapter's own statement of what its agent sends, and it is what
# lets a new adapter prove itself on the semantic case rather than only on
# shape. See docs/24-adapter-contract.md.

def probe_payload(command: str, *, cwd: str, session: str, step: int = 0) -> dict:
    """Claude Code's envelope with a lowercase tool name — Copilot's shape."""
    return {"session_id": session, "cwd": cwd,
            "hook_event_name": "PreToolUse", "tool_name": "bash",
            "tool_input": {"command": command}}
