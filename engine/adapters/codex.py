"""
OpenAI Codex CLI adapter.

⚠ THE LEAST VERIFIED OF THE FOUR. Read this before trusting it.

OpenAI does not publish the PreToolUse stdin schema. Neither the Codex config
docs nor the agent-approvals-security page cover it; only third-party write-ups
do, and those disagree on details. So `parse()` here is deliberately defensive:
it accepts snake_case and camelCase spellings of every field, and infers the
kind from the payload when the tool name is unfamiliar. **Verify against a real
Codex session before quoting any result from this adapter.**

Events: PreToolUse, PostToolUse. PreToolUse intercepts Bash, file edits made
through `apply_patch`, and MCP tool calls. It can only deny — it cannot modify
tool input.

Output — NESTED, as Codex's own source reads it (docs/108 §5):
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": "..."}}
Empty stdout means no opinion.

⚠ IT USED TO BE FLAT, AND A FLAT DENY NEVER BLOCKED. This docstring said
`{"permissionDecision": "deny", …}` at the top level, from third-party
write-ups. Codex 0.156.1's wire struct refuses unknown top-level fields
(`codex-rs/hooks/src/schema.rs` 127-140, `deny_unknown_fields`), a refused
parse is a FAILED hook run, and a failed run lets the call through
(`codex-rs/hooks/src/events/pre_tool_use.rs` 253-259). Confirmed live on 29
Sep 2026 (01:58, Codex 0.156.1): Codex created `.github/hooks/hooks.json`
under a logged DENY. `tests/test_codex_reads_the_block.py` applies Codex's
parsing, rebuilt from that source (identical at 0.158.0), to what this file
writes.

⚠ AND THE SECOND LIVE PROBE WAS NOT THIS FILE (docs/110 §A). At 13:52 the
same command ran again under Codex 0.158.0 with this nested answer installed.
Its record says DENY and lists `installed_guard:guard_selfmod` as RELAXED: the
Mac's `~/.sting/policy.json` sets that rule to `allow`, so the hook answered
nothing — an ALLOW — and Codex did as told. Run through this checkout's hook
in a temp home, the same payload prints the 470-byte nested deny without that
file and nothing with a copy of it. The 01:58 probe had both causes.

⚠ ONLY `deny` BLOCKS, AND ONLY WITH A NON-EMPTY REASON. `ask` is "unsupported"
(output_parser.rs 458-460) and an empty reason is invalid (461-468): both are
failed runs, and both let the call through. Our ASK is therefore rendered as
`deny`. That is the safe direction: a guard that wanted a human in the loop and
could not get one must not silently proceed. It does mean Codex users see a
hard block where other agents would see a prompt — a real product difference,
not a bug to paper over.

Config: .codex/hooks.json, ~/.codex/hooks.json, or [hooks] in config.toml.
One source says `[features] codex_hooks = true` is required (v0.114, Mar 2026),
another says hooks are GA — unresolved, so check config.toml if the hook never
fires.
"""
from __future__ import annotations

import json
from dataclasses import replace

from adapters import _common
from core.types import Action, ActionKind, Decision, Verdict

AGENT = "codex"

_KIND_BY_TOOL = {
    "bash": ActionKind.EXEC,
    "shell": ActionKind.EXEC,
    "local_shell": ActionKind.EXEC,
    "exec_command": ActionKind.EXEC,
    "apply_patch": ActionKind.EDIT,
    "edit": ActionKind.EDIT,
    "write_file": ActionKind.WRITE,
    "create_file": ActionKind.WRITE,
    "read_file": ActionKind.READ,
    "view": ActionKind.READ,
    "web_search": ActionKind.FETCH,
    "fetch": ActionKind.FETCH,
}

_PATH_FIELDS = ("file_path", "filePath", "path", "target_file")
_COMMAND_FIELDS = ("command", "commandLine", "cmd")


def _kind_for(tool_name: str, tool_input: dict) -> ActionKind:
    if tool_name.startswith("mcp__") or tool_name.startswith("mcp_"):
        return ActionKind.TOOL
    known = _KIND_BY_TOOL.get(tool_name.lower())
    if known is not None:
        return known
    # Schema is unpublished, so infer from what the payload actually carries
    # rather than dropping an action we cannot name. `local_shell` may send its
    # command as an argv LIST, which counts (the shared helper joins it).
    inferred = _common.inferred_kind(
        _common.shell_command(tool_input, keys=_COMMAND_FIELDS)[0],
        _common.first_str(tool_input, "url"))
    if inferred is not None:
        return inferred
    if _common.first_str(tool_input, *_PATH_FIELDS):
        return ActionKind.EDIT if _common.first_str(
            tool_input, "content", "new_string", "patch") else ActionKind.READ
    return ActionKind.TOOL


def parse(raw: dict) -> Action:
    """Codex's PreToolUse payload -> Action. Never raises.

    Every field is read through both spellings because the schema is not
    published and the write-ups disagree.
    """
    raw = _common.as_dict(raw)
    tool_name = _common.as_str(raw.get("tool_name") or raw.get("toolName"))
    tool_input = _common.as_dict(
        raw.get("tool_input") or raw.get("toolInput") or raw.get("arguments"))
    cwd = _common.resolve_cwd(
        _common.first_str(raw, "cwd", "workingDirectory", "working_directory")
        or _common.first_str(tool_input, "cwd", "workdir"))
    session_id = _common.first_str(
        raw, "session_id", "sessionId", "conversation_id", "conversationId") or "unknown"

    content = _common.first_str(tool_input, "content", "new_string", "newString", "patch")
    command, unreadable = _common.shell_command(tool_input, keys=_COMMAND_FIELDS)
    kind = _kind_for(tool_name, tool_input)

    return Action(
        session_id=session_id,
        seq=0,                      # not supplied; the session layer assigns it
        kind=kind,
        paths=_common.resolve_paths([tool_input.get(f) for f in _PATH_FIELDS], cwd),
        command=command,
        url=_common.first_str(tool_input, "url"),
        tool_name=tool_name or None,
        content=_common.with_tool_arguments(content, tool_name, tool_input),
        # ⚠ AN MCP CALL'S ARGUMENTS, WHOLE (docs/112 §3). Established at
        # rust-v0.158.0: `McpHandler::pre_tool_use_payload` sends `tool_name`
        # `mcp__<server>__<tool>` (`ensure_mcp_prefix`) and `tool_input` =
        # the arguments parsed from JSON — a plain STRING when they are not
        # JSON (`mcp_hook_tool_input`), which is then not visible whole.
        tool_arguments=_common.complete_tool_arguments(
            tool_name, next((raw[k] for k in ("tool_input", "toolInput", "arguments")
                             if k in raw), None)),
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
    """Verdict -> Codex's response. ALLOW is the empty string.

    ASK renders as deny. Codex honours no other blocking value, and a guard
    that wanted confirmation but could not ask for it must not fall through to
    allow.
    """
    if verdict.decision is Decision.ALLOW:
        return ""

    # ⚠ AN ASK IS TOLD AS THE BLOCK IT IS HERE: Codex cannot ask, so "approve
    # only if…" would name a choice nobody is given. No way out: Codex has no
    # field the model cannot read (docs/108 §1).
    reason = _common.told(replace(verdict, decision=Decision.DENY))
    if verdict.decision is Decision.ASK:
        # Say so in the reason, so the developer understands why they got a
        # hard block where another agent would have prompted.
        reason = (f"{reason}\n(Codex cannot prompt for confirmation, so this is "
                  f"blocked rather than asked)").strip()

    # ⚠ NESTED, AND NEVER AN EMPTY REASON: a deny Codex cannot read, or one
    # whose reason trims to nothing, is a failed hook run, and a failed run
    # lets the call through (see the module docstring).
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason or "Sting blocked this.",
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
    """Codex sends no `hook_event_name`; the tool name carries the kind."""
    return {"session_id": session, "cwd": cwd, "tool_name": "bash",
            "tool_input": {"command": command}}
