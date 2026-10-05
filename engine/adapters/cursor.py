"""
Cursor adapter.

Verified against https://cursor.com/docs/agent/hooks on 7 Aug 2026. Cursor
differs from Claude Code in three ways that matter:

1. Event names are camelCase but FIELD names are snake_case
   (`conversation_id`, `workspace_roots`, `hook_event_name`).
2. The response is flat-ish and uses its own vocabulary:
   `{"permission": "allow|deny|ask", "user_message": ..., "agent_message": ...}`
3. Cursor splits across several events what the others send through one
   PreToolUse, so parse() dispatches on `hook_event_name`.

Events we can be wired to (pre-execution only — the `after*` ones cannot block):
    beforeShellExecution   command, cwd, sandbox            -> EXEC
    beforeReadFile         file_path, content, attachments  -> READ
    beforeMCPExecution     tool_name, tool_input, url|command -> TOOL
    preToolUse             generic, covers everything else
Base fields on every event: conversation_id, generation_id, model, model_id,
model_params, hook_event_name, cursor_version, workspace_roots, user_email,
transcript_path.

Config: .cursor/hooks.json (project), ~/.cursor/hooks.json (user), or the
enterprise paths. Set `failClosed: true` on our entry — Cursor's own docs
recommend it for security-critical hooks, and a guard that fails open is not a
guard.

WHAT CURSOR DOES WITH THE ANSWER — read from its shipped code, Cursor 3.7.27
and cursor-agent 2026.08.04 (docs/110 §A; byte offsets in
tests/test_cursor_honours_the_answer.py):

* ⚠ AN EMPTY STDOUT IS A FAILED HOOK. With `failClosed: true` — what the
  installer writes in enforce mode — Cursor BLOCKS it: "Hook … returned no
  output." So an ALLOW is `{"permission": "allow"}`, never empty. It approves
  nothing Cursor would otherwise ask about: Cursor tests the answer for `deny`
  (AX @3378708, @3395771, @3388928) and, on a shell command, `ask`
  (@3379016), never for `allow`, so its own approval rules run as before — an
  MCP call's included.
* ⚠ `user_message` IS WHAT THE MODEL READS. On a deny Cursor puts it in the
  tool's rejected result, after "… was blocked by a hook:" and before an
  "Agent note" to the model; `agent_message` is never read on these events,
  and none of them has a field only the person reads. So no field carries the
  way out (docs/108 §1).
* ⚠ ASK EXISTS ON `beforeShellExecution` ONLY. On `beforeReadFile` an `ask`
  fails Cursor's schema and it blocks with its own words; on
  `beforeMCPExecution` it is accepted and IGNORED — the MCP call runs. So an
  ASK there is told as the block it is, as Codex's is.
* Only snake_case is read; the camelCase spellings are not.
* There is no `beforeFileEdit`. File edits are pre-execution-visible only
  through the generic `preToolUse`; `afterFileEdit` fires too late to block.
"""
from __future__ import annotations

import json
import os
from dataclasses import replace

from adapters import _common
from core.types import Action, ActionKind, Decision, Verdict

AGENT = "cursor"

# hook_event_name -> what the action is. The generic preToolUse carries no kind
# of its own, so it falls through to the tool-name map below.
_KIND_BY_EVENT = {
    "beforeShellExecution": ActionKind.EXEC,
    "afterShellExecution": ActionKind.EXEC,
    "beforeReadFile": ActionKind.READ,
    "beforeTabFileRead": ActionKind.READ,
    "beforeMCPExecution": ActionKind.TOOL,
    "afterMCPExecution": ActionKind.TOOL,
    "afterFileEdit": ActionKind.EDIT,
    "afterTabFileEdit": ActionKind.EDIT,
}

_KIND_BY_TOOL = {
    "read": ActionKind.READ,
    "read_file": ActionKind.READ,
    "write": ActionKind.WRITE,
    "create_file": ActionKind.WRITE,
    "edit": ActionKind.EDIT,
    "edit_file": ActionKind.EDIT,
    "search_replace": ActionKind.EDIT,
    "apply_patch": ActionKind.EDIT,
    "bash": ActionKind.EXEC,
    "shell": ActionKind.EXEC,
    "run_terminal_cmd": ActionKind.EXEC,
    "fetch": ActionKind.FETCH,
    "web_search": ActionKind.FETCH,
}

# ⚠ `file` IS HERE BECAUSE REAL HOOK CODE FALLS BACK TO IT. Every third-party
# Cursor hook read on this machine resolves a file event as
# `input.path || input.file`, so a payload spelling it `file` is a shape somebody
# has actually met. Missing it costs a SOURCE — an unseen credential read is the
# whole failure this adapter exists to prevent — while a key that never arrives
# costs one dict lookup. See docs/25-cursor-hooks.md.
_PATH_FIELDS = ("file_path", "path", "file", "target_file", "notebook_path")


def _kind_for(event: str, tool_name: str, tool_input: dict) -> ActionKind:
    if event in _KIND_BY_EVENT:
        return _KIND_BY_EVENT[event]
    if tool_name.startswith("mcp__") or tool_name.startswith("mcp_"):
        return ActionKind.TOOL
    known = _KIND_BY_TOOL.get(tool_name.lower())
    if known is not None:
        return known
    # Generic preToolUse with an unrecognised tool: infer from the payload
    # rather than dropping it. An action we cannot classify must still reach
    # the engine. The shared helper, so all five adapters infer alike.
    return _common.inferred_kind(
        _common.shell_command(tool_input, keys=("command",))[0],
        _common.first_str(tool_input, "url")) or ActionKind.TOOL


def parse(raw: dict) -> Action:
    """Any of Cursor's pre-execution events -> Action. Never raises."""
    raw = _common.as_dict(raw)
    event = _common.as_str(raw.get("hook_event_name") or raw.get("hookEventName"))
    tool_name = _common.as_str(raw.get("tool_name") or raw.get("toolName"))
    tool_input = _common.as_dict(raw.get("tool_input") or raw.get("toolInput"))

    # workspace_roots is an ARRAY — multi-root workspaces are supported, so the
    # project is a set of roots, not one prefix. cwd is present on shell events
    # and absent on others; fall back to the first root rather than to os.getcwd(),
    # which would be the hook process's directory and meaningless here.
    declared_roots = _common.workspace_roots(
        raw.get("workspace_roots") or raw.get("workspaceRoots"), "")
    cwd = _common.resolve_cwd(_common.first_str(raw, "cwd")
                               or (declared_roots[0] if declared_roots else None))
    # Every declared root is the project. Fall back to cwd only when Cursor
    # sent none, so a sibling root in a monorepo is never judged "outside".
    roots = declared_roots or _common.workspace_roots(None, cwd)

    session_id = _common.first_str(raw, "conversation_id", "conversationId") or "unknown"

    # Paths and command live at the top level on the dedicated events, and
    # inside tool_input on the generic one.
    path_values = [raw.get(f) for f in _PATH_FIELDS]
    path_values += [tool_input.get(f) for f in _PATH_FIELDS]
    attachments = raw.get("attachments")
    if isinstance(attachments, list):
        path_values += [_common.as_dict(a).get("file_path") for a in attachments]

    # Top level on the dedicated events, inside tool_input on the generic one.
    command, unreadable = _common.shell_command(raw, tool_input, keys=("command",))
    kind = _kind_for(event, tool_name, tool_input)

    return Action(
        session_id=session_id,
        seq=0,                      # not supplied; the session layer assigns it
        kind=kind,
        paths=_common.resolve_paths(path_values, cwd),
        command=command,
        url=_common.first_str(raw, "url") or _common.first_str(tool_input, "url"),
        tool_name=tool_name or event or None,
        # beforeReadFile carries the file's content; a Write/Edit through
        # preToolUse carries it in tool_input.
        content=_common.with_tool_arguments(
            (_common.first_str(tool_input, "content", "new_string", "code")
             or _common.first_str(raw, "content")), tool_name, tool_input),
        cwd=cwd,
        workspace_roots=roots,
        agent=AGENT,
        # The adapter knows its own agent's naming; the engine must not.
        tool_origin="mcp" if (tool_name or "").startswith(("mcp__", "mcp.")) else ("builtin" if kind is ActionKind.TOOL else ""),
        malformed=unreadable if kind is ActionKind.EXEC and command is None else "",
    )


def render(verdict: Verdict, action: Action | None = None) -> str:
    """Verdict -> Cursor's response, a flat snake_case object, always.

    `action` says which event this answers: Cursor can ask only before a shell
    command (`EXEC`); an ASK before a file read or an MCP call is told as the
    block it is. Without an action the answer is the shell event's.
    """
    if verdict.decision is Decision.ALLOW:
        # ⚠ NEVER EMPTY: Cursor reads an empty stdout as a failed hook, and in
        # enforce mode (`failClosed: true`) blocks it.
        return json.dumps({"permission": "allow"})

    can_ask = action is None or action.kind is ActionKind.EXEC
    if verdict.decision is Decision.ASK and not can_ask:
        reason = (f"{_common.told(replace(verdict, decision=Decision.DENY))}\n"
                  f"(Cursor cannot ask before this kind of call, so it is blocked "
                  f"rather than asked)")
        permission = "deny"
    else:
        reason = _common.told(verdict)
        permission = "deny" if verdict.decision is Decision.DENY else "ask"
    # ⚠ NO WAY OUT IN EITHER FIELD: Cursor hands `user_message` to the model,
    # and reads `agent_message` nowhere (module docstring).
    return json.dumps({"permission": permission, "user_message": reason,
                       "agent_message": reason})


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
    """`beforeShellExecution`, which is the event this adapter is wired to.

    ⚠ NOT `preToolUse`. That name does not appear in any real Cursor hooks file
    read on this machine — see docs/25-cursor-hooks.md. A probe that used it
    would prove the adapter against an event Cursor may never send.
    """
    return {"conversation_id": session, "cwd": cwd,
            "hook_event_name": "beforeShellExecution",
            "workspace_roots": [cwd], "command": command}
