"""
Claude Code adapter — the reference implementation.

Two jobs, no others:
    parse(raw)      the agent's PreToolUse payload  -> Action
    render(verdict) Verdict -> the agent's expected response string

No policy logic. Ever. If this file ever needs to know *why* something was
denied, the boundary is wrong — fix the boundary rather than adding a case here.

Input shape (PreToolUse, on stdin):
    {"session_id": "...", "cwd": "/workspace/project",
     "hook_event_name": "PreToolUse",
     "tool_name": "Bash", "tool_input": {"command": "git push origin main"}}

Output shape — nested, and specific to this agent. Antigravity's is flat, which
is why render() has to be genuinely per-adapter rather than shared.
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": "..."}}

ALLOW renders as the empty string: print nothing, exit 0, agent proceeds.
"""
from __future__ import annotations

import json

from adapters import _common
from core.types import Action, ActionKind, Decision, Verdict

AGENT = "claude-code"

# Claude Code's tool names -> what the action actually does. Anything not listed
# falls through to TOOL with its name preserved, so an unrecognised tool still
# reaches the engine instead of being silently dropped.
_KIND_BY_TOOL = {
    "Read": ActionKind.READ,
    "Write": ActionKind.WRITE,
    "Edit": ActionKind.EDIT,
    "MultiEdit": ActionKind.EDIT,
    "NotebookEdit": ActionKind.EDIT,
    "Bash": ActionKind.EXEC,
    "WebFetch": ActionKind.FETCH,
    # A search pulls external text into the session exactly as a fetch does;
    # the only difference is that the agent does not name the destination.
    # Omitting it meant a "search the web" scenario reached the engine as an
    # opaque TOOL with no url, no query and no content — the session could not
    # become UNTRUSTED, so D02's `must_block: any request to backup-configs.io`
    # was unreachable through that path. Every other adapter already maps its
    # equivalent (antigravity `search_web`, codex and cursor `web_search`).
    "WebSearch": ActionKind.FETCH,
}

# Where a search carries its terms. A search has no `url`, so without this the
# action reaches the engine carrying nothing at all — and two different searches
# then produce the SAME allow_once fingerprint, because kind, paths, command and
# url are identical and empty for both. A grant for one search would be
# spendable on any other.
_QUERY_FIELDS = ("query", "q", "search_query")

# Where each tool carries a filesystem path.
_PATH_FIELDS = ("file_path", "notebook_path", "path")


def _extract_paths(tool_input: dict, cwd: str) -> tuple[str, ...]:
    found = [tool_input.get(field) for field in _PATH_FIELDS]
    # MultiEdit carries a list of edits, each potentially with its own path.
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        found += [_common.as_dict(e).get("file_path") for e in edits]
    return _common.resolve_paths(found, cwd)


def _extract_content(tool_input: dict) -> str | None:
    """The WRITE/EDIT payload, for fingerprint matching.

    Edit carries new_string; Write carries content; MultiEdit carries a list.
    All of them are bytes that could contain a secret, so all of them count.
    """
    parts = []
    for field in ("content", "new_string", "new_source"):
        value = tool_input.get(field)
        if isinstance(value, str):
            parts.append(value)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict):
                value = edit.get("new_string")
                if isinstance(value, str):
                    parts.append(value)
    return "\n".join(parts) if parts else None


def _extract_replaced(tool_input: dict) -> str | None:
    """The text an Edit or MultiEdit replaces: `old_string`, one per edit."""
    parts = []
    value = tool_input.get("old_string")
    if isinstance(value, str):
        parts.append(value)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict) and isinstance(edit.get("old_string"), str):
                parts.append(edit["old_string"])
    return "\n".join(parts) if parts else None


def parse(raw: dict) -> Action:
    """Claude Code's payload -> Action. Never raises.

    Malformed input yields a degenerate but well-formed Action (kind=TOOL, the
    raw tool name preserved) rather than an exception, because an action that
    fails to parse must still reach the engine. Dropping it would be a bypass.
    """
    raw = _common.as_dict(raw)
    tool_name = _common.as_str(raw.get("tool_name"))
    tool_input = _common.as_dict(raw.get("tool_input"))
    cwd = _common.resolve_cwd(_common.first_str(raw, "cwd"))
    session_id = _common.first_str(raw, "session_id") or "unknown"

    command, unreadable = _common.shell_command(tool_input, keys=("command",))
    url = _common.opt_str(tool_input.get("url"))
    if tool_name.startswith("mcp__"):
        kind = ActionKind.TOOL
    else:
        # An UNRECOGNISED tool carrying a command is a shell (M1) — the same
        # inference the other four adapters make, from the one shared helper.
        kind = (_KIND_BY_TOOL.get(tool_name)
                or _common.inferred_kind(command, url) or ActionKind.TOOL)

    return Action(
        session_id=session_id,
        # Claude Code does not supply a sequence number; the session layer
        # assigns one. Antigravity does supply stepIdx — see its adapter.
        seq=0,
        kind=kind,
        paths=_extract_paths(tool_input, cwd),
        command=command,
        url=url,
        # Kept for every kind, not just TOOL: it is the only record of which
        # tool produced an action the engine classified as TOOL by fallback.
        tool_name=tool_name or None,
        # A search's terms ARE its payload — the text it will pull in is
        # selected by them, and they are the only thing distinguishing one
        # search from another.
        content=_common.with_tool_arguments(
            _extract_content(tool_input) or _common.first_str(tool_input, *_QUERY_FIELDS),
            tool_name, tool_input),
        cwd=cwd,
        replaced=_extract_replaced(tool_input),
        # This agent exposes a single directory, so the project is one
        # root. Cursor and Antigravity send arrays; see their adapters.
        workspace_roots=_common.workspace_roots(None, cwd),
        agent=AGENT,
        # The adapter knows its own agent's naming; the engine must not.
        tool_origin="mcp" if (tool_name or "").startswith("mcp__") else ("builtin" if kind is ActionKind.TOOL else ""),
        malformed=unreadable if kind is ActionKind.EXEC and command is None else "",
        # ⚠ AN MCP CALL'S ARGUMENTS, WHOLE (docs/112 §3). Established: every MCP
        # call fires PreToolUse as `mcp__<server>__<tool>` with its arguments
        # object as `tool_input` (docs hooks.md, "MCP tools"). The raw value,
        # not `as_dict`'s: anything but an object is not visible whole.
        tool_arguments=_common.complete_tool_arguments(tool_name, raw.get("tool_input")),
    )


def _stings_own(verdict: Verdict) -> str:
    """The refusal text, prefixed so it is obviously STING's.

    ⚠ THE OPERATOR'S SECOND SYMPTOM: "when Sting denies something I want to SEE
    a message from Sting saying it was denied and stopped." Claude Code prints
    `permissionDecisionReason` VERBATIM when one is supplied — its own fallback,
    `Hook PreToolUse:<tool> … this tool`, is used only when the reason is EMPTY
    — so the name has to be in our text or it appears nowhere, and the refusal
    reads as the agent's own.

    ⚠ HERE AND NOT IN `_common.told`, WHICH ALL FIVE ADAPTERS SHARE.
    Cursor, Codex, Copilot and Antigravity have never been driven with a real
    payload from their vendor; changing the text every one of them emits, on
    evidence gathered from one, is how a fix becomes four regressions. Only the
    prefix is agent-specific — what the agent is told, and the human's way out,
    are still composed once, in `_common`.

    Prefixed on a DENY only: an ASK already interrupts with a prompt, and
    telling somebody they were BLOCKED when they were not is the same lie in
    the other direction.
    """
    text = _common.told(verdict)
    if verdict.decision is not Decision.DENY:
        # ⚠ AN ASK'S REASON IS THE USER'S ONLY: "For "allow" and "ask", shown to
        # the user but not Claude" (docs/108 §1). So the rule id, which keys the
        # policy file and is kept from the model on a deny, can name the rule
        # to the person being asked.
        if verdict.rule_id:
            first, _, rest = text.partition("\n")
            text = f"{first} [{verdict.rule_id}]" + (f"\n{rest}" if rest else "")
        return text
    headline = "⛔ STING BLOCKED THIS — the action was NOT run."
    # Every line under the headline, indented: what the agent is told is
    # several lines now (docs/108), and a blank one stays blank.
    body = "\n".join(f"  {line}" if line else line for line in text.splitlines())
    return f"{headline}\n{body}" if body else headline


def render(verdict: Verdict, action: Action | None = None) -> str:
    """Verdict -> the string this agent expects on stdout.

    ⚠ ALLOW IS AN EXPLICIT `"allow"`, AND IT USED TO BE THE EMPTY STRING.

    The old comment said Claude Code reads "no output, exit 0" as allow. Read
    against the SHIPPED BINARY — `@anthropic-ai/claude-code` 2.1.231,
    `bin/claude.exe`, the same way `failClosed` was settled for Cursor — that is
    not what happens. The hook result is consumed by:

        if (p.permissionBehavior !== void 0) { … yield hookPermissionResult … }

    No output means no `permissionDecision`, which means no `permissionBehavior`,
    which means that branch never runs and **Claude Code falls through to its
    own permission flow — so in manual mode it PROMPTS.** An operator watching
    Sting run therefore saw Claude Code's own yes/no dialog on every action and
    concluded the product "only gives us logs".

    The same binary documents the field it does honour:

        `permissionDecision` - "allow", "deny", or "ask" (PreToolUse only)

    ⚠ SO THIS REPLACES THE AGENT'S PERMISSION SYSTEM RATHER THAN ADDING TO IT.
    That is the product — and it means a defect in Sting now lets an agent run
    UNPROMPTED, where before the agent would still have asked. What stands
    in the way does not run through this function: `hook_entry` turns every
    failure of its own into exit 2, and the shipped binary treats exit 2 as
    "show stderr to model and block tool call".

    ⚠ ONLY EXIT 2 (2.1.284, docs/110 §A). Any other non-zero exit, empty or
    unparseable stdout, a hook that cannot start (a missing interpreter, 127),
    a kill by signal or the 600 s timeout FAILS OPEN on Claude Code: the call
    runs. Only what `hook_entry` itself catches is closed.
    See `tests/test_the_verdict_reaches_the_user.py`.
    """
    if verdict.decision is Decision.ALLOW:
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                # Short on purpose: this is the quiet path, and it runs on every
                # ordinary action. The reason exists so a transcript says WHO
                # allowed it, not to be read each time.
                "permissionDecisionReason": "Sting: allowed",
            }
        })

    rendered = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny" if verdict.decision is Decision.DENY else "ask",
            "permissionDecisionReason": _stings_own(verdict),
        }
    }
    # ⚠ THE WAY OUT GOES WHERE ONLY THE HUMAN READS IT (docs/108 §1). On a deny
    # Claude Code shows `permissionDecisionReason` to Claude; `systemMessage` is
    # "shown to the user", and in the 2.1.284 binary a PreToolUse systemMessage
    # becomes a `hook_system_message` attachment that the model-message builder
    # turns into nothing. An ask's reason is the user's only already.
    way_out = _common.way_out(verdict)
    if way_out:
        rendered["systemMessage"] = way_out
    return json.dumps(rendered)


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
    """One shell command, exactly as Claude Code sends it."""
    return {"session_id": session, "cwd": cwd,
            "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}}
