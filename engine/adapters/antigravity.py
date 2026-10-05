"""
Google Antigravity adapter — the one that differs most.

Verified against https://antigravity.google/docs/hooks on 7 Aug 2026. Google
took the hook concept from Anthropic and did not copy the format.

Events: PreToolUse, PostToolUse, PreInvocation, PostInvocation, Stop.
(There is also a hook that fires before the model call, which the others do not
expose. That is where goal-policy derivation would eventually live. Noted, not
built — see docs/25.)

Input (stdin):
    {"toolCall": {"name": "run_command",
                  "args": {"CommandLine": "npm test", "Cwd": "/workspace/project"}},
     "stepIdx": 19,
     "conversationId": "ec33ebf9-...",
     "workspacePaths": ["/workspace/project"],
     "transcriptPath": "...", "artifactDirectoryPath": "...", "modelName": "..."}

Output (stdout) — FLAT:
    {"decision": "ask", "reason": "...", "permissionOverrides": ["command(npm test)"]}

The four differences that bite if skipped:

1. Response is flat — no hookSpecificOutput wrapper.
2. Arg keys are PascalCase: CommandLine, Cwd, WaitMsBeforeAsync.
3. conversationId is the session id; stepIdx is ALREADY a monotonic sequence
   number, so it is used directly rather than recomputed.
4. workspacePaths is an ARRAY. Multi-root workspaces mean "inside the project"
   is a set membership test, not a single prefix check.

Decision values Antigravity accepts: allow, deny, ask, force_ask,
deny_unless_prior_grant (and the CLI's auto_approve). We use deny and
force_ask; an ALLOW is empty stdout, "no say". `{}` would be a DENY: a missing
decision falls back to the deprecated `allowTool`, false by default. `permissionOverrides` has no
equivalent in our model and is deliberately not emitted — docs/25 says ignore
it in stage 1, and emitting a permission grant from a guard would be backwards.

Config: .agents/hooks.json (workspace), ~/.gemini/config/hooks.json (user),
~/.gemini/antigravity-cli/config/ (CLI variant).
"""
from __future__ import annotations

import json

from adapters import _common
from core.types import Action, ActionKind, Decision, Verdict

AGENT = "antigravity"

_KIND_BY_TOOL = {
    "run_command": ActionKind.EXEC,
    "run_terminal_command": ActionKind.EXEC,
    "execute_command": ActionKind.EXEC,
    "read_file": ActionKind.READ,
    "view_file": ActionKind.READ,
    "read_url_content": ActionKind.FETCH,
    "search_web": ActionKind.FETCH,
    "write_file": ActionKind.WRITE,
    "create_file": ActionKind.WRITE,
    "edit_file": ActionKind.EDIT,
    "replace_file_content": ActionKind.EDIT,
    "apply_patch": ActionKind.EDIT,
}

# PascalCase, per Google's schema. Lowercase spellings are accepted too so a
# schema tweak does not silently blind the adapter.
_COMMAND_KEYS = ("CommandLine", "Command", "commandLine", "command")
_CWD_KEYS = ("Cwd", "WorkingDirectory", "cwd")
_PATH_KEYS = ("TargetFile", "FilePath", "AbsolutePath", "Path",
              "file_path", "path", "target_file")
_CONTENT_KEYS = ("CodeContent", "Content", "NewString", "ReplacementContent",
                 "content", "new_string")
_URL_KEYS = ("Url", "URL", "url")


def _kind_for(tool_name: str, args: dict) -> ActionKind:
    if tool_name.startswith("mcp__") or tool_name.startswith("mcp_"):
        return ActionKind.TOOL
    known = _KIND_BY_TOOL.get(tool_name.lower())
    if known is not None:
        return known
    inferred = _common.inferred_kind(
        _common.shell_command(args, keys=_COMMAND_KEYS)[0],
        _common.first_str(args, *_URL_KEYS))
    if inferred is not None:
        return inferred
    if _common.first_str(args, *_PATH_KEYS):
        return ActionKind.EDIT if _common.first_str(args, *_CONTENT_KEYS) \
            else ActionKind.READ
    return ActionKind.TOOL


def parse(raw: dict) -> Action:
    """Antigravity's PreToolUse payload -> Action. Never raises."""
    raw = _common.as_dict(raw)
    tool_call = _common.as_dict(raw.get("toolCall") or raw.get("tool_call"))
    tool_name = _common.as_str(tool_call.get("name"))
    args = _common.as_dict(tool_call.get("args"))

    # workspacePaths is an ARRAY. Take the roots properly rather than assuming
    # element zero is "the project" — multi-root is supported and a sibling
    # root is not "outside the project".
    declared_roots = _common.workspace_roots(
        raw.get("workspacePaths") or raw.get("workspace_paths"), "")
    cwd = _common.resolve_cwd(_common.first_str(args, *_CWD_KEYS)
                               or (declared_roots[0] if declared_roots else None))
    # Every declared root is the project. Fall back to Cwd only when Antigravity
    # sent none, so a sibling root in a multi-root workspace is never "outside".
    roots = declared_roots or _common.workspace_roots(None, cwd)

    # stepIdx is already monotonic within the conversation — do not recompute it.
    step_idx = raw.get("stepIdx", raw.get("step_idx"))
    seq = step_idx if isinstance(step_idx, int) and step_idx >= 0 else 0

    session_id = _common.first_str(raw, "conversationId", "conversation_id") or "unknown"
    command, unreadable = _common.shell_command(args, keys=_COMMAND_KEYS)
    kind = _kind_for(tool_name, args)

    return Action(
        session_id=session_id,
        seq=seq,
        kind=kind,
        paths=_common.resolve_paths([args.get(k) for k in _PATH_KEYS], cwd),
        command=command,
        url=_common.first_str(args, *_URL_KEYS),
        tool_name=tool_name or None,
        content=_common.with_tool_arguments(
            _common.first_str(args, *_CONTENT_KEYS), tool_name, args),
        cwd=cwd,
        workspace_roots=roots,
        agent=AGENT,
        # The adapter knows its own agent's naming; the engine must not.
        tool_origin="mcp" if (tool_name or "").startswith(("mcp__", "mcp.")) else ("builtin" if kind is ActionKind.TOOL else ""),
        malformed=unreadable if kind is ActionKind.EXEC and command is None else "",
    )


def render(verdict: Verdict, action: Action | None = None) -> str:
    """Verdict -> Antigravity's flat response. ALLOW is the empty string.

    permissionOverrides is deliberately not emitted: it grants a standing
    permission, and a guard handing out permissions is backwards.
    """
    if verdict.decision is Decision.ALLOW:
        return ""

    # ⚠ `force_ask`, NOT `ask` (docs/110 §A): Antigravity lets an `ask` through
    # unasked when a person's standing "Always Allow" covers the call, and
    # only `force_ask` ignores cached permissions.
    payload = {"decision": "deny" if verdict.decision is Decision.DENY else "force_ask"}
    # No way out: "shown to the agent or user", undivided (docs/108 §1).
    reason = _common.told(verdict)
    if reason:
        payload["reason"] = reason
    return json.dumps(payload)


def render_failure(reason: str) -> str:
    """The answer when the guard could not decide — everywhere else exit 2.

    ⚠ ANTIGRAVITY READS EXIT 2 AS A HOOK ERROR, NOT A BLOCK (docs/110 §A): its
    consolidated path fails the tool call, and its legacy path logs the error
    and RUNS it; which path a session takes is not known. A deny with exit 0
    blocks on both. Keys it does not know are an error too, so only these two.
    """
    return json.dumps({"decision": "deny",
                       "reason": reason or "Sting could not decide, so this is blocked."})


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
    """`toolCall` in camelCase, and `stepIdx` IS the sequence number.

    ⚠ `step` is not decoration here. This adapter uses `stepIdx` as `seq`
    rather than recomputing one, so a probe that sent 0 four times would write
    four records at the same seq and the log would read as one action retried.
    """
    return {"conversationId": session, "stepIdx": step,
            "workspacePaths": [cwd],
            "toolCall": {"name": "run_command",
                         "args": {"CommandLine": command, "Cwd": cwd}}}
