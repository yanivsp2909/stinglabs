"""The adapter registry — the one place a new agent is added.

⚠ THIS FILE IS THE WHOLE REGISTRATION STEP. It used to live inside
`hook_entry.py`, which meant adding an agent required editing the process that
every hook invokes. Here, a contributor adds one module and one line, and three
things pick it up without further edits:

    hook_entry.py                 dispatches --agent to it
    tools/preflight.py            runs the SEMANTIC probe against it
    tests/test_adapter_conformance.py   applies the whole contract to it

`ADAPTERS_BY_NAME` is keyed by the string a user types after `--agent`, which is
the same string that lands in every record's `agent` field. See
docs/24-adapter-contract.md for what a module must expose.
"""
from __future__ import annotations

from adapters import antigravity, claude_code, codex, copilot, cursor

ADAPTERS_BY_NAME = {
    claude_code.AGENT: claude_code,
    copilot.AGENT: copilot,
    cursor.AGENT: cursor,
    codex.AGENT: codex,
    antigravity.AGENT: antigravity,
}

# ⚠ KEYED OFF EACH MODULE'S OWN `AGENT` CONSTANT, NOT OFF A STRING TYPED HERE.
# The name a user selects, the name in the registry and the name stamped into
# every record must be one value. Two spellings of "claude-code" would route
# correctly and label wrongly, which is the failure mode that is hardest to see:
# the guard works and the evidence points at the wrong agent.

__all__ = ["ADAPTERS_BY_NAME", "antigravity", "claude_code", "codex",
            "copilot", "cursor"]
