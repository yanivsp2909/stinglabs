"""The engine's source: `core/engine.py` and the modules it was split into
(docs/ENGINE_LAYOUT.md).

⚠ A TEST THAT READS THE ENGINE'S SOURCE READS ALL OF THEM. The split moved code
out of `core/engine.py`, so a check that reads that one file passes over
everything that moved: an absence check ("no bare code_mask()", "nothing
imports the shipper") goes silently vacuous, and a presence check fails. Read
the engine through here.

Not named `test_*`, so pytest imports it rather than collecting it.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Every file the engine is made of, `engine.py` first. The import pin in
# tests/test_hook_entry.py fails if engine.py imports a core module that is
# neither listed here nor one of the pure helpers it allows.
MODULES = ("engine", "command_text", "credentials", "globbing", "irreversible",
           "egress", "guard_runs", "guard_floor", "sources", "sinks", "secret_ladder",
           "why", "outside_content", "secret_reference", "downloads", "uncommitted",
           "deletes_in_text", "mcp_arguments", "uploads")


def path(module: str) -> Path:
    return ROOT / "core" / f"{module}.py"


def paths() -> list[Path]:
    return [path(module) for module in MODULES]


def sources() -> dict[str, str]:
    return {module: path(module).read_text(encoding="utf-8") for module in MODULES}


def text() -> str:
    """Every part's source, concatenated: for a substring check."""
    return "\n".join(sources().values())


def trees() -> dict[str, ast.Module]:
    return {module: ast.parse(source) for module, source in sources().items()}


def readers(name: str) -> set[str]:
    """The parts whose code LOOKS UP `name`: where a monkeypatch of it has to
    land to reach that code. A patch anywhere else is a silent no-op."""
    return {module for module, tree in trees().items()
            if any(isinstance(node, ast.Name) and node.id == name
                   and isinstance(node.ctx, ast.Load) for node in ast.walk(tree))}
