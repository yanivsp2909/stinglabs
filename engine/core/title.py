"""A human title for a session — content-blind by construction.

    book-app / npm run dev

⚠ WHAT IT IS MADE OF, AND WHAT IT MAY NEVER BE MADE OF. Two things every
adapter already delivers and every record already carries: the basename of the
declared project root (else the cwd), and the session's first command (else its
first tool and path). Nothing else. Claude Code keeps a far better title — in
the session TRANSCRIPT, which is the conversation, and Sting's claim is that it
never reads the conversation. Its sessions-METADATA `name` was measured on a
real machine and is the cwd basename plus two hex characters (`book-app-88`,
`team-deck-db`, `sting-4d`): the folder we already know, made worse, for a
file read and a Claude-Code-only PID mapping. So this module does no IO at all,
and `tests/test_a_session_has_a_title.py` plants decoys where Claude Code keeps
its files and proves the hook opens none of them. docs/79.

⚠ NOT ON THE DECISION PATH. `SessionState.title` is written once by hook_entry
and read by nothing in core/engine.py; a test decides the same action with and
without it under three session states. It embeds the first command, so on the
wire it is `full`-tier content exactly like `command` (core/wire.py drops it at
every reduced tier by construction, and a test pins that it travels only where
`command` does).
"""
from __future__ import annotations

from collections.abc import Sequence

MAX_TITLE = 96
"""The whole string. Bounded here AND clipped again by `build_body`
(`_MAX_TITLE`), so the record's size arithmetic never depends on this module."""

_MAX_WHAT = 56
"""The command half. A first command is usually short (`npm run dev`, `git
status`); a heredoc is not, and a title is a label, not a transcript."""

_MAX_TOOL = 24
"""The tool half when there is no command (`Read`, `mcp__github__search`)."""

_ELLIPSIS = "…"
_SEP = " / "


def _basename(path: str | None) -> str:
    text = str(path or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1] if text else ""


def _one_line(text: str, limit: int) -> str:
    """The first non-empty line, whitespace collapsed, cut with a marker."""
    for line in str(text).splitlines():
        words = line.split()
        if words:
            flat = " ".join(words)
            if len(flat) <= limit:
                return flat
            return flat[: limit - len(_ELLIPSIS)] + _ELLIPSIS
    return ""


def session_title(roots: Sequence[str] | None, cwd: str | None,
                  command: str | None, tool_name: str | None,
                  paths: Sequence[str] | None) -> str:
    """`<folder> / <what>`, from what the first action already carries.

    folder  the declared root's basename, else the cwd's — the ROOT, so a cwd
            deep inside the project does not retitle the session by subfolder.
    what    the first command, one line, bounded; else `<tool> <first path's
            basename>`; else the tool; else "session".
    """
    declared = [r for r in (roots or ()) if r]
    folder = (_basename(declared[0]) if declared else _basename(cwd)) or "?"
    if command is not None and str(command).strip():
        what = _one_line(command, _MAX_WHAT)
    else:
        named = [p for p in (paths or ()) if p]
        tool = _one_line(tool_name or "", _MAX_TOOL)
        if named and tool:
            what = f"{tool} {_basename(named[0])}"
        elif named:
            what = _basename(named[0])
        else:
            what = tool or "session"
    title = f"{folder}{_SEP}{what}"
    if len(title) > MAX_TITLE:
        title = title[: MAX_TITLE - len(_ELLIPSIS)] + _ELLIPSIS
    return title
