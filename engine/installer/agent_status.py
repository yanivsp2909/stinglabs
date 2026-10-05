"""What `install.py --status` says about each agent: one line each, never more
than the installer can show.

    protected    wired, the config verified (the guard's exact command, and the
                 hook it names is on disk), and the agent's config schema and
                 payload both checked against the real agent
    unverified   wired, but its schema or its payload was never checked against
                 the real agent (said which), or the wiring itself is not the
                 installer's (said why)
    partial      wired for one directory only (copilot keeps its hooks per
                 project), naming each directory
    not wired    the agent is on this machine; no config holds the guard
    not found    no sign of the agent, and no config holds the guard

⚠ WHAT WAS CHECKED IS DATA, NOT A GUESS (`CHECKED`). Claude Code's schema and
payload are verified from real configs and captured payloads; Cursor's schema
from real configs and its own shipped code, its payload never; the other three
adapters assume Claude Code's shape (install.py says the same when it wires
them, from this table).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import NamedTuple

from core import hook_configs
from installer import detect, place

AGENTS = ("claude-code", "cursor", "codex", "copilot", "antigravity")

CHECKED = {
    "claude-code": {"schema": True, "payload": True},
    "cursor":      {"schema": True, "payload": False},
    "codex":       {"schema": False, "payload": False},
    "copilot":     {"schema": False, "payload": False},
    "antigravity": {"schema": False, "payload": False},
}
"""What has been checked against each real agent, rather than assumed."""


def never_checked(agent: str) -> list[str]:
    """"schema", "payload": what nobody has checked for `agent`, in that order."""
    checked = CHECKED.get(agent, {})
    return [part for part in ("schema", "payload") if not checked.get(part)]


def _read(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


class Wiring(NamedTuple):
    """One config that holds the guard for an agent."""
    path: Path
    user_level: bool
    exact: bool
    """Every guard command in it is the installer's, naming a hook that is a
    file in this install's tree, on disk now."""


def _this_installs(command: str, agent: str, tree: Path | None) -> bool:
    """The installer's command for `agent`, naming a hook that is a file in
    `tree` (this install's prefix, resolved; None when it cannot be)."""
    parts = hook_configs.command_parts(command)
    if tree is None or parts is None or parts[2] != agent:
        return False
    script = Path(parts[1])
    try:
        return script.is_file() and script.resolve().is_relative_to(tree)
    except OSError:
        return False


def _wiring(agent: str, path: Path, user_level: bool, tree: Path | None) -> Wiring | None:
    """How `path` wires `agent`, or None when it holds no guard entry for it."""
    config = _read(path)
    if config is None:
        return None
    commands = [c for c in hook_configs.commands_in(config.get("hooks", {}))
                if hook_configs.sting_hook_agent(c) == agent]
    if not commands:
        return None
    return Wiring(path, user_level, all(_this_installs(c, agent, tree) for c in commands))


def _project_of(path: Path) -> Path:
    """The directory a project-level config covers: the parent of its dot-folder
    (`<project>/.github/hooks/hooks.json` -> `<project>`)."""
    for parent in path.parents:
        if parent.name.startswith("."):
            return parent.parent
    return path.parent


def _configs(agent: str, recorded: list[dict]) -> list[tuple[Path, bool]]:
    """(config, user-level) for every place `agent` could be wired: its
    user-level config, the ones install.py recorded writing, and this
    directory's project-level candidates."""
    seen, out = set(), []
    candidates = [(detect.expand(p), detect.expand(p).is_absolute())
                  for p in detect.AGENT_CONFIGS[agent]]
    candidates = [(p if p.is_absolute() else (Path.cwd() / p), user)
                  for p, user in candidates]
    candidates += [(Path(e["path"]), bool(e.get("user_level", True)))
                   for e in recorded if e.get("agent") == agent]
    for path, user in candidates:
        key = str(path)
        if key not in seen:
            seen.add(key)
            out.append((path, user))
    return out


def _resolved(prefix: Path) -> Path | None:
    try:
        return prefix.resolve()
    except OSError:
        return None


def agent_lines(prefix: Path | None = None) -> list[tuple[str, str]]:
    """(agent, what --status says about it), one per agent, every agent."""
    recorded = place.recorded_hook_entries(prefix)
    tree = _resolved(Path(prefix or place.default_prefix()))
    markers = detect.agent_markers()
    lines = []
    for agent in AGENTS:
        wired = [w for path, user in _configs(agent, recorded)
                 if (w := _wiring(agent, path, user, tree)) is not None]
        present = any(m.exists() for m in markers.get(agent, []))
        lines.append((agent, _say(agent, wired, present, markers.get(agent, []))))
    return lines


def _say(agent: str, wired: list[Wiring], present: bool, markers: list[Path]) -> str:
    if not wired:
        if present:
            return "not wired — the agent is here, and no hook config holds the guard"
        return f"not found — looked for {', '.join(str(m) for m in markers)}"
    unchecked = never_checked(agent)
    unchecked_note = (f"{' and '.join(unchecked)} never checked against a real "
                      f"{agent}" if unchecked else "")
    note = "; ".join(filter(None, [unchecked_note,
                                   _not_exact([str(w.path) for w in wired if not w.exact])]))
    if not any(w.user_level for w in wired):
        where = ", ".join(sorted(str(_project_of(w.path)) for w in wired))
        return f"partial — wired for {where} only" + (f"; {note}" if note else "")
    where = ", ".join(str(w.path) for w in wired)
    if note:
        return f"unverified — wired in {where}; {note}"
    return f"protected — wired in {where}; config and payload verified"


def _not_exact(paths: list[str]) -> str:
    if not paths:
        return ""
    return (f"{', '.join(paths)} does not run the installer's exact command, or "
            f"the hook it names is not on disk: re-run install.py")
