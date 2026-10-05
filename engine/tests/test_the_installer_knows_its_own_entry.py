"""D2: the installer recognises the guard's entry by its marker, and nothing else.

⚠ WHAT MAIN DID. Reinstall and uninstall kept an entry only if `"sting" not in
json.dumps(entry)`: a case-sensitive SUBSTRING over the whole entry. A person's
own hook running `npm run testing`, `./existing.sh` or anything under ~/sting/
contains "sting", so every reinstall and every uninstall deleted it. And the
Windows Cursor bridge entry contains "sting" only through the default install
prefix, so under a STING_INSTALL_ROOT without that word it was never replaced
and never removed.

⚠ NOW: one function, `core.hook_configs.is_sting_entry`, shared by the
installer and by the engine's check of ~/.claude/settings.json. The marker is
`sting_hook.py` or `hook_entry.py` followed by `--agent`, or `cursor_bridge.ps1`
followed by `-Agent`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import install                                                   # noqa: E402
from core import hook_configs                                    # noqa: E402

ENTRY = Path("/Users/dev/.local/share/sting/current/sting_hook.py")
THEIRS = [
    "npm run testing",
    "./scripts/existing.sh",
    "python3 ~/sting/tools/lint_hook.py",
    "/Users/dev/sting/bin/listing --fast",
]


def claude_file(tmp_path: Path, commands: list[str]) -> Path:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": c}]} for c in commands]}}),
        encoding="utf-8")
    return path


def cursor_file(tmp_path: Path, commands: list[str]) -> Path:
    path = tmp_path / "hooks.json"
    path.write_text(json.dumps({"version": 1, "hooks": {"beforeShellExecution": [
        {"command": c} for c in commands]}}), encoding="utf-8")
    return path


def commands(path: Path) -> list[str]:
    return hook_configs.commands_in(json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("theirs", THEIRS)
def test_a_persons_own_hook_survives_a_reinstall(theirs, tmp_path):
    for agent, make in (("claude-code", claude_file), ("cursor", cursor_file)):
        path = make(tmp_path, [theirs])
        install.write_hook_config(agent, path, ENTRY, {}, dry_run=False)
        install.write_hook_config(agent, path, ENTRY, {}, dry_run=False)
        assert theirs in commands(path), (agent, theirs)


@pytest.mark.parametrize("theirs", THEIRS)
def test_a_persons_own_hook_survives_an_uninstall(theirs, tmp_path):
    for agent, make in (("claude-code", claude_file), ("cursor", cursor_file)):
        path = make(tmp_path, [theirs])
        install.write_hook_config(agent, path, ENTRY, {}, dry_run=False)
        assert install.remove_hook_config(path) is True
        left = commands(path)
        assert theirs in left, (agent, theirs)
        assert not any(hook_configs.sting_hook_agent(c) for c in left), left


def test_the_guards_entry_is_replaced_not_duplicated(tmp_path):
    path = claude_file(tmp_path, ["npm run testing"])
    for _ in range(3):
        install.write_hook_config("claude-code", path, ENTRY, {}, dry_run=False)
    ours = [c for c in commands(path) if hook_configs.sting_hook_agent(c)]
    assert len(ours) == 1, ours


@pytest.mark.parametrize("command,agent", [
    ("'/usr/bin/python3' '/Users/dev/.local/share/sting/current/sting_hook.py' "
     "--agent claude-code", "claude-code"),
    ("python3 /opt/guard/hook_entry.py --agent codex", "codex"),
    ('powershell -NoProfile -ExecutionPolicy Bypass -File '
     '"C:/opt/guard/v1/installer/cursor_bridge.ps1" -Agent cursor', "cursor"),
])
def test_the_marker_names_the_agent(command, agent):
    assert hook_configs.sting_hook_agent(command) == agent


@pytest.mark.parametrize("command", THEIRS + [
    "python3 ~/sting/sting-engine/tools/grade_engine.py",
    "echo sting_hook",                      # the word, not the script
    "node hook_entry.js --agent x",         # another program's file
])
def test_the_marker_names_nothing_else(command):
    assert hook_configs.sting_hook_agent(command) is None


def test_a_bridge_under_a_custom_prefix_is_still_ours(tmp_path):
    """Main found the Windows bridge only through the word "sting" in the
    default prefix; under STING_INSTALL_ROOT=C:/opt/guard it was never removed."""
    bridge = ('powershell -NoProfile -ExecutionPolicy Bypass -File '
              '"C:/opt/guard/v1/installer/cursor_bridge.ps1" -Agent cursor')
    path = cursor_file(tmp_path, [bridge, "npm run testing"])
    assert install.remove_hook_config(path) is True
    assert commands(path) == ["npm run testing"]


def test_one_function_is_shared_by_the_installer_and_the_engine():
    source = Path(install.__file__).read_text(encoding="utf-8")
    assert '"sting" not in json.dumps' not in source and '"sting" in json.dumps' not in source
    assert "hook_configs.is_sting_entry" in source
    # the engine's check of ~/.claude/settings.json reaches the same marker
    command = ("'/usr/bin/python3' '/Users/dev/.local/share/sting/current/sting_hook.py' "
               "--agent claude-code")
    assert hook_configs.is_exact_command(command, "claude-code")
    assert not hook_configs.is_exact_command(command.replace("sting_hook.py", "x.py"),
                                             "claude-code")
