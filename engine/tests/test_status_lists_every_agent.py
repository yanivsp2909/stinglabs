"""`install.py --status` says, for every agent, how far the guard covers it.

Item C of fix/more-masking-and-agent-status. `--status` reported the version,
the supervisor and what ships, and nothing about the agents: whether the one a
developer works in is wired, and how far that wiring was ever checked. One line
per agent now (installer/agent_status.py), from what the installer can show:

    protected    wired, config and payload verified
    unverified   wired, but schema or payload never checked (says which), or
                 the wiring is not the installer's (says why)
    partial      wired for one directory only (copilot), naming it
    not wired    the agent is here, and no config holds the guard
    not found    no sign of the agent

Nothing here touches the real machine: tests/install_harness.py.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from install_harness import SAFE, home, no_real_supervisor        # noqa: E402,F401

import install                                                     # noqa: E402
from installer import place                                        # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX fake supervisor")


@pytest.fixture(autouse=True)
def the_environment_is_put_back(tmp_path, monkeypatch):
    """`--status` loads `~/.sting/env` into the process environment, and reads
    the project-level configs of the directory it runs in: a temp one."""
    saved = dict(os.environ)
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    yield
    os.environ.clear()
    os.environ.update(saved)


def _status(capsys) -> dict[str, str]:
    capsys.readouterr()
    assert install.main(["--status"]) == 0
    out = capsys.readouterr().out
    assert "\nAgents" in out or "Agents\n" in out, out
    lines = {}
    for line in out.split("Agents", 1)[1].splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in ("claude-code", "cursor", "codex",
                                            "copilot", "antigravity"):
            lines.setdefault(parts[0], parts[1])
    return lines


def _installed(home: Path) -> Path:
    """The hook entry the install wired claude-code to."""
    assert install.main(SAFE) == 0
    config = json.loads((home / ".claude" / "settings.json").read_text())
    command = config["hooks"]["PreToolUse"][-1]["hooks"][0]["command"]
    return Path(command.split("' '")[1].split("'")[0])


def _wire(agent: str, config: Path, entry: Path) -> None:
    written = install.write_hook_config(agent, config, entry, {}, dry_run=False)
    assert written["written"], written


def test_a_status_that_cannot_be_read_says_so_and_the_rest_prints(home, capsys,
                                                                   monkeypatch):
    """Python review, MEDIUM: `Path.home()` raises RuntimeError where no home
    can be resolved, and the section had no guard: `--status` would lose every
    line to a traceback."""
    from installer import agent_status

    _installed(home)

    def no_home(*a, **k):
        raise RuntimeError("fake: could not determine home directory")
    monkeypatch.setattr(agent_status, "agent_lines", no_home)
    capsys.readouterr()
    assert install.main(["--status"]) == 0
    out = capsys.readouterr().out
    assert "Agents" in out and "could not be read" in out, out
    assert "version" in out


def test_every_agent_has_a_line(home, capsys):
    _installed(home)
    lines = _status(capsys)
    assert set(lines) == {"claude-code", "cursor", "codex", "copilot", "antigravity"}


def test_claude_code_wired_by_the_installer_is_protected(home, capsys):
    _installed(home)
    line = _status(capsys)["claude-code"]
    assert line.startswith("protected"), line
    assert str(home / ".claude" / "settings.json") in line


def test_an_agent_that_is_absent_is_not_found(home, capsys):
    _installed(home)
    line = _status(capsys)["codex"]
    assert line.startswith("not found"), line


def test_an_agent_that_is_here_but_not_hooked_is_not_wired(home, capsys):
    _installed(home)
    (home / ".cursor").mkdir()
    line = _status(capsys)["cursor"]
    assert line.startswith("not wired"), line


def test_cursor_wired_is_unverified_because_its_payload_was_never_checked(home, capsys):
    entry = _installed(home)
    (home / ".cursor").mkdir()
    _wire("cursor", home / ".cursor" / "hooks.json", entry)
    line = _status(capsys)["cursor"]
    assert line.startswith("unverified"), line
    assert "payload never checked" in line and "schema" not in line, line


@pytest.mark.parametrize("agent, config", [
    ("codex", ".codex/hooks.json"), ("antigravity", ".gemini/config/hooks.json")])
def test_an_assumed_schema_is_unverified_and_says_both(home, capsys, agent, config):
    entry = _installed(home)
    _wire(agent, home / config, entry)
    line = _status(capsys)[agent]
    assert line.startswith("unverified"), line
    assert "schema and payload never checked" in line, line


def test_copilot_wired_in_one_project_is_partial_and_names_it(home, capsys, tmp_path):
    entry = _installed(home)
    project = tmp_path / "some-project"
    config = project / ".github" / "hooks" / "hooks.json"
    _wire("copilot", config, entry)
    place.record_hook_configs(place.current_dir(), [
        {"agent": "copilot", "path": str(config), "user_level": False}])
    line = _status(capsys)["copilot"]
    assert line.startswith("partial"), line
    assert f"wired for {project} only" in line, line


def test_a_command_that_is_not_the_installers_is_never_protected(home, capsys):
    _installed(home)
    settings = home / ".claude" / "settings.json"
    config = json.loads(settings.read_text())
    hook = config["hooks"]["PreToolUse"][-1]["hooks"][0]
    hook["command"] += " || true"
    settings.write_text(json.dumps(config))
    line = _status(capsys)["claude-code"]
    assert line.startswith("unverified"), line
    assert "not the installer's exact command" in line or "exact command" in line, line


def test_a_hook_that_is_not_on_disk_is_never_protected(home, capsys):
    entry = _installed(home)
    entry.resolve().unlink()
    line = _status(capsys)["claude-code"]
    assert not line.startswith("protected"), line
    assert line.startswith("unverified"), line
