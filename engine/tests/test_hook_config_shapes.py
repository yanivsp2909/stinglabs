"""What the installer writes into each agent's config file.

⚠ THIS FILE EXISTS BECAUSE THE CURSOR CONFIG WAS NEVER TESTED AND NEVER WORKED.
`install.py` wrote Claude Code's shape — `hooks.PreToolUse[].matcher` with a
nested `{"type": "command"}` — into `.cursor/hooks.json`. Cursor's real schema
has a top-level `version`, `hooks` keyed by camelCase EVENT names, and entries
of `{command, ...}`. **`PreToolUse` is not a Cursor event**, so the hook was
addressed to something Cursor never raises: an install that reported success and
guarded nothing.

Verified against real `hooks.json` files on this machine — see
docs/25-cursor-hooks.md for exactly what was read versus inferred.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import install                                                   # noqa: E402

ENV = {"STING_SESSION_ROOT": "/tmp/s", "STING_OBSERVE": "1"}
ENTRY = Path("/opt/sting/hook_entry.py")


def write(agent, path, observe=True, env=None):
    install.write_hook_config(agent, path, ENTRY, env or ENV,
                               dry_run=False, observe=observe)
    return json.loads(path.read_text())


# ───────────────────────────────────────────────── the label, for every agent

@pytest.mark.parametrize("agent",
                          ["claude-code", "cursor", "codex", "copilot", "antigravity"])
def test_every_agents_command_passes_its_own_name(agent, tmp_path):
    """⚠ `hook_entry.pick_agent` DEFAULTS, IT DOES NOT SNIFF. With no `--agent`
    and no STING_AGENT it returns claude-code, so every record Cursor produced
    was labelled claude-code. A wrong label is worse than none — the panel
    refuses to guess exactly so a label can be trusted."""
    config = write(agent, tmp_path / "c.json")
    blob = json.dumps(config)
    assert f"--agent {agent}" in blob, blob


# ─────────────────────────────────────────────────────────── Cursor's schema

def test_cursor_gets_cursors_schema_and_not_claude_codes(tmp_path):
    config = write("cursor", tmp_path / "hooks.json")

    assert config["version"] == 1, "Cursor's real files carry a top-level version"
    assert "PreToolUse" not in config["hooks"]
    assert "preToolUse" not in config["hooks"], (
        "no real Cursor config read on this machine contains either spelling")

    for event in ("beforeShellExecution", "beforeReadFile", "beforeMCPExecution"):
        entries = config["hooks"][event]
        assert len(entries) == 1, event
        assert "command" in entries[0], event
        # Claude Code's wrapper must not appear anywhere.
        assert "matcher" not in entries[0], event
        assert "hooks" not in entries[0], event
        assert entries[0].get("type") != "command", event


def test_the_engines_own_event_is_wired(tmp_path):
    """`beforeShellExecution` is what the engine models, and the whole I02 chain
    — cat, cp, git add, git push — arrives on it."""
    config = write("cursor", tmp_path / "hooks.json")
    assert "beforeShellExecution" in config["hooks"]


def test_reads_are_wired_because_that_is_where_a_SOURCE_comes_from(tmp_path):
    """⚠ WIRED DESPITE THE VOLUME. Without `beforeReadFile`, Cursor's own read
    of `.env` is invisible, the session never learns it holds a credential, and
    the later push is allowed. Rule #2 still holds — the engine SEES this event
    and does not block on it."""
    config = write("cursor", tmp_path / "hooks.json")
    assert "beforeReadFile" in config["hooks"]


def test_no_after_event_is_wired(tmp_path):
    """⚠ `after*` CANNOT BLOCK. Wiring one puts a verdict on the wire that
    Cursor ignores, which reads as coverage and is not."""
    config = write("cursor", tmp_path / "hooks.json")
    assert not [e for e in config["hooks"] if e.startswith("after")]


@pytest.mark.parametrize("observe,expected", [(True, False), (False, True)])
def test_failClosed_tracks_the_mode_rather_than_being_a_constant(
        observe, expected, tmp_path):
    """⚠ A SAFETY DECISION, NOT A DEFAULT TO COPY.

    observe  -> False. Observe mode's promise is that it blocks nothing, proved
                on 7 failure paths including a forced engine crash. `true` would
                turn any crash into a block, breaking that promise from OUTSIDE
                the engine, where none of those proofs reach.
    enforce  -> True.  A guard that fails open is not a guard.
    """
    config = write("cursor", tmp_path / "hooks.json", observe=observe)
    for event in ("beforeShellExecution", "beforeReadFile", "beforeMCPExecution"):
        assert config["hooks"][event][0]["failClosed"] is expected


# ─────────────────────────────────────────── merging, and cleaning up after us

def test_a_developers_own_cursor_hooks_survive(tmp_path):
    path = tmp_path / "hooks.json"
    path.write_text(json.dumps({
        "version": 1,
        "hooks": {
            "beforeShellExecution": [{"command": "node mine.js",
                                       "description": "my own hook"}],
            "afterFileEdit": [{"command": "node fmt.js"}],
        }}))
    config = write("cursor", path)

    theirs = [e for e in config["hooks"]["beforeShellExecution"]
              if "mine.js" in e["command"]]
    assert theirs, "the installer deleted a hook the developer wrote"
    assert config["hooks"]["afterFileEdit"] == [{"command": "node fmt.js"}]


def test_a_stale_PreToolUse_entry_from_an_older_install_is_removed(tmp_path):
    """⚠ IT WOULD OTHERWISE SIT THERE FOREVER UNDER AN EVENT CURSOR NEVER RAISES,
    looking exactly like coverage.

    ⚠ THE ENTRY CARRIES `--agent` SINCE D2. The guard's entry is found by its
    marker (`hook_entry.py --agent …`), never by the word "sting", which also
    deleted a person's own `npm run testing`. A stale entry WITHOUT `--agent`
    could only come from a pre-v0.10 build (9e56c4c made `--agent` universal),
    and every later reinstall had already removed it."""
    path = tmp_path / "hooks.json"
    path.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [{"type": "command",
                                     "command": "python3 /x/sting/hook_entry.py --agent cursor"}]}]}}))
    config = write("cursor", path)
    assert "PreToolUse" not in config["hooks"]


def test_a_non_sting_PreToolUse_entry_is_not_touched(tmp_path):
    path = tmp_path / "hooks.json"
    path.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [{"type": "command", "command": "node theirs.js"}]}]}}))
    config = write("cursor", path)
    assert config["hooks"]["PreToolUse"], "somebody else's entry was deleted"


def test_reinstalling_does_not_duplicate_the_entry(tmp_path):
    path = tmp_path / "hooks.json"
    write("cursor", path)
    config = write("cursor", path)
    for event in ("beforeShellExecution", "beforeReadFile", "beforeMCPExecution"):
        assert len(config["hooks"][event]) == 1, event


def test_uninstall_removes_the_entry_from_EVERY_event(tmp_path):
    """⚠ AN UNINSTALL THAT ONLY LOOKED AT `PreToolUse` LEFT THE GUARD WIRED AND
    REPORTED SUCCESS — the same class of defect as a supervisor reporting a
    service it never created."""
    path = tmp_path / "hooks.json"
    write("cursor", path)
    assert install.remove_hook_config(path) is True
    config = json.loads(path.read_text())
    assert "sting" not in json.dumps(config["hooks"]), config
    # and a second uninstall is a no-op rather than a lie
    assert install.remove_hook_config(path) is False


# ─────────────────────────────────────── the other agents are UNCHANGED shape

@pytest.mark.parametrize("agent", ["claude-code", "codex", "copilot", "antigravity"])
def test_the_unverified_agents_keep_claude_codes_shape(agent, tmp_path):
    """⚠ NOT A VERIFICATION — A DELIBERATE NON-CHANGE. No real config file for
    these three has been read, so their schema stays as it was rather than being
    changed to another guess. `install.py` says UNVERIFIED in its own output for
    copilot, codex and antigravity."""
    config = write(agent, tmp_path / "c.json")
    entry = config["hooks"]["PreToolUse"][0]
    assert entry["matcher"] == "*"
    assert entry["hooks"][0]["type"] == "command"
