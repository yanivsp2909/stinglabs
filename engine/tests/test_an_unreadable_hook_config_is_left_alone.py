"""D1: the installer never rewrites a hook config it cannot read.

⚠ WHAT MAIN DID. `write_hook_config` read the agent's config and, on a JSON
error, set `existing = {}` and wrote back ONLY the guard's entry. For
~/.claude/settings.json that wiped the person's permissions, env and model,
with no copy, under a docstring that says "Merges; never overwrites." A file
that parsed but held a list, or a `hooks` that was not an object, crashed the
install instead.

⚠ NOW. The file is copied beside itself, left byte for byte as it was, that
agent is NOT hooked, and the installer says so in the line a person reads.
Uninstall already never rewrote such a file, but said nothing; it now says the
guard's entry may still be in it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import install                                                   # noqa: E402

ENTRY = Path("/Users/dev/.local/share/sting/current/sting_hook.py")
UNREADABLE = {
    "a trailing comma": '{"permissions": {"allow": ["Bash(ls)"]},}',
    "a comment": '// mine\n{"model": "opus"}',
    "not an object": '[{"model": "opus"}]',
    "hooks not an object": '{"model": "opus", "hooks": ["x"]}',
    "an event that is not a list": '{"hooks": {"PreToolUse": {"x": 1}}}',
    "empty": "",
}
AGENTS = ["claude-code", "cursor"]


def backups(path: Path) -> list[Path]:
    return sorted(p for p in path.parent.iterdir()
                  if p.name.startswith(path.name + ".sting-backup-"))


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("case", UNREADABLE)
def test_an_unreadable_config_is_not_rewritten(case, agent, tmp_path):
    config = tmp_path / "settings.json"
    config.write_text(UNREADABLE[case], encoding="utf-8")
    result = install.write_hook_config(agent, config, ENTRY, {}, dry_run=False)
    assert result["written"] is False and result["skipped"], result
    assert config.read_text(encoding="utf-8") == UNREADABLE[case], "the file was rewritten"


@pytest.mark.parametrize("case", UNREADABLE)
def test_an_unreadable_config_is_backed_up_first(case, tmp_path):
    config = tmp_path / "settings.json"
    config.write_text(UNREADABLE[case], encoding="utf-8")
    result = install.write_hook_config("claude-code", config, ENTRY, {}, dry_run=False)
    copies = backups(config)
    assert len(copies) == 1 and copies[0].read_text(encoding="utf-8") == UNREADABLE[case]
    assert result["backup"] == str(copies[0])


def test_a_dry_run_changes_nothing_even_to_say_it_would_skip(tmp_path):
    config = tmp_path / "settings.json"
    config.write_text(UNREADABLE["a comment"], encoding="utf-8")
    result = install.write_hook_config("claude-code", config, ENTRY, {}, dry_run=True)
    assert result["written"] is False and result["skipped"]
    assert backups(config) == []


def test_the_installer_says_so_plainly(tmp_path):
    config = tmp_path / "settings.json"
    config.write_text(UNREADABLE["a trailing comma"], encoding="utf-8")
    result = install.write_hook_config("claude-code", config, ENTRY, {}, dry_run=False)
    said = "\n".join(install.hook_config_report("claude-code", result))
    assert "NOT HOOKED" in said and str(config) in said
    assert "untouched" in said and result["backup"] in said
    assert "without the guard" in said


def test_a_readable_config_still_merges(tmp_path):
    config = tmp_path / "settings.json"
    config.write_text(json.dumps({"model": "opus", "permissions": {"allow": ["Bash(ls)"]}}),
                      encoding="utf-8")
    result = install.write_hook_config("claude-code", config, ENTRY, {}, dry_run=False)
    written = json.loads(config.read_text(encoding="utf-8"))
    assert result["written"] is True and written["model"] == "opus"
    assert written["permissions"] == {"allow": ["Bash(ls)"]}
    assert backups(config) == []
    said = "\n".join(install.hook_config_report("claude-code", result))
    assert "wrote" in said and "NOT HOOKED" not in said


def test_a_missing_config_is_still_created(tmp_path):
    config = tmp_path / "new" / "settings.json"
    result = install.write_hook_config("claude-code", config, ENTRY, {}, dry_run=False)
    assert result["written"] is True and config.is_file()


def test_uninstall_says_when_it_cannot_read_a_config(tmp_path):
    config = tmp_path / "settings.json"
    config.write_text(UNREADABLE["a trailing comma"], encoding="utf-8")
    assert install.remove_hook_config(config) is False
    assert config.read_text(encoding="utf-8") == UNREADABLE["a trailing comma"]
    why = install.unreadable_hook_config(config)
    assert why and "JSON" in why
    assert install.unreadable_hook_config(tmp_path / "absent.json") is None
