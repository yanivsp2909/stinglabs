"""D3: uninstall finds Copilot's entry wherever install put it.

⚠ WHAT MAIN DID. Copilot's hook config is per project: the installer writes
`<the directory it ran in>/.github/hooks/hooks.json`, and nothing recorded
which directory that was. Uninstall walks `detect.agent_configs()`, whose
project paths are relative, so it cleaned the directory IT ran in. Run from
anywhere else, the entry stayed and Copilot kept calling a guard that was
being removed.

⚠ NOW. Every hook config the installer writes is recorded in the installed
tree's INSTALL.json (agent, absolute path, user-level or not). A reinstall
carries the list forward, so installing from project B does not forget A, and
uninstall cleans every recorded path before anything else.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import install                                                   # noqa: E402
from installer import place                                      # noqa: E402

ROOT = Path(__file__).parent.parent
ENTRY = Path("/Users/dev/.local/share/sting/current/sting_hook.py")


def copilot_config(project: Path) -> Path:
    config = project / ".github" / "hooks" / "hooks.json"
    install.write_hook_config("copilot", config, ENTRY, {}, dry_run=False)
    return config


def manifest(prefix: Path) -> dict:
    return json.loads((place.current_dir(prefix) / "INSTALL.json").read_text(encoding="utf-8"))


def test_the_manifest_records_every_hook_config_written(tmp_path):
    prefix = tmp_path / "prefix"
    placed = place.place(prefix=prefix, source=ROOT, session_root=tmp_path / "s")
    config = copilot_config(tmp_path / "project-a")
    place.record_hook_configs(placed["path"], [
        {"agent": "copilot", "path": str(config), "user_level": False}])
    recorded = manifest(prefix)["hook_configs"]
    assert {"agent": "copilot", "path": str(config), "user_level": False} in recorded
    assert place.recorded_hook_configs(prefix) == [str(config)]


def test_recording_the_same_config_twice_keeps_one(tmp_path):
    prefix = tmp_path / "prefix"
    placed = place.place(prefix=prefix, source=ROOT, session_root=tmp_path / "s")
    record = [{"agent": "copilot", "path": "/work/a/.github/hooks/hooks.json",
               "user_level": False}]
    place.record_hook_configs(placed["path"], record)
    place.record_hook_configs(placed["path"], record)
    assert place.recorded_hook_configs(prefix) == ["/work/a/.github/hooks/hooks.json"]


def test_a_reinstall_carries_the_record_forward(tmp_path):
    prefix = tmp_path / "prefix"
    first = place.place(prefix=prefix, source=ROOT, session_root=tmp_path / "s")
    place.record_hook_configs(first["path"], [
        {"agent": "copilot", "path": "/work/a/.github/hooks/hooks.json", "user_level": False}])
    second = place.place(prefix=prefix, source=ROOT, session_root=tmp_path / "s")
    place.record_hook_configs(second["path"], [
        {"agent": "copilot", "path": "/work/b/.github/hooks/hooks.json", "user_level": False}])
    assert place.recorded_hook_configs(prefix) == [
        "/work/a/.github/hooks/hooks.json", "/work/b/.github/hooks/hooks.json"]


def test_uninstall_cleans_copilots_entry_from_another_directory(tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    placed = place.place(prefix=prefix, source=ROOT, session_root=tmp_path / "s")
    project_a = tmp_path / "project-a"
    config = copilot_config(project_a)
    place.record_hook_configs(placed["path"], [
        {"agent": "copilot", "path": str(config), "user_level": False}])
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cleaned = install.clean_hook_configs(prefix)
    assert str(config) in cleaned, cleaned
    left = json.loads(config.read_text(encoding="utf-8"))
    assert not any("sting_hook.py" in json.dumps(e) for e in left["hooks"].get("PreToolUse", []))


def test_uninstall_without_a_manifest_still_cleans_what_it_can(tmp_path, monkeypatch):
    """An install from before the record existed: the relative walk still runs."""
    project = tmp_path / "project"
    config = copilot_config(project)
    monkeypatch.chdir(project)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cleaned = install.clean_hook_configs(tmp_path / "no-prefix")
    assert any(Path(path).resolve() == config.resolve() for path in cleaned), cleaned
