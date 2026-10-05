"""The supervisor label is per install prefix, not per account.

⚠ THE PER-ACCOUNT LABEL BIT LIVE, ON THIS MACHINE, DURING THE PREVIOUS PASS.
Installing into a sandboxed HOME to rehearse a clean install booted out the
developer's real shipper and took `dev.sting.shipper`. Preflight detected it and
said so; nothing prevented it. That is exactly what a customer piloting Sting on
a machine that already runs Sting would have done.

⚠ AND IT IS A MIGRATION, NOT A RENAME. Every machine installed before this
change runs the old label. Bootstrapping the new one without stopping the old
would leave TWO shippers running and only one findable by any command the
installer prints — an orphan, which is the stop condition for this change.

⚠ THE UPGRADE PATH IS SAFE BECAUSE THE PREFIX IS STABLE. `~/.local/share/sting`
does not move between versions; `current` moves inside it. So an ordinary
reinstall computes the same label it computed last time, and the only label
change any machine ever sees is the single migration off the legacy name.
"""
from __future__ import annotations

import os
import platform
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from installer import place, supervisor                             # noqa: E402
from shipper import service                                         # noqa: E402


def test_two_prefixes_get_two_labels(tmp_path):
    """THE DEFECT, as a test. Two installs under one account must coexist."""
    one = service.label(tmp_path / "install-a")
    two = service.label(tmp_path / "install-b")

    assert one != two
    assert one.startswith(service.LEGACY_LABEL + ".")
    assert two.startswith(service.LEGACY_LABEL + ".")


def test_the_sandboxed_home_case_specifically(tmp_path):
    """⚠ THE EXACT SHAPE THAT BIT: two HOMEs, each with its OWN default prefix.

    Both are `<home>/.local/share/sting` — the same relative name, different
    absolute directories. A label derived from "is this the default prefix"
    would give both the same name and reproduce the bug; deriving from the
    absolute path is what distinguishes them.
    """
    real = tmp_path / "real-home" / ".local" / "share" / "sting"
    sandbox = tmp_path / "sandbox-home" / ".local" / "share" / "sting"
    real.mkdir(parents=True)
    sandbox.mkdir(parents=True)

    assert service.label(real) != service.label(sandbox)


def test_the_label_is_stable_across_upgrades(tmp_path):
    """⚠ THE PROPERTY THAT KEEPS THIS FROM ORPHANING ANYTHING ON UPGRADE.

    A version lands INSIDE the prefix and `current` is repointed at it. If the
    label moved with the version, every upgrade would be a migration and every
    missed migration an orphan.
    """
    prefix = tmp_path / "prefix"
    (prefix / "v1").mkdir(parents=True)
    before = service.label(prefix)
    (prefix / "v2").mkdir()

    assert service.label(prefix) == before


def test_the_default_prefix_no_longer_uses_the_legacy_name(monkeypatch):
    """The legacy label must never be written again — it is only ever removed."""
    assert service.label() != service.LEGACY_LABEL
    assert service.plist_path().name != f"{service.LEGACY_LABEL}.plist"
    assert service.unit_path().name != f"{service.LEGACY_LABEL}.service"


# ─────────────────────────────────────────────────────────── the migration

def test_migration_is_free_when_there_is_nothing_to_migrate(monkeypatch, tmp_path):
    """⚠ ZERO SUBPROCESSES ON THE COMMON PATH, and that is why it can run on
    every activate. A machine installed after this change has no legacy file, so
    the service manager is never consulted."""
    monkeypatch.setattr(supervisor.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    calls = []
    monkeypatch.setattr(service, "_run",
                        lambda *a, **k: calls.append(a) or (0, ""))

    result = supervisor.migrate_legacy()

    assert calls == [], "it consulted the service manager with nothing to migrate"
    assert result["stopped"] is False
    assert result["removed"] == []


def test_migration_stops_and_removes_the_legacy_service(monkeypatch, tmp_path):
    """⚠ STOPPED **AND** THE FILE REMOVED. Booting out a service whose plist is
    still on disk means the next login loads it again — the orphan coming back
    by itself, which is worse than the orphan because by then nobody is looking.
    """
    monkeypatch.setattr(supervisor.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    agents = tmp_path / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    legacy = agents / f"{service.LEGACY_LABEL}.plist"
    legacy.write_text("<plist/>", encoding="utf-8")

    commands = []

    def fake_run(command, timeout=20):
        commands.append(command)
        return 0, ""

    monkeypatch.setattr(service, "_run", fake_run)

    result = supervisor.migrate_legacy()

    assert result["stopped"] is True
    assert any("bootout" in " ".join(c) for c in commands)
    assert any(service.LEGACY_LABEL in " ".join(c) for c in commands)
    assert not legacy.exists(), "the file must go, or it reloads at next login"
    assert str(legacy) in result["removed"]


def test_a_legacy_file_left_behind_is_removed_even_if_not_loaded(monkeypatch,
                                                                  tmp_path):
    """A boot-out without a delete, or a machine that never logged back in."""
    monkeypatch.setattr(supervisor.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    agents = tmp_path / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    legacy = agents / f"{service.LEGACY_LABEL}.plist"
    legacy.write_text("<plist/>", encoding="utf-8")
    monkeypatch.setattr(service, "_run", lambda *a, **k: (1, "no such service"))

    result = supervisor.migrate_legacy()

    assert result["stopped"] is False
    assert not legacy.exists()


def test_activate_migrates_before_it_bootstraps(monkeypatch, tmp_path):
    """⚠ ORDER. Bootstrapping first would mean two shippers running at once."""
    monkeypatch.setattr(supervisor.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    agents = tmp_path / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    (agents / f"{service.LEGACY_LABEL}.plist").write_text("<plist/>",
                                                             encoding="utf-8")
    order = []

    def fake_run(command, timeout=20):
        order.append(" ".join(str(c) for c in command))
        return 0, ""

    monkeypatch.setattr(service, "_run", fake_run)
    monkeypatch.setattr(service, "loaded",
                        lambda: {"loaded": True, "detail": "ok"})
    monkeypatch.setattr(supervisor, "_settle", lambda: True)

    supervisor.activate()

    legacy_at = next(i for i, c in enumerate(order)
                     if service.LEGACY_LABEL in c and "bootout" in c
                     and service.label() not in c)
    bootstrap_at = next(i for i, c in enumerate(order) if "bootstrap" in c)
    assert legacy_at < bootstrap_at


# ───────────────────────────────────────────── status finds what it cannot name

def test_siblings_finds_an_install_whose_label_it_cannot_predict(monkeypatch,
                                                                  tmp_path):
    """⚠ `--status` MUST FIND A SERVICE WHOSE NAME IT NO LONGER PREDICTS.

    With one label per prefix, this install cannot compute another install's
    label — so "is anything else shipping under this account?" stops being a
    question about a name and becomes one about a directory.
    """
    monkeypatch.setattr(supervisor.Path, "home", classmethod(lambda cls: tmp_path))
    agents = tmp_path / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    (agents / f"{service.LEGACY_LABEL}.plist").write_text("x", encoding="utf-8")
    (agents / f"{service.LEGACY_LABEL}.deadbeef.plist").write_text(
        "x", encoding="utf-8")
    (agents / f"{service.label()}.plist").write_text("x", encoding="utf-8")
    (agents / "com.example.unrelated.plist").write_text("x", encoding="utf-8")

    found = {entry["label"]: entry for entry in supervisor.siblings()}

    assert service.LEGACY_LABEL in found
    assert found[service.LEGACY_LABEL]["legacy"] is True
    assert f"{service.LEGACY_LABEL}.deadbeef" in found, \
        "an install this one cannot name must still be visible"
    assert found[f"{service.LEGACY_LABEL}.deadbeef"]["mine"] is False
    assert found[service.label()]["mine"] is True
    assert "com.example.unrelated" not in found
