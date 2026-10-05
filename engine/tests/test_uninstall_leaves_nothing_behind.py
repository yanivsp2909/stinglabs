"""⚠ `remove()`'s DOCSTRING SAID "Uninstall must leave nothing behind" AND IT
LEFT SOMETHING BEHIND.

`install.py` writes a Startup-folder `.cmd` whenever `schtasks /Create` is
refused — an unelevated shell, or domain policy. `remove_startup_shortcut()`
existed to undo that and had **zero callers anywhere in this repo**, so the
claim was false on exactly the Windows machines that needed the fallback.

What the orphan does when it runs is why this is more than untidiness: the
shortcut is `start "" /min "<wrapper>.cmd"`, and `remove()` deletes that
wrapper. So at every logon, forever, Windows runs a command that cannot find
its target and exits — no window, because it is `/min`; no log, because the
thing that would write one is what was uninstalled. It ships nothing and says
nothing, and somebody who finds the file cannot tell it from a live guard.
"""
from __future__ import annotations

import pytest

from installer import supervisor
from shipper import service


@pytest.fixture
def windows(monkeypatch, tmp_path):
    """A machine that looks like Windows to `remove()`, with real files."""
    xml = tmp_path / "sting-shipper.xml"
    wrapper = tmp_path / "sting-shipper-wrapper.cmd"
    shortcut = tmp_path / "Startup" / "sting-shipper.cmd"
    shortcut.parent.mkdir(parents=True)
    for f in (xml, wrapper):
        f.write_text("x", encoding="utf-8")
    shortcut.write_text(f'@echo off\nstart "" /min "{wrapper}"', encoding="utf-8")

    monkeypatch.setattr(service, "kind", lambda: "schtasks")
    monkeypatch.setattr(service, "task_paths", lambda: (xml, wrapper))
    monkeypatch.setattr(service, "startup_shortcut_path", lambda: shortcut)
    monkeypatch.setattr(service, "_run", lambda *a, **k: (0, "SUCCESS"))
    monkeypatch.setattr(service, "loaded", lambda: {"loaded": False})
    return xml, wrapper, shortcut


def test_uninstall_removes_the_startup_shortcut(windows):
    xml, wrapper, shortcut = windows

    result = supervisor.remove()

    assert not shortcut.exists(), (
        "uninstall left a Startup shortcut that runs at every logon and, with "
        "its wrapper deleted, silently starts nothing")
    assert not xml.exists() and not wrapper.exists()
    assert result["ok"] is True


def test_the_removed_shortcut_is_reported_not_removed_quietly(windows):
    """⚠ A DELETION NOBODY IS TOLD ABOUT IS ITS OWN PROBLEM. `remove()` returns
    what it removed and `install.py --uninstall` prints it; a file that vanishes
    without appearing in that list is indistinguishable from one that was never
    there — which is the confusion this whole fix is about."""
    _, _, shortcut = windows

    result = supervisor.remove()

    assert str(shortcut) in result["removed"]


def test_uninstall_is_unbothered_when_there_is_no_shortcut(windows, monkeypatch):
    """The common case: `schtasks` was never refused, so no fallback was ever
    written. Removing nothing must not report having removed something, and
    must not raise."""
    _, _, shortcut = windows
    shortcut.unlink()

    result = supervisor.remove()

    assert result["ok"] is True
    assert not any("Startup" in entry for entry in result["removed"])


def test_a_shortcut_that_cannot_be_deleted_does_not_abort_the_uninstall(
        windows, monkeypatch):
    """⚠ A LOCKED FILE MUST NOT LEAVE THE TASK REGISTERED. Antivirus holding
    the `.cmd` open is ordinary on Windows, and the task and wrapper matter
    more than the shortcut — so the failure is absorbed and simply not claimed
    in `removed`."""
    monkeypatch.setattr(supervisor, "remove_startup_shortcut",
                        lambda: (_ for _ in ()).throw(OSError("locked")))

    with pytest.raises(OSError):
        supervisor.remove_startup_shortcut()

    # and the real helper swallows OSError itself, which is what remove() relies on
    monkeypatch.undo()
    monkeypatch.setattr(service, "startup_shortcut_path",
                        lambda: (_ for _ in ()).throw(OSError("locked")))
    assert supervisor.remove_startup_shortcut() is False
