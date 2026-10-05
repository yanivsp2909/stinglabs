"""The Windows layout, and the chokepoint property it must not lose.

⚠ `current` IS NOT DECORATION. It is a symlink to a COPY, and that shape was
chosen for two properties:

    1 · a version swap is ATOMIC — `os.replace` over the link, never
        unlink-then-relink, so no hook ever follows a `current` that is not there
    2 · the link's own lstat mtime is HALF of `install_time()`, which is a
        security chokepoint: a grant written in the 4.6 ms between the grant
        sweep and the swap is later than `installed_at` and would otherwise
        survive a reinstall

Windows cannot create a symlink without Developer Mode or admin. The replacement
is a POINTER FILE, and it keeps both — `os.replace` is atomic for files on
Windows (it is not for directories, which is why a junction was rejected), and
the file's mtime records the swap exactly as the link's did.

⚠ EVERY TEST HERE RUNS ON BOTH PLATFORMS, driving the layout directly rather
than asking the OS which one it is. A Windows-only file would be a second
specification that could disagree with the POSIX one.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

def _touch_marker(path, at):
    """Set the swap marker's mtime, on either layout.

    ⚠ `follow_symlinks=False` IS ITSELF UNSUPPORTED ON WINDOWS — `os.utime`
    raises NotImplementedError there whatever it is pointed at, so routing these
    fixtures through `_swap_marker()` was only half the fix. The flag exists to
    stamp the LINK rather than its target; on Windows the marker is a regular
    file, so there is no link to distinguish and the flag is not needed.
    """
    import os as _os
    if _os.path.islink(path):
        _os.utime(path, (at, at), follow_symlinks=False)
    else:
        _os.utime(path, (at, at))


from core import allow_once
from installer import place


def _install(prefix: Path, name: str, at: float) -> Path:
    """One installed tree plus the pointer, in whichever layout `place` uses."""
    target = prefix / name
    target.mkdir(parents=True, exist_ok=True)
    (target / "INSTALL.json").write_text(json.dumps({
        "guard_version": name, "installed_at": at, "installed_by": "test"}),
        encoding="utf-8")
    os.utime(target / "INSTALL.json", (at, at))
    place._repoint(prefix / "current", target)
    # ⚠ THE MARKER IS AGED TOO, and forgetting it is a fixture bug that reads
    # like a code failure: `_repoint` stamps the marker at NOW, so an "old"
    # install whose manifest says `at` still has a marker saying now — and
    # `install_time()` correctly returns now. The fixture has to move both or it
    # is not describing an old install at all.
    _touch_marker(allow_once._swap_marker(), at)
    allow_once._install_manifest_time.cache_clear()
    allow_once._install_manifest_version.cache_clear()
    return target


@pytest.fixture
def prefix(tmp_path, monkeypatch):
    root = tmp_path / "share" / "sting"
    root.mkdir(parents=True)
    monkeypatch.setenv("STING_INSTALL_ROOT", str(root))
    return root


# ───────────────────────────────────────────── the layout resolves either way

def test_current_resolves_to_the_installed_tree(prefix):
    target = _install(prefix, "v1", time.time())
    assert place.current_dir(prefix).resolve() == target.resolve()
    assert allow_once._current_dir().resolve() == target.resolve()


def test_the_manifest_is_found_through_the_pointer(prefix):
    _install(prefix, "v1", time.time())
    assert allow_once._manifest_path().is_file()
    assert allow_once.install_time() is not None


def test_a_second_install_repoints_and_the_first_tree_survives(prefix):
    first = _install(prefix, "v1", time.time() - 100)
    second = _install(prefix, "v2", time.time())
    assert place.current_dir(prefix).resolve() == second.resolve()
    assert first.is_dir(), "the previous tree must stay for a rollback"


def test_repointing_never_leaves_current_missing(prefix):
    """⚠ ATOMICITY, WHICH IS THE PROPERTY A JUNCTION WOULD HAVE LOST.
    `os.replace` is the atomic primitive on both platforms — for a symlink on
    POSIX and for the pointer FILE on Windows. `MOVEFILE_REPLACE_EXISTING` does
    not apply to directories, so a junction would have to be deleted first and a
    hook firing in that window would get "no such file"."""
    _install(prefix, "v1", time.time() - 10)
    for n in range(5):
        _install(prefix, f"v{n + 2}", time.time())
        # after every swap, resolution works — there is no in-between state a
        # test can observe because `os.replace` has none to observe
        assert place.current_dir(prefix).joinpath("INSTALL.json").is_file()


def test_the_swap_marker_is_whatever_this_layout_repointed(prefix):
    _install(prefix, "v1", time.time())
    marker = allow_once._swap_marker()
    assert marker.exists(), marker
    if os.name == "nt":
        assert marker.name == place.POINTER
    else:
        assert marker.is_symlink()


# ══════════════ ⚠ THE CHOKEPOINT — the property that must not be lost

def test_a_grant_issued_before_a_reinstall_is_refused_after_it(prefix):
    """⚠ THE ONE THAT MATTERS, AND IT IS WHY THE MARKER HAS TO EXIST AT ALL.
    A grant approves one action under one policy. A reinstall changes the
    policy, so every outstanding grant is void — and the test is that it is
    STILL void under the new layout, not that the new layout runs."""
    _install(prefix, "v1", time.time() - 100)
    granted_at = time.time() - 50
    assert allow_once.install_time() < granted_at, "fixture is not ordered"

    _install(prefix, "v2", time.time())
    assert allow_once.install_time() > granted_at, (
        "a reinstall did not move install_time past an earlier grant — the "
        "chokepoint has no source and every stale grant now survives")


def test_the_marker_closes_the_window_between_the_sweep_and_the_swap(prefix):
    """⚠ THE 4.6 ms WINDOW, MEASURED ON A REAL INSTALL. `place.py` writes
    INSTALL.json first, sweeps grants second, repoints third. A grant written
    between the sweep and the swap is LATER than `installed_at`, so
    `installed_at` alone would let it survive. `install_time()` takes the LATER
    of the manifest time and the marker's mtime.

    Driven by making the manifest deliberately older than the swap, which is
    exactly the shape of that window.
    """
    target = _install(prefix, "v1", time.time())
    old = time.time() - 3600
    (target / "INSTALL.json").write_text(json.dumps({
        "guard_version": "v1", "installed_at": old}), encoding="utf-8")
    os.utime(target / "INSTALL.json", (old, old))
    allow_once._install_manifest_time.cache_clear()

    now = time.time()
    _touch_marker(allow_once._swap_marker(), now)

    assert allow_once.install_time() >= now - 1, (
        "install_time() ignored the swap marker and used only the manifest — "
        "a grant written in the sweep-to-swap window would survive")


def test_losing_the_marker_is_the_failure_this_pins(prefix, monkeypatch):
    """⚠ NON-VACUITY. If `_swap_marker` pointed at nothing, `install_time()`
    would fall back to the manifest alone and the test above would still pass on
    a fixture where the two happen to agree. Break the marker and the property
    must visibly disappear."""
    target = _install(prefix, "v1", time.time())
    old = time.time() - 3600
    (target / "INSTALL.json").write_text(json.dumps({
        "guard_version": "v1", "installed_at": old}), encoding="utf-8")
    os.utime(target / "INSTALL.json", (old, old))
    allow_once._install_manifest_time.cache_clear()

    monkeypatch.setattr(allow_once, "_swap_marker",
                         lambda: Path("/nonexistent-marker-xyz"))
    assert allow_once.install_time() == pytest.approx(old, abs=2), (
        "with no marker the manifest is all there is — if this does not hold, "
        "the test above was not measuring the marker")
