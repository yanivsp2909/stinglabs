"""--cleanup-after-install deletes the unpacked release source, and is PROVABLY
inert inside a git working tree.

⚠ THE TWO REFUSAL TESTS ARE THE POINT. install.py is run daily from real git
clones with uncommitted work; this feature firing there would delete a live
repo. The design is three independent gates, ALL required:

    1. the operator passed the flag              (install.py argparse; default OFF)
    2. the install genuinely succeeded           (the call site sits after the
       preflight-passed gate, before do_install's final `return 0`)
    3. a POSITIVE `.sting-release` marker is present AND no `.git` at or above
       the source dir                            (installer.cleanup.blocked_reason)

Every credential-shaped value here is irrelevant — nothing secret is minted —
but the marker/`.git` fixtures are built at runtime so no test ever writes into
a real archive or a real clone.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from installer import cleanup                                       # noqa: E402


def _archive(tmp: Path, *, marker: bool = True, sentinel: str | None = None,
             git: str | None = None) -> Path:
    """A fake unpacked source dir. `git` ∈ {None, 'dir', 'file', 'ancestor'}."""
    src = tmp / "sting-v9.9.9"
    src.mkdir(parents=True)
    (src / "install.py").write_text("# entry point\n")
    (src / "core").mkdir()
    (src / "core" / "engine.py").write_text("# code\n")
    if marker:
        payload = {"sentinel": sentinel or cleanup.RELEASE_SENTINEL,
                   "tag": "v9.9.9", "built_by": "tools/make_release.sh"}
        (src / cleanup.RELEASE_MARKER).write_text(json.dumps(payload))
    if git == "dir":
        (src / ".git").mkdir()
    elif git == "file":
        (src / ".git").write_text("gitdir: /somewhere/worktrees/x\n")
    elif git == "ancestor":
        (tmp / ".git").mkdir()          # a .git ABOVE the source dir
    return src


def _say():
    out: list[str] = []
    return out, out.append


# ───────────────────────────── the catastrophic-case refusals ──

def test_flag_absent_never_deletes_even_on_a_valid_archive(tmp_path):
    """Gate 1. A perfectly deletable archive is left ALONE when the flag is off."""
    src = _archive(tmp_path)                      # valid: marker, no .git
    out, say = _say()
    assert cleanup.run(src, enabled=False, say=say) == "disabled"
    assert src.exists(), "source deleted with the flag OFF"
    assert out == [], "said something while disabled"


def test_refuses_inside_a_git_directory(tmp_path):
    """Gate 3, the one that protects a live clone: marker present, but a `.git`
    directory sits in the source — REFUSE and explain, never delete."""
    src = _archive(tmp_path, git="dir")
    out, say = _say()
    result = cleanup.run(src, enabled=True, say=say)
    assert result.startswith("refused"), result
    assert ".git" in result
    assert src.exists(), "deleted inside a git working tree"
    assert any("refused" in line for line in out), out


def test_refuses_when_git_is_a_worktree_file(tmp_path):
    """A linked worktree / submodule uses a `.git` FILE, not a dir. Still refuse."""
    src = _archive(tmp_path, git="file")
    assert cleanup.run(src, enabled=True, say=lambda *a: None).startswith("refused")
    assert src.exists()


def test_refuses_when_git_is_in_an_ANCESTOR(tmp_path):
    """Unzipped INSIDE a git repo: the source has a marker and no local `.git`,
    but an ancestor does. Err safe — refuse."""
    src = _archive(tmp_path, git="ancestor")
    result = cleanup.run(src, enabled=True, say=lambda *a: None)
    assert result.startswith("refused") and ".git" in result, result
    assert src.exists()


def test_refuses_without_the_positive_marker(tmp_path):
    """Gate 3's positive half: no `.sting-release` → not an archive → refuse,
    even with the flag on and no `.git` anywhere."""
    src = _archive(tmp_path, marker=False)
    result = cleanup.run(src, enabled=True, say=lambda *a: None)
    assert result.startswith("refused") and cleanup.RELEASE_MARKER in result
    assert src.exists()


def test_a_wrong_sentinel_is_not_a_marker(tmp_path):
    """The marker must carry the sentinel, not merely exist — a file named
    `.sting-release` with the wrong contents does not authorise a delete."""
    src = _archive(tmp_path, sentinel="something-else")
    assert cleanup.run(src, enabled=True, say=lambda *a: None).startswith("refused")
    assert src.exists()


# ───────────────────────────── the success path ──

def test_deletes_a_real_archive_and_leaves_the_install_untouched(tmp_path):
    """Flag on, marker present, no `.git` at or above → delete the source, and
    prove the separate install locations are untouched."""
    src = _archive(tmp_path)
    # stand-ins for ~/.sting and ~/.local/share/sting/<version> — SEPARATE dirs
    sting = tmp_path / "dot-sting"; sting.mkdir(); (sting / "env").write_text("x")
    share = tmp_path / "share-sting"; share.mkdir(); (share / "current.txt").write_text("v")
    keep_cwd = os.getcwd()
    try:
        result = cleanup.run(src, enabled=True, say=lambda *a: None)
    finally:
        # perform() chdirs to home on POSIX; restore so pytest is unaffected
        if os.path.isdir(keep_cwd):
            os.chdir(keep_cwd)
    assert result == "deleted", result
    assert not src.exists(), "source not deleted on the success path"
    assert sting.exists() and (sting / "env").exists(), "~/.sting was touched"
    assert share.exists() and (share / "current.txt").exists(), "share dir touched"


def test_perform_chdirs_out_before_deleting(tmp_path, monkeypatch):
    """POSIX: deleting the cwd leaves getcwd() dangling. perform() must move the
    cwd OUT of the doomed tree first — verified empirically for this platform."""
    if platform.system() == "Windows":
        pytest.skip("POSIX-only behaviour; Windows uses the scheduled path")
    src = _archive(tmp_path)
    monkeypatch.chdir(src)                         # cwd INSIDE the doomed dir
    cleanup.perform(src, say=lambda *a: None)
    # if perform did not chdir out, this raises FileNotFoundError:
    assert Path(os.getcwd()).exists()
    assert not src.exists()


def test_windows_defers_to_a_post_exit_delete(tmp_path, monkeypatch):
    """Windows cannot delete an open/cwd dir live, so perform() must SCHEDULE it
    and NOT delete inline. Verified by faking the platform and capturing the
    detached spawn — the real Windows run is not executable in this build."""
    src = _archive(tmp_path)
    monkeypatch.setattr(cleanup.platform, "system", lambda: "Windows")
    spawned = {}
    monkeypatch.setattr(cleanup.subprocess, "Popen",
                        lambda *a, **k: spawned.update(args=a, kw=k))
    inline = cleanup.perform(src, say=lambda *a: None)
    assert inline is False, "Windows deleted inline instead of scheduling"
    assert src.exists(), "Windows deleted the tree inline — must defer"
    assert spawned, "no detached cleanup process was scheduled on Windows"


# ───────────────────────────── the wiring, pinned structurally ──

def test_the_flag_exists_and_defaults_off():
    import install
    ap = install.main.__globals__["argparse"].ArgumentParser()
    # build the real parser the way main() does, by inspecting the source:
    src = (ROOT / "install.py").read_text()
    assert "--cleanup-after-install" in src, "the flag was never added"
    # default must be OFF: the argument is a store_true (defaults False)
    assert 'add_argument("--cleanup-after-install", action="store_true"' in src \
        or "add_argument('--cleanup-after-install', action='store_true'" in src, \
        "the flag must be store_true so it defaults OFF"


def test_cleanup_runs_only_after_the_success_gate():
    """STRUCTURAL: the cleanup call must sit AFTER the preflight gate and the
    `Done` head in do_install, so it is unreachable from the dry-run, check-only
    and preflight-failed returns. A call placed earlier would delete on paths
    that are not genuine success."""
    src = (ROOT / "install.py").read_text()
    done = src.find('head("Done")')
    call = src.find("cleanup.run(")
    preflight_fail = src.find("preflight_failed()")
    assert done != -1 and call != -1, "cleanup.run is not wired into install.py"
    assert call > done, "cleanup runs before the Done gate — not genuine success"
    assert call > preflight_fail, "cleanup runs before the preflight-failed gate"


def test_make_release_writes_the_marker():
    """The POSITIVE signal has to be PRODUCED, or gate 3 can never pass for a
    real archive. make_release.sh must write the marker into the staged tree."""
    script = (ROOT / "tools" / "make_release.sh").read_text()
    assert cleanup.RELEASE_MARKER in script, "make_release.sh writes no marker"
    assert cleanup.RELEASE_SENTINEL in script, "the marker carries no sentinel"


def test_the_marker_is_gitignored():
    """Belt: a developer who somehow creates `.sting-release` in the clone must
    not be able to commit it and make a checkout look like an archive."""
    gi = (ROOT / ".gitignore").read_text()
    assert cleanup.RELEASE_MARKER in gi, ".sting-release is not gitignored"
