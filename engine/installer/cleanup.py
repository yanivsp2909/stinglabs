"""Delete the unpacked release source after a successful install — OPT-IN, and
provably inert inside a git working tree.

⚠ THIS DELETES A DIRECTORY, SO IT IS GATED THREE WAYS AND ALL THREE ARE REQUIRED.
install.py is run daily from real git clones with uncommitted work; this feature
firing there would delete a live repo. The gates:

    1. the operator passed --cleanup-after-install   (install.py; default OFF)
    2. the install genuinely succeeded               (install.py calls this only
       at do_install's final success return, after the preflight-passed gate —
       unreachable from the dry-run, check-only and preflight-failed returns)
    3. the source is a POSITIVE release archive AND carries no .git   (here)

⚠ GATE 3 IS A POSITIVE SIGNAL, NOT MERELY "NO .git". `make_release.sh` writes a
`.sting-release` manifest into the staged tree — a file `git archive` can never
produce, because it is added AFTER the archive step, exactly like VERSION. We
refuse unless that manifest is present AND carries its sentinel. The `.git` check
is a SECOND, INDEPENDENT refusal, walking the source dir and every ancestor and
matching a `.git` directory OR file (a linked worktree or submodule uses a `.git`
FILE). Either signal failing refuses; both must hold to delete. Erring toward
refusal is the whole design: an archive a founder unzipped INSIDE some git repo
has a `.git` ancestor and is left alone, which is correct.

⚠ SELF-DELETION IS PLATFORM-SPECIFIC, ESTABLISHED NOT ASSUMED.
  POSIX  a process may unlink its own containing directory while running — the
         interpreter and imported modules are already in memory — PROVIDED the
         cwd is moved out first, or getcwd() and every relative path afterwards
         raise FileNotFoundError. `perform` does the chdir, then rmtree. Verified.
  Windows a directory that is open or is a live process's cwd cannot be removed,
         so the delete is DEFERRED to a detached process that waits for this pid
         to exit and then removes the tree. ⚠ This mechanism is NOT executable in
         the build environment these notes were written in; it is isolated on its
         own per-platform path rather than attempted inline where it would fail.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

RELEASE_MARKER = ".sting-release"
"""The positive archive signal. Written by tools/make_release.sh into the staged
tree; never present in a git checkout (and .gitignored so it cannot be committed
into one). See `blocked_reason`."""

RELEASE_SENTINEL = "sting-release-archive"
"""The fixed string the marker must carry. Presence of a file named
`.sting-release` is not enough — it has to be OURS."""


def _marker_ok(source_dir: Path) -> bool:
    """True only if `source_dir` holds a `.sting-release` manifest carrying the
    sentinel. A missing, unreadable, non-JSON or wrong-sentinel file is False —
    the delete needs a positive yes, never the mere absence of a no."""
    try:
        data = json.loads((source_dir / RELEASE_MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("sentinel") == RELEASE_SENTINEL


def _git_at_or_above(source_dir: Path) -> Path | None:
    """The first `.git` (directory OR file) at `source_dir` or any ancestor, or
    None. A file matches because linked worktrees and submodules use a `.git`
    file rather than a directory."""
    resolved = source_dir.resolve()
    for candidate in (resolved, *resolved.parents):
        dotgit = candidate / ".git"
        if dotgit.exists():
            return dotgit
    return None


def blocked_reason(source_dir: Path) -> str | None:
    """Why cleanup must NOT fire, or None if `source_dir` is a deletable archive.

    Independent of the flag and of install success — those are install.py's
    gates 1 and 2. This is gate 3, and it is deliberately two independent
    refusals: no positive marker, or any `.git` at/above the source.
    """
    source_dir = Path(source_dir)
    if not _marker_ok(source_dir):
        return (f"no {RELEASE_MARKER} manifest — this is not an unpacked release "
                f"archive (a git checkout never carries one)")
    git = _git_at_or_above(source_dir)
    if git is not None:
        return (f".git present at {git} — this is a git working tree and is "
                f"never deleted")
    return None


def perform(source_dir: Path, say=print) -> bool:
    """Delete `source_dir`. The caller has already checked the flag, genuine
    success, and `blocked_reason(...) is None`.

    Returns True if the tree was removed inline (POSIX), False if removal was
    deferred to a post-exit process (Windows).
    """
    source_dir = Path(source_dir).resolve()
    if platform.system() == "Windows":
        _schedule_post_exit_delete(source_dir, say)
        return False
    # POSIX: move the cwd out of the doomed tree FIRST (see the module note),
    # then remove it. A failure here is surfaced, never swallowed — a
    # half-deleted source is worth a loud traceback.
    try:
        os.chdir(Path.home())
    except OSError:
        os.chdir(source_dir.parent if source_dir.parent.exists() else "/")
    shutil.rmtree(source_dir)
    say(f"  removed the unpacked source at {source_dir}")
    return True


def _schedule_post_exit_delete(source_dir: Path, say) -> None:
    """Windows: defer the delete to a detached cmd that waits for THIS pid to
    exit, removes the tree, then removes itself. ⚠ NOT VERIFIED ON A REAL WINDOWS
    HOST — the documented mechanism, isolated here rather than attempted inline
    where an open handle or the cwd lock would make an inline rmtree fail."""
    pid = os.getpid()
    bat = source_dir.parent / f".sting-cleanup-{pid}.bat"
    bat.write_text(
        "@echo off\r\n"
        ":wait\r\n"
        f'tasklist /FI "PID eq {pid}" | find "{pid}" >nul '
        "&& (timeout /t 1 /nobreak >nul & goto wait)\r\n"
        f'rmdir /s /q "{source_dir}"\r\n'
        '(goto) 2>nul & del "%~f0"\r\n',      # the bat removes itself last
        encoding="utf-8")
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    subprocess.Popen(
        ["cmd", "/c", str(bat)],
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        close_fds=True)
    say(f"  scheduled removal of {source_dir} after this process exits (Windows)")


def run(source_dir: Path, enabled: bool, say=print) -> str:
    """The one entry point install.py calls, ONLY at genuine success.

    Returns an outcome string: "disabled" (flag off — silent), "refused: <why>"
    (gate 3 said no — explained to the operator), "deleted" (removed inline) or
    "scheduled" (deferred to post-exit, Windows).
    """
    if not enabled:
        return "disabled"
    reason = blocked_reason(source_dir)
    if reason is not None:
        say(f"  --cleanup-after-install: refused — {reason}. Source left in place.")
        return f"refused: {reason}"
    inline = perform(source_dir, say)
    return "deleted" if inline else "scheduled"
