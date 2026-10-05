"""Which test runs and latency benches OF THIS REPOSITORY are running now, in
any of its worktrees. docs/PARALLEL.md.

The latency bench measures the machine, so it refuses to start while another
run of this repository is using it: two agents in two worktrees would each slow
the other, and both sets of numbers would describe the overlap instead of the
engine. A test run of this repository counts; another repository's does not.

⚠ WHERE THE REGISTRY LIVES: THE COMMON GIT DIRECTORY. Every worktree of a
repository shares one (`git rev-parse --git-common-dir`) and no other
repository does, which is exactly the scope the refusal needs. Nothing here
reads HOME, a temp directory or an environment variable, so there is no
setting to point the bench somewhere else.

⚠ LIVENESS IS A HELD LOCK, NOT A PID. A run holds an exclusive advisory lock on
its own entry for as long as it lives, and the kernel drops that lock when the
process dies however it dies, so a crashed run cannot leave behind an entry that
refuses every later bench. A pid is reused; a released lock is not held again.

⚠ A BENCH STARTED BY A TEST RUN IS THAT RUN'S OWN SMOKE TEST, NOT A MEASUREMENT.
The suite runs the bench (`tests/test_bench_robustness.py`) to check that its
report and its exit code agree. That run is not measuring anything, so it is not
refused, even while another worktree's suite is running: refusing it would be a
phantom failure of exactly the kind this file exists to prevent.

POSIX only. Where `fcntl` is missing (Windows) nothing registers and nothing
refuses, and the bench says so.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:                      # Windows: no advisory locks here
    fcntl = None

REGISTRY_NAME = "sting-runs"
GUARD_NAME = ".registry.lock"
SUITE = "suite"
BENCH = "bench"
REFUSED_BUSY = 3
"""The bench's exit code when it refused to start. Not 1, which is a budget
breach, and not 2, which is a usage error."""


def common_dir(start: Path) -> Path | None:
    """The repository's common git directory, found from any path inside a
    checkout or a linked worktree. None outside a git checkout (an unpacked
    release archive), where nothing registers."""
    start = start.resolve()
    for here in (start, *start.parents):
        dot_git = here / ".git"
        if dot_git.is_dir():
            return dot_git.resolve()
        if dot_git.is_file():
            text = dot_git.read_text(encoding="utf-8").strip()
            if not text.startswith("gitdir:"):
                return None
            gitdir = (here / text[len("gitdir:"):].strip()).resolve()
            commondir = gitdir / "commondir"
            if commondir.is_file():
                return (gitdir / commondir.read_text(encoding="utf-8").strip()).resolve()
            return gitdir
    return None


def registry_dir(root: Path) -> Path | None:
    common = common_dir(root)
    return None if common is None else common / REGISTRY_NAME


@contextmanager
def _guarded(directory: Path):
    """Serialise check-and-register, so two benches starting together cannot
    both see an empty registry and both run."""
    directory.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(directory / GUARD_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class Registration:
    """One live run. Holding the object holds the lock; `close()` ends it."""

    def __init__(self, path: Path, fd: int):
        self.path = path
        self._fd = fd

    def close(self) -> None:
        if self._fd < 0:
            return
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        os.close(self._fd)
        self._fd = -1


def _register_locked(directory: Path, kind: str, worktree: Path) -> Registration:
    entry = {"kind": kind, "pid": os.getpid(), "worktree": str(worktree),
             "started": time.time(), "command": " ".join(sys.argv)[:200]}
    path = directory / f"{kind}-{os.getpid()}-{uuid.uuid4().hex[:8]}.json"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.write(fd, json.dumps(entry).encode("utf-8"))
    return Registration(path, fd)


def register(kind: str, root: Path) -> Registration | None:
    """Register this process as a live run of the repository holding `root`."""
    directory = registry_dir(root)
    if fcntl is None or directory is None:
        return None
    with _guarded(directory):
        return _register_locked(directory, kind, root)


def _live_locked(directory: Path) -> list[dict]:
    """Entries whose owner still holds its lock, this process's own included.
    A released one is removed."""
    live = []
    for path in sorted(directory.glob("*.json")):
        try:
            fd = os.open(path, os.O_RDONLY)
        except FileNotFoundError:
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                try:
                    entry = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    entry = {"kind": "?", "pid": None, "worktree": "?", "started": None}
                live.append({**entry, "entry": str(path)})
                continue
            path.unlink(missing_ok=True)          # its owner is gone
        finally:
            os.close(fd)
    return live


def live(root: Path) -> list[dict]:
    """Every other live run of the repository holding `root`, any worktree."""
    directory = registry_dir(root)
    if fcntl is None or directory is None or not directory.is_dir():
        return []
    with _guarded(directory):
        return [e for e in _live_locked(directory) if e.get("pid") != os.getpid()]


def ancestors() -> set[int]:
    """This process and every process above it. One `ps` call, POSIX."""
    chain = {os.getpid()}
    try:
        table = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True,
                               text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return chain | {os.getppid()}
    parent = {}
    for line in table.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            parent[int(parts[0])] = int(parts[1])
    pid = os.getpid()
    while pid in parent and parent[pid] not in chain and parent[pid] > 1:
        pid = parent[pid]
        chain.add(pid)
    return chain


def describe(entry: dict) -> str:
    started = entry.get("started")
    since = time.strftime("%H:%M:%S", time.localtime(started)) if started else "?"
    what = "a test run" if entry.get("kind") == SUITE else f"a {entry.get('kind')}"
    return f"{what}, pid {entry.get('pid')}, since {since}, in {entry.get('worktree')}"


def claim_bench(root: Path, lineage: set[int] | None = None
                ) -> tuple[Registration | None, str | None]:
    """(registration, None) to go ahead, (None, reason) to refuse.

    `(None, None)` too, and that also means go ahead: this bench was started by
    a test run of this repository (its own smoke test), or this platform has no
    registry. `lineage` is for tests; it defaults to `ancestors()`.
    """
    directory = registry_dir(root)
    if fcntl is None or directory is None:
        return None, None
    with _guarded(directory):
        entries = _live_locked(directory)
        mine = ancestors() if lineage is None else lineage
        if any(e.get("kind") == SUITE and e.get("pid") in mine for e in entries):
            return None, None
        others = [e for e in entries if e.get("pid") != os.getpid()]
        if others:
            lines = "\n".join(f"    {describe(e)}" for e in others)
            return None, (
                "REFUSED: the latency bench measures this machine, and another run "
                "of this repository is using it now:\n"
                f"{lines}\n"
                "Two runs at once slow each other, so the numbers would describe the "
                "overlap, not the engine. Run the bench when nothing else of this "
                "repository is running (docs/PARALLEL.md).")
        return _register_locked(directory, BENCH, root), None


def bench_gate(root: Path) -> Registration | int | None:
    """What a bench's `main()` calls first. An int is the exit code to return
    after the refusal has been printed; anything else means measure, and a
    Registration is closed when the bench ends."""
    registration, refusal = claim_bench(root)
    if refusal:
        print(refusal)
        return REFUSED_BUSY
    if fcntl is None:
        print("⚠ no run registry on this platform: this bench cannot tell whether "
              "another run of this repository is using the machine.")
    return registration
