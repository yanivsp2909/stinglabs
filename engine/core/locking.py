"""File locking, behind one interface, so the platform arm is a seam and not a
scattered `if sys.platform` across three core modules.

────────────────────────────────────────────────────────────────────────────────
WHY THIS FILE EXISTS
────────────────────────────────────────────────────────────────────────────────

`import fcntl` sat at MODULE SCOPE in `core/session.py`, `core/audit_log.py` and
`core/allow_once.py`. On Windows that is an ImportError before any code runs, so
**the engine does not start** — which is also the one Windows defect that fails
LOUDLY. The other six named in docs/windows-redecision.md fail silently, and a
guard that boots while catching nothing is worse than one that refuses to boot.

⚠ **THE SEAM COMES BEFORE THE WINDOWS ARM, DELIBERATELY.** Writing both
implementations before either can be exercised is how the untested one ships.
This module is POSIX-only on purpose: it makes the suite *start* on Windows,
which is what turns "we think these 7 sites break" into a measured list.

────────────────────────────────────────────────────────────────────────────────
⚠ THE INTERFACE IS NOT A TRANSLATION OF flock, AND THAT IS THE HARD PART
────────────────────────────────────────────────────────────────────────────────

POSIX `flock` and Windows `msvcrt.locking` do not agree on anything that
matters here:

                        POSIX flock          Windows msvcrt.locking
    granularity         whole file           BYTE RANGE
    shared mode         LOCK_SH              ⚠ NONE — exclusive only
    advisory/mandatory  advisory             ⚠ MANDATORY
    on close            released             released
    blocking            LOCK_EX blocks       LK_LOCK retries 10× then raises

**`audit_log` and `session` both take `LOCK_SH` today**, and Windows has no
shared mode. So the Windows arm cannot be a translation; it is different
semantics presented through one interface, and the caller must not have to know
which. That is why `shared()` is a separate function from `exclusive()` — a
single `lock(fd, mode)` would let a caller pass a mode one platform cannot
honour and get silence instead of an error.

**What `shared()` means, stated once here so no caller has to guess:**

    "no writer may be mid-write while I read this"

On POSIX that is `LOCK_SH`, and concurrent readers do not block each other. On
Windows it will have to be an exclusive byte-range lock, so readers WILL
serialise against each other. That is a throughput difference, not a
correctness one — no reader observes a torn file either way — and it is written
down because a future reader of a Windows profile will otherwise think they
found a bug.
"""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager

WINDOWS = sys.platform.startswith("win")

# ⚠ IMPORTED INSIDE THE PLATFORM BRANCH, NEVER AT MODULE SCOPE. That placement
# is the entire defect this file was created to remove; putting it back at the
# top would reintroduce it in the one module that exists to prevent it.
if not WINDOWS:
    import fcntl
    msvcrt = None
else:                                                            # pragma: no cover
    import msvcrt
    fcntl = None

# ⚠ ONE BYTE, AT OFFSET 0, AND IT NEED NOT EXIST. `msvcrt.locking` is a
# BYTE-RANGE lock, so a region has to be chosen; Windows permits locking a range
# beyond end-of-file, which matters because a session file is created empty and
# the first writer must be able to lock it before there is anything to lock.
# One byte is enough: every caller in this repo locks the WHOLE file, so the
# range only has to be the same one on both sides, not large.
_LOCK_BYTES = 1

# How long to keep retrying before giving up. `msvcrt.LK_LOCK` retries for about
# ten seconds and then raises, which is both too short to be safe under a
# contended append and impossible to tune — so the retry loop is written here
# with `LK_NBLCK` instead.
_LOCK_TIMEOUT = 30.0
_LOCK_POLL = 0.005

# ─────────────────────────────────────────────────────────────────────────────
# ⚠ THE POSIX ARM HAD NO TIMEOUT AT ALL, AND THAT IS A HOLE OBSERVE MODE
#   CANNOT COVER.
#
# `fcntl.flock(fd, LOCK_EX)` blocks forever. A hook waiting on a lock nobody
# releases waits forever, and it waits BEFORE it has produced any output — so
# `sting_hook.main()`'s observe choke point, which turns every blocking result
# into exit 0, never runs. Measured, with the lock held deliberately:
#
#     lock held 4 s, STING_OBSERVE=0   the hook took 4.07 s
#     lock held 4 s, STING_OBSERVE=1   the hook took 4.02 s
#
# **Observe mode does not help**, because an unbounded wait is not a blocking
# RESULT — it is the absence of one. A guard that promises to block nothing must
# also promise to finish.
#
# ⚠ WHAT CAN ACTUALLY HOLD IT — measured, and most of the obvious answers
# CANNOT:
#
#     a daemon SIGKILLed mid-write     lock RELEASED by the kernel   not reachable
#     a hook killed by an agent        lock RELEASED                 not reachable
#     a crashed machine, local FS      nothing holds it after reboot not reachable
#     a process SIGSTOPped             lock HELD indefinitely        reachable
#     a filesystem that stops
#       answering — NFS, a hung FUSE
#       mount, a failing disk          lock HELD indefinitely        reachable
#
# `flock` belongs to an open file description, and the kernel closes those when
# a process dies however it dies. So the two most-cited causes are not causes.
# What remains is a LIVE process stuck inside the critical section — and the
# critical section contains `fsync`, `stat` and `subprocess`, every one of which
# blocks indefinitely on a filesystem that has stopped answering. `~/.sting` on
# a network home is the realistic shape, and a fleet is where that lives.
#
# ⚠ THE VALUE IS MEASURED, NOT GUESSED:
#
#     lock HELD per ordinary action     p50 0.177 ms, max 0.977 ms
#     16 hooks in parallel, ONE session total 237.6 ms, i.e. <=183 ms of waiting
#     a commit verdict holds it longest — the git probes run inside the lock
#
# 5 s is ~25x the worst contention ever measured here and ~5000x the median
# hold. To reach it legitimately you would need something like eighty concurrent
# commit verdicts against a single session. If it fires, something is broken.
DEFAULT_LOCK_TIMEOUT = 5.0

# ⚠ READ PER CALL, NOT AT IMPORT, AND THE REASON IS THE DAEMON. A module-level
# `os.environ.get` is evaluated once — in a resident process that is the
# environment of whichever shell happened to start it, frozen for its lifetime,
# which is the exact mistake `daemon/protocol.PINNED` exists to avoid one layer
# up. It also makes the value untestable without reimporting the module.
def lock_timeout() -> float:
    """Seconds to wait for a lock. `STING_LOCK_TIMEOUT` overrides the default.

    An unparseable or non-positive value falls back to the default rather than
    disabling the bound — "0" must not mean "wait forever", and a typo in an
    environment variable must not silently restore the hang this removes.
    """
    raw = os.environ.get("STING_LOCK_TIMEOUT")
    if raw:
        try:
            value = float(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return DEFAULT_LOCK_TIMEOUT

# ⚠ THE WINDOWS ARM KEEPS ITS 30 s AND IS NOT CHANGED FROM HERE. Its locks are
# MANDATORY rather than advisory and its contention profile is therefore not the
# one measured above. Lowering an untested platform's timeout on the strength of
# a POSIX measurement is exactly the kind of change that ships broken; the two
# numbers stay separate until somebody can measure the second one.
# ─────────────────────────────────────────────────────────────────────────────


class LockUnavailable(RuntimeError):
    """Raised when the platform cannot provide locking at all.

    ⚠ NOT CAUGHT AND NOT DOWNGRADED HERE. A caller that swallowed this would be
    performing an unserialised read-modify-write on the session state or the
    audit chain, which is silent corruption — the failure mode this whole module
    exists to prevent. If it is ever raised, the honest response is to fail the
    action, not to proceed without the lock.
    """


@contextmanager
def exclusive(fd: int):
    """Nobody else may read or write this file while the block runs.

    Blocks until the lock is available. Always released, including on an
    exception inside the block — that `finally` is why this is a context
    manager rather than a pair of functions somebody can forget to pair.
    """
    _acquire(fd, shared=False)
    try:
        yield
    finally:
        _release(fd)


@contextmanager
def shared(fd: int):
    """No WRITER may be mid-write while the block runs.

    See the module docstring: on POSIX readers do not block each other; on
    Windows they will, because there is no shared mode. Correctness is the same
    on both — a reader never sees a half-written file.
    """
    _acquire(fd, shared=True)
    try:
        yield
    finally:
        _release(fd)


# ─────────────────────────────────────────────────────────────── POSIX arm

def _acquire(fd: int, *, shared: bool, timeout: float | None = None) -> None:
    """Take the lock, or raise `LockUnavailable` after `timeout` seconds.

    ⚠ NON-BLOCKING IN A LOOP, NOT `LOCK_EX`. The blocking form has no timeout on
    any platform, and there is no portable way to interrupt it — `SIGALRM` would
    be a signal handler installed by a library into a process it does not own.
    Polling is the boring answer and it is the one that can be bounded.

    ⚠ THE POLL INTERVAL IS NOT A LATENCY COST IN THE COMMON CASE. The first
    attempt is made before any sleep, so an uncontended acquire — which is the
    overwhelming majority, see the measurement above — costs one `flock` call
    and no sleep at all.
    """
    if WINDOWS:                                                  # pragma: no cover
        _acquire_windows(fd)
        return
    limit = lock_timeout() if timeout is None else timeout
    mode = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB
    deadline = time.monotonic() + limit
    while True:
        try:
            fcntl.flock(fd, mode)
            return
        except OSError:
            # Held by somebody else — the normal case under contention, and an
            # error only once the deadline passes.
            if time.monotonic() >= deadline:
                raise LockUnavailable(
                    f"could not take the lock after {limit:.1f}s. "
                    f"Another process is holding it and is not letting go — a "
                    f"suspended process, or a filesystem that has stopped "
                    f"answering. Refusing to proceed unserialised.")
            time.sleep(_LOCK_POLL)


def _release(fd: int) -> None:
    if WINDOWS:                                                  # pragma: no cover
        _release_windows(fd)
        return
    fcntl.flock(fd, fcntl.LOCK_UN)


# ───────────────────────────────────────────────────────────── Windows arm

def _at_offset_zero(fd: int, action) -> None:                    # pragma: no cover
    """Run `action` with the file position at 0, then put it back.

    ⚠ THE RESTORE IS NOT TIDINESS. `msvcrt.locking` locks relative to the
    CURRENT file position, so the position is part of the lock's identity: lock
    at 0 and unlock at 40 and the unlock targets a different range, leaving the
    original locked until the process dies. Every caller in this repo also does
    its own `lseek`/`read`/`write` on this fd, so moving it under them would
    corrupt the very read-modify-write the lock exists to protect.
    """
    previous = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        action()
    finally:
        os.lseek(fd, previous, os.SEEK_SET)


def _acquire_windows(fd: int) -> None:                           # pragma: no cover
    """⚠ ALWAYS EXCLUSIVE, INCLUDING FOR `shared()`. Windows has no shared
    mode, so readers serialise against each other. That is a throughput
    difference and not a correctness one: no reader observes a torn file
    either way, which is the property `shared()` actually promises.

    Retried by hand rather than using `LK_LOCK`, whose ~10 s limit is both too
    short under a contended append and not tunable.
    """
    deadline = time.monotonic() + _LOCK_TIMEOUT

    def attempt():
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, _LOCK_BYTES)
                return
            except OSError:
                # ⚠ HELD BY SOMEBODY ELSE — the normal case, not an error. It is
                # only a failure once the deadline passes, and then it is raised
                # rather than swallowed: proceeding without the lock is the
                # silent corruption this module exists to prevent.
                if time.monotonic() >= deadline:
                    raise LockUnavailable(
                        f"could not lock after {_LOCK_TIMEOUT}s — another "
                        f"process is holding it. Refusing to proceed "
                        f"unserialised.")
                time.sleep(_LOCK_POLL)

    _at_offset_zero(fd, attempt)


def _release_windows(fd: int) -> None:                           # pragma: no cover
    def attempt():
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, _LOCK_BYTES)
        except OSError:
            # ⚠ SWALLOWED, AND ONLY HERE. An unlock that fails because the
            # region was never locked, or was already released when the handle
            # closed, must not turn a completed write into an exception — the
            # data is already on disk and the process is about to close the fd,
            # which releases the lock anyway. An acquire failure is fatal; a
            # release failure is not.
            pass

    _at_offset_zero(fd, attempt)


def describe() -> str:
    """What this process is actually using. For preflight and bug reports —
    "which lock am I on" must never be a guess."""
    if WINDOWS:                                                  # pragma: no cover
        return (f"windows: msvcrt.locking, byte range [0,{_LOCK_BYTES}), "
                f"ALWAYS EXCLUSIVE (no shared mode), {_LOCK_TIMEOUT}s timeout")
    return "posix: fcntl.flock (shared and exclusive)"
