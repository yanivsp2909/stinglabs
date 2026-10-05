"""One shipper per state root, and a way to ask whether one is running.

⚠ WHY A LOCK EXISTS AT ALL, MEASURED RATHER THAN ASSUMED.

`Cursor._load()` reads `cursor.json` ONCE, at construction, and `Cursor.save()`
rewrites the WHOLE file from that in-memory copy. Two shippers therefore do not
interleave — they diverge from the moment the second one starts, and every save
clobbers the other's entire view.

Most of what that costs is harmless:

  * duplicate sends      the collector deduplicates by document id, so nothing
                         is stored twice;
  * a stale `acked_seq`  a clobber moves it BACKWARDS, which only means
                         re-shipping. Backwards is the safe direction.

⚠ ONE THING IT COSTS IS NOT HARMLESS. `skipped_seqs` names records `_split`
stepped over — records the collector REFUSED and that exist nowhere else. If
process A records a skipped seq and process B saves its stale list over it, that
name is gone, while `acked_seq` keeps climbing past it. `tools/prune_shipped.py`
then reads it as acknowledged and DELETES THE ONE RECORD PROVEN NOT TO BE AT THE
COLLECTOR.

So: two shippers on one cursor can destroy evidence, and the answer to "does
this need a lock" is yes. It is also what makes starting a shipper at install
safe — a second one cannot race the first, it exits.

⚠ AND THE LOCK IS THE ONLY HONEST ANSWER TO "IS ONE RUNNING". `service.loaded()`
asks launchd/systemd/schtasks, which know nothing about a shipper started from a
Startup-folder `.cmd`, from a terminal, or by the installer. The lock is held by
the process itself, so it answers for all of them.
"""
from __future__ import annotations

import errno
import json
import os
import sys
import time
from pathlib import Path

# ⚠ WHAT THIS LOCK CANNOT DO, AND THE DEPLOYMENT IT MATTERS ON.
# `flock` is ADVISORY and, on some NFS/SMB mounts, is honoured only locally or
# emulated with known gaps. `installer/prepare.py` says plainly that plenty of
# enterprises put $HOME on NFS and the guard works there — and this file lives
# under $HOME. On such a mount two shippers can each believe they hold it, which
# is the corruption this exists to prevent. Nothing here detects that; it is a
# limit of the mechanism, not a bug in it, and the mitigation if it ever bites
# is to point STING_SHIPPER_STATE at local disk.
#
# ⚠ AND DELETING THE LOCK FILE DEFEATS IT. `rm -rf ~/.sting` — which the
# uninstaller itself prints — lets a new process open a NEW INODE at the same
# path and lock that, while the old process still holds the deleted one.
LOCK_NAME = "shipper.lock"


def lock_path(state_root: Path) -> Path:
    return Path(state_root) / LOCK_NAME


def _lock_exclusive(fd: int) -> bool:
    """Non-blocking exclusive lock. False if somebody else holds it."""
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as exc:
        # ⚠ EAGAIN/EACCES MEAN "HELD", WHICH IS NOT AN ERROR. Anything else is,
        # and must not be read as "held" — a filesystem that cannot lock at all
        # would otherwise silently stop every shipper on the machine.
        if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
            return False
        raise


class Held(Exception):
    """Another shipper holds the lock. Carries its pid when it is readable."""

    def __init__(self, pid: int | None, detail: str = ""):
        super().__init__(detail or f"another shipper is running (pid {pid})")
        self.pid = pid


class Lock:
    """Held for the life of the process. Released by exit, including a kill.

    ⚠ NOT A PID FILE WITH A LIVENESS CHECK. A pid file left by a crashed process
    has to be distinguished from a live one by guessing — and a recycled pid
    makes that guess wrong in the direction that refuses to start. An OS lock is
    released by the kernel when the holder dies, whatever killed it, so a stale
    lock cannot exist. The pid is written INSIDE the locked file purely so a
    reader can name who holds it.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> "Lock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if not _lock_exclusive(fd):
                raise Held(_read_pid(self.path))
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps({"pid": os.getpid(), "since": time.time(),
                                  "argv0": sys.argv[0]}).encode("utf-8"))
        try:
            os.fsync(fd)
        except OSError:
            # A filesystem that will not fsync still holds the lock; the pid is
            # a convenience for the reader, not the lock itself.
            pass
        return self

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            os.close(fd)        # closing drops flock and the msvcrt lock alike
        except OSError:
            pass

    def __enter__(self) -> "Lock":
        return self.acquire()

    def __exit__(self, *_exc) -> None:
        self.release()


def _read_pid(path: Path) -> int | None:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8") or "{}")
        pid = payload.get("pid")
        return int(pid) if pid is not None else None
    except (OSError, ValueError, TypeError):
        return None


def _read_since(path: Path) -> float | None:
    """When the holder took the lock: the moment that shipper read its
    settings, since it reads them once, at start (`shipper/run.py` `main`)."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8") or "{}")
        since = payload.get("since")
        return float(since) if isinstance(since, (int, float)) else None
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def running(state_root: Path) -> dict:
    """Is a shipper running against this state root, and which one?

    ⚠ ASKED BY TAKING THE LOCK, NOT BY LOOKING AT THE FILE. A lock file exists
    whether or not anybody holds it; the only question that means anything is
    whether it can be acquired right now. Returns immediately either way.

    `{"running": bool | None, "pid": int | None, "since": float | None,
    "detail": str}` — `None` means the question could not be answered, which
    is never the same as "no". `since` is when the running one started.
    """
    path = lock_path(state_root)
    if not path.exists():
        return {"running": False, "pid": None, "since": None,
                 "detail": f"no lock at {path} — no shipper has started here"}
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        return {"running": None, "pid": None, "since": None,
                 "detail": f"could not open {path}: {exc}"}
    try:
        if _lock_exclusive(fd):
            return {"running": False, "pid": None, "since": None,
                     "detail": "the lock is free — nothing is shipping"}
        pid = _read_pid(path)
        return {"running": True, "pid": pid, "since": _read_since(path),
                 "detail": f"a shipper holds {path}"
                            + (f" (pid {pid})" if pid else "")}
    except OSError as exc:
        return {"running": None, "pid": None, "since": None,
                 "detail": f"{type(exc).__name__}: {exc}"}
    finally:
        os.close(fd)
