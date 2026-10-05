"""A hook must finish. An unbounded lock wait is not a verdict, it is a hang.

⚠ THE CIRCUIT BREAKER DID NOT COVER THIS, AND THE REASONING THAT SAYS SO IS
RIGHT. A wedged daemon is tripped out by `daemon/client`, the next call falls
through to the in-process path — and there it takes the SAME lock and waits the
same forever. Bandaging the daemon does nothing for the cause.

⚠ AND OBSERVE MODE DOES NOT HELP, WHICH IS THE PART THAT MAKES IT SERIOUS.
Measured with the lock held deliberately for 4 s:

    STING_OBSERVE=0    the hook took 4.07 s
    STING_OBSERVE=1    the hook took 4.02 s

`sting_hook.main()`'s choke point turns a blocking RESULT into exit 0. A wait is
not a result; it is the absence of one, arriving before any code that could
suppress it. **A guard that promises to block nothing must also promise to
finish.**

⚠ WHAT CAN ACTUALLY HOLD THE LOCK — most of the obvious answers cannot:

    a daemon SIGKILLed mid-write   lock RELEASED by the kernel    not reachable
    a hook killed by its agent     lock RELEASED                  not reachable
    a crashed machine, local FS    nothing holds it after reboot  not reachable
    a SIGSTOPped process           HELD indefinitely              reachable
    a filesystem that stops
      answering (NFS, hung FUSE)   HELD indefinitely              reachable

`flock` belongs to an open file description and the kernel closes those when a
process dies, however it dies. So the two most-cited causes are not causes at
all. What remains is a LIVE process stuck inside the critical section — which
contains `fsync`, `stat` and `subprocess`, every one of which blocks forever on
a filesystem that has stopped answering.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

# ⚠ `importorskip`, NOT `import fcntl`, AND THIS FILE IS WHY PHASE 0 CAME BACK.
#
# `fcntl` at MODULE SCOPE is exactly what stopped the engine importing on
# Windows, and `core/locking.py` exists so that no file in `core/` can do it
# again. Nothing stopped a TEST from doing it — and a module-scope ImportError
# in a test is worse than one in the engine, because it is a COLLECTION ERROR:
# pytest abandons the whole run, so ZERO Windows tests execute and the job
# reports a collection failure instead of results.
#
# ⚠ WHY SKIP THE MODULE RATHER THAN GUARD EACH USE. The subject of this file is
# POSIX `flock` semantics — a lock held across a SIGSTOP, an fd the kernel
# releases on death, a HOLDER subprocess that itself calls `fcntl.flock`. On
# Windows `core/locking` takes the `msvcrt` arm and none of those behaviours
# exist to assert. Guarding each use would leave a file that runs on Windows and
# checks nothing there, which is the shape this project keeps refusing.
#
# ⚠ AND THE LOSS IS STATED RATHER THAN SILENT. `pytest.ini` sets `-ra`, so this
# skip prints its reason on every run. What is NOT covered on Windows is named
# in the reason, and `docs/48-windows-suite-collection.md` records that the
# `msvcrt` arm's timeout has never been exercised anywhere.
fcntl = pytest.importorskip(
    "fcntl",
    reason="POSIX-ONLY: this file asserts `flock` semantics — a lock surviving "
           "SIGSTOP, an fd the kernel releases on death, and a HOLDER "
           "subprocess that calls fcntl.flock. On Windows `core/locking` takes "
           "the msvcrt arm, where none of those exist. ⚠ THE msvcrt TIMEOUT IS "
           "THEREFORE UNTESTED ON EVERY PLATFORM — see "
           "docs/48-windows-suite-collection.md.")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import locking, session                                    # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HOLDER = """
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
sys.stderr.write("HELD\\n"); sys.stderr.flush()
time.sleep(float(sys.argv[2]))
"""


def _hold(path, seconds):
    proc = subprocess.Popen([sys.executable, "-c", HOLDER, str(path),
                             str(seconds)], stderr=subprocess.PIPE)
    assert proc.stderr.readline().strip() == b"HELD", "the holder never locked"
    return proc


# ────────────────────────────────────────────── the kernel releases on death

@pytest.mark.parametrize("sig", ["SIGKILL", "SIGTERM"])
def test_a_dead_process_cannot_hold_the_lock(tmp_path, sig):
    """⚠ THE MEASUREMENT THAT REMOVES TWO OF THE FOUR SUSPECTED CAUSES.

    "A daemon killed mid-write" and "a hook killed by an agent timing out" are
    the two obvious explanations for a stuck lock, and neither is one. Writing
    a timeout to defend against them would be defending against nothing.
    """
    import signal

    target = tmp_path / "s.json"
    target.write_text("{}", encoding="utf-8")
    proc = _hold(target, 600)

    fd = os.open(target, os.O_RDWR)
    try:
        with pytest.raises(OSError):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # precondition

        proc.send_signal(getattr(signal, sig))
        proc.wait(timeout=30)

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
                return
            except OSError:
                time.sleep(0.02)
        pytest.fail(f"the lock survived {sig}, which would change the whole "
                    f"argument for this timeout")
    finally:
        os.close(fd)


# ─────────────────────────────────────────────────────── the timeout itself

def test_acquire_gives_up_instead_of_waiting_forever(tmp_path):
    target = tmp_path / "s.json"
    target.write_text("{}", encoding="utf-8")
    proc = _hold(target, 30)
    fd = os.open(target, os.O_RDWR)
    try:
        started = time.perf_counter()
        with pytest.raises(locking.LockUnavailable):
            locking._acquire(fd, shared=False, timeout=0.4)
        waited = time.perf_counter() - started
        assert 0.4 <= waited < 3.0, f"waited {waited:.2f}s"
    finally:
        os.close(fd)
        proc.kill()
        proc.wait(timeout=10)


def test_an_uncontended_acquire_pays_no_poll(tmp_path):
    """⚠ THE POLL LOOP MUST NOT BECOME A LATENCY COST ON THE COMMON PATH.

    The overwhelming majority of acquires are uncontended — the lock is held for
    0.177 ms p50. If the first attempt slept before trying, every action on
    every machine would pay the poll interval.
    """
    target = tmp_path / "s.json"
    target.write_text("{}", encoding="utf-8")
    fd = os.open(target, os.O_RDWR)
    try:
        started = time.perf_counter()
        for _ in range(200):
            locking._acquire(fd, shared=False)
            locking._release(fd)
        each = (time.perf_counter() - started) / 200 * 1000
        assert each < locking._LOCK_POLL * 1000, (
            f"{each:.3f} ms per uncontended acquire — that is a sleep")
    finally:
        os.close(fd)


def test_the_default_timeout_is_far_above_measured_contention():
    """⚠ PINNED, BECAUSE THE NUMBER IS AN ARGUMENT AND NOT A PREFERENCE.

    ⚠ The DEFAULT is asserted, not `lock_timeout()`, which reads the
    environment — a developer with STING_LOCK_TIMEOUT exported would otherwise
    fail this test and nobody else would, which is the leaky-environment shape
    conftest already clears five other variables for.

    Measured on this machine: the lock is held 0.177 ms p50 / 0.977 ms max for
    an ordinary action, and sixteen hooks racing on ONE session cost 237.6 ms in
    total. 5 s is ~25x the worst contention ever seen here. Lowering it towards
    those figures would start refusing legitimate waits; raising it back towards
    the Windows arm's 30 s would make a wedge cost 30 s per tool call.
    """
    assert locking.DEFAULT_LOCK_TIMEOUT == 5.0
    assert locking._LOCK_TIMEOUT == 30.0, (
        "the Windows arm keeps its own number — its locks are mandatory, its "
        "contention profile is not the one measured, and it is untested here")


# ─────────────────────────────────────────── what the hook does about it

def _payload(session="locked", command="git status"):
    return json.dumps({"session_id": session, "cwd": ROOT,
                       "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": command}})


def _env(store, **over):
    env = dict(os.environ)
    env["STING_SESSION_ROOT"] = str(store)
    env["STING_LOG"] = str(os.path.join(store, "decisions.jsonl"))
    for k, v in over.items():
        env[k] = str(v)
    return env


def test_a_stuck_lock_no_longer_hangs_the_hook(tmp_path, monkeypatch):
    """The whole point: the hook FINISHES, and says why it is degraded."""
    store = tmp_path / "store"
    store.mkdir()
    target = store / "locked.json"
    target.write_text("{}", encoding="utf-8")
    proc = _hold(target, 30)
    try:
        env = _env(store, STING_LOCK_TIMEOUT="0.5", STING_OBSERVE="0")
        started = time.perf_counter()
        done = subprocess.run([sys.executable, os.path.join(ROOT, "hook_entry.py")],
                              input=_payload(), capture_output=True, text=True,
                              env=env, timeout=120)
        waited = time.perf_counter() - started

        assert waited < 20, f"the hook still hung for {waited:.1f}s"
        assert done.returncode == 0, done.stderr
        assert "degraded" in done.stderr
        assert "LABELLING WAS NOT RECORDED" in done.stderr, (
            "the developer must be told the session forgot this action")
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_a_stuck_lock_still_fails_closed_at_a_sink(tmp_path):
    """⚠ DEGRADED IS NOT OPEN. The verdict comes from `fallback_verdict`, which
    refuses at sinks and allows elsewhere — so the wedge costs memory, not the
    guard. Without this the test above would be satisfied by a hook that waved
    everything through quickly."""
    store = tmp_path / "store"
    store.mkdir()
    target = store / "locked.json"
    target.write_text("{}", encoding="utf-8")
    proc = _hold(target, 30)
    try:
        env = _env(store, STING_LOCK_TIMEOUT="0.5", STING_OBSERVE="0")
        done = subprocess.run([sys.executable, os.path.join(ROOT, "hook_entry.py")],
                              input=_payload(command="git push origin main"),
                              capture_output=True, text=True, env=env, timeout=120)

        assert done.returncode == 0, done.stderr
        assert '"deny"' in done.stdout or '"ask"' in done.stdout, (
            f"a sink under a stuck lock must not be allowed: {done.stdout!r}")
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_the_audit_record_is_not_lost_when_the_state_lock_times_out(tmp_path):
    """⚠ THE STOP CONDITION, ANSWERED WITH A FILE LISTING.

    The question was "risk the chain or lose the record". Neither happens,
    because THE TWO LOCKS ARE ON DIFFERENT FILES: the state is
    `<id>.json` and the chain is a separate log with its own lock, taken
    afterwards by `_log`. The chain is never written unserialised, and the
    record still lands.
    """
    from core import audit_log
    from pathlib import Path

    store = tmp_path / "store"
    store.mkdir()
    target = store / "locked.json"
    target.write_text("{}", encoding="utf-8")
    proc = _hold(target, 30)
    try:
        env = _env(store, STING_LOCK_TIMEOUT="0.5", STING_OBSERVE="0")
        subprocess.run([sys.executable, os.path.join(ROOT, "hook_entry.py")],
                       input=_payload(), capture_output=True, text=True,
                       env=env, timeout=120)

        log = Path(store) / "decisions.jsonl"
        assert log.exists(), "the decision record must still be written"
        records = audit_log.read_records(log)
        assert records, "and it must contain the action"
        ok, at, detail = audit_log.verify_chain(log)
        assert ok, f"the chain must still verify: {at} {detail}"
    finally:
        proc.kill()
        proc.wait(timeout=10)
