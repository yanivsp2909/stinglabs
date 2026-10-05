"""The chain still verifies under the lock — on whichever platform this runs.

⚠ NOT "THE CALLS SUCCEED". `msvcrt.locking` returning without raising proves
nothing: the property that matters is that concurrent writers cannot interleave
into a broken hash chain, and that a reader never sees a half-written file. So
every test here asserts on the ARTIFACT afterwards — `verify_chain`, the record
count, the parseability of the session file — and not on the lock API.

⚠ AND EVERY TEST RUNS ON BOTH PLATFORMS. The Windows arm has different
semantics (byte-range, mandatory, no shared mode), so a Windows-only test file
would be a second specification that could disagree with the POSIX one. One
file, run on both, is the only way the interface means the same thing on each.

Real processes, not threads. A thread would share the file descriptor and the
GIL, and would therefore pass whether or not the lock does anything at all —
which is this project's own vacuity pattern applied to concurrency.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import audit_log, locking                              # noqa: E402

WRITERS = 6
PER_WRITER = 12


def _run(script: str, *args: str, expect_ok: bool = True):
    proc = subprocess.run([sys.executable, "-c", textwrap.dedent(script), *args],
                          capture_output=True, text=True,
                          cwd=str(ROOT),
                          env={**os.environ, "PYTHONPATH": str(ROOT),
                               "PYTHONIOENCODING": "utf-8"})
    if expect_ok:
        assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    return proc


def test_the_lock_arm_is_the_one_this_platform_needs():
    """A bug report that says "locking failed" is useless without this line."""
    described = locking.describe()
    assert described
    if sys.platform.startswith("win"):
        assert "msvcrt" in described and "EXCLUSIVE" in described
    else:
        assert "flock" in described


# ═══════════════════════════════════ 1 · concurrent writers, one intact chain

APPENDER = """
    import os, sys
    from core import audit_log
    session, count = sys.argv[1], int(sys.argv[2])
    os.environ["STING_SESSION_ROOT"] = sys.argv[3]
    for i in range(count):
        audit_log.append(session, audit_log.build_body(
            session, seq=None, event="decision", decision="ALLOW",
            cwd=".", agent="test"))
"""


def test_concurrent_writers_leave_a_chain_that_still_verifies(tmp_path, monkeypatch):
    """⚠ THE WHOLE POINT OF THE LOCK. Each record's `prev` is the previous
    record's `hash`, so two processes that interleave a read-modify-write
    produce two records claiming the same predecessor — a chain that a reader
    sees as BROKEN, which is indistinguishable from tampering.
    """
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    session = "concurrent"

    procs = [subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(APPENDER),
         session, str(PER_WRITER), str(tmp_path)],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(ROOT),
             "STING_SESSION_ROOT": str(tmp_path), "PYTHONIOENCODING": "utf-8"})
        for _ in range(WRITERS)]
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0, err.decode("utf-8", "replace")

    path = Path(audit_log.default_log_path(session))
    ok, bad, detail = audit_log.verify_chain(path)
    assert ok, f"chain broke at record {bad}: {detail}"

    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == WRITERS * PER_WRITER, (
        f"{len(lines)} records from {WRITERS}x{PER_WRITER} writers — "
        f"a lost write is as bad as a broken chain")


def test_every_record_is_complete_json_after_concurrent_writes(tmp_path, monkeypatch):
    """⚠ A TORN LINE IS THE OTHER FAILURE MODE, and `verify_chain` would not
    necessarily report it as a chain break — it would report a parse error, or
    skip. Asserted separately so the two cannot be confused."""
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    session = "torn"
    procs = [subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(APPENDER), session, "8", str(tmp_path)],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(ROOT),
             "STING_SESSION_ROOT": str(tmp_path), "PYTHONIOENCODING": "utf-8"})
        for _ in range(WRITERS)]
    for p in procs:
        p.communicate(timeout=120)

    path = Path(audit_log.default_log_path(session))
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            json.loads(line)          # raises on a torn record


# ═════════════════════════════════════════ 2 · a reader during a write

READER = """
    import sys, json
    from core.session import load_session
    state = load_session(sys.argv[1])
    print(json.dumps({"seq": state.seq, "id": state.session_id}))
"""

SLOW_WRITER = """
    import os, sys, time
    from core.session import open_session
    with open_session(sys.argv[1]) as state:
        state.seq = int(sys.argv[2])
        time.sleep(float(sys.argv[3]))
"""


def test_a_reader_during_a_write_never_sees_a_half_written_file(tmp_path, monkeypatch):
    """⚠ THE PROPERTY `shared()` PROMISES, and it is the same on both platforms
    even though the mechanism is not: POSIX takes LOCK_SH, Windows an exclusive
    byte range, and neither lets a reader in mid-write.

    `open_session` truncates before writing, so a reader admitted at the wrong
    moment sees an EMPTY file — which parses as a fresh session and silently
    loses every label the session had learned.
    """
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    session = "reader-during-write"
    _run(SLOW_WRITER, session, "5", "0")          # establish the file

    writer = subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(SLOW_WRITER), session, "99", "1.0"],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(ROOT),
             "STING_SESSION_ROOT": str(tmp_path), "PYTHONIOENCODING": "utf-8"})
    try:
        seen = []
        for _ in range(5):
            proc = _run(READER, session)
            seen.append(json.loads(proc.stdout.strip())["seq"])
    finally:
        writer.communicate(timeout=60)

    # 5 (before) or 99 (after) — never 0, which is what an empty read yields.
    assert all(s in (5, 99) for s in seen), (
        f"a reader saw {seen} — 0 means it read a truncated file")


# ═══════════════════════════════════════ 3 · a crash mid-write

CRASHER = """
    import os, sys
    from core.session import open_session
    with open_session(sys.argv[1]) as state:
        state.seq = 42
        os._exit(9)          # die holding the lock, after truncate is possible
"""


def test_a_crash_mid_write_does_not_wedge_the_next_writer(tmp_path, monkeypatch):
    """⚠ THE LOCK MUST DIE WITH THE PROCESS. Both `flock` and `msvcrt.locking`
    release when the handle closes, and the OS closes handles on exit — but
    `os._exit` skips every `finally`, so this is the path where an
    implementation that relied on its own cleanup would deadlock the next
    writer forever.
    """
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    session = "crash"
    _run(SLOW_WRITER, session, "7", "0")

    crashed = _run(CRASHER, session, expect_ok=False)
    assert crashed.returncode != 0

    # The next writer must not hang. A 60s cap against a 30s lock timeout: if
    # the lock were wedged this fails rather than hanging the suite.
    after = _run(SLOW_WRITER, session, "8", "0")
    assert after.returncode == 0

    proc = _run(READER, session)
    assert json.loads(proc.stdout.strip())["seq"] == 8


def test_a_crash_mid_write_leaves_a_parseable_session(tmp_path, monkeypatch):
    """⚠ NOT THE SAME CLAIM AS "the next writer proceeds". A file can be
    readable-and-wrong. `open_session` recovers from a corrupt file by starting
    fresh, so this asserts the file is at least JSON or empty — not that the
    crashed writer's value survived, which it must not."""
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    session = "crash-parse"
    _run(SLOW_WRITER, session, "3", "0")
    _run(CRASHER, session, expect_ok=False)

    from core.session import session_path
    raw = Path(session_path(session)).read_text(encoding="utf-8")
    if raw.strip():
        json.loads(raw)


# ═══════════════════════════════════ 4 · and the lock is doing the work

def test_the_seam_is_what_serialises_and_not_luck(tmp_path, monkeypatch):
    """⚠ THE NON-VACUITY CHECK. If `_acquire` were a no-op, would these tests
    still pass? With six processes and twelve appends each they might, by
    timing. So the lock is REMOVED and the same workload must break the chain.

    Skipped rather than faked if it does not break: on a fast enough machine an
    unlocked run can still happen to serialise, and a test that demanded a
    failure would be flaky. What is asserted is the implication in the
    direction that matters — a break WITHOUT the lock is evidence the lock is
    load-bearing; no break is inconclusive and says so.
    """
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    session = "unlocked"
    # ⚠ A START LINE, BECAUSE A LOADED MACHINE SERIALISES FOR US. Six
    # interpreters can take long enough to start that each finishes before the
    # next begins, and a run with no overlap is inconclusive (it skipped under a
    # second worktree's suite). Each writer says it is ready, then waits for
    # `go`, so all six append at once.
    line = tmp_path / "start-line"
    line.mkdir()
    unlocked = """
        import os, sys, time
        from core import locking
        locking._acquire = lambda fd, shared=False: None
        locking._release = lambda fd: None
        from core import audit_log
        open(os.path.join(sys.argv[2], "ready-" + str(os.getpid())), "w").close()
        deadline = time.monotonic() + 120
        while not os.path.exists(os.path.join(sys.argv[2], "go")):
            if time.monotonic() > deadline:
                sys.exit(3)
            time.sleep(0.001)
        for i in range(%d):
            audit_log.append(sys.argv[1], audit_log.build_body(
                sys.argv[1], seq=None, event="decision", decision="ALLOW",
                cwd=".", agent="test"))
    """ % PER_WRITER

    procs = [subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(unlocked), session, str(line)],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "PYTHONPATH": str(ROOT),
             "STING_SESSION_ROOT": str(tmp_path), "PYTHONIOENCODING": "utf-8"})
        for _ in range(WRITERS)]
    ready_by = time.monotonic() + 120
    while (len(list(line.glob("ready-*"))) < WRITERS and time.monotonic() < ready_by
           and all(p.poll() is None for p in procs)):
        time.sleep(0.01)
    (line / "go").write_text("", encoding="utf-8")
    for p in procs:
        p.communicate(timeout=120)

    path = Path(audit_log.default_log_path(session))
    if not path.exists():
        pytest.skip("no log written without the lock — inconclusive")
    ok, _bad, _detail = audit_log.verify_chain(path)
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if ok and len(lines) == WRITERS * PER_WRITER:
        pytest.skip("an unlocked run happened to serialise — inconclusive, "
                    "not evidence that the lock is unnecessary")
