"""⚠ INSTALLED, REPORTING SUCCESS, SHIPPING NOTHING — the fourth time.

launchd and systemd START a service when they load one. Windows does not:

    launchd    bootstrap + RunAtLoad=true        starts immediately
    systemd    `systemctl --user enable --now`   `--now` IS the start
    Windows    <LogonTrigger> is the task's ONLY trigger, and the Startup
               folder fires at logon too — so BOTH Windows paths wait for the
               next sign-in.

On a machine that stays logged in, that is days of an install that reported
success and shipped nothing.

Starting one is only safe because a second one cannot run: two shippers share
one `cursor.json`, `Cursor._load()` reads it once at construction, and
`Cursor.save()` rewrites the whole file — so the loser's `skipped_seqs` (the
names of records the collector REFUSED, which exist nowhere else) is silently
lost while `acked_seq` climbs past them, after which `tools/prune_shipped.py`
deletes them.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from installer import supervisor
from shipper import singleton

ROOT = Path(__file__).resolve().parent.parent


# ════════════════════════ the lock, which is what makes starting safe ══

def test_a_second_shipper_cannot_take_the_lock(tmp_path):
    first = singleton.Lock(singleton.lock_path(tmp_path)).acquire()
    try:
        with pytest.raises(singleton.Held) as caught:
            singleton.Lock(singleton.lock_path(tmp_path)).acquire()
        assert caught.value.pid == os.getpid()
    finally:
        first.release()


def test_the_lock_is_released_by_the_process_dying_not_by_cleanup(tmp_path):
    """⚠ NOT A PID FILE. A pid file left by a killed process has to be told
    apart from a live one by guessing, and a recycled pid makes that guess wrong
    in the direction that refuses to start. An OS lock is dropped by the kernel
    however the holder dies, so a stale lock cannot exist.
    """
    holder = subprocess.Popen(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(ROOT)!r});"
         f"from shipper import singleton;"
         f"l = singleton.Lock(singleton.lock_path({str(tmp_path)!r})).acquire();"
         f"print('held', flush=True); __import__('time').sleep(60)"],
        stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        assert singleton.running(tmp_path)["running"] is True
        holder.kill()                      # SIGKILL — no cleanup runs at all
        holder.wait(timeout=10)
        for _ in range(50):                # the kernel drops it promptly
            if singleton.running(tmp_path)["running"] is False:
                break
            time.sleep(0.1)
        assert singleton.running(tmp_path)["running"] is False, (
            "a killed shipper left a lock nothing can clear")
    finally:
        if holder.poll() is None:
            holder.kill()


def test_running_answers_before_any_shipper_has_ever_started(tmp_path):
    state = singleton.running(tmp_path)
    assert state["running"] is False and state["pid"] is None


def test_an_unanswerable_question_is_not_a_no(tmp_path, monkeypatch):
    """⚠ `None` AND `False` MUST NOT COLLAPSE. "I could not tell" reported as
    "nothing is running" is how a supervisor claims a machine is idle."""
    lock = singleton.lock_path(tmp_path)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("{}", encoding="utf-8")

    def refuse(*_a, **_k):
        raise OSError("open refused")

    monkeypatch.setattr(singleton.os, "open", refuse)
    assert singleton.running(tmp_path)["running"] is None


def test_a_second_shipper_exits_zero_rather_than_failing(tmp_path, monkeypatch,
                                                          capsys):
    """⚠ NOT AN ERROR. The scheduled task, the Startup shortcut and the
    installer may all legitimately try; a non-zero exit would make Task
    Scheduler report a broken task for the one state that is entirely correct.
    """
    from shipper import config as scfg
    from shipper import run as shipper_run

    class _Settings:
        state_root = tmp_path
        log_root = tmp_path
        configured = False
        collector_url = ""
        device_id = ""

    held = singleton.Lock(singleton.lock_path(tmp_path)).acquire()
    try:
        monkeypatch.setattr(scfg, "from_env", lambda: _Settings())
        monkeypatch.setattr(shipper_run, "Shipper", lambda s: object())
        assert shipper_run.main([]) == 0
        assert "already running" in capsys.readouterr().out
    finally:
        held.release()


# ════════════════════════ starting it, detached ══

def test_start_now_detaches_so_the_child_outlives_the_installer(tmp_path):
    """⚠ TASK 1.2. A child that dies with the installer is worse than none,
    because `--status` would then report a pid that is already gone."""
    wrapper = tmp_path / "wrapper.cmd"
    wrapper.write_text("#!/bin/sh\nexec sleep 30\n", encoding="utf-8")

    # spawned from a CHILD python that then exits — the installer's shape
    proc = subprocess.run(
        [sys.executable, "-c",
         f"import sys, json; sys.path.insert(0, {str(ROOT)!r});"
         f"from installer import supervisor;"
         f"print(json.dumps(supervisor.start_now({str(wrapper)!r})))"],
        capture_output=True, text=True, timeout=60)
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    assert result["started"] is True and result["pid"]

    pid = result["pid"]
    try:
        time.sleep(0.5)
        os.kill(pid, 0)                    # still alive after its parent exited
        # and it is in its OWN session, not the spawner's process group
        ps = subprocess.run(["ps", "-o", "ppid=,pgid=", "-p", str(pid)],
                             capture_output=True, text=True)
        ppid, pgid = (int(x) for x in ps.stdout.split())
        # ⚠ THIS ASSERTION WAS `ppid != proc.returncode or True`, WHICH IS A
        # TAUTOLOGY — `X or True` can never fail — AND COMPARED A PID TO AN EXIT
        # CODE. The detachment claim it was meant to make was unverified.
        # (`subprocess.run` returns a CompletedProcess, which has no `.pid`, so
        # the orphaning is checked against the reaper instead.)
        assert ppid == 1, (
            f"ppid is {ppid}: the shipper was not reparented, so it is still "
            f"a child of the installer that has exited")
        assert pgid == pid, "the child stayed in the installer's process group"
    finally:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass


def test_start_now_reports_rather_than_raises_when_there_is_no_wrapper(tmp_path):
    """⚠ NEVER FATAL. An install that wired everything correctly must not fail
    because a process would not spawn."""
    result = supervisor.start_now(tmp_path / "does-not-exist.cmd")
    assert result["started"] is False and result["pid"] is None
    assert "no wrapper" in result["detail"]


# ════════════════════════ what each platform actually does ══

def test_the_windows_task_has_only_a_logon_trigger():
    """⚠ THE FINDING THIS PASS TURNS ON, PINNED. If a boot trigger is ever
    added, the installer's "and started now" reasoning changes and this test is
    where somebody is told."""
    xml = supervisor._task_xml(Path("C:/x/wrapper.cmd"))
    assert "<LogonTrigger>" in xml
    assert "BootTrigger" not in xml, (
        "the task now has a boot trigger — re-read why start_now() exists")


def test_launchd_and_systemd_are_told_to_start_on_load():
    """launchd's RunAtLoad and systemd's `enable --now` are what make Windows
    the exception. Read from what is written and run, not assumed."""
    plist = supervisor._plist("/usr/bin/python3", Path("/x/run.py"), {})
    assert "<key>RunAtLoad</key><true/>" in plist

    unit = supervisor._unit("/usr/bin/python3", Path("/x/run.py"), {})
    assert "WantedBy=default.target" in unit
