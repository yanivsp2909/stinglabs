"""Preflight must not call a shipping machine broken — nor a dead one healthy.

⚠ THE DEFECT THIS FIXES. On the one real Windows machine `schtasks /Create` is
refused by policy, so `install.py` WIRES a Startup-folder `.cmd` instead. That
machine ships at every logon — and preflight, which asked Task Scheduler and
nothing else, printed:

    [FAIL] the shipper's supervisor is loaded
           …xml exists but schtasks has no such service … Re-run install.py

Two things wrong at once: the headline said the guard was not known to be
working when it was, and the remedy was a command that will be refused again.

⚠ AND THE DEFECT THE FIRST FIX INTRODUCED, which is why these tests exist. That
version reported PASS when the shipper's cursor was fresh. A cursor cannot tell
the Startup shortcut from a shipper somebody started in a terminal — which is
the exact failure `check_supervisor_loaded` was written for — so the PASS was a
false claim about the MECHANISM, and would have been this repo's fifth defect of
the shape "reports success while shipping nothing".
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import preflight as pf                                            # noqa: E402
from shipper import service                                       # noqa: E402

WINDOWS_REFUSED = {
    "kind": "schtasks", "path": r"C:\...\dev.sting.shipper.xml",
    "startup_shortcut": True, "file_present": True, "loaded": False,
    "pid": None, "running_file": None, "is_this_install": None,
    "legacy_loaded": False, "detail": "schtasks has no such service",
}


@pytest.fixture
def fallback(monkeypatch, tmp_path, capsys):
    """Drive `_report_startup_fallback` with a real shortcut file on disk."""
    def run(*, body='@echo off\nstart "" "C:\\x.cmd"', shortcut_age=3600.0,
            cursor_moved=None):
        shortcut = tmp_path / "sting-shipper.cmd"
        shortcut.write_text(body, encoding="utf-8")
        os.utime(shortcut, (time.time() - shortcut_age,) * 2)
        monkeypatch.setattr(service, "startup_shortcut_path",
                            lambda: shortcut)
        monkeypatch.setattr(pf, "_shipper_last_moved",
                            lambda: (cursor_moved, tmp_path / "cursor.json"))
        monkeypatch.setattr(pf, "_failed", 0)
        pf._report_startup_fallback(dict(WINDOWS_REFUSED))
        return capsys.readouterr().out, pf._failed
    return run


# ════════════════ the state that was wrongly a FAIL ══

def test_a_machine_shipping_via_the_fallback_is_not_a_failure(fallback):
    """⚠ THE HEADLINE IS WHAT A PERSON ACTS ON. "the guard is not known to be
    working" on a machine that decides correctly and ships teaches somebody to
    ignore preflight, which is worse than any single wrong line."""
    out, failed = fallback(cursor_moved=300.0)
    assert failed == 0, "a shipping machine is still counted as a FAIL"
    assert "[INFO]" in out
    assert "cursor at" in out and "ADVANCED" in out
    # ⚠ AND IT MUST NOT CLAIM A COLLECTOR ACCEPTED ANYTHING. `run.py:256`
    # advances the cursor for a record too large to send, with no round trip.
    assert "not the same as a batch being accepted" in out


def test_it_is_INFO_and_never_PASS_because_the_cursor_cannot_name_the_carrier(
        fallback):
    """⚠ THE FIFTH SILENT-SUCCESS DEFECT, CAUGHT BEFORE IT SHIPPED.

    A fresh cursor proves *something* advanced it. A shipper started by hand in
    a terminal advances it identically and dies with that terminal — the very
    failure this check exists to catch. So PASS would assert a mechanism the
    evidence does not support, and the message has to say so.
    """
    out, _ = fallback(cursor_moved=300.0)
    assert "[PASS]" not in out, (
        "preflight claims the Startup shortcut is carrying it — the cursor "
        "cannot distinguish that from a hand-started shipper")
    assert "NOT PROOF" in out
    assert "started by hand" in out and "dies with that terminal" in out


def test_the_message_says_how_to_tell_the_two_apart(fallback):
    out, _ = fallback(cursor_moved=300.0)
    assert "close every terminal" in out
    assert "LOGON" in out, "the logon caveat is gone"


# ════════════════ the states that must still FAIL ══

def test_a_shortcut_that_has_carried_nothing_for_a_week_is_a_FAIL(fallback):
    """⚠ AN INFO THAT CAN NEVER BECOME A FAIL IS A CHECK THAT HAS STOPPED
    CHECKING. A logon shortcut is innocently silent for hours; at three weeks it
    is quarantined, deleted, or was never run."""
    out, failed = fallback(shortcut_age=21 * 86400, cursor_moved=None)
    assert failed == 1, "a permanently silent fallback never becomes a failure"
    assert "[FAIL]" in out
    # ⚠ IT MUST NAME BOTH EXPLANATIONS. The cursor only moves when there is a
    # batch, so a healthy machine with a week of no agent activity produces this
    # same silence — calling that "not working" is a claim the check cannot make.
    assert "either broken, or this machine has had no agent activity" in out


def test_an_empty_shortcut_file_is_a_FAIL_because_it_carries_nothing(fallback):
    """⚠ `is_file()` IS NOT "IS A CARRIER". `install_startup_shortcut` returns
    written=False on an OSError and a crash mid-write leaves a truncated file;
    `startup_shortcut_present()` counts both."""
    out, failed = fallback(body="   \n", cursor_moved=300.0)
    assert failed == 1, "an empty .cmd was treated as a working carrier"
    assert "EMPTY" in out


def test_a_fresh_install_that_has_not_logged_in_is_neither_pass_nor_fail(
        fallback):
    out, failed = fallback(shortcut_age=3600.0, cursor_moved=None)
    assert failed == 0, "a machine installed an hour ago is not yet broken"
    assert "[INFO]" in out
    assert "sign out and back in" in out
    # ⚠ AND IT MUST NAME THE STEP THAT MAKES THE CURSOR MOVE AT ALL. Telling
    # somebody to sign out and in is useless on a machine with nothing queued:
    # the cursor only advances when there is a batch, so the proof needs one
    # agent action first, then the logon gap, then a second run.
    assert "ONE action through your coding agent" in out
    assert "touch NOTHING" in out
    assert "becomes a FAIL" in out, "the escalation is not announced"


# ════════════════ the evidence helper ══

def test_the_helper_survives_a_machine_with_no_resolvable_home(monkeypatch):
    """⚠ `Path.home()` RAISES RuntimeError, NOT OSError, on a service account
    with no home — and the first version built the path outside its own try
    while claiming "never raises"."""
    from shipper import config as scfg

    def explode():
        raise RuntimeError("no home directory")

    monkeypatch.setattr(scfg, "from_env", explode)
    moved, where = pf._shipper_last_moved()
    assert moved is None, "an unresolvable home became a timing measurement"
    assert where is not None


def test_a_duration_reads_as_something_a_person_can_act_on():
    """`int(x // 3600)` printed "0h" for a 46-minute-old cursor."""
    assert pf._age(2760) == "46 min"
    assert pf._age(7200).endswith("h")
    assert pf._age(3 * 86400).endswith("days")


# ════════════════ the two answers to one question ══

def test_status_still_reports_the_key_both_readers_depend_on():
    """⚠ THEY HAD DRIFTED. `install.py --status` grew four states in the
    auto-shipping pass and preflight grew none, so the same `supervisor.status()`
    dict produced two different answers — and the one a person reads first was
    the wrong one. This calls the real `status()` rather than grepping it: an
    inspect/read_text check is line-fragile (it failed once purely because the
    source file was edited while the suite ran) and passes on a comment.
    """
    from shipper import service

    state = service.status()
    assert "startup_shortcut" in state, (
        "status() no longer reports the key both readers depend on")
    assert isinstance(state["startup_shortcut"], bool)


# ⚠ THE "does preflight read it" HALF OF THAT PAIR IS NOW A BEHAVIOURAL TEST —
# see `test_a_live_install_with_a_refused_task_routes_to_the_fallback` and
# `test_an_ORPHANED_shortcut_after_uninstall_is_not_called_a_fallback` below.
# The grep version ("startup_shortcut" appears in the source) passed just as
# well with the branch inverted, which is how the orphan case shipped unnoticed.
# `test_nothing_carrying_it_at_all_is_still_a_FAIL` carries the remedy check.


# ══════════ the routing itself, driven through the real entry point ══

# ⚠ EVERY TEST ABOVE CALLS THE PRIVATE HELPER. The routing that decides WHICH
# helper runs had only textual coverage — a grep for "startup_shortcut" in the
# source, which would pass just as well if the branch were inverted. That gap is
# exactly where the orphaned-shortcut defect lived, so these drive the real
# `check_supervisor_loaded()` across every reachable combination.

def _drive(monkeypatch, capsys, tmp_path, **state):
    from shipper import service

    base = {"kind": "schtasks", "path": str(tmp_path / "task.xml"),
            "startup_shortcut": False, "file_present": True, "loaded": False,
            "pid": None, "running_file": None, "is_this_install": None,
            "legacy_loaded": False, "detail": "schtasks has no such service"}
    base.update(state)
    shortcut = tmp_path / "sting-shipper.cmd"
    shortcut.write_text('@echo off\nstart "" "x"', encoding="utf-8")
    monkeypatch.setattr(service, "status", lambda: base)
    monkeypatch.setattr(service, "startup_shortcut_path", lambda: shortcut)
    monkeypatch.setattr(pf, "_shipper_last_moved",
                        lambda: (300.0, tmp_path / "cursor.json"))
    monkeypatch.setattr(pf, "_failed", 0)
    pf.check_supervisor_loaded()
    return capsys.readouterr().out, pf._failed


def test_a_live_install_with_a_refused_task_routes_to_the_fallback(
        monkeypatch, capsys, tmp_path):
    out, failed = _drive(monkeypatch, capsys, tmp_path,
                         file_present=True, startup_shortcut=True)
    assert failed == 0
    assert "STARTUP SHORTCUT is in place" in out


def test_an_ORPHANED_shortcut_after_uninstall_is_not_called_a_fallback(
        monkeypatch, capsys, tmp_path):
    """⚠ A REAL, REACHABLE STATE. `--uninstall` deletes the task XML and the
    wrapper .cmd and never calls `remove_startup_shortcut()` — which has NO
    CALLERS anywhere in this repo. So an uninstalled machine keeps a Startup
    .cmd pointing at a deleted wrapper.

    Routing that into the fallback report tells somebody who deliberately
    removed Sting that "schtasks refused to register a task", and a week later
    tells them to go and run the shipper by hand.
    """
    out, failed = _drive(monkeypatch, capsys, tmp_path,
                         file_present=False, startup_shortcut=True)
    assert failed == 0, "an uninstalled machine is not a failure"
    # ⚠ THE SENTENCE, NOT THE WORD. `"ORPHAN" in out` was vacuous: the message
    # prints the shortcut's path, which sits under pytest's `tmp_path`, and that
    # directory is named after THIS test — `…ORPHANED…`. See the test below.
    assert "That is an ORPHAN" in out
    assert "refused to register" not in out, (
        "an uninstalled machine is told a task registration was refused")


def test_the_orphan_assertion_can_fail(monkeypatch, capsys, tmp_path):
    """The live-install FALLBACK branch is not the orphan branch: the new
    assertion must fail there. The old `"ORPHAN" in out` would have passed
    anyway (the path carries the test's own name) — the vacuity, shown."""
    # a directory named the way pytest names the orphan test's own tmp_path
    where = tmp_path / "test_an_ORPHANED_shortcut_0"
    where.mkdir()
    out, _failed = _drive(monkeypatch, capsys, where,
                          file_present=True, startup_shortcut=True)
    assert "ORPHAN" in out, "precondition: the path alone puts the word in the output"
    assert "That is an ORPHAN" not in out


def test_nothing_carrying_it_at_all_is_still_a_FAIL(
        monkeypatch, capsys, tmp_path):
    """⚠ THE CHECK MUST NOT HAVE BEEN LOWERED. No service, no shortcut: the
    FAIL is correct and only the message needed fixing."""
    out, failed = _drive(monkeypatch, capsys, tmp_path,
                         file_present=True, startup_shortcut=False)
    assert failed == 1
    assert "[FAIL]" in out
    assert "Startup-folder .cmd" in out, (
        "the remedy still tells Windows only to re-run install.py, which will "
        "be refused again")


def test_a_loaded_service_is_still_a_plain_PASS(monkeypatch, capsys, tmp_path):
    out, failed = _drive(monkeypatch, capsys, tmp_path,
                         loaded=True, pid=4242, is_this_install=True)
    assert failed == 0 and "[PASS]" in out


# ══════════ the evidence helper, behaviourally ══

def test_the_cursor_is_read_from_the_state_root_the_shipper_would_use(
        monkeypatch, tmp_path):
    """⚠ THE SOURCE-GREP VERSION OF THIS TEST PASSED FOR THE WRONG REASON: it
    matched the substring "from_env()", which `log_root` would satisfy too, and
    its negative assertion was quote-style sensitive. This writes a real cursor
    and checks the age that comes back."""
    from shipper import config as scfg

    state = tmp_path / "shipper"
    state.mkdir()
    cursor = state / "cursor.json"
    cursor.write_text("{}", encoding="utf-8")
    os.utime(cursor, (time.time() - 600, time.time() - 600))

    class _Settings:
        state_root = state
        log_root = tmp_path / "WRONG"

    monkeypatch.setattr(scfg, "from_env", lambda: _Settings())
    moved, where = pf._shipper_last_moved()
    assert where == cursor, "the wrong field of Settings was used"
    assert 570 <= moved <= 660, moved


# ══════════ the summary must not overclaim either ══

# ⚠ TASK 2.2 IN REVERSE, AND THE COST OF FIXING IT THE OBVIOUS WAY. The headline
# must not say "the guard is not known to be working" when the guard IS working
# — but turning those FAILs into INFOs makes the OTHER closing line reachable:
# "all checks passed", on a machine whose supervisor evidence the INFO line
# calls NOT PROOF two sentences earlier. Both directions are the same rule.

def test_a_fallback_machine_is_not_told_all_checks_passed(
        monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(pf, "_unproven_supervisor", "")
    _drive(monkeypatch, capsys, tmp_path,
           file_present=True, startup_shortcut=True)
    assert pf._unproven_supervisor, (
        "the fallback INFO left no mark, so the summary will claim everything "
        "passed on a machine nothing is proven to be shipping from")


def test_a_registered_task_leaves_no_mark_and_still_gets_the_plain_summary(
        monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(pf, "_unproven_supervisor", "")
    _drive(monkeypatch, capsys, tmp_path,
           loaded=True, pid=4242, is_this_install=True)
    assert not pf._unproven_supervisor, (
        "a machine with a running scheduled task was downgraded")


def test_an_orphan_leaves_no_mark_either(monkeypatch, capsys, tmp_path):
    """An uninstalled machine is not an unproven install — it is not an install."""
    monkeypatch.setattr(pf, "_unproven_supervisor", "")
    _drive(monkeypatch, capsys, tmp_path,
           file_present=False, startup_shortcut=True)
    assert not pf._unproven_supervisor


# ══════════ drift in status() must not kill the whole run ══

def test_a_renamed_status_key_reports_itself_instead_of_crashing_preflight(
        monkeypatch, capsys, tmp_path):
    """⚠ THIS FILE'S ONE INVARIANT IS THAT PREFLIGHT SURVIVES ITS OWN SUBJECT
    BEING BROKEN. Every access below `status()` is a bracket, and every test
    that drives the function supplies its own dict — so renaming a key in
    `shipper/service.py` would pass the whole suite and raise KeyError out
    of main(), taking every remaining check with it.
    """
    from shipper import service

    # ⚠ `kind` IS THE FIRST KEY THE FUNCTION INDEXES, so this reaches a real
    # KeyError. Note the guard does NOT pre-validate the key set: an earlier
    # version did, and it turned a genuine takeover FAIL into an INFO because
    # that branch returns before reading most of these.
    broken = {"platform": "schtasks", "path": "x", "startup_shortcut": False,
              "file_present": True, "loaded": False, "pid": None,
              "running_file": None,
              "is_this_install": None, "legacy_loaded": False, "detail": "d"}
    monkeypatch.setattr(service, "status", lambda: broken)
    monkeypatch.setattr(pf, "_failed", 0)

    pf.check_supervisor_loaded()             # must not raise

    out = capsys.readouterr().out
    assert "kind" in out, "the drift is not named"
    assert "[INFO]" in out and pf._failed == 0


def test_the_guarded_key_set_is_the_one_status_actually_returns():
    """⚠ THE NARROW VERSION OF THIS TEST ASSERTED ONE KEY. Nine others are
    indexed with brackets and were unguarded by any test at all."""
    from shipper import service

    assert set(service.status()) == set(pf._SUPERVISOR_KEYS), (
        "service.status() and preflight's guarded key set have drifted")


def test_the_freshness_constant_does_not_claim_an_idle_shipper_touches_it():
    """The derivation comment said a live shipper touches the cursor every
    heartbeat. It does not — `should_flush` is False with nothing pending and
    Heartbeat only reads the cursor — and the same function says so 100 lines
    later. A comment that contradicts its own function is how a threshold gets
    retuned on a guarantee that was never true."""
    import inspect

    src = inspect.getsource(pf)
    head = src[:src.index("_CURSOR_FRESH_SECONDS = ")]
    assert "touches it at least every heartbeat" not in head


def test_the_drift_guard_does_not_downgrade_a_real_takeover_FAIL(
        monkeypatch, capsys, tmp_path):
    """⚠ THE REGRESSION THE FIRST VERSION OF THE GUARD SHIPPED. Validating all
    ten keys up front turned `[FAIL] another install owns this label` — a true
    finding on a real machine — into `[INFO] could not be determined`, because
    that branch returns before reading most of them. A guard that downgrades a
    FAIL is worse than the crash it was preventing.
    """
    from shipper import service

    monkeypatch.setattr(service, "status", lambda: {
        "kind": "launchd", "path": str(tmp_path / "mine.plist"),
        "file_present": True, "loaded": True, "pid": 9,
        "running_file": str(tmp_path / "theirs.plist"),
        "is_this_install": False, "detail": ""})     # ⚠ two keys absent
    monkeypatch.setattr(pf, "_failed", 0)

    pf.check_supervisor_loaded()

    out = capsys.readouterr().out
    assert "[FAIL]" in out and pf._failed == 1, (
        "a partial dict swallowed a real takeover finding")
