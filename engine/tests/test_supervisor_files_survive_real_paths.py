"""A supervisor file is generated from paths, and paths are not markup.

⚠ FOUND WHILE REHEARSING A SECOND MACHINE, NOT BY A USER — which is the point of
rehearsing one. Neither generator escaped anything, and both formats have
characters that a real home directory contains.

The failure mode is the one this repo keeps meeting: not a crash, but a service
that quietly does not do what its file says. A systemd unit whose
`Environment=` line lost half a path still loads; the trust boundary it declares
is simply smaller than the operator asked for, and the installer's own text says
that costs 74 of 89 denials.
"""
from __future__ import annotations

import platform
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from installer import supervisor                                 # noqa: E402
from shipper import service                                      # noqa: E402


def env_lines(env):
    return [l for l in supervisor._unit("/usr/bin/python3", Path("/x/run.py"),
                                         env).splitlines()
             if l.startswith("Environment=")]


# ------------------------------------------------------- systemd, i.e. Linux

def test_a_path_with_a_space_stays_one_assignment():
    """⚠ THE LINE A WSL USER BREAKS FIRST. Windows home directories under
    /mnt/c routinely contain a space, and systemd splits an unquoted
    `Environment=` value on whitespace into further assignments — so
    `/mnt/c/Users/John Smith/code` would declare `/mnt/c/Users/John`."""
    lines = env_lines({"STING_ROOTS": "/mnt/c/Users/John Smith/code:/home/j/x"})
    assert lines == ['Environment="STING_ROOTS=/mnt/c/Users/John Smith/code:/home/j/x"']


def test_every_value_is_quoted_even_when_it_does_not_need_to_be():
    """Quoting only the ones that look dangerous means deciding, per value,
    which ones those are — and being wrong once is silent."""
    for line in env_lines({"A": "plain", "B": "/tmp", "C": "has space"}):
        assert line.startswith('Environment="') and line.endswith('"')


def test_a_quote_in_a_path_cannot_end_the_value_early():
    value = 'a"b'
    assert env_lines({"K": value}) == ['Environment="K=a\\"b"']


def test_a_backslash_is_escaped_before_the_quote_is():
    """Order matters: escaping the quote first and the backslash second would
    double the backslash this function just added."""
    assert env_lines({"K": "a\\b"}) == ['Environment="K=a\\\\b"']


def test_nothing_is_stripped_or_rejected():
    """A path is the operator's. Dropping a character quietly is how a declared
    root ends up naming a directory that does not exist."""
    weird = "/mnt/c/Users/Ann-Marie O'Neill/dev (work)/repo"
    assert weird in env_lines({"STING_ROOTS": weird})[0]


# ---------------------------------------------------------- launchd, i.e. macOS

def test_an_ampersand_in_a_path_does_not_produce_an_unparseable_plist():
    """launchd refuses the whole file, and the symptom is a service that does
    not load — never anything that mentions the ampersand."""
    from xml.etree import ElementTree

    body = supervisor._plist("/usr/bin/python3", Path("/x/run.py"),
                              {"STING_ROOTS": "/home/a&b/<x>"})
    ElementTree.fromstring(body)          # raises if the escaping is wrong
    assert "&amp;" in body and "&lt;x&gt;" in body


def test_the_plist_is_well_formed_for_ordinary_paths_too():
    from xml.etree import ElementTree

    body = supervisor._plist("/usr/bin/python3", Path("/x/run.py"),
                              {"STING_TIER": "verdict_reason_location"})
    root = ElementTree.fromstring(body)
    assert root.tag == "plist"


# ------------------------------------------------- the Linux branch, on macOS

def test_the_linux_branch_targets_the_xdg_location(monkeypatch):
    """⚠ READ AND EXERCISED, NOT RUN ON LINUX. This asserts what the code
    PRODUCES for Linux; whether systemd then accepts it is a claim only a Linux
    machine can settle, and the handover says so."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    assert service.kind() == "systemd"
    # ⚠ THE LABEL IS NOW PER INSTALL PREFIX, so this asserts the SHAPE and the
    # LOCATION rather than a literal name. A literal would have to be recomputed
    # here, which would make the test a copy of the implementation.
    label = service.label()
    assert label.startswith("dev.sting.shipper."), label
    assert service.target_path() == (
        Path.home() / ".config" / "systemd" / "user" / f"{label}.service")
    # `restart`, not `enable --now`: a re-run must restart a running shipper
    # (tests/test_a_settings_change_reaches_the_running_shipper.py).
    assert supervisor.activate(dry_run=True)["commands"] == [
        "systemctl --user daemon-reload",
        f"systemctl --user enable {label}.service",
        f"systemctl --user restart {label}.service"]


def test_an_unsupported_platform_says_so_instead_of_writing_a_file(monkeypatch,
                                                                    tmp_path):
    """⚠ THIS TEST USED TO NAME WINDOWS, and Windows is now supported. Using a
    real platform as the stand-in for "unsupported" is how a test quietly stops
    testing what it says: the day the platform gains an arm, the test either
    fails (this one, usefully) or passes while asserting nothing."""
    monkeypatch.setattr(platform, "system", lambda: "Plan9")
    written = supervisor.write("/py", tmp_path / "run.py", {})
    assert written["path"] is None
    assert "no supported supervisor" in written["note"]


# ══════════════════════════ the Windows arm — Scheduled Tasks (Phase 2)

def test_windows_writes_a_task_xml_and_a_wrapper(monkeypatch, tmp_path):
    """⚠ TWO FILES, BECAUSE TASK SCHEDULER HAS NO ENVIRONMENT BLOCK. launchd
    has EnvironmentVariables and systemd has Environment=; this has neither, so
    the variables are set by a generated .cmd the task runs."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    written = supervisor.write("C:\\py\\python.exe", Path("C:\\sting\\hook.py"),
                                {"STING_SESSION_ROOT": "C:\\Users\\a b\\.sting"})
    assert written["kind"] == "schtasks"

    xml, wrapper = service.task_paths()
    assert xml.exists() and wrapper.exists()

    body = wrapper.read_text(encoding="utf-8")
    # ⚠ `set "K=v"` — quotes OUTSIDE the assignment. `set K="v"` stores the
    # quotes, and a value with a space truncates without them.
    assert 'set "STING_SESSION_ROOT=C:\\Users\\a b\\.sting"' in body
    assert '"C:\\py\\python.exe" "C:\\sting\\hook.py"' in body


def test_the_task_xml_turns_off_every_battery_default(monkeypatch, tmp_path):
    """⚠ TASK SCHEDULER'S DEFAULTS ARE HOSTILE TO A BACKGROUND GUARD.
    DisallowStartIfOnBatteries and StopIfGoingOnBatteries are both TRUE unless
    stated, so on a laptop the shipper would stop the moment the charger came
    out — and the collector would read that as a machine gone quiet, which is
    the one signal this product asks people to act on."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    supervisor.write("py", Path("hook.py"), {})
    xml = service.task_paths()[0].read_text(encoding="utf-16")

    assert "<DisallowStartIfOnBatteries>false<" in xml
    assert "<StopIfGoingOnBatteries>false<" in xml
    # PT0S = no limit. The default kills a long-running task after 72 hours.
    assert "<ExecutionTimeLimit>PT0S<" in xml
    assert "<LogonTrigger>" in xml


def test_the_xml_is_utf16_because_it_declares_utf16(monkeypatch, tmp_path):
    """⚠ `schtasks /Create /XML` READS THE ENCODING FROM THE DECLARATION and
    refuses a file whose bytes disagree, with a parse error naming neither."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    supervisor.write("py", Path("hook.py"), {})
    raw = service.task_paths()[0].read_bytes()
    assert raw[:2] in (b"\xff\xfe", b"\xfe\xff"), "no UTF-16 BOM"
    assert 'encoding="UTF-16"' in raw.decode("utf-16")


def test_status_on_windows_asks_schtasks_and_never_the_file(monkeypatch, tmp_path):
    """⚠ THE MISTAKE THIS REPO ALREADY MADE ONCE. `installed = path.exists()`
    reported a plist as a running shipper, and a failed bootstrap was
    indistinguishable from success. The XML is an INPUT to /Create; it is not
    evidence that /Create ran, or that it succeeded."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    supervisor.write("py", Path("hook.py"), {})

    asked = []

    def fake_run(command, timeout=20):
        asked.append(command)
        return 1, "ERROR: The system cannot find the file specified."

    monkeypatch.setattr(service, "_run", fake_run)
    state = service.status()

    assert state["file_present"] is True, "the XML really is on disk"
    assert state["loaded"] is False, "and the task is NOT registered"
    assert any("schtasks" in c[0] for c in asked), "it never asked the platform"


def test_an_unreadable_schtasks_answer_is_UNKNOWN_not_absent(monkeypatch):
    """⚠ "CANNOT TELL" MUST NOT READ AS "NOT THERE". schtasks exits non-zero for
    a missing task AND for a real error, distinguishing them only in prose, so
    anything unrecognised stays None."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(service, "_run",
                         lambda c, timeout=20: (1, "ERROR: Access is denied."))
    assert service.loaded()["loaded"] is None


def test_a_registered_task_reports_the_file_it_runs(monkeypatch):
    """`is_this_install` works on Windows the same way it does elsewhere: two
    installs share one task name, so "a task exists" and "MY task exists" are
    different questions."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(service, "_run", lambda c, timeout=20: (0, (
        "TaskName:      \\Sting\\dev.sting.shipper\n"
        "Status:        Ready\n"
        "Task To Run:   C:\\Users\\a\\AppData\\Local\\sting\\dev.sting.shipper.cmd\n"
        "Last Result:   0\n")))
    state = service.loaded()
    assert state["loaded"] is True
    assert state["file"].endswith("dev.sting.shipper.cmd")
    assert state["pid"] is None, "Task Scheduler reports no pid; None is honest"
    assert "Status=Ready" in state["detail"]


def test_stop_command_is_the_one_for_this_platform(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    assert "schtasks /End" in service.stop_command()


def test_no_windows_path_calls_os_getuid(monkeypatch):
    """⚠ THE EIGHTH SITE, PINNED. `os.getuid` does not exist on Windows, and an
    unconditional call raised AttributeError in 15 tests before any platform
    branch could decide it was not needed."""
    import os as os_module
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.delattr(os_module, "getuid", raising=False)
    assert service.kind() == "schtasks"
    assert service._uid_or_none() is None
    service.stop_command()
    monkeypatch.setattr(service, "_run", lambda c, timeout=20: (0, "Status: Ready"))
    service.status()
