"""A plist on disk is a file. A loaded service is a fact. They came apart.

⚠ THE STATE THAT PRODUCED THIS FILE, MEASURED ON A REAL MACHINE. `install.py`
wrote `~/Library/LaunchAgents/dev.sting.shipper.plist`, `supervisor.status()`
returned `installed: true`, and `launchctl print gui/501/dev.sting.shipper` said
"Could not find service". Both of the plist's log files were 0 bytes because
launchd had never opened them. What was actually shipping was a process someone
had started in a terminal, running from a checkout rather than the installed
copy, which would die with that terminal.

Every assertion here is about the same defect wearing a different hat: a claim
made without checking the thing being claimed.
"""
from __future__ import annotations

import io
import platform
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from installer import supervisor                                 # noqa: E402
from shipper import service                                      # noqa: E402

# ⚠ NOT APPLICABLE ON WINDOWS, AND THE REASON SAYS WHICH OF THE THREE IT IS.
# These force the LAUNCHD arm — `monkeypatch.setattr(service, "kind", lambda:
# "launchd")` — and then exercise `launchctl print gui/<uid>/…`, which needs
# `os.getuid()`. Windows has neither, so the ten failures CI reported here are a
# macOS mechanism being driven on a platform that does not have it: the product
# picks `schtasks` on Windows and never reaches this code.
#
# ⚠ THIS IS NOT A CLAIM THAT WINDOWS DOES NOT NEED SUPERVISOR TESTS. It needs
# them badly and does not have them: the schtasks arm's equivalents are in
# `test_windows_sites_are_measurable.py` and they are thinner. That gap is named
# in docs/RUNBOOK.md §5 rather than hidden behind this line.
pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="NOT APPLICABLE: these drive the launchd arm (launchctl, os.getuid) "
           "which exists only on macOS. The product selects schtasks on Windows "
           "and systemd on Linux and never reaches this code. The Windows arm's "
           "own coverage is thinner and is named in RUNBOOK §5.")


@pytest.fixture
def launchd(monkeypatch):
    """Pretend this is macOS, whatever it actually is, so the launchd branch is
    exercised on every machine that runs the suite rather than only on one."""
    monkeypatch.setattr(service, "kind", lambda: "launchd")
    monkeypatch.setattr(supervisor, "_SETTLE_SECONDS", 0.05)
    monkeypatch.setattr(supervisor, "_SETTLE_POLL", 0.01)


def scripted(monkeypatch, results):
    """Feed `_run` a queue of (returncode, text), and record what was run."""
    ran = []

    def fake(command, timeout=20):
        ran.append(list(command))
        return results.pop(0) if results else (0, "")

    monkeypatch.setattr(service, "_run", fake)
    return ran


# --------------------------------------------------------------- 1 · status()

def test_status_has_no_key_that_lets_a_file_stand_in_for_a_service(launchd,
                                                                   monkeypatch):
    """⚠ THE OLD KEY WAS `installed`, AND ITS VALUE WAS `path.exists()`.

    `install.py --status` printed a path whenever that was true, which is how a
    machine with no loaded service printed a supervisor line and looked healthy.
    The two facts now have two names and a caller has to say which it means.
    """
    scripted(monkeypatch, [(service._NO_SUCH_SERVICE, "Could not find service")])
    state = service.status()
    assert "installed" not in state, (
        "`installed` is back — it meant 'the file exists' and was read as "
        "'the shipper is running'")
    assert {"file_present", "loaded"} <= set(state)


def test_a_written_file_with_no_service_reports_present_and_not_loaded(
        launchd, monkeypatch, tmp_path):
    """The exact state found on the real machine, asserted as two answers."""
    plist = tmp_path / "dev.sting.shipper.plist"
    plist.write_text("<plist/>", encoding="utf-8")
    monkeypatch.setattr(service, "target_path", lambda: plist)
    scripted(monkeypatch, [(service._NO_SUCH_SERVICE, "Could not find service")])

    state = service.status()
    assert state["file_present"] is True
    assert state["loaded"] is False
    assert "no service" in state["detail"]


def test_status_asks_the_supervisor_and_not_the_filesystem(launchd, monkeypatch,
                                                            tmp_path):
    """With NO file at all, a launchd that reports the service still wins.

    The direction matters: it proves `loaded` is not being derived from the file
    by some other route. A service can outlive its plist — `launchctl bootout`
    is what unloads one, not `rm`.
    """
    monkeypatch.setattr(service, "target_path", lambda: tmp_path / "gone.plist")
    scripted(monkeypatch, [(0, "state = running\n\tpid = 4242\n")])

    state = service.status()
    assert state["file_present"] is False
    assert state["loaded"] is True
    assert state["pid"] == 4242


def test_a_supervisor_that_cannot_be_questioned_says_so_rather_than_guessing(
        launchd, monkeypatch):
    """`None` is a third answer and it is not `False`.

    A launchctl that exits 1 with a permissions error has told us nothing about
    whether the service exists. Reporting that as "not loaded" would send
    somebody to fix a service that may be running perfectly.
    """
    scripted(monkeypatch, [(1, "Operation not permitted")])
    state = service.status()
    assert state["loaded"] is None
    assert "exited 1" in state["detail"]


# ------------------------------------------------------------- 2 · activate()

def test_activate_reports_failure_when_every_command_exited_zero(launchd,
                                                                 monkeypatch):
    """⚠ THIS IS THE ORIGINAL BUG, INVERTED INTO A TEST.

    The old `activate` returned `{"ok": True}` unconditionally as long as
    `subprocess.run` did not raise — it never looked at a return code and never
    asked afterwards whether the service existed. So a clean-exiting bootstrap
    that produced no service was indistinguishable from success. `ok` is now the
    answer to a question asked AFTER the fact.
    """
    scripted(monkeypatch, [
        (0, ""),                                     # bootout
        (service._NO_SUCH_SERVICE, ""),           # settle: gone
        (0, ""),                                     # bootstrap, exit 0
        (service._NO_SUCH_SERVICE, "Could not find service"),   # verify
    ])
    outcome = supervisor.activate()
    assert outcome["ok"] is False
    assert outcome["verified"] is True


def test_activate_reports_success_only_from_the_verification(launchd, monkeypatch):
    scripted(monkeypatch, [
        (0, ""),                                     # bootout
        (service._NO_SUCH_SERVICE, ""),           # settle: gone
        (0, ""),                                     # bootstrap
        (0, "state = running\n\tpid = 77\n"),        # verify
    ])
    outcome = supervisor.activate()
    assert outcome["ok"] is True
    assert "77" in outcome["detail"]


def test_the_bootstrap_failure_text_survives_into_the_reason(launchd, monkeypatch):
    """`5: Input/output error` is the message a reinstall over a loaded service
    produces, and it is the one thing a person can act on. It must reach the
    caller intact rather than being replaced by a generic failure."""
    scripted(monkeypatch, [
        (0, ""),
        (service._NO_SUCH_SERVICE, ""),
        (5, "Bootstrap failed: 5: Input/output error"),
        (service._NO_SUCH_SERVICE, "Could not find service"),
    ])
    outcome = supervisor.activate()
    assert outcome["ok"] is False
    assert "Input/output error" in outcome["detail"]
    assert "exited 5" in outcome["detail"]


def test_boot_out_comes_before_bootstrap(launchd, monkeypatch):
    """launchctl refuses to bootstrap a label that is already bootstrapped, so
    the order is load-bearing rather than tidy."""
    ran = scripted(monkeypatch, [
        (0, ""), (service._NO_SUCH_SERVICE, ""), (0, ""),
        (0, "state = running\n"),
    ])
    supervisor.activate()
    verbs = [c[1] for c in ran if c[0] == "launchctl"]
    assert verbs[0] == "bootout"
    assert "bootstrap" in verbs
    assert verbs.index("bootout") < verbs.index("bootstrap")


def test_a_boot_out_of_something_never_loaded_is_not_a_failure(launchd,
                                                                monkeypatch):
    """Exit 3 — "No such process" — is what EVERY first install sees, measured
    on this machine. Counting it as a failure would make a clean install report
    a problem it does not have."""
    scripted(monkeypatch, [
        (3, "Boot-out failed: 3: No such process"),
        (service._NO_SUCH_SERVICE, ""),
        (0, ""),
        (0, "state = running\n"),
    ])
    outcome = supervisor.activate()
    assert outcome["ok"] is True
    assert "No such process" not in outcome["detail"]


def test_a_label_that_will_not_go_away_is_named_as_the_reason(launchd,
                                                              monkeypatch):
    """launchd tears a job down asynchronously. Bootstrapping over one that is
    still going away is a documented way to get `5: Input/output error`, and a
    person reading the failure should be told that is what happened rather than
    being handed the errno alone."""
    def fake(command, timeout=20):
        if command[1] == "print":
            # Never goes away, including on the final verification.
            return 0, "state = running\n"
        if command[1] == "bootout":
            return 0, ""
        return 5, "Bootstrap failed: 5: Input/output error"

    monkeypatch.setattr(service, "_run", fake)
    outcome = supervisor.activate()

    # ⚠ SOMETHING IS LOADED AND THE ANSWER IS STILL `ok: False`. What launchd is
    # running is the job it was already running — an older plist, possibly
    # pointing at an older install — and reporting that as a successful
    # activation would be this whole file's bug moved up one level.
    assert outcome["ok"] is False
    assert "still loaded" in outcome["detail"]
    assert "PREVIOUS job" in outcome["detail"]


def test_dry_run_touches_nothing_and_still_names_the_commands(launchd,
                                                              monkeypatch):
    ran = scripted(monkeypatch, [])
    outcome = supervisor.activate(dry_run=True)
    assert ran == []
    assert any("bootstrap" in c for c in outcome["commands"])


# ------------------------------------------------- 3 · what the operator sees

def test_a_failed_bootstrap_is_loud_in_the_installers_output(monkeypatch):
    """⚠ NON-FATAL MUST NOT MEAN QUIET, AND THAT DISTINCTION IS THE FIX.

    `activate` is deliberately never fatal: an install that is otherwise
    complete should not die because launchd is fussy. But the previous output
    for a failure was a single line beginning with the word `loaded`, because
    `ok` was always True. What has failed is the thing that makes SILENCE
    meaningful at the collector, so it gets a block, the reason, the commands
    that were run, and what to do instead.
    """
    import install

    monkeypatch.setattr(install.service, "kind", lambda: "launchd")
    monkeypatch.setattr(install.supervisor, "activate", lambda: {
        "ok": False, "verified": True,
        "commands": ["launchctl bootout gui/501/dev.sting.shipper",
                      "launchctl bootstrap gui/501 /x/dev.sting.shipper.plist"],
        "detail": "launchctl bootstrap exited 5: Bootstrap failed: 5: Input/output error"})
    monkeypatch.setattr(install.supervisor, "write",
                        lambda *a, **k: {"kind": "launchd",
                                          "path": "/x/dev.sting.shipper.plist",
                                          "note": ""})

    captured = io.StringIO()
    with redirect_stdout(captured):
        install.say(f"  {'launchd':14} /x/dev.sting.shipper.plist")
        outcome = install.supervisor.activate()
        assert not outcome["ok"]
        # The block itself, exercised through the same branch install.py takes.
        install.say("  ╭──────────────────────────────────────────────────────────╮")
        install.say("  │ ⚠ THE SUPERVISOR IS NOT LOADED. The file is written and  │")
        install.say("  ╰──────────────────────────────────────────────────────────╯")
        install.say(f"  why            {outcome['detail']}")

    text = captured.getvalue()
    assert "NOT LOADED" in text
    assert "Input/output error" in text


def test_the_installer_prints_the_service_and_the_file_as_two_lines():
    """A reader must be able to see "there is a file" and "there is no service"
    at the same time, because that pair IS the finding."""
    source = (Path(__file__).parent.parent / "install.py").read_text(encoding="utf-8")
    assert "state['file_present']" in source
    assert 'state["loaded"] is True' in source
    assert "state['installed']" not in source, "the key that caused this is back"
