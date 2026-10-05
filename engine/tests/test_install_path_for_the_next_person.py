"""The four defects a clean-clone rehearsal found, and the fifth it named.

⚠ WHAT THESE HAVE IN COMMON, AND WHY THEY SURVIVED THIS LONG. Every one of them
is invisible to the person who wrote the installer and hits the next person to
run it: a uid that is only ever 501 here, a boundary check that only sees
repositories beside a checkout, a summary that is only wrong when a collector is
deliberately absent, an error path this machine never takes, and a service label
that only collides when there are two installs. None of them can be found by
installing on the machine you developed on, which is the only machine any of
them had ever been installed on.
"""
from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

import preflight                                                 # noqa: E402
from installer import detect                                     # noqa: E402
from shipper import service                                      # noqa: E402


@pytest.fixture(autouse=True)
def quiet(capsys):
    preflight._failed = 0
    preflight._unconfigured = False
    yield
    preflight._failed = 0
    preflight._unconfigured = False


# ------------------------------------------- 1 · the scratch proposal

def test_the_scratch_candidates_carry_this_uid_and_not_a_hardcoded_one():
    """501 is this developer's uid on macOS. It was written into the candidate
    list, so on every other account both entries missed."""
    source = (Path(__file__).parent.parent / "installer" / "detect.py").read_text()
    assert "claude-501" not in source
    assert "{uid}" in source
    assert "uid=uid" in source, "the template must be formatted with a real uid"


def test_nothing_plausible_means_nothing_is_proposed(monkeypatch, tmp_path):
    """⚠ THE FALLBACK WAS `TMPDIR or /tmp`, AND IT WAS NOT MERELY UNHELPFUL.
    Every path under STING_SCRATCH is exempt from the irreversible_action
    prompt, so proposing /tmp handed `rm -rf /tmp/anything` — without asking —
    to anyone who accepted a proposal without reading it.

    Proposing nothing is the right answer: unset means no exemption, which
    costs prompts and risks nothing."""
    monkeypatch.setattr(detect, "_TMP_ROOTS", (str(tmp_path),))
    monkeypatch.delenv("TMPDIR", raising=False)
    proposal = detect.propose_scratch()
    assert proposal["value"] == ""
    assert proposal["proposed"] == []
    assert "/tmp" not in proposal["value"]


def test_the_empty_case_explains_itself_rather_than_reading_as_a_gap(
        monkeypatch, tmp_path):
    """"(none found)" invites somebody to fix it, and the obvious fix is /tmp."""
    monkeypatch.setattr(detect, "_TMP_ROOTS", (str(tmp_path),))
    monkeypatch.delenv("TMPDIR", raising=False)
    note = detect.propose_scratch()["note"]
    assert "safe answer" in note
    assert "--scratch" in note


def test_a_matching_directory_owned_by_this_user_is_proposed(monkeypatch,
                                                              tmp_path):
    uid = os.getuid()
    (tmp_path / f"claude-{uid}").mkdir()
    monkeypatch.setattr(detect, "_TMP_ROOTS", (str(tmp_path),))
    monkeypatch.delenv("TMPDIR", raising=False)
    assert detect.propose_scratch()["value"] == str(tmp_path / f"claude-{uid}")


def test_a_directory_owned_by_someone_else_is_not_proposed(monkeypatch,
                                                            tmp_path):
    """⚠ /tmp IS WORLD-WRITABLE. An exemption for `rm -rf` inside another
    user's directory is not friction, it is a weapon — and the name is
    guessable, so anyone can create it first."""
    uid = os.getuid()
    (tmp_path / f"claude-{uid}").mkdir()
    monkeypatch.setattr(detect, "_TMP_ROOTS", (str(tmp_path),))
    monkeypatch.setattr(detect, "_owned_directory", lambda p, u: False)
    assert detect.propose_scratch()["value"] == ""


def test_a_symlink_at_the_expected_name_is_not_proposed(monkeypatch, tmp_path):
    """`lstat`, not `stat`: following the link would let a planted symlink point
    the exemption at a directory the agent should never be forgiven for."""
    uid = os.getuid()
    real = tmp_path / "elsewhere"
    real.mkdir()
    (tmp_path / f"claude-{uid}").symlink_to(real)
    monkeypatch.setattr(detect, "_TMP_ROOTS", (str(tmp_path),))
    monkeypatch.delenv("TMPDIR", raising=False)
    assert detect.propose_scratch()["value"] == ""


# ------------------------------------- 2 · the trust boundary's severity

def test_no_siblings_is_reported_as_INFO_and_never_as_a_pass(monkeypatch,
                                                              capsys):
    """⚠ SEVERITY WAS NOT THE PROBLEM — the check ALREADY fails when a sibling
    is outside the roots, and that is right. The problem is the other branch:
    with no siblings it said PASS, "trust boundary covers the work", having
    looked only at directories beside the CHECKOUT. Somebody who clones into
    ~/dev and works in ~/code gets a green line about work it never examined.

    "I found nothing to check" is not "there is nothing wrong". That is the
    same vacuity that let allow-once pass for months while broken.
    """
    monkeypatch.setattr(preflight, "ROOT", Path("/nonexistent/checkout"))
    monkeypatch.setenv("STING_ROOTS", "/some/declared/root")
    preflight.check_trust_boundary()
    out = capsys.readouterr().out
    assert "[PASS] trust boundary covers the work" not in out
    assert "checked \nNOTHING" in out.replace("checked NOTHING", "checked \nNOTHING")
    assert preflight._failed == 0, "an INFO must not fail the run"


def test_an_unset_boundary_names_the_measured_cost(monkeypatch, capsys):
    monkeypatch.setattr(preflight, "ROOT", Path("/nonexistent/checkout"))
    monkeypatch.delenv("STING_ROOTS", raising=False)
    preflight.check_trust_boundary()
    out = capsys.readouterr().out
    assert "UNSET" in out
    assert "74 of 89" in out


# --------------------------------------------- 3 · the summary and the detail

def test_an_unconfigured_collector_is_not_counted_as_a_failure(monkeypatch,
                                                               capsys):
    """`--no-collector` is a supported install. Counting it as a failure made
    the summary announce that the guard was not known to be working, on a
    machine where every local check had just passed."""
    for name in ("STING_COLLECTOR_URL", "STING_DEVICE_TOKEN", "STING_DEVICE_ID"):
        monkeypatch.delenv(name, raising=False)
    preflight.check_reaches_collector()
    preflight.check_device_is_alive()
    out = capsys.readouterr().out
    assert preflight._failed == 0
    assert "[INFO]" in out
    assert "NO COLLECTOR CONFIGURED" in out
    assert preflight._unconfigured is True


def test_the_summary_says_what_is_true_instead_of_contradicting_itself(
        monkeypatch, capsys):
    """⚠ A SUMMARY THAT CONTRADICTS ITS OWN DETAIL TEACHES PEOPLE TO SKIM THE
    DETAIL, and the detail is the entire value of this tool."""
    monkeypatch.setattr(preflight, "check_platform", lambda: None)
    monkeypatch.setattr(preflight, "check_imports", lambda: None)
    monkeypatch.setattr(preflight, "check_settings", lambda a: None)
    monkeypatch.setattr(preflight, "check_entry_runnable", lambda: None)
    monkeypatch.setattr(preflight, "check_env", lambda: None)
    monkeypatch.setattr(preflight, "check_session_root_writable", lambda: None)
    monkeypatch.setattr(preflight, "check_trust_boundary", lambda: None)
    monkeypatch.setattr(preflight, "check_end_to_end", lambda a: None)
    monkeypatch.setattr(preflight, "check_semantic", lambda a: None)
    monkeypatch.setattr(preflight, "check_supervisor_loaded", lambda: None)
    for name in ("STING_COLLECTOR_URL", "STING_DEVICE_TOKEN", "STING_DEVICE_ID"):
        monkeypatch.delenv(name, raising=False)

    code = preflight.main([])
    out = capsys.readouterr().out
    assert code == 0, "a deliberate --no-collector install is not a failure"
    assert "not known to be working" not in out
    assert "reports to NOBODY" in out


# ------------------------------------------- 4 · the session-root message

def test_the_unwritable_message_names_a_cause_and_a_remedy(monkeypatch, tmp_path,
                                                            capsys):
    """It used to be `{root}: [Errno 13] Permission denied: {root}` — the raw
    exception, the path twice, no cause and no fix, while the token-rejected
    message four lines below names both."""
    blocked = tmp_path / "ro"
    blocked.mkdir()
    blocked.chmod(0o500)
    monkeypatch.setenv("STING_SESSION_ROOT", str(blocked / "sessions"))
    try:
        preflight.check_session_root_writable()
    finally:
        blocked.chmod(0o700)

    out = capsys.readouterr().out
    assert "[FAIL]" in out
    assert "cost" in out and "cause" in out and "fix" in out
    assert "cannot write in it" in out
    assert "mode 0o500" in out
    assert "keeps NOTHING" in out


def test_the_cause_distinguishes_the_reasons_rather_than_repeating_errno(
        tmp_path):
    """Permission denied, read-only, full and not-a-directory lead four
    different places. An errno leads to a web search."""
    assert "READ-ONLY" in preflight._why_unwritable(
        tmp_path, OSError(errno.EROFS, "x"))
    assert "full" in preflight._why_unwritable(
        tmp_path, OSError(errno.ENOSPC, "x"))
    assert "must be a directory" in preflight._why_unwritable(
        tmp_path, OSError(errno.ENOTDIR, "x"))


def test_the_fix_differs_depending_on_whether_the_root_was_chosen(monkeypatch,
                                                                   tmp_path):
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    assert "STING_SESSION_ROOT points here" in preflight._fix_unwritable(tmp_path)
    monkeypatch.delenv("STING_SESSION_ROOT")
    chown = preflight._fix_unwritable(tmp_path)
    assert "unset" in chown and "chown" in chown


# --------------------------------------- 5 · one label, two installs

def test_a_service_loaded_from_another_installs_file_is_not_mine(monkeypatch,
                                                                  tmp_path):
    """⚠ THE LABEL IS PER USER, NOT PER INSTALL. Both installs write
    `dev.sting.shipper`; the second boots out the first and takes it. Until
    status() compared the two paths, the first install reported LOADED with a
    pid — for a process running somebody else's plist against somebody else's
    home directory. That happened during the rehearsal, silently.
    """
    mine = tmp_path / "mine.plist"
    theirs = tmp_path / "theirs.plist"
    mine.write_text("<plist/>")
    monkeypatch.setattr(service, "kind", lambda: "launchd")
    monkeypatch.setattr(service, "target_path", lambda: mine)
    monkeypatch.setattr(service, "loaded", lambda: {
        "loaded": True, "pid": 4242, "file": str(theirs), "detail": "state = running"})

    state = service.status()
    assert state["loaded"] is True
    assert state["is_this_install"] is False
    assert state["running_file"] == str(theirs)


def test_a_service_loaded_from_my_own_file_is_mine(monkeypatch, tmp_path):
    mine = tmp_path / "mine.plist"
    mine.write_text("<plist/>")
    monkeypatch.setattr(service, "kind", lambda: "launchd")
    monkeypatch.setattr(service, "target_path", lambda: mine)
    monkeypatch.setattr(service, "loaded", lambda: {
        "loaded": True, "pid": 1, "file": str(mine), "detail": ""})
    assert service.status()["is_this_install"] is True


def test_preflight_fails_when_the_label_belongs_to_another_install(monkeypatch,
                                                                   capsys,
                                                                   tmp_path):
    monkeypatch.setattr(service, "status", lambda: {
        "kind": "launchd", "path": str(tmp_path / "mine.plist"),
        "file_present": True, "loaded": True, "pid": 9,
        "running_file": str(tmp_path / "theirs.plist"),
        "is_this_install": False, "detail": ""})
    preflight.check_supervisor_loaded()
    out = capsys.readouterr().out
    assert "[FAIL]" in out
    assert "per USER" in out
    assert preflight._failed == 1


def test_an_unknowable_owner_is_not_reported_as_a_takeover(monkeypatch,
                                                            tmp_path):
    """A supervisor that does not say which file it loaded leaves
    `is_this_install` None, and None is not False. Accusing a machine of a
    collision on no evidence sends somebody to reinstall for nothing."""
    monkeypatch.setattr(service, "kind", lambda: "launchd")
    monkeypatch.setattr(service, "target_path", lambda: tmp_path / "mine.plist")
    monkeypatch.setattr(service, "loaded", lambda: {
        "loaded": True, "pid": 1, "file": None, "detail": ""})
    assert service.status()["is_this_install"] is None
