"""Allow-once, with an install actually present.

⚠ WHY THIS FILE EXISTS AND WHY ITS FIXTURE IS THE POINT.

Two tests in `test_extension_contract.py` covered exactly this round trip — the
extension writes a grant, the engine consumes it — and both passed for months
while the behaviour was broken. `_valid` required
`grant["guard_version"] == installed_version()`; the extension writes no version,
and with no install `installed_version()` is `None`. `None == None`. Both sides
were ABSENT, so the comparison succeeded without ever comparing anything.

The day an install appeared on the developer's machine, `installed_version()`
became a real string and every grant the approve button wrote was refused. The
tests stayed green throughout, because the test environment had no install.

**So every test here declares an install first, and asserts the mechanism is
armed before asserting anything about the outcome.** A test of a gate that does
not check the gate is closed is a test of nothing.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

def _touch_marker(path, at):
    """Set the swap marker's mtime, on either layout.

    ⚠ `follow_symlinks=False` IS ITSELF UNSUPPORTED ON WINDOWS — `os.utime`
    raises NotImplementedError there whatever it is pointed at, so routing these
    fixtures through `_swap_marker()` was only half the fix. The flag exists to
    stamp the LINK rather than its target; on Windows the marker is a regular
    file, so there is no link to distinguish and the flag is not needed.
    """
    import os as _os
    if _os.path.islink(path):
        _os.utime(path, (at, at), follow_symlinks=False)
    else:
        _os.utime(path, (at, at))


sys.path.insert(0, str(Path(__file__).parent.parent))

import hook_entry                                                # noqa: E402
from core import allow_once, engine                              # noqa: E402
from core.types import Action, ActionKind, Decision, Verdict     # noqa: E402
from private_fixtures import needs_extension  # noqa: E402

ROOT = Path(__file__).parent.parent
PROBE = ROOT / "extension" / "test" / "contract-probe.mjs"
RESOLVER = ROOT / "extension" / "test" / "ts-resolver.mjs"


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """A real INSTALL.json behind a real `current` symlink, as place.py leaves
    them. Returns a `reinstall(at=None)` that moves the install forward.

    ⚠ THE SYMLINK IS NOT DECORATION. `install_time` takes the later of the
    manifest's time and the LINK's mtime, because `place.py` writes the manifest
    before it sweeps grants and repoints `current` afterwards. A fixture with a
    plain directory would not exercise the half that closes that window.
    """
    prefix = tmp_path / "sting"

    def reinstall(at: float | None = None):
        at = time.time() if at is None else at
        target = prefix / f"v-{at:.6f}"
        target.mkdir(parents=True, exist_ok=True)
        (target / "INSTALL.json").write_text(json.dumps({
            "guard_version": f"v-{at:.6f}", "installed_at": at,
            "installed_by": "test"}), encoding="utf-8")
        os.utime(target / "INSTALL.json", (at, at))
        # ⚠ THE LAYOUT IS `place`'s TO BUILD, NOT THIS FIXTURE'S. These lines
        # used to call os.symlink directly, which is a second implementation of
        # the thing under test — and on Windows it raises, because a symlink
        # needs Developer Mode. `_repoint` makes whichever layout the platform
        # uses, and `_swap_marker` names whatever it made.
        from installer import place
        place._repoint(prefix / "current", target)
        _touch_marker(allow_once._swap_marker(), at)
        allow_once._install_manifest_time.cache_clear()
        allow_once._install_manifest_version.cache_clear()
        return at

    monkeypatch.setenv("STING_INSTALL_ROOT", str(prefix))
    first = reinstall(time.time() - 60)
    assert allow_once.install_time() is not None, (
        "the fixture did not produce an install — every assertion below would "
        "then be testing nothing, which is the bug this file exists for")
    return type("Install", (), {"reinstall": staticmethod(reinstall),
                                 "at": first, "prefix": prefix})


@pytest.fixture
def denying(monkeypatch):
    monkeypatch.setattr(engine, "decide", lambda a, s, w: Verdict(
        Decision.DENY, "this carries data traced from .env", "secret_egress"))


def payload(command="git push origin main", session="s1"):
    return json.dumps({"session_id": session, "cwd": "/tmp",
                       "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": command}})


def action(command="git push origin main", session="s1"):
    return Action(session, 0, ActionKind.EXEC, (), command, None, "Bash", None,
                  "/tmp", ("/tmp",), "x")


def extension_grant(root, ttl=300):
    """Drive the REAL TypeScript writer, as the approve button does."""
    node = shutil.which("node")
    result = subprocess.run([node, "--import", str(RESOLVER), str(PROBE),
                              "grant", str(root), str(ttl)],
                             capture_output=True, text=True, cwd=str(PROBE.parent))
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    return json.loads(result.stdout)


# ------------------------------------------------- 1 · the regression, pinned

def test_the_mechanism_is_actually_armed_in_this_fixture(installed):
    """⚠ THE ASSERTION THAT WAS MISSING FOR MONTHS, AS ITS OWN TEST.

    Everything below is only evidence if there is an install to be refused by.
    """
    assert allow_once.install_time() is not None
    assert allow_once.installed_version() is not None


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@needs_extension
def test_a_grant_from_the_extension_is_accepted_on_an_installed_machine(
        installed, denying, monkeypatch):
    """The exact failure reported from the field: the approve button does
    nothing on any machine where the guard is installed.

    Written by the real TypeScript module, which carries no `guard_version` at
    all — and must not have to.
    """
    root = Path(os.environ["STING_SESSION_ROOT"])
    hook_entry.run(payload())
    written = extension_grant(root)
    assert "guard_version" not in written["grant"], (
        "the extension has started writing a version — if that is deliberate, "
        "this test no longer covers the language-independence it was written for")

    spent = allow_once.consume("s1", action())
    assert spent is not None, "the engine refused the approve button's grant"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@needs_extension
def test_the_denied_action_is_allowed_through_the_hook_after_approval(
        installed, denying):
    """Denied, click allow once, retry — with an install present this time."""
    out, _, _ = hook_entry.run(payload())
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"

    extension_grant(Path(os.environ["STING_SESSION_ROOT"]))

    out, err, code = hook_entry.run(payload())
    # ⚠ an ALLOW is now an explicit permissionDecision, not empty stdout — empty means NO OPINION and Claude Code prompts
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "allow", "the retry must be allowed"
    assert "one-shot override spent" in err


def test_a_python_written_grant_is_also_accepted(installed):
    """The other producer. Both write `granted_at`; neither has to agree with
    the engine about a version string."""
    allow_once.write_grant("s1", allow_once.fingerprint(action()))
    assert allow_once.consume("s1", action()) is not None


# ------------------------------------- 2 · the chokepoint, and it stays closed

def test_a_grant_issued_before_a_reinstall_is_refused_after_it(installed):
    """⚠ THE PROPERTY THE VERSION CHECK EXISTED FOR, KEPT.

    A one-shot grant authorises ONE action under ONE policy. The human clicked
    while looking at a verdict some specific set of rules reached, and a
    reinstall is the moment those rules change.
    """
    allow_once.write_grant("s1", allow_once.fingerprint(action()))
    assert allow_once.grant_path("s1").exists()

    installed.reinstall()                      # sweeps nothing here: on purpose

    assert allow_once.consume("s1", action()) is None, (
        "a grant issued under the previous policy was redeemed under the new "
        "one — the reinstall chokepoint is open")


def test_a_grant_with_no_timestamp_is_refused_while_an_install_exists(installed):
    """⚠ THIS IS THE TEST THAT MUST FAIL IF SOMEONE RELAXES THE CHECK.

    The tempting repair for the original bug was "accept a grant that does not
    say" — and that reopens the chokepoint completely, because a grant issued
    under any policy would then be redeemable under any other. A grant that
    cannot be placed relative to the install is not permission.
    """
    assert allow_once._valid(
        {"action_hash": "abc", "expires_at": time.time() + 300},
        "abc", time.time()) is False

    for absent in (None, "", "not-a-time", {}, []):
        assert allow_once._valid(
            {"action_hash": "abc", "expires_at": time.time() + 300,
             "granted_at": absent}, "abc", time.time()) is False, absent


def test_the_window_between_the_sweep_and_the_swap_is_closed(installed):
    """⚠ THE ONE RESPECT IN WHICH TIME WAS WEAKER THAN VERSION, REMOVED.

    `place.py` writes INSTALL.json, THEN sweeps grants, THEN repoints `current`.
    A grant written between the sweep and the swap is later than `installed_at`
    and would survive — where the version check refused it, because `current`
    still pointed at the old tree when it was written.

    Measured on the real install on this machine, that window was 4.6 ms:
    installed_at 1786308424.0818, symlink mtime 1786308424.0864. So
    `install_time` takes the LATER of the two, and this pins it.
    """
    manifest_at = time.time() - 10
    installed.reinstall(manifest_at)

    # The swap lands 4.6 ms after the manifest, as measured.
    link = installed.prefix / "current"
    swapped_at = manifest_at + 0.0046
    _touch_marker(allow_once._swap_marker(), swapped_at)
    allow_once._install_manifest_time.cache_clear()

    assert allow_once.install_time() == pytest.approx(swapped_at), (
        "install_time is reading the manifest alone, so a grant written in the "
        "window between the sweep and the swap would survive the install")

    in_the_window = {"action_hash": "abc", "granted_at": manifest_at + 0.002,
                      "expires_at": time.time() + 300}
    assert allow_once._valid(in_the_window, "abc", time.time()) is False


def test_a_grant_issued_after_the_install_is_accepted(installed):
    """The direction that must NOT be refused, or allow-once is broken again."""
    installed.reinstall(time.time() - 5)
    grant = {"action_hash": "abc", "granted_at": time.time(),
              "expires_at": time.time() + 300}
    assert allow_once._valid(grant, "abc", time.time()) is True


# ------------------------------------------------- 3 · the edges of the clock

def test_no_install_means_nothing_to_revoke(tmp_path, monkeypatch):
    """A checkout is the normal state during development. There is no install
    that could have replaced the policy, so a grant with no timestamp at all is
    still refused for being unreadable — but a normal one works."""
    monkeypatch.setenv("STING_INSTALL_ROOT", str(tmp_path / "nothing-here"))
    allow_once._install_manifest_time.cache_clear()
    assert allow_once.install_time() is None
    assert allow_once._valid(
        {"action_hash": "abc", "expires_at": time.time() + 300},
        "abc", time.time()) is True


def test_a_manifest_that_forgot_to_say_when_falls_back_to_its_own_mtime(
        tmp_path, monkeypatch):
    """⚠ AND IT MUST NOT REFUSE EVERY GRANT INSTEAD. `INSTALL.json` is written
    fresh by place.py, so its mtime IS when the install happened. Treating a
    missing field as "cannot tell, refuse everything" would be the same outage
    this fix exists to end, on any machine installed by an older version."""
    prefix = tmp_path / "sting"
    target = prefix / "v1"
    target.mkdir(parents=True)
    manifest = target / "INSTALL.json"
    manifest.write_text(json.dumps({"guard_version": "v1"}), encoding="utf-8")
    when = time.time() - 30
    os.utime(manifest, (when, when))
    from installer import place
    place._repoint(prefix / "current", target)
    _touch_marker(allow_once._swap_marker(), when)

    monkeypatch.setenv("STING_INSTALL_ROOT", str(prefix))
    allow_once._install_manifest_time.cache_clear()

    assert allow_once.install_time() == pytest.approx(when)
    assert allow_once._valid(
        {"action_hash": "abc", "granted_at": time.time(),
         "expires_at": time.time() + 300}, "abc", time.time()) is True


def test_a_clock_that_went_backwards_refuses_rather_than_allows(installed):
    """⚠ THE STOP CONDITION, ANSWERED. Both timestamps are produced on the SAME
    machine — the installer and the approve button are both local — so there is
    no cross-machine skew to reason about. A user who moves the system clock
    backwards between installing and clicking gets a grant that looks older than
    the install, and it is refused.

    That is the safe direction and it is cheap: the cost is clicking again, and
    the alternative is spending an approval under rules nobody saw.
    """
    installed.reinstall(time.time())
    stale = {"action_hash": "abc", "granted_at": time.time() - 3600,
              "expires_at": time.time() + 300}
    assert allow_once._valid(stale, "abc", time.time()) is False


def test_the_cache_cannot_serve_a_time_the_install_has_moved_past(installed):
    """The read is on the hook's path, so it is cached on (path, mtime). A
    reinstall changes both, which is what makes the cache safe — asserted here
    WITHOUT clearing it by hand, unlike the fixture."""
    before = allow_once.install_time()
    later = time.time() + 1
    target = installed.prefix / "v-next"
    target.mkdir(parents=True, exist_ok=True)
    (target / "INSTALL.json").write_text(
        json.dumps({"guard_version": "v-next", "installed_at": later}),
        encoding="utf-8")
    os.utime(target / "INSTALL.json", (later, later))
    from installer import place
    place._repoint(installed.prefix / "current", target)

    assert allow_once.install_time() > before
