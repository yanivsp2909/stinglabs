"""Put the repo root on sys.path so `core`, `adapters` and `runner` import
cleanly under pytest without an install step."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

# Captured at import, BEFORE any fixture can move it — `real_home` needs the
# machine's actual home and every test has already had it replaced by then.
_ORIGINAL_HOME = Path.home()


@pytest.fixture(autouse=True)
def isolated_session_root(tmp_path, monkeypatch):
    """No test may touch the real ~/.sting.

    Autouse so it cannot be forgotten: a test that writes real session state
    would leak taint between runs and, worse, between a test run and the
    developer's own sessions.

    STING_LOG is cleared for the same reason. It names a single file outright,
    so a developer who has it exported would otherwise have every test run
    append to their real decision log — and the hash chain would then record
    those writes as genuine history.
    """
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path / "sting-sessions"))
    monkeypatch.delenv("STING_LOG", raising=False)

    # ⚠ AND `$HOME` ITSELF, BECAUSE ISOLATING `~/.sting` WAS NOT ENOUGH — AND
    # THE PROOF IS THAT THIS SUITE DELETED THE DEVELOPER'S REAL LAUNCH AGENT.
    #
    # `installer/supervisor.py` writes to `~/Library/LaunchAgents` and
    # `~/.config/systemd/user`, neither of which STING_SESSION_ROOT covers. When
    # `activate()` grew a legacy-migration step, a test that faked `_run` while
    # `Path.home()` was still real found the machine's own
    # `dev.sting.shipper.plist` and unlinked it. The service stayed up — launchd
    # holds it in memory — so it would have come back as MISSING at the next
    # login, hours later, with nothing connecting it to a test run.
    #
    # This is the same defect class as the sandbox install taking the real
    # supervisor label: code that computes a path from `$HOME` and is then
    # pointed at the wrong one. One fixture closes both for the suite.
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    # The suite declares its own project roots — which is precisely what
    # STING_ROOTS is for. Most tests use a synthetic cwd like "/tmp" that is not
    # a git repository, so without this every one of them would take the
    # fallback path and emit the "project root unknown" note, burying that
    # signal in tests that are not about roots at all. Tests that ARE about root
    # resolution clear it explicitly — see tests/test_project_roots.py.
    monkeypatch.setenv("STING_ROOTS", str(tmp_path))


@pytest.fixture
def real_home(monkeypatch):
    """Undo the HOME isolation, for the tests that READ this machine's own logs.

    ⚠ THEY ARE THE ANTIDOTE TO CORPUS BLINDNESS, so losing them silently would
    be the worst possible cost of isolating $HOME. The live logs are the only
    population containing `cd X &&`, heredocs and 2048-character commands, and a
    test that reads them is worth more than one that reads a fixture.

    ⚠ READ-ONLY BY CONVENTION AND BY REVIEW, NOT BY ENFORCEMENT. Nothing here
    stops a test that asks for this from WRITING to the real home — which is
    exactly what happened before the isolation existed. A test using this
    fixture must only read, and that is a thing to check in review.
    """
    import os as _os

    home = _os.path.expanduser("~")
    real = Path(_ORIGINAL_HOME)
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: real))
    return real


# ⚠ ABSENCE IS NO LONGER THE DEFAULT THE SUITE INHERITS. THIS IS WORKING RULE
# #13, ENFORCED RATHER THAN REMEMBERED.
#
# Five defects in one week shared one shape: a comparison where BOTH SIDES CAN
# BE ABSENT, so it succeeded without comparing anything, and the covering test
# passed while the behaviour was broken. The worst of them was allow-once —
# `grant["guard_version"] == installed_version()` was `None == None` in every
# test environment, because no test environment had an install. The approve
# button was dead on every installed machine for as long as that was true.
#
# The cheapest possible fix is to stop making ABSENCE the default. If the suite
# runs with a gate ARMED, a test that wants the absent branch has to ask for it,
# and "I never established the precondition" becomes visible instead of being
# inherited.
#
# ⚠ THE COST IS MEASURED AND IT IS ZERO, which is why this is the mechanism and
# not a second full run. The whole suite was run under each of these settings
# before adopting them: `STING_INSTALL_ROOT` armed, 0 of 2051 tests changed
# outcome; `STING_SCRATCH` armed, 0; `STING_ROOTS` armed, 0. A second profile
# run would double the time of the thing people run most often and find the
# same nothing.
#
# ⚠ NOT ARMED, EACH FOR A STATED REASON, so this list is a decision and not an
# oversight:
#   the collector      arming it means naming a URL, and a test that then tries
#                      to reach it has network behaviour that depends on what is
#                      listening on this machine. Absence is the honest default
#                      for a thing that is genuinely optional.
#   STING_TIER         the DEFAULT tier is documented behaviour worth exercising,
#                      so it is cleared rather than set — see below.
#   STING_OBSERVE      the same: enforce-vs-observe is what several tests are
#                      about, and a suite-wide default would decide it for them.
@pytest.fixture(autouse=True)
def armed_gates(tmp_path, monkeypatch):
    """An install exists, and a scratch root exists, unless a test says not.

    Both are real on disk: `installed_version()` reads a manifest and
    `install_time()` reads the `current` symlink's mtime, so a fixture that only
    set the variable would arm the flag and not the mechanism.
    """
    prefix = tmp_path / "armed-install"
    target = prefix / "v-suite"
    target.mkdir(parents=True, exist_ok=True)
    (target / "INSTALL.json").write_text(
        '{"guard_version": "v-suite", "installed_at": 1.0,'
        ' "installed_by": "conftest"}', encoding="utf-8")
    link = prefix / "current"
    if not link.exists():
        link.symlink_to(target)
    monkeypatch.setenv("STING_INSTALL_ROOT", str(prefix))

    scratch = tmp_path / "armed-scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("STING_SCRATCH", str(scratch))

    # ⚠ A SUITE MUST NOT LEAVE RESIDENT PROCESSES ON THE DEVELOPER'S MACHINE,
    # AND IT DID. Any test that drives `sting_hook.py` with no daemon running
    # starts one — that is the product's designed behaviour — and nothing on the
    # test side owns it, because the hook deliberately does not wait for what it
    # spawned. Measured after one full run: FOURTEEN daemons still resident,
    # each holding an imported engine, each pointed at a pytest tmpdir that no
    # longer existed, each with 30 minutes to live.
    #
    # Not fixed with `pkill`, which would also kill the daemon serving this
    # developer's own agent session. Fixed by making the residency short for
    # anything the suite starts: a leaked daemon goes away in seconds instead of
    # half an hour. The default is exercised by its own test rather than by
    # every test inheriting it.
    monkeypatch.setenv("STING_DAEMON_IDLE", "5")

    # ⚠ AND THE SUITE'S RESULT MUST NOT DEPEND ON THE SHELL THAT RAN IT. These
    # are cleared, not set: a developer with STING_TIER=full exported had one
    # test asserting a tier the environment chose, and it passed here and failed
    # for them. That is the same disease as the one above, pointing outward.
    for leaky in ("STING_TIER", "STING_COLLECTOR_URL", "STING_DEVICE_TOKEN",
                   "STING_DEVICE_ID", "STING_SHIPPER_STATE", "STING_OBSERVE",
                   # A developer with this exported would run the whole suite
                   # under a different lock bound than everyone else, and the
                   # test that pins the default would fail for them alone.
                   "STING_LOCK_TIMEOUT",
                   # A developer with this exported would have every record the
                   # suite writes declare itself work, and the tests that assert
                   # on absence would pass for them and fail for everyone else.
                   "STING_PURPOSE",
                   # A developer with Sparta on would ship every suite batch
                   # through a model, and the flag-off goldens would fail for
                   # them alone.
                   "STING_SPARTA", "STING_SPARTA_TAINT"):
        monkeypatch.delenv(leaky, raising=False)

    # ⚠ NO MODEL IN A TEST. The real Sparta detector's package, the first part
    # of `DETECTOR_MODULE` in shipper/sparta_iface.py, cannot be imported
    # anywhere in the suite: a test that turns the flag on and forgets to point
    # the import at a stub fails, instead of loading a model on whoever runs
    # it (tests/test_sparta_contract.py pins that the two names agree).
    monkeypatch.setitem(sys.modules, "sparta", None)
