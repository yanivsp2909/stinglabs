"""A settings change reaches the RUNNING shipper.

⚠ THE BUG, SEEN ON THE AZURE VM. The shipper started 26 Sep 14:45:34 UTC;
`install.py --tier full` rewrote ~/.sting/env at 14:56:15; the shipper was not
restarted and shipped at the old tier (LOCATED) for 6.5 hours while `--status`
said full. The shipper reads its settings once, when it starts (`shipper/run.py`
`main` -> `config.from_env()`), and on Linux the install ran `systemctl --user
enable --now`, which starts a stopped unit and leaves a running one exactly as
it was. A rotated device token has the same problem, and stops shipping
altogether once the old token is revoked.

launchd was never affected: its install boots the job out and bootstraps it
again, which ends the old process and starts one on the plist just written
(RunAtLoad). That is pinned here too, so it cannot drift into the Linux bug.

⚠ FAKES ONLY. `systemctl` and `launchctl` are scripts on a temp PATH that
record their calls, and `service._run` refuses any command that does not
resolve to one of them, so nothing here can reach the real supervisor. HOME,
~/.sting and the shipper's lock are the per-test ones (the root conftest).
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from pathlib import Path

import pytest

import install
from installer import supervisor
from shipper import run as shipper_run
from shipper import service, singleton

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX fakes and flock")

ROOT = Path(__file__).resolve().parent.parent

# Records every call, and keeps just enough state to answer `print` and `show`
# the way the real tools would: launchd holds a label from bootstrap to bootout.
FAKE = '''#!{python}
import os, sys
from pathlib import Path
log = Path(os.environ["FAKE_SUPERVISOR_LOG"])
name, args = Path(sys.argv[0]).name, sys.argv[1:]
with log.open("a") as out:
    out.write(" ".join([name] + args) + "\\n")
state = log.with_name("launchd-holds")
held = set(state.read_text().split()) if state.exists() else set()
if name == "launchctl" and args[:1] == ["print"]:
    if args[1].rsplit("/", 1)[-1] not in held:
        sys.exit(113)
    print("state = running")
    print("pid = 4242")
elif name == "launchctl" and args[:1] == ["bootout"]:
    held.discard(args[1].rsplit("/", 1)[-1])
elif name == "launchctl" and args[:1] == ["bootstrap"]:
    held.add(Path(args[2]).stem)
elif name == "systemctl" and "show" in args:
    print("LoadState=loaded")
    print("ActiveState=active")
    print("MainPID=4242")
state.write_text("\\n".join(sorted(held)))
'''

PLATFORMS = {"systemd": "Linux", "launchd": "Darwin"}


@pytest.fixture
def fake_supervisor(tmp_path, monkeypatch):
    """fake_supervisor(flavour) -> calls(): every supervisor command run, in order."""
    fakes = tmp_path / "fakebin"
    fakes.mkdir()
    for name in ("launchctl", "systemctl"):
        tool = fakes / name
        tool.write_text(FAKE.format(python=sys.executable), encoding="utf-8")
        tool.chmod(0o700)
    log = tmp_path / "supervisor.log"
    monkeypatch.setenv("FAKE_SUPERVISOR_LOG", str(log))
    monkeypatch.setenv("PATH", f"{fakes}{os.pathsep}{os.environ.get('PATH', '')}")
    real_run = service._run

    def only_the_fakes(command, timeout=20):
        resolved = shutil.which(command[0])
        assert resolved and Path(resolved).parent == fakes, (
            f"{command[0]} resolves to {resolved}, not a fake: refusing to run it")
        return real_run(command, timeout)

    monkeypatch.setattr(service, "_run", only_the_fakes)
    monkeypatch.setattr(supervisor, "_SETTLE_POLL", 0.01)

    def use(flavour):
        monkeypatch.setattr(platform, "system", lambda: PLATFORMS[flavour])
        assert service.kind() == flavour
        return lambda: log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return use


def install_run(tier: str, token: str) -> dict:
    """What one install run does to the shipper's service, in install.py's
    order (section 8): the env file, the supervisor file, then `activate`."""
    install.write_env({"STING_COLLECTOR_URL": "https://collector.invalid",
                       "STING_DEVICE_ID": "laptop", "STING_DEVICE_TOKEN": token,
                       "STING_TIER": tier})
    supervisor.write(sys.executable, ROOT / "shipper" / "run.py", {"STING_TIER": tier})
    return supervisor.activate()


CHANGES = {
    "the tier": (("verdict_reason_location", "tok-a"), ("full", "tok-a")),
    "the token": (("verdict_reason_location", "tok-a"),
                  ("verdict_reason_location", "tok-b")),
}


# ═══════════════════════════════════ 1 · a re-run restarts what it manages

@pytest.mark.parametrize("change", sorted(CHANGES))
def test_a_rerun_restarts_a_running_systemd_shipper(fake_supervisor, change):
    """RED on main: the second run issued daemon-reload and `enable --now`,
    and the running unit kept the settings it started with."""
    calls = fake_supervisor("systemd")
    first, second = CHANGES[change]
    install_run(*first)
    before = len(calls())
    install_run(*second)
    rerun = calls()[before:]
    unit = f"{service.label()}.service"
    assert f"systemctl --user restart {unit}" in rerun, rerun
    assert rerun.index("systemctl --user daemon-reload") < rerun.index(
        f"systemctl --user restart {unit}"), "restarted before the unit was re-read"


@pytest.mark.parametrize("change", sorted(CHANGES))
def test_a_rerun_restarts_a_running_launchd_shipper(fake_supervisor, change):
    """Already true on main, pinned: bootout ends the running job, bootstrap
    starts it again from the plist just written. Equivalent to `kickstart -k`,
    and unlike it, the new plist's environment is the one that runs."""
    calls = fake_supervisor("launchd")
    first, second = CHANGES[change]
    install_run(*first)
    before = len(calls())
    outcome = install_run(*second)
    rerun = calls()[before:]
    target = f"gui/{os.getuid()}/{service.label()}"
    bootout = rerun.index(f"launchctl bootout {target}")
    bootstrap = rerun.index(f"launchctl bootstrap gui/{os.getuid()} {service.plist_path()}")
    assert bootout < bootstrap, rerun
    assert outcome["ok"] is True, outcome


@pytest.mark.parametrize("flavour, expected", [
    ("systemd", "systemctl --user restart {label}.service"),
    ("launchd", "launchctl kickstart -k gui/{uid}/{label}"),
])
def test_the_restart_command_a_person_is_shown(fake_supervisor, flavour, expected):
    fake_supervisor(flavour)
    assert service.restart_command() == expected.format(label=service.label(),
                                                        uid=os.getuid())


# ═══════════════════════════════════ 2 · --status says when it is stale

def hold_the_lock(started: float) -> int:
    """A shipper that started at `started`: the lock held, as the real one
    writes it. Returns the fd; the lock is released when the test closes it.
    ⚠ `fcntl` IS IMPORTED HERE, NOT AT MODULE SCOPE: the Windows CI job
    collects every test file, and a module-scope import breaks collection."""
    import fcntl

    path = singleton.lock_path(Path.home() / ".sting" / "shipper")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.write(fd, json.dumps({"pid": os.getpid(), "since": started,
                             "argv0": "shipper/run.py"}).encode())
    return fd


def settings_changed_at(when: float) -> Path:
    path = install.write_env({"STING_TIER": "full", "STING_DEVICE_TOKEN": "tok-b"})
    os.utime(path, (when, when))
    return path


STALE = "the running shipper predates your settings: restart it"


@pytest.mark.parametrize("flavour", sorted(PLATFORMS))
def test_status_warns_when_the_running_shipper_predates_the_env_file(
        fake_supervisor, flavour, capsys):
    """RED on main: `--status` printed the new tier and said nothing about the
    process still running on the old one."""
    fake_supervisor(flavour)
    fd = hold_the_lock(started=1_790_000_000.0)
    try:
        settings_changed_at(1_790_000_000.0 + 651)
        install.main(["--status"])
    finally:
        os.close(fd)
    out = capsys.readouterr().out
    assert STALE in out, out
    assert service.restart_command() in out, out


@pytest.mark.parametrize("offset", [-60, 1.5], ids=["before", "same-tick"])
def test_status_is_quiet_when_the_shipper_did_not_predate_the_env_file(
        fake_supervisor, capsys, offset):
    """⚠ "same-tick": the install writes the file, then restarts, and a
    filesystem that rounds mtimes up (FAT, to 2 s) can date the file a moment
    AFTER the restart. That must not read as stale (python review)."""
    fake_supervisor("systemd")
    fd = hold_the_lock(started=1_790_000_000.0)
    try:
        settings_changed_at(1_790_000_000.0 + offset)
        install.main(["--status"])
    finally:
        os.close(fd)
    assert STALE not in capsys.readouterr().out


def test_the_shippers_own_status_carries_the_same_warning(fake_supervisor, capsys):
    """`python3 -m shipper.run --status` reads the settings fresh too, so it
    also printed the new tier over a process running the old one."""
    fake_supervisor("systemd")
    fd = hold_the_lock(started=1_790_000_000.0)
    try:
        settings_changed_at(1_790_000_000.0 + 651)
        shipper_run.main(["--status"])
    finally:
        os.close(fd)
    status = json.loads(capsys.readouterr().out)
    stale = status["running_shipper"]
    assert stale["predates_settings"] is True, stale
    assert stale["restart"] == service.restart_command()
    assert STALE in stale["message"]
