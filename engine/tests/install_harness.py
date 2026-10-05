"""The harness every test that runs install.py uses: nothing real is touched.

A helper module, not a test: a test file puts `tests/` on sys.path and imports
the fixtures it needs by name, not through the `tests` package (whose meaning
depends on what was collected before it),

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from install_harness import SAFE, home, no_real_supervisor   # noqa: E402,F401

⚠ NOTHING HERE TOUCHES THE REAL MACHINE, WHATEVER THE CODE UNDER TEST DOES.
HOME is the test's own, the install prefix is a temp dir, the agent is stubbed
into the temp home and preflight is stubbed. `launchctl` and `systemctl` are
fakes first on PATH, and `service._run` refuses any command that does not
resolve to one of them. The same guards tests/test_there_are_no_tiers.py keeps
(a stray launchd job was registered once by a test run without them).
"""
from __future__ import annotations

import os
import shutil
import subprocess as sp
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import install                                                     # noqa: E402
from installer import recorded                                     # noqa: E402
from shipper import service                                        # noqa: E402

_FAKE_SUPERVISOR = """#!{python}
import os, sys
from pathlib import Path
with Path(os.environ["FAKE_SUPERVISOR_LOG"]).open("a") as out:
    out.write(" ".join([Path(sys.argv[0]).name] + sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["print"]:
    sys.exit(113)
if "show" in sys.argv:
    print("LoadState=not-found")
    print("ActiveState=inactive")
    print("MainPID=0")
"""

SAFE = ["--yes", "--no-collector", "--no-supervisor", "--agent", "claude-code",
        "--scratch", ""]
"""Install flags that write only into the temp home and register nothing."""


@pytest.fixture
def no_real_supervisor(tmp_path, monkeypatch):
    """Fake `launchctl` and `systemctl` first on PATH, and `service._run`
    refusing anything that is not one of them."""
    fakes = tmp_path / "fakebin"
    fakes.mkdir(exist_ok=True)
    for name in ("launchctl", "systemctl"):
        tool = fakes / name
        tool.write_text(_FAKE_SUPERVISOR.format(python=sys.executable), encoding="utf-8")
        tool.chmod(0o700)
    monkeypatch.setenv("FAKE_SUPERVISOR_LOG", str(tmp_path / "supervisor.log"))
    monkeypatch.setenv("PATH", f"{fakes}{os.pathsep}{os.environ.get('PATH', '')}")
    real_run = service._run

    def only_the_fakes(command, timeout=20):
        resolved = shutil.which(command[0])
        assert resolved and Path(resolved).parent == fakes, (
            f"{command[0]} resolves to {resolved}, not a fake: refusing to run it")
        return real_run(command, timeout)

    monkeypatch.setattr(service, "_run", only_the_fakes)


@pytest.fixture
def home(tmp_path, monkeypatch, no_real_supervisor):
    """A temp home to install into: the agent stubbed into it, only preflight
    stubbed, and the supervisor faked (`no_real_supervisor`)."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("STING_INSTALL_ROOT", str(home / "prefix"))
    env_file = home / ".sting" / "env"
    monkeypatch.setattr(install, "ENV_FILE", env_file)
    monkeypatch.setattr(recorded, "ENV_FILE", env_file)
    config_file = home / ".claude" / "settings.json"
    monkeypatch.setattr(install, "choose_agents", lambda requested: [
        {"agent": "claude-code", "evidence": "stubbed",
         "config": str(config_file), "user_level": True}])
    real_run = sp.run

    def only_preflight(cmd, *a, **k):
        if any("preflight" in str(part) for part in (cmd or [])):
            return sp.CompletedProcess(cmd, 0)
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(install.subprocess, "run", only_preflight)
    monkeypatch.setattr(install.console, "make_output_safe", lambda: None)
    return home
