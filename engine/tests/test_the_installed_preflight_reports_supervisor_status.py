"""G2 — the INSTALLED preflight could not report the supervisor's status.

`tools/preflight.py` is shipped (PAYLOAD copies `tools/`). Its supervisor check
did `from installer import supervisor`, and `installer/*.py` is NOT shipped —
PAYLOAD copies only `installer/cursor_bridge.ps1`. So on every real install the
one diagnostic that could catch a dead supervisor degraded to

    [INFO] the shipper's supervisor is loaded  —  could not be determined:
           ImportError: cannot import name 'supervisor' from 'installer'

and preflight still exited 0. "A list cannot notice its own omission."

⚠ THIS TEST RUNS THE INSTALLED TREE AS A SUBPROCESS, AND THAT IS THE WHOLE
TEST. Two ways to get this wrong, both measured while writing it:

  1. Testing the checkout. The checkout HAS installer/, so the import
     succeeds and the check reports a real status. That is exactly why this
     shipped: every test that exercised preflight exercised it from here.
  2. Importing the installed preflight IN-PROCESS from pytest. The checkout is
     on sys.path, `installer/` is a namespace package, and Python MERGES the
     installed (empty) installer/ with the checkout's — the import succeeds and
     the test passes for the wrong reason. Measured: `python -c` with the
     checkout as cwd found `supervisor` through the merge and printed nothing.

So: stage PAYLOAD with the real `place()`, then run the staged preflight as a
script (its sys.path[0] is its own directory), from a neutral cwd.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from core import allow_once
from installer import place

ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR_LINE = "the shipper's supervisor is loaded"
THE_BUG = ("could not be determined", "ImportError")


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """A real install into a temp prefix — the same fixture shape as
    tests/test_install.py, so this stages exactly what a stranger receives."""
    prefix = tmp_path / "share" / "sting"
    sessions = tmp_path / "state"
    sessions.mkdir(parents=True)
    monkeypatch.setenv("STING_INSTALL_ROOT", str(prefix))
    monkeypatch.setenv("STING_SESSION_ROOT", str(sessions))
    allow_once._install_manifest_version.cache_clear()
    place.place(prefix=prefix, session_root=sessions)
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    return prefix / "current", sessions, home


def _run_preflight(script: Path, sessions: Path, home: Path, prefix: Path,
                   cwd: Path) -> str:
    env = {**os.environ, "HOME": str(home),
           "STING_SESSION_ROOT": str(sessions),
           "STING_INSTALL_ROOT": str(prefix)}
    proc = subprocess.run([sys.executable, str(script), "--agent", "claude-code"],
                          cwd=str(cwd), env=env, capture_output=True, text=True,
                          timeout=180)
    return proc.stdout + proc.stderr


def _supervisor_line(output: str) -> str:
    lines = [ln for ln in output.splitlines() if SUPERVISOR_LINE in ln]
    assert lines, f"preflight never printed the supervisor check:\n{output[-1500:]}"
    return lines[-1]


def test_the_installed_preflight_reports_a_real_supervisor_status(installed, tmp_path):
    """From the INSTALLED tree: a real outcome (loaded / not loaded / no file),
    never 'could not be determined'. This is what a stranger runs."""
    current, sessions, home = installed
    script = current / "tools" / "preflight.py"
    assert script.is_file(), "PAYLOAD stopped shipping tools/preflight.py"
    # ARM THE GATE: this must be a PLACED tree, not the checkout in a costume.
    # `installer/prepare.py` exists in the checkout and is in nobody's PAYLOAD
    # (`detect.py`, which used to be the sentinel here, ships since docs/78),
    # so its absence proves the narrow placed set is what is being exercised.
    # (The first version asserted supervisor.py was ABSENT — true before the
    # fix, false after it, and a gate that flips with the fix is not a gate.)
    assert current.resolve() != ROOT
    assert (current / "INSTALL.json").is_file()
    assert not (current / "installer" / "prepare.py").exists()

    line = _supervisor_line(_run_preflight(script, sessions, home,
                                           current.parent, tmp_path))
    for sign in THE_BUG:
        assert sign not in line, (
            f"the installed preflight cannot see the supervisor:\n  {line}")


def test_the_checkout_preflight_reports_a_real_status_too(installed, tmp_path):
    """CONTROL. The same run from the checkout — which has installer/ — must
    report a real status. If it did not, the assertion above would be about
    the environment, not about what ships. And it is the reason the bug was
    invisible: this is the only tree the old tests ever ran preflight from."""
    _current, sessions, home = installed
    line = _supervisor_line(_run_preflight(ROOT / "tools" / "preflight.py",
                                           sessions, home, _current.parent,
                                           tmp_path))
    for sign in THE_BUG:
        assert sign not in line, line
