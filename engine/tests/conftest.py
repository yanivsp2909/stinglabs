"""Run-wide hooks and fixtures for tests/. The per-test isolation of HOME,
~/.sting and the install root is the root conftest.py's; this adds what that
cannot reach. docs/PARALLEL.md.

  - A test run of this repository marks itself live in the repository's run
    registry for as long as it runs, so a latency bench started from any
    worktree of this repository refuses instead of measuring the overlap.
  - Module constants frozen to the REAL home at import are pointed at each
    test's own home, and variables that would aim a test at outside state are
    cleared.
  - Tests that measure against this machine's own decision logs read a copy
    taken once per run, never the live roots.
"""
from __future__ import annotations

import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from runner import blast_radius
from tools import run_registry

_ROOT = Path(__file__).resolve().parent.parent

# This module is imported before any test runs, so this is the machine's own
# home: the root conftest moves $HOME per test, later.
_REAL_HOME = Path.home()


def pytest_configure(config):
    config._sting_run = run_registry.register(run_registry.SUITE, _ROOT)


def pytest_unconfigure(config):
    registration = getattr(config, "_sting_run", None)
    if registration is not None:
        registration.close()


# ⚠ FROZEN TO THE REAL HOME AT IMPORT, so the root conftest's $HOME cannot move
# them (the inventory: tests/test_a_test_can_only_fail_elsewhere.py). On the
# machine that wrote a test, `~/.sting/env` names a real collector, and a test
# that reads it passes there for a reason it does not name.
_FROZEN_ENV_FILES = (("install", "ENV_FILE"), ("installer.recorded", "ENV_FILE"),
                     ("shipper.config", "ENV_FILE"))

# Each would aim a test at state outside this run: a policy or org-policy file
# somewhere real, or, for every temp-repo `git` call, the real repository.
_OUTSIDE_POINTERS = ("STING_POLICY", "STING_POLICY_CACHE", "GIT_DIR", "GIT_WORK_TREE",
                     "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE")


@pytest.fixture(autouse=True)
def nothing_outside_this_test(isolated_session_root, monkeypatch):
    home = Path.home()                       # this test's, from the root conftest
    for module, name in _FROZEN_ENV_FILES:
        loaded = sys.modules.get(module)
        if loaded is not None and hasattr(loaded, name):
            current = getattr(loaded, name)
            monkeypatch.setattr(loaded, name, type(current)(home / ".sting" / "env"))
    for name in _OUTSIDE_POINTERS:
        monkeypatch.delenv(name, raising=False)


class LiveLogs:
    """This run's copy of the machine's decision logs. `of(root)` is the copy
    of a real root, or a path that does not exist when the machine has none."""

    def __init__(self, roots: dict[str, Path], copies: dict[str, Path], absent: Path):
        self._copies = copies
        self._absent = absent
        for name, root in roots.items():
            setattr(self, name, self.of(root))

    def of(self, root) -> Path:
        return self._copies.get(str(Path(root)), self._absent)


@pytest.fixture(scope="session")
def live_logs(tmp_path_factory) -> Iterator[LiveLogs]:
    """THIS MACHINE'S DECISION LOGS, COPIED ONCE PER TEST RUN.

    The installed guard keeps appending to them while agents work, so a test
    reading the live roots could read different records from one moment to the
    next, or a record half-written. Every test that measures against the real
    logs reads this copy, taken the first time one asks, under the log lock
    (`runner/blast_radius.snapshot`).

    ⚠ DELETED WHEN THE RUN ENDS. The logs hold the commands agents ran, and
    pytest keeps its last few temp directories: without this, every run would
    leave another copy of the machine's history in the system temp directory.
    """
    roots = {"sessions": _REAL_HOME / ".sting" / "sessions",
             "dogfood": _REAL_HOME / ".sting" / "dogfood",
             "archive": _REAL_HOME / "sting" / "sting-logs-archive"}
    base = tmp_path_factory.mktemp("live-logs")
    try:
        copies = blast_radius.snapshot(list(roots.values()), base / "snapshot")
        yield LiveLogs(roots, copies, base / "absent")
    finally:
        shutil.rmtree(base, ignore_errors=True)
