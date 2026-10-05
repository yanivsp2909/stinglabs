"""Frozen populations: one snapshot of this machine's decision logs, kept out
of git and pinned in it, for the tests that measure a rule's false-alarm cost
against real traffic. docs/PARALLEL.md.

⚠ WHY FROZEN. The live logs grow with everything any agent here does, so a test
that reads them answers a different question every day. One sandboxed tamper
check another agent ran, a TRUE positive, turned a false-alarm test red on every
tree. A frozen population is one snapshot (`runner/blast_radius.py snapshot`), so
the question stays the one the test was written for.

⚠ NEVER COMMITTED. The copy is unredacted: real commands. It lives in
`logs/frozen/<name>/` (gitignored, 0700 / 0600). What is committed is the pin,
`tests/frozen/<name>.json`: the snapshot MANIFEST's sha256, its record count and
the date. No log content.

A test reads the copy only after its manifest matches the pin, every file
matches the manifest and the record count matches. Absent (another machine, a
fresh worktree, CI): the test skips and says how to get it. Present but
different: the test FAILS. A population changes on purpose, as a new version,
never by drift.

The copy's path is this checkout's, so HOME never enters it; the live logs a
new version is taken from are named from the machine's real home, read here at
import the way tests/conftest.py reads it, because the root conftest moves HOME
per test.

Not named `test_*`, so pytest imports it rather than collecting it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runner import blast_radius

ROOT = Path(__file__).resolve().parent.parent
FROZEN = ROOT / "logs" / "frozen"
PINS = Path(__file__).resolve().parent / "frozen"
PIN_KEYS = {"manifest_sha256", "records", "taken"}

# Imported by a test module at collection, before any test moves HOME.
_REAL_HOME = Path.home()


def pin(name: str, pins: Path = PINS) -> dict:
    return json.loads((pins / f"{name}.json").read_text(encoding="utf-8"))


def _changed(name: str, why: str) -> str:
    return (f"the frozen population changed; make v2 on purpose. {name}: {why}. "
            f"A population is never edited in place (docs/PARALLEL.md).")


def records(name: str, frozen: Path = FROZEN, pins: Path = PINS) -> list[dict]:
    """Every record of the frozen population `name`, once it is proven to be
    the pinned one. Skips when it is absent; fails when it differs."""
    expected = pin(name, pins)
    dest = frozen / name
    manifest = dest / blast_radius.MANIFEST
    if not manifest.is_file():
        pytest.skip(
            f"the frozen population {name} is not in this checkout: logs/frozen/ is "
            f"never committed. Copy logs/frozen/{name}/ from a checkout that has it "
            f"(`cp -Rp` keeps 0700/0600). A new snapshot of the live logs "
            f"(`python3 runner/blast_radius.py snapshot logs/frozen/<name> "
            f"{_REAL_HOME / '.sting' / 'sessions'}`) is a new population, pinned as "
            f"a new version (docs/PARALLEL.md)")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    if digest != expected["manifest_sha256"]:
        pytest.fail(_changed(name, f"MANIFEST sha256 {digest}, pinned "
                                   f"{expected['manifest_sha256']}"))
    try:
        copies = blast_radius.verify(dest)
    except ValueError as error:
        pytest.fail(_changed(name, str(error)))
    found: list[dict] = []
    for copy in copies:
        for log in sorted(copy.glob("*.log.jsonl")):
            for raw in log.read_text(encoding="utf-8", errors="replace").splitlines():
                if not raw.strip():
                    continue
                try:
                    found.append(json.loads(raw))
                except ValueError:
                    continue
    if len(found) != expected["records"]:
        pytest.fail(_changed(name, f"{len(found)} records, pinned {expected['records']}"))
    return found
