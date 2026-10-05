"""Fixtures built from the maintainers' own real sessions, which are NOT published.

Several tests check the engine against a redacted copy of real decision logs
(`logs/live-fixture`) and the standing replay baseline derived from them
(`runner/live_baseline.json`). Those files hold real commands from real work, so
the public repository does not carry them. A test that needs one SKIPS here,
naming what is missing, instead of failing or passing vacuously; with the files
in place the same test runs unchanged.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIVE_FIXTURE = ROOT / "logs" / "live-fixture"
LIVE_BASELINE = ROOT / "runner" / "live_baseline.json"
EXTENSION = ROOT / "extension"
DESIGN_DOCS = ROOT / "docs"

needs_live_fixture = pytest.mark.skipif(
    not LIVE_FIXTURE.is_dir(),
    reason="needs logs/live-fixture: real decision logs, not published")
needs_live_baseline = pytest.mark.skipif(
    not LIVE_BASELINE.is_file(),
    reason="needs runner/live_baseline.json: derived from real decision logs, not published")
needs_extension = pytest.mark.skipif(
    not EXTENSION.is_dir(),
    reason="needs extension/: the VS Code viewer is not part of this repository")


def needs_design_doc(name: str):
    return pytest.mark.skipif(
        not (DESIGN_DOCS / name).is_file(),
        reason=f"needs docs/{name}: an internal design record, not published")
