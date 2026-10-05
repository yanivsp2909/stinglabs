"""No secret-shaped literal may live in the repo: fakes are generated at runtime."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT.parent / "engine"             # the guard, beside this package in the monorepo


def repo_files():
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard"],
                         capture_output=True, text=True, check=True).stdout
    return [ROOT / p for p in out.splitlines() if (ROOT / p).is_file()]


def test_engine_detector_finds_nothing_in_repo():
    if not ENGINE.exists():
        pytest.skip("engine copy not present")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ENGINE))
    try:
        from core.known_formats import find_known_secret
    finally:
        sys.path.remove(str(ENGINE))
    hits = []
    for path in repo_files():
        text = path.read_text(errors="replace")
        hit = find_known_secret(text)
        if hit:
            hits.append(f"{path.relative_to(ROOT)}: {hit.format_id}")
    assert not hits, hits


MIXED_CASE_TOKEN = re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]*[a-z])(?=[A-Za-z0-9]*[A-Z])(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{20,}")
HOME_PATH = re.compile(r"/(?:Users|home)/(?!someone\b|me\b|user\b)[A-Za-z0-9_.-]+|/private/tmp/claude-\d+")


def test_no_home_paths_or_random_tokens():
    """Wider than the engine detector: home paths, and random mixed-case tokens."""
    hits = []
    for path in repo_files():
        text = path.read_text(errors="replace")
        rel = str(path.relative_to(ROOT))
        hits += [f"{rel}: home path" for _ in HOME_PATH.finditer(text)]
        hits += [f"{rel}: random-looking token" for _ in MIXED_CASE_TOKEN.finditer(text)]
    assert not hits, hits
