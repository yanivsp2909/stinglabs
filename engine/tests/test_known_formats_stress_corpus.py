"""The stress corpus, asserted by name: every shipped format's real-shaped key
is caught on every inspected surface, and every look-alike class is held.

`pytest -v tests/test_known_formats_stress_corpus.py` prints one line per
(format, surface) and per negative class — that listing IS the proof, and
runner/stress_known_formats.py prints the same table for a report.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))

from core.known_formats import FORMATS, find_known_secret        # noqa: E402
from known_formats_corpus import (EVASIONS, FORMAT_IDS, NEGATIVES,  # noqa: E402
                                  SURFACES, embed, make_key)


def test_the_corpus_covers_every_shipped_format_and_only_shipped_formats():
    """ARM: a format row without a corpus key, or a corpus key for a row that
    no longer exists, fails here before the parametrised proof runs."""
    shipped = {f.id for f in FORMATS}
    assert set(FORMAT_IDS) == shipped, set(FORMAT_IDS) ^ shipped
    assert len(NEGATIVES) >= 30, f"only {len(NEGATIVES)} negative classes"
    assert len(set(name for name, _ in NEGATIVES)) == len(NEGATIVES), "duplicate negative name"


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("format_id", FORMAT_IDS)
def test_positive_is_caught(format_id, surface):
    key = make_key(format_id)
    text = embed(surface, key)
    hit = find_known_secret(text)
    assert hit is not None, f"{format_id} on {surface}: missed"
    assert hit.format_id == format_id, f"{format_id} on {surface}: caught as {hit.format_id}"
    assert text[hit.start:hit.end] == key, "the span is not the key"


@pytest.mark.parametrize("name,text", NEGATIVES, ids=[n for n, _ in NEGATIVES])
def test_negative_is_held(name, text):
    hit = find_known_secret(text)
    assert hit is None, f"{name}: flagged as {hit and hit.format_id}"


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("name,text", NEGATIVES, ids=[n for n, _ in NEGATIVES])
def test_negative_is_held_on_every_surface(name, text, surface):
    """A negative embedded the way a positive is — quoting, JSON, a diff —
    must stay a negative; the surrounding syntax must not create a hit."""
    assert find_known_secret(embed(surface, text)) is None, (name, surface)


@pytest.mark.parametrize("name,text", EVASIONS, ids=[n for n, _ in EVASIONS])
def test_an_evasion_the_review_found_is_caught(name, text):
    """⚠ FOUND BY THE SECURITY REVIEW OF THE FIRST DRAFT, which matched a
    prefix only at the start of a token and read the raw text only: adjacent
    quotes, a mid-key backslash and leading glue all walked a real-shaped key
    past it. Each is one shell argument to the receiver."""
    hit = find_known_secret(text)
    assert hit is not None, f"{name}: evaded"
    assert 0 <= hit.start < hit.end <= len(text), "offsets are not into the raw text"
