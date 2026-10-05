"""Identity must not reach a tracked artifact, in ANY spelling.

Two artifacts in this repo are built from real sessions on the developer's
machine: `logs/live-fixture/` and `runner/live_baseline.json`. Both are tracked.
Everything else is source.

⚠ WHY THIS FILE EXISTS. Both artifacts leaked, and they leaked the same way — a
pattern written for ONE spelling of an identifier while the identifier appeared
in another:

    fixture   115 occurrences of the username across 15 of 141 files, all of
              them the DASH-FLATTENED form `-Users-<name>-src-my-project`
              that Claude Code builds its per-project directories from. Both the
              substitution and the check were anchored on `/Users/`, so both
              were looking for a shape that was no longer present while the
              username sat in plain text beside it.

    baseline  32 of 43 entries, never redacted at all — the file is written
              straight from the real logs by `--update-baseline`, and the
              redaction its neighbour gets was simply never applied to it.

The email above them in `SUBSTITUTIONS` had already taught the lesson once: it
appears JSON-escaped inside commands that contain regexes, and a pattern written
for a literal dot missed every one. The fix there was to substitute the bare
TOKEN. It was applied to the email and not to the username.

So the property pinned here is not "these two strings are gone". It is that the
substitution and the check are both TOKEN-shaped rather than CONTEXT-shaped, and
that the two shipping artifacts are clean when scanned as bytes — which is the
only form of the question that does not depend on guessing the spelling.
"""
import json
import re
from pathlib import Path

import pytest

from tools.redact_logs import (leak_patterns, leaks_in, redact,      # noqa: F401
                                substitutions)
from private_fixtures import needs_live_baseline, needs_live_fixture  # noqa: E402

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "logs" / "live-fixture"
BASELINE = ROOT / "runner" / "live_baseline.json"


def a_derived_identifier() -> str:
    """One identifier THIS machine derives, whichever machine that is.

    ⚠ THIS USED TO BE A LITERAL ACCOUNT NAME, AND THAT IS THE SAME DEFECT AS A
    TOOL THAT HARDCODES ONE — it passed on one laptop for a reason unrelated to
    what it tests, and failed on every runner. The property under test was never
    "this name is handled"; it is "EVERY SPELLING of whatever identifier this
    machine has is handled", and the identifier is an INPUT to that property,
    not part of it. Third time this shape has appeared here.

    ⚠ AND IT IS THE RUNNING USER'S, DELIBERATELY. `redact()` and `leaks_in()`
    are the LIVE-LOG half — see `tools/redact_logs._derived_identities`. The
    archive half has its own census and its own file.
    """
    from tools.redact_logs import _derived_identities

    derived = [v for v in _derived_identities() if "@" not in v]
    if not derived:
        pytest.skip("no identifier could be derived on this machine, so the "
                     "substituter and the checker have no input — that is a "
                     "REFUSAL to redact, not a clean result, and "
                     "test_every_derived_identifier_is_present_and_fires "
                     "is where it is asserted")
    return derived[0]      # longest first


# ---------------------------------------------------------------- substitution

# ⚠ TEMPLATES, NOT STRINGS. The SPELLING is the thing under test — each of these
# is a real shape an identifier appeared in — and the identifier itself is
# supplied by the machine running the test.
SPELLINGS = [
    ("/Users/{id}/sting/sting-engine", "the slash form"),
    ("-Users-{id}-src-my-project", "THE 115-TIME MISS"),
    ("/private/tmp/claude-501/-Users-{id}-sting-x/scratch", "as it really appears"),
    ("~/.claude/projects/-Users-{id}-src-my-project", "and here"),
    ("cwd={id}", "no path at all"),
]


@pytest.mark.parametrize("template, why", SPELLINGS,
                          ids=[why for _, why in SPELLINGS])
def test_every_spelling_of_an_identifier_is_substituted(template, why):
    """Anchoring on `/Users/` is what let the flattened form through 115 times."""
    identifier = a_derived_identifier()
    assert identifier not in redact(template.format(id=identifier)), why


def test_the_identity_rule_is_a_bare_token_not_a_path():
    """The shape of the rule IS the fix, so the shape is what gets pinned.

    A future edit that re-anchors this on a separator would restore the exact
    bug, and would still pass every "is the fixture clean" test on the day it
    landed — because the fixture is only rebuilt occasionally. Pin the rule.
    """
    import re as _re
    from tools.redact_logs import _derived_identities

    patterns = [_re.sub(r"\\(.)", r"\1", p) for p, _ in substitutions()]
    derived = _derived_identities()
    assert derived, "nothing derived — see the skip message above"

    for value in derived:
        assert value in patterns, (
            "the substitution for this identifier must be the BARE TOKEN; it "
            f"is not among the {len(patterns)} pattern(s) the tool holds")
        assert f"/Users/{value}" not in patterns, (
            "a path-anchored entry is subsumed by the bare token and must not "
            "come back — keeping both invites re-anchoring the wrong one")


# ---------------------------------------------------------------------- checker

PLANTINGS = [
    ("-Users-{id}-sting", "flattened home dir — the form that leaked"),
    ("cd /Users/{id}/x", "slash home dir"),
    ("user is {id}", "bare username, no path context at all"),
]


@pytest.mark.parametrize("template, why", PLANTINGS,
                          ids=[why for _, why in PLANTINGS])
def test_the_leak_check_catches_every_identity_shape(template, why):
    planted = template.format(id=a_derived_identifier())
    assert leaks_in(planted), f"LEAK_PATTERNS must catch: {why}"


# The identity patterns are LITERALS, so each pattern is its own matching sample.
# Deriving the cases from the list rather than restating them keeps the machine
# name and the developer's legal name in exactly ONE tracked file — the detector
# that cannot work without them — instead of copying them into a second. It also
# means a pattern added tomorrow is exercised today, with no test to remember.
# ⚠ THE NAMES BECAME `derived identity N`, BECAUSE THE ENTRIES ARE NO LONGER
# TYPED. What is pinned is what always mattered: every identifier this machine
# HAS is both substituted and detected. Naming them individually pinned the
# hardcoding, which was the defect.
def test_every_derived_identifier_is_present_and_fires():
    from tools.redact_logs import _derived_identities

    derived = _derived_identities()
    assert derived, (
        "nothing was derived on this machine, so neither the substituter nor "
        "the checker has any input — that is a REFUSAL to redact, not a clean "
        "result")
    for value in derived:
        assert leaks_in(value), (
            f"{value!r} is an identifier of this machine and the leak check "
            f"does not match it — the detector and the substituter have drifted")
        assert value not in redact(value), (
            f"{value!r} is detected but not substituted")


def test_the_leak_check_is_not_anchored_on_a_separator():
    """The detector half of the same mistake.

    `--check` passed on a fixture containing the username 115 times because it
    searched for `/Users/<name>` and every surviving occurrence was
    `-Users-<name>-`. A checker that can only see one spelling reports on the
    wrong thing.
    """
    anchored = [p for _, p in leak_patterns()
                if p.startswith("/Users/") or p.startswith(re.escape("/Users/"))]
    assert not anchored, ("the identity check must not be path-anchored; "
                          "that is what produced a passing check over a "
                          "leaking fixture")


# --------------------------------------------------------- the shipping bytes

def _all_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


@needs_live_fixture
def test_the_vendored_fixture_carries_no_identity():
    """Scanned as BYTES, over every file — not just the ones the tool targets.

    141 files, 13 of the 15 that leaked were sidecars. Globbing `*.jsonl` here
    would reproduce the blind spot rather than test for it.
    """
    files = _all_files(FIXTURE)
    assert len(files) > 100, "fixture missing — this test would pass vacuously"
    dirty = {str(p.relative_to(ROOT)): leaks_in(p.read_text(errors="replace"))
             for p in files}
    dirty = {k: v for k, v in dirty.items() if v}
    assert not dirty, f"identity in the vendored fixture: {dirty}"


@needs_live_baseline
def test_the_tracked_baseline_carries_no_identity():
    """This is the test that would have caught the second leak.

    `runner/live_baseline.json` is written from the same real logs as the
    fixture and was never redacted — 36 KB tracked, holding the home directory,
    the author name and the git email in 32 of its 43 entries.
    """
    assert BASELINE.is_file(), "baseline missing — test would pass vacuously"
    survived = leaks_in(BASELINE.read_text(errors="replace"))
    assert not survived, f"identity in {BASELINE.name}: {survived}"


@needs_live_baseline
def test_the_baseline_still_explains_itself():
    """Redaction must not have cost the reasons.

    The obvious way to clean this file is `--update-baseline`, which rewrites
    every reason to "TODO: explain" — trading a privacy leak for 43 unexplained
    accepted differences, which the runner itself calls "a regression nobody
    looked at". The in-place redaction exists precisely to avoid that trade.
    """
    accepted = json.loads(BASELINE.read_text())["accepted"]
    todo = [k for k, v in accepted.items()
            if not v.get("reason") or v["reason"].startswith("TODO")]
    assert not todo, f"{len(todo)} baseline entries lost their reason: {todo[:5]}"


def test_redaction_happens_before_truncation():
    """ORDER, not presence — and the excerpt is truncated to 160 chars.

    Truncating first can cut the token in half at the boundary, and half a token
    matches no pattern while still naming the person. This asserts the unsafe
    ordering really is unsafe, so the safe one is not cargo cult.
    """
    identifier = a_derived_identifier()
    if len(identifier) < 4:
        pytest.skip("the derived identifier is too short to be cut in half")

    # ⚠ SIZED FROM THE IDENTIFIER, NOT FROM ONE MACHINE'S USERNAME. The cut must
    # land INSIDE the token, leaving all but its last two characters — enough to
    # name the person, and one character short of anything the substitution can
    # match. The old `147` computed that offset for a seven-character name and
    # for nobody else's.
    keep = len(identifier) - 2
    prefix = "x" * (160 - len("/Users/") - keep)
    command = f"{prefix}/Users/{identifier}/sting/engine && git status"
    fragment = re.escape(identifier[:keep])

    truncate_then_redact = redact(command[:160])
    redact_then_truncate = redact(command)[:160]

    assert re.search(fragment, truncate_then_redact), (
        "the unsafe ordering is supposed to leave a fragment; if it no longer "
        "does, this test has stopped testing anything")
    assert not re.search(fragment, redact_then_truncate)
