"""The named, cited real-incident replay suite, pinned.

Each incident in runner/incidents.py is a real public attack SHAPE replayed
through the REAL engine. These tests pin the HONEST snapshot — the blocked/asked/
passed split and the exact set of coverage GAPS — so a regression (a stopped
attack starts passing, or a NEW gap appears) fails here, and an improvement (a gap
closes) also fails, prompting a snapshot update rather than a silent drift. The
citations themselves cannot be machine-checked; that is the human step this suite
hands to the maintainer (see the UNVERIFIED rows).
"""
from __future__ import annotations

from core.types import Decision
from runner import incidents


def test_more_than_twelve_incidents():
    """Beats Stroq's 12 — verified plus clearly-marked unverified."""
    assert len(incidents.INCIDENTS) > 12


def test_every_incident_replays_to_a_real_verdict_without_crashing():
    """The suite reuses the real engine; every incident must produce an actual
    DENY/ASK/ALLOW, never an error."""
    for inc in incidents.INCIDENTS:
        v = incidents.replay(inc)
        assert v.decision in (Decision.DENY, Decision.ASK, Decision.ALLOW), inc.name


def test_the_blocked_asked_passed_split_is_the_recorded_snapshot():
    """⚠ THE HONEST NUMBER, pinned. Not cherry-picked: PASSED rows are real gaps,
    counted. A change here is a signal to review and update PROGRESS, in either
    direction.

    ⚠ ASKED dropped 2 -> 1 when npm colors/faker was REMOVED: it is real but is
    sabotage/DoS (an infinite loop, no read, no exfil) with nothing in the shape
    for a data-exfil guard to catch, so it is not modelled here. The split counts
    all 16 entries (14 real incidents + 2 illustrative shapes)."""
    assert incidents.split() == {"BLOCKED": 11, "ASKED": 1, "PASSED": 4}


def test_the_coverage_gaps_are_exactly_the_known_ones():
    """⚠ HONESTY GATE. The gaps are named, not hidden. A NEW attack shape passing
    (a regression) or a listed gap closing (an improvement worth recording) both
    fail here — the suite may not silently drift. Two root causes underlie today's
    gaps: pipe-to-shell RCE (`curl | bash`) in a clean session, and interpreter-
    based env-var exfil (`python -c os.environ…`). Neither is fixed here — that is a
    separate engine change, reported, not bundled."""
    known = {
        "ua-parser-js-hijack-2021",       # curl | bash RCE
        "log4shell-2021",                 # fetch-to-execute RCE
        "claude-code-unsafe-exec",        # curl | sh RCE
        "pypi-ctx-aws-exfil-2022",        # python -c os.environ exfil
    }
    assert {inc.name for inc, _got in incidents.gaps()} == known


def test_a_secret_exfil_shape_is_actually_blocked():
    """A load-bearing WIN, checked directly: the canonical read-.env-then-exfil
    shape denies (so the suite's BLOCKED count is real, not a mislabel)."""
    inc = next(i for i in incidents.INCIDENTS if i.name == "event-stream-flatmap-2018")
    assert incidents.replay(inc).decision is Decision.DENY


def test_unverified_rows_carry_the_marker():
    """Every row without a web-verified source says so in its source string, so
    the artifact never presents an unconfirmed link as fact. Two kinds carry no
    verified source and each is marked distinctly: an UNVERIFIED real incident,
    and an ILLUSTRATIVE shape that is not a public event at all."""
    for inc in incidents.INCIDENTS:
        if inc.illustrative:
            assert "illustrative" in inc.source.lower(), inc.name
            assert "http" not in inc.source, f"{inc.name} carries a URL as a shape"
        elif not inc.verified:
            assert "UNVERIFIED" in inc.source, inc.name


def test_illustrative_shapes_are_marked_not_counted_and_never_a_gap():
    """⚠ FIX 2, PINNED. The invented attack SHAPES are kept as scenarios but must
    never be presented as named incidents: they carry `illustrative=True`, no
    source URL, and are excluded from the coverage-gap findings."""
    shapes = [i for i in incidents.INCIDENTS if i.illustrative]
    assert {i.name for i in shapes} == {"env-file-to-webhook-shape",
                                        "prompt-injection-git-push-shape"}
    gap_names = {inc.name for inc, _ in incidents.gaps()}
    assert not (gap_names & {i.name for i in shapes})


def test_the_two_known_gap_incidents_are_gaps_not_wins():
    """⚠ FIX 3, PINNED. ua-parser-js (pipe-to-shell RCE) and ctx (interpreter
    env-var exfil) are REAL, and the engine currently PASSES both — they are
    coverage GAPS, never counted or labelled as stopped."""
    gap = {inc.name: got for inc, got in incidents.gaps()}
    assert gap.get("ua-parser-js-hijack-2021") == "PASSED"
    assert gap.get("pypi-ctx-aws-exfil-2022") == "PASSED"


def test_the_sabotage_only_incident_was_removed():
    """⚠ FIX 1, PINNED. npm colors/faker is sabotage/DoS with no data exfil —
    nothing for this guard to catch — so it is not in the suite (and is not
    dressed up as a destructive delete it never ran)."""
    names = {i.name for i in incidents.INCIDENTS}
    assert not any("colors" in n or "faker" in n for n in names)


def test_the_report_renders_and_names_the_split_and_gaps():
    text = incidents.format_report()
    assert "BLOCKED 11" in text and "PASSED 4" in text
    assert "COVERAGE GAPS" in text
    assert "browser-verified" in text          # the citation disclaimer is present
