"""The standing replay is a GATE, so it has to be able to fail.

⚠ IT COULD NOT. `replay_live.py` defaulted to `~/.sting/dogfood`, that directory
emptied when the logs moved to `~/.sting/sessions`, and it went on printing
"No unexplained differences" over ZERO records. Every checkpoint since has
pinned "standing replay green" as evidence — working rule 13 aimed at the
checkpoint itself.

Two properties, both of which were absent:

    1 · an empty population FAILS rather than passing
    2 · a LOOSENING can never be baselined away
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "runner"))

import replay_live                                               # noqa: E402
from private_fixtures import needs_live_baseline  # noqa: E402


def test_an_empty_log_root_fails_instead_of_reporting_green(tmp_path, capsys):
    """⚠ THE EXACT SHAPE THAT WENT UNNOTICED: a directory that exists, is
    readable, and contains nothing."""
    empty = tmp_path / "sessions"
    empty.mkdir()
    assert replay_live.main(["--root", str(empty), "--quiet"]) == 2
    assert "REFUSING TO REPORT" in capsys.readouterr().err


def test_a_root_of_unreplayable_logs_also_fails(tmp_path, capsys):
    """⚠ THE SAME VACUUM WEARING A BETTER DISGUISE. A root full of records none
    of which can be replayed is not a population either — which is why the
    check counts COMPARISONS and not files."""
    root = tmp_path / "sessions"
    root.mkdir()
    (root / "s.log.jsonl").write_text(
        json.dumps({"event": "session_start", "seq": None}) + "\n",
        encoding="utf-8")
    assert replay_live.main(["--root", str(root), "--quiet"]) == 2
    assert "REFUSING TO REPORT" in capsys.readouterr().err


def test_a_missing_root_still_fails(tmp_path, capsys):
    assert replay_live.main(["--root", str(tmp_path / "nope"), "--quiet"]) == 2


@pytest.mark.parametrize("was,now,expected", [
    ("DENY", "ALLOW", True),
    ("ASK", "ALLOW", True),
    ("ALLOW", "DENY", False),
    ("ALLOW", "ASK", False),
    ("DENY", "ASK", False),
])
def test_only_a_move_toward_ALLOW_counts_as_a_loosening(was, now, expected):
    """⚠ STRICTER DRIFT IS A JUDGEMENT CALL; LOOSER DRIFT IS A BUG, ALWAYS. An
    engine that used to catch something and now does not is a regression, and
    baselining one would convert it into a documented feature."""
    assert replay_live._is_loosening(
        {"recorded": {"decision": was}, "current": {"decision": now}}) is expected


def test_the_default_root_follows_the_logs():
    """It used to be a hardcoded path that was true once. STING_SESSION_ROOT is
    what the hook actually writes to."""
    assert "dogfood" not in str(replay_live.DEFAULT_LOG_ROOT)


@needs_live_baseline
def test_every_baseline_entry_carries_a_real_reason():
    """⚠ AN UNEXPLAINED BASELINE ENTRY IS A REGRESSION NOBODY LOOKED AT.
    `--update-baseline` writes `TODO: explain` on purpose so that shipping one
    is a visible act rather than an oversight."""
    baseline = json.loads(replay_live.BASELINE.read_text())
    accepted = baseline.get("accepted", {})
    # ⚠ ARMED. Caught by this repo's own rule-13 scanner while being written:
    # a `for … assert` over a file-derived collection passes for free when the
    # file is empty, which is the exact defect the rest of this file exists to
    # fix, one level up.
    assert accepted, "the baseline is empty — this test would prove nothing"
    for key, entry in accepted.items():
        reason = entry.get("reason", "")
        assert reason and "TODO" not in reason, f"{key}: {reason!r}"
        assert len(reason) > 40, f"{key}: reason is too short to be one"


# ⚠ MEASURED, NOT ASSUMED — AND IT CORRECTED THE RULE. The first version of
# this file asserted that NO baseline entry may be a loosening. Against the
# committed baseline that is false 42 times, and every one of the 42 is a
# deliberate false-positive fix citing the commit that made it: `fb071e3`
# narrowed _GUARD_SELFMOD from a bare `sting` substring that matched 188 of 190
# real paths. Forbidding loosenings would have pinned the engine to that bug.
#
# So the claim is the weaker, true one: a loosening is where a regression hides,
# so the COUNT is pinned and may not grow without somebody looking.
#
# ⚠ 51 -> 54 (fix/false-positives, docs/112 item C), REAL ENGINE MOVES, AND
# DELIBERATE: a delete no longer asks for what the session itself created,
# whatever the session read (maintainer, 30 Sep). Three records delete only files
# their session wrote earlier: ASK irreversible_action -> ALLOW. Their reason
# is in the baseline entries.
#
# ⚠ 50 -> 51 (fix/false-positives, docs/112 item A), A REAL ENGINE MOVE, AND A
# DELIBERATE ONE: piping the session's own work into a shell is no longer gated
# by the outside content it read (maintainer, 30 Sep). One record's pipe feeds only
# that: DENY untrusted_unexpected:pipe_to_shell -> ALLOW. Its reason is in the
# baseline entry.
#
# ⚠ 42 -> 50 (fix/agents-block-and-env-reads, docs/110 §B), AND NOT ONE IS AN
# ENGINE MOVE. Its environment reads mark sessions as holding a secret, which
# satisfies eight records' state witness (`state_implied_by`) for the first
# time, so the replay COMPARES them now. Main's engine answers each the same
# with the read switched off (replayed both ways, record by record); they
# differ from the RECORDED verdict because the replay has no file contents,
# so the live session's own secret read cannot fire here.
KNOWN_LOOSENINGS = 54


@needs_live_baseline
def test_the_number_of_accepted_loosenings_has_not_grown():
    """A new DENY/ASK -> ALLOW appearing in the baseline is either a deliberate
    false-positive fix — in which case update this number and cite the commit —
    or an engine that quietly stopped catching something."""
    baseline = json.loads(replay_live.BASELINE.read_text())
    accepted = baseline.get("accepted", {})
    assert accepted, "the baseline is empty — this test would prove nothing"
    loosenings = [k for k, v in accepted.items() if replay_live._is_loosening(v)]
    assert len(loosenings) <= KNOWN_LOOSENINGS, (
        f"{len(loosenings)} loosenings, was {KNOWN_LOOSENINGS}: "
        f"{sorted(set(loosenings))[:5]}")


@needs_live_baseline
def test_every_loosening_cites_the_change_that_caused_it():
    """⚠ A LOOSENING'S REASON MUST NAME SOMETHING CHECKABLE. "the engine
    changed" is not a reason.

    ⚠ AND "CHECKABLE" IS NOT "A COMMIT HASH" — the first version of this test
    demanded a hash and failed 6 entries whose reason is
    `loopback is not egress — the fix in check_sinks`. That names the code site,
    which is traceable. A reader can go and look at either; that is the property
    worth asserting, and the narrower one would have deleted good reasons to
    satisfy a regex.
    """
    import re
    baseline = json.loads(replay_live.BASELINE.read_text())
    accepted = baseline.get("accepted", {})
    assert accepted, "the baseline is empty — this test would prove nothing"
    commit = re.compile(r"\b[0-9a-f]{7,40}\b")
    code_site = re.compile(r"\b_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b|\b_[A-Z][A-Z0-9_]{4,}\b")
    for key, entry in accepted.items():
        if not replay_live._is_loosening(entry):
            continue
        reason = entry.get("reason", "")
        assert commit.search(reason) or code_site.search(reason), (
            f"{key}: a loosening citing neither a commit nor a code site: "
            f"{reason[:90]!r}")


@needs_live_baseline
def test_entries_whose_direction_is_unknowable_are_counted_not_assumed_safe():
    """⚠ 15 COMMITTED ENTRIES HAVE NO `recorded` VERDICT — an older baseline
    format. Nothing can be said about their direction, and unknowable is not
    the same as safe, so they are counted rather than quietly passed."""
    baseline = json.loads(replay_live.BASELINE.read_text())
    accepted = baseline.get("accepted", {})
    assert accepted, "the baseline is empty — this test would prove nothing"
    blind = [k for k, v in accepted.items() if replay_live.undirected(v)]
    assert len(blind) <= 15, f"{len(blind)} undirected entries: {sorted(blind)[:5]}"
