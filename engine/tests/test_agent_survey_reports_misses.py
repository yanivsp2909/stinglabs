"""Agent detection reports what it did NOT find, not only what it did.

⚠ THIS COST AN EVENING, ONCE, AND IT IS THE REASON THE TEST EXISTS. A second
developer had Cursor installed. This installer did not list it — detection is a
marker DIRECTORY and his was not where `AGENT_MARKERS` says — and the run looked
SUCCESSFUL, because two other agents were found. The only clue that
`--agent cursor` was needed was knowing the tool well enough to guess.

Misses were printed only when the count reached ZERO, which is the one case that
is already obvious. The confusing case is finding SOME.

Same shape as working rule 13: "I found nothing to check" is not "there is
nothing to find", and a report carrying only hits cannot tell them apart.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from installer import detect                                     # noqa: E402


def test_the_survey_covers_every_supported_agent_found_or_not():
    survey = detect.agent_survey()
    assert {row["agent"] for row in survey} == set(detect.AGENT_MARKERS), (
        "an agent that is not surveyed is one a report cannot mention")


def test_a_miss_names_the_paths_that_decided_it(tmp_path, monkeypatch):
    """⚠ "not found" ON ITS OWN SENDS SOMEBODY LOOKING IN THE WRONG PLACE. The
    path is what turns it into an actionable line: a developer who sees the
    directory this looked for can tell in one glance whether theirs is
    elsewhere."""
    monkeypatch.setattr(detect, "AGENT_MARKERS",
                        {"cursor": [tmp_path / "nowhere" / ".cursor"]})
    row = detect.agent_survey()[0]
    assert row["present"] is False
    assert row["evidence"] is None
    assert row["looked_in"] == [str(tmp_path / "nowhere" / ".cursor")]


def test_a_hit_still_names_what_proved_it(tmp_path, monkeypatch):
    marker = tmp_path / ".cursor"
    marker.mkdir()
    monkeypatch.setattr(detect, "AGENT_MARKERS", {"cursor": [marker]})
    row = detect.agent_survey()[0]
    assert row["present"] is True and row["evidence"] == str(marker)


def test_agents_present_still_returns_only_hits(tmp_path, monkeypatch):
    """The found-only view is kept, so callers that INSTALL do not have to
    filter. It is `agent_survey` that reports."""
    hit = tmp_path / ".claude"
    hit.mkdir()
    monkeypatch.setattr(detect, "AGENT_MARKERS",
                        {"claude-code": [hit], "codex": [tmp_path / "absent"]})
    present = detect.agents_present()
    assert [a["agent"] for a in present] == ["claude-code"]
    assert "present" not in present[0] and "looked_in" not in present[0]


def test_the_installer_prints_misses_beside_hits_and_says_they_may_be_wrong():
    """Asserted on the source: the branch that prints a miss, and the sentence
    that tells a developer detection can be wrong and how to override it. A
    report that lists a miss without saying `--agent` exists has named a problem
    and withheld the fix."""
    source = (Path(__file__).parent.parent / "install.py").read_text(
        encoding="utf-8")
    assert "detect.agent_survey()" in source
    assert "not found  looked in" in source
    assert "may still be installed" in source
    assert "install.py --agent <name>" in source
