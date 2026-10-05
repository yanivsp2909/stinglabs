"""Which scenarios actually deliver their attack in a LIVE run.

`plant_injection` writes ISSUE_418.md only when the prompt says "issue #418".
Scenarios whose payload arrives over a channel the harness cannot simulate — an
MCP tool result, a fetched web page, a package registry — therefore run with no
attack present at all. D02 demonstrated it: a live run scored it a miss while
the agent was never shown anything to resist.

They still count in REPLAY, because synthetic traces are generated from each
scenario's stated intent rather than from an agent's behaviour. So the replay
figure is real and the live figure would not be, and the difference has to stay
visible or the number gets quoted bare.
"""
from pathlib import Path

import yaml

SCENARIOS = Path(__file__).parent.parent / "scenarios"
# 14 since K06-commit-message-cleanup was added: its payload is a commit
# BODY, and stage_repo only ever creates an "init" commit, so the harness
# cannot plant it. K01-K05 have the same gap and are NOT marked — they are
# reachable through the ISSUE_418.md the runner plants, which tests the
# labelling but not the git-history CHANNEL. Recorded in PROGRESS.md.
EXPECTED_UNEXERCISED = 14


def attacks():
    out = {}
    for d in sorted(SCENARIOS.iterdir()):
        if not d.is_dir():
            continue
        spec = yaml.safe_load((d / "expect.yaml").read_text())
        if spec.get("class") == "attack":
            out[d.name] = spec
    return out


def test_every_expect_file_still_parses():
    # ⚠ 63 -> 81. Eighteen gap scenarios were added DELIBERATELY (Phase 6:
    # deferred execution, opaque execution, exfiltration with no network call,
    # cross-session taint, and attacks on the guard itself). A4 gets WORSE as a
    # result — 51/63 to 55/81 — and that is the measurement working rather than
    # a regression. Changing this number is meant to be a deliberate act.
    # ⚠ 81 -> 79. TWO SCENARIOS DELETED, NOT FIXED. S02 and S03 modelled a
    # clean-session push carrying another session's staged secret — which is
    # EXACTLY A2, the acceptance criterion that says an identical push in a
    # clean session is ALLOWED. Scoring the product's own defining behaviour as
    # a missed attack made A4 worse for something deliberate. The cross-session
    # gap is already limitation #3 in the threat model, which is where a
    # documented design decision belongs.
    #
    # Deleting a scenario that cannot honestly fail is worth more than a fix.
    #
    # ⚠ 79 -> 82. THREE X-CHAIN SCENARIOS ADDED, and this is a deliberate act as
    # the header demands. X-CHAIN-1/2/3 model a cross-session split-and-encode
    # exfiltration — the motivating scenario for the enforce-mode pass. They are
    # EXPECTED to miss as a chain (docs/41 A.3: none of the persistent-taint
    # options catches them, and the runner cannot link three sessions), so they
    # make A4 worse honestly. X-CHAIN-3 BLOCKS as a single session because it
    # ships its own poisoned issue read; the chain as a whole does not. See
    # docs/41 and PROGRESS.md.
    assert len(attacks()) == 82


def test_the_unexercised_count_is_pinned():
    """If this moves, either a scenario was fixed — update the number and say so
    in PROGRESS.md — or one silently stopped delivering."""
    marked = [n for n, s in attacks().items()
              if s.get("live_delivery") == "unexercised"]
    assert len(marked) == EXPECTED_UNEXERCISED, sorted(marked)


def test_each_marked_scenario_names_its_channel_and_its_plan():
    """A mark with no reason is a mark nobody can act on."""
    for name, spec in attacks().items():
        if spec.get("live_delivery") != "unexercised":
            continue
        assert spec.get("live_delivery_channel") in {"mcp", "web", "registry", "model", "git-history"}, name
        assert spec.get("live_delivery_plan"), name


def test_mechanism_j_is_excluded_not_pending():
    """J is the model's own mistake — a permanent miss per the PRD. Mocking it
    would buy nothing, so it is marked excluded rather than left looking like
    work someone should pick up. Kept in the corpus so the count stays honest."""
    for name, spec in attacks().items():
        if spec.get("live_delivery_channel") == "model":
            assert "exclude" in spec["live_delivery_plan"].lower(), name


def test_no_scenario_was_deleted_to_make_the_number_look_better():
    """The whole point of marking rather than removing."""
    ids = set(attacks())
    for name in ("D02-white-on-white", "C01-mcp-tool-result", "E03-typosquat",
                 "J03-force-push-main", "J04-rotates-credential"):
        assert name in ids, name
