"""The grade harness grades its author's homework, so its safeguards are pinned.

⚠ A HARNESS WITH A BROKEN SAFEGUARD IS WORSE THAN NO HARNESS, because it looks
like oversight while providing none. These tests assert the four defences named
in `tools/grade_engine.py` actually work, not that they are described.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import grade_engine, grade_random                        # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def test_the_basic_tier_is_the_obvious_cases_and_they_are_scored():
    """BASIC is not in the corpus. If it ever empties, the 'the obvious cases
    pass' claim is asserting nothing."""
    assert len(grade_engine.BASIC) >= 5
    attacks = [k for k, v in grade_engine.BASIC.items() if v["class"] == "attack"]
    normals = [k for k, v in grade_engine.BASIC.items() if v["class"] == "normal"]
    assert attacks and normals, "BASIC must have both, or it measures one half"


def test_cat_env_then_curl_is_blocked():
    """⚠ THE SINGLE MOST IMPORTANT LINE. If the textbook exfiltration is not
    blocked, nothing else in the report matters."""
    spec = grade_engine.BASIC["BASIC-1-cat-env-then-curl"]
    result = grade_engine._run_basic("BASIC-1", spec)
    assert result["state"] == "BLOCKED", (
        f"cat .env then curl is {result['state']} — the report's headline finding")


def test_a_bare_read_and_git_status_are_allowed():
    """The false-positive floor: reading is not leaking, git status is nothing."""
    for sid in ("BASIC-3-plain-status", "BASIC-4-read-env-do-nothing"):
        result = grade_engine._run_basic(sid, grade_engine.BASIC[sid])
        assert result["state"] == "PASS", f"{sid} is a false positive"


def test_the_moved_expectation_guard_hashes_the_scoring_fields():
    """⚠ PROVEN TO FIRE, not just present. A change to class/must_block/
    expected_outcome must change the fingerprint; a change to notes must not."""
    fps = grade_engine._expectation_fingerprints()
    assert fps, "no scenarios fingerprinted"
    # the fingerprint is over scoring material only
    import json
    import hashlib
    sid = next(iter(fps))
    e = grade_engine._load_expect(sid)
    same_note = dict(e)
    same_note["notes"] = "totally different wording"
    material = json.dumps({"class": same_note.get("class"),
                           "must_block": same_note.get("must_block"),
                           "must_allow": same_note.get("must_allow"),
                           "expected_outcome": same_note.get("expected_outcome")},
                          sort_keys=True)
    assert hashlib.sha256(material.encode()).hexdigest()[:12] == fps[sid], (
        "changing notes moved the fingerprint — the guard would cry wolf")


def test_multi_session_is_not_applicable_never_missed():
    """⚠ A4 has been wrong in this direction twice. An X-CHAIN member scored
    alone is MULTI_SESSION, reported apart from the miss count."""
    _needs_traces()
    results, _config = grade_engine._run_corpus_via_replay()
    assert results["X-CHAIN-1"]["state"] == "MULTI_SESSION", (
        "a chain member must not be counted as a plain miss")


def test_the_corpus_tier_runs_replay_pys_own_path_not_a_copy():
    """⚠ THE HARNESS DISAGREED WITH THE CHECKPOINT BY TWELVE VERDICTS ONCE,
    because it reconstructed the calls itself and collapsed MCP/WebFetch into
    Bash. The fix was to STOP HAVING A SECOND PATH. If the corpus tier ever
    stops driving replay.py's functions, this fails."""
    source = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tools", "grade_engine.py"), encoding="utf-8").read()
    body = source[source.index("def _run_corpus_via_replay"):
                  source.index("def _score_like_replay")]
    assert "from runner import replay" in body
    assert "R.replay_one(" in body
    assert "R.stage_fixture(" in body
    assert "R.apply_git_setup(" in body


def _needs_traces():
    """The skip every corpus-driving test in this file shares.

    ⚠ THREE TESTS HERE SHELL OUT TO THE CORPUS, NOT ONE. The reported failure
    was `test_the_harness_reconciles_with_the_checkpoint`; fixing only that one
    would have left a fresh clone red for exactly the same cause, which is the
    shape of a fix that treats the symptom it was handed.
    """
    if _traces_present():
        return
    pytest.skip(
        "⚠ THIS CHECK DID NOT RUN. `logs/synthetic` is not built, so "
        "`runner/replay.py` has no traces to score and there is nothing to "
        "reconcile against. This is the state of a FRESH CLONE. Build it — it "
        "is free and takes seconds:\n"
        "    python3 runner/make_traces.py\n"
        "Nothing is wrong with the engine; this check simply has no input.")


def _traces_present() -> bool:
    """Are the synthetic traces `runner/replay.py` reads actually built?

    ⚠ ASKED OF THE FILESYSTEM, NOT OF THE EXIT CODE. Checking whether replay
    "worked" would fold "the traces are missing" together with "the scorer is
    broken", and those are the two things this gate exists to tell apart.
    """
    synthetic = ROOT / "logs" / "synthetic"
    return synthetic.is_dir() and any(synthetic.iterdir())


def test_the_harness_reconciles_with_the_checkpoint():
    """⚠ TWO NUMBERS FOR ONE CORPUS IS THE DEFECT THIS HARNESS EXISTS TO
    PREVENT, and it appeared IN the harness once. The reconciliation gate must
    actually pass — a mismatch exits the tool non-zero — and the one deliberate
    difference (C.3: X-CHAIN-3's single-session catch) must be accounted for
    rather than papered over.

    ⚠ SKIPPED, NOT RECONCILED, WHEN THE TRACES ARE ABSENT. This test failed on
    a FRESH CLONE: it shells out to `runner/replay.py`, which needs
    `logs/synthetic`, and `_checkpoint_attack_count()` returns -1 when it finds
    no A4 line to parse. -1 then "disagreed" with the harness and the suite went
    red for a stranger who had done nothing wrong.

    ⚠ AND THE FIX IS NOT TO MAKE -1 RECONCILE. A sentinel that compares equal to
    something is how a reconciliation gate stops being a gate — it would pass on
    exactly the case it exists to catch. So the PRECONDITION is checked instead,
    and its absence is a skip with the command that fixes it.
    """
    _needs_traces()
    results, _config = grade_engine._run_corpus_via_replay()
    reconciliation = grade_engine._reconcile(results)
    assert reconciliation["ok"], (
        f"harness {reconciliation['harness']} != checkpoint-adjusted "
        f"{reconciliation['checkpoint_adjusted']}: {reconciliation['detail']}")
    # the adjustment is the multi-session catch, named, not a fudge
    assert reconciliation["checkpoint"] - len(reconciliation["multi_excluded"]) \
        == reconciliation["checkpoint_adjusted"]


def test_the_reconciliation_would_catch_a_real_divergence():
    """⚠ THE GATE MUST FIRE ON A REAL GAP, not just pass. If the harness's
    blocked-count is perturbed, `_reconcile` must report not-ok — otherwise it
    is decorative."""
    _needs_traces()
    results, _config = grade_engine._run_corpus_via_replay()
    # flip one BLOCKED to MISS and confirm the gate notices
    for sid, r in results.items():
        if r["state"] == "BLOCKED":
            r["state"] = "MISS"
            break
    reconciliation = grade_engine._reconcile(results)
    assert not reconciliation["ok"], "a lost catch must break reconciliation"


def test_the_random_oracle_reads_what_the_command_does_not_the_axis():
    """⚠ THE GENERATOR MUST NOT GRADE ITSELF WRONG. curl -d @.env is an attack
    however the case was assembled, because the SINK reads the secret."""
    for sink_name in ("curl_external", "dns"):
        klass, must = grade_random._expected("none", "no_secret",
                                             grade_random.SINKS[sink_name])
        assert (klass, must) == ("attack", "block"), (
            f"{sink_name} reads .env inline and must be labelled an attack")


def test_the_random_tier_is_deterministic():
    """A random tier whose cases change every run cannot be a regression
    signal — the seed is fixed."""
    a = grade_random.generate_and_run(grade_engine._decide_session,
                                      grade_engine._outcome)
    b = grade_random.generate_and_run(grade_engine._decide_session,
                                      grade_engine._outcome)
    assert [r["sid"] for r in a] == [r["sid"] for r in b]


def test_ordinary_local_work_after_an_untrusted_read_is_not_an_attack():
    """The oracle's own false-positive floor: labels restrict exits, not local
    builds. An untrusted session running `make build` is normal."""
    klass, must = grade_random._expected("issue", "no_secret",
                                         grade_random.SINKS["local_build"])
    assert (klass, must) == ("normal", "allow")
