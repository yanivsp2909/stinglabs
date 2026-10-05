"""The A6 budgets, pinned. An unenforced budget drifts; so does an unpinned one.

A6 was one number — p99 < 12 ms across every action. It was written before
anyone measured anything and assumed a uniform per-action cost the design does
not have: rule #7 mandates inspecting the real git index at commit and push, and
that inspection costs a process spawn (~12 ms each, measured) no matter what the
engine does.

It is now TWO budgets, both binding:

    p99 < 12 ms   every kind except git_commit and git_push
    p99 < 50 ms   git_commit and git_push, against a DIRTY index

The dirty index is the load-bearing part. 40 of 50 real commit/push commands in
a measured session are `git add … && git commit`, so the index is not empty and
all three probes fire at ~38 ms. Measuring against a clean index would describe
the 1-in-50 case and pass — the exact dodge a second budget exists to prevent.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

import bench_latency as bench


def test_the_criteria_are_what_was_agreed():
    """If any of these moves, it should be a decision someone made on purpose.

    IT MOVED, AND IT WAS. The old pair was (12 ms wall, 50 ms wall). The 50 ms
    budget was retired because 98% of it was time inside `git` — Sting's own
    contribution to a commit verdict is ~1 ms p99 — so it measured the host, not
    the product, and failed on the host's clock.

    ⚠ A6b-i IS NOT THE OLD A6b RELAXED. It is A6a's budget, unchanged at 12 ms,
    applied to Sting's own work with probes excluded. The retired wall-time figure
    is KEPT as a reference and still reported, so a reader comparing two reports
    sees what changed rather than finding the failing criterion quietly gone.

    ⚠ A6b-ii MOVED FROM 2 TO 3, AND THIS TEST IS WHY THAT HAD TO BE ARGUED.
    It failed on the change, which is the whole point of pinning a criterion:
    a budget cannot drift, it can only be edited by somebody who then has to
    say why. The reasoning is in `tools/bench_latency.py` beside the constant.
    The short form:

      * the instrument was counting World METHOD CALLS, not git spawns, so 2
        was never a measured claim about anything;
      * this code spawns 1 (clean index) or 3 (dirty index) and NEVER 2, so a
        budget of 2 described no reachable state;
      * each of the three answers something nothing else does — which files,
        WHERE they are, and what is in them;
      * dropping the middle one turns A1's own case from DENY into ALLOW when
        cwd is a subdirectory, which is 92.8% of live commands. It is covered
        by `tests/test_staged_paths_are_absolute.py`, which did not exist
        before this was costed — the whole suite passed without that spawn.

    ⚠ THE SEPARATION WAS DELIBERATE: the instrument was fixed in one pass and
    FAILED honestly at 3-against-2 for that whole pass, and the budget was
    argued in the next. Doing both at once would have meant neither was
    measured.
    """
    assert bench.BUDGET_DEFAULT == 12.0            # A6a
    assert bench.BUDGET_ENGINE == 12.0             # A6b-i — the SAME number
    assert bench.MAX_PROBE_SPAWNS == 3             # A6b-ii — argued, not bumped
    assert bench.BUDGET_INDEX_LEGACY == 50.0       # retired, reported, not a gate


def test_the_index_budget_covers_exactly_the_kinds_that_inspect_the_index():
    """Widening this set is how a slow kind escapes the tighter budget."""
    # These are the kinds whose WALL TIME is reported rather than budgeted, and
    # whose engine-only time is held to A6b-i. Widening the set is how a slow kind
    # would escape the 12 ms budget entirely, so it stays pinned.
    assert bench.INDEX_KINDS == {"commit + heredoc", "push"}
    labels = {label for label, _ in bench.CASES}
    assert bench.INDEX_KINDS <= labels
    # Everything else must be held to 12 ms.
    assert labels - bench.INDEX_KINDS == {
        "short exec", "read", "write", "long exec (8 KiB)"}


def test_the_benchmark_stages_a_real_change():
    """The dirty index is the whole point. If this silently produced a clean
    repo, the second budget would measure the wrong case and pass."""
    import subprocess
    repo, cleanup = bench.dirty_repo()
    if repo is None:
        import pytest
        pytest.skip("git unavailable")
    try:
        out = subprocess.run(["git", "diff", "--cached", "--name-only"],
                              cwd=repo, capture_output=True, text=True).stdout
        assert out.strip(), "the benchmark repo has nothing staged"
    finally:
        cleanup()


def test_an_unmeasurable_index_budget_is_not_a_pass(monkeypatch, capsys):
    """No git means the dirty case could not be measured. That must count as a
    breach, not as silence — otherwise A6 passes on any machine without git."""
    monkeypatch.setattr(bench, "dirty_repo", lambda: (None, None))
    breaches = bench.bench_in_process(60)
    out = capsys.readouterr().out
    assert "UNMEASURED" in out
    assert breaches >= 1, "an unmeasured budget must not pass by default"
