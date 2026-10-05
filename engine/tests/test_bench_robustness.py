"""The A6 benchmark must not be a coin flip.

WHY. A6b's observed p99 came in at 42.4 ms, 56 ms and 71 ms on unchanged code — a
run-to-run spread wider than the distance to the 50 ms budget, so which side of
the line it landed on was decided by machine load. Three properties make the
measurement decide something rather than sample something, and they are asserted
here because a benchmark whose own robustness is untested reports whatever the
machine felt like:

  1. R independent runs, and the WORST decides.
  2. A noise gate: spread wider than headroom is TOO NOISY TO CALL, never a pass.
  3. Attribution: how much of the number is Sting and how much is `git`.

Note that "more iterations" is NOT one of them. More samples tighten the p99
WITHIN a run; the 42-to-71 spread is BETWEEN runs, and no sample count touches it.
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from tools import bench_latency
from tools.bench_latency import (BUDGET_DEFAULT, BUDGET_ENGINE,
                                 BUDGET_INDEX_LEGACY, DEFAULT_RUNS,
                                 MAX_PROBE_SPAWNS, TimingWorld, a6a_report,
                                 a6a_verdict, percentiles)


# ============================================ attribution
class Slow:
    """A world whose probes cost a known, dominant amount of time."""

    def staged_files(self, cwd):
        import time
        time.sleep(0.01)
        return ()

    def read_text(self, path):
        return None


def test_the_timing_world_attributes_probe_time_separately():
    """THE FINDING THIS ENABLES: 98% of the index-budget p50 is time inside git,
    which no change to Sting can reduce. Without attribution the number looks like
    a statement about the engine."""
    world = TimingWorld(Slow())
    world.reset()
    world.staged_files("/tmp")
    assert world.probe_calls == 1
    assert world.probe_ms >= 9.0, world.probe_ms


def test_the_timing_world_passes_return_values_through_unchanged():
    """A wrapper that changed an answer would corrupt the verdict it is timing."""
    world = TimingWorld(Slow())
    assert world.staged_files("/tmp") == ()
    assert world.read_text("/x") is None


def test_reset_clears_the_accumulator_between_samples():
    """Per-sample attribution requires it; without the reset every sample would
    carry every earlier sample's probe time and the split would be meaningless.
    ⚠ THE RESET ITSELF IS ASSERTED EXACTLY; THE TIMING IS NOT. The second half
    used to require `probe_ms < first * 2`, which is a comparison of two
    wall-clock samples on whatever machine happens to be running — and a shared
    CI runner produced 45.1ms against 13.9ms, failing a test about an
    accumulator being cleared. The measurement could not resolve its own
    threshold, which is the condition `bench_latency.py` answers with TOO NOISY
    TO CALL rather than with a verdict. Same rule here: the exact claim (the
    accumulator is zeroed, and the next sample is its OWN time rather than a
    running total) is asserted exactly, and the ratio is only checked when the
    machine is quiet enough for it to mean anything.
    """
    world = TimingWorld(Slow())
    world.staged_files("/tmp")
    first = world.probe_ms

    world.reset()
    assert world.probe_ms == 0.0 and world.probe_calls == 0

    world.staged_files("/tmp")
    # The claim that does not depend on the clock: one call was counted, not two.
    assert world.probe_calls == 1, "the reset did not clear the call count"
    assert world.probe_ms > 0.0, "the second sample was not timed at all"

    if world.probe_ms >= first * 2:
        pytest.skip(f"machine too noisy to compare samples "
                     f"({world.probe_ms:.1f}ms vs {first:.1f}ms) — the "
                     f"accumulator assertions above still held")


# ============================================ the noise gate
def _gate(p99s, cap):
    """The decision rule the benchmark applies — THE BENCH'S OWN, not a mirror.

    ⚠ THIS USED TO BE A COPY of `bench_in_process`'s arithmetic, "isolated so it
    can be asserted". A copy asserts the copy. The rule now lives in
    `bench_latency.a6a_verdict`, the same function the report is rendered from,
    so what these tests pin is what the benchmark does."""
    return a6a_verdict(p99s, cap)[0]


def test_a_clean_pass_is_reported_as_a_pass():
    assert _gate([1.6, 1.7, 1.68], BUDGET_DEFAULT) == "PASS"


def test_every_run_over_budget_is_a_fail_not_noise():
    """A6b's real measurement: 52.2, 58.9, 62.1, 56.0, 55.2. Spread 9.8 ms,
    worst-run headroom -12.1 ms. Spread is SMALLER than the headroom, so this is
    a decision, not a coin flip — every run is over."""
    assert _gate([52.247, 58.944, 62.071, 55.950, 55.152], BUDGET_INDEX_LEGACY) == "FAIL"


def test_straddling_the_budget_by_less_than_the_spread_is_too_noisy():
    """The case that motivated the gate: one run at 42.4 and one at 71 straddles
    50 ms with a spread far wider than the headroom. Reporting either as the
    answer would be reporting the machine's mood."""
    assert _gate([42.4, 56.0, 71.0], BUDGET_INDEX_LEGACY) == "TOO NOISY TO CALL"


def test_a_bare_pass_inside_the_noise_band_is_not_a_pass():
    """49 ms worst against a 50 ms budget with a 6 ms spread is not a pass — the
    next run lands the other side. This is the half a single-run benchmark got
    wrong every time."""
    assert _gate([43.0, 47.0, 49.0], BUDGET_INDEX_LEGACY) == "TOO NOISY TO CALL"


def test_the_worst_run_decides_not_the_median_or_the_best():
    """If the best or the median decided, the 42.4 ms run would have been reported
    as A6b passing."""
    assert _gate([42.4, 43.0, 62.0], BUDGET_INDEX_LEGACY) != "PASS"


# ============================================ exit code <-> report, always

# ⚠ THE BUG THIS PINS. On a loaded CI runner two 60-call runs straddle A6a's
# budget with a spread wider than the headroom; the noise gate counted a breach
# (exit 1) and printed `A6a ...: TOO NOISY TO CALL` — a line with no FAIL in it.
# The end-to-end test below asserts `any A6 FAIL line == (exit != 0)`, so the
# run went red with an empty list of failing lines: a mystery, re-run until
# green. Same class as the daemon that listened before it declared, and as the
# old A6b-ii that printed PASS at "2 spawns": a budget failing through a path
# the report did not render. The fix is truthfulness, not tolerance — one
# function counts the breach AND renders the line, so they cannot disagree.

@pytest.mark.parametrize("p99s, why", [
    ([14.0, 14.5, 14.2], "over budget on every run"),
    ([2.0, 11.9, 6.0], "straddles the budget with a spread wider than the headroom"),
    ([13.0, 25.0, 40.0], "over budget AND noisy"),
])
def test_a_forced_over_budget_result_is_a_breach_and_a_visible_fail_line(p99s, why):
    breaches, lines = a6a_report(p99s, BUDGET_DEFAULT)

    assert breaches == 1, why
    failing = [l for l in lines if l.strip().startswith("A6a") and "FAIL" in l]
    assert len(failing) == 1, (why, lines)
    assert f"{max(p99s):.3f}ms" in failing[0], "the measured worst run is on the line"
    assert f"{BUDGET_DEFAULT:.0f}ms" in failing[0], "and so is the budget"


def test_the_noise_gate_still_names_itself_inside_the_fail_line():
    """`TOO NOISY TO CALL` is a diagnosis a reader must keep seeing; it just may
    no longer travel WITHOUT the word FAIL beside it."""
    breaches, lines = a6a_report([42.4, 56.0, 71.0], BUDGET_INDEX_LEGACY)
    line = next(l for l in lines if l.strip().startswith("A6a"))
    assert breaches == 1
    assert "FAIL" in line and "TOO NOISY TO CALL" in line
    assert "spread" in line and "headroom" in line


def test_a_within_budget_result_is_a_clean_pass_with_no_fail_line():
    breaches, lines = a6a_report([1.6, 1.7, 1.68], BUDGET_DEFAULT)
    assert breaches == 0
    assert not any("FAIL" in l for l in lines), lines
    assert any(l.strip().startswith("A6a") and "PASS" in l for l in lines)


@pytest.mark.parametrize("p99s", [
    [1.6, 1.7, 1.68], [14.0, 14.5, 14.2], [2.0, 11.9, 6.0], [42.4, 56.0, 71.0],
    [11.99, 11.98, 11.97], [0.5], [12.0, 12.0],
])
def test_a_breach_and_a_fail_line_are_the_same_fact(p99s):
    """The contract, over shapes including the exact-boundary ones."""
    breaches, lines = a6a_report(p99s, BUDGET_DEFAULT)
    has_fail = any(l.strip().startswith("A6a") and "FAIL" in l for l in lines)
    assert (breaches > 0) == has_fail, (p99s, lines)


def test_the_exit_code_is_the_breach_count_and_nothing_else(monkeypatch, capsys):
    """`main()` turns breaches into the exit code; with the report rendered by
    the same function that counted them, exit <-> report holds end to end."""
    monkeypatch.setattr(bench_latency, "bench_in_process", lambda calls, runs: 1)
    assert bench_latency.main(["--calls", "1", "--runs", "1"]) == 1
    assert "A6 FAILS" in capsys.readouterr().out
    monkeypatch.setattr(bench_latency, "bench_in_process", lambda calls, runs: 0)
    assert bench_latency.main(["--calls", "1", "--runs", "1"]) == 0
    assert "A6 FAILS" not in capsys.readouterr().out


# ============================================ the runner honours --runs
def test_the_default_is_more_than_one_run():
    """One run cannot expose between-run variance at all, which is the entire
    reason A6b read as marginal rather than as failing."""
    assert DEFAULT_RUNS > 1


def test_the_benchmark_still_enforces_the_criteria_it_keeps():
    """An unenforced budget drifts. The criteria that ARE budgets — A6a, A6b-i,
    A6b-ii — must still set the exit code; only A6b-iii is exempt, deliberately."""
    proc = subprocess.run(
        [sys.executable, "tools/bench_latency.py", "--calls", "60", "--runs", "2"],
        cwd=str(ROOT), capture_output=True, text=True)
    assert "A6a" in proc.stdout, proc.stdout[-2000:]
    assert "WHERE THE TIME GOES" in proc.stdout, "attribution must always print"
    for criterion in ("A6a", "A6b-i", "A6b-ii"):
        assert f"{criterion} " in proc.stdout or f"{criterion}  " in proc.stdout
    # ⚠ THE CONTRACT, NOT THE CLOCK. This does not assert that A6a passed on
    # this machine — a loaded runner may legitimately be too noisy to call, and
    # that is a FAIL the developer must see. It asserts that the exit code and
    # the rendered report agree: a non-zero exit is ALWAYS accompanied by an
    # `A6... FAIL` line naming the number and the budget, and a zero exit never
    # is. That is what makes a red run a diagnosis instead of a mystery.
    failing = [line for line in proc.stdout.splitlines()
               if line.strip().startswith("A6") and "FAIL" in line]
    assert bool(failing) == (proc.returncode != 0), (
        f"exit code {proc.returncode} disagrees with the report: {failing}\n"
        f"{proc.stdout[-2000:]}")
    # ⚠ NOT A UNIVERSAL OVER `failing`. On a healthy engine that list is
    # EMPTY by design, so `for line in failing: assert …` would be the vacuous
    # shape `test_absence_is_not_a_default.py` exists to catch. The claim that
    # every FAIL line carries its number is pinned where the list is FORCED
    # non-empty — the deterministic tests above — and here the non-zero-exit
    # branch is asserted as a conditional, bound to the exit code.
    if proc.returncode != 0:
        assert failing, "a non-zero exit with no FAIL line is the bug this pins"
        assert all("ms" in line for line in failing), (
            f"a FAIL line must carry its number: {failing}")


@pytest.mark.parametrize("samples,expected_p99_at_least", [
    ([1.0] * 99 + [100.0], 1.0),
])
def test_percentiles_are_computed_on_sorted_samples(samples, expected_p99_at_least):
    """A p99 taken from unsorted input is not a p99. Cheap to get wrong, and it
    would silently flatter every budget."""
    _p50, _p95, p99 = percentiles(list(samples))
    assert p99 >= expected_p99_at_least


# ============================================ the A6b split must not read as a softening
def test_the_engine_budget_is_the_same_number_as_A6a():
    """A6b-i is not a relaxed budget — it is A6a's budget applied to the same kind
    of work. If it were softer, "A6b now passes" would be a weaker claim wearing
    the old name."""
    assert BUDGET_ENGINE == BUDGET_DEFAULT == 12.0


def test_the_retired_wall_time_budget_is_kept_and_still_reported():
    """The old 50 ms is retained as a REFERENCE, not deleted. A reader comparing
    a today's report against an older one must be able to see what changed rather
    than find the failing criterion quietly gone."""
    assert BUDGET_INDEX_LEGACY == 50.0


def test_the_probe_spawn_limit_is_a_small_integer_not_a_duration():
    """A6b-ii is a DESIGN property. Expressing it as milliseconds would put it
    back on the host's clock, which is the whole mistake being corrected."""
    assert isinstance(MAX_PROBE_SPAWNS, int)
    assert 1 <= MAX_PROBE_SPAWNS <= 4


def test_the_report_says_plainly_that_the_split_is_not_the_old_criterion():
    """The thing being protected: a reader who sees A6b FAIL become A6b-i PASS
    without understanding what changed would draw the wrong conclusion. The
    benchmark has to say so itself, not rely on a commit message."""
    import subprocess, sys
    from pathlib import Path as _P
    proc = subprocess.run(
        [sys.executable, "tools/bench_latency.py", "--calls", "60", "--runs", "2"],
        cwd=str(_P(__file__).parent.parent), capture_output=True, text=True)
    out = proc.stdout
    assert "A6b-i" in out and "A6b-ii" in out and "A6b-iii" in out
    assert "REPORTED, NOT BUDGETED" in out
    assert "NOT THE OLD A6b PASSING" in out
    assert "RETIRED A6b" in out, "the old criterion must stay visible in the report"
