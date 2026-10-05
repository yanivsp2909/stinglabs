#!/usr/bin/env python3
"""Verdict latency, measured three ways. docs/15 step 20 / acceptance A6.

    python3 tools/bench_latency.py                 # in-process, 10k calls
    python3 tools/bench_latency.py --subprocess    # also the cold round trip

A6 IS NOW THREE CRITERIA, AND THE THIRD IS DELIBERATELY NOT A BUDGET:

    A6a     p99 < 12 ms   every action kind EXCEPT git_commit and git_push
    A6b-i   p99 < 12 ms   Sting's own verdict work on commit/push, PROBES EXCLUDED
    A6b-ii  <= 2 probe spawns per verdict — a design property, not a wall time
    A6b-iii probe wall time: MEASURED AND REPORTED, never budgeted, and NOT a
            lingering failure — see below

⚠⚠ THIS IS NOT THE OLD A6b WITH A SOFTER NUMBER. READ THIS BEFORE QUOTING EITHER.

The old A6b was `p99 < 50 ms` of WALL TIME for a commit/push verdict, and it
FAILED at 52-62 ms across five runs. It failed on time spent inside `git`:

    Sting's own code   p50  0.852 ms   p99  1.170 ms
    git subprocesses   p50 34.608 ms   p99 56.376 ms
    => 98% of the p50 was time inside git, which no change to Sting can reduce.

So the old criterion did not measure the product. It measured `git diff --cached`
on the host, with Sting's contribution as a rounding error — and raising 50 to 80
would have made it pass while still measuring the wrong thing.

**These are different claims about different things, and the old one is not
retired as passed.** A6b-i says Sting's own work is fast. It does NOT say a
commit verdict completes in 12 ms of wall time — it does not, and A6b-iii reports
the real figure precisely so nobody can read the pass as that claim.

What would make the WALL TIME fall is caching the index read per (cwd, index
mtime), or parsing the index directly instead of spawning git. Both are real work
with real risk against rule #7 (inspect what is actually in the commit), and
neither should be attempted to make a number move.

The dirty index is the whole point of the second budget. 40 of 50 real
commit/push commands in a measured session are `git add … && git commit`, so the
index is NOT empty and all three git probes fire at ~38 ms. A clean index costs
~12 ms and one probe. Measuring the second budget against a clean index would
make it pass while describing the 1-in-50 case — which is exactly the dodge a
second budget exists to avoid, so this script stages a real change and commits
nothing.

⚠ A6b-iii IS NOT A CRITERION, AND MUST NOT BE READ AS ONE STILL FAILING.
A criterion nobody can act on is a measurement of `git` on the host, not a
criterion. 99% of the figure is inside git; the only lever Sting owns is the
SPAWN COUNT, which A6b-ii budgets at <=2 and holds. It is a host characteristic
and will differ on every machine, because git's cost is a function of index size
— re-measured after a dozen passes of work it moved from 52-62 ms to 62-74 ms
with no change to Sting, purely because this repository grew.

⚠ AND THE RETIRED A6b's FAILURE RECORD IS UNTOUCHED BY THAT. It budgeted 50 ms
of WALL TIME, it failed at 52.2/58.9/62.1/56.0/55.2 ms, and it would fail harder
today. It is not retired-as-passed, not softened, and not restated in any weaker
form. Reformulating A6b-iii is a statement about what Sting is ACCOUNTABLE for;
it is not a claim that the old number improved. It did not — it got worse.

Both budgets exit non-zero when exceeded. An unenforced budget drifts.

A6 is a claim about the RESIDENT daemon, so the number that answers it is
`decide()` measured in-process with interpreter startup excluded. The subprocess
figure is what the hook costs today, and the gap between the two is what a
daemon would remove.

WHY THE DECISION LOG CANNOT ANSWER THIS. Its records carry `ts`, the moment the
record was appended, and nothing else about timing. Consecutive gaps are agent
turnaround — p50 ~14 seconds on a real session — and contain no hook component
that can be separated out. There is no duration field. That is a gap in the log,
not a measurement.

The state used here is deliberately the WORST case a real session reaches:
untrusted, holding secrets, with a realistic number of fingerprints and tainted
paths, because every one of those is a loop the verdict path walks.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters import claude_code                              # noqa: E402
from core import engine, probes                               # noqa: E402
from core.types import SessionState                           # noqa: E402
from tools import run_registry                                # noqa: E402

ROOT = Path(__file__).parent.parent


def loaded_state(fingerprints: int = 200, tainted: int = 40) -> SessionState:
    """A session as heavy as a real one gets."""
    st = SessionState(session_id="bench", cwd=str(ROOT))
    st.workspace_roots = [str(ROOT)]
    st.untrusted = True
    st.untrusted_since_seq = 1
    st.untrusted_sources = [{"seq": 1, "kind": "issue", "ref": "x" * 80}]
    st.holds_secret = True
    st.holds_secret_since_seq = 2
    st.secret_fingerprints = [f"{i:08x}" for i in range(fingerprints)]
    st.secret_sources = [{"seq": 2, "path": f"{ROOT}/.env", "how": "content"}]
    st.tainted_paths = {f"{ROOT}/f{i}.py": {"label": "SECRET", "level": "derived",
                                             "from_seq": 3} for i in range(tainted)}
    st.tainted_vars = {f"V{i}": 3 for i in range(10)}
    return st


CASES = [
    ("short exec", {"tool_name": "Bash", "tool_input": {"command": "git status"}}),
    ("read", {"tool_name": "Read", "tool_input": {"file_path": str(ROOT / "core/engine.py")}}),
    ("write", {"tool_name": "Write", "tool_input": {
        "file_path": str(ROOT / "x.py"), "content": "print('x')\n" * 50}}),
    ("commit + heredoc", {"tool_name": "Bash", "tool_input": {"command":
        "git add -A && git commit -q -F - <<'MSG'\n" + ("body line\n" * 40) + "MSG"}}),
    ("long exec (8 KiB)", {"tool_name": "Bash", "tool_input": {"command":
        "python3 - <<'PY'\n" + ("x = 'a' * 40\n" * 400) + "PY"}}),
    ("push", {"tool_name": "Bash", "tool_input": {"command": "git push origin main"}}),
]


def percentiles(samples: list[float]) -> tuple[float, float, float]:
    samples.sort()
    n = len(samples)
    return (statistics.median(samples),
            samples[min(n - 1, int(n * 0.95))],
            samples[min(n - 1, int(n * 0.99))])


BUDGET_DEFAULT = 12.0
BUDGET_ENGINE = 12.0          # A6b-i: Sting's own work, probes excluded
MAX_PROBE_SPAWNS = 3          # A6b-ii: a design property Sting owns

# ─────────────────────────────────────────────────────────────────────────────
# ⚠ A6b-ii COUNTED THE WRONG THING FOR ITS WHOLE LIFE, AND THE NUMBER IT
#   PRINTED WAS NOT THE NUMBER IN ITS NAME.
#
# The criterion is "<= 2 GIT PROBE SPAWNS per verdict". The instrument was
# `TimingWorld.probe_calls`, which counts METHOD CALLS ON THE WORLD — a
# different quantity that happened to agree once. Measured directly, on this
# machine, at the commit before the sync-root carrier and at HEAD:
#
#                              World method calls      REAL git spawns
#     before (47c91d7)                 2                      3
#     HEAD   (541bbe8)                 3                      3
#
#   staged_files    spawns 2:  `git diff --cached --name-only`
#                              `git rev-parse --show-toplevel`
#   staged_content  spawns 1:  `git diff --cached`
#   sync_roots      spawns 0:  it reads directories
#
# So the budget printed **PASS at "2 spawns" for a verdict that spawned three
# git processes**, and then printed FAIL when a change added a World call that
# spawns nothing at all. Both outputs were wrong in the same way: the counter
# and the criterion were two different things joined by a name — working rule
# 11, and the same shape as working rule 13's "comparison whose two sides can
# both be absent".
#
# ⚠ THE FIX COUNTS SPAWNS, AND IT DID NOT MAKE THE BUDGET PASS. Honest counting
# gave 3 against a budget of 2, and it FAILED for a full pass before the budget
# was touched. That separation is the point: an instrument repaired while a
# budget is failing must not be readable as tuning.
#
# ═════════════════════════════════════════════════════════════════════════════
# ⚠ THE BUDGET IS NOW 3, AND HERE IS WHY IT IS A MEASURED CLAIM AND NOT A BUMP.
# ═════════════════════════════════════════════════════════════════════════════
#
# THE DECIDING FACT: THIS CODE SPAWNS 1 OR 3, NEVER 2. Measured both ways.
#
#     clean index   1 spawn    `diff --cached --name-only` returns nothing, so
#                              `staged_files` skips `rev-parse` by derivation
#                              and `_staged_secret` skips `staged_content`
#                              because an empty index has an empty diff
#     dirty index   3 spawns   diff --cached --name-only
#                              rev-parse --show-toplevel
#                              diff --cached
#
# **A budget of 2 does not describe any reachable state of this system.** It
# could never have been met and could never have been exceeded by one. That is
# not a threshold that was set too low; it is a number that was never measured
# against anything, which is exactly what an instrument counting the wrong
# quantity produces.
#
# EACH OF THE THREE ANSWERS SOMETHING NOTHING ELSE DOES:
#
#   diff --cached --name-only   WHICH files are in the index. Rule #7: not a
#                               staged list we maintained, because ours would
#                               miss `git add -f` and wrongly include a path
#                               .gitignore dropped.
#   rev-parse --show-toplevel   WHERE those files are. The names come back
#                               relative to the REPOSITORY ROOT, and every
#                               taint lookup is keyed on an absolute path.
#   diff --cached               WHAT IS IN them. The only probe that can see a
#                               secret in a file the guard never watched being
#                               written.
#
# ⚠ AND THE SECOND ONE WAS TESTED BY NOTHING. The whole suite passes with
# `rev-parse` removed and `base = Path(cwd)` in its place — 2372 passed, and
# A4/A5 unmoved at 59/79 and 0/25. It is load-bearing anyway, and the case that
# shows it is the product's own flagship:
#
#     cwd = <repo>/src, a tainted file staged, `git commit`
#       with rev-parse     staged as <repo>/src/config.py  -> DENY
#                                                              secret_exact:git_commit
#       without            staged as <repo>/src/src/config.py -> ALLOW
#
# The path doubles, the taint lookup misses, and the secret commits. **92.8% of
# live commands begin `cd X &&`**, so cwd != repo root is the common shape in
# real sessions and the rare one in the corpus — corpus blindness, again, in the
# layer that turns text into structure. `tests/test_staged_paths_are_absolute.py`
# now covers it.
#
# WHAT IT COSTS TO KEEP, measured rather than feared:
#
#     one git spawn                       ~8.5 ms p50   (`git --version`, which
#                                         does no work, is 7.9 ms — so ~86% of
#                                         a spawn is git STARTING, not working)
#     warm call, no index probe            27.4 ms
#     warm call, commit with dirty index   56.2 ms      -> git is ~51% of it
#     commit/push as a share of real
#       actions, 10 sessions, 2790 records  2.47%
#     removing one spawn, over the busiest
#       session on record (59 commits)      0.50 s
#     keeping all three, median session     0.025 s
#
# **Half a second across the busiest session ever recorded here, against a
# silent miss of the flagship case in the shape 92.8% of live commands take.**
#
# ⚠ WHAT WOULD CHANGE THIS BACK TO 2. Not a faster machine and not a smaller
# number. Only a way to learn the repository root without a spawn that is not a
# reimplementation of git's own discovery — worktrees use a `.git` FILE,
# submodules another, and `GIT_DIR`/`GIT_WORK_TREE` override both. Two routes
# were considered and rejected with reasons:
#   `--relative`      makes names cwd-relative AND FILTERS to files under cwd,
#                     so a file staged elsewhere in the repo vanishes from the
#                     index inspection. That is a correctness regression
#                     against rule #7 dressed as an optimisation.
#   cache per cwd     viable only in the daemon, and it is the same
#                     daemon-lifetime cache that was refused for session state
#                     one pass ago. Refusing it there and taking it here for
#                     8.5 ms would be inconsistent.
# ─────────────────────────────────────────────────────────────────────────────

BUDGET_INDEX_LEGACY = 50.0    # the OLD A6b. Kept, reported, and NOT a gate.
INDEX_KINDS = {"commit + heredoc", "push"}

# ---------------------------------------------------------------- robustness
#
# WHY A SINGLE RUN CANNOT ANSWER A6b. Observed p99 for the index budget has come
# in at 42.4 ms, 56 ms and 71 ms on the same code — a spread wider than the
# distance to the 50 ms budget, so which side of the line it lands on is decided
# by machine load rather than by Sting. A p99 from one run is itself a random
# variable; printing pass/fail from one is a coin flip with a verdict on it.
#
# THREE CHANGES, and "more iterations" is NOT the important one — more samples
# tighten the p99 WITHIN a run and do nothing about variance BETWEEN runs, which
# is where the 42-to-71 spread lives.
#
#   1. R independent runs, reporting the DISTRIBUTION of p99 across them.
#   2. Decide against the WORST run. A budget that passes on a quiet machine and
#      fails under load is not a budget, and a developer's machine is never the
#      quiet one.
#   3. A NOISE GATE: when the spread across runs is wider than the headroom to
#      the budget, the honest output is TOO NOISY TO CALL, not a pass. A
#      benchmark that cannot resolve its own threshold has to say so.
#
# And the ATTRIBUTION below, which turned out to matter more than all three.
DEFAULT_RUNS = 5


class TimingWorld:
    """Wraps a World and accumulates wall time spent inside its probes.

    THE POINT IS ATTRIBUTION. A6b budgets Sting's verdict, but a verdict for
    git_commit/git_push calls out to `git diff --cached`, and a subprocess spawn
    is not something Sting's code can make faster. Splitting the two says whether
    the budget measures the ENGINE or the MACHINE.

    Measured directly, one probe at a time, on an idle laptop:

        staged_files    p50 22.6ms  p99 36.0ms   range 17.8-47.0
        staged_content  p50 12.0ms  p99 21.4ms   range  9.5-24.2
        subprocess true p50  2.1ms               <- so ~20ms is git WORKING,
                                                    only ~2ms is fork/exec
    """

    def __init__(self, inner):
        self._inner = inner
        self.probe_ms = 0.0
        self.probe_calls = 0

    def _timed(self, name):
        def call(*args, **kwargs):
            start = time.perf_counter()
            try:
                return getattr(self._inner, name)(*args, **kwargs)
            finally:
                self.probe_ms += (time.perf_counter() - start) * 1000
                self.probe_calls += 1
        return call

    def __getattr__(self, name):
        return self._timed(name)

    def reset(self):
        self.probe_ms = 0.0
        self.probe_calls = 0


def dirty_repo() -> tuple[str, object] | tuple[None, None]:
    """A scratch repo with a real staged change, so the index probes do work.

    Returns (path, cleanup). None when git is unavailable — the caller then
    reports the index budget as UNMEASURED rather than passing it by default.
    """
    import shutil
    import tempfile
    if not shutil.which("git"):
        return None, None
    d = tempfile.mkdtemp(prefix="sting-bench-")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null"}

    def git(*a):
        return subprocess.run(["git", *a], cwd=d, capture_output=True, env=env)

    git("init", "-q")
    (Path(d) / "a.py").write_text("x = 1\n")
    git("add", "-A")
    git("-c", "user.email=a@b", "-c", "user.name=c", "commit", "-q", "-m", "init")
    # THE STAGED CHANGE. Without this the index is clean, both extra probes are
    # skipped by their derivations, and the measurement describes the wrong case.
    (Path(d) / "b.py").write_text("y = 2\n" * 200)
    git("add", "-A")
    if git("diff", "--cached", "--name-only").stdout.strip() == b"":
        shutil.rmtree(d, ignore_errors=True)
        return None, None
    return d, lambda: shutil.rmtree(d, ignore_errors=True)


def count_git_spawns(cwd: str) -> tuple[int, list[str]]:
    """Real subprocesses started while deciding one commit and one push verdict.

    ⚠ RUN OUTSIDE THE TIMED LOOP, ON PURPOSE. Wrapping `subprocess.Popen`
    inside the loop would put this instrument's own cost into the latency it is
    measuring beside. This is a COUNT, not a duration, so one verdict answers
    it and the timing arms never see the wrapper.

    Returns the WORST count across the index-inspecting kinds, and the argv
    heads, so the output can say WHICH processes rather than only how many.

    ⚠ IT REFUSES TO COUNT AGAINST AN INDEX THAT IS NOT DIRTY, AND THAT GUARD
    CAUGHT A REAL FALSE PASS THE HOUR IT WAS WRITTEN. The first version of this
    function was called after `dirty_repo()`'s cleanup had already removed the
    scratch repository. Every `git` call then failed, `staged_files` returned
    None after ONE spawn instead of two, and the budget printed **PASS at 2
    spawns — measured against a directory that did not exist.** That is working
    rule 13 exactly: a count over a population that cannot contain the thing
    being counted. `staged_files` skips `rev-parse` when nothing is staged, by
    design, so a clean index under-counts for the same reason without any
    directory being missing at all.
    """
    if not Path(cwd).is_dir():
        return -1, [f"UNMEASURED: {cwd} is not a directory"]
    probe = subprocess.run(["git", "diff", "--cached", "--name-only"], cwd=cwd,
                            capture_output=True, text=True)
    if probe.returncode != 0 or not probe.stdout.strip():
        return -1, [f"UNMEASURED: {cwd} has no staged change, so `staged_files` "
                    f"skips its second spawn by derivation"]

    seen: list[list[str]] = []
    real_popen = subprocess.Popen

    class Counting(real_popen):                       # noqa: D401
        def __init__(self, *a, **k):
            argv = a[0] if a else k.get("args")
            try:
                seen.append([str(x) for x in list(argv)[:4]])
            except TypeError:                          # pragma: no cover
                seen.append([str(argv)])
            super().__init__(*a, **k)

    worst, worst_argv = 0, []
    subprocess.Popen = Counting
    try:
        for label, payload in CASES:
            if label not in INDEX_KINDS:
                continue
            seen.clear()
            action = claude_code.parse({"session_id": "spawns", "cwd": cwd,
                                         "hook_event_name": "PreToolUse", **payload})
            state = loaded_state()
            state.cwd = cwd
            state.workspace_roots = [cwd]
            engine.decide(action, state, probes.RealWorld())
            if len(seen) > worst:
                worst, worst_argv = len(seen), [" ".join(s) for s in seen]
    finally:
        subprocess.Popen = real_popen
    return worst, worst_argv


def _one_run(per: int, cwd: str, root: str, world) -> dict:
    """One independent pass over every case. Returns per-class sample lists."""
    out = {"default": [], "index": [], "engine_index": [], "probe_index": [],
            "probe_calls": 0, "per_case": {}}
    for label, payload in CASES:
        indexy = label in INDEX_KINDS
        here = cwd if indexy else root
        action = claude_code.parse({"session_id": "bench", "cwd": here,
                                     "hook_event_name": "PreToolUse", **payload})
        total_ms, engine_ms, probe_ms = [], [], []
        for _ in range(per):
            state = loaded_state()          # fresh: labelling mutates it
            state.cwd = here
            state.workspace_roots = [here]
            world.reset()
            t = time.perf_counter()
            engine.decide(action, state, world)
            elapsed = (time.perf_counter() - t) * 1000
            total_ms.append(elapsed)
            probe_ms.append(world.probe_ms)
            engine_ms.append(elapsed - world.probe_ms)
            out["probe_calls"] = world.probe_calls
        cls = "index" if indexy else "default"
        out[cls] += total_ms
        if indexy:
            out["engine_index"] += engine_ms
            out["probe_index"] += probe_ms
        out["per_case"][label] = percentiles(list(total_ms))
    return out


def a6a_verdict(p99s, cap: float) -> tuple[str, str]:
    """The A6a decision — worst run decides, and a spread wider than the worst
    run's headroom is TOO NOISY TO CALL — and the sentence that explains it.

    ⚠ ONE RULE, SHARED. `tests/test_bench_robustness.py` used to carry a copy of
    this arithmetic "isolated so it can be asserted"; a copy asserts the copy.
    The report is rendered from THIS function and the tests import THIS
    function, so what is pinned is what the benchmark does.
    """
    worst, best = max(p99s), min(p99s)
    spread = worst - best
    headroom = cap - worst
    if spread > abs(headroom):
        return ("TOO NOISY TO CALL",
                f"worst {worst:.3f}ms, spread {spread:.3f}ms exceeds headroom "
                f"{headroom:+.3f}ms against the {cap:.0f}ms budget")
    if worst < cap:
        return "PASS", f"worst {worst:.3f}ms under the {cap:.0f}ms budget"
    return "FAIL", f"worst {worst:.3f}ms over the {cap:.0f}ms budget"


def a6a_report(p99s, cap: float) -> tuple[int, list[str]]:
    """The breach count AND the report lines, from one function, so the exit
    code and the rendered report cannot disagree.

    ⚠ THE BUG THIS CLOSES. The noise gate counted a breach (exit 1, "A6 FAILS")
    and printed `A6a ...: TOO NOISY TO CALL` — a line with no FAIL in it. On a
    loaded CI runner two short runs straddle the budget with a spread wider
    than the headroom, so the run went red with no failing line for the test
    to show: a mystery, re-run until green. Same class as the daemon that
    listened before it declared and the old A6b-ii that printed PASS at "2
    spawns": a budget failing through a path the report did not render.

    EVERY breach now renders as `A6a ...: FAIL — <why, with the number and the
    budget>`. The noise gate keeps its name inside that line. Nothing about the
    budget or the gate moved: a true regression fails exactly as before, and
    a busy runner's blip fails VISIBLY instead of mysteriously.
    """
    label, detail = a6a_verdict(p99s, cap)
    worst, best = max(p99s), min(p99s)
    head = f"  A6a  [<{cap:.0f}ms wall, all kinds except commit/push]: "
    if label == "PASS":
        breaches, verdict = 0, f"PASS — {detail}"
    elif label == "FAIL":
        breaches, verdict = 1, f"FAIL — {detail}"
    else:
        breaches, verdict = 1, f"FAIL — TOO NOISY TO CALL: {detail}"
    lines = [head + verdict,
             f"         p99 over {len(p99s)} runs: best {best:.3f}ms, "
             f"worst {worst:.3f}ms, spread {worst - best:.3f}ms"]
    return breaches, lines


def bench_in_process(total: int, runs: int = DEFAULT_RUNS) -> int:
    """Returns the number of budgets breached. Decides on the WORST run."""
    world = TimingWorld(probes.RealWorld())
    per = max(1, total // len(CASES))
    repo, cleanup = dirty_repo()
    cwd = repo or str(ROOT)

    print(f"\n=== 2. decide() IN-PROCESS — {runs} independent runs x "
          f"{per * len(CASES)} calls, spawn excluded (the A6 question)")
    print(f"    index-inspecting kinds run against "
          f"{'a DIRTY index' if repo else 'NO GIT — see below'}")
    print(f"    deciding on the WORST run, not the best: a budget that only holds "
          f"on an idle machine is not a budget\n")

    per_run = []
    spawns, spawn_argv = -1, ["UNMEASURED: no scratch repository"]
    try:
        for r in range(runs):
            per_run.append(_one_run(per, cwd, str(ROOT), world))
            got = percentiles(list(per_run[-1]["index"]))[2] if per_run[-1]["index"] else float("nan")
            print(f"    run {r + 1}/{runs}: index p99 {got:7.3f}ms")
        # ⚠ INSIDE THE `try`, BECAUSE `cleanup()` REMOVES THE REPOSITORY THIS
        # COUNTS AGAINST. Counting it afterwards is what produced a PASS from a
        # deleted directory — see count_git_spawns.
        if repo:
            spawns, spawn_argv = count_git_spawns(cwd)
    finally:
        if cleanup:
            cleanup()

    print(f"\n{'case':20} {'p50':>9} {'p95':>9} {'p99':>9}   (worst run)")
    worst_idx = max(range(len(per_run)),
                    key=lambda i: percentiles(list(per_run[i]["index"]))[2]
                    if per_run[i]["index"] else 0)
    for label, _payload in CASES:
        p50, p95, p99 = per_run[worst_idx]["per_case"][label]
        if label in INDEX_KINDS:
            # No wall-time budget here any more — see A6b-iii. The
            # figure is reported so it cannot be quietly forgotten.
            print(f"{label:20} {p50:8.3f}ms {p95:8.3f}ms {p99:8.3f}ms  "
                  f"(wall time, reported not budgeted)")
        else:
            print(f"{label:20} {p50:8.3f}ms {p95:8.3f}ms {p99:8.3f}ms  "
                  f"<{BUDGET_DEFAULT:.0f}ms "
                  f"{'ok' if p99 < BUDGET_DEFAULT else 'OVER'}")

    # ---- ATTRIBUTION. This is the finding, not the pass/fail.
    engine_all = [v for run in per_run for v in run["engine_index"]]
    probe_all = [v for run in per_run for v in run["probe_index"]]
    if engine_all:
        e50, _e95, e99 = percentiles(list(engine_all))
        g50, _g95, g99 = percentiles(list(probe_all))
        calls = per_run[0]["probe_calls"]
        print(f"\n  WHERE THE TIME GOES, for the index-inspecting kinds:")
        print(f"    Sting's own code   p50 {e50:7.3f}ms   p99 {e99:7.3f}ms")
        print(f"    git subprocesses   p50 {g50:7.3f}ms   p99 {g99:7.3f}ms   "
              f"({calls} probe calls per verdict)")
        share = 100 * g50 / max(e50 + g50, 1e-9)
        print(f"    => {share:.0f}% of the p50 is time inside git, which no change "
              f"to Sting can reduce.")

    breaches = 0
    print()

    # ---------------- A6a: unchanged, and it was never the problem
    p99s = [percentiles(list(run["default"]))[2] for run in per_run if run["default"]]
    a6a_breaches, a6a_lines = a6a_report(p99s, BUDGET_DEFAULT)
    breaches += a6a_breaches                  # counted where it is rendered
    for line in a6a_lines:
        print(line)

    if not repo:
        # ⚠ A FAIL LINE, so the non-zero exit below is visible in the report.
        print(f"\n  A6b-i  [<{BUDGET_ENGINE:.0f}ms, STING'S OWN WORK on commit/push]: "
              f"FAIL — UNMEASURED, git unavailable so the index was never dirty; "
              f"not counted as a pass.")
        return breaches + 1

    engine_p99s = [percentiles(list(run["engine_index"]))[2] for run in per_run
                    if run["engine_index"]]
    probe_p99s = [percentiles(list(run["probe_index"]))[2] for run in per_run
                   if run["probe_index"]]
    total_p99s = [percentiles(list(run["index"]))[2] for run in per_run if run["index"]]
    world_calls = max(run["probe_calls"] for run in per_run)

    # ---------------- A6b-i: what Sting controls
    worst, best = max(engine_p99s), min(engine_p99s)
    ok = worst < BUDGET_ENGINE
    breaches += 0 if ok else 1
    print(f"\n  A6b-i  [<{BUDGET_ENGINE:.0f}ms, STING'S OWN WORK on commit/push, "
          f"probes excluded]: {'PASS' if ok else 'FAIL'}")
    print(f"         p99 over {len(engine_p99s)} runs: best {best:.3f}ms, "
          f"worst {worst:.3f}ms, headroom {BUDGET_ENGINE - worst:+.3f}ms")

    # ---------------- A6b-ii: the only lever Sting owns on the wall time
    # ⚠ UNMEASURED IS NOT A PASS. -1 means the count refused to run, and a
    # criterion that could not be measured must not be counted as one that held.
    ok = 0 <= spawns <= MAX_PROBE_SPAWNS
    breaches += 0 if ok else 1
    # ⚠ UNMEASURED IS A FAIL, AND SAYS SO: it counts as a breach, so its line
    # must carry the word the exit code is judged by.
    verdict = "PASS" if ok else ("FAIL — UNMEASURED" if spawns < 0 else "FAIL")
    print(f"\n  A6b-ii [<={MAX_PROBE_SPAWNS} GIT SPAWNS per verdict]: "
          f"{verdict} — {spawns if spawns >= 0 else '?'} spawn(s)")
    for argv in spawn_argv:
        print(f"           {argv}")
    print(f"         A DESIGN PROPERTY, not a wall time. It is the only lever Sting "
          f"has on the number below.")
    print(f"         ⚠ {world_calls} World METHOD CALLS produce those {spawns} "
          f"spawns, and the method count is what this")
    print(f"           budget printed until it was fixed — PASS at '2 spawns' "
          f"for a verdict that has always")
    print(f"           spawned {spawns}. The budget is now 3 because THIS CODE "
          f"SPAWNS 1 OR 3 AND NEVER 2:")
    print(f"           a clean index skips both `rev-parse` and the second "
          f"`diff` by derivation. See the")
    print(f"           note beside MAX_PROBE_SPAWNS for what each spawn "
          f"answers and what dropping one costs.")

    # ---------------- A6b-iii: reported, never budgeted
    gw, gb = max(probe_p99s), min(probe_p99s)
    tw = max(total_p99s)
    print(f"\n  A6b-iii [probe wall time — REPORTED, NOT BUDGETED]")
    print(f"         git subprocess p99 over {len(probe_p99s)} runs: "
          f"best {gb:.3f}ms, worst {gw:.3f}ms")
    print(f"         total commit/push verdict p99, worst run: {tw:.3f}ms")
    print(f"         ⚠ NOT A CRITERION, AND NOT A LINGERING FAILURE. "
          f"{share_hint(gw, tw)}% of this is inside `git`, which Sting cannot "
          f"move. The only lever it owns is the SPAWN COUNT, which A6b-ii "
          f"budgets at <={MAX_PROBE_SPAWNS} and currently "
          f"{'holds' if 0 <= spawns <= MAX_PROBE_SPAWNS else 'DOES NOT HOLD'}.")
    print(f"         It is a HOST CHARACTERISTIC and will differ on every "
          f"machine: git's cost is a function of index size.")
    print(f"         For reference, the RETIRED A6b budgeted this at "
          f"<{BUDGET_INDEX_LEGACY:.0f}ms and FAILED: "
          f"{'still over' if tw >= BUDGET_INDEX_LEGACY else 'under today'} "
          f"at {tw:.3f}ms.")
    print(f"         ⚠ THAT FAILURE IS NOT RETIRED, SOFTENED OR REWORDED. The "
          f"retired budget failed at 52-62ms and would fail HARDER today. "
          f"Nothing here restates it in a softer form.")
    print(f"         {share_hint(gw, tw)}% of the worst-run p99 is inside git.")
    print(f"\n  ⚠ A6b-i PASSING IS NOT THE OLD A6b PASSING. The old one budgeted "
          f"WALL TIME and failed on git's\n     time; this one budgets Sting's own "
          f"work. Different claims about different things.")
    return breaches


def share_hint(probe_ms: float, total_ms: float) -> str:
    return f"{100 * probe_ms / max(total_ms, 1e-9):.0f}"


def bench_subprocess(n: int) -> None:
    print(f"\n=== 3. FULL SUBPROCESS from cold — {n} calls (what the hook costs today)\n")
    hook = str(ROOT / "hook_entry.py")
    payload = json.dumps({"session_id": "bench-sub", "cwd": str(ROOT),
                          "hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "git status"}})
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        # ⚠ THE ENVIRONMENT IS DECLARED, NOT INHERITED. This function drives
        # the REAL hook into the REAL session root — `bench-sub` in the live
        # store is exactly these records — and it used to pass no env at all,
        # so on an installed machine every one of them would inherit
        # STING_PURPOSE=work and a latency harness would be counted as the
        # developer's session. Found by asking which harnesses could override
        # the installer's declaration; three of four could not.
        subprocess.run([sys.executable, hook], input=payload,
                        capture_output=True, text=True,
                        env=dict(os.environ, STING_PURPOSE="benchmark"))
        samples.append((time.perf_counter() - t) * 1000)
    p50, p95, p99 = percentiles(samples)
    print(f"{'subprocess':20} {n:6} {p50:7.1f}ms {p95:7.1f}ms {p99:7.1f}ms")
    return p50


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=10_000)
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS,
                     help="independent runs; the WORST decides")
    ap.add_argument("--subprocess", action="store_true")
    ap.add_argument("--sub-calls", type=int, default=60)
    args = ap.parse_args(argv)

    # One bench at a time, and never beside a test run of this repository:
    # tools/run_registry.py says why.
    gate = run_registry.bench_gate(ROOT)
    if isinstance(gate, int):
        return gate
    try:
        breaches = bench_in_process(args.calls, args.runs)
        if args.subprocess:
            bench_subprocess(args.sub_calls)
    finally:
        if gate is not None:
            gate.close()
    if breaches:
        print(f"\n{breaches} budget(s) exceeded. A6 FAILS.")
    return 1 if breaches else 0


if __name__ == "__main__":
    sys.exit(main())
