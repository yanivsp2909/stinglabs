#!/usr/bin/env python3
"""Where a hook invocation's wall time goes, split four ways.

    python3 tools/bench_startup.py
    python3 tools/bench_startup.py --calls 60 --importtime

    bare interpreter startup   `python3 -c pass`
    engine import              the same, plus exactly what hook_entry imports
    the rest                   the full round trip, minus the two above
    total                      hook_entry.py driven from cold, end to end

⚠ WHY THIS FILE EXISTS. The split it produces has been quoted for several passes
— 15.7 / 24.3 / 11.2 / 51.2 ms — and PROGRESS.md records it as four numbers with
NO COMMAND BESIDE THEM. A measurement nobody can re-run is a claim, and this
project's own rule 11 says a number is not a measurement until the thing it
counts and the population it counts over are both stated. The daemon decision
rests on this split: it says 78% of per-call cost is startup. That figure has to
be reproducible before it can justify building anything.

⚠ WHAT EACH ARM MEASURES, AND THE SUBTRACTION IT DEPENDS ON.

`bare` and `import` are both full subprocess round trips as seen by the PARENT,
so they share a basis, and `import` - `bare` is the cost of reaching the engine.
That subtraction is the whole point: a Go client removes `bare` and CANNOT remove
`import`, because it still has to reach an engine that imports. The daemon
removes both. Keeping them as separate arms is what makes those two claims
different numbers rather than one number argued about.

`total` drives the REAL hook_entry.py with a real payload, so it includes the
session lock, the audit-chain append and the fsync — the things the two floors
deliberately exclude. `rest` is what is left, and it is the only part of the four
that is a residual rather than a measurement. It is labelled as such.

⚠ THE SESSION ROOT IS ISOLATED AND THE PURPOSE IS DECLARED. `bench_latency.py`
learned this the hard way: driving the real hook with an inherited environment
writes the harness's own records into the developer's live store and counts them
as their session. Here the store is a temp directory that is removed afterwards,
so the arm measures the same code without leaving 60 records behind. That does
make the log START empty, which is stated rather than hidden: `_tail_lines` has
less to read on call 1 than on call 60, and the log grows across the run exactly
as a real session's does.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from tools import run_registry                                # noqa: E402

# Exactly what hook_entry.py imports at module scope, in its order. Kept in step
# with it by a test — an import that this list misses is time the split would
# attribute to "the rest", which is the residual and would absorb it silently.
IMPORT_SRC = (
    "import sys; sys.path.insert(0, %r)\n"
    "from adapters import ADAPTERS_BY_NAME\n"
    "from adapters import antigravity, claude_code, codex, copilot, cursor\n"
    "from core import allow_once, audit_log, engine, probes\n"
    "from core.session import open_session\n"
    "from core.types import Decision, Verdict\n"
) % str(ROOT)

PAYLOAD = json.dumps({
    "session_id": "bench-startup",
    "cwd": str(ROOT),
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "git status"},
})


def p50(samples: list[float]) -> float:
    # ⚠ rule 13 / F2: a median over nothing is not a small number, it is a
    # crash or a lie depending on the statistic. Say so rather than return 0.
    if not samples:
        raise RuntimeError("no samples — refusing to report a percentile over "
                           "an empty population")
    return statistics.median(samples)


def _run(argv: list[str], calls: int, *, stdin: str | None = None,
         env: dict | None = None) -> list[float]:
    samples = []
    for _ in range(calls):
        t = time.perf_counter()
        subprocess.run(argv, input=stdin, capture_output=True, text=True,
                       env=env)
        samples.append((time.perf_counter() - t) * 1000)
    return samples


def measure(calls: int) -> dict[str, float]:
    py = sys.executable
    store = tempfile.mkdtemp(prefix="sting-startup-")
    # ⚠ DECLARED, NOT INHERITED — see the module docstring. STING_OBSERVE is
    # cleared too: a shell with it exported would measure the observe path,
    # which returns earlier, and the split would quietly describe a different
    # code path than the one it names.
    env = dict(os.environ,
               STING_SESSION_ROOT=store,
               STING_LOG=str(Path(store) / "logs"),
               STING_PURPOSE="benchmark")
    # ⚠ SET, NOT POPPED. Since settings moved into `~/.sting/env`, popping a
    # variable no longer removes it — `envfile.load` fills any key the
    # environment does not hold, so a developer's own `STING_OBSERVE='1'` walked
    # back in from the file and the benchmark measured the observe path while
    # naming the enforcing one. Same defect as tools/preflight.py's semantic
    # probe; found in the same sweep.
    env["STING_OBSERVE"] = "0"
    try:
        bare = _run([py, "-c", "pass"], calls)
        imported = _run([py, "-c", IMPORT_SRC], calls)
        total = _run([py, str(ROOT / "hook_entry.py")], calls,
                     stdin=PAYLOAD, env=env)
    finally:
        shutil.rmtree(store, ignore_errors=True)

    b, i, t = p50(bare), p50(imported), p50(total)
    return {"bare": b, "import": i - b, "rest": t - i, "total": t}


def _run_traced(argv: list[str], calls: int, *, stdin: str,
                env: dict) -> tuple[list[float], int]:
    """Time each call AND count how many the daemon served."""
    samples, served = [], 0
    for _ in range(calls):
        t = time.perf_counter()
        done = subprocess.run(argv, input=stdin, capture_output=True,
                              text=True, env=env)
        samples.append((time.perf_counter() - t) * 1000)
        if "served by the daemon" in done.stderr:
            served += 1
    return samples, served


def with_daemon(calls: int) -> dict[str, float]:
    """The same round trip, against a WARM resident daemon.

    ⚠ THE FIRST CALL IS EXCLUDED, AND SAID SO. It starts the daemon and then
    decides in-process, so it is a cold call by construction. Including it in a
    median of 40 would move the median by nothing and the story by a lot — this
    is the number that answers "what does a tool call cost once the daemon is
    up", and the cold number is reported separately because it is a different
    question.
    """
    import shutil
    import tempfile

    root = tempfile.mkdtemp(prefix="sting-warm-")
    env = dict(os.environ,
               STING_SESSION_ROOT=root,
               STING_LOG=os.path.join(root, "decisions.jsonl"),
               STING_PURPOSE="benchmark")
    env["STING_OBSERVE"] = "0"          # set, not popped — see with_daemon's twin above
    # ⚠ SO THE ARM CAN NAME ITS OWN POPULATION. Every call says which path
    # served it, and a sample containing one fallback is refused rather than
    # reported as the daemon's.
    env["STING_DAEMON_TRACE"] = "1"
    entry = os.path.join(ROOT, "sting_hook.py")
    server = os.path.join(ROOT, "daemon", "server.py")
    proc = subprocess.Popen([sys.executable, server], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        sock = os.path.join(root, "daemon.sock")
        deadline = time.time() + 30
        while time.time() < deadline and not os.path.exists(sock):
            time.sleep(0.02)
        if not os.path.exists(sock):
            raise RuntimeError("the daemon never published a socket")

        cold = _run([sys.executable, entry], 1, stdin=PAYLOAD, env=env)
        warm, served = _run_traced([sys.executable, entry], calls,
                                   stdin=PAYLOAD, env=env)
        # ⚠ PROOF THAT THE DAEMON ACTUALLY SERVED THEM, RATHER THAN AN
        # INFERENCE FROM THE SOCKET STILL BEING THERE. A fallback in this
        # sample would make the arm report the slow path under the fast path's
        # name — a number from a population that does not contain the thing
        # being measured, which is the error this repo has made most often.
        if served != calls:
            raise RuntimeError(
                f"only {served} of {calls} calls were served by the daemon; "
                f"refusing to report a warm figure over a mixed population")
        return {"warm": p50(warm), "first": cold[0], "served": served}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:                              # noqa: BLE001
            proc.kill()
        shutil.rmtree(root, ignore_errors=True)


def importtime() -> None:
    """Which imports cost what. Attribution, for when the total moves."""
    print("\n=== per-module import cost (python3 -X importtime, cumulative us)\n")
    out = subprocess.run([sys.executable, "-X", "importtime", "-c", IMPORT_SRC],
                         capture_output=True, text=True)
    rows = []
    for line in out.stderr.splitlines():
        if not line.startswith("import time:"):
            continue
        parts = line.split("|")
        if len(parts) != 3 or "cumulative" in parts[1]:
            continue
        try:
            rows.append((int(parts[1].strip()), parts[2].strip()))
        except ValueError:
            continue
    rows.sort(reverse=True)
    shown = [r for r in rows if r[1].startswith(("core", "adapters"))][:12]
    for us, name in shown:
        print(f"    {us / 1000:7.1f} ms   {name}")
    if not shown:
        print("    (no core/adapters rows — importtime output not as expected)")


# The figures this replaces, so a reader never has to go and find them.
LAST = {"bare": 15.7, "import": 24.3, "rest": 11.2, "total": 51.2}

# ⚠ ONLY THE TOTAL IS COMPARABLE TO `LAST`, AND THE LINES ARE NOT.
#
# The 11 Aug split has no recorded method — which is why this file exists. Run
# here, the `import` line comes out ~11 ms above it and the `rest` line ~11 ms
# below, which reads like an 11 ms regression in the engine's import and is not
# one. Settled by measuring with ONE instrument at both commits, in a worktree:
#
#     core import, 0cd29ee~1 (before the five hot-path changes)   35.0 ms
#     core import, 541bbe8   (at HEAD)                            35.3 ms
#     moved                                                       +0.3 ms
#
# So the five changes cost NOTHING measurable at import time, and the 11 ms is
# a difference between two instruments rather than between two engines. The old
# `import` arm almost certainly excluded `adapters/`, which this one includes
# because `hook_entry` imports it — measured separately, `core` alone is 34.9 ms
# and `adapters` alone 21.7 ms, and together they are 35.4 ms, because the
# adapters import `core.types` and nearly all of their cost is already paid.
#
# ⚠ WHERE THE FIVE CHANGES DID COST SOMETHING IS A6a, NOT THE IMPORT:
# p99 went 1.844-1.872 ms to 2.152-2.348 ms — real, ~+0.4 ms, and still five
# times inside the 12 ms budget.


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=40)
    ap.add_argument("--importtime", action="store_true")
    ap.add_argument("--daemon", action="store_true",
                     help="also measure a warm resident daemon")
    args = ap.parse_args(argv)

    # One bench at a time, and never beside a test run of this repository:
    # tools/run_registry.py says why.
    gate = run_registry.bench_gate(ROOT)
    if isinstance(gate, int):
        return gate
    try:
        return _report(args)
    finally:
        if gate is not None:
            gate.close()


def _report(args: argparse.Namespace) -> int:
    print(f"=== per-call cost of one hook invocation — p50 of {args.calls} "
          f"subprocess round trips\n")
    now = measure(args.calls)

    print(f"    {'':26} {'now':>9}   {'11 Aug':>9}   {'moved':>9}")
    for key, label in (("bare", "bare interpreter startup"),
                       ("import", "engine import"),
                       ("rest", "everything else (residual)"),
                       ("total", "total")):
        delta = now[key] - LAST[key]
        print(f"    {label:26} {now[key]:6.1f} ms   {LAST[key]:6.1f} ms   "
              f"{delta:+6.1f} ms")

    load = now["bare"] + now["import"]
    print(f"\n    loading the engine = {load:.1f} ms of {now['total']:.1f} ms "
          f"= {100 * load / now['total']:.0f}% of per-call cost")
    print(f"    a Go client removes {now['bare']:.1f} ms and LEAVES "
          f"{now['import']:.1f} ms; a daemon removes both.")
    print(f"\n    ⚠ 'everything else' is a RESIDUAL, not a measurement: it is "
          f"total minus the two\n      floors, so anything the floors miss "
          f"lands here.")

    if args.daemon:
        print(f"\n=== the same call, against a WARM daemon\n")
        d = with_daemon(args.calls)
        floor = now["bare"]
        print(f"    {'in-process (no daemon)':30} {now['total']:6.1f} ms")
        print(f"    {'warm daemon':30} {d['warm']:6.1f} ms   "
              f"{100 * (1 - d['warm'] / now['total']):.0f}% less")
        print(f"    {'first call after a boot':30} {d['first']:6.1f} ms   "
              f"(it starts the daemon, then decides in-process)")
        print(f"    {'daemon-served':30} {int(d['served']):6d} of {args.calls} "
              f"calls, verified per call")
        print(f"\n    ⚠ WHAT REMAINS. Interpreter startup is {floor:.1f} ms of "
              f"the warm {d['warm']:.1f} ms = "
              f"{100 * floor / d['warm']:.0f}%.")
        print(f"      The client's own imports (json, socket) are most of the "
              f"rest; the round trip\n      itself is what is left after both.")

    if args.importtime:
        importtime()
    return 0


if __name__ == "__main__":
    sys.exit(main())
