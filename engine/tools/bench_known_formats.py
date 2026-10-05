"""What Feeder B costs per inspected text, against the A6a budget.

    python3 tools/bench_known_formats.py

Five cases, each timed as a best-of-5 mean over many calls:

    typical      a 200-byte curl with no credential (the prefilter path)
    32 KB clean  the scan bound, no trigger substring anywhere
    32 KB worst  the scan bound, a trigger in every token, the key at the end
    32 KB glue   the same, every token quoted: the glue-stripped pass runs
                 beside the first, as it does for any quoted text since the
                 matcher reads every value (python review)
    32 KB keys   the scan bound packed with distinct valid keys, quoted: what
                 reading every value would cost, and the first does not
                 (security review)

Three columns. `hot path` is what every action pays: `holds_known_secret`,
the yes or no `carries_secret` asks (on a tree from before it, the same
`find_known_secret`, which then answered both). `find_known_secret` is the
leftmost value, asked only once an action carries one. `fingerprints_in` runs
on the same call, and only the sum with the hot path is what an action pays.
"""
from __future__ import annotations

import string
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import engine, known_formats                           # noqa: E402
from core.known_formats import find_known_secret                 # noqa: E402

HOT_PATH = getattr(known_formats, "holds_known_secret", find_known_secret)

TYPICAL = ('curl -s -X POST -H "Content-Type: application/json" '
           '-d \'{"job": "nightly", "ref": "refs/heads/main"}\' '
           "https://ci.example.invalid/api/v4/projects/42/trigger/pipeline")
CLEAN_32K = ("python3 -m pytest tests/test_module_%d.py -q --maxfail=1 && " * 400)[:32 * 1024]
WORST_32K = (("sk-abcdefghij0123456789 skip-this AKIAtoken ghp_placeholder " * 600)
             + " ghp_" + "A" * 30)[:32 * 1024 - 60]
WORST_32K += " AKIA" + "B7C4D2E5F6G7H2J3" + "  "
GLUE_32K = (('"sk-abcdefghij0123456789" "skip-this" "AKIAtoken" "ghp_placeholder" ' * 520)
            + ' "ghp_' + "A" * 30 + '"')[:32 * 1024 - 60]
GLUE_32K += ' "AKIA' + "B7C4D2E5F6G7H2J3" + '"  '
_B32 = string.ascii_uppercase + "234567"
KEYS_32K = " ".join(f'"AKIA{_B32[i // 1024 % 32]}{_B32[i // 32 % 32]}{_B32[i % 32]}'
                    f'B7C4D2E5F6G7H"' for i in range(1400))[:32 * 1024]


def _time(fn, text: str, calls: int) -> float:
    best = float("inf")
    for _ in range(5):
        start = time.perf_counter()
        for _ in range(calls):
            fn(text)
        best = min(best, (time.perf_counter() - start) / calls)
    return best * 1000.0


def main() -> int:
    rows = (("typical 200 B", TYPICAL, 2000), ("32 KB clean", CLEAN_32K, 50),
            ("32 KB worst", WORST_32K, 50), ("32 KB glue", GLUE_32K, 50),
            ("32 KB keys", KEYS_32K, 50))
    print(f"{'case':16s} {'hot path':>10s} {'find_known_secret':>18s} "
          f"{'fingerprints_in':>16s}   (ms per call, best of 5)")
    for label, text, calls in rows:
        hot = _time(HOT_PATH, text, calls)
        ours = _time(find_known_secret, text, calls)
        theirs = _time(engine.fingerprints_in, text, calls)
        print(f"{label:16s} {hot:10.3f} {ours:18.3f} {theirs:16.3f}")
    print("A6a budget: p99 < 12 ms per decision, all kinds except commit/push.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
