"""Print the Feeder B stress corpus as a table, by name.

    python3 runner/stress_known_formats.py

Exit 0 only if every positive is caught on every surface and every negative
is held. The same corpus is asserted by tests/test_known_formats_stress_corpus.py;
this is the readable form for a report.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.known_formats import FORMATS, find_known_secret        # noqa: E402
from known_formats_corpus import (EVASIONS, FORMAT_IDS, NEGATIVES,  # noqa: E402
                                  SURFACES, embed, make_key)


def main() -> int:
    failures = 0
    print(f"POSITIVES — {len(FORMAT_IDS)} formats × {len(SURFACES)} surfaces")
    for fid in FORMAT_IDS:
        key = make_key(fid)
        cells = []
        for surface in SURFACES:
            hit = find_known_secret(embed(surface, key))
            ok = hit is not None and hit.format_id == fid
            failures += not ok
            cells.append("caught" if ok else "MISSED")
        print(f"  {fid:32s} " + "  ".join(f"{s}:{c}" for s, c in zip(SURFACES, cells)))
    print(f"\nNEGATIVES — {len(NEGATIVES)} classes (bare, and on each surface)")
    for name, text in NEGATIVES:
        flagged = [s for s in ("bare",) + SURFACES
                   if find_known_secret(text if s == "bare" else embed(s, text))]
        failures += bool(flagged)
        print(f"  {name:44s} " + ("held" if not flagged else f"FLAGGED on {flagged}"))
    print(f"\nEVASIONS — {len(EVASIONS)} shapes the security review found")
    for name, text in EVASIONS:
        caught = find_known_secret(text) is not None
        failures += not caught
        print(f"  {name:44s} " + ("caught" if caught else "EVADED"))
    print(f"\nformats shipped: {len(FORMATS)}   failures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
