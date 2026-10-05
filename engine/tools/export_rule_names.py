#!/usr/bin/env python3
"""Generate `rule_names.json` from core/rule_names.py, for other repositories.

    python3 tools/export_rule_names.py --out rule_names.json

⚠ WHY A GENERATED ARTIFACT RATHER THAN A HAND-KEPT LIST. The panel and the
collector are separate repos and cannot import this one. A list typed there is a
list that can disagree with the ids it describes, and the copy a READER sees
would be the wrong one — a stale name beside a live verdict is worse than a raw
id, because the raw id is obviously machine text and invites a lookup while a
confident wrong sentence does not.

This is a copy that cannot drift, because nobody types it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import rule_names                                      # noqa: E402


def payload() -> dict:
    return {
        "generated_from": "core/rule_names.py",
        "note": ("Generated. Do not hand-edit: the engine mints rule ids, so a "
                  "second list anywhere else can drift from the ids it "
                  "describes. Re-run tools/export_rule_names.py instead."),
        "families": {family: {"title": title, "why": why}
                      for family, (title, why) in rule_names.RULE_FAMILIES.items()},
        "sinks": dict(rule_names.SINK_MEANINGS),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)
    text = json.dumps(payload(), indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"  wrote {args.out}  "
               f"({len(rule_names.RULE_FAMILIES)} families, "
               f"{len(rule_names.SINK_MEANINGS)} sinks)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
