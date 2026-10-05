#!/usr/bin/env python3
"""What is on this disk, how old it is, and what could be removed SAFELY.

    python3 tools/retention.py              # what is here, and what it costs
    python3 tools/retention.py --days 14    # what a 14-day policy would remove

⚠ THIS TOOL DELETES NOTHING, AND THAT IS A DECISION RATHER THAN AN UNFINISHED
FEATURE. This codebase's entire subject is irreversible actions, and it prompts a
human before one. A tool that decided on its own to delete a developer's command
history would be doing the thing the guard exists to interrupt — and the logs are
the only real data this project has. So this measures and reports, and a human
runs `rm` on what it names.

────────────────────────────────────────────────────────────────────────────────
⚠ WHOLE SESSIONS ONLY. TRUNCATION IS RULED OUT, AND IT IS RULED OUT BY A
MEASUREMENT RATHER THAN BY TASTE.
────────────────────────────────────────────────────────────────────────────────

Trimming the OLDEST records out of a log — the obvious way to bound a file —
produces this, measured on a real 13-record log:

    HEAD REMOVED       BROKEN  record 1 chains from '0f7e5546…',
                               expected '00000000…'
    ONE RECORD EDITED  BROKEN  record 6 content does not match its hash

Both say BROKEN. The messages differ in shape, so a careful reader CAN tell them
apart — but the shapes are not the point. **Deleting the first N records of a log
is exactly what an attacker removing evidence of an early `.env` read would do**,
and a retention policy that did it routinely would turn that signature into
ordinary housekeeping noise. The first BROKEN a developer learns to ignore is the
last one that means anything.

Trimming the NEWEST records is worse in the other direction:

    TAIL REMOVED       OK, chain intact

— a log that verifies perfectly while missing everything that happened after
some point, with nothing local able to say so.

**Deleting a WHOLE SESSION has neither problem.** The chain is per session, so a
removed file leaves no record whose `prev` points at anything missing; it is
simply absent. Measured: `verify_log` reports OK over what remains and
`replay_live` lists one fewer session. Absence of a session and truncation of one
are different artifacts, and only the first is safe to make routine.

────────────────────────────────────────────────────────────────────────────────
⚠ "SHIPPED" IS NOT "STORED", AND THIS TOOL ONCE SAID `all` FROM THE WRONG ONE
────────────────────────────────────────────────────────────────────────────────

The shipper's cursor keeps TWO marks per session (`shipper/cursor.py`). `shipped`
is how far the LOOP has moved on: `_split` steps it over a record the collector
refused as too large — nothing stored anywhere — and a 202 advances it past
batches the collector says it is MISSING. `acked_seq` moves only on a 200/202
that carries the collector's own `records_stored`, and `skipped_seqs` names every
record the loop stepped over. The deleter, `tools/prune_shipped.py`, reads the
second set and refuses on the first.

This tool read `shipped`, called it "a COUNT of records the collector CONFIRMED
it stored", and printed `all` — its never-shipped warning suppressed — for a
session sent in full and acknowledged through seq 5 of 8. A human deleting on
that word destroys three records that exist nowhere else. B3 of the v1.0.3
audit; docs/77 has the reproduction.

So `stored` here is `prune_shipped.stored_prefix()`: the SAME walk the deleter
makes, over the SAME cursor entry, read the way the shipper resolves it — and
nothing else. It fails toward keeping. No cursor, an unreadable cursor, a session
the collector never acknowledged, a reported gap, a stepped-over record: each is
NOT STORED, with its reason printed beside it, and never `all`. A record kept
too long costs disk; a record deleted on a wrong `all` is gone.

────────────────────────────────────────────────────────────────────────────────
⚠ AND "STORED" IS NOT KNOWABLE ON AN INSTALL WITH NO COLLECTOR
────────────────────────────────────────────────────────────────────────────────

The collector's acknowledgement never moves on an install that never had a
collector — `Cursor.get` returns a fresh `Position()` forever, because nothing
ever answers. That install is supported, and on it **every record is unstored
and always will be**, so a policy of "delete what is stored" removes nothing and
a policy of "delete what is old" removes the only copy in existence.

This tool therefore reports those two populations separately and never conflates
them.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.audit_log import parse_records                             # noqa: E402
from tools import prune_shipped                                      # noqa: E402

LOG_SUFFIX = ".log.jsonl"

NEVER_SEEN = "the shipper has never seen this session"


def session_root() -> Path:
    return Path(os.environ.get("STING_SESSION_ROOT")
                 or "~/.sting/sessions").expanduser()


def collector_configured() -> bool:
    """⚠ FROM THE RECORDED INSTALL, NOT FROM THIS SHELL. A developer running this
    by hand has a different environment from the supervised shipper, and asking
    the shell would report "no collector" on a machine that has one."""
    try:
        from installer import recorded
        env = recorded.read()
    except Exception:                                            # noqa: BLE001
        env = {}
    return bool(env.get("STING_COLLECTOR_URL")
                 or os.environ.get("STING_COLLECTOR_URL"))


def cursor_positions() -> tuple[dict, str | None]:
    """The shipper's cursor, read the way the shipper resolves it, plus WHY it
    is empty when it is. The deleter treats an unreadable cursor as "no receipt
    for anything"; this tool says the same thing, and says it out loud, because
    a reader of this report cannot tell `{}` from "nothing was ever shipped"."""
    return prune_shipped.read_cursor(prune_shipped.cursor_file())


def sidecar_bytes(root: Path, session: str) -> int:
    """The unclipped command text, which is easy to forget and is not small."""
    directory = root / f"{session}{LOG_SUFFIX}.commands"
    if not directory.is_dir():
        return 0
    return sum(f.stat().st_size for f in directory.rglob("*") if f.is_file())


def survey(root: Path, positions: dict | None = None) -> list:
    """One row per log on disk — including the ones this tool cannot read.

    `positions` is the cursor's sessions table. `main` reads it once and passes
    it in, so the rows and the banner above them describe the same file; two
    reads of a file the shipper rewrites can disagree.
    """
    if positions is None:
        positions, _ = cursor_positions()
    now = time.time()
    rows = []
    for log in sorted(root.glob(f"*{LOG_SUFFIX}")):
        session = log.name[:-len(LOG_SUFFIX)]
        try:
            records = parse_records(log.read_text(encoding="utf-8", errors="replace"))
            log_bytes = log.stat().st_size
        except OSError as exc:
            # ⚠ A LOG THIS TOOL CANNOT READ IS STILL ON THE DISK. Dropping it
            # from a report about what is on the disk was the quiet kind of
            # wrong: no row, no bytes, no verdict. It gets a row that says so,
            # and nothing about it is "stored".
            rows.append({"session": session, "records": 0, "log_bytes": 0,
                         "sidecar_bytes": 0, "state_bytes": 0, "last_ts": None,
                         "age_days": None, "stored": None, "unstored": 0,
                         "why": f"the log could not be read ({exc})",
                         "unreadable": True})
            continue
        first = last = None
        for rec in records:
            ts = rec.get("ts")
            if isinstance(ts, (int, float)):
                first = ts if first is None else min(first, ts)
                last = ts if last is None else max(last, ts)
        # ⚠ THE COLLECTOR'S MARKS, WALKED BY THE DELETER'S OWN PREDICATE. A
        # session the cursor has never seen is `None`, not 0: "never seen" and
        # "acknowledged nothing" are different facts, and both mean keep.
        position = positions.get(session)
        if position:
            stored, why = prune_shipped.stored_prefix(records, position)
        else:
            stored, why = None, NEVER_SEEN
        state = root / f"{session}.json"
        rows.append({
            "session": session,
            "records": len(records),
            "log_bytes": log_bytes,
            "sidecar_bytes": sidecar_bytes(root, session),
            "state_bytes": state.stat().st_size if state.exists() else 0,
            "last_ts": last,
            "age_days": None if last is None else (now - last) / 86400,
            "stored": stored,
            "unstored": len(records) - (stored or 0),
            "why": why,
        })
    return rows


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{n:,} B"
        n /= 1024.0
    return f"{n:.1f} GB"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=float, default=None,
                     help="report what a retention of this many days would reach")
    ap.add_argument("--root", default=None)
    args = ap.parse_args(argv)

    root = Path(args.root).expanduser() if args.root else session_root()
    if not root.is_dir():
        print(f"no session root at {root} — nothing is being kept here")
        return 0

    positions, cursor_problem = cursor_positions()     # once: rows and banner agree
    rows = survey(root, positions)
    total = sum(r["log_bytes"] + r["sidecar_bytes"] + r["state_bytes"] for r in rows)
    has_collector = collector_configured()

    print(f"session root   {root}")
    print(f"sessions       {len(rows)}")
    print(f"on disk        {human(total)}  "
           f"(logs {human(sum(r['log_bytes'] for r in rows))}, "
           f"sidecars {human(sum(r['sidecar_bytes'] for r in rows))}, "
           f"state {human(sum(r['state_bytes'] for r in rows))})")
    print(f"collector      {'configured' if has_collector else 'NOT configured'}")
    print()

    print(f"  {'session':38} {'records':>7} {'size':>10} {'age':>8}  stored")
    for r in sorted(rows, key=lambda r: -(r["age_days"] or 0)):
        size = human(r["log_bytes"] + r["sidecar_bytes"] + r["state_bytes"])
        age = "?" if r["age_days"] is None else f"{r['age_days']:.1f}d"
        if r.get("unreadable"):
            ship = f"UNREADABLE — {r['why']}"
        elif not has_collector:
            ship = "n/a"
        elif r["records"] == 0:
            ship = "empty"
        elif r["stored"] is None:
            ship = "never seen"
        elif r["unstored"] == 0:
            ship = "all"
        else:
            ship = f"{r['unstored']} NOT STORED"
        print(f"  {r['session'][:38]:38} {r['records']:7} {size:>10} {age:>8}  {ship}")

    if not has_collector:
        print()
        print("⚠ NO COLLECTOR IS CONFIGURED, so `stored` means nothing here and")
        print("  is not reported. The collector's acknowledgement only moves when")
        print("  a collector CONFIRMS a batch; with none, every record is unstored")
        print("  forever. These files are the only copy that exists.")
    elif cursor_problem:
        # ⚠ LOUD, NOT `{}`. The deleter reads an unreadable cursor as "no receipt
        # for anything" and correctly does nothing; a report that did the same
        # SILENTLY would show every session as "never seen", which a reader
        # can mistake for "nothing was ever sent". Say what was looked for.
        print()
        print(f"⚠ NO SHIPPER CURSOR COULD BE READ — {cursor_problem}.")
        print("  Nothing here is provably stored by the collector, so every session")
        print("  above reads as `never seen`. Fix the cursor before deleting anything.")

    if args.days is not None:
        print()
        reach = [r for r in rows
                  if r["age_days"] is not None and r["age_days"] > args.days]
        freed = sum(r["log_bytes"] + r["sidecar_bytes"] + r["state_bytes"]
                     for r in reach)
        unsafe = [r for r in reach if has_collector and r["unstored"]]
        print(f"A {args.days:g}-day retention would reach {len(reach)} session(s), "
               f"{human(freed)}:")
        for r in reach:
            flag = (f"   ⚠ {r['unstored']} RECORDS THE COLLECTOR NEVER STORED — {r['why']}"
                    if has_collector and r["unstored"] else "")
            print(f"    {r['session'][:38]:38} {r['age_days']:.1f}d{flag}")
        if unsafe:
            print()
            print("  ⚠ SOME OF THOSE ARE NOT PROVABLY STORED BY THE COLLECTOR. Deleting")
            print("    them destroys evidence the tool exists to keep — the only copy")
            print("    that exists — which is a worse outcome than the disk they occupy.")
        if not reach:
            print("    (nothing)")

    print()
    print("⚠ THIS TOOL DELETES NOTHING. To act on the above, remove WHOLE")
    print("  sessions — never lines from a log. Truncating a log leaves a chain")
    print("  that reads as BROKEN, which is the same thing an attacker removing")
    print("  early evidence produces; deleting a whole session leaves nothing")
    print("  dangling, because the chain is per session.")
    print()
    print("    rm ~/.sting/sessions/<session>.log.jsonl \\")
    print("       ~/.sting/sessions/<session>.json \\")
    print("       -r ~/.sting/sessions/<session>.log.jsonl.commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
