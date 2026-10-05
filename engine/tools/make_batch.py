#!/usr/bin/env python3
"""Build and verify the batches decision logs travel in. $0, no network.

    python3 tools/make_batch.py build  <session.log.jsonl> --device <id>
    python3 tools/make_batch.py verify <batch.json> [--continues-from HASH]

⚠ BUILT EXACTLY AS THE SHIPPER BUILDS IT: every record whole, every value Sting
recognises replaced by its type, through `shipper/mask.py`, with the values the
session's own state recognises (the state file beside the log). There are no
tiers any more (28 Sep 2026), so there is nothing to choose.

This does NOT send anything. It is how a person sees, before anything ships,
exactly what a batch of their own log would carry.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import session, wire                                       # noqa: E402
from core.audit_log import GENESIS, read_records                     # noqa: E402
from shipper import config, fingerprint_key, mask                    # noqa: E402


def cmd_build(args: argparse.Namespace) -> int:
    if args.tier is not None:
        print("make_batch: --tier is gone: there are no tiers any more, and every "
              "record ships whole with every value Sting recognises replaced by "
              "its type", file=sys.stderr)
        return 2
    log = Path(args.log)
    state = session.load_session(log.name.split(".")[0], root=log.parent)
    known = mask.session_values(state)
    seen: dict[str, str] = {}
    for record in read_records(log):
        for value, kind in mask.recognised_values(record, known).items():
            seen.setdefault(value, kind)
    known = dataclasses.replace(known, seen=seen)
    # ⚠ KEYED WITH THIS LAPTOP'S KEY, AS THE SHIPPER KEYS IT — read, never made
    # and never printed here: a key this tool made would key nothing that ships.
    key_path = args.key or config.from_env().fingerprint_key_path
    key = fingerprint_key.load(key_path)
    if key is None:
        print(f"make_batch: no fingerprint key at {key_path} "
              f"({fingerprint_key.state(key_path)}); install.py makes it",
              file=sys.stderr)
        return 2
    batch = wire.batch_from_log(log, device_id=args.device,
                                mask=lambda r: mask.mask_record(r, known),
                                fingerprint=wire.fingerprinter(key),
                                continues_from=args.continues_from)
    text = json.dumps(batch, sort_keys=True, indent=None if args.compact else 2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"  wrote {args.out}  ({len(text):,} bytes, {batch['tier']})")
    else:
        print(text)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    batch = json.loads(Path(args.batch).read_text(encoding="utf-8"))
    result = wire.verify_batch(batch, expected_continues_from=args.continues_from)
    print(f"  status        {result['status']}")
    print(f"  records       {result['records']}")
    if "decisions" in result:
        print(f"  decisions     {result['decisions']}")
    # docs/99: only `verified` means the content was checked. Old-format is
    # history; `tampered` and an unknown version also make `status` broken.
    print(f"  content       {result.get('content')}")
    if result.get("detail"):
        print(f"  detail        {result['detail']}")
    for problem in result.get("problems", []):
        print(f"  ⚠ {problem}")
    print(f"\n  device        {batch.get('device_id')}")
    print(f"  session       {batch.get('session_id')}")
    print(f"  tier          {batch.get('tier')}")
    print(f"  seq range     {batch.get('seq_range')}")
    manifest = batch.get("manifest", {})
    print(f"  agent / os    {manifest.get('agent')} / {manifest.get('os')}")
    print(f"  guard ref     {manifest.get('guard_ref')}")
    print(f"  canary        {manifest.get('canary_present')}")
    print("\n  what this batch does and does not attest:")
    for key, value in batch.get("provenance", {}).items():
        print(f"    {key:42} {value}")
    print(f"\n  ends at       {result.get('ends_at', '')[:16]}…"
          "   <- pass to the next batch as --continues-from")
    return 0 if result["status"] in ("intact", "nothing to verify") else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build")
    b.add_argument("log")
    b.add_argument("--device", required=True)
    # Gone, and said so in one line rather than as argparse's usage error.
    b.add_argument("--tier", default=None, help=argparse.SUPPRESS)
    b.add_argument("--continues-from", default=GENESIS)
    b.add_argument("--key", type=Path, default=None,
                   help="the fingerprint key file (default: this laptop's, "
                        "~/.sting/.env.fingerprint)")
    b.add_argument("--out")
    b.add_argument("--compact", action="store_true")
    b.set_defaults(func=cmd_build)

    v = sub.add_parser("verify")
    v.add_argument("batch")
    v.add_argument("--continues-from", default=None)
    v.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
