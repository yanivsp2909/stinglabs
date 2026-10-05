#!/usr/bin/env python3
"""
Delete local records the COLLECTOR has said it stored. $0, no network.

    python3 tools/prune_shipped.py                 # report only, changes nothing
    python3 tools/prune_shipped.py --apply
    python3 tools/prune_shipped.py --apply --keep-days 14

⚠ THE CURSOR IS NOT PERMISSION, AND THAT IS THE WHOLE DESIGN.

`shipper/run.py` advances the cursor in TWO places. One is a 200/202 from the
collector. The other is `_split`, which steps over a single record the collector
REFUSED as too large — no round trip, nothing stored. A prune written against
the cursor would therefore delete the one record proven not to be at the
collector, which is evidence destroyed by the thing meant to keep it.

So this reads a different mark. `Cursor.acknowledge()` is written only from the
collector's own response body — its `records_stored` and its `batch_ref` — and
`Cursor.note_skipped()` names every seq the loop stepped over. Nothing here
trusts a count this side computed.

WHAT IS REFUSED, AND WHY EACH ONE IS NOT PARANOIA:

  * `gaps > 0`          a 202 means the collector is MISSING earlier batches.
                        Records below the cursor did not arrive. Pruning them
                        deletes exactly what the gap was reporting.
  * a skipped seq       stops the prefix dead. Everything after it stays too,
                        because "acknowledged" past a hole is a claim about the
                        hole as well.
  * newer than KEEP     a floor in days, so a developer can read what just
                        happened without a network round trip.
  * an unverifiable log if the chain does not verify BEFORE the prune, this
                        tool will not be the thing that rewrote it.

WHAT IT CANNOT DO. A local manifest is not proof against someone with write
access — the chain never gave that locally, and `verify_log.py` says so about
tail truncation. The manifest makes an HONEST prune distinguishable from a
dishonest one and writes down which receipt authorised it. That is the claim.

⚠ AND IT TRUSTS `cursor.json` WITHOUT ASKING ANYONE. There is no network here by
design, so a cursor restored from a backup, kept across a device
re-registration, or surviving a collector-side reset is believed verbatim — it
carries no device or token binding. The receipts it holds may name batches the
collector no longer has. That is a different failure from a forged manifest and
neither is detectable locally; confirming `last_batch_ref` against the collector
would need a reader credential this tool deliberately does not want.

⚠ RECOVERING FROM A CRASH BETWEEN THE TWO WRITES. The manifest is written
first, then the log — the safer order, because the reverse would leave a
truncated log with nothing declaring why. A crash exactly between them leaves a
manifest whose `starts_from` names a record that is still present. The log then
reports a break at record 1 and this tool refuses it forever after, which is
loud but stuck. The fix is by hand and is one of two:

    the log still starts at GENESIS  ->  drop the last entry from
                                          <log>_pruned.json; nothing was removed
    the log starts mid-chain         ->  the truncation completed; the manifest
                                          is already correct, look for a second
                                          cause
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import locking                                                # noqa: E402
from core.audit_log import (LOG_SUFFIX, is_derived, parse_records,      # noqa: E402
                            prune_manifest_for, pruned_start, read_fd,
                            verify_records)
from core.session import default_root                                   # noqa: E402

KEEP_DAYS_DEFAULT = 7
"""⚠ A FLOOR, NOT A TARGET. The collector is the archive; this window exists so
that reading what just happened does not require the network, a token, and a
reader role. Seven days is the span of one investigation."""


def cursor_file() -> Path:
    """Where the shipper keeps its cursor, resolved the way the shipper does."""
    from shipper import config as scfg

    return scfg.from_env().state_root / "cursor.json"


def read_cursor(path: Path) -> tuple[dict, str | None]:
    """The cursor's sessions, and WHY they are empty when they are.

    ⚠ AN UNREADABLE CURSOR AUTHORISES NOTHING. Empty means every log is skipped
    for want of a receipt, which is the safe direction for a deleter. It is not
    a safe thing to be SILENT about in a report — `{}` and "nothing was ever
    shipped" look identical to a reader — so the reason travels with the empty
    dict and `tools/retention.py` prints it.
    """
    if not path.is_file():
        return {}, f"no shipper cursor at {path}"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {}, f"the shipper cursor at {path} could not be read ({exc})"
    # ⚠ CHECKED BEFORE ANY `or {}`. A `sessions` of false/null/[] would
    # otherwise normalise to an empty table and read as "nothing shipped yet",
    # with no problem to print — the quiet shape of wrong.
    sessions = data.get("sessions") if isinstance(data, dict) else None
    if not isinstance(sessions, dict):
        return {}, f"the shipper cursor at {path} has no sessions table"
    return sessions, None


def _cursor_positions() -> dict:
    """The shipper's own cursor, read the way the shipper resolves it."""
    return read_cursor(cursor_file())[0]



def _eligible(records: list, position: dict, keep_before: float) -> tuple:
    """How many leading records may go, and why it stopped there.

    ⚠ EVERY EXIT IS BOUNDED BY `shipped`, not only the one that falls out of the
    loop — an early return that skipped the bound was the same bug in a second
    place. See `_walk` for what the bound is for.
    """
    count, why = _walk(records, position, keep_before)
    # ⚠ NEVER PAST WHAT THE LOOP PHYSICALLY WALKED. `shipped` is an INDEX —
    # `run.py:117` slices `read_records(path)[position.shipped:]` — while `seq`
    # is a value that repeats. Bounding on seq alone deleted a never-shipped
    # record that merely shared a seq with an acknowledged one; an allow-once
    # override is exactly that shape, and it is the record whose whole purpose
    # is proving a human, not the policy, made the final call.
    walked = int(position.get("shipped") or 0)
    if count > walked:
        return walked, f"only {walked} record(s) were ever walked by the shipper"
    return count, why


def stored_prefix(records: list, position: dict) -> tuple[int, str]:
    """How many leading records the COLLECTOR provably stored, and why the
    count stopped where it did.

    ⚠ THE ONE PREDICATE, SHARED. This tool deletes on it and
    `tools/retention.py` reports on it, so the report a human runs `rm` from
    cannot disagree with the deleter — which it did (B3, docs/77): retention
    read the loop's `shipped` and printed `all` for a session the collector had
    acknowledged through seq 5 of 8. Nothing here reads `shipped`; `_eligible`
    is where that bound applies, and it is a bound, not a receipt.
    """
    # ⚠ THE CURSOR IS A FILE, AND A FILE CAN BE WRONG. A hand-edited or
    # corrupted entry used to raise out of here — a traceback instead of a
    # verdict, and for the deleter's run, an abort that may already have
    # rewritten earlier logs. Every malformed shape is a verdict of 0, named.
    if not isinstance(position, dict):
        return 0, (f"the cursor entry is not a table "
                    f"({type(position).__name__}) — malformed, nothing is stored")
    acked = position.get("acked_seq")
    if acked is None:
        return 0, "the collector has never acknowledged a batch for this session"
    try:
        acked = int(acked)
    except (TypeError, ValueError):
        return 0, f"acked_seq {acked!r} is not a number — the cursor entry is malformed"
    if position.get("gaps"):
        return 0, (f"{position['gaps']} gap(s) reported — the collector is "
                    f"missing earlier batches, and these may be them")
    try:
        skipped = {int(s) for s in (position.get("skipped_seqs") or [])}
    except (TypeError, ValueError):
        return 0, "skipped_seqs holds a non-number — the cursor entry is malformed"
    if not records:
        return 0, "the log holds no records"

    count = 0
    seen_seqs = set()
    for rec in records:
        seq = rec.get("seq")
        if seq is None or "_unparseable" in rec:
            return count, "a record without a usable seq"
        try:
            seq = int(seq)
        except (TypeError, ValueError):
            # ⚠ A HARD STOP FOR THIS LOG, NOT A CRASH FOR THE RUN. `main()`
            # loops over every log; an unparseable seq in one must not abort a
            # pass that may already have rewritten earlier ones.
            return count, f"seq {rec.get('seq')!r} is not a number"
        if seq in skipped:
            return count, (f"seq {seq} was stepped over by _split and is stored "
                            f"NOWHERE — it and everything after it stay")
        if seq in seen_seqs:
            # ⚠ SEQ IS NOT UNIQUE, AND THIS TOOL COMPARES AGAINST IT.
            # `identity()` is (session, seq, action_hash, EVENT) precisely
            # because allow-once writes a SECOND record at the SAME seq with
            # event="allow_once_used" — the record proving a human overruled the
            # policy. Two hooks appending have also doubled logs here before.
            # A repeat inside the window means `seq <= acked` can no longer be
            # read as "this record was acknowledged".
            return count, (f"seq {seq} occurs twice — seq is not unique "
                            f"(allow-once overrides reuse it), so the "
                            f"acknowledged mark cannot speak for this record")
        seen_seqs.add(seq)
        if seq > acked:
            return count, f"seq {seq} is past the acknowledged mark ({acked})"
        count += 1
    return count, "the collector acknowledged every record"


def _walk(records: list, position: dict, keep_before: float) -> tuple:
    """The per-record scan. Bounded by its caller.

    `stored_prefix` is the collector's evidence. This adds the two things that
    are the DELETER's business and not the report's: the keep window, a floor
    in days; and the final record, which `_last_hash` reads to chain the next
    append and which therefore never goes.
    """
    count, why = stored_prefix(records, position)
    for index, rec in enumerate(records[:count]):
        ts = rec.get("ts")
        if isinstance(ts, (int, float)) and ts >= keep_before:
            return index, "inside the keep window"
    # ⚠ NEVER THE WHOLE FILE. The last record is what `_last_hash` reads to
    # chain the next append; deleting it would restart the chain from GENESIS
    # mid-session and make the log look like a different, shorter session.
    if count >= len(records):
        return len(records) - 1, "all but the final record, which anchors the chain"
    return count, why



def _write_manifest(log: Path, removed: list, position: dict) -> None:
    manifest = prune_manifest_for(log)
    entries = []
    if manifest.is_file():
        try:
            entries = json.loads(manifest.read_text(encoding="utf-8")).get("prunes") or []
        except (OSError, json.JSONDecodeError):
            entries = []
    entries.append({
        "at": time.time(),
        "removed": len(removed),
        "first_seq": removed[0].get("seq"),
        "last_seq": removed[-1].get("seq"),
        # the hash the log now legitimately starts from
        "starts_from": removed[-1].get("hash"),
        # ⚠ THE RECEIPT THAT AUTHORISED IT, quotable back at the collector
        "authorised_by": {
            "acked_seq": position.get("acked_seq"),
            "acked_records": position.get("acked_records"),
            "last_batch_ref": position.get("last_batch_ref"),
            "acked_at": position.get("acked_at"),
        },
    })
    payload = json.dumps({"log": log.name, "prunes": entries},
                          sort_keys=True, indent=1)
    tmp = manifest.with_suffix(f".tmp{secrets.token_hex(4)}")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, manifest)


def _restore_manifest(manifest: Path, prior: bytes | None) -> None:
    """Put the manifest back the way it was before this prune claimed anything.

    ⚠ THE MANIFEST MUST NOT SAY "PRUNED" ABOUT A LOG THAT WAS NOT. The manifest
    is written first and the log replaced second, so a log replace that RAISES
    — `os.replace` refused by a Windows mandatory lock, ENOSPC, EPERM — leaves
    a manifest whose `starts_from` the log does not have. `verify_chain` then
    reports a break at record 1: loud, but a false tamper, on every `--apply`
    that fails the same way. A raised failure is one this process is still
    alive to undo, so it undoes it. (A process that DIES between the two writes
    cannot, and that window is pre-existing and stated in docs/73.)
    """
    if prior is None:
        try:
            manifest.unlink()
        except FileNotFoundError:
            pass
        return
    tmp = manifest.with_suffix(f".tmp{secrets.token_hex(4)}")
    tmp.write_bytes(prior)
    os.chmod(tmp, 0o600)
    os.replace(tmp, manifest)


def _rewrite(log: Path, keep_lines: list) -> None:
    """tmp + rename, exactly as the cursor does. A crash here must not leave a
    half-written log — the file this tool exists to preserve."""
    tmp = log.with_suffix(f".tmp{secrets.token_hex(4)}")
    tmp.write_text("".join(keep_lines), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, log)


def prune(log: Path, positions: dict, keep_days: int, apply: bool) -> dict:
    session = log.name[:-len(LOG_SUFFIX)] if log.name.endswith(LOG_SUFFIX) else log.stem
    out = {"log": log, "removed": 0, "why": "", "bytes": 0}

    if is_derived(log):
        out["why"] = "derived (redacted) log — not evidence, not pruned here"
        return out
    position = positions.get(session)
    if not position:
        out["why"] = "no cursor entry for this session"
        return out

    # ⚠ EVERYTHING FROM HERE TO THE REPLACE HAPPENS UNDER ONE EXCLUSIVE LOCK ON
    # THE LOG — the same lock, taken the same way, as `audit_log.append()`.
    #
    # This used to be four separate opens: three shared-locked reads and then
    # an UNLOCKED `log.read_text()` followed by an unlocked `os.replace`. A hook
    # append that landed between that read and that replace was overwritten by
    # the stale snapshot — silently, in the file that exists to be evidence.
    # "Two shippers plus pruning is permanent loss" is the lesson on file, and
    # the lock has to cover the READ: a lock around the replace alone still
    # replaces with a snapshot taken before the append.
    #
    # ⚠ READ THROUGH THIS fd, NEVER THROUGH THE PATH. `read_records(path)` and
    # `verify_chain(path)` each open a second file description and take a
    # SHARED lock on it — which waits on the exclusive lock held right here.
    # That is a deadlock, not a race. `read_fd` / `parse_records` /
    # `verify_records` are the same code, fed the bytes already in hand, so the
    # records counted and the lines rewritten are one read of one snapshot.
    #
    # ⚠ THE REPLACE STAYS INSIDE THE LOCK. Releasing before `os.replace`
    # reopens the exact window this closes. tmp+rename is kept because an
    # in-place truncate-and-write would let a crashed prune leave the evidence
    # file cut in half. The hook's side of the resulting inode swap — a hook
    # that opened the old file and waited — is closed in `append()`, which
    # re-checks the name after it acquires. Native Windows, where `os.replace`
    # over a file this process holds a mandatory lock on is untested here, is
    # not the supported path (WSL is), and CI's Windows job is a measurement.
    try:
        fd = os.open(log, os.O_RDWR)
    except OSError as exc:
        out["why"] = f"could not open the log ({exc}) — nothing rewritten"
        return out
    # ⚠ EXCLUSIVE ONLY WHEN IT WILL WRITE. A report (`--apply` absent — the
    # default invocation) reads and decides and touches nothing, so it takes
    # the SHARED lock: it still cannot see a torn line, and it does not stall
    # every hook on the machine for the length of a full read-and-verify of a
    # log that has no size cap. On Windows there is no shared mode and this is
    # exclusive either way — correctness is identical, only contention differs.
    take = locking.exclusive if apply else locking.shared
    try:
        try:
            with take(fd):
                raw = read_fd(fd).decode("utf-8", "replace")
                records = parse_records(raw)

                head = records[:1]
                if head and head[0].get("session_id") not in (None, session):
                    # `STING_LOG` lets a harness name the file, and a renamed
                    # or merged log would otherwise borrow a foreign session's
                    # receipts.
                    out["why"] = (f"log contains session "
                                   f"{head[0].get('session_id')!r}, "
                                   f"not {session!r}")
                    return out

                ok, bad, detail = verify_records(records, pruned_start(log))
                if not ok:
                    # ⚠ REFUSED, LOUDLY. A log that already fails to verify is
                    # the one case where rewriting it destroys the evidence of
                    # what went wrong.
                    out["why"] = (f"⚠ chain does not verify ({detail}) — "
                                   f"refusing to rewrite")
                    return out

                count, why = _eligible(records, position,
                                       time.time() - keep_days * 86400)
                out["why"] = why
                if count <= 0:
                    return out

                lines = raw.splitlines(True)
                if len(lines) != len(records):
                    out["why"] = ("line count does not match record count — "
                                   "refusing to rewrite a file this tool does "
                                   "not fully understand")
                    return out

                out["removed"] = count
                out["bytes"] = sum(len(ln.encode("utf-8"))
                                   for ln in lines[:count])
                if apply:
                    manifest = prune_manifest_for(log)
                    prior = manifest.read_bytes() if manifest.is_file() else None
                    _write_manifest(log, records[:count], position)
                    try:
                        _rewrite(log, lines[count:])
                    except OSError:
                        # The log was NOT replaced. Take back the claim the
                        # manifest just made about it, then let the failure
                        # be seen — a swallowed one here would report a prune
                        # that did not happen. See _restore_manifest.
                        _restore_manifest(manifest, prior)
                        raise
                return out
        except locking.LockUnavailable as exc:
            # A hook is mid-append and would not let go in time. Refusing is
            # the honest failure. Proceeding would be the unserialised
            # read-modify-write this lock exists to prevent — `LockUnavailable`
            # says so itself: never downgraded into "carry on".
            out["why"] = (f"⚠ could not take the log's lock ({exc}) — another "
                           f"writer is on it; refusing to rewrite")
            return out
    finally:
        os.close(fd)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=None)
    ap.add_argument("--keep-days", type=int, default=KEEP_DAYS_DEFAULT)
    ap.add_argument("--apply", action="store_true",
                     help="actually delete; without it nothing is written")
    args = ap.parse_args(argv)

    root = Path(args.root) if args.root else default_root()
    logs = sorted(root.rglob(f"*{LOG_SUFFIX}"))
    if not logs:
        print(f"no logs under {root}")
        return 2

    positions = _cursor_positions()
    if not positions:
        print("⚠ the shipper's cursor holds no acknowledged position for any "
               "session. Nothing here has a receipt, so nothing may be deleted.")
        return 0

    total_removed = total_bytes = 0
    print(f"{'log':46} {'gone':>6} {'bytes':>10}   why")
    for log in logs:
        r = prune(log, positions, args.keep_days, args.apply)
        total_removed += r["removed"]
        total_bytes += r["bytes"]
        print(f"{log.name[:46]:46} {r['removed']:6,} {r['bytes']:10,}   {r['why']}")

    verb = "removed" if args.apply else "WOULD remove (dry run — pass --apply)"
    print(f"\n{verb}: {total_removed:,} records, {total_bytes:,} bytes")
    print(f"keep window: {args.keep_days} days · authorised only by the "
           f"collector's own receipts")
    if not args.apply:
        print("⚠ nothing was written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
