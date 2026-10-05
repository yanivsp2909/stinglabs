#!/usr/bin/env python3
"""
Verify a decision log's hash chain — the other half of docs/15 step 16.

A chain nobody can check is decoration. This recomputes every record's hash and
reports the first one that does not match.

    python3 tools/verify_log.py                     # every log in the session root
    python3 tools/verify_log.py ~/.sting/sessions/abc.log.jsonl
    python3 tools/verify_log.py --root logs/sessions-taint
    python3 tools/verify_log.py --export --root <export dir>   # a shipped/exported log
    python3 tools/verify_log.py --export --root <export dir> --key ~/.sting/.env.fingerprint
                                                    # ... matched against THIS laptop's log

Exit codes:
    0   every log checked verifies, or under --export is CONSISTENT, and holds
        no duplicates
    1   at least one chain is broken or tampered, a log is UNVERIFIABLE or
        CHAIN MISSING, or a log has duplicate records
    2   nothing to check

WHAT A BREAK MEANS. Someone edited or deleted a record in place. It does NOT
prove the log is complete: an attacker with write access can recompute the whole
chain, and wholesale truncation of the tail leaves a shorter, still-valid chain.
See core/audit_log.py for why that limit is inherent to a purely local log.
BROKEN is printed only where a check that should hold failed: a record whose
local hash cannot be checked is never called a break (below).

A SHIPPED OR EXPORTED LOG CARRIES A SECOND CHAIN (docs/99), and is read as one
ONLY UNDER `--export`. Its records carry `tier_chain`/`tier_prev`/`tier_hash`,
added after the hook hashed them, so the local hash is recomputed without those
three, and the local links are checked on every record. For a record shipped as
written (nothing masked; or, before 28 Sep 2026, `full` and unredacted) the two
verdicts are NEVER folded: its local hash must match, and the tier chain is
printed beside it and can only ADD a failure. An old-format log is read exactly
as it always was, unless (below) a record in it was reduced or redacted.

⚠ A MASKED, REDUCED OR REDACTED RECORD'S LOCAL HASH CANNOT BE CHECKED FROM AN
EXPORT. It covers bytes that never shipped, so it cannot match, edited or not.
It prints "local hash: not checkable at this tier", never BROKEN, and the log's
verdict is the tier chain's. It holds: CONSISTENT, exit 0, with "consistent: this file
agrees with itself; the collector's stored copy is the proof". It fails:
TAMPERED, exit 1. Its version is unknown, or an old-format record predates it:
UNVERIFIABLE, exit 1, not tampering and not clean. No record carries a tier
chain at all: CHAIN MISSING, exit 1. The chain is not broken, it is absent: an
export from before the chain existed, or one someone stripped, and the file
cannot tell which. Never "verified": nothing in
an unsigned export proves it was not rewritten by someone who can edit it, and
they can recompute a tier chain, even re-anchored on an edited record's own
`prev` so the chain head stays put (docs/99). The strict reading this replaces
called every reduced record BROKEN, edited or not, so it caught nothing there.

⚠ A RECORD SHIPPED SINCE 29 SEP 2026 CARRIES KEYED FINGERPRINTS (`fingerprints`,
core/wire.py): its `hash` and `prev` are HMAC-SHA256 under its laptop's key,
and `command_sha256` / `action_hash` were not sent. Its local hash is not
checkable from the export — the links between records still are — so it reads
as a masked record does, and the tier chain decides. WITH THE KEY (`--key`,
the laptop's `~/.sting/.env.fingerprint`) and that laptop's log (`--local`,
default the session root), every shipped record is matched to the local
record it came from, and a record masking did not rewrite must equal it field
for field: "N of N shipped records match this laptop's log".

⚠ HOW A RECORD SAYS IT WAS REWRITTEN: FIELDS IN THE FILE. An export keeps only
records. Since 28 Sep 2026 every record ships whole and masked, and one masking
rewrote carries `masked`, the count of what it hid (`wire.carries_masks`). An
older export's record reads reduced when every field it carries is one a tier
below `full` shipped (`wire.shipped_below_full`: the hook writes `command`,
`paths`, `url` and `action_hash` into every record, and no lower tier shipped
them), and redacted when a field the old Layer A or B rewrote holds its mark
(`redact.carries_a_mark`). So an editor could relabel one, adding `masked`,
cutting it to a lower tier's fields or writing a mark, and read CONSISTENT. That is the same limit, not a new one: whoever can
edit an unsigned file can rewrite and re-hash both chains, which always exited 0.

⚠ THE MODE IS THE VERIFIER'S, NEVER THE FILE'S. It used to be chosen by the
records: any one carrying a shipped-copy field sent the file down the shipped
path. A LOCAL log never carries those fields — the shipper adds them to the
copy it ships — but whoever can edit a local log can add them. So the default
reads a LOCAL log, exactly as before, and a record carrying any of the three is
TAMPERED there: nothing inside a file can change how it is judged (security
review of 0200270; docs/99).

DUPLICATES ARE CHECKED SEPARATELY, and that half matters more than it sounds.
Two hook processes per tool call — one installed at user scope, one wired by a
harness at project scope, with Claude Code MERGING the two rather than letting
the project override — append every action twice. Each append chains correctly
onto the tail it finds, so the chain VERIFIES: a log can be perfectly intact and
still have every count in it doubled. The chain is structurally incapable of
noticing that. Counting sequence numbers is the only thing that can, which is
why this check exists and why it runs over every log, not a sample.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import wire                                                   # noqa: E402
from core.audit_log import (LOG_SUFFIX, REDACTION_MANIFEST,  # noqa: E402
                            SIDECAR_ABSENT, SIDECAR_CORRUPT,
                            clock_contradictions, duplicate_events,
                            is_derived, load_full_command, pruned_start,
                            read_records, verify_chain)
from core.session import default_root                                   # noqa: E402
from shipper import fingerprint_key                                     # noqa: E402
from shipper import redact                                              # noqa: E402
from shipper import sparta_iface                                        # noqa: E402


def logs_under(root: Path) -> list[Path]:
    """Every log under `root`, whichever way it was named.

    Both suffixes, deliberately. The engine's own logs are `<sid>.log.jsonl`,
    but a harness that sets STING_LOG names the file itself — the corpus runner
    writes `logs/observe/<scenario>.log`. Globbing only LOG_SUFFIX meant this
    tool silently checked nothing at all for exactly the runs most worth
    checking, which is how a doubled corpus log went unnoticed.
    """
    if not root.is_dir():
        return []
    found = set(root.rglob(f"*{LOG_SUFFIX}")) | set(root.rglob("*.log"))
    return sorted(found)


TAMPERED_LOCAL = ("a local log never carries shipped-copy fields; "
                  "pass --export to verify an export")


def _first_shipped_copy_record(records: list[dict]) -> int | None:
    """The number of the first record carrying `tier_chain`, `tier_prev` or
    `tier_hash`, or None."""
    return next((i for i, r in enumerate(records, 1)
                 if isinstance(r, dict) and wire.carries_tier_chain(r)), None)


def _reduced_or_redacted(record: dict) -> bool:
    """Was this record rewritten before it shipped — masked (`masked`, since 28
    Sep 2026), reduced by an old tier, or redacted by an old Layer A or B? Read
    from its own fields; the docstring says what that costs."""
    return (wire.carries_masks(record) or wire.carries_keyed_fingerprints(record)
            or wire.shipped_below_full(record) or redact.carries_a_mark(record))


def _shipped_state(path: Path, records: list[dict]) -> tuple[str, int | None, str]:
    """`--export`'s reading of one log: `wire.verify_shipped_records`, told
    which records' local hash cannot be checked."""
    return wire.verify_shipped_records(records, pruned_start(path),
                                       reduced_or_redacted=_reduced_or_redacted)


_NOT_COMPARED = ("prev", "hash", "tier_chain", "tier_prev", "tier_hash",
                 wire.FINGERPRINTS_FIELD, *sparta_iface.FIELDS)
"""What a shipped record and its local record may differ in: the two chains'
links, the mark saying they were keyed, and what Sparta's enrichment wrote
beside the record (STING_SPARTA=1; never in the local log) — and every digest
that is not sent (`wire.is_not_sent`)."""


def _compared(record: dict) -> dict:
    return {k: v for k, v in record.items()
            if k not in _NOT_COMPARED and not wire.is_not_sent(k)}


def _match_local(export: list[dict], local: list[dict], key: bytes) -> tuple[int, list[str]]:
    """(matched, problems) for ONE session: every shipped record matched to the
    local record it came from — by its keyed `hash` (or, shipped raw before 29
    Sep 2026, its raw one) — its `prev` checked, and a record masking did not
    rewrite compared field for field. A masked record's body is not compared:
    the local one holds what the shipped one hides.

    ⚠ A RAW `prev` ON A KEYED RECORD ONLY AT THE SEAM A BRIDGE LEAVES: right
    after a record shipped raw (core/wire.py). Anywhere else it is a raw local
    hash where a keyed one belongs, and a mismatch (python review, HIGH)."""
    keyed = wire.fingerprinter(key)
    by_hash: dict[str, dict] = {}
    for record in local:
        if isinstance(record, dict) and isinstance(record.get("hash"), str):
            by_hash[keyed(record["hash"])] = record
            by_hash.setdefault(record["hash"], record)
    matched, problems, after_raw = 0, [], False
    for number, shipped in enumerate(export, 1):
        is_keyed = wire.carries_keyed_fingerprints(shipped)
        at_seam, after_raw = is_keyed and after_raw, not is_keyed
        origin = by_hash.get(shipped.get("hash"))
        if origin is None:
            problems.append(f"record {number} does not match any record in this "
                            f"laptop's log under this key")
            continue
        prev = origin.get("prev")
        allowed = {prev} if not is_keyed else {keyed(prev), prev} if at_seam else {keyed(prev)}
        if shipped.get("prev") not in allowed:
            problems.append(f"record {number} does not match this laptop's log: its "
                            f"prev is not the one its local record chains from")
            continue
        if not wire.carries_masks(shipped) and _compared(shipped) != _compared(origin):
            problems.append(f"record {number} does not match this laptop's log: "
                            f"nothing was masked in it, and its content differs")
            continue
        matched += 1
    return matched, problems


def _local_match_report(path: Path, export: list, key: bytes, root: Path) -> int:
    """Print how an export's records match this laptop's log, each session's
    against its own log (python review, MEDIUM); the number of problems. A line
    that is not a record is counted, and named."""
    sessions: dict[str, list[dict]] = {}
    problems = []
    for number, record in enumerate(export, 1):
        if not isinstance(record, dict):
            problems.append(f"line {number} is not a record")
            continue
        session = str(record.get("session_id") or path.name.split(".")[0])
        sessions.setdefault(session, []).append(record)
    matched = 0
    for session, records in sessions.items():
        local_path = root / f"{session}{LOG_SUFFIX}"
        if not local_path.exists():
            problems.append(f"no local log for session {session[:8]} under {root}")
            continue
        found, wrong = _match_local(records, read_records(local_path), key)
        matched += found
        problems += [f"session {session[:8]}: {problem}" for problem in wrong]
    masked = sum(1 for records in sessions.values() for r in records if wire.carries_masks(r))
    print(f"         with the key: {matched} of {len(export)} shipped records match "
          f"this laptop's log ({len(sessions)} session{'s' if len(sessions) != 1 else ''} "
          f"under {root})" + (f"; {masked} masked, their hidden values not compared"
                               if masked else ""))
    for problem in problems[:5]:
        print(f"         ⚠ {problem}")
    if len(problems) > 5:
        print(f"         … and {len(problems) - 5} more")
    return len(problems)


def _chain_state(path: Path, records: list[dict],
                 export: bool = False) -> tuple[str, int | None, str]:
    """(state, first bad record, detail); state is "ok", "broken", "tampered"
    or "unverifiable", and under --export also "consistent", "chain_missing" or
    "uncovered".

    ⚠ AN OLD-FORMAT LOG IS READ EXACTLY AS BEFORE, through `verify_chain`, in
    either mode — unless, under `--export`, a record in it reads reduced or
    redacted. Its local hash cannot be checked and no tier chain exists to
    decide it, so it is not called BROKEN: `_shipped_state` says CHAIN MISSING,
    and a log whose hashes all check after all goes on to `verify_chain`.

    A log whose records carry the chain over what SHIPPED
    (`tier_chain`/`tier_prev`/`tier_hash`, docs/99) is read by
    `wire.verify_shipped_records` ONLY when the verifier said `--export`: it
    sets the three aside for the local hash and checks the tier chain BESIDE
    it — the rule the collector's export applies. Without `--export` such a
    record is TAMPERED: the hook never writes them.

    ⚠ A LINE THAT IS JSON BUT NOT AN OBJECT IS BROKEN HERE, before either path.
    `read_records` keeps `[1, 2]` or `42` as it parsed it, and
    `audit_log.verify_records` (untouched) calls `.get` on every record — it
    raised, and ended the whole run, so every other log in a `--root` scan went
    unchecked (security review)."""
    stray = next((i for i, r in enumerate(records, 1) if not isinstance(r, dict)), None)
    if stray is not None:
        return "broken", stray, f"record {stray} is not a JSON object"
    marked = _first_shipped_copy_record(records)
    if marked is not None and not export:
        return ("tampered", marked,
                f"record {marked} carries tier_chain/tier_prev/tier_hash: "
                f"{TAMPERED_LOCAL}")
    if marked is not None:
        return _shipped_state(path, records)
    if export and any(map(_reduced_or_redacted, records)):
        state = _shipped_state(path, records)
        if state[0] != "ok":
            return state
    ok, bad, detail = verify_chain(path)
    return ("ok" if ok else "broken"), bad, detail


def _report_sidecars(records: list[dict], path: Path, quiet: bool) -> int:
    """Print the sidecar census for one log. Returns 1 if any are CORRUPT.

    Shared by the derived and the recorded path, because a sidecar nobody
    verifies is evidence nobody can trust and that is true of both. Unlike the
    chain, its three states mean three different things: ABSENT is not a failure
    — the normal result of a size cap or a log copied without its directory — so
    it never sets the exit code. CORRUPT is: the stored bytes do not hash to the
    digest the chain attests, so the file is lying about what was judged.
    """
    clipped = [r for r in records if r.get("command_clipped")]
    if not clipped:
        return 0
    states: dict[str, int] = {}
    for record in clipped:
        state, _text = load_full_command(record, path)
        states[state] = states.get(state, 0) + 1
    corrupt = states.get(SIDECAR_CORRUPT, 0)
    if corrupt or not quiet:
        summary = ", ".join(f"{count} {state}"
                            for state, count in sorted(states.items()))
        print(f"         {len(clipped)} clipped commands: {summary}")
    if corrupt:
        print(f"         CORRUPT: {corrupt} sidecar(s) do not match the "
              f"digest in the chain — they are not what was judged.")
    if states.get(SIDECAR_ABSENT):
        print("         absent is not tampering: recovery unavailable, "
              "integrity intact.")
    return 1 if corrupt else 0


CONSISTENT_CAVEAT = ("consistent: this file agrees with itself; "
                     "the collector's stored copy is the proof")

CHAIN_MISSING = ("CHAIN MISSING: exported below full with no tier chain, "
                 "nothing here can be checked")


class _Unchecked(NamedTuple):
    """How a log nothing here could check is printed: its label, the line that
    says why, and what the summary counts it as. None of them is tampering, and
    none is clean: each exits 1."""
    label: str
    why: str
    counted_as: str


# By the state `wire.verify_shipped_records` returned.
_UNCHECKED = {
    "unverifiable": _Unchecked(
        "UNVERIFIABLE",
        "not tampering, and not clean: this verifier does not know that format.",
        "UNVERIFIABLE (a tier_chain format unknown here)"),
    "uncovered": _Unchecked(
        "UNVERIFIABLE",
        "not tampering, and not clean: no tier chain covers its reduced or "
        "redacted records.",
        "UNVERIFIABLE (reduced or redacted records no tier chain covers)"),
    # ⚠ NOT BROKEN, AND NOT A FORMAT NOBODY KNOWS: THE CHAIN IS ABSENT. An
    # export from before the chain existed, or one someone stripped; the file
    # cannot tell which, so neither is claimed.
    "chain_missing": _Unchecked(
        "CHAIN MISSING", CHAIN_MISSING,
        "CHAIN MISSING (exported below full with no tier chain)"),
}


def _print_consistent(path: Path, n: int, detail: str, derived: bool) -> None:
    """A log whose verdict is the tier chain's, and it holds. Printed whatever
    `--quiet` says, as REDACTED is: the caveat is the finding. Never 'verified'."""
    print(f"  CONSISTENT {path}{'  (derived)' if derived else ''}  ({n} records; "
          f"every local link holds; the tier chain recomputes)")
    print(f"         {detail}")
    print(f"         {CONSISTENT_CAVEAT}")


def _print_unchecked(path: Path, state: str, detail: str, derived: bool) -> None:
    """A log nothing here could check: not tampering, and not clean."""
    how = _UNCHECKED[state]
    print(f"  {how.label} {path}{'  (derived)' if derived else ''}")
    print(f"         {detail}")
    print(f"         {how.why}")


def _unchecked_parts(unchecked: Counter) -> list[str]:
    return [f"{count} {_UNCHECKED[state].counted_as}"
            for state, count in sorted(unchecked.items())]


def _consistent_summary(verified: int, consistent: int, derived: int) -> str:
    """The closing line when a log is CONSISTENT. It may not launder the
    distinction the per-log line draws: no 'verified' for those logs."""
    parts = [f"{verified} recorded log(s) verified"] if verified else []
    parts.append(f"{consistent} CONSISTENT (the local hash is not checkable at "
                 f"this tier; the collector's stored copy is the proof)")
    if derived:
        parts.append(f"{derived} REDACTED (derived bytes only, provenance not "
                     f"verifiable here)")
    return "\n" + "; ".join(parts) + ". No duplicates."


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="*", type=Path,
                     help="log files to check (default: every log under --root)")
    ap.add_argument("--root", type=Path, default=None,
                     help="session directory to scan (default: the engine's own)")
    ap.add_argument("--quiet", action="store_true", help="only report breaks")
    ap.add_argument("--export", action="store_true",
                     help="verify a SHIPPED or EXPORTED log (records carrying "
                          "tier_chain/tier_prev/tier_hash, docs/99). Without it a "
                          "log is read as LOCAL, and a record carrying any of "
                          "those fields is TAMPERED.")
    ap.add_argument("--key", type=Path, default=None,
                     help="with --export: THIS laptop's fingerprint key "
                          "(~/.sting/.env.fingerprint), to match every shipped "
                          "record to the local record it came from. Never printed.")
    ap.add_argument("--local", type=Path, default=None,
                     help="with --key: the local session directory those records "
                          "came from (default: the engine's own)")
    args = ap.parse_args(argv)
    key = None
    if args.key is not None:
        if not args.export:
            print("--key reads an export: pass --export too", file=sys.stderr)
            return 2
        key = fingerprint_key.load(args.key)
        if key is None:
            print(f"{args.key} does not hold a fingerprint key", file=sys.stderr)
            return 2

    targets = list(args.logs) or logs_under(args.root or default_root())
    if not targets:
        where = args.root or default_root()
        print(f"No logs to check under {where}", file=sys.stderr)
        return 2

    broken = 0
    tampered = 0
    clock_broken = 0
    doubled = 0
    corrupt_sidecars = 0
    derived = 0
    consistent = 0
    derived_consistent = 0
    unmatched = 0
    unchecked: Counter = Counter()
    for path in targets:
        records = read_records(path)
        state, bad, detail = _chain_state(path, records, args.export)
        ok = state == "ok"
        n = len(records)
        # The checks below read fields; a non-object line is already BROKEN above.
        objects = [r for r in records if isinstance(r, dict)]
        dupes = duplicate_events(objects)
        # ⚠ THE CLOCK, CHECKED AGAINST THE CHAIN. Q03-move-the-clock is the one
        # corpus attack aimed at the EVIDENCE rather than at detection, and the
        # engine cannot prevent it — the guard runs as the developer, and `sudo
        # date` is theirs to run. What it can do is refuse to let the move pass
        # unrecorded: the chain orders records without reading a clock, so a
        # record the chain places AFTER carrying a time that says BEFORE is the
        # two disagreeing, and the chain is the half that cannot be rewritten
        # without breaking every hash following it.
        skewed = clock_contradictions(objects)

        # ---- DERIVED LOGS. The refusal, and it is load-bearing ---------------
        # A redacted fixture's chain is recomputed over the rewritten bytes, so
        # it verifies — and attests only "unmodified since redaction". Printing
        # the plain OK a real session gets would let a reader conclude the
        # SESSION is attested. That is a wrong answer rather than a missing one,
        # the failure this whole scheme exists to prevent.
        #
        # ⚠ NEVER route a log beside a manifest into the plain-OK branch below.
        # Without this refusal option E collapses into option A: a clean chain
        # that quietly means far less than it looks like it means. Pinned by
        # tests/test_redaction_is_declared.py.
        #
        # It ALSO fixes a misreport that existed whether or not redaction was
        # ever declared: two of the three vendored logs printed BROKEN, a false
        # alarm on the one signal that is supposed to mean tampering. An alarm
        # that is routinely wrong trains the reader to ignore the alarm.
        if skewed:
            clock_broken += 1
            print(f"  ⚠ CLOCK {path}")
            for before, after, drift in skewed[:5]:
                print(f"         seq {before} -> {after}: the chain says AFTER, "
                      f"the timestamp says {abs(drift):,.0f}s EARLIER")
            print("         The hash chain orders these; the clock disagrees. "
                  "Either the")
            print("         system clock moved backwards, or record timestamps "
                  "were edited.")
            print("         ⚠ THIS IS DETECTION, NOT PROOF OF ATTACK — and it is "
                  "a device")
            print("         comparing its own clock against itself. The receiver "
                  "holds the")
            print("         only independent one; see docs/60.")

        if is_derived(path):
            derived += 1
            if state == "tampered":
                tampered += 1
                print(f"  TAMPERED {path}  (derived)")
                print(f"         {detail}")
            elif state in _UNCHECKED:
                unchecked[state] += 1
                _print_unchecked(path, state, detail, derived=True)
            elif state == "consistent":
                derived_consistent += 1
                _print_consistent(path, n, detail, derived=True)
            elif ok:
                print(f"  REDACTED {path}  ({detail})")
                print("         chain intact over DERIVED bytes; provenance not "
                      "verifiable here.")
                print("         redaction is not tampering: the transformation is "
                      f"declared in {REDACTION_MANIFEST},")
                print("         and the original log attests the session.")
            else:
                broken += 1
                print(f"  BROKEN {path}  (derived)")
                print(f"         {detail}")
                print("         a derived log still chains over its own bytes, so "
                      "this is a real break.")
            corrupt_sidecars += _report_sidecars(objects, path, args.quiet)
            continue

        if state == "tampered":
            tampered += 1
            print(f"  TAMPERED {path}")
            print(f"         {detail}")
        elif state in _UNCHECKED:
            unchecked[state] += 1
            _print_unchecked(path, state, detail, derived=False)
        elif state not in ("ok", "consistent"):
            broken += 1
            print(f"  BROKEN {path}")
            print(f"         {detail}")
            print(f"         {n} records present; everything from record "
                  f"{bad} onward is unverifiable.")
        elif dupes:
            doubled += 1
            distinct = len({(s, q) for s, q, _e, _n in dupes})
            holds = "chain verifies" if ok else "the file agrees with itself"
            print(f"  DOUBLED {path}")
            print(f"         {holds}, but {len(dupes)} events are logged "
                  f"more than once across {distinct} sequence numbers.")
            for session, seq, event, count in dupes[:3]:
                print(f"           seq {seq} ({event}) appears {count}x "
                      f"in session {session}")
            if len(dupes) > 3:
                print(f"           … and {len(dupes) - 3} more")
            print( "         Almost always TWO HOOKS REGISTERED AT DIFFERENT "
                   "SETTINGS SCOPES.")
            print( "         Check ~/.claude/settings.json against the project's "
                   ".claude/settings.json.")
            print(f"         Any count taken from this log is inflated; {n} "
                  f"records is not {n} actions.")
        elif state == "consistent":
            consistent += 1
            _print_consistent(path, n, detail, derived=False)
        elif not args.quiet:
            print(f"  OK    {path}  ({detail})")
        if key is not None:
            unmatched += bool(_local_match_report(path, records, key,
                                                  args.local or default_root()))

        corrupt_sidecars += _report_sidecars(objects, path, args.quiet)

    # ⚠ A CONTRADICTION EXITS NON-ZERO. A verifier that prints "the clock
    # disagrees with the chain" and then exits 0 is a verifier nobody notices,
    # and the one thing this check exists for is to be noticed. It is reported
    # separately from a broken chain because they mean different things: a
    # broken chain is bytes that were edited, a clock contradiction is time that
    # moved — and only the first proves tampering.
    # ⚠ A MISMATCH UNDER THE KEY EXITS NON-ZERO TOO, and says so on its own line
    # before any other finding: the export does not match this laptop's log.
    if unmatched:
        print(f"\n{unmatched} of {len(targets)} logs do not match this laptop's log "
              f"under this key.")
    if broken or tampered or doubled or corrupt_sidecars or clock_broken:
        parts = []
        if broken:
            parts.append(f"{broken} with a broken chain")
        if tampered:
            # Under --export a TAMPERED can only be the tier chain's verdict.
            why = ("the chain over what shipped does not hold" if args.export
                   else "shipped-copy fields in a log read as local; "
                        "--export verifies an export")
            parts.append(f"{tampered} TAMPERED ({why})")
        if clock_broken:
            parts.append(f"{clock_broken} whose CLOCK contradicts the chain")
        if doubled:
            parts.append(f"{doubled} with duplicate records")
        if corrupt_sidecars:
            parts.append(f"{corrupt_sidecars} with a corrupt command sidecar")
        parts += _unchecked_parts(unchecked)
        print(f"\n{' and '.join(parts)}, out of {len(targets)} logs checked.")
        return 1
    if unmatched:
        return 1
    # ⚠ UNVERIFIABLE AND CHAIN MISSING ARE NOT CLEAN. A format this verifier
    # does not know, a reduced record no tier chain covers, or an export with no
    # tier chain at all was not checked, and exiting 0 would say it was (the
    # rule wire.verify_batch applies to an unknown version).
    if unchecked:
        print(f"\n{' and '.join(_unchecked_parts(unchecked))}, "
              f"out of {len(targets)} logs checked.")
        return 1
    if not args.quiet:
        # THE SUMMARY MUST NOT LAUNDER THE DISTINCTION EITHER. "3 logs verified"
        # over a set containing derived files would restore, in one line, exactly
        # the impression the per-log refusal above exists to prevent — and so
        # would the same line over a CONSISTENT export.
        recorded = len(targets) - derived
        if consistent or derived_consistent:
            # A derived CONSISTENT log is counted as CONSISTENT, never as
            # REDACTED: that line says its chain is intact over derived bytes.
            print(_consistent_summary(recorded - consistent,
                                      consistent + derived_consistent,
                                      derived - derived_consistent))
        elif derived:
            print(f"\n{recorded} recorded log(s) verified; {derived} REDACTED "
                  f"(derived bytes only, provenance not verifiable here). "
                  f"No duplicates.")
        else:
            print(f"\n{len(targets)} logs verified, no duplicates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
