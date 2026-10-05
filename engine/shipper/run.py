#!/usr/bin/env python3
"""The shipper loop. A separate process from the hook.

    python3 -m shipper.run                 # run until stopped
    python3 -m shipper.run --once          # one pass, for testing and for cron
    python3 -m shipper.run --status        # what the cursor holds, no network

⚠ WHAT HAPPENS WHEN THIS IS NOT RUNNING: **logs accumulate locally and ship
later.** Not "actions are lost", and not "the hook blocks". The hook writes
`~/.sting/<session>.log.jsonl` on every decision whether or not this process
exists; the cursor remembers what has been shipped; a later run sends the
backlog in capped batches. A collector that is down for a week costs the
developer nothing but disk.

STARTED BY: the developer, or launchd/systemd. It is deliberately NOT started by
the hook — a hook that spawns a process on a tool call has put process creation
on the 12 ms path, and a hook that reaps one has put waiting there.

    macOS   ~/Library/LaunchAgents/dev.sting.shipper.plist, RunAtLoad + KeepAlive
    Linux   a systemd --user unit with Restart=always
    ad hoc  `python3 -m shipper.run &`, or `--once` from cron
"""
from __future__ import annotations

import argparse
import dataclasses
import functools
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# ⚠ THE SAME FLOOR AS install.py AND hook_entry.py, AND FOR THE SAME REASON.
# `python3 -m shipper.run` is a DOCUMENTED command — `install.py
# --no-supervisor` prints it verbatim — so a person can reach this file with
# whatever `python3` is first on their PATH. On macOS that is 3.9, and without
# this the answer is a traceback out of `core.types`.
#
# The supervised path is unaffected: the plist/unit/task runs the interpreter
# recorded at install time, which is by definition one this floor accepts.
if sys.version_info < (3, 11):
    sys.stderr.write(
        "sting: the shipper needs Python 3.11 or newer (StrEnum); "
        "this is %d.%d at %s\n"
        % (sys.version_info[0], sys.version_info[1], sys.executable))
    raise SystemExit(2)

from core import wire                                            # noqa: E402
from core.audit_log import GENESIS, LOG_SUFFIX, read_records     # noqa: E402
from shipper import (client, config, disclosure, fingerprint_key,  # noqa: E402
                     mask, redact, service, singleton, sparta_enrich, sparta_iface)
from shipper.cursor import Cursor, Position                      # noqa: E402
from shipper.heartbeat import Heartbeat                          # noqa: E402
from shipper.policy_poll import PolicyPoll                       # noqa: E402


def _is_count(value) -> bool:
    """Would the receipt arithmetic read `value` as a number (as `int()` did)?"""
    if value is None:
        return False
    try:
        int(value)
    except (TypeError, ValueError, OverflowError):
        return False
    return True


def _receipt_count(stored, deduped) -> int | None:
    """`records_stored` + `records_deduplicated`, or None when the receipt does not
    say — a missing or non-numeric count is never read as coverage (M2)."""
    if not (_is_count(stored) and _is_count(deduped)):
        return None
    return int(stored) + int(deduped)


class Shipper:
    def __init__(self, settings: config.Settings, *, now=time.time,
                 log=print):
        self.settings = settings
        self.now = now
        self.log = log
        self._receipt_warned = False           # `_say_unreadable_receipt`, once
        self._url_refused_said = False        # `_refuse_url`, once
        self.cursor = Cursor(settings.state_root / "cursor.json")
        # ⚠ WHAT THIS MACHINE AGREED TO SEND, READ ONCE WITH THE SETTINGS. Without
        # the agreement nothing ships: see `config.HELD` and `tick`.
        self.ships = settings.what_ships()
        self._held_said = False                # `_say_held`, once
        # `wire.fingerprinter` over this laptop's key, once it is loaded; see
        # `_keyed`. `_key_said`: why nothing ships without one, said once.
        self._fingerprint = None
        self._key_id: str | None = None           # `fingerprint_key.key_id`, for its record
        self._key_born: float | None = None       # when the key was made
        # The sessions its record says shipped keyed (`fingerprint_key`); None
        # while the record cannot be read: then nothing is bridged.
        self._keyed_sessions: set | None = None
        self._key_said = False
        self._record_said = False
        self._state_said: set = set()          # `_session_values`, once per session
        # Per session: the last record scanned (its hash) and every value of
        # `mask.MIN_SESSION_ECHO`+ chars masking recognised in the log so far.
        self._seen: dict[str, tuple[str | None, dict]] = {}
        self.heartbeat = Heartbeat(settings, self.cursor, now=now)
        # ⚠ OUT OF BAND, BESIDE THE HEARTBEAT — never the decision path. Fetches
        # this org's policy on the same loop cadence and caches it for the engine
        # (step 3) to read locally. Changes no verdict.
        self.policy_poll = PolicyPoll(settings, now=now)
        self.started_at = now()
        # Layer B's NER analyzer, loaded ONCE (lazily, on first batch) and reused —
        # never reloaded per record. None until Layer B is on and the first batch
        # ships. Loading fails loud if the dependency is missing (see _pii_analyzer).
        # It plugs into the masking socket as one more provider (`[person]`).
        self._analyzer = None
        # Sparta's detector, asked fail-open (`sparta_enrich.Guarded`): resolved
        # ONCE, on the first batch, and only when STING_SPARTA=1. None when the
        # flag is off or no detector could be had (`_sparta`).
        self._sparta_guarded: sparta_enrich.Guarded | None = None
        self._sparta_resolved = False
        self._last_flush = 0.0
        self._backoff = 0.0
        self._retry_after = 0.0
        self._undeliverable = settings.state_root / "undeliverable.jsonl"

    # ------------------------------------------------------------- discovery

    def session_logs(self) -> list[Path]:
        root = self.settings.log_root
        if not root.is_dir():
            return []
        return sorted(root.glob(f"*{LOG_SUFFIX}"))

    def pending(self) -> int:
        total = 0
        for path in self.session_logs():
            position = self.cursor.get(path.name[:-len(LOG_SUFFIX)])
            total += max(0, len(read_records(path)) - position.shipped)
        return total

    # ⚠ WHICH DECISIONS ARE WORTH NOT WAITING FIVE MINUTES FOR.
    #
    # A DENY is the event the product exists to produce, and learning about it
    # up to `flush_seconds + POLL_SECONDS` late is the wrong latency for the one
    # record that matters most. An ASK is included because a HUMAN IS ALREADY
    # WAITING on it — the prompt is on their screen — so the record describing
    # it is the most perishable thing the session will produce.
    #
    # ⚠ ALLOW IS NOT HERE AND MUST NOT BE. It is ~95% of records; treating it as
    # urgent would turn the batch into a stream, which is the design this
    # shipper exists to avoid.
    URGENT_DECISIONS = ("deny", "ask")

    def urgent_sessions(self) -> set:
        """Session ids with a PENDING deny or ask. Costs no extra IO.

        ⚠ THE RECORDS ARE ALREADY BEING READ. `pending()` parses every record of
        every session on every poll — measured at 16.8 ms for 2928 records
        across 3.6 MB — so noticing a `decision` field among records already in
        memory adds nothing the loop was not already paying.

        ⚠ AND THE HOOK IS UNTOUCHED, WHICH IS THE POINT. No sentinel file, no
        mtime dance, no signal, and above all no network dependency and no
        latency on the warm path (25.5 ms, where every millisecond is now a
        larger share). The shipper learns by reading what the hook already
        wrote. `tests/test_flush_on_deny.py` asserts this from the source, the
        way the no-networking claim is already asserted.
        """
        urgent = set()
        for path in self.session_logs():
            session_id = path.name[:-len(LOG_SUFFIX)]
            position = self.cursor.get(session_id)
            for record in read_records(path)[position.shipped:]:
                decision = str(record.get("decision") or "").lower()
                if decision in self.URGENT_DECISIONS:
                    urgent.add(session_id)
                    break
        return urgent

    # ----------------------------------------------------------- the decision

    def should_flush(self, pending: int, urgent: bool = False) -> bool:
        if pending <= 0:
            return False
        # ⚠ URGENT DOES NOT BYPASS BACKOFF — `tick` checks `_retry_after`
        # before it gets here. A refused collector must not be hammered harder
        # because the thing waiting is important; that is how an outage becomes
        # an outage plus a thundering herd.
        if urgent:
            return True
        if pending >= self.settings.flush_records:
            return True
        return (self.now() - self._last_flush) >= self.settings.flush_seconds

    # ------------------------------------------------------------- one batch

    def ship_session(self, path: Path) -> str | None:
        """Ship what is pending for one session. Returns an outcome kind."""
        session_id = path.name[:-len(LOG_SUFFIX)]
        records = read_records(path)
        position = self.cursor.get(session_id)
        fresh = records[position.shipped:]
        if not fresh:
            return None

        # ⚠ WHAT THIS SESSION'S STATE KNOWS, OR NOTHING SHIPS FOR IT. Values the
        # session read from a credential file are masked by their needles; a
        # state that cannot be read would ship them as written.
        known = self._session_values(session_id)
        if known is None:
            return None
        known = self._with_what_the_session_showed(session_id, records, known)
        # Capped, so a laptop that was offline for a day sends several batches
        # rather than one body the collector will refuse outright.
        chunk = fresh[:config.MAX_BATCH_RECORDS]
        return self._send(session_id, position, chunk, len(records), known)

    def purpose_for(self, records: list[dict]) -> str | None:
        """The batch's purpose, derived from the records it is carrying.

        ⚠ THE RECORDS NOW KNOW, WHICH IS WHY THIS STOPPED GUESSING. One pass ago
        this read an operator's `STING_PURPOSE` and otherwise declared nothing,
        because a developer's session, a preflight log and `bench-sub` were the
        same shape on disk and nothing could tell them apart. They are no longer
        the same shape: every record carries what the process that WROTE it
        declared, in the hashed body, in every record that ships. So this reads rather than
        guesses.

        ⚠ UNANIMOUS OR ABSENT, AND NEVER A MAJORITY. A session can legitimately
        hold more than one purpose — a preflight and a real session can land in
        one session root, and a chunk can straddle them. When the records
        disagree, the batch-level field is left ABSENT, because it is a single
        string and a single string cannot honestly express a mixture. Nothing is
        lost by that: `purpose` is in `_SPINE`, so the records travel with their
        own values in every record and a receiver computes the union itself —
        every distinct value, sorted, the discipline `agent` and `os` already
        follow. Collapsing to a majority would invent a fact about the minority.

        ⚠ AND A RECORD THAT DECLARED NOTHING COUNTS AS A DISAGREEMENT when
        anything beside it did. A chunk of nine `work` records and one undeclared
        record is not a work batch; it is a batch this sender cannot summarise,
        and saying so costs nothing because the records are right there.
        """
        seen = {r.get("purpose") for r in records}
        if len(seen) == 1:
            only = seen.pop()
            return only if only in wire.PURPOSES else None
        return None

    def _session_values(self, session_id: str) -> mask.SessionValues | None:
        """What this session's engine state lets the masking recognise — Layer A's
        needles and the files they came from, and the org policy's — loaded from
        the session's own state file at ship time, in this process, never on
        the hook. A missing state file is the normal "read no secret" case
        (`load_session` returns an empty state), and so is a pruned one still
        draining its log: nothing to match, and every other mask still holds.

        ⚠ A STATE THAT CANNOT BE READ HOLDS THE SESSION: None, and nothing
        ships for it. Every batch carries the command now, so shipping without
        the needles could send a value this session read from `.env` as
        written. Said once per session; the records stay on disk."""
        try:
            from core import session
            state = session.load_session(session_id, root=self.settings.log_root)
            # ⚠ AND WHAT THE ORG'S POLICY SENDS AS WRITTEN: home-folder account
            # names only when it says exactly so (shipper/disclosure.py).
            return dataclasses.replace(
                mask.session_values(state),
                send_folder_names=disclosure.sends_folder_names())
        except Exception as exc:
            if session_id not in self._state_said:
                self._state_said.add(session_id)
                self.log(f"  ⚠ could not read session {session_id[:8]}'s state "
                          f"({type(exc).__name__}); nothing ships for it until "
                          f"it can be read, because the values it read from a "
                          f"secret file could not be masked. Records stay on disk.")
            return None

    def _with_what_the_session_showed(self, session_id: str, records: list,
                                      known: mask.SessionValues) -> mask.SessionValues:
        """`known`, plus every value masking recognised ANYWHERE in this
        session's log, the records not sent yet included (`SessionValues.seen`).

        ⚠ MEASURED: `T=<a real token>` shipped raw in five records of a session
        that masked the same token where a clue named it. So the whole log is
        read once, then only what came after the last record read — found by
        its hash, so a prune that rewrote the log's head cannot make it skip a
        record. What was learnt is kept: masking more is never the error."""
        last, seen = self._seen.get(session_id, (None, {}))
        start = 0
        if last is not None:
            at = next((i for i, r in enumerate(records)
                       if isinstance(r, dict) and r.get("hash") == last), None)
            start = 0 if at is None else at + 1
        for record in records[start:]:
            if isinstance(record, dict):
                for value, kind in mask.recognised_values(record, known).items():
                    seen.setdefault(value, kind)
        tail = next((r.get("hash") for r in reversed(records)
                     if isinstance(r, dict) and r.get("hash")), last)
        self._seen[session_id] = (tail, seen)
        # A copy: the batch's masking indexes it once, and must not see it grow.
        return dataclasses.replace(known, seen=dict(seen))

    def _pii_analyzer(self):
        """Layer B's NER analyzer, loaded ONCE and cached. Raises RedactionUnavailable
        (fails loud) if the dependency is missing — the batch is then NOT sent."""
        if self._analyzer is None:
            self._analyzer = redact.load_pii_analyzer()
        return self._analyzer

    def _masker(self, known: mask.SessionValues, analyzer) -> Callable[[dict], dict]:
        """What masks a record before it ships.

        ⚠ WITH STING_SPARTA OFF, THE MASKER IT ALWAYS WAS, AND NOTHING ELSE RUNS:
        no detector is looked for and no Sparta code is entered (a test makes
        every enrichment entry point raise and ships byte-identical to main).
        On, and with a detector, `sparta_enrich.enrich_record`: more masks and
        two fields, never a verdict."""
        if sparta_iface.enabled(self.settings.sparta_flags):
            guarded = self._sparta()
            if guarded is not None:
                return functools.partial(sparta_enrich.enrich_record, known=known,
                                         analyzer=analyzer, guarded=guarded)
        return functools.partial(mask.mask_record, known=known, analyzer=analyzer)

    def _sparta(self) -> sparta_enrich.Guarded | None:
        """The detector, resolved once per process; None when none could be
        had (`get_detector` says why, once). ⚠ THE TAINT FLAG IS READ HERE,
        behind the first, and only to say that seeding is not built: nothing
        Sparta answers reaches the session state the hook reads."""
        if not self._sparta_resolved:
            self._sparta_resolved = True
            flags = self.settings.sparta_flags
            if sparta_iface.taint_enabled(flags):
                self.log(f"  ⚠ {sparta_iface.TAINT_FLAG}=1, but seeding taint from "
                         f"Sparta is not built: its answers are masked and recorded, "
                         f"and never reach a verdict. Said once.")
            detector = sparta_iface.get_detector(flags, log=self.log)
            if not isinstance(detector, sparta_iface.NullSpartaDetector):
                self._sparta_guarded = sparta_enrich.Guarded(detector, log=self.log)
        return self._sparta_guarded

    def _keyed(self, *, again: bool = False) -> Callable[[str], str] | None:
        """`wire.fingerprinter` over this laptop's key (`fingerprint_key`),
        made if missing — a machine upgraded without reinstalling — or None.

        ⚠ A FILE THAT DOES NOT HOLD A KEY IS NEVER REPLACED: a new key would
        give every live session a `continues_from` the collector has never
        seen. Nothing ships until a person looks, said once. The key itself is
        never logged: only where it lives.
        ⚠ A KEY CHANGED UNDER THIS PROCESS IS READ AGAIN (python review): an
        install.py making a new one before it restarts this shipper would
        otherwise leave it keying with the old one, and noting sessions under
        it in a record reset for the new. `again` — once, at the top of each
        tick — so every call within one tick answers alike."""
        path = self.settings.fingerprint_key_path
        if self._fingerprint is not None:
            if not again or fingerprint_key.born(path) == self._key_born:
                return self._fingerprint
            self._fingerprint = self._key_id = None
        # ⚠ SECURITY REVIEW: a key made anew over one sessions were keyed with
        # opens a gap in each, silently and for good; so does keying with one
        # the record does not name. A person decides (`why_held`).
        held = fingerprint_key.why_held(path)
        if held is not None:
            self._say_no_key(held, path)
            return None
        record = fingerprint_key.read_record(path)
        keyed_with = (record or {}).get("sessions")
        try:
            fingerprint_key.create_if_missing(path)
        except OSError as exc:
            self._say_no_key(f"could not be made ({type(exc).__name__})", path)
            return None
        key = fingerprint_key.load(path)
        if key is None:                          # changed since `why_held` read it
            self._say_no_key(fingerprint_key.DAMAGED, path)
            return None
        self._fingerprint = wire.fingerprinter(key)
        self._key_id = fingerprint_key.key_id(key)
        self._key_born = fingerprint_key.born(path)
        self._keyed_sessions = set(keyed_with) if keyed_with is not None else (
            None if record is not None else set())
        return self._fingerprint

    def _collector_holds_it_raw(self, session_id: str, position: Position) -> bool:
        """Does the collector hold this session's head RAW — shipped before this
        laptop had a key — so its next batch must bridge (core/wire.py)?

        ⚠ TWO SIGNALS MUST AGREE: no keyed mark, AND last stored before the key
        was made. The mark alone can be lost — an older version rewriting
        cursor.json, a hand edit — while the collector holds the head keyed,
        and a bridge would then ship a raw hash of a record it holds only keyed.
        Wrong in either direction this reads as a gap, never as a raw value.
        ⚠ AND THE KEY'S RECORD MUST NOT NAME THE SESSION (security review): a
        cursor restored from a backup brings both signals back; the record,
        beside the key and outside this process's state, does not roll back
        with it. A record that cannot be read bridges nothing."""
        return (position.ends_at != GENESIS and not position.keyed
                and self._key_born is not None
                and position.updated_at < self._key_born
                and self._keyed_sessions is not None
                and session_id not in self._keyed_sessions)

    def _note_keyed(self, session_id: str) -> None:
        """The key's record: this session is now held keyed at the collector."""
        if self._keyed_sessions is None or session_id in self._keyed_sessions:
            return
        try:
            fingerprint_key.note_keyed(self.settings.fingerprint_key_path, session_id,
                                       self._key_id)
            self._keyed_sessions.add(session_id)
        except OSError as exc:
            # ⚠ NOT FATAL, AND NOT SILENT. The cursor's mark still holds; only a
            # cursor restored from a backup would miss this. Said once.
            if not self._record_said:
                self._record_said = True
                self.log(f"  ⚠ the fingerprint key's record could not be written "
                          f"({type(exc).__name__}): shipping goes on, but a cursor "
                          f"restored from a backup could bridge {session_id[:8]} again.")

    def _say_no_key(self, why: str, path) -> None:
        if not self._key_said:
            self._key_said = True
            self.log(f"  ⚠ the fingerprint key {path} {why}. Nothing ships "
                      f"without it; records stay on disk.")

    def _send(self, session_id, position, chunk, total, known) -> str:
        # ⚠ MASKED BEFORE IT LEAVES THE MACHINE, AND CHAINED OVER WHAT LEAVES.
        # Every record ships whole, every value the masking recognises replaced
        # by its type (`shipper/mask.py`); `build_batch` masks, then chains, so
        # `tier_hash` covers exactly the bytes sent. Off the hook: the verdict
        # was decided and logged, and the local record is never touched. The
        # NER analyzer is loaded ONCE here (not per record) when Layer B is on.
        analyzer = self._pii_analyzer() if self.settings.redact_pii else None
        masker = self._masker(known, analyzer)
        # ⚠ KEYED, AND BRIDGED ONCE (core/wire.py). A session the collector
        # holds raw — shipped before keyed fingerprints (docs/107) — continues
        # from the raw head it holds; every batch after that is keyed. Both
        # read the key the tick resolved (`_keyed(again=True)`, once): never
        # read it again here.
        batch = wire.build_batch(
            chunk, device_id=self.settings.device_id, session_id=session_id,
            continues_from=position.ends_at, purpose=self.purpose_for(chunk),
            raw_anchor=self._collector_holds_it_raw(session_id, position),
            fingerprint=self._keyed(),
            mask=masker)
        if masker.func is sparta_enrich.enrich_record:
            # ⚠ ITS RECORDS CARRY SPARTA'S FIELDS, SO ITS `can_leak` SAYS SO.
            batch = sparta_enrich.disclosed(batch)
        payload = json.dumps(batch, sort_keys=True).encode("utf-8")
        outcome = client.post(f"{self.settings.collector_url}/v1/batches",
                               self.settings.device_token, payload,
                               timeout=self.settings.timeout_seconds)

        if outcome.kind == client.TOO_LARGE:
            return self._split(session_id, position, chunk, total, outcome, known)

        if outcome.advances:
            ends_at = next((r["hash"] for r in reversed(chunk)
                             if isinstance(r.get("hash"), str)), position.ends_at)
            last_seq = next((r.get("seq") for r in reversed(chunk)
                              if r.get("seq") is not None), position.last_seq)
            gap = outcome.kind == client.STORED_WITH_GAP
            self.cursor.advance(session_id, shipped=position.shipped + len(chunk),
                                 ends_at=ends_at, last_seq=last_seq, gap=gap,
                                 keyed=True)
            self._note_keyed(session_id)
            # ⚠ THE RECEIPT, WHICH THIS LOOP USED TO THROW AWAY. The collector
            # answers with `records_stored` and a `batch_ref` and the client
            # classifies by STATUS ALONE, so the one piece of evidence that a
            # record actually arrived was read and discarded. It is the only
            # thing that may ever authorise deleting a local record.
            # ⚠ AND THE RECEIPT MUST COVER THE WHOLE CHUNK BEFORE ITS LAST SEQ
            # IS TREATED AS ACKNOWLEDGED. `last_seq` is computed on THIS side
            # from what was sent; only `records_stored` says what landed. A 200
            # that stored fewer than were posted would otherwise push the
            # deletion boundary past a record nothing holds.
            #
            # `records_deduplicated` counts records the collector already had —
            # those ARE stored, so they count toward coverage.
            stored = outcome.body.get("records_stored")
            deduped = outcome.body.get("records_deduplicated") or 0
            # ⚠ A RECEIPT THAT DOES NOT SAY HOW MANY IT STORED AUTHORISES NOTHING
            # (M2, docs/95). `int("abc")` used to raise out of here and kill the
            # loop — tick() and run() catch only KeyboardInterrupt — and a 200 with
            # NO `records_stored` counted as FULL coverage. Both now fail toward
            # KEEPING, the B3 rule: the queue moves on, nothing becomes prunable,
            # and the value's TYPE is said once. Every count `int()` read before
            # is read the same way.
            covered = _receipt_count(stored, deduped)
            if covered is None:
                self._say_unreadable_receipt(stored, deduped)
            elif covered >= len(chunk):
                self.cursor.acknowledge(
                    session_id, last_seq=last_seq, ends_at=ends_at,
                    stored=stored,
                    batch_ref=str(outcome.body.get("batch_ref") or ""))
            else:
                # Loud, and NON-ADVANCING for deletion purposes — the same shape
                # REFUSED gets. The queue still moves on; nothing may be pruned.
                self.log(f"  ⚠ The collector stored {stored} + deduplicated "
                          f"{deduped} of {len(chunk)} records posted for "
                          f"{session_id[:8]}. The acknowledged mark is NOT "
                          f"advanced; nothing in this batch may be pruned.")
            if gap:
                # ⚠ A GAP IS INFORMATION, NOT AN ERROR. The batch IS stored. It
                # says something earlier never arrived — which on this side
                # usually means the cursor was reset or the log was truncated.
                # Reported once, loudly, and the cursor advances: stalling
                # behind a hole that can never fill would wedge the session
                # forever while its log kept growing.
                self.log(f"  ⚠ gap accepted by the collector for {session_id[:8]}: "
                          f"{outcome.detail}")
            self._backoff = 0.0
            return outcome.kind

        if outcome.kind == client.UNAUTHORISED:
            self._retry_after = self.now() + config.BACKOFF_UNAUTHORISED
            self.log(f"  ⚠ collector refused the device token ({outcome.status}). "
                      f"Nothing is lost — records keep accumulating locally. "
                      f"Retrying in {config.BACKOFF_UNAUTHORISED}s.")
            return outcome.kind

        if outcome.kind == client.REFUSED:
            # The collector says this batch is malformed. Retrying cannot help,
            # and advancing past it would silently drop records. Say so and
            # leave the cursor: a human has to look.
            self.log(f"  ⚠ collector refused the batch as malformed: "
                      f"{outcome.detail}. The cursor is NOT advanced; these "
                      f"records are still on disk.")
            self._back_off()
            return outcome.kind

        self._back_off()
        self.log(f"  collector unavailable ({outcome.detail}); "
                  f"{total - position.shipped} records waiting, retry in "
                  f"{int(self._backoff)}s")
        return outcome.kind

    def _split(self, session_id, position, chunk, total, outcome, known) -> str:
        """413 — halve and retry.

        ⚠ AND A SINGLE RECORD THAT IS STILL TOO LARGE MUST NOT WEDGE THE QUEUE.
        One 8 MB heredoc would otherwise block every later record in that
        session forever, which converts one undeliverable action into a silently
        dead session. It is written to `undeliverable.jsonl` with the reason,
        the cursor steps over it, and the loss is LOCAL, EXPLICIT and one record
        — instead of remote, silent and unbounded.
        """
        if len(chunk) == 1:
            self._record_undeliverable(session_id, chunk[0], outcome.detail, known)
            record = chunk[0]
            # ⚠ NOTHING STORED THIS ANYWHERE. Later batches will push
            # `acked_seq` past it, so it has to be named or a prune would read
            # it as acknowledged and delete the single record that is proven
            # NOT to be at the collector.
            self.cursor.note_skipped(session_id, record.get("seq"))
            self.cursor.advance(
                session_id, shipped=position.shipped + 1,
                ends_at=record.get("hash") or position.ends_at,
                last_seq=record.get("seq", position.last_seq))
            self.log(f"  ⚠ one record is too large for the collector and was "
                      f"skipped: {session_id[:8]} seq {record.get('seq')}. "
                      f"Written to {self._undeliverable}")
            return client.TOO_LARGE
        half = max(1, len(chunk) // 2)
        return self._send(session_id, position, chunk[:half], total, known)

    def _record_undeliverable(self, session_id, record, reason, known) -> None:
        # ⚠ AS IT WOULD HAVE SHIPPED, NEVER RAW (#76's open list). The raw record
        # is in the local log already; a second raw copy here was every value
        # masking exists to hide, in a file nothing else reads.
        analyzer = self._pii_analyzer() if self.settings.redact_pii else None
        shipped = wire.ship_record(
            record, fingerprint=self._keyed(), mask=self._masker(known, analyzer))
        try:
            self._undeliverable.parent.mkdir(parents=True, exist_ok=True)
            with self._undeliverable.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "at": self.now(), "session_id": session_id,
                    "seq": record.get("seq"), "reason": reason,
                    "record": shipped}, sort_keys=True) + "\n")
        except OSError as exc:
            # ⚠ DISK FULL ON THE SENDER'S SIDE. Nothing here may raise into the
            # loop; the agent is unaffected either way, and the log the hook
            # writes is the artifact that matters.
            self.log(f"  ⚠ could not record an undeliverable record: {exc}")

    def _back_off(self) -> None:
        self._backoff = min(config.BACKOFF_CAP,
                             max(config.BACKOFF_START, self._backoff * 2))
        self._retry_after = self.now() + self._backoff

    # ------------------------------------------------------------- one pass

    def _say_unreadable_receipt(self, stored, deduped) -> None:
        """Once per process, and only the field and its TYPE — never the body,
        which is the collector's to describe and could carry anything."""
        if self._receipt_warned:
            return
        self._receipt_warned = True
        field, value = (("records_stored", stored) if not _is_count(stored)
                        else ("records_deduplicated", deduped))
        kind = "missing" if value is None else type(value).__name__
        self.log(f"  ⚠ The collector's receipt carries no readable `{field}` "
                  f"({kind}). The acknowledged mark is NOT advanced; nothing in "
                  f"this batch may be pruned. Shipping continues; said once.")

    def _say_held(self) -> None:
        """Once per process: the loop keeps ticking, the operator is told once."""
        if self._held_said:
            return
        self._held_said = True
        self.log(f"  ⚠ NOT SENDING RECORDS: {self.ships['detail']}. Every record "
                  f"stays on this machine and nothing is deleted. Said once.")

    def _refuse_url(self, refusal: str) -> None:
        """Once per process: the loop keeps ticking, the operator is told once."""
        if self._url_refused_said:
            return
        self._url_refused_said = True
        self.log(f"  ⚠ NOT SENDING: {refusal}. Every record stays on this "
                  f"machine and nothing is deleted; re-run install.py with an "
                  f"https:// --collector-url to resume. Said once.")

    def tick(self) -> dict:
        result = {"shipped": 0, "outcomes": [], "skipped": ""}
        if not self.settings.configured:
            result["skipped"] = f"not configured: {self.settings.why_not_configured()}"
            return result
        refusal = config.collector_url_refusal(self.settings.collector_url)
        if refusal:
            # ⚠ BEFORE ANY SEND, HEARTBEAT OR POLICY POLL (item E). A saved
            # http:// URL on an existing install: nothing leaves, nothing is
            # marked shipped, nothing is pruned — every record stays local.
            self._refuse_url(refusal)
            result["skipped"] = f"refused: {refusal}"
            return result
        if not self.ships["agreed"]:
            # ⚠ NEVER MORE THAN THE MACHINE AGREED TO. No batch without the
            # agreement install.py records after showing what ships. The
            # heartbeat and the policy poll carry no record and ran under every
            # agreement there ever was, so they go on.
            self._say_held()
            result["skipped"] = f"held: {self.ships['detail']}"
            self.heartbeat.maybe_send(self.log)
            self.policy_poll.maybe_fetch(self.log)
            return result
        if self._keyed(again=True) is None:
            # ⚠ NEVER A RAW FINGERPRINT, AND NEVER A NEW KEY OVER AN OLD ONE. A
            # key file that does not hold a key holds every record instead; the
            # heartbeat and the policy poll carry none, so they go on.
            result["skipped"] = "held: no usable fingerprint key"
            self.heartbeat.maybe_send(self.log)
            self.policy_poll.maybe_fetch(self.log)
            return result
        if self.now() < self._retry_after:
            result["skipped"] = "backing off"
            return result

        pending = self.pending()
        urgent = self.urgent_sessions()
        result["urgent"] = sorted(urgent)
        if self.should_flush(pending, urgent=bool(urgent)):
            for path in self.session_logs():
                session_id = path.name[:-len(LOG_SUFFIX)]
                # ⚠ "UP TO AND INCLUDING IT" NEEDS A LOOP, AND THE CAP IS WHY.
                #
                # `ship_session` sends at most MAX_BATCH_RECORDS (1000). A deny
                # sitting at pending position 1500 would NOT be in the first
                # batch, so a single call would flush urgently and still leave
                # the urgent record on disk — the feature silently not working
                # in exactly the case it was built for (a laptop back from
                # being offline, which is also when a deny matters most).
                #
                # ⚠ BOUNDED, AND THE BOUND IS THE PENDING COUNT. Each pass ships
                # at least one record or stops, so this cannot spin: a send that
                # does not advance the cursor returns a non-advancing outcome
                # and breaks out below.
                rounds = 0
                while True:
                    kind = self.ship_session(path)
                    rounds += 1
                    if kind:
                        result["outcomes"].append(kind)
                        if kind in (client.STORED, client.STORED_WITH_GAP):
                            result["shipped"] += 1
                    # Stop unless this session is urgent AND still has an
                    # urgent record pending AND the last send made progress.
                    if (session_id not in urgent
                            or kind not in (client.STORED, client.STORED_WITH_GAP)
                            or session_id not in self.urgent_sessions()
                            or rounds >= config.MAX_URGENT_ROUNDS):
                        break
            self._last_flush = self.now()

        self.heartbeat.maybe_send(self.log)
        self.policy_poll.maybe_fetch(self.log)
        return result

    def announce_what_ships(self) -> None:
        """What this process sends, and where that was agreed, before anything
        ships. ⚠ A SETTING NOTHING READS ANY MORE IS STILL NAMED: a machine
        that carries `STING_TIER` is told, here and in `--status`, that nothing
        sends by it."""
        what = self.ships
        if what["ships"] == config.HELD:
            self.log(f"  ships    NOTHING YET — {what['detail']}")
        else:
            self.log(f"  ships    {what['detail']}")
        for ignored in what["ignored"]:
            self.log(f"  ignored  {ignored['setting']}={ignored['value']!r} "
                      f"({ignored['where']}): tiers are gone, and nothing reads it")
        if sparta_iface.enabled(self.settings.sparta_flags):
            # ⚠ ONLY WHEN ON: with the flag off this banner is the one it was.
            self.log(f"  sparta   {sparta_iface.FLAG}=1: what Sparta suspects is masked "
                     f"too, and records carry {sparta_iface.SUSPECTED_FIELD} (types "
                     f"and offsets, never values) and {sparta_iface.INTENT_FIELD}; "
                     f"never a verdict")

    def run(self) -> int:
        self.log(f"sting shipper -> {self.settings.collector_url or '(unset)'}")
        self.log(f"  device   {self.settings.device_id or '(unset)'}")
        self.announce_what_ships()
        self.log(f"  logs     {self.settings.log_root}")
        self.log(f"  flush    every {self.settings.flush_seconds}s or "
                  f"{self.settings.flush_records} records "
                  f"(worst case ~{self.settings.flush_seconds + config.POLL_SECONDS}s "
                  f"from action to collector)")
        if not self.settings.configured:
            self.log(f"  ⚠ NOT CONFIGURED ({self.settings.why_not_configured()}). "
                      f"Records still accumulate locally and will ship when this "
                      f"is set — nothing is lost and the hook is unaffected.")
        try:
            while True:
                self.tick()
                time.sleep(config.POLL_SECONDS)
        except KeyboardInterrupt:
            self.log("\nstopped — unshipped records remain on disk")
        return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="one pass, then exit")
    ap.add_argument("--status", action="store_true",
                     help="what the cursor holds; touches no network")
    args = ap.parse_args(argv)

    settings = config.from_env()
    shipper = Shipper(settings)

    if args.status:
        print(json.dumps({
            "collector": settings.collector_url or None,
            "device_id": settings.device_id or None,
            "configured": settings.configured,
            # ⚠ THE SAME FACTS AS THE STARTUP BANNER, IN THE OUTPUT SOMEONE
            # PARSES. `--status` is what a second person runs when asking "what
            # is this machine sending?": `masked`, or `held` until install.py.
            "ships": shipper.ships["ships"],
            "what_ships": shipper.ships,
            "pending_records": shipper.pending(),
            "sessions": shipper.cursor.summary(),
            # ⚠ WHAT SHIPS IS READ FROM THE SETTINGS NOW; A RUNNING SHIPPER
            # READ THEM WHEN IT STARTED. `predates_settings` says when those
            # differ in time, with the command that restarts it.
            "running_shipper": service.running_shipper(settings.state_root)},
            indent=2))
        return 0

    # ⚠ ONE SHIPPER PER STATE ROOT, AND THIS IS WHERE IT IS ENFORCED.
    # Two processes on one cursor can lose `skipped_seqs` — the names of records
    # the collector REFUSED, which exist nowhere else — while `acked_seq` climbs
    # past them, after which `tools/prune_shipped.py` deletes them. See
    # `shipper/singleton.py` for the measurement.
    #
    # ⚠ AND A SECOND SHIPPER EXITS 0, NOT 1. It is not a failure that the job is
    # already being done; the Startup shortcut, the scheduled task and the
    # installer may all legitimately try, and a non-zero exit would make Task
    # Scheduler report a broken task for the one state that is entirely correct.
    lock = singleton.Lock(singleton.lock_path(settings.state_root))
    try:
        lock.acquire()
    except singleton.Held as held:
        print(f"another shipper is already running (pid {held.pid}); "
               f"this one is exiting so the two cannot share a cursor")
        return 0

    try:
        if args.once:
            # ⚠ FLUSH REGARDLESS OF THE INTERVAL. `--once` is what cron and a
            # test invoke, and honouring a 300 s timer in a process that exits
            # immediately would mean it almost never ships.
            shipper._last_flush = 0.0
            print(json.dumps(shipper.tick(), sort_keys=True))
            return 0

        return shipper.run()
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
