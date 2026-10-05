"""Where each session got to. Persisted, so a closed laptop resumes.

⚠ THE CURSOR IS AN INDEX, NOT A SEQ, AND THE DIFFERENCE IS LOAD-BEARING.
`seq` is not unique within a session: allow-once deliberately writes a SECOND
record at the same seq, and a canary carries `seq: None`. Slicing a log with
"everything after seq N" would drop one record of every allow-once pair and
would not know what to do with a canary at all.

The log is append-only, so the COUNT of records already shipped is a stable
slice point: `records[shipped:]` is exactly what is new, forever. `last_seq` is
carried alongside for humans and for the heartbeat, and nothing slices on it.

⚠ AND `ends_at` IS CARRIED BECAUSE THE COLLECTOR NEEDS IT. A batch declares
`continues_from` — the hash of the last record of the previous batch — and the
collector compares that against what it holds. Recomputing it would mean
re-hashing the log; remembering it is one string.

WHAT THIS SURVIVES, which is the reason it is on disk at all:

    the laptop is closed mid-session      resumes at the same index
    the shipper is killed                 same
    wifi dies for a day                   the log keeps growing, nothing is
                                          shipped, and one restart later the
                                          backlog goes out in capped batches
    the collector was down and returns    same

⚠ RETRIES ARE EXPECTED AND ARE NOT MADE SAFE HERE. The cursor advances only
after a batch is confirmed stored, so a crash between POST and confirmation
re-sends. That is correct and cheap: the collector keys records on
(device, session, seq, event) and drops what it already holds. Idempotency is
the collector's job — trying to never retry would be a much harder promise, and
a wrong one.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

GENESIS = "0" * 64


@dataclass
class Position:
    """One session's place in the queue.

    ⚠ TWO MARKS, AND THEY ARE NOT THE SAME MARK. `shipped` is how far the loop
    has moved on; `acked_seq` is how far the COLLECTOR has said it stored. They
    differ, and the difference is the whole reason anything may be deleted.

    `_split` steps `shipped` over a record the collector refused as too large —
    no round trip, nothing stored — so `shipped` alone authorises nothing. Only
    a 200/202 carrying the collector's own `records_stored` and `batch_ref`
    moves `acked_seq`.
    """
    shipped: int = 0            # how far the loop has moved on
    ends_at: str = GENESIS      # hash of the last one, for continues_from
    last_seq: int | None = None
    updated_at: float = 0.0
    gaps: int = 0               # 202s seen for this session — information
    # ⚠ HOW THE COLLECTOR HOLDS THIS SESSION'S CHAIN: keyed once a batch whose
    # fingerprints were keyed was stored (core/wire.py). A session it holds raw
    # — shipped before keyed fingerprints (docs/107) — continues through one
    # bridge batch that starts from the raw head it holds. `ends_at` stays the
    # LOCAL hash.
    keyed: bool = False

    # ---- what the COLLECTOR said, and nothing else --------------------------
    acked_seq: int | None = None     # highest seq inside a batch it stored
    acked_ends_at: str = GENESIS     # that batch's last hash
    acked_records: int = 0           # SUM of its own records_stored
    acked_at: float = 0.0
    last_batch_ref: str = ""         # the receipt, quotable back at it
    skipped_seqs: list = None        # ⚠ stepped over, NEVER stored anywhere

    def __post_init__(self) -> None:
        if self.skipped_seqs is None:
            self.skipped_seqs = []

    def as_dict(self) -> dict:
        return {"shipped": self.shipped, "ends_at": self.ends_at,
                "last_seq": self.last_seq, "updated_at": self.updated_at,
                "gaps": self.gaps, "keyed": self.keyed,
                "acked_seq": self.acked_seq,
                "acked_ends_at": self.acked_ends_at,
                "acked_records": self.acked_records,
                "acked_at": self.acked_at,
                "last_batch_ref": self.last_batch_ref,
                "skipped_seqs": sorted(self.skipped_seqs)}


class Cursor:
    """session_id -> Position, persisted as one small JSON file."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._positions: dict[str, Position] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # ⚠ A CORRUPT CURSOR RESETS TO ZERO RATHER THAN CRASHING, and that
            # is the safe direction: re-shipping a whole session costs the
            # collector some deduplication work, while refusing to start costs
            # every later record. The collector's key makes the re-ship inert.
            return
        for session, entry in (raw.get("sessions") or {}).items():
            if not isinstance(entry, dict):
                continue
            self._positions[session] = Position(
                shipped=int(entry.get("shipped") or 0),
                ends_at=str(entry.get("ends_at") or GENESIS),
                last_seq=entry.get("last_seq"),
                updated_at=float(entry.get("updated_at") or 0.0),
                gaps=int(entry.get("gaps") or 0),
                keyed=entry.get("keyed") is True,
                acked_seq=entry.get("acked_seq"),
                acked_ends_at=str(entry.get("acked_ends_at") or GENESIS),
                acked_records=int(entry.get("acked_records") or 0),
                acked_at=float(entry.get("acked_at") or 0.0),
                last_batch_ref=str(entry.get("last_batch_ref") or ""),
                skipped_seqs=[int(x) for x in (entry.get("skipped_seqs") or [])
                               if isinstance(x, (int, float))])

    def get(self, session_id: str) -> Position:
        return self._positions.setdefault(session_id, Position())

    def advance(self, session_id: str, *, shipped: int, ends_at: str,
                 last_seq: int | None, gap: bool = False,
                 keyed: bool | None = None) -> None:
        position = self.get(session_id)
        if keyed is not None:
            position.keyed = keyed
        position.shipped = shipped
        position.ends_at = ends_at
        position.last_seq = last_seq
        position.updated_at = time.time()
        if gap:
            position.gaps += 1
        self.save()

    def acknowledge(self, session_id: str, *, last_seq: int | None,
                     ends_at: str, stored: int, batch_ref: str) -> None:
        """⚠ THE ONLY THING THAT MAY AUTHORISE A DELETION, and the only writer
        of it. Called from the `outcome.advances` branch alone, with values
        taken from the collector's own response body — `records_stored` and
        `batch_ref` — rather than from what this side hoped it sent.
        """
        position = self.get(session_id)
        if last_seq is not None and (position.acked_seq is None
                                      or last_seq > position.acked_seq):
            position.acked_seq = int(last_seq)
        position.acked_ends_at = ends_at
        position.acked_records += max(0, int(stored or 0))
        position.acked_at = time.time()
        if batch_ref:
            position.last_batch_ref = str(batch_ref)
        self.save()

    def note_skipped(self, session_id: str, seq: int | None) -> None:
        """A record the loop stepped over that NOTHING has stored. It sits below
        `acked_seq` once later batches land, so without this list a prune would
        read it as acknowledged and delete the one record known not to exist
        anywhere else."""
        if seq is None:
            return
        position = self.get(session_id)
        if int(seq) not in position.skipped_seqs:
            position.skipped_seqs.append(int(seq))
        self.save()

    def save(self) -> None:
        """tmp + rename. A crash mid-write must not leave a truncated cursor —
        a truncated cursor parses as "nothing shipped" and re-sends everything,
        which is survivable but noisy, and it is free to avoid."""
        payload = json.dumps(
            {"sessions": {s: p.as_dict() for s, p in self._positions.items()}},
            sort_keys=True, indent=1)
        tmp = self.path.with_suffix(f".tmp{secrets.token_hex(4)}")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self.path)

    def summary(self) -> dict:
        return {session: position.as_dict()
                for session, position in sorted(self._positions.items())}
