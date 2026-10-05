"""The fingerprints a record ships with: keyed, or not sent at all.

Re-exported by `core.wire`, the batch format, which requires `fingerprint`
the way it requires `mask`: no batch leaves carrying a digest of text it does
not ship.

────────────────────────────────────────────────────────────────────────────────
WHY `prev` AND `hash` SURVIVE, KEYED — AND WHY THE DIGESTS DO NOT
────────────────────────────────────────────────────────────────────────────────

They are the local chain, sha256 over the RAW record, and the collector's gap
detection follows them (§2.3): `continues_from` against the head it holds, and
its export walks `prev` -> `hash` from GENESIS. Shipped as they are, they were
also a CHECK AGAINST A GUESS: every other byte of a masked record ships beside
`hash`, so a masked value that can be guessed — a weak password, an email from
a staff list — could be confirmed offline (fill it in, hash, compare), and so
could `command_sha256` (the raw command) and `action_hash`.

So the copy that ships carries neither form (`ship_record`, docs/107):

  hash, prev,        HMAC-SHA256 of the local value under a per-laptop key
  continues_from     (`fingerprinter`). Every equality holds — record i's keyed
                     `prev` is record i-1's keyed `hash` — and nothing can be
                     checked without the key, which never leaves the laptop.
                     GENESIS stays GENESIS: the collector compares a new
                     session's first batch with the literal.
  command_sha256,    NOT SENT, and neither is a derived log's `original_sha256`
  action_hash        or any other field named as a digest (`is_not_sent`).
                     Nothing downstream reads them (the collector and
                     its dashboard, read at their main).

A record says so in its own `fingerprints` field. Its keyed `hash` attests the
original record to someone holding the key and the local log
(`tools/verify_log.py --export --key`), and nothing to anyone else —
`provenance.original_provenance_verifiable` says that, as a field.

⚠ THE SWITCH INSIDE A LIVE SESSION. A session the collector holds raw
continues through one bridge batch (`raw_anchor`): its `continues_from` and its
first record's `prev` stay raw — values the collector already holds — and
everything after is keyed, so no gap and no break reads where the form changes.
The sender bridges only on three signals that agree (no keyed mark for the
session, its last store older than the key, and the key's record not naming
it): a lost mark or a restored cursor reads as a gap, never as a raw hash of a
record the collector holds keyed (shipper/run.py).
"""
from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable

from core.audit_log import GENESIS, ORIGINAL_DIGEST_FIELD

FINGERPRINTS_FIELD = "fingerprints"
FINGERPRINTS_KEYED = "hmac-sha256"
"""On every record shipped keyed (docs/107), in `fingerprints`: its `hash`
and `prev` are HMAC-SHA256 of the local values under its laptop's key, and
`command_sha256` / `action_hash` were not sent. A verifier reads it to know
the record's local hash is not checkable without that key."""

_NOT_SENT = ("command_sha256", "action_hash", ORIGINAL_DIGEST_FIELD)
"""Digests of raw text nothing downstream reads: dropped from what ships —
the hook's two, and the digest a derived log keeps from before its
redaction (tools/redact_logs.py). ⚠ FOUND BY THE MEASURE: that third name
carried the raw command's digest in 35 records of the snapshot."""


_DIGEST_SUFFIXES = ("_sha256", "_sha512", "_sha1", "_md5", "_digest", "_hmac", "_hash")
"""What a field named as a digest ends in (security review, LOW: only
`*_sha256` generalised). The chain's own `hash` and `prev` are keyed, not
dropped, and `tier_hash` is added after this runs."""


def is_not_sent(key: str) -> bool:
    """Is this field a digest of raw text, which stays behind? The named ones,
    and ANY field named as a digest a later version adds: a digest beside
    masked text is a check for a guess, whatever it is called."""
    return key in _NOT_SENT or key.endswith(_DIGEST_SUFFIXES)


_MIN_KEY_BYTES = 32


def fingerprinter(key: bytes) -> Callable[[str], str]:
    """The keyed form of a local chain value: HMAC-SHA256 under `key`, 64 hex.

    ⚠ GENESIS STAYS GENESIS. It is a constant, not a digest of anything, and
    the collector compares a new session's first `continues_from` with the
    literal: keyed, every new session would open with a gap."""
    if not isinstance(key, (bytes, bytearray)) or len(key) < _MIN_KEY_BYTES:
        raise ValueError(f"a fingerprint key is {_MIN_KEY_BYTES}+ bytes")
    secret = bytes(key)

    def keyed(value: str) -> str:
        if value == GENESIS:
            return GENESIS
        return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return keyed


def ship_record(record: dict, *, mask: Callable[[dict], dict],
                fingerprint: Callable[[str], str], raw_prev: bool = False) -> dict:
    """A record exactly as it leaves the machine: masked, then its fingerprints
    keyed and the digests nothing reads dropped, then marked. `raw_prev` keeps
    the local `prev` for the first record of a bridge batch (`build_batch`)."""
    out = {k: v for k, v in mask(record).items() if not is_not_sent(k)}
    if isinstance(out.get("hash"), str):
        out["hash"] = fingerprint(out["hash"])
    if isinstance(out.get("prev"), str) and not raw_prev:
        out["prev"] = fingerprint(out["prev"])
    out[FINGERPRINTS_FIELD] = FINGERPRINTS_KEYED
    return out


def carries_keyed_fingerprints(record: dict) -> bool:
    """Were this record's fingerprints keyed before it shipped? Read from its
    own field; like `masked`, a field whoever can edit an export can add."""
    return FINGERPRINTS_FIELD in record
