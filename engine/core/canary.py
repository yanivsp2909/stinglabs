"""Decoy secrets — "canaries" — for the secret/egress matcher.

⚠ NOT the audit-log canary in core/wire.py. That one attests a shipped batch's log
is intact. THIS canary is a DECOY CREDENTIAL: a value nothing legitimate ever
reads, so if it appears in an action it is near-certain proof of exfiltration —
the strongest signal the engine can produce. It is recognised by the same idea as
a real traced secret (an exact hash of the value tokens), stored HASH-ONLY, and it
never announces itself with a prefix.

Pure by construction — this module does no IO and imports nothing but `secrets`
and `hashlib`, so `core/` stays replayable (the same rule `core/engine.py` obeys).
The IO half — persisting the fingerprint, planting the decoy VALUE where an
attacker would find it — lives at the session boundary (`core/session.py`).

THE PLANT, end to end:
  value, fp = canary.mint()          # value is high-entropy, prefix-free
  # 1. write `value` into a decoy an attacker rummages but real work never reads
  # 2. persist ONLY `fp` (e.g. STING_CANARY_FP in ~/.sting/env) — never `value`
The engine then loads `fp` into SessionState.canary_fingerprints and matches it on
every egress AND on git-staged content about to be pushed. The plaintext `value`
never returns to the engine or the agent.

⚠ TWO LIMITATIONS, STATED NOT HIDDEN:

  1. FULL-TRUST HOST READ DEFEATS IT. The fingerprint is a PUBLIC, unkeyed
     `sha256(value)` and the store (STING_CANARY_FP, ~/.sting/env, 0600) is
     readable by the user the agent runs as. An attacker who has ALREADY reached
     that boundary — same-user filesystem read+exec, exactly Sting's own threat
     model — can read the decoy value(s) and the fingerprint, recompute the hash
     of each thing it plans to send, and DROP anything that matches, defeating the
     canary for the very attacker most likely to trip it. This is the fundamental
     limit of any on-host hash honeytoken whose verifier shares the target's trust
     boundary; it is not fixed here. Mitigations that would (a keyed/HMAC
     fingerprint whose key is NOT co-located, remote-only verification, or watching
     reads of the store itself) are out of scope and noted as follow-ups.

  2. The canary catches a value carried in an action's command/url/content and in
     git-STAGED content headed for a push/commit. A value smuggled through a
     channel the engine cannot see (a covert side-channel, an unlogged tool) is
     outside its reach — the same blind spot every content check here has.
"""
from __future__ import annotations

import hashlib
import secrets

# A canary VALUE is 32 url-safe base64 characters (~192 bits). It is deliberately
# INDISTINGUISHABLE from an ordinary API token:
#   - NO prefix, NO marker. Stroq shipped `stroq_canary_…`, which anyone who read
#     the disk could grep out and step around; a prefix-free random string cannot
#     be singled out as "the decoy" by its shape.
#   - high entropy, so it survives the value-token scan wherever it appears.
_CANARY_VALUE_BYTES = 24

# ⚠ THE FULL sha256, NOT the engine's 8-hex needle. `fingerprint_values`/
# `fingerprints_in` truncate to 8 hex because a real-secret match feeds an ASK/DENY
# where a 2**-32 collision is tolerable. A CANARY match is an UNCONDITIONAL DENY
# labelled "near-certain exfiltration" — a false one blocks real work with a theft
# alarm — so the canary matches on the WHOLE 64-hex digest: an accidental collision
# with a value legitimately in an egress is ~2**-256, i.e. impossible, which is what
# lets "near-certain" be a true statement rather than a 32-bit approximation. Still
# an exact fingerprint, deterministic, hash-only — no entropy or heuristic.
_FP_LEN = 64
_HEX = set("0123456789abcdef")


def fingerprint(value: str) -> str:
    """The needle for `value`: the full sha256 hex digest. One-way — the value
    cannot be recovered from it, which is what lets the fingerprint be stored at
    rest while the value is not."""
    return hashlib.sha256(value.encode()).hexdigest()


def mint() -> tuple[str, str]:
    """A fresh (value, fingerprint). The caller plants `value` in a decoy location
    and persists ONLY `fingerprint`; the value never comes back to the engine.

    The value is ~192 bits of randomness and the match is on the full digest, so an
    accidental collision with any value a session legitimately handles is effectively
    impossible — which is what makes a canary hit certain rather than probabilistic."""
    value = secrets.token_urlsafe(_CANARY_VALUE_BYTES)
    return value, fingerprint(value)


def _is_fingerprint(token: str) -> bool:
    """A stored needle is exactly _FP_LEN lowercase hex characters. Anything else is
    corruption or a hand-edit, never a live canary — so it is REPORTED, not silently
    kept or silently dropped."""
    return len(token) == _FP_LEN and all(c in _HEX for c in token)


def parse_fingerprints(raw: str | None) -> tuple[list[str], str | None]:
    """A persisted store value -> (fingerprints, unarmed_reason).

    ⚠ FAIL LOUD, NOT SILENT — the second Stroq weakness. Their canary vanished
    without a trace when its index corrupted, leaving false confidence. Here the
    four cases are distinct and the dangerous ones are always surfaced:
      - raw empty / None        -> ([], None)      no canary configured; silent is
                                                   correct, no protection is claimed.
      - raw present, all valid  -> (fps, None)     ARMED.
      - raw present, none valid -> ([], reason)    CONFIGURED BUT DISARMED — the
                                                   caller MUST surface `reason`.
      - raw present, some valid -> (good, reason)  partial corruption — still armed
                                                   on the survivors, still surfaced.
    """
    if not raw or not raw.strip():
        return [], None
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    good = [t for t in tokens if _is_fingerprint(t)]
    bad = [t for t in tokens if not _is_fingerprint(t)]
    reason = None
    if bad or not good:
        n = len(bad)
        reason = (f"{n} unreadable canary entr{'y' if n == 1 else 'ies'} in the "
                  f"store and {len(good)} valid — the decoy may be DISARMED; "
                  f"re-plant it (a disarmed canary gives false confidence).")
    return good, reason
