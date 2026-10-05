"""The batch format decision logs travel in, and what a record is when it ships.

⚠ SINCE 28 SEP 2026 THERE ARE NO TIERS. Every record ships as ONE thing: the
whole record, with every value Sting recognises replaced by its TYPE,

    curl -H "Authorization: Bearer [token]" https://api.example.com -d owner=[email]

and every batch says so: `tier: "masked"`. The masking belongs to the sending
process (its `mask` module), done while the batch is built, on the sending
machine, so a value it recognises is ABSENT from the artifact that travels
rather than hidden in it. This module builds the batch around the masker it is
handed (`build_batch(mask=…)`); it cannot import the sender, and neither the
hook nor the engine imports it. (Worded without naming that process: this
module is on the hook path, imports `subprocess`, and a test forbids the
conjunction.) The local record is never touched: the log stays raw, it
is the developer's evidence.

⚠ THIS IS NOT IDENTIFIER REDACTION, AND THE TWO MUST NOT BE CONFLATED.

    IDENTIFIER REDACTION (tools/redact_logs.py) hides WHO produced a record, so
    a PUBLISHED artifact — a vendored fixture, a demo — does not name a person.
    It has no business on this path: a manager seeing which developer ran a
    command is the product, not a leak. Nothing in this module imports it.

    MASKING (the sender's `mask` module) hides the VALUES a record carries —
    keys, tokens, passwords, emails, what the session read from a credential
    file — and leaves the command readable.

WHAT A MASKED BATCH CAN STILL CARRY is `can_leak()`, in every batch's
provenance, stated at its worst: a value Sting does not recognise leaves as
written, and every path, host and heredoc body goes with the command.

⚠ THE TIERS THAT WERE, AND WHY THEIR NAMES ARE STILL HERE. Until 28 Sep 2026 a
batch declared one of four tiers — `full`, `verdict_reason_evidence`,
`verdict_reason_location` (the default), `verdict` — and every tier below
`full` dropped the command, the cwd and the paths before the batch existed
(docs/99, #74). Exports shipped at those tiers are still read, so their names
and the fields each carried stay: `verify_batch`, `shipped_below_full` and the
tier-chain verifiers read them exactly as before. Nothing builds one any more,
and a machine that agreed to one ships nothing new until a person re-runs the
installer and sees what ships now (the sender's `Settings.ships`).

────────────────────────────────────────────────────────────────────────────────
WHY `prev` AND `hash` SURVIVE, KEYED — AND WHY THE DIGESTS DO NOT
────────────────────────────────────────────────────────────────────────────────

The local chain is what the collector's gap detection follows, so it ships —
keyed with the laptop's key, and every digest of raw text stays behind, so
nothing that ships can check a guess of a masked value: `core/fingerprints.py`
(`ship_record`, `fingerprinter`), docs/107. A session the collector holds raw
continues through one bridge batch (`build_batch(raw_anchor=True)`).
"""
from __future__ import annotations

import platform
import subprocess
from collections.abc import Callable
from pathlib import Path

from core.audit_log import GENESIS, canonical, read_records, record_hash
from core.fingerprints import (FINGERPRINTS_FIELD, FINGERPRINTS_KEYED,  # noqa: F401
                               carries_keyed_fingerprints, fingerprinter, is_not_sent,
                               ship_record)
from core.purpose import (BENCHMARK, INSTALL_PROBE, PREFLIGHT,  # noqa: F401
                           PURPOSES, WORK)

WIRE_VERSION = 2
"""2 added the top-level `purpose`. See `PURPOSES` for what it is and — more
importantly — for what its ABSENCE means.

⚠ BOTH DIRECTIONS, STATED HERE, BECAUSE A FORMAT THAT DOCUMENTS ONLY THE
CONVENIENT ONE IS A FORMAT THAT BREAKS SOMEBODY.

  A NEWER BATCH (v2) AT AN OLDER COLLECTOR (knows v1)
      Its `check_shape` requires a fixed list of fields and does not forbid
      extra ones, so a v2 batch is ACCEPTED AND STORED, with `purpose` carried
      into whatever it keeps verbatim. It is not read, because nothing there
      looks for it, and it is not exposed, because that collector's tripwire
      governs manifest keys and this is not one. Additive, not fatal — which is
      the whole reason this is a top-level field and not a new required one.

  AN OLDER BATCH (v1) AT A NEWER COLLECTOR (knows v2)
      No `purpose` key at all, which is exactly the state the third value exists
      for. It reads as ABSENT, never as `work`. A collector that defaulted it to
      `work` would relabel every session already in its store as real work,
      which is the error this field was built to remove.

  THIS ENGINE READING EITHER
      `verify_batch` pins `wire_version == WIRE_VERSION`, so a v1 batch is
      reported as a version problem rather than silently interpreted. Reading is
      a verification path, and a verifier that accepts a format it does not know
      is not a verifier.

⚠ `masked` DID NOT BUMP IT. The envelope's keys are the same; its `tier` holds
a new value, which the collector carries verbatim and never re-derives (its
own test posts a tier invented "next year" and expects 200), and the records
hold the same fields they held at `full`, plus `masked` where masking rewrote
one.
"""

MASKED = "masked"
"""What every batch declares since 28 Sep 2026, in its `tier` field: whole
records, every value Sting recognises replaced by its type."""

MASKED_FIELD = "masked"
"""The count beside every record masking rewrote — `{"aws-key": 1, "email": 2}`
— and the only trace of a rewrite a reader of the record has. Absent on a record
masking did not change, which then still matches its own local `hash`."""

FULL = "full"
REASONED = "verdict_reason_evidence"
LOCATED = "verdict_reason_location"
VERDICT = "verdict"
TIERS = (FULL, REASONED, LOCATED, VERDICT)
"""The tiers a batch declared before 28 Sep 2026. Read, never built."""

SHAPES = (MASKED, *TIERS)
"""Every `tier` value a batch this verifier reads can declare."""

# ─────────────────────────────────────────────────────────────────── purpose
#
# ⚠ WHAT THIS IS FOR. Nine of the twelve sessions in the first real collector
# store are not work: two install probes, four preflights, a latency harness,
# and two that predate everything. Nothing downstream could tell them from a
# developer's actual session, so any rate measured over that store pools probes
# with work — the error that has already invalidated two of this project's
# headline numbers.
#
# ⚠ AND IT IS A CLAIM, NEVER A MEASUREMENT. `purpose` is what the SENDER says
# this batch is. Nothing verifies it and nothing can: a probe that declares
# itself `work` is indistinguishable from work, and a reader who treats this
# field as evidence has been misled by it. It is carried verbatim for the same
# reason `can_leak` is — the receiver renders the sender's claim, and never
# paraphrases it into something stronger.
#
# ⚠ THE ALTERNATIVE WAS REFUSED AND THE REFUSAL IS THE DESIGN. Classifying by
# session-id spelling — "starts with preflight-" — infers intent from a name the
# sender chose, and breaks the day a probe is named differently. Declaration at
# the source is the only version of this that cannot rot.
# ⚠ FEWER IS BETTER THAN MORE, AND A MEMBER WITH NO CURRENT SENDER DOES NOT
# EXIST YET. Each of these three has a producer in this repo today:
#
#   work           the sending loop, carrying a session an agent produced.
#                  The only value that means "count this".
#   install_probe  install.py's empty authenticated batch — it proves a token
#                  before anything is written into a hook config, and it is the
#                  purest example of the problem: zero records, one session, and
#                  indistinguishable from a real session that shipped nothing.
#   preflight      tools/preflight.py's round trip. It builds a real record and
#                  reads it back OUT of the collector, so it is a full session
#                  with a real chain — and it happens on every install.
#
# TWO WERE PROPOSED AND ARE NOT HERE:
#
#   benchmark      `bench-sub` is in the store, but nothing SENDS it. It is
#                  written by tools/bench_latency.py THROUGH the hook, into the
#                  ordinary session root, and then swept up like any other log.
#                  No sender can declare it, so the member would be a value
#                  nothing ever sets — `purpose_for` in the sending loop states
#                  why that is a real gap rather than an oversight.
#   test           the suite posts to an in-process collector fixture it starts
#                  itself, never to a deployed one. There is no sender.
#
# Adding a member later is additive at the wire and costs the receiver one line.
# Removing one is not. So the set starts at three.
# ⚠ DEFINED IN `core/purpose.py`, NOT HERE, AND RE-EXPORTED. The record body
# needs the same closed set, `audit_log` cannot import this module without a
# cycle, and two copies of a closed set is one chance for them to disagree.

# Every record carries these UNMASKED, and every tier carried them. Ours or
# opaque: no user-authored bytes.
#   ts/seq/event/kind/decision  the shape of what happened
#   rule_id                     a name we chose
#   session_id/agent            the agent's own ids
#   duration_ms                 a number
#   prev/hash                   digests; see the module docstring
#   guard_version               which policy DECIDED it; see below
#   purpose                     what the session IS; see below
#
# ⚠ `guard_version` IS IN THE SPINE. It is a string this project writes at
# install time — no user-authored bytes, nothing an attacker composes — and a
# verdict that arrives without the policy that made it cannot be judged.
# ⚠ `relaxed` IS IN THE SPINE FOR EXACTLY `guard_version`'s REASON: "which rules
# were turned down" is part of the policy that made a verdict. It is our own
# strings, no user-authored bytes, and it is absent from the record entirely on
# an unrelaxed machine, which is every machine by default.
# ⚠ `enforced` IS IN THE SPINE FOR `decision`'s REASON: it is the answer the
# agent was given (after the relaxations, a one-shot grant, observe mode), one
# of our three decision strings, and a record shipped without it would make
# every relaxed DENY read as a stop (docs/113 §1).
# ⚠ `session_id`, `seq`, `event`, `prev` AND `hash` ARE THE COLLECTOR'S KEYS: its
# document id and its gap detection read them, so masking one would file a
# record under a different name or break the chain it continues.
_SPINE = ("ts", "session_id", "seq", "event", "kind", "decision", "rule_id",
           "agent", "duration_ms", "prev", "hash", "guard_version", "purpose",
           "relaxed", "enforced")

# What LOCATED and REASONED added to the spine, before 28 Sep 2026: `reason`
# (the rule's own words by then, #74) and `granted_by`, WHO approved a human
# override. Kept to read an old export by; see `shipped_below_full`.
_LOCATED_EXTRA = ("reason", "granted_by")

# The offset LOCATED carried in place of the span. Kept to read old exports by.
_LOCATION_FIELD = "evidence_location"


# ═══════════════════════════════ the chain over what SHIPS (docs/99)
#
# ⚠ WHY A SECOND CHAIN. `prev`/`hash` are made by the hook over the FULL body
# as it writes the local log, and masking happens later, in the sending process
# — so on any record masking rewrote (and, before 28 Sep 2026, on every record
# below `full`) the shipped `hash` attests bytes that never left the machine and
# nothing can re-verify it (the collector's chain-at-tier design, option (a)).
#
# So the SENDER chains the bytes it actually ships, in the order
# mask -> hash, and ADDS the result. The local chain, the cursor and
# `continues_from` are untouched. `tier_chain` is the format marker a verifier
# reads: a record without it is old-format, never a tampered one.
TIER_CHAIN_VERSION = 1
_TIER_CHAIN_KEYS = ("tier_prev", "tier_hash")
_NOT_IN_TIER_BODY = ("prev", "hash") + _TIER_CHAIN_KEYS


def tier_body(record: dict) -> dict:
    """The bytes `tier_hash` covers: the shipped record minus both chains' links."""
    return {k: v for k, v in record.items() if k not in _NOT_IN_TIER_BODY}


def chain_at_tier(records: list[dict], start: str) -> list[dict]:
    """New records, each marked and carrying `tier_prev` / `tier_hash` over
    exactly its shipped bytes. `start` is the batch's `continues_from` as it
    ships — the local hash, keyed (or raw for a bridge) — so a batch anchors on
    the chain the collector holds and no new cursor state exists. Call it
    LAST: on the records as they will be sent (`build_batch` does)."""
    chained, prev = [], start
    for record in records:
        marked = {**{k: v for k, v in record.items() if k not in _TIER_CHAIN_KEYS},
                  "tier_chain": TIER_CHAIN_VERSION}
        digest = record_hash(prev, tier_body(marked))
        chained.append({**marked, "tier_prev": prev, "tier_hash": digest})
        prev = digest
    return chained


def record_key(device_id: str, record: dict) -> tuple:
    """(device, session, seq, event) — the idempotency key.

    `event` is in the key for the reason `audit_log.identity` gives: allow-once
    deliberately writes a SECOND record at the same seq, and a canary carries
    `seq: None`, so seq alone is neither unique nor always present. A collector
    that upserts on this key dedupes a retried batch without thinking about it.
    """
    return (device_id, record.get("session_id"), record.get("seq"),
            record.get("event"))


def guard_ref() -> str:
    """The commit the SENDING TREE is on. Not the one that decided anything.

    ⚠ THIS DOCSTRING USED TO SAY "so a verdict can be tied to a policy", AND
    THAT WAS FALSE. `git describe` runs in the tree this file lives in — the
    one packing the batch. The records inside it were decided by whatever the
    hook was executing, which is a different copy the moment anything is
    installed. On the first real end-to-end run the gap was two commits, and
    every verdict in every batch was attributed to a policy that had not made
    it. Provenance that is wrong is worse than provenance that is absent,
    because a reader opens the named commit and reads the wrong rule.

    The deciding version travels per record as `guard_version` — see
    core/version.py. Two facts, two fields, and this one answers only "which
    build of the sender packed this batch". Best effort: a checkout without git
    still produces a batch.
    """
    try:
        out = subprocess.run(["git", "describe", "--always", "--dirty", "--tags"],
                              cwd=str(Path(__file__).parent.parent),
                              capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def signing_bytes(batch: dict) -> bytes:
    """EXACTLY the bytes a per-device signature covers. §2.2.

    ⚠ DEFINED NOW THOUGH SIGNING IS NOT BUILT, because deciding it later makes
    every batch stored before that decision unverifiable. The rule:

        the whole batch, with the `signature` key REMOVED, serialised by
        `audit_log.canonical` — sort_keys, no whitespace, ensure_ascii

    REUSING THE CHAIN'S CANONICALISATION IS DELIBERATE AND IT FITS. It is
    already the definition of "the exact bytes that get hashed" here, it is
    stable across Python versions and platforms (a test pins that the record
    chain is byte-identical under LF and CRLF), and having one canonical form in
    the system means a future verifier cannot disagree with the chain about what
    a record's bytes are.

    The signature block itself is excluded rather than zeroed: a zeroed field
    would still have to be reproduced byte-for-byte by the verifier, which is
    one more thing to get wrong for no gain.
    """
    return canonical({k: v for k, v in batch.items() if k != "signature"}).encode("utf-8")




def build_batch(records: list[dict], *, device_id: str, session_id: str,
                mask: Callable[[dict], dict], fingerprint: Callable[[str], str],
                continues_from: str = GENESIS, raw_anchor: bool = False,
                purpose: str | None = None) -> dict:
    """A batch of one session's records, masked and chained, ready to transmit.

    ⚠ `mask` IS REQUIRED, AND IT IS THE SENDER'S: its `mask.mask_record` with
    the session's values bound. `core/` may not import the sender, and a
    batch built with no masker would be the raw log under a label saying
    otherwise, so there is no default: no batch leaves this function unmasked.

    ⚠ AND SO IS `fingerprint` (`fingerprinter(key)`, the laptop's key): no
    batch leaves carrying a digest of text it does not ship. `continues_from`
    is the LOCAL hash the cursor holds; the batch declares it keyed — or raw
    when `raw_anchor` says the collector holds this session raw, and then the
    first record's `prev` stays raw too (the bridge; module docstring).

    ⚠ IN THE ORDER mask -> hash (docs/99). `chain_at_tier` runs LAST, over the
    records exactly as they will be sent, so `tier_hash` covers the shipped
    bytes. The local `prev`/`hash`, `continues_from` and the cursor are
    untouched, and the manifest counts the records as the hook wrote them.

    `continues_from` is the `hash` of the last record of the PREVIOUS batch for
    this session, or GENESIS for the first. §2.3: a collector that holds batch 1
    and batch 3 sees that 3 does not continue from 1's last hash and reports a
    hole, rather than accepting a session with a missing middle.

    ⚠ `purpose` HAS THREE STATES AND THE THIRD IS THE POINT. A member of
    `PURPOSES` is a claim; `None` writes NO KEY AT ALL, which is a different
    answer from every member and must stay different all the way to the reader.
    Absence means "this sender did not say" — a batch from before the field
    existed, or a sender that genuinely cannot know. **It must never be read as
    `work`**: defaulting the missing case to the common case is a comparison
    that succeeds without comparing, which is working rule 13 at the wire.

    The key is DROPPED rather than set to null: a key present with a null value
    tells a reader the field existed and was withheld, and invites a later
    reader to "restore" it. Absence is the honest encoding of "this was never
    claimed".

    ⚠ PER BATCH, SO PER SESSION IT IS A UNION. One session can receive a probe
    batch and a work batch — do not assume it cannot — so a receiver reports
    every distinct value it has seen as a sorted list, the discipline `agent`
    and `os` already follow. This function declares one batch and says nothing
    about the session.
    """
    if purpose is not None and purpose not in PURPOSES:
        raise ValueError(f"unknown purpose {purpose!r}; expected one of {PURPOSES} "
                          f"or None for 'not claimed'")
    anchor = continues_from if raw_anchor else fingerprint(continues_from)
    shipped = chain_at_tier(
        [ship_record(r, mask=mask, fingerprint=fingerprint, raw_prev=raw_anchor and i == 0)
         for i, r in enumerate(records)], anchor)
    events: dict[str, int] = {}
    for r in records:
        key = str(r.get("event") or "decision")
        events[key] = events.get(key, 0) + 1
    seqs = [r.get("seq") for r in records if r.get("seq") is not None]
    stamps = [r.get("ts") for r in records if r.get("ts") is not None]
    agents = sorted({r.get("agent") for r in records if r.get("agent")})

    batch = {
        "wire_version": WIRE_VERSION,
        "device_id": device_id,
        "session_id": session_id,
        # ⚠ THE KEY STAYS `tier`: every collector requires it and carries it
        # verbatim. Its value says what this batch IS, and there is one answer.
        "tier": MASKED,
        # A SIBLING OF `tier`, NOT A MANIFEST ENTRY. The manifest holds counts
        # this engine computed and facts about the sending environment; purpose
        # is neither. It is a property of the batch in exactly the way the tier
        # is — chosen by the sender, describing what this payload IS.
        **({"purpose": purpose} if purpose is not None else {}),
        # None when the batch holds no numbered action — a canary-only session
        # is a real session and says so, rather than claiming seqs it lacks.
        "seq_range": [min(seqs), max(seqs)] if seqs else None,
        "continues_from": anchor,
        "manifest": {
            "record_count": len(records),
            "events": events,
            "date_range": [min(stamps), max(stamps)] if stamps else None,
            "agent": agents[0] if len(agents) == 1 else (agents or None),
            "os": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
            "guard_ref": guard_ref(),
            # §2.5. Absence is a finding, not a formatting detail: it means the
            # session predates the canary or the log was assembled by hand.
            "canary_present": events.get("session_start", 0) > 0,
        },
        "provenance": provenance(),
        "records": shipped,
    }
    # Written last so `signing_bytes` has a stable input regardless of when a
    # signer runs. §2.2 — one slot, empty, with the covering rule already fixed.
    batch["signature"] = {
        "alg": None,
        "key_id": None,
        "value": None,
        "covers": "canonical(batch without the 'signature' key), utf-8",
    }
    return batch


# ⚠ WHAT A MASKED BATCH CAN LEAK, PHRASED AS A CAPABILITY AND NOT AS A REMOVAL.
#
# A removal list is a claim about the author's intent, and it is how "REASONED
# removes the thing that matters" once got written about a tier that still
# shipped the span. A leak list is a claim about the artifact, and it is the one
# an operator has to act on. Each entry is stated at its worst, not its typical.
_CAN_LEAK = [
    "every field of every record: the command (heredoc bodies included, so "
    "file contents inline), the cwd, the paths, the url, the reason and the "
    "evidence — with every value Sting recognises replaced by its type: "
    "[aws-key] and the other vendor formats, [secret-from-<file>], "
    "[org-sensitive], [token], [password], [url-password], [email], [phone], "
    "[card], [ip], and [user] for the account name in a home folder",
    "a value Sting does not recognise, as written: a password in an unusual "
    "spot (`mysql -pX`, `curl -u user:X`, a positional argument), a person's "
    "name, a hostname, and the account name in a home folder when the org's "
    "policy sends folder names (`disclosure: {\"folder_names\": \"send\"}`)",
    "the raw command's length (`command_len`), and so the total length of the "
    "values masked in it; not the values: `hash` and `prev` are keyed with a "
    "secret that never leaves this laptop, so nothing can check a guess against "
    "them, and `command_sha256` and `action_hash` are not sent",
    "which rules fired, when, how often and on which agent: a behavioural "
    "profile of the developer, and wall-clock timestamps that place a person "
    "at a keyboard",
]


def can_leak() -> list:
    """What a masked batch could reveal. Never what it removes."""
    return list(_CAN_LEAK)


def provenance() -> dict:
    """§2.4 — FIELDS, not prose, because the panel renders these and must not
    paraphrase a claim about evidence into a stronger one. The same keys a
    tiered batch carried, so no reader meets a new one."""
    return {
        # ⚠ STATED AS A CAPABILITY. See `_CAN_LEAK`: a batch that advertises
        # what it strips invites the reader to supply the complement themselves,
        # and they will supply a more generous one than is true.
        "can_leak": can_leak(),
        # The whole command, masked.
        "carries_command_text": True,
        # What the chain does prove.
        "chain_proves_no_edit_after_writing": True,
        # What it says nothing about — the gap the canary narrows and does not
        # close: a hook that died mid-session leaves a log that simply stops.
        "chain_proves_nothing_about_unrecorded": True,
        # A masked record is derived bytes, internally consistent over what it
        # carries: the tier chain.
        "intact_over_derived_bytes": True,
        # And one masking rewrote cannot be checked against the original, which
        # the collector does not hold. A record carrying no `masked` still can.
        "original_provenance_verifiable": False,
        "signed": False,
        "unsigned_means": ("this batch proves nothing to a party that does not "
                            "already trust the sender"),
    }


# ------------------------------------------------------------------ verifying

OLD_FORMAT_REDUCED = "old-format, not independently verifiable at this tier"
OLD_FORMAT_FULL = "old-format, checkable only through the local hash over the full record"
_TIER_CHAIN_FIELDS = ("tier_chain",) + _TIER_CHAIN_KEYS


def tier_chain_content(records: list[dict], start: str, tier: str) -> tuple[str, list[str]]:
    """(content verdict, problems) for the chain over the SHIPPED bytes.

    "verified" is the only verdict that means verified. A batch with no marked
    record is OLD-FORMAT history, never tampered: its full body is gone below
    `full`, and it predates the second chain. But once the chain is running, a
    record without it is a REMOVED attestation, and reads as tampered.

    ⚠ THE STATELESS LIMIT. Stripping the chain from EVERY record of a batch is
    indistinguishable, from the batch alone, from a pre-boundary batch — it
    reads old-format, never verified. Catching it needs state kept outside the
    batch (docs/99). An unknown version is a problem, as an unknown
    `wire_version` is: a verifier that accepts a format it does not know is not
    a verifier."""
    if not records:
        return "no records carried", []
    marked = [any(k in r for k in _TIER_CHAIN_FIELDS) for r in records]
    if not any(marked):
        return (OLD_FORMAT_FULL if tier == FULL else OLD_FORMAT_REDUCED), []
    for i, record in enumerate(records, 1):
        if not all(k in record for k in _TIER_CHAIN_FIELDS):
            return "tampered", [f"record {i} lacks part of the tier chain the batch carries"]
        if type(record["tier_chain"]) is not int:
            return "tampered", [f"record {i} carries a malformed tier_chain marker"]
    versions = {r["tier_chain"] for r in records}
    if len(versions) > 1:
        return "tampered", [f"one batch carries tier_chain versions {sorted(versions)}"]
    if versions != {TIER_CHAIN_VERSION}:
        version = versions.pop()
        return (f"unverifiable: tier_chain version {version} is unknown to this verifier",
                [f"tier_chain version {version} is not one this verifier knows"])
    prev = start
    for i, record in enumerate(records, 1):
        if record["tier_prev"] != prev:
            return "tampered", [f"record {i} does not continue the tier chain"]
        if record_hash(prev, tier_body(record)) != record["tier_hash"]:
            return "tampered", [f"record {i} content does not match its tier_hash"]
        prev = record["tier_hash"]
    return "verified", []


def carries_tier_chain(record: dict) -> bool:
    """Does this record carry any part of the chain over what shipped?"""
    return any(k in record for k in _TIER_CHAIN_FIELDS)


# Every record ships these unmasked: the spine, the command's length and digest,
# the allow-once fingerprint, and the chain over what shipped. Everything else a
# record carries is a string masking reads, or holds one (the sender's `mask`).
UNMASKED = frozenset(_SPINE + ("command_sha256", "command_len", "command_clipped",
                               "action_hash") + _TIER_CHAIN_FIELDS)


def carries_masks(record: dict) -> bool:
    """Did masking rewrite this record before it shipped? Read from `masked`,
    the count the sender writes beside every record it rewrote: that record's
    local `hash` covers values that never left the machine.

    ⚠ A FIELD IN THE FILE. Whoever can edit an export can add one and make an
    edited record read "not checkable" rather than broken; that is the limit an
    unsigned file already has (docs/99), the one `shipped_below_full` states."""
    return MASKED_FIELD in record


# ⚠ AND ONE THAT NO TIER BELOW `full` SENT AFTER 27 SEP 2026: REASONED carried
# the span as `evidence` until then, and an export from before then still does.
# It is still a reduced record, never a full one whose hash broke.
_SHIPPED_BELOW_FULL_BEFORE = ("evidence",)

# Every field a record could carry when it shipped below `full`: the spine
# (VERDICT), what LOCATED and REASONED added, the offset, the chain over what
# shipped, and the span above.
_BELOW_FULL_FIELDS = frozenset().union(
    _SPINE, _LOCATED_EXTRA, (_LOCATION_FIELD,), _TIER_CHAIN_FIELDS,
    _SHIPPED_BELOW_FULL_BEFORE)


def shipped_below_full(record: dict) -> bool:
    """Does every field this record carries belong to a tier below `full`?

    ⚠ AN EXPORT FROM BEFORE 28 SEP 2026: nothing ships below `full` now.
    ⚠ THE RECORD IS THE ONLY WITNESS AN EXPORT KEEPS. The tier travels on the
    batch, and an export keeps records, not batches. The hook has written
    `command`, `paths` and `url` into every record, null or not, since the log's
    first version (c865037), and `action_hash` since the same day (c5df6e5); no
    tier below `full` carries any of them. So a genuine record from any version
    reads exactly: that is the log's history, not a sample (and every record in
    logs/live-fixture has all four, pinned). ⚠ BUT IT IS FIELDS IN THE
    FILE: cutting a full record down to a lower tier's fields makes it read
    reduced. That is the limit an unsigned file already has (docs/99), not a new
    one."""
    return set(record) <= _BELOW_FULL_FIELDS


def _tier_batches(records: list[dict], first: int) -> list[tuple[int, list[dict]]]:
    """[(record number of its first record, records)]: the batches a run of
    marked records shipped in, recovered from the records themselves.

    ⚠ A BATCH'S FIRST RECORD ANCHORS ON THE LOCAL CHAIN: its `tier_prev` is the
    `continues_from` its batch declared, which is its own `prev`. Every later
    record's `tier_prev` is the `tier_hash` before it. So `tier_prev == prev`
    opens a batch, and a change of marker does too: an unknown version's batch
    boundaries are that version's rule, not this verifier's to guess."""
    batches: list[tuple[int, list[dict]]] = []
    for number, record in enumerate(records, first):
        prev = record.get("prev")
        anchors = isinstance(prev, str) and record.get("tier_prev") == prev
        if (not batches or anchors
                or record.get("tier_chain") != batches[-1][1][-1].get("tier_chain")):
            batches.append((number, [record]))
        else:
            batches[-1][1].append(record)
    return batches


def _batch_verdict(batch: list[dict], tier: str | None) -> tuple[str, list[str]]:
    """One recovered batch through the engine's one-batch rule, started from its
    first record's own `prev` — the `continues_from` its batch declared."""
    start = batch[0].get("prev")
    if not isinstance(start, str):
        return "tampered", ["record 1 carries no local `prev`, so there is no "
                            "continues_from for the tier chain to start from"]
    return tier_chain_content(batch, start, tier or "")


def verify_tier_chain(records: list[dict], tier: str | None = None) -> tuple[str, list[str]]:
    """(content, problems) for a WHOLE SESSION, records in chain order.

    `tier_chain_content` on every batch recovered from the records, plus what
    one batch cannot show: once any record carries the chain, a LATER record
    without it is a regression — tampered, never history. Records before the
    first marked one are history (an engine upgraded mid-session). Any tampered
    batch makes the session tampered; otherwise any batch not verified (an
    unknown version) is the session's verdict. The same rule the collector's
    export applies."""
    if not records:
        return "no records carried", []
    first = next((i for i, r in enumerate(records) if carries_tier_chain(r)), None)
    if first is None:
        return (OLD_FORMAT_FULL if tier == FULL else OLD_FORMAT_REDUCED), []
    chained = records[first:]
    for number, record in enumerate(chained, first + 1):
        if not carries_tier_chain(record):
            return "tampered", [f"record {number} carries no tier chain after record "
                                f"{first + 1} began it: a regression, not history"]
    verdicts = [(number, *_batch_verdict(batch, tier))
                for number, batch in _tier_batches(chained, first + 1)]
    worst = (next((v for v in verdicts if v[1] == "tampered"), None)
             or next((v for v in verdicts if v[1] != "verified"), None))
    if worst is None:
        return "verified", []
    number, content, problems = worst
    return content, [f"in the batch from record {number}: {p}" for p in problems]


# The local hash's body on a NEW-format record: the chain over what shipped
# was added after the hook hashed it, so it was never inside the local hash.
_NOT_IN_LOCAL_BODY = ("prev", "hash") + _TIER_CHAIN_FIELDS

NOT_CHECKABLE = "local hash: not checkable at this tier"


def _local_hash_holds(prev: str, record: dict) -> bool:
    """The hook's hash over this record as stored, with the tier chain's three
    fields set aside on a record that carries them."""
    aside = _NOT_IN_LOCAL_BODY if carries_tier_chain(record) else ("prev", "hash")
    return record["hash"] == record_hash(prev, {k: v for k, v in record.items()
                                                if k not in aside})


def verify_shipped_records(records: list[dict], start: str | None = None, *,
                           reduced_or_redacted: Callable[[dict], bool] | None = None,
                           ) -> tuple[str, int | None, str]:
    """A shipped or exported session, read as a file: (state, first bad record
    number or None, detail). `state` is "ok", "broken", "consistent",
    "tampered", "unverifiable", "chain_missing" or "uncovered".

    ⚠ TWO VERDICTS, NEVER FOLDED (the collector's rule). The LOCAL chain is
    read as it always was — linkage, then the local hash — except that a record
    carrying the tier chain has those three fields set aside, because they were
    added after the hook hashed it. Linkage is checkable at every tier: `prev`
    and `hash` travel unchanged. The TIER chain is checked beside it.

    ⚠ WHICH LOCAL MISMATCH IS A BREAK. A record shipped whole, `full` and
    unredacted, must match; a mismatch is BROKEN, and a verified tier chain never
    excuses it (a first version let it, and a forged, self-anchored tier chain
    then hid a real edit: security review). A record `reduced_or_redacted` names
    cannot match, edited or not: the bytes its local hash covers never shipped.
    That hash is NOT CHECKABLE, never a break, and once one is, the verdict is
    the tier chain's (`_tier_chain_decides`). Without the predicate every
    mismatch is a break.

    ⚠ NEVER "VERIFIED" FOR SUCH A LOG. Its only content check is a chain whoever
    can edit the file can recompute, so a tier chain that holds reads
    "consistent" in every detail here."""
    for i, record in enumerate(records, 1):
        if not isinstance(record, dict) or "_unparseable" in record:
            return "broken", i, f"record {i} is not valid JSON"
    content, problems = verify_tier_chain(records)
    reduced = reduced_or_redacted is not None and any(map(reduced_or_redacted, records))
    shown = "consistent" if reduced and content == "verified" else content
    tier = f"tier chain: {problems[0] if problems else shown}"
    unchecked = uncovered = 0
    prev = start or GENESIS
    for i, record in enumerate(records, 1):
        if record.get("prev") != prev:
            return ("broken", i,
                    f"record {i} chains from {record.get('prev')!r}, expected {prev!r}; {tier}")
        if not isinstance(record.get("hash"), str):
            return "broken", i, f"record {i} carries no hash; {tier}"
        if not _local_hash_holds(prev, record):
            if reduced_or_redacted is None or not reduced_or_redacted(record):
                return "broken", i, f"record {i} content does not match its hash; {tier}"
            unchecked += 1
            if not carries_tier_chain(record):
                uncovered += 1
        prev = record["hash"]
    if unchecked:
        return _tier_chain_decides(content, tier, unchecked, uncovered, len(records))
    if content == "tampered":
        return "broken", None, tier
    if content.startswith("unverifiable"):
        return "unverifiable", None, tier
    if content == "verified":
        # Every local hash held, so every stored byte is covered, whatever a
        # record looks like (a developer can type a mark: python review).
        return "ok", None, f"{len(records)} records, local chain intact; tier chain verified"
    return "ok", None, f"{len(records)} records, local chain intact; {content}"


def _tier_chain_decides(content: str, tier: str, unchecked: int, uncovered: int,
                        total: int) -> tuple[str, None, str]:
    """The verdict once a record's local hash is not checkable: the tier
    chain's, because nothing else here covers that record's bytes.

        tampered       the chain over what shipped does not hold
        unverifiable   its version is unknown here
        chain_missing  no record carries it at all. Not broken and not
                       unknown: ABSENT. An export from before the chain
                       existed, or one someone stripped; the file cannot tell
                       which, so neither is claimed
        uncovered      it holds, but an unchecked record predates it (old
                       format): nothing here can check that record
        consistent     it holds over every unchecked record

    ⚠ CONSISTENT IS NOT VERIFIED. Nothing in an unsigned export proves it was
    not rewritten by someone who can edit it: this chain can be recomputed too,
    re-anchored on an edited record's own `prev` (docs/99). The collector's
    stored copy is the proof."""
    why = (f"{NOT_CHECKABLE} ({unchecked} of {total} records were rewritten "
           f"before they shipped: masked, keyed, reduced or redacted)")
    if content == "tampered":
        return "tampered", None, f"{why}; {tier}"
    if content.startswith("unverifiable"):
        return "unverifiable", None, f"{why}; {tier}"
    if content.startswith("old-format"):
        # No record carries the chain, so every unchecked record is uncovered.
        return "chain_missing", None, why
    if uncovered:
        return ("uncovered", None,
                f"{why}; {uncovered} of them carry no tier chain: {OLD_FORMAT_REDUCED}")
    return "consistent", None, why


def verify_batch(batch: dict, *, expected_continues_from: str | None = None) -> dict:
    """Check a batch WITHOUT the original log. Returns a result dict.

    `status` is one of:
        "nothing to verify"  a valid batch carrying no numbered action — §2.5.
                             NEVER "verified": a canary alone attests that the
                             hook ran, and nothing about any decision.
        "intact"             the records chain consistently among themselves
        "broken"             they do not
    """
    problems: list[str] = []
    for field in ("wire_version", "device_id", "session_id", "tier",
                   "continues_from", "manifest", "provenance", "records",
                   "signature"):
        if field not in batch:
            problems.append(f"missing field {field!r}")
    if problems:
        return {"status": "broken", "problems": problems, "records": 0}

    if batch["tier"] not in SHAPES:
        problems.append(f"unknown tier {batch['tier']!r}")
    if batch["wire_version"] != WIRE_VERSION:
        problems.append(f"wire_version {batch['wire_version']} != {WIRE_VERSION}")

    records = batch["records"]
    # A malformed record is a broken batch, never a traceback out of the one
    # function that must assess a batch nobody can trust.
    malformed = [i for i, r in enumerate(records, 1) if not isinstance(r, dict)]
    if malformed:
        return {"status": "broken", "records": len(records), "content": "tampered",
                "problems": [f"record {i} is not an object" for i in malformed],
                "detail": f"not consistent: record {malformed[0]} is not an object"}
    manifest = batch["manifest"]
    if manifest.get("record_count") != len(records):
        problems.append(f"manifest says {manifest.get('record_count')} records, "
                        f"carries {len(records)}")

    # §2.3 — continuity ACROSS batches.
    if expected_continues_from is not None and \
            batch["continues_from"] != expected_continues_from:
        problems.append(
            f"gap: batch continues from {batch['continues_from'][:12]}… but the "
            f"previous batch ended at {expected_continues_from[:12]}… — a batch "
            f"is missing between them")

    # Continuity WITHIN the batch: each record's prev is the one before it.
    prev = batch["continues_from"]
    for i, record in enumerate(records, 1):
        if record.get("prev") != prev:
            problems.append(f"record {i} does not continue the chain")
            break
        prev = record.get("hash")

    # The CONTENT, over the bytes carried (docs/99): the tier chain, when the
    # records carry it. Linkage above stays exactly as it was.
    content, tier_problems = tier_chain_content(records, batch["continues_from"],
                                                batch["tier"])
    problems.extend(tier_problems)

    decisions = [r for r in records if r.get("event") == "decision"]
    if not decisions:
        # §2.5. A real session, a real batch, and nothing decided in it.
        return {"status": "nothing to verify", "problems": problems,
                "records": len(records), "content": content,
                "detail": ("the hook ran and recorded no decision"
                            if manifest.get("canary_present")
                            else "no canary and no decisions — this batch "
                                 "attests nothing about whether the hook ran"),
                "ends_at": prev}

    if problems:
        detail = f"not consistent: {problems[0]}"
    elif content == "verified":
        detail = "consistent, and every record's tier_hash covers the bytes carried"
    elif batch["tier"] != FULL:
        detail = "consistent over the bytes carried; not checkable against the original at this tier"
    else:
        detail = "consistent, and full records were carried"
    return {"status": "broken" if problems else "intact", "problems": problems,
            "records": len(records), "decisions": len(decisions),
            "ends_at": prev, "content": content, "detail": detail}



def batch_from_log(path: Path, *, device_id: str, mask: Callable[[dict], dict],
                    fingerprint: Callable[[str], str], continues_from: str = GENESIS,
                    purpose: str | None = None) -> dict:
    """Read a session log and build one batch from all of it, masked by `mask`.

    ⚠ `purpose` DEFAULTS TO ABSENT AND MUST. A log on disk says what happened,
    not what it was FOR — a preflight log, a benchmark log and a developer's
    session are the same shape, same writer, same suffix. Anything that knows
    better passes it; a helper that reads a file does not know better.
    """
    records = read_records(path)
    session_id = next((r.get("session_id") for r in records if r.get("session_id")),
                       path.name.split(".")[0])
    return build_batch(records, device_id=device_id, session_id=session_id,
                        mask=mask, fingerprint=fingerprint, purpose=purpose,
                        continues_from=continues_from)
