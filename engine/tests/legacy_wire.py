"""What a shipper sent before 28 Sep 2026 — a FIXTURE BUILDER for the tests
that prove an old export still reads and verifies as before. Nothing in the
product imports it, and nothing builds a tiered batch any more.

Until then a batch declared one of four tiers. Every record was reduced to its
tier's fields (`tier_record`), its reason replaced below `full` by the rule's own
words (`reason_below_full`, #74), rewritten by Layer A (`redact_record`,
`[REDACTED:secret]`), and chained over what shipped (`wire.chain_at_tier`). The
functions below are core/wire.py's and shipper/redact.py's as they stood on main
at c882a91, copied unchanged but for the names they read from `wire`, so an old
export in a test is built exactly the way the old sender built a real one.
"""
from __future__ import annotations

import hashlib
import platform
import re

from core import rule_names
from core.audit_log import GENESIS
from core.credentials import _VALUE_TOKEN
from core.evidence import location_of
from core.purpose import PURPOSES
from core.wire import (FULL, LOCATED, REASONED, TIERS, VERDICT, WIRE_VERSION,  # noqa: F401
                       _LOCATED_EXTRA, _LOCATION_FIELD, _SPINE, guard_ref)

SECRET_MARK = "[REDACTED:secret]"


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:8]


# ⚠ THE TIERS ARE TOTALLY ORDERED BY WHAT THEY LEAK, and that order is written
# down here rather than inferred from `_TIER_FIELDS` by whoever needs it next.
# It is what makes "this setting WIDENS what leaves the machine" a computable
# statement instead of a judgement call — the sending side announces a widening
# against the tier the operator agreed to, and says nothing about a narrowing.
#
# Nesting is real and not merely conventional: VERDICT's fields are a subset of
# LOCATED's, LOCATED's of REASONED's, and FULL keeps the record whole. A test
# pins the containment so a new tier cannot quietly break the ordering.
LEAK_RANK = {VERDICT: 0, LOCATED: 1, REASONED: 2, FULL: 3}


# ⚠ REASONED CARRIES WHAT LOCATED CARRIES. It added the firing SPAN, a raw
# ±60-character window of the command, until 27 Sep 2026; the span now travels
# at `full` only, like the command it is cut from. The tier keeps its name, so
# an env file, a flag or a collector that knows it keeps working.
_TIER_FIELDS = {
    VERDICT: _SPINE,
    LOCATED: _SPINE + _LOCATED_EXTRA,
    REASONED: _SPINE + _LOCATED_EXTRA,
    # FULL keeps the record whole; listed as None so the code cannot silently
    # drop a field added to build_body() later.
    FULL: None,
}


# The one pointer taken from the engine's prose: the step its reason cites.
#
# ⚠ NEVER AN `@offset`, AND NEVER JUST ANY `step N`. A reason QUOTES text, and
# quoted text can carry both shapes: a fetched URL `…/@1234567/page`, a commit
# message's `@7654321` (security review). A pattern over the prose would ship
# digits chosen by whoever wrote that text. So:
#   - the LAST `step N` only. In every template the engine writes the step it
#     cites AFTER what it quotes (`_untrusted_origin`, `_secret_origin`,
#     `_what_was_seen`, the derived-secret reasons, the allow-once prefix);
#   - and only when it is EARLIER than this record (1 <= N < seq). The engine
#     cites a step that already happened; anything else is not a pointer, and
#     then none ships.
# The record's own offset travels as `evidence_location`, read from the start
# of its `evidence`, where the engine writes it before any quoted text.
_STEP = re.compile(r"\bstep (\d{1,7})(?!\d)")


def _cited_step(record: dict) -> int | None:
    seq, reason = record.get("seq"), record.get("reason")
    if type(seq) is not int or not isinstance(reason, str):
        return None
    steps = _STEP.findall(reason)
    step = int(steps[-1]) if steps else None
    return step if step is not None and 1 <= step < seq else None


def reason_below_full(record: dict):
    """The reason a tier below `full` carries: the rule's own words
    (`rule_names.describe`) and the earlier step the engine's reason cites,
    e.g. `… this executes code that this session did not author (step 120)`.

    ⚠ NEVER THE ENGINE'S PROSE. The engine writes its reason for the agent and
    for the local log, where quoting the command is the point: "this session
    read @235 …git commit -q -F $S/msg4.txt && git push -q … (step 120)".
    Shipped below `full`, that quote broke the one promise the tiers make —
    `full` is the only tier that carries the command, the cwd and the paths.
    A reason that is empty or absent stays exactly as it was."""
    raw = record.get("reason")
    if not raw:
        return raw
    words = rule_names.describe(record.get("rule_id"))["why"]
    step = _cited_step(record)
    return f"{words} (step {step})" if step is not None else words


def tier_record(record: dict, tier: str) -> dict:
    """One record, reduced to what this tier transmits.

    KEYS ARE DROPPED, NOT BLANKED. A key present with a null value tells a
    reader the field existed and was withheld, which is a different artifact
    from one that never carried it — and it invites a later reader to "restore"
    it. Absence is the honest encoding of "this never left the machine".

    ⚠ BELOW `full` NOTHING QUOTES THE COMMAND, THE CWD OR A PATH: the reason is
    `reason_below_full`, and the span is its offset. A new record, always; the
    local record is never touched.
    """
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}; expected one of {TIERS}")
    fields = _TIER_FIELDS[tier]
    if fields is None:
        return dict(record)
    out = {k: record[k] for k in fields if k in record}
    if "reason" in out:
        out["reason"] = reason_below_full(record)
    if tier == VERDICT:
        return out
    # ⚠ THE POINTER, NEVER THE SPAN. `location_of` returns `@<offset>` or
    # "" and is incapable of returning command text — the property is asserted
    # over this function in tests/test_wire_format.py, not only over the helper.
    where = location_of(record.get("evidence"))
    if where:
        out[_LOCATION_FIELD] = where
    return out


def build_batch(records: list[dict], *, device_id: str, session_id: str,
                 tier: str = REASONED, continues_from: str = GENESIS,
                 purpose: str | None = None) -> dict:
    """A batch of one session's records, tiered, ready to transmit.

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

    The key is DROPPED rather than set to null, for the reason `tier_record`
    gives: a key present with a null value tells a reader the field existed and
    was withheld, and invites a later reader to "restore" it. Absence is the
    honest encoding of "this was never claimed".

    ⚠ PER BATCH, SO PER SESSION IT IS A UNION. One session can receive a probe
    batch and a work batch — do not assume it cannot — so a receiver reports
    every distinct value it has seen as a sorted list, the discipline `agent`
    and `os` already follow. This function declares one batch and says nothing
    about the session.
    """
    if purpose is not None and purpose not in PURPOSES:
        raise ValueError(f"unknown purpose {purpose!r}; expected one of {PURPOSES} "
                          f"or None for 'not claimed'")
    tiered = [tier_record(r, tier) for r in records]
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
        "tier": tier,
        # A SIBLING OF `tier`, NOT A MANIFEST ENTRY. The manifest holds counts
        # this engine computed and facts about the sending environment; purpose
        # is neither. It is a property of the batch in exactly the way the tier
        # is — chosen by the sender, describing what this payload IS.
        **({"purpose": purpose} if purpose is not None else {}),
        # None when the batch holds no numbered action — a canary-only session
        # is a real session and says so, rather than claiming seqs it lacks.
        "seq_range": [min(seqs), max(seqs)] if seqs else None,
        "continues_from": continues_from,
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
        "provenance": provenance_for(tier),
        "records": tiered,
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


# ⚠ WHAT EACH TIER CAN LEAK, PHRASED AS A CAPABILITY AND NOT AS A REMOVAL.
#
# The previous framing described what a tier STRIPS, which is how "REASONED
# removes the thing that matters" got written down — a claim that was about
# COMMANDS and was then read as covering evidence, which REASONED still ships.
# A removal list is a claim about the author's intent. A leak list is a claim
# about the artifact, and it is the one an operator has to act on.
#
# Each entry is what a reader of a batch at that tier COULD extract, stated at
# its worst rather than its typical. Nothing here is derived from a measurement
# that might not hold on another machine.
_CAN_LEAK = {
    # ⚠ FULL IS FOR ONE MACHINE ONLY — the developer's own, feeding differential
    # replay and the log view locally. Choosing it for a batch that TRAVELS means
    # agreeing to hand the receiving party the source code, every path, and any
    # credential ever typed into a shell during the session; there is no
    # narrower reading of it and nothing downstream can undo it.
    FULL: ["every command verbatim, including heredoc bodies — 64% of command "
           "bytes on a real session were file contents inline, so this ships "
           "the codebase",
           "file paths, hostnames, and any credential typed into any command",
           "intended for the developer's OWN machine; sending it to a collector "
           "means agreeing to give that collector the source code",
           "everything the lower tiers can leak"],
    # ⚠ REASONED SENDS WHAT LOCATED SENDS (27 Sep 2026): the firing span travels
    # at `full` only, with the command it is cut from.
    REASONED: ["the same record as LOCATED: the firing span, like the command, "
               "the cwd and the paths, travels only at `full`",
               "everything LOCATED can leak"],
    LOCATED: ["the rule's own words for why it fired, with the earlier step "
              "number it cites — no command, cwd or path text",
              "who approved an override (`granted_by`), which can be a username",
              "a byte OFFSET into the command, which carries no command text",
              "everything VERDICT can leak"],
    VERDICT: ["which rules fired, when, how often, and on which agent — a "
              "behavioural profile of the developer, but no bytes they wrote",
              "wall-clock timestamps, which place a person at a keyboard"],
}


def can_leak(tier: str) -> list:
    """What a batch at this tier could reveal. Never what it removes."""
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}; expected one of {TIERS}")
    return list(_CAN_LEAK[tier])


def provenance_for(tier: str) -> dict:
    """§2.4 — FIELDS, not prose, because the panel renders these and must not
    paraphrase a claim about evidence into a stronger one."""
    derived = tier != FULL
    return {
        # ⚠ STATED AS A CAPABILITY. See `_CAN_LEAK`: a tier that advertises what
        # it strips invites the reader to supply the complement themselves, and
        # they will supply a more generous one than is true.
        "can_leak": can_leak(tier),
        # `full` only: below it, no field quotes the command (27 Sep 2026).
        "carries_command_text": tier == FULL,
        # What the chain does prove.
        "chain_proves_no_edit_after_writing": True,
        # What it says nothing about — the gap the canary narrows and does not
        # close: a hook that died mid-session leaves a log that simply stops.
        "chain_proves_nothing_about_unrecorded": True,
        # A tiered batch is internally consistent over the bytes it carries.
        "intact_over_derived_bytes": derived,
        # And cannot be checked against the original, which the collector does
        # not hold. False at every tier below FULL, by construction.
        "original_provenance_verifiable": not derived,
        "signed": False,
        "unsigned_means": ("this batch proves nothing to a party that does not "
                            "already trust the sender"),
    }



# ── the old Layer A (shipper/redact.py at c882a91) ──

_TEXT_FIELDS = ("command", "reason", "evidence", "url", "granted_by",
                "cwd", "title", "tool_name")
_LIST_TEXT_FIELDS = ("paths", "workspace_roots")


def _mask_secrets_in(text: str, fingerprints: set[str]) -> str:
    def repl(m):
        return SECRET_MARK if _fingerprint(m.group(0)) in fingerprints else m.group(0)
    return _VALUE_TOKEN.sub(repl, text)


def redact_secrets(record: dict, fingerprints) -> dict:
    """LAYER A. Replace every fingerprinted secret value in the record's text fields
    with SECRET_MARK, matched by the engine's own needle. Deterministic, stdlib,
    always on. Returns a NEW dict; structural/digest fields are copied untouched."""
    fps = set(fingerprints or ())
    out = dict(record)
    if not fps:
        return out
    for f in _TEXT_FIELDS:
        if isinstance(out.get(f), str):
            out[f] = _mask_secrets_in(out[f], fps)
    for f in _LIST_TEXT_FIELDS:
        if isinstance(out.get(f), list):
            out[f] = [_mask_secrets_in(p, fps) if isinstance(p, str) else p
                       for p in out[f]]
    return out


def redact_record(record: dict, fingerprints) -> dict:
    """The old shipper's rewrite: Layer A only (Layer B was opt-in)."""
    return redact_secrets(record, fingerprints)


def ship(records: list[dict], *, tier: str, start: str = GENESIS,
         fingerprints=(), chained: bool = True, device_id: str = "dev",
         session_id: str | None = None) -> dict:
    """One batch as the old shipper posted it: tier, then Layer A, then the
    tier chain (unless `chained` is False: a sender from before docs/99)."""
    from core import wire
    batch = build_batch(records, device_id=device_id,
                        session_id=session_id or str(records[0].get("session_id")),
                        tier=tier, continues_from=start)
    body = [redact_record(r, set(fingerprints)) for r in batch["records"]]
    batch["records"] = wire.chain_at_tier(body, start) if chained else body
    return batch
