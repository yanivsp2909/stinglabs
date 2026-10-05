"""A shipped record carries a second chain over the bytes it SHIPS (docs/99).

⚠ THE BUG (the collector's chain-at-tier design; PROGRESS.md 2026-09-24). The
hook hashes and chains every record over its FULL body into the local log.
The shipper tiers and redacts afterwards, and ships the record with that
full-body `hash`, so a reduced record could never be re-verified (0/4 at
verdict_reason_location), and a full record Layer A rewrote failed too (3/4).

⚠ THE FIX IS ADDITIVE (option (a)). In `Shipper._send`, after the record is
reduced (masked, since 28 Sep 2026: every record whole, every recognised value
replaced by its type), each record gains `tier_chain` (the format marker),
`tier_prev` and `tier_hash = sha256(tier_prev + canonical(record minus
prev/hash/tier_prev/tier_hash))`. The local `prev`/`hash`, the cursor and
`continues_from` are untouched, and this file proves it.

Everything here drives the REAL `Shipper._send` and captures the exact bytes
`client.post` was handed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core import audit_log, engine, wire
from shipper import client, config, fingerprint_key, mask
from shipper import run as shipper_run
from shipper.run import Shipper
from tests import legacy_wire

SESSION = "sess-tier-chain"
DUMMY_SECRET_LINE = "TOKEN=F4keT0k3nQ7vX2mZp9LtR4wY\n"      # a dummy, never real
COMMANDS = ["pytest -q", "git status", "ls -la", "echo k=F4keT0k3nQ7vX2mZp9LtR4wY"]


def write_log(root, commands, start=1):
    os.environ["STING_SESSION_ROOT"] = str(root)
    for i, command in enumerate(commands, start=start):
        audit_log.append(SESSION, audit_log.build_body(
            SESSION, seq=i, event="decision", decision="ALLOW", kind="EXEC",
            command=command, cwd="/work/repo", agent="claude-code",
            ts=1_786_000_000.0 + i, rule_id=None, reason="probe reason",
            evidence=f"@0 {command}"))
    return audit_log.default_log_path(SESSION, root)


KNOWN = mask.SessionValues(
    secret_prints=frozenset(engine.fingerprint_values(DUMMY_SECRET_LINE)),
    secret_files=(".env",))


@pytest.fixture
def ship(tmp_path, monkeypatch):
    """ship() -> the batches posted, parsed, in order. Layer A sees the dummy
    fingerprints, exactly as it would after the session read that value."""
    posted: list[dict] = []

    def fake_post(url, token, payload, *, timeout=30.0):
        if not url.endswith("/v1/batches"):          # the heartbeat rides the same client
            return client.Outcome(client.STORED, 200, {})
        batch = json.loads(payload)
        posted.append(batch)
        return client.Outcome(client.STORED, 200,
                              {"records_stored": len(batch["records"]),
                               "batch_ref": f"b{len(posted)}"})

    monkeypatch.setattr(shipper_run.client, "post", fake_post)
    monkeypatch.setattr(Shipper, "_session_values", lambda self, sid: KNOWN)

    def run():
        settings = config.Settings(
            collector_url="https://collector.invalid", device_token="tok",
            device_id="laptop", ships=wire.MASKED, log_root=tmp_path / "logs",
            state_root=tmp_path / "state", flush_seconds=0, flush_records=1)
        shipper = Shipper(settings, log=lambda *a: None)
        shipper.tick()
        return shipper
    return run, posted, tmp_path / "logs"


def laptop_fingerprint():
    """The key the shipper made in this test's home, as the batch was keyed
    (tests/test_fingerprints_are_keyed.py)."""
    return wire.fingerprinter(fingerprint_key.load(fingerprint_key.path_under(Path.home())))


def own_tier_hash_ok(record: dict) -> bool:
    body = {k: v for k, v in record.items()
            if k not in ("prev", "hash", "tier_prev", "tier_hash")}
    return audit_log.record_hash(record["tier_prev"], body) == record["tier_hash"]


def local_hash_ok(record: dict) -> bool:
    """The LOCAL hash, recomputed the only way that can still work on a shipped
    record: the hook's body is the record minus BOTH chains' fields. ⚠ This is
    the rule the collector's `export_store.verify` must adopt; with only
    prev/hash set aside, every new-format full record reads as broken."""
    body = {k: v for k, v in record.items()
            if k not in ("prev", "hash", "tier_chain", "tier_prev", "tier_hash")}
    return audit_log.record_hash(record["prev"], body) == record["hash"]


# ═════════════════════════════════════════════ 1 · every shipped record self-verifies


def test_every_shipped_record_self_verifies(ship):
    run, posted, logs = ship
    write_log(logs, COMMANDS)
    run()
    records = [r for batch in posted for r in batch["records"]]
    assert len(records) == len(COMMANDS), "precondition: everything shipped"
    assert all(r.get("tier_chain") == wire.TIER_CHAIN_VERSION for r in records)
    assert sum(own_tier_hash_ok(r) for r in records) == len(COMMANDS)


def test_a_record_masking_rewrote_self_verifies_and_with_the_key_each_is_its_local_one(ship):
    """The fourth command carries the dummy value, which Layer A masks; its tier
    hash covers what shipped, as every record's does. RE-PINNED (keyed
    fingerprints): no shipped record's local hash recomputes from what shipped
    any more — `hash` and `prev` are keyed — and with the laptop's key each is
    its local record's: the three masking did not rewrite, field for field."""
    run, posted, logs = ship
    path = write_log(logs, COMMANDS)
    run()
    records = posted[0]["records"]
    local = audit_log.read_records(path)
    keyed = laptop_fingerprint()
    assert [bool(r.get("masked")) for r in records] == [False, False, False, True]
    assert sum(local_hash_ok(r) for r in records) == 0, "keyed: nothing recomputes"
    assert [r["hash"] for r in records] == [keyed(r["hash"]) for r in local]
    aside = ("prev", "hash", "command_sha256", "action_hash", "tier_chain", "tier_prev",
             "tier_hash", wire.FINGERPRINTS_FIELD)
    same = [{k: v for k, v in s.items() if k not in aside} ==
            {k: v for k, v in l.items() if k not in aside} for s, l in zip(records, local)]
    assert same == [True, True, True, False]
    assert sum(own_tier_hash_ok(r) for r in records) == 4


def test_no_recompute_of_the_local_hash_holds_on_a_keyed_record(ship):
    """The collector-compatibility pin, RE-PINNED (keyed fingerprints): neither
    the old recompute rule nor the tier-aware one holds on a shipped record
    now — its `hash` is keyed and its digests were not sent — which
    the collector's export reads as `tiered` for a batch that is not `full`
    (its own rule), and every batch is `masked`. The key is what matches it."""
    run, posted, logs = ship
    path = write_log(logs, COMMANDS)
    run()
    record = posted[0]["records"][0]
    old_rule_body = {k: v for k, v in record.items() if k not in ("prev", "hash")}
    assert audit_log.record_hash(record["prev"], old_rule_body) != record["hash"]
    assert not local_hash_ok(record)
    assert posted[0]["tier"] == wire.MASKED != wire.FULL
    assert record["hash"] == laptop_fingerprint()(audit_log.read_records(path)[0]["hash"])


# ═══════════════════════════════════════════════════ 2 · the tier chain is continuous


def test_the_tier_chain_is_continuous_within_and_across_batches(ship):
    run, posted, logs = ship
    write_log(logs, COMMANDS[:2])
    run()
    write_log(logs, COMMANDS[2:], start=3)
    run()
    assert len(posted) == 2, "precondition: two batches"
    for batch in posted:
        prev = batch["continues_from"]
        for record in batch["records"]:
            assert record["tier_prev"] == prev
            prev = record["tier_hash"]
    # The second batch re-anchors on the local chain as it ships (keyed), which
    # is what `continues_from` already carries: no new cursor state.
    assert posted[1]["records"][0]["tier_prev"] == posted[0]["records"][-1]["hash"]


# ════════════════════════════════════════ 3 · the local chain and cursor are untouched


def test_the_local_chain_cursor_and_continues_from_are_byte_identical(ship):
    run, posted, logs = ship
    path = write_log(logs, COMMANDS[:2])
    shipper = run()
    write_log(logs, COMMANDS[2:], start=3)
    before = path.read_bytes()
    run()
    local = audit_log.read_records(path)
    assert path.read_bytes() == before, "the local log is never rewritten"
    assert audit_log.verify_chain(path)[0], "the local chain still verifies"
    shipped = [r for batch in posted for r in batch["records"]]
    # RE-PINNED (keyed fingerprints): what ships is the local chain KEYED, and
    # the cursor keeps the local hash.
    keyed = laptop_fingerprint()
    assert [(r["prev"], r["hash"]) for r in shipped] == \
        [(keyed(r["prev"]), keyed(r["hash"])) for r in local]
    assert posted[0]["continues_from"] == audit_log.GENESIS
    assert posted[1]["continues_from"] == keyed(local[1]["hash"])
    assert shipper.cursor.get(SESSION).ends_at == local[1]["hash"]


def test_minus_the_three_new_fields_a_shipped_record_is_the_masked_record(ship):
    """What ships is `mask_record` of the local record with its fingerprints
    keyed (`wire.ship_record`), byte for byte, plus `tier_chain`, `tier_prev`
    and `tier_hash`. RE-PINNED: the fingerprints used to ship raw."""
    run, posted, logs = ship
    path = write_log(logs, COMMANDS)
    run()
    expected = [wire.ship_record(r, mask=lambda x: mask.mask_record(x, KNOWN),
                                 fingerprint=laptop_fingerprint())
                for r in audit_log.read_records(path)]
    stripped = [{k: v for k, v in r.items()
                 if k not in ("tier_chain", "tier_prev", "tier_hash")}
                for r in posted[0]["records"]]
    assert stripped == expected


# ═════════════════════════════════════════════════════ 4 · verify_batch reads both


def _batch(ship_fixture):
    run, posted, logs = ship_fixture
    write_log(logs, COMMANDS)
    run()
    return posted[0]


def test_verify_batch_checks_the_tier_hash_of_a_new_format_batch(ship):
    batch = _batch(ship)
    result = wire.verify_batch(batch)
    assert result["status"] == "intact"
    assert result["content"] == "verified"


def test_verify_batch_catches_an_edit_to_a_new_format_record(ship):
    batch = _batch(ship)
    edited = dict(batch, records=[dict(batch["records"][0], decision="DENY"),
                                  *batch["records"][1:]])
    result = wire.verify_batch(edited)
    assert result["status"] == "broken"
    assert result["content"] == "tampered"


def test_stripping_the_tier_fields_after_the_chain_began_is_tampering(ship):
    """A downgrade: an old-format record where the tier chain was running is
    not 'old history', it is a removed attestation."""
    batch = _batch(ship)
    last = {k: v for k, v in batch["records"][-1].items()
            if k not in ("tier_chain", "tier_prev", "tier_hash")}
    result = wire.verify_batch(dict(batch, records=[*batch["records"][:-1], last]))
    assert result["content"] == "tampered"
    assert result["status"] == "broken"


def test_an_old_format_reduced_batch_is_unverifiable_history_never_tampered(tmp_path):
    """A batch a sender from before docs/99 posted at LOCATED: no tier chain.
    Built the way that sender built it (tests/legacy_wire.py)."""
    path = write_log(tmp_path / "logs", COMMANDS)
    old = legacy_wire.build_batch(audit_log.read_records(path), device_id="laptop",
                                  session_id=SESSION, tier=wire.LOCATED)
    assert not any("tier_hash" in r for r in old["records"]), "precondition: old format"
    result = wire.verify_batch(old)
    assert result["status"] == "intact"
    assert result["content"] == wire.OLD_FORMAT_REDUCED


# ═════════════════════════════════════════ 5 · review follow-ups (this branch)


def _with_every_record(batch, **changes):
    return dict(batch, records=[dict(r, **changes) for r in batch["records"]])


def test_an_unknown_tier_chain_version_is_broken_never_intact(ship):
    """security-reviewer HIGH: a uniform version flip must not read intact —
    the same rule the file applies to an unknown wire_version."""
    result = wire.verify_batch(_with_every_record(_batch(ship), tier_chain=2))
    assert result["status"] == "broken"
    assert result["content"] != "verified"


def test_a_malformed_tier_chain_value_is_tampered_not_a_crash(ship):
    """python-reviewer HIGH: an unhashable marker raised TypeError."""
    result = wire.verify_batch(_with_every_record(_batch(ship), tier_chain=[1]))
    assert result["status"] == "broken"
    assert result["content"] == "tampered"


def test_a_non_object_record_is_broken_not_a_crash(ship):
    batch = _batch(ship)
    result = wire.verify_batch(dict(batch, records=[*batch["records"][:-1], 42]))
    assert result["status"] == "broken"


def test_a_tampered_batch_never_calls_itself_consistent(ship):
    """python-reviewer HIGH: `detail` said "consistent" beside status broken."""
    batch = _batch(ship)
    edited = dict(batch, records=[dict(batch["records"][0], decision="DENY"),
                                  *batch["records"][1:]])
    result = wire.verify_batch(edited)
    assert result["status"] == "broken"
    assert "consistent" not in result["detail"].replace("not consistent", "")


def test_a_uniform_strip_is_old_format_history_never_verified(ship):
    """⚠ THE STATELESS LIMIT, PINNED. Stripping the chain from EVERY record of a
    batch is indistinguishable, from the batch alone, from a pre-boundary batch
    (docs/99). It must never read `verified`; catching it needs state the
    collector keeps (the first tier-chained hash per session)."""
    stripped = _batch(ship)
    stripped = dict(stripped, records=[
        {k: v for k, v in r.items() if k not in ("tier_chain", "tier_prev", "tier_hash")}
        for r in stripped["records"]])
    result = wire.verify_batch(stripped)
    assert result["content"] == wire.OLD_FORMAT_REDUCED
    assert result["content"] != "verified"


def test_an_empty_batch_is_not_called_old_format():
    content, problems = wire.tier_chain_content([], audit_log.GENESIS, wire.LOCATED)
    assert content not in (wire.OLD_FORMAT_REDUCED, wire.OLD_FORMAT_FULL, "verified")
    assert problems == []


def test_the_persisted_cursor_after_both_ships_is_the_local_end(ship):
    """python-reviewer MEDIUM: read the cursor from DISK after the second ship,
    not a stale in-memory snapshot from the first."""
    from shipper.cursor import Cursor
    run, posted, logs = ship
    path = write_log(logs, COMMANDS[:2])
    run()
    write_log(logs, COMMANDS[2:], start=3)
    run()
    local = audit_log.read_records(path)
    fresh = Cursor(logs.parent / "state" / "cursor.json")
    assert fresh.get(SESSION).ends_at == local[-1]["hash"]
