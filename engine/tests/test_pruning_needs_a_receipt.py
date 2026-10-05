"""⚠ THE CURSOR IS NOT PERMISSION TO DELETE, AND THAT IS THE WHOLE POINT.

`shipper/run.py` advances the cursor in two places. One is a 200/202 from the
collector. The other is `_split`, which steps over a single record the collector
REFUSED as too large — no round trip, nothing stored anywhere. A prune written
against the cursor deletes exactly that record: the one proven not to be at the
collector. Evidence destroyed by the thing meant to keep it.

So these tests are mostly about what pruning REFUSES.
"""
from __future__ import annotations

import json
import time

import pytest

from core.audit_log import (append, build_body, prune_manifest_for,
                            pruned_start, verify_chain)
from tools import prune_shipped


@pytest.fixture
def session(tmp_path):
    """A real log with a real chain, and the cursor entry beside it."""
    log = tmp_path / "s1.log.jsonl"
    old = time.time() - 30 * 86400
    for seq in range(1, 11):
        body = build_body("s1", seq=seq, event="decision", decision="allow",
                          command=f"git status {seq}")
        body["ts"] = old + seq
        append("s1", body, path=log)
    return log


def _position(**kw):
    base = {"shipped": 999, "gaps": 0, "acked_seq": 10, "acked_records": 10,
            "last_batch_ref": "batches/abc123", "acked_at": time.time(),
            "skipped_seqs": []}
    base.update(kw)
    return {"s1": base}


# ════════════════════════════ what it refuses ══

def test_a_session_the_collector_never_acknowledged_is_untouched(session):
    r = prune_shipped.prune(session, _position(acked_seq=None), 7, apply=True)

    assert r["removed"] == 0
    assert "never acknowledged" in r["why"]
    assert len(session.read_text(encoding="utf-8").splitlines()) == 10


def test_a_record_split_stepped_over_stops_the_prune_dead(session):
    """⚠ THE RECORD THIS TOOL EXISTS NOT TO DELETE. `_split` advances the cursor
    past a record the collector refused, so later batches push `acked_seq` well
    beyond it. Only `skipped_seqs` remembers that nothing ever stored it."""
    r = prune_shipped.prune(session, _position(skipped_seqs=[4]), 7, apply=True)

    assert r["removed"] == 3, "the prune ran past a record stored nowhere"
    assert "seq 4" in r["why"] and "NOWHERE" in r["why"]
    kept = [json.loads(ln) for ln in
            session.read_text(encoding="utf-8").splitlines()]
    assert [k["seq"] for k in kept] == [4, 5, 6, 7, 8, 9, 10]


def test_a_reported_gap_blocks_the_session_entirely(session):
    """A 202 says the collector is MISSING earlier batches. The records below
    the cursor are candidates for exactly what it is missing."""
    r = prune_shipped.prune(session, _position(gaps=1), 7, apply=True)

    assert r["removed"] == 0
    assert "gap" in r["why"]


def test_the_keep_window_is_a_floor_regardless_of_acknowledgement(tmp_path):
    """TASK 2.3 — a developer reads what just happened without the network."""
    log = tmp_path / "s1.log.jsonl"
    for seq in range(1, 6):
        body = build_body("s1", seq=seq, event="decision", decision="allow",
                          command=f"c{seq}")
        body["ts"] = time.time() - 60          # a minute ago
        append("s1", body, path=log)

    r = prune_shipped.prune(log, _position(acked_seq=5), 7, apply=True)

    assert r["removed"] == 0
    assert "keep window" in r["why"]


def test_a_log_that_does_not_verify_is_never_rewritten(session):
    """⚠ THE ONE CASE WHERE REWRITING DESTROYS THE EVIDENCE OF WHAT WENT WRONG."""
    lines = session.read_text(encoding="utf-8").splitlines(True)
    tampered = json.loads(lines[2])
    tampered["command"] = "something else"
    lines[2] = json.dumps(tampered, sort_keys=True) + "\n"
    session.write_text("".join(lines), encoding="utf-8")

    r = prune_shipped.prune(session, _position(), 7, apply=True)

    assert r["removed"] == 0
    assert "does not verify" in r["why"]
    assert len(session.read_text(encoding="utf-8").splitlines()) == 10


def test_the_final_record_is_never_removed(session):
    """It is what `_last_hash` reads to chain the next append. Deleting it
    restarts the chain from GENESIS mid-session."""
    r = prune_shipped.prune(session, _position(acked_seq=10), 7, apply=True)

    assert r["removed"] == 9
    assert len(session.read_text(encoding="utf-8").splitlines()) == 1


def test_a_dry_run_writes_nothing(session):
    before = session.read_text(encoding="utf-8")

    r = prune_shipped.prune(session, _position(), 7, apply=False)

    assert r["removed"] > 0, "the dry run reported nothing to do"
    assert session.read_text(encoding="utf-8") == before
    assert not prune_manifest_for(session).exists()


# ════════════════════════════ what survives it ══

def test_a_pruned_log_still_verifies_through_its_manifest(session):
    """⚠ WITHOUT THE MANIFEST THIS IS INDISTINGUISHABLE FROM TAMPERING.
    `verify_chain` starts at GENESIS; delete the head and the surviving first
    record chains from a hash that exists nowhere, which is precisely what the
    verifier should call a break when it cannot tell the difference."""
    prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)

    ok, bad, detail = verify_chain(session)
    assert ok, f"a legitimately pruned log reports a break: {detail}"
    assert "declared prune point" in detail


def test_a_manifest_naming_the_wrong_hash_does_not_excuse_the_log(session):
    """The manifest is a declaration, not a skeleton key."""
    prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)
    manifest = prune_manifest_for(session)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["prunes"][-1]["starts_from"] = "f" * 64
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    ok, bad, detail = verify_chain(session)
    assert not ok, "any hash in a manifest was accepted as a starting point"


def test_a_corrupt_manifest_reports_a_break_rather_than_excusing_one(session):
    prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)
    prune_manifest_for(session).write_text("{not json", encoding="utf-8")

    assert pruned_start(session) is None
    ok, _, _ = verify_chain(session)
    assert not ok


def test_the_manifest_records_which_receipt_authorised_the_deletion(session):
    """A deletion whose authority is not written down is a deletion you have to
    take on trust later."""
    prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)

    entry = json.loads(prune_manifest_for(session).read_text(
        encoding="utf-8"))["prunes"][-1]
    assert entry["removed"] == 6            # seqs 1..6 inclusive
    assert entry["first_seq"] == 1 and entry["last_seq"] == 6
    assert entry["authorised_by"]["last_batch_ref"] == "batches/abc123"
    assert entry["authorised_by"]["acked_seq"] == 6


def test_pruning_twice_appends_rather_than_replaces_the_history(session):
    prune_shipped.prune(session, _position(acked_seq=4), 7, apply=True)
    prune_shipped.prune(session, _position(acked_seq=8), 7, apply=True)

    entries = json.loads(prune_manifest_for(session).read_text(
        encoding="utf-8"))["prunes"]
    assert len(entries) == 2, "the first prune's record was overwritten"
    ok, _, detail = verify_chain(session)
    assert ok, detail


# ══════════ ⚠ seq IS NOT UNIQUE, AND THIS TOOL COMPARES AGAINST IT ══

# `identity()` is (session_id, seq, action_hash, EVENT) — and its docstring says
# why: allow-once DELIBERATELY writes a SECOND record for the same action, same
# seq, with event="allow_once_used", so the log shows both what the policy
# decided and that a human overruled it. This repo has also produced doubled
# logs from two hooks appending per tool call.
#
# The first version of this tool stopped the prefix at `seq > acked_seq`. For a
# record sharing a seq with an acknowledged one, `5 > 5` is False — so it was
# eligible, and it was deleted. The override record is precisely the one whose
# purpose is proving a human, not the policy, made the final call.

def test_an_allow_once_override_sharing_a_seq_is_not_deleted(tmp_path):
    log = tmp_path / "s1.log.jsonl"
    old = time.time() - 30 * 86400
    for seq in (1, 2, 3):
        body = build_body("s1", seq=seq, event="decision", decision="deny",
                          command=f"c{seq}")
        body["ts"] = old + seq
        append("s1", body, path=log)
    # the human overrules seq 3 — SAME seq, different event, appended after
    override = build_body("s1", seq=3, event="allow_once_used",
                          decision="allow", command="c3")
    override["ts"] = old + 4
    append("s1", override, path=log)

    # the collector acknowledged the first three; the override has not shipped
    r = prune_shipped.prune(
        log, {"s1": {"shipped": 3, "gaps": 0, "acked_seq": 3,
                      "acked_records": 3, "last_batch_ref": "b/1",
                      "skipped_seqs": []}}, 7, apply=True)

    kept = [json.loads(ln) for ln in
            log.read_text(encoding="utf-8").splitlines()]
    assert any(k["event"] == "allow_once_used" for k in kept), (
        "the record proving a human overruled the policy was deleted, because "
        "it shared a seq with the decision it overruled")
    # the three acknowledged decisions may go; the override may NOT
    assert r["removed"] == 3
    assert kept[-1]["event"] == "allow_once_used"


def test_a_duplicate_seq_stops_the_prune_and_says_why(tmp_path):
    """Two hooks appending per tool call have doubled a log here before. A seq
    that repeats inside the window means `seq <= acked` no longer identifies a
    record at all."""
    log = tmp_path / "s1.log.jsonl"
    old = time.time() - 30 * 86400
    for seq, cmd in ((1, "a"), (2, "b"), (3, "c")):
        body = build_body("s1", seq=seq, event="decision", decision="allow",
                          command=cmd)
        body["ts"] = old + seq
        append("s1", body, path=log)
    # ⚠ `append()` REJECTS AN EXACT DUPLICATE, so a doubled log is produced by
    # two processes racing the tail read — reproduced here by writing the line
    # rather than by calling append, which is what actually happens.
    lines = log.read_text(encoding="utf-8").splitlines(True)
    lines.insert(2, lines[1])
    log.write_text("".join(lines), encoding="utf-8")

    r = prune_shipped.prune(log, _position(acked_seq=3, shipped=4), 7, apply=True)

    assert r["removed"] == 0
    # the doubled line breaks the chain, which is caught even earlier
    assert "does not verify" in r["why"] or "occurs twice" in r["why"]


def test_the_prune_never_runs_past_what_the_loop_physically_walked(session):
    """⚠ THE BOUND THAT MAKES THE ABOVE SAFE BY CONSTRUCTION. `shipped` is an
    INDEX — `run.py:117` slices `read_records(path)[position.shipped:]` — while
    `seq` is a value. A cursor claiming a high `acked_seq` but a small `shipped`
    must not authorise deleting records the loop never reached."""
    r = prune_shipped.prune(session, _position(acked_seq=10, shipped=3), 7,
                             apply=True)

    assert r["removed"] == 3
    assert len(session.read_text(encoding="utf-8").splitlines()) == 7


def test_a_log_holding_another_session_does_not_borrow_its_receipts(session):
    """`STING_LOG` lets a harness name the file; a renamed or merged log would
    otherwise be pruned against a foreign session's acknowledged mark."""
    r = prune_shipped.prune(session, {"s1": _position()["s1"]}, 7, apply=False)
    assert r["removed"] > 0                      # baseline: same session, fine

    renamed = session.parent / "someone-else.log.jsonl"
    renamed.write_bytes(session.read_bytes())
    r2 = prune_shipped.prune(renamed, {"someone-else": _position()["s1"]}, 7,
                              apply=True)

    assert r2["removed"] == 0
    assert "not" in r2["why"] and "session" in r2["why"]


def test_a_non_numeric_seq_stops_one_log_instead_of_crashing_the_run(session):
    lines = session.read_text(encoding="utf-8").splitlines(True)
    rec = json.loads(lines[2])
    rec["seq"] = "three"
    lines[2] = json.dumps(rec, sort_keys=True) + "\n"
    session.write_text("".join(lines), encoding="utf-8")

    r = prune_shipped.prune(session, _position(), 7, apply=True)   # must not raise

    assert r["removed"] == 0
    assert "does not verify" in r["why"] or "not a number" in r["why"]
