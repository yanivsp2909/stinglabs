"""`purpose` — what a batch IS, claimed by its sender, with THREE states.

⚠ WHAT IT IS FOR. Nine of the twelve sessions in the first real collector store
are not work: two install probes, four preflights, a latency harness, and two
that predate everything. Nothing downstream could tell them from a developer's
actual session, so any rate measured over that store pools probes with work —
the error that has already invalidated two of this project's headline numbers.

⚠ AND THE THIRD STATE IS THE PART THAT MATTERS. A batch from a sender predating
the field declares NOTHING, and absent must never read as `work` — that would
silently relabel every session already in the store as real. This is working
rule 13 at the wire: a field whose absence defaults to the common case is a
comparison that succeeds without comparing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import audit_log, wire                                 # noqa: E402


def body(seq=1):
    return audit_log.build_body("s1", seq=seq, event="decision", decision="ALLOW",
                                 kind="EXEC", command="pytest -q", ts=1.0)


def batch(**over):
    from shipper import mask
    args = dict(records=[body()], device_id="d1", session_id="s1",
                 mask=mask.mask_record,
                 # Every batch is keyed (tests/test_fingerprints_are_keyed.py).
                 fingerprint=wire.fingerprinter(bytes(range(32))))
    args.update(over)
    records = args.pop("records")
    return wire.build_batch(records, **args)


# ------------------------------------------------------- 1 · the three states

def test_absent_claimed_work_and_claimed_probe_are_three_distinguishable_states():
    """⚠ THE TEST THAT FAILS IF ABSENT IS EVER COERCED.

    Not two states with a default. Three, and a reader can tell which it has
    without knowing anything about the sender:

        no `purpose` key at all   this sender did not say
        purpose == "work"         this sender says it is work
        purpose == a probe value  this sender says it is not

    If a later change makes absence resolve to `work` — in build_batch, in a
    receiver, or in a convenience accessor — the first and second collapse into
    one and every session already in the store silently becomes real work.
    """
    absent = batch()
    work = batch(purpose=wire.WORK)
    probe = batch(purpose=wire.PREFLIGHT)

    assert "purpose" not in absent, (
        "absence must be the ABSENCE of the key, not a null and not a default")
    assert work["purpose"] == wire.WORK
    assert probe["purpose"] == wire.PREFLIGHT

    seen = {absent.get("purpose"), work.get("purpose"), probe.get("purpose")}
    assert len(seen) == 3, f"three states collapsed into {seen}"
    assert None in seen, "absent stopped being its own answer"


def test_absent_is_a_missing_key_on_the_ENVELOPE_and_a_null_on_the_RECORD():
    """⚠ THE TWO ARTIFACTS ENCODE ABSENCE DIFFERENTLY, ON PURPOSE.

    ENVELOPE: the key is dropped — a key present with a
    null tells a reader the field existed and was withheld, which is a different
    artifact from one that never carried it, and it invites a later reader to
    'restore' it.

    RECORD: the key is present and null. A record body is HASHED, and a key that
    appeared only when somebody happened to declare would make the canonical
    form depend on the declaration, so two readers could disagree about what
    bytes a record is. Null means "nobody said" there, exactly as it does for
    every other undeclared field in the body.

    Both are absence. Neither is `work`.
    """
    envelope = json.dumps({k: v for k, v in batch().items() if k != "records"})
    assert '"purpose"' not in envelope

    record = batch()["records"][0]
    assert "purpose" in record and record["purpose"] is None


def test_a_v1_batch_read_today_has_no_purpose_and_is_not_work():
    """The population this field exists to protect: everything already stored.
    A v1 envelope hand-built the way install.py used to build one carries no
    purpose, and nothing may invent one for it."""
    old = {"wire_version": 1, "device_id": "d", "session_id": "install-probe",
            "tier": "verdict", "seq_range": None, "continues_from": "0" * 64,
            "manifest": {}, "provenance": {}, "records": [], "signature": {}}
    assert old.get("purpose") is None
    assert "purpose" not in old


# --------------------------------------------------------- 2 · the closed set

def test_the_set_is_closed_and_an_unknown_value_is_refused():
    """Quietly widening a closed set at the sending end is how a closed set
    stops being one — and a receiver would then hold a claim nobody can
    interpret."""
    for member in wire.PURPOSES:
        assert batch(purpose=member)["purpose"] == member
    for bogus in ("test", "corpus", "WORK", "", "probe", "Work"):
        with pytest.raises(ValueError):
            batch(purpose=bogus)


def test_every_member_has_a_sender_in_this_repo():
    """⚠ A MEMBER WITH NO CURRENT SENDER SHOULD NOT EXIST YET. `benchmark` and
    `test` were proposed and left out: bench-sub is written THROUGH the hook and
    swept up like any other log, and the suite posts to a collector fixture it
    starts itself. Both would have been values nothing ever sets."""
    root = Path(__file__).parent.parent
    senders = {
        wire.INSTALL_PROBE: (root / "install.py").read_text(encoding="utf-8"),
        wire.PREFLIGHT: (root / "tools" / "preflight.py").read_text(encoding="utf-8"),
        wire.WORK: (root / "install.py").read_text(encoding="utf-8"),
        wire.BENCHMARK: (root / "tools" / "bench_latency.py").read_text(
            encoding="utf-8"),
    }
    assert set(senders) == set(wire.PURPOSES), (
        "a purpose was added or removed without its sender being named here")
    assert "wire.INSTALL_PROBE" in senders[wire.INSTALL_PROBE]
    assert "wire.PREFLIGHT" in senders[wire.PREFLIGHT]
    # ⚠ `work` IS DECLARED BY THE INSTALLER, not by the sending loop. That is
    # the whole change: the one value nothing could declare now has a producer,
    # and it is the moment a human is asked rather than the moment a log is read.
    assert 'STING_PURPOSE": wire.WORK' in senders[wire.WORK]
    assert 'STING_PURPOSE="benchmark"' in senders[wire.BENCHMARK]


# ---------------------------------------------- 3 · a claim, never a measurement

def test_the_code_says_it_is_a_claim_rather_than_only_the_report():
    """⚠ A PROBE THAT DECLARES ITSELF WORK IS INDISTINGUISHABLE FROM WORK, and
    nothing here may pretend otherwise. Carried verbatim like `can_leak`: the
    receiver renders the sender's claim and never paraphrases it into something
    stronger. Asserted on the source, because a reader who is told this in a
    report and not in the file will act on the field as if it were evidence."""
    source = (Path(__file__).parent.parent / "core" / "wire.py").read_text(
        encoding="utf-8")
    assert "A CLAIM, NEVER A MEASUREMENT" in source
    assert "indistinguishable from work" in source


def test_nothing_verifies_the_claim_against_the_records():
    """A batch of ordinary decision records can call itself an install probe and
    this format will carry it. That is the design; the test exists so nobody
    later mistakes the absence of a check for an oversight."""
    chained, prev = [], audit_log.GENESIS
    for seq in (1, 2):
        record = dict(body(seq))
        record["prev"] = prev
        record["hash"] = prev = audit_log.record_hash(prev, body(seq))
        chained.append(record)

    lying = batch(records=chained, purpose=wire.INSTALL_PROBE)
    assert lying["purpose"] == wire.INSTALL_PROBE
    assert lying["manifest"]["record_count"] == 2
    assert wire.verify_batch(lying)["status"] == "intact", (
        "verification must not start judging the purpose — it verifies chains")


# ------------------------------------------------------ 4 · per batch, a union

def test_purpose_is_per_batch_so_one_session_can_carry_two():
    """⚠ DO NOT ASSUME A SESSION IS ONE THING. A session can receive a probe
    batch and a work batch, so a receiver reports every distinct value as a
    sorted list — the discipline `agent` and `os` already follow. This function
    declares ONE batch and says nothing about the session."""
    first = batch(session_id="same", purpose=wire.PREFLIGHT)
    second = batch(session_id="same", purpose=wire.WORK)
    assert first["session_id"] == second["session_id"]
    assert {first["purpose"], second["purpose"]} == {wire.PREFLIGHT, wire.WORK}
    union = sorted({b.get("purpose") for b in (first, second) if b.get("purpose")})
    assert union == [wire.PREFLIGHT, wire.WORK]


def test_the_union_keeps_absence_visible_beside_a_claim():
    """A session with one declared batch and one undeclared one is not a
    declared session. The absent batch has to stay countable, or a single
    `work` batch launders every batch beside it."""
    batches = [batch(session_id="same"), batch(session_id="same", purpose=wire.WORK)]
    declared = [b.get("purpose") for b in batches]
    assert declared.count(None) == 1 and declared.count(wire.WORK) == 1


# ------------------------------------------------------- 5 · the wire version

def test_the_version_moved_and_both_directions_are_documented():
    """A format that documents only the convenient direction breaks somebody."""
    assert wire.WIRE_VERSION == 2
    doc = wire.__dict__.get("WIRE_VERSION") and (
        Path(__file__).parent.parent / "core" / "wire.py").read_text(encoding="utf-8")
    assert "A NEWER BATCH (v2) AT AN OLDER COLLECTOR" in doc
    assert "AN OLDER BATCH (v1) AT A NEWER COLLECTOR" in doc


def test_a_batch_carrying_the_old_version_is_reported_not_reinterpreted():
    stale = dict(batch(), wire_version=1)
    result = wire.verify_batch(stale)
    assert any("wire_version" in p for p in result["problems"])


# ------------------------------------------- 6 · the sender that cannot say

def test_the_sending_loop_reads_the_records_instead_of_guessing(tmp_path):
    """⚠ THE HALF THAT WAS UNDECLARABLE, CLOSED. One pass ago this could only
    read an operator's environment variable, because a session, a preflight log
    and `bench-sub` were the same shape on disk. The records now carry what the
    process that wrote them declared, so the sender reads."""
    from shipper import config as scfg
    from shipper.run import Shipper

    settings = scfg.Settings(collector_url="http://127.0.0.1:9", device_token="t",
                              device_id="d", log_root=tmp_path,
                              state_root=tmp_path / "state")
    shipper = Shipper(settings, log=lambda *a: None)

    work = [dict(body(1), purpose=wire.WORK), dict(body(2), purpose=wire.WORK)]
    assert shipper.purpose_for(work) == wire.WORK

    probes = [dict(body(1), purpose=wire.PREFLIGHT)]
    assert shipper.purpose_for(probes) == wire.PREFLIGHT


def test_a_batch_whose_records_disagree_declares_nothing_and_never_a_majority(
        tmp_path):
    """⚠ NEVER A MAJORITY. Nine work records and one undeclared record is not a
    work batch — it is a batch the sender cannot summarise in one string. The
    records travel with their own values at every tier, so a receiver computes
    the union itself and nothing is lost by the envelope staying quiet."""
    from shipper import config as scfg
    from shipper.run import Shipper

    settings = scfg.Settings(collector_url="http://127.0.0.1:9", device_token="t",
                              device_id="d", log_root=tmp_path,
                              state_root=tmp_path / "state")
    shipper = Shipper(settings, log=lambda *a: None)

    mixed = [dict(body(i), purpose=p) for i, p in
              enumerate([wire.WORK, wire.WORK, wire.PREFLIGHT], start=1)]
    assert shipper.purpose_for(mixed) is None

    lopsided = [dict(body(i), purpose=wire.WORK) for i in range(1, 10)]
    lopsided.append(dict(body(10), purpose=None))
    assert shipper.purpose_for(lopsided) is None, (
        "one undeclared record among nine is still a disagreement")

    assert shipper.purpose_for([dict(body(1), purpose=None)]) is None


def test_the_union_a_receiver_computes_keeps_every_distinct_value(tmp_path):
    """The discipline `agent` and `os` already follow: every distinct value, as
    a sorted list, even when there is one — and absence stays countable beside
    a claim rather than being swallowed by it."""
    records = [dict(body(1), purpose=wire.WORK),
                dict(body(2), purpose=wire.PREFLIGHT),
                dict(body(3), purpose=None)]
    declared = sorted({r["purpose"] for r in records if r["purpose"]})
    assert declared == [wire.PREFLIGHT, wire.WORK]
    assert sum(1 for r in records if r["purpose"] is None) == 1
