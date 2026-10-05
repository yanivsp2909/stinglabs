"""One seq, two records: the deliberate allow-once pair, and where it is judged.

Real, exact ground truth from a live session — a DENY the developer overrode:

    seq=222 event=decision        DENY   unexpected destination 'claude.ai' ...
    seq=222 event=allow_once_used  ALLOW  allowed once by the developer ...

`seq` numbers the ACTION, and this pair is the one case where one action writes
two records at one seq (hook_entry `_apply_allow_once`). This test pins WHERE
that is judged, because two functions have deliberately different jobs:

  * `verify_chain` is the HASH check. It reads only prev/hash and never `seq`,
    so it ACCEPTS this pair AND even a genuinely doubled log — the chain is
    intact either way. A collision is not a quiet edit, and making the hash
    checker report one would make a settings-scope mistake look like tampering.
  * `duplicate_events` is the DOUBLING check, keyed on (session, seq, event).
    It does NOT flag the pair (different events), and DOES flag two same-event
    records at one seq. `tools/verify_log.py` surfaces that as DOUBLED.

A SKIPPED seq (a gap) is judged by neither — legitimate fail-open holes exist
(docs/76). These pin the accepted pattern so a future change cannot quietly
move collision detection into the hash checker (which regresses the doubled-log
tests) or stop recognising the override pair.
"""
import hashlib
from pathlib import Path

import pytest

from core.audit_log import (append, build_body, duplicate_events, read_records,
                            verify_chain)


@pytest.fixture
def log(tmp_path) -> Path:
    return tmp_path / "s1.log.jsonl"


def _fp(command: str) -> str:
    return hashlib.sha256(command.encode()).hexdigest()


def _decision(session, seq, decision, reason, command):
    return build_body(session, seq=seq, event="decision", decision=decision,
                      reason=reason, rule_id="untrusted_unexpected:git_commit",
                      kind="EXEC", command=command, action_hash=_fp(command))


def _override(session, seq, reason, command):
    return build_body(session, seq=seq, event="allow_once_used", decision="allow",
                      reason=reason, rule_id="untrusted_unexpected:git_commit",
                      kind="EXEC", command=command, action_hash=_fp(command))


# ─────────────────────────────────────────────────────────────────────────────
# verify_chain — the hash check — ACCEPTS the pair; the chain is intact.
# ─────────────────────────────────────────────────────────────────────────────
def test_verify_chain_accepts_the_real_allow_once_pair(log):
    """The exact seq=222 shape: DENY then its allow_once_used at the same seq."""
    session = "s1"
    cmd = "git checkout -b x && git commit -F msg && cp a b && pytest"
    append(session, _decision(session, 221, "allow", None, "ls"), path=log)
    append(session, _decision(session, 222, "deny",
                              "unexpected destination 'claude.ai' ...", cmd), path=log)
    append(session, _override(session, 222,
                              "allowed once by the developer; the engine denied "
                              "this: unexpected destination 'claude.ai' ...", cmd), path=log)
    ok, bad, detail = verify_chain(log)
    assert ok and bad is None, detail


# ─────────────────────────────────────────────────────────────────────────────
# duplicate_events — the doubling check — is where the pattern is recognised
# and where a genuine collision is caught.
# ─────────────────────────────────────────────────────────────────────────────
def test_duplicate_events_does_not_flag_the_allow_once_pair(log):
    session = "s1"
    append(session, _decision(session, 1, "deny", "r", "git commit -F m"), path=log)
    append(session, _override(session, 1, "allowed once", "git commit -F m"), path=log)
    append(session, _decision(session, 2, "allow", None, "ls"), path=log)
    assert duplicate_events(read_records(log)) == [], \
        "a decision and its own override share a seq by design — not a duplicate"


def test_duplicate_events_catches_two_same_event_records_at_one_seq():
    """Two `decision` records at one seq in one session is a genuine collision —
    a doubled log. Built by hand: append() would refuse identical records, and
    distinct action_hashes are what two racing hooks or an older engine produced."""
    recs = [
        {"session_id": "s1", "seq": 5, "event": "decision", "action_hash": "a"},
        {"session_id": "s1", "seq": 5, "event": "decision", "action_hash": "b"},
    ]
    dupes = duplicate_events(recs)
    assert dupes == [("s1", 5, "decision", 2)], dupes


def test_duplicate_events_ignores_cross_session_seq_reuse_and_seqless():
    recs = [
        {"session_id": "a", "seq": 1, "event": "decision"},
        {"session_id": "b", "seq": 1, "event": "decision"},   # different session
        {"session_id": "a", "seq": None, "event": "session_start"},
        {"session_id": "a", "seq": None, "event": "session_start"},
    ]
    assert duplicate_events(recs) == []


# ─────────────────────────────────────────────────────────────────────────────
# The boundary itself: verify_chain must stay hash-only, so a doubled log still
# verifies there and is reported by duplicate_events, not by the chain checker.
# ─────────────────────────────────────────────────────────────────────────────
def test_a_doubled_log_still_verifies_at_the_chain_level(log):
    """Two distinct actions accidentally sharing seq 3 — chain intact, so
    verify_chain says OK; duplicate_events is the one that catches it."""
    session = "s1"
    append(session, _decision(session, 3, "allow", None, "cat a.txt"), path=log)
    append(session, _decision(session, 3, "allow", None, "cat SECRET.txt"), path=log)
    ok, _, _ = verify_chain(log)
    assert ok, "verify_chain is hash-only; a doubled log's chain is genuinely intact"
    assert duplicate_events(read_records(log)), "duplicate_events must catch it"


def test_a_seq_gap_is_flagged_by_neither(log):
    session = "s1"
    append(session, _decision(session, 1, "allow", None, "ls"), path=log)
    append(session, _decision(session, 3, "allow", None, "echo skipped 2"), path=log)
    ok, bad, detail = verify_chain(log)
    assert ok and bad is None, detail
    assert duplicate_events(read_records(log)) == []
