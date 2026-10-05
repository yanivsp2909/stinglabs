"""A deny flushes everything up to and including it. Order is never broken.

⚠ THE OBVIOUS IMPLEMENTATION IS WORSE THAN THE BRIEF SAYS, AND THE CODE IS WHY.

Sending the deny OUT OF BAND while allows keep batching does not produce "a gap
that heals five minutes later". Read against `collector/ingest.py` and
`collector/store.py`, it produces something quieter:

    continues_from   the SENDER's cursor: the hash of the last record it shipped
    expected         the COLLECTOR's head: the hash of the last record it stored

Neither is the arriving record's own `prev`. `store.append` dedupes by key and
sets `ends_at` from the last record in the batch — **it never checks that the
batch's first record continues the chain.** So an out-of-band deny would arrive
with `got == expected`, be stored with **200 OK and no gap recorded at all**,
and the allows that belong before it would be appended after it.

⚠ AND THE SENDER'S CURSOR WOULD BE CORRUPTED TOO. `shipped` is an INDEX into
`read_records(path)` and advances by `len(chunk)`. Ship a record that is not at
`records[shipped]` and the count no longer indexes what was sent — the next
periodic flush takes `records[shipped:]` and silently SKIPS a record.

So the conclusion in the brief is right and the reason is stronger: out-of-band
is not a visible discontinuity, it is a silent hole on both sides.

**Flush-on-deny has neither problem** because it changes only WHEN a flush
happens, never WHAT a batch contains: every batch stays the prefix
`fresh[:MAX_BATCH_RECORDS]`, the cursor advances by exactly what was sent, and
the collector needs no change.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shipper import client, config                                   # noqa: E402
from shipper.run import Shipper                                      # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Collector:
    """A collector that stores in arrival order and checks continuity the way
    the real one does — `continues_from` against its own head, nothing else."""

    def __init__(self, fail_with=None):
        self.batches = []
        self.records = []
        self.head = "0" * 64
        self.gaps = []
        self.fail_with = fail_with

    def post(self, url, token, payload, timeout=None):
        body = json.loads(payload.decode("utf-8"))
        # ⚠ THE HEARTBEAT POSTS THROUGH THE SAME CLIENT, and it is not a batch.
        # The first version of this fake read `continues_from` off every body
        # and died on the first heartbeat — which is also a reminder that an
        # urgent flush shares a client with the liveness signal.
        if "records" not in body:
            self.heartbeats = getattr(self, "heartbeats", 0) + 1
            return client.Outcome(client.STORED, 200, {})
        if self.fail_with is not None:
            return self.fail_with
        if body["continues_from"] != self.head:
            self.gaps.append((self.head, body["continues_from"]))
        self.batches.append(body)
        for record in body["records"]:
            self.records.append(record)
            if isinstance(record.get("hash"), str):
                self.head = record["hash"]
        return client.Outcome(client.STORED, 200, {"records_stored": len(body["records"])})


def _log(path, decisions):
    """A real hash-chained log, because the chain is what is being protected.

    ⚠ SEQ CONTINUES from whatever is already there. Restarting at 1 makes
    `audit_log.append` raise DuplicateRecord — correctly, it is the duplicate
    check doing its job — and the tests that append a second time need a
    genuinely growing log, not a re-written one.
    """
    from core import audit_log

    start = len(audit_log.read_records(path)) + 1 if path.exists() else 1
    for seq, decision in enumerate(decisions, start=start):
        audit_log.append("s", audit_log.build_body(
            "s", seq=seq, event="decision", decision=decision,
            reason="r", rule_id=None, kind="EXEC", command=f"cmd {seq}",
            cwd="/tmp"), path=path)


def _shipper(tmp_path, collector, monkeypatch, **over):
    from shipper.config import Settings

    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    settings = Settings(
        collector_url="https://collector.invalid", device_id="d",
        device_token="t", log_root=logs, state_root=tmp_path / "state",
        ships="masked",
        **over)
    monkeypatch.setattr(client, "post", collector.post)
    ticks = {"t": 1000.0}

    def now():
        return ticks["t"]

    shipper = Shipper(settings, now=now, log=lambda *a, **k: None)
    # ⚠ THE PERIODIC TRIGGER IS DISARMED, AND THIS CAUGHT A REAL FAULT IN THESE
    # TESTS. `_last_flush` starts at 0.0, so `now() - _last_flush` is 1000 s on
    # the very first tick and EVERY test here would have flushed for the
    # ordinary reason — the deny tests passing without urgency ever being
    # exercised. Pretending a flush just happened is what makes urgency the
    # only thing left that can fire. `test_the_periodic_flush_still_works`
    # arms it again, so this is a control and not a disabled feature.
    shipper._last_flush = ticks["t"]
    return shipper, logs, ticks


# ─────────────────────────────────────────────────────── it flushes at all

def test_a_deny_flushes_before_the_interval(tmp_path, monkeypatch):
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow", "allow", "deny"])

    # Far below flush_records (200) and far short of flush_seconds (300).
    result = shipper.tick()

    assert result["shipped"] == 1, "the deny must not wait for the interval"
    assert result["urgent"] == ["s"]
    assert len(collector.records) == 3, "everything UP TO AND INCLUDING it"
    assert [r["decision"] for r in collector.records] == ["allow", "allow", "deny"]


def test_an_ask_flushes_too(tmp_path, monkeypatch):
    """A HUMAN IS ALREADY WAITING on an ask — the prompt is on their screen."""
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow", "ask"])

    shipper.tick()

    assert len(collector.records) == 2


def test_the_periodic_flush_still_works(tmp_path, monkeypatch):
    """⚠ THE CONTROL FOR THE CONTROL. `_shipper` disarms the periodic trigger so
    urgency can be measured alone; this re-arms it, so "allows did not ship"
    cannot be satisfied by a shipper that never ships allows at all."""
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow"] * 10)

    ticks["t"] += 400                    # past flush_seconds (300)
    result = shipper.tick()

    assert result["shipped"] == 1
    assert len(collector.records) == 10


def test_allows_alone_do_not_flush_early(tmp_path, monkeypatch):
    """⚠ THE OTHER HALF. Without it every test above is satisfied by a shipper
    that flushes on every tick, which is the streaming design this one exists
    to avoid — allow is ~95% of records."""
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow"] * 10)

    result = shipper.tick()

    assert result["shipped"] == 0, "allows must keep batching"
    assert collector.records == []
    assert result["urgent"] == []


# ────────────────────────────────────────────── the stop condition: ordering

def test_every_batch_is_a_prefix_so_order_can_never_break(tmp_path, monkeypatch):
    """THE STOP CONDITION. Records must arrive in seq order in every case."""
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow"] * 5 + ["deny"] + ["allow"] * 3)

    shipper.tick()                       # urgent: ships through the deny
    _log(logs / "s.log.jsonl", ["allow", "deny"])
    shipper.tick()                       # a second urgent flush

    seqs = [r["seq"] for r in collector.records]
    assert seqs == sorted(seqs), f"records arrived out of order: {seqs}"
    assert seqs == list(range(1, len(seqs) + 1)), f"a record was skipped: {seqs}"
    assert collector.gaps == [], f"the collector recorded a gap: {collector.gaps}"


def test_a_periodic_flush_racing_an_urgent_one_still_ships_in_order(
        tmp_path, monkeypatch):
    """Two flushes back to back — the second finds the cursor where the first
    left it, because the cursor is the only thing either consults."""
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow"] * 3 + ["deny"])

    shipper.tick()                       # urgent
    ticks["t"] += 400                    # the periodic interval also elapses
    _log(logs / "s.log.jsonl", ["allow", "allow"])
    shipper.tick()                       # periodic

    seqs = [r["seq"] for r in collector.records]
    assert seqs == list(range(1, 7)), seqs
    assert collector.gaps == []


def test_two_sessions_interleaving_do_not_disturb_each_other(tmp_path,
                                                              monkeypatch):
    """⚠ CONTINUITY IS PER SESSION on both sides — one cursor each, one head
    each — so a deny in one session cannot make the other look discontinuous."""
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "a.log.jsonl", ["allow", "allow"])
    _log(logs / "b.log.jsonl", ["allow", "deny"])

    # The fake collector keeps ONE head, so per-session continuity is checked
    # by the cursor rather than by it; assert on ordering within each session.
    shipper.tick()

    by_session = {}
    for batch in collector.batches:
        by_session.setdefault(batch["session_id"], []).extend(
            r["seq"] for r in batch["records"])
    assert by_session["a"] == [1, 2]
    assert by_session["b"] == [1, 2]


def test_the_deny_is_included_even_past_the_batch_cap(tmp_path, monkeypatch):
    """⚠ THE CASE A SINGLE `ship_session` CALL WOULD HAVE MISSED.

    `ship_session` sends at most MAX_BATCH_RECORDS. A deny beyond that boundary
    would be flushed "urgently" and left on disk — the feature silently not
    working in exactly the situation it exists for: a laptop back from being
    offline, where the backlog is deep and a deny matters most.
    """
    monkeypatch.setattr(config, "MAX_BATCH_RECORDS", 4)
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow"] * 9 + ["deny"])

    shipper.tick()

    decisions = [r["decision"] for r in collector.records]
    assert "deny" in decisions, "the deny was left on disk by an urgent flush"
    assert decisions == ["allow"] * 9 + ["deny"]
    assert len(collector.batches) > 1, "this must have taken several batches"


def test_an_urgent_flush_is_bounded(tmp_path, monkeypatch):
    """One tick must not try to drain an unbounded backlog in a single burst
    against a collector that has only just come back."""
    monkeypatch.setattr(config, "MAX_BATCH_RECORDS", 1)
    monkeypatch.setattr(config, "MAX_URGENT_ROUNDS", 3)
    collector = Collector()
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow"] * 10 + ["deny"])

    shipper.tick()

    assert len(collector.batches) == 3, "the burst must stop at the bound"
    seqs = [r["seq"] for r in collector.records]
    assert seqs == [1, 2, 3], "and what it did send is still a prefix, in order"


# ─────────────────────────────────── the cursor's guarantee is unchanged

# ⚠ 429 IS `UNAVAILABLE`, READ FROM `_classify` RATHER THAN ASSUMED. It falls
# through the status ladder to the final `return`, which means backoff and DO
# NOT ADVANCE — exactly the behaviour that preserves "delay, never data". The
# urgent flush reuses `_send`, so it inherits that instead of restating it.
@pytest.mark.parametrize("failure,why", [
    (client.Outcome(client.UNAVAILABLE, 0, {}, "down"),
     "an unreachable collector"),
    (client.Outcome(client.UNAUTHORISED, 401, {}, "no"), "a refused token"),
    (client.Outcome(client.UNAVAILABLE, 429, {}, "slow down"), "a 429"),
    (client.Outcome(client.REFUSED, 400, {}, "malformed"), "a malformed batch"),
])
def test_a_failed_urgent_flush_behaves_exactly_like_a_failed_periodic_one(
        tmp_path, monkeypatch, failure, why):
    """⚠ DELAY, NEVER DATA — and no second path that forgets it.

    The urgent flush reuses `ship_session` and `_send` unchanged, so every
    outcome class is handled by the code that already handled it. A separate
    urgent send would be a second place for the 429 path to be got wrong.
    """
    collector = Collector(fail_with=failure)
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow", "deny"])

    shipper.tick()

    assert shipper.cursor.get("s").shipped == 0, (
        f"{why}: the cursor advanced past records that were never stored")

    # And when it comes back, the same records ship, in order, once.
    collector.fail_with = None
    shipper._retry_after = 0.0
    shipper._backoff = 0.0
    shipper.tick()

    assert [r["seq"] for r in collector.records] == [1, 2]
    assert shipper.cursor.get("s").shipped == 2


def test_urgency_does_not_bypass_backoff(tmp_path, monkeypatch):
    """A refused collector must not be hammered harder because the thing
    waiting is important — that turns an outage into an outage plus a herd."""
    collector = Collector(fail_with=client.Outcome(
        client.UNAVAILABLE, 0, {}, "down"))
    shipper, logs, ticks = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["deny"])

    shipper.tick()
    attempts_after_first = len(collector.batches) if collector.batches else 0
    shipper.tick()                       # still inside the backoff window

    assert shipper._retry_after > ticks["t"], "no backoff was armed"
    assert (len(collector.batches) if collector.batches else 0) == \
        attempts_after_first, "an urgent flush retried inside the backoff"


# ─────────────────────────────────────────────── the hook is not involved

def test_the_hook_gained_nothing(tmp_path):
    """⚠ ASSERTED FROM THE SOURCE, the way the no-networking claim already is.

    The whole design rests on the shipper learning by READING what the hook
    already wrote. If a sentinel, a signal or a socket ever appears on the hook
    side, this fails in the same run.
    """
    for name in ("hook_entry.py", "sting_hook.py"):
        source = open(os.path.join(ROOT, name), encoding="utf-8").read()
        code = "\n".join(line for line in source.splitlines()
                         if not line.strip().startswith("#"))
        for forbidden in ("shipper", "flush", "urgent", "sentinel"):
            assert forbidden not in code, f"{name} mentions {forbidden!r}"


def test_the_shipper_learns_by_reading_the_log_it_already_reads():
    """No new watcher, no new file, no new syscall class — `urgent_sessions`
    uses `read_records`, which `pending()` already calls every poll."""
    source = open(os.path.join(ROOT, "shipper", "run.py"),
                  encoding="utf-8").read()
    body = source[source.index("def urgent_sessions"):source.index("def should_flush")]
    # ⚠ CODE ONLY. The first version scanned the whole function including its
    # docstring and tripped on the word "signal" in a sentence explaining that
    # no signal is used — a scan that fails on its own explanation.
    code = "\n".join(
        line for line in body.splitlines()
        if line.strip() and not line.strip().startswith(("#", '"""', "*", "⚠")))

    assert "read_records" in code
    for forbidden in ("inotify", "kqueue", "watchdog", "st_mtime",
                      "import signal", "socket", "urllib"):
        assert forbidden not in code, f"urgent_sessions uses {forbidden}"
