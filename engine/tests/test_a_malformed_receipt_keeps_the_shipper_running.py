"""A malformed collector receipt must not stop the shipper, nor authorise a prune.

M2 (PROGRESS.md, 2026-09-22 establish). `shipper/run.py` read the receipt as
`int(stored) + int(deduped)`: a non-numeric `records_stored` (`"abc"`, `[1]`,
`{}`) raised out of `ship_session`, and `tick()` / `run()` catch only
KeyboardInterrupt, so the shipper died. And a 200 with NO `records_stored` at all
counted as FULL coverage — the acknowledgement, the one thing that may authorise
deleting a local record, advanced on a receipt that said nothing.

The fix follows the B3 rule, fail toward KEEPING: a missing or non-numeric count
never advances the acknowledgement, is logged once with the value's TYPE (never
the body), and the loop keeps running. A normal receipt behaves exactly as
before. The collector here is a fake; no network is touched.
"""
from __future__ import annotations

import json

import pytest

from shipper import client
from shipper.run import Shipper


def _log(path, decisions):
    from core import audit_log

    start = len(audit_log.read_records(path)) + 1 if path.exists() else 1
    for seq, decision in enumerate(decisions, start=start):
        audit_log.append("s", audit_log.build_body(
            "s", seq=seq, event="decision", decision=decision, reason="r",
            rule_id=None, kind="EXEC", command=f"cmd {seq}", cwd="/tmp"), path=path)


class Collector:
    """Stores every batch and answers with whatever receipt it is told to."""

    def __init__(self, receipts):
        self.receipts = list(receipts)
        self.batches = 0

    def post(self, url, token, payload, timeout=None):
        body = json.loads(payload.decode("utf-8"))
        if "records" not in body:                       # a heartbeat
            return client.Outcome(client.STORED, 200, {})
        self.batches += 1
        receipt = self.receipts.pop(0) if self.receipts else {"records_stored": len(body["records"])}
        if callable(receipt):
            receipt = receipt(len(body["records"]))
        return client.Outcome(client.STORED, 200, receipt)


def _shipper(tmp_path, collector, monkeypatch):
    from shipper.config import Settings

    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    settings = Settings(collector_url="https://collector.invalid", device_id="d",
                        device_token="t", log_root=logs, state_root=tmp_path / "state",
                        ships="masked")
    monkeypatch.setattr(client, "post", collector.post)
    lines: list[str] = []
    shipper = Shipper(settings, now=lambda: 1000.0, log=lines.append)
    shipper._last_flush = 0.0                           # periodic flush is due
    return shipper, logs, lines


SECRET_LOOKING_BODY = "SENTINEL-body-must-not-be-logged"
MALFORMED = [
    ("non-numeric string", {"records_stored": "abc"}, "str"),
    ("a list", {"records_stored": [1]}, "list"),
    ("an object", {"records_stored": {"x": SECRET_LOOKING_BODY}}, "dict"),
    ("missing", {"batch_ref": SECRET_LOOKING_BODY}, "missing"),
    ("null", {"records_stored": None}, "missing"),
    ("non-numeric dedup", {"records_stored": 1, "records_deduplicated": "x"}, "str"),
]


@pytest.mark.parametrize("label,receipt,kind", MALFORMED, ids=[m[0] for m in MALFORMED])
def test_a_malformed_receipt_keeps_running_and_authorises_nothing(
        tmp_path, monkeypatch, label, receipt, kind):
    shipper, logs, lines = _shipper(tmp_path, Collector([receipt]), monkeypatch)
    _log(logs / "s.log.jsonl", ["allow", "allow", "deny"])

    shipper.tick()                                      # must not raise

    position = shipper.cursor.get("s")
    assert position.acked_seq is None, "a receipt that says nothing authorised a prune"
    assert position.shipped == 3, "the queue should still move on, as before"
    said = "\n".join(lines)
    assert kind in said and "records_" in said, said
    assert SECRET_LOOKING_BODY not in said, "the receipt body must never be logged"


def test_the_warning_is_logged_once_and_the_loop_recovers(tmp_path, monkeypatch):
    collector = Collector([{"records_stored": "abc"}, {"records_stored": "abc"}])
    shipper, logs, lines = _shipper(tmp_path, collector, monkeypatch)
    _log(logs / "s.log.jsonl", ["allow"])
    shipper.tick()
    _log(logs / "s.log.jsonl", ["allow"])
    shipper._last_flush = 0.0
    shipper.tick()
    assert sum("records_stored" in line for line in lines) == 1, lines
    # and a normal receipt after it acknowledges again
    _log(logs / "s.log.jsonl", ["allow"])
    shipper._last_flush = 0.0
    shipper.tick()
    assert shipper.cursor.get("s").acked_seq == 3


# `acked_records` counts what was STORED, not what was deduplicated — today's
# arithmetic, pinned as it is.
@pytest.mark.parametrize("receipt,acked_records", [
    (lambda n: {"records_stored": n}, 3),
    (lambda n: {"records_stored": n - 1, "records_deduplicated": 1}, 2),
    (lambda n: {"records_stored": str(n)}, 3),         # int() read this before
], ids=["count", "count-plus-dedup", "numeric-string"])
def test_a_normal_receipt_acknowledges_exactly_as_before(
        tmp_path, monkeypatch, receipt, acked_records):
    shipper, logs, lines = _shipper(tmp_path, Collector([receipt]), monkeypatch)
    _log(logs / "s.log.jsonl", ["allow", "allow", "deny"])
    shipper.tick()
    position = shipper.cursor.get("s")
    assert position.acked_seq == 3 and position.acked_records == acked_records
    assert not any("records_stored" in line for line in lines)


def test_a_short_receipt_still_does_not_acknowledge(tmp_path, monkeypatch):
    """The existing non-covering branch, unchanged."""
    shipper, logs, lines = _shipper(tmp_path, Collector([{"records_stored": 1}]),
                                    monkeypatch)
    _log(logs / "s.log.jsonl", ["allow", "allow", "deny"])
    shipper.tick()
    assert shipper.cursor.get("s").acked_seq is None
