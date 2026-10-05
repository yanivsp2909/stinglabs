"""The heartbeat says, once, when it clamps or replaces its interval.

ITEM 9. `shipper/heartbeat.py` declares `interval_seconds` clamped to the window
the collector accepts (30 s .. 24 h), and falls back to the default on a value
that is not a number — both in silence, so `STING_HEARTBEAT_INTERVAL=5` quietly
became 30 and nobody could tell why the collector showed a different number.
Now one line names the value and what was declared instead. NOTHING ELSE
CHANGES: the payload is exactly what it was. The collector is a fake.
"""
from __future__ import annotations

import json

import pytest

from shipper import client, config
from shipper.cursor import Cursor
from shipper.heartbeat import Heartbeat


def _heartbeat(tmp_path, monkeypatch, seconds):
    settings = config.Settings(collector_url="http://collector.invalid",
                               device_id="d", device_token="t",
                               log_root=tmp_path / "logs", state_root=tmp_path,
                               heartbeat_seconds=seconds)
    sent = []
    monkeypatch.setattr(client, "post", lambda url, token, payload, timeout=None: (
        sent.append(json.loads(payload)), client.Outcome(client.STORED, 200, {}))[1])
    ticks = {"t": 10_000_000.0}
    beat = Heartbeat(settings, Cursor(tmp_path / "cursor.json"), now=lambda: ticks["t"])
    return beat, sent, ticks


@pytest.mark.parametrize("seconds,declared", [(5, 30.0), (10**9, 86_400.0)])
def test_a_clamp_is_said_once_and_the_payload_is_unchanged(
        tmp_path, monkeypatch, seconds, declared):
    beat, sent, ticks = _heartbeat(tmp_path, monkeypatch, seconds)
    ticks["t"] = 4.0 * 10**9                    # due, whatever the interval
    lines: list[str] = []
    beat.maybe_send(lines.append)
    ticks["t"] += 2.0 * 10**9
    beat.maybe_send(lines.append)
    assert [p["interval_seconds"] for p in sent] == [declared, declared]
    notes = [line for line in lines if "heartbeat interval" in line]
    assert len(notes) == 1, lines
    assert repr(str(seconds)) in notes[0] and f"{declared:g} s" in notes[0]


def test_a_value_that_is_not_a_number_is_named_and_still_falls_back(tmp_path, monkeypatch):
    """`from_env` int()s the setting, so `maybe_send` never sees text — `due()`
    would stop on it first (unchanged here). The standalone payload (preflight
    builds one) still falls back to the default, and the note names the value."""
    from shipper.heartbeat import _clamp_note

    beat, _sent, _ticks = _heartbeat(tmp_path, monkeypatch, "abc")
    assert beat.payload()["interval_seconds"] == float(config.HEARTBEAT_SECONDS)
    note = _clamp_note("abc")
    assert "'abc'" in note and f"{float(config.HEARTBEAT_SECONDS):g} s" in note


def test_an_interval_inside_the_window_says_nothing(tmp_path, monkeypatch):
    beat, sent, _ticks = _heartbeat(tmp_path, monkeypatch, 900)
    lines: list[str] = []
    beat.maybe_send(lines.append)
    assert sent[0]["interval_seconds"] == 900.0
    assert not any("heartbeat interval" in line for line in lines)
