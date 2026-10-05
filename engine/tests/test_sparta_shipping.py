"""Sparta in the shipper: off, the batch is the one main sent, byte for byte;
on, what only Sparta finds is masked and two fields say what it found, and
every verdict field is the flag-off one; failing, the record ships anyway.

The detector is `FakeSpartaDetector`, reached through the real loader
(`get_detector`) by pointing its import path at a stub module. No model.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sparta_fixtures as fx                                       # noqa: E402
from core import audit_log, wire                                   # noqa: E402

ON = {"sparta": "1"}
VERDICT_FIELDS = ("decision", "rule_id", "enforced", "relaxed", "kind", "event",
                  "seq", "session_id", "ts", "agent")


@pytest.fixture(autouse=True)
def _no_org_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("STING_POLICY_CACHE", str(tmp_path / "org_policy.json"))


@pytest.fixture
def collector(monkeypatch):
    from shipper import run
    fake = fx.FakeCollector()
    monkeypatch.setattr(run.client, "post", fake.post)
    monkeypatch.setattr(run.client, "get", fake.get)
    return fake


def _ship(tmp_path, collector, **flags) -> tuple[dict, list[str]]:
    said: list[str] = []
    shipper = fx.make_shipper(tmp_path, said.append, **flags)
    shipper.tick()
    batches = collector.batches()
    assert len(batches) == 1, said
    return batches[0], said


def _golden() -> str:
    return fx.GOLDEN.read_text(encoding="utf-8")


def _local(tmp_path) -> list[dict]:
    return audit_log.read_records(audit_log.default_log_path(fx.SESSION, tmp_path / "logs"))


# ═══════════════════════════════════════════════════════════ the flag off

@pytest.mark.parametrize("flags", [{}, {"sparta": "0"}, {"sparta": "true"},
                                   {"sparta": "0", "sparta_taint": "1"}],
                         ids=["unset", "0", "true", "taint-alone"])
def test_with_sparta_off_the_records_ship_byte_identical_to_main(tmp_path, collector,
                                                                 flags):
    """⚠ THE GOLDEN WAS WRITTEN BY MAIN AT f48beae, before Sparta existed: this
    compares against what the shipper sent then, not against itself."""
    batch, said = _ship(tmp_path, collector, **flags)
    assert fx.shipped_part(batch) == _golden()
    assert not [line for line in said if "parta" in line], said


def test_with_sparta_off_the_enrichment_is_never_entered(tmp_path, collector, monkeypatch):
    from shipper import sparta_enrich, sparta_iface

    def entered(*a, **k):
        raise AssertionError("the enrichment was entered with the flag off")
    for module, name in ((sparta_enrich, "enrich_record"), (sparta_enrich, "Guarded"),
                         (sparta_iface, "get_detector"), (sparta_iface, "taint_enabled"),
                         (sparta_iface, "call_within")):
        monkeypatch.setattr(module, name, entered)
    batch, _said = _ship(tmp_path, collector, sparta="0", sparta_taint="1")
    assert fx.shipped_part(batch) == _golden()


def test_with_sparta_off_the_masker_is_the_one_it_always_was(tmp_path):
    from shipper import mask
    shipper = fx.make_shipper(tmp_path, print)
    masker = shipper._masker(mask.NO_SESSION, None)
    assert masker.func is mask.mask_record
    assert masker.keywords == {"known": mask.NO_SESSION, "analyzer": None}


# ═══════════════════════════════════════════════════════════ the flag on

@pytest.fixture
def fake(monkeypatch):
    from shipper import sparta_iface
    detector = sparta_iface.FakeSpartaDetector(intent_score=0.42)
    fx.install_factory(monkeypatch, lambda: detector)
    return detector


def test_with_sparta_on_what_only_sparta_finds_is_masked(tmp_path, collector, fake):
    batch, _said = _ship(tmp_path, collector, **ON)
    shipped = json.dumps(batch)
    for value in fx.FOUND_ONLY_BY_SPARTA:
        problem = fx.absent(value, shipped, "the batch")
        assert problem is None, problem
    golden = json.loads(_golden())["records"]
    plain = json.dumps(golden)
    shown = sum(value in plain for value in fx.FOUND_ONLY_BY_SPARTA)
    assert shown == len(fx.FOUND_ONLY_BY_SPARTA) == 3, \
        "the control: off, each of these ships as written"
    first, second, _third, fourth = batch["records"]
    assert first["command"] == ('curl -d "note=call [person] at [address]" '
                                "-d owner=[email] https://x.invalid")
    assert second["command"] == "echo [secret] > /tmp/notes.txt"
    assert fourth["paths"] == ["/repo/notes/[person].txt"]
    assert first["masked"] == {"address": 1, "email": 2, "person": 1}
    assert second["masked"] == {"secret": 1}


def test_sparta_suspected_says_where_and_what_and_never_the_value(tmp_path, collector,
                                                                  fake):
    batch, _said = _ship(tmp_path, collector, **ON)
    local = _local(tmp_path)
    checked = 0
    for shipped, origin in zip(batch["records"], local):
        for entry in shipped.get("sparta_suspected", ()):
            assert set(entry) == {"field", "item", "type", "start", "end", "confidence"}
            texts = list(_texts(origin[entry["field"]]))
            piece = texts[entry["item"]][entry["start"]:entry["end"]]
            assert fake.detect(piece)[0].type == entry["type"], "the offsets are true"
            assert 0 <= entry["confidence"] <= 1
            checked += 1
        problem = fx.absent(fx.NAME, json.dumps(shipped.get("sparta_suspected")),
                            "the provenance")
        assert problem is None, problem
    assert checked == 7, "name, address and two emails; a secret; a phone; a name in a path"
    assert batch["records"][3]["sparta_suspected"] == [
        {"field": "paths", "item": 0, "type": "name", "start": 12, "end": 27,
         "confidence": 0.91}]


def _texts(value):
    from shipper import mask
    return mask._texts(value)


def test_sparta_intent_is_recorded_beside_the_decision(tmp_path, collector, fake):
    batch, _said = _ship(tmp_path, collector, **ON)
    scores = [r.get("sparta_intent") for r in batch["records"]]
    assert scores == [0.42, 0.42, 0.42, None], "every record with a command; none without"


def test_with_sparta_on_every_verdict_field_is_the_flag_offs(tmp_path, collector, fake):
    batch, _said = _ship(tmp_path, collector, **ON)
    golden = json.loads(_golden())["records"]
    assert {r["decision"] for r in golden} == {"DENY", "ALLOW", "ASK"}, \
        "the comparison covers every verdict"
    assert len(golden) == len(batch["records"]) == 4
    for off, on in zip(golden, batch["records"]):
        for name in VERDICT_FIELDS:
            assert (name in off) == (name in on) and off.get(name) == on.get(name), name


def test_with_sparta_on_the_local_log_and_the_session_root_are_untouched(tmp_path,
                                                                         collector, fake):
    said: list[str] = []
    shipper = fx.make_shipper(tmp_path, said.append, **ON)
    root = tmp_path / "logs"
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    assert before, "the log is there"
    shipper.tick()
    assert collector.batches(), said
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before


def test_the_tier_chain_covers_what_sparta_added(tmp_path, collector, fake):
    batch, _said = _ship(tmp_path, collector, **ON)
    result = wire.verify_batch(batch)
    assert result["status"] == "intact" and result["content"] == "verified", result
    batch["records"][0]["sparta_intent"] = 0.01
    assert wire.verify_batch(batch)["content"] != "verified", "the control: an edit shows"


def test_the_detector_is_loaded_once_per_process(tmp_path, collector, monkeypatch):
    from shipper import sparta_iface
    made: list[object] = []

    def factory():
        made.append(sparta_iface.FakeSpartaDetector())
        return made[-1]
    fx.install_factory(monkeypatch, factory)
    said: list[str] = []
    shipper = fx.make_shipper(tmp_path, said.append, **ON)
    shipper.tick()
    audit_log.append(fx.SESSION, audit_log.build_body(
        fx.SESSION, seq=5, event="decision", decision="ALLOW", kind="EXEC",
        ts=1_786_000_005.0, command=f"echo {fx.NAME}"), root=tmp_path / "logs")
    shipper._last_flush = 0.0
    shipper.tick()
    assert len(collector.batches()) == 2, said
    assert len(made) == 1


def _ship_one(tmp_path, collector, command: str, **flags) -> dict:
    """One record carrying `command`, shipped; the record as it left."""
    from shipper import run
    record = audit_log.build_body(fx.SESSION, seq=1, event="decision", decision="ALLOW",
                                  kind="EXEC", ts=1_786_000_001.0, command=command)
    audit_log.append(fx.SESSION, record, root=tmp_path / "logs")
    run.Shipper(fx.settings(tmp_path, **flags), now=lambda: 1.0, log=print).tick()
    (shipped,) = collector.batches()[-1]["records"]
    return shipped


def test_an_id_only_sparta_finds_ships_as_id_number(tmp_path, collector, fake):
    """An Israeli ID failing its check digit and an SSN in area 9xx: the code
    leaves both as written; Sparta's `id` masks them with the code's own ID
    label, and `sparta_suspected` names them `id`."""
    command = f"echo ID {fx.ISRAELI_ID} SSN {fx.SSN_9XX}"
    off = _ship_one(tmp_path / "off", collector, command)
    assert off["command"] == command and "masked" not in off, \
        "the control: off, both ship as written"
    on = _ship_one(tmp_path / "on", collector, command, **ON)
    assert on["command"] == "echo ID [id-number] SSN [id-number]"
    assert on["masked"] == {"id-number": 2}
    suspected = on["sparta_suspected"]
    assert [s["type"] for s in suspected] == ["id", "id"]
    assert sorted(command[s["start"]:s["end"]] for s in suspected) == \
        sorted([fx.ISRAELI_ID, fx.SSN_9XX]), "the offsets are true"
    for value in (fx.ISRAELI_ID, fx.SSN_9XX):
        problem = fx.absent(value, json.dumps(on), "the record")
        assert problem is None, problem


def test_an_edited_log_cannot_put_words_in_spartas_mouth(tmp_path, collector, fake):
    """The two fields are the enrichment's to write, as `masked` is masking's."""
    root = tmp_path / "logs"
    record = audit_log.build_body(fx.SESSION, seq=1, event="decision", decision="ALLOW",
                                  kind="EXEC", ts=1_786_000_001.0, command="pytest -q")
    record["sparta_intent"] = 0.99
    record["sparta_suspected"] = [{"field": "command", "type": "name"}]
    audit_log.append(fx.SESSION, record, root=root)
    said: list[str] = []
    from shipper import run
    shipper = run.Shipper(fx.settings(tmp_path, **ON), now=lambda: 1.0, log=said.append)
    shipper.tick()
    (shipped,) = collector.batches()[0]["records"]
    assert shipped["sparta_intent"] == 0.42
    assert "sparta_suspected" not in shipped


@pytest.mark.parametrize("flags,lines", [({}, 0), ({"sparta": "0"}, 0), (ON, 1)])
def test_the_banner_names_sparta_only_when_it_is_on(tmp_path, flags, lines):
    said: list[str] = []
    fx.make_shipper(tmp_path, said.append, **flags).announce_what_ships()
    assert said, "the banner was written"
    assert sum("parta" in line for line in said) == lines, said


def test_the_taint_flag_is_said_to_be_unbuilt_once(tmp_path, collector, fake):
    batch, said = _ship(tmp_path, collector, sparta="1", sparta_taint="1")
    lines = [line for line in said if "STING_SPARTA_TAINT" in line]
    assert len(lines) == 1 and "not built" in lines[0], said
    assert batch["records"][0]["sparta_intent"] == 0.42


# ═══════════════════════════════════════════════════ failing, it ships anyway

class _Raises:
    def detect(self, text):
        raise RuntimeError(f"broke on {text[:10]}")

    def intent(self, text):
        raise RuntimeError("broke")


class _Hangs:
    def __init__(self, release):
        self.release, self.calls = release, 0

    def detect(self, text):
        self.calls += 1
        self.release.wait(10)
        return []


class _Malformed:
    def detect(self, text):
        return [{"type": "name", "start": 0, "end": 4, "confidence": 0.9}, "Dana"]

    def intent(self, text):
        return 7.5


def _same_as_golden_and_said_once(batch, said, word):
    assert fx.shipped_part(batch) == _golden(), "deterministic masking, exactly as off"
    sparta_lines = [line for line in said if "Sparta" in line]
    assert len(sparta_lines) == 1 and word in sparta_lines[0], said


def test_a_detector_that_raises_never_stops_a_record(tmp_path, collector, monkeypatch):
    fx.install_factory(monkeypatch, _Raises)
    batch, said = _ship(tmp_path, collector, **ON)
    _same_as_golden_and_said_once(batch, said, "RuntimeError")


def test_a_detector_that_hangs_never_stops_a_record(tmp_path, collector, monkeypatch):
    import threading

    from shipper import sparta_enrich
    release = threading.Event()
    hangs = _Hangs(release)
    fx.install_factory(monkeypatch, lambda: hangs)
    monkeypatch.setattr(sparta_enrich, "CALL_SECONDS", 0.05)
    try:
        batch, said = _ship(tmp_path, collector, **ON)
    finally:
        release.set()
    _same_as_golden_and_said_once(batch, said, "within")
    assert hangs.calls == 1


def test_a_detector_that_answers_malformed_never_stops_a_record(tmp_path, collector,
                                                                monkeypatch):
    fx.install_factory(monkeypatch, _Malformed)
    batch, said = _ship(tmp_path, collector, **ON)
    assert fx.shipped_part(batch) == _golden()
    assert sum("Sparta" in line for line in said) == 2, said     # spans, and the score


def test_a_detector_that_cannot_be_loaded_never_stops_a_record(tmp_path, collector,
                                                               monkeypatch):
    from shipper import sparta_iface
    monkeypatch.setattr(sparta_iface, "DETECTOR_MODULE", "sting_no_such_sparta_module")
    batch, said = _ship(tmp_path, collector, **ON)
    _same_as_golden_and_said_once(batch, said, "could not be loaded")


def test_a_fault_in_the_enrichment_itself_never_stops_a_record(tmp_path, collector,
                                                               monkeypatch, fake):
    """⚠ FAIL-OPEN COVERS THIS MODULE TOO, not only the detector: a bug in
    the enrichment's own code ships the record as the flag-off masker would."""
    from shipper import sparta_enrich

    def broken(*a, **k):
        raise KeyError("a fault in the enrichment")
    monkeypatch.setattr(sparta_enrich, "_suspected", broken)
    batch, said = _ship(tmp_path, collector, **ON)
    _same_as_golden_and_said_once(batch, said, "KeyError")


def test_a_batch_says_it_can_carry_spartas_fields_only_when_it_does(tmp_path, collector,
                                                                    fake):
    """`can_leak` is the batch's own statement of what it can reveal; with
    the enrichment it carries two more things, and says so."""
    batch, _said = _ship(tmp_path, collector, **ON)
    added = [line for line in batch["provenance"]["can_leak"] if "sparta" in line]
    assert len(added) == 1 and "never the value" in added[0], added
    assert batch["provenance"]["can_leak"][:-1] == wire.can_leak()


def test_with_sparta_off_the_batch_states_what_it_always_did(tmp_path, collector):
    batch, _said = _ship(tmp_path, collector, sparta="0")
    assert batch["provenance"] == wire.provenance()


class _TooLarge:
    def post(self, url, token, payload, timeout=None):
        from shipper import client
        if b'"records"' not in payload:
            return client.Outcome(client.STORED, 200, {})
        return client.Outcome(client.TOO_LARGE, 413, {"error": "too large"},
                              detail="the collector's body cap")


def test_an_undeliverable_record_is_kept_as_it_would_have_shipped(tmp_path, monkeypatch,
                                                                  fake):
    from shipper import run
    monkeypatch.setattr(run.client, "post", _TooLarge().post)
    monkeypatch.setattr(run.client, "get", fx.FakeCollector.get)
    said: list[str] = []
    shipper = fx.make_shipper(tmp_path, said.append, **ON)
    for _ in range(4):
        shipper._last_flush = 0.0
        shipper.tick()
    kept = (tmp_path / "state" / "undeliverable.jsonl").read_text(encoding="utf-8")
    lines = [json.loads(line) for line in kept.splitlines()]
    assert len(lines) == 4, said
    for value in fx.FOUND_ONLY_BY_SPARTA:
        problem = fx.absent(value, kept, "undeliverable.jsonl")
        assert problem is None, problem
    assert all("sparta_intent" in line["record"] for line in lines[:3])


# ═══════════════════════════════════════════════════ verifying an export

def test_an_export_with_spartas_fields_still_matches_this_laptops_log(tmp_path,
                                                                      collector,
                                                                      monkeypatch, capsys):
    """A record nothing masked, carrying only `sparta_intent`: the verifier
    compares it with its local record, and Sparta's field was never local."""
    from shipper import sparta_iface
    from tools import verify_log
    scorer = sparta_iface.FakeSpartaDetector(intent_score=0.42)
    scorer.PATTERNS = ()
    fx.install_factory(monkeypatch, lambda: scorer)
    batch, _said = _ship(tmp_path, collector, **ON)
    plain = [r for r in batch["records"] if "masked" not in r and "sparta_intent" in r]
    assert plain, "a record carrying Sparta's field and no mask"
    export = tmp_path / "export" / f"{fx.SESSION}.log.jsonl"
    export.parent.mkdir()
    export.write_text("".join(json.dumps(r) + "\n" for r in batch["records"]),
                      encoding="utf-8")
    key = tmp_path / "home" / ".sting" / ".env.fingerprint"
    args = ["--export", str(export), "--key", str(key), "--local", str(tmp_path / "logs")]
    assert verify_log.main(args) == 0
    assert "4 of 4 shipped records match" in capsys.readouterr().out
    lines = export.read_text(encoding="utf-8").splitlines()
    at = next(i for i, r in enumerate(batch["records"]) if r is plain[0])
    edited = json.loads(lines[at])
    edited["command"] = edited["command"] + " # edited"
    lines[at] = json.dumps(edited)
    export.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_log.main(args) == 1, "the control: an edit beside it still shows"
