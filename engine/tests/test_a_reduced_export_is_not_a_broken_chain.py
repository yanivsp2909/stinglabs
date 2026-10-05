"""A reduced or redacted export is not a broken chain (`verify_log --export`).

⚠ THE ALARM THIS REMOVES. After #66/#68, `verify_log --export` read ANY local
mismatch as BROKEN, and BROKEN means "someone edited or deleted a record in
place". Below `full`, and on a record Layer A or B rewrote, the local hash covers
bytes that never shipped, so it cannot match, edited or not. A normal export at
the default tier (LOCATED) printed BROKEN and exited 1, while the collector's
export_store reads the same session as verified by its tier chain.

⚠ WHAT REPLACES IT, UNDER `--export` ONLY. A record shipped whole (`full`,
unredacted) keeps the strict local check. A record whose local hash cannot be
checked prints "local hash: not checkable at this tier", and the log's verdict
comes from the tier chain: it holds -> CONSISTENT, exit 0, with the caveat that
the file only agrees with itself; it fails -> TAMPERED, exit 1. An unknown
version stays UNVERIFIABLE. Never "verified": nothing in an unsigned export
proves it was not rewritten by someone who can edit it.

⚠ HOW A RECORD SAYS IT WAS REDUCED OR REDACTED: its own fields, the only witness
an export keeps. So an editor can relabel one. That is the limit rewriting the
chain already has, pinned in § 5 so it is never mistaken for a check.

Records come from the real path: `audit_log.append` (the hook), then the
reduction, Layer A and the tier chain, one JSON line per record, as an export
holds them. ⚠ SINCE 28 SEP 2026 NOTHING SHIPS A TIER: these are exports as the
sender before then built them (tests/legacy_wire.py, main's own code, frozen),
because an old export must still read and verify exactly as before. A masked
export is tests/test_every_record_ships_masked.py's.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core import audit_log, engine, wire
from shipper import redact
from tests import legacy_wire
from tools import verify_log
from private_fixtures import needs_live_fixture  # noqa: E402

ROOT = Path(__file__).parent.parent
SESSION = "sess-reduced-export"
DUMMY_SECRET_LINE = "TOKEN=F4keT0k3nQ7vX2mZp9LtR4wY\n"      # a dummy, never real
COMMANDS = ["pytest -q", "git status", "ls -la", "echo k=F4keT0k3nQ7vX2mZp9LtR4wY"]
TIER_FIELDS = ("tier_chain", "tier_prev", "tier_hash")
BELOW_FULL = (wire.VERDICT, wire.LOCATED, wire.REASONED)
EXPORT = "--export"

NOT_CHECKABLE = "local hash: not checkable at this tier"
CAVEAT = "consistent: this file agrees with itself; the collector's stored copy is the proof"


def local_log(root, monkeypatch, commands=COMMANDS):
    monkeypatch.setenv("STING_SESSION_ROOT", str(root))
    for i, command in enumerate(commands, start=1):
        audit_log.append(SESSION, audit_log.build_body(
            SESSION, seq=i, event="decision", decision="ALLOW", kind="EXEC",
            command=command, cwd="/work/repo", agent="claude-code",
            ts=1_786_000_000.0 + i, rule_id=None, reason="probe reason",
            evidence=f"@0 {command}"))
    return audit_log.default_log_path(SESSION, root)


def shipped(records, *batches, redacted=False):
    """The records as the sender ships them, batch by batch. Each batch is
    (index of its first record, tier, chained): tiered, then Layer A, then the
    tier chain, unless `chained` is False (an engine from before docs/99)."""
    prints = engine.fingerprint_values(DUMMY_SECRET_LINE) if redacted else set()
    out = []
    for n, (begin, tier, chained) in enumerate(batches):
        end = batches[n + 1][0] if n + 1 < len(batches) else len(records)
        start = audit_log.GENESIS if begin == 0 else records[begin - 1]["hash"]
        batch = legacy_wire.build_batch(records[begin:end], device_id="dev",
                                 session_id=SESSION, tier=tier, continues_from=start)
        body = [legacy_wire.redact_record(r, prints) for r in batch["records"]]
        out += wire.chain_at_tier(body, start) if chained else body
    return out


def at(tier, *, split=None, chained=True):
    """One tier throughout: one batch, or two with the second from `split`."""
    first = (0, tier, chained)
    return (first,) if split is None else (first, (split, tier, chained))


def export(tmp_path, records, name="export"):
    path = tmp_path / name / f"{SESSION}.log.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    return path


def run(path, capsys, *flags):
    code = verify_log.main([*flags, str(path)])
    return code, capsys.readouterr().out


def bare(ship):
    """The shipped records without the chain over what shipped."""
    return [{k: v for k, v in r.items() if k not in TIER_FIELDS} for r in ship]


@pytest.fixture
def records(tmp_path, monkeypatch):
    return audit_log.read_records(local_log(tmp_path / "sessions", monkeypatch))


def assert_consistent(code, out):
    assert code == 0, out
    assert "CONSISTENT" in out and NOT_CHECKABLE in out and CAVEAT in out, out
    assert "BROKEN" not in out and "TAMPERED" not in out, out
    assert "verified" not in out.lower(), "never 'verified' for a reduced export"


# ═════════════════════════════════════ § 1 · the false alarm, closed


@pytest.mark.parametrize("split", [None, 2], ids=["one-batch", "two-batches"])
@pytest.mark.parametrize("tier", BELOW_FULL)
def test_a_reduced_export_is_consistent_not_broken(tmp_path, records, capsys, tier, split):
    code, out = run(export(tmp_path, shipped(records, *at(tier, split=split))),
                    capsys, EXPORT)
    assert_consistent(code, out)
    assert "4 of 4 records" in out, out


def test_a_redacted_full_export_counts_only_the_redacted_record(tmp_path, records, capsys):
    """Layer A rewrote record 4 only: records 1-3 are checked strictly and hold."""
    code, out = run(export(tmp_path, shipped(records, *at(wire.FULL), redacted=True)),
                    capsys, EXPORT)
    assert_consistent(code, out)
    assert "1 of 4 records" in out, out


def test_a_redacted_reduced_export_is_consistent(tmp_path, monkeypatch, capsys):
    """⚠ BUILT ON `granted_by`. Below `full` the reason is the rule's own words
    and the span travels at `full` only (tests/test_nothing_below_full_quotes_
    the_command.py), so the one reduced field Layer A can still rewrite is who
    approved an override. The value there is the dummy, as in COMMANDS."""
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path / "sessions"))
    for i, command in enumerate(COMMANDS, start=1):
        audit_log.append(SESSION, audit_log.build_body(
            SESSION, seq=i, event="decision", decision="ALLOW", kind="EXEC",
            command=command, cwd="/work/repo", agent="claude-code",
            ts=1_786_000_000.0 + i, rule_id=None, reason="probe reason",
            evidence=f"@0 {command}",
            granted_by="F4keT0k3nQ7vX2mZp9LtR4wY" if i == len(COMMANDS) else None))
    records = audit_log.read_records(
        audit_log.default_log_path(SESSION, tmp_path / "sessions"))
    ship = shipped(records, *at(wire.REASONED), redacted=True)
    assert redact.SECRET_MARK in json.dumps(ship), "precondition: Layer A rewrote one"
    assert_consistent(*run(export(tmp_path, ship), capsys, EXPORT))


def test_a_reduced_export_over_a_root_exits_zero_and_never_says_verified(
        tmp_path, records, capsys):
    """the collector's layout, `<out>/<org>/<device>/<session>.log.jsonl`."""
    where = tmp_path / "out" / "org" / "device"
    where.mkdir(parents=True)
    (where / f"{SESSION}.log.jsonl").write_text("".join(
        json.dumps(r, sort_keys=True) + "\n" for r in shipped(records, *at(wire.LOCATED))))
    code = verify_log.main([EXPORT, "--root", str(tmp_path / "out")])
    out = capsys.readouterr().out
    assert_consistent(code, out)
    summary = out.strip().splitlines()[-1]
    assert "CONSISTENT" in summary and "collector's stored copy" in summary, summary


def test_a_full_export_holding_a_typed_mark_still_reads_verified(
        tmp_path, monkeypatch, capsys):
    """python review: the wording followed any record that LOOKED redacted, so a
    full export whose every local hash holds read 'tier chain consistent'. Every
    hash held, so every stored byte is covered: that is verified."""
    commands = [*COMMANDS[:3], f"echo {redact.SECRET_MARK}"]
    records = audit_log.read_records(local_log(tmp_path / "sessions", monkeypatch, commands))
    code, out = run(export(tmp_path, shipped(records, *at(wire.FULL))), capsys, EXPORT)
    assert code == 0, out
    assert "tier chain verified" in out and "CONSISTENT" not in out, out


def test_a_derived_reduced_export_is_consistent_and_never_verified(
        tmp_path, records, capsys):
    """A redaction manifest beside it (a published fixture). Still CONSISTENT, and
    the closing line may not fall back to the derived one, which counts
    'recorded log(s) verified'."""
    path = export(tmp_path, shipped(records, *at(wire.LOCATED)))
    (path.parent / audit_log.REDACTION_MANIFEST).write_text("{}")
    code, out = run(path, capsys, EXPORT)
    assert_consistent(code, out)
    assert "(derived)" in out, out


def test_quiet_still_prints_the_caveat(tmp_path, records, capsys):
    """`--quiet` hides the plain OK line. CONSISTENT is not an OK: its caveat is
    the finding, so it prints, as REDACTED does for a derived log."""
    code, out = run(export(tmp_path, shipped(records, *at(wire.LOCATED))), capsys,
                    EXPORT, "--quiet")
    assert_consistent(code, out)


# ═══════════════════════ § 2 · a record shipped whole keeps the strict check


def test_an_edited_full_record_beside_a_redacted_one_is_broken(tmp_path, records, capsys):
    ship = shipped(records, *at(wire.FULL), redacted=True)
    ship[1] = dict(ship[1], decision="DENY")
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "BROKEN" in out and "record 2 content does not match its hash" in out, out
    assert "CONSISTENT" not in out


def test_an_edited_full_batch_beside_a_reduced_batch_is_broken(tmp_path, records, capsys):
    """The tier changed mid-session: batch 1 at `full`, batch 2 at LOCATED. The
    strict check is per record, never per log."""
    ship = shipped(records, (0, wire.FULL, True), (2, wire.LOCATED, True))
    ship[0] = dict(ship[0], command="something else")
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "BROKEN" in out and "record 1 content does not match its hash" in out, out


def test_a_record_deleted_from_a_reduced_export_is_broken_and_never_verified(
        tmp_path, records, capsys):
    """The local LINKS survive every tier, so a deletion is still a break. Deleting
    the last record of batch 1 leaves every tier chain intact, since batch 2
    anchors on its own `prev`, and the verdict must still not say 'verified'."""
    ship = shipped(records, *at(wire.LOCATED, split=2))
    del ship[1]
    assert wire.verify_tier_chain(ship)[0] == "verified", "precondition"
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "BROKEN" in out and "record 2 chains from" in out, out
    assert "verified" not in out.lower(), out


# ═════════════ § 3 · the tier chain decides, and when it fails that is TAMPERED


def _tampered(code, out):
    assert code == 1, out
    assert "TAMPERED" in out and NOT_CHECKABLE in out and "tier chain:" in out, out
    assert "BROKEN" not in out and "CONSISTENT" not in out, out


def test_an_edited_reduced_record_is_tampered(tmp_path, records, capsys):
    ship = shipped(records, *at(wire.LOCATED))
    ship[2] = dict(ship[2], decision="DENY")
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    _tampered(code, out)
    assert "record 3 content does not match its tier_hash" in out, out


def test_a_forged_tier_hash_on_a_reduced_export_is_tampered(tmp_path, records, capsys):
    ship = shipped(records, *at(wire.VERDICT))
    ship[1] = dict(ship[1], tier_hash="0" * 64)
    _tampered(*run(export(tmp_path, ship), capsys, EXPORT))


def test_a_broken_tier_link_on_a_reduced_export_is_tampered(tmp_path, records, capsys):
    ship = shipped(records, *at(wire.REASONED))
    ship[3] = dict(ship[3], tier_prev="b" * 64)
    _tampered(*run(export(tmp_path, ship), capsys, EXPORT))


def test_a_tier_chain_stripped_after_it_began_is_tampered(tmp_path, records, capsys):
    ship = shipped(records, *at(wire.LOCATED, split=2))
    ship[3] = bare([ship[3]])[0]
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    _tampered(code, out)
    assert "regression" in out, out


# ═══════ § 4 · what nothing here can check is UNVERIFIABLE: never BROKEN, never clean


def test_an_unknown_version_on_a_reduced_export_stays_unverifiable(tmp_path, records, capsys):
    ship = [dict(r, tier_chain=2) for r in shipped(records, *at(wire.LOCATED))]
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "UNVERIFIABLE" in out and NOT_CHECKABLE in out, out
    assert "BROKEN" not in out and "CONSISTENT" not in out, out


def test_an_old_format_reduced_export_is_chain_missing_not_broken(tmp_path, records, capsys):
    """Shipped before docs/99: no tier chain exists to decide it, and its local
    hash cannot be checked. Not tampering, and not clean: the chain is ABSENT,
    which #69 printed as UNVERIFIABLE (tests/test_an_absent_tier_chain_reads_
    chain_missing.py has the rename)."""
    ship = shipped(records, *at(wire.LOCATED, chained=False))
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "CHAIN MISSING" in out and NOT_CHECKABLE in out, out
    assert "BROKEN" not in out and "CONSISTENT" not in out, out


def test_old_format_history_is_not_covered_by_a_later_tier_chain(tmp_path, records, capsys):
    """The engine was upgraded mid-session: the chain covers only records from
    the first one carrying it, so the reduced records before it stay unchecked."""
    ship = shipped(records, (0, wire.LOCATED, False), (2, wire.LOCATED, True))
    assert wire.verify_tier_chain(ship)[0] == "verified", "precondition"
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "UNVERIFIABLE" in out and "2 of them carry no tier chain" in out, out
    assert "CONSISTENT" not in out


# ════════════════════════════════════ § 5 · the classification, and its limit


@needs_live_fixture
def test_every_real_record_carries_a_field_no_reduced_tier_ships():
    """The hook writes `command`, `paths`, `url` and `action_hash` into every
    record, null or not, and no tier below `full` ships them. So a genuine record
    is classified exactly: this is what keeps `full` strict."""
    fixture = sorted((ROOT / "logs" / "live-fixture").glob("*.log.jsonl"))
    real = [r for log in fixture for r in audit_log.read_records(log)]
    assert len(real) > 1000, f"only {len(real)} records: the check would be vacuous"
    assert not [r for r in real if wire.shipped_below_full(r)]


def test_each_tier_below_full_reads_below_full_and_full_does_not(records):
    for record in records:
        assert not wire.shipped_below_full(legacy_wire.tier_record(record, wire.FULL))
        for tier in BELOW_FULL:
            reduced = legacy_wire.tier_record(record, tier)
            assert wire.shipped_below_full(reduced), tier
            chained = wire.chain_at_tier([reduced], record["prev"])[0]
            assert wire.shipped_below_full(chained), f"{tier}, tier-chained"


def test_a_layer_a_or_layer_b_mark_is_recognised(records):
    prints = engine.fingerprint_values(DUMMY_SECRET_LINE)
    secret = legacy_wire.redact_secrets(records[3], prints)
    assert redact.carries_a_mark(secret) and not redact.carries_a_mark(records[3])
    assert redact.carries_a_mark(dict(records[0], paths=[f"/x/{redact.PII_MARK}"]))
    assert redact.carries_a_mark(dict(records[0], reason=f"by {redact.PII_MARK}"))
    assert not redact.carries_a_mark(dict(records[0], rule_id=redact.SECRET_MARK)), (
        "only a field redaction rewrites can carry its mark")


def test_the_docstring_says_an_editor_could_relabel_one():
    doc = " ".join(verify_log.__doc__.split())
    assert "relabel" in doc and "same limit" in doc, (
        "the classification comes from fields in the file; say so where it is used")


def test_a_relabelled_full_record_reads_consistent_never_verified(tmp_path, records, capsys):
    """⚠ THE STATED LIMIT, PINNED SO IT IS NEVER MISTAKEN FOR A CHECK. Edit a full
    record, reduce it to LOCATED's fields and re-chain its batch: the export now
    agrees with itself. Rewriting and re-hashing both chains always got the same
    exit 0; this is one more rewrite of that kind. What the tool may say is only
    CONSISTENT, and that the collector's stored copy is the proof."""
    records_out = bare(shipped(records, *at(wire.FULL)))
    records_out[1] = legacy_wire.tier_record(dict(records_out[1], decision="DENY"),
                                             wire.LOCATED)
    forged = wire.chain_at_tier(records_out, audit_log.GENESIS)
    code, out = run(export(tmp_path, forged), capsys, EXPORT)
    assert_consistent(code, out)
    assert "1 of 4 records" in out, out


# ═════════════════════════════════ § 6 · the default (LOCAL) mode is unchanged

TAMPERED_REASON = "a local log never carries shipped-copy fields"


def test_a_reduced_export_read_as_local_is_still_tampered(tmp_path, records, capsys):
    code, out = run(export(tmp_path, shipped(records, *at(wire.LOCATED))), capsys)
    assert code == 1
    assert "TAMPERED" in out and TAMPERED_REASON in out and EXPORT in out, out
    assert "CONSISTENT" not in out


def test_a_local_record_stripped_to_look_reduced_is_still_broken_locally(
        tmp_path, records, capsys):
    """The classification never runs in the default mode: a local log is held to
    every hash, whatever a record looks like."""
    stripped = [records[0], legacy_wire.tier_record(records[1], wire.VERDICT),
                *records[2:]]
    code, out = run(export(tmp_path, stripped), capsys)
    assert code == 1
    assert "BROKEN" in out and "record 2 content does not match its hash" in out, out


def test_a_local_log_holding_a_mark_reads_exactly_as_before_in_both_modes(
        tmp_path, monkeypatch, capsys):
    """A developer can type a mark's text. The log still verifies, in either mode,
    on the line main prints."""
    commands = [*COMMANDS[:3], f"echo {redact.SECRET_MARK}"]
    path = local_log(tmp_path / "sessions", monkeypatch, commands)
    ok, _bad, detail = audit_log.verify_chain(path)
    assert ok, "precondition"
    for flags in ((), (EXPORT,)):
        code, out = run(path, capsys, *flags)
        assert code == 0, (flags, out)
        assert f"OK    {path}  ({detail})" in out, (flags, out)
