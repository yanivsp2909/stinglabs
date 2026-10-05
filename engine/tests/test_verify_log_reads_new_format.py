"""`tools/verify_log.py` reads a NEW-FORMAT record (docs/99) without a false alarm.

⚠ THE BUG. verify_log.py recomputed the LOCAL hash as "record minus prev/hash".
A shipped or exported record also carries `tier_chain`/`tier_prev`/`tier_hash`,
added after the hook hashed it, so every new-format record read BROKEN — at
`full` too — although nothing was edited. The collector's export_store.py
got the same fix (its PR #17); this mirrors it.

⚠ TWO VERDICTS, NEVER FOLDED (the collector's rule, and a review finding here).
The LOCAL chain stays authoritative for a record shipped whole: its hash is
recomputed with the three fields set aside on a record that carries them, and a
mismatch is BROKEN, as it always was. The TIER chain is checked beside it and
can only ADD a failure (tampered, or an unknown version) — it never excuses a
local mismatch on such a record. The first version let a verified tier chain
excuse one, and a forged, self-anchored tier chain then hid a real edit to a
local log: pinned below.

So a new-format record verifies wherever its local hash still covers the bytes
stored — `full`, unredacted. A reduced or redacted record's local hash cannot be
checked from an export, and there the tier chain decides: CONSISTENT, never
"verified" (tests/test_a_reduced_export_is_not_a_broken_chain.py has the rule).

Records here come from the REAL path: `audit_log.append` (the hook), then
the old reduction and Layer A (tests/legacy_wire.py: main's own code, frozen,
because nothing builds a tier since 28 Sep 2026 and an old export must still
read as before), and `wire.chain_at_tier`, written one
JSON line per record, as an export holds them.

⚠ AND THE MODE IS THE VERIFIER'S, NEVER THE FILE'S (docs/99). A shipped or
exported log is read that way only under `--export`, which the person verifying
passes. The default reads a LOCAL log, which never carries the three fields, so
a record carrying any of them is TAMPERED there — section 3 below. The cases in
sections 1-2 are exports, and keep their verdicts under `--export`.
"""
from __future__ import annotations

import json

import pytest

from core import audit_log, engine, wire
from tests import legacy_wire
from tools import verify_log

SESSION = "sess-verify-log"
DUMMY_SECRET_LINE = "TOKEN=F4keT0k3nQ7vX2mZp9LtR4wY\n"      # a dummy, never real
COMMANDS = ["pytest -q", "git status", "ls -la", "echo k=F4keT0k3nQ7vX2mZp9LtR4wY"]
TIER_FIELDS = ("tier_chain", "tier_prev", "tier_hash")


def local_log(root, monkeypatch):
    monkeypatch.setenv("STING_SESSION_ROOT", str(root))
    for i, command in enumerate(COMMANDS, start=1):
        audit_log.append(SESSION, audit_log.build_body(
            SESSION, seq=i, event="decision", decision="ALLOW", kind="EXEC",
            command=command, cwd="/work/repo", agent="claude-code",
            ts=1_786_000_000.0 + i, rule_id=None, reason="probe reason",
            evidence=f"@0 {command}"))
    return audit_log.default_log_path(SESSION, root)


def shipped(records, tier, *, redacted=False, split=None):
    """The records as the sender ships them: tiered, redacted, tier-chained,
    batch by batch (`split` = where the second batch starts)."""
    prints = engine.fingerprint_values(DUMMY_SECRET_LINE) if redacted else set()
    out, starts = [], [0] if split is None else [0, split]
    for n, begin in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(records)
        chunk = records[begin:end]
        start = audit_log.GENESIS if begin == 0 else records[begin - 1]["hash"]
        batch = legacy_wire.build_batch(chunk, device_id="dev", session_id=SESSION,
                                 tier=tier, continues_from=start)
        body = [legacy_wire.redact_record(r, prints) for r in batch["records"]]
        out += wire.chain_at_tier(body, start)
    return out


def export(tmp_path, records, *, derived=False):
    path = tmp_path / "export" / f"{SESSION}.log.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    if derived:
        (path.parent / audit_log.REDACTION_MANIFEST).write_text("{}")
    return path


def run(path, capsys, *flags):
    code = verify_log.main([*flags, str(path)])
    return code, capsys.readouterr().out


EXPORT = "--export"


@pytest.fixture
def records(tmp_path, monkeypatch):
    return audit_log.read_records(local_log(tmp_path / "sessions", monkeypatch))


def forged_from(records, first):
    """What an attacker with write access and the engine's public functions can
    add: a self-anchored tier chain on every record from `first` on."""
    out = list(records[:first])
    for record in records[first:]:
        marked = {**record, "tier_chain": wire.TIER_CHAIN_VERSION}
        out.append({**marked, "tier_prev": record["prev"],
                    "tier_hash": audit_log.record_hash(record["prev"], wire.tier_body(marked))})
    return out


# ═════════════════════════════════════════════════ the false alarm, closed


def test_a_new_format_full_export_verifies(tmp_path, records, capsys):
    code, out = run(export(tmp_path, shipped(records, wire.FULL)), capsys, EXPORT)
    assert code == 0, out
    assert "BROKEN" not in out
    assert "tier chain verified" in out


# ════════ where the local hash cannot cover what is stored: the tier chain decides
#
# These two read BROKEN, exit 1, through #68: the false alarm the next pass
# removed. Every other test here is unchanged.


def test_a_redacted_full_record_is_not_checkable_and_the_tier_chain_decides(
        tmp_path, records, capsys):
    code, out = run(export(tmp_path, shipped(records, wire.FULL, redacted=True)), capsys,
                    EXPORT)
    assert code == 0, out
    assert "CONSISTENT" in out and "local hash: not checkable at this tier" in out
    assert "BROKEN" not in out and "verified" not in out


def test_a_reduced_export_is_not_checkable_and_the_tier_chain_decides(
        tmp_path, records, capsys):
    code, out = run(export(tmp_path, shipped(records, wire.LOCATED, split=2)), capsys,
                    EXPORT)
    assert code == 0, out
    assert "CONSISTENT" in out and "local hash: not checkable at this tier" in out
    assert "BROKEN" not in out and "verified" not in out


# ═══════════════════════════════════════════════ old-format: exactly as before


def test_an_old_format_local_log_verifies_as_today(tmp_path, monkeypatch, capsys):
    code, out = run(local_log(tmp_path / "sessions", monkeypatch), capsys)
    assert code == 0, out
    assert "OK" in out


def test_an_edited_old_format_record_is_still_broken(tmp_path, records, capsys):
    edited = [dict(records[0], decision="DENY"), *records[1:]]
    code, out = run(export(tmp_path, edited), capsys)
    assert code == 1
    assert "BROKEN" in out


# ════════════════════════════════════════════════ real tampering stays BROKEN


def test_an_edited_new_format_full_record_is_broken(tmp_path, records, capsys):
    ship = shipped(records, wire.FULL)
    ship[2] = dict(ship[2], command="something else")
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "BROKEN" in out
    assert "tier chain" in out, "the tier verdict is printed beside the break"


def test_a_record_stripped_of_the_chain_after_it_began_is_broken(tmp_path, records, capsys):
    ship = shipped(records, wire.FULL, split=2)
    ship[3] = {k: v for k, v in ship[3].items() if k not in TIER_FIELDS}
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "BROKEN" in out
    assert "regression" in out, "a stripped chain is a regression, not history"


def test_an_edit_behind_a_forged_self_anchored_tier_chain_is_broken(tmp_path, records, capsys):
    """security-reviewer CRITICAL: the first version let a verified tier chain
    excuse a local mismatch, so an edited LOCAL log plus a forged tier chain
    read OK. The local hash is authoritative again."""
    edited = [records[0], dict(records[1], decision="DENY"), *records[2:]]
    forged = forged_from(edited, 1)
    assert wire.verify_tier_chain(forged)[0] == "verified", "precondition: the forgery holds"
    code, out = run(export(tmp_path, forged), capsys, EXPORT)
    assert code == 1
    assert "BROKEN" in out


def test_an_edit_behind_an_unknown_version_is_broken_not_merely_unverifiable(
        tmp_path, records, capsys):
    """security-reviewer HIGH: an unknown version skips the tier checks, so a
    content edit must still be called BROKEN by the local hash."""
    edited = [records[0], dict(records[1], decision="DENY"), *records[2:]]
    flipped = [*edited[:1], *({**r, "tier_chain": 2, "tier_prev": "x", "tier_hash": "y"}
                              for r in edited[1:])]
    code, out = run(export(tmp_path, flipped), capsys, EXPORT)
    assert code == 1
    assert "BROKEN" in out


# ════════════════════════════════════════════════ an unknown format is not clean


def test_an_unknown_version_on_intact_content_is_unverifiable(tmp_path, records, capsys):
    ship = [dict(r, tier_chain=2) for r in shipped(records, wire.FULL)]
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "UNVERIFIABLE" in out
    assert "BROKEN" not in out


def test_a_derived_log_with_an_unknown_version_is_unverifiable_not_broken(
        tmp_path, records, capsys):
    """python-reviewer MEDIUM: the derived branch handled only ok / broken."""
    ship = [dict(r, tier_chain=2) for r in shipped(records, wire.FULL)]
    code, out = run(export(tmp_path, ship, derived=True), capsys, EXPORT)
    assert code == 1
    assert "UNVERIFIABLE" in out
    assert "BROKEN" not in out


def test_verify_shipped_records_never_claims_a_tier_chain_it_did_not_see(records):
    """python-reviewer MEDIUM: an old-format list read "tier_hash chain verified"."""
    state, _bad, detail = wire.verify_shipped_records(records)
    assert state == "ok"
    assert "verified" not in detail


# ══════════════════════════ 3 · the mode is the verifier's, never the file's
#
# security review of 0200270: the shipped-records reading was chosen by the
# records themselves, and a local log never carries shipped-copy fields — the
# shipper adds them to the copy it ships. Whoever can edit the local log can
# add them. The reading is now chosen by `--export`, passed by the person
# verifying; nothing inside a file can choose it.

TAMPERED_REASON = "a local log never carries shipped-copy fields"


def test_a_genuine_local_log_verifies_exactly_as_before(tmp_path, monkeypatch, capsys):
    path = local_log(tmp_path / "sessions", monkeypatch)
    ok, _bad, detail = audit_log.verify_chain(path)
    code, out = run(path, capsys)
    assert ok and code == 0, out
    assert f"OK    {path}  ({detail})" in out, "the same line main prints"


def test_a_local_log_with_shipped_copy_fields_added_is_tampered(tmp_path, records, capsys):
    """Nothing edited, only the three fields added — main read it OK."""
    code, out = run(export(tmp_path, forged_from(records, 1)), capsys)
    assert code == 1
    assert "TAMPERED" in out and TAMPERED_REASON in out and EXPORT in out, out
    assert "OK " not in out


def test_an_edited_local_record_behind_added_tier_fields_is_tampered(tmp_path, records, capsys):
    """The security review's case: edit a record, leave prev/hash alone, add a
    self-anchored tier chain. In local mode it can never read clean."""
    edited = [records[0], dict(records[1], decision="DENY"), *records[2:]]
    forged = forged_from(edited, 1)
    assert wire.verify_tier_chain(forged)[0] == "verified", "precondition: the forgery holds"
    code, out = run(export(tmp_path, forged), capsys)
    assert code == 1
    assert "TAMPERED" in out and TAMPERED_REASON in out, out
    assert "record 2 " in out, "the first record carrying the fields is named"


def test_tampered_is_reported_under_quiet(tmp_path, records, capsys):
    """python review: `--quiet` hides only the plain OK line, never a finding."""
    code, out = run(export(tmp_path, forged_from(records, 1)), capsys, "--quiet")
    assert code == 1
    assert "TAMPERED" in out and TAMPERED_REASON in out, out


@pytest.mark.parametrize("field", TIER_FIELDS)
def test_one_shipped_copy_field_on_one_record_is_enough(tmp_path, records, capsys, field):
    marked = [*records[:2], dict(records[2], **{field: 1}), *records[3:]]
    code, out = run(export(tmp_path, marked), capsys)
    assert code == 1
    assert "TAMPERED" in out and "record 3 " in out, out


def test_an_export_verified_as_a_local_log_is_tampered_with_the_clear_reason(
        tmp_path, records, capsys):
    path = export(tmp_path, shipped(records, wire.FULL))
    code, out = run(path, capsys)
    assert code == 1
    assert "TAMPERED" in out and TAMPERED_REASON in out and EXPORT in out, out
    assert run(path, capsys, EXPORT)[0] == 0, "the same file, verified as an export"


def test_a_derived_local_log_with_shipped_copy_fields_is_tampered(tmp_path, records, capsys):
    code, out = run(export(tmp_path, forged_from(records, 0), derived=True), capsys)
    assert code == 1
    assert "TAMPERED" in out, out


def test_export_over_a_root_reads_the_collector_layout(tmp_path, records, capsys):
    """the collector's export writes `<out>/<org>/<device>/<session>.log.jsonl`
    and recommends `verify_log.py --root <out>`; that now needs `--export`."""
    where = tmp_path / "out" / "org" / "device"
    where.mkdir(parents=True)
    (where / f"{SESSION}.log.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in shipped(records, wire.FULL)))
    assert verify_log.main([EXPORT, "--root", str(tmp_path / "out")]) == 0
    assert "tier chain verified" in capsys.readouterr().out
    assert verify_log.main(["--root", str(tmp_path / "out")]) == 1
    assert "TAMPERED" in capsys.readouterr().out


def test_a_tampered_tier_hash_under_export_is_broken(tmp_path, records, capsys):
    ship = shipped(records, wire.FULL)
    ship[1] = dict(ship[1], tier_hash="0" * 64)
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1
    assert "BROKEN" in out and "tier chain: in the batch" in out, out


def test_an_old_format_log_under_export_reads_as_before(tmp_path, records, capsys):
    path = export(tmp_path, records)
    assert run(path, capsys, EXPORT)[0] == 0
    assert run(path, capsys)[0] == 0


@pytest.mark.parametrize("line", [[1, 2, 3], "x", 42], ids=["list", "string", "number"])
@pytest.mark.parametrize("flags", [(), (EXPORT,)], ids=["local", "export"])
def test_a_json_line_that_is_not_an_object_is_broken_not_a_crash(
        tmp_path, records, capsys, line, flags):
    """security-review LOW (pre-existing): valid JSON that is not an object
    reached `verify_records`, whose `.get` raised and ended the whole run —
    every other log in a `--root` scan went unchecked. It is a BROKEN file."""
    bad = export(tmp_path, [*records[:2], line, *records[2:]])
    good = tmp_path / "good" / f"{SESSION}.log.jsonl"
    good.parent.mkdir()
    good.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    code = verify_log.main([*flags, str(bad), str(good)])
    out = capsys.readouterr().out
    assert code == 1
    assert f"BROKEN {bad}" in out and "record 3 is not a JSON object" in out, out
    assert f"OK    {good}" in out, "the scan went on to the next log"


def test_the_install_preflight_chain_check_still_passes(capsys):
    """tools/preflight.py drives the REAL hook into a temporary root and checks
    that chain with `audit_log.verify_chain`, which this change leaves alone."""
    from tools import preflight
    preflight.check_end_to_end("claude-code")
    out = capsys.readouterr().out
    assert "[PASS] chain verifies" in out, out
