"""An export below full with NO tier chain reads CHAIN MISSING (`verify_log --export`).

⚠ THE ONE CASE RENAMED. A reduced or redacted record's local hash cannot be
checked from an export, and its verdict comes from the tier chain (#69). When no
record carries a tier chain at all, #69 printed UNVERIFIABLE. The chain is not
broken, and its format is not unknown: it is ABSENT. An export from before the
chain existed, or one someone stripped; the file cannot tell which, so neither is
claimed. Exit 1, unchanged.

Every other case that prints UNVERIFIABLE keeps it: an unknown `tier_chain`
version, and unchecked records that predate a tier chain beginning later in the
same log (that chain does check the records after it, so "nothing here can be
checked" would be false). The default (LOCAL) mode is untouched.
"""
from __future__ import annotations

import pytest

from core import audit_log, wire
from tests.test_a_reduced_export_is_not_a_broken_chain import (  # noqa: F401
    EXPORT, at, export, records, run, shipped)                    # records: fixture

LINE = ("CHAIN MISSING: exported below full with no tier chain, "
        "nothing here can be checked")


def assert_chain_missing(code, out):
    assert code == 1, out
    assert "CHAIN MISSING " in out and LINE in out, out
    assert "UNVERIFIABLE" not in out and "BROKEN" not in out, out
    assert "CONSISTENT" not in out and "verified" not in out.lower(), out


@pytest.mark.parametrize("tier", [wire.VERDICT, wire.LOCATED, wire.REASONED])
def test_a_reduced_export_with_no_tier_chain_is_chain_missing(tmp_path, records, capsys, tier):
    code, out = run(export(tmp_path, shipped(records, *at(tier, chained=False))),
                    capsys, EXPORT)
    assert_chain_missing(code, out)
    assert "4 of 4 records" in out, out
    summary = out.strip().splitlines()[-1]
    assert summary.startswith("1 CHAIN MISSING"), summary


def test_a_redacted_full_export_with_no_tier_chain_is_chain_missing(tmp_path, records, capsys):
    ship = shipped(records, *at(wire.FULL, chained=False), redacted=True)
    assert_chain_missing(*run(export(tmp_path, ship), capsys, EXPORT))


def test_a_derived_export_with_no_tier_chain_is_chain_missing(tmp_path, records, capsys):
    path = export(tmp_path, shipped(records, *at(wire.LOCATED, chained=False)))
    (path.parent / audit_log.REDACTION_MANIFEST).write_text("{}")
    code, out = run(path, capsys, EXPORT)
    assert_chain_missing(code, out)
    assert "(derived)" in out, out


# ═══════════════════════════════════ every other UNVERIFIABLE case keeps its name


def test_an_unknown_version_stays_unverifiable(tmp_path, records, capsys):
    for tier in (wire.FULL, wire.LOCATED):
        ship = [dict(r, tier_chain=2) for r in shipped(records, *at(tier))]
        code, out = run(export(tmp_path, ship, name=tier), capsys, EXPORT)
        assert code == 1, out
        assert "UNVERIFIABLE" in out and "CHAIN MISSING" not in out, (tier, out)


def test_history_before_a_tier_chain_stays_unverifiable(tmp_path, records, capsys):
    """The chain exists and checks records 3-4; only 1-2 predate it."""
    ship = shipped(records, (0, wire.LOCATED, False), (2, wire.LOCATED, True))
    code, out = run(export(tmp_path, ship), capsys, EXPORT)
    assert code == 1, out
    assert "UNVERIFIABLE" in out and "CHAIN MISSING" not in out, out


# ═════════════════════════════════════════════ the default mode is untouched


def test_local_mode_never_says_chain_missing(tmp_path, records, capsys):
    """Read as a LOCAL log, an old-format reduced export is held to every hash,
    exactly as before: BROKEN at the first record that cannot match."""
    code, out = run(export(tmp_path, shipped(records, *at(wire.LOCATED, chained=False))),
                    capsys)
    assert code == 1, out
    assert "BROKEN" in out and "CHAIN MISSING" not in out, out
