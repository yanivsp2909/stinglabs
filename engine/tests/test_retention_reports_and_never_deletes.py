"""Retention: a measurement, and the reason truncation is ruled out.

⚠ THE STOP CONDITION THIS PASS WAS GIVEN, ANSWERED BY MEASUREMENT. "If retention
cannot be done without making a truncated log indistinguishable from a tampered
one, stop and report that." It can — by never truncating. Whole-session deletion
leaves nothing dangling, because the chain is PER SESSION. Trimming records out
of a log does not, and the tests below pin both halves so a later convenience
cannot quietly reintroduce the unsafe one.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import audit_log                                       # noqa: E402
from tools import retention                                      # noqa: E402


@pytest.fixture
def log(tmp_path, monkeypatch):
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    for seq in range(1, 9):
        audit_log.append("s1", audit_log.build_body(
            "s1", seq=seq, event="decision", decision="ALLOW", kind="EXEC",
            command=f"pytest -q # {seq}", ts=1_700_000_000.0 + seq), root=tmp_path)
    return tmp_path / "s1.log.jsonl"


def verify(path: Path) -> str:
    out = subprocess.run([sys.executable, "tools/verify_log.py", str(path)],
                          cwd=str(ROOT), capture_output=True, text=True).stdout
    return out


# ---------------------------------------------- 1 · why truncation is refused

def test_removing_the_head_of_a_log_reads_as_BROKEN(log):
    """⚠ AND THAT IS THE SAME THING AN ATTACKER REMOVING EARLY EVIDENCE
    PRODUCES. Deleting the first records of a log is exactly how you would hide
    an early `.env` read. A retention policy that did it routinely would turn
    that signature into housekeeping noise, and the first BROKEN a developer
    learns to ignore is the last one that means anything."""
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lines[3:]) + "\n", encoding="utf-8")
    out = verify(log)
    assert "BROKEN" in out
    assert "expected '0000" in out, (
        "the head-truncation signature is 'chains from X, expected GENESIS'")


def test_removing_the_tail_of_a_log_reads_as_PERFECTLY_FINE(log):
    """The other direction, and it is worse: a log missing everything after
    some point verifies cleanly, and nothing local can say so."""
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lines[:4]) + "\n", encoding="utf-8")
    assert "OK" in verify(log) and "chain intact" in verify(log)


def test_editing_one_record_also_reads_as_BROKEN(log):
    """The comparison that matters: tampering and head-truncation both say
    BROKEN. They differ in the DETAIL line, not in the verdict."""
    lines = log.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[3])
    edited["command"] = "rm -rf /"
    lines[3] = json.dumps(edited, sort_keys=True)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = verify(log)
    assert "BROKEN" in out
    assert "does not match its hash" in out


def test_deleting_a_WHOLE_session_leaves_nothing_dangling(log, tmp_path):
    """⚠ THE ONE SAFE GRANULARITY. The chain is per session, so a removed file
    leaves no record whose `prev` points at anything missing. It is absent, and
    absence of a session is a different artifact from truncation of one."""
    for seq in range(1, 4):
        audit_log.append("s2", audit_log.build_body(
            "s2", seq=seq, event="decision", decision="ALLOW", ts=1.0 + seq),
            root=tmp_path)
    log.unlink()
    survivor = tmp_path / "s2.log.jsonl"
    assert "OK" in verify(survivor) and "chain intact" in verify(survivor)

    from runner import replay_live
    assert set(replay_live.load_records(tmp_path)) == {"s2"}


# ------------------------------------------------- 2 · the tool only reports

def test_the_tool_deletes_nothing(log, tmp_path, capsys):
    """⚠ A CODEBASE WHOSE SUBJECT IS IRREVERSIBLE ACTIONS MUST NOT PERFORM ONE
    SILENTLY. The guard prompts a human before `rm -rf`; a cleanup that decided
    on its own to remove a developer's command history would be doing the thing
    the guard exists to interrupt."""
    before = sorted(p.name for p in tmp_path.iterdir())
    retention.main(["--root", str(tmp_path), "--days", "0"])
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert "DELETES NOTHING" in capsys.readouterr().out


def test_it_has_no_delete_flag_and_no_unlink_at_all():
    """Asserted on the source, so adding one is a decision somebody makes in a
    review rather than a convenience that slips in."""
    source = (ROOT / "tools" / "retention.py").read_text(encoding="utf-8")
    assert "--delete" not in source
    assert ".unlink(" not in source and "shutil.rmtree" not in source
    assert "os.remove" not in source


def test_sidecars_are_counted_because_they_are_easy_to_forget(log, tmp_path):
    """They hold the UNCLIPPED command text — the part a disclosure question is
    actually about — and they live beside the log rather than in it."""
    sidecar = tmp_path / "s1.log.jsonl.commands"
    sidecar.mkdir()
    (sidecar / "abc").write_text("x" * 4096, encoding="utf-8")
    row = next(r for r in retention.survey(tmp_path) if r["session"] == "s1")
    assert row["sidecar_bytes"] >= 4096


# --------------------------------- 3 · "shipped" is unknowable without a collector

def test_with_no_collector_shipped_is_not_reported_as_a_fact(log, tmp_path,
                                                              monkeypatch,
                                                              capsys):
    """⚠ THE CURSOR ONLY ADVANCES WHEN A COLLECTOR CONFIRMS A BATCH. On an
    install that never had one, every record is unshipped forever — so "delete
    what has shipped" removes nothing and "delete what is old" removes the only
    copy that exists. That install is supported and must not lose data."""
    monkeypatch.setattr(retention, "collector_configured", lambda: False)
    retention.main(["--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert "NO COLLECTOR IS CONFIGURED" in out
    assert "only copy that exists" in out
    assert "n/a" in out, "shipped must not be printed as a number nobody can trust"


def test_unstored_records_are_flagged_when_a_policy_would_reach_them(
        log, tmp_path, monkeypatch, capsys):
    """The collector acknowledged 2 of the 8. `shipped` is deliberately absent
    from the entry: the loop's position is not evidence, and this tool no
    longer reads it (B3, docs/77)."""
    monkeypatch.setattr(retention, "collector_configured", lambda: True)
    monkeypatch.setattr(retention, "cursor_positions",
                        lambda: ({"s1": {"acked_seq": 2, "gaps": 0,
                                          "skipped_seqs": []}}, None))
    retention.main(["--root", str(tmp_path), "--days", "0"])
    out = capsys.readouterr().out
    assert "6 RECORDS THE COLLECTOR NEVER STORED" in out
    assert "destroys" in out
