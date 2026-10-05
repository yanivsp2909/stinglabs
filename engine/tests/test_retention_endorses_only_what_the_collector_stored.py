"""⚠ "SHIPPED" IS NOT "STORED", AND THE REPORT A HUMAN DELETES FROM MUST KNOW.

`tools/retention.py` deletes nothing; a human reads its `shipped` column and
its `--days` warning and runs `rm` on whole sessions. Until this file, that
column was computed from the cursor's `shipped` — how far the SHIPPER'S LOOP has
moved on — and its docstring called that "a COUNT of records the collector
CONFIRMED it stored". `shipper/cursor.py` says the opposite in capitals: the
loop steps `shipped` over a record the collector refused (`_split`), a 202
advances it past batches the collector is MISSING, and only a 200/202 carrying
the collector's own `records_stored` moves `acked_seq`. The deleter,
`tools/prune_shipped.py`, was moved onto that receipt in B2. The report was not.

So retention printed `all` — and suppressed its NEVER SHIPPED warning — for a
session whose records the collector had never acknowledged: sent past acked,
nothing between them stored anywhere, and the tool endorsing the `rm`.

B3 of the v1.0.3 audit. Reproduced, not asserted: with 8 records sent and the
collector acknowledging through seq 5, the old column said `all`, the old
`--days 0` report carried no warning, and `prune_shipped._walk` on the same
cursor entry said 5 deletable, "seq 6 is past the acknowledged mark (5)".

The fix reads ONE predicate for both tools — `prune_shipped.stored_prefix()`,
the collector-evidence walk the deleter already used — so the report cannot
disagree with the deleter again. Every test below fails toward KEEPING: a
record the collector has not provably stored is reported as NOT STORED, with
the reason, and a cursor that cannot be read says so instead of saying `all`.
"""
from __future__ import annotations

import json
import time

import pytest

from core.audit_log import append, build_body, read_records
from tools import prune_shipped, retention

N = 8
NEVER = "NEVER STORED"          # the per-session warning in the --days report
LOUD = "NOT PROVABLY STORED"    # the block under it


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A real 8-record chain, a shipper state dir, and a configured collector —
    the state in which retention shows the column at all."""
    root = tmp_path / "sessions"
    state = tmp_path / "shipper"
    root.mkdir(); state.mkdir()
    monkeypatch.setenv("STING_SESSION_ROOT", str(root))
    monkeypatch.setenv("STING_SHIPPER_STATE", str(state))
    monkeypatch.setenv("STING_COLLECTOR_URL", "https://collector.invalid")
    old = time.time() - 30 * 86400
    for seq in range(1, N + 1):
        append("s1", build_body("s1", seq=seq, event="decision", decision="allow",
                                command=f"git status {seq}", ts=old + seq), root=root)
    return root, state


def cursor(state, **kw) -> dict:
    """The shipper's cursor entry for s1: everything sent AND acknowledged
    unless a keyword says otherwise. `shipped` is always N — the loop has
    always moved on; the question is what the collector said."""
    pos = {"shipped": N, "acked_seq": N, "acked_records": N, "gaps": 0,
           "skipped_seqs": [], "last_batch_ref": "batches/abc123",
           "acked_at": time.time()}
    pos.update(kw)
    (state / "cursor.json").write_text(json.dumps({"sessions": {"s1": pos}}),
                                       encoding="utf-8")
    return pos


def report(root, capsys) -> str:
    retention.main(["--root", str(root), "--days", "0"])
    return capsys.readouterr().out


def column(out: str) -> str:
    """The `stored` cell of s1's row. The cells are fixed-width and the size
    cell is two tokens ("3.2 KB"), so split on the two-space separator that
    precedes the last cell, never on whitespace."""
    line = next(l for l in out.splitlines() if l.strip().startswith("s1 "))
    return line.rstrip().rsplit("  ", 1)[-1].strip()


def row(root) -> dict:
    (r,) = retention.survey(root)
    return r


# ═══════════════════════════════════════════ 1 · the reproduction, pinned

def test_a_record_the_collector_never_acked_is_no_longer_endorsed(world, capsys):
    """⚠ THE BUG. Sent 8, acknowledged through 5. The old report said `all`
    and warned about nothing; the deleter, on the same cursor, stops at 5."""
    root, state = world
    pos = cursor(state, acked_seq=5, acked_records=5)

    r = row(root)
    out = report(root, capsys)

    assert r["stored"] == 5 and r["unstored"] == 3
    assert "past the acknowledged mark (5)" in r["why"]
    assert column(out).startswith("3 NOT STORED")
    assert NEVER in out and LOUD in out
    # and it is the deleter's own answer, not a second opinion
    assert prune_shipped._walk(read_records(root / "s1.log.jsonl"), pos,
                               keep_before=float("inf"))[0] == 5


# ═══════════════════════════════════════════ 2 · positive control

def test_a_session_the_collector_acked_in_full_is_still_endorsed(world, capsys):
    """⚠ THE GATE MUST NOT DEGRADE TO NEVER-DELETE. Every record acknowledged,
    no gap, nothing skipped: `all`, and no warning anywhere."""
    root, state = world
    cursor(state)

    r = row(root)
    out = report(root, capsys)

    assert r["stored"] == N and r["unstored"] == 0
    assert column(out) == "all"
    assert NEVER not in out and LOUD not in out


# ═══════════════════════════════════════════ 3 · the boundary

@pytest.mark.parametrize("acked, stored", [(N - 1, N - 1), (N, N)])
def test_the_acknowledged_mark_is_inclusive_and_one_past_it_is_not(world, acked, stored):
    """`acked_seq` is the HIGHEST seq inside a batch the collector stored, so
    seq == acked_seq is stored and seq == acked_seq + 1 is not. Off by one
    here is one record the collector never had, endorsed for deletion."""
    root, state = world
    cursor(state, acked_seq=acked, acked_records=acked)

    r = row(root)

    assert r["stored"] == stored
    assert r["unstored"] == N - stored
    if stored < N:
        assert f"seq {N} is past the acknowledged mark ({acked})" in r["why"]


# ═══════════════════════════════════════════ 4 · missing / unreadable watermark

def test_a_session_the_collector_never_acknowledged_stores_nothing_and_says_so(world, capsys):
    root, state = world
    cursor(state, acked_seq=None, acked_records=0)

    r = row(root)
    out = report(root, capsys)

    assert r["stored"] == 0 and r["unstored"] == N
    assert "never acknowledged" in r["why"]
    assert column(out).startswith(f"{N} NOT STORED")
    assert NEVER in out and "never acknowledged" in out


def test_no_cursor_at_all_endorses_nothing_and_names_the_missing_file(world, capsys):
    """⚠ FAIL TOWARD KEEPING, OUT LOUD. The absence of the shipper's cursor is
    not `0 unshipped`; it is `nothing here is provably stored`, said once with
    the path it looked at, so a human does not read silence as safety."""
    root, state = world
    assert not (state / "cursor.json").exists()

    r = row(root)
    out = report(root, capsys)

    assert r["stored"] is None and r["unstored"] == N
    assert column(out) == "never seen"
    assert "NO SHIPPER CURSOR" in out and str(state) in out
    assert NEVER in out


def test_a_corrupt_cursor_is_the_same_as_no_cursor(world, capsys):
    root, state = world
    (state / "cursor.json").write_text("{not json", encoding="utf-8")

    out = report(root, capsys)

    assert column(out) == "never seen"
    assert "NO SHIPPER CURSOR" in out and NEVER in out


# ═══════════════════════════════════════════ 5 · the audit's two families

def test_a_split_skipped_record_is_not_stored_even_below_the_mark(world, capsys):
    """The record `_split` stepped over is BELOW `acked_seq` once later batches
    land. Only `skipped_seqs` knows it is stored nowhere; the report must stop
    there exactly as the deleter does."""
    root, state = world
    cursor(state, acked_records=N - 1, skipped_seqs=[6])

    r = row(root)
    out = report(root, capsys)

    assert r["stored"] == 5 and r["unstored"] == 3
    assert "seq 6" in r["why"] and "NOWHERE" in r["why"]
    assert column(out).startswith("3 NOT STORED")
    assert NEVER in out


def test_a_reported_gap_means_nothing_below_the_mark_is_stored(world, capsys):
    """The "37 batches never arrived" family: the collector said 202, the loop
    moved on, and the records below the mark are the ones it is missing."""
    root, state = world
    cursor(state, gaps=37)

    r = row(root)
    out = report(root, capsys)

    assert r["stored"] == 0 and "37 gap(s)" in r["why"]
    assert column(out).startswith(f"{N} NOT STORED")
    assert NEVER in out


# ═══════════════════════════════════════════ 6 · one predicate, two tools

@pytest.mark.parametrize("kw", [
    {}, {"acked_seq": 5, "acked_records": 5}, {"acked_seq": None},
    {"skipped_seqs": [3]}, {"gaps": 1}, {"acked_seq": N - 1},
])
def test_the_report_and_the_deleter_read_the_same_predicate(world, kw):
    """`retention.survey` must never grow its own idea of "stored" again."""
    root, state = world
    pos = cursor(state, **kw)
    records = read_records(root / "s1.log.jsonl")

    expected, why = prune_shipped.stored_prefix(records, pos)

    assert row(root)["stored"] == expected
    assert row(root)["why"] == why


def test_the_deleter_itself_is_unchanged_by_the_extraction(world):
    """`_walk` = stored_prefix + the keep window + the final-record anchor.
    Pinned here on the shapes the prune tests do not parametrise."""
    root, state = world
    records = read_records(root / "s1.log.jsonl")
    pos = cursor(state)

    assert prune_shipped._walk(records, pos, keep_before=float("inf")) == (
        N - 1, "all but the final record, which anchors the chain")
    assert prune_shipped._walk(records, pos, keep_before=records[3]["ts"]) == (
        3, "inside the keep window")
    assert prune_shipped.stored_prefix(records, pos) == (
        N, "the collector acknowledged every record")
    # and a malformed entry is a verdict of 0 for the deleter too, not a
    # traceback that aborts a pass which may already have rewritten a log
    assert prune_shipped._walk(records, {"acked_seq": "five"}, keep_before=float("inf")) == (
        0, "acked_seq 'five' is not a number — the cursor entry is malformed")


# ═══════════════════════════════════════════ 7 · what the hunter found

@pytest.mark.parametrize("entry", [
    {"acked_seq": [5]},
    {"acked_seq": "five"},
    {"acked_seq": N, "skipped_seqs": ["x"]},
    "not a table",
    ["not", "a", "table"],
], ids=["acked_seq is a list", "acked_seq is a word", "skipped_seqs holds a word",
        "entry is a string", "entry is a list"])
def test_a_malformed_cursor_entry_is_not_stored_and_does_not_crash(world, capsys, entry):
    """⚠ FOUND BY silent-failure-hunter. A hand-edited or corrupted entry
    raised out of the walk: a traceback instead of a report, and for the
    deleter an abort mid-pass. Now a verdict of 0, with the reason."""
    root, state = world
    (state / "cursor.json").write_text(json.dumps({"sessions": {"s1": entry}}),
                                       encoding="utf-8")

    r = row(root)
    out = report(root, capsys)

    assert r["stored"] == 0 and r["unstored"] == N
    assert "malformed" in r["why"]
    assert column(out).startswith(f"{N} NOT STORED") and NEVER in out


@pytest.mark.parametrize("sessions", ["false", "null", "[]", '"x"'])
def test_a_cursor_whose_sessions_is_not_a_table_is_reported_not_normalised(
        world, capsys, sessions):
    """⚠ FOUND BY silent-failure-hunter. `or {}` ran before the type check, so
    a false/null/list `sessions` became an empty table with no problem to
    print — every session `never seen`, and no banner saying why."""
    root, state = world
    (state / "cursor.json").write_text('{"sessions": %s}' % sessions, encoding="utf-8")

    out = report(root, capsys)

    assert "NO SHIPPER CURSOR" in out and "no sessions table" in out
    assert column(out) == "never seen"


def test_an_unreadable_log_still_gets_a_row_that_says_so(world, capsys):
    """⚠ FOUND BY silent-failure-hunter. A log the tool could not read was
    dropped from a report about what is on the disk — no row, no bytes, no
    verdict. A directory wearing a log's name is the portable way to make
    `read_text` raise."""
    root, state = world
    cursor(state)
    (root / "s2.log.jsonl").mkdir()

    rows = {r["session"]: r for r in retention.survey(root)}
    out = report(root, capsys)

    assert rows["s2"]["unreadable"] is True and rows["s2"]["stored"] is None
    assert "could not be read" in rows["s2"]["why"]
    s2 = next(l for l in out.splitlines() if l.strip().startswith("s2 "))
    assert "UNREADABLE" in s2
    assert column(out) == "all", "s1 is unaffected"


def test_an_empty_log_is_called_empty_not_all(world, capsys):
    root, state = world
    cursor(state)
    (root / "s3.log.jsonl").write_text("", encoding="utf-8")

    out = report(root, capsys)

    s3 = next(l for l in out.splitlines() if l.strip().startswith("s3 "))
    assert s3.rstrip().endswith("  empty")


def test_the_cursor_is_read_once_per_run(world, monkeypatch, capsys):
    """⚠ FOUND BY silent-failure-hunter. Two reads of a file the shipper
    rewrites can disagree — rows from one read, the banner from another."""
    root, state = world
    cursor(state)
    calls = []
    real = retention.cursor_positions
    monkeypatch.setattr(retention, "cursor_positions",
                        lambda: calls.append(1) or real())

    report(root, capsys)

    assert len(calls) == 1


# ═══════════════════════════════════════════ 8 · unchanged where it should be

def test_without_a_collector_the_column_is_still_not_applicable(world, monkeypatch, capsys):
    """An install with no collector has no `stored` to speak of, and the fix
    must not turn that into a wall of NOT STORED."""
    root, state = world
    # ⚠ PATCHED, NOT UNSET. `collector_configured` asks the RECORDED install,
    # and `installer.recorded` binds its path from Path.home() at import —
    # whichever test module imported it first, under whichever HOME. Alone
    # this test imports it under its own tmp HOME and an unset variable
    # suffices; inside the full run the real install answers. The existing
    # retention test patches for the same reason.
    monkeypatch.setattr(retention, "collector_configured", lambda: False)
    cursor(state, acked_seq=None)

    out = report(root, capsys)

    assert column(out) == "n/a"
    assert "NO COLLECTOR IS CONFIGURED" in out
    assert NEVER not in out


def test_the_loop_position_is_never_read_as_authority():
    """Asserted on the source: the cursor's `shipped` is an index the loop
    keeps for itself, and this tool reads the collector's marks only."""
    source = (retention.ROOT / "tools" / "retention.py").read_text(encoding="utf-8")
    assert '.get("shipped"' not in source
    assert '["shipped"]' not in source
    assert "shipped_counts" not in source
