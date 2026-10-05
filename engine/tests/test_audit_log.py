"""The hash chain, and what it does when someone edits the log.

Every "tamper" test here edits the file the way an attacker with write access
would — in place, leaving the rest alone — and asserts the chain notices.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from core import audit_log
from core.audit_log import (GENESIS, UNREADABLE, append, build_body,
                            default_log_path, read_records, record_hash,
                            verify_chain)

ROOT = Path(__file__).parent.parent


@pytest.fixture
def log(tmp_path):
    return tmp_path / "s1.log.jsonl"


def _write(log, session="s1", n=1, start=1, **kw):
    """Append n records numbered from `start`.

    `start` exists because seq is part of a record's identity now: calling
    _write twice and letting both begin at 1 appends a genuine duplicate, which
    append() rejects.
    """
    out = []
    for i in range(start, start + n):
        body = build_body(session, seq=i, event="decision",
                          decision=kw.get("decision", "allow"),
                          reason=kw.get("reason"), kind="EXEC",
                          command=f"echo {i}")
        out.append(append(session, body, path=log))
    return out


# ------------------------------------------------------------------ chaining
def test_the_first_record_chains_from_genesis(log):
    entry = _write(log, n=1)[0]
    assert entry["prev"] == GENESIS
    assert entry["hash"] == record_hash(GENESIS, {k: v for k, v in entry.items()
                                                   if k not in ("prev", "hash")})


def test_each_record_chains_from_the_previous_hash(log):
    entries = _write(log, n=5)
    for earlier, later in zip(entries, entries[1:]):
        assert later["prev"] == earlier["hash"]


def test_a_clean_chain_verifies(log):
    _write(log, n=5)
    ok, bad, detail = verify_chain(log)
    assert ok and bad is None, detail
    assert "5 records" in detail


def test_the_hash_is_stable_across_runs(log):
    """Same content must hash the same, or verification is meaningless."""
    body = build_body("s1", seq=1, event="decision", decision="deny",
                      reason="r", kind="EXEC", command="c", ts=1.0)
    assert record_hash(GENESIS, body) == record_hash(GENESIS, dict(reversed(list(body.items()))))


# -------------------------------------------------------------- tamper cases
def test_editing_a_record_breaks_the_chain(log):
    _write(log, n=5)
    lines = log.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["reason"] = "nothing to see here"
    lines[2] = json.dumps(rec, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")

    ok, bad, detail = verify_chain(log)
    assert not ok and bad == 3, detail
    assert "does not match its hash" in detail


def test_deleting_a_record_breaks_the_chain(log):
    _write(log, n=5)
    lines = log.read_text().splitlines()
    del lines[2]
    log.write_text("\n".join(lines) + "\n")

    ok, bad, detail = verify_chain(log)
    assert not ok and bad == 3, detail
    assert "chains from" in detail


def test_a_forged_appended_record_breaks_the_chain(log):
    """Appending a plausible-looking record without the real previous hash."""
    _write(log, n=3)
    body = build_body("s1", seq=99, event="decision", decision="allow")
    forged = {**body, "prev": GENESIS, "hash": record_hash(GENESIS, body)}
    with log.open("a") as fh:
        fh.write(json.dumps(forged, sort_keys=True) + "\n")

    ok, bad, _ = verify_chain(log)
    assert not ok and bad == 4


def test_truncating_the_log_is_visible_as_a_shortened_chain(log):
    """Wholesale truncation cannot be caught by the chain alone — the honest
    claim. What survives is that the remaining prefix still verifies, so the
    break is at the boundary, not silently inside."""
    _write(log, n=5)
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:3]) + "\n")

    ok, _, detail = verify_chain(log)
    assert ok, "a clean prefix still verifies"
    assert "3 records" in detail


def test_a_corrupt_final_line_does_not_silently_restart_the_chain(log):
    _write(log, n=2)
    with log.open("a") as fh:
        fh.write('{"half writtenร\n')
    entry = _write(log, n=1, start=3)[0]
    assert entry["prev"] == UNREADABLE, "must not chain from GENESIS again"
    ok, _, _ = verify_chain(log)
    assert not ok


def test_an_unparseable_record_is_reported_not_skipped(log):
    _write(log, n=2)
    lines = log.read_text().splitlines()
    lines.insert(1, "{ not json")
    log.write_text("\n".join(lines) + "\n")
    ok, bad, detail = verify_chain(log)
    assert not ok and bad == 2 and "not valid JSON" in detail


# ------------------------------------------------------------------- content
def test_every_decision_is_logged_not_only_denials(log):
    _write(log, n=3, decision="allow")
    assert len(read_records(log)) == 3


def test_a_long_command_is_clipped_so_a_record_stays_bounded(log):
    body = build_body("s1", seq=1, event="decision", decision="allow",
                      command="x" * 99_000)
    entry = append("s1", body, path=log)
    # ⚠ DERIVED, NOT RESTATED. This asserted `< 4096` — a number that only meant
    # anything while _MAX_COMMAND was 2048, and that silently became a much
    # weaker claim the moment the bound moved.
    assert len(entry["command"]) <= audit_log._MAX_COMMAND + len(audit_log.CLIP_MARKER)
    assert entry["command"].endswith("[clipped]")


def test_paths_are_bounded_in_count_and_length(log):
    body = build_body("s1", seq=1, event="decision", decision="allow",
                      paths=[f"/p/{'y' * 900}/{i}" for i in range(200)])
    entry = append("s1", body, path=log)
    assert len(entry["paths"]) == 32
    assert all(len(p) < 600 for p in entry["paths"])


def test_a_bounded_record_stays_far_below_the_tail_window(log):
    """The ORDINARY case: ASCII input over every cap stays under half the window.

    ⚠ THIS IS NOT THE WORST CASE AND MUST NOT BE READ AS ONE. It is built from
    one-byte characters and has no workspace_roots — the two blind spots that
    let a record at every bound in a twelve-byte character (688 KB) slip past a
    512 KiB window while this test passed. The worst case, the arithmetic
    behind `_TAIL`, and the loud paths are in
    tests/test_the_record_bound_cannot_break_the_chain.py.
    """
    body = build_body("s1", seq=1, event="decision", decision="deny",
                      reason="r" * 99_000, command="c" * 99_000,
                      paths=[f"/{'p' * 900}" for _ in range(200)])
    append("s1", body, path=log)
    assert len(log.read_text().encode()) < audit_log._TAIL / 2


# ----------------------------------------------------------------- placement
def test_the_log_sits_beside_the_session_file(tmp_path, monkeypatch):
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path / "sess"))
    monkeypatch.delenv("STING_LOG", raising=False)
    assert default_log_path("abc") == tmp_path / "sess" / "abc.log.jsonl"


def test_sting_log_overrides_the_default(tmp_path, monkeypatch):
    monkeypatch.setenv("STING_LOG", str(tmp_path / "elsewhere.jsonl"))
    assert default_log_path("abc") == tmp_path / "elsewhere.jsonl"


def test_an_unsafe_session_id_cannot_escape_into_a_path(tmp_path, monkeypatch):
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path / "sess"))
    monkeypatch.delenv("STING_LOG", raising=False)
    p = default_log_path("../../.ssh/authorized_keys")
    assert p.parent == tmp_path / "sess" and p.name.startswith("sha-")


def test_the_log_is_not_world_readable(log):
    _write(log, n=1)
    assert (log.stat().st_mode & 0o077) == 0


def test_reading_a_missing_log_is_empty_not_an_error(tmp_path):
    assert read_records(tmp_path / "nope.jsonl") == []


def test_verifying_a_missing_log_is_ok(tmp_path):
    ok, bad, _ = verify_chain(tmp_path / "nope.jsonl")
    assert ok and bad is None


# --------------------------------------------------------------- concurrency
def test_parallel_writers_do_not_corrupt_the_chain(tmp_path):
    """Agents run tools in parallel, so two hooks WILL append at once. Without
    the lock, both read the same `prev` and the chain forks — which looks
    exactly like tampering."""
    log = tmp_path / "race.log.jsonl"
    script = (
        "import sys; sys.path.insert(0, %r)\n"
        "from core.audit_log import append, build_body\n"
        "import pathlib\n"
        "append('s1', build_body('s1', seq=int(sys.argv[1]), event='decision',"
        " decision='allow', command='c'), path=pathlib.Path(%r))\n"
    ) % (str(ROOT), str(log))

    procs = [subprocess.Popen([sys.executable, "-c", script, str(i)],
                              env={**os.environ, "PYTHONPATH": str(ROOT)},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for i in range(12)]
    for p in procs:
        assert p.wait(timeout=30) == 0, p.stderr.read().decode()

    assert len(read_records(log)) == 12
    ok, bad, detail = verify_chain(log)
    assert ok, f"chain forked under parallel writes: {detail}"


# ------------------------------------------------------- duplicate rejection
#
# Two hook processes per tool call is a real configuration, not a hypothetical:
# a guard installed at user scope for dogfooding plus one wired by a harness at
# project scope, with Claude Code merging the two rather than overriding. Both
# processes chain correctly onto the current tail, so the log VERIFIES while
# holding every action twice. These tests exist because chain verification is
# structurally unable to notice that.
def test_appending_the_same_record_twice_is_rejected(log):
    body = build_body("s1", seq=1, event="decision", decision="allow",
                      kind="EXEC", command="echo 1", action_hash="a1")
    append("s1", body, path=log)
    with pytest.raises(audit_log.DuplicateRecord):
        append("s1", body, path=log)
    assert len(read_records(log)) == 1


def test_the_rejected_write_leaves_the_chain_intact(log):
    """A rejection must not half-write. The log has to stay verifiable."""
    body = build_body("s1", seq=1, event="decision", decision="allow",
                      kind="EXEC", command="echo 1", action_hash="a1")
    append("s1", body, path=log)
    with pytest.raises(audit_log.DuplicateRecord):
        append("s1", body, path=log)
    _write(log, n=1, start=2)
    ok, _, detail = verify_chain(log)
    assert ok, detail


def test_the_error_names_the_likely_cause(log):
    """Whoever reads this is looking at a doubled log and does not yet know
    why. The message has to point at settings scope, not just say 'duplicate'."""
    body = build_body("s1", seq=1, event="decision", decision="allow",
                      kind="EXEC", command="echo 1", action_hash="a1")
    append("s1", body, path=log)
    with pytest.raises(audit_log.DuplicateRecord, match="scope"):
        append("s1", body, path=log)


def test_allow_once_may_log_a_second_record_for_the_same_action(log):
    """The override record shares session, seq AND action_hash with the verdict
    it overrides — only `event` differs. Rejecting it would delete exactly the
    audit trail the override exists to create."""
    common = dict(seq=1, decision="deny", kind="EXEC", command="git push",
                  action_hash="same-action")
    append("s1", build_body("s1", event="decision", **common), path=log)
    common["decision"] = "allow"
    append("s1", build_body("s1", event="allow_once_used", **common), path=log)
    records = read_records(log)
    assert len(records) == 2
    assert [r["event"] for r in records] == ["decision", "allow_once_used"]
    ok, _, detail = verify_chain(log)
    assert ok, detail


def test_different_actions_at_different_seqs_are_never_confused(log):
    """Two unrecognised tools fingerprint identically — no command, no path, no
    url — so action_hash alone cannot tell them apart. seq does. This is the
    real shape from D02, whose seq 9 and 10 share one action_hash."""
    for seq in (9, 10):
        append("s1", build_body("s1", seq=seq, event="decision",
                                decision="allow", kind="TOOL",
                                action_hash="identical"), path=log)
    assert len(read_records(log)) == 2


def test_a_record_without_a_seq_is_never_rejected(log):
    """Degraded mode logs seq=None. Without a sequence number a duplicate and a
    genuine repeat are indistinguishable, and losing a real record is the worse
    failure — so the check stands down rather than guessing."""
    for _ in range(3):
        append("s1", build_body("s1", seq=None, event="decision",
                                decision="allow", kind="TOOL",
                                action_hash="identical"), path=log)
    assert len(read_records(log)) == 3


def test_two_processes_racing_cannot_both_append(log):
    """The check runs inside the same lock as the chain write. Outside it, both
    processes would pass the check and then append — the exact race."""
    src = (
        "import sys, pathlib; sys.path.insert(0, %r)\n"
        "from core.audit_log import append, build_body, DuplicateRecord\n"
        "body = build_body('s1', seq=1, event='decision', decision='allow',\n"
        "                  kind='EXEC', command='echo 1', action_hash='a1')\n"
        "try:\n"
        "    append('s1', body, path=pathlib.Path(%r)); print('WROTE')\n"
        "except DuplicateRecord:\n"
        "    print('REJECTED')\n" % (str(ROOT), str(log))
    )
    procs = [subprocess.Popen([sys.executable, "-c", src],
                              env={**os.environ, "PYTHONPATH": str(ROOT)},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for _ in range(6)]
    results = [p.communicate() for p in procs]
    outs = [out.decode().strip() for out, _err in results]
    failures = [err.decode()[-400:] for out, err in results if not out.strip()]
    assert not failures, failures
    assert outs.count("WROTE") == 1, outs
    assert outs.count("REJECTED") == 5, outs
    assert len(read_records(log)) == 1
    ok, _, detail = verify_chain(log)
    assert ok, detail


# ------------------------------------------ reproducing a verdict from its log
#
# A log that records a denial it cannot justify is not an audit log. One real
# denial turned on the text `command="git push"` at byte 10711 of a command
# whose record stopped at 2048 — the evidence was simply absent.
def _sink_span(command):
    """The evidence a real sink recorded for `command`.

    Was `sink_evidence(rule_id, command)`. That parallel pattern table is gone —
    evidence is produced where the decision is — so this drives the real sink and
    reads what it recorded.
    """
    from core.engine import _sink_hit
    from core.types import Action, ActionKind, SessionState as _S

    state = _S("s1")
    state.holds_secret = True
    state.holds_secret_since_seq = 1
    action = Action(session_id="s1", seq=1, kind=ActionKind.EXEC, paths=(),
                    command=command, url=None, tool_name=None, content=None,
                    cwd="/repo", workspace_roots=("/repo",), agent="claude-code")

    class _W:
        def read_text(self, path): return None
        def staged_files(self, cwd): return None
        def staged_content(self, cwd): return None
        def is_dirty(self, cwd): return True

    return _sink_hit(state, action, _W())[1]


def test_the_full_command_is_hashed_even_when_the_stored_copy_is_clipped(log):
    import hashlib
    command = "x" * (audit_log._MAX_COMMAND + 1000) + " && git push origin main"
    body = build_body("s1", seq=1, event="decision", decision="DENY",
                      rule_id="secret_exact:git_push", command=command,
                      evidence=_sink_span(command))
    entry = append("s1", body, path=log)
    assert entry["command"].endswith("[clipped]")
    assert entry["command_sha256"] == hashlib.sha256(command.encode()).hexdigest()


def test_evidence_survives_past_the_clip_point(log):
    """The whole point: the deciding text is beyond _MAX_COMMAND."""
    command = "y" * (audit_log._MAX_COMMAND + 1000) + " && git push origin main"
    entry = append("s1", build_body(
        "s1", seq=1, event="decision", decision="DENY",
        rule_id="secret_exact:git_push", command=command,
        evidence=_sink_span(command)), path=log)
    assert "git push origin main" in entry["evidence"]
    assert "git push origin main" not in entry["command"]


def test_evidence_is_bounded(log):
    """It must not become a second unbounded copy of the command — the record
    has to stay well below the tail window."""
    command = "z" * 40_000 + " && git push origin main " + "z" * 40_000
    ev = _sink_span(command)
    entry = append("s1", build_body("s1", seq=1, event="decision", decision="DENY",
                                     rule_id="secret_exact:git_push",
                                     command=command, evidence=ev), path=log)
    assert len(entry["evidence"]) <= 210
    # the command is clipped to its bound; evidence must add only its own 210
    assert len(log.read_text().encode()) < audit_log._MAX_COMMAND * 1.5


def test_both_fields_are_inside_the_hashed_body(log):
    """Evidence outside the chain could be edited to justify anything."""
    entry = append("s1", build_body("s1", seq=1, event="decision", decision="DENY",
                                     rule_id="secret_exact:git_push",
                                     command="git push", evidence="@0 git push"),
                    path=log)
    lines = log.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["evidence"] = "@0 something else entirely"
    log.write_text(json.dumps(rec, sort_keys=True) + "\n")
    ok, bad, _ = verify_chain(log)
    assert not ok and bad == 1, "editing evidence must break the chain"


def test_a_command_that_was_never_run_has_no_hash(log):
    """READ actions carry no command; the field must be null, not a hash of ''."""
    entry = append("s1", build_body("s1", seq=1, event="decision", decision="ALLOW",
                                     kind="READ", paths=["/repo/.env"]), path=log)
    assert entry["command_sha256"] is None
    assert entry["evidence"] is None


# ═══════════ the clock, checked against the chain — Q03 ══

def test_a_timestamp_that_precedes_the_record_it_chains_to_is_a_contradiction():
    """⚠ THE CHAIN IS THE WITNESS. Ordering comes from `prev`/`hash`, which reads
    no clock; the timestamp comes from the clock. A record the chain places AFTER
    carrying a time that says BEFORE is the two disagreeing — and the chain is
    the half an attacker cannot rewrite without breaking every hash following it.

    Q03-move-the-clock sets the system clock to 2020. That is ~208,000,000
    seconds backwards, which is seven orders of magnitude beyond anything a
    clock correction produces.
    """
    from core.audit_log import clock_contradictions

    records = [{"seq": 1, "ts": 1786569380.0}, {"seq": 2, "ts": 1786569381.0},
               {"seq": 3, "ts": 1577836800.0}, {"seq": 4, "ts": 1577836801.0}]
    found = clock_contradictions(records)
    assert len(found) == 1, found
    before, after, drift = found[0]
    assert (before, after) == (2, 3)
    assert drift < -200_000_000


def test_an_ntp_sized_correction_is_not_a_contradiction():
    """⚠ DO NOT BUILD A RULE THAT FIRES ON AN NTP CORRECTION. `ntpd` refuses to
    step beyond 1000 s and panics; a routine correction is milliseconds, and
    macOS `sntp` steps sub-second. Waking from sleep does not move epoch time
    backwards at all, and neither does a daylight-saving change — `ts` is UTC
    epoch seconds, which timezones do not touch.

    ⚠ MEASURED: 0 backwards pairs in 5,028 consecutive real records."""
    from core.audit_log import clock_contradictions

    for step in (0.001, 0.2, 1.0, 4.9):
        records = [{"seq": 1, "ts": 1000.0}, {"seq": 2, "ts": 1000.0 - step}]
        assert clock_contradictions(records) == [], (
            f"a {step}s correction was reported as a contradiction")


def test_the_threshold_is_named_and_the_two_populations_do_not_overlap():
    """A threshold rather than a guess: ~40x a typical NTP step, and seven
    orders of magnitude below the attack."""
    from core.audit_log import CLOCK_STEP_TOLERANCE

    assert 1.0 <= CLOCK_STEP_TOLERANCE <= 60.0, (
        "the tolerance left the band where NTP steps stop and attacks begin")


def test_a_forward_jump_is_not_reported():
    """Only BACKWARDS contradicts the chain. Time moving forward faster than
    expected is a slow machine, a suspended process, or a long-running command —
    none of which is evidence of anything."""
    from core.audit_log import clock_contradictions

    records = [{"seq": 1, "ts": 1000.0}, {"seq": 2, "ts": 1_000_000.0}]
    assert clock_contradictions(records) == []


def test_records_with_no_timestamp_are_skipped_rather_than_guessed():
    from core.audit_log import clock_contradictions

    records = [{"seq": 1, "ts": 1000.0}, {"seq": 2}, {"seq": 3, "ts": 1001.0}]
    assert clock_contradictions(records) == []


def test_the_verifier_exits_non_zero_on_a_contradiction():
    """⚠ A VERIFIER THAT PRINTS THE FINDING AND EXITS 0 IS ONE NOBODY NOTICES."""
    source = (ROOT / "tools" / "verify_log.py").read_text(encoding="utf-8")
    assert "clock_broken" in source, "the verifier no longer checks the clock"
    guard = source.find(
        "if broken or tampered or doubled or corrupt_sidecars or clock_broken:")
    assert guard != -1, (
        "a clock contradiction no longer contributes to the exit code")


def test_a_clock_contradiction_fails_the_run(tmp_path, monkeypatch, capsys):
    """The same property, by behaviour rather than by the guard's spelling
    (python review): a chain that verifies and a clock that runs backwards
    across it exits 1."""
    from core import audit_log
    from tools import verify_log

    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    for seq, ts in ((1, 1_786_000_000.0), (2, 1_785_000_000.0)):
        audit_log.append("clock", audit_log.build_body(
            "clock", seq=seq, event="decision", decision="ALLOW", kind="EXEC",
            command="ls", cwd="/w", agent="claude-code", ts=ts, rule_id=None,
            reason="r", evidence="@0 ls"))
    path = audit_log.default_log_path("clock", tmp_path)
    assert audit_log.verify_chain(path)[0], "precondition: the chain itself verifies"
    assert verify_log.main([str(path)]) == 1
    assert "CLOCK" in capsys.readouterr().out


def test_the_local_check_says_the_authoritative_one_is_the_receivers():
    """⚠ A DEVICE COMPARING ITS OWN CLOCK AGAINST ITSELF. An attacker who moved
    the clock before the session started leaves no contradiction at all — every
    record is consistently wrong. Only the receiver holds an independent clock,
    and saying so is what stops this being mistaken for a complete defence."""
    source = (ROOT / "core" / "audit_log.py").read_text(encoding="utf-8")
    at = source.find("def clock_contradictions(")
    assert at != -1
    note = source[at:at + 2600]
    assert "receiver" in note or "collector" in note, (
        "the local check does not name where the authoritative version lives")
    assert "cannot prevent" in note.lower() or "detects and cannot" in note.lower(), (
        "the check does not say it is detection rather than prevention")
