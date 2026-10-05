"""tools/verify_log.py — the chain checker's exit codes and output.

Exit codes matter more than the text: this is the thing a cron job or a future
control plane calls, and "broken" has to be distinguishable from "nothing to
check" without parsing English.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

import hook_entry
from core.audit_log import default_log_path
from tools import verify_log

ROOT = Path(__file__).parent.parent
CLI = ROOT / "tools" / "verify_log.py"


def payload(session="s1", command="ls"):
    return json.dumps({"session_id": session, "cwd": "/tmp",
                       "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": command}})


def run(*args):
    return subprocess.run([sys.executable, str(CLI), *map(str, args)],
                           capture_output=True, text=True, cwd=str(ROOT))


@pytest.fixture
def log():
    for i in range(4):
        hook_entry.run(payload(command=f"echo {i}"))
    return default_log_path("s1")


def test_a_clean_log_verifies(log):
    """4 decisions + 1 `session_start` canary = 5 records.

    ⚠ The count changed with the canary, and the number is asserted rather than
    made vague on purpose: `verify_log` reporting a record COUNT is how a
    deleted record is spotted, so a test that stopped caring how many there are
    would give up the second of the two signals the log was built to have.
    """
    r = run(log)
    assert r.returncode == 0
    assert "OK" in r.stdout and "5 records" in r.stdout


def test_an_edited_record_is_reported_with_its_number(log):
    lines = log.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["command"] = "echo something-else"
    lines[1] = json.dumps(rec, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")

    r = run(log)
    assert r.returncode == 1
    assert "BROKEN" in r.stdout
    assert "record 2" in r.stdout


def test_a_deleted_record_is_reported(log):
    lines = log.read_text().splitlines()
    del lines[1]
    log.write_text("\n".join(lines) + "\n")
    assert run(log).returncode == 1


def test_nothing_to_check_is_its_own_exit_code(tmp_path):
    r = run("--root", tmp_path / "empty")
    assert r.returncode == 2
    assert "No logs" in r.stderr


def test_scanning_a_root_finds_logs_by_suffix(log):
    r = run("--root", log.parent)
    assert r.returncode == 0
    assert log.name in r.stdout


def test_quiet_says_nothing_when_everything_verifies(log):
    r = run("--quiet", log)
    assert r.returncode == 0 and r.stdout.strip() == ""


def test_quiet_still_reports_a_break(log):
    lines = log.read_text().splitlines()
    lines[1] = json.dumps({**json.loads(lines[1]), "command": "x"}, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")
    r = run("--quiet", log)
    assert r.returncode == 1 and "BROKEN" in r.stdout


def test_one_broken_log_fails_a_whole_scan(log):
    """A scan is only as good as its worst log."""
    hook_entry.run(payload(session="s2"))
    lines = log.read_text().splitlines()
    lines[0] = json.dumps({**json.loads(lines[0]), "command": "x"}, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")

    r = run("--root", log.parent)
    assert r.returncode == 1
    # The summary now separates a broken chain from a doubled log: different
    # causes, different fixes, and only one of them means tampering.
    assert "1 with a broken chain, out of 2 logs checked" in r.stdout


def test_the_suffix_comes_from_the_engine_not_a_copy():
    """If audit_log renames its files, the scanner follows automatically."""
    from core.audit_log import LOG_SUFFIX
    assert verify_log.LOG_SUFFIX is LOG_SUFFIX


# ----------------------------------------------------- duplicate detection
#
# The lesson from the 7 Aug run: a doubled log VERIFIES. Two hook processes each
# chain correctly onto the tail they find, so every hash matches and every
# action appears twice. Chain verification cannot see this, and nothing else was
# looking — so a benchmark taken from that log would have been 2x and looked
# perfectly well-formed.
def _chained(path: Path, records: list[dict]) -> None:
    """Write records as a VALID chain — duplicates included.

    Built by hand rather than via append(), which now refuses duplicates. The
    point is to reproduce a log an older engine (or two racing hooks) really
    produced: internally consistent, and wrong.
    """
    from core.audit_log import GENESIS, record_hash
    prev, lines = GENESIS, []
    for body in records:
        h = record_hash(prev, body)
        lines.append(json.dumps({**body, "prev": prev, "hash": h}, sort_keys=True))
        prev = h
    path.write_text("\n".join(lines) + "\n")


def _body(seq: int, event: str = "decision", session: str = "s1") -> dict:
    return {"ts": 1.0, "session_id": session, "seq": seq, "event": event,
            "kind": "EXEC", "decision": "allow", "rule_id": None, "reason": None,
            "paths": [], "command": f"echo {seq}", "url": None,
            "action_hash": f"h{seq}"}


def test_a_doubled_log_verifies_but_is_still_reported(tmp_path):
    """The whole point. If this ever passes clean, the check is worthless."""
    log = tmp_path / "doubled.log.jsonl"
    _chained(log, [_body(s) for s in (1, 1, 2, 2, 3, 3)])
    result = run(log)
    assert result.returncode == 1, result.stdout
    assert "DOUBLED" in result.stdout
    assert "chain verifies" in result.stdout


def test_the_report_names_settings_scope_as_the_cause(tmp_path):
    """Whoever reads this is holding a doubled log and does not know why."""
    log = tmp_path / "doubled.log.jsonl"
    _chained(log, [_body(s) for s in (1, 1, 2, 2)])
    out = run(log).stdout
    assert "settings.json" in out
    assert "SCOPES" in out or "scope" in out.lower()


def test_a_clean_log_is_not_flagged(tmp_path):
    log = tmp_path / "clean.log.jsonl"
    _chained(log, [_body(s) for s in (1, 2, 3)])
    result = run(log)
    assert result.returncode == 0, result.stdout
    assert "DOUBLED" not in result.stdout


def test_an_allow_once_override_is_not_a_duplicate(tmp_path):
    """Same session, same seq — different event. Legitimate, and the audit
    trail an override exists to create."""
    log = tmp_path / "override.log.jsonl"
    _chained(log, [_body(1), _body(1, event="allow_once_used"), _body(2)])
    result = run(log)
    assert result.returncode == 0, result.stdout


def test_records_without_a_seq_are_not_flagged(tmp_path):
    """Degraded mode logs seq=None; two of them are not evidence of anything."""
    log = tmp_path / "degraded.log.jsonl"
    _chained(log, [{**_body(1), "seq": None} for _ in range(3)])
    assert run(log).returncode == 0


def test_two_sessions_reusing_the_same_seq_are_not_duplicates(tmp_path):
    """Sequence numbers restart per session, so seq alone is not an identity."""
    log = tmp_path / "two.log.jsonl"
    _chained(log, [_body(1, session="a"), _body(1, session="b")])
    assert run(log).returncode == 0


def test_a_broken_chain_is_reported_as_broken_not_doubled(tmp_path):
    """Precedence: a tampered log is the more serious finding and must not be
    relabelled by the newer check."""
    log = tmp_path / "both.log.jsonl"
    _chained(log, [_body(s) for s in (1, 1, 2)])
    lines = log.read_text().splitlines()
    rec = json.loads(lines[1]); rec["command"] = "tampered"
    lines[1] = json.dumps(rec, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")
    out = run(log).stdout
    assert "BROKEN" in out
    assert "DOUBLED" not in out


def test_logs_named_dot_log_are_found_not_only_dot_log_dot_jsonl(tmp_path):
    """The corpus runner sets STING_LOG and names the file itself
    (`logs/observe/<scenario>.log`). Globbing only LOG_SUFFIX meant this tool
    checked nothing at all for exactly the runs most worth checking."""
    (tmp_path / "harness.log").write_text("")
    _chained(tmp_path / "harness.log", [_body(s) for s in (1, 1)])
    result = run("--root", tmp_path)
    assert result.returncode == 1, result.stdout
    assert "harness.log" in result.stdout
