"""The command sidecar — recovering the exact string a verdict was judged on.

WHY. `command` is clipped to `_MAX_COMMAND`, so a verdict on a long command
cannot be RE-RUN from the log. `command_sha256` proves WHICH string was judged
but cannot recover it: one real investigation only succeeded because the clipped
tail happened to be a commit message that still existed in git, and nothing
guarantees that.

THE TRUST MODEL, which is the part worth getting right. The sidecar is OUTSIDE
the hash chain and inside the tamper-evident boundary, and that is stronger than
chaining it:

  - `command_sha256` is inside the hashed body, so the CHAIN attests the digest;
  - the sidecar is verified by recomputing its own hash against that digest;
  - so the file supplies bytes and the chain supplies authority, and a forged
    sidecar is caught by content-addressing alone.

Chaining the sidecar's BYTES would mean putting the full command back in the
record — destroying the bound that made clipping necessary and pushing large
records past `_TAIL`, where `_last_hash()` breaks.

THE ASYMMETRY IS DELIBERATE: deleting a log record breaks the chain, because the
chain attests THE DECISION. Deleting a sidecar loses recovery and nothing else.
"""
import hashlib
import json

import pytest

from core.audit_log import (SIDECAR_ABSENT, SIDECAR_CORRUPT, SIDECAR_RECOVERED,
                            _MAX_COMMAND, _MAX_SIDECAR_BYTES, _MAX_SIDECAR_FILES,
                            append, build_body, load_full_command, sidecar_dir,
                            store_full_command, verify_chain)


@pytest.fixture
def log(tmp_path):
    return tmp_path / "s1.log.jsonl"


def long_command(extra=5000, filler="x"):
    return "git commit -m '" + filler * (_MAX_COMMAND + extra) + "'"


def record_for(command, log):
    body = build_body("s1", seq=1, event="decision", decision="deny",
                      kind="EXEC", command=command)
    append("s1", body, path=log)
    store_full_command(log, command)
    return body


# ===================================================== the round trip
def test_a_clipped_command_is_recovered_exactly(log):
    command = long_command()
    record = record_for(command, log)
    assert record["command_clipped"] is True
    status, recovered = load_full_command(record, log)
    assert status == SIDECAR_RECOVERED
    assert recovered == command, "recovery must be byte-exact or it proves nothing"


def test_the_recovered_command_is_the_one_the_verdict_used(log):
    """The whole point: the recovered text must hash to the digest the chain
    attests, so it is provably the string that was judged."""
    command = long_command()
    record = record_for(command, log)
    _status, recovered = load_full_command(record, log)
    assert hashlib.sha256(recovered.encode()).hexdigest() == record["command_sha256"]


def test_an_unclipped_command_needs_no_sidecar(log):
    """It is already whole in the record; writing a file would be pure waste."""
    record = record_for("git push origin main", log)
    assert not sidecar_dir(log).exists()
    status, recovered = load_full_command(record, log)
    assert (status, recovered) == (SIDECAR_RECOVERED, "git push origin main")


def test_the_same_long_command_twice_is_stored_once(log):
    """Content-addressing. Measured on the real logs: 77 clipped records, 61
    distinct hashes — the duplicates are repeated invocations."""
    command = long_command()
    store_full_command(log, command)
    store_full_command(log, command)
    assert len(list(sidecar_dir(log).iterdir())) == 1


def test_two_different_commands_are_two_files(log):
    store_full_command(log, long_command(filler="a"))
    store_full_command(log, long_command(filler="b"))
    assert len(list(sidecar_dir(log).iterdir())) == 2


# ===================================================== the three states
def test_a_missing_sidecar_is_ABSENT_and_not_tampering(log):
    """The state that matters most. Absence is the normal result of a cap, a copy
    without the directory, or a cleanup — it must never read as corruption, and
    the chain must still verify."""
    command = long_command()
    record = record_for(command, log)
    (sidecar_dir(log) / record["command_sha256"]).unlink()
    assert load_full_command(record, log) == (SIDECAR_ABSENT, None)
    assert verify_chain(log)[0] is True, (
        "deleting a sidecar must NOT break the chain — it loses recovery, not "
        "integrity")


def test_an_edited_sidecar_is_CORRUPT(log):
    """A forged sidecar is caught by content-addressing, with no help from the
    chain — this is what makes chain coverage unnecessary."""
    command = long_command()
    record = record_for(command, log)
    (sidecar_dir(log) / record["command_sha256"]).write_text("git push origin main")
    assert load_full_command(record, log) == (SIDECAR_CORRUPT, None)


def test_a_record_predating_command_sha256_is_ABSENT_not_corrupt(log):
    """16 of the 77 real clipped records have no digest. They can never be
    recovered or verified, and saying so is the honest answer."""
    record = {"command": "x" * 50 + "…[clipped]", "command_clipped": True}
    assert load_full_command(record, log) == (SIDECAR_ABSENT, None)


def test_a_record_with_no_command_at_all_is_ABSENT(log):
    record = build_body("s1", seq=1, event="decision", decision="allow",
                        kind="READ", paths=("/repo/.env",))
    assert load_full_command(record, log) == (SIDECAR_ABSENT, None)


# ===================================================== the bounds
def test_a_command_over_the_per_command_cap_is_NOT_stored(log):
    """Storing a truncated sidecar would produce a file whose content does not
    hash to its own name — indistinguishable from tampering. Absence is honest."""
    command = "y" * (_MAX_SIDECAR_BYTES + 10)
    assert store_full_command(log, command) is None
    assert not sidecar_dir(log).exists() or not list(sidecar_dir(log).iterdir())


def test_over_the_file_cap_writing_stops_and_nothing_is_deleted(log):
    """Pruning oldest-first would destroy evidence to make room for evidence, and
    the older record is the one more likely to be under investigation."""
    for i in range(_MAX_SIDECAR_FILES):
        (sidecar_dir(log)).mkdir(parents=True, exist_ok=True)
        (sidecar_dir(log) / f"{i:064x}").write_text("filler")
    before = set(p.name for p in sidecar_dir(log).iterdir())

    assert store_full_command(log, long_command()) is None
    after = set(p.name for p in sidecar_dir(log).iterdir())
    assert after == before, "existing evidence must survive untouched"


def test_an_unwritable_directory_never_raises(log, monkeypatch):
    """Losing the ability to re-run a verdict is an observability failure. A
    guard that fails closed because a directory is unwritable protects nothing."""
    def boom(*_args, **_kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr("pathlib.Path.mkdir", boom)
    assert store_full_command(log, long_command()) is None


def test_no_partial_file_is_ever_visible_under_its_hash_name(log):
    """Written to a temp name in the same directory and renamed, so a concurrent
    reader never sees a half-written file claiming to be its own digest."""
    command = long_command()
    digest = store_full_command(log, command)
    names = [p.name for p in sidecar_dir(log).iterdir()]
    assert names == [digest]
    assert not any(n.endswith(".tmp") for n in names)


# ===================================================== end to end, real engine
def test_the_hook_writes_a_sidecar_for_a_real_long_command(tmp_path, monkeypatch):
    """Through hook_entry, not through the helper — the wiring is the thing that
    was missing, and a helper nobody calls recovers nothing."""
    import subprocess
    import sys
    from pathlib import Path

    root = tmp_path / "sessions"
    root.mkdir()
    env = {**dict(__import__("os").environ),
           "STING_SESSION_ROOT": str(root), "STING_OBSERVE": "1"}
    env.pop("STING_LOG", None)
    command = "echo " + "z" * (_MAX_COMMAND + 1000)
    payload = json.dumps({
        "session_id": "sidecar-e2e", "cwd": str(tmp_path),
        "tool_name": "Bash", "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "hook_entry.py"], input=payload,
                          capture_output=True, text=True,
                          cwd=str(Path(__file__).parent.parent), env=env)
    assert proc.returncode == 0, proc.stderr

    logs = list(root.glob("*.log.jsonl"))
    assert logs, f"no log written; stderr={proc.stderr}"
    records = [json.loads(line) for line in logs[0].read_text().splitlines() if line.strip()]
    decisions = [r for r in records if r.get("command_clipped")]
    assert decisions, "the long command should have been recorded as clipped"
    status, recovered = load_full_command(decisions[0], logs[0])
    assert status == SIDECAR_RECOVERED
    assert recovered == command
