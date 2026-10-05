"""The blast-radius tool reads a frozen snapshot of the log roots, taken once,
never the live roots. docs/PARALLEL.md, runner/blast_radius.py.

The live roots keep growing while agents work: the installed guard appends a
record for every tool call. A comparison that read them twice (once per engine
tree) would compare two different populations and report movement no engine
made. So a snapshot is taken once, hashed, and both sides read only that.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.audit_log import append, build_body
from runner import blast_radius as br
from private_fixtures import needs_live_fixture  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "logs" / "live-fixture"


def _log(root: Path, session: str, commands: list[str], first_seq: int = 1) -> None:
    for offset, command in enumerate(commands):
        seq = first_seq + offset
        append(session, build_body(session, seq=seq, event="decision", decision="ALLOW",
                                   kind="EXEC", command=command, cwd="/work",
                                   ts=1000.0 + seq), root=root)


def test_a_snapshot_is_frozen_while_the_live_root_keeps_growing(tmp_path):
    live = tmp_path / "sessions"
    _log(live, "s1", ["git status", "ls -la"])
    dest = tmp_path / "snap"
    copies = br.snapshot([live], dest)
    assert list(copies) == [str(live)]

    before = br.replay(dest, ROOT, "/work")
    _log(live, "s1", ["git log -1"], first_seq=3)          # the guard keeps writing
    after = br.replay(dest, ROOT, "/work")

    assert [row["key"] for row in before] == ["s1:1", "s1:2"]
    assert after == before, "the snapshot moved with the live root"


def test_a_snapshot_that_changed_is_refused(tmp_path):
    live = tmp_path / "sessions"
    _log(live, "s1", ["git status"])
    dest = tmp_path / "snap"
    copy = br.snapshot([live], dest)[str(live)]
    log = next(copy.rglob("*.jsonl"))
    log.write_text(log.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed since the snapshot"):
        br.replay(dest, ROOT, "/work")


def test_a_file_added_to_a_snapshot_is_refused(tmp_path):
    live = tmp_path / "sessions"
    _log(live, "s1", ["git status"])
    dest = tmp_path / "snap"
    copy = br.snapshot([live], dest)[str(live)]
    (copy / "late.log.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="differ from the manifest"):
        br.verify(dest)


def test_a_snapshot_is_taken_never_topped_up(tmp_path):
    live = tmp_path / "sessions"
    _log(live, "s1", ["git status"])
    dest = tmp_path / "snap"
    br.snapshot([live], dest)
    with pytest.raises(FileExistsError):
        br.snapshot([live], dest)


def test_a_missing_root_is_recorded_and_not_invented(tmp_path):
    dest = tmp_path / "snap"
    assert br.snapshot([tmp_path / "absent"], dest) == {}
    manifest = json.loads((dest / br.MANIFEST).read_text(encoding="utf-8"))
    assert manifest["roots"] == [{"source": str(tmp_path / "absent"), "copy": None,
                                  "files": {}}]
    assert br.verify(dest) == []


def test_the_sidecars_travel_with_their_logs(tmp_path):
    """A clipped command is recovered from `<log>.commands/`, so a snapshot
    without the sidecars would replay a different command than the hook saw."""
    live = tmp_path / "sessions"
    _log(live, "s1", ["git status"])
    sidecar = live / "s1.log.jsonl.commands"
    sidecar.mkdir()
    (sidecar / "abc").write_text("git status --short", encoding="utf-8")
    copy = br.snapshot([live], tmp_path / "snap")[str(live)]
    assert (copy / "s1.log.jsonl.commands" / "abc").read_text(encoding="utf-8") == \
        "git status --short"


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_a_snapshot_is_as_private_as_the_logs_it_copies(tmp_path):
    """The logs hold the commands an agent ran, 0600 in a 0700 directory. A
    snapshot is a copy of them, so it is owner-only too, whatever the umask."""
    live = tmp_path / "sessions"
    _log(live, "s1", ["git status"])
    sidecar = live / "s1.log.jsonl.commands"
    sidecar.mkdir()
    (sidecar / "abc").write_text("git status --short", encoding="utf-8")
    dest = tmp_path / "snap"
    previous = os.umask(0o022)
    try:
        br.snapshot([live], dest)
    finally:
        os.umask(previous)
    opened = [f"{path} {oct(path.stat().st_mode & 0o777)}"
              for path in [dest, *dest.rglob("*")] if path.stat().st_mode & 0o077]
    assert not opened, opened


@pytest.mark.skipif(os.name == "nt", reason="POSIX flock")
def test_a_writer_that_never_lets_go_fails_the_snapshot_instead_of_hanging_it(
        tmp_path, monkeypatch):
    """A stalled append (a suspended hook, a filesystem that stopped answering)
    holds the log's exclusive lock. The copy waits the bounded time
    core.locking allows and raises; it never hangs the run that asked for it."""
    import fcntl

    from core import locking
    live = tmp_path / "sessions"
    _log(live, "s1", ["git status"])
    log = next(live.glob("*.jsonl"))
    monkeypatch.setenv("STING_LOCK_TIMEOUT", "0.3")
    fd = os.open(log, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(locking.LockUnavailable):
            br.snapshot([live], tmp_path / "snap")
    finally:
        os.close(fd)


@needs_live_fixture
def test_the_standing_fixture_replays_identically_twice(tmp_path):
    dest = tmp_path / "snap"
    br.snapshot([FIXTURE], dest)
    first = br.replay(dest, ROOT, "/work")
    assert first, "the tracked fixture replayed nothing"
    assert br.replay(dest, ROOT, "/work") == first
    assert br.diff(first, first) == []


def test_the_replay_refuses_to_pass_off_one_tree_as_another(tmp_path):
    """In one process `core` is imported once; replaying "another" tree there
    would replay this one twice and find nothing moved."""
    dest = tmp_path / "snap"
    br.snapshot([FIXTURE], dest)
    elsewhere = tmp_path / "other-tree"
    elsewhere.mkdir()
    with pytest.raises(RuntimeError, match="its own process"):
        br.replay(dest, elsewhere, "/work")


def test_diff_names_every_moved_verdict_and_nothing_else():
    allow = {"decision": "ALLOW", "rule_id": None, "reason": None, "evidence": None,
             "beneath": None}
    deny = {**allow, "decision": "DENY", "rule_id": "secret_exact:network_egress"}
    reworded = {**deny, "reason": "a different sentence"}
    before = [{"key": "s:1", "session": allow}, {"key": "s:2", "session": deny},
              {"key": "s:3", "session": deny, "isolated": allow}]
    after = [{"key": "s:1", "session": allow}, {"key": "s:2", "session": reworded},
             {"key": "s:3", "session": deny, "isolated": deny},
             {"key": "s:4", "session": allow}]
    assert br.diff(before, after) == [
        "s:4  only in after",
        "s:2  session (reason): DENY secret_exact:network_egress -> "
        "DENY secret_exact:network_egress",
        "s:3  isolated (decision, rule_id): ALLOW None -> "
        "DENY secret_exact:network_egress"]


def test_the_default_roots_are_resolved_when_asked(tmp_path):
    """Never frozen at import (tests/test_a_test_can_only_fail_elsewhere.py)."""
    roots = br.default_roots(tmp_path / "home", tmp_path / "repo")
    assert all(str(root).startswith(str(tmp_path)) for root in roots)
    assert tmp_path / "home" / ".sting" / "sessions" in roots


def test_the_command_line_round_trip(tmp_path, capsys):
    live = tmp_path / "sessions"
    _log(live, "s1", ["git status"])
    dest, out = tmp_path / "snap", tmp_path / "rows.json"
    assert br.main(["snapshot", str(dest), str(live)]) == 0
    out.write_text("[]", encoding="utf-8")
    out.chmod(0o644)                          # an older, wider file is replaced
    assert br.main(["replay", str(dest), str(out), "--cwd", "/work"]) == 0
    if os.name != "nt":
        assert out.stat().st_mode & 0o077 == 0, oct(out.stat().st_mode)
    assert br.main(["diff", str(out), str(out)]) == 0
    assert "no verdict moved" in capsys.readouterr().out
