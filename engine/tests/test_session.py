"""
Part B step 5 — session state and its locking.

The concurrency test is the one that matters. Agents run tools in parallel, so
two hooks race for real; without an exclusive lock held across the whole
read-modify-write, the second writer overwrites the first and a fingerprint the
guard had already recorded silently vanishes. That is the guard forgetting a
secret it has seen — precisely what session memory exists to prevent.
"""
import json
import multiprocessing
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.session import (SessionState, load_session, open_session,
                           safe_session_id, session_path)

ROOT = Path(__file__).parent.parent


@pytest.fixture
def sessions(tmp_path):
    return tmp_path / "sessions"


# ------------------------------------------------------------ the schema
def test_a_fresh_session_is_clean(sessions):
    with open_session("s1", sessions) as st:
        assert st.is_clean()
        assert st.seq == 0
        assert st.untrusted is False and st.holds_secret is False
        assert st.secret_fingerprints == [] and st.tainted_paths == {}


def test_state_round_trips_through_disk(sessions):
    with open_session("s1", sessions) as st:
        st.seq = 4
        st.mark_untrusted(3, "issue", "ISSUE_418.md")
        st.mark_secret(4, ".env", "content", ["a3f1c9d2", "7b2e4816"])
        st.taint("debug/.env", "exact", 6)
        st.expected_hosts = ["github.com"]
        st.staged_secret_files = ["debug/.env"]

    again = load_session("s1", sessions)
    assert again.seq == 4
    assert again.untrusted and again.untrusted_since_seq == 3
    assert again.untrusted_sources == [{"seq": 3, "kind": "issue", "ref": "ISSUE_418.md"}]
    assert again.holds_secret and again.holds_secret_since_seq == 4
    assert again.secret_fingerprints == ["a3f1c9d2", "7b2e4816"]
    assert again.secret_sources == [{"seq": 4, "path": ".env", "how": "content"}]
    assert again.tainted_paths["debug/.env"] == {
        "label": "SECRET", "level": "exact", "from_seq": 6}
    assert again.staged_secret_files == ["debug/.env"]


def test_the_file_matches_the_documented_schema(sessions):
    with open_session("s1", sessions) as st:
        st.mark_secret(5, ".env", "content", ["ff01a9c3"])
    data = json.loads(session_path("s1", sessions).read_text())
    for key in ("session_id", "started_at", "seq", "cwd", "untrusted",
                "untrusted_since_seq", "untrusted_sources", "holds_secret",
                "holds_secret_since_seq", "secret_fingerprints", "secret_sources",
                "tainted_paths", "expected_hosts", "approved_hosts",
                "staged_secret_files"):
        assert key in data, f"missing documented field {key}"


def test_started_at_is_set_once_and_kept(sessions):
    with open_session("s1", sessions) as st:
        first = st.started_at
    assert first > 0
    time.sleep(0.01)
    with open_session("s1", sessions) as st:
        assert st.started_at == first


# ------------------------------------------------------------------ labels
def test_untrusted_records_every_source_but_pins_the_first_seq(sessions):
    with open_session("s1", sessions) as st:
        st.mark_untrusted(3, "issue", "ISSUE_418.md")
        st.mark_untrusted(9, "web", "https://evil.io")
    st = load_session("s1", sessions)
    assert st.untrusted_since_seq == 3, "the first taint is when trust was lost"
    assert len(st.untrusted_sources) == 2, "a deny reason must name which source"


def test_fingerprints_are_deduplicated(sessions):
    with open_session("s1", sessions) as st:
        st.mark_secret(1, ".env", "content", ["aaa", "bbb"])
        st.mark_secret(2, ".env.local", "content", ["bbb", "ccc"])
    assert load_session("s1", sessions).secret_fingerprints == ["aaa", "bbb", "ccc"]


def test_taint_never_downgrades_an_exact_label_to_derived(sessions):
    """A file known to hold a verbatim copy of a secret does not become merely
    'derived' because it was written to again."""
    with open_session("s1", sessions) as st:
        st.taint("debug/.env", "exact", 6)
        st.taint("debug/.env", "derived", 9)
    assert load_session("s1", sessions).tainted_paths["debug/.env"]["level"] == "exact"


def test_taint_does_upgrade_derived_to_exact(sessions):
    with open_session("s1", sessions) as st:
        st.taint("out.css", "derived", 6)
        st.taint("out.css", "exact", 9)
    assert load_session("s1", sessions).tainted_paths["out.css"]["level"] == "exact"


# --------------------------------------------------------------------- seq
def test_seq_is_assigned_when_the_agent_supplies_none():
    st = SessionState(seq=7)
    assert st.next_seq(None) == 8
    assert st.next_seq(0) == 8


def test_a_supplied_seq_is_used_as_is_not_recomputed():
    """Antigravity's stepIdx already arrives monotonic."""
    st = SessionState(seq=3)
    assert st.next_seq(19) == 19


def test_a_supplied_seq_can_never_move_backwards():
    st = SessionState(seq=20)
    assert st.next_seq(5) == 20, "seq must stay monotonic even if an agent lies"


# ------------------------------------------------- untrusted session ids
@pytest.mark.parametrize("evil", [
    "../../../etc/passwd",
    "../../.ssh/authorized_keys",
    "/etc/shadow",
    "a/b/c",
    "..",
    "with space",
    "sess\0null",
    "x" * 500,
    "",
])
def test_a_session_id_can_never_escape_the_sessions_directory(evil, sessions):
    """The session id arrives from the agent, so it is untrusted input. Used
    naively it is a path traversal that truncates and rewrites whatever it
    points at."""
    path = session_path(evil, sessions)
    assert path.parent == sessions, f"{evil!r} escaped to {path}"
    assert ".." not in str(path)
    with open_session(evil, sessions) as st:
        st.seq = 1
    assert path.exists()


def test_safe_ids_are_left_readable():
    assert safe_session_id("01J8ZQ9K7X2V4M6N8P0R2T4W6Y") == "01J8ZQ9K7X2V4M6N8P0R2T4W6Y"
    assert safe_session_id("ec33ebf9-0cba-4100-8142-c61503f6c587").startswith("ec33ebf9")


def test_an_unsafe_id_hashes_stably(sessions):
    a, b = safe_session_id("../evil"), safe_session_id("../evil")
    assert a == b and a.startswith("sha-")
    assert safe_session_id("../other") != a


def test_non_string_session_ids_do_not_crash():
    for weird in (None, 42, [], {}):
        assert safe_session_id(weird).startswith("sha-")


# ------------------------------------------------------------- robustness
def test_a_corrupt_state_file_starts_fresh_rather_than_refusing_to_run(sessions):
    sessions.mkdir(parents=True)
    session_path("s1", sessions).write_text("{ this is not json")
    with open_session("s1", sessions) as st:
        assert st.is_clean()
        st.seq = 1
    assert load_session("s1", sessions).seq == 1


def test_unknown_fields_from_a_future_build_are_ignored(sessions):
    sessions.mkdir(parents=True)
    session_path("s1", sessions).write_text(json.dumps({"seq": 5, "from_the_future": True}))
    with open_session("s1", sessions) as st:
        assert st.seq == 5


def test_loading_a_session_that_does_not_exist_returns_a_clean_one(sessions):
    assert load_session("never-seen", sessions).is_clean()


def test_the_sessions_directory_is_not_world_readable(sessions):
    with open_session("s1", sessions) as st:
        st.seq = 1
    assert (sessions.stat().st_mode & 0o077) == 0, "state names read paths and holds fingerprints"


# =====================================================================
# The concurrency test. 10 concurrent writers, no lost updates.
# =====================================================================
WORKER = r'''
import sys, time
sys.path.insert(0, %r)
from core.session import open_session
from pathlib import Path
idx = int(sys.argv[1])
root = Path(sys.argv[2])
with open_session("race", root) as st:
    st.seq = st.seq + 1
    # Widen the read-modify-write window so an unlocked implementation is
    # guaranteed to lose updates rather than getting away with it by luck.
    time.sleep(0.02)
    st.secret_fingerprints.append("fp-%%02d" %% idx)
    st.untrusted_sources.append({"seq": idx, "kind": "worker", "ref": str(idx)})
''' % str(ROOT)


def test_ten_concurrent_writers_lose_no_updates(tmp_path):
    sessions = tmp_path / "sessions"
    script = tmp_path / "worker.py"
    script.write_text(WORKER)

    procs = [subprocess.Popen([sys.executable, str(script), str(i), str(sessions)])
             for i in range(10)]
    for p in procs:
        assert p.wait(timeout=60) == 0

    st = load_session("race", sessions)
    assert st.seq == 10, f"lost updates: seq={st.seq}, expected 10"
    assert sorted(st.secret_fingerprints) == [f"fp-{i:02d}" for i in range(10)], \
        "a fingerprint recorded by one call vanished — the guard forgot a secret"
    assert len(st.untrusted_sources) == 10


def test_concurrent_writers_never_leave_the_file_unparseable(tmp_path):
    """A half-written state file read by the next hook would look corrupt and
    silently reset the session, which is a guard losing its memory."""
    sessions = tmp_path / "sessions"
    script = tmp_path / "worker.py"
    script.write_text(WORKER)
    procs = [subprocess.Popen([sys.executable, str(script), str(i), str(sessions)])
             for i in range(10)]
    for p in procs:
        p.wait(timeout=60)
    json.loads(session_path("race", sessions).read_text())


def test_the_lock_is_held_across_the_whole_read_modify_write(tmp_path):
    """A second writer must block until the first has written, not read the
    pre-change value and race it."""
    sessions = tmp_path / "sessions"
    script = tmp_path / "worker.py"
    script.write_text(WORKER)

    started = time.perf_counter()
    procs = [subprocess.Popen([sys.executable, str(script), str(i), str(sessions)])
             for i in range(5)]
    for p in procs:
        p.wait(timeout=60)
    elapsed = time.perf_counter() - started

    # Each worker sleeps 20ms inside the locked window. Serialised that is
    # >=100ms; if they overlapped, the lock is not doing its job.
    assert elapsed >= 0.10, f"writers overlapped ({elapsed:.3f}s) — lock not held"
    assert load_session("race", sessions).seq == 5
