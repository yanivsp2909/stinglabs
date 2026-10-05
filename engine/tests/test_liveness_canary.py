"""A session that did nothing must be distinguishable from a guard that never ran.

⚠ THE FAILURE THIS EXISTS FOR. A hook that never fires and a hook that fires and
allows everything produce byte-identical evidence: none. Every record until now
was written BY a decision, so an install that was never wired, a settings file
that got reset, or an interpreter that moved all look exactly like a quiet week.

The canary is one `session_start` record, written once per session, INSIDE the
hash chain. In the chain is the point: outside it a marker can be deleted or
forged with no trace, so its presence would prove nothing. Inside, removing it
breaks every following hash AND leaves the record count short — the same
two-signal argument that put every decision in the log rather than only denials.

WHAT IT STILL DOES NOT CATCH, stated here so nobody reads this file as more than
it is: a hook that dies MID-session leaves a log that simply stops, and that log
verifies perfectly. Catching that needs a heartbeat, which is a per-N-actions
write and a different cost. Not built.
"""
from __future__ import annotations

import json

import pytest

import hook_entry
from core.audit_log import default_log_path, read_records, verify_chain


def payload(session="s1", command="ls"):
    return json.dumps({"session_id": session, "cwd": "/tmp",
                        "hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": command}})


def test_a_session_opens_with_a_canary():
    hook_entry.run(payload())
    records = read_records(default_log_path("s1"))
    assert records[0]["event"] == "session_start"
    assert records[0]["decision"] is None, "a canary is not a verdict"
    assert records[0]["seq"] is None, "a canary is not an action"


def test_the_canary_names_what_was_running():
    """Without these it proves something ran and nothing about what.

    ⚠ THE AGENT IS NOW DECLARED IN THE CALL. It used to rely on `run()`'s
    default, which was `claude-code` — so this assertion said "the canary names
    the agent" while actually proving "the canary repeats the default". The
    undeclared case is the next test, and it names `unknown`."""
    hook_entry.run(payload(), agent="claude-code")
    canary = read_records(default_log_path("s1"))[0]
    assert canary["agent"] == "claude-code"
    # RESOLVED, not verbatim: on macOS /tmp is a symlink to /private/tmp and
    # the adapter resolves it deliberately (adapters/_common.py:72) so a taint
    # lookup cannot miss by spelling. Assert the property, not the literal.
    assert canary["cwd"] and canary["cwd"].endswith("/tmp")
    assert canary["ts"]


def test_the_canary_of_an_unlabelled_invocation_says_unknown():
    """⚠ THE CANARY IS THE FIRST THING WRITTEN, so it is the first place a
    fabricated agent name would appear — and it is written before any verdict,
    so a reader trusts it. It must carry the same `unknown` the records do
    rather than the reference adapter's name."""
    hook_entry.run(payload(), agent=hook_entry.pick_agent([]))
    canary = read_records(default_log_path("s1"))[0]
    assert canary["agent"] == "unknown"


def test_exactly_one_canary_per_session_however_many_actions():
    for i in range(5):
        hook_entry.run(payload(command=f"echo {i}"))
    records = read_records(default_log_path("s1"))
    canaries = [r for r in records if r["event"] == "session_start"]
    assert len(canaries) == 1, f"{len(canaries)} canaries"
    assert len(records) == 6, "1 canary + 5 decisions"


def test_separate_sessions_each_get_one():
    hook_entry.run(payload(session="a"))
    hook_entry.run(payload(session="b"))
    for sid in ("a", "b"):
        assert read_records(default_log_path(sid))[0]["event"] == "session_start"


def test_the_canary_is_inside_the_chain():
    """If it were outside, deleting it would cost nothing — and a marker that
    can be removed silently proves nothing about whether the hook ran."""
    hook_entry.run(payload())
    path = default_log_path("s1")
    ok, bad, _ = verify_chain(path)
    assert ok, f"chain broken at {bad}"

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")   # drop the canary
    ok_after, bad_after, detail = verify_chain(path)
    assert not ok_after, "removing the canary went undetected"
    assert bad_after == 1, detail


# --------------------------------------------- the two cases it must separate

def test_a_quiet_session_is_distinguishable_from_a_dead_hook(tmp_path, monkeypatch):
    """THE WHOLE POINT, as two files on disk.

    CASE A — the hook ran and the session had nothing worth a verdict: a log
             exists and says when, and under which agent.
    CASE B — the hook never ran: no log at all.
    """
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    hook_entry.run(payload(session="quiet"))

    live = default_log_path("quiet")
    records = read_records(live)
    # Strip the decision, leaving the shape of a session that decided nothing.
    canary_only = [r for r in records if r["event"] == "session_start"]
    live.write_text(json.dumps(canary_only[0], sort_keys=True) + "\n",
                    encoding="utf-8")

    assert live.exists() and read_records(live)[0]["event"] == "session_start"
    assert not default_log_path("never-ran").exists()


def test_the_canary_does_not_make_a_dead_hook_look_alive():
    """The inverse, and the one that would make this whole thing a lie: a
    session id that was never driven must not acquire a canary from anywhere."""
    hook_entry.run(payload(session="driven"))
    assert default_log_path("driven").exists()
    assert not default_log_path("not-driven").exists()


# ------------------------------------------------- every reader tolerates it

def test_the_differential_ignores_the_canary(tmp_path, monkeypatch):
    """replay_live filters on `event == "decision"` (runner/replay_live.py:143),
    which pre-dates this and already handled `allow_once_used`. Pinned because a
    canary counted as a comparable record would be a permanent phantom diff."""
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    hook_entry.run(payload(session="d1"))
    from runner import replay_live
    loaded = replay_live.load_records(tmp_path)
    # ⚠ THE CANARY MUST BE THERE TO BE IGNORED. Without these three lines the
    # test passes when `load_records` returns nothing at all — a changed glob, a
    # changed suffix, a session root it no longer looks in — and "the canary was
    # filtered out" becomes indistinguishable from "no record was ever read".
    # The loop below is a universal quantifier, and a universal over nothing is
    # true.
    raw = (tmp_path / "d1.log.jsonl").read_text(encoding="utf-8")
    assert '"session_start"' in raw, "no canary was written, so none can be ignored"
    assert loaded, "load_records found no sessions — this test would prove nothing"
    assert any(loaded.values()), "every session loaded empty"
    for session, records in loaded.items():
        assert all(r.get("event") == "decision" for r in records), session


def test_the_labelling_tool_does_not_see_a_canary_as_a_prompt(tmp_path, monkeypatch):
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    hook_entry.run(payload(session="d2"))
    from tools import label_prompts
    records = label_prompts.load_records([tmp_path])
    assert any(r.get("event") == "session_start" for r in records), "canary missing"
    assert not label_prompts.prompts(records), "a canary was counted as a prompt"
