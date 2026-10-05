"""Recovering what the developer ASKED for, from the agent's transcript.

The labelling tool showed the agent's side of the conversation only, and the
owner could not judge anything with it. The instruction is the missing half.

The failure mode to guard is not "returns nothing" — that is visible. It is
**returning the wrong text confidently**, because a plausible-looking paragraph
under the heading "YOU ASKED" is exactly the thing a person will trust and label
against. Two ways that happens, one test group each:

    a tool RESULT read as a human turn — every tool result comes back with
    `role: "user"`, and they outnumber real turns 1137 to 47 in the session
    measured, so a naive filter returns the output of the previous command

    machinery read as instruction — slash commands, the caveat banner wrapped
    around them, injected reminders, and the auto-summary a continued session
    opens with
"""
from __future__ import annotations

import json

import pytest

from tools import session_context as sc


def transcript(tmp_path, rows):
    path = tmp_path / "s1.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return path


def human(text, ts="2026-08-08T10:00:00.000Z"):
    return {"type": "user", "timestamp": ts,
            "message": {"role": "user", "content": [{"type": "text", "text": text}]}}


def tool_result(output, ts="2026-08-08T10:00:01.000Z"):
    return {"type": "user", "timestamp": ts,
            "message": {"role": "user",
                        "content": [{"type": "tool_result", "content": output}]}}


def tool_use(command, ts="2026-08-08T10:00:02.000Z"):
    return {"type": "assistant", "timestamp": ts,
            "message": {"role": "assistant",
                        "content": [{"type": "tool_use", "name": "Bash",
                                     "input": {"command": command}}]}}


@pytest.fixture(autouse=True)
def _fresh_cache():
    sc.index.cache_clear()
    yield
    sc.index.cache_clear()


# ------------------------------------------------ a tool result is not a turn

def test_a_tool_result_is_never_read_as_the_instruction(tmp_path, monkeypatch):
    """THE ONE THAT MATTERS. `role: "user"` is not enough — a tool result would
    be returned as "what you asked for", which is confidently wrong."""
    path = transcript(tmp_path, [
        human("please fix the failing test"),
        tool_result("PASSED 14 tests in 0.4s"),
        tool_use("pytest -q")])
    monkeypatch.setattr(sc, "TRANSCRIPTS", tmp_path)
    monkeypatch.setattr(sc, "transcript_path", lambda sid: path)
    import hashlib
    digest = hashlib.sha256(b"pytest -q").hexdigest()
    asked, how = sc.asked_for("s1", digest, None)
    assert asked == "please fix the failing test"
    assert "PASSED" not in (asked or "")
    assert how.startswith("exact")


@pytest.mark.parametrize("noise", [
    "<local-command-caveat>Caveat: the messages below…</local-command-caveat>",
    "<command-name>/clear</command-name>",
    "<system-reminder>remember to…</system-reminder>",
    "This session is being continued from a previous conversation that ran out "
    "of context. Summary: …",
])
def test_machinery_is_not_read_as_an_instruction(tmp_path, monkeypatch, noise):
    path = transcript(tmp_path, [
        human("the real instruction"),
        human(noise),
        tool_use("ls")])
    monkeypatch.setattr(sc, "transcript_path", lambda sid: path)
    import hashlib
    asked, _ = sc.asked_for("s1", hashlib.sha256(b"ls").hexdigest(), None)
    assert asked == "the real instruction"


# ------------------------------------------------------------------- routes

def test_the_digest_route_is_exact_or_it_does_not_claim_to_be(tmp_path, monkeypatch):
    path = transcript(tmp_path, [human("do the thing"), tool_use("git status")])
    monkeypatch.setattr(sc, "transcript_path", lambda sid: path)
    asked, how = sc.asked_for("s1", "0" * 64, None)
    assert not how.startswith("exact")


def test_the_time_route_takes_the_last_turn_at_or_before_the_action(tmp_path, monkeypatch):
    """WRITE and EDIT have no command and so no digest — a third of all prompts.
    Without this route they would show no instruction at all."""
    path = transcript(tmp_path, [
        human("first instruction", ts="2026-08-08T10:00:00.000Z"),
        human("second instruction", ts="2026-08-08T12:00:00.000Z")])
    monkeypatch.setattr(sc, "transcript_path", lambda sid: path)
    import datetime as dt
    at = dt.datetime.fromisoformat("2026-08-08T13:00:00+00:00").timestamp()
    asked, how = sc.asked_for("s1", None, at)
    assert asked == "second instruction"
    assert how.startswith("by time")


def test_a_missing_transcript_says_so_rather_than_guessing(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "transcript_path", lambda sid: None)
    asked, how = sc.asked_for("nope", "0" * 64, 1.0)
    assert asked is None and how == "no transcript"


# ---------------------------------------------------------------- time gaps

@pytest.mark.parametrize("seconds, expect", [
    (3, "3s"), (300, "5 min"), (7200, "2.0 h")])
def test_the_gap_is_shown_in_units_a_person_thinks_in(seconds, expect):
    assert expect in sc.human_gap(seconds)


def test_a_long_gap_says_you_had_been_away():
    """3s later is the agent mid-loop; 2h later is a person coming back. The same
    prompt is a different judgement across those, and the record has always
    carried `ts` with nothing showing it."""
    assert "away" in sc.human_gap(7200)
    assert "away" not in sc.human_gap(30)


def test_no_gap_is_blank_not_zero():
    assert sc.human_gap(None) == ""
    assert sc.gap_before({"ts": 10.0}, []) is None


def test_the_gap_is_measured_against_the_previous_action():
    earlier = [{"ts": 100.0}, {"ts": 160.0}]
    assert sc.gap_before({"ts": 200.0}, earlier) == 40.0


# --------------------------------------------------------- against real data

REAL = sc.TRANSCRIPTS.is_dir()


@pytest.mark.skipif(not REAL, reason="no transcripts on this machine")
def test_an_instruction_is_recovered_for_the_real_prompts(live_logs):
    """The number that decides whether the tool is usable at all: on the live
    logs this is 246 of 246, 141 exact and 105 by time. The decision logs are
    this run's copy (tests/conftest.py `live_logs`); the transcripts are read
    where Claude Code keeps them, by session id, and never written."""
    from tools import label_prompts as lp
    roots = [live_logs.of(r) for r in lp.LIVE_ROOTS]
    roots = [r for r in roots if r.is_dir()]
    if not roots:
        pytest.skip("no live logs")
    ps = [r for r in lp.prompts(lp.load_records(roots)) if lp.judgeable(r)]
    if not ps:
        pytest.skip("no judgeable prompts")
    missing = 0
    for r in ps:
        digest = r.get("original_sha256") or r.get("command_sha256")
        asked, _ = sc.asked_for(r.get("session_id"), digest, r.get("ts"))
        if not asked:
            missing += 1
    assert missing == 0, f"{missing} of {len(ps)} prompts have no instruction"
