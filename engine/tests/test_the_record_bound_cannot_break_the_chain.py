"""⚠ THE BOUND THAT WAS TRUE BY LUCK — TWICE.

`_last_hash()` reads the last `_TAIL` bytes and takes the final line as a whole
record. If a record ever exceeds `_TAIL`, that line is a fragment, it fails to
parse, and EVERY SUBSEQUENT APPEND CHAINS FROM `UNREADABLE` — a silent,
permanent break of the hash chain on a log that is otherwise intact. It is the
worst failure this file can have, because the log's only claim is that it is
tamper-evident.

THE FIRST TIME (docs/64): the comment beside the bounds said a record stays far
below `_TAIL`, and it held only because real data escapes at 1.04x. `_TAIL` was
resized "from the bounds" and this file asserted the arithmetic.

⚠ THE SECOND TIME (docs/76): THAT ARITHMETIC HAD THE WRONG WORST CHARACTER AND
NOT ALL THE FIELDS. It priced JSON escaping at 6 bytes per character — the cost
of `\\u001b` — but `_clip` bounds a field in CODE POINTS, and a code point
outside the Basic Multilingual Plane (most emoji) is written by `ensure_ascii`
as a surrogate pair, `\\ud83d\\ude00`: TWELVE bytes. And it summed six caps
while `build_body` bounds twelve; `workspace_roots` alone is another
`_MAX_PATHS * _MAX_PATH`. Either mistake on its own still fit: every field at
its cap is 344 KB in the six-byte character, and 491 KB in the twelve-byte one
without roots. Together they do not: 688 KB against a 512 KiB window. The
record after it chained from UNREADABLE, and nothing said so.

So this file now (1) prices the escape at what it costs, (2) sums EVERY cap
`build_body` applies, (3) runs a record at every bound in the worst character
and checks the record after it still chains, and (4) proves the two loud
paths: a record that would not fit is REFUSED before it is written, and a hook
whose record chains from UNREADABLE says so on stderr.
"""
from __future__ import annotations

import json

import pytest

import hook_entry
from core import audit_log
from core.audit_log import (CLIP_MARKER, UNREADABLE, RecordTooLarge, append,
                            build_body, canonical, default_log_path,
                            worst_record_bytes)
from tests.test_adapter_conformance import NATIVE_EXEC_PAYLOAD

# ⚠ THE WORST CHARACTER IS NOT A CONTROL CHARACTER. U+001B escapes to six
# bytes; anything past U+FFFF escapes to a surrogate PAIR, twelve. 😀 is one
# code point to `len()` and to `_clip`, and twelve bytes to `canonical()`.
_ASTRAL = "\U0001F600"
_WORST_ESCAPE = 12


@pytest.fixture
def log(tmp_path):
    return tmp_path / "s1.log.jsonl"


def _over(limit: int, ch: str = _ASTRAL) -> str:
    """One past the cap, so the field is clipped AND carries the clip marker —
    the largest a bounded field can be on disk, not merely the largest input."""
    return ch * (limit + 1)


def a_record_at_every_bound(ch: str = _ASTRAL,
                            roots: int = audit_log._MAX_PATHS, why: bool = True) -> dict:
    """Every field `build_body` bounds, over its bound, in the worst character.

    `roots` is a parameter because zero roots is exactly the case the previous
    version of this file exercised, and the difference is the bug.
    """
    return build_body(
        "x" * 128,                    # the longest id safe_session_id passes through
        seq=1, event="decision", decision="deny",
        rule_id="r" * audit_log._MAX_RULE_ID, kind="EXEC",
        reason=_over(audit_log._MAX_REASON, ch),
        command=_over(audit_log._MAX_COMMAND, ch),
        url=_over(audit_log._MAX_PATH, ch),
        cwd=_over(audit_log._MAX_PATH, ch),
        tool_name=_over(audit_log._MAX_PATH, ch),
        paths=[_over(audit_log._MAX_PATH, ch)
               for _ in range(audit_log._MAX_PATHS + 1)],
        workspace_roots=[_over(audit_log._MAX_PATH, ch) for _ in range(roots)],
        evidence=_over(audit_log._MAX_EVIDENCE, ch),
        agent=_over(audit_log._MAX_AGENT, ch),
        guard_version=_over(audit_log._MAX_AGENT, ch),
        granted_by=_over(audit_log._MAX_AGENT, ch),
        title=_over(audit_log._MAX_TITLE, ch),
        relaxed=[ch * audit_log._MAX_RULE_ID + str(i)
                 for i in range(audit_log._MAX_RELAXED + 1)],
        # a DENY's why fields (docs/108), each over its bound
        why=None if not why else {"action": _over(audit_log._MAX_WHY_PHRASE, ch),
             "value_type": _over(audit_log._MAX_WHY_PHRASE, ch),
             "destination": _over(audit_log._MAX_PATH, ch),
             "source_file": _over(audit_log._MAX_PATH, ch),
             "location": _over(audit_log._MAX_PATH, ch),
             "sentence": _over(audit_log._MAX_REASON, ch),
             "source_step": 2 ** 62},
        action_hash="a" * 64, duration_ms=123456.789)


# ------------------------------------------------------- 1 · the arithmetic

def test_the_worst_escape_is_twelve_bytes_not_six():
    """The crux, as a fact about `json.dumps` rather than about this repo."""
    def escaped_bytes(ch: str) -> int:
        return len(json.dumps(ch, ensure_ascii=True)) - 2        # minus the quotes

    assert escaped_bytes("\x1b") == 6, "a control character is the SIX-byte case"
    assert escaped_bytes("é") == 6, "so is anything else inside the BMP"
    assert escaped_bytes(_ASTRAL) == _WORST_ESCAPE, "outside the BMP: a surrogate pair"
    assert len(_ASTRAL) == 1, "and _clip counts it as ONE character"
    assert audit_log._WORST_ESCAPE == _WORST_ESCAPE


def test_every_bounded_field_at_its_limit_still_fits_the_tail_window():
    """The arithmetic, from the constants themselves — every cap `build_body`
    applies, at twelve bytes a character, plus a clip marker per clipped field.
    Restated here independently of `worst_record_bytes()` so the module cannot
    be wrong in the same way as this test."""
    a = audit_log
    bounded_chars = (
        a._MAX_COMMAND + a._MAX_REASON + a._MAX_EVIDENCE
        + 2 * a._MAX_PATHS * a._MAX_PATH          # paths AND workspace_roots
        + 3 * a._MAX_PATH                         # url, cwd, tool_name
        + 3 * a._MAX_AGENT                        # agent, guard_version, granted_by
        + a._MAX_TITLE                            # title
        + a._MAX_RELAXED * a._MAX_RULE_ID         # relaxed
        + 2 * a._MAX_WHY_PHRASE                   # action, value_type (docs/108)
        + 3 * a._MAX_PATH                         # destination, source_file, location
        + a._MAX_REASON)                          # sentence
    # reason, command, evidence, url, cwd, tool_name, agent, guard_version,
    # granted_by, title and the six why texts: sixteen scalars, each _clip()ped
    # — plus every path and root
    clipped_fields = 16 + 2 * a._MAX_PATHS
    marker_bytes = len(json.dumps(CLIP_MARKER, ensure_ascii=True)) - 2
    worst = _WORST_ESCAPE * bounded_chars + clipped_fields * marker_bytes + a._SPINE_BYTES

    assert worst == worst_record_bytes(), "the module's own arithmetic drifted"
    assert worst < a._TAIL, (
        f"a record at every bound, escaped at {_WORST_ESCAPE}x, is {worst:,} "
        f"bytes and _TAIL is {a._TAIL:,} — a log whose final record looks like "
        f"this chains from UNREADABLE forever after")


def test_the_arithmetic_bounds_what_json_dumps_actually_produces(log):
    """⚠ A FORMULA IS A CLAIM ABOUT `json.dumps`. This runs it: the largest
    body `build_body` can make, in the worst character, with every field over
    its cap, AS WRITTEN TO DISK — prev, hash, separators and newline included,
    because the line is what has to fit the window — measures at or under the
    number the module computes from the caps."""
    append("s1", a_record_at_every_bound(), path=log)
    measured = log.stat().st_size                      # exactly one line

    assert measured <= worst_record_bytes(), (
        f"{measured:,} bytes on disk, {worst_record_bytes():,} claimed")
    # and the claim is not slack enough to be meaningless: the spine allowance
    # is the only part that is not derived, and it is under 1% of the record
    assert worst_record_bytes() - measured < audit_log._SPINE_BYTES


def test_the_guard_version_fallback_is_bounded_like_the_rest(monkeypatch):
    """⚠ FOUND BY REVIEW. `guard_version` was clipped only when a caller passed
    it; the fallback — `version.running_version()`, read from the guard's own
    INSTALL.json — was not, while the arithmetic counted it as one `_MAX_AGENT`.
    Only a rewritten guard tree can make it long, but a bound the window's
    arithmetic relies on cannot depend on who wrote the value."""
    monkeypatch.setattr(audit_log.version, "running_version",
                        lambda: _ASTRAL * (audit_log._MAX_AGENT * 50))

    body = build_body("s1", seq=1, event="decision", decision="allow")

    assert len(body["guard_version"]) == audit_log._MAX_AGENT + len(CLIP_MARKER)
    assert body["guard_version"].endswith(CLIP_MARKER)


# ------------------------------------------------------- 2 · the live record

def test_a_record_built_entirely_from_escaping_characters_still_chains(log):
    """⚠ THE BREAK DOES NOT SHOW ON THE RECORD THAT IS TOO LARGE. It shows on
    the one after it, which reads the tail to find its `prev`. Every field is
    over its cap, in the twelve-byte character, with all 32 workspace roots —
    the record the previous version of this test did not build."""
    first = append("s1", a_record_at_every_bound(), path=log)
    second = append("s1", build_body("s1", seq=2, event="decision",
                                      decision="allow", command="git status"),
                    path=log)

    assert second["prev"] != UNREADABLE, (
        "the chain broke on the record AFTER an oversized one")
    assert second["prev"] == first["hash"]
    assert audit_log.verify_chain(log)[0] is True


def test_the_previous_version_of_this_test_was_under_the_window_either_way(log):
    """The blind spot, stated: the six-byte character with all 32 roots, and
    the twelve-byte character with none, BOTH fit the old 512 KiB window. Only
    the combination did not. Kept so the next resize cannot re-open the gap by
    testing one axis at a time. ⚠ The record AS IT WAS THEN: without the why
    fields a DENY carries since docs/108, which that version did not have."""
    old_tail = 512 * 1024
    six_byte_all_roots = len(canonical(a_record_at_every_bound("\x1b", why=False)).encode())
    twelve_byte_no_roots = len(canonical(a_record_at_every_bound(roots=0, why=False)).encode())
    both = len(canonical(a_record_at_every_bound(why=False)).encode())

    assert six_byte_all_roots < old_tail
    assert twelve_byte_no_roots < old_tail
    assert both > old_tail, "the case that broke the chain"


# ------------------------------------------------------- 3 · the loud paths

def test_a_record_that_would_not_fit_is_refused_before_it_is_written(log):
    """⚠ THE CAUSE, NOT THE SYMPTOM. If the arithmetic is ever wrong again, the
    record that would break every later record is refused — loudly, by name —
    and the log is left exactly as it was, so the chain stays intact."""
    good = append("s1", build_body("s1", seq=1, event="decision",
                                    decision="allow", command="ls"), path=log)
    before = log.read_bytes()
    oversize = build_body("s1", seq=2, event="decision", decision="deny")
    oversize["command"] = _ASTRAL * (audit_log._TAIL // _WORST_ESCAPE + 1)

    with pytest.raises(RecordTooLarge) as caught:
        append("s1", oversize, path=log)

    assert "seq 2" in str(caught.value) and "_TAIL" in str(caught.value)
    assert log.read_bytes() == before, "nothing may be written"
    third = append("s1", build_body("s1", seq=3, event="decision",
                                     decision="allow", command="ls"), path=log)
    assert third["prev"] == good["hash"], "the chain continued from the last GOOD record"
    assert audit_log.verify_chain(log)[0] is True


def test_the_hook_says_so_when_its_record_chains_from_unreadable():
    """⚠ THE SENTINEL IS CONTRACTUAL; THE SILENCE WAS NOT. A torn final line
    makes `_last_hash` return UNREADABLE and the next record chain from it —
    that is the visible, permanent break the sentinel exists for. The hook
    must SAY it happened, on stderr, the moment it does."""
    payload = NATIVE_EXEC_PAYLOAD["claude-code"]
    session = hook_entry.ADAPTERS["claude-code"].parse(payload).session_id
    log = default_log_path(session)
    append(session, build_body(session, seq=1, event="decision",
                               decision="allow", command="ls"), path=log)
    with log.open("ab") as fh:
        fh.write(b'{"seq": 2, "event": "decision", "torn":')     # died mid-write

    out, err, code = hook_entry.run(json.dumps(payload), agent="claude-code")

    assert code == 0, err
    last = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    assert last["prev"] == UNREADABLE, "the record is still written, and still marked"
    assert last["seq"] is not None, "the note is bound to the record by its seq"
    assert "UNREADABLE" in err and f"seq {last['seq']}" in err, (
        f"the hook chained from UNREADABLE without saying so; stderr was {err!r}")


def test_an_ordinary_record_produces_no_such_note():
    """The mirror: the note is for the break, not for every append.

    ⚠ NOT VACUOUS BY CONSTRUCTION. "No note" is also what an unwritten record
    looks like — a `decision not logged` failure carries no UNREADABLE either —
    so the record's existence and an intact chain are asserted alongside."""
    payload = NATIVE_EXEC_PAYLOAD["claude-code"]
    session = hook_entry.ADAPTERS["claude-code"].parse(payload).session_id

    out, err, code = hook_entry.run(json.dumps(payload), agent="claude-code")

    assert code == 0, err
    log = default_log_path(session)
    records = audit_log.read_records(log)
    assert records, "no record was written — silence would prove nothing"
    assert audit_log.verify_chain(log)[0] is True
    assert "UNREADABLE" not in err and "not logged" not in err


# ------------------------------------------------------- 4 · unchanged claims

def test_the_clip_still_announces_itself_at_the_new_bound(log):
    """⚠ TASK 1.3. Raising the bound does not mean nothing is ever cut — it
    means less is. A record that IS still clipped must say so and say by how
    much, or the receiver cannot tell a whole command from a cut one."""
    command = "q" * (audit_log._MAX_COMMAND + 5_000)
    entry = append("s1", build_body("s1", seq=1, event="decision",
                                     decision="allow", command=command),
                    path=log)

    assert entry["command_clipped"] is True
    assert entry["command_len"] == len(command)
    assert entry["command"].endswith(audit_log.CLIP_MARKER)
    # and the TRUE length is recoverable, so "how much is missing" is arithmetic
    assert entry["command_len"] - audit_log._MAX_COMMAND == 5_000


def test_a_command_that_used_to_be_clipped_now_arrives_whole(log):
    """The point of the change, stated as a record: the p90 of what this
    machine actually runs (6,901 characters) was cut at 2,048 and is not now."""
    command = "p" * 6_901
    entry = append("s1", build_body("s1", seq=1, event="decision",
                                     decision="allow", command=command),
                    path=log)

    assert entry["command_clipped"] is False
    assert entry["command"] == command
