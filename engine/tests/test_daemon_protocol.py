"""The wire, and the one duplicated constant it depends on.

`daemon/protocol.py` cannot import `core.session` — that would drag the engine
into the client and cost the whole saving. So it restates one expression: where
session state lives. A duplicated default that drifts is worse than an import,
because the client would then look for a socket in a directory the daemon never
publishes one in, and every call would silently fall back to the slow path with
nothing anywhere saying why.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import session                                             # noqa: E402
from daemon import protocol                                          # noqa: E402


def test_the_duplicated_session_root_matches_the_one_that_owns_it(monkeypatch):
    monkeypatch.delenv("STING_SESSION_ROOT", raising=False)
    assert protocol.session_root() == str(session.default_root())


def test_it_matches_when_the_environment_overrides_it(monkeypatch, tmp_path):
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path / "elsewhere"))
    assert protocol.session_root() == str(session.default_root())


def test_absent_and_empty_are_different_pins(monkeypatch):
    """⚠ WORKING RULE 13, IN AN ENVIRONMENT DICT.

    `None` means "this process did not say"; `""` means "it said nothing". A
    `pins()` that collapsed them would let a daemon booted with no STING_LOG
    serve a client that set it to the empty string, and the two would be
    writing to different places while comparing equal.
    """
    monkeypatch.delenv("STING_LOG", raising=False)
    absent = protocol.pins()
    monkeypatch.setenv("STING_LOG", "")
    empty = protocol.pins()

    assert absent["STING_LOG"] is None
    assert empty["STING_LOG"] == ""
    assert absent != empty


def test_every_pinned_and_carried_name_is_one_the_code_actually_reads():
    """⚠ TWO LISTS OF ENVIRONMENT VARIABLES IS ONE LIST THAT CAN BE WRONG.

    A name in PINNED that nothing reads is dead weight; a name the engine reads
    that is in NEITHER list is a setting the daemon answers from its own boot
    environment while the caller believes theirs applied. This test catches the
    first. The second is caught by the sweep below.
    """
    sources = ""
    for name in ("hook_entry.py", "core/session.py", "core/probes.py",
                 "core/allow_once.py", "core/audit_log.py", "core/purpose.py",
                 "core/wire.py"):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), name)
        sources += open(path, encoding="utf-8").read()

    for name in protocol.PINNED + protocol.CARRIED:
        assert name in sources, f"{name} is declared but nothing reads it"


def test_no_sting_variable_the_hot_path_reads_is_left_undeclared():
    """The other half: a setting that reaches a verdict must be pinned OR
    carried, never neither.

    ⚠ THE EXCLUSIONS ARE NAMED AND ARGUED, not a filter that quietly grows.
    """
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    read_by_the_hot_path = set()
    for name in ("hook_entry.py", "core/session.py", "core/probes.py",
                 "core/allow_once.py", "core/audit_log.py"):
        source = open(os.path.join(root, name), encoding="utf-8").read()
        read_by_the_hot_path |= set(
            re.findall(r'environ\.get\(\s*"(STING_[A-Z_]+)"', source))

    # ⚠ WORKING RULE 13, FORM F2: a universal over an empty collection is TRUE.
    # If the regex ever stops matching — a rename, a reformat, a move to a
    # helper — the subset check below passes while checking nothing, and the
    # daemon could grow an undeclared setting with a green suite. So the
    # population is asserted to contain the names this test exists to police.
    assert len(read_by_the_hot_path) >= 5, (
        f"the scan found only {sorted(read_by_the_hot_path)} — it is not "
        f"reading the sources it thinks it is")
    for expected in ("STING_OBSERVE", "STING_SESSION_ROOT", "STING_ROOTS"):
        assert expected in read_by_the_hot_path, (
            f"{expected} must be findable, or this test is not measuring")

    allowed = set(protocol.PINNED) | set(protocol.CARRIED) | {
        # Chosen by the CLIENT before it ever speaks, and sent as its own field
        # rather than as an environment variable.
        "STING_AGENT",
    }
    assert read_by_the_hot_path <= allowed, (
        f"undeclared on the wire: {sorted(read_by_the_hot_path - allowed)}")


def test_a_refusal_carries_no_verdict():
    refusal = protocol.refusal(protocol.REFUSED_PINS, "different store")
    assert "exit" not in refusal
    assert "stdout" not in refusal


def test_one_frame_survives_a_multiline_command():
    """A live command is 461 characters and 13 segments at the median, with
    heredocs in 43.9% of sessions. `json.dumps` escapes the newlines, so the
    framing stays one line — asserted, because a protocol that broke on a
    heredoc would break on nearly half of real sessions."""
    command = "python3 - <<'PY'\nfor i in range(3):\n    print(i)\nPY"
    frame = protocol.encode(protocol.request(command, "claude-code", {}))

    assert frame.count(b"\n") == 1
    assert frame.endswith(b"\n")
    assert json.loads(frame.decode())["payload"] == command
