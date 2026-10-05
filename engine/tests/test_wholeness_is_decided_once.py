"""Is the stored command whole? One predicate, or two callers that disagree.

THE BUG THIS LOCKS DOWN. `load_full_command` tested `command_clipped` alone;
the differential's `classify()` had a three-branch ladder — flag, then marker,
then bare length. Nine records in a real session predate the flag and carry only
the marker, so `load_full_command` took its early return and answered

    (SIDECAR_RECOVERED, <2058 bytes: 2048 plus the clip marker>)

**a wrong answer, not a missing one** — the single outcome the three-state
contract exists to rule out. `classify()` got those same nine right. Two callers,
one question, two answers.

Both now call `stored_command_is_whole`. These tests assert the ladder itself,
and then assert the two callers agree — on constructed records AND on every
record of the vendored fixture, so a future edit to either one fails here rather
than in a measurement six months later.

⚠ A DIGEST MISMATCH IS NOT EVIDENCE OF CLIPPING. The fixture is redacted, so its
text was rewritten after `command_sha256` was computed: 397 of 617 records
mismatch while only 203 are truly clipped. `test_redaction_does_not_read_as_
truncation` is that case, and it is why the hash can prove wholeness and never
disprove it.
"""
import hashlib
import json
from pathlib import Path

import pytest

from core import audit_log
from core.audit_log import (CLIP_MARKER, SIDECAR_ABSENT, SIDECAR_RECOVERED,
                             _MAX_COMMAND, load_full_command,
                             stored_command_is_whole)
from runner.replay_live import NO_CONTENT, TRUNCATED, classify

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "logs" / "live-fixture"


def record_for(original: str, **over) -> dict:
    """A record as `build_body` would write it, before any override.

    `original` is what the engine JUDGED; the overrides let a test rewrite the
    stored text afterwards, which is exactly what redaction does.
    """
    body = {
        "kind": "EXEC",
        "command": (original if len(original) <= _MAX_COMMAND
                    else original[:_MAX_COMMAND] + CLIP_MARKER),
        "command_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
        "command_len": len(original),
        "command_clipped": len(original) > _MAX_COMMAND,
        "cwd": "/repo",
    }
    body.update(over)
    return body


# ==================================================== the ladder, rung by rung
def test_a_matching_digest_proves_wholeness():
    assert stored_command_is_whole(record_for("git status")) is True


def test_a_command_containing_the_marker_is_still_whole():
    """THE CASE THAT MOTIVATED THE MARKER NEVER BEING A SIGNAL. Content
    addressing settles it before the marker is ever consulted."""
    command = f"echo 'the log writes {CLIP_MARKER} when it truncates'"
    assert CLIP_MARKER in command
    assert stored_command_is_whole(record_for(command)) is True


def test_the_recorded_flag_decides_when_the_digest_cannot():
    """Redacted text, so the digest misses — the FACT in the record governs."""
    whole = record_for("git status", command="git status REDACTED",
                       command_clipped=False)
    assert stored_command_is_whole(whole) is True
    cut = record_for("git status", command="git status REDACTED",
                     command_clipped=True)
    assert stored_command_is_whole(cut) is False


def test_the_marker_decides_for_records_predating_the_flag():
    """THE NINE. No flag at all, so the marker is the only thing left."""
    nine = {"kind": "EXEC", "command": "x" * _MAX_COMMAND + CLIP_MARKER,
            "command_sha256": "0" * 64}
    assert nine.get("command_clipped") is None
    assert stored_command_is_whole(nine) is False


def test_length_decides_for_records_predating_flag_and_marker():
    old = {"kind": "EXEC", "command": "x" * _MAX_COMMAND}
    assert stored_command_is_whole(old) is False


def test_a_record_that_cannot_say_says_so():
    assert stored_command_is_whole({"kind": "EXEC", "command": None}) is None
    assert stored_command_is_whole({"kind": "EXEC", "command": "git status"}) is None


def test_redaction_does_not_read_as_truncation():
    """A whole command whose bytes were rewritten after the digest was taken.
    Reading the mismatch as truncation would mislabel 194 fixture records."""
    redacted = record_for("cd /Users/alice/x && git status",
                          command="cd /Users/dev/x && git status",
                          command_clipped=False)
    assert hashlib.sha256(redacted["command"].encode()).hexdigest() != \
        redacted["command_sha256"]
    assert stored_command_is_whole(redacted) is True


# ==================================================== the two callers agree
def test_the_nine_are_no_longer_reported_as_recovered(tmp_path):
    """The exact defect: truncated text labelled SIDECAR_RECOVERED."""
    nine = {"kind": "EXEC", "command": "x" * _MAX_COMMAND + CLIP_MARKER,
            "command_sha256": "0" * 64, "cwd": "/repo"}
    state, text = load_full_command(nine, tmp_path / "s.log.jsonl")
    assert state == SIDECAR_ABSENT, "truncated text must not be RECOVERED"
    assert text is None


@pytest.mark.parametrize("record", [
    record_for("git status"),
    record_for(f"echo '{CLIP_MARKER}'"),
    record_for("y" * (_MAX_COMMAND * 2)),
    record_for("git status", command="git status REDACTED", command_clipped=False),
    record_for("git status", command="git status REDACTED", command_clipped=True),
    {"kind": "EXEC", "command": "x" * _MAX_COMMAND + CLIP_MARKER,
     "command_sha256": "0" * 64, "cwd": "/repo"},
    {"kind": "EXEC", "command": "x" * _MAX_COMMAND, "cwd": "/repo"},
])
def test_classify_and_load_full_command_never_disagree(record, tmp_path):
    """THE ANTI-DIVERGENCE PROPERTY, stated as one biconditional.

    `classify` says TRUNCATED  <->  `load_full_command` cannot return the whole
    text. Anything else means one of them is answering a question the other is
    answering differently, which is how the nine happened.
    """
    log = tmp_path / "s.log.jsonl"
    klass, _cmd = classify(record, log)
    state, _text = load_full_command(record, log)
    if klass == NO_CONTENT:
        pytest.skip("wholeness is not consulted for WRITE/EDIT")
    assert (klass == TRUNCATED) == (state != SIDECAR_RECOVERED), (
        f"classify={klass} but load_full_command={state}")


def fixture_records():
    for log in sorted(FIXTURE.glob("*.jsonl")):
        for line in log.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("event") == "decision" and record.get("command") is not None:
                yield record, log


def test_no_recovered_text_is_ever_truncated_across_the_fixture():
    """THE DEFECT ITSELF, over 617 real records and stated without reference to
    the predicate that fixes it.

    A returned text ending in CLIP_MARKER is the observable symptom of the nine:
    `load_full_command` claimed SIDECAR_RECOVERED and handed back 2048 bytes plus
    the marker. This test would have caught them and does not depend on
    `stored_command_is_whole` being right, which is what keeps it honest.
    """
    if not FIXTURE.is_dir():
        pytest.skip("no vendored fixture")
    lying = [(r.get("seq"), len(t))
             for r, log in fixture_records()
             for state, t in [load_full_command(r, log)]
             if state == SIDECAR_RECOVERED and t and t.endswith(CLIP_MARKER)]
    assert not lying, f"{len(lying)} records returned truncated text as RECOVERED: {lying[:5]}"


def test_the_two_agree_whenever_the_record_CAN_say():
    """The anti-divergence property, over real records, correctly scoped.

    ⚠ IT IS NOT AN UNCONDITIONAL BICONDITIONAL — that version failed on 384 of
    617 records, and the failure was the test's, not the code's. Those 384 have
    `stored_command_is_whole is None`: no digest match (redaction), no flag, no
    marker, under the length. The two callers then answer DIFFERENT questions
    and are both right to:

        classify            "should I compare this?"  -> yes, unknown is not
                                                         proof of truncation
        load_full_command   "can I hand you the exact
                             judged text, provably?"  -> no, I cannot prove it

    Conflating those is the same error as reading a digest mismatch as
    truncation. The property only binds where the record actually answers.
    """
    if not FIXTURE.is_dir():
        pytest.skip("no vendored fixture")
    checked = disagreed = 0
    for record, log in fixture_records():
        if stored_command_is_whole(record) is None:
            continue
        klass, _cmd = classify(record, log)
        if klass == NO_CONTENT:
            continue
        state, _text = load_full_command(record, log)
        checked += 1
        if (klass == TRUNCATED) != (state != SIDECAR_RECOVERED):
            disagreed += 1
    assert checked > 100, f"too few records that can say: {checked}"
    assert disagreed == 0, f"{disagreed} of {checked} records disagree"


def test_the_marker_is_still_not_a_signal_on_its_own():
    """`stored_command_is_whole` consults the marker ONLY when there is no
    digest match and no flag. A short command carrying the marker with a valid
    digest must never be called truncated — the courtesy stays a courtesy."""
    command = f"echo {CLIP_MARKER}"
    assert audit_log.build_body(
        session_id="s", seq=1, event="decision", kind="EXEC", decision="ALLOW",
        rule_id=None, reason="", paths=(), command=command,
    )["command_clipped"] is False
    assert stored_command_is_whole(record_for(command)) is True
