"""Truncation is a FACT in the record, not a marker inside the value.

WHY THIS EXISTS. `command` is clipped to `_MAX_COMMAND`, and for a long time the
only way to know that had happened was to string-match `…[clipped]` inside the
command itself. That is a signal living inside the thing it reports on, and it
fails in both directions:

  - a command that genuinely CONTAINS that text reads as truncated;
  - a reader who does not know the marker sees a complete-looking command.

It cost real analysis time. A clipped record lost the terminator of a heredoc, so
the stored command parsed differently from the one the engine actually judged —
and the truncation had to be INFERRED from a suffix rather than read off a field.

`command_len` and `command_clipped` are the signal. `CLIP_MARKER` is an
annotation for humans and nothing may branch on it.
"""
import json

import pytest

from core.audit_log import (CLIP_MARKER, _MAX_COMMAND, append, build_body,
                            read_records, verify_chain)


@pytest.fixture
def log(tmp_path):
    return tmp_path / "s1.log.jsonl"


def body_for(command):
    return build_body("s1", seq=1, event="decision", decision="deny",
                      kind="EXEC", command=command)


# ===================================================== the fields themselves
def test_a_short_command_is_recorded_as_not_clipped():
    body = body_for("git push origin main")
    assert body["command_clipped"] is False
    assert body["command_len"] == len("git push origin main")
    assert body["command"] == "git push origin main"


def test_a_long_command_is_recorded_as_clipped_with_its_TRUE_length():
    command = "x" * (_MAX_COMMAND + 5000)
    body = body_for(command)
    assert body["command_clipped"] is True
    assert body["command_len"] == _MAX_COMMAND + 5000, (
        "the full length must survive even though the full text does not — it is "
        "how you know how much is missing before going to look for it")
    assert len(body["command"]) < body["command_len"]


def test_a_command_exactly_at_the_limit_is_not_clipped():
    """The boundary, both sides — an off-by-one here would misreport every
    record of exactly the limit length."""
    assert body_for("x" * _MAX_COMMAND)["command_clipped"] is False
    assert body_for("x" * (_MAX_COMMAND + 1))["command_clipped"] is True


def test_no_command_yields_none_not_false():
    """`False` would claim "a command that was not clipped"; there is no command.
    A READ action has none, and conflating the two would make every non-EXEC
    record look like it carried an untruncated command."""
    body = build_body("s1", seq=1, event="decision", decision="allow",
                      kind="READ", paths=("/repo/.env",))
    assert body["command_clipped"] is None
    assert body["command_len"] is None
    assert body["command"] is None


# ===================================================== the marker is not a signal
def test_a_command_containing_the_marker_is_not_reported_as_clipped():
    """THE CASE THAT MOTIVATED E. Under the old string-match test this command
    reads as truncated; it is complete."""
    command = f"echo 'the log writes {CLIP_MARKER} when it truncates'"
    body = body_for(command)
    assert CLIP_MARKER in body["command"]
    assert body["command_clipped"] is False
    assert body["command_len"] == len(command)


def test_a_genuinely_clipped_command_is_flagged_even_without_the_marker():
    """The other direction: the flag must not depend on the marker surviving.
    Whatever the value looks like, the boolean is computed from the true length."""
    body = body_for("y" * (_MAX_COMMAND * 3))
    assert body["command_clipped"] is True


# ===================================================== inside the chain
def test_the_clip_fields_are_covered_by_the_hash(log):
    """Both are inside the hashed body, so a tamperer cannot quietly relabel a
    truncated command as complete — which is exactly what someone hiding what
    was judged would want to do."""
    append("s1", body_for("z" * (_MAX_COMMAND + 100)), path=log)
    assert verify_chain(log)[0] is True

    records = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    assert records[0]["command_clipped"] is True
    records[0]["command_clipped"] = False
    log.write_text(json.dumps(records[0], sort_keys=True) + "\n")
    ok, bad, _detail = verify_chain(log)
    assert ok is False, "relabelling a clipped command as complete must break the chain"
    assert bad == 1


def test_command_len_is_covered_by_the_hash(log):
    append("s1", body_for("z" * (_MAX_COMMAND + 100)), path=log)
    records = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    records[0]["command_len"] = 12
    log.write_text(json.dumps(records[0], sort_keys=True) + "\n")
    assert verify_chain(log)[0] is False


def test_the_sha256_still_covers_the_FULL_command(log):
    """E does not replace `command_sha256`; it explains it. The hash proves WHICH
    string was judged, the flag says the stored copy is not that string."""
    import hashlib
    command = "w" * (_MAX_COMMAND + 77)
    body = body_for(command)
    assert body["command_sha256"] == hashlib.sha256(command.encode()).hexdigest()
    assert body["command_clipped"] is True
