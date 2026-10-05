"""A chain written on Windows must verify on macOS, and the reverse.

⚠ WHY THIS IS THE TEST THAT DECIDES WHETHER LOG BUNDLES CAN TRAVEL AT ALL.
A second developer on Windows produces logs that get read here. If a line
terminator reached the hash, his chain would read as TAMPERED on this machine —
which is the worst possible failure shape, because "tampered" is the one word
this log exists to be trusted about. A false alarm there costs more than no
alarm at all.

THE PROPERTY, and it holds by construction rather than by luck:

    record_hash(prev, body) = sha256(prev + canonical(body))

`canonical()` is `json.dumps(sort_keys=True, separators=(",",":"),
ensure_ascii=True)` over the record BODY — the line terminator is not in it and
cannot be. The file's `\\n` is a framing byte the hash never sees.

Both sides of the I/O agree with that:

    write  core/audit_log.py  `os.write(fd, (json.dumps(...) + "\\n").encode())`
    read   core/audit_log.py  `os.open(O_RDONLY)` + `os.read`

Raw file descriptors, not the builtin `open()` in text mode — so Python's
newline translation, which is what differs between platforms, is never in the
path in either direction.

⚠ IF THIS TEST EVER FAILS, DO NOT FIX IT BY NORMALISING AT VERIFICATION TIME.
Stripping `\\r` before hashing would make the verifier accept bytes the writer
did not write, which is exactly the property the chain exists to deny. The fix
would have to be at the writer.
"""
from __future__ import annotations

import json

import pytest

from core import audit_log


def _one_record() -> tuple[dict, str]:
    body = audit_log.build_body(
        "s-platform", seq=1, event="decision", decision="ALLOW", kind="EXEC",
        command="git status", cwd="/repo", agent="cursor", ts=1_700_000_000.0)
    entry = dict(body)
    entry["prev"] = audit_log.GENESIS
    entry["hash"] = audit_log.record_hash(audit_log.GENESIS, body)
    return entry, json.dumps(entry, sort_keys=True)


TERMINATORS = {
    "posix_LF": b"\n",
    "windows_CRLF": b"\r\n",
    "old_mac_CR": b"\r",
}


def test_the_hashed_bytes_contain_no_line_terminator():
    """The root of the property. If this ever gains a `\\n`, everything below
    it becomes platform-dependent."""
    body, _ = _one_record()
    canonical = audit_log.canonical(
        {k: v for k, v in body.items() if k not in ("prev", "hash")})
    assert "\n" not in canonical
    assert "\r" not in canonical


@pytest.mark.parametrize("name", sorted(TERMINATORS))
def test_a_record_verifies_under_any_line_terminator(tmp_path, name):
    entry, line = _one_record()
    path = tmp_path / f"{name}.log.jsonl"
    # Written as BYTES so the terminator is ours, not the platform's — this test
    # must assert the same thing when it runs on Windows.
    path.write_bytes(line.encode("utf-8") + TERMINATORS[name])

    records = audit_log.read_records(path)
    assert len(records) == 1, f"{name}: {len(records)} records"

    ok, bad, detail = audit_log.verify_chain(path)
    assert ok, f"{name}: chain broken at {bad} — {detail}"

    got = records[0]
    recomputed = audit_log.record_hash(
        got["prev"], {k: v for k, v in got.items() if k not in ("prev", "hash")})
    assert recomputed == got["hash"], name


def test_every_terminator_parses_to_the_identical_record(tmp_path):
    """THE CROSS-PLATFORM CLAIM ITSELF: his file and mine differ in framing
    bytes and in nothing the chain reads."""
    entry, line = _one_record()
    parsed = {}
    for name, term in TERMINATORS.items():
        path = tmp_path / f"{name}.log.jsonl"
        path.write_bytes(line.encode("utf-8") + term)
        parsed[name] = audit_log.read_records(path)[0]

    first = parsed["posix_LF"]
    for name, record in parsed.items():
        assert record == first, f"{name} parsed differently"
        assert record["hash"] == first["hash"], f"{name} hashed differently"


def test_the_writer_does_not_go_through_text_mode(tmp_path, monkeypatch):
    """A regression guard on the mechanism, not just the outcome.

    If `append()` were ever changed to the builtin `open()` in text mode, this
    test would still pass on macOS and fail only on Windows — i.e. only on the
    machine nobody runs the suite on. So assert the bytes directly: exactly one
    `\\n`, no `\\r`, whatever platform wrote them.
    """
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    body = audit_log.build_body("s-bytes", seq=1, event="decision",
                                decision="ALLOW", ts=1_700_000_000.0)
    audit_log.append("s-bytes", body)
    path = audit_log.default_log_path("s-bytes")
    raw = path.read_bytes()
    assert raw.count(b"\n") == 1
    assert b"\r" not in raw, "a CR reached the log file — text mode is in the path"
