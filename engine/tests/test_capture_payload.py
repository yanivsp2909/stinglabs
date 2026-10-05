"""The capture wrapper: records the payload, and never touches the verdict.

⚠ IT WRITES A SECOND COPY OF EVERYTHING, OUTSIDE THE TIER SYSTEM. On a real
session the raw stdin is the developer's commands and, for read events, file
contents — with no `verdict` tier, no redaction and no agreement behind it. So
the tests below are as much about it staying OFF and staying PRIVATE as about it
working.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
TOOL = ROOT / "tools" / "capture_payload.py"

PAYLOAD = json.dumps({"session_id": "cap", "cwd": "/tmp",
                       "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "echo hi"}})


def run(tmp_path, capture: bool):
    env = {**os.environ,
           "STING_CAPTURE_DIR": str(tmp_path / "out"),
           "STING_SESSION_ROOT": str(tmp_path / "s")}
    env.pop("STING_CAPTURE", None)
    if capture:
        env["STING_CAPTURE"] = "1"
    return subprocess.run([sys.executable, str(TOOL), "--agent", "cursor",
                            "--", "--agent", "claude-code"],
                           input=PAYLOAD, capture_output=True, text=True, env=env)


def files(tmp_path):
    return sorted((tmp_path / "out" / "cursor").glob("*.json"))


def test_it_records_nothing_unless_asked(tmp_path):
    """⚠ BEING WIRED IS NOT ENOUGH ON ITS OWN. A capture tool that records
    because somebody left it in a config is the failure this exists to warn
    about, so the opt-in is a separate, explicit act."""
    run(tmp_path, capture=False)
    assert not (tmp_path / "out").exists() or not files(tmp_path)


def test_it_records_the_raw_stdin_verbatim(tmp_path):
    """⚠ DECODED, NOT PARSED. Parsing it here would apply this repo's
    assumptions to the evidence meant to test them."""
    run(tmp_path, capture=True)
    written = files(tmp_path)
    assert len(written) == 1
    record = json.loads(written[0].read_text())
    assert record["stdin"] == PAYLOAD
    assert record["agent"] == "cursor"
    assert "exit" in record["hook"]


def test_the_capture_is_private_before_the_first_byte(tmp_path):
    """⚠ 0700/0600 SET AT CREATION, not after. Opening then chmod-ing leaves a
    window in which a file holding a developer's commands is world-readable —
    the same ordering bug the token file avoids."""
    run(tmp_path, capture=True)
    directory = tmp_path / "out" / "cursor"
    assert oct(directory.stat().st_mode)[-3:] == "700"
    for f in files(tmp_path):
        assert oct(f.stat().st_mode)[-3:] == "600"


@pytest.mark.parametrize("capture", [True, False])
def test_the_verdict_passes_through_untouched(tmp_path, capture):
    """The hook is spawned either way; this must be transparent to it."""
    wrapped = run(tmp_path, capture=capture)
    direct = subprocess.run(
        [sys.executable, str(ROOT / "hook_entry.py"), "--agent", "claude-code"],
        input=PAYLOAD, capture_output=True, text=True,
        env={**os.environ, "STING_SESSION_ROOT": str(tmp_path / "s2")})
    assert wrapped.returncode == direct.returncode
    assert wrapped.stdout == direct.stdout


def test_a_capture_failure_never_fails_the_hook(tmp_path):
    """⚠ A CAPTURE TOOL THAT CAN BLOCK A TOOL CALL IS WORSE THAN NO FIXTURE.
    Pointed at a path that cannot be created, the verdict must still arrive."""
    env = {**os.environ, "STING_CAPTURE": "1",
           "STING_CAPTURE_DIR": "/nonexistent-root-xyz/nope",
           "STING_SESSION_ROOT": str(tmp_path / "s")}
    proc = subprocess.run([sys.executable, str(TOOL), "--agent", "cursor",
                            "--", "--agent", "claude-code"],
                           input=PAYLOAD, capture_output=True, text=True, env=env)
    assert proc.returncode == 0
    assert "capture failed" in proc.stderr
