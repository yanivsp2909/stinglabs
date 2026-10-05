"""STING_OBSERVE — log every verdict, block nothing.

For a live RECORDING run: the agent must reach the end of an attack chain or the
trace you paid for is truncated at the first sink.
"""
import json

import pytest

import hook_entry
from core import engine
from core.audit_log import default_log_path, read_records
from core.types import Decision, Verdict


def payload(command="git push origin main", session="s1"):
    return json.dumps({"session_id": session, "cwd": "/tmp",
                       "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": command}})


@pytest.fixture
def denying(monkeypatch):
    monkeypatch.setattr(engine, "decide", lambda a, s, w: Verdict(
        Decision.DENY, "this carries data traced from .env (read at step 2)",
        "secret_exact:git_push"))


@pytest.fixture
def observe(monkeypatch):
    monkeypatch.setenv("STING_OBSERVE", "1")


# ------------------------------------------------------ the two named tests
def test_observe_never_emits_non_empty_stdout(denying, observe):
    """The whole contract. Non-empty stdout is how every adapter expresses a
    block; if observe ever emits one, the recording is truncated."""
    out, err, code = hook_entry.run(payload())
    assert out == ""
    assert code == 0


def test_the_log_still_records_the_true_deny(denying, observe):
    """Blocking nothing must not mean recording nothing. The verdict in the log
    is the engine's real one, not the rendered ALLOW."""
    hook_entry.run(payload())
    rec = [r for r in read_records(default_log_path("s1"))
           if r.get("event") == "decision"][0]
    assert rec["decision"] == "DENY"
    assert rec["rule_id"] == "secret_exact:git_push"
    assert rec["reason"].startswith("this carries data traced from")


# ---------------------------------------------------------------- behaviour
def test_it_is_loud_on_every_call(denying, observe):
    out, err, code = hook_entry.run(payload())
    assert "OBSERVE" in err
    assert "blocking nothing" in err
    assert "DENY" in err, "the note must say what the engine actually decided"


def test_an_ask_is_also_rendered_as_allow(monkeypatch, observe):
    monkeypatch.setattr(engine, "decide",
                        lambda a, s, w: Verdict(Decision.ASK, "confirm?", "r"))
    out, _, code = hook_entry.run(payload())
    assert (out, code) == ("", 0)


def test_labelling_still_happens(observe):
    """The point of a recording run: real session state, nothing blocked."""
    hook_entry.run(json.dumps({
        "session_id": "s1", "cwd": "/tmp", "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch", "tool_input": {"url": "https://example.com/x"}}))
    from core.session import load_session
    assert load_session("s1").untrusted, "a fetch must still taint the session"


def test_allow_once_is_not_consumed(denying, observe):
    """Nothing is being blocked, so there is nothing to override. Spending a
    grant here would burn it on an action that was never going to be stopped."""
    from core import allow_once
    a_hash = "deadbeef"
    allow_once.write_grant("s1", a_hash, granted_by="test")
    hook_entry.run(payload())
    assert allow_once.grant_path("s1").exists(), "the grant must still be armed"


# ------------------------------------------------------------- off by default
def test_enforcement_is_the_default(denying, monkeypatch):
    monkeypatch.delenv("STING_OBSERVE", raising=False)
    out, _, _ = hook_entry.run(payload())
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("value", ["", "0", "false", "no"])
def test_falsy_values_do_not_enable_it(denying, monkeypatch, value):
    """`STING_OBSERVE=0` must not silently disable the guard."""
    monkeypatch.setenv("STING_OBSERVE", value)
    out, _, _ = hook_entry.run(payload())
    assert out != "", f"observe wrongly enabled by {value!r}"


# ============================================ THE GUARANTEE, through main()
#
# run() fails CLOSED by design: exit 2 on unparseable input, an unknown agent,
# or any engine exception. Correct when enforcing; WRONG in observe, where
# exit 2 blocks the tool call. These go through the real subprocess, because
# that is the path Claude Code actually invokes.
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOOK = str(Path(__file__).parent.parent / "hook_entry.py")


def _run_hook(stdin_text, env_extra):
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "STING_SESSION_ROOT": tmp,
               "STING_LOG": str(Path(tmp) / "log.jsonl"), **env_extra}
        return subprocess.run([sys.executable, HOOK], input=stdin_text,
                               capture_output=True, text=True, env=env)


def _blocks(r):
    """Claude Code blocks on a non-zero exit OR a non-empty stdout verdict."""
    return r.returncode != 0 or bool(r.stdout.strip())


_PAYLOAD = json.dumps({"session_id": "s", "cwd": "/tmp",
                        "hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": "git push origin main"}})


@pytest.mark.parametrize("label,stdin_text", [
    ("benign", json.dumps({"session_id": "s", "cwd": "/tmp", "tool_name": "Bash",
                            "tool_input": {"command": "ls -la"}})),
    ("would-deny", _PAYLOAD),
    ("unparseable stdin", "{not json"),
    ("empty stdin", ""),
])
def test_observe_never_blocks_through_the_real_hook(label, stdin_text):
    r = _run_hook(stdin_text, {"STING_OBSERVE": "1"})
    assert not _blocks(r), f"{label}: exit={r.returncode} stdout={r.stdout!r}"


def test_observe_never_blocks_on_an_unknown_agent():
    """run() returns exit 2 here. Measured as BLOCKING before the guarantee."""
    r = _run_hook(_PAYLOAD, {"STING_OBSERVE": "1", "STING_AGENT": "nope"})
    assert not _blocks(r), f"exit={r.returncode}"


def test_observe_never_blocks_on_an_engine_crash(tmp_path):
    """The one that matters most for a week of real work: a bug in the engine
    must not stop the developer. Forced via sitecustomize."""
    root = Path(__file__).parent.parent
    (tmp_path / "sitecustomize.py").write_text(
        f'import sys\nsys.path.insert(0, {str(root)!r})\n'
        'import core.engine as e\n'
        'def boom(*a, **k): raise RuntimeError("forced")\n'
        'e.decide = boom\n')
    r = _run_hook(_PAYLOAD, {"STING_OBSERVE": "1",
                              "PYTHONPATH": f"{tmp_path}:{root}"})
    assert not _blocks(r), f"exit={r.returncode} stdout={r.stdout!r}"
    assert "OBSERVE suppressed" in r.stderr or "RuntimeError" in r.stderr


def test_the_failure_is_still_reported_on_stderr():
    """Suppressed, not hidden. A silent observe mode would be worse."""
    r = _run_hook("{not json", {"STING_OBSERVE": "1"})
    assert "sting:" in r.stderr


def test_enforce_still_fails_closed_on_the_same_inputs():
    """The guarantee must not leak into enforcement."""
    for stdin_text in ("{not json", _PAYLOAD):
        r = _run_hook(stdin_text, {"STING_AGENT": "nope"})
        assert r.returncode == 2, f"enforce must fail closed: {stdin_text[:20]}"
