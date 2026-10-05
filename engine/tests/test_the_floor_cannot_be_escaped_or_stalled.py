"""Security review of item C: the floor could be escaped, and it could be stalled.

⚠ ESCAPED (CRITICAL). The Edit check of ~/.claude/settings.json and of every
other settings layer matched literal words (`disableAllHooks`, `STING_…`,
`"hooks"`) in the edit's raw text. JSON spells any character as `\\uXXXX`, so
`"disable\\u0041llHooks": true` passed the check, and Claude Code, parsing the
file, read `disableAllHooks`. The same text through a shell write, the registry
policy value or `claude --settings` passed the same way. The Write check parses
real JSON and was never affected.

⚠ STALLED (CRITICAL). The new readers re-scanned the rest of a segment once per
match: `tee tee tee …`, `rm rm rm …`, a `pkill -f` pattern repeating
`daemon/server.py`, a run of `claude`, `reg add`, `install.py` or `schtasks`
words. Quadratic, so a command of tens of KB outran Claude Code's hook timeout,
and a timed-out hook renders no decision (docs/93): the WHOLE guard, not only
this rule, fails open. Each is now read once per segment.
"""
from __future__ import annotations

import os
import signal
import stat
import time
from pathlib import Path

import pytest

import install
from core import engine
from core.probes import NullWorld
from core.session import SessionState
from core.types import Action, ActionKind, Decision
from tests.test_engine_sources import FakeWorld, act

RULE = "installed_guard:guard_selfmod"
SETTINGS = "/Users/dev/.claude/settings.json"
LAYER = "/work/repo/.claude/settings.local.json"
A = "\\u0041"            # `A`, as JSON spells it
I = "\\u0049"            # `I`


def decide(action):
    state = SessionState("t")
    state.seq = 1
    return engine.decide(action, state, FakeWorld())


def denied(verdict):
    return verdict.decision is Decision.DENY and verdict.rule_id == RULE


# ═════════════════════════════════════════════════════ escaped by \\uXXXX

ESCAPED_EDITS = {
    "disableAllHooks": ('"model": "opus"', f'"model": "opus", "disable{A}llHooks": true'),
    "STING_OBSERVE": ('"NODE_ENV": "test"', f'"ST{I}NG_OBSERVE": "1", "NODE_ENV": "test"'),
    "the hooks key": ('"model": "opus"', '"model": "opus", "hook\\u0073": {}'),
    "PYTHONPATH": ('"NODE_ENV": "test"', '"PYTHONP\\u0041TH": "/tmp/py"'),
}


@pytest.mark.parametrize("name", ESCAPED_EDITS)
def test_an_escaped_key_is_the_key_in_the_user_settings(name):
    old, new = ESCAPED_EDITS[name]
    action = act(ActionKind.EDIT, paths=(SETTINGS,), content=new, replaced=old)
    assert denied(decide(action)), name


@pytest.mark.parametrize("name", ["disableAllHooks", "STING_OBSERVE"])
def test_an_escaped_key_is_the_key_in_any_layer(name):
    old, new = ESCAPED_EDITS[name]
    action = act(ActionKind.EDIT, paths=(LAYER,), content=new, replaced=old)
    assert denied(decide(action)), name


@pytest.mark.parametrize("command", [
    "echo '{\"disable" + A + "llHooks\": true}' > .claude/settings.local.json",
    "echo '{\"env\": {\"ST" + I + "NG_OBSERVE\": \"1\"}}' > .claude/settings.local.json",
    "claude -p x --settings '{\"disable" + A + "llHooks\": true}'",
    "reg add \"HKCU\\SOFTWARE\\Policies\\ClaudeCode\" /v Settings /d "
    "\"{\\\"disable" + A + "llHooks\\\":true}\" /f",
])
def test_an_escaped_key_is_the_key_in_shell_text(command):
    assert denied(decide(act(ActionKind.EXEC, command=command, cwd="/work/repo"))), command


# ═════════════════════════════════════════════════════════════ stalled

# ⚠ GROWTH, NOT A WALL-CLOCK BOUND (item E of fix/agents-block-and-env-reads,
# docs/110 §E). This asserted `< 2.0 s` per whole decide, and `schtasks-words`
# crossed it under a full suite's load (2.14 s; 1.75 s alone) — because it was
# QUADRATIC: `SERVICE_STOP`'s lazy `schtasks … /End` re-read the line from every
# `schtasks` (0.49 / 1.74 / 6.9 s at 4 / 8 / 16 thousand words). A load-proof
# check is the ratio: four times the text, about four times the time, never
# sixteen. The 10 s alarm below still catches a stall outright.
GROWTH = 8
SLACK_SECONDS = 0.1


class _TooSlow(Exception):
    pass


def _decide_seconds(command: str) -> float:
    """Wall time of one decide, cut off at 10 s so a quadratic run fails fast."""
    state = SessionState("t")
    state.seq = 1
    action = Action("t", 1, ActionKind.EXEC, (), command, None, "Bash", None,
                    "/repo", ("/repo",), "claude-code")

    def cut(*_):
        raise _TooSlow

    previous = signal.signal(signal.SIGALRM, cut)
    signal.alarm(10)
    start = time.perf_counter()
    try:
        engine.decide(action, state, NullWorld())
    except _TooSlow:
        return 10.0
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    return time.perf_counter() - start


STALLS = {
    # security review 2b: an ordinary-looking run of one verb
    "tee-words": "tee " * 5000 + "/tmp/end",
    "sed-words": "sed " * 5000 + "-i x",
    "rm-words": "rm " * 6000 + "x",
    # security review 2a: a long pattern repeating the daemon's name
    "pkill-pattern": 'pkill -f "' + "x" * 8 + "-daemon/server.py" * 4000 + '"',
    # the same shape in every other new reader
    "claude-words": "claude " * 8000,
    "registry-words": "reg add " * 6000 + "Policies\\ClaudeCode",
    "install-py-words": "install.py " * 6000 + "x",
    "schtasks-words": "schtasks " * 8000,
}


@pytest.mark.parametrize("shape", list(STALLS))
def test_a_long_command_cannot_stall_the_floor(shape):
    full = STALLS[shape]
    small = min(_decide_seconds(full[: len(full) // 4]) for _ in range(3))
    large = min(_decide_seconds(full) for _ in range(3))
    assert large < GROWTH * small + SLACK_SECONDS, (shape, small, large)


def test_one_read_per_segment_still_sees_every_write():
    """The first verb of its kind in a segment reads every word after it, so a
    write named after a decoy of the same verb is still caught."""
    for command in ("tee /tmp/a tee ~/.sting/env",
                    "rm /tmp/a rm ~/.sting/env",
                    "sed -n p /tmp/a sed -i s/a/b/ ~/.sting/env",
                    "curl -o /tmp/a https://x curl -o ~/.sting/env https://x"):
        assert denied(decide(act(ActionKind.EXEC, command=command, cwd="/repo"))), command


# ════════════════════════════════════════ the D1 backup is never exposed

def test_the_backup_is_created_private_before_anything_is_written(tmp_path, monkeypatch):
    """`shutil.copy2` creates the copy under the umask and narrows it after:
    a 0600 config spent a moment as a world-readable copy."""
    config = tmp_path / "settings.json"
    config.write_text("{not json", encoding="utf-8")
    config.chmod(0o600)
    opened = []
    real_open = os.open

    def spy(path, flags, mode=0o777, *args, **kwargs):
        opened.append((str(path), flags, mode))
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    old_umask = os.umask(0)
    try:
        backup = install._backup(config)
    finally:
        os.umask(old_umask)
    created = [(flags, mode) for path, flags, mode in opened if path == str(backup)]
    assert created, "the backup was not created through os.open"
    flags, mode = created[0]
    assert flags & os.O_EXCL and flags & os.O_CREAT and mode == 0o600
    assert stat.S_IMODE(Path(backup).stat().st_mode) == 0o600
    assert Path(backup).read_text(encoding="utf-8") == "{not json"


# ══════════════════ python review: a redirect before the operand, and a glob

@pytest.mark.parametrize("command", [
    "rm 2>&1 ~/.sting/env",
    "rm -f 2>&1 ~/.local/share/sting/current/daemon/server.py",
    "mv 2>&1 ~/.sting/env /tmp/x",
    "cp 2>&1 /tmp/x ~/.sting/env",
    "rm &>/dev/null ~/.sting/policy.json",
])
def test_a_redirect_before_the_operand_hides_nothing(command):
    """`rm 2>&1 x` deletes x: the `&` of a redirect ends no command, and the
    delete and copy readers stopped at it."""
    assert denied(decide(act(ActionKind.EXEC, command=command, cwd="/repo"))), command


@pytest.mark.parametrize("command", [
    "rm -rf .github/hooks/*",
    "rm -rf /work/repo/.github/*",
    "rm -f .github/hooks/hoo*.json",
])
def test_a_glob_reaches_copilots_hook_config_in_any_project(command):
    assert denied(decide(act(ActionKind.EXEC, command=command, cwd="/work/repo"))), command


def test_a_bare_star_does_not_reach_a_dot_directory():
    """Bash's `*` matches no leading dot (no dotglob), so `rm -rf *` in a
    project leaves `.github` alone and is not the guard's business."""
    verdict = decide(act(ActionKind.EXEC, command="rm -rf *", cwd="/work/repo"))
    assert verdict.rule_id != RULE, verdict
