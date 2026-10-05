"""No message the agent reads tells it how to switch the guard to observe mode
or off, and an agent may not run install.py in a way that changes the install
(item 2).

⚠ ESTABLISHED, NOT SUPPOSED (docs/108 §6). An agent running `python3
install.py --observe` was ALLOW, and the guard-crash message named that very
command to the model: "To keep working meanwhile: `python3 install.py
--observe` records and blocks nothing." So:

- the crash message says what broke and names no switch;
- an agent tool call that runs install.py is `DENY installed_guard:
  guard_selfmod`, the allow-once rule's family, in every session, unless every
  argument is `--status`, `--dry-run` or `--check-only`: the three that change
  nothing. Stricter only. A person's own terminal is not hooked, and the
  install's closing block and the README tell the person the way out.

Fakes only for the installer (tests/install_harness.py): a temp home,
`--no-supervisor`, the fake launchctl and systemctl.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from install_harness import SAFE, home, no_real_supervisor     # noqa: E402,F401

import hook_entry                                                # noqa: E402
import install                                                   # noqa: E402
from adapters import _common                                     # noqa: E402
from core import engine                                          # noqa: E402
from core.probes import NullWorld                                # noqa: E402
from core.types import Action, ActionKind, Decision, SessionState  # noqa: E402

ROOT = "/work/repo"
CHECKOUT = "/Users/someone/sting/sting-engine/install.py"
INSTALLED = "/Users/someone/.local/share/sting/current/install.py"

# What switches the guard to observe mode or off, in words an agent could act on.
SWITCHES = ("--observe", "STING_OBSERVE", "observe mode", "--uninstall", "allow_once",
            "policy.json")

CHANGES = [
    "python3 install.py",
    "python3 install.py --observe",
    "python3 install.py --enforce",
    "python3 install.py --yes --no-collector --no-supervisor",
    f"python3 {CHECKOUT} --observe",
    f"python3 {INSTALLED} --agent cursor",
    "cd ~/sting/sting-engine && python3 install.py --observe",
    "./install.py --observe",
    "sudo python3 install.py --observe",
    "bash -c 'python3 install.py --observe'",
    "uv run install.py --observe",
    "py -3 install.py --observe",
    "find . -name install.py -exec python3 {} \\;",
    "python3 install.py --status && python3 install.py --observe",
    # anything but the three, alone or together
    "python3 install.py --status --observe",
    "python3 install.py --dry-run --observe",
    "python3 install.py --dry-run --roots /work",
    "python3 install.py --help",
]

READS = [
    "python3 install.py --status",
    "python3 install.py --dry-run",
    "python3 install.py --check-only",
    "python3 install.py --status 2>&1 | tail -40",
    "python3 install.py --dry-run --check-only",
    f"python3 {INSTALLED} --status",
    "python3 install.py --status > status.txt",
    # naming the file is not running it
    "cat install.py",
    "grep -n STING_OBSERVE install.py",
    "git diff install.py",
    "git add install.py tests/test_install.py",
    "sed -n '1,40p' install.py",
    "python3 -m pytest tests/test_install.py -q",
    "python3 tools/reinstall.py",
    "pip install -e .",
]


def clean() -> SessionState:
    state = SessionState(session_id="s", seq=5)
    state.workspace_roots = [ROOT]
    state.scratch_roots = []
    return state


def untrusted() -> SessionState:
    state = clean()
    state.mark_untrusted(2, "issue", f"{ROOT}/ISSUE.md")
    return state


def holding() -> SessionState:
    state = clean()
    prints = sorted(engine.fingerprint_values("TOKEN=F4keT0k3nQ7vX2mZp9LtR4wY\n"))
    state.mark_secret(seq=1, path=f"{ROOT}/.env", how="content", fingerprints=prints)
    return state


def ex(command: str) -> Action:
    return Action("s", 5, ActionKind.EXEC, (), command, None, None, None,
                  ROOT, (ROOT,), "claude-code")


# ═══════════════════════════════════════ 1 · running install.py

@pytest.mark.parametrize("session", [clean, untrusted, holding],
                         ids=["clean", "untrusted", "holding-a-secret"])
@pytest.mark.parametrize("command", CHANGES)
def test_an_agent_running_install_py_is_refused_in_every_session(command, session):
    verdict = engine.decide(ex(command), session(), NullWorld())
    assert (verdict.decision, verdict.rule_id) == (
        Decision.DENY, "installed_guard:guard_selfmod"), command


@pytest.mark.parametrize("command", READS)
def test_reading_the_install_or_the_file_stays_allowed(command):
    verdict = engine.decide(ex(command), clean(), NullWorld())
    assert verdict.decision is Decision.ALLOW, (command, verdict.rule_id, verdict.reason)


# ⚠ REVIEW: allowed only when EVERY argument is --status, --dry-run or
# --check-only. A redirect and its target are not arguments, so a target that
# names install.py (`install.py.txt`) is not a run of it, and a redirect glued
# to an argument (`--status>f`) leaves the argument. Anything else is an
# argument, an empty one or a quoted `>` too.
EVERY_ARGUMENT_READS = [
    "python3 install.py --status > install.py.txt",
    "python3 tools/gen.py > install.py.txt",
    "python3 install.py --status>status.txt",
    "python3 install.py --dry-run 2> install.py.log",
    "python3 install.py --status --check-only >> install.py.out 2>&1",
    # these read the same before and after: they pin what stays
    "python3 install.py --status < answers.txt",
    "bash -c 'python3 install.py --status'",
    'bash -c "python3 install.py --status 2>&1"',
    "(python3 install.py --status)",
    'python3 "install.py" --status',
]
EVERY_ARGUMENT_CHANGES = [
    'python3 install.py --status ""',
    "python3 install.py --status '>' status.txt",
    # the same before and after
    "python3 install.py < answers.txt",
    "python3 install.py --status --dry-run --verbose",
    # ⚠ PYTHON REVIEW, MEDIUM: pinned, and stated in docs/108 §6. An argument
    # the shell computes is not one of the three, and a trailing comment is
    # read as arguments: refused on doubt, never allowed.
    "python3 install.py --status $EXTRA",
    "python3 install.py --status $(cat flags.txt)",
    "python3 install.py --status # a note",
]


@pytest.mark.parametrize("command", EVERY_ARGUMENT_READS)
def test_a_redirect_and_its_target_are_not_arguments(command):
    verdict = engine.decide(ex(command), clean(), NullWorld())
    assert verdict.decision is Decision.ALLOW, (command, verdict.rule_id, verdict.reason)


@pytest.mark.parametrize("command", EVERY_ARGUMENT_CHANGES)
def test_any_other_argument_is_refused(command):
    verdict = engine.decide(ex(command), clean(), NullWorld())
    assert (verdict.decision, verdict.rule_id) == (
        Decision.DENY, "installed_guard:guard_selfmod"), command


# ═══════════════════════════════════════ 2 · what the agent reads

def _model_reads(verdict) -> str:
    """Every adapter's model text is this one composer (docs/108 §6)."""
    return _common.told(verdict)


@pytest.mark.parametrize("command", ["python3 install.py --observe",
                                     "python3 install.py --uninstall",
                                     "python3 install.py"])
def test_the_refusal_names_no_way_to_observe_mode_or_off(command):
    verdict = engine.decide(ex(command), clean(), NullWorld())
    told = _model_reads(verdict)
    for switch in SWITCHES:
        assert switch not in verdict.reason, (switch, verdict.reason)
        assert switch not in told, (switch, told)


def test_the_crash_message_names_no_way_to_observe_mode_or_off(monkeypatch):
    """It is stderr on exit 2: every agent reads it (Claude Code gives it to
    the model). It still says what broke, and that no rule ran."""
    def boom(action, state, world):
        raise RuntimeError("engine exploded")
    monkeypatch.setattr(hook_entry.engine, "decide", boom)

    out, err, code = hook_entry.run(json.dumps(
        {"session_id": "crash-2", "cwd": "/tmp", "tool_name": "Bash",
         "tool_input": {"command": "ls"}}), agent="claude-code")

    assert code == 2 and out == ""
    assert "NOT a policy refusal" in err and "engine exploded" in err
    for switch in SWITCHES:
        assert switch not in err, (switch, err)


@pytest.mark.parametrize("argv", [["--status"],
                                  ["--dry-run", "--no-supervisor"],
                                  ["--check-only", "--no-supervisor"]])
def test_what_an_agent_may_still_run_names_no_way_to_observe_mode_or_off(argv, home,
                                                                          capsys):
    """The three runs an agent may still make print text it reads. An install
    first, into the temp home, so `--status` has settings to show."""
    assert install.main([*SAFE]) == 0
    capsys.readouterr()
    install.main(argv)
    out = capsys.readouterr().out
    for switch in ("--observe", "--uninstall", "observe mode"):
        assert switch not in out, (argv, switch)


def test_a_person_in_their_own_terminal_is_still_told(home, capsys):
    """Nothing is taken from the person: `install.py --help`, which an agent
    may not run, still names both modes."""
    with pytest.raises(SystemExit):
        install.main(["--help"])
    out = capsys.readouterr().out
    assert "--observe" in out and "--enforce" in out
