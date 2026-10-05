"""An agent may not run the guard's one-shot override, in any session.

⚠ ESTABLISHED, NOT SUPPOSED (docs/108 §3). With the engine alone, in a temp
home, a Claude Code `Bash` call running `python3 tools/allow_once.py --yes` was
ALLOW in a clean session, an untrusted one and one holding a secret, for the
checkout's copy and for the installed tree's. The refusal named that very
command, so an agent could arm its own grant and retry. `tools/allow_once.py`
says as much: "it does not stop a caller that passes `--yes`".

So running it is a change to the installed guard, the family that already
guards `~/.sting/policy.json`: DENY `installed_guard:guard_selfmod`, in every
session. A person in their own terminal is not hooked, and is not affected.

⚠ READING, LISTING AND COMMITTING THE FILE STAY ALLOWED: Sting is developed in
this repo, by agents. What the floor refuses is a segment that RUNS it: the
script as the command word, or after a word that runs what follows it (an
interpreter, a shell, a wrapper such as `sudo` or `uv run`), or the `-m` form.
"""
from __future__ import annotations

import pytest

from core import engine
from core.probes import NullWorld
from core.types import Action, ActionKind, Decision, SessionState

ROOT = "/work/repo"
INSTALLED = "/Users/someone/.local/share/sting/v1.0.4/tools/allow_once.py"

RUNS = [
    "python3 tools/allow_once.py --yes",
    f"python3 {INSTALLED} --yes",
    "python /work/sting/tools/allow_once.py",
    "python3.12 -B tools/allow_once.py --seq 7",
    "py -3 tools\\allow_once.py --yes",
    "./tools/allow_once.py --yes",
    "/Users/someone/.local/share/sting/current/tools/allow_once.py",
    "python3 -m tools.allow_once --yes",
    'python3 "tools/allow_once.py" --yes',
    "cd ~/.local/share/sting/current && python3 tools/allow_once.py --yes",
    "sh -c 'python3 tools/allow_once.py --yes'",
    'bash -lc "python3 tools/allow_once.py"',
    "echo $(python3 tools/allow_once.py --yes)",
    "env PYTHONPATH=. python3 tools/allow_once.py",
    "X=1 python3 tools/allow_once.py",
    "sudo python3 tools/allow_once.py --yes",
    "uv run tools/allow_once.py --yes",
    "python3 -c \"exec(open('tools/allow_once.py').read())\"",
    "true; python3 tools/allow_once.py --yes",
    "find tools -name allow_once.py -exec python3 {} --yes \\;",
    "direnv exec . python3 tools/allow_once.py --yes",
]

# Naming the file is not running it. What can still reach a grant is listed in
# docs/108 §3 (`python3 -c "import core.allow_once…"`, a copy under another
# name, a script written and then run).
STAYS = [
    "cat tools/allow_once.py",
    "grep -n GRANTED tools/allow_once.py",
    "git diff tools/allow_once.py",
    "git add tools/allow_once.py tests/test_allow_once_cli.py",
    "ls -la tools/allow_once.py",
    "wc -l tools/allow_once.py",
    "python3 -m pytest tests/test_allow_once.py -q",
    "python3 -m pytest tests/test_allow_once_cli.py -q",
    "echo 'see tools/allow_once.py'",
    "head -40 tools/allow_once.py | tail -5",
    # ⚠ FROM THE SNAPSHOT (docs/108): Sting is developed by agents, and these
    # name the file without running it. Refusing them would refuse the work.
    "sed -n '1,40p' tools/allow_once.py",
    "printf '%s\\n' tools/allow_once.py",
    "mkdir -p /tmp/x && cp tools/allow_once.py /tmp/x/",
    "mv tools/allow_once.py tools/allow_once.py.bak",
    "find tools -name allow_once.py",
    "gh pr create --title t --body-file /tmp/body.md",
    "for f in tools/allow_once.py tests/test_allow_once.py; do wc -l $f; done",
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


@pytest.mark.parametrize("session", [clean, untrusted, holding],
                         ids=["clean", "untrusted", "holding-a-secret"])
@pytest.mark.parametrize("command", RUNS)
def test_running_the_override_is_refused_in_every_session(command, session):
    verdict = engine.decide(ex(command), session(), NullWorld())
    assert (verdict.decision, verdict.rule_id) == (
        Decision.DENY, "installed_guard:guard_selfmod"), command


@pytest.mark.parametrize("command", STAYS)
def test_reading_or_committing_the_file_stays_allowed(command):
    verdict = engine.decide(ex(command), clean(), NullWorld())
    assert verdict.decision is Decision.ALLOW, (command, verdict.rule_id, verdict.reason)


def test_the_refusal_says_what_was_run_and_names_no_way_round_it():
    """⚠ RE-PINNED BY ITEM 3: this asserted "one-shot override" in the reason,
    which described the approval tool to the model; the refusal now says only
    that a part of the installed guard was run."""
    verdict = engine.decide(ex("python3 tools/allow_once.py --yes"), clean(), NullWorld())
    assert "part of the installed Sting guard" in verdict.reason
    assert "allow_once" not in verdict.reason
    assert "policy.json" not in verdict.reason


# What describes the one-time approval tool: what it is, what it does, and how
# a person uses it.
DESCRIBES_THE_TOOL = ("allow_once", "allow-once", "allow once", "one-shot", "one-time",
                      "override", "re-allow", "grant", "approv", "terminal")


@pytest.mark.parametrize("command", RUNS)
def test_the_refusal_does_not_describe_the_approval_tool(command):
    """⚠ ITEM 3. The floor's reason read "this runs the guard's one-shot
    override (allow-once), which re-allows an action the guard refused … You
    can do this yourself from your own terminal": the model learnt the tool
    exists, what it does, and where it works. Every agent's model text is the
    one composer, `adapters._common.told`, so both are read here."""
    from adapters import _common
    verdict = engine.decide(ex(command), clean(), NullWorld())
    for said in (verdict.reason.lower(), _common.told(verdict).lower()):
        for word in DESCRIBES_THE_TOOL:
            assert word not in said, (command, word, said)
