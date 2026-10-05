"""`$(cat .env)` written INTO a test file is not `$(cat .env)` run.

WHY THIS FILE EXISTS. Two records in the vendored logs — `1f089cfa:465` and
`1f089cfa:473` — were recorded `DENY untrusted_unexpected:secret_in_argv` and are
ALLOWed by the current engine. A loosening in a security rule is the one
difference that must not stay unattributed, so it was bisected rather than
guessed at.

    recording-era engine   a24ecca   secret_in_argv fires on both
    first commit after it  352b5a6   "a code-vs-data scanner, and the per-rule
                                      split" — fires on neither

**The old verdict was a false positive and the narrowing is correct.** Both
commands are `python3 - <<'PYEOF'` heredocs holding TEST CASES, and every `.env`
and `$(` in them is inside a Python string literal:

    ("A01: $(cat .env) in a message", 'git commit -m "$(cat .env)"', …, True),
    ("described in a heredoc", "cat > t.py <<'PY'\\nc=['cp /r/.env /r/x']\\nPY", …)

Both parse cleanly and every one of those bytes is DATA. The engine was denying a
command whose only "secret in argv" was prose ABOUT a secret in argv — the same
text-vs-structure class as `_GUARD_SELFMOD` matching a directory name and
`propagate` reading a commit message as shell.

⚠ The joke, and the reason to keep the record: the commands it fired on are the
tests for the scanner that fixed it. The false positive was on the very change
that removed it.

The pair below pins BOTH directions, because narrowing a security rule is only
correct if the real thing still fires.
"""
import json
import re
from pathlib import Path

import pytest

from core import engine
from core.shell_scan import code_mask_checked
from core.types import Action, ActionKind, SessionState

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "logs" / "live-fixture"
PROJECT = "/Users/dev/sting/sting-engine"


class _World:
    def read_text(self, path): return None
    def staged_files(self, cwd): return None
    def staged_content(self, cwd): return None
    def is_dirty(self, cwd): return True
    def remotes(self, cwd): return ()
    def __getattr__(self, _name): return lambda *a, **k: None


def exec_action(command: str) -> Action:
    return Action(session_id="t", seq=1, kind=ActionKind.EXEC, paths=(),
                  command=command, url=None, tool_name="Bash", content=None,
                  cwd=PROJECT, workspace_roots=(PROJECT,), agent="claude-code")


# ===================================================== the shape, without the fixture
REAL = 'cd /r && git commit -m "$(cat .env)"'

PROSE = (
    "cd /r && python3 - <<'PYEOF'\n"
    "cases = [\n"
    '  ("A01: $(cat .env) in a message", \'git commit -m "$(cat .env)"\', True),\n'
    '  ("described in a heredoc", "cat > t.py <<\'PY\'\\nc=[\'cp /r/.env /r/x\']\\nPY", False),\n'
    "]\n"
    "PYEOF"
)


def test_a_real_subshell_read_of_a_credential_still_fires():
    """THE HALF THAT MATTERS MORE. A01 is exactly this command, and narrowing
    `secret_in_argv` is only defensible while this line stays green.

    The PREDICATE is asserted rather than `check_sinks`, because `git_commit` is
    a sink too and wins the ladder first — which would make a green test here say
    nothing at all about the rule this file is about.
    """
    state = SessionState()
    state.untrusted = True
    assert engine._secret_in_argv(state, exec_action(REAL), REAL) is True


def test_the_same_text_inside_a_heredoc_of_test_cases_does_not():
    state = SessionState()
    state.untrusted = True
    assert engine._secret_in_argv(state, exec_action(PROSE), PROSE) is False
    assert engine.check_sinks(state, exec_action(PROSE), _World()) != "secret_in_argv"


def test_every_credential_token_in_the_prose_case_is_data():
    """The mechanism, not just the outcome: it is the code mask that decides."""
    mask, parsed = code_mask_checked(PROSE)
    assert parsed, "the scanner must actually understand this command"
    hits = list(re.finditer(r"\.env|\$\(", PROSE))
    assert hits, "precondition: the text does contain credential tokens"
    assert not any(mask[m.start()] for m in hits), "none of them are executed"


# ===================================================== the two real records
RECORDS = (465, 473)


def recovered(seq: int) -> str | None:
    """The full command for a `1f089cfa` record, as the differential replays it."""
    from runner.replay_live import classify
    for log in sorted(FIXTURE.glob("*.jsonl")):
        for line in log.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if (record.get("session_id", "").startswith("1f089cfa")
                    and record.get("seq") == seq
                    and record.get("event") == "decision"):
                return classify(record, log)[1]
    return None


@pytest.mark.parametrize("seq", RECORDS)
def test_the_two_records_are_prose_about_secrets_not_secrets(seq):
    """Named individually so the baseline entry and this test cannot drift apart.

    Only reachable because these records were TRUNCATED until transcript
    recovery landed — the fixture could not see either of them before.
    """
    if not FIXTURE.is_dir():
        pytest.skip("no vendored fixture")
    command = recovered(seq)
    assert command, f"1f089cfa:{seq} not in the fixture"
    mask, parsed = code_mask_checked(command)
    assert parsed, f"1f089cfa:{seq} must parse for this to be a decision, not a guess"
    hits = list(re.finditer(r"\.env|\$\(", command))
    assert hits, f"1f089cfa:{seq} should contain credential tokens"
    executed = [m.group(0) for m in hits if m.start() < len(mask) and mask[m.start()]]
    assert not executed, f"1f089cfa:{seq} has credential tokens at a code position: {executed}"

    state = SessionState()
    state.untrusted = True
    assert engine.check_sinks(state, exec_action(command), _World()) is None
