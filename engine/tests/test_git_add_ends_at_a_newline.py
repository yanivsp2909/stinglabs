"""`git add` ends where its segment ends — a newline included (item D).

⚠ THE BUG. `_GIT_ADD` captured its paths with `(.+?)(?:&&|;|\\||$)`. `.` does not
cross a newline and `$` (no MULTILINE) matches only at the very end, so
`git add debug/cfg.txt<newline>echo ok` matched NOTHING: the tainted file was
never recorded in `state.staged_secret_files`. That list is what
`_staged_secret_level` falls back to when git cannot be inspected, so the next
`git commit` went ALLOW where the `&&`, `;` and `|` spellings DENY. A
`git add \\<newline>path` continuation lost it the same way.

The fix builds the capture from the shared `_NOT_SEGMENT_END` atom (which
crosses a line continuation and stops at a bare newline) and ends it at any
segment separator. Allowed moves: ALLOW -> ASK/DENY only.
"""
from __future__ import annotations

import pytest

from core import engine
from core.probes import NullWorld
from core.types import Action, ActionKind, SessionState

ROOT = "/work/repo"
TAINTED = f"{ROOT}/debug/cfg.txt"
NL = "\n"
CONT = "\\" + "\n"


def ex(command: str, seq: int) -> Action:
    return Action("s", seq, ActionKind.EXEC, (), command, None, None, None,
                  ROOT, (ROOT,), "claude-code")


def add_then_commit(add_command: str) -> tuple[list[str], tuple[str, str | None]]:
    state = SessionState(session_id="s", seq=5)
    state.workspace_roots = [ROOT]
    state.scratch_roots = []
    state.taint(TAINTED, "exact", 3)
    engine.decide(ex(add_command, 5), state, NullWorld())
    staged = list(state.staged_secret_files)
    state.seq = 6
    world = NullWorld()
    assert world.staged_files(ROOT) is None, "precondition: git cannot be inspected"
    v = engine.decide(ex("git commit -m wip", 6), state, world)
    return staged, (v.decision.value, v.rule_id)


DENIED = ("DENY", "secret_exact:git_commit")


@pytest.mark.parametrize("command", [
    "git add debug/cfg.txt" + NL + "echo ok",
    "git add debug/cfg.txt" + NL + "git add README.md",
    "git add " + CONT + "debug/cfg.txt",
])
def test_a_newline_or_continuation_after_git_add_still_records_the_file(command):
    """Was ALLOW on main (staged=[]); now the same DENY as the one-line forms."""
    staged, commit = add_then_commit(command)
    assert staged == [TAINTED]
    assert commit == DENIED


@pytest.mark.parametrize("command", [
    "git add debug/cfg.txt",
    "git add debug/cfg.txt && echo ok",
    "git add debug/cfg.txt ; echo ok",
    "git add debug/cfg.txt | cat",
    "git add debug/cfg.txt" + NL,
    "git add debug/cfg.txt & wait",
    "git add -v debug/cfg.txt README.md && git status",
])
def test_every_form_caught_before_is_still_caught(command):
    staged, commit = add_then_commit(command)
    assert TAINTED in staged
    assert commit == DENIED


def test_a_later_line_is_not_read_as_a_staged_path():
    captured = [m.group(1).split() for m in engine._GIT_ADD.finditer(
        "git add a b" + NL + "rm -rf c")]
    assert captured == [["a", "b"]]


def test_git_add_is_built_from_the_shared_boundary_atom():
    assert engine._NOT_SEGMENT_END in engine._GIT_ADD.pattern
