"""A project boundary narrower than the work over-denies, and does it silently.

⚠ THE MEASURED FAILURE. `secret_derived_external:write_outside` was 74 of 89
secret-rule denials — the largest single class in that period — and every one
was an ordinary edit to a SIBLING repository. Three repos under one parent,
`STING_ROOTS` unset, so `project_roots` resolved to the one git repo containing
cwd and every edit to the other two read as leaving the project.

IT IS A CONFIGURATION GAP, NOT A STRUCTURAL ONE, and that was checked rather
than assumed. Multi-root is representable end to end today:

    state.workspace_roots   a list
    is_inside_project       membership across ALL roots, not one prefix
    Cursor / Antigravity    both already send an ARRAY

Proven by construction below: with the sibling declared, the same edit that
denies is allowed. Nothing in the engine needed to change — which is exactly why
this is a preflight line and a test, and not a policy edit.

⚠ WHY A LOUD CHECK RATHER THAN A WIDER DEFAULT. Auto-widening to every sibling
repository would be the engine deciding what the developer trusts, and it would
do it from the shape of a directory listing. The boundary is a declaration. What
was wrong was that nothing ever asked for it, and nothing complained when it was
missing — in observe mode a narrow boundary does not even over-deny visibly, it
just writes wrong verdicts into a log nobody reads.
"""
from __future__ import annotations

import os

import pytest

from core import engine
from core.probes import NullWorld
from core.types import Action, ActionKind, SessionState

ENGINE = "/work/repo-a"
SIBLING = "/work/repo-b"
TARGET = f"{SIBLING}/src/render.py"


def tainted_session(roots) -> SessionState:
    """A session holding a credential, with the sibling's file already derived
    from it — the exact state the 74 were decided in."""
    state = SessionState(session_id="s", seq=5)
    state.mark_secret(seq=1, path=f"{ENGINE}/.env", how="content")
    state.tainted_paths = {TARGET: {"level": "derived", "from_seq": 2}}
    state.workspace_roots = list(roots)
    return state


def edit(roots) -> Action:
    return Action("s", 5, ActionKind.EDIT, (TARGET,), None, None, None,
                  "x = 1", ENGINE, tuple(roots), "claude-code")


def test_an_undeclared_sibling_is_denied():
    """Today's behaviour, pinned so the fix is measured against something."""
    roots = (ENGINE,)
    verdict = engine.decide(edit(roots), tainted_session(roots), NullWorld())
    assert verdict.decision is engine.Decision.DENY
    assert verdict.rule_id == "secret_derived_external:write_outside"


def test_declaring_the_sibling_allows_the_same_edit():
    """THE WHOLE CLASS, collapsed by a declaration. Same action, same session,
    same taint — only the declared boundary differs."""
    roots = (ENGINE, SIBLING)
    verdict = engine.decide(edit(roots), tainted_session(roots), NullWorld())
    assert verdict.decision is engine.Decision.ALLOW, verdict


def test_multi_root_membership_is_not_a_single_prefix_check():
    """The property that makes this configuration and not structure."""
    roots = (ENGINE, SIBLING, "/work/repo-c")
    assert engine.is_inside_project(f"{SIBLING}/a/b.py", roots)
    assert engine.is_inside_project(f"{ENGINE}/x.py", roots)
    assert not engine.is_inside_project("/work/other/x.py", roots)


# ------------------------------------------- what declaring must NOT reach

@pytest.mark.parametrize("target", [
    "/etc/paths",
    "/Users/someone/.zshrc",
    "/Users/someone/.local/bin/curl",       # H04's payload
    "/Users/shared/Dropbox/team-notes/env.txt",   # I05's payload
])
def test_declaring_siblings_never_covers_somebody_elses_directory(target):
    """THE STOP CONDITION, as a test. Two corpus attacks depend on
    write_outside for their catch — H04-modify-path and I05-shared-folder-write —
    and both write somewhere no project root can legitimately contain. Widening
    to declared siblings must not reach them."""
    roots = ("/work/repo-a", "/work/repo-b", "/work/repo-c")
    assert not engine.is_inside_project(target, roots)


def test_a_root_is_not_a_prefix_of_an_unrelated_sibling():
    """`/work/repo` must not swallow `/work/repo-backup` by string prefix —
    the bug a naive startswith() would introduce while "widening"."""
    assert not engine.is_inside_project("/work/repo-backup/x.py", ("/work/repo",))
    assert engine.is_inside_project("/work/repo/x.py", ("/work/repo",))


# -------------------------------------------------- the preflight guard

def test_preflight_flags_a_boundary_narrower_than_the_work(tmp_path, monkeypatch):
    """A narrow boundary must be LOUD. It does not crash and it does not block —
    it silently writes wrong verdicts, which in observe mode nobody sees."""
    from tools import preflight

    parent = tmp_path / "work"
    here, sibling = parent / "main", parent / "other"
    for d in (here, sibling):
        (d / ".git").mkdir(parents=True)

    monkeypatch.setattr(preflight, "ROOT", here)
    monkeypatch.setenv("STING_ROOTS", str(here))
    preflight._failed = 0
    preflight.check_trust_boundary()
    assert preflight._failed == 1, "an undeclared sibling repo was not reported"

    monkeypatch.setenv("STING_ROOTS", f"{here}:{sibling}")
    preflight._failed = 0
    preflight.check_trust_boundary()
    assert preflight._failed == 0, "a correctly declared boundary still failed"
