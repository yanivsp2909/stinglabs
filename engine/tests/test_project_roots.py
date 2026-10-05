"""What counts as "the project", and what happens when we cannot tell.

The PreToolUse payload carries no workspace field — only `cwd`. So the adapter
filled in cwd alone, every sibling repository looked like it was outside the
project, and one real session denied 44 ordinary writes with the reason "this
destination leaves the machine". Worse, it did so silently: `workspace_roots`
was null for 181 actions and nothing said a word.

These tests clear STING_ROOTS, which conftest sets for the rest of the suite.
"""
import subprocess

import pytest

from core.probes import RealWorld


@pytest.fixture(autouse=True)
def no_override(monkeypatch):
    monkeypatch.delenv("STING_ROOTS", raising=False)


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                           text=True, env={"GIT_CONFIG_GLOBAL": "/dev/null",
                                           "GIT_CONFIG_SYSTEM": "/dev/null",
                                           "PATH": "/usr/bin:/bin:/usr/local/bin",
                                           "HOME": str(cwd)})


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "main"
    d.mkdir()
    git(d, "init", "-q")
    (d / "a.txt").write_text("x")
    git(d, "add", "-A")
    git(d, "-c", "user.email=a@b", "-c", "user.name=c", "commit", "-q", "-m", "init")
    return d


# ------------------------------------------------------------------- git shapes
def test_a_plain_repo_resolves_to_its_own_root(repo):
    roots, note = RealWorld().project_roots(str(repo))
    assert roots == (str(repo.resolve()),)
    assert note is None


def test_a_subdirectory_resolves_to_the_repo_root_not_itself(repo):
    """The point of the whole change: working in src/ must not make the rest of
    the repository 'outside the project'."""
    sub = repo / "src" / "deep"
    sub.mkdir(parents=True)
    roots, note = RealWorld().project_roots(str(sub))
    assert roots == (str(repo.resolve()),)
    assert note is None


def test_the_repo_root_is_used_NOT_its_parent(repo, tmp_path):
    """The failure mode that would have shipped. Taking the parent makes every
    unrelated sibling repository part of the project — for anyone who keeps
    their work under one directory, write_outside becomes unreachable. That
    trades a false positive for a false negative, and only one of those is
    visible when it happens."""
    sibling = tmp_path / "someone-elses-repo"
    sibling.mkdir()
    roots, _ = RealWorld().project_roots(str(repo))
    assert str(sibling.resolve()) not in roots
    assert str(tmp_path.resolve()) not in roots


def test_a_linked_worktree_resolves_to_the_worktree_not_the_main_checkout(repo, tmp_path):
    """A worktree is a different checkout, usually a different branch. Adding
    the main one would make an edit over there look like ordinary work here."""
    wt = tmp_path / "wt"
    if git(repo, "worktree", "add", "-q", str(wt), "-b", "wtb").returncode != 0:
        pytest.skip("git worktree unavailable")
    roots, note = RealWorld().project_roots(str(wt))
    assert roots == (str(wt.resolve()),)
    assert str(repo.resolve()) not in roots
    assert note is None


def test_a_submodule_resolves_to_the_outermost_superproject(repo, tmp_path):
    """A submodule is part of its parent and editing both is normal work.
    Bounded — it stops at the top of the nesting — unlike taking the parent
    directory, which has no bound at all."""
    sub = tmp_path / "sub"
    sub.mkdir()
    git(sub, "init", "-q")
    (sub / "b.txt").write_text("y")
    git(sub, "add", "-A")
    git(sub, "-c", "user.email=a@b", "-c", "user.name=c", "commit", "-q", "-m", "i")
    added = git(repo, "-c", "protocol.file.allow=always", "submodule", "add",
                "-q", str(sub), "vendor/sub")
    if added.returncode != 0:
        pytest.skip("submodule add unavailable in this environment")
    roots, note = RealWorld().project_roots(str(repo / "vendor" / "sub"))
    assert roots == (str(repo.resolve()),), roots
    assert note is None


def test_a_bare_repository_falls_back_and_says_why(tmp_path):
    """A bare repo has no working tree, so there is no project directory."""
    bare = tmp_path / "bare.git"
    git(tmp_path, "init", "-q", "--bare", str(bare))
    roots, note = RealWorld().project_roots(str(bare))
    assert roots == (str(bare.resolve()),)
    assert note and "bare repository" in note


def test_a_directory_outside_any_repo_falls_back_and_says_why(tmp_path):
    roots, note = RealWorld().project_roots(str(tmp_path))
    assert roots == (str(tmp_path.resolve()),)
    assert note and "not in a git repository" in note
    assert "STING_ROOTS" in note, "the note must say how to fix it"


def test_the_fallback_is_never_silent(tmp_path):
    """THE POINT. Silence is what let workspace_roots: null sit unnoticed
    through 181 actions while 44 writes were denied because of it."""
    _roots, note = RealWorld().project_roots(str(tmp_path))
    assert note


# --------------------------------------------------------------- STING_ROOTS
#
# ⚠ `os.pathsep`, NOT `":"`. The variable is a PATH-style list, so the test has
# to build it the way the platform writes one — a hardcoded `":"` splits
# `C:\Users\…` into two nonexistent directories and the test then asserts
# against the wreckage. The shipped `split_roots` was already right; this was
# the harness disagreeing with it.
def test_sting_roots_overrides_git_entirely(repo, tmp_path, monkeypatch):
    a, b = tmp_path / "one", tmp_path / "two"
    a.mkdir(); b.mkdir()
    monkeypatch.setenv("STING_ROOTS", f"{a}{os.pathsep}{b}")
    roots, note = RealWorld().project_roots(str(repo))
    assert roots == (str(a.resolve()), str(b.resolve()))
    assert note is None


def test_sting_roots_ignores_entries_that_do_not_exist(tmp_path, monkeypatch):
    a = tmp_path / "real"
    a.mkdir()
    monkeypatch.setenv("STING_ROOTS", f"{a}{os.pathsep}{tmp_path}/nope")
    roots, _ = RealWorld().project_roots(str(tmp_path))
    assert roots == (str(a.resolve()),)


def test_sting_roots_naming_nothing_real_falls_back_and_says_so(tmp_path, monkeypatch):
    """Widening a trust boundary must not fail open silently."""
    monkeypatch.setenv("STING_ROOTS", "/no/such/dir:/also/not")
    roots, note = RealWorld().project_roots(str(tmp_path))
    assert roots == (str(tmp_path.resolve()),)
    assert note and "STING_ROOTS" in note


# ------------------------------------------------------- resolved once, cached
def test_the_roots_are_resolved_once_per_session_not_per_action(repo, monkeypatch):
    """Resolving shells out to git. CLAUDE.md rule #8's principle: derive once,
    then it is a set lookup."""
    import hook_entry
    calls = []
    real = RealWorld.project_roots

    def counting(self, cwd):
        calls.append(cwd)
        return real(self, cwd)

    monkeypatch.setattr(RealWorld, "project_roots", counting)
    import json
    for _ in range(5):
        hook_entry.run(json.dumps({
            "session_id": "s-cache", "cwd": str(repo),
            "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": "ls"}}))
    assert len(calls) == 1, calls


def test_the_note_is_said_once_not_on_every_action(tmp_path):
    """One line per session. Repeating it on all 181 actions would be its own
    kind of silence."""
    import hook_entry, json
    p = json.dumps({"session_id": "s-note", "cwd": str(tmp_path),
                    "hook_event_name": "PreToolUse", "tool_name": "Bash",
                    "tool_input": {"command": "ls"}})
    first = hook_entry.run(p)[1]
    second = hook_entry.run(p)[1]
    assert "project root unknown" in first
    assert "project root unknown" not in second


# ---------------------------------------------- the cache must re-check itself
#
# A real session cached git-derived roots at its first action, the developer set
# STING_ROOTS afterwards, and every action after that kept the stale single root
# and said nothing. $HOME expansion was fine and the variable reached the hook —
# the cache was the whole bug, and its silence was the worse half.
import json
import subprocess


def _run(session_root, sid, cwd, roots=None):
    import hook_entry
    env = {**os.environ, "STING_SESSION_ROOT": str(session_root),
           "STING_LOG": str(session_root) + "/l.jsonl"}
    env.pop("STING_ROOTS", None)
    if roots:
        env["STING_ROOTS"] = roots
    payload = json.dumps({"session_id": sid, "cwd": str(cwd),
                          "hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "git status"}})
    proc = subprocess.run([sys.executable, str(ROOT_DIR / "hook_entry.py")],
                           input=payload, text=True, capture_output=True, env=env)
    state = json.loads((Path(session_root) / f"{sid}.json").read_text())
    return state, proc.stderr.strip()


import os
import sys
from pathlib import Path
ROOT_DIR = Path(__file__).parent.parent


def test_setting_sting_roots_midsession_takes_effect(repo, tmp_path):
    """The exact reported failure."""
    d = tmp_path / "sess"
    d.mkdir()
    a, b = tmp_path / "one", tmp_path / "two"
    a.mkdir(); b.mkdir()
    state, _ = _run(d, "s", repo)
    assert state["workspace_roots"] == [str(repo.resolve())]
    state, err = _run(d, "s", repo, f"{a}:{b}")
    assert state["workspace_roots"] == [str(a.resolve()), str(b.resolve())]
    assert "STING_ROOTS changed" in err, err


def test_a_session_predating_the_field_re_checks_once(repo, tmp_path):
    """roots_env absent means unknown provenance, not 'confirmed correct'."""
    d = tmp_path / "sess"
    d.mkdir()
    a = tmp_path / "one"
    a.mkdir()
    (d / "old.json").write_text(json.dumps({
        "session_id": "old", "cwd": str(repo), "seq": 5,
        "workspace_roots": [str(repo)], "roots_note": None}))
    state, _err = _run(d, "old", repo, str(a))
    assert state["workspace_roots"] == [str(a.resolve())]


def test_sting_roots_set_but_not_in_use_is_reported_every_time(repo, tmp_path):
    """A trust boundary the developer believes they widened and did not is
    exactly the case that must never be quiet."""
    d = tmp_path / "sess"
    d.mkdir()
    _state, err = _run(d, "s", repo, "/no/such/dir:/also/not")
    assert "did not take effect" in err, err


def test_a_correctly_applied_sting_roots_says_nothing(repo, tmp_path):
    """Loud on failure, silent on success — or the noise trains people to
    ignore it."""
    d = tmp_path / "sess"
    d.mkdir()
    a = tmp_path / "one"
    a.mkdir()
    _state, err = _run(d, "s", repo, str(a))
    assert "STING_ROOTS" not in err, err


def test_home_expands_in_the_value(repo, tmp_path):
    """Measured against a real Claude Code hook: $HOME IS expanded before the
    hook runs. Pinned so the diagnosis is not re-litigated."""
    d = tmp_path / "sess"
    d.mkdir()
    a = tmp_path / "one"
    a.mkdir()
    state, _ = _run(d, "s", repo, str(a))
    assert state["workspace_roots"] == [str(a.resolve())]
