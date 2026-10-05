"""`git diff --cached --name-only` returns REPOSITORY-ROOT-RELATIVE names.

⚠ THIS FILE EXISTS BECAUSE NOTHING TESTED THE SECOND GIT SPAWN. Found while
costing A6b-ii: `core/probes.staged_files` calls `rev-parse --show-toplevel` to
turn those names into absolute paths, and the entire suite passes with that call
removed and `base = Path(cwd)` in its place — 2372 passed, A4 and A5 unmoved at
59/79 and 0/25.

It is load-bearing anyway, and what it holds up is the product's flagship case.
Every taint lookup is keyed on an ABSOLUTE path, so resolving a root-relative
name against the wrong base does not raise, does not log, and does not fail a
test. It silently produces a path that matches nothing:

    cwd = <repo>/src, a tainted file staged, `git commit`
      with rev-parse      <repo>/src/config.py       -> DENY  secret_exact:git_commit
      without             <repo>/src/src/config.py   -> ALLOW

⚠ AND THE SHAPE IT NEEDS IS THE COMMON ONE, NOT AN EDGE CASE. 92.8% of live
commands begin `cd X &&`, so cwd != repo root is what real sessions look like.
The corpus runs almost everything from the repository root, which is why it
could not see this — corpus blindness in the layer that turns text into
structure, which is where every blind spot so far has been.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters import claude_code                                     # noqa: E402
from core import engine, probes                                      # noqa: E402
from core.types import Decision, SessionState                        # noqa: E402


def _repo(tmp_path) -> str:
    """A real repository with a subdirectory, because the bug needs one."""
    if not __import__("shutil").which("git"):
        pytest.skip("git is not available")
    root = os.path.realpath(str(tmp_path / "repo"))
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null"}

    def git(*args, cwd=root):
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                              env=env)

    git("init", "-q")
    (tmp_path / "repo" / "README.md").write_text("hi\n", encoding="utf-8")
    git("add", "-A")
    git("-c", "user.email=a@b", "-c", "user.name=c", "commit", "-q", "-m", "i")
    return root


def test_staged_names_resolve_against_the_repo_root_not_the_cwd(tmp_path):
    """The probe's own contract, stated where a reader will look for it."""
    root = _repo(tmp_path)
    sub = os.path.join(root, "src")
    (tmp_path / "repo" / "src" / "config.py").write_text("x = 1\n",
                                                          encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=sub, capture_output=True,
                   env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_CONFIG_SYSTEM": "/dev/null"})

    staged = probes.RealWorld().staged_files(sub)

    assert staged == (os.path.join(root, "src", "config.py"),), (
        "a root-relative name resolved against cwd doubles the subdirectory")


def test_a_tainted_file_staged_from_a_subdirectory_is_still_denied(tmp_path):
    """⚠ THE CASE THAT MAKES THE SPAWN LOAD-BEARING — A1's shape, from `src/`.

    The engine holds an absolute tainted path. The agent stages it and commits
    from a subdirectory, which is what 92.8% of live commands do. If the staged
    name is resolved against the wrong base the lookup misses and the secret
    commits, with no error anywhere.
    """
    root = _repo(tmp_path)
    sub = os.path.join(root, "src")
    tainted = os.path.join(root, "src", "config.py")
    (tmp_path / "repo" / "src" / "config.py").write_text(
        "AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=sub, capture_output=True,
                   env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_CONFIG_SYSTEM": "/dev/null"})

    action = claude_code.parse({
        "session_id": "sub", "cwd": sub, "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "git commit -q -m wip"}})
    state = SessionState(session_id="sub", cwd=sub)
    state.workspace_roots = [root]
    state.holds_secret = True
    state.holds_secret_since_seq = 2
    state.secret_sources = [{"seq": 2, "path": os.path.join(root, ".env"),
                             "how": "content"}]
    state.tainted_paths = {tainted: {"label": "SECRET", "level": "exact",
                                     "from_seq": 2}}
    state.seq = 5

    verdict = engine.decide(action, state, probes.RealWorld())

    assert verdict.decision is Decision.DENY, (
        f"a tainted file staged from a subdirectory must not commit; "
        f"got {verdict.decision} {verdict.rule_id}")
    assert verdict.rule_id == "secret_exact:git_commit"


def test_the_same_commit_from_the_repo_root_is_denied_too(tmp_path):
    """⚠ THE CONTROL. Without it the test above cannot distinguish "the
    subdirectory case works" from "this action is denied whatever the cwd" —
    two measurements joined in prose, which is working rule 11's disease.
    """
    root = _repo(tmp_path)
    tainted = os.path.join(root, "src", "config.py")
    (tmp_path / "repo" / "src" / "config.py").write_text(
        "AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True,
                   env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_CONFIG_SYSTEM": "/dev/null"})

    action = claude_code.parse({
        "session_id": "top", "cwd": root, "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "git commit -q -m wip"}})
    state = SessionState(session_id="top", cwd=root)
    state.workspace_roots = [root]
    state.holds_secret = True
    state.holds_secret_since_seq = 2
    state.secret_sources = [{"seq": 2, "path": os.path.join(root, ".env"),
                             "how": "content"}]
    state.tainted_paths = {tainted: {"label": "SECRET", "level": "exact",
                                     "from_seq": 2}}
    state.seq = 5

    verdict = engine.decide(action, state, probes.RealWorld())

    assert verdict.decision is Decision.DENY


def test_a_clean_index_costs_one_spawn_and_a_dirty_one_costs_three(tmp_path):
    """⚠ THE FACT THAT DECIDED A6b-ii's BUDGET, PINNED SO IT CANNOT DRIFT.

    The budget was 2. This code spawns 1 or 3 and never 2 — a budget of 2 did
    not describe any reachable state, which is what an instrument counting the
    wrong quantity produces. If either count changes, the budget's argument
    changes with it and somebody has to write a new one.
    """
    root = _repo(tmp_path)
    spawns: list[str] = []
    real_popen = subprocess.Popen

    class Counting(real_popen):
        def __init__(self, *args, **kwargs):
            argv = args[0] if args else kwargs.get("args")
            spawns.append(" ".join(str(x) for x in list(argv)[:4]))
            super().__init__(*args, **kwargs)

    def count(command: str) -> list[str]:
        action = claude_code.parse({
            "session_id": "c", "cwd": root, "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}})
        state = SessionState(session_id="c", cwd=root)
        state.workspace_roots = [root]
        state.holds_secret = True
        state.secret_fingerprints = [f"{i:08x}" for i in range(20)]
        spawns.clear()
        subprocess.Popen = Counting
        try:
            engine.decide(action, state, probes.RealWorld())
        finally:
            subprocess.Popen = real_popen
        return list(spawns)

    clean = count("git commit -q -m x")
    assert len(clean) == 1, f"a clean index must cost one spawn, got {clean}"

    (tmp_path / "repo" / "src" / "b.py").write_text("y = 2\n" * 50,
                                                     encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True,
                   env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_CONFIG_SYSTEM": "/dev/null"})

    dirty = count("git commit -q -m x")
    assert len(dirty) == 3, f"a dirty index must cost three spawns, got {dirty}"
    assert any("--name-only" in s for s in dirty)
    assert any("--show-toplevel" in s for s in dirty)
