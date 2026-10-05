"""
Step 10 — inspect what is ACTUALLY in the commit at push time.

CLAUDE.md rule #7: use `git diff --cached`, not a staged-file list we
maintained ourselves. Ours is wrong in both directions, and each direction has
a test here:

    too broad   we recorded a `git add` of a path .gitignore then dropped, so
                we would deny a push carrying nothing
    too narrow  `git add -f` forced in an ignored file, or an edit made outside
                the agent's tool calls, and we never saw either
"""
import hashlib
import subprocess

import pytest

from core import engine
from core.probes import RealWorld
from core.types import ActionKind, Decision, SessionState

from tests.test_engine_sources import FakeWorld, act

PUSH = act(ActionKind.EXEC, command="git push origin main")
SECRET = "AKIA_TEST_I02_commit_into_pr_branch"
# The WHOLE-value hash. fingerprint_values also returns prefix hashes now,
# so sorted(...)[0] would pick an arbitrary prefix instead.
FP = hashlib.sha256(SECRET.encode()).hexdigest()[:8]


def held(**kw):
    st = SessionState(seq=6, holds_secret=True, holds_secret_since_seq=2,
                      secret_fingerprints=[FP],
                      secret_sources=[{"seq": 2, "path": "/repo/.env",
                                        "how": "content"}])
    for k, v in kw.items():
        setattr(st, k, v)
    return st


def push_verdict(state, world):
    return engine.decide(PUSH, state, world)


# ============================================ what the index really contains
def test_a_tainted_file_in_the_index_is_denied():
    st = held(tainted_paths={"/repo/debug/.env": {"label": "SECRET",
                                                   "level": "exact", "from_seq": 3}})
    v = push_verdict(st, FakeWorld(staged=["/repo/debug/.env"]))
    assert v.decision is Decision.DENY
    assert v.rule_id.startswith("secret_exact")


def test_a_credential_shaped_path_in_the_index_is_denied_even_if_unlabelled():
    """We may never have seen it written — it is still a .env in the commit."""
    v = push_verdict(held(), FakeWorld(staged=["/repo/config/.env.production"]))
    assert v.decision is Decision.DENY


def test_a_secret_in_the_staged_DIFF_is_caught_even_for_a_file_we_never_saw():
    """The `git add -f` case, and the edited-outside-our-tool-calls case.

    A path list cannot see this: the file was never written through a tool
    call, so it is in no taint table. Only the content shows it.
    """
    diff = (f"diff --git a/notes.txt b/notes.txt\n"
            f"+++ b/notes.txt\n+AWS_KEY={SECRET}\n")
    v = push_verdict(held(), FakeWorld(staged=["/repo/notes.txt"], staged_diff=diff))
    assert v.decision is Decision.DENY
    assert v.rule_id.startswith("secret_exact")


def test_a_clean_index_is_allowed_even_while_the_session_holds_secrets():
    """N09's shape: read .env to debug, commit something unrelated, push.

    holds_secret is true, but nothing tainted is in the commit. Denying here
    would block ordinary work after any credential read — the false positive
    that makes developers uninstall.
    """
    v = push_verdict(held(), FakeWorld(staged=["/repo/src/login.py"],
                                        staged_diff="+def login(): pass\n"))
    assert v.decision is Decision.ALLOW


def test_an_empty_index_is_not_treated_as_a_stale_list():
    """() means inspected-and-empty. Falling back to our own list here would
    deny a push that genuinely carries nothing."""
    st = held(staged_secret_files=["/repo/debug/.env"],
              tainted_paths={"/repo/debug/.env": {"label": "SECRET",
                                                   "level": "exact", "from_seq": 3}})
    v = push_verdict(st, FakeWorld(staged=[]))
    assert v.decision is Decision.ALLOW, (
        "an empty commit carries nothing; our own list must not override that")


def test_gitignore_dropping_a_path_does_not_cause_a_false_denial():
    """We saw `git add debug/.env` and recorded it, but .gitignore excluded it
    so it never reached the index. The push carries nothing."""
    st = held(staged_secret_files=["/repo/debug/.env"],
              tainted_paths={"/repo/debug/.env": {"label": "SECRET",
                                                   "level": "exact", "from_seq": 3}})
    v = push_verdict(st, FakeWorld(staged=["/repo/README.md"]))
    assert v.decision is Decision.ALLOW


# ============================================ when git cannot be inspected
def test_our_own_list_is_used_only_when_the_index_cannot_be_read():
    """None means "could not look" — not a repo, git missing, timeout. Falling
    back is right here; it is the only information we have."""
    st = held(staged_secret_files=["/repo/debug/.env"],
              tainted_paths={"/repo/debug/.env": {"label": "SECRET",
                                                   "level": "exact", "from_seq": 3}})
    v = push_verdict(st, FakeWorld(staged=None))      # None, not []
    assert v.decision is Decision.DENY


def test_none_and_empty_are_different_facts():
    st = held(staged_secret_files=["/repo/debug/.env"],
              tainted_paths={"/repo/debug/.env": {"label": "SECRET",
                                                   "level": "exact", "from_seq": 3}})
    could_not_look = push_verdict(st, FakeWorld(staged=None)).decision
    nothing_staged = push_verdict(st, FakeWorld(staged=[])).decision
    assert (could_not_look, nothing_staged) == (Decision.DENY, Decision.ALLOW)


# ============================================ RealWorld against a real repo
@pytest.fixture
def repo(tmp_path):
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, check=False)
    git("init", "-q")
    git("config", "user.email", "t@t.com")
    git("config", "user.name", "t")
    (tmp_path / "README.md").write_text("# project\n")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    return tmp_path


def test_realworld_reports_nothing_staged_as_empty_not_none(repo):
    assert RealWorld().staged_files(str(repo)) == ()


def test_realworld_reports_a_non_repo_as_none(tmp_path):
    """The distinction the whole fallback rests on."""
    assert RealWorld().staged_files(str(tmp_path)) is None


def test_realworld_sees_what_git_actually_staged(repo):
    (repo / "notes.txt").write_text("hello\n")
    subprocess.run(["git", "add", "notes.txt"], cwd=repo, capture_output=True)
    staged = RealWorld().staged_files(str(repo))
    assert staged is not None and len(staged) == 1
    assert staged[0].endswith("notes.txt")


def test_realworld_respects_gitignore(repo):
    """The too-broad direction, against real git."""
    (repo / ".gitignore").write_text(".env\n")
    (repo / ".env").write_text(f"AWS={SECRET}\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True)
    staged = RealWorld().staged_files(str(repo))
    assert not any(p.endswith("/.env") for p in staged), \
        ".gitignore kept it out of the index; our own list would not have known"


def test_realworld_catches_git_add_dash_f(repo):
    """The too-narrow direction, against real git."""
    (repo / ".gitignore").write_text(".env\n")
    (repo / ".env").write_text(f"AWS={SECRET}\n")
    subprocess.run(["git", "add", "-f", ".env"], cwd=repo, capture_output=True)
    staged = RealWorld().staged_files(str(repo))
    assert any(p.endswith("/.env") for p in staged), "forced in, and we must see it"


def test_realworld_staged_content_carries_the_secret(repo):
    (repo / "notes.txt").write_text(f"AWS_KEY={SECRET}\n")
    subprocess.run(["git", "add", "notes.txt"], cwd=repo, capture_output=True)
    diff = RealWorld().staged_content(str(repo))
    assert diff and SECRET in diff
    assert FP in engine.fingerprint_values(diff)


def test_end_to_end_a_forced_ignored_env_is_denied_at_push(repo):
    """Everything together, against real git: .gitignore says no, the agent
    forces it in anyway, and we catch it from the index rather than from
    anything we recorded ourselves."""
    (repo / ".gitignore").write_text(".env\n")
    (repo / ".env").write_text(f"AWS={SECRET}\n")
    subprocess.run(["git", "add", "-f", ".env"], cwd=repo, capture_output=True)

    st = held()                       # note: staged_secret_files is EMPTY
    assert st.staged_secret_files == []
    action = act(ActionKind.EXEC, command="git push origin main", cwd=str(repo),
                 workspace_roots=(str(repo),))
    v = engine.decide(action, st, RealWorld())
    assert v.decision is Decision.DENY
    assert v.rule_id.startswith("secret_exact")


# ------------------------------------------------ rule #7 without the spawns
#
# Three git subprocesses fired per commit/push verdict, ~12 ms each — spawn
# cost, not git's work: `rev-parse --show-toplevel` measured as expensive as a
# full `diff --cached`. Two of the three are derivable from the first, and a
# derivation cannot go stale the way a cache can.
class CountingWorld:
    """Records which probes were called, and answers as given."""

    def __init__(self, staged=(), content="", files=None):
        self.calls = []
        self._staged, self._content, self._files = staged, content, files or {}

    def read_text(self, path):
        return self._files.get(path)

    def staged_files(self, cwd):
        self.calls.append("staged_files")
        return self._staged

    def staged_content(self, cwd):
        self.calls.append("staged_content")
        return self._content

    def remotes(self, cwd):
        return ()

    def branch(self, cwd):
        return "main"

    def project_roots(self, cwd):
        return (cwd,), None


def _push(cwd="/repo"):
    from core.types import Action, ActionKind
    return Action("s", 1, ActionKind.EXEC, (), "git push origin main", None,
                   "Bash", None, cwd, (cwd,), "claude-code")


def test_a_verified_empty_index_does_not_ask_git_for_its_diff():
    """No staged files means no staged content, necessarily."""
    from core.engine import decide
    from core.types import SessionState
    st = SessionState(session_id="s", holds_secret=True, holds_secret_since_seq=1)
    world = CountingWorld(staged=())
    decide(_push(), st, world)
    assert "staged_files" in world.calls
    assert "staged_content" not in world.calls, world.calls


def test_an_UNINSPECTABLE_index_still_asks_for_the_diff():
    """None means 'could not look', which is NOT 'nothing staged'. Collapsing
    the two would turn a failed probe into a clean bill of health — the exact
    shape of a fail-open bug."""
    from core.engine import decide
    from core.types import SessionState
    st = SessionState(session_id="s", holds_secret=True, holds_secret_since_seq=1)
    world = CountingWorld(staged=None)
    decide(_push(), st, world)
    assert "staged_content" in world.calls, world.calls


def test_a_dirty_index_still_reads_the_real_diff():
    """Rule #7 in full: when something IS staged, the bytes get inspected."""
    from core.engine import decide
    from core.types import SessionState
    st = SessionState(session_id="s", holds_secret=True, holds_secret_since_seq=1)
    world = CountingWorld(staged=("/repo/notes.txt",), content="+ hello\n")
    decide(_push(), st, world)
    assert world.calls == ["staged_files", "staged_content"], world.calls


def test_staged_files_skips_rev_parse_when_nothing_is_staged(monkeypatch):
    """The second derivation: no names to resolve means no need to ask where
    the repository root is."""
    from core import probes
    seen = []
    real = probes.RealWorld._git

    def spy(self, cwd, *args):
        seen.append(args)
        return "" if args[:2] == ("diff", "--cached") else real(self, cwd, *args)

    monkeypatch.setattr(probes.RealWorld, "_git", spy)
    assert probes.RealWorld().staged_files("/tmp") == ()
    assert ("rev-parse", "--show-toplevel") not in seen, seen
