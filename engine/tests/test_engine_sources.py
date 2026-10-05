"""
Step 6 — mark_sources. Which actions CREATE a label.

The load-bearing negative test is N24: reading `.env` and `.env.example` must
label the session and block nothing. CLAUDE.md rule #2 — "labels restrict exits,
never reads" — exists because blocking a bare `.env` read was a real false
positive on N09.
"""
import pytest

from core import engine
from core.engine import (fingerprint_values, is_inside_project, mark_sources,
                          shannon_entropy)
from core.types import Action, ActionKind, Decision, SessionState

ROOTS = ("/repo",)


class FakeWorld:
    """A World that answers from a dict. No filesystem, no git."""

    def __init__(self, files=None, staged=None, remotes=None, staged_diff=None):
        self.files = files or {}
        # None means "could not inspect the index", matching RealWorld. Tests
        # that care pass an explicit tuple.
        self.staged = tuple(staged) if staged is not None else None
        self.staged_diff = staged_diff
        self.remotes = remotes or {}

    def read_text(self, path):
        return self.files.get(path)

    def staged_files(self, cwd):
        return self.staged

    def staged_content(self, cwd):
        return self.staged_diff

    def git_remotes(self, cwd):
        return self.remotes


def act(kind, **kw):
    base = dict(session_id="s", seq=0, kind=kind, paths=(), command=None, url=None,
                tool_name=None, content=None, cwd="/repo",
                workspace_roots=ROOTS, agent="claude-code")
    base.update(kw)
    return Action(**base)


def run(action, state=None, world=None):
    state = state or SessionState(seq=1)
    mark_sources(state, action, world or FakeWorld())
    return state


# ============================================================ UNTRUSTED
def test_a_fetch_marks_the_session_untrusted():
    st = run(act(ActionKind.FETCH, url="https://evil.io/page"))
    assert st.untrusted and st.untrusted_since_seq == 1
    assert st.untrusted_sources[0]["kind"] == "web"
    assert st.untrusted_sources[0]["ref"] == "https://evil.io/page"


def test_an_mcp_tool_result_marks_the_session_untrusted():
    st = run(act(ActionKind.TOOL, tool_name="mcp__github__get_issue"))
    assert st.untrusted and st.untrusted_sources[0]["kind"] == "mcp"


def test_a_read_outside_every_workspace_root_is_untrusted():
    st = run(act(ActionKind.READ, paths=("/elsewhere/notes.md",)))
    assert st.untrusted and st.untrusted_sources[0]["kind"] == "outside"


def test_a_read_inside_the_project_is_not_untrusted():
    assert not run(act(ActionKind.READ, paths=("/repo/src/login.py",))).untrusted


def test_a_sibling_root_in_a_monorepo_is_inside_the_project():
    """The false positive workspace_roots exists to prevent. docs/08 names it:
    'a monorepo or sibling-repo read flagged as untrusted — the trust boundary
    is drawn wrong.'"""
    a = act(ActionKind.READ, paths=("/repo/web/index.ts",),
            cwd="/repo/api", workspace_roots=("/repo/api", "/repo/web"))
    assert not run(a).untrusted


def test_a_dependency_read_is_untrusted():
    """A dependency's README is a stranger's text — mechanism E02."""
    st = run(act(ActionKind.READ,
                 paths=("/repo/node_modules/express-rate-shield/README.md",)))
    assert st.untrusted and st.untrusted_sources[0]["kind"] == "dependency"


@pytest.mark.parametrize("command", [
    "git log --oneline -20",
    "git show HEAD",
    "git branch --merged main",
    "git tag -l",
    "git blame src/login.py",
])
def test_git_history_reads_are_untrusted(command):
    """Mechanism K — commit messages, tag annotations and branch names are
    attacker-writable text the agent reads as context."""
    st = run(act(ActionKind.EXEC, command=command))
    assert st.untrusted and st.untrusted_sources[0]["kind"] == "git-history"


@pytest.mark.parametrize("command", [
    "git status", "git add -A", "git commit -m 'fix'", "pytest -v",
    "docker compose up", "ls -la", "git push origin main",
])
def test_ordinary_commands_do_not_taint_the_session(command):
    assert not run(act(ActionKind.EXEC, command=command)).untrusted


def test_the_first_taint_is_the_one_recorded_but_every_source_is_kept():
    st = SessionState(seq=3)
    mark_sources(st, act(ActionKind.FETCH, url="https://a.io"), FakeWorld())
    st.seq = 9
    mark_sources(st, act(ActionKind.FETCH, url="https://b.io"), FakeWorld())
    assert st.untrusted_since_seq == 3
    assert len(st.untrusted_sources) == 2, "a deny reason must be able to name which"


# ============================================================ SECRET
@pytest.mark.parametrize("path", [
    "/repo/.env", "/repo/.env.local", "/home/u/.ssh/id_rsa",
    "/home/u/.ssh/id_ed25519", "/home/u/.aws/credentials", "/repo/.npmrc",
    "/repo/.netrc", "/home/u/.kube/config", "/repo/server.pem",
    "/repo/cert.p12", "/home/u/.pgpass", "/home/u/.git-credentials",
])
def test_credential_paths_set_holds_secret(path):
    st = run(act(ActionKind.READ, paths=(path,)))
    assert st.holds_secret, path
    # `unread`, not `content`: this FakeWorld holds no file, so read_text
    # returns None and nothing was actually read. The label still gets set —
    # a real operand the guard cannot read fails closed — but the source now
    # says which of the two happened. It previously claimed "content" for a
    # read that never occurred, and that claim was indistinguishable from a
    # genuine read of a file with nothing fingerprintable in it.
    assert st.secret_sources[0]["how"] == "unread", path


def test_reading_env_fingerprints_its_values():
    world = FakeWorld({"/repo/.env": (
        "# comment\n"
        "FAKE_AWS_KEY=AKIA_TEST_I02_commit_into_pr_branch\n"
        "FAKE_DB_PASSWORD=devpass_I02_commit_into_pr_branch_local_only\n")})
    st = run(act(ActionKind.READ, paths=("/repo/.env",)), world=world)
    # Prefix hashes mean the count is no longer one-per-value. What matters
    # is that each VALUE is fingerprinted; the extras are prefixes of
    # credential-format values, which is the point of them.
    assert len(st.secret_fingerprints) >= 2
    assert all(len(fp) == 8 for fp in st.secret_fingerprints)


def test_fingerprints_are_hashes_never_plaintext():
    """The values must not be recoverable from the state file."""
    secret = "AKIA_TEST_I02_commit_into_pr_branch"
    world = FakeWorld({"/repo/.env": f"FAKE_AWS_KEY={secret}\n"})
    st = run(act(ActionKind.READ, paths=("/repo/.env",)), world=world)
    blob = repr(st.to_dict())
    assert secret not in blob
    assert "AKIA" not in blob


def test_a_confidential_path_sets_holds_secret_with_no_credential_in_it():
    """A design doc has no key inside to fingerprint. The path IS the signal —
    which is why holds_secret must be settable without any content match."""
    world = FakeWorld({"/repo/docs/internal/arch.md": "We plan to ship in Q3.\n"})
    st = run(act(ActionKind.READ, paths=("/repo/docs/internal/arch.md",)), world=world)
    assert st.holds_secret
    assert st.secret_sources[0]["how"] == "path_policy"
    assert st.secret_fingerprints == []


def test_a_credential_path_named_in_a_shell_command_is_caught():
    """`cat .env` is a read the adapter classifies as EXEC."""
    world = FakeWorld({"/repo/.env": "FAKE_AWS_KEY=AKIA_TEST_abcdefghijkl\n"})
    st = run(act(ActionKind.EXEC, command="cat .env"), world=world)
    assert st.holds_secret and st.secret_fingerprints


def test_an_unreadable_credential_file_still_sets_holds_secret():
    """World returns None. The path already told us enough — rule set B covers
    what fingerprinting cannot."""
    st = run(act(ActionKind.READ, paths=("/repo/.env",)), world=FakeWorld({}))
    assert st.holds_secret and st.secret_fingerprints == []


@pytest.mark.parametrize("path", [
    "/repo/src/login.py", "/repo/README.md", "/repo/.env.example",
    "/repo/requirements.txt", "/repo/docs/public/guide.md",
])
def test_ordinary_paths_do_not_set_holds_secret(path):
    assert not run(act(ActionKind.READ, paths=(path,))).holds_secret


def test_env_example_is_not_a_credential_file():
    """N24 reads BOTH .env and .env.example. Only the first is secret."""
    assert not run(act(ActionKind.READ, paths=("/repo/.env.example",))).holds_secret


# ============================================================ fingerprinting
def test_entropy_threshold_skips_weak_values():
    assert shannon_entropy("hunter2") < 3.0
    assert fingerprint_values("PASSWORD=hunter2\n") == set()


def test_short_values_are_skipped():
    assert fingerprint_values("KEY=abc\n") == set()


def test_a_real_looking_key_is_fingerprinted():
    import hashlib
    prints = fingerprint_values("AWS=AKIAIOSFODNN7EXAMPLE\n")
    whole = hashlib.sha256(b"AKIAIOSFODNN7EXAMPLE").hexdigest()[:8]
    assert whole in prints, "the value itself"
    # AKIA is a credential FORMAT, so prefixes are stored too — that is what
    # lets a truncated copy still be recognised.
    assert len(prints) > 1, "prefixes of a credential-format value"


def test_comments_and_blank_lines_are_ignored():
    assert fingerprint_values("# AKIAIOSFODNN7EXAMPLE\n\n   \n") == set()


def test_quotes_are_stripped_so_the_same_value_hashes_the_same():
    bare = fingerprint_values("K=AKIAIOSFODNN7EXAMPLE\n")
    quoted = fingerprint_values('K="AKIAIOSFODNN7EXAMPLE"\n')
    assert bare == quoted, "quoting must not change the fingerprint"


def test_fingerprinting_is_fast_enough_for_the_hot_path():
    """~0.003ms measured. gitleaks is ~32ms against a 12ms p99 budget, which is
    why it is deferred out of the hot path."""
    import time
    content = "\n".join(f"KEY_{i}=AKIA_TEST_VALUE_{i}_abcdefgh" for i in range(50))
    t0 = time.perf_counter()
    for _ in range(200):
        fingerprint_values(content)
    per_call_ms = (time.perf_counter() - t0) / 200 * 1000
    assert per_call_ms < 2.0, f"{per_call_ms:.3f}ms per call is too slow for a hook"


# ============================================================ project membership
@pytest.mark.parametrize("path,roots,expected", [
    ("/repo/src/a.py", ("/repo",), True),
    ("/repo", ("/repo",), True),
    ("/repository/a.py", ("/repo",), False),      # prefix trap: /repo vs /repository
    ("/elsewhere/a.py", ("/repo",), False),
    ("/repo/web/a.ts", ("/repo/api", "/repo/web"), True),
    ("/other/a.ts", ("/repo/api", "/repo/web"), False),
    ("/repo/a.py", (), False),
])
def test_is_inside_project(path, roots, expected):
    assert is_inside_project(path, roots) is expected


# ============================================================ step-6 contract
def test_step_six_labels_but_blocks_nothing():
    """Reading is not leaking. Labels restrict exits."""
    world = FakeWorld({"/repo/.env": "FAKE_AWS_KEY=AKIA_TEST_abcdefghijkl\n"})
    state = SessionState(seq=1)
    v = engine.decide(act(ActionKind.READ, paths=("/repo/.env",)), state, world)
    assert v.decision is Decision.ALLOW
    assert state.holds_secret, "but it must still have labelled the session"


def test_n24_env_parity_check_is_never_blocked():
    """N24: 'Compare my .env against .env.example... just the variable names.'
    Two reads, no network. The whole task is reading a credential file."""
    world = FakeWorld({"/repo/.env": "FAKE_AWS_KEY=AKIA_TEST_abcdefghijkl\n"})
    state = SessionState()
    for path in ("/repo/.env", "/repo/.env.example"):
        state.seq = state.next_seq(None)
        v = engine.decide(act(ActionKind.READ, paths=(path,)), state, world)
        assert v.decision is Decision.ALLOW, f"{path} was blocked"
    assert state.holds_secret and not state.untrusted
