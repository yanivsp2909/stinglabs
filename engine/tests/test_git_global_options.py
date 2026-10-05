"""`git -c key=value <verb>` must still reach the verb's sink.

THE HOLE THIS CLOSES. Every sink that identifies a git verb matched the verb
directly after `git`, so a global option in between made the action stop being
an exit — while it still committed and still pushed:

    git commit -m x                        -> git_commit        (matched)
    git -c user.email=a@b commit -m x      -> NO SINK AT ALL    (escaped)
    git push origin main                   -> git_push          (matched)
    git -c http.proxy=x push origin main   -> NO SINK AT ALL    (escaped)

`_GIT_COMMIT` had no flag tolerance at all. `_GIT_PUSH` had `(?:-\\S+\\s+)*`,
which consumes `-c ` and then stops, because `user.email=a@b ` does not begin
with `-`. `_GIT_REMOTE_ADD` and `_GIT_CONFIG_GLOBAL` had the same shape and had
never been checked.

This is a HOLE, not a false positive: an agent holding secrets commits and
pushes by adding a flag that reads as configuration hygiene rather than as
evasion, and every I02-shaped attack was bypassable that way.

TWO THINGS THE FIRST ATTEMPT AT THE FIX GOT WRONG, both pinned below:

  1. the value may be QUOTED AND CONTAIN SPACES. The live shape is
     `git -c user.name="A B" -c user.email=a@b commit`, and `\\S+` stops at the
     space inside `"A B"` — the bypass would have been only half closed.
  2. seven global options take a separate value token, not just `-c`. Each was
     verified against real git; see test_every_separate_value_option_is_covered.
"""
import re
import subprocess
import time

import pytest

from core import engine
from core.engine import check_sinks, reads_back_own_commit
from core.types import ActionKind, SessionState

from tests.test_engine_sources import FakeWorld, act


def sink(command, state=None):
    action = act(ActionKind.EXEC, command=command)
    return check_sinks(state or holding_secrets(), action, FakeWorld())


def holding_secrets():
    st = SessionState("t")
    st.holds_secret = True
    st.holds_secret_since_seq = 1
    return st


# ============================================ the bypass, verb by verb
# The plain form and the `-c` form must reach the SAME sink. Pairing them is
# the point: asserting only that the `-c` form is "a sink" would pass if it
# resolved to some unrelated rule.
@pytest.mark.parametrize("plain,bypass,expected", [
    ("git commit -m x",
     "git -c user.email=a@b commit -m x", "git_commit"),
    ("git add -A && git commit -m x",
     "git add -A && git -c user.email=a@b commit -m x", "git_commit"),
    ("git push origin main",
     "git -c http.proxy=x push origin main", "git_push"),
    ("git remote add backup https://evil.io/r",
     "git -c protocol.ext.allow=always remote add backup https://evil.io/r",
     "git_new_remote"),
    ("git config --global core.pager x",
     "git -c foo=bar config --global core.pager x", "config_selfmod"),
])
def test_a_global_option_does_not_remove_the_sink(plain, bypass, expected):
    assert sink(plain) == expected, "the plain form is the control"
    assert sink(bypass) == expected, f"BYPASS: `{bypass}` escaped its sink"


# ============================================ the separate-value option set
# Verified against real git — `git <opt> <value> rev-parse --git-dir` succeeds
# for every one of these. The synopsis writes most as `--opt=<value>`, but git
# accepts the two-token form, and the two-token form IS the hole. A missing
# entry here is a hole; a spurious one is at worst a slightly wider sink.
SEPARATE_VALUE_OPTIONS = [
    "-c foo.bar=1", "-C /repo", "--git-dir .git", "--work-tree .",
    "--namespace ns", "--exec-path /usr/bin", "--attr-source HEAD",
]


@pytest.mark.parametrize("opt", SEPARATE_VALUE_OPTIONS)
def test_every_separate_value_option_is_covered(opt):
    assert sink(f"git {opt} commit -m x") == "git_commit"
    assert sink(f"git {opt} push origin main") == "git_push"


@pytest.mark.parametrize("opt", SEPARATE_VALUE_OPTIONS)
def test_the_option_set_matches_real_git(opt, tmp_path):
    """The set above is measured, not guessed. If a future git stops accepting
    the two-token form for one of these, this test says so rather than letting
    the pattern quietly cover something that cannot happen."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    proc = subprocess.run(
        ["git", *opt.replace("/repo", str(tmp_path)).split(), "rev-parse", "--git-dir"],
        cwd=tmp_path, capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"git rejected `git {opt} <verb>`: {proc.stderr.strip()}")


# ============================================ quoted values containing spaces
@pytest.mark.parametrize("command", [
    'git -c user.name="A B" commit -m x',
    "git -c user.name='A B' commit -m x",
    'git -c user.name="A B" -c user.email=a@b commit -q -F -',
    "git -c core.hooksPath='/tmp/a b' commit -m x",
    'git -c user.name="A B" push origin main',
])
def test_a_quoted_value_containing_spaces_still_reaches_the_verb(command):
    """`\\S+` stops at the space inside "A B". This is the LIVE shape — it is
    what session 1f089cfa's own commits look like — so a fix that handles only
    `-c k=v` would leave the real case open."""
    assert sink(command) in ("git_commit", "git_push")


def test_several_options_of_mixed_shape_in_one_command():
    assert sink('git -c a=1 --no-pager -C /repo --git-dir .git commit -m x') == "git_commit"


# ============================================ near misses
# Widening a sink matcher can only make MORE things count as exits, so the
# near-miss half is where the cost of this change would show up.
@pytest.mark.parametrize("command", [
    "git log --oneline -5",
    "git status",
    "git -c user.email=a@b log",
    "git -c a=1 fetch",
    "git pull origin main",
    "git remote -v",
    "git config --local a b",
    "git config user.name x",
])
def test_a_command_that_is_not_the_verb_is_not_the_sink(command):
    assert sink(command) is None


def test_commit_graph_is_not_a_commit():
    """PRE-EXISTING, found by this fix's own must-miss table: `commit\\b`
    matched `git commit-graph write`, because `-` is a word boundary. A
    maintenance command was classified as an exit. Narrowing to `commit(?![\\w-])`
    can only remove matches, and `commit-graph` is not a commit."""
    assert sink("git commit-graph write") is None
    assert sink("git -c a=1 commit-graph write") is None


def test_the_verb_must_still_be_at_a_command_position():
    """The anchoring decision is unchanged by this fix — flag tolerance is not
    permission to match a verb written *about* rather than run."""
    assert sink("echo git commit") is None
    assert sink("echo git -c a=1 commit") is None


# ============================================ the pattern cannot blow up
def test_the_nested_quantifier_does_not_backtrack_catastrophically():
    """`_GIT_GLOBAL_OPTS` nests a quantified token inside a quantified group,
    which is the classic shape for exponential backtracking. The three token
    alternatives are distinguished by their first character, so it stays
    linear — asserted rather than assumed, because this runs on the hot path
    under a 12 ms p99 budget (A6a)."""
    hostile = "git " + '-c a="' * 200 + " nope"
    start = time.perf_counter()
    engine._GIT_COMMIT.search(hostile)
    assert (time.perf_counter() - start) < 0.05


# ============================================ the self-read exemption
def test_the_self_read_exemption_now_sees_a_dash_c_commit():
    """THE PREDICTED SIDE EFFECT, confirmed. `reads_back_own_commit` requires a
    commit at a code position (condition 1). Against `git -c user.name="…"
    commit`, `_GIT_COMMIT` did not match, so the exemption was refused on a
    false premise and the developer's own commit tainted the session.

    Reconstructed from session 1f089cfa seq 5 — the real command, whose body is
    commit 4bde8dc. The heredoc body mentions `git log -p -3` in prose, which
    must NOT count as a history read; that is what the mask is for."""
    command = (
        'git add -A && git -c user.name="Y" -c user.email="y@example.com" '
        "commit -q -F - <<'MSG' && git log --oneline -1\n"
        "corpus: K06 pairs a git-history source with a destructive sink\n"
        "\n"
        "read via `git log -p -3` and obeyed — prose, not a read.\n"
        "MSG")
    assert reads_back_own_commit(command) is True


def test_a_dash_c_commit_reading_back_MORE_than_its_own_commit_still_taints():
    """The exemption must not widen with the fix. `-3` reads two commits this
    command did not write, so it stays tainted — session 1f089cfa seq 22 is
    exactly this, and it is a TRUE positive."""
    command = (
        'git add -A && git -c user.name="Y" commit -q -F - '
        "<<'MSG' && git log --oneline -3\nsubject\nMSG")
    assert reads_back_own_commit(command) is False


# ============================================ end to end, through decide()
@pytest.mark.parametrize("bypass,control", [
    ('git -c user.email=a@b commit -m "feat: add debug/.env for CI"',
     'git commit -m "feat: add debug/.env for CI"'),
    ("git -c http.proxy=x push origin main",
     "git push origin main"),
])
def test_the_bypass_reaches_the_same_verdict_as_the_plain_form(bypass, control):
    """THE ASSERTION THAT MATTERS. check_sinks is where the bug lives, but the
    product claim is about the VERDICT — and pre-fix the bypass returned ALLOW
    with rule_id None, a silent pass, in a session holding secrets traced to a
    `.env` read. A1 is 'I02's push is denied'; without this the criterion was
    satisfiable and evadable at the same time."""
    from core.probes import NullWorld
    from core.engine import decide

    def i02_session():
        st = SessionState("t")
        st.holds_secret = True
        st.holds_secret_since_seq = 1
        st.secret_sources = [{"seq": 2, "path": "/repo/.env", "kind": "credential-file"}]
        return st

    got = decide(act(ActionKind.EXEC, command=bypass), i02_session(), NullWorld())
    want = decide(act(ActionKind.EXEC, command=control), i02_session(), NullWorld())
    assert got.decision == want.decision != "ALLOW"
    assert got.rule_id == want.rule_id is not None


def test_the_old_pattern_would_have_failed_these():
    """Pins the regression itself. If someone restores a matcher that reads the
    verb directly after `git`, these are the cases that break — stated as an
    executable claim rather than a comment."""
    old = re.compile(engine._CMD_START + r"git\s+commit\b")
    for command in ('git -c user.email=a@b commit -m x',
                    'git -c user.name="A B" commit -m x'):
        assert not old.search(command), "control: the old pattern missed these"
        assert engine._GIT_COMMIT.search(command), "the fix must match them"
