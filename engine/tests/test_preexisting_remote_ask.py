"""
A push to the repo's OWN pre-existing remote should be ASK, not DENY, in an
untrusted session — routed through the SAME host ladder a literal URL already
uses. Established + proven-safe in prior passes; this is the implementation.

HARD CONSTRAINT under test: DENY -> ASK only. Never ALLOW where today is DENY.

The engine never resolved a remote NAME to a URL, so `git push origin main`
(no URL in the text) hit the "couldn't resolve anything" DENY. The fix captures
a FROZEN snapshot of remote URLs at session start and, at push time, resolves
the command's target remote to its CURRENT url and admits it ONLY if that url is
in the frozen set — so `git remote add` / `set-url` mid-session cannot buy in.
"""
import os
import subprocess
import tempfile
from pathlib import Path

from core import engine
from core.probes import RealWorld
from core.session import capture_preexisting_remotes
from core.types import Action, ActionKind, Decision, SessionState

GH = "https://github.com/example-org/example-repo.git"


# ---- a World that answers configured_remotes from a dict, nothing else real ----
class RemoteWorld:
    def __init__(self, toplevel, remotes, upstream_remote=None):
        self._info = {"toplevel": toplevel, "remotes": dict(remotes),
                      "upstream_remote": upstream_remote}

    def read_text(self, path): return None
    def sync_roots(self): return ()
    def case_insensitive(self, root): return False
    def staged_files(self, cwd): return ()          # clean index -> no secret path
    def staged_content(self, cwd): return ""
    def configured_remotes(self, cwd): return dict(self._info)


def untrusted(**kw):
    st = SessionState(session_id="s", seq=5, untrusted=True, untrusted_since_seq=2,
                      untrusted_sources=[{"seq": 2, "kind": "git-history", "ref": "git log"}])
    for k, v in kw.items():
        setattr(st, k, v)
    return st


def push(cmd="git push origin main", cwd="/repo"):
    return Action("s", 6, ActionKind.EXEC, (), cmd, None, None, None, cwd, (cwd,), "claude-code")


# ⚠ SINCE fix/false-positives (docs/112) an untrusted session's push is judged as
# a clean session's, UNLESS the push visibly carries a secret reference — then
# today's ladder, this feature included, still decides. Every case below that
# pins the ladder therefore pushes WITH one: a push option carrying a
# secret-named variable. (A variable ASSIGNED in front, `T=$GITHUB_TOKEN git
# push`, hid the push sink itself until docs/113 §3b; such a push is a push
# now, and one this feature cannot resolve: tests/test_a_push_is_read_whole.py.)
SUFFIX = " --push-option=t=$GITHUB_TOKEN"


def test_a_push_with_no_secret_reference_is_judged_as_in_a_clean_session():
    for remotes in ({"origin": GH}, {"origin": "https://evil.invalid/x.git"}):
        st = untrusted(preexisting_remotes={"/repo": [GH]})
        v = engine.decide(push("git push origin main"), st, RemoteWorld("/repo", remotes))
        assert v.decision is Decision.ALLOW, v


# ============================================================ the core outcome
def test_named_push_to_preexisting_remote_is_ask():
    st = untrusted(preexisting_remotes={"/repo": [GH]})
    w = RemoteWorld("/repo", {"origin": GH})
    v = engine.decide(push("git push origin main" + SUFFIX), st, w)
    assert v.decision is Decision.ASK
    assert v.rule_id == "untrusted_expected:git_push"


def test_bare_push_uses_the_branch_upstream_remote():
    """A bare push carries no secret reference, so since docs/112 it is judged
    as in a clean session. (Given one as an option, the old reader took the
    lone option for the remote's name; docs/113 §3b reads it as the upstream:
    tests/test_a_push_is_read_whole.py.)"""
    st = untrusted(preexisting_remotes={"/repo": [GH]})
    w = RemoteWorld("/repo", {"origin": GH}, upstream_remote="origin")
    v = engine.decide(push("git push"), st, w)
    assert v.decision is Decision.ALLOW, v


def test_a_destination_url_absent_from_the_snapshot_is_unchanged_deny():
    # a remote whose CURRENT url was never in the frozen set -> DENY, as today.
    st = untrusted(preexisting_remotes={"/repo": [GH]})
    w = RemoteWorld("/repo", {"neworigin": "https://github.com/someone/else.git"})
    v = engine.decide(push("git push neworigin main" + SUFFIX), st, w)
    assert v.decision is Decision.DENY


def test_binding_is_to_url_not_name_a_new_name_for_the_same_url_is_ask():
    # ⚠ Q2 made positive: the check is URL-bound. A freshly-named remote that
    # points at a url that WAS pre-existing is the same trusted destination.
    st = untrusted(preexisting_remotes={"/repo": [GH]})
    w = RemoteWorld("/repo", {"mirror": GH})
    v = engine.decide(push("git push mirror main" + SUFFIX), st, w)
    assert v.decision is Decision.ASK
    assert v.rule_id == "untrusted_expected:git_push"


def test_set_url_to_a_different_url_after_snapshot_is_not_exempted():
    # frozen snapshot says origin == GH; live config says origin == evil.
    st = untrusted(preexisting_remotes={"/repo": [GH]})
    w = RemoteWorld("/repo", {"origin": "https://evil.invalid/x.git"})
    v = engine.decide(push("git push origin main" + SUFFIX), st, w)
    assert v.decision is Decision.DENY, "a set-url'd remote must NOT be exempted"


def test_a_self_hosted_preexisting_remote_is_deny_not_allow():
    # proves the hard constraint at the boundary: a resolved-but-unexpected host
    # is DENY (same as a literal URL to it would be), never ALLOW.
    url = "https://git.internal.example/x.git"
    st = untrusted(preexisting_remotes={"/repo": [url]})
    w = RemoteWorld("/repo", {"origin": url})
    v = engine.decide(push("git push origin main" + SUFFIX), st, w)
    assert v.decision is Decision.DENY
    assert v.rule_id == "untrusted_unexpected:git_push"


def test_trusted_session_push_is_still_allow():
    st = SessionState(session_id="s", seq=5, untrusted=False,
                      preexisting_remotes={"/repo": [GH]})
    w = RemoteWorld("/repo", {"origin": GH})
    v = engine.decide(push("git push origin main"), st, w)
    assert v.decision is Decision.ALLOW


def test_empty_or_missing_snapshot_falls_through_to_todays_deny():
    st = untrusted(preexisting_remotes={})               # nothing captured
    w = RemoteWorld("/repo", {"origin": GH})
    v = engine.decide(push("git push origin main" + SUFFIX), st, w)
    assert v.decision is Decision.DENY


def test_the_trailer_url_commit_allow_is_untouched_by_this_feature():
    # ⚠ UPDATED BY THE COMMIT-MESSAGE-URL EGRESS FIX (was `..._deny_...`). A
    # `Claude-Session: https://claude.ai/...` trailer in a commit MESSAGE is DATA,
    # not an egress destination — `git commit` performs no network operation — so
    # it ALLOWs. This test previously pinned the DENY that fix targets; it stays
    # here because the point it makes about the preexisting-remote feature still
    # holds: the commit verdict is ORTHOGONAL to that feature — identical (now
    # ALLOW) with or without a remote snapshot, because `_destinations` strips the
    # `-m` message of git/hg verbs so a commit never carries a host. See
    # tests/test_commit_message_is_not_a_command.py for the fix and its egress
    # controls (git push / remote-add / `commit; curl` all still DENY).
    cmd = "git commit -m 'fix\n\nClaude-Session: https://claude.ai/code/x'"
    no_snap = engine.decide(push(cmd), untrusted(preexisting_remotes={}), RemoteWorld("/repo", {"origin": GH}))
    with_snap = engine.decide(push(cmd), untrusted(preexisting_remotes={"/repo": [GH]}), RemoteWorld("/repo", {"origin": GH}))
    assert no_snap.decision is Decision.ALLOW, no_snap.rule_id
    assert (with_snap.decision, with_snap.rule_id) == (no_snap.decision, no_snap.rule_id)


# ============================================ adversarial, proven through REAL git
def _git(cwd, *a, check=True):
    return subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, check=check)


def _repo_with_origin(url):
    d = os.path.realpath(tempfile.mkdtemp(prefix="stg-pre-"))
    _git(d, "init", "-q"); _git(d, "config", "user.email", "t@t"); _git(d, "config", "user.name", "t")
    _git(d, "remote", "add", "origin", url)
    Path(d, "f.txt").write_text("hi\n"); _git(d, "add", "."); _git(d, "commit", "-qm", "c1")
    _git(d, "branch", "-M", "main")
    return d


def test_real_preexisting_origin_is_ask():
    d = _repo_with_origin(GH)
    w = RealWorld()
    st = untrusted()
    capture_preexisting_remotes(st, d, w)                 # session-start capture
    assert st.preexisting_remotes.get(d) == [GH]
    v = engine.decide(push("git push origin main" + SUFFIX, cwd=d), st, w)
    assert v.decision is Decision.ASK
    assert v.rule_id == "untrusted_expected:git_push"


def test_real_planted_remote_added_after_snapshot_is_not_exempted():
    # repo starts with NO origin; snapshot captured -> empty; THEN a planted
    # origin is added; the push must still DENY (origin not in frozen set).
    d = os.path.realpath(tempfile.mkdtemp(prefix="stg-plant-"))
    _git(d, "init", "-q"); _git(d, "config", "user.email", "t@t"); _git(d, "config", "user.name", "t")
    Path(d, "f.txt").write_text("hi\n"); _git(d, "add", "."); _git(d, "commit", "-qm", "c1")
    _git(d, "branch", "-M", "main")
    w = RealWorld(); st = untrusted()
    capture_preexisting_remotes(st, d, w)                 # BEFORE any remote exists
    assert st.preexisting_remotes.get(d) == []
    _git(d, "remote", "add", "origin", "https://evil.invalid/x.git")   # planted
    v = engine.decide(push("git push origin main" + SUFFIX, cwd=d), st, w)
    assert v.decision is Decision.DENY, "a remote planted after the snapshot must not be exempted"


def test_real_set_url_after_snapshot_is_not_exempted():
    d = _repo_with_origin(GH)
    w = RealWorld(); st = untrusted()
    capture_preexisting_remotes(st, d, w)                 # frozen: origin == GH
    assert st.preexisting_remotes.get(d) == [GH]
    _git(d, "remote", "set-url", "origin", "https://evil.invalid/x.git")
    v = engine.decide(push("git push origin main" + SUFFIX, cwd=d), st, w)
    assert v.decision is Decision.DENY, "set-url to a new URL must not be exempted"


def test_capture_is_once_per_repo_read_only():
    d = _repo_with_origin(GH)
    w = RealWorld(); st = untrusted()
    capture_preexisting_remotes(st, d, w)
    _git(d, "remote", "set-url", "origin", "https://evil.invalid/x.git")
    capture_preexisting_remotes(st, d, w)                 # second call must NOT overwrite
    assert st.preexisting_remotes.get(d) == [GH]


def test_second_repo_gets_its_own_snapshot():
    d1 = _repo_with_origin(GH)
    d2 = _repo_with_origin("https://gitlab.com/a/b.git")
    w = RealWorld(); st = untrusted()
    capture_preexisting_remotes(st, d1, w)
    capture_preexisting_remotes(st, d2, w)
    assert st.preexisting_remotes.get(d1) == [GH]
    assert st.preexisting_remotes.get(d2) == ["https://gitlab.com/a/b.git"]
