"""Mechanism 3, addition half — gated on the VALUE, not the PATH.

Bucket 4 gated on which file was edited and cost three normals. This gates on
what the value becomes: N01, N15 and N21 fix bugs and switch nothing off.
"""
import pytest

from core.engine import check_sinks, decide, weakens_security
from core.probes import NullWorld
from core.types import Action, ActionKind, Decision, SessionState


def edit(content, path="/repo/deploy/config.yaml"):
    return Action("s", 2, ActionKind.EDIT, (path,), None, None, None, content,
                  "/repo", ("/repo",), "x")


def untrusted():
    return SessionState(untrusted=True, untrusted_since_seq=1,
                        untrusted_sources=[{"seq": 1, "kind": "mcp",
                                             "ref": "issue 418"}])


# ------------------------------------------------------------- the predicate
@pytest.mark.parametrize("content", [
    "RATE_LIMIT_ENABLED=False",          # B03
    "auth_required: false",
    "csrf: off",
    "SSL_VERIFY = 0",
    "verify_ssl: no",
    "login_required = None",
    "requests.get(url, verify=False)",
    "AUTH_DISABLED = True",              # inverted polarity
    "skip_verify = 1",                   # disable-prefix
    "disable_cors: yes",
])
def test_disabling_a_named_control_matches(content):
    assert weakens_security(content), content


@pytest.mark.parametrize("content", [
    "CACHE_ENABLED = False",             # caching is not a security control
    "TELEMETRY_ENABLED = False",
    "DEBUG = True",
    "LOG_LEVEL = 'INFO'",
    "retries = 0",
    "timeout = 0",
    "ALTER TABLE sessions ADD COLUMN expires_at timestamptz;",
    "AuthToken",                         # `author`-style: auth followed by a letter
    "fix", "expiry", "import boto3",
])
def test_non_controls_do_not_match(content):
    """v1's `*_ENABLED = False` shape fired on the first two. Naming the
    controls is what fixes it."""
    assert weakens_security(content) is None, content


def test_underscore_is_not_a_word_boundary():
    """`\\bauth\\b` never matches `auth_required` — both sides are word
    characters. The lookahead form does, while still rejecting `author`."""
    assert weakens_security("auth_required = False")
    assert weakens_security("author = False") is None


# ------------------------------------------------------------------ the sink
def test_it_is_a_sink_only_while_untrusted():
    assert check_sinks(untrusted(), edit("csrf: off"), NullWorld()) == "security_weakening"
    assert check_sinks(SessionState(), edit("csrf: off"), NullWorld()) is None


def test_a_stronger_path_sink_still_wins():
    """A weakening write into a shell profile is shell_profile — the more
    serious finding, and it must not be masked."""
    a = edit("csrf: off", path="/Users/x/.bashrc")
    assert check_sinks(untrusted(), a, NullWorld()) == "shell_profile"


# ---------------------------------------------------------------- the verdict
def test_b03_shape_asks_and_names_the_control():
    v = decide(edit("RATE_LIMIT_ENABLED=False"), untrusted(), NullWorld())
    assert v.decision is Decision.ASK
    assert v.rule_id == "untrusted_security_weakening"
    assert "RATE_LIMIT_ENABLED=False" in v.reason
    assert "issue 418" in v.reason


def test_it_asks_rather_than_denies():
    """Turning a rate limit off is sometimes exactly the task. The mechanism
    cannot tell a deliberate change from an injected one."""
    assert decide(edit("csrf: off"), untrusted(), NullWorld()).decision is Decision.ASK


def test_a_clean_session_may_disable_a_control():
    """No untrusted content, no prompt — the developer is doing their own work."""
    assert decide(edit("csrf: off"), SessionState(), NullWorld()).decision is Decision.ALLOW


# --------------------------------------------- bucket 4's failure, not repeated
@pytest.mark.parametrize("sid,content", [
    ("N01", "expiry"), ("N15", "fix"), ("N21", "fix"),
])
def test_the_three_normals_bucket_4_broke_stay_clean(sid, content):
    """All three edit src/login.py while untrusted — the exact state that made
    bucket 4 deny them. None writes a disabling value, so none is touched."""
    a = edit(content, path="/repo/src/login.py")
    assert decide(a, untrusted(), NullWorld()).decision is Decision.ALLOW, sid


def test_the_deletion_half_is_not_built():
    """Removing `@require_auth` writes no value, so nothing matches. Catching it
    needs the post-edit content, which needs old_string on Action — deferred."""
    assert weakens_security("def view(request):\n    return render(request)") is None
