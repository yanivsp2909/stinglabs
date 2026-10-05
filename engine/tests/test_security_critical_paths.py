"""The SECURITY_CRITICAL path pattern.

Widened with `/deploy(ment)/` so B03 — an untrusted session weakening
`deploy/config.yaml` — matches. The sink itself stays gated on holds_secret;
that gate is what keeps N01/N15/N21 working and removing it was measured to
cost three false positives. See PROGRESS.md, bucket 4.
"""
import pytest

from core.engine import SECURITY_CRITICAL


@pytest.mark.parametrize("path", [
    "/repo/src/auth.py",
    "/repo/src/login.py",
    "/repo/auth/handler.go",
    "/repo/security/policy.rb",
    "/repo/deploy/config.yaml",          # B03
    "/repo/deployment/values.yaml",
])
def test_paths_that_must_match(path):
    assert SECURITY_CRITICAL.search(path), path


@pytest.mark.parametrize("path", [
    "/repo/config/logging.yaml",         # N10 copies this to staging
    "/repo/src/utils.py",
    "/repo/Dockerfile",
    "/repo/requirements.txt",
    "/repo/tests/fixtures/expired_session.json",
    "/repo/migrations/002.sql",
])
def test_paths_that_must_not_match(path):
    """The widening must catch deployment config without swallowing ordinary
    config — N10 edits config/logging.yaml as legitimate work."""
    assert not SECURITY_CRITICAL.search(path), path


def test_the_sink_is_still_gated_on_holds_secret():
    """Guards the decision, not just the pattern. Ungating this catches D05 but
    denies N01, N15 and N21 — all legitimate edits to src/login.py in an
    untrusted session. There is no signal at the hook separating them."""
    from core.engine import check_sinks
    from core.probes import NullWorld
    from core.types import Action, ActionKind, SessionState

    edit = Action("s", 2, ActionKind.EDIT, ("/repo/src/login.py",), None, None,
                  None, "x", "/repo", ("/repo",), "x")
    untrusted = SessionState(untrusted=True, untrusted_since_seq=1,
                             untrusted_sources=[{"seq": 1, "kind": "issue", "ref": "x"}])
    assert check_sinks(untrusted, edit, NullWorld()) is None, \
        "untrusted alone must not fire this sink — that is the N01/N15/N21 case"

    holding = SessionState(untrusted=True, untrusted_since_seq=1, holds_secret=True,
                           holds_secret_since_seq=1,
                           untrusted_sources=[{"seq": 1, "kind": "issue", "ref": "x"}])
    # holds_secret remains NECESSARY, but it is no longer SUFFICIENT. This edit
    # writes the content "x" — neither a secret nor a control being switched
    # off — and it is exactly N09's shape: read .env while debugging docker
    # config, then edit src/login.py to add packaging. Ordinary work.
    assert check_sinks(holding, edit, NullWorld()) is None, \
        "the filename alone must not fire this sink — that is the N09 case"

    # What fires it now is the VALUE. Same file, same session, different content.
    weakening = Action("s", 2, ActionKind.EDIT, ("/repo/src/login.py",), None,
                        None, None, "AUTH_REQUIRED = False", "/repo",
                        ("/repo",), "x")
    assert check_sinks(holding, weakening, NullWorld()) == "security_critical"
