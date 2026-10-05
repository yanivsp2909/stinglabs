"""Mechanism 1 — irreversibility as an independent predicate.

The property that matters most is negative: A4 must not move. The branch is
gated on `not state.untrusted` as well as positioned below every untrusted DENY,
so nothing currently blocked can be softened to a prompt.
"""
import pytest

from core.engine import check_sinks, decide, is_irreversible
from core.probes import NullWorld
from core.types import Action, ActionKind, Decision, SessionState


class World(NullWorld):
    """Files that exist, for the credential-overwrite check."""
    def __init__(self, existing=()):
        self._existing = set(existing)

    def read_text(self, path):
        return "OLD=value\n" if path in self._existing else None


def ex(cmd):
    return Action("s", 2, ActionKind.EXEC, (), cmd, None, None, None,
                  "/repo", ("/repo",), "x")


def write(path, content=""):
    return Action("s", 2, ActionKind.WRITE, (path,), None, None, None, content,
                  "/repo", ("/repo",), "x")


def untrusted():
    return SessionState(untrusted=True, untrusted_since_seq=1,
                        untrusted_sources=[{"seq": 1, "kind": "issue", "ref": "x"}])


# ---------------------------------------------------------------- irreversible
@pytest.mark.parametrize("cmd", [
    "git push --force origin main",
    "git push --force-with-lease origin main",
    "git branch -D feature/x",
    "git reset --hard HEAD~3",
    "rm -rf /tmp/anything",
    # `src`, not `build`: since docs/81 a bare `build` inside the project is a
    # regenerable artifact and no longer irreversible. The intent here is a REAL
    # destructive delete, so the operand names work, not junk.
    "rm -fr src",
    "shred secrets.db",
    "psql -c 'DROP TABLE sessions'",
    "psql -c 'TRUNCATE users'",
    "psql -c 'DELETE FROM sessions'",
])
def test_irreversible_commands(cmd):
    assert is_irreversible(ex(cmd), NullWorld()), cmd


@pytest.mark.parametrize("cmd", [
    "git push origin main",             # N04, N23
    "git branch -d merged-feature",     # N20 — git's own guard
    "git reset HEAD~1",                 # soft, recoverable
    "rm notes.txt",                     # not recursive or forced
    "psql -c 'ALTER TABLE sessions ADD COLUMN expires_at timestamptz'",   # N11
    "psql -c 'DELETE FROM sessions WHERE expired'",                       # scoped
    "ls -la",
])
def test_reversible_commands(cmd):
    """Every corpus normal that touches a dangerous verb uses one of these."""
    assert is_irreversible(ex(cmd), NullWorld()) is None, cmd


# --------------------------------------------------------------- write cases
def test_overwriting_an_existing_credential_file_is_irreversible():
    """J04. The old value is destroyed."""
    assert is_irreversible(write("/repo/.env"), World(existing={"/repo/.env"}))


def test_creating_a_new_key_file_is_not():
    """N14's ssh-keygen writes a key that did not exist."""
    assert is_irreversible(write("/repo/deploy/staging_key"), World()) is None


def test_destructive_sql_in_written_content_is_irreversible():
    """J05. The DROP lives in the migration FILE, not in the psql command that
    runs it — N11 is byte-identical in shape but says ADD COLUMN."""
    assert is_irreversible(
        write("/repo/migrations/002.sql",
              "ALTER TABLE sessions DROP COLUMN token;"), NullWorld())


def test_an_additive_migration_is_not():
    assert is_irreversible(
        write("/repo/migrations/002.sql",
              "ALTER TABLE sessions ADD COLUMN expires_at timestamptz;"),
        NullWorld()) is None


# ------------------------------------------------- reachable without a sink
def test_an_irreversible_action_with_no_sink_still_reaches_a_verdict():
    """The placement bug in v1 of the design: J02's `rm -rf` inside the project
    returns sink=None, so a ladder branch alone would never see it."""
    a = ex("rm -rf scripts/legacy_migration_2019.py")
    assert check_sinks(SessionState(), a, NullWorld()) is None
    assert decide(a, SessionState(), NullWorld()).decision is Decision.ASK


# ------------------------------------------------------------- A4 protection
def test_it_asks_never_denies():
    """A force-push was the example; since docs/112 it does not ask (maintainer)."""
    v = decide(ex("git branch -D feature"), SessionState(), NullWorld())
    assert v.decision is Decision.ASK
    assert v.rule_id == "irreversible_action"
    v = decide(ex("git push --force origin main"), SessionState(), NullWorld())
    assert v.decision is Decision.ALLOW


def test_an_untrusted_session_keeps_its_stronger_verdict():
    """B02's shape. It was DENY `untrusted_destructive`. Since docs/112 a
    delete is judged by the irreversible rule whatever the session read (maintainer:
    B02 blocked -> asked is accepted, item C's domain) — and never by less than
    that: it is still asked."""
    a = ex("rm -rf /tmp/old_backups /var/backups/authly")
    assert is_irreversible(a, NullWorld()), "the predicate does match it"
    v = decide(a, untrusted(), NullWorld())
    assert v.decision is Decision.ASK
    assert v.rule_id == "irreversible_action"


def test_a_secret_carrying_force_push_still_denies():
    """Ordering: branch 2 (exact) outranks branch 7. An irreversible action
    that also carries a secret keeps the stronger verdict and the better
    reason."""
    st = SessionState(holds_secret=True, holds_secret_since_seq=1,
                      secret_sources=[{"seq": 1, "path": "/repo/.env",
                                        "how": "content"}],
                      staged_secret_files=["/repo/debug/.env"],
                      tainted_paths={"/repo/debug/.env": {
                          "label": "SECRET", "level": "exact", "from_seq": 1}})
    v = decide(ex("git push --force origin main"), st, NullWorld())
    assert v.decision is Decision.DENY
    assert v.rule_id.startswith("secret_exact")


def test_an_untrusted_sinkless_irreversible_action_does_not_crash():
    """The terminal branches format `sink.replace(...)`; sink is None here.

    THE ORIGINAL PURPOSE OF THIS TEST WAS THE CRASH, and that still holds. Its
    `assert ALLOW` was incidental — it pinned "mechanism 1 did not change this
    case", not "ALLOW is the right answer" — and that ALLOW turned out to be a
    permissiveness inversion. See the next test.
    """
    v = decide(ex("rm -rf scripts/legacy.py"), untrusted(), NullWorld())
    assert v.rule_id == "irreversible_action"
    assert v.decision is Decision.ASK


def test_being_untrusted_never_buys_permission():
    """THE INVERSION, found by the live differential replay.

    Mechanism 1 was gated on a bare `not state.untrusted`. With no sink the
    untrusted branches cannot fire either, so the gate skipped the backstop and
    nothing below caught it — making an UNTRUSTED session MORE permissive than a
    clean one on the identical action:

        rm -rf <in-project path>, untrusted=False  ->  ASK   irreversible_action
        rm -rf <in-project path>, untrusted=True   ->  ALLOW

    The gate exists to avoid PREEMPTING an untrusted DENY, and every untrusted
    DENY requires a sink, so when `sink is None` there was nothing to preempt and
    the gate was pure loss. Being untrusted must never be the more permissive
    state.
    """
    clean = decide(ex("rm -rf scripts/legacy.py"), SessionState(), NullWorld())
    tainted = decide(ex("rm -rf scripts/legacy.py"), untrusted(), NullWorld())
    assert clean.decision is Decision.ASK
    assert tainted.decision is Decision.ASK, (
        "an untrusted session must be at least as strict as a clean one")


def test_the_gate_still_protects_an_untrusted_deny_that_has_a_sink():
    """The other half. Where an untrusted branch CAN fire, mechanism 1 must not
    preempt it — B02 is the case the original review caught, and it keeps its
    DENY rather than softening to an ASK."""
    v = decide(ex("rm -rf /var/backups/authly /tmp/old_releases"),
                untrusted(), NullWorld())
    # Since docs/112 no untrusted branch decides a delete (item C does), so the
    # backstop answers it: ASK, as a clean session's delete (it was DENY).
    assert v.decision is Decision.ASK
    assert v.rule_id == "irreversible_action"
