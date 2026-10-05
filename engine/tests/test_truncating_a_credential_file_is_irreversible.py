"""A shell redirect that truncates an EXISTING credential file cannot be undone.

THE GAP. `is_irreversible` already says so for a Write or Edit — "overwriting an
existing credential file destroys the old value; creating a NEW key file does
not" — and scopes it exactly: the destination must be credential-shaped
(`CREDENTIAL_PATHS`) AND already exist (`world.read_text` is not None). The
EXEC branch had no twin. `echo x > .env`, `: > id_rsa` and `cat > .netrc`
destroy the same bytes through a different verb, and every one of them ALLOWED.

WHY NOT `_TRUNCATING_REDIRECT`. That pattern exists to record AUTHORSHIP for the
deferred rule ("did this session create the target"), so it requires one of a
short verb list plus a source operand — it does not match `: > id_rsa` or a bare
`echo > .env` at all, and widening it would widen what counts as "ours", which
is the LOOSENING direction. The irreversibility check therefore uses its own
target extractor and leaves authorship untouched.

THE SCOPING IS THE WHOLE FIX. An EXEC redirect fires only when BOTH of the
Write/Edit conditions hold. Ordinary `>` usage — a new file, a non-credential
file, an append — must be exactly as silent as it is today; regressing that
would worsen the dominant real problem (over-tainting) to close a narrower one.
The `>` must also sit at a CODE position: `echo "x > .env"` prints a string and
redirects nothing.

THE VERDICT IS THE ENGINE'S OWN, NOT A NEW ONE. Once `is_irreversible` says so,
the action passes the early "no sink, nothing irreversible" gate and reaches
the ladder — where the EXEC branch of `_secret_level` already treats an
irreversible operation on a credential path as `secret_exact:no_sink`. That is
precisely what `rm -rf .env` produces today, and the tests below pin the two as
identical. It is STRICTER than the Write path, which asks `irreversible_action`
for the same file; that asymmetry predates this change and is recorded here as
a finding, not resolved. Either way the baseline was ALLOW, so this can only
catch more.
"""
import pytest

from core import engine
from core.session import SessionState
from core.types import Action, ActionKind

ROOT = "/repo"
_CRED = "this overwrites an existing credential file"
# The rule the ladder reaches for an irreversible op on a credential path — the
# same one `rm -rf .env` has always produced. See the module docstring.
_NO_SINK = "secret_exact:no_sink"


class FakeWorld:
    def __init__(self, files=None):
        self.files = files or {}

    def sync_roots(self):
        return None

    def case_insensitive(self, root):
        return None

    def read_text(self, path):
        return self.files.get(path)

    def project_roots(self, cwd):
        return ((cwd,) if cwd else ()), None

    def staged_files(self, cwd):
        return None

    def staged_content(self, cwd):
        return None


def _exec(command, cwd=ROOT):
    return Action(session_id="t", seq=1, kind=ActionKind.EXEC, paths=(),
                  command=command, url=None, tool_name="Bash", content=None,
                  cwd=cwd, workspace_roots=(cwd,), agent="claude-code")


# The credential files EXIST in this world; notes.txt exists and is ordinary.
EXISTING = {
    f"{ROOT}/.env": "DB_PASSWORD=old\n",
    f"{ROOT}/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    f"{ROOT}/.netrc": "machine x login y password z\n",
    f"{ROOT}/.npmrc": "//registry/:_authToken=old\n",
    f"{ROOT}/notes.txt": "hello\n",
}


def _why(command, files=EXISTING):
    return engine.is_irreversible(_exec(command), FakeWorld(files))


def _verdict(command, files=EXISTING):
    state = SessionState("t")
    return engine.decide(_exec(command), state, FakeWorld(files))


# ─────────────────────────────────────────────────────────────────────────────
# THE GAP: truncating an existing credential file through a redirect.
# ─────────────────────────────────────────────────────────────────────────────
_TRUNCATES = [
    ("echo-to-env", "echo x > .env"),
    ("null-command-to-id-rsa", ": > id_rsa"),
    ("bare-echo-to-env", "echo > .env"),
    ("printf-to-netrc", "printf '' > .netrc"),
    ("cat-heredoc-to-npmrc", "cat > .npmrc <<'EOF'\nnew\nEOF"),
    ("stderr-redirect-to-env", "true 2> .env"),
    ("absolute-target", f"echo x > {ROOT}/.env"),
]


@pytest.mark.parametrize("label,command", _TRUNCATES, ids=[c[0] for c in _TRUNCATES])
def test_truncating_an_existing_credential_file_is_irreversible(label, command):
    assert _why(command) == _CRED, (label, command)


@pytest.mark.parametrize("label,command", _TRUNCATES, ids=[c[0] for c in _TRUNCATES])
def test_the_verdict_denies_exactly_as_rm_rf_of_the_same_file_does(label, command):
    """The ladder's existing treatment of an irreversible op on a credential
    path, not a new verdict: `rm -rf <file>` and the truncation reach the same
    (decision, rule_id). Pinned as an EQUALITY so a later change to either side
    is visible, rather than as two literals that could drift apart."""
    v = _verdict(command)
    assert v.decision.value == "DENY", (label, command, v.decision, v.rule_id)
    assert v.rule_id == _NO_SINK, (label, v.rule_id)
    # the same file, destroyed by the verb the engine already judged this way
    target = command.split(">", 1)[1].split()[0]
    rm = _verdict(f"rm -rf {target}")
    assert (rm.decision, rm.rule_id) == (v.decision, v.rule_id), (label, rm, v)


# ─────────────────────────────────────────────────────────────────────────────
# MUST TEST: chaining. This project has a documented history of chaining
# defeating similar checks. A redirect is a redirect wherever it sits.
# ─────────────────────────────────────────────────────────────────────────────
_CHAINED = [
    ("redirect-then-and", "echo x > .env && ls"),
    ("and-then-redirect", "ls && echo x > .env"),
    ("redirect-then-semicolon", "echo x > .env; git status"),
    ("or-then-redirect", "false || echo x > .env"),
    ("piped-then-redirect", "printf x | tee /dev/null; echo y > .env"),
]


@pytest.mark.parametrize("label,command", _CHAINED, ids=[c[0] for c in _CHAINED])
def test_chaining_does_not_hide_the_truncation(label, command):
    assert _why(command) == _CRED, (label, command)
    v = _verdict(command)
    assert (v.decision.value, v.rule_id) == ("DENY", _NO_SINK), (label, v)


# ─────────────────────────────────────────────────────────────────────────────
# MUST TEST, NOT OPTIONAL: ordinary `>` stays exactly as silent as today.
# ─────────────────────────────────────────────────────────────────────────────
_STAYS_SILENT = [
    ("new-non-sensitive-file", "echo hello > notes-new.txt"),        # does not exist
    ("existing-non-sensitive-file", "echo hello > notes.txt"),      # exists, not a credential
    ("new-credential-file", "echo x > .env.local"),                 # credential-shaped, does NOT exist
    ("append-not-truncate", "echo x >> .env"),                      # `>>` adds; it destroys nothing
    ("quoted-not-a-redirect", 'echo "x > .env"'),                   # a string, no redirect
    ("single-quoted-not-a-redirect", "echo 'x > .env'"),
    ("dev-null", "echo x > /dev/null"),
    ("fd-dup-stderr", "make 2>&1"),
    ("fd-dup-stdout", "make >&2"),
    ("redirect-from-credential-to-plain", "cat .env > /tmp/copy"),  # the TARGET is not a credential
    ("no-redirect-at-all", "cat .env"),
]


@pytest.mark.parametrize("label,command", _STAYS_SILENT, ids=[c[0] for c in _STAYS_SILENT])
def test_ordinary_redirects_are_not_irreversible(label, command):
    assert _why(command) is None, (label, command, _why(command))


def test_a_new_file_and_an_existing_ordinary_file_still_allow():
    """End to end, the two cases that must not regress: a fresh non-sensitive
    file and an existing non-sensitive file. Both ALLOW, unchanged."""
    for command in ("echo hello > notes-new.txt", "echo hello > notes.txt"):
        v = _verdict(command)
        assert v.decision.value == "ALLOW", (command, v.decision, v.rule_id)


def test_creating_a_credential_file_that_does_not_exist_still_allows():
    """The Write/Edit rule's own line: creating a NEW key file is not
    destroying one. An EXEC redirect to a credential path that is not there
    yet is exactly that, and stays ALLOW."""
    v = _verdict("echo x > .env", files={})
    assert v.decision.value == "ALLOW", (v.decision, v.rule_id)
    assert _why("echo x > .env", files={}) is None


def test_the_exec_rule_is_the_write_rule_word_for_word():
    """The scoping is borrowed, not reinvented: the Write path gives the same
    reason for the same file, so a reader sees one rule, two verbs."""
    write = Action(session_id="t", seq=1, kind=ActionKind.WRITE,
                   paths=(f"{ROOT}/.env",), command=None, url=None,
                   tool_name="Write", content="new", cwd=ROOT,
                   workspace_roots=(ROOT,), agent="claude-code")
    assert engine.is_irreversible(write, FakeWorld(EXISTING)) == _CRED
    assert _why("echo x > .env") == _CRED


def test_the_reason_is_shared_but_the_exec_ladder_is_stricter():
    """A FINDING, PINNED, NOT RESOLVED. The two verbs give the same
    `is_irreversible` reason for the same file, yet the Write path ASKS
    (`irreversible_action`) while the EXEC path DENIES (`secret_exact:no_sink`)
    — because the EXEC branch of `_secret_level` treats any credential path the
    command operates on as exact, and the early gate no longer hides it. This
    asymmetry predates the truncation rule: `rm -rf .env` has always denied
    where a Write of the same file asks. Recorded here so it is a deliberate
    question for a later pass, never a silent drift in either direction."""
    write = Action(session_id="t", seq=1, kind=ActionKind.WRITE,
                   paths=(f"{ROOT}/.env",), command=None, url=None,
                   tool_name="Write", content="new", cwd=ROOT,
                   workspace_roots=(ROOT,), agent="claude-code")
    w = engine.decide(write, SessionState("t"), FakeWorld(EXISTING))
    e = _verdict("echo x > .env")
    assert (w.decision.value, w.rule_id) == ("ASK", "irreversible_action")
    assert (e.decision.value, e.rule_id) == ("DENY", _NO_SINK)


def test_authorship_marking_is_untouched():
    """`_TRUNCATING_REDIRECT` still feeds mark_authored exactly as before — the
    irreversibility check did not widen it. `: > id_rsa` matches the new target
    extractor but must NOT suddenly count as authored (that is the loosening
    direction for the deferred rule)."""
    assert engine._TRUNCATING_REDIRECT.findall(": > id_rsa") == []
    assert engine._TRUNCATING_REDIRECT.findall("echo x > .env") == [("x", ".env")]
