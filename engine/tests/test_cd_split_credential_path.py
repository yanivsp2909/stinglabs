"""A `cd` into a credential directory makes a bare read there a credential read.

THE GAP (establish pass, 2026-09-10). PR #38 closed the bare-relative DIRECT
spelling — `cat .aws/credentials`. It explicitly did not close the cd-split
form `cd .aws && cat credentials`: `_paths_mentioned_in` resolves every relative
token against the ONE static `action.cwd`, nothing folds a preceding `cd` into
an effective cwd, and `credentials`/`config`/`id_rsa` are generic filenames
never extracted as candidates on their own. So the second segment's
`credentials` resolved to `/repo/credentials` (not `/repo/.aws/credentials`) and
matched nothing.

THE FIX (Gate B, resolved-file-path). Per command segment, fold preceding
`cd`(s) to an effective cwd — reusing the SAME infra the rm/destructive path
uses (`_CD_PREFIX`/`_expand`/`_abs`/`_norm_path`/`_literal_assignments`) — and
emit a segment operand resolved against that cwd ONLY when the RESOLVED path
matches `CREDENTIAL_PATHS`. The resolved-path check (not a cwd-is-cred-dir
check) is what keeps `.docker` correct: only `.docker/config.json` is a
credential, never a bare `.docker/` dir, so `cd .docker && cat somefile.txt`
stays clean while `cd .docker && cat config.json` is caught.

The verdict/reason is IDENTICAL to the direct spelling for the same target,
because both routes feed the same `/repo/.aws/credentials` into the same
consumers. Dynamic `cd` targets (`$(...)`, an env var not assigned in-command)
resolve to a non-matching path and contribute nothing — the established
fail-open direction.
"""
import pytest

from core import engine
from core.session import SessionState
from core.types import Action, ActionKind

ROOT = "/repo"


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


def _holds_secret_after(command, files, cwd=ROOT):
    state = SessionState("t")
    world = FakeWorld(files)
    engine.decide(_exec(command, cwd), state, world)
    engine.mark_sources(state, _exec(command, cwd), world)
    return state.holds_secret


def _source_path_after(command, files, cwd=ROOT):
    """The credential-file path recorded as the session's secret SOURCE."""
    state = SessionState("t")
    world = FakeWorld(files)
    engine.decide(_exec(command, cwd), state, world)
    engine.mark_sources(state, _exec(command, cwd), world)
    return [s["path"] for s in state.secret_sources]


# ── the four credential dirs, cd-split: read must set holds_secret ────────────
# (label, cd-target, bare-file, the resolved credential path)
_CD_SPLIT = [
    ("aws",    ".aws",    "credentials", "/repo/.aws/credentials"),
    ("ssh",    ".ssh",    "id_rsa",      "/repo/.ssh/id_rsa"),
    ("ssh-cfg",".ssh",    "config",      "/repo/.ssh/config"),
    ("kube",   ".kube",   "config",      "/repo/.kube/config"),
    ("docker", ".docker", "config.json", "/repo/.docker/config.json"),
]


@pytest.mark.parametrize("label,d,f,resolved", _CD_SPLIT, ids=[c[0] for c in _CD_SPLIT])
def test_cd_into_cred_dir_then_bare_read_marks_the_session(label, d, f, resolved):
    files = {resolved: "AKIA_TEST_cd_split\n"}
    assert _holds_secret_after(f"cd {d} && cat {f}", files), (label, d, f)


@pytest.mark.parametrize("label,d,f,resolved", _CD_SPLIT, ids=[c[0] for c in _CD_SPLIT])
def test_cd_split_matches_the_direct_spelling_exactly(label, d, f, resolved):
    """Same holds_secret AND same recorded source path as `cat .aws/credentials`."""
    files = {resolved: "AKIA_TEST_cd_split\n"}
    direct = f"cat {d}/{f}"
    split = f"cd {d} && cat {f}"
    assert _holds_secret_after(split, files) == _holds_secret_after(direct, files)
    assert _source_path_after(split, files) == _source_path_after(direct, files) == [resolved]


def test_semicolon_separator_also_resolves():
    files = {"/repo/.aws/credentials": "AKIA_TEST\n"}
    assert _holds_secret_after("cd .aws; cat credentials", files)


def test_tilde_cd_target_resolves():
    files = {"/HOME/.aws/credentials": "AKIA_TEST\n"}
    assert _holds_secret_after("cd ~/.aws && cat credentials", files)


def test_literal_in_command_assignment_resolves():
    files = {"/repo/.aws/credentials": "AKIA_TEST\n"}
    assert _holds_secret_after("X=.aws; cd $X && cat credentials", files)


# ── MUST-NOT-REGRESS ──────────────────────────────────────────────────────────
def test_cd_into_lookalike_dir_does_not_match():
    files = {"/repo/my-aws-backup/readme.txt": "AKIA_TEST\n"}
    assert not _holds_secret_after("cd my-aws-backup && cat readme.txt", files)


def test_docker_non_config_file_does_not_match():
    """.docker is credential ONLY at config.json — a bare .docker/ dir is not."""
    files = {"/repo/.docker/daemon.json": "AKIA_TEST\n"}
    assert not _holds_secret_after("cd .docker && cat daemon.json", files)


def test_dynamic_command_substitution_target_stays_unresolved():
    files = {"/repo/.aws/credentials": "AKIA_TEST\n"}
    assert not _holds_secret_after("cd $(mktemp -d) && cat credentials", files)


def test_dynamic_env_var_target_stays_unresolved():
    files = {"/repo/.aws/credentials": "AKIA_TEST\n"}
    assert not _holds_secret_after('cd "$SECRETDIR" && cat credentials', files)


def test_no_cd_bare_generic_filename_still_does_not_match():
    """Without a cd into a cred dir, a bare `cat credentials` is just a file."""
    files = {"/repo/credentials": "AKIA_TEST\n"}
    assert not _holds_secret_after("cat credentials", files)


def test_direct_spelling_is_unchanged():
    """PR #38's form must keep working, byte-identical."""
    files = {"/repo/.aws/credentials": "AKIA_TEST\n"}
    assert _holds_secret_after("cat .aws/credentials", files)


# ─────────────────────────────────────────────────────────────────────────────
# NEWLINE BOUNDARY (2026-09-13 audit). `_CD_PREFIX` folded a `cd` after
# `;`/`&`/`|` but NOT after a newline, while the segment splitter (`_SEGMENT_END`
# = [;|&\n]) always treats a newline as a real boundary. So a `cd` on its own
# line — preceded by a newline rather than `&&` — was invisible to the fold, and
# a full read-then-exfiltrate sequence written line-by-line returned ALLOW.
# A `cd` at position 0 was saved only by the `^` branch; the gap is a `cd`
# preceded by a newline. RED before the one-char fix, GREEN after. The fix can
# only fold MORE `cd`s, so it can only ever catch MORE.
# ─────────────────────────────────────────────────────────────────────────────
_NEWLINE_FORMS = [
    # the exact audit case: a line before the cd, so it is NOT at position 0
    ("after-a-line", "echo start\ncd .aws\ncat credentials"),
    # a leading newline ahead of the cd
    ("leading-nl", "\ncd .aws\ncat credentials"),
    # a newline after an `&&` chain, then the cd on its own line
    ("nl-after-chain", "cd /repo && echo hi\ncd .aws\ncat credentials"),
    # semicolons and newlines mixed
    ("mixed-sep", "echo a;\ncd .aws\ncat credentials"),
]


@pytest.mark.parametrize("label,command", _NEWLINE_FORMS, ids=[c[0] for c in _NEWLINE_FORMS])
def test_cd_on_its_own_line_then_read_marks_the_session(label, command):
    """A `cd .aws` on its own line (preceded by a newline, not `&&`) followed by
    `cat credentials` must set holds_secret, exactly as the `&&` form does."""
    files = {"/repo/.aws/credentials": "AKIA_TEST_newline\n"}
    assert _holds_secret_after(command, files), (label, command)


def test_newline_form_matches_the_ampersand_form_exactly():
    files = {"/repo/.aws/credentials": "AKIA_TEST_newline\n"}
    amp = "echo start && cd .aws && cat credentials"
    nl = "echo start\ncd .aws\ncat credentials"
    assert _holds_secret_after(nl, files) == _holds_secret_after(amp, files) is True
    assert _source_path_after(nl, files) == _source_path_after(amp, files) == [
        "/repo/.aws/credentials"
    ]


def test_newline_cd_into_lookalike_dir_still_does_not_match():
    """Must-not-regress: folding across a newline must not manufacture a
    credential from a look-alike directory name."""
    files = {"/repo/my-aws-backup/readme.txt": "AKIA_TEST_newline\n"}
    assert not _holds_secret_after("echo x\ncd my-aws-backup\ncat readme.txt", files)


def test_newline_dynamic_cd_target_stays_unresolved():
    """Must-not-regress: a dynamic `cd` target on its own line still resolves to
    a non-matching path and contributes nothing (fail-open, as established)."""
    files = {"/repo/.aws/credentials": "AKIA_TEST_newline\n"}
    assert not _holds_secret_after("echo x\ncd $(mktemp -d)\ncat credentials", files)


# ─────────────────────────────────────────────────────────────────────────────
# The SIBLING call site: `_deletion_targets` shares `_CD_PREFIX`, so the same
# newline fold must reach the scratch/regenerable delete-scoping. A `cd` into a
# scratch dir on its own line must resolve the delete target into that dir,
# exactly as the `&&` form does — RED before the fix (resolved against /repo),
# GREEN after. Unit-level on the helper, since it is the shared mechanism.
# ─────────────────────────────────────────────────────────────────────────────
def test_deletion_targets_folds_a_cd_across_a_newline():
    from core.engine import _deletion_targets

    amp = _deletion_targets("cd /tmp/scratch && rm -rf junk", "/repo")
    nl = _deletion_targets("echo x\ncd /tmp/scratch\nrm -rf junk", "/repo")
    assert amp == ("/tmp/scratch/junk",)
    assert nl == amp  # the newline form must resolve identically, not to /repo/junk


def test_deletion_targets_escape_stays_caught_across_a_newline():
    """Must-not-catch-less: a `..` escape out of the cd'd dir still normalises
    outside it across a newline, so the exemption can never widen to it."""
    from core.engine import _deletion_targets

    nl = _deletion_targets("echo x\ncd /tmp/scratch\nrm -rf ../../etc", "/repo")
    assert nl == ("/etc",)  # escaped the scratch dir — not /tmp/scratch/...
