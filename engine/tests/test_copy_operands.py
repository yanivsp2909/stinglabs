"""Which operand does a copy WRITE?

THE BUG THIS REPLACES did not fail by missing — it failed by MIS-CAPTURING, and
every consumer believed the answer:

    install -m 755 .env debug/.env     -> ('755', '.env')             WRONG
    cp --preserve=mode .env debug/.env -> ('--preserve=mode', '.env')  WRONG
    cp -t debug/ .env                  -> ('debug/', '.env')           REVERSED
    cp .env other.txt backup/          -> ('.env', 'other.txt')        WRONG dst

`(?:-\\w+\\s+)*(\\S+)\\s+(\\S+)` cannot express the option grammar: `-\\w+` never
matches `--preserve=mode` because `\\w` excludes `-`, it has no notion of an
option that takes a SEPARATE value, and it assumes the destination is operand 2.

WHY IT IS A HOLE AND NOT A PRECISION BUG. `_copy_destinations()` feeds
`mark_sources`, which SUBTRACTS destinations from its source candidates — so
naming the real secret as the destination SUPPRESSES it. Measured end to end
with the copy as the only ingestion point:

    cp .env debug/.env        ALLOW ASK  ASK    holds_secret=True
    cp -t debug/ .env         ALLOW ALLOW ALLOW holds_secret=False   <- total miss

The session forgets it ever held a secret and the whole ladder goes inert.

WHY THE CORPUS DID NOT CATCH IT: it contains ZERO cp/mv/install invocations.
I02's synthetic trace makes its copy with a `Write` tool; the live agent used
`cp`. Fifth time the corpus has been structurally blind to a real defect.
"""
import subprocess

import pytest

from core.engine import _copy_pairs, _copy_destinations, mark_sources, propagate, decide
from core.types import Action, ActionKind, SessionState

CWD = "/repo"


def act(command, seq=1, kind=ActionKind.EXEC, paths=()):
    return Action(session_id="t", seq=seq, kind=kind, paths=tuple(paths),
                  command=command, url=None, tool_name=None, content=None,
                  cwd=CWD, workspace_roots=(CWD,), agent="claude-code")


class World:
    """`.env` exists and holds a credential; nothing else does."""

    def __init__(self, files=None):
        self.files = files if files is not None else {
            "/repo/.env": "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"}

    def read_text(self, path): return self.files.get(path)
    def staged_files(self, cwd): return None
    def staged_content(self, cwd): return None
    def is_dirty(self, cwd): return True
    def remotes(self, cwd): return ()
    def branch(self, cwd): return "main"


def pairs(command):
    return [(src, dst) for _pos, src, dst in _copy_pairs(command, CWD)]


# ================================================= the four mis-captures
@pytest.mark.parametrize("command", [
    "cp .env debug/.env",
    "mv .env debug/.env",
    "install .env debug/.env",
    "install -m 755 .env debug/.env",
    "install -m 755 -o me -g staff .env debug/.env",
    "cp --preserve=mode .env debug/.env",
    "cp -R -f -p .env debug/.env",
    "cp -- .env debug/.env",
])
def test_the_destination_is_the_file_the_command_actually_writes(command):
    assert pairs(command) == [("/repo/.env", "/repo/debug/.env")], command


@pytest.mark.parametrize("command", [
    "cp -t debug/ .env",
    "cp -t debug .env",
    "cp --target-directory=debug/ .env",
    "cp --target-directory debug/ .env",
    "install -t debug/ .env",
])
def test_target_directory_reverses_the_operand_order(command):
    """`-t DIR SRC` is the one form where the destination comes FIRST. The old
    pattern read it positionally and produced ('debug/', '.env') — naming the
    secret as the destination, which is what suppresses it."""
    assert pairs(command) == [("/repo/.env", "/repo/debug/.env")], command


def test_the_destination_is_the_last_operand_not_the_second():
    """`cp a b DIR/` is legal and the destination is DIR/. Verified against real
    cp in test_n_ary_copy_is_real_below."""
    assert pairs("cp .env other.txt backup/") == [
        ("/repo/.env", "/repo/backup/.env"),
        ("/repo/other.txt", "/repo/backup/other.txt")]


def test_a_directory_destination_receives_the_source_by_basename():
    """`_level_of_path` is an exact dict lookup with no prefix matching, so
    tainting `/repo/backup/` for `cp .env backup/` labels a path nothing ever
    writes and the taint is unreachable."""
    assert pairs("cp .env backup/") == [("/repo/.env", "/repo/backup/.env")]


def test_install_d_creates_directories_and_reads_nothing():
    """Every operand is a destination and there is no source at all."""
    assert pairs("install -d /tmp/x /tmp/y") == []


@pytest.mark.parametrize("command", ["cp .env", "cp", "mv", "install -m 755"])
def test_too_few_operands_yields_no_pair(command):
    assert pairs(command) == []


# ================================================= verb-conditional options
def test_dash_f_is_force_for_cp_and_a_value_for_install():
    """`cp -f` takes nothing; BSD `install -f flags` takes a value. Treating
    `-f` as value-taking for cp would eat a real operand and lose the source."""
    assert pairs("cp -f .env debug/.env") == [("/repo/.env", "/repo/debug/.env")]
    assert pairs("install -f uchg .env debug/.env") == [("/repo/.env", "/repo/debug/.env")]


def test_an_unrecognised_option_value_cannot_move_the_destination():
    """THE DIRECTION-OF-ERROR GUARANTEE. Rule 4 takes the LAST operand, so a
    value we failed to consume becomes a spurious SOURCE — inert unless it is
    credential-shaped — and never displaces the destination. This is why the
    option table may be conservative without becoming a hole."""
    got = pairs("install --some-future-option 755 .env debug/.env")
    assert ("/repo/.env", "/repo/debug/.env") in got


# ================================================= measured against real tools
#
# ⚠ TWO TOOLS WEAR THIS NAME, and the test used to assume one of them. BSD
# install (macOS) takes `-B .bak`; GNU coreutils install (Linux) has no `-B` at
# all and spells it `--suffix=`. Asserting the BSD set against whatever is on
# PATH failed every Ubuntu run — a red CI job that says nothing about the
# engine, which is exactly what makes a Windows number unreadable.
#
# ⚠ AND THIS IS AN UPGRADE, NOT JUST A FIX. `_COPY_VALUE_OPTS` says of its GNU
# entries: "FROM DOCUMENTATION, NOT MEASURED — this machine has no coreutils".
# A Linux runner HAS coreutils, so those entries are measured for the first time
# here rather than remaining a reading.
BSD_INSTALL_VALUE_OPTS = ["-m 755", "-B .bak"]
GNU_INSTALL_VALUE_OPTS = ["-m 755", "--suffix=.bak", "-S .bak"]


def _install_flavour() -> str:
    """BSD or GNU, asked of the tool rather than inferred from the platform —
    a Mac with coreutils on PATH is a real configuration."""
    proc = subprocess.run(["install", "--version"], capture_output=True, text=True)
    return "gnu" if "GNU coreutils" in (proc.stdout + proc.stderr) else "bsd"


@pytest.mark.parametrize("opt", sorted(set(BSD_INSTALL_VALUE_OPTS)
                                        | set(GNU_INSTALL_VALUE_OPTS)))
def test_the_install_option_set_matches_the_real_tool(opt, tmp_path):
    """The option table is measured, not read off a man page — the same standard
    the git global options were held to. `-f uchg` is deliberately NOT exercised
    here: it sets a macOS immutable flag that breaks tmp_path teardown."""
    flavour = _install_flavour()
    wanted = BSD_INSTALL_VALUE_OPTS if flavour == "bsd" else GNU_INSTALL_VALUE_OPTS
    if opt not in wanted:
        pytest.skip(f"{opt} is not an option of {flavour} install — "
                     f"the OTHER flavour exercises it")
    src = tmp_path / "src.txt"
    src.write_text("data")
    dst = tmp_path / "dst.txt"
    proc = subprocess.run(["install", *opt.split(), str(src), str(dst)],
                          capture_output=True, text=True)
    assert proc.returncode == 0 and dst.exists(), (
        f"{flavour} install {opt} <src> <dst> failed: {proc.stderr.strip()}")

    # ⚠ AND THE ENGINE'S TABLE MUST KNOW IT. Measuring the tool is only half the
    # claim; the point of the measurement is that `_COPY_VALUE_OPTS` covers what
    # the real tool accepts, or an option's VALUE is read as a source path.
    from core.engine import _COPY_VALUE_OPTS
    flag = opt.split()[0].split("=")[0]
    assert flag in _COPY_VALUE_OPTS["install"], (
        f"{flavour} install accepts {flag} and the engine does not know it")


def test_n_ary_copy_is_real(tmp_path):
    """`cp a b DIR/` — pins that the LAST-operand rule describes real cp."""
    (tmp_path / "a").write_text("a")
    (tmp_path / "b").write_text("b")
    (tmp_path / "d").mkdir()
    proc = subprocess.run(["cp", str(tmp_path / "a"), str(tmp_path / "b"),
                           str(tmp_path / "d") + "/"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert (tmp_path / "d" / "a").exists() and (tmp_path / "d" / "b").exists()


# ================================================= what the mis-capture cost
@pytest.mark.parametrize("command", [
    "cp .env debug/.env",
    "cp -t debug/ .env",
    "install -m 755 .env debug/.env",
    "cp --preserve=mode .env debug/.env",
    "cp .env backup/",
])
def test_a_copy_is_never_recorded_as_its_own_destination(command):
    """The suppression, asserted directly: `.env` must survive as a SOURCE. When
    the mis-captured dst was `.env`, `mark_sources` subtracted it and the session
    never learned it held a secret."""
    state = SessionState("t")
    action = act(command)
    mark_sources(state, action, World())
    assert "/repo/.env" not in _copy_destinations(command, CWD)
    assert [s.get("path") for s in state.secret_sources] == ["/repo/.env"], command
    assert state.holds_secret is True


@pytest.mark.parametrize("command", [
    "cp .env debug/.env",
    "cp -t debug/ .env",
    "install -m 755 .env debug/.env",
    "cp --preserve=mode .env debug/.env",
])
def test_every_copy_form_reaches_the_same_verdicts_as_the_plain_form(command):
    """END TO END, with the copy as the ONLY ingestion point — the case that
    scored ALLOW / ALLOW / ALLOW before. Compared against the plain form rather
    than against literals, so the assertion survives a policy change."""
    def chain(copy_command):
        state, world, out = SessionState("t"), World(), []
        for action in (act(copy_command, 1),
                       act("git add -A && git commit -m 'chore'", 2),
                       act("git push origin main", 3)):
            state.seq = action.seq
            out.append(decide(action, state, world).decision)
            mark_sources(state, action, world)
            propagate(state, action, world)
        return out, state

    got, got_state = chain(command)
    want, want_state = chain("cp .env debug/.env")
    assert got == want, f"{command} diverged from the plain form"
    assert got_state.holds_secret is want_state.holds_secret is True
    assert got[1] != "ALLOW" and got[2] != "ALLOW"


def test_install_at_a_command_position_is_a_read_but_pip_install_is_not():
    """`install` was in neither read gate, so `install -m 755 .env debug/.env`
    marked no source and stayed a total miss even after the operands were parsed
    correctly. It is added ANCHORED, and that is load-bearing: `install`
    unanchored appears 6 times in the corpus and every one is `pip install` or
    `npm install`, which read no file."""
    state = SessionState("t")
    mark_sources(state, act("install -m 755 .env debug/.env"), World())
    assert [s.get("path") for s in state.secret_sources] == ["/repo/.env"]

    for benign in ("pip install -r requirements.txt", "npm install express",
                   "pip install boto3"):
        clean = SessionState("t")
        mark_sources(clean, act(benign), World())
        assert clean.secret_sources == [], benign
        assert clean.holds_secret is False, benign


def test_propagation_labels_the_file_that_is_actually_written():
    """The other half: the destination must be tainted, and it must be the real
    path. Before, three of these taints landed on nothing or on the wrong path."""
    for command, expected in [
        ("cp .env debug/.env", "/repo/debug/.env"),
        ("cp -t debug/ .env", "/repo/debug/.env"),
        ("install -m 755 .env debug/.env", "/repo/debug/.env"),
        ("cp .env backup/", "/repo/backup/.env"),
    ]:
        state = SessionState("t")
        state.holds_secret = True
        state.holds_secret_since_seq = 1
        propagate(state, act(command), World())
        assert expected in state.tainted_paths, command
