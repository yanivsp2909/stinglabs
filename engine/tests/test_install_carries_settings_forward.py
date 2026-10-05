"""A reinstall keeps what the operator chose, or says it did not.

⚠ THE DEFECT, MEASURED ON THIS MACHINE RATHER THAN IMAGINED. `install.py` read
the collector URL, the token and the device id from flags or from the process
ENVIRONMENT and never from the `~/.sting/env` it wrote itself; `--tier`
defaulted to LOCATED and `--observe` defaulted to True. So re-running it for one
reason — a changed tunnel URL, which the runbook says WILL happen — dropped the
collector, reset the tier, and silently reverted an ENFORCING machine to
observe. The plan printed on the way looked correct because every value in it
was a real value. It just was not theirs.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from installer import recorded                                   # noqa: E402


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    path = tmp_path / "env"
    monkeypatch.setattr(recorded, "ENV_FILE", path)
    def write(**values):
        path.write_text("# written by install.py\n" + "".join(
            f"export {k}={v!r}\n".replace('"', "'") for k, v in values.items()),
            encoding="utf-8")
        return path
    return write


# ------------------------------------------------------------- 1 · the rule

def test_an_explicit_flag_beats_a_recorded_value(env_file):
    """⚠ THE OBJECTION THIS ANSWERS. An installer that trusts its own previous
    output is how a WRONG value becomes permanent — a bad URL surviving every
    reinstall meant to fix it. It is answered by this line, not dismissed:
    overriding is exactly what a developer re-running the installer is doing."""
    assert recorded.resolve("new", "old", "default", key="K") == (
        "new", "given on the command line")


def test_an_absent_flag_carries_the_recorded_value_and_says_so(env_file):
    value, source = recorded.resolve(None, "old", "default", key="K")
    assert value == "old"
    assert source.startswith("carried forward from"), (
        "a carried value must be visible in the plan, not implied by absence")


def test_an_explicitly_empty_flag_clears_rather_than_carries(env_file):
    """`--roots ''` is a real answer. It must beat a recorded value, or a
    setting can be set and never unset."""
    assert recorded.resolve("", "old", "default", key="K")[0] == ""


def test_nothing_recorded_falls_back_to_the_default(env_file):
    assert recorded.resolve(None, None, "default", key="K") == (
        "default", "the default")


def test_the_file_is_parsed_and_never_sourced(tmp_path, monkeypatch):
    path = tmp_path / "env"
    path.write_text("export STING_TIER='verdict'\n"
                     "export EVIL=$(touch /tmp/sting-install-should-not-exist)\n",
                     encoding="utf-8")
    assert recorded.read(path)["STING_TIER"] == "verdict"
    assert not Path("/tmp/sting-install-should-not-exist").exists()


def test_a_missing_file_is_a_first_install_and_not_an_error(tmp_path):
    assert recorded.read(tmp_path / "absent") == {}


# ------------------------------------------------ 2 · enforcement is special

def test_enforce_is_recorded_as_a_value_and_not_as_an_absent_key(env_file):
    """⚠ WORKING RULE 13, FOUND INSIDE THE INSTALLER. `STING_OBSERVE='1'` was
    written ONLY in observe mode, so "enforcing", "no install at all" and "an
    install predating this key" were one artifact. Three states need three
    values, and `hook_entry` already reads '0' as false."""
    env_file(STING_OBSERVE="0")
    assert recorded.observe_from(recorded.read(recorded.ENV_FILE)) is False
    env_file(STING_OBSERVE="1")
    assert recorded.observe_from(recorded.read(recorded.ENV_FILE)) is True
    assert recorded.observe_from({}) is None, "never recorded is its own answer"


def test_a_bare_reinstall_cannot_turn_enforcement_off(env_file):
    """The whole point. `args.observe is None` means the operator said nothing,
    and saying nothing must not downgrade the guard."""
    env_file(STING_OBSERVE="0")
    was = recorded.observe_from(recorded.read(recorded.ENV_FILE))
    value, source = recorded.resolve(None, "1" if was else "0", "1",
                                     key="STING_OBSERVE")
    assert value == "0" and source.startswith("carried")


def test_turning_it_off_requires_saying_so_and_is_not_a_line_among_twenty():
    """A downgrade of the guard gets a block, because a machine that was
    enforcing and comes back observing decides everything and blocks nothing —
    and the collector cannot tell it from a working one."""
    source = (Path(__file__).parent.parent / "install.py").read_text(
        encoding="utf-8")
    assert "THIS TURNS ENFORCEMENT OFF" in source
    assert "a bare re-run keeps enforcement" in source
    assert "undo            re-run with --enforce" in source


def test_the_flags_are_tri_state_or_the_rule_cannot_be_implemented():
    """With `--observe` defaulting True there is no way to tell "asked for
    observe" from "said nothing", so an explicit downgrade and a bare re-run are
    the same input and the installer cannot behave differently."""
    source = (Path(__file__).parent.parent / "install.py").read_text(
        encoding="utf-8")
    assert 'action="store_true",\n                     default=None)' in source


# ------------------------------------------------------ 3 · the escape hatch

def test_status_names_every_carried_value_and_the_flag_that_overrides_it():
    """⚠ AN ESCAPE HATCH THAT REQUIRES READING THE SOURCE IS NOT ONE. Carrying
    settings forward is only honest if a developer can see what would be carried
    and knows the single flag that replaces each."""
    source = (Path(__file__).parent.parent / "install.py").read_text(
        encoding="utf-8")
    assert "Carried into your next install unless you pass the flag beside it" in source
    carried = source.split("Carried into your next install unless", 1)[1]
    carried = carried.split("reset everything", 1)[0]
    # ⚠ RE-PINNED BY ITEM 2: the mode's flag was "--observe / --enforce". An
    # agent may run --status and reads this, so only the way back to enforce is
    # named, and only when the machine observes; `--help` names both.
    for flag in ("--collector-url", "--device-id", "--device-token",
                  "--enforce", "--roots", "--scratch"):
        assert flag in carried
    assert "--observe" not in carried
    # There are no tiers any more (28 Sep 2026): nothing carries one forward.
    assert "--tier" not in carried and "STING_TIER" not in carried
    assert "reset everything:  rm" in source


def test_the_token_is_never_printed_in_full():
    source = (Path(__file__).parent.parent / "install.py").read_text(
        encoding="utf-8")
    assert '"<set>" if "TOKEN" in key' in source


# --------------------------------------------- 4 · what a reinstall must reset

def test_the_boundary_between_preference_and_fact_is_written_down():
    """Not everything is a preference. The allow-once chokepoint revokes grants
    on reinstall deliberately, and that must not be swept into "carry it all"."""
    assert "one-shot grants" in recorded.NEVER_CARRIED
    assert "guard_version" in recorded.NEVER_CARRIED
    assert "STING_SESSION_ROOT" in recorded.NEVER_CARRIED
    for key in recorded.CARRIED:
        assert key not in recorded.NEVER_CARRIED, (
            f"{key} is on both lists — the boundary has to be one or the other")
