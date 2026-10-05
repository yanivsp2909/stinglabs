"""Turning the guard off by writing to a dotfile — matched on CONTENT.

⚠ `_GUARD_SELFMOD` MATCHES PATHS THAT ARE THE GUARD. This matches CONTENT THAT
CONFIGURES IT. Same category — an action aimed at the guard rather than at the
developer's work — and no new mechanism, which is why it reports under the same
rule id.

⚠ AND IT IS THE CONJUNCTION. Measured over 1,685 real commands from this
developer's own sessions:

    any `STING_` assignment                  53   3.1% — unusable
    `export STING_…`                          7          unusable
    `STING_OBSERVE=` anywhere                 6          unusable, AND WRONG:
                                                         observe mode is a
                                                         SUPPORTED mode and
                                                         setting it for one
                                                         command is legitimate
    an assignment PERSISTED to a startup file 0   <- this rule

The danger was never the assignment. A value in one shell dies with it; a line
in a profile disables enforcement on every later session on that machine.
"""
from __future__ import annotations

import pytest

from core.engine import _STING_PERSISTED
from tests import frozen_population


PERSISTED = [
    "echo 'export STING_OBSERVE=1' >> ~/.zshrc",
    "echo STING_OBSERVE=1 >> ~/.bashrc",
    'echo "export STING_TIER=verdict" >> ~/.bash_profile',
    "echo STING_TIER=full >> ~/.sting/env",
    "echo STING_OBSERVE=1 | tee -a ~/.zshrc",
    "echo STING_OBSERVE=1 | sudo tee -a /root/.profile",
]

EPHEMERAL = [
    # ⚠ EVERY ONE OF THESE IS LEGITIMATE AND MUST STAY ALLOWED. Observe mode is
    # a supported mode; setting it for one command is how a developer records a
    # session without blocking.
    "STING_OBSERVE=1 python3 tools/preflight.py",
    "export STING_ROOTS=/a:/b",
    "STING_TIER=full python3 -m shipper.run",
    "env | grep STING_",
    "grep -n STING_OBSERVE install.py",
    "echo 'alias ll=ls -la' >> ~/.zshrc",          # a dotfile write, not ours
    # ⚠ THE ONE THAT COST A REGEX REWRITE. A read that redacts the env file for
    # display: the assignment is inside a grep pattern, the `>` is inside sed's
    # replacement, and the path is in a third segment. Two true sub-matches of a
    # command that writes nothing — 1 false positive in 1,691 live commands
    # until the pattern required them in the SAME segment.
    "grep -n 'os.environ.get(\"STING' install.py; "
    "sed 's/=.*TOKEN.*/=<redacted>/' ~/.sting/env",
]


@pytest.mark.parametrize("command", PERSISTED)
def test_persisting_a_sting_variable_is_guard_directed(command):
    assert _STING_PERSISTED.search(command), command


@pytest.mark.parametrize("command", EPHEMERAL)
def test_ordinary_use_of_a_sting_variable_is_not(command):
    assert not _STING_PERSISTED.search(command), command


POPULATION = "guard-selfmod-v1"

# ⚠ KNOWN TRUE POSITIVES IN guard-selfmod-v1, by (session id, seq). The rule is
# RIGHT about each of these: not false alarms, but what it exists to catch.
KNOWN_TRUE_POSITIVES: dict[tuple[str, int], str] = {
    # A test harness writing STING_OBSERVE=1 into a CONTAINER's
    # ~/.sting/env, to prove the guard refuses it.
    ("345db5d8-08bc-431d-9c9b-41533ef8274f", 168):
        "deliberate sandboxed tamper attempt, caught correctly",
}


def test_the_false_positive_cost_on_the_frozen_live_logs_is_zero():
    """⚠ MEASURED, NOT PREDICTED — rule 11. The 25 normals are 15 commands and
    cannot see this class; the live logs are the population that can.

    ⚠ FROZEN, NOT LIVE. The live logs grow with every agent's work, so a test
    reading them answered a different question each day. This reads
    guard-selfmod-v1, one pinned snapshot of them (tests/frozen_population.py,
    docs/PARALLEL.md): skipped where it is absent, failed where it drifted.
    """
    records = frozen_population.records(POPULATION)
    commands = [(r.get("session_id"), r.get("seq"), r["command"])
                for r in records if r.get("command")]
    assert len(commands) >= 500, f"only {len(commands)} commands: too thin to measure"

    # ⚠ EXCLUDING COMMANDS THAT AUTHOR THIS RULE OR ITS TESTS, and the effect is
    # worth naming rather than hiding. Every match in the live logs is a command
    # from the session that WROTE this pattern — a heredoc carrying
    # `echo 'export STING_OBSERVE=1' >> ~/.zshrc` as TEST DATA, and the regex
    # itself as source. The rule matches its own specification.
    #
    # That is a real false-positive class — editing the guard's own source and
    # tests — and it is already guard-directed by every other measure, so it is
    # excluded here rather than tuned away. Against traffic that is not
    # authoring the guard, the cost is ZERO.
    authoring = ("sting-engine" , "_STING_PERSISTED", "test_guard_selfmod")
    flagged = {(session, seq) for session, seq, command in commands
               if _STING_PERSISTED.search(command)
               and not any(marker in command for marker in authoring)}
    # By id, never the command: the population holds real commands.
    beyond = sorted(flagged - KNOWN_TRUE_POSITIVES.keys(), key=str)
    assert not beyond, (
        f"{len(beyond)} of {len(commands)} commands in {POPULATION} flagged beyond "
        f"the known true positives, by (session id, seq): {beyond}. Read each in "
        f"logs/frozen/{POPULATION}/: a real tamper attempt is listed in "
        f"KNOWN_TRUE_POSITIVES with its reason; anything else is a false alarm")
    missed = sorted(KNOWN_TRUE_POSITIVES.keys() - flagged, key=str)
    assert not missed, f"known true positives the rule no longer flags: {missed}"


# ═════════ stopping the guard's own reporter (Q01) — names, not paths

KILLS_THE_GUARD = [
    "pkill -f shipper.run",
    "launchctl bootout gui/501/dev.sting.shipper && pkill -f shipper.run",
    "killall -9 dev.sting.shipper",
    "pkill -f dev.sting.shipper",
]

# ⚠ EVERY ONE OF THESE IS LEGITIMATE FOR A PERSON, AND MEASURED. Three of them
# appear in the live logs as genuine supervisor development, and they are
# TEXTUALLY IDENTICAL to the attack in every respect except the verb. None is
# THIS sink's. From an AGENT the stops among them are refused by the
# installed-guard floor instead (`installed_guard:guard_selfmod`, item C); the
# reads stay ALLOW. tests/test_the_installed_guard_is_protected.py pins both.
LEGITIMATE = [
    "launchctl bootout gui/501/dev.sting.shipper",
    "launchctl print gui/501/dev.sting.shipper",
    "launchctl list | grep -i sting",
    "python3 -m shipper.run --status",
    "systemctl --user stop dev.sting.shipper.service",
    "schtasks /End /TN \\Sting\\dev.sting.shipper",
    # ⚠ THE ONE fb071e3 ALREADY NARROWED AWAY FROM. The developer's repos live
    # under ~/sting/, so a bare `sting` match hit 188 of 190 real paths.
    "pkill -f sting",
    "cd ~/src/sparta-security/engine && pytest -q",
]


@pytest.mark.parametrize("command", KILLS_THE_GUARD)
def test_killing_the_guards_reporter_is_guard_directed(command):
    from core.engine import _GUARD_PROCESS, _KILL
    assert _GUARD_PROCESS.search(command) and _KILL.search(command), command


@pytest.mark.parametrize("command", LEGITIMATE)
def test_stopping_it_the_documented_way_is_not(command):
    """⚠ `launchctl bootout` IS WHAT THE PRODUCT TELLS A PERSON TO TYPE.
    `supervisor.stop_command()` prints that exact line, and `activate()` runs it
    on every reinstall. This sink does not take it: it cost 3 false positives in
    1,752 live commands when it did. An AGENT typing it is refused by the
    installed-guard floor (item C); the person runs it in their own terminal,
    where the hook does not run."""
    from core.engine import _GUARD_PROCESS, _KILL
    assert not (_GUARD_PROCESS.search(command) and _KILL.search(command)), command


def test_the_documented_stop_command_is_not_this_sinks():
    """Pinned against the installer itself, so the two cannot drift: if
    `stop_command()` ever changes to something this sink matches, this fails.
    The line is a person's to type; from an agent the installed-guard floor
    refuses it (`test_the_documented_stop_command_is_for_a_person_not_an_agent`)."""
    import platform
    from shipper import service
    from core.engine import _GUARD_PROCESS, _KILL

    command = service.stop_command()
    assert not (_GUARD_PROCESS.search(command) and _KILL.search(command)), (
        f"the installer prints {command!r}, which this rule would deny")
