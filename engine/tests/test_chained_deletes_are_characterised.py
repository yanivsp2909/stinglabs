"""Chained deletes, pinned as they decide today (item 11a — characterisation).

The regenerable-artifact exemption (`__pycache__`, `node_modules`, `dist`, …) and
the manifest gate (`target`/`out` count as build output only beside a build
manifest) were tested one delete at a time. These pin how they COMPOSE across
`&&`, `;` and `||`: the whole target set must be exempt, or the command asks —
and a chained non-delete keeps its own verdict. Measured on main 7c676ec and on
this branch (identical) before being written down; this file adds no behaviour.
"""
from __future__ import annotations

import pytest

from core import engine
from core.probes import NullWorld
from core.types import Action, ActionKind, SessionState

PROJECT = "/work/repo"
ALLOW = ("ALLOW", None)
ASK = ("ASK", "irreversible_action")


class _WithManifest(NullWorld):
    def __init__(self, *present):
        self._present = set(present)

    def read_text(self, path):
        return "manifest\n" if path in self._present else None


CARGO = _WithManifest(f"{PROJECT}/Cargo.toml")


def _verdict(command, world=None):
    state = SessionState(session_id="s")
    v = engine.decide(Action("s", 1, ActionKind.EXEC, (), command, None, None, None,
                             PROJECT, (PROJECT,), "claude-code"),
                      state, world or NullWorld())
    return v.decision.value, v.rule_id


# (first, second, without a manifest, beside Cargo.toml)
PAIRS = [
    ("rm -rf __pycache__", "rm -rf node_modules", ALLOW, ALLOW),
    ("rm -rf __pycache__", "rm -rf real_important_data", ASK, ASK),
    ("rm -rf dist", "rm -rf target", ASK, ALLOW),
    ("rm -rf target", "rm -rf build", ASK, ALLOW),
]


@pytest.mark.parametrize("joiner", [" && ", " ; ", " || "], ids=["and", "semi", "or"])
@pytest.mark.parametrize("first,second,bare,manifest", PAIRS,
                         ids=[f"{a[7:]}+{b[7:]}" for a, b, _, _ in PAIRS])
def test_a_chained_delete_is_exempt_only_when_every_target_is(
        joiner, first, second, bare, manifest):
    command = first + joiner + second
    assert _verdict(command) == bare, command
    assert _verdict(command, CARGO) == manifest, command


@pytest.mark.parametrize("command,today", [
    # junk first does not launder the real delete after it
    ("rm -rf __pycache__ && rm -rf real_important_data", ASK),
    # nor a force push after it — it asked; since docs/112 a force-push does
    # not (maintainer), and the junk loses nothing
    ("rm -rf __pycache__ && git push --force", ALLOW),
    # `&&` inside a commit MESSAGE is text, not a chain
    ('git commit -m "fixed a && b bug"', ALLOW),
])
def test_the_three_adversarial_chains(command, today):
    assert _verdict(command) == today
