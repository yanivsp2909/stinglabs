"""A catastrophic delete stays a catastrophic delete through brace and glob.

ROW F of the #61 establish table (PROGRESS.md, 2026-09-22). Bash expands
`rm -rf /e{tc,x}` to `rm -rf /etc /ex` and `rm -rf /et?` to `rm -rf /etc`, so
both delete /etc exactly as `rm -rf /etc` does — which is DENY
`catastrophic_delete`. On main both were ASK `irreversible_action`, and
`find /et? -delete` was ALLOW. The destructive-target resolver now reads the
operand through #61's expander (no second one), beside the raw and un-quoted
forms, and unions the hits.

PARITY WITH THE PLAIN SPELLING is the spec, for every catastrophic root. A glob
counts as naming a root only when it SPELLS at least half the root's name —
the exit rule #61 settled, because a target is judged on text alone: `/e*` or
`/*/cache` could be anything and keep main's verdict. Every probe is data fed to
`engine.decide`; nothing is executed.
"""
import time

import pytest

from core import engine
from core.probes import NullWorld
from core.session import SessionState
from core.types import Action, ActionKind

CWD = "/work/repo"


def _verdict(command, cwd=CWD):
    state = SessionState("t")
    state.seq = 1
    action = Action("t", 1, ActionKind.EXEC, (), command, None, "Bash", None,
                    cwd, (cwd,), "claude-code")
    v = engine.decide(action, state, NullWorld())
    return v.decision.value, v.rule_id


ROOTS = sorted(r for r in engine._CATASTROPHIC_ROOTS if r not in ("/", "/HOME"))
TARGETS = ROOTS + ["/Users/alice", "/home/bob"]


def _spellings(root):
    """The root as a brace (`/et{c,x}`) and a glob (`/et?`)."""
    return {"brace": root[:-1] + "{" + root[-1] + ",x}", "glob": root[:-1] + "?"}


@pytest.mark.parametrize("root", TARGETS)
@pytest.mark.parametrize("how", ["brace", "glob"])
def test_a_spelled_catastrophic_delete_decides_like_the_plain_one(root, how):
    plain = _verdict(f"rm -rf {root}")
    assert plain == ("DENY", "catastrophic_delete"), plain
    assert _verdict(f"rm -rf {_spellings(root)[how]}") == plain


@pytest.mark.parametrize("command,plain", [
    ("rm -rf /us?/*", "rm -rf /usr/*"),
    ("rm -rf /{usr,x}/*", "rm -rf /usr/*"),
    ("find /et? -delete", "find /etc -delete"),
    ("find /e{tc,x} -delete", "find /etc -delete"),
    ("cd / && rm -rf et?", "cd / && rm -rf etc"),
    ("cd / && rm -rf {etc,x}", "cd / && rm -rf etc"),
    ("rm -rf /{e,x}{t,y}{c,z}" + "{,}" * 12, "rm -rf /etc"),   # over the cap
])
def test_the_contents_find_cd_and_over_cap_forms_match_their_plain_spelling(
        command, plain):
    start = time.perf_counter()
    assert _verdict(command) == _verdict(plain) == ("DENY", "catastrophic_delete")
    assert time.perf_counter() - start < 2.0


# ─── unchanged: each pinned to MAIN's measured verdict (7c676ec) ───────────────
_MAIN = {
    "rm -rf build/*": ("ASK", "irreversible_action"),
    "rm -rf dist/{a,b}": ("ASK", "irreversible_action"),
    "rm -rf ./*.pyc": ("ALLOW", None),
    "rm -rf /tmp/*": ("ASK", "irreversible_action"),
    "rm -rf /tmp/build-*": ("ASK", "irreversible_action"),
    # quoted: literal in bash, a file named `/et?` — unchanged
    "rm -rf '/et?'": ("ASK", "irreversible_action"),
    'rm -rf "/e{tc,x}"': ("ASK", "irreversible_action"),
    # under-spelled: `/e*` spells 1 of `etc`'s 3; `*` spells nothing
    "rm -rf /e*": ("ASK", "irreversible_action"),
    "rm -rf /*/cache": ("ASK", "irreversible_action"),
    # case: bash's glob is case-sensitive and so is the root rule — `/ET?`
    # matches no `etc`, exactly as plain `/ETC` is not a root here
    "rm -rf /ET?": ("ASK", "irreversible_action"),
}


@pytest.mark.parametrize("command", list(_MAIN))
def test_ordinary_and_under_spelled_deletes_keep_mains_verdict(command):
    assert _verdict(command) == _MAIN[command]


def test_the_plain_spellings_are_untouched():
    """The raw pass is unchanged, so every plain catastrophic delete still
    denies — including the home forms the raw pass already caught."""
    for command in ["rm -rf /etc", "rm -rf /usr/*", "rm -rf ~", "rm -rf ~/*",
                    "rm -rf /Users/al*", "find /etc -delete"]:
        assert _verdict(command) == ("DENY", "catastrophic_delete"), command
