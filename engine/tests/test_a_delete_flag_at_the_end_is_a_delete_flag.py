"""`rm -rf` is a recursive or forced delete wherever it ends.

Filed by fix/false-positives (docs/112): `irreversible._RM_DESTRUCTIVE` wanted
WHITESPACE after the flag, so `… | xargs rm -rf` at the end of a command (or
before `;`, `)`, `|`, `&`) was not one — and `is_irreversible`, which decides
whether an action with no sink reaches the secret family's ladder at all, read
it as harmless. The flag now ends at a blank, a separator or the end (docs/113
§3c). `-R`, rm's other spelling of recursive, is read too.

Tightening only: the pattern can match more, never less.
"""
from __future__ import annotations

import random
import re
import time

import pytest

from core.irreversible import _RM_DESTRUCTIVE, is_irreversible
from core.probes import NullWorld
from core.types import Action, ActionKind


@pytest.mark.parametrize("command", [
    "find . -name '*.pyc' | xargs rm -rf",
    "xargs rm -rf",
    "xargs rm -f",
    "xargs rm -r;",
    "(xargs rm -rf)",
    "ls | xargs rm -rf| cat",
    "ls | xargs rm -rf&",
    "rm -rf",
    "rm -fr\n",
    "rm -R dir",
    "xargs rm -R",
    "rm -Rf dir",
    "rm -rf dir",                      # the old shape, still read
    "rm --recursive",
    "rm --force",
    # the round-1 python review: a flag after rm's other options
    "rm -v -rf dir",
    "rm -i --verbose -f x",
])
def test_a_recursive_or_forced_flag_is_read_wherever_it_ends(command):
    assert _RM_DESTRUCTIVE.search(command), command


@pytest.mark.parametrize("command", [
    "rm file.txt",
    "rm -i file.txt",
    "rm -v",
    "rmdir -p a/b",
    "xargs rm",
    "rm -- -rf",
    "rm -v -i x",
    "rm -- -v -rf",
    # Markdown quoting the command: a bare `rm -rf` in backticks names nothing
    # (the standing replay's one move in round 2, reverted)
    "see `rm -rf` in the notes",
])
def test_a_plain_delete_is_not_one(command):
    assert not _RM_DESTRUCTIVE.search(command), command


# main's pattern, verbatim: the reference every new match must cover.
_MAIN = re.compile(r"\brm\s+(?:-\w*[rf]\w*\s+)|\brm\s+--(?:recursive|force)\b|\bshred\b")


def test_every_match_main_found_is_still_found():
    """Seeded shell-ish text: each span main's pattern matched is matched now,
    so the change can only add a delete flag, never lose one."""
    pieces = ["rm", " ", "  ", "-rf", "-r", "-f", "-R", "-i", "-v", "--force",
              "--recursive", "x", ";", "|", "&", ")", "(", "\n", "xargs", "shred",
              "a", "-", "rf", '"', "'", "rmdir"]
    rng = random.Random(113)
    matched = 0
    for _ in range(20000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        old = {m.span() for m in _MAIN.finditer(text)}
        new = {m.span() for m in _RM_DESTRUCTIVE.finditer(text)}
        matched += bool(old)
        assert not old - new, (repr(text), sorted(old - new))
    assert matched, "the seeded texts never matched main's pattern: nothing was compared"


@pytest.mark.parametrize("command", [
    "find . -name '*.tmp' | xargs rm -rf",
    "ls | xargs rm -rf; echo done",
    "rm -R src",
])
def test_such_a_delete_reaches_the_secret_familys_ladder(command):
    """`is_irreversible` decides whether an action with no sink meets the secret
    rules at all (`engine._judged`, docs/112 item C); main said None here."""
    action = Action("s", 1, ActionKind.EXEC, (), command, None, "Bash", None,
                    "/repo", ("/repo",), "x")
    assert is_irreversible(action, NullWorld()) == "a recursive or forced delete", command


def _best_ms(text: str) -> float:
    best = float("inf")
    for _ in range(5):
        start = time.perf_counter()
        _RM_DESTRUCTIVE.search(text)
        best = min(best, time.perf_counter() - start)
    return best * 1000


SIZE = 64 * 1024
SHAPES = {
    "a long flag, then a quote": lambda n: "rm -" + "r" * n + '"',
    "a long flag of other letters": lambda n: "rm -" + "a" * n + '"',
    "many flags": lambda n: "rm -rf" * (n // 6),
    "many verbs": lambda n: "rm -x " * (n // 6),
    "many plain flags, then a quote": lambda n: "rm " + "-v " * (n // 3) + '-r"',
    "many destructive flags, then a quote": lambda n: "rm " + "-r " * (n // 3) + '-r"',
    # the round-2 security review: every `rm` inside `--rm` was a start of its own
    "rm options named rm": lambda n: "rm " + "--rm " * (n // 5) + "x",
    "flags ending in rm": lambda n: "rm " + "-a-rm " * (n // 6) + "x",
}


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_flag_match_is_linear(shape):
    """Four times the text, about four times the time, never sixteen."""
    small = _best_ms(SHAPES[shape](SIZE // 4))
    large = _best_ms(SHAPES[shape](SIZE))
    assert large < 6 * small + 2, (shape, small, large)
    assert large < 1000, (shape, large)        # a stall guard, not a speed test
