"""`executed_text`'s message strip reads a command in linear time.

Filed by #80's reviews (PROGRESS.md): `command_text.executed_text` is
quadratic on some shapes. It has two halves, and both were (docs/113 §3f):

* `_strip_message_args` re-scanned every separator from the start of the text
  for each `-m`, to find the segment the message is in: `git commit -m x; `
  repeated, 16 KB, 104 ms; four times that, sixteen times the time. Now the
  separators are found once and each message's segment is a bisection.
* `_HEREDOC_BODY` retries its body scan for every opener with no terminator
  and every shorter prefix of its delimiter. NOT changed here: a linear form
  that keeps every quirk of the pattern is a rewrite, and the real shell
  parser (docs/111) reads heredocs itself. The shapes are listed in docs/113.

Every rewrite is checked against main's function, copied verbatim below.
"""
from __future__ import annotations

import random
import time

import pytest

from core import command_text
from core.command_text import (_MESSAGE_ARG, _MESSAGE_VERB, _SEGMENT_END,
                               _strip_message_args, code_mask_checked)


def _main_strip_message_args(command: str) -> str:
    """main 0fd38ea, verbatim."""
    if "-m" not in command:
        return command
    mask, parsed = code_mask_checked(command)
    pieces: list[str] = []
    last = 0
    for match in _MESSAGE_ARG.finditer(command):
        start = 0
        for separator in _SEGMENT_END.finditer(command, 0, match.start()):
            at = separator.start()
            if not parsed or (at < len(mask) and mask[at]):
                start = separator.end()
        if not _MESSAGE_VERB.match(command, start):
            continue
        pieces.append(command[last:match.start()])
        pieces.append(" ")
        last = match.end()
    pieces.append(command[last:])
    return "".join(pieces)


PIECES = ["git", "commit", "hg", " ", "  ", "-m", "--message", "--message=", "x", "'a b'",
          '"c;d"', ";", "|", "&", "&&", "\n", "(", "{", ")", "}", "cd", "python3", "-m",
          "pytest", "json.tool", "'", '"', ">", ">|", "2>&1", "&>", "\\\n", "=", "echo"]


def test_the_strip_is_mains_on_seeded_commands():
    rng = random.Random(1133)
    for _ in range(30000):
        command = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 16)))
        assert _strip_message_args(command) == _main_strip_message_args(command), repr(command)


def test_the_strip_is_mains_on_the_fixtures_shapes():
    for command in ["git commit -m 'fix: x' && git push", "cd a && git commit -qm x",
                    "python3 -m pytest -q", "head -1 x.jsonl | python3 -m json.tool",
                    'git -c user.name="A | B" commit -m "m; n"', "(git commit -m x)",
                    "echo a; git commit --message=x; hg commit -m y"]:
        assert _strip_message_args(command) == _main_strip_message_args(command), command


def _best_ms(command: str) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        _strip_message_args(command)
        best = min(best, time.perf_counter() - start)
    return best * 1000


SIZE = 64 * 1024
SHAPES = {
    "messages in segments": lambda n: "git commit -m x; " * (n // 17),
    "messages in one segment": lambda n: "git commit -m x " * (n // 16),
    "messages after many separators": lambda n: "a;" * (n // 4) + "git commit -m x " * (n // 32),
    "--message words": lambda n: "git commit --message x; " * (n // 24),
    "module flags": lambda n: "python3 -m pytest; " * (n // 19),
}


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_strip_is_linear(shape):
    """Four times the text, about four times the time, never sixteen."""
    small = _best_ms(SHAPES[shape](SIZE // 4))
    large = _best_ms(SHAPES[shape](SIZE))
    assert large < 6 * small + 2, (shape, small, large)
    assert large < 1000, (shape, large)        # a stall guard, not a speed test


def test_executed_text_still_strips_both():
    command = "git commit -m 'git push' && cat <<EOF\ngit push\nEOF\n"
    shown = command_text.executed_text(command)
    assert "git push" not in shown
