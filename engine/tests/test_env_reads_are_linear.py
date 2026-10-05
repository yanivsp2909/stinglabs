"""The environment-read check reads a command in linear time.

`core/env_reads.env_read` runs on every EXEC action (docs/110 §B). Each verb's
segment, each PowerShell statement and each grep that follows a dump is read
once; a PowerShell `(` looks back a bounded window. Four times the text, about
four times the time, never sixteen.
"""
from __future__ import annotations

import time

import pytest

from core import env_reads

SIZE = 128 * 1024
ENVIRON = {"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEYq",
           "HOME": "/home/dev"}


def _fill(unit: str, size: int) -> str:
    return unit * (size // len(unit))


SHAPES = {
    "echo expansions": lambda n: "echo " + _fill("$AWS_SECRET_ACCESS_KEY ", n),
    "dumps into grep": lambda n: _fill("env | grep PATH; ", n),
    "presence checks": lambda n: _fill("echo ${AWS_SECRET_ACCESS_KEY:+set} ", n),
    "powershell calls": lambda n: _fill("IsNullOrEmpty($env:AWS_SECRET_ACCESS_KEY)", n),
    "powershell nesting": lambda n: "(" * (n // 2) + "$env:AWS_SECRET_ACCESS_KEY",
    "cmd echoes": lambda n: "echo " + _fill("%AWS_SECRET_ACCESS_KEY% ", n),
    "redirect runs": lambda n: "printenv AWS_SECRET_ACCESS_KEY " + _fill("> /dev/null ", n),
    "unquoted words": lambda n: "printenv " + _fill("a ", n),
    # the review: a verb opened by `(` or `{` re-read to the segment's end
    "subshell echoes": lambda n: _fill("(echo ", n),
    "group echoes": lambda n: _fill("{ echo ", n),
    "subshell printenvs": lambda n: _fill("(printenv ", n),
    "substitution echoes": lambda n: _fill("echo $(", n),
    # and a list of names searched once per name
    "many names": lambda n: "echo " + " ".join(f"$A{i}_KEY" for i in range(n // 9)),
    "many printenv names": lambda n: "printenv " + " ".join(f"X{i}_TOKEN" for i in range(n // 10)),
    "many cmd names": lambda n: "echo " + " ".join(f"%A{i}_KEY%" for i in range(n // 9)),
    # the second round: several verbs on ONE level of one segment, each of
    # which walked every later sibling block or re-read the rest
    "verbs after backtick blocks": lambda n: _fill("`x`echo ", n),
    "echoes in backticks": lambda n: _fill("echo `", n),
    "echoes in open expansions": lambda n: _fill("echo ${", n),
    "verbs after -c": lambda n: _fill("x -c echo $A ", n),
    "verbs piped after -c": lambda n: (_fill("x -c env ", n // 2) + "| grep "
                                       + _fill("a ", n // 2)),
    # and the verb pattern's assignments and options, tried from every start
    # (each names a verb: a command naming none is never read at all)
    "assignments in subshells": lambda n: "echo " + _fill("(A=", n),
    "assignments after separators": lambda n: "echo " + _fill(";A=", n),
    "assignments in groups": lambda n: "echo " + _fill("{ A=", n),
    "assignments in backticks": lambda n: "echo " + _fill("`A=", n),
    "options in subshells": lambda n: "echo " + _fill("(sudo -x", n),
    "keywords in subshells": lambda n: "echo " + _fill("(if do -x", n),
    "substitutions in assignments": lambda n: "echo " + _fill("(A=$(a)", n),
    "expansions in assignments": lambda n: "echo " + _fill("(A=${a}", n),
    "grep options": lambda n: "env | grep " + _fill("-ie ", n),
    # the third round: a command position inside a prefix chain (`-c`,
    # `-command`, a newline), and PowerShell statements with no end
    "prefix options at -c": lambda n: "echo " + _fill("sudo -c ", n),
    "prefix options at -command": lambda n: "echo " + _fill("sudo -command ", n),
    "keywords at -c": lambda n: "echo " + _fill("if -c ", n),
    "prefixes over lines": lambda n: "echo " + _fill("sudo\n", n),
    "options over lines": lambda n: "echo " + _fill("sudo -x\n", n),
    "keywords over lines": lambda n: "echo " + _fill("if\n", n),
    "assignments over lines": lambda n: "echo " + _fill("A=1\n", n),
    "powershell statements after -c": lambda n: _fill('-c "$env:A ', n),
    "powershell statements after -command": lambda n: _fill('-Command "x $env:A ', n),
    "shell bodies": lambda n: _fill("bash -c 'env' ", n),
    "echoes in shell bodies": lambda n: _fill("sh -c 'echo $A ", n),
    "dumps into subshells": lambda n: _fill("env | (", n),
    "prefix sets": lambda n: _fill("set A;", n),
    # the fourth round: `-command` counted as a command position after any
    # character, so `--command` and `x-command` started one inside the chain
    "prefix options at --command": lambda n: "echo x;" + _fill("sudo --command ", n),
    "prefix options at x-command": lambda n: "echo x;" + _fill("sudo x-command ", n),
    "verbs at --command": lambda n: "echo x;" + _fill("env --command ", n),
    # docs/113 §3d: a prefix's option may take a value word
    "valued options": lambda n: "echo x;" + _fill("sudo -u a ", n),
    "valued options in subshells": lambda n: "echo " + _fill("(sudo -u a ", n),
    "valued options, then a verb": lambda n: _fill("nice -n 5 ", n) + "env",
    "values that look like verbs": lambda n: "echo x;" + _fill("sudo -u env ", n),
}
STALL_MS = 1000
"""A stall guard, not a speed test: the growth is the assertion (docs/113 §3e).
It was a 150 ms cap, and `expansions in assignments` took 187 ms at 128 KB on
a machine at load 7–8 while growing as it always had."""


def _best_ms(command: str, tries: int = 5, environ=ENVIRON) -> float:
    best = float("inf")
    for _ in range(tries):
        start = time.perf_counter()
        env_reads.env_read(command, environ)
        best = min(best, (time.perf_counter() - start) * 1000)
        if best > 5 * STALL_MS:
            break                   # plainly quadratic: no need to wait again
    return best


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_environment_read_check_is_linear(shape):
    small = _best_ms(SHAPES[shape](SIZE // 4))
    assert small < STALL_MS, (shape, small)
    large = _best_ms(SHAPES[shape](SIZE))
    assert large < 6 * small + 3, (shape, small, large)
    assert large < STALL_MS, (shape, large)


# The third round: each dump into grep and each cmd `set PREFIX` walked the
# whole hook environment, so the cost was the command's size TIMES the
# environment's. The secret-looking part of the view is taken once per read.
LARGE_ENVIRON = {**{f"VAR_{i}": f"value {i}" for i in range(290)},
                 **{f"APP_{i}_TOKEN": f"tok-{i}-Zq8vN2xLr4TkWp7Y" for i in range(10)}}


@pytest.mark.parametrize("unit", ["env|grep ZZ;", "set V;", "env | grep -i zz; ",
                                  "printenv | grep ^ZZ; "])
def test_a_large_environment_is_read_once_per_command(unit):
    small = _best_ms(_fill(unit, SIZE // 4), environ=LARGE_ENVIRON)
    assert small < STALL_MS, (unit, small)
    large = _best_ms(_fill(unit, SIZE), environ=LARGE_ENVIRON)
    assert large < 6 * small + 3, (unit, small, large)
    assert large < STALL_MS, (unit, large)
