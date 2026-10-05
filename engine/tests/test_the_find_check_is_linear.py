"""`find … -delete`, and `schtasks … /End`, are read in linear time, with
exactly the old answers.

Item E of fix/agents-block-and-env-reads (docs/110 §E). The check found its
`find`s with

    \\bfind\\b(?P<args>{_NOT_SEGMENT_END}*?)(?:-delete\\b|-exec(?:dir)?\\s+rm\\b)

whose lazy `*?` walked from every `find` to the end of its segment when no
destroy word followed. `(` ends no segment, so a run of `(find …` was O(n²):
33, 109, 389 ms at 4, 8, 16 KB on main 8336bce (the skip in
tests/test_the_override_check_is_linear.py). `irreversible._find_destroys` now
returns the same matches from two precomputed position lists.

The reference below is main's committed code (c41dad7), verbatim: the pattern
and the function body. It is compared with the new reader on every pinned case
of the suite's find tests and on random commands built from the pieces that
matter — segment separators and their exceptions, destroy words and near
misses, quotes, `cd`s and starting points.
"""
from __future__ import annotations

import random
import re
import time

import pytest

from core import irreversible
from core.command_text import _NOT_SEGMENT_END
from core.types import Action, ActionKind

# ── main c41dad7 core/irreversible.py, verbatim: the reference ──────────────
_REF_FIND_DESTROYS = re.compile(
    rf"\bfind\b(?P<args>{_NOT_SEGMENT_END}*?)(?:-delete\b|-exec(?:dir)?\s+rm\b)")


def _reference(action: Action) -> str | None:
    i = irreversible
    command = action.command or ""
    mask, ok = i._code_positions(command)
    if not ok:
        return None
    assignments = i._literal_assignments(command)
    lenient = bool(i._SHOPT_WIDENS_GLOB.search(command))
    matches = [m for m in _REF_FIND_DESTROYS.finditer(command)
               if m.start() < len(mask) and mask[m.start()]]
    bases = i._cd_bases(command, [m.start() for m in matches], action.cwd, assignments)
    for match, base in zip(matches, bases):
        args = match.group("args") or ""
        for source in i._operand_forms(args, None, lenient):
            found = i._FIRST_ABS.search(source)
            if not found:
                continue
            target = i._norm_path(i._abs(i._expand(found.group(1), assignments), action.cwd))
            if i._is_catastrophic_root(target):
                return target
        for point in i._find_starting_points(args):
            for form in i._operand_forms(point, base, lenient):
                target = i._norm_path(i._abs(i._expand(form, assignments), base))
                if i._is_catastrophic_root(target):
                    return target
    return None
# ─────────────────────────────────────────────────────────────────────────────


def ex(command: str, cwd: str = "/home/dev/repo") -> Action:
    return Action("t", 1, ActionKind.EXEC, (), command, None, "Bash", None,
                  cwd, (cwd,), "claude-code")


PINNED = [
    "find / -delete", "find /etc -delete", "find . -delete", "cd / && find . -delete",
    "cd /etc && find . -name x -delete", "find $'\\x2f' -delete", "find ~ -delete",
    "find /etc -exec rm {} +", "find /etc -execdir  rm {} \\;", "find /tmp/x -delete",
    "find /etc\n-delete", "find /etc; -delete", "find /etc | -delete", "find /etc >| x -delete",
    "find /etc 2>&1 -delete", "find /etc &> x -delete", "find /etc \\\n -delete",
    "find /etc -deleted", "find /etc -exec rmdir {} +", "echo 'find / -delete'",
    "git commit -m 'find / -delete'", "sh -c 'cd / && find . -delete'",
    "find -L / -delete", "find -D tree / -delete", "find / -name x -o -delete",
    "X=/; find $X -delete", "find /tmp /etc -delete", "(find / -delete)",
    "find /a -print; find / -delete", "find /a -delete; find / -delete",
    "shopt -s nullglob; find /e* -delete", "find /etc -name '*.bak' -delete; rm x",
]


@pytest.mark.parametrize("command", PINNED)
def test_the_pinned_cases_read_as_before(command):
    action = ex(command)
    assert irreversible.find_destroys_a_catastrophic_root(action) == _reference(action)


def test_the_matches_are_finditers_on_random_commands():
    pieces = ["find", "find ", " find", "(find", "/", "/etc", " /etc ", ".", "~", "x",
              " -delete", "-delete", " -deleted", " -exec rm", " -execdir\trm",
              " -exec rmdir", " -exec\nrm", ";", "|", "||", "&", "&&", ">|", "2>&1",
              "&>", "<&", "\\\n", "\n", "\\", " ", "'", '"', "$'\\x2f'", "cd / && ",
              "cd /etc; ", "-L ", "-name y ", "{} +", "rm", "-"]
    rng = random.Random(110)
    for _ in range(6000):
        command = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 14)))
        expected = [(m.start(), m.group("args") or "")
                    for m in _REF_FIND_DESTROYS.finditer(command)]
        assert irreversible._find_destroys(command) == expected, repr(command)
        action = ex(command)
        assert (irreversible.find_destroys_a_catastrophic_root(action)
                == _reference(action)), repr(command)


def _best_ms(command: str, tries: int = 5) -> float:
    action = ex(command)
    best = float("inf")
    for _ in range(tries):
        start = time.perf_counter()
        irreversible.find_destroys_a_catastrophic_root(action)
        best = min(best, time.perf_counter() - start)
    return best * 1000


SIZE = 128 * 1024
SHAPES = {
    "find starts": lambda n: "cat " + "(find /allow_once.py " * (n // 21),
    "finds, no destroy": lambda n: "find /a " * (n // 8),
    "finds with a destroy at the end": lambda n: "find /a " * (n // 8) + "-delete",
    "segments": lambda n: "find /a -print; " * (n // 16),
}


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_find_check_is_linear(shape):
    """Four times the text, about four times the time, never sixteen."""
    small = _best_ms(SHAPES[shape](SIZE // 4))
    large = _best_ms(SHAPES[shape](SIZE))
    assert large < 6 * small + 2, (shape, small, large)
    # A stall guard, not a speed test: the growth above is the assertion (the
    # final review: 125 ms against a 100 ms cap on a loaded machine, while the
    # check itself grew exactly with the text — 16, 33, 64, 129 ms).
    assert large < 1000, (shape, large)


# ── `schtasks … /End`: the same defect in `guard_parts.SERVICE_STOP` ─────────
def test_the_service_stop_span_is_searchs_on_random_segments():
    """`guard_parts.service_stop` against `SERVICE_STOP.search`, the committed
    pattern kept as the definition."""
    from core import guard_parts
    pieces = ["schtasks", "SCHTASKS.exe", "schtasks.exex", "xschtasks", " ", "  ",
              "/End", "/delete", "/CHANGE", "/Endx", "/tn x", "\n", "launchctl bootout",
              "launchctl print", "systemctl -a stop", "systemctl status", "Stop-ScheduledTask",
              "dev.sting.shipper", "a", "/", "."]
    rng = random.Random(1102)
    for _ in range(8000):
        segment = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        found = guard_parts.SERVICE_STOP.search(segment)
        assert guard_parts.service_stop(segment) == (found.span() if found else None), (
            repr(segment))


def test_the_service_stop_check_is_linear():
    from core import guard_parts

    def best_ms(text: str) -> float:
        best = float("inf")
        for _ in range(5):
            start = time.perf_counter()
            guard_parts.service_stop(text)
            best = min(best, time.perf_counter() - start)
        return best * 1000

    small = best_ms("schtasks " * (SIZE // 36))
    large = best_ms("schtasks " * (SIZE // 9))
    assert large < 6 * small + 2, (small, large)
