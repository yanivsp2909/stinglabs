"""The runner check reads a long command in linear time, and decides the same.

⚠ MEASURED, NOT SUPPOSED (item 1). The committed check was quadratic in three
places: `_RUNNER`'s optional path prefix re-read the rest of a long path from
every `/` (`cat a/a/…/allow_once.py`: 121 ms at 2 KB, 1.9 s at 8 KB, ~11 s at
20 KB); each segment start after a `(`, `{` or backtick re-searched the rest
of its segment; and the first word was re-read from every backtick inside one
word.

THIS IS A PERFORMANCE CHANGE AND NOTHING ELSE. So besides the time bound, the
committed code is copied verbatim below as the reference, and every segment
start of every command (the existing cases, the fixture's real commands, and
seeded generated text) must read exactly as it did. A difference in ANY output
fails. Every probe is data; nothing is executed.
"""
from __future__ import annotations

import random
import re
import signal
import sys
import time
from pathlib import Path

import pytest

from core import guard_floor
from core.command_text import _segment_end
from core.probes import NullWorld
from core.session import SessionState
from core.types import Action, ActionKind

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_an_agent_cannot_run_allow_once import RUNS, STAYS   # noqa: E402
from private_fixtures import needs_live_fixture  # noqa: E402

BUDGET_MS = 12.0
"""A6a's p99 budget for the whole hook (core/probes.py)."""
SIZE = 128 * 1024


# ── the committed code (c3f075d core/guard_floor.py), verbatim: the reference ─
_OVERRIDE = re.compile(
    r"(?<![^\s/\\'\"`=(:])allow_once\.py(?![\w\-])"
    r"|(?<![\w.\-])(?P<module>-m[ \t]*['\"]?(?:tools\.)?allow_once)(?![\w.])", re.IGNORECASE)
_COMMAND_START = re.compile(r"[;|&\n(`{]")
_FIRST_WORD = re.compile(
    r"\s*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|()<>]*\s+)*['\"]?([^\s;&|()<>'\"]+)")
_RUNNER = re.compile(
    r"(?<![\w.\-])(?:[^\s;&|()<>'\"`]*[/\\])?"
    r"(?:python(?:\d+(?:\.\d+)*)?w?|py|pypy\d*|ipython\d*|uvx?|pipx|poetry|pdm|hatch|rye"
    r"|conda|mamba|micromamba|pixi|env|sudo|doas|nice|nohup|time|timeout|exec|command"
    r"|xargs|watch|parallel|direnv|mise|asdf|sh|bash|zsh|dash|ksh|fish|pwsh|powershell"
    r"|cmd|osascript)(?:\.exe)?(?![\w.\-])", re.IGNORECASE)
_FIND_EXEC = re.compile(r"(?<![\w\-])-(?:exec|execdir|ok|okdir)(?![\w\-])")


def _old_runs_from(command: str, start: int, end: int) -> int:
    word = _FIRST_WORD.match(command, start, end)
    if word:
        verb = word.group(1).replace("\\", "/").rsplit("/", 1)[-1].lower()
        if verb.endswith("allow_once.py"):
            return word.start(1)
        if verb == "find" and _FIND_EXEC.search(command, start, end):
            return start
    runner = _RUNNER.search(command, start, end)
    return runner.start() if runner else end


def _old_override_run(command: str) -> tuple[int, int] | None:
    starts = [0] + [m.end() for m in _COMMAND_START.finditer(command)]
    at, judged, runs_at = 0, -1, 0
    for found in _OVERRIDE.finditer(command):
        while at + 1 < len(starts) and starts[at + 1] <= found.start():
            at += 1
        start = starts[at]
        if start != judged:
            judged = start
            runs_at = _old_runs_from(command, start, _segment_end(command, start))
        if found.group("module") or runs_at <= found.start():
            return found.start(), found.end()
    return None


# ── the population ────────────────────────────────────────────────────────────
def _fixture_commands() -> list[str]:
    from runner import replay_live
    out = []
    for records in replay_live.load_records(ROOT / "logs" / "live-fixture").values():
        for record in records:
            _klass, command = replay_live.classify(record, Path(record["_log_path"]))
            if isinstance(command, str) and command:
                out.append(command)
    return sorted(set(out))


# Every piece the three readers turn on: runner names in each spelling and
# after each glue, the script and the module form, assignments, quotes, the six
# command starts, separators, `find -exec`, and characters whose lower case is
# not one ASCII letter.
_PIECES = ["python3", "py", "Python3.12", "pythonw", "python.exe", "PY", "pypy3",
           "sudo", "env", "sh", "-c", "bash", "time", "uv", "run", "exec", "command",
           "find", "-exec", "-execdir", "-ok", "{}", "\\;", "cat", "grep", "sed",
           "allow_once.py", "ALLOW_ONCE.PY", "tools/allow_once.py", "tools\\allow_once.py",
           "/x/allow_once.py", "xallow_once.py", "allow_once.pyc", "-m", "tools.allow_once",
           "-mallow_once", "A=1", "B=", "X=y{z", "C='a b'", "D=\"$(x)\"", "x", "a/b", "/",
           "\\", "{", "}", "(", ")", "`", "'", '"', ";", "&&", "|", "&", ">", "2>&1",
           "&>", "<", "\n", "\\\n", " ", " ", " ", "  ", "\t", "=", ":", "$(", "İ", "K",
           "Σ", "/python", "{python", "=python", ":sh", ".exe", "FIND", "fİnd", "-"]


def _generated(count: int, seed: int = 20260929) -> list[str]:
    rng = random.Random(seed)
    return ["".join(rng.choice(_PIECES) for _ in range(rng.randint(1, 30)))
            for _ in range(count)]


POPULATION = None


def _population() -> list[str]:
    global POPULATION
    if POPULATION is None:
        POPULATION = list(RUNS) + list(STAYS) + _fixture_commands() + _generated(6000)
    return POPULATION


# ── identical results ─────────────────────────────────────────────────────────
@needs_live_fixture
def test_every_segment_start_reads_as_it_did():
    """In ascending order, one reader per command, as `override_run` asks."""
    from core import guard_runs
    differ = []
    assert len(_population()) > len(RUNS) + len(STAYS) + 6000, "the fixture was not read"
    for command in _population():
        runs = guard_runs.Runs(command)
        starts = sorted({0} | {m.end() for m in _COMMAND_START.finditer(command)})
        for start in starts:
            old = _old_runs_from(command, start, _segment_end(command, start))
            new = runs.runs_from(start, guard_runs.OVERRIDE)
            if new != old:
                differ.append((command, start, old, new))
    assert not differ, differ[:5]


def test_a_reader_asked_in_any_order_answers_the_same():
    """Its records are correct whatever the order; only the time bound needs
    ascending starts."""
    from core import guard_runs
    rng = random.Random(5)
    for command in _generated(800, seed=77):
        runs = guard_runs.Runs(command)
        starts = sorted({0} | {m.end() for m in _COMMAND_START.finditer(command)})
        assert starts, command
        rng.shuffle(starts)
        for start in starts:
            assert runs.runs_from(start, guard_runs.OVERRIDE) == _old_runs_from(
                command, start, _segment_end(command, start)), (command, start)


def test_the_override_is_found_where_it_was():
    differ = []
    for command in _population():
        old = _old_override_run(command)
        touch = guard_floor._override_run(command)
        new = (touch.start, touch.end) if touch else None
        if new != old:
            differ.append((command, old, new))
    assert not differ, differ[:5]


# ── the pieces the new reader rests on ─────────────────────────────────────────
_OLD_NAMES = ("python", "py", "pypy", "ipython", "uv", "uvx", "pipx", "poetry", "pdm",
              "hatch", "rye", "conda", "mamba", "micromamba", "pixi", "env", "sudo", "doas",
              "nice", "nohup", "time", "timeout", "exec", "command", "xargs", "watch",
              "parallel", "direnv", "mise", "asdf", "sh", "bash", "zsh", "dash", "ksh", "fish",
              "pwsh", "powershell", "cmd", "osascript")
"""Every word in the committed `_RUNNER`'s alternation, which `guard_runs`
writes as a trie."""


@pytest.mark.parametrize("name", _OLD_NAMES)
def test_every_runner_name_reads_as_it_did(name):
    from core import guard_runs
    for word in (name, name.upper(), name.title(), f"{name}.exe", f"{name}3", f"{name}3.12",
                 f"{name}w", f"{name}x", f"{name}-", f"{name}.", f"/usr/bin/{name}",
                 f"C:\\bin\\{name}.EXE", f"x{name}", f"{name}/", f"{name}ſ", f"{name}K"):
        command = f"cat {word} tools/allow_once.py"
        old = _old_runs_from(command, 0, len(command))
        assert guard_runs.Runs(command).runs_from(0, guard_runs.OVERRIDE) == old, word


def test_folding_changes_nothing_the_names_read():
    """`guard_runs._FOLD`: over every code point, folding keeps the length,
    `[\\w.\\-]` and `\\d`, and a character IGNORECASE matches to an ASCII
    letter folds to exactly that letter (and nothing else does)."""
    from core import guard_runs
    word, digit = re.compile(r"[\w.\-]"), re.compile(r"\d")
    letter = re.compile(r"[a-z]", re.IGNORECASE)
    for point in range(0x110000):
        if 0xD800 <= point <= 0xDFFF:
            continue
        char = chr(point)
        folded = char.translate(guard_runs._FOLD).lower()
        assert len(folded) == 1, hex(point)
        assert bool(word.match(char)) == bool(word.match(folded)), hex(point)
        assert bool(digit.match(char)) == bool(digit.match(folded)), hex(point)
        if letter.match(char) or "a" <= folded <= "z":
            assert re.match(re.escape(folded), char, re.IGNORECASE), hex(point)
            assert "a" <= folded <= "z", hex(point)


# ── bounded time ──────────────────────────────────────────────────────────────
def _fill(unit: str, head: str = "cat ", tail: str = "", size: int = SIZE) -> str:
    return head + unit * ((size - len(head) - len(tail)) // len(unit)) + tail


NAME = "allow_once.py"
ONE_READ = {
    # `_RUNNER`'s path prefix, re-read from every `/`: ~11 s at 20 KB before
    "a long path": lambda size: _fill("a/", tail=NAME, size=size),
    "a long path naming it at every step": lambda size: _fill("/" + NAME, size=size),
    # the first word re-read from every brace inside one word
    "braces in one word": lambda size: _fill("{/" + NAME + "x", size=size),
    "runner names in one run": lambda size: _fill("{python{/" + NAME, size=size),
    "assignments": lambda size: _fill("A=1 ", tail=NAME, size=size),
}
MANY_STARTS = {
    # every start inside one segment searched the rest of it (quadratic before)
    "paren starts": lambda size: _fill("(cat /" + NAME + " ", size=size),
    "brace starts": lambda size: _fill("{cat /" + NAME + " ", size=size),
    "backtick starts": lambda size: _fill("`cat /" + NAME + "` ", size=size),
    "find starts": lambda size: _fill("(find /" + NAME + " ", size=size),
    "backticks in one word": lambda size: _fill("`/" + NAME, tail="x", size=size),
    "assignments in one value": lambda size: _fill("{A=/" + NAME, head="X=", tail=" y",
                                                   size=size),
    # linear before too
    "semicolons": lambda size: _fill(";cat " + NAME, size=size),
}
STALLS = {**ONE_READ, **MANY_STARTS}


class _TooSlow(Exception):
    pass


def _seconds(call, *args) -> float:
    """Wall time of one call, cut off at 10 s so a quadratic read fails fast."""
    def cut(*_):
        raise _TooSlow

    previous = signal.signal(signal.SIGALRM, cut)
    signal.alarm(10)
    began = time.perf_counter()
    try:
        call(*args)
    except _TooSlow:
        return 10.0
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    return time.perf_counter() - began


def _best_ms(command: str, tries: int = 5) -> float:
    return min(_seconds(guard_floor._override_run, command) for _ in range(tries)) * 1000


@pytest.mark.parametrize("shape", list(ONE_READ))
def test_a_128_kb_command_is_read_within_the_hook_budget(shape):
    """Measured on this machine, best of 5: 1.0 to 5.1 ms."""
    assert _best_ms(ONE_READ[shape](SIZE)) < BUDGET_MS, shape


@pytest.mark.parametrize("shape", list(MANY_STARTS))
def test_thousands_of_segment_starts_are_read_in_linear_time(shape):
    """⚠ OVER THE HOOK BUDGET, AND LINEAR. 128 KB of `(cat /allow_once.py `
    is ~6,500 segment starts that each name the script, and each is judged,
    as the committed code judged them: 12 to 21 ms here (the committed code:
    17 to 27 ms on the two shapes that were linear, seconds to minutes on the
    rest). A whole `decide` on any 128 KB command already costs 220 to 1,100
    ms in the engine's other readers. So the bound here is the growth: four
    times the text, about four times the time, never sixteen."""
    small = _best_ms(MANY_STARTS[shape](SIZE // 4))
    large = _best_ms(MANY_STARTS[shape](SIZE))
    assert large < 6 * small + 2, (shape, small, large)
    assert large < 60, (shape, large)


# ⚠ THE INSTALLER'S RUN IS READ THE SAME WAY (the review). Its arguments are
# read once per segment, and a match inside a redirect target is looked back
# from once per word, so neither a run of targets nor a long argument list
# re-reads the command.
INSTALLER = "install.py"
INSTALLER_SHAPES = {
    "redirect targets naming it": lambda size: _fill(" > " + INSTALLER + ".txt",
                                                     head="python3 x.py", size=size),
    "one target naming it at every step": lambda size: _fill("/" + INSTALLER,
                                                             head="python3 x.py > t",
                                                             size=size),
    "read-only arguments": lambda size: _fill(" --status", head="python3 " + INSTALLER,
                                              size=size),
    "read-only runs": lambda size: _fill(";python3 " + INSTALLER + " --status", size=size),
}


def _installer_ms(command: str, tries: int = 5) -> float:
    return min(_seconds(guard_floor._installer_run, command) for _ in range(tries)) * 1000


@pytest.mark.parametrize("shape", list(INSTALLER_SHAPES))
def test_the_installer_run_is_read_in_linear_time(shape):
    small = _installer_ms(INSTALLER_SHAPES[shape](SIZE // 4))
    large = _installer_ms(INSTALLER_SHAPES[shape](SIZE))
    assert large < 6 * small + 2, (shape, small, large)
    assert large < 60, (shape, large)


@pytest.mark.parametrize("shape", list(STALLS))
def test_the_whole_decision_on_it_is_bounded(shape):
    """The stall tests' bound for a whole `decide` (2 s); the runner check was
    the part that exceeded it."""
    # `find starts` was skipped here: a whole decide on `(find …` was quadratic
    # in irreversible.find_destroys_a_catastrophic_root. Linear since item E of
    # fix/agents-block-and-env-reads (tests/test_the_find_check_is_linear.py).
    from core import engine
    state = SessionState("t")
    state.seq = 1
    action = Action("t", 1, ActionKind.EXEC, (), STALLS[shape](SIZE), None, "Bash", None,
                    "/repo", ("/repo",), "claude-code")
    assert _seconds(engine.decide, action, state, NullWorld()) < 2.0, shape
