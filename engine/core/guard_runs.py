"""What RUNS a part of the guard no agent may run: the one-shot override
(`tools/allow_once.py`) and the installer (`install.py`, but for the runs that
change nothing), read once per command so a long one cannot stall the hook
(docs/108 §6).

`core/guard_floor.py` turns what this finds into a touch of the installed
guard; this module decides nothing.

⚠ LINEAR, AND THE SAME ANSWERS AS THE REGEXES IT REPLACED (item 1). Reading
every segment start with `_FIRST_WORD.match` and `_RUNNER.search` was quadratic
three ways: `_RUNNER`'s optional path prefix re-read the rest of a long path
from every `/` (a 20 KB `cat a/a/…/allow_once.py` took ~11 s); each start after
a `(`, `{` or backtick re-searched the rest of its segment; and the first word
was re-read from every backtick inside one word. `Runs` answers the same
questions from records it keeps as it reads, so each character is scanned a
bounded number of times however many starts are asked about.
tests/test_the_override_check_is_linear.py holds the old code verbatim as the
reference and compares every segment start.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from typing import NamedTuple

from core.command_text import _SEGMENT_END


class Script(NamedTuple):
    """A script the floor refuses to run, as the command word names it: `name`
    ends the command word's last path part (`exact`: is all of it)."""
    name: str
    exact: bool


OVERRIDE = Script("allow_once.py", exact=False)
INSTALLER = Script("install.py", exact=True)
_FIND = Script("find", exact=True)

# ⚠ THE ONE-SHOT OVERRIDE IS A PART OF THE GUARD AN AGENT MAY NOT RUN (docs/108
# §3). Established: `python3 tools/allow_once.py --yes` was ALLOW in a clean, an
# untrusted and a secret-holding session, and every refusal named it. A script
# named by any path, either separator, in any case, and the module form.
_OVERRIDE = re.compile(
    r"(?<![^\s/\\'\"`=(:])allow_once\.py(?![\w\-])"
    r"|(?<![\w.\-])(?P<module>-m[ \t]*['\"]?(?:tools\.)?allow_once)(?![\w.])", re.IGNORECASE)
# Each alternative with its lookbehind read as the character before it: the
# same matches, found without trying the lookbehind at every character.
_SCRIPT_GLUED = re.compile(r"[\s/\\'\"`=(:]allow_once\.py(?![\w\-])", re.IGNORECASE)
_MODULE_GLUED = re.compile(r"[^\w.\-]-m[ \t]*['\"]?(?:tools\.)?allow_once(?![\w.])",
                           re.IGNORECASE)
_MODULE_NAMED = re.compile(r"-m[ \t]*['\"]?(?:tools\.)?allow_once", re.IGNORECASE)
"""The module form's literal first: absent, the glued search is skipped."""
_COMMAND_START = re.compile(r"[;|&\n(`{]")

# ⚠ AN AGENT MAY NOT CHANGE THE INSTALL (item 2). `python3 install.py
# --observe`, run by an agent, was ALLOW, and switches the guard to blocking
# nothing. Any path, either separator, any case; `reinstall.py` is another file.
_INSTALLER = re.compile(r"(?<![^\s/\\'\"`=(:])install\.py(?![\w\-])", re.IGNORECASE)
_INSTALLER_GLUED = re.compile(r"[\s/\\'\"`=(:]install\.py(?![\w\-])", re.IGNORECASE)
READS_ONLY = frozenset({"--status", "--dry-run", "--check-only"})
"""The installer's runs that change nothing. An agent may make these, alone or
together; any other argument, or none, changes the install."""
REDIRECT_WORD = re.compile(r"(?:\d*|&)(?:>>?\|?|<<?<?)")
"""A redirect operator opening a word: `>`, `>>`, `>|`, `2>`, `&>`, `<`, `<<`."""
_ARGUMENT = re.compile(
    r"(?P<redirect>(?:(?<![^\s()`])\d+)?(?:[<>]&|>>|>\||<<<|<<-?|<>|[<>])|&>>?)"
    r"|(?:[^\s<>()`&'\"\\]|&(?!>)|'[^']*'|\"[^\"]*\"|\\[\s\S]?|['\"])+")
"""A redirect operator (`>`, `2>&`, `&>>`, `<<<`, … : its target is the next
word, glued or not), or a word. An unquoted `<`, `>`, `(`, `)` or backtick ends
a word, as in the shell; a quoted or escaped one is part of it."""
_QUOTING = str.maketrans("", "", "'\"\\")
_CLOSING_QUOTES = re.compile(r"['\"]+(?=[\s<>()`]|$)")
"""The quotes that close the script's own word (`python3 "install.py" …`): its
end, not an argument."""
_WORD_BREAK = re.compile(r"[\s<>]")

_FIRST_WORD = re.compile(
    r"\s*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|()<>]*\s+)*['\"]?([^\s;&|()<>'\"]+)")
"""Leading blanks, `NAME=VALUE` assignments each followed by blanks, then an
optional quote and the command word (group 1). It reads nothing past the first
of `;&|()<>`, so starts beyond that are read by it directly; a start inside
what it read (after a `{` or a backtick) is read by `Runs._first_word`'s
pieces, below, from records."""
_READ_STOP = re.compile(r"[;&|()<>]")
_BLANKS = re.compile(r"\s+")
_NAME_EQ = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_VALUE_RUN = re.compile(r"[^\s;&|()<>]+")
_WORD_RUN = re.compile(r"[^\s;&|()<>'\"]+")

# What `_RUNNER` read, as one regex, before item 1:
#     (?<![\w.\-])(?:[^\s;&|()<>'\"`]*[/\\])?NAMES(?:\.exe)?(?![\w.\-])
# with NAMES the alternation python(?:\d+(?:\.\d+)*)?w?|py|pypy\d*|ipython\d*|uvx?
# |pipx|poetry|pdm|hatch|rye|conda|mamba|micromamba|pixi|env|sudo|doas|nice|nohup
# |time|timeout|exec|command|xargs|watch|parallel|direnv|mise|asdf|sh|bash|zsh|dash
# |ksh|fish|pwsh|powershell|cmd|osascript, in any case. A runner NAME, bare or at
# the end of a path glued in front of it. A match starts at the name itself, or,
# when a name in the same path run follows a `/` or `\`, at the start of that
# run: `Runs._first_runner` finds that start without re-reading the path from
# every `/`. The names are written as a trie: the same words, tried far fewer
# times per character (measured: 17 ms to 8 ms on 128 KB).
_NAMES = (r"(?:p(?:y(?:thon(?:\d+(?:\.\d+)*)?w?|py\d*)?|ipx|oetry|dm|ixi|arallel|wsh"
          r"|owershell)|ipython\d*|uvx?|c(?:onda|ommand|md)|m(?:amba|icromamba|ise)"
          r"|e(?:nv|xec)|s(?:udo|h)|d(?:oas|irenv|ash)|n(?:ice|ohup)|time(?:out)?|xargs"
          r"|watch|hatch|rye|asdf|bash|zsh|ksh|fish|osascript)(?:\.exe)?(?![\w.\-])")
"""A word that RUNS what follows it: an interpreter, a shell, or a wrapper that
hands its arguments to one (`sudo`, `env`, `uv run`, `direnv exec . python3`)."""
_RUNNER_NAME = re.compile(r"(?<![\w.\-])" + _NAMES)
_AFTER_A_GAP = re.compile(r"[^\w.\-]" + _NAMES)
"""A name after the character that makes it one: `_RUNNER_NAME`'s lookbehind
read as a character, which is faster."""
_AFTER_A_SLASH = re.compile(r"[/\\]" + _NAMES)
_FOLD = {0x130: "i", 0x131: "i", 0x17F: "s", 0x212A: "k"}
"""The names are matched in FOLDED text, without IGNORECASE, which is 2.6
times faster (8.3 ms to 3.2 ms on 128 KB). Folding is `translate(_FOLD)` then
`lower()`: every character that IGNORECASE matches to an ASCII letter becomes
that letter, and nothing else does; no length, word character, `.`, `-` or
digit changes.
Checked over every code point (tests/test_the_override_check_is_linear.py)."""
_PATH_RUN = re.compile(r"[^\s;&|()<>'\"`]+")
_FIND_EXEC = re.compile(r"(?<![\w\-])-(?:exec|execdir|ok|okdir)(?![\w\-])")


class _RunEnds:
    """Where a maximal run of one character class ends, from any position in
    it. A run already read answers from its record, and a new read stops where
    a recorded run begins, so each character is scanned at most once."""

    __slots__ = ("_text", "_run", "_starts", "_ends")

    def __init__(self, text: str, run: re.Pattern) -> None:
        self._text, self._run = text, run
        self._starts: list[int] = []      # disjoint, ascending: read suffixes of runs
        self._ends: list[int] = []

    def end(self, at: int) -> int:
        """The end of the run holding `at`, or `at` when none does."""
        i = bisect_right(self._starts, at)
        if i and at < self._ends[i - 1]:
            return self._ends[i - 1]
        stop = self._starts[i] if i < len(self._starts) else len(self._text)
        found = self._run.match(self._text, at, stop)
        if found is None:
            return at
        if found.end() == stop and i < len(self._starts):
            self._starts[i] = at          # the same run: the record just grows back
            return self._ends[i]
        self._starts.insert(i, at)
        self._ends.insert(i, found.end())
        return found.end()


def _verb_is(text: str, begin: int, end: int, script: Script) -> bool:
    """Whether the word `text[begin:end]`'s last path part, lower-cased, ends
    with (`exact`: is) `script.name`: `verb.endswith(name)` read from the tail
    only. Lower-casing maps a character to one ASCII letter only if it is one,
    so the tail decides, and a `/` or `\\` just before it bounds the part."""
    size = len(script.name)
    if (end - begin < size or text[end - 1].lower() != script.name[-1]
            or text[end - size:end].lower() != script.name):
        return False
    return not script.exact or end - size == begin or text[end - size - 1] in "/\\"


class Runs:
    """`runs_from` for one command. Asked about ascending segment starts, as
    `override_run` asks, it reads the command in linear time; asked in any
    order, it answers the same."""

    def __init__(self, command: str) -> None:
        self.text = command
        self._segment = (-1, -1)          # (from, the first separator at or after it)
        self._read: tuple[int, int, int | None] = (-1, -1, -1)
        # `_FIRST_WORD`'s last read: (from, its segment end, where it stopped)
        self._runner = (-1, -1, -1)       # (from, segment end, the runner found)
        self._name = (-1, -1)             # (from, the first runner name at or after it)
        self._exec = (-1, -1)             # (from, the first -exec at or after it)
        self._slash = (-1, -1)            # (from, the first slash-led name at or after it)
        self._path = (-1, -1)             # a path run read: (from, its end)
        self._folded: str | None = None
        self._chains: dict[int, tuple[int, int] | None] = {}
        self._values = _RunEnds(command, _VALUE_RUN)
        self._words = _RunEnds(command, _WORD_RUN)

    def runs_from(self, start: int, script: Script) -> int:
        """Where, in the segment from `start`, the first word that could run
        `script` stands; the segment's end when none does. The script as the
        command word runs from its own start; a `find … -exec` from `start`, on
        doubt; else the first runner, as `_RUNNER.search` found it."""
        text = self.text
        end = self.segment_end(start)
        word = self._first_word(start, end)
        if word:
            if _verb_is(text, word[0], word[1], script):
                return word[0]
            if _verb_is(text, word[0], word[1], _FIND) and self._has_exec(start, end):
                return start
        begun, segment_end, found = self._runner
        if not (begun <= start <= found and segment_end == end):
            found = self._first_runner(start, end)
            self._runner = (start, end, found)
        return found

    # ── the segment and its first word ───────────────────────────────────────
    def segment_end(self, start: int) -> int:
        begun, found = self._segment
        if not begun <= start <= found:
            hit = _SEGMENT_END.search(self.text, start)
            found = hit.start() if hit else len(self.text)
            self._segment = (start, found)
        return found

    def _first_word(self, start: int, end: int) -> tuple[int, int] | None:
        """`_FIRST_WORD.match(text, start, end)`'s group 1 span: by the regex
        itself where it cannot re-read what its last read did, which stopped at
        the first of `;&|()<>` or the segment's end; else in pieces."""
        begun, begun_end, bound = self._read
        if 0 <= begun < start and self.text[start - 1] not in ";&|(":
            if bound is None:             # the last read's bound, searched once
                stop = _READ_STOP.search(self.text, begun, begun_end)
                bound = stop.start() if stop else begun_end
                self._read = (begun, begun_end, bound)
            if start <= bound:
                return self._first_word_in_pieces(start, end)
        self._read = (start, end, None)
        word = _FIRST_WORD.match(self.text, start, end)
        return word.span(1) if word else None

    def _first_word_in_pieces(self, start: int, end: int) -> tuple[int, int] | None:
        """The same span, for a start inside what an earlier start's
        `_FIRST_WORD` read. From where the blanks end, each `NAME=VALUE `
        assignment is stepped over; the word is what follows the last, or, when
        nothing follows it, the last itself (the regex backs off one
        assignment). A chain already read is joined."""
        blanks = _BLANKS.match(self.text, start, end)
        at, chain = blanks.end() if blanks else start, []
        while at not in self._chains:
            after = self._assignment_end(at, end)
            if after is None:
                self._chains[at] = self._word_at(at)
                break
            chain.append(at)
            at = after
        found = self._chains[at]
        for token in reversed(chain):
            found = found or self._word_at(token)
            self._chains[token] = found
        return found

    def _assignment_end(self, at: int, end: int) -> int | None:
        """Where `NAME=VALUE` and the blanks after it end, or None."""
        name = _NAME_EQ.match(self.text, at, end)
        if name is None:
            return None
        blanks = _BLANKS.match(self.text, self._values.end(name.end()), end)
        return blanks.end() if blanks else None

    def _word_at(self, at: int) -> tuple[int, int] | None:
        """An optional quote, then a word: its span, or None."""
        if at < len(self.text) and self.text[at] in "'\"":
            after = self._words.end(at + 1)
            return (at + 1, after) if after > at + 1 else None
        after = self._words.end(at)
        return (at, after) if after > at else None

    def _has_exec(self, start: int, end: int) -> bool:
        begun, found = self._exec
        if not begun <= start <= found:
            hit = _FIND_EXEC.search(self.text, start)
            found = hit.start() if hit else len(self.text)
            self._exec = (start, found)
        return found < end

    # ── the runner ───────────────────────────────────────────────────────────
    def _first_runner(self, start: int, end: int) -> int:
        """`_RUNNER.search(text, start, end)`'s start, or `end`: the first name,
        or the start of its path run when a name in that run follows a slash."""
        at = self._next_name(start)
        if at >= end:
            return end
        if self._slash_led(at) < self._path_end(at):
            back = _PATH_RUN.match(self.text[start:at][::-1])
            return at - back.end() if back else at
        return at

    def _names(self) -> str:
        """The command folded for the runner names (`_FOLD`)."""
        if self._folded is None:
            folded = self.text.translate(_FOLD).lower()
            if len(folded) != len(self.text):
                raise AssertionError("folding changed the command's length")
            self._folded = folded
        return self._folded

    def _next_name(self, start: int) -> int:
        """The first runner name at or after `start`, in the whole command, or
        its length. Unbounded and kept, so starts with no name before the next
        one found share one search."""
        begun, found = self._name
        if not begun <= start <= found:
            names = self._names()
            if start == 0 and _RUNNER_NAME.match(names):
                found = 0
            else:
                # A start follows a character `_AFTER_A_GAP` reads as a gap, so
                # one search from it finds a name at the start too.
                hit = _AFTER_A_GAP.search(names, max(start - 1, 0))
                found = hit.start() + 1 if hit else len(names)
            self._name = (start, found)
        return found

    def _path_end(self, at: int) -> int:
        begun, found = self._path
        if not begun <= at < found:
            run = _PATH_RUN.match(self.text, at)
            found = run.end() if run else at
            self._path = (at, found)
        return found

    def _slash_led(self, at: int) -> int:
        """The first runner name at or after `at` that follows a `/` or `\\`,
        within the path run holding `at`; that run's end when none does."""
        begun, found = self._slash
        if not begun <= at <= found:
            end = self._path_end(at)
            hit = _AFTER_A_SLASH.search(self._names(), max(at - 1, 0), end)
            found = hit.start() + 1 if hit else end
            self._slash = (at, found)
        return found


class _Overrides:
    """`_OVERRIDE.finditer(command)`'s matches, as (start, end, is the module
    form), found from the glued forms: each lookbehind read as the character
    before, the same matches. A script match may be skipped where the caller
    knows it cannot count; the next module match is kept, so it is searched for
    once, however often the script side moves."""

    def __init__(self, command: str) -> None:
        self.text = command
        self._module = (-1, -1, -1)       # (from, the first module match's start, end)

    def next(self, script_from: int, module_from: int) -> tuple[int, int, bool] | None:
        """The first match: a script at or after `script_from`, or a module
        form at or after `module_from`."""
        text = self.text
        if module_from == 0 and (here := _OVERRIDE.match(text, 0)):
            return here.start(), here.end(), bool(here.group("module"))
        script = _SCRIPT_GLUED.search(text, max(script_from - 1, 0))
        begun, module, module_end = self._module
        if not begun <= module_from <= module:
            hit = (_MODULE_NAMED.search(text, module_from)
                   and _MODULE_GLUED.search(text, max(module_from - 1, 0)))
            module, module_end = (hit.start() + 1, hit.end()) if hit else (len(text), -1)
            self._module = (module_from, module, module_end)
        if script and script.start() + 1 < module:
            return script.start() + 1, script.end(), False
        return (module, module_end, True) if module_end >= 0 else None


def _next_installer(command: str, at: int) -> tuple[int, int] | None:
    """`_INSTALLER`'s first match at or after `at`, from its glued form."""
    if at == 0 and (here := _INSTALLER.match(command, 0)):
        return here.span()
    glued = _INSTALLER_GLUED.search(command, max(at - 1, 0))
    return (glued.start() + 1, glued.end()) if glued else None


def _reads_only(command: str, after: int, end: int) -> bool:
    """Whether EVERY argument from `after` to `end` is one of `READS_ONLY`,
    and there is one (the review). A redirect and its target are not
    arguments; anything else is, an empty one or a quoted `>` too. Quotes and
    backslashes are dropped before the comparison: what is left equals one of
    the three only if the shell's word does, or holds a quote install.py's
    parser refuses."""
    closing = _CLOSING_QUOTES.match(command, after, end)
    target, seen = False, False
    for token in _ARGUMENT.finditer(command, closing.end() if closing else after, end):
        if token.group("redirect"):
            target = True
        elif target:
            target = False
        elif token.group().translate(_QUOTING) in READS_ONLY:
            seen = True
        else:
            return False
    return seen


class _RedirectTargets:
    """Whether an `install.py` match stands in a redirect's target (`>
    install.py.txt`, `2>logs/install.py.log`, `--status>install.py.out`): a
    file written, not a script run. Asked in ascending order, as
    `installer_run` asks: each word's start is found reading forward from the
    last question, and each word is judged once."""

    def __init__(self, command: str) -> None:
        self.text = command
        self._read_to = 0                 # the word starts before this are known
        self._word = 0                    # the start of the word holding `_read_to`
        self._judged = (-1, False)        # (a word's start, is it a target)

    def holds(self, at: int) -> bool:
        for gap in _WORD_BREAK.finditer(self.text, self._read_to, at):
            self._word = gap.end()
        self._read_to = max(self._read_to, at)
        if self._judged[0] != self._word:
            self._judged = (self._word, self._after_an_operator(self._word))
        return self._judged[1]

    def _after_an_operator(self, word: int) -> bool:
        """Whether a redirect operator, unquoted, ends right before `word`
        (glued) or before the blanks before it. Its last character is `<` or
        `>`, or the `&`, `|` or `-` after one (`>&`, `>|`, `<<-`)."""
        text, at = self.text, word - 1
        while at >= 0 and text[at] in " \t":
            at -= 1
        if at > 0 and text[at] in "&|-" and text[at - 1] in "<>":
            at -= 1
        if at < 0 or text[at] not in "<>":
            return False
        while at > 0 and text[at - 1] in "<>&":
            at -= 1
        return at == 0 or text[at - 1] not in "'\"\\"


def installer_run(command: str) -> tuple[int, int] | None:
    """The span of the first `install.py` a segment RUNS, as `override_run`
    reads a run, with an argument other than `READS_ONLY`'s or with none:
    anything that changes the install. `--status`, `--dry-run` and
    `--check-only`, alone or together, stay allowed; so does naming the file,
    and writing to a file whose name holds it (`> install.py.txt`).

    A segment's run is judged once, on every word after it: when they all
    read, every later match in that segment stands in a redirect's target, so
    the next match looked at is past the segment's end. The next command
    start is searched for once however many targets lie before it."""
    runs, targets = Runs(command), _RedirectTargets(command)
    start, judged, runs_at, next_start = 0, -1, 0, 0
    searched = (-1, -1)                   # (from, the first command start at or after it)
    found = _next_installer(command, 0)
    while found is not None:
        at, found_end = found
        if at >= next_start:
            back = _COMMAND_START.search(command[next_start - 1 if next_start else 0:at][::-1])
            if back:
                start = at - back.start()
        if start != judged:
            judged = start
            runs_at = runs.runs_from(start, INSTALLER)
        if runs_at <= at and not targets.holds(at):
            end = runs.segment_end(start)
            if not _reads_only(command, found_end, end):
                return at, found_end
            next_start = end + 1
            found = _next_installer(command, end)
            continue
        if not searched[0] <= found_end <= searched[1]:
            nxt = _COMMAND_START.search(command, found_end)
            searched = (found_end, nxt.start() if nxt else len(command))
        next_start = searched[1] + 1
        found = _next_installer(command, max(found_end, min(runs_at, next_start)))
    return None


def override_run(command: str) -> tuple[int, int] | None:
    """The span of the first `tools/allow_once.py` a segment RUNS, installed
    tree or checkout: the script as the command word, or after a word that runs
    what follows it (`python3`, `sh -c`, `sudo`, `uv run`), or `-m
    tools.allow_once`. Naming the file is not running it: `cat`, `sed`, `grep`,
    `git add` and a PR body stay allowed, so developing Sting does not trip it
    (docs/108 §6 lists what can still reach a grant).

    The matches in order, as `_OVERRIDE.finditer` gave them; each one's segment
    start is the last command start before it, and each start is judged once,
    by `Runs`. A start that runs nothing before the next start skips its other
    script matches; a module form always counts, so none is skipped."""
    runs, overrides = Runs(command), _Overrides(command)
    start, judged, runs_at, next_start = 0, -1, 0, 0
    found = overrides.next(0, 0)
    while found is not None:
        at, found_end, module = found
        if at >= next_start:
            back = _COMMAND_START.search(command[next_start - 1 if next_start else 0:at][::-1])
            if back:
                start = at - back.start()
        if start != judged:
            judged = start
            runs_at = runs.runs_from(start, OVERRIDE)
        if module or runs_at <= at:
            return at, found_end
        nxt = _COMMAND_START.search(command, found_end)
        next_start = nxt.end() if nxt else len(command) + 1
        found = overrides.next(max(found_end, min(runs_at, next_start)), found_end)
    return None
