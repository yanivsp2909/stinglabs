"""Where a value that a clue names begins and ends: the reading behind the
context provider in `shipper/mask.py` (`Authorization:`, `--password`,
`NAME=`, `"key":`), which asks `value_span` for the value after each clue.

⚠ MASK ON DOUBT. Where the end of a value is a guess, the guess takes more:
everything the shell, JSON or YAML would read as the value, a bracket to its
close, a quoted string to its close however far, and a value still going
after `_MAX_VALUE` characters to the end of the text. Only an unquoted literal
and the engine's own stand-in are no value. Entropy is never read (hard rule).
"""
from __future__ import annotations

import re

from core import known_formats

_CONTINUATION = re.compile(r"\\(?:\r\n|\n|\r)")
r"""A shell line continuation: `\` and a line break, removed by the shell. It
joins a value across lines, and it can sit between a clue and its value."""
_MAX_VALUE = 4096
"""How far a word or a line is scanned for the end of a value (a quoted value's
close is found however far). ⚠ ONE STILL GOING THERE RUNS TO THE END OF THE
TEXT (security review, round three: the rest of a 16 KB value shipped as
written). Where it would end past this is a guess, and a guess must not leak."""
_QUOTE_OPEN = re.compile(r"[rbfuRBFU]{0,2}(\\{0,3}(?:\"\"\"|'''|```|[\"'`]))")
"""An opening quote, a triple one first: to one-quote reading `\"\"\"X\"\"\"` is an
empty string and then `X` (security review, round three)."""
_WORD_STOP = frozenset(" \t\r\n;&|()\"'`")
"""What ends a shell word. Not `<` or `>`: a value glued to one is the value too
(`X<y>SECRET`), and a redirect masked with its value is an over-mask."""

_LOOSE_STOP = frozenset("\r\n\"'`,}])")
_LITERAL = re.compile(r"True|False|None|true|false|null|nil|undefined")
"""An unquoted literal that states no value: the one thing after a clue left
alone for its shape. ⚠ ONLY THIS (security review, round two). A reference
(`$NAME`, `$(…)`), a placeholder (`{name}`, `<name>`) and a call (`f(…)`)
were exempt too, and each can hold the value itself: `{SECRET}`,
`wrap(SECRET)`, `$(echo SECRET)`. They are masked, whole: mask on doubt."""
_STAND_IN = re.compile(r"<(?:%s), [0-9]{1,6} chars>" % "|".join(
    re.escape(fmt.name) for fmt in known_formats.FORMATS))
"""`<a GitHub token, 40 chars>`: what the engine writes in `evidence` where a
known-format value sat (#75, `known_formats.stand_in`). Our own vocabulary,
never a value — and only a format's own name, so no free text rides in it.
⚠ ONLY THE WHOLE VALUE: `<a GitHub token, 40 chars>SECRET` is a value
(security review, round three)."""
def _no_value(value: str, quoted: bool) -> bool:
    """Nothing to mask: an empty value, an unquoted literal (`_LITERAL`), or
    the engine's own stand-in for a value it already hid (`_STAND_IN`)."""
    value = value.strip()
    return (not value or bool(_STAND_IN.fullmatch(value))
            or (not quoted and bool(_LITERAL.fullmatch(value))))


def _closing(text: str, start: int, quote: str) -> int:
    """Where a quoted value that opens before `start` ends: at its closing
    quote, an escaped one not counting, however far (a cap shipped the rest of
    a long value). None at all: the end of the line (mask on doubt)."""
    at = text.find(quote, start)
    while at != -1:
        before = at
        while before > start and text[before - 1] == "\\":
            before -= 1
        if len(quote) > 1 or (at - before) % 2 == 0:
            return at
        at = text.find(quote, at + 1)
    line = text.find("\n", start)
    return line if line != -1 else len(text)


def _balanced(text: str, opening: int, limit: int) -> int:
    """The index after the bracket that closes the one at `opening`. An escaped
    character and a quoted string inside count for nothing (security review,
    round three: `wrap("a)", SECRET)` closed at the quoted `)` and shipped
    SECRET)."""
    pair = {"(": ")", "{": "}", "[": "]"}[text[opening]]
    depth, i = 0, opening
    while i < limit:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c in "\"'`":
            i = _closing(text, i + 1, c) + 1
            continue
        if c == text[opening]:
            depth += 1
        elif c == pair:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return limit


def _word_end(text: str, i: int) -> int:
    """The end of a shell word from `i`: whitespace, an operator or a quote ends
    it (a quote after an unquoted value closes the string around it far more
    often than it opens a new one); `\\x`, a line continuation and a bracket
    read to its close are part of it: `$(…)`, `${…}`, a call's `(…)` whole, or
    `wrap(SECRET)` would keep its argument out of the value, and `{…}` and
    `[…]` whole (security review, round four: `TOKEN={"a}": SECRET}`)."""
    limit = min(len(text), i + _MAX_VALUE)
    while i < limit:
        c = text[i]
        continued = _CONTINUATION.match(text, i)
        if continued:
            i = continued.end()
        elif c == "\\" and i + 1 < limit:
            i += 2
        elif c in "([{":
            i = _balanced(text, i, limit)
        elif c in _WORD_STOP:
            return i
        else:
            i += 1
    return len(text)                                 # the text ended, or the cap did


def _loose_end(text: str, i: int) -> int:
    """The end of a `NAME: value` (YAML, a header, INI): the rest of the line,
    up to a quote, `,`, `}`, `]`, `)` or a literal `\\n`, trailing space off.
    A bracket the value opens is read to its close: `os.environ.get("X")` and
    `data["x"]` are one value each."""
    limit = min(len(text), i + _MAX_VALUE)
    j = i
    while j < limit:
        continued = _CONTINUATION.match(text, j)
        if continued:
            j = continued.end()
            continue
        if text[j] in "([{":
            j = _balanced(text, j, limit)
            continue
        if text[j] in _LOOSE_STOP or text.startswith("\\n", j):
            break
        j += 1
    else:
        j = len(text)                                # the text ended, or the cap did
    while j > i and text[j - 1] in " \t":
        j -= 1
    return j


def _angle_close(text: str, i: int) -> int:
    """After the `>` that closes the `<` at `i`: the engine's stand-in whole,
    else the first `>` on the line; with none, after the `<`. To a shell `<`
    redirects, and in prose it sets a value off (security review, round two);
    what is glued after the `>` is read on as the value (round three)."""
    stand_in = _STAND_IN.match(text, i)
    if stand_in:
        return stand_in.end()
    line = text.find("\n", i)
    close = text.find(">", i, line if line != -1 else len(text))
    return close + 1 if close != -1 else i + 1


def value_span(text: str, at: int, *, loose: bool,
                flag_value: bool = False) -> tuple[int, int] | None:
    """[start, end) of the value that begins at `at`, or None."""
    i = at
    while True:                     # spaces, and any line continuation among them
        while i < len(text) and text[i] in " \t":
            i += 1
        continued = _CONTINUATION.match(text, i)
        if not continued:
            break
        i = continued.end()
    if i >= len(text) or text[i] in "\r\n":
        return None
    # ⚠ A BACKTICK IS A QUOTE HERE TOO. To a shell it runs a command, and in
    # JS or Go it is a string, which a heredoc carries (security review): mask
    # on doubt, so its content is a value unless it is only a reference.
    opening = _QUOTE_OPEN.match(text, i)
    if opening:
        start = opening.end()
        end = _closing(text, start, opening.group(1))
    else:
        if flag_value and text[i] == "-":          # the next word is a flag
            return None
        start = i
        end = _loose_end(text, i) if loose else _word_end(text, i)
        if text[i] == "<":
            end = max(end, _word_end(text, _angle_close(text, i)))
    if _no_value(text[start:end], quoted=bool(opening)):
        return None
    return start, end
