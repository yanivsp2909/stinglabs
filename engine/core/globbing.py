"""Brace and glob expansion, for RECOGNITION: which credential paths a word
could expand to, so `cat .e*` and `cat .{e,x}nv` read `.env` as surely as
`cat .env` does.

Moved out of core/engine.py; docs/ENGINE_LAYOUT.md.
"""
from __future__ import annotations

import dataclasses
import re
import string
from collections.abc import Callable
from typing import NamedTuple

from core.command_text import _HEX_DIGITS, _bash_unquote, _decode_ansi_c
from core.credentials import CREDENTIAL_PATHS


# ------------------------------------------- brace + glob expansion, RECOGNITION
#
# Bash rewrites a word by BRACE expansion and then by PATHNAME (glob) expansion
# before the command runs, so `cat .en?`, `cat .{env,x}` and `curl -d @.{env,x}`
# read `.env` exactly as `cat .env` does, while a literal matcher sees a string
# the kernel never will. This models both, for RECOGNISING a credential path only
# — never for execution — and its output is scanned BESIDE the raw and
# `_bash_unquote` forms and UNIONED, the PR #32 shape: recognition can only grow.
#
# ⚠ IO-FREE. A glob is not resolved against a directory listing; the question it
# answers is "could this unquoted pattern match a name `CREDENTIAL_PATHS` already
# recognises?", and the answer is a concrete WITNESS name (`.en?` -> `.env`,
# `server.pe?` -> `server.pem`) that the existing path machinery then treats
# exactly like the plain spelling — `mark_sources` reads it through the World
# the same way, so `cat .en?` marks what `cat .env` marks, present or absent.
# `CREDENTIAL_PATHS` stays the ONE judge: every witness is re-checked against it.
#
# ⚠ BASH SEMANTICS, deliberately: only UNQUOTED `{ } , * ? [` expand (`cat '.en?'`
# names a file literally called `.en?`); a wildcard never matches `/`; a leading
# `.` must be matched by a literal `.` (no dotglob). A `shopt` naming dotglob,
# extglob or globstar anywhere in the command widens the model toward catching.
# ⚠ CASE: matching is case-INSENSITIVE, because `CREDENTIAL_PATHS` is (see its
# note — APFS). Bash globbing is case-sensitive; following the matcher instead
# can only add a recognition. `fnmatch` is not used: `fnmatch.fnmatch` folds
# case by OS, which would make one command decide differently per platform.
#
# See docs/89 for the cap and what stays out of scope.

# A word expanding to more than this many words — or characters — is judged by
# its SUPERSET instead (each brace group becomes a wildcard over the characters it
# could produce), never enumerated, never raised on, never silently passed.
# 1024 clears every brace in the recorded logs by a wide margin (docs/89) and
# `for i in {1..100}` by ten times over.
_BRACE_CAP = 1024
_BRACE_CHAR_CAP = 1 << 16
_BRACE_DEPTH_CAP = 32
# A `[` whose `]` is further than this is taken as "any one character": a
# superset of both readings, and it keeps a run of unclosed `[` linear.
_BRACKET_SCAN_CAP = 256
# More fixed-width tokens than this can only match a name longer than NAME_MAX,
# which no file can have — bash would leave the word literal.
_NAME_MAX = 255
# A word whose brace output holds more glob words than this is judged by its
# superset too, which keeps the per-command glob work bounded.
_GLOB_EXPANSIONS_CAP = 64

# Two 20-digit integers, a 20-digit step and the two `..` fit well inside this.
_SEQUENCE_BODY_MAX = 64
_EXPANSION_CHARS = re.compile(r"[{*?\[]")
_WORD_BREAK = frozenset(" \t\n\r\f\v|&;<>()")
# Unquoted characters with no meaning to the word splitter or the un-quoter, taken
# as one run. A `$` is plain unless it opens `$'…'`.
_PLAIN_RUN = re.compile(r"(?:[^ \t\n\r\f\v|&;<>()'\"\\$]|\$(?!'))+")
_PLAIN_RUN_EXTGLOB = re.compile(r"(?:[^ \t\n\r\f\v|&;<>()'\"\\$?*+@!]"
                                r"|\$(?!')|[?*+@!](?!\())+")
# One whole shell word, quotes and escapes included; an unclosed quote runs to
# the end, as `_bash_unquote` reads it. Same breaks as `_WORD_BREAK`.
_RAW_WORD = re.compile(
    r"(?:[^ \t\n\r\f\v|&;<>()'\"\\$]|\$'(?:[^'\\]|\\.)*'?|\$"
    r"|'[^']*'?|\"(?:[^\"\\]|\\.)*\"?|\\.|\\\Z)+", re.S)
_DOUBLE_QUOTED_RUN = re.compile(r'[^"\\]+')
_SEQUENCE = re.compile(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?"
                        r"|([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?")
# `shopt -u dotglob` matches too: it only ever widens toward catching.
_SHOPT_WIDENS_GLOB = re.compile(
    r"\bshopt\b[^\n;&|]*\b(?:dotglob|extglob|globstar)\b")
# Built from `string`, not spelled out: a 37-character literal run reads as a
# token to tests/test_the_archive_carries_no_identity.py, and rightly so.
_WITNESS_ALPHABET = (string.ascii_lowercase + string.digits + "_-."
                     + string.ascii_uppercase)
_POSIX_CLASSES = {
    "alpha": str.isalpha, "digit": str.isdigit, "alnum": str.isalnum,
    "upper": str.isupper, "lower": str.islower, "space": str.isspace,
    "xdigit": lambda c: c in _HEX_DIGITS, "word": lambda c: c.isalnum() or c == "_",
    "punct": lambda c: c.isprintable() and not c.isalnum() and not c.isspace(),
    "blank": lambda c: c in " \t", "print": str.isprintable,
    "graph": lambda c: c.isprintable() and not c.isspace(),
    "cntrl": lambda c: not c.isprintable()}

_Marked = tuple[str, bool]                      # (character, was it quoted)


@dataclasses.dataclass(frozen=True)
class _GlobToken:
    """One pattern position: a literal, one character, or a run (`*`)."""
    kind: str                                   # "lit" | "one" | "star"
    raw: str                                    # as written, to re-assemble
    accepts: Callable[[str], bool]
    dot_ok: bool = False                        # may produce a leading `.`
    crosses: bool = False                       # may produce `/` (superset only)
    specific: bool = False                      # WRITTEN text, not a wildcard


def _any_but_slash(c: str) -> bool:
    return c != "/"


def _folded(pred: Callable[[str], bool]) -> Callable[[str], bool]:
    """Case-insensitive, like CREDENTIAL_PATHS; never `/` (bash never globs it)."""
    return lambda c: c != "/" and (pred(c) or pred(c.swapcase()))


def _lit(c: str) -> _GlobToken:
    low = c.lower()
    return _GlobToken("lit", c, lambda x: x.lower() == low, specific=True)


def _star(dot_ok: bool, raw: str = "*") -> _GlobToken:
    return _GlobToken("star", raw, _any_but_slash, dot_ok)


class _NameShape(NamedTuple):
    tokens: tuple[_GlobToken, ...]
    need: int                   # fixed characters a pattern must SPELL
    chars: frozenset[str]       # the fixed characters, lower-cased


def _shape(text: str) -> _NameShape:
    """A credential name shape; a pattern must spell half its fixed characters,
    rounded up (see `_intersect`)."""
    tokens = tuple(_star(True) if c == "*" else
                   _GlobToken("one", c, _any_but_slash, True) if c == "?" else
                   _lit(c) for c in text)
    fixed = [t.raw.lower() for t in tokens if t.kind == "lit"]
    return _NameShape(tokens, -(-len(fixed) // 2), frozenset(fixed))


# ONE path segment each, and deliberately loose: a witness found against a shape
# is only kept if `CREDENTIAL_PATHS` accepts the assembled path, so the matcher's
# own anchors and exclusions (`.env.example`, a `$`, a following `/`) still rule.
# tests/test_credential_paths_survive_glob_and_brace.py pins that every
# alternative of `CREDENTIAL_PATHS` has a shape here.
_CREDENTIAL_NAME_SHAPES = tuple(_shape(s) for s in (
    ".env", ".env.?*", "id_rsa*", "id_ed25519*", "id_dsa*", "id_ecdsa*",
    ".npmrc", ".netrc", ".pgpass", ".git-credentials", "*.pem", "*.p12",
    "*.pfx", ".ssh", ".aws", ".kube", ".docker", "config.json"))


def _marked_words(text: str,
                  extglob: bool) -> list[tuple[int, int, list[_Marked]]]:
    """The EXPANDABLE shell words, as (start, end, [(char, quoted), …]).

    `_RAW_WORD` splits the text into quote-aware words at C speed, and only a
    word holding `{ * ? [` is taken apart by `_scan_words`; with extglob
    possibly on, an unquoted `(` joins words, so the slow path reads it all."""
    if extglob:
        return _scan_words(text, True)
    out: list[tuple[int, int, list[_Marked]]] = []
    for m in _RAW_WORD.finditer(text):
        if _EXPANSION_CHARS.search(m.group()):
            out += [(m.start() + a, m.start() + b, w)
                    for a, b, w in _scan_words(m.group(), False)]
    return out


def _scan_words(text: str,
                extglob: bool) -> list[tuple[int, int, list[_Marked]]]:
    """The EXPANDABLE shell words, as (start, end, [(char, quoted), …]) —
    `_bash_unquote`'s four states, but split at unquoted blanks and operators,
    and remembering WHICH characters were quoted, because only unquoted ones
    expand. A word with no unquoted `{ * ? [` is skipped: nothing in it expands.
    An extglob group (`@(…)`), when a `shopt` may have enabled it, becomes the
    brace group it spells (`_extglob_as_brace`). Each word is built as a text and
    a quoted-mask of string PIECES, and runs are taken whole by regex or
    `str.find`, so a long heredoc costs a few passes, not one per character."""
    plain = _PLAIN_RUN_EXTGLOB if extglob else _PLAIN_RUN
    words: list[tuple[int, int, list[_Marked]]] = []
    chars: list[str] = []
    mask: list[str] = []
    begin = 0
    i, n = 0, len(text)

    def take(piece: str, quoted: bool) -> None:
        chars.append(piece)
        mask.append(("1" if quoted else "0") * len(piece))

    def flush(end: int) -> None:
        word, quoted = "".join(chars), "".join(mask)
        if any(word[k] in "{*?[" and quoted[k] == "0"
               for k in _expandable_positions(word)):
            words.append((begin, end, [(c, q == "1") for c, q in zip(word, quoted)]))
        chars.clear()
        mask.clear()

    while i < n:
        if not chars:
            begin = i
        run = plain.match(text, i)
        if run:
            take(run.group(), False)
            i = run.end()
            continue
        ch = text[i]
        if ch == "'":
            close = text.find("'", i + 1)
            close = n if close < 0 else close
            take(text[i + 1:close], True)
            i = close + 1
        elif ch == '"':
            i = _double_quoted(text, i + 1, take)
        elif ch == "$" and i + 1 < n and text[i + 1] == "'":
            decoded, i = _decode_ansi_c(text, i + 2, n)
            take(decoded, True)
        elif ch == "\\" and i + 1 < n:
            if text[i + 1] != "\n":                      # `\<newline>` joins
                take(text[i + 1], True)
            i += 2
        elif extglob and ch in "?*+@!" and i + 1 < n and text[i + 1] == "(":
            group, i = _extglob_as_brace(text, i)
            for c, q in group:
                take(c, q)
        elif ch in _WORD_BREAK:
            if chars:
                flush(i)
            i += 1
        else:
            take(ch, False)
            i += 1
    if chars:
        flush(n)
    return words


def _expandable_positions(word: str) -> list[int]:
    return [m.start() for m in _EXPANSION_CHARS.finditer(word)]


def _double_quoted(text: str, i: int,
                   take: Callable[[str, bool], None]) -> int:
    """Take a `"…"` body starting at `text[i]`; return the index after it.
    `\\` escapes only `"` `\\` `$` `` ` `` and a newline (a continuation)."""
    n = len(text)
    while i < n:
        run = _DOUBLE_QUOTED_RUN.match(text, i)
        if run:
            take(run.group(), True)
            i = run.end()
            continue
        if text[i] == '"':
            return i + 1
        if i + 1 < n and text[i + 1] == "\n":            # backslash-newline
            i += 2
        elif i + 1 < n and text[i + 1] in '"\\$`':
            take(text[i + 1], True)
            i += 2
        else:
            take("\\", True)
            i += 1
    return n


def _extglob_as_brace(text: str, i: int,
                      depth: int = 0) -> tuple[list[_Marked], int]:
    """`@(a|b)` at `text[i]` as the brace group `{a,b}` — its alternatives are
    WRITTEN text and must count as spelled, exactly as a brace's do. `?(…)` and
    `*(…)` may also be empty (`{,a,b}`); a repetition beyond one is not modelled.
    `!(…)` matches what it does NOT spell, so it is a plain `*`. A group nested
    in an alternative (`.@(en@(v|x)|nope)`) converts the same way, recursively;
    past `_BRACE_DEPTH_CAP` it is a plain `*`, a superset. Returns the marked
    characters and the index after the closing `)`."""
    prefix, n = text[i], len(text)
    if prefix == "!" or depth >= _BRACE_DEPTH_CAP:
        return [("*", False)], _paren_end(text, i + 1)
    pieces: list[_Marked] = [("{", False)] + ([(",", False)] if prefix in "?*"
                                              else [])
    j, plain_depth = i + 2, 0
    while j < n:
        c = text[j]
        if c in "?*+@!" and j + 1 < n and text[j + 1] == "(":
            group, j = _extglob_as_brace(text, j, depth + 1)
            pieces += group
            continue
        j += 1
        if c == ")" and plain_depth == 0:
            break
        plain_depth += {"(": 1, ")": -1}.get(c, 0)
        pieces.append((",", False) if c == "|" and plain_depth == 0 else (c, False))
    return pieces + [("}", False)], j


def _paren_end(text: str, i: int) -> int:
    """The index after the `)` matching the `(` at `text[i]` (or the end)."""
    depth = 0
    for j in range(i, len(text)):
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        if depth == 0:
            return j + 1
    return len(text)


def _brace_map(word: list[_Marked]) -> tuple[dict[int, int], dict[int, list[int]]]:
    """Matching `}` and top-level commas of every unquoted `{`, in one pass, so
    no expansion step rescans the word (an unclosed `{{{…` stays linear)."""
    close: dict[int, int] = {}
    commas: dict[int, list[int]] = {}
    stack: list[int] = []
    for k, (ch, quoted) in enumerate(word):
        if quoted:
            continue
        if ch == "{":
            stack.append(k)
            commas[k] = []
        elif ch == "}" and stack:
            close[stack.pop()] = k
        elif ch == "," and stack:
            commas[stack[-1]].append(k)
    return close, commas


def _sequence_bounds(word: list[_Marked], start: int,
                     end: int) -> tuple[int, int, int, int, bool] | None:
    """`{x..y[..step]}` as (first, last, step, zero-pad width, letters), or None.
    Integers or single letters only, unquoted, as bash requires. A body longer
    than any sequence can be is rejected before it is sliced, which keeps a run
    of nested non-groups (`{{{…}}}`) linear."""
    if end - start > _SEQUENCE_BODY_MAX:
        return None
    body = word[start + 1:end]
    if any(quoted for _, quoted in body):
        return None
    m = _SEQUENCE.fullmatch("".join(c for c, _ in body))
    if not m:
        return None
    if m.group(1) is not None:
        a, b, s = m.group(1), m.group(2), m.group(3)
        padded = any(x.lstrip("-").startswith("0") and len(x.lstrip("-")) > 1
                     for x in (a, b))
        width = max(len(a), len(b)) if padded else 0
        return int(a), int(b), abs(int(s or 1)) or 1, width, False
    return ord(m.group(4)), ord(m.group(5)), abs(int(m.group(6) or 1)) or 1, 0, True


def _sequence_items(bounds: tuple[int, int, int, int, bool]) -> list[str]:
    first, last, step, width, letters = bounds
    stride = step if last >= first else -step
    values = range(first, last + (1 if stride > 0 else -1), stride)
    if letters:
        return [chr(v) for v in values]
    return [f"{v:0{width}d}" if width else str(v) for v in values]


def _sequence_count(bounds: tuple[int, int, int, int, bool]) -> int:
    first, last, step, _width, _letters = bounds
    return abs(last - first) // step + 1


def _brace_expand(word: list[_Marked], lo: int, hi: int,
                  maps: tuple[dict[int, int], dict[int, list[int]]],
                  depth: int) -> list[list[_Marked]] | None:
    """Every word `word[lo:hi]` brace-expands to, left to right as bash does, or
    None when that would pass the cap. A `{` that is not a group (no top-level
    comma, not a sequence) stays literal and the scan moves on, so `{a{b,c}}`
    gives `{ab}` `{ac}` like bash. `${…}` is a parameter, never a group."""
    close, commas = maps
    out: list[list[_Marked]] = [[]]
    run = k = lo
    while k < hi:
        ch, quoted = word[k]
        end = close.get(k) if ch == "{" and not quoted else None
        if end is None or end >= hi:
            k += 1
            continue
        if k > lo and word[k - 1] == ("$", False):
            k = end + 1
            continue
        alternatives = _group_alternatives(word, k, end, maps, depth)
        if alternatives == []:
            k += 1                                        # not a group: literal
            continue
        if alternatives is None or len(out) * len(alternatives) > _BRACE_CAP:
            return None
        literal = word[run:k]
        out = [o + literal + a for o in out for a in alternatives]
        if sum(len(o) for o in out) > _BRACE_CHAR_CAP:
            return None
        k = run = end + 1
    tail = word[run:hi]
    return [o + tail for o in out]


def _group_alternatives(word: list[_Marked], start: int, end: int,
                        maps: tuple[dict[int, int], dict[int, list[int]]],
                        depth: int) -> list[list[_Marked]] | None:
    """The words one `{…}` group yields; [] when it is not a group, None when
    it passes a cap."""
    commas = maps[1][start]
    if not commas:
        bounds = _sequence_bounds(word, start, end)
        if bounds is None:
            return []
        if _sequence_count(bounds) > _BRACE_CAP:
            return None
        return [[(c, False) for c in item] for item in _sequence_items(bounds)]
    if depth >= _BRACE_DEPTH_CAP:
        return None
    alternatives: list[list[_Marked]] = []
    edges = [start, *commas, end]
    for a, b in zip(edges, edges[1:]):
        sub = _brace_expand(word, a + 1, b, maps, depth + 1)
        if sub is None or len(alternatives) + len(sub) > _BRACE_CAP:
            return None
        alternatives += sub
    return alternatives


def _brace_superset(word: list[_Marked],
                    maps: tuple[dict[int, int], dict[int, list[int]]]
                    ) -> dict[int, tuple[int, _GlobToken]]:
    """For an over-cap word: each OUTERMOST group -> one wildcard over the
    characters it could produce. Every expansion of the group is a string over
    that set, so every word bash would produce is matched by the result — a
    credential spelled anywhere inside still yields a witness. Its cost is only
    over-matching, and it knows an integer range spells digits and `-` alone."""
    close, commas = maps
    groups: dict[int, tuple[int, _GlobToken]] = {}
    k = 0
    while k < len(word):
        end = close.get(k) if word[k] == ("{", False) else None
        if end is None or (k and word[k - 1] == ("$", False)):
            k = end + 1 if end is not None else k + 1
            continue
        bounds = None if commas[k] else _sequence_bounds(word, k, end)
        if not commas[k] and bounds is None:
            k += 1
            continue
        if bounds is not None:
            first, last, _step, _width, letters = bounds
            chars = ({chr(v) for v in range(min(first, last), max(first, last) + 1)}
                     if letters else set("0123456789-"))
            globbing = False
        else:
            body = word[k + 1:end]
            chars = {c for c, _ in body}
            globbing = any(c in "*?[" and not q for c, q in body)
        pred = _folded(lambda c, cs=frozenset(chars), g=globbing: g or c in cs)
        raw = "".join(c for c, _ in word[k:end + 1])
        # SPECIFIC: its alternatives are text the author wrote out, so a name
        # spelled across them (`.{e,x}{n,y}{v,z}…`) still counts as spelled.
        groups[k] = (end, _GlobToken("star", raw, pred, True, "/" in chars,
                                     specific=True))
        k = end + 1
    return groups


def _bracket(word: list[_Marked], k: int,
             limit: int) -> tuple[_GlobToken, int]:
    """A bash `[...]` starting at `word[k]`: (token, index after it). Unclosed
    in the word -> a literal `[`; unclosed within `limit` -> any one char."""
    j = k + 1
    negate = j < len(word) and word[j][0] in "!^" and not word[j][1]
    j += negate
    singles: set[str] = set()
    ranges: list[tuple[str, str]] = []
    classes: list[Callable[[str], bool]] = []
    first = True
    while j < len(word) and j - k <= limit:
        ch, quoted = word[j]
        if ch == "]" and not quoted and not first:
            members = (lambda c, s=frozenset(singles), r=tuple(ranges),
                       cl=tuple(classes): c in s or any(a <= c <= b for a, b in r)
                       or any(f(c) for f in cl))
            pred = (lambda c, m=members: not m(c)) if negate else members
            raw = "".join(c for c, _ in word[k:j + 1])
            return _GlobToken("one", raw, _folded(pred)), j + 1
        first = False
        if ch == "[" and not quoted and j + 1 < len(word) and word[j + 1][0] == ":":
            tail = "".join(c for c, _ in word[j + 2:j + 12])
            name = tail.split(":]", 1)[0]
            if ":]" in tail:
                classes.append(_POSIX_CLASSES.get(name, _any_but_slash))
                j += len(name) + 4
                continue
        if (j + 2 < len(word) and word[j + 1] == ("-", False)
                and word[j + 2][0] != "]"):
            ranges.append((ch, word[j + 2][0]))
            j += 3
            continue
        singles.add(ch)
        j += 1
    if j >= len(word):
        return _lit("["), k + 1
    return _GlobToken("one", "[", _any_but_slash), k + 1


def _glob_tokens(word: list[_Marked], lenient: bool,
                 groups: dict[int, tuple[int, _GlobToken]] | None = None
                 ) -> list[_GlobToken]:
    tokens: list[_GlobToken] = []
    # Bracket scanning shares ONE budget per word, so a run of `[` that never
    # closes costs linear time; once spent, a `[` is taken as any one character.
    budget = 4 * len(word) + _BRACKET_SCAN_CAP
    k = 0
    while k < len(word):
        if groups and k in groups:
            end, token = groups[k]
            tokens.append(token)
            k = end + 1
            continue
        ch, quoted = word[k]
        if quoted or ch not in "*?[":
            tokens.append(_lit(ch))
            k += 1
        elif ch == "*":
            run = k
            while k < len(word) and word[k] == ("*", False):
                k += 1
            # globstar `**` spans directories; widened only when a shopt may be on
            tokens.append(_GlobToken("star", "*" * (k - run), _any_but_slash,
                                     lenient, lenient and k - run > 1))
        elif ch == "?":
            tokens.append(_GlobToken("one", "?", _any_but_slash, lenient))
            k += 1
        else:
            start = k
            token, k = _bracket(word, k, min(_BRACKET_SCAN_CAP, budget))
            budget -= _BRACKET_SCAN_CAP if token.raw == "[" else k - start
            tokens.append(dataclasses.replace(token, dot_ok=lenient)
                          if token.kind != "lit" else token)
    return tokens


def _segments(tokens: list[_GlobToken]) -> list[list[_GlobToken]]:
    """Split at literal `/`. A wildcard that may produce `/` (superset or
    globstar) becomes `*/*/*`: any middle segment, and both edges, stay open —
    a superset for every credential shape, none of which spans three segments."""
    segments: list[list[_GlobToken]] = [[]]
    for token in tokens:
        if token.kind == "lit" and token.raw == "/":
            segments.append([])
        elif token.crosses:
            open_star = dataclasses.replace(token, crosses=False, dot_ok=True)
            segments[-1].append(open_star)
            segments += [[open_star], [open_star]]
        else:
            segments[-1].append(token)
    return segments


def _pick(p: _GlobToken, q: _GlobToken, leading_dot_rule: bool) -> str | None:
    """A character both positions accept — or None."""
    if p.kind == "lit":
        candidates: tuple[str, ...] | str = p.raw
    elif q.kind == "lit":
        candidates = (q.raw, q.raw.upper(), q.raw.lower())
    else:
        candidates = _WITNESS_ALPHABET
    for c in candidates:
        if c == "/" or (leading_dot_rule and c == "." and not (
                p.kind == "lit" or p.dot_ok)):
            continue
        if p.accepts(c) and q.accepts(c):
            return c
    return None


def _intersect(pattern: list[_GlobToken], shape: tuple[_GlobToken, ...],
               need: int) -> str | None:
    """One name matched by BOTH the pattern segment and the shape, in which the
    pattern SPELLS at least `need` of the shape's fixed characters — or None.

    ⚠ "SPELLS", BECAUSE A BARE WILDCARD CANNOT DISCRIMINATE. `*` could match
    `id_rsa` and `x.pem`, and so could every `rm -rf build/*` — which would then
    read as deleting a credential. A match counts only when the pattern's
    WRITTEN characters (literals, brace alternatives; not `*`, `?`, `[...]`)
    supply at least half of the name's fixed ones: `.en?`, `.e*v`, `.a?s`,
    `server.pe?` do; `*` and `.*` do not. Those read-everything globs are a
    separate, non-discriminating problem (docs/89), not a spelling of a name.

    Breadth-first over (pattern position, shape position, at-start, spelled so
    far, capped at `need`) — which character is chosen never changes a later
    state, so this finds a witness whenever one exists, with no recursion. The
    leading-`.` rule applies to the pattern only.
    """
    goal = (len(pattern), len(shape), need)
    start = (0, 0, True, 0)
    parent: dict[tuple[int, int, bool, int],
                 tuple[tuple[int, int, bool, int], str] | None]
    parent = {start: None}
    queue = [start]
    for state in queue:
        i, j, leading, spelled = state
        if (i, j, spelled) == goal:
            return _backtrace(parent, state)
        p = pattern[i] if i < len(pattern) else None
        q = shape[j] if j < len(shape) else None
        moves: list[tuple[tuple[int, int, bool, int], str]] = []
        if p is not None and p.kind == "star":
            moves.append(((i + 1, j, leading, spelled), ""))
        if q is not None and q.kind == "star":
            moves.append(((i, j + 1, leading, spelled), ""))
        if p is not None and q is not None:
            c = _pick(p, q, leading)
            if c is not None:
                gained = min(need, spelled + (q.kind == "lit" and p.specific))
                moves.append(((i if p.kind == "star" else i + 1,
                               j if q.kind == "star" else j + 1, False, gained),
                              c))
        for nxt, c in moves:
            if nxt not in parent:
                parent[nxt] = (state, c)
                queue.append(nxt)
    return None


def _backtrace(parent: dict, state: tuple) -> str:
    """The witness `_intersect` reached `state` by, read back along `parent`."""
    out: list[str] = []
    step = parent[state]
    while step is not None:
        state, c = step
        out.append(c)
        step = parent[state]
    return "".join(reversed(out))


# Every credential name with no free part, and the anchors of those with one.
_FIXED_CREDENTIAL_NAMES = (
    ".env", "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", ".npmrc", ".netrc",
    ".pgpass", ".git-credentials", ".ssh", ".aws", ".kube", ".docker",
    "config.json")
_PINNED_PREFIXES = (".env.", "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa")
_PINNED_SUFFIXES = (".pem", ".p12", ".pfx")


def _matches(segment: list[_GlobToken], name: str) -> bool:
    """Does the pattern segment match `name` exactly, as bash would (a leading
    `.` only by a literal)? A set-of-positions walk: O(len(name) * len(segment))."""
    def closure(states: set[int]) -> set[int]:
        out, stack = set(states), list(states)
        while stack:
            i = stack.pop()
            if i < len(segment) and segment[i].kind == "star" and i + 1 not in out:
                out.add(i + 1)
                stack.append(i + 1)
        return out

    states = closure({0})
    for pos, c in enumerate(name):
        nxt: set[int] = set()
        for i in states:
            token = segment[i] if i < len(segment) else None
            if token is None or not token.accepts(c) or (
                    pos == 0 and c == "." and not (token.kind == "lit"
                                                   or token.dot_ok)):
                continue
            nxt.add(i if token.kind == "star" else i + 1)
        states = closure(nxt)
        if not states:
            return False
    return len(segment) in states


def _read_names(segment: list[_GlobToken]) -> list[str]:
    """For MARKING only: the credential names this segment matches however
    little of them it spells — the fixed names it matches exactly, and a
    free-part name whose every wildcard the anchor pins (`cert???m` ->
    `cert.pem`). Each is only a CANDIDATE: `mark_sources` reads it through the
    World exactly as it reads the plain spelling, so a name that is not on disk
    marks nothing. That existence check is what tells `??????` reading `id_rsa`
    from `??????` reading `README` — text alone cannot (docs/89)."""
    fixed = sum(t.kind != "star" for t in segment)
    starred = fixed != len(segment)
    names = [n for n in _FIXED_CREDENTIAL_NAMES
             if (fixed <= len(n) if starred else fixed == len(n))
             and _matches(segment, n)]
    if starred:
        return names
    for anchor, at_end in ([(a, False) for a in _PINNED_PREFIXES]
                           + [(a, True) for a in _PINNED_SUFFIXES]):
        if len(anchor) > len(segment):
            continue
        chars = [t.raw if t.kind == "lit" else "" for t in segment]
        offset = len(segment) - len(anchor) if at_end else 0
        for k, a in enumerate(anchor):
            chars[offset + k] = chars[offset + k] or a
        name = "".join(chars)
        # every position filled, and the anchor really there (a literal may
        # disagree with it — `_matches` alone would accept `.env.locam`)
        if (len(name) == len(segment)
                and name[offset:offset + len(anchor)].lower() == anchor
                and _matches(segment, name)):
            names.append(name)
    return names


def _glob_witnesses(tokens: list[_GlobToken], reads: bool = False) -> list[str]:
    """Credential paths this glob could name: each wild segment in turn takes
    each name it could match (and the next segment too, for the two-segment
    `.docker/config.json`), the rest stay as written, and only an assembly that
    `CREDENTIAL_PATHS` accepts is returned. `reads` adds `_read_names`."""
    segments = _segments(tokens)
    raws = ["".join(t.raw for t in s) for s in segments]
    options: list[list[str]] = []
    for segment in segments:
        fixed = sum(t.kind != "star" for t in segment)
        if all(t.kind == "lit" for t in segment) or fixed > _NAME_MAX:
            options.append([])
            continue
        # SOUND PREFILTER: every spelled character is a written literal meeting
        # one of the shape's, so fewer such literals than `need` cannot reach
        # it. A written brace wildcard may supply any number, and disables it.
        literals = [t.raw.lower() for t in segment if t.kind == "lit"]
        unbounded = any(t.specific and t.kind == "star" for t in segment)
        names = (_intersect(segment, shape.tokens, shape.need)
                 for shape in _CREDENTIAL_NAME_SHAPES
                 if unbounded or sum(c in shape.chars for c in literals)
                 >= shape.need)
        spelled = [n for n in names if n]
        options.append(list(dict.fromkeys(
            spelled + (_read_names(segment) if reads else []))))
    found: list[str] = []
    for k, names in enumerate(options):
        for name in names:
            base = raws[:k] + [name] + raws[k + 1:]
            tries = [base] + [base[:k + 1] + [nxt] + base[k + 2:]
                              for nxt in (options[k + 1] if k + 1 < len(options)
                                          else [])]
            for parts in tries:
                path = "/".join(parts)
                if CREDENTIAL_PATHS.search(path) and path not in found:
                    found.append(path)
    return found


def _word_expansions(word: list[_Marked], lenient: bool, reads: bool = False,
                     witnesses: Callable[[list[_GlobToken]], list[str]] | None = None
                     ) -> list[str]:
    """What one shell word can become: its brace expansions, with each glob
    among them replaced by the names it could match — credential paths by
    default, or whatever `witnesses` names (row f passes the catastrophic
    roots). ONE expander, so the cap rule and bash semantics are shared."""
    witness = witnesses or (lambda tokens: _glob_witnesses(tokens, reads))
    maps = _brace_map(word)
    expanded = _brace_expand(word, 0, len(word), maps, 0) if maps[0] else [word]

    def globbing(w: list[_Marked]) -> bool:
        return any(c in "*?[" and not q for c, q in w)

    if expanded is None or sum(map(globbing, expanded)) > _GLOB_EXPANSIONS_CAP:
        return witness(_glob_tokens(word, lenient, _brace_superset(word, maps)))
    forms: list[str] = []
    for w in expanded:
        if globbing(w):
            forms += witness(_glob_tokens(w, lenient))
        else:
            forms.append("".join(c for c, _ in w))
    return forms


class _Expansion(NamedTuple):
    text: str               # the command, expandable words rewritten; "" if none
    positional: bool        # must the cd-resolving pass read `text` too?
    forms: tuple[str, ...] = ()     # every word the rewriting put in


def _near_credential(form: str) -> bool:
    """Is this expanded word a credential path, or one segment away from one on
    either side (`.aws` -> `.aws/…`, `config.json` under `.docker/`)?"""
    return any(CREDENTIAL_PATHS.search(p) for p in
               (form, form + "/config.json", ".docker/" + form))


def _expanded_form(command: str, reads: bool = False) -> _Expansion:
    """The command with each brace- or glob-expandable word REWRITTEN IN PLACE to
    what bash could expand it to. In place, not as a word list, so the positional
    pass (`_cd_resolved_credential_paths`: `cd .{aws,x} && cat credentials`) reads
    it exactly as it reads the plain spelling. A glob that can name no credential
    is left as written. Recognition only.

    ⚠ THE POSITIONAL PASS IS QUADRATIC IN COMMAND LENGTH (229 ms on the longest
    recorded command, on main), so it re-reads the expanded text only when some
    expanded word is near a credential (`_near_credential`) — the only way that
    pass can find something on the expanded text that it did not find on the raw
    one, which already resolves every token under a credential directory.
    `reads` (marking only) adds `_read_names`; those never set `positional` —
    they are fixed names resolved against the cwd, read by the direct pass in
    `_paths_mentioned_in` — so a heredoc full of `*` does not re-run it."""
    lenient = bool(_SHOPT_WIDENS_GLOB.search(command))
    if not lenient and not _EXPANSION_CHARS.search(command):
        return _Expansion("", False)    # an extglob `@(…)` holds none of these
    pieces: list[str] = []
    every: list[str] = []
    positional = False
    last = 0
    for start, end, word in _marked_words(command, lenient):
        forms = _word_expansions(word, lenient)
        extra = ([f for f in _word_expansions(word, lenient, True)
                  if f not in forms] if reads else [])
        if forms or extra:
            pieces += [command[last:start], " ".join(forms + extra)]
            positional = positional or any(map(_near_credential, forms))
            every += forms + extra
            last = end
    if not pieces:
        return _Expansion("", False)
    return _Expansion("".join(pieces) + command[last:], positional, tuple(every))


def _credential_scan_texts(command: str,
                           expansion: _Expansion | None = None) -> tuple[str, ...]:
    """The texts a credential-path scan reads: as WRITTEN, as bash UNQUOTES it,
    and as bash EXPANDS its braces and globs. Unioned by the caller, so each
    later form can only add a recognition to the ones before it."""
    expanded = (expansion or _expanded_form(command)).text
    base = (command, _bash_unquote(command))
    return (*base, expanded) if expanded else base
