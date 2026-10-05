"""A command that can print environment variables whose NAME looks secret.

Item B of fix/agents-block-and-env-reads (docs/110 §B).

⚠ THE ENVIRONMENT WAS THE ONE CREDENTIAL SOURCE WITH NO PATH. `cat .env` marks
the session and fingerprints the file's values (`sources.mark_sources`); `env`,
`printenv GITHUB_TOKEN`, `set`, `export -p`, `declare -x`, `/proc/self/environ`,
PowerShell's `gci env:` and cmd's `set` printed the same kind of value into the
session, and it never knew. Only `env | curl …` in ONE command was caught
(`credentials.sends_the_environment`), because that is a sink.

Now such a command marks the session exactly as reading a secret file does, and
the values of the variables whose NAME looks secret are fingerprinted from the
hook's own view of the environment (`World.environment`), so provenance follows
the exact values to any later exit.

WHAT COUNTS

    a full dump      `env`, `printenv`, `set`, `export`/`export -p`,
                     `declare`/`typeset` with no names (not `-f`/`-F`),
                     `/proc/<pid>/environ`, `gci env:`/`dir env:`/`ls env:`,
                     `[Environment]::GetEnvironmentVariables()`, cmd's `set`;
                     also when piped (`env | sort`)
    ⚠ except         a dump piped straight into grep with ONE literal pattern
                     that names no secret-looking variable (`env | grep PATH`):
                     the pattern does not look secret itself, and no
                     secret-looking variable in the hook's view has it in its
                     line. `-v`, context options, a file operand or a regex
                     pattern keep the dump counting.
    a named read     `printenv NAME`, `echo`/`printf` of `$NAME`,
                     `declare -p NAME`, PowerShell's `$env:NAME` where it is
                     written out (a statement of its own, or an argument of
                     `echo`/`Write-Output`/`Write-Host`…), `gci env:NAME`,
                     `[Environment]::GetEnvironmentVariable('NAME')`, cmd's
                     `echo %NAME%` and `set PREFIX` — ONLY when the name looks
                     secret (`printenv HOME` counts for nothing)

WHERE: a POSIX verb only at a command position the scanner reads as code
(`code_mask`, and each `sh -c '…'` body as its own command), so a commit message,
a heredoc body or an `echo 'printenv'` prints nothing. PowerShell and cmd forms
are read from `executed_text` (heredoc bodies and commit messages removed),
because their bodies are usually quoted inside `powershell -Command "…"`.

⚠ STATED LIMITS, not guessed at:
  * an interpreter one-liner (`python -c 'print(os.environ)'`, `node -e …`) is
    not read — its body is another language (the same line docs/57 drew);
  * the hook sees the environment its agent started it with, not variables
    the agent exported in its own shell since; those dumps still MARK, with
    no value to fingerprint (`path_policy` / `unread`);
  * a value below the fingerprint floor (`credentials.fingerprint_values`: 12
    characters, some entropy, or a vendor format) marks and is not traced —
    the same gap a credential file has;
  * a verb is found at a command position, behind `sudo`-like prefixes and
    their options — one that takes a value too (`nice -n 5 env`, `sudo -u root
    printenv`, docs/113 §3d) — `xargs`, the reserved words that run a command
    (`then`, `do`, `else`, `!`, …) and `NAME=value` assignments; not behind
    another program that runs it (`env X=1 printenv`, `timeout 5 env`), a
    value that is itself a prefix word or an assignment, or an assignment whose
    value holds a space or a backtick.

Every function here is linear in the command: each verb reads its own level up
to the next verb on it, the verb pattern's assignments and options stop at the
next command position, and the grep, `echo` and `$env:` checks read their own
segment, never the whole text again (tests/test_env_reads_are_linear.py).
"""
from __future__ import annotations

import bisect
import re
from collections.abc import Mapping
from dataclasses import dataclass

from core.command_text import _SEGMENT_END, executed_text
from core.credentials import fingerprint_values
from core.shell_scan import code_mask, shell_bodies

DUMP_LABEL = "the environment"
"""How a full dump is named where a reason names a read."""

# ═══════════════════════════════════════════════ which NAMES look secret
#
# The item's words, plus the two credential kinds the known-format table names
# that none of them covers: a personal access token (`github-fine-grained-pat`,
# `docker-pat` — `GH_PAT`) and a webhook URL (`slack-webhook-url`,
# `discord-webhook-url`). `PASSWD` and `PASSPHRASE` are the same kind as
# `PASSWORD`.
_SUBSTRING_WORDS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE",
                    "CREDENTIAL", "PRIVATE", "WEBHOOK")
_AUTH = re.compile(r"AUTH(?!OR(?!IZ))")
_WHOLE_WORDS = ("PAT",)   # a whole word of a LONGER name: not `PATH`, `PATCH` or `PAT`
_PART = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def looks_secret(name: str) -> bool:
    """Does an environment variable's NAME say it holds a secret?

    Read word by word, split on `_`/`-`/`.` and on camelCase, so `GitHubToken`
    and `OPENAI_APIKEY` count and `GIT_AUTHOR_NAME`, `XAUTHORITY` and `MANPATH`
    do not: `AUTH` counts inside a word only where the word is not `AUTHOR…`."""
    if not name:
        return False
    for chunk in re.split(r"[^A-Za-z0-9]+", name):
        for word in _PART.findall(chunk) or ([chunk] if chunk else []):
            upper = word.upper()
            if any(w in upper for w in _SUBSTRING_WORDS):
                return True
            # AUTH, not AUTHOR (`GIT_AUTHOR_NAME`, `XAUTHORITY`) — but
            # AUTHORIZATION is AUTH (the review).
            if _AUTH.search(upper):
                return True
            # PAT only inside a longer name (`GH_PAT`, `AZURE_DEVOPS_PAT`): a
            # variable named just `PAT` as often holds a pattern.
            if upper in _WHOLE_WORDS and name.upper() != upper:
                return True
    return False


# ═══════════════════════════════════════════════ what a command reads

@dataclass(frozen=True)
class EnvRead:
    """What one command can print: the whole environment, and/or these
    secret-looking variables by name."""

    dump: bool
    names: tuple[str, ...]


_MAX_NAMES = 64
"""More secret-looking names than this in ONE command is read as a dump: every
secret-named value in view, one mark (the review's HIGH: each name used to be
looked up in a list, and marked one by one)."""


class _Found:
    def __init__(self) -> None:
        self.dump = False
        self.names: list[str] = []
        self._seen: set[str] = set()
        self._plain: set[str] = set()         # names already found not to look secret

    def name(self, name: str | None) -> None:
        if not name or name in self._seen or name in self._plain:
            return
        if not looks_secret(name):
            self._plain.add(name)
            return
        self._seen.add(name)
        if len(self.names) >= _MAX_NAMES:
            self.dump = True
            return
        self.names.append(name)

    def result(self) -> EnvRead | None:
        # over the limit, read as the dump it amounts to
        names = () if len(self._seen) > _MAX_NAMES else tuple(self.names)
        if not self.dump and not names:
            return None
        return EnvRead(self.dump, names)


# A command position: the text's start, after a separator, `(`, `{` (not the
# `{` of a `${…}` expansion) or a backtick, or after cmd's `/c` and a
# `-c`/`-Command` word (a whole word: `--command` and `x-command` start
# nothing, or a chain through them ran to the end from each) — then `sudo`/`command`/`exec`/…, `xargs`, a reserved word
# that runs the next command (`then`, `do`, `!`, …), and `NAME=value`
# assignments, all of which leave the verb the verb. A `case` arm's command
# follows a `)` that closes nothing: `_read_posix` tries those itself.
_AT_START = (r"(?:^|(?<=[;&|\n({`])(?<!\$\{)(?<!>\|)(?<![<>]&)|(?<=\s/[cCkK] )"
             r"|(?<=\s-[cC] )|(?i:(?<=\s-command )|(?<=^-command )))")
# One piece of an assignment's value or an option: a character that neither
# starts a command (`;`, `&`, `|`, `(`, `{`, a backtick) nor closes one, or a
# whole `$(…)` / `${…}` of its own. Tried from every command position, `\S*`
# ran to the end of the text from each (the second round's HIGH); this stops
# at the next one. A value with a backtick or a space in it hides the verb.
# The words are joined by blanks, never a newline (a separator, so a command
# position of its own), and an option is never `-c`/`-command`, after which a
# command position starts too (the third round: from each of those, the
# chain ran on to the end of the text).
_PIECE = r"(?:[^\s;&|(){}`<>]|\$\([^\s()]*\)|\$\{[^\s{}]*\})"
_OPTION = r"-(?!(?i:c|command)[ \t])" + _PIECE + r"+"
# ⚠ AN OPTION MAY TAKE A VALUE WORD (docs/113 §3d): `nice -n 5 env`, `sudo -u
# root printenv` were read as the verb `5`, `root`, and missed. The value is
# optional, so a flag that takes none (`sudo -E env`) reads as before; whichever
# reading finds a verb is read — the stricter one.
# ⚠ AND IT IS NEVER AN OPTION, A PREFIX WORD OR AN ASSIGNMENT. With a prefix
# word allowed, `sudo --command sudo --command …` had two readings per word,
# value or next prefix, and a text with no verb tried every one of them: 1 KB
# did not finish in 20 s. Each word now has one reading.
_PREFIX_WORDS = (r"(?:sudo|command|builtin|exec|nohup|time|nice|doas|xargs"
                 r"|if|then|do|else|elif|while|until|!)")
_OPTION_VALUE = (r"(?:[ \t]+(?!-|" + _PREFIX_WORDS + r"[ \t]|[A-Za-z_]\w*=)"
                 + _PIECE + r"+)?")
_PREFIXES = (r"(?:" + _PREFIX_WORDS + r"[ \t]+(?:" + _OPTION + _OPTION_VALUE
             + r"[ \t]+)*)*")
_ASSIGNMENTS = r"(?:[A-Za-z_]\w*=" + _PIECE + r"*[ \t]+)*"
_VERB_HERE = re.compile(r"[ \t]*" + _PREFIXES + _ASSIGNMENTS
                        + r"(?:/usr/local/bin/|/usr/bin/|/bin/|\\)?"
                        r"(?P<verb>env|printenv|set|export|declare|typeset|echo|printf)"
                        r"(?=$|[ \t;&|)<>\n`])")
_VERB = re.compile(_AT_START + _VERB_HERE.pattern)
_CASE = re.compile(r"(?<![\w-])case\s")
_TOKEN = re.compile(r"(?:[^\s\"'`]|\"[^\"]*\"|'[^']*')+")
_REDIRECT = re.compile(r"^(?:\d*|&)(?:>>?|<|>\||<<<?|>&|<&)")
_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_DOLLAR_NAME = re.compile(r"\$(?:\{(?P<b>[A-Za-z_]\w*)|(?P<n>[A-Za-z_]\w*))")
_GREP = re.compile(r"^(?:/usr/bin/|/bin/)?(?:grep|egrep|fgrep)$")
_GREP_FLAGS = frozenset("iwxFEGncqsHh")
_GREP_LONG = frozenset({"--ignore-case", "--word-regexp", "--line-regexp",
                        "--fixed-strings", "--extended-regexp", "--basic-regexp",
                        "--line-number", "--count", "--quiet", "--silent",
                        "--no-messages", "--with-filename", "--no-filename",
                        "--color", "--colour"})
_LITERAL = re.compile(r"^\^?[A-Za-z0-9_]+=?$")


def _unquote(token: str) -> str:
    return token.replace('"', "").replace("'", "")


def _ansi_end(text: str, at: int) -> int:
    """Where a `$'…'` string whose body starts at `at` ends: inside it a
    backslash escapes the next character, a quote included."""
    n = len(text)
    while at < n:
        if text[at] == "\\":
            at += 2
        elif text[at] == "'":
            return at + 1
        else:
            at += 1
    return n


def _separates(text: str, i: int) -> bool:
    """Is the `;`, `&`, `|` or newline at `i` a separator? `>|` and `>&`, `<&`,
    `&>` are redirects (`command_text._SEGMENT_END`)."""
    c, before = text[i], text[i - 1] if i else ""
    if c == "|":
        return before != ">"
    if c == "&":
        return before not in ("<", ">") and not text.startswith(">", i + 1)
    return True


class _Structure:
    """Where a command nests, found in ONE pass (the review's HIGH: a verb
    opened by `(`, `{` or `$(` used to re-read to the end of its segment, so a
    run of `(echo …` was quadratic).

    `opens` are the positions of `$(`, `(`, `{` and backticks outside single
    quotes (`$(` and backticks inside double quotes too), each with its close
    in `close_of` (the end of the text when unclosed); `closes` every `)`, `}`
    and backtick that closes one (`ticks_closing` the backticks among them);
    `unmatched` every `)` that closes nothing, a `case` pattern's end; `seps`
    the segment separators outside quotes. A `${…}` parameter expansion is not
    a block, and a `$'…'` string is read with its escapes. Each verb then
    reads only its own level: it jumps over the blocks inside its segment.
    """

    def __init__(self, text: str) -> None:
        self.n = len(text)
        self.seps: list[int] = []
        self.opens: list[int] = []
        self.close_of: dict[int, int] = {}
        self.closes: list[int] = []
        self.ticks_closing: set[int] = set()
        self.unmatched: list[int] = []
        frames: list[tuple[str, int, str | None]] = []   # (opener, at, quote outside)
        quote: str | None = None
        i, n = 0, self.n
        while i < n:
            c = text[i]
            if quote == "'":
                quote = None if c == "'" else quote
                i += 1
                continue
            if c == "\\":
                i += 2
                continue
            if c == "$" and quote is None and text.startswith("'", i + 1):
                i = _ansi_end(text, i + 2)
                continue
            if c == "$" and text.startswith("{", i + 1):
                end = text.find("}", i + 2)                 # an expansion, not a group
                i = n if end < 0 else end + 1
                continue
            if c == "$" and text.startswith("(", i + 1):
                self.opens.append(i)
                frames.append(("(", i, quote))
                quote = None
                i += 2
                continue
            if c == "`":
                if frames and frames[-1][0] == "`":
                    _, at, quote = frames.pop()
                    self.close_of[at] = i
                    self.closes.append(i)
                    self.ticks_closing.add(i)
                else:
                    self.opens.append(i)
                    frames.append(("`", i, quote))
                    quote = None
                i += 1
                continue
            if quote == '"':
                quote = None if c == '"' else quote
            elif c in "'\"":
                quote = c
            elif c in "({":
                self.opens.append(i)
                frames.append((c, i, None))
            elif c in ")}":
                if frames and frames[-1][0] == ("(" if c == ")" else "{"):
                    _, at, quote = frames.pop()
                    self.close_of[at] = i
                    self.closes.append(i)       # an unmatched `}` is a word (`echo }`)
                elif c == ")":
                    self.unmatched.append(i)
            elif c in ";&|\n" and _separates(text, i):
                self.seps.append(i)
            i += 1
        for _, at, _outside in frames:
            self.close_of[at] = n

    def scope(self, at: int,
              verbs: list[int]) -> tuple[list[tuple[int, int]], int, bool]:
        """The stretches from `at` to the end of this command AT THIS LEVEL —
        nested blocks skipped — where it ends (a separator, a close, the end),
        and whether it ends instead where another verb on this level starts
        (`verbs`, sorted): that verb's words are its own, so every character
        is read by one verb however many share a level (the second round:
        `` `x`echo `` repeated walked every later block from each).
        O(log n) per block skipped."""
        stretches: list[tuple[int, int]] = []
        cur = at
        while cur < self.n:
            s = bisect.bisect_left(self.seps, cur)
            c = bisect.bisect_left(self.closes, cur)
            o = bisect.bisect_left(self.opens, cur)
            stop = min(self.seps[s] if s < len(self.seps) else self.n,
                       self.closes[c] if c < len(self.closes) else self.n)
            opened = self.opens[o] if o < len(self.opens) else self.n
            v = bisect.bisect_left(verbs, cur)
            if v < len(verbs) and verbs[v] < min(stop, opened):
                if verbs[v] > cur:
                    stretches.append((cur, verbs[v]))
                return stretches, verbs[v], True
            if opened < stop:
                if opened > cur:
                    stretches.append((cur, opened))
                cur = self.close_of[opened] + 1
                continue
            if stop > cur:
                stretches.append((cur, stop))
            return stretches, stop, False
        return stretches, self.n, False


def _words(text: str, stretches: list[tuple[int, int]]) -> tuple[list[str], bool]:
    """The words in these stretches, redirects removed, and whether standard
    output goes to /dev/null: the LAST stdout redirect (`>`, `>>`, `1>`, `&>`,
    `>&`; not `2>`) decides, as the shell does."""
    words: list[str] = []
    to_null = False
    pending = False                   # a stdout redirect waiting for its target
    skip_next = False
    for start, stop in stretches:
        for match in _TOKEN.finditer(text, start, stop):
            word = match.group(0)
            if skip_next:
                skip_next = False
                if pending:
                    to_null = _unquote(word) == "/dev/null"
                    pending = False
                continue
            redirect = _REDIRECT.match(word)
            if redirect:
                fd = re.match(r"&|\d*", word).group(0)
                stdout = fd in ("", "1", "&") and word[len(fd):].startswith(">")
                if redirect.end() == len(word):          # `> file`: the next word
                    skip_next, pending = True, stdout
                elif stdout:
                    to_null = _unquote(word[redirect.end():].lstrip("&")) == "/dev/null"
                continue
            words.append(word)
    return words, to_null


def _segment(text: str, at: int) -> tuple[list[str], int, bool]:
    """The words of the segment that starts at `at` (the command a dump is
    piped into), redirects removed; where it ends; whether its standard output
    goes to /dev/null. A `)`, `}` or backtick ends a subshell's words."""
    end = _SEGMENT_END.search(text, at)
    stop = end.start() if end else len(text)
    words, to_null = _words(text, [(at, stop)])
    for k, word in enumerate(words):
        if word[0] in ")}`":
            words = words[:k]
            break
    return words, stop, to_null


_NAME = re.compile(r"[A-Za-z_]\w*")


def _name_of(word: str) -> str | None:
    """An operand as a variable name: its leading identifier (`NAME)` is
    `NAME`), or None."""
    found = _NAME.match(_unquote(word))
    return found.group(0) if found else None


_QUIET_GREP = frozenset("qclL")
_QUIET_GREP_LONG = frozenset({"--quiet", "--silent", "--count",
                              "--files-with-matches", "--files-without-match"})
_GREP_TAKES = frozenset("efmABCdD")              # the rest of the word, or the next
_GREP_PRINTS = frozenset("iwxFEGnsHhvobaUzrRIPTZy")  # print lines, take nothing
_GREP_LONG_TAKES = frozenset({"--regexp", "--file", "--max-count", "--after-context",
                              "--before-context", "--context", "--devices", "--directories",
                              "--binary-files", "--label", "--include", "--exclude",
                              "--exclude-from", "--exclude-dir"})


def _grep_is_quiet(words: list[str]) -> bool:
    """Does this grep print no lines — `-q`, `-c`, `-l`, `-L` or their long
    forms? Its options are read as grep reads them (the second round): `--`
    ends them, and one that takes an argument (`-e`, `-f`, `-m`, …) takes the
    rest of its word or the next word, so `-eclean` is a pattern, not `-c`."""
    takes_next = False
    for word in map(_unquote, words[1:]):
        if takes_next:
            takes_next = False
            continue
        if word == "--":
            return False
        if word.startswith("--"):
            name, equals, _ = word.partition("=")
            if name in _QUIET_GREP_LONG:
                return True
            takes_next = name in _GREP_LONG_TAKES and not equals
            continue
        if len(word) < 2 or not word.startswith("-"):
            continue                    # an operand: GNU grep reads options after it too
        for k, letter in enumerate(word[1:], start=2):
            if letter in _QUIET_GREP:
                return True
            if letter in _GREP_TAKES:
                takes_next = k == len(word)      # nothing attached: the next word
                break
            if letter not in _GREP_PRINTS:
                break                            # not known: read no further
    return False


def _piped_into(text: str, stop: int) -> list[str] | None:
    """The words of the command a segment ending at `stop` is piped straight
    into, or None. Read once per verb, for both questions asked of it."""
    if stop >= len(text) or text[stop] != "|" or text[stop + 1:stop + 2] == "|":
        return None
    words, _, _ = _segment(text, stop + 1)
    return words or None


def _piped_quietly(words: list[str] | None) -> bool:
    """Is the command piped into (`words`) `wc` (a length) or a `grep` that
    prints no lines (a presence check)?"""
    if not words:
        return False
    if _unquote(words[0]).rsplit("/", 1)[-1] == "wc":
        return True
    return bool(_GREP.match(words[0])) and _grep_is_quiet(words)


def _env_is_a_dump(words: list[str]) -> bool:
    """`env [options] [NAME=value]…` with no command prints the environment;
    `-i`/`-` empties it first, and a command word means it RUNS something."""
    ignore = False
    i = 0
    while i < len(words):
        word = words[i]
        if word in ("-", "-i", "--ignore-environment"):
            ignore = True
        elif word in ("-u", "--unset", "-C", "--chdir"):
            i += 1
        elif word.startswith(("--unset=", "--chdir=", "--null", "--debug")):
            pass
        elif word.startswith(("-S", "--split-string")):
            return False
        elif word.startswith("-") and not word.startswith("--"):
            letters = word[1:]
            ignore = ignore or "i" in letters
            if "S" in letters:
                return False
            if letters[-1:] in ("u", "C"):
                i += 1
        elif word.startswith("--") or _ASSIGN.match(word):
            pass
        else:
            return False                                    # it runs a command
        i += 1
    return not ignore


def _names_in_output(text: str, stretches: list[tuple[int, int]], found: _Found) -> None:
    """`$NAME` and `${NAME…}` an `echo`/`printf` expands in its own stretches,
    skipping single quotes. Nested blocks are not in them: each is read by the
    verb inside it, so every character is read once."""
    in_single = in_double = False
    for start, stop in stretches:
        i = start
        while i < stop:
            char = text[i]
            if char == "'" and not in_double:
                in_single = not in_single
            elif char == '"' and not in_single:
                in_double = not in_double
            elif char == "\\" and not in_single:
                i += 2
                continue
            elif char == "$" and not (in_single or in_double) and text.startswith("'", i + 1):
                i = _ansi_end(text, i + 2)           # `$'…'`: its own escapes
                continue
            elif char == "$" and not in_single:
                match = _DOLLAR_NAME.match(text, i)
                if match:
                    # `${NAME:+x}` and `${NAME+x}` print `x` when NAME is set —
                    # a presence check, not the value (`${#NAME}` never matches).
                    presence = match.group("b") and text.startswith(
                        (":+", "+"), match.end())
                    if not presence:
                        found.name(match.group("b") or match.group("n"))
                    i = match.end()
                    continue
            i += 1


def _grep_names_nothing(words: list[str] | None, view: _View) -> bool:
    """Is the dump piped straight into `grep` (`words`, from `_piped_into`)
    with ONE literal pattern that names no secret-looking variable? Anything
    else answers no."""
    if not words or not _GREP.match(words[0]):
        return False
    pattern, ignore_case, i = None, False, 1
    while i < len(words):
        word = _unquote(words[i])
        if word in ("-e", "--regexp"):
            if pattern is not None or i + 1 >= len(words):
                return False
            pattern = _unquote(words[i + 1])
            i += 2
            continue
        if word.startswith("--"):
            if word.split("=", 1)[0] not in _GREP_LONG:
                return False
            ignore_case = ignore_case or word == "--ignore-case"
        elif word.startswith("-") and len(word) > 1:
            if not set(word[1:]) <= _GREP_FLAGS:
                return False
            ignore_case = ignore_case or "i" in word
        elif pattern is None:
            pattern = word
        else:
            return False                          # a file operand: not the dump it greps
        i += 1
    if pattern is None or not _LITERAL.match(pattern):
        return False
    core = pattern.lstrip("^").rstrip("=")
    if looks_secret(core):
        return False
    return view.names_nothing(core, ignore_case, pattern.startswith("^"))


class _View:
    """The hook's environment as one read needs it: its secret-looking part,
    taken once, and each grep pattern's and `set PREFIX`'s answer, kept (the
    third round: every dump into grep and every `set PREFIX` walked the whole
    environment, so the cost was the command's size times the view's)."""

    def __init__(self, environ: Mapping[str, str]) -> None:
        self._environ = environ
        self._secret: list[tuple[str, str]] | None = None
        self._greps: dict[tuple[str, bool, bool], bool] = {}
        self._prefixes: dict[str, list[str]] = {}

    def _secret_lines(self) -> list[tuple[str, str]]:
        if self._secret is None:
            self._secret = [(name, f"{name}={value}")
                            for name, value in self._environ.items() if looks_secret(name)]
        return self._secret

    def names_nothing(self, core: str, ignore_case: bool, anchored: bool) -> bool:
        """Does no secret-looking variable's `NAME=value` line hold `core` (at
        its start when `anchored`)?"""
        key = (core, ignore_case, anchored)
        if key not in self._greps:
            needle = core.upper() if ignore_case else core
            self._greps[key] = not any(
                (hay.startswith(needle) if anchored else needle in hay)
                for hay in ((line.upper() if ignore_case else line)
                            for _name, line in self._secret_lines()))
        return self._greps[key]

    def prefix_names(self, prefix: str) -> list[str]:
        """cmd's `set PREFIX` prints every variable whose name starts with it,
        case-insensitively; resolved against the hook's view, else the prefix."""
        upper = prefix.upper()
        if upper not in self._prefixes:
            named = [name for name, _line in self._secret_lines()
                     if name.upper().startswith(upper)]
            self._prefixes[upper] = named or [prefix]
        return self._prefixes[upper]


def _verbs(text: str) -> tuple[list[re.Match], _Structure | None]:
    """The verbs at command positions the scanner reads as code, in order, and
    where the command nests. Not after a backtick that CLOSES a block (the
    word goes on: `` `x`echo `` is one word); after a `)` that closes nothing
    (a `case` arm)."""
    mask = code_mask(text)

    def is_code(match: re.Match) -> bool:
        at = match.start("verb")
        return at < len(mask) and bool(mask[at])

    candidates = [m for m in _VERB.finditer(text) if is_code(m)]
    if not candidates and not _CASE.search(text):
        return [], None
    structure = _Structure(text)
    verbs = [m for m in candidates if m.start() - 1 not in structure.ticks_closing]
    for paren in structure.unmatched:
        match = _VERB_HERE.match(text, paren + 1)
        if match and is_code(match):
            verbs.append(match)
    return sorted(verbs, key=lambda m: m.start()), structure


def _read_posix(text: str, view: _View, found: _Found) -> None:
    """The POSIX verbs, each over its own level of the command up to the next
    verb on that level (`_Structure.scope`): linear in the text however the
    verbs nest or follow each other."""
    verbs, structure = _verbs(text)
    if structure is None:
        return
    starts = [m.start() for m in verbs]
    for match in verbs:
        verb = match.group("verb")
        stretches, stop, cut = structure.scope(match.end(), starts)
        words, to_null = _words(text, stretches)
        target = None if cut else _piped_into(text, stop)
        if to_null or _piped_quietly(target):
            continue                    # nothing it prints reaches anyone as values
        if verb in ("echo", "printf"):
            _names_in_output(text, stretches, found)
            continue
        if verb == "printenv":
            operands = [w for w in words if not w.startswith("-")]
            for word in operands:
                found.name(_name_of(word))
            dump = not operands
        elif verb == "env":
            dump = _env_is_a_dump(words)
        elif verb == "set":
            dump = not words
            if (len(words) == 1 and not words[0].startswith(("-", "+"))
                    and "=" not in words[0] and _name_of(words[0])):
                for name in view.prefix_names(_name_of(words[0])):
                    found.name(name)
        elif verb == "export":
            dump = all(w == "-p" for w in words)
            if not dump and "-p" in words:
                for word in words:
                    if not word.startswith("-") and "=" not in word:
                        found.name(_name_of(word))
        else:                                                # declare, typeset
            options = [w for w in words if w.startswith(("-", "+"))]
            operands = [w for w in words if not w.startswith(("-", "+"))]
            letters = set("".join(o[1:] for o in options))
            dump = not operands and not letters & {"f", "F"}
            if operands and "p" in letters:
                for word in operands:
                    if "=" not in word:
                        found.name(_name_of(word))
        if dump and not _grep_names_nothing(target, view):
            found.dump = True


# ═══════════════════════════════════════════ PowerShell, cmd and /proc

_PROC_ENVIRON = re.compile(r"/proc/[^/\s'\"]+/environ(?![\w.-])")
_ENV_DRIVE = re.compile(
    r"(?i)(?<![\w-])(?:get-childitem|gci|ls|dir|get-item|gi|get-content|gc|cat|type)"
    r"\s+(?:-(?:literal)?path\s+)?['\"]?env:[\\/]?(?P<name>[\w*?]*)")
_ENV_TABLE = re.compile(r"(?i)\[(?:system\.)?environment\]::getenvironmentvariables\s*\(")
_ENV_ONE = re.compile(
    r"(?i)\[(?:system\.)?environment\]::getenvironmentvariable\s*\(\s*['\"](?P<name>\w+)")
_PS_STATEMENT = re.compile(
    r"(?i)(?:^|(?<=[;|\n{(])|(?<=-command \")|(?<=-command ')|(?<=-c \")|(?<=-c '))[ \t]*"
    r"(?P<head>(?:&\s*)?(?:echo|write-output|write-host|write-information|write|"
    r"out-host|out-string|print)\b)?")
_PS_END = re.compile(r"[;|\n{(}]")
_DOLLAR = re.compile(r"\$")
_PS_VAR = re.compile(r"(?i)\$(?:\{env:(?P<b>\w+)\}|env:(?P<n>[A-Za-z_]\w*))")
# A statement of its own writes out only a variable that opens it, maybe after
# one quote (`"$env:NAME"`).
_PS_LEAD_VAR = re.compile(r"(?i)(?:\s*[\"']\s*)?" + _PS_VAR.pattern[4:])
_PS_ASSIGNED = re.compile(r"\s*[+\-*/]?=(?!=)")
# A presence or length check prints no value: `.Length`, or a comparison.
_PS_PRESENCE = re.compile(
    r"(?i)\.length\b|\s*-(?:eq|ne|gt|ge|lt|le|like|notlike|match|notmatch|is|isnot)\b")
_PS_OUTPUT_WORD = re.compile(
    r"(?i)(?:echo|write-output|write-host|write-information|write|out-host"
    r"|out-string|print)\s*$")
_PS_OUTPUT_WORD_LONGEST = len("write-information")
_CMD_PERCENT = re.compile(r"%(?P<name>[A-Za-z_]\w*)%")
_CMD_ECHO = re.compile(r"(?i)(?<![\w-])echo(?=[ \t.])")
_CMD_BREAK = re.compile(r"[&|\n]")


def _read_powershell(text: str, found: _Found) -> None:
    """`$env:NAME` where PowerShell writes it out: a statement of its own, or an
    argument of an output command. Every character is read once (the third
    round: a statement after each `-c "` searched, and read, to the end): the
    statements' ends are found in one pass; an output command reads its
    arguments only past what one before it on the same stretch already read;
    a statement of its own looks at its first word only."""
    dollars = [m.start() for m in _DOLLAR.finditer(text)]
    if not dollars:
        return                                  # no variable to write out
    ends = [m.start() for m in _PS_END.finditer(text)]
    covered = 0
    for statement in _PS_STATEMENT.finditer(text):
        k = bisect.bisect_left(ends, statement.end())
        stop = ends[k] if k < len(ends) else len(text)
        d = bisect.bisect_left(dollars, statement.end())
        if d == len(dollars) or dollars[d] >= stop:
            continue                            # nothing in this stretch to write out
        standalone = statement.group("head") is None
        at = statement.start()
        if standalone and at and text[at - 1] == "(":
            # A `(` after a word is a call's or an `if`'s argument — a check,
            # not output — unless the word is an output command. Read back a
            # bounded window, never the whole text.
            before = text[max(0, at - 81):at - 1].rstrip()
            if before and (before[-1].isalnum() or before[-1] in "_-])"):
                # the word ends where `before` does: only its tail can match
                tail = max(0, len(before) - _PS_OUTPUT_WORD_LONGEST)
                if not _PS_OUTPUT_WORD.search(before, tail):
                    continue
        if standalone:
            lead = _PS_LEAD_VAR.match(text, statement.end(), stop)
            if lead and not _ps_checked(text, lead.end()):
                found.name(lead.group("b") or lead.group("n"))
            continue
        for var in _PS_VAR.finditer(text, max(statement.end(), covered), stop):
            if not _ps_checked(text, var.end()):
                found.name(var.group("b") or var.group("n"))
        covered = max(covered, stop)


def _ps_checked(text: str, at: int) -> bool:
    """Is the variable ending at `at` assigned, or only checked (`.Length`, a
    comparison) — no value written out?"""
    return bool(_PS_ASSIGNED.match(text, at) or _PS_PRESENCE.match(text, at))


def _read_cmd_echo(text: str, found: _Found) -> None:
    """cmd's `echo … %NAME% …`: a `%NAME%` counts when an `echo` precedes it
    in the same cmd statement."""
    percents = list(_CMD_PERCENT.finditer(text))
    if not percents:
        return
    echoes = [m.start() for m in _CMD_ECHO.finditer(text)]
    breaks = [m.start() for m in _CMD_BREAK.finditer(text)]
    for match in percents:
        at = match.start()
        before = bisect.bisect_left(breaks, at)
        opened = breaks[before - 1] if before else -1
        k = bisect.bisect_right(echoes, opened)
        if k < len(echoes) and echoes[k] < at:
            found.name(match.group("name"))


def env_read(command: str | None,
             environ: Mapping[str, str] | None = None) -> EnvRead | None:
    """What `command` can print of the environment, or None."""
    if not command:
        return None
    lowered = command.lower()
    if not any(key in lowered for key in ("env", "set", "export", "declare", "typeset",
                                          "echo", "printf", "write", "print", "%", "$")):
        return None
    view = _View(environ or {})
    found = _Found()
    _read_posix(command, view, found)
    for open_, close in shell_bodies(command):
        _read_posix(command[open_ + 1:close], view, found)
    executed = executed_text(command)
    if _PROC_ENVIRON.search(executed) or _ENV_TABLE.search(executed):
        found.dump = True
    for match in _ENV_DRIVE.finditer(executed):
        name = match.group("name")
        if not name or "*" in name or "?" in name:
            found.dump = True
        else:
            found.name(name)
    for match in _ENV_ONE.finditer(executed):
        found.name(match.group("name"))
    _read_powershell(executed, found)
    _read_cmd_echo(executed, found)
    return found.result()


def reads_proc_environ(path: str) -> bool:
    """An agent's own file read of `/proc/<pid>/environ` is a full dump."""
    return bool(_PROC_ENVIRON.fullmatch(path or ""))


# ═══════════════════════════════════════════════ what the session records

def as_environment(environ) -> dict[str, str]:
    """`environ` as a str-to-str dict; anything else is no view (`{}`)."""
    if not isinstance(environ, Mapping):
        return {}
    return {k: v for k, v in environ.items() if isinstance(k, str) and isinstance(v, str)}


_MAX_VALUE = 64 * 1024


def _prints(values: Mapping[str, str]) -> list[str]:
    """Fingerprints of these values, exactly as a credential file's `NAME=value`
    lines are fingerprinted — one line of a multi-line value at a time."""
    lines = [f"{name}={line}" for name, value in values.items()
             for line in (value[:_MAX_VALUE].splitlines() or [""])]
    return sorted(fingerprint_values("\n".join(lines)))


# `NAME=value`, `export NAME=value`, `name: value`, `"name": "value"` — one line.
_NAME_VALUE = re.compile(r"""^\s*(?:export\s+)?["']?([\w.-]+)["']?\s*(?:=|:\s)\s*(.*)$""")


def unprinted_secret(values: Mapping[str, str]) -> bool:
    """Is there a secret-looking NAME here whose value is not fingerprinted —
    too short or too plain (`DB_PASSWORD=hunter2`)? fix/false-positives item 3
    (docs/112, the second review round): an MCP call after a secret read is let
    through only on fingerprints, so a value nothing fingerprinted keeps the
    ask. A name that does not look secret (`PORT=3000`) is not one."""
    return any(looks_secret(name) and value and not _prints({name: value})
               for name, value in values.items())


def unprinted_secret_in_text(content: str) -> bool:
    """`unprinted_secret` for a credential file's text, read line by line."""
    values: dict[str, str] = {}
    for line in content.splitlines():
        found = _NAME_VALUE.match(line)
        if found:
            value = found.group(2).strip().rstrip(",").strip().strip("\"'")
            if value not in ("", "{", "["):
                values[found.group(1)] = value
    return unprinted_secret(values)


def _lookup(name: str, environ: Mapping[str, str],
            by_upper: dict[str, str]) -> str | None:
    """The value, by name — case-insensitively when it is not there as
    written: Windows names are (`by_upper`, indexed once per read)."""
    if name in environ:
        return environ[name]
    return by_upper.get(name.upper())


def marks(read: EnvRead, environ: Mapping[str, str]) -> list[tuple[str, str, list[str]]]:
    """(label, how, fingerprints) for each source this read creates. `how` is
    what a credential file's read records: `content` with values, `path_policy`
    when nothing in it could be fingerprinted, `unread` when the hook cannot
    see the variable at all."""
    out: list[tuple[str, str, list[str]]] = []
    if read.dump:
        prints = _prints({n: v for n, v in environ.items() if looks_secret(n)})
        out.append((DUMP_LABEL, "content" if prints else "path_policy", prints))
    by_upper = {key.upper(): value for key, value in environ.items()} if read.names else {}
    for name in read.names:
        value = _lookup(name, environ, by_upper)
        if value is None:
            out.append((f"${name}", "unread", []))
            continue
        prints = _prints({name: value})
        out.append((f"${name}", "content" if prints else "path_policy", prints))
    return out
