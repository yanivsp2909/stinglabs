"""What does an action SEND? fix/false-positives, the maintainer's decisions of 1 Oct
(item 2) and after the fourth review round (docs/112).

Option 2 gated a push after other people's text: X-CHAIN-3's blob is a
credential split and re-encoded so nothing in it looks like one, and the read of
the poisoned issue was the only thing that caught it. The same blob can leave
by any send. Item 2 listed the ways a file is uploaded; the fourth review round
found a list of SPELLINGS cannot hold (`-d@f`, `-sT f`, `UA='curl' curl -T f`,
`eval`, `python -c`, `$F`, `sftp <<<`). So it is turned round: after other
people's text, a network send is judged as in a clean session ONLY when every
byte it sends is literal text written in the command (`sends_only_literal_text`).

    curl                   every option known, and none reads a file: not `@f`
                           (`-d`, `--data*`, `--json`, `-H`), `-T`, `-F x=@f` /
                           `x=<f`, `--data-urlencode [name]@f`, `-b f`, `-K`,
                           `--netrc`, `-E`; no `file:` URL
    wget                   every option known: not `--post-file`, `--body-file`,
                           `-i`, `-e`, `--load-cookies`, `--config`, `--certificate`
    http/https/xh/xhs      every option known: no `@f` body, no file item
                           (`f@x`, `f=@x`, `f:=@x`), no `--session`, `--cert`
    scp/rsync/sftp         a download only: every source remote, the destination here
    dig/nslookup/host      no `-f`/`-k` file
    echo, grep, ls …       send nothing (`_SENDS_NOTHING`)
    anything else          not read: nc, socat, ssh, psql, eval, an interpreter …

and in every segment that sends: no `$`, backtick or `$(…)` outside single
quotes, nothing on standard input (`<`, `<<`, `<<<`, a pipe into it), no
`/dev/tcp`, no alias. Anything else keeps today's verdict.

An MCP tool NAMED to write a remote file, push, upload or make a gist is an
upload by its name, for every agent (`uploads_a_file`): create_or_update_file,
push_files, create_gist, upload_file, put_object … — not a tool named for
reading (`list_uploads`, `get_upload_status`).

Each command is read once, a character run at a time: linear.
"""
from __future__ import annotations

import re
from collections.abc import Callable

from core.types import Action, ActionKind

_UPLOAD_TOOL = re.compile(
    r"(?i)create_or_update_file|push_files|upload|gist|put_object|put_file"
    r"|(?<![a-z])push(?![a-z])")
# A tool named for reading what it lists or fetches is not an upload.
_READ_TOOL = re.compile(r"^(?i:list|get|read|search|describe|fetch|find|query|show"
                        r"|view|check|status)(?:[_-]|(?=[A-Z])|$)")

# A word that may send: a network tool, a URL, a socket path.
_SENDER = re.compile(
    r"(?i)(?<![\w.-])(?:curl|wget|https?|xhs?|nc|ncat|netcat|socat|telnet|ftp|sftp|scp"
    r"|rsync|ssh|psql|mysql|mongo|mongosh|nslookup|dig|host)(?![\w-])"
    # ⚠ `(?<!\w)` BEFORE `\w+://` (P1, round 6): without it, on a run of n word
    # characters with no `://`, `search` tried `\w+://` from every start and
    # scanned to the run's end each time — O(n²), tens of seconds at 128 KB. A
    # match can only begin at a word start, so this forbids the mid-run starts
    # that all fail anyway; the match set is unchanged (checked below).
    r"|(?<!\w)\w+://|/dev/(?:tcp|udp)/")
_DEV_SOCKET = re.compile(r"/dev/(?:tcp|udp)/")
_FILE_URL = re.compile(r"(?i)\s*file:")
_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=")
_REMOTE = re.compile(r"(?:[\w.-]+@)?[\w.-]+:|\w+://")
# Words that open a compound command: the word after them is the verb.
_OPENERS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"})
# A run of characters that is a plain word part: read in one step.
_PLAIN = re.compile(r"[^\s'\"\\$`<>&|;()#]+")
_SEPARATORS = ";\n&|"


class _Segment:
    """One simple command: where it is, its words (None when bash would
    expand or feed anything into them), and whether a pipe feeds it."""
    __slots__ = ("start", "end", "words", "piped_in")

    def __init__(self, start: int, end: int, words: list[str] | None, piped_in: bool):
        self.start, self.end, self.words, self.piped_in = start, end, words, piped_in


def _segments(command: str) -> list[_Segment]:
    """The command's simple commands, read as bash splits them: quotes kept
    whole, a redirect's target dropped, a comment skipped. Words are None for
    a segment with a `$` or a backtick outside single quotes, a `<` (a file or
    text on standard input), or an unclosed quote."""
    out: list[_Segment] = []
    words: list[str] = []
    word: list[str] = []
    in_word = drop = unread = piped_in = False
    start, i, n = 0, 0, len(command)

    def end_word() -> None:
        nonlocal in_word, drop
        if in_word and not drop:
            words.append("".join(word))
        elif in_word:
            drop = False
        word.clear()
        in_word = False

    while i < n:
        c = command[i]
        plain = _PLAIN.match(command, i)
        if plain:
            word.append(plain.group(0))
            in_word, i = True, plain.end()
            continue
        if c == "'":
            close = command.find("'", i + 1)
            if close < 0:
                unread, close = True, n - 1
            word.append(command[i + 1:close])
            in_word, i = True, close + 1
            continue
        if c == '"':
            i, in_word = i + 1, True
            while i < n and command[i] != '"':
                if command[i] in "$`":
                    unread = True
                if command[i] == "\\" and i + 1 < n:
                    i += 1
                word.append(command[i])
                i += 1
            unread = unread or i >= n
            i += 1
            continue
        if c == "\\":
            word.append(command[i + 1:i + 2])
            in_word, i = True, i + 2
            continue
        if c in "$`<":
            unread, in_word, i = True, True, i + 1
            continue
        if c == "#":
            if in_word:                               # `a#b` is one word
                word.append(c)
                i += 1
                continue
            newline = command.find("\n", i)
            i = n if newline < 0 else newline
            continue
        if c == ">" or (c == "&" and command[i + 1:i + 2] == ">"):
            if in_word and "".join(word).isdigit():
                word.clear()
                in_word = False
            end_word()
            i += 1
            while i < n and command[i] in ">&|":
                i += 1
            drop = True
            continue
        if c in _SEPARATORS:
            end_word()
            out.append(_Segment(start, i, None if unread else list(words), piped_in))
            pair = command[i:i + 2]
            piped_in = c == "|" and pair != "||"
            i += 2 if pair in ("&&", "||", "|&") else 1
            words.clear()
            start, unread, drop = i, False, False
            continue
        end_word()                                    # a blank, `(` or `)`
        i += 1
    end_word()
    out.append(_Segment(start, n, None if unread else list(words), piped_in))
    return out


def _any(_value: str) -> bool:
    return True


def _not_a_file(value: str) -> bool:
    """`-d`, `--data`, `--json`, `-H`: a leading `@` reads a file (or `@-`, stdin)."""
    return not value.startswith("@")


def _form(value: str) -> bool:
    """`-F name=@f` or `name=<f` reads a file."""
    return not value.partition("=")[2].startswith(("@", "<"))


def _urlencoded(value: str) -> bool:
    """`--data-urlencode @f` / `name@f` reads a file; `name=x@y` does not."""
    at, eq = value.find("@"), value.find("=")
    return at < 0 or 0 <= eq < at


def _cookie(value: str) -> bool:
    """`-b name=value` is text; `-b jar.txt` reads a file."""
    return "=" in value


def _not_a_file_url(value: str) -> bool:
    return not _FILE_URL.match(value)


_NO_VALUE = None


def _read_options(args: list[str], flags: str, short: dict, long: dict,
                  whole: frozenset = frozenset()) -> list[str] | None:
    """The operands of a command whose every option is known and literal, or
    None. `flags`: short options that take nothing; `short`/`long`: an
    option's check of its value (`_NO_VALUE`: it takes none); `whole`:
    multi-letter short options (`-nv`)."""
    operands: list[str] = []
    i = 0
    while i < len(args):
        word = args[i]
        i += 1
        if word == "--":
            operands += args[i:]
            break
        if not word.startswith("-") or word == "-" or word in whole:
            if not word.startswith("-"):
                operands.append(word)
            continue
        if word.startswith("--"):
            name, eq, value = word.partition("=")
            if name not in long:
                return None
            check = long[name]
            if check is _NO_VALUE:
                continue
            if not eq:
                if i >= len(args):
                    return None
                value, i = args[i], i + 1
            if not check(value):
                return None
            continue
        letters = word[1:]
        for k, letter in enumerate(letters):
            if letter in flags:
                continue
            if letter not in short:
                return None
            value = letters[k + 1:]
            if not value:
                if i >= len(args):
                    return None
                value, i = args[i], i + 1
            if not short[letter](value):
                return None
            break
    return operands


_CURL_FLAGS = "#:0123456" "aBfgGiIjJklLMNOpqRsSvVZ"
_CURL_SHORT = {**dict.fromkeys("AeXmowxuryYzCDcUPtQ", _any),
               "H": _not_a_file, "d": _not_a_file, "F": _form, "b": _cookie}
_CURL_LONG = {
    **dict.fromkeys((
        "--silent", "--show-error", "--fail", "--fail-with-body", "--fail-early",
        "--location", "--location-trusted", "--insecure", "--compressed", "--include",
        "--head", "--verbose", "--get", "--globoff", "--http1.0", "--http1.1", "--http2",
        "--http2-prior-knowledge", "--http3", "--http3-only", "--ipv4", "--ipv6",
        "--no-progress-meter", "--progress-bar", "--remote-name", "--remote-name-all",
        "--remote-header-name", "--create-dirs", "--no-buffer", "--no-keepalive", "--raw",
        "--tlsv1", "--tlsv1.0", "--tlsv1.1", "--tlsv1.2", "--tlsv1.3", "--ssl", "--ssl-reqd",
        "--retry-connrefused", "--retry-all-errors", "--disable", "--path-as-is",
        "--styled-output", "--no-styled-output", "--tr-encoding", "--parallel",
        "--suppress-connect-headers", "--proxy-insecure", "--list-only", "--digest", "--basic",
        "--anyauth", "--junk-session-cookies", "--remote-time", "--no-sessionid",
        "--tcp-nodelay", "--tcp-fastopen", "--no-clobber", "--show-headers"), _NO_VALUE),
    **dict.fromkeys((
        "--user-agent", "--referer", "--request", "--max-time", "--connect-timeout",
        "--retry", "--retry-delay", "--retry-max-time", "--output", "--output-dir",
        "--write-out", "--proxy", "--user", "--range", "--resolve", "--connect-to",
        "--cookie-jar", "--dump-header", "--max-redirs", "--limit-rate", "--keepalive-time",
        "--oauth2-bearer", "--aws-sigv4", "--proxy-user", "--cacert", "--capath",
        "--interface", "--dns-servers", "--unix-socket", "--abstract-unix-socket",
        "--data-raw", "--form-string", "--expect100-timeout", "--speed-limit", "--speed-time",
        "--local-port", "--ciphers", "--tls-max", "--proto", "--proto-redir",
        "--request-target", "--noproxy", "--max-filesize", "--time-cond", "--continue-at",
        "--parallel-max", "--rate"), _any),
    **dict.fromkeys(("--header", "--data", "--data-ascii", "--data-binary", "--json"),
                    _not_a_file),
    "--data-urlencode": _urlencoded, "--form": _form, "--cookie": _cookie,
    "--url": _not_a_file_url,
}

_WGET_FLAGS = "qvcNrkpSEKxmbHL46"
_WGET_WHOLE = frozenset({"-nv", "-nc", "-nd", "-nH", "-np"})
_WGET_SHORT = dict.fromkeys("OoaPUTtwlARDQIXB", _any)
_WGET_LONG = {
    **dict.fromkeys((
        "--quiet", "--verbose", "--no-verbose", "--continue", "--timestamping", "--recursive",
        "--convert-links", "--page-requisites", "--server-response", "--adjust-extension",
        "--backup-converted", "--force-directories", "--mirror", "--background",
        "--inet4-only", "--inet6-only", "--no-check-certificate", "--spider", "--no-parent",
        "--no-clobber", "--no-directories", "--no-host-directories", "--content-disposition",
        "--https-only", "--save-headers", "--show-progress", "--retry-connrefused",
        "--random-wait", "--no-cookies", "--span-hosts", "--relative", "--ignore-case",
        "--no-cache", "--no-dns-cache", "--trust-server-names", "--auth-no-challenge",
        "--no-proxy", "--no-http-keep-alive", "--ignore-length"), _NO_VALUE),
    **dict.fromkeys((
        "--output-document", "--output-file", "--append-output", "--directory-prefix",
        "--user-agent", "--timeout", "--tries", "--wait", "--waitretry", "--level",
        "--accept", "--reject", "--domains", "--quota", "--header", "--method", "--user",
        "--password", "--http-user", "--http-password", "--referer", "--post-data",
        "--body-data", "--max-redirect", "--limit-rate", "--progress", "--compression",
        "--save-cookies", "--ca-certificate", "--ca-directory", "--secure-protocol",
        "--cut-dirs", "--dns-timeout", "--connect-timeout", "--read-timeout"), _any),
}

_HTTPIE_FLAGS = "jfvhbFIdcqSx"
_HTTPIE_SHORT = dict.fromkeys("spoaA", _any)
_HTTPIE_LONG = {
    **dict.fromkeys((
        "--json", "--form", "--multipart", "--verbose", "--headers", "--body", "--all",
        "--follow", "--check-status", "--ignore-stdin", "--offline", "--download",
        "--continue", "--quiet", "--stream", "--compress", "--path-as-is", "--chunked",
        "--sorted", "--unsorted", "--ignore-netrc", "--meta"), _NO_VALUE),
    **dict.fromkeys((
        "--pretty", "--style", "--print", "--output", "--timeout", "--auth", "--auth-type",
        "--verify", "--ssl", "--ciphers", "--default-scheme", "--max-redirects", "--proxy",
        "--raw", "--response-charset", "--response-mime", "--format-options",
        "--max-headers", "--boundary"), _any),
}
_METHOD = re.compile(r"[A-Z]+")


def _curl(args: list[str]) -> bool:
    operands = _read_options(args, _CURL_FLAGS, _CURL_SHORT, _CURL_LONG)
    return operands is not None and not any(_FILE_URL.match(w) for w in operands)


def _wget(args: list[str]) -> bool:
    return _read_options(args, _WGET_FLAGS, _WGET_SHORT, _WGET_LONG, _WGET_WHOLE) is not None


def _httpie_item(item: str) -> bool:
    """A request item of literal text: `f=x`, `f:=json`, `H:x`, `q==x` — not a
    file (`@f`, `f@x`, `f=@x`, `f:=@x`, `H:@x`). The first separator decides."""
    for k, c in enumerate(item):
        if c == "@":
            return False
        if c in "=:":
            return not item[k + 1:].lstrip("=").startswith("@")
    return True


def _httpie(args: list[str]) -> bool:
    operands = _read_options(args, _HTTPIE_FLAGS, _HTTPIE_SHORT, _HTTPIE_LONG)
    if operands is None:
        return False
    if operands and _METHOD.fullmatch(operands[0]):
        operands = operands[1:]
    if not operands or _FILE_URL.match(operands[0]):
        return not operands
    return all(_httpie_item(item) for item in operands[1:])


_SCP_FLAGS = "346BCpqrvTO"
_RSYNC_FLAGS = "avzhPnucilptogDHAXSWxR"
_COPY_FLAGS = _SCP_FLAGS + _RSYNC_FLAGS
_COPY_SHORT = dict.fromkeys("PlcJ", _any)
_COPY_LONG = {
    **dict.fromkeys((
        "--progress", "--archive", "--verbose", "--compress", "--recursive", "--partial",
        "--human-readable", "--stats", "--checksum", "--update", "--times", "--perms",
        "--links", "--dry-run", "--itemize-changes", "--no-motd", "--size-only",
        "--ignore-existing"), _NO_VALUE),
    **dict.fromkeys(("--exclude", "--include", "--info", "--port", "--bwlimit"), _any),
}


def _download_only(args: list[str]) -> bool:
    """scp / rsync / sftp sending nothing but a request: every source is
    remote and the destination (the last operand, if more than one) is here."""
    operands = _read_options(args, _COPY_FLAGS, _COPY_SHORT, _COPY_LONG)
    if not operands:
        return False
    sources = operands[:-1] or operands
    destination = operands[-1] if len(operands) > 1 else "."
    return all(_REMOTE.match(s) for s in sources) and not _REMOTE.match(destination)


def _dns(args: list[str]) -> bool:
    """dig / nslookup / host: the name is the text; `-f`, `-k` read a file."""
    return not any(w.startswith(("-f", "-k")) for w in args)


def _nothing(_args: list[str]) -> bool:
    return True


# Commands that send nothing whatever their words name.
_SENDS_NOTHING = frozenset({
    "echo", "printf", "which", "type", "man", "grep", "egrep", "fgrep", "rg", "cat", "head",
    "tail", "less", "more", "ls", "wc", "sort", "cut", "tr", "diff", "jq", "test", "[",
    "true", "false", "cd", "pwd", "mkdir", "touch", "chmod", "rm", "cp", "mv"})
_READERS: dict[str, Callable[[list[str]], bool]] = {
    "curl": _curl, "wget": _wget, "http": _httpie, "https": _httpie, "xh": _httpie,
    "xhs": _httpie, "scp": _download_only, "rsync": _download_only,
    "sftp": _download_only, "dig": _dns, "nslookup": _dns, "host": _dns,
    **dict.fromkeys(_SENDS_NOTHING, _nothing)}


def sends_only_literal_text(action: Action, aliases: dict | None = None) -> bool:
    """Is every byte this action sends literal text written in it (see the
    module)? A fetch sends its URL. Anything this cannot read is not."""
    if action.kind is ActionKind.FETCH:
        return True
    if action.kind is not ActionKind.EXEC or not action.command:
        return False
    command = action.command
    # An alias runs what it was defined as (`sinks` reads it after the command).
    first = command.split(None, 1)[:1]
    if aliases and first and first[0] in aliases:
        return False
    for segment in _segments(command):
        if not _SENDER.search(command, segment.start, segment.end):
            continue
        if segment.words is None or segment.piped_in:
            return False
        words = segment.words
        at = 0
        while at < len(words) and (words[at] in _OPENERS or _ASSIGNMENT.match(words[at])):
            at += 1
        if at == len(words):
            continue
        verb = words[at].rsplit("/", 1)[-1]
        # Into a socket (`> /dev/tcp/h/p`): literal only what echo or printf writes.
        if _DEV_SOCKET.search(command, segment.start, segment.end):
            if verb not in ("echo", "printf"):
                return False
            continue
        reader = _READERS.get(verb)
        if reader is None or not reader(words[at + 1:]):
            return False
    return True


def uploads_a_file(action: Action) -> bool:
    """Is this an MCP tool named to upload (see the module)?"""
    if action.kind is not ActionKind.TOOL:
        return False
    name = (action.tool_name or "").rsplit("__", 1)[-1]
    return bool(_UPLOAD_TOOL.search(name)) and not _READ_TOOL.match(name)
