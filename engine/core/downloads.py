"""Which files a command writes from a download.

fix/false-positives, item A (docs/112). A file that `curl -o` or `wget` wrote
is OUTSIDE CONTENT, whoever ran the command: running it (`cat it | sh`) keeps
the verdict it had before this pass, while running a file the session wrote
from its own work is no longer gated. `sources.mark_sources` records what this
returns in `SessionState.downloaded_paths`.

    curl -o F / --output F / -oF / a cluster ending in o (`-fsSLo F`)
    curl -O / --remote-name URL          the URL's last path component
    wget URL                             the same, or index.html
    wget -O F / --output-document F      (`-O -` is standard output: no file)
    a `>` / `>>` / `&>` redirect in the same command as curl or wget
    what a later stage of a fetch's pipeline writes: `| tee F`, `| cat > F`,
    `| sed … > F`, `| dd of=F` (the fourth review round); `gh … > F`, `http …
    > F` (the output of a fetch is outside content, never the session's own)

RECORDED too (item 1, the maintainer, round 5; `pulled_downloads`): what `git clone`,
a `gh repo clone`, an `scp`/`rsync`/`sftp` pull from a host, and a `gh release
download` write. A single-file scp/rsync and a `gh release download -O F` are
named; a clone, a folder sync and a release into a directory cannot be
enumerated, so they lose track of downloads (`Carried.lost`) — the fail-closed
direction, since running what they wrote was ALLOW where main gave DENY. A
COPY of a download is a download too (`carried_downloads`), and what cannot be
followed loses track of them all (`Carried.lost`).

Relative names resolve against the action's cwd. What cannot be read — a
substitution, a glob — is left out; `outside_content` then judges the command
by what it can read, and a pipe with a network tool in it keeps today's verdict
whatever file it names.
"""
from __future__ import annotations

import bisect
import re
from typing import NamedTuple

from core.command_text import (_CMD_START, _SEGMENT_END, _SEGMENT_REST, _abs,
                               _bash_unquote, _copy_pairs, _norm_path,
                               is_inside_project)
from core.shell_scan import code_mask_checked

# A fetch at a code position, in a substitution too (`echo "$(gh api …)" > f`):
# what its segment redirects to is a download (the fourth review round).
_DOWNLOADER = re.compile(r"(?<![\w./-])(?:(?:curl|wget)(?![\w-])|(?:gh|https?|xhs?)(?=[ \t]))")
_REDIRECT = re.compile(r"(?<![<>0-9])(?:&|1)?>>?\|?\s*([^\s<>|;&()]+)")
_URL = re.compile(r"^(?:https?|ftp)://[^/\s]+(/[^\s?#]*)?")


def _url_name(token: str) -> str | None:
    """The last path component of a URL operand, or None when it has none."""
    found = _URL.match(token)
    if not found:
        return None
    name = (found.group(1) or "").rstrip("/").rsplit("/", 1)[-1]
    return name or None


def _curl_outputs(words: list[str]) -> list[str]:
    out, remote_name, urls, directory = [], False, [], ""
    i = 0
    while i < len(words):
        word = words[i]
        if word in ("-o", "--output") and i + 1 < len(words):
            out.append(words[i + 1])
            i += 2
            continue
        if word == "--output-dir" and i + 1 < len(words):
            directory = words[i + 1]
            i += 2
            continue
        if word.startswith("--output-dir="):
            directory = word.split("=", 1)[1]
        elif word.startswith("--output="):
            out.append(word.split("=", 1)[1])
        elif word in ("-O", "--remote-name", "--remote-name-all"):
            remote_name = True
        elif word.startswith("-") and not word.startswith("--") and len(word) > 1:
            letters = word[1:]
            if "o" in letters:
                rest = letters[letters.index("o") + 1:]
                if rest:
                    out.append(rest)
                elif i + 1 < len(words):
                    out.append(words[i + 1])
                    i += 1
            elif "O" in letters:
                remote_name = True
        elif _URL.match(word):
            urls.append(word)
        i += 1
    if remote_name:
        out += [name for name in map(_url_name, urls) if name]
    if directory:                       # `--output-dir`: where every relative name lands
        out = [name if name.startswith("/") else f"{directory.rstrip('/')}/{name}"
               for name in out]
    return out


def _wget_outputs(words: list[str]) -> list[str]:
    out, named, urls, prefix = [], False, [], ""
    i = 0
    while i < len(words):
        word = words[i]
        if word in ("-O", "--output-document") and i + 1 < len(words):
            named = True
            out.append(words[i + 1])
            i += 2
            continue
        if word.startswith("--output-document="):
            named = True
            out.append(word.split("=", 1)[1])
        elif word in ("-P", "--directory-prefix") and i + 1 < len(words):
            prefix = words[i + 1]
            i += 1
        elif word.startswith("--directory-prefix="):
            prefix = word.split("=", 1)[1]
        elif word.startswith("-") and not word.startswith("--") and "O" in word:
            named = True
            rest = word[word.index("O") + 1:]
            if rest:
                out.append(rest)
            elif i + 1 < len(words):
                out.append(words[i + 1])
                i += 1
        elif _URL.match(word):
            urls.append(word)
        i += 1
    if not named:
        for url in urls:
            name = _url_name(url) or "index.html"
            out.append(f"{prefix.rstrip('/')}/{name}" if prefix else name)
    return out


_PIPE = re.compile(r"(?<!\|)\|(?![|&])")
_LIST = re.compile(r"&&|\|\||;|\n|(?<![>&|])&(?![>&])")
_CARRY_ROUNDS = 4
"""A copy of a copy: chains are followed this many steps in one command."""
_COPY_OR_LINK = re.compile(_CMD_START + rf"(cp|mv|install|ln)\s+({_SEGMENT_REST})")
# A copy or link WHEREVER the shell runs one — `sudo cp`, `/bin/cp`, a later
# stage — not only at a command start (the round-6 reviews). Gated to code
# positions by `at_code`, like the installed-guard floor's copy verb.
_OUTSIDE_COPY_VERB = re.compile(rf"(?<![\w.-])(cp|mv|install|ln)[ \t]+({_SEGMENT_REST})")
# A command whose standard output is fetched text: what a later stage of its
# pipeline writes is a download (`curl … | cat > f`, `gh api … > f`).
_FETCHERS = frozenset({"curl", "wget", "http", "https", "xh", "xhs", "gh"})
_FETCHER_WORD = re.compile(r"(?<![\w./-])(?:curl|wget|https?|xhs?|gh)(?![\w-])")
# A word of a pipeline stage, and the redirect before it: `>`, `>>`, `>|` of
# standard output (an fd of `1` or none) write it, `<` reads it. Blanks are
# taken only after an operator and the fd is one digit, so a failed try costs
# one character: linear.
_STAGE_WORD = re.compile(r"(?:(\d?)(>>?\|?)[ \t]*|(<)[ \t]*)?([^\s<>|;&()]+)")
_ASSIGNMENT = re.compile(r"\w+=")
# Words that open a compound command: the word after them is the verb.
_OPENERS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"})
# ⚠ AN ALLOW-LIST: THE COMMANDS WHOSE EVERY WRITE OF A DOWNLOAD IS READ HERE
# (the fourth review round). They write only standard output — followed by a
# `>`, `>>` or `tee` — or what they write is an operand read below (`-o F`,
# `of=F`, a copy's or a link's destination), or nothing. A download handed to
# anything else — an unpacker (`tar`, `unzip`), an editor that writes on its
# own (`sed -i`, `awk`'s `print >`), a wrapper, an interpreter running it — may
# write files nobody can name: from then on any file may be a download
# (`Carried.lost`), the verdict every pipe into a shell had before docs/112.
_FOLLOWED = frozenset({
    "cat", "head", "tail", "less", "more", "wc", "ls", "stat", "file", "grep", "egrep",
    "fgrep", "rg", "diff", "cmp", "test", "[", "sha1sum", "sha224sum", "sha256sum",
    "sha384sum", "sha512sum", "shasum", "md5", "md5sum", "b2sum", "strings", "od", "cut",
    "tr", "rev", "jq", "echo", "printf", "base64", "sort", "chmod", "chown", "rm", "touch",
    "cp", "mv", "install", "ln", "tee", "dd", "cd", "pushd", "popd", "pwd", "export",
    "unset", "mkdir", "true", "false", "sleep", "which", *_FETCHERS})


class _Stage(NamedTuple):
    """One pipeline stage, as written: its verb; its other words in order (a
    redirect's target left out); every word it names — the verb's own, a `<`
    input, a `x=F` word's value; what it redirects standard output to; and
    everything it writes: that, `-o F`, `-oF`, `--output[=]F`, `of=F`, a
    `tee`'s operands."""
    verb: str
    words: list[str]
    named: list[str]
    redirected: list[str]
    written: list[str]


def _stage(text: str) -> _Stage:
    verb, words, named, redirected, options = "", [], [], [], []
    output_next = False
    for fd, out, into, raw in _STAGE_WORD.findall(text):
        word = _bash_unquote(raw)
        if out:
            if fd in ("", "1"):
                redirected.append(word)
            continue
        if not verb and not into and (word in _OPENERS or _ASSIGNMENT.match(word)):
            continue
        if not verb and not into:
            verb = word.rsplit("/", 1)[-1]
            named.append(word)
            continue
        named += [word, word.split("=", 1)[1]] if "=" in word else [word]
        if into:
            continue
        words.append(word)
        if output_next:
            options.append(word)
            output_next = False
        elif word in ("-o", "--output"):
            output_next = True
        elif word.startswith(("--output=", "of=")):
            options.append(word.split("=", 1)[1])
        elif word.startswith("-o") and len(word) > 2 and not word.startswith("--"):
            options.append(word[2:])
    tee = [word for word in words if not word.startswith("-")] if verb == "tee" else []
    return _Stage(verb, words, named, redirected, redirected + options + tee)


def _pipelines(command: str) -> list[list[_Stage]]:
    """Each pipeline's stages; a blank one is none."""
    return [[_stage(text) for text in _PIPE.split(item)]
            for item in _LIST.split(command) if item and not item.isspace()]


def _unreadable(word: str) -> bool:
    """A word that may name any file: a variable, a substitution, a glob."""
    return word not in ("[", "[[") and any(c in word for c in "$`*?[")


def _under(paths: list[str], folder: str) -> bool:
    """Is one of the sorted `paths` inside `folder`?"""
    prefix = folder.rstrip("/") + "/"
    k = bisect.bisect_left(paths, prefix)
    return k < len(paths) and paths[k].startswith(prefix)


class Carried(NamedTuple):
    """The files a command copies downloads into, and whether it handed one to
    a command whose writes cannot be read (`_FOLLOWED`)."""
    paths: list[str]
    lost: bool


def carried_downloads(command: str | None, cwd: str, known: set[str]) -> Carried:
    """The files this command copies a download into — a download still (the
    third and fourth review rounds) — and whether it lost track of one.

    Carried: a `cp`/`mv`/`install`/`ln` destination whose source is one, and
    the copy in the destination folder (`cp i.sh bin` writes `bin/i.sh` when
    `bin` is a folder); every write of a pipeline stage that names one, or that
    a stage before it named or fetched (`| sed … > f`, `| tee f`, `of=f`).
    Lost: such a stage is not `_FOLLOWED`; or a copy's source is a folder
    holding one, or cannot be read (`$S`, `*.sh`) — and so is any word that
    cannot be read, once there is a download it could name.
    `known`: the downloads so far, collapsed. Chains (`cp i j && cp j k`) are
    followed `_CARRY_ROUNDS` steps."""
    if not command or not (known or _FETCHER_WORD.search(command)):
        return Carried([], False)
    known = set(known)
    any_known = bool(known)
    carried: list[str] = []
    lost = False

    def carry(path: str) -> None:
        path = _norm_path(_abs(path, cwd))
        if path not in known and not path.startswith("/dev/"):
            known.add(path)
            carried.append(path)

    def names_one(word: str) -> bool:
        return (_norm_path(_abs(word, cwd)) in known
                or (any_known and _unreadable(word)))

    mask, _parsed = code_mask_checked(command)

    def at_code(at: int) -> bool:
        return at >= len(mask) or bool(mask[at])

    pairs = [(_norm_path(src), dst)
             for _at, src, dst in _copy_pairs(command, cwd, _OUTSIDE_COPY_VERB, at_code)]
    pipelines = _pipelines(command)
    for _round in range(_CARRY_ROUNDS):
        before = len(carried)
        everything = sorted(known)
        for src, dst in pairs:
            if src in known:
                carry(dst)
                carry(f"{dst.rstrip('/')}/{src.rsplit('/', 1)[-1]}")
            elif any_known and (_unreadable(src) or _under(everything, src)):
                lost = True
        for pipeline in pipelines:
            reads = False
            for stage in pipeline:
                if reads or any(names_one(word) for word in stage.named):
                    for path in stage.written:
                        carry(path)
                    lost = lost or stage.verb not in _FOLLOWED
                    reads = True
                reads = reads or stage.verb in _FETCHERS
        if len(carried) == before:
            break
    return Carried(carried, lost)


# ── item 1 (docs/112): a clone, an scp/rsync pull from a host, a gh release
# download write OUTSIDE CONTENT, the same as curl or wget. What can be
# enumerated is recorded; what cannot (a clone, a folder sync, a release into a
# directory) sets `Carried.lost`, so the session loses track of its downloads.
# A pull of a whole repository, which cannot be enumerated: git clone / pull /
# fetch / submodule (with any global options or a path-qualified git before
# the subcommand), and the gh equivalents. The round-6 reviews widened this
# from `git [-C D] clone` only.
# ⚠ `(?<![\w.-])`, NOT `(?<![\w./-])` and NOT a `(?:[\w./-]*/)?` prefix: the
# lookbehind leaves `/` out of its class, so a path-qualified `/usr/bin/git`
# matches with NO forward scan. An actual path prefix in the pattern re-read
# the long path from every `/` — O(n²), the exact stall the override-check
# linear test guards. The git-option repeat is lazy and bounded to 8 words, so
# `git -c k=v clone` matches without scanning.
_CLONE = re.compile(
    r"(?<![\w.-])git(?:[ \t]+[^\s]+){0,8}?[ \t]+(?:clone|pull|fetch|submodule)(?![\w-])"
    r"|(?<![\w.-])gh[ \t]+(?:repo[ \t]+clone|repo[ \t]+fork|pr[ \t]+checkout"
    r"|run[ \t]+download|gist[ \t]+clone)(?![\w-])")
_RELEASE = re.compile(r"(?<![\w.-])gh[ \t]+release[ \t]+download(?![\w-])")
_PULL_TOOL = re.compile(r"(?<![\w.-])(?:scp|rsync|sftp)(?![\w-])")
# A `host:`, `user@host:`, bracketed-IPv6 `[::1]:` or `scheme://` source — a
# remote the pull reads from (the re-review's G5 added IPv6).
_REMOTE = re.compile(r"(?:[\w.-]+@)?(?:\[[0-9A-Fa-f:]+\]|[\w.-]+):|\w+://")
# A folder sync writes files that cannot be named one by one.
_FOLDER_SYNC = re.compile(r"(?:^|[ \t])-\w*[ra]|--recursive\b|--archive\b")


def _remote_basename(source: str) -> str | None:
    """The file name a `host:/path/to/f` or `scheme://h/path/f` source writes
    locally, or None when it names no single file (a folder, a bare host)."""
    after = source.split("://", 1)[-1]
    after = after.split(":", 1)[-1] if ":" in after and "://" not in source else after
    if source.rstrip().endswith("/"):
        return None
    name = after.rstrip("/").rsplit("/", 1)[-1]
    return name or None


_REDIRECT_TOKEN = re.compile(r"^(?:\d*|&)>|^<|\|$")


def _pull_operands(rest: str) -> list[str]:
    """The non-option, non-redirect words of a pull, bash-unquoted. A redirect
    (`2>/dev/null`, `2>&1`, `> log`) is the shell's, never the destination
    (the round-6 reviews; `_copy_pairs` strips them too). A value an option
    eats (`-P 2222`) stays an operand: a non-remote source is inert, and the
    LAST operand is still the destination (the direction-of-error of
    `_copy_pairs`). A `>` target word is dropped with its operator."""
    words: list[str] = []
    skip_next = False
    for w in rest.split():
        if skip_next:
            skip_next = False
            continue
        if _REDIRECT_TOKEN.search(w):
            skip_next = w.endswith(">") or w.endswith("&")  # `> log` splits in two
            continue
        if w.startswith("-"):
            continue
        words.append(_bash_unquote(w))
    return words


def pulled_downloads(command: str | None, cwd: str) -> Carried:
    """The files a clone / scp / rsync / sftp / gh-release pull writes, and
    whether it lost track of them (a clone, a folder sync, a release into a
    directory: the files cannot be enumerated). Linear: one pass per segment."""
    if not command or not (_CLONE.search(command) or _RELEASE.search(command)
                           or _PULL_TOOL.search(command)):
        return Carried([], False)
    mask, _parsed = code_mask_checked(command)

    def at_code(at: int) -> bool:
        return at >= len(mask) or bool(mask[at])

    def at_code_in(segment: str, offset: int, pattern: re.Pattern) -> re.Match | None:
        # ⚠ The FIRST match AT A CODE POSITION, not the first match (round-6
        # re-review R3/N6): a quoted mention before the real call used to hide
        # it. `downloaded_files` already loops this way.
        for found in pattern.finditer(segment):
            if at_code(offset + found.start()):
                return found
        return None

    paths: list[str] = []
    lost = False
    start = 0
    for m in list(_SEGMENT_END.finditer(command)) + [None]:
        end = m.start() if m else len(command)
        segment, offset = command[start:end], start
        start = end + 1
        if at_code_in(segment, offset, _CLONE):
            lost = True
            continue
        release = at_code_in(segment, offset, _RELEASE)
        if release:
            rest = segment[release.end():]
            output = re.search(r"(?:^|[ \t])(?:-O[ \t]+|--output[= \t])(\S+)", rest)
            if output:
                paths.append(_norm_path(_abs(_bash_unquote(output.group(1)), cwd)))
            else:
                lost = True                         # a directory or the cwd: cannot enumerate
            continue
        tool = at_code_in(segment, offset, _PULL_TOOL)
        if not tool:
            continue
        operands = _pull_operands(segment[tool.end():])
        sources = operands[:-1] or operands
        destination = operands[-1] if len(operands) > 1 else "."
        remote = [s for s in sources if _REMOTE.match(s)]
        if not remote or _FOLDER_SYNC.search(segment) or _unreadable(destination):
            lost = lost or bool(remote)
            continue
        into_dir = destination.endswith("/") or destination in (".", "..")
        for source in remote:
            if _unreadable(source):
                lost = True
                continue
            name = _remote_basename(source)
            if name is None:                        # a folder: cannot enumerate
                lost = True
                continue
            if into_dir or len(remote) > 1:
                paths.append(_norm_path(_abs(f"{destination.rstrip('/')}/{name}", cwd)))
            else:
                paths.append(_norm_path(_abs(destination, cwd)))
                # ⚠ `scp h:f bin` writes `bin` OR `bin/f` — `bin` may be an
                # existing directory, unknowable lexically (the re-review's F8).
                # Record both when the destination looks like a directory (its
                # last component has no extension), as `carried_downloads` does.
                if "." not in destination.rstrip("/").rsplit("/", 1)[-1]:
                    paths.append(_norm_path(_abs(f"{destination.rstrip('/')}/{name}", cwd)))
    collapsed = [p for p in paths if not p.startswith("/dev/")]
    return Carried(list(dict.fromkeys(collapsed)), lost)


# ⚠ AN ALLOWLIST, NOT A DENYLIST (the round-6 re-review's G3). An outside file
# read by any verb NOT here persists or transforms it in a way this reader
# cannot follow (`tar`, `unzip`, `patch`, `awk`, `sed -i`, `split`, `ar`,
# `dpkg-deb`, a wrapper such as `sudo`/`env`/`timeout`), so it LOSES TRACK. The
# set is the inert readers and copiers `carried_downloads` can follow — the same
# `_FOLLOWED` it uses — so the two agree. An interpreter RUNNING an outside file
# (`sh f`, `python f`) is `runs_outside_content`'s job and main never gated it,
# so it is excused here (`_RUNNERS`) rather than lost.
_RUNNERS = frozenset({"sh", "bash", "zsh", "ksh", "dash", "ash", "fish", "python", "python2",
                      "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun", "pwsh",
                      "powershell", "osascript", "lua", "tclsh", "Rscript", "iex"})
# A recursive-copy flag, scoped to ONE copy's own segment (not the whole command,
# which made an unrelated `-r`/`-a` lose track — the round-6 re-review's R4).
# ⚠ r/R/a ANYWHERE in a short cluster, not only as the last letter: `-rf`,
# `-rv`, `-Rp`, `-av` are recursive too (the re-review's N-A). Long forms
# (`--recursive`, `--archive`; F9/G2) handled separately.
_RECURSIVE_FLAG = re.compile(r"(?<![\w-])-[A-Za-z]*[rRa][A-Za-z]*(?![\w])"
                            r"|(?<![\w-])--(?:recursive|archive|no-dereference)(?![\w-])")
# A segment boundary for scoping the flag scan — a list separator, NEVER a lone
# `&` (which is part of `2>&1`/`&>`; the re-review's G2 sub-variant).
_SEG_BOUND = re.compile(r";|\n|\|\|?|&&")
# A brace expansion is readable to `_unreadable` but the shell expands it, so
# the literal string names no real file (the re-review's G1).
_BRACE = re.compile(r"\{[^}]*[,.][^}]*\}")


def _uncertain(word: str) -> bool:
    """A source/destination word whose real files cannot be named: a variable,
    a glob, or a brace expansion."""
    return _unreadable(word) or bool(_BRACE.search(word))


def _looks_like_path(word: str) -> bool:
    """A word that could NAME a file — has a separator or a path-ish lead — so a
    bare pattern or flag (`hi`, `s/a/b/`'s operand) is not mistaken for one (R5)."""
    return bool(word) and ("/" in word or "\\" in word or word[0] in "~.${")


def copied_outside_files(command: str | None, cwd: str, roots, world, state) -> Carried:
    """The outside-file SOURCES this command COPIES into a local file (item 3,
    docs/112): seeded into `carried_downloads` by the caller, which follows a
    clean single-file `cp`/`install` to its destination. Anything that is a
    copy of outside content but cannot be followed to named files
    (`Carried.lost`, the fail-closed direction): a folder copy (`-r`/`-R`/`-a`,
    a trailing `/`), a `mv`/`ln` of outside (a folder is not knowable
    lexically), an unreadable source or destination, an unpacker or local
    `rsync`/`scp` of an outside path, and a write fed by an unreadable or
    outside read (`cat /opt/x > f`, `cat $F | tee f`, `< /opt/x cat > f`).

    ⚠ A PURE READ that persists nothing — `cat /opt/x | sh`, `cat /etc/x` — is
    NOT a copy and is left to `outside_content.runs_outside_content`, which
    already gates it; tainting it would gate later pushes main never gated.
    `state` answers authorship; `roots`/`world` answer membership."""
    if not command or not (_OUTSIDE_COPY_VERB.search(command) or "/" in command):
        return Carried([], False)
    mask, _parsed = code_mask_checked(command)

    def at_code(at: int) -> bool:
        return at >= len(mask) or bool(mask[at])

    def is_outside(word: str) -> bool:
        resolved = _norm_path(word) if word.startswith("/") else _norm_path(_abs(word, cwd))
        if is_inside_project(resolved, tuple(roots), world):
            return False
        # A file the session itself WROTE outside the roots is its own; one it
        # recorded as a download is outside, not own.
        return not (state.authored(resolved) is True and state.downloaded(resolved) is False)

    sources: list[str] = []
    lost = False
    # ⚠ Each copy's flag scan is bounded to its OWN operand span — the next copy,
    # the next separator, or a cap — so many `cp …` with no separator stays
    # linear instead of each scanning to the end (the re-review's F11).
    pairs = list(_copy_pairs(command, cwd, _OUTSIDE_COPY_VERB, at_code))
    seps = [m.start() for m in _SEG_BOUND.finditer(command)]
    # ⚠ The NEXT DISTINCT copy position, not `pairs[i+1]` — every pair from one
    # verb match (a multi-source copy, or the two readings of a dir dest) shares
    # that match's `at`, so `pairs[i+1][0] == at` left the flag segment EMPTY for
    # all but the last pair and the recursive flag went unseen (the re-review's
    # N-B). `_FLAG_CAP` bounds a flag after a very long operand list.
    distinct_ats = sorted({p[0] for p in pairs})
    _FLAG_CAP = 256
    # ⚠ Each copy's verb and recursive-flag decision computed ONCE per DISTINCT
    # copy position, not per pair — a single copy of many sources shares one
    # `at`, so re-scanning its segment per pair was linear-but-with-a-256
    # constant and blew the bound (the re-review's N-B/F11). A plain dict, not a
    # cache decorator, so the engine grows no second memoised function
    # (tests/test_mask_cache.py). `at` is the verb's start, so a cheap slice
    # reads it rather than re-running `_OUTSIDE_COPY_VERB` (whose `_SEGMENT_REST`
    # scans to the command end). The segment ends at the next DISTINCT copy, the
    # next separator, or a cap.
    copy_decision: dict[int, tuple[str, bool]] = {}
    for i, at in enumerate(distinct_ats):
        head = command[at:at + 10].split(None, 1)
        k = bisect.bisect_right(seps, at)
        end = min(distinct_ats[i + 1] if i + 1 < len(distinct_ats) else len(command),
                  seps[k] if k < len(seps) else len(command), at + _FLAG_CAP)
        copy_decision[at] = (head[0] if head else "",
                             bool(_RECURSIVE_FLAG.search(command[at:end])))

    for at, src, dst in pairs:
        if _uncertain(src):
            lost = True                             # cannot tell if it is outside
            continue
        if not is_outside(src):
            continue
        verb, recursive = copy_decision[at]
        if (verb in ("mv", "ln") or _uncertain(dst) or src.rstrip().endswith("/") or recursive):
            lost = True                             # a folder / move / unknown dst: unenumerable
        else:
            sources.append(_norm_path(src) if src.startswith("/") else _norm_path(_abs(src, cwd)))
    _COPY_VERBS = ("cp", "mv", "install", "ln")
    for pipeline in _pipelines(command):
        # A `>`/`tee`/`of=` target can be followed only when every write target
        # is readable; an unreadable one (`> $D/y`) cannot (N2).
        writes = any(stage.written for stage in pipeline)
        targets_readable = all(not _uncertain(t) for stage in pipeline for t in stage.written)
        # ⚠ A verb that is neither a pure reader/copier (`_FOLLOWED`) nor an
        # interpreter run (`_RUNNERS`) nor a `cp`/`mv`/`ln` the copy loop handled
        # TRANSFORMS or persists outside content in a way this reader cannot
        # follow (`tar`, `patch`, `awk`, `xargs`, a wrapper `sudo`/`env`/
        # `timeout`). It makes the whole pipeline a persist.
        transforms = any(stage.verb not in _FOLLOWED and stage.verb not in _RUNNERS
                         and stage.verb not in _COPY_VERBS for stage in pipeline)
        if not (writes or transforms):
            continue                                # a pure read or run: gated elsewhere
        followable = writes and targets_readable and not transforms
        for stage in pipeline:
            if stage.verb in _COPY_VERBS:
                continue                            # the copy loop handled it
            for word in stage.named:                # named[0] may be a `<` input, not the verb (N4)
                if not _looks_like_path(word):
                    continue
                if _uncertain(word):
                    lost = True                     # an unknown source feeding a persist
                elif is_outside(word):
                    if followable:
                        sources.append(_norm_path(_abs(word, cwd)))   # followed to its `>` target
                    else:
                        lost = True                 # a transform/unpack/wrapper: cannot name it
    return Carried(list(dict.fromkeys(s for s in sources if not s.startswith("/dev/"))), lost)


def downloaded_files(command: str | None, cwd: str) -> list[str]:
    """Absolute paths this command writes from a download, in order: what a
    curl or wget writes (the first one at a code position in each segment),
    and what a later stage of a fetch's pipeline writes (`curl … | cat > f`,
    `| sed … > f`, `| dd of=f`, `gh api … > f`; the fourth review round)."""
    if not command or not _FETCHER_WORD.search(command):
        return []
    mask, _parsed = code_mask_checked(command)
    ends = [m.start() for m in _SEGMENT_END.finditer(command)] + [len(command)]
    found: list[str] = []
    start = 0
    for end in ends:
        segment = command[start:end]
        verb = next((m for m in _DOWNLOADER.finditer(segment)
                     if start + m.start() >= len(mask) or mask[start + m.start()]), None)
        if verb is not None:
            args = [_bash_unquote(w) for w in segment[verb.end():].split()]
            if verb.group(0) == "curl":
                found += _curl_outputs(args)
            elif verb.group(0) == "wget":
                found += _wget_outputs(args)
            found += [m.group(1) for m in _REDIRECT.finditer(segment)]
        start = end + 1
    for pipeline in _pipelines(command):
        fetched = False
        for stage in pipeline:
            if fetched:
                found += stage.written
            elif stage.verb in _FETCHERS:
                found += stage.redirected
            fetched = fetched or stage.verb in _FETCHERS
    # Collapsed (`_norm_path`): `./i.sh` and `i.sh` are one download.
    collapsed = (_norm_path(_abs(path, cwd)) for path in found
                 if path and path != "-" and "$" not in path and "`" not in path)
    return list(dict.fromkeys(path for path in collapsed if not path.startswith("/dev/")))
