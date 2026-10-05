"""Does this command RUN outside content? The one thing an untrusted session
still gates — fix/false-positives, item A (docs/112).

Principle (maintainer): taint the DATA, not the session. Outside content is a web
fetch or search result, a download, an MCP tool result, and a file outside the
project roots that the session did not write. NOT outside: the agent's own
command output (`git log`, `git diff`, build and test output), the files this
session wrote, and Claude Code's own tool-result and transcript files.

Reading outside content no longer gates what the session does next — a network
send, a write, an MCP call (item B) — except a push to an existing remote
(`read_outside_content`, below: X-CHAIN-3). It gates RUNNING what came from
outside, and there the verdict is exactly what it was before this pass:

    a download piped into a shell or interpreter    curl … | sh, sh <(curl …)
    fetched text run as code                        eval "$(curl …)", bash -c "$(wget …)",
                                                    source <(curl …), `$(curl …)` as a command
    anything else piped into a shell                cat /opt/x.sh | sh, a downloaded file,
                                                    echo … | base64 -d | sh, printf '\\x…' | sh

Piping into a shell is the session's own work ONLY for its own files, files
under the project roots (`cat`/`head`/`tail`) and its own `git` output
(maintainer, 30 Sep): `cat my_own_script.sh | sh` and `git log | python3 -c …` are
no longer gated.

⚠ WHAT CANNOT BE READ COUNTS AS OUTSIDE: a `$` or a backtick in a producer's
operand, no project roots, an authorship or download record past its cap. The
verdict then stays what it was — the direction this pass may not loosen.

Linear in the command: every pattern is found once, positions are looked up by
bisect, and each pipeline is read once, from its start to the shell it feeds.
"""
from __future__ import annotations

import bisect
import re

from core.command_text import _abs, _bash_unquote, _norm_path, is_inside_project
from core.downloads import (carried_downloads, copied_outside_files,
                            downloaded_files, pulled_downloads)
from core.shell_scan import _depths, code_mask_checked
from core.sinks import (_NET_TOOL, _PIPE_TO_INTERPRETER, _PIPE_TO_SHELL,
                        _interpreter_runs_stdin)
from core.types import Action, ActionKind, SessionState

_FETCHERS = r"(?:curl|wget|fetch|invoke-webrequest|invoke-restmethod|iwr|irm)\b"
_WEB = re.compile(r"(?i)\b(?:invoke-webrequest|invoke-restmethod|iwr|irm)\b|/dev/(?:tcp|udp)/")
# A command or process substitution whose command downloads.
_FETCHED_TEXT = re.compile(r"(?i)(?:\$\(|`|<\()\s*(?:sudo\s+)?" + _FETCHERS)
# ⚠ `[^\S\n]*`, NEVER `\s*`, AFTER THE SEPARATOR LOOKBEHIND (the reviews): a
# newline is itself a separator, so on a run of blank lines every position
# qualified and `\s*` swallowed the rest of the run each time — quadratic.
# The same, standing where a command starts: its output is run as a command.
_FETCHED_AS_COMMAND = re.compile(
    r"(?i)(?:^|(?<=[;&|\n({]))[^\S\n]*(?:\$\(|`)\s*(?:sudo\s+)?" + _FETCHERS)
_INTERPRETERS = (r"(?:(?:ba|z|k|da|a)?sh|python\d?(?:\.\d+)?|node|perl|ruby|php|deno|bun"
                 r"|pwsh|powershell)")
# A word that runs its argument as code, where a command starts: `-c`/`-e`/
# `-command`, also inside a cluster (`bash -lc`, `sh -ec`), or a here-string.
_RUNNER = re.compile(
    r"(?i)(?:^|(?<=[;&|\n({`]))[^\S\n]*(?:sudo[ \t]+)?(?:eval|source|\.|iex|invoke-expression"
    r"|" + _INTERPRETERS + r"(?:(?:[ \t]+-\w+)*[ \t]+-(?:\w*[ce]|command)\b|[ \t]*<<<))"
    r"(?=[\s\"'$`])")
# A pipe into an interpreter other than a shell or python (`_PIPE_TO_SHELL` and
# `_PIPE_TO_INTERPRETER` read those): from a download, its stdin is the program
# (when it names no script), as with python.
_PIPE_TO_OTHER = re.compile(
    r"\|[ \t]*(?:sudo[ \t]+)?(?:perl|node|ruby|php|deno|bun|pwsh|powershell|osascript"
    r"|lua|tclsh|Rscript)(?![\w-])")
# ⚠ AN ALLOW-LIST, NOT A LIST OF RUNNERS (the second review round): a file the
# same command downloads is RUN by any command but these, which only read,
# hash, list, move or delete it — or write it (the download itself). A wrapper
# (`timeout`, `xargs`, `sudo`), an interpreter nobody listed (`lua`), an
# unpacker (`tar`) all count as running it. Before this pass the download
# alone was refused (`network_egress`), so nothing here is stricter than that.
_INERT = frozenset({
    "cat", "less", "more", "head", "tail", "wc", "ls", "stat", "file", "chmod", "chown",
    "cp", "mv", "rm", "touch", "diff", "cmp", "grep", "egrep", "fgrep", "rg", "test", "[",
    "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "shasum", "md5",
    "md5sum", "b2sum", "jq", "echo", "printf", "curl", "wget", "tee"})
_LEAD = re.compile(r"(?:[ \t({!]|\w+=(?:'[^']*'|\"[^\"]*\"|[^\s'\"]*)[ \t])*")
_WORD = re.compile(r"[^\s;&|()<>]+")
_MAX_RUN_CHECKS = 64
"""More mentions of a downloaded file than this are not read one by one."""
# Where a command starts inside a list: after `;`, `&&`, `||`, a lone `&`, a
# newline, or an opening `(`/`{`/backtick.
_COMMAND_START = re.compile(r"&&|\|\||;|\n|(?<![>&|])&(?![>&])|[({`]")
# Where a pipeline ends: a list separator only, so a pipeline's region takes in
# its process substitutions (`sh <(curl …)`).
_LIST_END = re.compile(r"&&|\|\||;|\n|(?<![>&|])&(?![>&])")


# The readers that pipe a FILE's own bytes; their operands decide.
_FILE_READERS = frozenset({"cat", "head", "tail"})


def _own_file(token: str, action: Action, state: SessionState,
              downloads: frozenset[str], lost: bool = False) -> bool:
    """Is this operand the session's own file, or a file under the project
    roots — and not a download (an earlier one, or one this command makes)?
    `lost`: this command lost track of a download, so any file may be one.

    ⚠ ONLY A PATH THAT CAN BE READ (the reviews): `$`, a backtick or a glob
    cannot; `<<EOF`, `<<<` and `<` are text or a redirect, not a file operand;
    and `..`/`.` are collapsed before anything is compared, or `cat
    /repo/../opt/x.sh` would be "under the roots" and `./a.sh` not the
    download `a.sh`."""
    if any(c in token for c in "$`*?[") or token.startswith("<"):
        return False                                # cannot be read: as before
    path = _norm_path(_abs(_bash_unquote(token), action.cwd))
    if lost or path in downloads or state.downloaded(path) is not False:
        return False
    return bool(state.authored(path)) or is_inside_project(
        path, tuple(action.workspace_roots))


def _runs_a_download(command: str, cwd: str, downloads: frozenset[str], at_code) -> bool:
    """Does this command RUN a file it downloads? Every mention of the file at
    a code position counts, unless the command it is in only reads it
    (`_INERT`) — and even then not inside a substitution (`"$(cat i.sh)"`,
    `$(<i.sh)`: its text is used) or fed in by `<` (`sh < i.sh`).
    `curl -o i.sh … && sh i.sh` was refused with the download
    (`network_egress`) before this pass."""
    if not downloads:
        return False
    scanned = _depths(command)
    if scanned is None:
        return True                                 # cannot be read: as before
    _mask, depth = scanned
    starts = [m.end() for m in _COMMAND_START.finditer(command) if at_code(m.start())]
    checked = 0
    for word in _WORD.finditer(command):
        if not at_code(word.start()) or any(c in word.group(0) for c in "$`"):
            continue
        if _norm_path(_abs(_bash_unquote(word.group(0)), cwd)) not in downloads:
            continue
        checked += 1
        if checked > _MAX_RUN_CHECKS or depth[word.start()] > 0:
            return True                             # too many, or inside a substitution
        k = bisect.bisect_right(starts, word.start())
        begin = starts[k - 1] if k else 0
        # A command that starts a substitution — `$(`, `<(`, a backtick — even
        # where the scanner keeps no depth (inside a `bash -c` body).
        if command[max(0, begin - 2):begin].endswith(("$(", "<(", "`")):
            return True
        lead = _LEAD.match(command, begin)
        verb = _WORD.match(command, lead.end() if lead else begin)
        name = verb.group(0).rsplit("/", 1)[-1] if verb else ""
        if name not in _INERT or command[begin:word.start()].rstrip().endswith("<"):
            return True
    return False


def _own_work(producer: str, action: Action, state: SessionState,
              downloads: frozenset[str], lost: bool) -> bool:
    """Is everything this pipeline feeds its shell the session's own work?

    The maintainer, 30 Sep: ONLY the session's own files, files under the project roots
    (read by `cat`/`head`/`tail`) and its own `git` output. Literal or decoded
    text — `echo`, `printf` escapes, base64, hex, xxd — could have been copied
    from anything the session read, so it keeps today's verdict (G01, G02)."""
    stages = [stage.split() for stage in producer.split("|")]
    stages = [words for words in stages if words]
    if not stages:
        return False                                # `| sh` fed by nothing we read
    for words in stages:
        verb = words[0].rsplit("/", 1)[-1]
        if verb == "git":
            continue
        if verb not in _FILE_READERS:
            return False
        operands = [w for w in words[1:] if not w.startswith("-")]
        if not operands or not all(_own_file(w, action, state, downloads, lost)
                                   for w in operands):
            return False
    return True


def _fetched_text_run(command: str, at_code) -> str | None:
    """A download's output run as code: substituted into a runner's argument in
    the same command, or standing where a command starts."""
    if any(at_code(m.start()) for m in _FETCHED_AS_COMMAND.finditer(command)):
        return "fetched text run as a command"
    fetched = [m.start() for m in _FETCHED_TEXT.finditer(command) if at_code(m.start())]
    if not fetched:
        return None
    ends = [m.start() for m in _LIST_END.finditer(command)]
    runners = [m.start() for m in _RUNNER.finditer(command) if at_code(m.start())]
    for at in fetched:
        k = bisect.bisect_right(ends, at)
        begin = ends[k - 1] if k else -1
        r = bisect.bisect_right(runners, at)
        if r and runners[r - 1] > begin:
            return "fetched text run as code"
    return None


def runs_outside_content(action: Action, state: SessionState) -> str | None:
    """What outside content this action runs, or None.

    None for every action that is not a shell command: a Write, a Read, a fetch
    or an MCP call runs nothing."""
    if action.kind is not ActionKind.EXEC or not action.command:
        return None
    command = action.command
    mask, _parsed = code_mask_checked(command)

    def at_code(at: int) -> bool:
        return at >= len(mask) or bool(mask[at])

    fetched = _fetched_text_run(command, at_code)
    if fetched:
        return fetched
    # A file this same command downloads is a download already (the record of
    # it is made after the verdict): running it, or piping it, is judged so.
    # So is a copy of one this command makes (`cp i.sh j.sh && sh j.sh`; the
    # third review round). An EARLIER download run by this command was not
    # refused before this pass (`sh` alone is no sink), so only this command's
    # own downloads, and what it carries them into, decide a run; a pipe reads
    # every download the session knows of.
    pulled = pulled_downloads(command, action.cwd)
    # Item 3 returns outside SOURCES; carried_downloads follows them to the
    # files this command writes. Seed with them, this command's fetches and
    # pulls, and the session's known downloads (the round-6 reviews).
    outside = copied_outside_files(command, action.cwd, action.workspace_roots, None, state)
    made = set(downloaded_files(command, action.cwd)) | set(pulled.paths)
    seed = made | set(outside.paths)
    made |= set(carried_downloads(command, action.cwd, seed).paths)
    if _runs_a_download(command, action.cwd, frozenset(made), at_code):
        return "a file this command downloads, run"
    known = made | set(state.downloaded_paths)
    carried = carried_downloads(command, action.cwd, known | set(outside.paths))
    # ⚠ A DOWNLOAD THIS COMMAND HANDS TO WHAT CANNOT BE FOLLOWED (`tar xzf i.tgz
    # && cat setup.sh | sh`; the fourth review round): any file may be one.
    return _pipes_run_outside(command, at_code, action, state,
                              frozenset(known | set(carried.paths)),
                              carried.lost or pulled.lost or outside.lost)


def _pipes_run_outside(command: str, at_code, action: Action, state: SessionState,
                       downloads: frozenset[str], lost: bool) -> str | None:
    """A pipe into a shell or an interpreter that runs a download, or that a
    shell is fed by anything but the session's own work. A pipe into perl,
    node, ruby … was gated only with a download in it (`network_egress`), so
    only that is read for them. `lost`: any file may be a download."""
    pipes = [(m.start(), True) for m in _PIPE_TO_SHELL.finditer(command) if at_code(m.start())]
    pipes += [(m.start(), True) for m in _PIPE_TO_INTERPRETER.finditer(command)
              if at_code(m.start()) and _interpreter_runs_stdin(command, m)]
    pipes += [(m.start(), False) for m in _PIPE_TO_OTHER.finditer(command)
              if at_code(m.start()) and _interpreter_runs_stdin(command, m)]
    if not pipes:
        return None
    pipes.sort()
    network = sorted([m.start() for m in _NET_TOOL.finditer(command)]
                     + [m.start() for m in _WEB.finditer(command)])
    starts = [m.end() for m in _COMMAND_START.finditer(command)]
    ends = [m.start() for m in _LIST_END.finditer(command)] + [len(command)]
    read: set[tuple[int, bool]] = set()
    for at, own_work_decides in pipes:
        k = bisect.bisect_right(starts, at)
        begin = starts[k - 1] if k else 0
        if (begin, own_work_decides) in read:
            continue                                # this pipeline was read already
        read.add((begin, own_work_decides))
        end = ends[bisect.bisect_right(ends, at)] if at < ends[-1] else ends[-1]
        n = bisect.bisect_left(network, begin)
        if n < len(network) and network[n] < end:
            return "a download piped into a shell"
        if own_work_decides and not _own_work(command[begin:at], action, state, downloads,
                                              lost):
            return "something other than the session's own work piped into a shell"
    return None


# ═══════════════════════════════════ did the session READ other people's text?
#
# The maintainer, 30 Sep (option 2) and 1 Oct, after X-CHAIN-3 slipped item B: a push
# to an existing remote stays gated when the session read real outside content.
# X-CHAIN-3 pushes a credential split and re-encoded across sessions, so nothing
# in the push looks like a secret; the read of the poisoned issue was the only
# thing that caught it.

# Kinds of `SessionState.untrusted_sources` that are the session's OWN output.
# Every other kind counts — web, mcp, issue, dependency, outside, and
# reference-data in a state saved before docs/113 §3a stopped marking it — and
# so does any kind added later: an unknown kind keeps today's verdict.
_OWN_KINDS = frozenset({"git-history", "git-history-unreadable"})

# Claude Code's own files: its transcripts and saved tool results, under THIS
# session's home directory's `.claude/projects/` — `/HOME` (the engine's `~`),
# or the home the session works under (its cwd or a root). Another repo's
# `.claude/projects/` folder is not one, nor another user's home, nor macOS's
# `/Users/Shared`, which every user may write (the reviews).
_HOME = re.compile(r"(?:/Users/(?!Shared(?:/|$))[^/]+|/home/[^/]+|/root)(?=/|$)")


def _homes(action: Action | None) -> tuple[str, ...]:
    homes = {"/HOME"}
    if action is not None:
        for path in (action.cwd, *action.workspace_roots):
            found = _HOME.match(path or "")
            if found:
                homes.add(found.group(0))
    return tuple(sorted(homes))


def _claude_codes_own(ref: str, homes: tuple[str, ...]) -> bool:
    return any(ref.startswith(home + "/.claude/projects/") for home in homes)


def read_outside_content(state: SessionState, action: Action | None = None) -> bool:
    """Did this session read other people's text, not only its own work?

    Other people's text: a web fetch or search result, a download, an MCP tool
    result, a file outside the roots the session did not write, and the
    in-project kinds — an issue body saved to disk (`PLANTED_CONTENT`), an
    installed dependency. Not: the session's own git output, files it wrote,
    Claude Code's own files, the repository's own files (docs/113 §3a).

    ⚠ WHAT CANNOT BE TOLD COUNTS: an untrusted label with no recorded source
    (a state file read under schema skew is labelled maximally), an authorship
    or download record past its cap. The push then keeps today's verdict."""
    if state.downloaded_paths or state.downloads_truncated:
        return True
    if not state.untrusted_sources:
        return state.untrusted
    homes = _homes(action)
    for source in state.untrusted_sources:
        kind, ref = source.get("kind"), str(source.get("ref") or "")
        if kind in _OWN_KINDS:
            continue
        # Collapsed first: `~/.claude/projects/../../Downloads/x` is not Claude
        # Code's own file (the third review round).
        path = _norm_path(ref) if ref.startswith("/") else ref
        if kind == "outside" and (_claude_codes_own(path, homes)
                                  or state.authored(path) is True):
            continue
        return True
    return False
