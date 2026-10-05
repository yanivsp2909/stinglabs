"""A delete written inside TEXT: data, or code that something runs?

fix/false-positives, item C (docs/112). `core/uncommitted.py` reads what a
command deletes where the shell runs it — at CODE positions. Today's
irreversible rule read the whole text, so `rm -rf` or `git reset --hard`
anywhere asked: in a file a heredoc writes, in an `echo`, in a commit message.
It also asked inside text that a shell or an interpreter runs but that the
scanner reads as data — `bash -lc '…'`, `eval "…"`, `ssh host '…'`,
`python3 - <<EOF`. What that code deletes cannot be read, so there the answer
stays today's: ASK. Only text that is DATA, and stays data in this command,
is let go:

    a heredoc read by cat, tee, git or gh
    an argument of echo, printf, cat or tee
    a grep or rg pattern, a commit or tag message (`quoted_text_view`)

— directly inside a top-level quote or heredoc (never inside a `$( )`), and
only when what holds it is not piped on into anything but a reader (`head`,
`grep`, `wc`…) and does not write a file the same command names again
(`cat > x.sh <<EOF … EOF && bash x.sh`). Anything else: ASK.
"""
from __future__ import annotations

import bisect
import re

from core.command_text import _REDIRECT_TARGET, _bash_unquote
from core.irreversible import _RESET_HARD, _RM_DESTRUCTIVE
from core.shell_scan import _depths, code_mask_checked, quoted_text_view

_TODAYS = (_RM_DESTRUCTIVE, _RESET_HARD)
"""Today's text patterns that delete work (a force-push no longer asks)."""

_MAX_HITS = 64
"""More deletes in text than this are not read one by one: ASK."""

_RUN_TEXT = ("this deletes inside text that a shell or an interpreter runs (`bash -lc`, "
             "`eval`, `ssh`, a heredoc fed to one), so what it deletes cannot be checked "
             "against git")

_HEREDOC_READERS = frozenset({"cat", "tee", "git", "gh"})
_PRINTERS = frozenset({"echo", "printf", "cat", "tee"})
_READERS = frozenset({"head", "tail", "wc", "grep", "egrep", "fgrep", "rg", "sort",
                      "uniq", "less", "more", "cat", "cut", "tr", "column", "nl"})

_SEPARATOR = re.compile(r"[;&|\n]")
_LEAD = re.compile(r"(?:[ \t({!]|\w+=(?:'[^']*'|\"[^\"]*\"|[^\s'\"]*)[ \t])*")
_WORD = re.compile(r"[^\s;&|()<>'\"]+")
_HEREDOC = re.compile(r"(?<!<)<<(?!<)")            # not a `<<<` here-string
# A name as `_names_again` compares one: what lies between `/` and blanks.
_NAME = re.compile(r"[^\s/;&|()<>'\"=]+")
_TEE = re.compile(r"(?<![\w./-])tee(?=[ \t])")


def _separates(command: str, at: int) -> bool:
    """`_SEGMENT_END`'s exceptions: `>|` and `2>&1` / `&>` are redirects."""
    c, before = command[at], command[at - 1] if at else ""
    if c == "|" and before == ">":
        return False
    if c == "&" and (before in "<>" or command[at + 1:at + 2] == ">"):
        return False
    return True


def _word_at(command: str, at: int) -> str:
    """The command word of the segment starting at `at`, as a bare name."""
    lead = _LEAD.match(command, at)
    word = _WORD.match(command, lead.end() if lead else at)
    return word.group(0).rsplit("/", 1)[-1] if word else ""


def _names_again(command: str, mask, start: int, end: int) -> bool:
    """Does [start, end) — a pipeline, every stage of it — write a file this
    command names after it?"""
    segment = command[start:end]
    written = [m.group("target") for m in _REDIRECT_TARGET.finditer(segment)
               if mask[start + m.start()]]
    # ⚠ SPLIT ONCE, after the first `tee` the shell runs (the second review
    # round): every later `tee`'s operands are among those words, and
    # re-splitting the rest of the segment at each one was quadratic.
    tee = next((t for t in _TEE.finditer(segment) if mask[start + t.start()]), None)
    if tee is not None:
        written += [w for w in segment[tee.end():].split() if not w.startswith("-")]
    names = {_bash_unquote(t).rsplit("/", 1)[-1] for t in written
             if not t.startswith(("&", "/dev/"))} - {""}
    if not names:
        return False
    # ⚠ ONE SCAN FOR ALL OF THEM (the reviews): a regex per written name, each
    # over the rest of the command, was quadratic in the names a segment writes.
    return any(mask[m.start()] and m.group(0) in names
               for m in _NAME.finditer(command, end))


def _pipeline(command: str, seps: list[int], end: int) -> tuple[bool, int]:
    """From the holding segment's `end`: (whether the pipeline goes on into
    anything but readers, where the pipeline ends). Every stage is read, to
    the end: `| cat | sh` runs it, `| cat > r.sh` writes it (the reviews)."""
    while end < len(command) and command[end] == "|" and command[end + 1:end + 2] != "|":
        if _word_at(command, end + 1) not in _READERS:
            return True, end
        k = bisect.bisect_right(seps, end)
        end = seps[k] if k < len(seps) else len(command)
    return False, end


def _stays_data(command: str, mask, depth, seps: list[int], hit: int,
                held: dict[tuple[int, int], bool]) -> bool:
    """Is the delete at `hit` (a data byte) text that nothing in this command
    runs? `held` remembers each holding segment's answer about its output."""
    q = mask.rfind(1, 0, hit)
    heredoc = q >= 0 and command[q] == "\n"
    anchor = hit
    if heredoc:
        line = command.rfind("\n", 0, q) + 1
        openers = [m.start() for m in _HEREDOC.finditer(command, line, q) if mask[m.start()]]
        # One heredoc on the line: its body is the stdin of the segment that
        # opens it. With two, which body is whose is not read here.
        if depth[q] != 0 or len(openers) != 1:
            return False
        anchor = openers[0]
    k = bisect.bisect_left(seps, anchor)
    start = seps[k - 1] + 1 if k else 0
    end = seps[k] if k < len(seps) else len(command)
    word = _word_at(command, start)
    if heredoc:
        if word not in _HEREDOC_READERS:
            return False
    else:
        view = quoted_text_view(command)
        is_text = view[hit] == "x" and command[hit] != "x"
        if depth[hit] != 1 or not (word in _PRINTERS or is_text):
            return False
    if (start, end) not in held:
        runner, last = _pipeline(command, seps, end)
        held[(start, end)] = not runner and not _names_again(command, mask, start, last)
    return held[(start, end)]


def delete_in_run_text(command: str) -> str | None:
    """Why a delete written inside this command's text keeps today's ASK, or None.

    None also when the command did not parse: its mask is then all code, and
    `core/uncommitted.py` reads every delete in it as one the shell runs."""
    mask, parsed = code_mask_checked(command)
    hits = sorted(m.start() for pattern in _TODAYS for m in pattern.finditer(command)
                  if parsed and not mask[m.start()])
    if not hits:
        return None
    if len(hits) > _MAX_HITS:
        return _RUN_TEXT
    scanned = _depths(command)
    if scanned is None:
        return None
    mask, depth = scanned
    seps = [m.start() for m in _SEPARATOR.finditer(command)
            if mask[m.start()] and depth[m.start()] == 0 and _separates(command, m.start())]
    held: dict[tuple[int, int], bool] = {}
    for hit in hits:
        if not _stays_data(command, mask, depth, seps, hit, held):
            return _RUN_TEXT
    return None
