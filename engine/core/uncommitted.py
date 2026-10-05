"""Would this command destroy work that is not safely in git?

fix/false-positives, item C (docs/112). The irreversible rule asked on every
`rm -rf`, `shred`, `git reset --hard` and force-push, and on any command whose
TEXT held one (a heredoc writing a file that mentions `rm -rf`): 460 of the
2,132 interruptions in the START snapshot of the maintainer's real sessions.

Now a delete or an overwrite ASKs only when it would destroy content that is
not safely in git — untracked files (ignored ones included: `.env`) and files
with uncommitted changes — and the ask names them. Read at code positions,
each where it runs (its leading `cd`s folded, and `git -C`):

    rm / shred / unlink          what they name
    mv SRC… DST                  DST, when it exists (DST/SRC for a directory)
    `>`, `>|`, `&>`, `2>`        an EXISTING file; a new one loses nothing
    git clean -f (-d, -x, -X)    the untracked (and ignored) files it would remove
    git checkout -- / restore    the uncommitted changes in what they name
    git checkout . / -f, git reset --hard
                                 the uncommitted changes in the repository

No ask for what the session created (a file, or anything under a folder it
made), anything under a declared scratch root, a known regenerable artifact
in the project (`irreversible.REGENERABLE_ARTIFACTS`), or `git push --force`.

Where the targets cannot be read, today's rule answers, its exemptions
included: a delete inside text a shell or an interpreter runs
(`core/deletes_in_text.py`), and one fed by `xargs` or `find -exec`.

The World answers (`World.uncommitted`): only for these commands, only about
these paths, within `GIT_LIMIT` seconds. When it cannot — no answer in time,
no such World, a path the command cannot name — the answer is ASK: never
ALLOW, never DENY. Catastrophic deletes are decided before this and stay DENY.
"""
from __future__ import annotations

import bisect
import re

from core.command_text import (_SEGMENT_END, _SEGMENT_REST, _abs, _bash_unquote, _copy_pairs,
                               _literal_assignments, _norm_path, _segment_end,
                               is_inside_project)
from core.deletes_in_text import delete_in_run_text
from core.irreversible import (_RESET_HARD, _RM_DESTRUCTIVE, _TRUNCATING_TARGET, _cd_bases,
                               _deleted_by, _is_regenerable_artifact, is_irreversible)
from core.shell_scan import code_mask_checked
from core.types import Action, ActionKind, SessionState, World

GIT_LIMIT = 1.0
"""Seconds git may take for one command's paths, all of them together."""

_MAX_OPERATIONS = 64
"""More deletes and overwrites than this in one command are not read one by one."""

_MAX_TARGETS = 256
"""More paths than this are not asked about one by one."""

_EVERYTHING = frozenset({"untracked", "ignored", "modified"})
_CHANGES = frozenset({"modified"})
# `git reset --hard` and `git checkout -f` discard the changes of the whole
# REPOSITORY wherever they run (the reviews): "repository" tells the World to
# ask about all of it, not about the directory the command runs in.
_WHOLE_REPOSITORY = frozenset({"modified", "repository"})

# `/bin/rm` is `rm`: a `/` may come before the name, a word, `.` or `-` not.
# After it a blank, a separator or the end — `… | xargs rm` ends the command.
_DELETE = re.compile(r"(?<![\w.-])(?:rm|shred|unlink)(?=[\s;&|)]|$)")
# `_COPY_VERB`'s shape, where a command starts — with `[^\S\n]*` after the
# separator, not `command_text._CMD_START`'s `\s*`: a newline is itself a
# separator, and on a run of blank lines `\s*` was quadratic (the reviews).
_MOVE = re.compile(r"(?:^|(?<=[;&|\n(])(?<!>\|)(?<![<>]&))[^\S\n]*(mv)\s+(" + _SEGMENT_REST + ")")
_GIT_VERB = re.compile(
    r"(?<![\w./-])git\s+(?:-C\s+(?P<dir>\S+)\s+)?(?P<verb>clean|checkout|restore|reset)\b"
    r"(?P<args>[^;&|\n]*)")
# A delete whose operands arrive from elsewhere — `xargs rm`, `find -exec rm {}`:
# what it deletes is not in the text.
_FED = re.compile(r"(?:(?<![\w-])(?:xargs|parallel)|(?<!\S)-(?:exec|execdir|ok|okdir))"
                  r"(?![\w-])")
_UNREAD = ("this deletes what the command does not name (`xargs`, `find -exec`, or no "
           "operand at all), so whether it is committed cannot be known")
# git's own data: every commit not pushed, every branch, stash and hook.
# `git status -- .git` reports nothing, so it is never "uncommitted work".
_GIT_DATA = re.compile(r"(?:^|/)\.git(?:/|$)")
_GIT_DATA_REASON = ("this deletes git's own data (`.git`): every commit not pushed, and "
                    "every branch, stash and hook in it")
# Counted before anything is read, against `_MAX_OPERATIONS`.
_COUNTED = (_DELETE, _RM_DESTRUCTIVE, _RESET_HARD, _GIT_VERB, _MOVE)

# A word every pattern this module and `deletes_in_text` match contains: `rm`
# (`_DELETE`, `_RM_DESTRUCTIVE`), `shred`, `unlink`, `git` (`_GIT_VERB`,
# `_RESET_HARD`), `mv` (`_MOVE`), `>` (`_TRUNCATING_TARGET`). A command with
# none of them names nothing this reads.
_VERB_WORDS = ("rm", "shred", "unlink", "git", "mv", ">")


def _operations(command: str) -> int:
    """How many deletes and overwrites the shell runs here — at CODE positions
    (the mask is linear and cached): a heredoc'd file full of `>` comparisons
    or `rm` examples is data, and `2>/dev/null` destroys nothing. A delete in
    text is bounded where it is read (`deletes_in_text._MAX_HITS`)."""
    mask, _parsed = code_mask_checked(command)

    def at_code(at: int) -> bool:
        return at >= len(mask) or bool(mask[at])

    count = sum(1 for pattern in _COUNTED for m in pattern.finditer(command)
                if at_code(m.start()))
    return count + sum(1 for m in _TRUNCATING_TARGET.finditer(command)
                       if at_code(m.start()) and not m.group(1).startswith("/dev/"))


def _here(directory: str) -> str:
    """A directory's own contents as a target — `<dir>/.`, what `git checkout .`
    resolves to — so git is asked inside it, not in its parent."""
    return directory.rstrip("/") + "/."


def _bases(command: str, starts: list[int], cwd: str) -> dict[int, str]:
    """The directory each position runs in, its leading `cd`s folded."""
    starts = sorted(set(starts))
    if not starts:
        return {}
    return dict(zip(starts, _cd_bases(command, starts, cwd, _literal_assignments(command))))


def _git_targets(command: str, cwd: str, at_code) -> list[tuple[str, frozenset]]:
    """(path, what would be lost there) for each git verb that discards work."""
    found: list[tuple[str, frozenset]] = []
    matches = [m for m in _GIT_VERB.finditer(command) if at_code(m.start())]
    bases = _bases(command, [m.start() for m in matches], cwd)
    for match in matches:
        base = bases[match.start()]
        if match.group("dir"):
            base = _abs(_bash_unquote(match.group("dir")), base)
        found += _git_verb_targets(match.group("verb"), match.group("args"), base)
    return found


def _git_verb_targets(verb: str, args: str, base: str) -> list[tuple[str, frozenset]]:
    words = [_bash_unquote(w) for w in args.split()]
    flags = "".join(w[1:] for w in words if w.startswith("-") and not w.startswith("--"))
    longs = {w.split("=", 1)[0] for w in words if w.startswith("--")}
    if "--" in words:
        paths = words[words.index("--") + 1:]
    else:
        paths = [w for w in words if not w.startswith("-")]
    if verb == "clean":
        if "n" in flags or "--dry-run" in longs or not ("f" in flags or "--force" in longs):
            return []                       # a dry run, or git's own refusal without -f
        kinds = (frozenset({"ignored"}) if "X" in flags
                 else frozenset({"untracked", "ignored"}) if "x" in flags
                 else frozenset({"untracked"}))
        return [(_path(p, base), kinds) for p in paths] or [(_here(base), kinds)]
    if verb == "reset":
        return [(_here(base), _WHOLE_REPOSITORY)] if "--hard" in longs else []
    if verb == "restore":
        if ("--staged" in longs or "S" in flags) and not ("--worktree" in longs or "W" in flags):
            return []                       # the index only: the file on disk stays
        return [(_path(p, base), _CHANGES) for p in paths if not p.startswith("--source")]
    if "f" in flags or "--force" in longs:  # checkout
        return [(_here(base), _WHOLE_REPOSITORY)]
    return [(_path(p, base), _CHANGES) for p in paths]


def _path(word: str, base: str) -> str:
    """An operand as an absolute path, `..` and `.` collapsed — so it cannot
    borrow an exemption by its spelling (`newdir/../modified.txt`). A git
    pathspec of `.` or a folder spelled with its `/` names that folder's
    contents (`_here`), asked inside it."""
    path = _norm_path(_abs(word, base))
    return _here(path) if word in (".", "./") or word.endswith("/") else path


def _deletes(command: str, cwd: str, at_code) -> tuple[list[tuple[str, frozenset]], bool]:
    """(what the deletes name, whether a delete names nothing that can be read).
    A delete whose operands arrive from `xargs` or `find -exec` — with or
    without `-r`/`-f` (the reviews) — or one of today's `rm -r`/`rm -f`/`shred`
    that names nothing readable: whether what it deletes is committed cannot be
    known."""
    seps = [m.start() for m in _SEGMENT_END.finditer(command) if at_code(m.start())]
    found: list[tuple[str, frozenset]] = []
    read: dict[int, int | None] = {}        # verb -> where its reading ends (None: fed)
    for verb in _DELETE.finditer(command):
        at = verb.start()
        if at_code(at):
            k = bisect.bisect_left(seps, at)
            if _FED.search(command, seps[k - 1] + 1 if k else 0, at):
                read[at] = None
    for verb, path in _deleted_by(command, cwd, _DELETE, at_code):
        at = verb.start()
        if at not in read:                  # once per verb: a verb has many operands
            read[at] = _segment_end(command, verb.end())
        if read[at] is not None:
            found.append((path, _EVERYTHING))
    if any(end is None for end in read.values()):
        return found, True
    spans = list(read.items())
    unread = any(at_code(m.start()) and not any(s <= m.start() < e for s, e in spans)
                 for m in _RM_DESTRUCTIVE.finditer(command))
    return found, unread


def _overwrites(command: str, cwd: str, at_code, world: World) -> list[tuple[str, frozenset]]:
    """`mv` onto, and `>` into, a file that is already there.

    ⚠ AN OVERWRITE LOSES SOMETHING ONLY WHERE A FILE ALREADY IS. A World that
    cannot say whether it is there (`exists` None) keeps today's answer for `>`
    and `mv`, which never asked; a delete is asked about either way."""
    exists = getattr(world, "exists", None)
    is_directory = getattr(world, "is_directory", None)
    if exists is None:
        return []
    found: list[tuple[str, frozenset]] = []
    moves = [m.start() for m in _MOVE.finditer(command) if at_code(m.start(1))]
    redirects = [m for m in _TRUNCATING_TARGET.finditer(command)
                 if at_code(m.start()) and not m.group(1).startswith("/dev/")]
    bases = _bases(command, moves + [m.start() for m in redirects], cwd)
    for base in sorted({bases[at] for at in moves}):
        for at, src, dst in _copy_pairs(command, base, _MOVE, at_code):
            if bases.get(at) != base:
                continue
            dst = _norm_path(dst)
            if is_directory is not None and is_directory(dst):
                dst = f"{dst.rstrip('/')}/{src.rstrip('/').rsplit('/', 1)[-1]}"
            if exists(dst):
                found.append((dst, _EVERYTHING))
            if _GIT_DATA.search(_norm_path(src)):
                found.append((_norm_path(src), _EVERYTHING))      # moving `.git` away
    for match in redirects:
        path = _path(_bash_unquote(match.group(1)), bases[match.start()])
        if not path.startswith("/dev/") and exists(path):
            found.append((path, _EVERYTHING))
    return found


def _targets(action: Action, world: World) -> tuple[list[tuple[str, frozenset]], bool]:
    command, cwd = action.command or "", action.cwd
    mask, _parsed = code_mask_checked(command)

    def at_code(at: int) -> bool:
        return at >= len(mask) or bool(mask[at])

    found, unread = _deletes(command, cwd, at_code)
    found += _overwrites(command, cwd, at_code, world)
    return found + _git_targets(command, cwd, at_code), unread


def _exempt(path: str, state: SessionState, action: Action, world: World) -> bool:
    """Created by this session (the path or a folder above it, when it was not
    there before: `SessionState.created_paths`), under a declared scratch root,
    or a regenerable artifact in the project. Compared collapsed, so `..`
    borrows nothing (the reviews)."""
    path = _norm_path(path)
    roots = tuple(_norm_path(root) for root in state.scratch_roots)
    if roots and is_inside_project(path, roots):
        return True
    # The path, or a folder above it, among what the session created — tested
    # against that (capped) set, not by walking up the path: a `cd` repeated
    # makes a path as long as the command, and a walk per level was cubic.
    bare = path.rstrip("/")
    if any(bare == made or bare.startswith(made.rstrip("/") + "/")
           for made in state.created_paths):
        return True
    return _is_regenerable_artifact(path, tuple(action.workspace_roots), world)


def _shown(paths: list[str], cwd: str) -> str:
    prefix = cwd.rstrip("/") + "/"
    names = [p[len(prefix):] if p.startswith(prefix) else p for p in paths]
    listed = ", ".join(names[:3])
    return listed + ("…" if len(names) > 3 else "")


def destroys_uncommitted_work(action: Action, state: SessionState,
                              world: World) -> str | None:
    """Why this action would destroy work that is not in git, or None."""
    if action.kind is not ActionKind.EXEC or not action.command:
        return None
    command = action.command
    # Most commands name none of the verbs this reads: say so in a few
    # substring scans, not six regex passes (the bench's long exec: +1.4 ms).
    if not any(word in command for word in _VERB_WORDS):
        return None
    # ⚠ BOUNDED BEFORE ANYTHING IS RESOLVED: each `cd` a command repeats makes
    # the paths after it longer, so reading hundreds of deletes is quadratic in
    # the text. Past these counts the answer is the one for "cannot tell": ASK.
    operations = _operations(command)
    if operations > _MAX_OPERATIONS:
        return f"this deletes or overwrites in more places ({operations}) than can be checked"
    found, unread = _targets(action, world)
    if unread:
        return _UNREAD
    # ⚠ A DELETE INSIDE TEXT A SHELL RUNS: today's rule answers, its exemptions
    # included (a declared scratch root, a regenerable artifact).
    hidden = delete_in_run_text(command)
    if hidden and is_irreversible(action, world, tuple(state.scratch_roots)):
        return hidden
    if len(found) > _MAX_TARGETS:
        return f"this deletes or overwrites more paths ({len(found)}) than can be checked"
    if any(_GIT_DATA.search(path) for path, _kinds in found):
        return _GIT_DATA_REASON
    # A whole-repository verb is never exempted by where it runs (a created
    # folder, a scratch root inside the repository): only git's answer about
    # it is, path by path, in `_ask_git` (the second review round).
    targets = [(path, kinds) for path, kinds in found
               if "repository" in kinds or not _exempt(path, state, action, world)]
    if not targets:
        return None
    if any(_unnamed(path) for path, _kinds in targets):
        return ("this destroys paths the command names through a variable, a "
                "substitution, `~` or a git pathspec, so whether they are committed "
                "cannot be known")
    return _ask_git(targets, state, action, world)


def _unnamed(path: str) -> bool:
    """A path the engine cannot resolve on disk: a variable or a substitution;
    `~` (`/HOME` to the engine, which may not read the environment); a git
    pathspec's magic (`:/`, `:(top)`, `:(glob)…`), which git reads as more
    than the name."""
    return ("$" in path or "`" in path or path == "/HOME" or path.startswith("/HOME/")
            or "/:" in path)


def _ask_git(targets: list[tuple[str, frozenset]], state: SessionState, action: Action,
             world: World) -> str | None:
    """Git's answer about these targets, within `GIT_LIMIT`: why, or None."""
    ask = getattr(world, "uncommitted", None)
    if ask is None:
        return "git could not say whether this destroys uncommitted work"
    answer = ask(tuple(dict.fromkeys(targets)), action.cwd, GIT_LIMIT)
    if answer is None:
        return "git could not say in time whether this destroys uncommitted work"
    lost = list(dict.fromkeys(p for p in answer if not _exempt(p, state, action, world)))
    if not lost:
        return None
    noun, verb = ("path", "isn't") if len(lost) == 1 else ("paths", "aren't")
    return (f"this destroys work that is not in git — {len(lost)} {noun} here "
            f"{verb} committed: {_shown(lost, action.cwd)}")
