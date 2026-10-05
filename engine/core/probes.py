"""
The real World. The only module in core/ that touches the machine.

Everything the engine needs from outside itself comes through here, so the
engine stays a pure function and the whole policy is testable with a fake.

Latency matters: this runs inside a PreToolUse hook with a p99 budget of 12 ms
(criterion A6). `read_text` is cheap and only called when an action already
matched a credential path. `staged_files` and `staged_content` shell out to git and
are called ONLY on the git_push / git_new_remote sinks — never in the ~97% of
calls that touch no sink at all.
"""
from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import time as _time
from pathlib import Path

# Big enough for any config file, small enough that a stray multi-GB file
# cannot stall the hook.
_MAX_READ = 4 * 1024 * 1024
_GIT_TIMEOUT = 3.0
# `uncommitted` runs one `git status` per directory its targets sit in; past
# this many directories it does not try, and the answer is ASK (docs/112).
_MAX_GIT_GROUPS = 8
# A glob a delete names is expanded here; past this many paths it is not read
# one by one, and the answer is ASK.
_MAX_GLOB = 256
_MAX_GLOB_LEVELS = 2
"""Path components a glob may make wild before it is not walked: ASK."""
# What a delete or an overwrite asks about: everything not committed.
_DELETED = frozenset({"untracked", "ignored", "modified"})
# git's own data — `git status` never reports it (see `core/uncommitted.py`).
_GIT_DATA = re.compile(r"(?:^|/)\.git(?:/|$)")


def _expanded(target: str, deadline: float) -> list[str] | None:
    """The paths a target names: itself when it is there (also when it holds
    `*?[` — `app/[id]` is a real folder's name, and a glob of it matches
    nothing), and a glob's matches — at most `_MAX_GLOB`, within the deadline,
    and with at most `_MAX_GLOB_LEVELS` wild path components, since a glob
    that matches nothing in a wide tree yields nothing to check a deadline
    by. None: cannot say."""
    literal = [target] if os.path.lexists(target) else []
    if not any(c in target for c in "*?["):
        return literal
    if sum(any(c in part for c in "*?[") for part in target.split("/")) > _MAX_GLOB_LEVELS:
        return None
    paths: list[str] = literal
    for path in glob.iglob(target):
        if len(paths) >= _MAX_GLOB or _time.monotonic() > deadline:
            return None
        if path != target:
            paths.append(path)
    return paths


def _toplevel(directory: str) -> str | None:
    """The repository root above `directory`: where a `.git` is (a folder, or
    a worktree's file). git's `-z` output names paths from there."""
    path = os.path.abspath(directory)
    while True:
        if os.path.lexists(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def _git_environment() -> dict[str, str]:
    """The caller's environment without its `GIT_*` (a `GIT_DIR` or
    `GIT_INDEX_FILE` would point git elsewhere) — except a discovery ceiling,
    which only ever stops git sooner — and with literal pathspecs, no
    optional locks and C messages."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") or k == "GIT_CEILING_DIRECTORIES"}
    env.update(GIT_LITERAL_PATHSPECS="1", GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    return env


def _git_status(directory: str, kinds: frozenset, paths: list[str],
                deadline: float) -> list[str] | None:
    """`git status` in `directory`, about `paths` (or, with the kind
    "repository", about the whole repository): what of `kinds` is lost."""
    remaining = deadline - _time.monotonic()
    if remaining <= 0:
        return None
    whole = "repository" in kinds
    argv = ["git", "--no-optional-locks", "-C", directory, "-c", "core.fsmonitor=false",
            "-c", "core.untrackedCache=false", "status", "--porcelain=v1", "-z",
            "--ignored=matching", "--untracked-files=normal"]
    if not whole:
        argv += ["--", *("." if p.endswith("/.") else os.path.basename(p.rstrip("/")) or "."
                         for p in paths)]
    try:
        proc = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL,
                              timeout=remaining, env=_git_environment())
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if proc.returncode != 0:
        if b"not a git repository" in (proc.stderr or b""):
            return [] if whole else list(paths)     # exists, and git holds none of it
        return None
    top = _toplevel(directory)
    if top is None:
        return None
    return _lost_in(os.fsdecode(proc.stdout or b""), kinds, top)


def _lost_in(output: str, kinds: frozenset, top: str) -> list[str]:
    """The entries of `git status --porcelain=v1 -z` of `kinds`, as absolute
    paths: git names them from the repository root, whatever the directory."""
    lost: list[str] = []
    skip = False
    for entry in output.split("\0"):
        if skip:                                    # a rename's second (old) path
            skip = False
            continue
        if len(entry) < 4:
            continue
        code, name = entry[:2], entry[3:]
        skip = code[0] in "RC"
        kind = "untracked" if code == "??" else "ignored" if code == "!!" else "modified"
        if kind in kinds:
            path = os.path.normpath(os.path.join(top, name))
            lost.append(path + "/" if name.endswith("/") else path)
    return lost


def split_roots(value: str, sep: str | None = None) -> list[str]:
    r"""Split a PATH-style list the way THIS platform writes one.

    ⚠ `":"` SHATTERS A WINDOWS PATH. `C:\proj` splits into `["C", "\proj"]` —
    two directories that do not exist — so `STING_ROOTS` resolved to nothing,
    the project had no roots, and every write was outside it. Silent: the
    fallback to the working directory looks like a normal session.

    `os.pathsep` is `;` on Windows and `:` on POSIX, which is the whole fix.
    The separator is a PARAMETER so a test can drive both without pretending to
    be another operating system.
    """
    return [part for part in value.split(sep or os.pathsep) if part]


def join_roots(paths, sep: str | None = None) -> str:
    r"""The INVERSE of `split_roots`, and it exists because three places wrote
    the inverse by hand with `":".join(...)`.

    ⚠ A SPLITTER WITHOUT A JOINER GETS A HAND-WRITTEN JOINER, AND IT WILL BE
    WRONG. `split_roots` was fixed to `os.pathsep` in the Windows port; the
    three places that BUILD such a value were not, because nothing pointed at
    them. Measured on the first native Windows install:

        installer/detect.py   proposed  C:\a:C:\b   -> install.py wrote a
                                                       trust boundary that
                                                       `split_roots` reads as
                                                       ONE path that does not
                                                       exist
        tools/preflight.py    printed   export STING_ROOTS='C:\a:C:\b' — a
                                        colon separator, on Windows, in the
                                        remediation for a check that exists to
                                        catch colon separators on Windows

    One function, so the two halves cannot disagree again.
    """
    return (sep or os.pathsep).join(str(p) for p in paths)



_UNSET = object()


class RealWorld:
    """Reads the actual filesystem and the actual git index."""

    def __init__(self, environ: dict | None = None) -> None:
        # Per-root case answers, cached for this process. Bounded by the number
        # of workspace roots (1–4 in every session measured), never by actions.
        self._case: dict[str, bool | None] = {}
        self._sync = _UNSET
        self._environ = dict(environ) if environ else {}

    def environment(self) -> dict[str, str]:
        """The environment the HOOK was started with, as its caller handed it
        (item B, docs/110 §B): `hook_entry.main` and `sting_hook.main` take it
        before `~/.sting/env` is loaded, and the daemon receives its caller's
        with the request.

        ⚠ NEVER `os.environ`. In the daemon that is the environment the DAEMON
        booted with — another process's — and in any hook it holds what Sting
        loaded for itself. `{}` when nobody handed one over."""
        return dict(self._environ)

    def sync_roots(self) -> tuple[str, ...] | None:
        r"""Every cloud-sync root on this machine, cached for the process.

        ⚠ WHAT IS ACTUALLY DETECTED, AND WHY NOT A NAME MATCH. `~/OneDrive` is
        renamed per tenant (`OneDrive - Acme`), iCloud lives at
        `~/Library/Mobile Documents/com~apple~CloudDocs`, and Dropbox records
        its real location in `~/.dropbox/info.json` — a user who moved it to
        `/Volumes/work/Dropbox` matches no name pattern at all.

        So: the two that PUBLISH their location are read from their own config
        (Dropbox's `info.json`, iCloud's fixed container path), and the two that
        do not are matched by directory PREFIX under $HOME, which is where their
        installers put them.

        ⚠ WHAT IT COSTS WHEN SOMEBODY'S DROPBOX IS ELSEWHERE: nothing, if
        `info.json` is present — that is the point of reading it. If a client
        moved a folder and left no config, the root is MISSED and a copy into it
        is allowed. That under-denies, which is the direction this carrier is
        allowed to fail in, and it is why `None` is quiet here.
        """
        if self._sync is not _UNSET:
            return self._sync
        found: list[str] = []
        home = Path.home()
        try:
            # Dropbox publishes its real path, wherever the user moved it.
            info = home / ".dropbox" / "info.json"
            if info.is_file():
                for entry in json.loads(info.read_text(encoding="utf-8")).values():
                    path = (entry or {}).get("path")
                    if path:
                        found.append(str(Path(path)))
            # iCloud's container is a fixed location.
            icloud = home / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
            if icloud.is_dir():
                found.append(str(icloud))
            # OneDrive and Google Drive: per-tenant names, so match the prefix
            # where their installers put them.
            for child in home.iterdir():
                if not child.is_dir():
                    continue
                name = child.name.lower()
                if (name.startswith("onedrive") or name.startswith("google drive")
                        or name.startswith("googledrive")):
                    found.append(str(child))
        except OSError:
            # ⚠ UNKNOWN, and unknown is QUIET here. See World.sync_roots.
            self._sync = None
            return None
        # ⚠ BOTH SPELLINGS, because `engine._abs` maps a leading `~` to the
        # literal `/HOME` rather than expanding it — the engine may not know a
        # home directory, since knowing one is IO. A root under $HOME is
        # therefore reachable as `/Users/x/OneDrive` OR `/HOME/OneDrive`, and a
        # sink that only knew the first would miss `cp .env ~/OneDrive/...`,
        # which is the form a human actually types.
        both: list[str] = []
        for path in dict.fromkeys(found):
            both.append(path)
            try:
                both.append("/HOME/" + str(Path(path).relative_to(home)))
            except ValueError:
                pass
        self._sync = tuple(dict.fromkeys(both))
        return self._sync

    def case_insensitive(self, root: str) -> bool | None:
        """Ask the filesystem, once per root, by CREATING A PROBE FILE.

        ⚠ NOT `platform.system()`. "Windows means case-insensitive" is false on
        any directory with `setCaseSensitiveInfo` set — which is every directory
        WSL creates — and "Darwin means case-insensitive" is false on a
        case-sensitive APFS volume. Both are configurations developers actually
        run, and a wrong answer here is silent in both directions.

        ⚠ NOT `os.path.exists(root.upper())` EITHER. That answers a different
        question: whether an upper-cased *sibling* happens to exist. On a
        case-sensitive filesystem holding both `Src/` and `src/` it says
        "insensitive", which is exactly backwards.

        So: write a lower-case probe, stat the upper-case name. Same inode means
        one file means insensitive. The probe is created and removed inside this
        call, in the root the caller already writes to.

        Cost: one create + one stat + one unlink, ONCE PER ROOT PER PROCESS.
        A session resolves 1–4 roots, so this is bounded by the workspace and
        not by the number of actions — the same shape as project_roots.
        """
        # ⚠ `.get(root, _UNSET)` — AND THE DEFAULT IS THE WHOLE POINT. This
        # was `.get(root)`, which returns None for a MISSING key while None is
        # also a legitimate ANSWER ("could not tell"). So the sentinel could
        # never fire, every call returned None before probing anything, and the
        # detection silently never ran. The same absent-versus-present collision
        # this project has now found in `purpose`, in `chain_continuous` and
        # here — a tri-state read through an API with a two-state default.
        cached = self._case.get(root, _UNSET)
        if cached is not _UNSET:
            return cached

        answer: bool | None = None
        probe = Path(root) / f".sting-case-probe-{os.getpid()}"
        try:
            probe.write_text("", encoding="utf-8")
            try:
                upper = probe.with_name(probe.name.upper())
                # ⚠ SAME INODE, NOT "BOTH EXIST". On Windows `st_ino` is
                # meaningful for a real file, and comparing the stat results
                # rather than the names is what distinguishes "one file with two
                # spellings" from "two files".
                answer = (upper.exists()
                          and upper.stat().st_ino == probe.stat().st_ino)
            finally:
                probe.unlink()
        except OSError:
            # ⚠ UNKNOWN, AND SAID SO. A read-only root, a permission error, a
            # full disk. Returning False here would be a GUESS wearing the
            # costume of a measurement, and the engine's conservative default
            # already covers None.
            answer = None

        self._case[root] = answer
        return answer

    def read_text(self, path: str) -> str | None:
        try:
            p = Path(path)
            # ⚠ `/HOME` IS THE ENGINE'S PLACEHOLDER FOR `~` AND `$HOME`, and the
            # home directory is resolved HERE, at the IO boundary, because the
            # engine may not read the environment (item 5, docs/94). Asked for
            # `/HOME/.aws/credentials` literally, this found nothing, so
            # `cat ~/.aws/credentials` never armed the session while the absolute
            # spelling of the same file did. A file really at the literal path
            # is still read first; only a miss falls through to the home.
            # A `..` part is refused rather than resolved (security review): the
            # engine normalises before it asks, so none should arrive, and one
            # that did must not walk out of the home directory.
            if (not p.is_file() and (path == "/HOME" or path.startswith("/HOME/"))
                    and ".." not in Path(path).parts):
                p = Path.home() / path[len("/HOME/"):]
            if not p.is_file():
                return None
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                return fh.read(_MAX_READ)
        except OSError:
            return None

    def _git(self, cwd: str, *args: str) -> str | None:
        try:
            proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                                   text=True, timeout=_GIT_TIMEOUT)
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout if proc.returncode == 0 else None

    def project_roots(self, cwd: str) -> tuple[tuple[str, ...], str | None]:
        """Every directory that counts as "the project". Returns (roots, note).

        `note` is None when the answer is confident and a sentence when it is a
        FALLBACK; hook_entry surfaces it on stderr. Silence is what let
        `workspace_roots: null` sit unnoticed through 181 actions of a real
        session, denying 44 writes to sibling repositories with the reason
        "this destination leaves the machine".

        WHAT EACH GIT LAYOUT RESOLVES TO — established by probing git, not by
        reading its documentation:

          plain repo        `--show-toplevel`, the repo root.
          linked worktree   the WORKTREE's own root; `--show-toplevel` already
                            returns it. The main worktree is deliberately NOT
                            added — it is a different checkout of the same
                            repository, usually on a different branch, and
                            adding it would make an edit in one branch look
                            like ordinary work in another.
          submodule         the OUTERMOST superproject, walked up through
                            `--show-superproject-working-tree`. A submodule is
                            part of its parent and editing both is normal work.
                            Bounded: it terminates at the top of the nesting.
          bare repo         no working tree exists, so there is no project
                            directory at all. cwd, with a note.
          not a repo        cwd, with a note.
          git missing       cwd, with a note.

        NOT THE GIT ROOT'S PARENT. That is the obvious way to make sibling
        repositories one project, and it is wrong: for anyone who keeps their
        work under one directory it makes every unrelated repository part of
        the project and `write_outside` nearly unreachable. It trades a false
        positive for a false negative, and only one of those is visible when it
        happens. Widening past the repository is what STING_ROOTS is for.
        """
        override = os.environ.get("STING_ROOTS")
        if override:
            roots = tuple(str(Path(p).resolve()) for p in split_roots(override)
                          if Path(p).is_dir())
            if roots:
                return roots, None
            return (str(Path(cwd).resolve()),), (
                f"sting: STING_ROOTS names no existing directory ({override!r}); "
                f"falling back to the working directory")

        top = self._git(cwd, "rev-parse", "--show-toplevel")
        if not top or not top.strip():
            bare = self._git(cwd, "rev-parse", "--is-bare-repository")
            why = ("this is a bare repository, which has no working tree"
                   if bare and bare.strip() == "true"
                   else "this directory is not in a git repository")
            return (str(Path(cwd).resolve()),), (
                f"sting: project root unknown — {why}; treating only {cwd} as "
                f"the project. Set STING_ROOTS to widen it.")

        root = top.strip()
        # Climb out of any submodule nesting to the outermost superproject.
        for _ in range(8):                    # a bound, not a guess at depth
            parent = self._git(root, "rev-parse",
                                "--show-superproject-working-tree")
            if not parent or not parent.strip():
                break
            root = parent.strip()
        return (str(Path(root).resolve()),), None

    def staged_files(self, cwd: str) -> tuple[str, ...] | None:
        """What is ACTUALLY in the index, as absolute paths.

        `git diff --cached --name-only` rather than a staged list we maintained
        ourselves — CLAUDE.md rule #7. Ours would miss `git add -f` on an
        ignored file and would wrongly include a path that .gitignore dropped.

        None means the index could not be inspected; () means it was inspected
        and is empty. The caller must treat those differently.
        """
        out = self._git(cwd, "diff", "--cached", "--name-only")
        if out is None:
            return None
        names = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if not names:
            # NOTHING STAGED, so there are no relative names to resolve and no
            # reason to ask where the repository root is. Measured: each git
            # call costs ~12 ms on this machine — spawn, not work, since
            # `rev-parse` is as expensive as a full `diff --cached` — and a
            # clean index is the common case for a push. This is a derivation,
            # not a cache: it cannot go stale, because it follows from a result
            # that was just read fresh.
            return ()
        root = self._git(cwd, "rev-parse", "--show-toplevel")
        base = Path((root or cwd).strip())
        paths = []
        for name in names:
            try:
                paths.append(str((base / name).resolve()))
            except (OSError, ValueError):
                paths.append(name)
        return tuple(paths)

    def staged_content(self, cwd: str) -> str | None:
        """The staged diff itself.

        Fingerprinting this catches a secret in a file we never saw written —
        `git add -f` on an ignored path, or an edit made outside the agent's
        tool calls. A path list alone cannot see that.
        """
        return self._git(cwd, "diff", "--cached")

    def configured_remotes(self, cwd: str) -> dict | None:
        """The repo's remotes and the current branch's upstream remote.

        Returns {"toplevel", "remotes": {name: url}, "upstream_remote"} or None.
        None on ANY uncertainty (not a repo, git missing, timeout, no remotes)
        — the fail-safe that preserves today's DENY. Used both to FREEZE the URL
        set at session start and to resolve a push's CURRENT target url at push
        time; the engine admits the target only if its current url is in the
        frozen set, so a mid-session `remote add`/`set-url` cannot buy in.
        """
        top = self._git(cwd, "rev-parse", "--show-toplevel")
        if top is None:
            return None
        toplevel = top.strip()
        # `git remote -v` prints: "<name>\t<url> (fetch)\n<name>\t<url> (push)".
        # The FETCH url is the canonical one; a push-only url is rare and taking
        # fetch keeps one url per name, which is what the frozen set compares.
        out = self._git(cwd, "remote", "-v")
        if out is None:
            return None
        remotes: dict[str, str] = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == "(fetch)":
                remotes.setdefault(parts[0], parts[1])
        # The upstream remote NAME for a bare `git push`. Absent (no upstream,
        # detached HEAD) is fine — a bare push then resolves to no name.
        up = self._git(cwd, "rev-parse", "--abbrev-ref", "--symbolic-full-name",
                       "@{upstream}")
        upstream_remote = None
        if up is not None and "/" in up.strip():
            upstream_remote = up.strip().split("/", 1)[0]
        return {"toplevel": toplevel, "remotes": remotes,
                "upstream_remote": upstream_remote}

    def is_directory(self, path: str) -> bool | None:
        """For `mv SRC DIR`: the file it would overwrite is DIR/SRC."""
        try:
            return os.path.isdir(path)
        except (OSError, ValueError):
            return None

    def exists(self, path: str) -> bool | None:
        """For `>` and `mv`: an overwrite loses something only where a file is."""
        try:
            return os.path.lexists(path)
        except (OSError, ValueError):
            return None

    def uncommitted(self, targets: tuple[tuple[str, frozenset], ...], cwd: str,
                    limit: float) -> tuple[str, ...] | None:
        """Which of these paths, or what is under them, is NOT safely in git —
        each with its `kinds` of "untracked", "ignored" and "modified"
        (uncommitted changes, staged or not) — as absolute paths, a folder
        with a trailing `/`.

        fix/false-positives item C (docs/112). One `git status` per directory
        the targets sit in (and kinds asked there), about those targets only,
        all within `limit` seconds; None when it cannot answer in that time, or
        at all. The clock is read here, at the IO boundary: the engine may not.
        A path that does not exist loses nothing; one that exists outside
        every repository is not in git, so it is lost whole; so is a folder
        that is itself a repository (its own history).

        A target ending `/.` is a directory's own contents (`git clean`,
        `git checkout .`), asked inside it; with the kind "repository" (`git
        reset --hard`, `git checkout -f`), the whole repository it is in. A
        glob is expanded here, at most `_MAX_GLOB` paths, and git is given
        only literal names.

        ⚠ GIT IS ASKED, NOT OBEYED (the reviews): no `core.fsmonitor` (a
        command the repository's config would have git run), no optional
        index lock, literal pathspecs, the caller's `GIT_*` environment
        dropped, no stdin; the answer is read as bytes, so a name that is not
        UTF-8 cannot make it raise."""
        deadline = _time.monotonic() + limit
        groups: dict[tuple[str, frozenset], list[str]] = {}
        lost: list[str] = []
        for target, kinds in targets:
            if target.endswith("/."):
                if os.path.isdir(target[:-2]):
                    groups.setdefault((target[:-2], kinds), []).append(target)
                continue
            paths = _expanded(target, deadline)
            if paths is None:
                return None
            for path in paths:
                # A delete (every kind asked) of git's own data — reached by a
                # glob (`.g*`, the second review round) — or of a folder that is
                # itself a repository loses its history, which status never
                # reports.
                if _DELETED <= kinds and (_GIT_DATA.search(path) or (
                        os.path.isdir(path) and os.path.lexists(os.path.join(path, ".git")))):
                    lost.append(path.rstrip("/") + "/")
                parent = os.path.dirname(path.rstrip("/")) or cwd
                groups.setdefault((parent, kinds), []).append(path)
        if len(groups) > _MAX_GIT_GROUPS:
            return None
        for (directory, kinds), paths in groups.items():
            answer = _git_status(directory, kinds, paths, deadline)
            if answer is None:
                return None
            lost += answer
        return tuple(dict.fromkeys(lost))


class NullWorld:
    """Answers nothing. Used when state or the filesystem is unavailable.

    Every method returns the empty answer, so the engine degrades to deciding
    on session state alone rather than crashing. Step 11's fail-closed rule
    then applies: deny at a sink, allow elsewhere.
    """

    def sync_roots(self) -> tuple[str, ...] | None:
        """None — could not tell, which is the quiet branch here."""
        return None

    def case_insensitive(self, root: str) -> bool | None:
        """⚠ ALWAYS "COULD NOT TELL", WHICH IS THE HONEST ANSWER FOR A WORLD
        THAT TOUCHES NOTHING. Returning False would claim a case-sensitive
        filesystem was measured; None makes the engine take its conservative
        branch, which is the same behaviour and an honest reason for it."""
        return None

    def read_text(self, path: str) -> str | None:
        return None

    def project_roots(self, cwd: str) -> tuple[tuple[str, ...], str | None]:
        return (cwd,) if cwd else (), None

    def staged_files(self, cwd: str) -> tuple[str, ...] | None:
        return None            # "could not inspect", not "nothing staged"

    def staged_content(self, cwd: str) -> str | None:
        return None

    def environment(self) -> dict[str, str]:
        return {}

    def configured_remotes(self, cwd: str) -> dict | None:
        return None            # could not inspect -> no exemption, today's DENY

    def is_directory(self, path: str) -> bool | None:
        return None

    def exists(self, path: str) -> bool | None:
        return None            # could not inspect

    def uncommitted(self, targets, cwd, limit) -> tuple[str, ...] | None:
        return None            # could not inspect -> ASK, as staged_files' None

