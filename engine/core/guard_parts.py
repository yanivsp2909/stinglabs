"""The parts of an INSTALLED Sting guard, as an agent's action names them.

An agent tool call that writes, deletes, moves, stops, unloads or uninstalls any
of these is DENY in every session (`installed_guard:guard_selfmod`, the maintainer,
25 Sep). The engine decides; this module only says what a path or a command
segment is. The list is the installer's own, read from `installer/place.py`,
`install.py`, `installer/supervisor.py` and `shipper/service.py`:

    ~/.local/share/sting/…      the install tree: every version, `current`,
                                INSTALL.json
    ~/.sting/…                  env (settings and device token), policy.json
                                (local relaxations), org_policy.json (org
                                cache), sessions/ (logs, state, allow-once
                                grants, the daemon's socket, lock and
                                declaration), shipper/ (cursor, queue, lock),
                                shipper.out.log / shipper.err.log
    the daemon                  `python <tree>/daemon/server.py`
    the shipper service         label `dev.sting.shipper.<hash>` (legacy
                                `dev.sting.shipper`), running
                                `<tree>/shipper/run.py`: a launch agent in
                                ~/Library/LaunchAgents, a systemd user unit in
                                ~/.config/systemd/user, a scheduled task and
                                files in %LOCALAPPDATA%\\sting, a Startup entry
    the hook                    `sting_hook.py` / `hook_entry.py`

    the hook configs            the four HOOKS-ONLY files, protected by path
                                (item C step 3a): ~/.cursor/hooks.json,
                                ~/.codex/hooks.json, ~/.gemini/config/hooks.json
                                and a project's .github/hooks/hooks.json
                                (Copilot's, written where the installer ran)

⚠ ~/.claude/settings.json IS NOT A PART BY PATH. It also holds the person's own
settings, so a change to it is judged by what it changes
(`core/hook_configs.py`, item C step 3b). Deleting or moving it, or ~/.claude,
takes the guard's hook with it, so it is a HOLDER here.

⚠ THE INSTALLED GUARD, NEVER ITS SOURCE. A checkout such as ~/sting/sting-engine
is development: no pattern below matches it, and editing it stays exactly as it
was. A home-level `.sting` is the guard's; a `.sting` inside a project is not.

⚠ PURE: NO IO, NO ENVIRONMENT. The engine may not read the machine (a test
enforces it), so a home is matched as `_abs`'s `/HOME` placeholder for `~`, or as
a literal `/Users/<name>`, `/home/<name>`, `/root`, `/var/root` or
`C:\\Users\\<name>`. An install moved by STING_INSTALL_ROOT is not visible here,
and that is a stated limit, not a silent one.
"""
from __future__ import annotations

import bisect
import fnmatch
import functools
import re

# ⚠ `/HOME` AND `/home/` ARE CASE-SENSITIVE, THE REST IS NOT. The patterns below
# ignore case, because macOS's disk does (`~/.STING/policy.json` is the same
# file). But `/HOME` is `_abs`'s placeholder for `~`, so `/HOME/projects` must
# never read as a Linux home, `/home/<name>`: `cd ~/projects && rm -rf .` was a
# delete of "your home directory" until this was scoped.
_HOME = (r"(?:(?-i:/HOME|/home/[^/\\]+)|/Users/[^/\\]+|/root|/var/root"
         r"|[A-Za-z]:[/\\]Users[/\\][^/\\]+)")
_SEP = r"[/\\]"
_UNDER = r"(?:[/\\].*)?$"          # the part itself, or anything beneath it

LABEL = re.compile(r"dev\.sting\.shipper", re.IGNORECASE)

# (what it matches, what to call it), most specific first. Each name is how a
# person would find it: the path as their own shell spells it.
_PARTS = (
    (rf"^{_HOME}{_SEP}\.sting{_SEP}env$",
     "~/.sting/env, the guard's settings and device token"),
    (rf"^{_HOME}{_SEP}\.sting{_SEP}policy\.json$",
     "~/.sting/policy.json, the guard's local relaxations"),
    (rf"^{_HOME}{_SEP}\.sting{_SEP}org_policy\.json$",
     "~/.sting/org_policy.json, the guard's org policy cache"),
    (rf"^{_HOME}{_SEP}\.sting{_SEP}sessions{_UNDER}",
     "~/.sting/sessions, the guard's decision logs, session state and daemon"),
    (rf"^{_HOME}{_SEP}\.sting{_SEP}shipper{_UNDER}",
     "~/.sting/shipper, the shipper's cursor and queue"),
    (rf"^{_HOME}{_SEP}\.sting{_UNDER}",
     "~/.sting, the guard's state directory"),
    (rf"^{_HOME}{_SEP}\.local{_SEP}share{_SEP}sting{_UNDER}",
     "~/.local/share/sting, the installed guard's code"),
    (rf"^{_HOME}{_SEP}AppData{_SEP}Local{_SEP}sting{_UNDER}",
     "%LOCALAPPDATA%\\sting, the shipper's scheduled task"),
    (r"(?:^|[/\\])sting-shipper\.cmd$",
     "the shipper's Startup entry"),
    (LABEL.pattern,
     "the shipper service (dev.sting.shipper), which reports the guard's decisions"),
    (rf"^{_HOME}{_SEP}\.cursor{_SEP}hooks\.json$",
     "~/.cursor/hooks.json, Cursor's hook config, which runs the guard"),
    (rf"^{_HOME}{_SEP}\.codex{_SEP}hooks\.json$",
     "~/.codex/hooks.json, Codex's hook config, which runs the guard"),
    (rf"^{_HOME}{_SEP}\.gemini{_SEP}config{_SEP}hooks\.json$",
     "~/.gemini/config/hooks.json, Antigravity's hook config, which runs the guard"),
    # ⚠ IN EVERY PROJECT. The installer writes it where it ran, and the engine
    # cannot know where that was (it reads nothing), so every project's copy is
    # protected: a hooks-only file, whose every edit is a hook edit.
    (r"(?:^|[/\\])\.github[/\\]hooks[/\\]hooks\.json$",
     "the project's .github/hooks/hooks.json, Copilot's hook config, which runs "
     "the guard"),
)
# ⚠ COMPILED ON FIRST USE, NOT AT IMPORT. Each repeats the home alternation,
# and the ~25 of them cost ~5 ms at import on every cold hook, where most calls
# (reads, a command with no write) never ask about a path at all.
@functools.cache
def _part_patterns() -> tuple:
    return tuple((re.compile(p, re.IGNORECASE), name) for p, name in _PARTS)


# Directories whose deletion or move takes a part with them. The home directory
# itself is here too, for a home no catastrophic-delete rule names (`/root`).
_HOLDERS = (
    (rf"^{_HOME}{_SEP}?$", "your home directory, which holds the guard"),
    (rf"^{_HOME}{_SEP}\.local(?:{_SEP}share)?{_SEP}?$",
     "~/.local/share, which holds the installed guard"),
    (rf"^{_HOME}{_SEP}Library(?:{_SEP}LaunchAgents)?{_SEP}?$",
     "~/Library/LaunchAgents, which holds the shipper's launch agent"),
    (rf"^{_HOME}{_SEP}\.config(?:{_SEP}systemd(?:{_SEP}user)?)?{_SEP}?$",
     "~/.config/systemd/user, which holds the shipper's unit"),
    (rf"^{_HOME}{_SEP}\.claude{_SEP}settings\.json$",
     "~/.claude/settings.json, Claude Code's settings, which run the guard's hook"),
    (rf"^{_HOME}{_SEP}\.claude{_SEP}?$",
     "~/.claude, which holds Claude Code's settings and the guard's hook"),
    (rf"^{_HOME}{_SEP}\.cursor{_SEP}?$", "~/.cursor, which holds Cursor's hook config"),
    (rf"^{_HOME}{_SEP}\.codex{_SEP}?$", "~/.codex, which holds Codex's hook config"),
    (rf"^{_HOME}{_SEP}\.gemini(?:{_SEP}config)?{_SEP}?$",
     "~/.gemini/config, which holds Antigravity's hook config"),
    (r"(?:^|[/\\])\.github(?:[/\\]hooks)?[/\\]?$",
     "the project's .github/hooks, which holds Copilot's hook config"),
)
@functools.cache
def _holder_patterns() -> tuple:
    return tuple((re.compile(p, re.IGNORECASE), name) for p, name in _HOLDERS)

# Where a glob is tested: every part and holder, as a path under a home.
_GLOB_CANDIDATES = (
    ".sting", ".sting/env", ".sting/policy.json", ".sting/org_policy.json",
    ".sting/sessions", ".sting/shipper", ".local", ".local/share",
    ".local/share/sting", ".local/share/sting/current", "Library",
    "Library/LaunchAgents", ".config", ".config/systemd", ".config/systemd/user",
    ".cursor", ".cursor/hooks.json", ".codex", ".codex/hooks.json", ".gemini",
    ".gemini/config", ".gemini/config/hooks.json", ".claude", ".claude/settings.json",
)
_GLOB_CHARS = re.compile(r"[*?\[]")
@functools.cache
def _home_prefix() -> re.Pattern:
    return re.compile(rf"^{_HOME}(?={_SEP})")

# ── what a command does to a part, by name rather than by path ───────────────
# A PROCESS of the guard: its shipper, its daemon, its hook. Only with a stop
# verb in the same segment. `stingd` is the name docs/02 used; nothing installs
# it, and it is kept because killing it is unambiguous.
_OWN_PROCESS = re.compile(
    r"dev\.sting\.shipper|\bsting_hook(?:\.py)?\b|\bhook_entry\b|\bstingd\b")
# ⚠ TWO NAMES ANOTHER PROJECT CAN HAVE TOO. The guard runs `python
# <tree>/daemon/server.py` and `python <tree>/shipper/run.py`, so a bare
# `pkill -f daemon/server.py` stops it, and so does one under a wildcard or the
# install tree. One under a concrete path somewhere else
# (`myapp/daemon/server.py`, the source checkout) cannot match the guard's
# command line, and stops nothing of it.
_SHARED_PROCESS = re.compile(r"\b(?:daemon[./]server|shipper[./]run)(?:\.py)?\b")
_WILDCARD = re.compile(r"[*?\[+]")
_INSTALL_TREE = re.compile(
    r"\.local[/\\]share[/\\]sting[/\\]|AppData[/\\]Local[/\\]sting[/\\]"
    r"|(?:^|[/\\])current[/\\]$", re.IGNORECASE)
KILL = re.compile(r"(?<![\w.-])(?:pkill|killall|kill|taskkill)\b", re.IGNORECASE)


# A SERVICE manager told to stop, unload or remove a unit. Only with the
# shipper's label in the same segment; `print`, `list` and `status` are reads.
SERVICE_STOP = re.compile(
    r"\blaunchctl\s+(?:bootout|unload|remove|stop|kill|disable)\b"
    r"|\bsystemctl\b(?:\s+-\S+)*\s+(?:stop|disable|mask|kill|reset-failed)\b"
    r"|\bschtasks(?:\.exe)?\b.*?/(?:End|Delete|Change)\b"
    r"|\b(?:Stop|Unregister|Disable)-ScheduledTask\b", re.IGNORECASE)

# ⚠ READ IN LINEAR TIME, NOT WITH THAT PATTERN (item E, docs/110 §E). Its
# `schtasks` alternative's lazy `.*?` walked from every `schtasks` to the end of
# the line when no flag followed, so a run of them was O(n²): 1.7 s at 72 KB,
# 6.9 s at 144 KB. `service_stop` returns exactly `SERVICE_STOP.search`'s span:
# the other alternatives as they are, and the `schtasks` one from precomputed
# positions. tests/test_the_find_check_is_linear.py compares the two.
_SERVICE_STOP_OTHER = re.compile(
    r"\blaunchctl\s+(?:bootout|unload|remove|stop|kill|disable)\b"
    r"|\bsystemctl\b(?:\s+-\S+)*\s+(?:stop|disable|mask|kill|reset-failed)\b"
    r"|\b(?:Stop|Unregister|Disable)-ScheduledTask\b", re.IGNORECASE)
_SCHTASKS = re.compile(r"\bschtasks\b", re.IGNORECASE)
_SCHTASKS_FLAG = re.compile(r"/(?:End|Delete|Change)\b", re.IGNORECASE)
_NEWLINE = re.compile(r"\n")


def service_stop(segment: str) -> tuple[int, int] | None:
    r"""`SERVICE_STOP.search(segment)`'s (start, end), or None, in linear time.

    A `schtasks` word matches when a flag starts at or after its end with no
    newline between (`.` never crosses one), and the match ends at the FIRST
    such flag; the leftmost start of all alternatives wins, and no two start
    at the same place. `\bschtasks(?:\.exe)?\b` is `\bschtasks\b`: `.` is not a
    word character, and a flag starts with `/`, never inside `.exe`."""
    other = _SERVICE_STOP_OTHER.search(segment)
    flags = [(m.start(), m.end()) for m in _SCHTASKS_FLAG.finditer(segment)]
    best = (other.start(), other.end()) if other else None
    if flags:
        starts = [f[0] for f in flags]
        newlines = [m.start() for m in _NEWLINE.finditer(segment)]
        for word in _SCHTASKS.finditer(segment):
            if best is not None and word.start() > best[0]:
                break
            k = bisect.bisect_left(starts, word.end())
            if k == len(flags):
                break                       # no flag after any later word either
            line = bisect.bisect_left(newlines, word.end())
            if line < len(newlines) and newlines[line] < starts[k]:
                continue                    # the line ends before the flag
            if best is None or word.start() < best[0]:
                best = (word.start(), flags[k][1])
            break
    return best

# ⚠ TWO SEARCHES, NOT ONE LAZY `.*?` (security review of item C). The lazy form
# re-scanned the rest of the segment from every `install.py`, so a run of them
# was quadratic.
_INSTALLER = re.compile(r"\binstall\.py\b")
_UNINSTALL_FLAG = re.compile(r"\s--uninstall\b")
_PIP_UNINSTALL = re.compile(r"\bpip3?\s+uninstall\b")
_PACKAGE = re.compile(r"(?<![/\w.-])sting-engine\b")


def uninstalls(segment: str) -> re.Match | None:
    """`install.py … --uninstall` or `pip uninstall … sting-engine` in one
    segment: the match that starts it, or None."""
    first = _INSTALLER.search(segment)
    if first and _UNINSTALL_FLAG.search(segment, first.end()):
        return first
    pip = _PIP_UNINSTALL.search(segment)
    if pip and _PACKAGE.search(segment, pip.end()):
        return pip
    return None


# ⚠ BOUNDED (security review of item C). Walking back from every match to the
# start of a long word was quadratic in a `pkill -f` pattern repeating the name.
# A prefix longer than this is taken as one that could match the guard: that
# direction refuses more, never less.
_UNDER_LIMIT = 256


def _stops_the_guard(text: str, name: re.Match) -> bool:
    """A shared name counts bare, under a wildcard, or under the install tree:
    the path glued in front of it, back to a blank, a quote, `=` or `(`."""
    begin, floor = name.start(), max(0, name.start() - _UNDER_LIMIT)
    while begin > floor and text[begin - 1] not in " \t\n'\"=(":
        begin -= 1
    if begin == floor and floor and text[floor - 1] not in " \t\n'\"=(":
        return True
    under = text[begin:name.start()]
    return not under or bool(_WILDCARD.search(under) or _INSTALL_TREE.search(under))


def process_named(text: str) -> re.Match | None:
    """The first of the guard's own processes `text` names, or None."""
    shared = next((m for m in _SHARED_PROCESS.finditer(text)
                   if _stops_the_guard(text, m)), None)
    found = [m for m in (_OWN_PROCESS.search(text), shared) if m]
    return min(found, key=lambda m: m.start(), default=None)


# Every word one of the three above needs: a segment without one holds no stop,
# and a command without one needs no segment read at all.
STOP_CUE = re.compile(
    r"\b(?:install\.py|pip3?|launchctl|systemctl|schtasks|pkill|killall|kill"
    r"|taskkill|(?:Stop|Unregister|Disable)-ScheduledTask)\b", re.IGNORECASE)


def could_stop(text: str) -> bool:
    """Whether `text` holds a stop, unload or uninstall verb at all: the cheap
    question asked before the per-segment one."""
    return STOP_CUE.search(text) is not None


def _first(patterns, path: str) -> str | None:
    return next((name for pattern, name in patterns if pattern.search(path)), None)


# A project's Copilot hook config is in EVERY project, so a glob is tested
# against its path from the end, wherever the project is (python review).
_PROJECT_GLOB_CANDIDATES = (".github", ".github/hooks", ".github/hooks/hooks.json")


def _segment_matches(candidate: str, pattern: str, dotglob: bool) -> bool:
    """One path segment against one glob segment, the way bash globs: a leading
    `.` must be matched by a literal `.` unless `dotglob` is on. So `rm -rf *`
    in a project leaves `.github` alone, as bash does."""
    if candidate.startswith(".") and not pattern.startswith(".") and not dotglob:
        return False
    return fnmatch.fnmatchcase(candidate, pattern)


def _glob_part(path: str, patterns, dotglob: bool = False) -> str | None:
    """The part a GLOB could name: each candidate is tested segment by segment,
    so a `*` never crosses a `/`, as in bash. Under the pattern's own home for
    the home-level parts; from the end of the path for a project's."""
    home = _home_prefix().match(path)
    if home:
        wanted = re.split(r"[/\\]", path[home.end():].strip("/\\"))
        for suffix in _GLOB_CANDIDATES:
            parts = suffix.split("/")
            if len(parts) == len(wanted) and all(
                    _segment_matches(p, w, dotglob) for p, w in zip(parts, wanted)):
                found = _first(patterns, f"{home.group(0)}/{suffix}")
                if found:
                    return found
    segments = re.split(r"[/\\]", path)
    for suffix in _PROJECT_GLOB_CANDIDATES:
        parts = suffix.split("/")
        if len(segments) > len(parts) and all(
                _segment_matches(p, w, dotglob)
                for p, w in zip(parts, segments[-len(parts):])):
            found = _first(patterns, "/".join(segments[:-len(parts)] + parts))
            if found:
                return found
    return None


@functools.cache
def _install_tree_path() -> re.Pattern:
    return re.compile(
        rf"^{_HOME}{_SEP}(?:\.local{_SEP}share|AppData{_SEP}Local){_SEP}sting{_SEP}.",
        re.IGNORECASE)


_DOT_SEGMENT = re.compile(r"(?:^|[/\\])\.\.?(?:[/\\]|$)")


def in_install_tree(path: str) -> bool:
    """Whether an absolute path lies inside the installed guard's tree, with no
    `.`/`..` segment that could climb out of it."""
    return bool(_install_tree_path().match(path)) and not _DOT_SEGMENT.search(path)


def part_at(path: str, dotglob: bool = False) -> str | None:
    """The guard part `path` IS or lies inside, or None. `path` is absolute and
    normalised (`~` already the `/HOME` placeholder). `dotglob`: the command
    turned bash's `shopt -s dotglob` (or extglob/globstar) on."""
    found = _first(_part_patterns(), path)
    if found or not _GLOB_CHARS.search(path):
        return found
    return _glob_part(path, _part_patterns(), dotglob)


def holder_of(path: str, dotglob: bool = False) -> str | None:
    """The part `path` CONTAINS, for a delete or a move: a part, or a directory
    that holds one."""
    found = part_at(path, dotglob) or _first(_holder_patterns(), path)
    if found or not _GLOB_CHARS.search(path):
        return found
    return _glob_part(path, _holder_patterns(), dotglob)
