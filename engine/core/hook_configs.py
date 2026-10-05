"""What an agent's hook config holds, and whether the guard's entry is in it.

Two readers share this module:

    install.py   finds the guard's OWN entry to replace or remove, and nothing
                 else (item D2): a person's hook that says `testing`, `existing`
                 or a ~/sting/ path is theirs, and survives.
    the engine   decides whether a change to Claude Code's settings keeps the
                 guard's hook effective (item C step 3b), and whether any other
                 settings layer would switch hooks, or the guard, off.

⚠ PURE: strings and parsed JSON only. The engine reads no file, so a change is
judged by what the agent sends: a Write's whole new content, an Edit's own old
and new text. What that cannot see is written down as a limit, not guessed.

⚠ WHAT CLAUDE CODE DOES WITH A SETTINGS FILE (code.claude.com/docs, checked
26 Sep): strict JSON, no comments; layers in precedence managed > `--settings`
> .claude/settings.local.json > .claude/settings.json > ~/.claude/settings.json;
hooks from every layer MERGE and the most restrictive decision wins;
`disableAllHooks` is read after precedence, so ANY higher layer switches the
user's hooks off; a hook process inherits the environment, `env` included.
"""
from __future__ import annotations

import functools
import json
import re

from core import guard_parts

# ═══════════════════════════════ the guard's own entry, by its marker (D2)
#
# ⚠ NEVER A BARE "sting" SUBSTRING. The installer used `"sting" in
# json.dumps(entry)` to find its entry, which also matched a person's own hook
# running `npm run testing`, `existing.sh`, or anything under ~/sting/, and
# deleted it on every reinstall and uninstall.
_MARKER = re.compile(
    r"(?:sting_hook|hook_entry)\.py['\"]?\s+--agent\s+['\"]?(?P<agent>[\w-]+)"
    r"|cursor_bridge\.ps1['\"]?\s+-Agent\s+['\"]?(?P<bridge>[\w-]+)")


def sting_hook_agent(command: object) -> str | None:
    """The agent a hook command runs the guard for, or None when it is not the
    guard's: `sting_hook.py` or `hook_entry.py` with `--agent`, or the Windows
    Cursor bridge, `cursor_bridge.ps1` with `-Agent`."""
    if not isinstance(command, str):
        return None
    found = _MARKER.search(command)
    return (found.group("agent") or found.group("bridge")) if found else None


def commands_in(value: object) -> list[str]:
    """Every `command` string anywhere inside a config value. Iterative: the
    content is the agent's, and its nesting depth is too."""
    found, stack = [], [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, inner in item.items():
                if key == "command" and isinstance(inner, str):
                    found.append(inner)
                else:
                    stack.append(inner)
        elif isinstance(item, list):
            stack.extend(item)
    return found


def is_sting_entry(entry: object) -> bool:
    """Whether a hook config entry, in any agent's shape, runs the guard."""
    return any(sting_hook_agent(command) for command in commands_in(entry))


# ═══════════════════════════════════ the guard's exact command (C3b)
#
# `install.write_hook_config` writes `'<sys.executable>' '<entry>' --agent <a>`,
# each path POSIX-quoted by `_quote` ('…', a quote inside as '\''). Both paths
# are absolute. "Exact" is that shape and nothing else: no `|| true`, no
# redirect, no second command.
_QUOTED = r"'((?:[^']|'\\'')*)'"
_COMMAND_SHAPE = re.compile(rf"{_QUOTED} {_QUOTED} --agent ([\w-]+)")
_PYTHON = re.compile(r"(?:^|[/\\])python(?:\d+(?:\.\d+)*)?w?(?:\.exe)?$", re.IGNORECASE)
_ENTRY = re.compile(r"(?:^|[/\\])(?:sting_hook|hook_entry)\.py$", re.IGNORECASE)
_ABSOLUTE = re.compile(r"^(?:/|[A-Za-z]:[/\\])")


def is_exact_command(command: object, agent: str) -> bool:
    """The installer's command for `agent`: an absolute python, then the hook
    inside the installed tree, then `--agent <agent>`, byte for byte in shape.

    ⚠ THE INTERPRETER IS CHECKED BY NAME ONLY. Which python the installer used
    is on disk, and the engine reads no disk, so another executable NAMED
    python* passes. A stated limit (PROGRESS.md)."""
    if sting_hook_agent(command) != agent:       # the one marker, shared (D2)
        return False
    parts = command_parts(command)
    return (parts is not None and parts[2] == agent
            and guard_parts.in_install_tree(parts[1]))


def command_parts(command: object) -> tuple[str, str, str] | None:
    """(interpreter, hook script, agent) when `command` has the installer's
    shape — an absolute python, a hook script, `--agent <agent>` — else None.
    Where the script lives is the caller's question: `is_exact_command` asks
    for the installed tree by its path, `install.py --status` for this
    install's tree on disk (installer/agent_status.py)."""
    if not isinstance(command, str):
        return None
    shape = _COMMAND_SHAPE.fullmatch(command)
    if shape is None:
        return None
    interpreter = shape.group(1).replace("'\\''", "'")
    script = shape.group(2).replace("'\\''", "'")
    if not (_ABSOLUTE.match(interpreter) and _PYTHON.search(interpreter)
            and _ENTRY.search(script)):
        return None
    return interpreter, script, shape.group(3)


# ═════════════════════════════════════════ where Claude Code's settings live
@functools.cache
def _claude_user() -> re.Pattern:   # compiled on first use
    return re.compile(
        r"^(?:(?-i:/HOME|/home/[^/\\]+)|/Users/[^/\\]+|/root|/var/root"
        r"|[A-Za-z]:[/\\]Users[/\\][^/\\]+)[/\\]\.claude[/\\]settings\.json$",
        re.IGNORECASE)


_PROJECT_LAYER = re.compile(r"(?:^|[/\\])\.claude[/\\]settings(?:\.local)?\.json$",
                            re.IGNORECASE)


# Managed settings (code.claude.com/docs/en/managed-settings, checked 26 Sep):
# `managed-settings.json` and every `*.json` in `managed-settings.d/` beside it.
@functools.cache
def _managed_layer() -> re.Pattern:
    return re.compile(
        r"^(?:/Library/Application Support/ClaudeCode|/etc/claude-code"
        r"|[A-Za-z]:[/\\]Program Files[/\\]ClaudeCode)[/\\]"
        r"(?:managed-settings\.json|managed-settings\.d[/\\][^/\\]+\.json)$",
        re.IGNORECASE)


CLAUDE_SETTINGS = "~/.claude/settings.json, Claude Code's settings"


def is_claude_user_settings(path: str) -> bool:
    """~/.claude/settings.json itself: the file the installer hooks."""
    return bool(_claude_user().match(path))


def settings_layer(path: str) -> str | None:
    """What a Claude Code settings layer is called, or None: a project's
    .claude/settings.json or .claude/settings.local.json in any repo, or the
    managed settings. The user's own file is `is_claude_user_settings`."""
    if _managed_layer().match(path):
        return "Claude Code's managed settings"
    if _PROJECT_LAYER.search(path) and not is_claude_user_settings(path):
        return "a project's Claude Code settings"
    return None


# ══════════════════════════ environment keys that reach the guard's hook
#
# ⚠ THE COMMAND IS ABSOLUTE, AND THESE STILL CHANGE WHAT RUNS. A hook inherits
# Claude Code's environment, `env` included. PYTHONPATH and PYTHONUSERBASE make
# the interpreter run a sitecustomize / usercustomize BEFORE the hook, and
# PYTHONHOME moves its standard library (both verified, 26 Sep); PATH names the
# `git` the hook's own probes run (core/probes.py). STING_* is the guard's own
# configuration, and the environment wins over ~/.sting/env: STING_OBSERVE=1
# makes it block nothing.
RUNS_THE_HOOK = frozenset({"PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE"})


def configures_the_guard(key: object) -> bool:
    """A STING_* variable: refused in EVERY settings layer."""
    return isinstance(key, str) and key.upper().startswith("STING_")


def changes_the_hook(key: object) -> bool:
    """A variable that changes what the guard's hook runs or decides: refused in
    the user's own file. Not in a project's layers, where real projects set
    PATH and PYTHONPATH: a stated limit (PROGRESS.md)."""
    return configures_the_guard(key) or (isinstance(key, str)
                                         and key.upper() in RUNS_THE_HOOK)


# ═══════════════════════════════════ parsing the way Claude Code will
class _Duplicate(ValueError):
    pass


def _one_of_each(pairs: list) -> dict:
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise _Duplicate(key)
        seen[key] = value
    return seen


def _not_json(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def parse_settings(content: object) -> tuple[dict | None, str | None]:
    """(settings, why not): strict JSON, one object, no key twice.

    ⚠ A REPEATED KEY IS REFUSED, NOT RESOLVED. JSON.parse keeps the LAST, so a
    second "hooks" silently replaces the guard's. `NaN` and `Infinity` are
    Python's, not JSON's: Claude Code would reject the file."""
    if not isinstance(content, str):
        return None, "its new content cannot be seen"
    try:
        value = json.loads(content, object_pairs_hook=_one_of_each,
                           parse_constant=_not_json)
    except _Duplicate as repeated:
        return None, f'it repeats the key "{repeated}", and the last one would win'
    except (ValueError, RecursionError):
        return None, "it is not strict JSON, so Claude Code would not read it"
    if not isinstance(value, dict):
        return None, "it is not a JSON object"
    return value, None


# ══════════════════════════════ (b) a Write of ~/.claude/settings.json
_COVERS_EVERY_TOOL = frozenset({"*", "", ".*"})


def _keeps_the_guard(entry: object) -> bool:
    """The guard's PreToolUse entry, as installed and effective: a matcher that
    still covers every tool, and a hook object that is exactly
    {"type": "command", "command": <the exact command>}. Any other key can
    neuter it without removing it: `timeout` (a timed-out hook renders no
    decision), `args` (exec form), `async` (runs without blocking), `if` (runs
    only when a rule matches), `shell`."""
    if not isinstance(entry, dict) or set(entry) - {"matcher", "hooks"}:
        return False
    matcher = entry.get("matcher", "*")
    if not isinstance(matcher, str) or matcher not in _COVERS_EVERY_TOOL:
        return False
    inner = entry.get("hooks")
    return isinstance(inner, list) and any(
        isinstance(hook, dict) and set(hook) == {"type", "command"}
        and hook["type"] == "command" and is_exact_command(hook["command"], "claude-code")
        for hook in inner)


def claude_settings_problem(content: object, stops_the_guard=lambda command: False
                            ) -> str | None:
    """Why this new ~/.claude/settings.json would not keep the guard's hook
    effective, or None when it would. `stops_the_guard` is the engine's own
    stop reader, asked of every other hook command in the file: hooks run side
    by side, and one that kills the guard's process leaves no decision."""
    settings, why = parse_settings(content)
    if why:
        return why
    if settings.get("disableAllHooks", False) is not False:
        return "it sets disableAllHooks, which switches every hook off"
    env = settings.get("env", {})
    if not isinstance(env, dict):
        return "its env is not an object, so Claude Code would reject the file"
    changed = sorted(key for key in env if changes_the_hook(key))
    if changed:
        return f"it sets {changed[0]} in env, which changes what the guard's hook runs"
    hooks = settings.get("hooks")
    entries = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    if not isinstance(entries, list) or not any(_keeps_the_guard(e) for e in entries):
        return "the guard's PreToolUse entry is missing or no longer as installed"
    if any(stops_the_guard(command) for command in commands_in(hooks)):
        return "another hook in it stops the guard"
    return None


# ═══════════════════════════════ (b) an Edit of ~/.claude/settings.json
#
# ⚠ JUDGED ON THE EDIT'S OWN TEXT, OLD AND NEW, NEVER THE FILE. Anything that
# names the hook structure, the guard's command, or an environment key that
# reaches the hook touches the hook. Permissions, other env, the status line
# and the model do not. The event names are Claude Code's (docs, 26 Sep).
_EVENTS = (
    "SessionStart|Setup|UserPromptSubmit|UserPromptExpansion|PreToolUse"
    "|PermissionRequest|PermissionDenied|PostToolUse|PostToolUseFailure"
    "|PostToolBatch|Notification|MessageDisplay|SubagentStart|SubagentStop"
    "|TaskCreated|TaskCompleted|Stop|StopFailure|TeammateIdle"
    "|InstructionsLoaded|ConfigChange|CwdChanged|DirectoryAdded|FileChanged"
    "|WorktreeCreate|WorktreeRemove|PreCompact|PostCompact|PreModelSwitch"
    "|PostModelSwitch|Elicitation|ElicitationResult|SessionEnd")


@functools.cache
def _touches_the_hook() -> re.Pattern:   # compiled on first use
    return re.compile(
        r'"hooks"|disableAllHooks'
        r'|"(?:matcher|timeout|args|async|asyncRewake|shell|if|once)"'
        rf'|"(?:{_EVENTS})"'
        r'|"\.?\*"'                               # a matcher covering every tool
        r"|sting_hook\.py|hook_entry\.py|cursor_bridge\.ps1|--agent\b"
        r"|\.local[/\\]share[/\\]sting|(?<![a-z])sting(?![a-z])"  # never `testing`
        r"|[/\\]python[\d.]*w?(?:\.exe)?'"        # the hook's interpreter
        r'|"(?:PATH|PYTHONPATH|PYTHONHOME|PYTHONUSERBASE)"',
        re.IGNORECASE)


_PATCH = re.compile(r"^\*\*\* Begin Patch|^@@", re.MULTILINE)


# ⚠ JSON SPELLS ANY CHARACTER AS \uXXXX, AND CLAUDE CODE DECODES IT (security
# review of item C). `"disable\u0041llHooks": true` is `disableAllHooks` to the
# file's reader and was nothing to a check of the raw text. Every text check
# below asks the raw text AND this decoded view: decoding can only add a match.
_JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _decoded(text: str) -> str:
    return (_JSON_ESCAPE.sub(lambda escape: chr(int(escape.group(1), 16)), text)
            if "\\u" in text else text)


def _searched(pattern: re.Pattern, text: str) -> re.Match | None:
    """`pattern` in `text`, or in `text` with its JSON escapes decoded."""
    decoded = _decoded(text)
    return pattern.search(text) or (pattern.search(decoded) if decoded != text else None)


def claude_edit_problem(replaced: object, content: object) -> str | None:
    """Why this Edit of ~/.claude/settings.json touches the guard's hook, or
    None when it leaves the hook alone.

    ⚠ AN EDIT WHOSE OLD TEXT IS NOT CARRIED IS REFUSED: an adapter that sends
    only the new text leaves a deleted hook entry looking like an empty edit.
    A patch carries both sides in its own text, so it is judged whole."""
    new = content if isinstance(content, str) else None
    old = replaced if isinstance(replaced, str) else None
    if old is None and new is not None and _PATCH.search(new):
        old = ""
    if old is None or new is None:
        return "what the edit replaces cannot be seen"
    touches = _touches_the_hook()
    found = _searched(touches, old) or _searched(touches, new)
    if found:
        return f"it touches the guard's hook ({found.group(0)!r})"
    return None


# ═══════════════ every other layer: never switch hooks, or the guard, off
_DISABLE_KEY = re.compile(r"disableAllHooks", re.IGNORECASE)
_KEPT_FALSE = re.compile(r'"?\s*:\s*false\b', re.IGNORECASE)
_STING_KEY = re.compile(r"(?<![A-Za-z0-9_])STING_\w+", re.IGNORECASE)
# In SHELL text a STING_ key counts only in the shape a settings file or jq
# gives it (`"STING_X":`, `.env.STING_X =`, `["STING_X"]`), never as a shell
# assignment (`STING_TIER=x cmd`), which configures the command it prefixes.
_SWITCH_TEXT = re.compile(
    r"disableAllHooks|[\"'.\[]STING_\w+\\?[\"']?\s*[:=\]]", re.IGNORECASE)


def layer_problem(content: object) -> str | None:
    """Why a Write of a settings layer would switch hooks or the guard off, or
    None. Everything else about a layer is unchanged: an unreadable file is
    one Claude Code ignores, so it switches nothing."""
    try:
        settings = json.loads(content) if isinstance(content, str) else None
    except (ValueError, RecursionError):
        return None
    if not isinstance(settings, dict):
        return None
    if settings.get("disableAllHooks", False) is not False:
        return "it sets disableAllHooks, which switches the user's hooks off"
    env = settings.get("env")
    if isinstance(env, dict):
        found = sorted(key for key in env if configures_the_guard(key))
        if found:
            return f"it sets {found[0]} in env, which configures the guard"
    return None


def layer_edit_problem(content: object) -> str | None:
    """Why an Edit of a settings layer would switch hooks or the guard off: its
    new text sets `disableAllHooks` to anything but false, or a STING_ key."""
    if not isinstance(content, str):
        return None
    for text in {content, _decoded(content)}:
        # ⚠ THE KEY ALONE SETS IT: renaming an existing `"x": true` to
        # `"disableAllHooks"` needs no value in the new text. Only an explicit
        # `: false` right after the key is left alone.
        if any(not _KEPT_FALSE.match(text, key.end())
               for key in _DISABLE_KEY.finditer(text)):
            return "it sets disableAllHooks, which switches the user's hooks off"
        if _STING_KEY.search(text):
            return "it sets a STING_ variable, which configures the guard"
    return None


def names_a_switch(text: str) -> bool:
    """Whether shell text mentions `disableAllHooks` or a STING_ variable: a
    command that writes a settings layer AND says this is refused."""
    return _searched(_SWITCH_TEXT, text) is not None


# ═══════════ the managed policy in the registry, and a nested `claude` run
#
# ⚠ THE HKCU VALUE IS USER-WRITABLE (docs: "The HKCU registry is user-writable
# and isn't one [an admin source]"). Claude Code reads
# `HKCU\SOFTWARE\Policies\ClaudeCode` value `Settings` as MANAGED policy when no
# admin source delivers one, which is most machines. HKLM is the same key under
# the machine hive, and the same pattern reads it.
POLICY_KEY = re.compile(r"Policies[/\\]+ClaudeCode", re.IGNORECASE)
REGISTRY_WRITE = re.compile(
    r"\breg(?:\.exe)?\s+(?:add|import|copy|restore)\b|\b(?:Set|New)-ItemProperty\b"
    r"|\bNew-Item\b", re.IGNORECASE)


def writes_the_policy_registry(segment: str) -> bool:
    """One command segment that writes Claude Code's policy key in a way that
    switches hooks or the guard off. `reg import` of a file whose content is not
    in the command is not seen: a stated limit."""
    return bool(POLICY_KEY.search(segment) and REGISTRY_WRITE.search(segment)
                and names_a_switch(segment))


# `claude --bare` skips hooks (docs: "skip auto-discovery of hooks …"); inline
# `--settings` JSON is the command-line layer, above every file. A `--settings`
# FILE is not read here: a stated limit.
CLAUDE_RUN = re.compile(r"(?<![\w./-])claude(?:\.exe)?(?![\w.-])")
_BARE = re.compile(r"(?<![\w-])--bare\b")
_SETTINGS_FLAG = re.compile(r"(?<![\w-])--settings\b")


def starts_claude_unguarded(segment: str) -> str | None:
    """Why this command segment starts a Claude Code session with the guard's
    hook off, or None."""
    if not CLAUDE_RUN.search(segment):
        return None
    if _BARE.search(segment):
        return "claude --bare, which skips every hook"
    # `--settings` takes several sources, space-separated, so the whole segment
    # is asked, not the next word.
    if _SETTINGS_FLAG.search(segment) and names_a_switch(segment):
        return "claude --settings, switching hooks or the guard off"
    return None
