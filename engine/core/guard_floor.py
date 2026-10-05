"""The installed guard is not the agent's to change: the guard_selfmod
patterns, the write readers, what an action does to a guard part, and the
floor that holds over every other verdict (item C, docs/104).

`_DECISION_RANK`, the order of the engine's decisions, lives here because the
floor ranks by it; the org-policy ladder in engine.py reads the same table.

Moved out of core/engine.py; docs/ENGINE_LAYOUT.md.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import NamedTuple

from core import guard_parts, guard_runs, hook_configs
from core.shell_scan import code_mask_checked
from core.types import Action, ActionKind, Decision, SessionState, Verdict
from core.command_text import (_REDIRECT_TARGET, _SEGMENT_REST, _SHELL_TOKEN, _abs,
                               _copy_operands, _literal_assignments, _norm_path,
                               _segment_end, _structure_action, _verb,
                               span_evidence)
from core.globbing import _SHOPT_WIDENS_GLOB
from core.irreversible import _cd_bases, _deleted_by, _resolved


# Narrowed from docs/02's `"sting" in cmd.lower()`, which substring-matches
# "testing", "existing" and "casting" — `run the existing tests` would deny.
# THE GUARD'S OWN ARTEFACTS, named specifically.
#
# This was `\bsting(?:d|-engine)?\b|\bhook_entry\b|\.sting/`, and `\bsting\b`
# matches any occurrence of the word — including a directory named `sting`.
# Measured on one real session: 188 of 190 file paths and 786 of 808 commands
# matched, because the developer's repositories live in ~/sting/. The corpus is
# no better: run_corpus names its staging directories `sting-<scenario>`, so
# D02, G01 and H01 all matched their own temp path, and A02 matched
# `webhook.site/sting-test`. Of every corpus match, exactly ONE was real —
# H05's `pkill -f stingd`.
#
# A noun that matches a coincidence is the same failure as a verb matched in
# quoted text: the pattern is doing name-recognition on a string that merely
# contains the name.
#
# `sting-engine` is deliberately NOT here. Editing the guard's SOURCE is
# development, not disabling; see the installation-shape spec. If that decision
# lands, the guard's INSTALLED path belongs here — path-anchored — and the
# source checkout still does not.
_GUARD_SELFMOD = re.compile(
    r"\bstingd\b"            # the installed daemon, as a process or binary name
    r"|\bhook_entry\b"       # the hook script itself
    r"|/\.sting(?:/|\b)"     # the state and log directory
    # The PACKAGE name, e.g. `pip uninstall sting-engine`. The lookbehind is
    # what keeps it from matching the same string as a path SEGMENT: in
    # `~/sting/sting-engine` it is preceded by `/`, in `pip uninstall
    # sting-engine` by a space.
    r"|(?<![/\w.-])sting-engine\b",
    re.IGNORECASE)
_KILL = re.compile(r"\b(?:pkill|killall|kill|taskkill)\b")

# ⚠ THE GUARD'S OWN PROCESS AND SERVICE NAMES. `_GUARD_SELFMOD` above knows the
# guard's PATHS; killing the shipper touches none of them —
# `launchctl bootout gui/501/dev.sting.shipper` names a launchd LABEL and
# `pkill -f shipper.run` a module. Same category, same mechanism.
#
# ⚠ `\bsting\b` IS REJECTED, AND MEASURED. `fb071e3` already narrowed
# _GUARD_SELFMOD away from a bare `sting` substring because the developer's
# repositories live under ~/sting/ and it matched 188 of 190 real paths. A
# `pkill -f sting` rule would reintroduce exactly that.

_GUARD_PROCESS = re.compile(r"dev\.sting\.shipper|\bshipper\.run\b")
# ⚠ `launchctl bootout` IS DELIBERATELY NOT A STOP VERB HERE, AND THE
# MEASUREMENT IS WHY. Including it cost 3 false positives in 1,752 live
# commands — all genuine supervisor development: booting out a sandbox service,
# testing a label that was not loaded, checking the print output. Those are not
# artifacts and they are textually IDENTICAL to the attack.
#
# The discriminator is that `launchctl bootout` is the DOCUMENTED, reversible
# way to stop this service: `supervisor.stop_command()` prints that exact line
# for the developer to run, and `activate()` runs it itself on every reinstall.
# A rule that denies the command the product tells you to type is a rule people
# route around.
#
# `pkill`/`kill` against the guard's own module is the opposite: nothing in this
# product ever asks for it, and it is 0 of 1,752.

# ⚠ TURNING THE GUARD OFF FOR EVERY FUTURE SESSION, WHICH IS WHY IT IS HERE AND
# NOT WITH THE DEFERRED-EXECUTION SCENARIOS. `_GUARD_SELFMOD` above matches
# PATHS that are the guard; this matches CONTENT that CONFIGURES it. Same
# category — a write aimed at the guard rather than at the developer's work —
# and no new mechanism.
#
# ⚠ IT IS THE CONJUNCTION, AND EVERY WIDER FORM WAS REJECTED ON A MEASUREMENT.
# Counted over 1,685 real commands from this developer's own sessions:
#
#     any `STING_` assignment                 53   3.1% — unusable
#     `export STING_…`                         7          unusable
#     `STING_OBSERVE=` anywhere                6          unusable, AND WRONG:
#                                                         observe mode is a
#                                                         SUPPORTED mode, and
#                                                         setting it for one
#                                                         command is legitimate
#     assignment PERSISTED into a startup file 0   <- this rule
#
# The danger was never the assignment. It is the PERSISTENCE: a value in one
# shell dies with it, and a line in a profile disables enforcement on every
# later session on that machine. So the match is the pair.
# ⚠ ONE PATTERN, NOT TWO, AND THAT IS THE WHOLE FIX. Matching an assignment
# ANYWHERE and a redirect ANYWHERE cost 1 false positive in 1,691 live commands:
#
#   grep -n "…os.environ.get(\"STING" install.py ; sed 's/=.*TOKEN.*/=<redacted>/' ~/.sting/env
#
# — a READ that redacts the env file for display. `STING_DEVICE_TOKEN=` was
# inside the grep pattern, the `>` was inside sed's replacement, and the path
# was in a third segment. Two true sub-matches, in different segments, of a
# command that writes nothing.
#
# Requiring them in the SAME segment (`[^;&|\n]*`) takes it to ZERO of 1,691.
_STING_PERSISTED = re.compile(
    # STING_X=… > ~/.zshrc      (a redirect, same segment)
    r"\bSTING_[A-Z0-9_]+\s*=[^;&|\n]*?>>?\s*[^\s;&|]*"
    r"(?:/\.(?:bashrc|zshrc|bash_profile|zprofile|profile|zshenv)|/\.sting/env)"
    # STING_X=… | tee -a ~/.zshrc   (the one legitimate pipe, allowed through)
    r"|\bSTING_[A-Z0-9_]+\s*=[^;&\n]*?\|\s*(?:sudo\s+)?tee\b[^;&\n]*?"
    r"(?:/\.(?:bashrc|zshrc|bash_profile|zprofile|profile|zshenv)|/\.sting/env)")

# ⚠ EVERY HOOK CONFIG, EITHER SEPARATOR, ANY CASE (item C step 3). This missed
# the two files the installer writes for Antigravity and Copilot, a project's
# settings.local.json (a layer ABOVE the user's), every Windows path (`\\`), and
# `.Claude/Settings.json`, which macOS's disk opens as the same file.
CONFIG_SELFMOD_PATHS = re.compile(
    r"(?:^|[/\\])(?:\.claude[/\\]settings(?:\.local)?\.json|\.mcp\.json|CLAUDE\.md"
    r"|\.(?:cursor|agents|codex)[/\\]hooks\.json|\.gemini[/\\]config[/\\]hooks\.json"
    r"|\.github[/\\]hooks[/\\]hooks\.json)$", re.IGNORECASE)
# A command can only write one of those if it names one (or globs one).
_CONFIG_NAME_HINT = re.compile(r"settings|\.mcp|claude\.md|hooks|[*?\[]", re.IGNORECASE)

_DECISION_RANK = {Decision.ALLOW: 0, Decision.ASK: 1, Decision.DENY: 2}

# ═══════════════════ the INSTALLED guard is not the agent's to change (item C)
#
# ⚠ AN AGENT TOOL CALL THAT WRITES, DELETES, MOVES, STOPS, UNLOADS OR UNINSTALLS
# ANY PART OF THE INSTALLED GUARD IS DENY IN EVERY SESSION (maintainer, 25 Sep). The
# parts are `core/guard_parts.py`'s, read from the installer. A person does any
# of this from their own terminal: the hook only sees agent tool calls.
#
# ⚠ A FLOOR AFTER THE LADDER, AND RELAXATION IS WHY. What the engine decides
# without it varies (ALLOW in a clean session, the irreversible ASK for `rm -rf`,
# `untrusted_unexpected:guard_selfmod` when untrusted), so the floor keeps it as
# `beneath`, and relaxing `installed_guard:guard_selfmod` in a person's
# `~/.sting/policy.json` gives exactly that back (`policy.Overlay.enforce`), never
# a blanket ALLOW. It never relabels a more specific DENY (a credential leaving,
# a canary, a catastrophic delete, an org-policy catch), which relaxing it must
# not reach.
#
# ⚠ THE WRITE READERS ARE THE ENGINE'S OWN, EXTENDED, NOT A SECOND SET. A copy's
# destination is `_copy_operands`' grammar, a delete's operand `_deleted_by`'s,
# a redirect's `_REDIRECT_TARGET`, each resolved by `_resolved` (`~`, `$HOME`,
# quotes, braces, globs) against the `cd` in effect. What was missing (tee, sed
# -i, curl, wget, -OutFile, rsync, patch, dd, truncate) is read word by word
# below, gated to bytes the shell executes. A stop, an uninstall and a persisted
# STING_ setting are read UNGATED, as the `guard_selfmod` sink reads them: an
# interpreter body can carry one. That is also why a heredoc QUOTING
# `pkill -f shipper.run` reads as one (measured: 21 such records, all in
# the developers' own sessions writing Sting's docs and tests).
#
# ⚠ THE SOURCE REPO IS NOT THE GUARD: no part matches ~/sting/sting-engine, so
# developing Sting is exactly as it was. And a read stays a read.
_FLOOR_FAMILIES = frozenset({
    "canary_exfil", "catastrophic_delete", "catastrophic_overwrite",
    "secret_exact", "secret_derived_external", "policy_source_deny",
    "policy_value_exfil"})

# Every delete verb, not only the recursive ones: a plain `rm` of a guard file
# is enough. `cp`/`mv`/`install`/`ln` wherever the shell executes one (`sudo cp`,
# a `bash -c` body), not only at the start of a command.
_DELETE_NAMES = "rm|unlink|rmdir|shred"
_COPY_NAMES = "cp|mv|install|ln"
_GUARD_DELETE_VERB = _verb(_DELETE_NAMES)
_GUARD_COPY_VERB = re.compile(rf"(?<![\w.-])({_COPY_NAMES})\s+({_SEGMENT_REST})")
_WORD = re.compile(_SHELL_TOKEN)
_REDIRECT_WORD = guard_runs.REDIRECT_WORD
_OUTFILE = re.compile(r"(?<!\S)-OutFile\s+(?P<target>\S+)", re.IGNORECASE)
_CURL_FLAGS = "sSLfkvqiIN#"          # boolean short flags a `-o` can follow
_WGET_FLAGS = "qvcNrkpEbnx"


class _Touch(NamedTuple):
    """What an action does to which guard part, and where in its command (or
    the path a Write or Edit names). DENY unless it says otherwise; `reason`,
    when set, replaces the part's standard one."""
    doing: str
    part: str
    start: int = -1
    end: int = -1
    evidence: str = ""
    decision: Decision = Decision.DENY
    reason: str = ""


class _Target(NamedTuple):
    """A path a verb writes, as written, and where. A directory the verb writes
    INTO (curl -O, wget, patch with no file) is a target too: a write inside a
    part is a write to it."""
    start: int
    end: int
    text: str


def _words_after(command: str, at: int) -> list[re.Match]:
    """The words from `at` to the end of that segment, without its redirects
    (`_REDIRECT_TARGET` reads those): `tee f 2>/dev/null` writes `f` only."""
    words, skip_next = [], False
    for word in _WORD.finditer(command, at, _segment_end(command, at)):
        operator = _REDIRECT_WORD.match(word.group(0))
        if skip_next:
            skip_next = False
        elif operator:
            skip_next = operator.end() == len(word.group(0))   # `> f`: f is next
        else:
            words.append(word)
    return words


def _flag_values(words: list[re.Match], short: str, long: tuple[str, ...],
                 flags: str = "") -> list[_Target]:
    """The values of one option, however spelled: `-o V`, `-oV`, `-so V` (after
    boolean flags in `flags`), `--output V`, `--output=V`."""
    out: list[_Target] = []
    for i, word in enumerate(words):
        text, after = word.group(0), (words[i + 1] if i + 1 < len(words) else None)
        if text in long and after:
            out.append(_Target(after.start(), after.end(), after.group(0)))
        elif any(text.startswith(f"{name}=") for name in long):
            out.append(_Target(word.start(), word.end(), text.split("=", 1)[1]))
        elif short and text.startswith("-") and not text.startswith("--"):
            for k, letter in enumerate(text[1:], start=1):
                if letter == short:
                    if text[k + 1:]:
                        out.append(_Target(word.start(), word.end(), text[k + 1:]))
                    elif after:
                        out.append(_Target(after.start(), after.end(), after.group(0)))
                    break
                if letter not in flags:
                    break
    return out


def _has_flag(words: list[re.Match], short: str, long: tuple[str, ...],
              flags: str) -> re.Match | None:
    """The word carrying a boolean option (`-O`, `-sSO`, `--remote-name`)."""
    for word in words:
        text = word.group(0)
        if text in long:
            return word
        if text.startswith("-") and not text.startswith("--"):
            for letter in text[1:]:
                if letter == short:
                    return word
                if letter not in flags:
                    break
    return None


def _operands(words: list[re.Match], takes_value: frozenset[str]) -> list[re.Match]:
    """The words that are not options, skipping each value of `takes_value`."""
    out, skip = [], False
    for word in words:
        text = word.group(0)
        if skip:
            skip = False
        elif text in takes_value:
            skip = True
        elif not text.startswith("-"):
            out.append(word)
    return out


def _as_targets(words: list[re.Match]) -> list[_Target]:
    return [_Target(w.start(), w.end(), w.group(0)) for w in words]


def _tee_writes(_verb: re.Match, words: list[re.Match]) -> list[_Target]:
    return _as_targets(w for w in words if not w.group(0).startswith("-"))


_SED_IN_PLACE = re.compile(r"-[A-Za-z]*i|--in-place")


def _sed_writes(_verb: re.Match, words: list[re.Match]) -> list[_Target]:
    """`sed -i` rewrites every FILE operand. The first operand is the script
    unless `-e` / `-f` gave one."""
    texts = [w.group(0) for w in words]
    if not any(_SED_IN_PLACE.match(t) for t in texts):
        return []
    scripted = any(t in ("-e", "--expression", "-f", "--file")
                   or t.startswith(("--expression=", "--file=")) for t in texts)
    files = _operands(words, frozenset({"-e", "--expression", "-f", "--file",
                                        "-l", "--line-length"}))
    return _as_targets(files if scripted else files[1:])


def _curl_writes(_verb: re.Match, words: list[re.Match]) -> list[_Target]:
    out = _flag_values(words, "o", ("--output",), _CURL_FLAGS)
    remote = _has_flag(words, "O", ("--remote-name", "--remote-name-all"), _CURL_FLAGS)
    if remote:
        into = _flag_values(words, "", ("--output-dir",))
        out.append(_Target(remote.start(), remote.end(),
                           into[0].text if into else "."))
    return out


def _wget_writes(_verb: re.Match, words: list[re.Match]) -> list[_Target]:
    """`-O FILE` (never `-O -`, which is stdout), the log of `-o`, and with no
    `-O` a download INTO the directory (`-P DIR`, or the one it runs in)."""
    documents = _flag_values(words, "O", ("--output-document",), _WGET_FLAGS)
    out = [t for t in documents if t.text != "-"]
    out += _flag_values(words, "o", ("--output-file", "--append-output"), _WGET_FLAGS)
    urls = [w for w in words if "://" in w.group(0)]
    if urls and not documents and "--spider" not in {w.group(0) for w in words}:
        into = _flag_values(words, "P", ("--directory-prefix",), _WGET_FLAGS)
        out.append(_Target(urls[0].start(), urls[0].end(),
                           into[0].text if into else "."))
    return out


_RSYNC_VALUES = frozenset({"-e", "--rsh", "-f", "--filter", "--exclude",
                           "--include", "--exclude-from", "--include-from",
                           "--files-from", "-T", "--temp-dir", "--chmod"})


def _rsync_writes(_verb: re.Match, words: list[re.Match]) -> list[_Target]:
    operands = _operands(words, _RSYNC_VALUES)
    return _as_targets(operands[-1:]) if len(operands) >= 2 else []


_PATCH_VALUES = frozenset({"-p", "-i", "-o", "-d", "-r", "-B", "-z", "-Y", "-D",
                           "-F", "-V", "-g", "--input", "--output", "--directory",
                           "--reject-file", "--prefix", "--suffix", "--strip"})


def _patch_writes(verb: re.Match, words: list[re.Match]) -> list[_Target]:
    """`patch [FILE [PATCHFILE]]` rewrites FILE; with none it writes the files
    the diff names, INTO its directory (`-d DIR`, or the one it runs in)."""
    out = _flag_values(words, "o", ("--output",)) + _flag_values(words, "r", ("--reject-file",))
    operands = _operands(words, _PATCH_VALUES)
    if operands:
        return out + _as_targets(operands[:1])
    into = _flag_values(words, "d", ("--directory",))
    return out + [_Target(verb.start(), verb.end(), into[0].text if into else ".")]


def _dd_writes(_verb: re.Match, words: list[re.Match]) -> list[_Target]:
    return [_Target(w.start(), w.end(), w.group(0)[3:])
            for w in words if w.group(0).startswith("of=")]


def _truncate_writes(_verb: re.Match, words: list[re.Match]) -> list[_Target]:
    return _as_targets(_operands(words, frozenset({"-s", "--size", "-r", "--reference"})))


_PS_PATH_OPTIONS = ("-filepath", "-path", "-literalpath")


def _content_cmdlet_writes(_verb: re.Match, words: list[re.Match]) -> list[_Target]:
    """`Out-File` / `Set-Content` / `Add-Content`: `-FilePath`, `-Path` or
    `-LiteralPath`, else the first positional word."""
    for i, word in enumerate(words[:-1]):
        if word.group(0).lower() in _PS_PATH_OPTIONS:
            return _as_targets(words[i + 1:i + 2])
    positional = [w for w in words if not w.group(0).startswith("-")]
    return _as_targets(positional[:1])


_WRITE_READERS = (
    ("tee", _tee_writes),
    ("sed", _sed_writes),
    (r"curl(?:\.exe)?", _curl_writes),
    ("wget", _wget_writes),
    ("rsync", _rsync_writes),
    ("patch", _patch_writes),
    ("dd", _dd_writes),
    ("truncate", _truncate_writes),
    ("(?i:Out-File|Set-Content|Add-Content)", _content_cmdlet_writes),
)
# One scan for every write verb; the group that matched names its reader.
_WRITE_VERB = _verb("|".join(f"(?P<w{i}>{name})"
                             for i, (name, _reader) in enumerate(_WRITE_READERS)))

# ⚠ WHAT COULD BE A TOUCH AT ALL, ASKED OF THE RAW TEXT BEFORE ANY OF THE WORK.
# Every reader here needs its verb or a `>` in the text, a stop needs a stop
# verb, the persisted setting needs `STING_`, and the structure view only ever
# replaces bytes by `x`, so it cannot add one. Built from the readers' own name
# lists, so the two cannot drift. Measured on 15,200 recorded commands: the
# floor cost p50 0.28 ms / p99 4.8 ms per command without it.
_COULD_WRITE = _verb("|".join([_DELETE_NAMES, _COPY_NAMES]
                              + [name for name, _reader in _WRITE_READERS]))
# A redirect onto a descriptor (`2>&1`) or into /dev (`2>/dev/null`) writes no
# part, and those two are in most commands.
_COULD_REDIRECT = re.compile(r">[>|]?\s*(?!&|/dev/)|-OutFile", re.IGNORECASE)


def _redirect_writes(command: str, at_code: Callable[[int], bool]) -> list[_Target]:
    """Every redirect's target (`>`, `>>`, `>|`, `2>`, `&>`), and `-OutFile`."""
    out = []
    for match in list(_REDIRECT_TARGET.finditer(command)) + list(_OUTFILE.finditer(command)):
        target = re.split(r"[;&|()]", match.group("target"))[0]
        if (at_code(match.start()) and target
                and not target.startswith(("&", "/dev/"))):
            out.append(_Target(match.start(), match.end(), target))
    return out


def _verb_writes(command: str, at_code: Callable[[int], bool]) -> list[_Target]:
    """Every path a write verb names.

    ⚠ ONE READING PER VERB PER SEGMENT (security review of item C). Reading
    the rest of the segment again at every `tee` made `tee tee tee …`
    quadratic, and a hook that outruns its timeout decides nothing. The first
    of a kind reads every word after it, so a later one adds nothing."""
    out: list[_Target] = []
    read_until: dict[str, int] = {}
    for verb in _WRITE_VERB.finditer(command):
        if verb.start() < read_until.get(verb.lastgroup, -1) or not at_code(verb.start()):
            continue
        read_until[verb.lastgroup] = _segment_end(command, verb.start())
        reader = _WRITE_READERS[int(verb.lastgroup[1:])][1]
        out += reader(verb, _words_after(command, verb.end()))
    return out


def _written(command: str, cwd: str) -> Iterator[tuple[str, str, int, int]]:
    """(doing, resolved path, start, end) for every path this command deletes,
    moves or writes, read with the engine's own readers, `cd` folded. Lazy, so a
    caller that finds what it wants stops the reading. The installed-guard floor
    and `config_selfmod` both read it.

    ⚠ NOT GATED ON THE PARSE, unlike the DENY rules that read a mask to EXEMPT.
    An unparseable command is all code here, which can only find more: one
    unbalanced quote (`…> ~/.sting/policy.json; echo "`) must not switch the
    floor off, and the agent chooses whether its command parses. The cost is 0
    in the live logs, whose parse failures are all clipped records."""
    mask, _ = code_mask_checked(command)

    def at_code(at: int) -> bool:
        return 0 <= at < len(mask) and bool(mask[at])

    for verb, path in _deleted_by(command, cwd, _GUARD_DELETE_VERB, at_code):
        yield "deletes", path, verb.start(), verb.end()
    copies = [m for m in _GUARD_COPY_VERB.finditer(command) if at_code(m.start(1))]
    writes = _redirect_writes(command, at_code) + _verb_writes(command, at_code)
    if not copies and not writes:
        return
    assignments = _literal_assignments(command)
    lenient = bool(_SHOPT_WIDENS_GLOB.search(command))
    starts = sorted({m.start() for m in copies} | {t.start for t in writes})
    base_at = dict(zip(starts, _cd_bases(command, starts, cwd, assignments)))
    for match in copies:
        shape = _copy_operands(match.group(1), match.group(2))
        if shape is None:
            continue
        sources, destination, _to_dir = shape
        base = base_at[match.start()]
        if match.group(1) == "mv":            # an `mv` takes its sources away
            for source in sources:
                for path in _resolved(source, base, assignments, lenient):
                    yield "moves", path, match.start(1), match.end()
        for path in _resolved(destination, base, assignments, lenient):
            yield "writes", path, match.start(1), match.end()
    for target in writes:
        for path in _resolved(target.text, base_at[target.start], assignments, lenient):
            yield "writes", path, target.start, target.end


def _config_written(command: str, cwd: str) -> str | None:
    """The first agent config this command writes, for `config_selfmod`."""
    if not (_CONFIG_NAME_HINT.search(command)
            and (_COULD_WRITE.search(command) or _COULD_REDIRECT.search(command))):
        return None
    return next((path for doing, path, _start, _end in _written(command, cwd)
                 if doing == "writes" and CONFIG_SELFMOD_PATHS.search(path)), None)


def _strongest(touches) -> _Touch | None:
    """The first DENY among lazily produced touches, else the first ASK."""
    asked = None
    for touch in touches:
        if touch is not None:
            if touch.decision is Decision.DENY:
                return touch
            asked = asked or touch
    return asked


def _guard_file_touch(command: str, cwd: str, switch: bool = False) -> _Touch | None:
    """The strongest touch this command makes on the guard by path. `switch`:
    the command names `disableAllHooks` or a STING_ variable."""
    dotglob = bool(_SHOPT_WIDENS_GLOB.search(command))
    return _strongest(_path_touch(doing, path, start, end, switch, dotglob)
                      for doing, path, start, end in _written(command, cwd))


_SHELL_EDIT_REASON = (
    f"this edits {hook_configs.CLAUDE_SETTINGS} by shell, and the guard cannot "
    f"see what the edit leaves: the file holds the guard's hook for Claude Code. "
    f"You can make this edit yourself from your own terminal, where the hook does "
    f"not run")


def _path_touch(doing: str, path: str, start: int, end: int,
                switch: bool, dotglob: bool = False) -> _Touch | None:
    """What deleting, moving or writing one path does to the guard."""
    if doing != "writes":
        part = guard_parts.holder_of(path, dotglob)
        return _Touch(doing, part, start, end) if part else None
    part = guard_parts.part_at(path, dotglob)
    if part:
        return _Touch("writes", part, start, end)
    user = hook_configs.is_claude_user_settings(path)
    layer = hook_configs.settings_layer(path)
    if switch and (user or layer):
        return _Touch("writes", layer or hook_configs.CLAUDE_SETTINGS, start, end,
                      reason=_switch_reason(layer or hook_configs.CLAUDE_SETTINGS, path,
                                            "the command sets disableAllHooks or a "
                                            "STING_ variable"))
    if user:
        return _Touch("edits", hook_configs.CLAUDE_SETTINGS, start, end,
                      decision=Decision.ASK, reason=_SHELL_EDIT_REASON)
    return None


def _switch_reason(what: str, path: str, why: str) -> str:
    return (f"this writes {what} ({path}), where {why}: that switches off the "
            f"installed Sting guard, which no agent may do in any session. You can "
            f"do this yourself from your own terminal, where the hook does not run")


def _hook_reason(doing: str, why: str) -> str:
    return (f"this {doing} {hook_configs.CLAUDE_SETTINGS}, where {why}. The guard's "
            f"hook there is part of the installed Sting guard, which no agent may "
            f"change in any session. You can do this yourself from your own "
            f"terminal, where the hook does not run")


def _file_tool_touch(action: Action, path: str) -> _Touch | None:
    """What a Write or Edit of one path does to the guard: a part by path; the
    user's Claude settings by what the change keeps (item C step 3b); any other
    settings layer by whether it switches hooks or the guard off."""
    norm = _norm_path(_abs(path, action.cwd))
    evidence = f"path={path}"
    part = guard_parts.part_at(norm)
    if part:
        return _Touch("writes", part, evidence=evidence)
    writing = action.kind is ActionKind.WRITE
    if hook_configs.is_claude_user_settings(norm):
        why = (hook_configs.claude_settings_problem(action.content, _stops_the_guard)
               if writing else hook_configs.claude_edit_problem(action.replaced,
                                                                action.content))
        doing = "writes" if writing else "edits"
        return _Touch(doing, hook_configs.CLAUDE_SETTINGS, evidence=evidence,
                      reason=_hook_reason(doing, why)) if why else None
    layer = hook_configs.settings_layer(norm)
    if layer:
        why = (hook_configs.layer_problem(action.content) if writing
               else hook_configs.layer_edit_problem(action.content))
        return _Touch("writes", layer, evidence=evidence,
                      reason=_switch_reason(layer, path, why)) if why else None
    return None


def _stops_the_guard(command: str) -> bool:
    """A hook command in a settings file that the floor would refuse to run as
    a stop, asked by the Claude settings check."""
    return _guard_stop(command) is not None


def _process_name(name: str) -> str:
    lowered = name.lower()
    if "shipper" in lowered:
        return "the shipper, which reports the guard's decisions"
    if "daemon" in lowered or "stingd" in lowered:
        return "the guard's daemon"
    return "the guard's hook"


def _guard_stop(command: str) -> _Touch | None:
    """A stop, unload or uninstall of the guard, named by process, service or
    package. UNGATED, as the `guard_selfmod` sink is: `python -c
    "os.system('pkill -f shipper.run')"` is data to the shell and a stop to the
    machine. Scoped to one segment, so a verb and a name in two different
    commands are not a pair."""
    cues = [cue.start() for cue in guard_parts.STOP_CUE.finditer(command)]
    begin, next_cue = 0, 0
    while next_cue < len(cues):
        end = _segment_end(command, begin)
        if cues[next_cue] <= end:            # only a segment holding a cue is read
            touch = _segment_stop(command[begin:end], begin)
            if touch:
                return touch
            while next_cue < len(cues) and cues[next_cue] <= end:
                next_cue += 1
        begin = end + 1
    return None


def _segment_stop(segment: str, at: int) -> _Touch | None:
    """`_guard_stop` for one segment starting at offset `at`."""
    found = guard_parts.uninstalls(segment)
    if found:
        return _Touch("uninstalls", "the guard itself",
                      at + found.start(), at + found.end())
    found = guard_parts.service_stop(segment)
    label = found and guard_parts.LABEL.search(segment)
    if label:
        return _Touch("stops", guard_parts.part_at(label.group(0)),
                      at + found[0], at + found[1])
    name = guard_parts.KILL.search(segment) and guard_parts.process_named(segment)
    if name:
        return _Touch("stops", _process_name(name.group(0)),
                      at + name.start(), at + name.end())
    return None


def _guard_setting_persisted(command: str) -> _Touch | None:
    """The `guard_selfmod` sink's content shape: a STING_ setting written into a
    shell startup file configures the guard for every later session."""
    found = _STING_PERSISTED.search(command)
    if found is None:
        return None
    return _Touch("writes", "the guard's settings, as a STING_ variable in a "
                  "shell startup file", found.start(), found.end())


def _policy_registry_touch(command: str) -> _Touch | None:
    """A registry write to Claude Code's policy key that switches hooks or the
    guard off (the HKCU value is user-writable). A WRITE, so gated to bytes the
    shell executes and read one segment at a time: a heredoc quoting
    `reg add … ClaudeCode` writes nothing."""
    mask, _ = code_mask_checked(command)
    read_until = -1
    for write in hook_configs.REGISTRY_WRITE.finditer(command):
        if write.start() < read_until or not (write.start() < len(mask)
                                              and mask[write.start()]):
            continue
        end = read_until = _segment_end(command, write.start())   # once per segment
        if hook_configs.writes_the_policy_registry(command[write.start():end]):
            break
    else:
        return None
    return _Touch("writes", "Claude Code's managed policy in the registry",
                  write.start(), end,
                  reason=_switch_reason("Claude Code's managed policy",
                                        "HKCU\\SOFTWARE\\Policies\\ClaudeCode",
                                        "the command sets disableAllHooks or a "
                                        "STING_ variable"))


def _nested_claude(command: str) -> _Touch | None:
    """A `claude` this command RUNS with the guard's hook off (`--bare`, or
    `--settings` that switches hooks or the guard off). Gated to bytes the shell
    executes: `claude --bare -p` is the documented way to script Claude Code,
    and a CI file written by a heredoc runs nothing now."""
    mask, _ = code_mask_checked(command)
    read_until = -1
    for run in hook_configs.CLAUDE_RUN.finditer(command):
        if run.start() < read_until or not (run.start() < len(mask) and mask[run.start()]):
            continue
        end = read_until = _segment_end(command, run.start())   # once per segment
        why = hook_configs.starts_claude_unguarded(command[run.start():end])
        if why:
            return _Touch("starts", "a Claude Code session without the guard's hook",
                          run.start(), end,
                          reason=(f"this starts {why}: a Claude Code session the "
                                  f"installed Sting guard cannot see, which no agent "
                                  f"may start in any session. You can run it "
                                  f"yourself from your own terminal, where the hook "
                                  f"does not run"))
    return None


def _override_run(command: str) -> _Touch | None:
    """A segment that RUNS `tools/allow_once.py` (`guard_runs.override_run`).

    ⚠ ITS REASON DOES NOT DESCRIBE THE TOOL (item 3). It read "this runs the
    guard's one-shot override (allow-once), which re-allows an action the
    guard refused … You can do this yourself from your own terminal": the
    model learnt that the tool exists, what it does and where it works. The
    person reads it in the install's closing block and the README."""
    span = guard_runs.override_run(command)
    if span is None:
        return None
    return _Touch("runs", "a part of the installed Sting guard", *span, reason=(
        "this runs a part of the installed Sting guard that no agent may run, "
        "in any session"))


def _installer_run(command: str) -> _Touch | None:
    """A segment that RUNS install.py in a way that changes the install
    (`guard_runs.installer_run`, item 2). Its reason names no switch: the
    person reads how to change the mode in `--help`, from their own terminal."""
    span = guard_runs.installer_run(command)
    if span is None:
        return None
    return _Touch("runs", "install.py", *span, reason=(
        "this runs install.py in a way that changes the installed Sting guard, "
        "which no agent may do in any session. On their own, --status, --dry-run "
        "and --check-only change nothing"))


def touched_guard_part(action: Action, state: SessionState | None = None
                       ) -> _Touch | None:
    """What this action does to a part of the INSTALLED guard, or None.

    Pure: paths and text only, no IO. A Write or Edit is judged by its path, and
    a Claude Code settings file by what the change keeps (item C step 3b). A
    shell command by what it stops or uninstalls (by name), by what it deletes,
    moves or writes (the engine's own readers, `cd` folded), by a STING_ setting
    it persists, by a policy it puts in the registry, by a `claude` it runs
    with the hook off, and by a guard tool it runs (`guard_runs`: the one-shot
    override, and install.py but for the runs that change nothing). The
    strongest touch wins: a DENY over an ASK."""
    if action.kind in (ActionKind.WRITE, ActionKind.EDIT):
        return _strongest(_file_tool_touch(action, path) for path in action.paths)
    if action.kind is not ActionKind.EXEC or not action.command:
        return None
    raw = action.command
    could_stop = guard_parts.could_stop(raw)
    could_write = bool(_COULD_WRITE.search(raw) or _COULD_REDIRECT.search(raw))
    could_persist = "STING_" in raw
    could_run = hook_configs.CLAUDE_RUN.search(raw) is not None
    could_register = hook_configs.POLICY_KEY.search(raw) is not None
    could_override = "allow_once" in raw.lower()
    could_install = "install.py" in raw.lower()
    if not (could_stop or could_write or could_persist or could_run or could_register
            or could_override or could_install):
        return None
    command = _structure_action(action, state or SessionState()).command
    switch = hook_configs.names_a_switch(command)
    return _strongest(touch() for touch in (
        lambda: could_override and _override_run(command) or None,
        lambda: could_stop and _guard_stop(command) or None,
        lambda: could_register and _policy_registry_touch(command) or None,
        lambda: could_run and _nested_claude(command) or None,
        lambda: could_write and _guard_file_touch(command, action.cwd, switch) or None,
        lambda: could_persist and _guard_setting_persisted(command) or None,
        # Last: a stop, a write or the override above keeps its own touch.
        lambda: could_install and _installer_run(command) or None))


def _guard_floor(verdict: Verdict, action: Action,
                 state: SessionState | None = None) -> Verdict:
    """DENY (or, for a shell edit of the Claude settings, ASK) an action on the
    installed guard, over whatever was decided, keeping that verdict as
    `beneath`. A stricter verdict stays, and a more specific DENY keeps its own
    name."""
    touch = touched_guard_part(action, state)
    if touch is None:
        return verdict
    if _DECISION_RANK[verdict.decision] > _DECISION_RANK[touch.decision]:
        return verdict
    family = (verdict.rule_id or "").partition(":")[0]
    if verdict.decision is Decision.DENY and family in _FLOOR_FAMILIES:
        return verdict
    reason = touch.reason or (
        f"this {touch.doing} {touch.part}: part of the installed Sting guard, which "
        f"no agent may change in any session. You can do this yourself from your "
        f"own terminal, where the hook does not run")
    evidence = touch.evidence or span_evidence(action.command or "", touch.start,
                                               touch.end)
    if touch.decision is Decision.ASK:
        return Verdict(Decision.ASK, reason, "installed_guard:settings_shell_edit",
                       evidence=evidence, beneath=verdict)
    return Verdict(Decision.DENY, reason, "installed_guard:guard_selfmod",
                   evidence=evidence, beneath=verdict)
