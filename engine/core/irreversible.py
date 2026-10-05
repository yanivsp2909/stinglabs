"""Mechanism 1, irreversible actions: deletion targets and cd folding,
regenerable artifacts and declared scratch, a truncated credential file, and
the catastrophic roots (row f): a deleted root, the find sweep, a raw block
device.

Moved out of core/engine.py; docs/ENGINE_LAYOUT.md.
"""
from __future__ import annotations

import bisect
import re
from collections.abc import Callable

from core.shell_scan import (UNPARSED, bail_reason, code_mask_checked,
                             first_code_match, shell_bodies)
from core.types import Action, ActionKind, World
from core.command_text import (_NOT_SEGMENT_END, _REDIRECT_TARGET, _SEGMENT_END,
                               _WINDOWS_ABSOLUTE, _abs, _bash_unquote, _expand,
                               _join_line_continuations, _literal_assignments,
                               _norm_path, _segment_end, _verb, is_inside_project)
from core.credentials import CREDENTIAL_PATHS
from core.globbing import (_EXPANSION_CHARS, _GlobToken, _RAW_WORD,
                           _SHOPT_WIDENS_GLOB, _intersect, _lit, _marked_words,
                           _segments, _shape, _word_expansions)


def _operand_forms(token: str, base: str | None = None,
                   lenient: bool = False) -> tuple[str, ...]:
    """A shell operand as WRITTEN, plus its bash-resolved form when they differ.

    The resolved form decodes quoting/glue and ANSI-C escaping — `$'\\x2f'` -> `/`,
    `"/"` -> `/` — so a destructive target hidden in either is recognised the same
    as its plaintext spelling. Returned BESIDE the raw token and unioned by the
    caller, never in place of it: a decode can only ADD a resolution, never drop
    the literal one, so the pre-change catch set is preserved by construction.

    ⚠ AND AS BASH EXPANDS IT (row f, docs/91). `rm -rf /e{tc,x}` and `rm -rf /et?`
    delete /etc exactly as `rm -rf /etc` does, and were ASK where it is DENY;
    `find /et? -delete` was ALLOW. `_destructive_forms` reads the operand through
    #61's expander and adds the catastrophic roots it could name — appended, so
    the two forms above are byte-identical. `base` resolves a relative glob
    (`cd / && rm -rf et?`); `lenient` is the command's `shopt` widening.
    """
    resolved = _bash_unquote(token)
    forms = (token,) if resolved == token else (token, resolved)
    return forms + tuple(dict.fromkeys(
        f for f in _destructive_forms(token, base, lenient) if f not in forms))

# ---------------------------------------------------------------- MECHANISM 1
#
# IRREVERSIBILITY — orthogonal to check_sinks(), and it has to be.
#
# An action can be irreversible with no sink at all (J02's `rm -rf` inside the
# project, J04 overwriting .env), or be a sink AND irreversible (J03, J05).
# A ladder branch alone reaches only the second kind: the first exits decide()
# on its very first line. So this is a predicate evaluated alongside the sink,
# not a sink return value.
#
# WHY THIS IS NOT TAINT. Nothing here asks where data came from or where it is
# going. It asks whether the action can be undone. CLAUDE.md and the PRD declare
# mechanism J a permanent non-goal on the grounds that TAINT is irrelevant to
# it — which remains true. This is a deliberate, recorded scope expansion; see
# PROGRESS.md.
#
# ASK, NEVER DENY. Irreversible is not the same as unwanted; a force-push can be
# exactly what the developer meant. The mechanism cannot tell, so it escalates.

_FORCE_PUSH = re.compile(rf"\bgit\s+push\b{_NOT_SEGMENT_END}*--force(?:-with-lease)?\b")
_BRANCH_FORCE_DELETE = re.compile(rf"\bgit\s+branch\b{_NOT_SEGMENT_END}*\s-D\b")
_RESET_HARD = re.compile(rf"\bgit\s+reset\b{_NOT_SEGMENT_END}*--hard\b")
# Recursive/forced only. A plain `rm one_file.txt` is ordinary work.
# ⚠ THE FLAG ENDS AT A BLANK, A SEPARATOR OR THE END (docs/113 §3c): it wanted
# a blank, so `… | xargs rm -rf` ending a command, or before `;`, `)`, `|`,
# `&`, was no recursive delete. `-R` is rm's other spelling of recursive.
# ⚠ AND IT IS LINEAR: `-\w*[rf]\w*\s+` retried every split of the flag word
# when no blank followed it — `rm -` and 64 KB of `r` and a quote stalled for
# minutes. The letter is a lookahead; the word is then taken whole.
# ⚠ AFTER rm's OTHER OPTIONS TOO (the round-1 python review): `rm -v -rf x`,
# `rm -i --verbose -f x`. The options run is lazy, so the FIRST destructive
# flag is the match, as before; `--` ends the options (`rm -- -rf` deletes a
# file named `-rf`). ⚠ A CLOSING BACKTICK DOES NOT END ONE: the review asked,
# and the standing replay answered — a bare `` `rm -rf` `` names nothing to
# delete, and it is how Markdown quotes the command (an ALLOW → ASK on a
# heredoc that edited PROGRESS.md).
# ⚠ AT MOST 16 OF THEM (the round-2 security review): every `rm` inside a
# `--rm` word is a start of its own, and an unbounded run let each start walk
# the rest of the text — `rm --rm --rm … x` was quadratic. main read none.
_RM_DESTRUCTIVE = re.compile(
    r"\brm\s+(?:-(?:-?\w[\w-]*)\s+){0,16}?"
    r"(?:-(?=\w*[rfR])\w+(?:\s+|(?=[;&|)\n])|$)|--(?:recursive|force)\b)"
    r"|\bshred\b")
_SQL_DESTRUCTIVE = re.compile(
    r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|COLUMN)\b|\bTRUNCATE\b"
    r"|\bALTER\s+TABLE\b[^;]*\bDROP\b", re.I)
_SQL_DELETE_UNSCOPED = re.compile(r"\bDELETE\s+FROM\b(?![^;]*\bWHERE\b)", re.I)

_IRREVERSIBLE_COMMANDS = (
    (_FORCE_PUSH, "a force-push rewrites history other clones cannot recover"),
    (_BRANCH_FORCE_DELETE, "`git branch -D` deletes an unmerged branch; `-d` "
                            "refuses to, which is git's own guard"),
    (_RESET_HARD, "`git reset --hard` discards uncommitted work"),
    (_RM_DESTRUCTIVE, "a recursive or forced delete"),
    (_SQL_DESTRUCTIVE, "a schema change that drops data"),
    (_SQL_DELETE_UNSCOPED, "a DELETE with no WHERE clause"),
)

# Which of those patterns names something the command DELETES, so a target-based
# exemption is even meaningful. A force-push, a `branch -D` and a `reset --hard`
# destroy git state rather than a path; SQL destroys rows. None of them has a
# filesystem operand to test against a scratch root, and pretending otherwise
# would silently widen the exemption to rules it was never argued for.
_DELETES_A_PATH = frozenset({_RM_DESTRUCTIVE})

REGENERABLE_ARTIFACTS = frozenset({
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".eggs",
    "node_modules", ".next", ".nuxt", "dist", "build", ".venv", "venv",
    # ⚠ TEST-COVERAGE AND BUILD OUTPUT — the same class as the caches above, and
    # the ENTIRE measured false-positive rate of the blind-spot coverage map
    # (docs/86): `rm -rf coverage` / `rm -rf target` asked on throwaway output.
    # coverage.py writes `coverage`/`htmlcov`/`.coverage`; nyc writes
    # `.nyc_output`; Gradle and Parcel write `.gradle`/`.parcel-cache` — all
    # tool-specific names that are never anything but regenerable output.
    "coverage", "htmlcov", ".coverage", ".nyc_output", ".gradle", ".parcel-cache",
    # `target` and `out` are ALSO ordinary words — see `_MANIFEST_GATED` below:
    # they are forgiven only with a sibling build manifest, never on the name
    # alone. They are listed here so the allowlist stays the single contract,
    # but `_is_regenerable_artifact` reaches the gate before this membership.
    "target", "out",
})
"""⚠ KNOWN-ARTIFACT IDENTITY, AND NOTHING ELSE. Deleting one of these is not an
irreversible act: the interpreter, the package manager or the build regenerates
it on the next run. Measured on one machine's real logs before this existed:
128 `irreversible_action` prompts across 62 sessions, 48 with `__pycache__` as
the first operand, one session asking 41 times for the same cache — on an
install with observe mode OFF, so every one was a live interruption on
throwaway junk.

⚠ WHAT IS NOT HERE, DELIBERATELY. Nothing that names WORK: `src`, a file, a
directory the developer typed. Nothing matched by directory-is-inside-project —
`src/` is inside the project and is exactly what the rule exists to catch. And
nothing broad enough to hide a real target behind a glob: the basename must BE
one of these names (or carry one of the suffixes below); `*` in a directory
component cannot leave the declared root, and `*` as the whole basename is not
a name. Adding an entry is a decision somebody writes down here."""

_REGENERABLE_SUFFIXES = (".pyc", ".pyo", ".egg-info")
"""The file-shaped artifacts: `*.pyc`, `*.pyo`, `*.egg-info`, matched on the
basename's suffix so `rm -f app.pyc` and `rm -rf *.pyc` both qualify."""


_MANIFEST_GATED = frozenset({"target", "out"})
"""⚠ THE TWO NAMES THAT ARE ALSO ENGLISH WORDS. `target` is Cargo's/Maven's/
Gradle's build dir and `out` is a Next export / `tsc --outDir` — but in a
project with NO build tool, both are just directories a developer may keep real
data in. Unlike `__pycache__` (never anything but a cache), forgiving them on
the BASENAME alone silently allows `rm -rf out` over a week of computed results
in a repo that has no build system at all — a gap a follow-up check measured
through the real engine after docs/86's fix. So these two are forgiven ONLY when a sibling build manifest
proves the directory IS build output; without one they fall through to the
prompt like `src`. The other six additions carry no such ambiguity."""

_BUILD_MANIFESTS = {
    # A manifest that, sitting beside the directory, proves it is build output.
    "target": ("Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts"),
    "out": ("next.config.js", "next.config.mjs", "next.config.ts",
            "next.config.cjs", "tsconfig.json", "package.json"),
}


def _is_regenerable_artifact(path: str, roots: tuple[str, ...],
                             world: World) -> bool:
    """Is THIS resolved deletion target a known regenerable artifact, strictly
    inside a declared project root?

    Four refusals, each closing a trap:
      a `$` or a backtick     an unresolved substitution names a path nobody
                              knows — `_expand` leaves it in on purpose, and
                              `_abs` then prefixes it with the cwd, which would
                              read as "inside" by string alone. Refused first.
      outside every root      `~/node_modules`, `/tmp/__pycache__`,
                              `../__pycache__` after normalising.
      the root itself         `is_inside_project` counts equality as inside;
                              a project CALLED `build` is still the project.
      not a listed name       everything else — a source file, a directory the
                              developer typed, `{}` from find, a bare `*`.
    """
    if "$" in path or "`" in path:
        return False
    normalised = path.rstrip("/")
    for root in roots:
        if root and normalised == root.rstrip("/"):
            return False
    if not is_inside_project(normalised, roots):
        return False
    name = normalised.rsplit("/", 1)[-1]
    if name in _MANIFEST_GATED:
        # A generic name is build output only when a build manifest sits beside
        # the directory. `world.read_text` returning non-None IS the existence
        # probe (manifests are small); a NullWorld — or a real repo with no
        # such file — answers None, so the delete falls through to the prompt.
        parent = normalised.rsplit("/", 1)[0] if "/" in normalised else ""
        return any(world.read_text(f"{parent}/{m}" if parent else m) is not None
                   for m in _BUILD_MANIFESTS[name])
    if name in REGENERABLE_ARTIFACTS:
        return True
    return name.endswith(_REGENERABLE_SUFFIXES) and name not in _REGENERABLE_SUFFIXES


def _deletes_only_regenerable_artifacts(command: str, cwd: str,
                                         roots: tuple[str, ...],
                                         world: World) -> bool:
    """Is EVERY path this command deletes a regenerable artifact inside a
    declared project root? ALL, never ANY: `rm -rf __pycache__ src/` is not
    half safe. No roots declared, or nothing parsed, is a prompt — absence of a
    setting is never permission, and the same three-way refusal
    `_deletes_only_declared_scratch` argues for applies here unchanged."""
    if not roots:
        return False
    targets = _deletion_targets(command, cwd)
    return bool(targets) and all(_is_regenerable_artifact(t, roots, world) for t in targets)


def _deletion_targets(command: str, cwd: str, verbs: re.Pattern | None = None,
                      at_code: Callable[[int], bool] | None = None
                      ) -> tuple[str, ...]:
    """Every path a delete verb in this command operates on, resolved.

    `verbs` defaults to the recursive or forced deletes (`_RM_DESTRUCTIVE`); the
    installed-guard floor passes every delete verb, because a plain `rm` of a
    guard file is enough. `at_code`, when given, keeps only verbs the shell
    executes (not a quoted `rm` inside an `echo`).

    Empty when nothing could be parsed — and the caller treats empty as NOT
    exempt, so a parse this cannot manage costs a prompt rather than a silent
    permission. That direction is the whole reason the tuple is returned instead
    of a boolean.

    SCOPED THE SAME WAY `destructive_outside` SCOPES ITS OPERANDS, and for the
    reasons already measured there: to the SEGMENT the verb runs in, so a later
    unrelated command contributes nothing, and with redirect destinations removed
    first, because `2>/dev/null` is written to and destroyed by nothing — that one
    produced four denials of ordinary work in a single real session.

    ⚠ A LEADING `cd` IS FOLLOWED, and it has to be: 92.8% of real commands begin
    `cd <somewhere> &&`, so a relative operand resolved against `action.cwd`
    would name a path the command never touches. It does not widen anything an
    attacker controls — the resolved target must still land inside a DECLARED
    root, and `cd <declared root> && rm -rf ../../src` normalises to `/…/src`,
    outside it, and stays caught.
    """
    return tuple(path for _verb, path in _deleted_by(command, cwd, verbs, at_code))


def _deleted_by(command: str, cwd: str, verbs: re.Pattern | None = None,
                at_code: Callable[[int], bool] | None = None
                ) -> list[tuple[re.Match, str]]:
    """(the deleting verb, one resolved path it deletes), for `_deletion_targets`
    and for the installed-guard floor, which also needs WHERE the verb is."""
    if not command:
        return []
    # ⚠ ONE READING PER SEGMENT (security review of item C). The first delete
    # verb's operands are every later word of its segment, so reading again at
    # each later one found nothing new and made `rm rm rm …` quadratic.
    # ⚠ AND A SECOND ONE WHERE THE SEGMENT'S DIRECTORY CHANGED (item C, this
    # pass). `_CD_PREFIX` matches only at a segment's start, so a directory
    # changes at most once inside one: after its leading `cd`. When the first
    # verb IS that `cd`'s target (`cd rm -rf a rm -rf b`), it was read before
    # the `cd` folded, and the later verb's operands were never read from
    # `<cwd>/rm`, where the reference reads them. Still linear: at most two
    # readings a segment, and a reading can only add a target.
    candidates = [match for match in (verbs or _RM_DESTRUCTIVE).finditer(command)
                  if at_code is None or at_code(match.start())]
    if not candidates:
        return []
    assignments = _literal_assignments(command)
    lenient = bool(_SHOPT_WIDENS_GLOB.search(command))
    at_each = _cd_bases(command, [m.start() for m in candidates], cwd, assignments)
    readings: list[tuple[re.Match, int, str]] = []
    read_until, read_from = -1, None
    for match, base in zip(candidates, at_each):
        # Skipped only when its OPERANDS begin inside what was read from the same
        # directory: a match can end past a separator its trailing whitespace
        # swallowed (`rm -rf \n`).
        if match.end() <= read_until and base == read_from:
            continue
        if match.end() > read_until:
            read_until = _segment_end(command, match.end())
        read_from = base
        readings.append((match, read_until, base))
    found: list[tuple[re.Match, str]] = []
    for match, end, base in readings:
        segment = command[match.end():end]
        segment = _REDIRECT_TARGET.sub(" ", segment)
        for token in segment.split():
            if token.startswith("-"):
                continue
            found += [(match, path) for path in
                      _resolved(token, base, assignments, lenient)]
    return found


def _resolved(token: str, base: str, assignments: dict, lenient: bool) -> list[str]:
    """One operand as absolute paths: as written AND as bash would read it after
    decoding quoting/ANSI-C escaping (`$'\\x2f'` -> `/`), braces and globs.
    Unioned, so a decode can only ADD a target the literal pass missed, never
    drop one — the catch-more-never-less rule the credential-path extractors
    follow."""
    return [_norm_path(_abs(_expand(form, assignments), base))
            for form in _operand_forms(token, base, lenient)]


# `cd <dir>` where it STARTS a command — at the string's head or after a
# separator — so a `cd` written inside an argument is not mistaken for one.
#
# ⚠ THE SEPARATOR CLASS MUST MATCH `_SEGMENT_END` (`[;|&\n]`) EXACTLY. It used to
# omit the newline, so a `cd` that began a line rather than following `;`/`&`/`|`
# was not folded into the effective directory — the segment splitter treated the
# newline as a real boundary while this did not. Proven against the real engine:
# `cd .aws && cat credentials` was caught but `<anything>\ncd .aws\ncat
# credentials` returned ALLOW, because the `cd` on its own line was invisible
# here (a `cd` at position 0 was saved only by the `^` branch). Both callers —
# `_cd_resolved_credential_paths` and `_deletion_targets` — inherited the gap.
# Adding `\n` can only FOLD MORE `cd`s, never fewer, so it only ever resolves a
# target more accurately. The trailing `[^\s;&|]+` already stops at a newline via
# `\s`, so only the leading class changes.
#
# ⚠ A QUOTED TARGET KEEPS WHAT IS GLUED TO IT (item C1, docs/101). `cd "/e"tc`
# is `cd /etc` to bash; the quoted alternative stopped at the closing quote and
# folded `/e`. What follows the quote up to a blank or separator is the same word.
_CD_TARGET = r"(?:'[^']*'|\"[^\"]*\")[^\s;&|]*|[^\s;&|]+"
# ⚠ `[^\S\n]*` after the separator, not `\s*`: a newline is itself one, and on
# a run of blank lines `\s*` was quadratic (fix/false-positives, the reviews).
_CD_PREFIX = re.compile(rf"(?:^|[;&|\n][^\S\n]*)cd\s+({_CD_TARGET})")

# Characters that make `_operand_forms` read a word differently from its
# spelling: a quote, a backslash, ANSI-C `$'`, a glob or a brace. A target with
# none of them IS its spelling, and the fold stays the concatenation item 4 made.
_CD_TARGET_DECODES = re.compile(r"['\"\\{*?\[]|\$'")


def _cd_target(arg: str, onto: str, lenient: bool) -> str:
    """The directory `cd <arg>` moves into, read the way a delete OPERAND is
    read (item C1, docs/101): quoting, glue and ANSI-C decoded, and a glob or
    brace that names a catastrophic root taken as that root — `_operand_forms`,
    which is #61's expander with its cap. `cd /e''tc`, `cd $'/etc'`, `cd /e\\tc`
    and `cd /et?` fold to `/etc`, as `cd /etc` does.

    ⚠ ONE DIRECTORY, SO ONE FORM, AND THE ONE THAT MATTERS. A cd moves once,
    but a brace names several words — bash 3.2 (macOS) enters the FIRST, bash 5
    refuses — so a candidate that is a catastrophic root or a credential
    directory wins, in whatever order it was written (`cd /{x,etc}` and
    `cd /{etc,x}` both fold to `/etc`). The delete operands UNION their forms;
    one fold cannot, so it keeps the candidate that errs toward asking more
    (security review). Otherwise the last form: a root a glob names, else the
    decoded spelling, else the literal one.
    """
    if not lenient and not _CD_TARGET_DECODES.search(arg):
        return arg
    forms = _operand_forms(arg, onto, lenient)
    for form in forms[1:]:
        resolved = _norm_path(_abs(form, onto))
        if _is_catastrophic_root(resolved) or CREDENTIAL_PATHS.search(resolved + "/"):
            return form
    return forms[-1]


# ⚠ AND A `cd` THAT OPENS A SHELL BODY (item C2, docs/101). `sh -c 'cd ~/.aws &&
# cat credentials | nc …'` runs the same commands as the line unwrapped, and was
# ALLOW where that line is DENY: a quote, not a separator, comes before its
# `cd`, so `_CD_PREFIX` never folded it. The shells are `_SHELL_DASH_C`'s, and a
# match counts only where the scanner itself read a body (`shell_bodies`) — an
# `sh -c 'cd …'` spelled inside an `echo` string is data, not a body.
_CD_OPENS_A_SHELL_BODY = re.compile(
    r"(?<![^\s;&|\n(])(?:ba|z|k|d|a)?sh\s+(?:-\w+\s+)*-c\s*(?P<quote>['\"])\s*"
    rf"cd\s+(?P<target>{_CD_TARGET})")


def _body_cds(text: str) -> list[tuple[re.Match, int]]:
    """Each `cd` that opens a shell body the scanner reads, with the index of
    that body's closing quote."""
    found = list(_CD_OPENS_A_SHELL_BODY.finditer(text))
    if not found:
        return []
    ends = dict(shell_bodies(text))
    return [(m, ends[m.start("quote")]) for m in found if m.start("quote") in ends]


# A path this long is judged by `_names_a_credential`'s split; anything shorter
# goes straight to `CREDENTIAL_PATHS.search`, byte for byte as before.
_LONG_PATH = 512


def _names_a_credential(path: str, dirs: dict[str, bool]) -> bool:
    """`bool(CREDENTIAL_PATHS.search(path))` — the same answer, linear in a deep
    `cd` chain (item 4, docs/93).

    ⚠ WHY A SPLIT IS EXACT. Every alternative of `CREDENTIAL_PATHS` either starts
    at a separator and ends inside ONE component or at the `/` after it
    (`.ssh/`, `id_rsa`, `.aws/`, `.kube/`), or is anchored at the END and lies in
    the last one or two components (`.env…$`, `.npmrc$`, `.pem$`,
    `.docker/config.json$`). So for a normalised absolute `/c1/…/cm` the search
    is: some directory component, tested as `/ci/`, matches — or the last two
    components, as `/c(m-1)/cm`, do. The directory half is memoised per
    directory within ONE call (`dirs`), never across calls. Only paths past
    `_LONG_PATH` take this route; `tests/test_the_guard_cannot_be_stalled.py`
    checks it against the plain search, and fails if an alternative that spans
    three components is ever added."""
    if (len(path) <= _LONG_PATH or not path.startswith("/")
            or "//" in path or path.endswith("/")):
        return bool(CREDENTIAL_PATHS.search(path))
    directory, _, name = path.rpartition("/")
    parent, _, last_dir = directory.rpartition("/")
    tail = f"/{last_dir}/{name}" if directory else f"/{name}"
    return _directory_names_a_credential(directory, dirs) or bool(
        CREDENTIAL_PATHS.search(tail))


def _is_clean_relative(token: str) -> bool:
    """A relative path `_abs` + `_norm_path` would join to a base unchanged: no
    root, `~`, backslash, drive, empty, `.` or `..` part, and no quote to strip."""
    return bool(token) and token == token.strip().strip("'\"") and not (
        token.startswith(("/", "~", "./", "../")) or token in (".", "..")
        or "\\" in token or "//" in token or "/./" in token or "/../" in token
        or token.endswith(("/", "/.", "/..")) or _WINDOWS_ABSOLUTE.match(token))


def _credential_under(base: str, token: str, dirs: dict[str, bool],
                      clean_bases: dict[str, bool]) -> str | None:
    """`_norm_path(_abs(token, base))` if `CREDENTIAL_PATHS` names it, else None.

    ⚠ THE PATH IS BUILT ONLY WHEN IT IS RETURNED (item 4, docs/93). Under a deep
    `cd` chain every token's full path was built, normalised and searched, and
    each is as long as the chain. A CLEAN token under a normalised base joins as
    `base/token` with nothing to normalise, so the credential test reads the
    base's memoised directory answer, the token's own components and the last
    two components — `_names_a_credential`'s split — and the string is made
    only for a hit. Anything else takes the original route unchanged.
    """
    if base not in clean_bases:
        clean_bases[base] = (_norm_path(base) == base and base.startswith("/")
                             and "\\" not in base)
    if not (clean_bases[base] and _is_clean_relative(token)):
        resolved = _norm_path(_abs(token, base))
        return resolved if _names_a_credential(resolved, dirs) else None
    joined = f"/{token}" if base == "/" else f"{base}/{token}"
    if len(base) + len(token) + 1 <= _LONG_PATH:
        return joined if CREDENTIAL_PATHS.search(joined) else None
    *inner, name = token.split("/")
    directory_hit = (_directory_names_a_credential("" if base == "/" else base, dirs)
                     or any(CREDENTIAL_PATHS.search(f"/{c}/") for c in inner))
    last_dir = inner[-1] if inner else base.rpartition("/")[2]
    tail = f"/{last_dir}/{name}" if (inner or base != "/") else f"/{name}"
    return joined if (directory_hit or CREDENTIAL_PATHS.search(tail)) else None


def _directory_names_a_credential(directory: str, dirs: dict[str, bool]) -> bool:
    """Does any component of `directory` (`/c1/…/ck`), followed by `/`, match?
    Walks up to the nearest directory already answered, then back down."""
    pending: list[str] = []
    while directory and directory not in dirs:
        pending.append(directory)
        directory = directory.rpartition("/")[0]
    answer = dirs.get(directory, False)
    for path in reversed(pending):
        answer = answer or bool(CREDENTIAL_PATHS.search(
            "/" + path.rpartition("/")[2] + "/"))
        dirs[path] = answer
    return answer


def _cd_bases(text: str, starts: list[int], cwd: str, assignments: dict,
              clean: dict[str, bool] | None = None) -> list[str]:
    """The effective directory at each of `starts` (ascending): exactly what
    folding every `_CD_PREFIX` match in `text[:start]` onto `cwd` gives.

    ⚠ FOLDED ONCE, NOT ONCE PER START (item 4, docs/93). Both callers re-folded
    every earlier `cd` for every segment — quadratic in `cd`s, and each fold
    re-normalised a base that grows with the command, so a 7.5 KB
    `cd sub; cat x;` × 500 took 25 s in `decide`.

    ⚠ THE ONE CASE THE FULL-TEXT SCAN READS DIFFERENTLY. A `cd` whose quoted
    argument runs PAST `start` (`cd 'a;b'` split at the `;`) is a longer match in
    the whole text than in `text[:start]`. That one match is re-scanned with
    `endpos=start`, which the regex treats exactly as if the string ended
    there — and every match before it is the same in both, since this pattern
    looks at nothing after the characters it consumes.

    ⚠ A `cd` OPENING A SHELL BODY FOLDS FOR THE REST OF THAT BODY ONLY (item C2,
    docs/101). `sh -c` runs its body in a CHILD shell, so a start after the
    body's closing quote keeps the outer directory — `sh -c 'cd /etc' ; rm -rf .`
    deletes the outer `.`, as bash runs it. A `_CD_PREFIX` cd inside the body
    folds onto both, exactly as before for the outer one.
    """
    known = {} if clean is None else clean     # base -> normalised, `/`-rooted
    lenient = bool(_SHOPT_WIDENS_GLOB.search(text))

    def is_clean(path: str) -> bool:
        return (path.startswith("/") and "\\" not in path
                and _norm_path(path) == path)

    known.setdefault(cwd, is_clean(cwd))

    def fold(arg: str, onto: str) -> str:
        # A clean `cd` onto a clean base is `onto/arg` exactly, with nothing to
        # normalise — one concatenation instead of a walk of the whole chain.
        target = _expand(_cd_target(arg, onto, lenient), assignments)
        if known.get(onto) and _is_clean_relative(target):
            folded = f"/{target}" if onto == "/" else f"{onto}/{target}"
            known[folded] = True
            return folded
        folded = _norm_path(_abs(target, onto))
        known.setdefault(folded, is_clean(folded))
        return folded

    cds = list(_CD_PREFIX.finditer(text))
    opens = _body_cds(text)
    out: list[str] = []
    base, i, b = cwd, 0, 0
    scoped, scope_end = None, -1               # inside a body its `cd` opened
    for start in starts:
        # The two kinds of fold, in the order the shell meets them.
        while ((i < len(cds) and cds[i].end() <= start)
               or (b < len(opens) and opens[b][0].end() <= start)):
            if b < len(opens) and (i >= len(cds) or opens[b][0].end() < cds[i].end()):
                cd, scope_end = opens[b]
                scoped = fold(cd.group("target"), base)
                b += 1
                continue
            if scoped is not None and cds[i].start() < scope_end:
                scoped = fold(cds[i].group(1), scoped)
            base = fold(cds[i].group(1), base)
            i += 1
        here = scoped if scoped is not None and start < scope_end else base
        if i < len(cds) and cds[i].start() < start:
            for cd in _CD_PREFIX.finditer(text, cds[i].start(), start):
                here = fold(cd.group(1), here)
        out.append(here)
    return out


def _cd_resolved_credential_paths(command: str, cwd: str) -> list[str]:
    """Credential files read from a directory an earlier `cd` moved into.

    `cd .aws && cat credentials` -> `/repo/.aws/credentials`. The bare filename
    is generic and is never a candidate on its own; what makes it a credential is
    the EFFECTIVE cwd after folding the preceding `cd`(s). Reuses the exact
    cd-folding the rm/destructive path uses — `_CD_PREFIX`, `_expand`, `_abs`,
    `_norm_path`, `_literal_assignments` — iterated per SEGMENT rather than per
    verb, with redirect targets stripped the same way (`> x` writes, it does not
    read).

    ⚠ GATED ON THE RESOLVED PATH, NOT ON "the cwd is a credential directory".
    That cwd gate is WRONG for `.docker`, which `CREDENTIAL_PATHS` recognises
    ONLY at `.docker/config.json`, never as a bare directory — so
    `cd .docker && cat daemon.json` must stay clean while
    `cd .docker && cat config.json` is caught. Checking the RESOLVED file path
    does exactly that, and is FP-bounded: a token becomes a path only when its
    resolved form is ALREADY a credential shape, so an ordinary cwd, a look-alike
    directory (`my-aws-backup`), or a dynamic `cd` target — `$(...)`, a `$VAR`
    not assigned in this command — resolves to a non-matching path and
    contributes nothing. That last case is the established fail-open direction: a
    genuinely dynamic value beats static analysis.

    Only ADDS to `_paths_mentioned_in`; the existing passes are untouched, so no
    path found today can stop being found (PR #38 stays byte-identical).
    """
    out: list[str] = []
    listed: set[str] = set()                   # `out` as a set, for membership
    dirs: dict[str, bool] = {}                 # one call's memo, `_names_a_credential`
    clean_bases: dict[str, bool] = {}          # one call's memo, `_credential_under`
    # Scan the command AS WRITTEN, then — unioned — as bash reads it after removing
    # line continuations, so a `cd` target or filename spelled across a `\<newline>`
    # (`cd .a\<newline>ws && cat credentials`, `cat creden\<newline>tials`) resolves
    # like its one-line form. The raw pass below is byte-identical to before and
    # runs first; the joined pass only APPENDS paths not already found, so no path
    # recognised today can stop being recognised.
    joined = _join_line_continuations(command)
    for text in (command, joined):
        assignments = _literal_assignments(text)
        ends = [m.start() for m in _SEGMENT_END.finditer(text)] + [len(text)]
        starts = [0] + [end + 1 for end in ends[:-1]]
        for start, end, base in zip(starts, ends, _cd_bases(
                text, starts, cwd, assignments, clean_bases)):
            segment = _REDIRECT_TARGET.sub(" ", text[start:end])
            for token in segment.split():
                if token.startswith("-"):
                    continue
                resolved = _credential_under(base, _expand(token, assignments),
                                             dirs, clean_bases)
                if resolved is not None and (
                        text == command or resolved not in listed):
                    out.append(resolved)
                    listed.add(resolved)
        if joined == command:
            break        # no continuation present — the second pass is identical
    return out


def _deletes_only_declared_scratch(command: str, cwd: str,
                                    scratch_roots: tuple[str, ...]) -> bool:
    """Is every path this command deletes inside a DECLARED scratch root?

    ⚠ SCRATCH ROOTS ONLY. A PROJECT ROOT MUST NEVER QUALIFY, and that is the
    boundary this whole exemption rests on. `rm -rf src/` is inside the project
    and is precisely what `irreversible_action` exists to catch — the project is
    where the work with value lives, so containment in it is the strongest
    reason to ask, not a reason to stay quiet. The two rules ask different
    questions: `destructive_outside` asks "is this outside your project", and
    exempting project paths there is right; this one asks "can this be undone",
    and the answer does not improve because the target was yours.

    A declared scratch root is different IN KIND rather than in degree. It is a
    statement by the developer — `STING_SCRATCH`, alongside `STING_ROOTS` — that
    everything beneath it is agent-owned, ephemeral and recreatable. Deleting
    from it destroys nothing that existed before the session.

    ⚠ AND THE DECLARATION IS WHAT SATISFIES WORKING RULE #5. The attacker writes
    the poisoned README, and therefore writes the command — so any exemption
    read out of command TEXT is an exemption the attacker chooses. This one is
    read out of the developer's environment, which the attacker does not write.
    `SP=/` followed by `rm -rf $SP/` resolves to `/`, which is inside no declared
    root, and stays caught: the attacker may choose the path, and never the set
    of paths that are forgivable.

    THREE WAYS THIS RETURNS FALSE, each closing a trap:
      no declaration      `scratch_roots` empty -> no exemption, ever. Absence
                          of a setting must never read as permission.
      nothing parsed      an unparseable command is a prompt, not a pass.
      any target outside  `rm -rf <scratch>/a /etc/passwd` is not two thirds
                          safe. ALL, never ANY.
    """
    if not scratch_roots:
        return False
    targets = _deletion_targets(command, cwd)
    return bool(targets) and all(is_inside_project(p, scratch_roots)
                                  for p in targets)


# ⚠ THE EXEC TWIN OF THE WRITE/EDIT CREDENTIAL-OVERWRITE RULE IN `is_irreversible`.
#
# `echo x > .env`, `: > id_rsa` and `cat > .netrc <<EOF` destroy the same bytes
# a Write does, and none of them reached `is_irreversible` at all. NOT reused:
# `_TRUNCATING_REDIRECT`, which records AUTHORSHIP for the deferred rule and so
# requires a listed verb plus a source operand — it matches neither `: > id_rsa`
# nor a bare `echo > .env`, and widening it would widen what counts as "ours",
# which is the LOOSENING direction. This extractor is its own and feeds only the
# irreversibility question; authorship is untouched and pinned.
#
# `>` only, never `>>` (an append destroys nothing) and never `>&N` (a
# descriptor duplication names no file). `2>` and `&>` DO truncate the target
# and are included. The `>` must sit at a CODE position — `echo "x > .env"`
# prints a string — so the mask is consulted; on a command the scanner cannot
# parse the mask is all-code, which leans toward ASKING: the documented
# direction for a rule that prompts rather than blocks.
# `>|` truncates exactly as `>` does (it overrides noclobber), so it counts too.
_TRUNCATING_TARGET = re.compile(r"(?<![<>])(?:\d+|&)?>\|?(?![>|&])\s*([^\s<>|;&()]+)")


def _truncated_credential_file(command: str, cwd: str, world: World) -> str | None:
    """The first EXISTING credential-shaped file this command truncates through
    a redirect, or None. The two conditions are the Write/Edit rule's own —
    credential-shaped (`CREDENTIAL_PATHS`) AND already there (`read_text` is not
    None) — so `echo hello > notes.txt`, a redirect to a file that is not yet
    there, and every append stay exactly as silent as they are today."""
    mask, _parsed = code_mask_checked(command)
    for match in _TRUNCATING_TARGET.finditer(command):
        at = match.start()
        if at < len(mask) and not mask[at]:
            continue                                   # quoted or heredoc text
        # The TARGET TOKEN is de-glued, never the whole command: unquoting the
        # command would turn `echo "x > .env"` into a real redirect.
        path = _abs(_bash_unquote(match.group(1)), cwd)
        if CREDENTIAL_PATHS.search(path) and world.read_text(path) is not None:
            return path
    return None


def is_irreversible(action: Action, world: World,
                     scratch_roots: tuple[str, ...] = (),
                     untrusted: bool = False) -> str | None:
    """Can this action be undone? Returns why, or None.

    Reads a line git already drew: `-d` refuses on an unmerged branch and `-D`
    does not, because the same question mattered to git's designers. We are not
    inventing a taxonomy, we are reading one.

    NOT IMPLEMENTED, DELIBERATELY: "did this session create the target". It
    would make deleting your own scratch file silent, but it needs a new
    SessionState field, a read probe on every write, and a cap that goes lossy
    in exactly the long sessions where it would matter. Zero corpus normals
    reach this predicate at all, so the discriminator has nothing to
    discriminate yet. Dogfooding decides. See PROGRESS.md.
    """
    if action.kind is ActionKind.EXEC and action.command:
        for pattern, why in _IRREVERSIBLE_COMMANDS:
            if not pattern.search(action.command):
                continue
            # ⚠ THE EXEMPTION REACHES ONLY THE PATTERNS THAT DELETE A PATH.
            # A force-push, `branch -D`, `reset --hard` and the SQL rules have no
            # filesystem operand to test, so they fall through unchanged however
            # `STING_SCRATCH` is set. J03 and J05 depend on exactly that.
            if (pattern in _DELETES_A_PATH
                    and _deletes_only_declared_scratch(
                        action.command, action.cwd, scratch_roots)):
                continue
            # ⚠ THE SECOND EXEMPTION, READ OUT OF KNOWN-ARTIFACT IDENTITY, and it
            # is withheld from an untrusted session: the attacker who wrote the
            # README wrote the command, and a session that read it forfeits the
            # shortcut whatever the target is called. Every other pattern in the
            # table falls through unchanged — a force-push has no path to test.
            if (pattern in _DELETES_A_PATH and not untrusted
                    and _deletes_only_regenerable_artifacts(
                        action.command, action.cwd, action.workspace_roots,
                        world)):
                continue
            return why
        # The EXEC twin of the Write/Edit rule below: the same two conditions
        # and the same reason string, so a reader sees one rule and two verbs.
        if _truncated_credential_file(action.command, action.cwd, world):
            return "this overwrites an existing credential file"

    if action.kind in (ActionKind.WRITE, ActionKind.EDIT):
        for dest in action.paths:
            # Overwriting an existing credential file destroys the old value.
            # Creating a NEW key file does not — N14's ssh-keygen is silent.
            # read_text() is the existence check; World has no path_exists, and
            # this only probes paths CREDENTIAL_PATHS already matched, so it
            # adds no cost to the hot path.
            if CREDENTIAL_PATHS.search(dest) and world.read_text(dest) is not None:
                return "this overwrites an existing credential file"
        # J05's DROP COLUMN lives in the migration FILE, not in the psql command
        # that runs it — N11 is byte-identical but says ADD COLUMN. So the
        # discriminator has to read the written content.
        #
        # KNOWN IMPRECISION, accepted for v1: this fires at the WRITE, and
        # writing a migration is reversible; running it is not. Firing at the
        # exec would need `-f <path>` parsing plus a read probe. Recorded in
        # PROGRESS.md as imprecision, not a bug.
        content = action.content or ""
        if _SQL_DESTRUCTIVE.search(content) or _SQL_DELETE_UNSCOPED.search(content):
            return "this writes a schema change that drops data"

    return None

_NO_WORKING_TREE = frozenset({_BRANCH_FORCE_DELETE, _SQL_DESTRUCTIVE, _SQL_DELETE_UNSCOPED})


def irreversible_without_a_tree(action: Action, world: World) -> str | None:
    """What still asks by its shape alone since fix/false-positives (docs/112,
    item C): the rules with no working tree to consult — `git branch -D`,
    destructive SQL, an existing credential file overwritten by Write or Edit,
    a written schema change that drops data. A delete or an overwrite of files
    is `core/uncommitted.py`'s now, and a force-push no longer asks (maintainer).

    ⚠ `is_irreversible` IS KEPT AS IT WAS, AND THE ENGINE STILL CALLS IT: it
    decides whether an action with no sink reaches the ladder at all, and so
    whether the secret family answers it (`secret_*:no_sink`) — which this
    pass may not move. Only the irreversible ASK itself is item C's."""
    if action.kind is ActionKind.EXEC and action.command:
        for pattern, why in _IRREVERSIBLE_COMMANDS:
            if pattern in _NO_WORKING_TREE and pattern.search(action.command):
                return why
        return None
    if action.kind in (ActionKind.WRITE, ActionKind.EDIT):
        return is_irreversible(action, world)          # its WRITE/EDIT branch
    return None


# ⚠ DIRECTORIES WHOSE DELETION IS NEVER A STEP IN ANY TASK.
#
# ONE SENTENCE COVERS THE WHOLE SET, which is the test a set like this has to
# pass: **no task deletes one of these directories WHOLE, ever.** Not "rarely",
# not "only in cleanup" — never. That is why it can be a DENY rather than a
# prompt, and why the set is short.
#
#   /                        the machine
#   /HOME                    this person's entire working life. `_abs` maps `~`
#                            to this placeholder; the engine may not read the
#                            environment, so `~` is as close as it gets
#   /Users, /home            every person's, on this machine
#   the OS directories       the machine's ability to boot and run
#
# ⚠ IT IS THE ROOT ITSELF, NEVER A PATH UNDER ONE. `rm -rf /tmp/foo` and
# `rm -rf ~/projects/x` are ordinary work and are not touched by this. The
# distinction is membership, not prefix — which is the entire difference between
# this rule and one that would be unusable.
_CATASTROPHIC_ROOTS = frozenset({
    "/",
    "/HOME",
    "/Users", "/home",
    "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/boot",
    "/var", "/opt", "/System", "/Library", "/Applications", "/private",
})

# `/Users/alice` and `/home/bob` ARE home directories — a structural fact about
# those two directories, needing no environment read. Without this, `rm -rf ~`
# is caught and the literal spelling of the same directory is not, which is
# exactly the "attacker picks whichever spelling the matcher misses" failure
# this rule exists to avoid.
_HOME_PARENTS = ("/Users", "/home")


_ROOT_DISPLAY = {"/HOME": "your home directory", "/": "the filesystem root"}


def _root_display(path: str) -> str:
    """⚠ `/HOME` IS AN INTERNAL SENTINEL AND MUST NOT REACH A DEVELOPER. `_abs`
    uses it because the engine may not read the environment; a person reading
    "this deletes /HOME" has to know that to understand the sentence."""
    if path in _ROOT_DISPLAY:
        return _ROOT_DISPLAY[path]
    if path.startswith("/HOME/"):
        return "your home directory" + path[len("/HOME"):]
    return path


def _is_catastrophic_root(path: str) -> bool:
    if path in _CATASTROPHIC_ROOTS:
        return True
    parent, _, child = path.rpartition("/")
    # ⚠ `<root>/*` IS THE ROOT'S CONTENTS, AND THAT IS THE WHOLE CATASTROPHE.
    # `rm -rf /*` expands to every entry of `/`; the directory inode survives
    # and nothing else does, which is materially the same event as `rm -rf /`.
    # The glob is not expanded here — it does not have to be. A `*` that is the
    # ENTIRE last component means "everything in the parent", whatever the
    # entries happen to be.
    #
    # ⚠ EXACTLY `*`, NEVER A PREFIX GLOB. `/usr/l*` is a subset chosen by
    # someone who knew what they were selecting; `/usr/*` is not a selection.
    # And `/tmp/*` is untouched because /tmp is not a catastrophic root — the
    # membership test is unchanged, only the spelling of the member is.
    if child == "*" and (parent or "/") in _CATASTROPHIC_ROOTS:
        return True
    return parent in _HOME_PARENTS and bool(child) and "/" not in child


# ── row f: a glob or brace in a destructive target (docs/91) ──────────────────
#
# #61's expander, pointed at the catastrophic roots instead of credential names.
# A glob names a root only when it SPELLS half the root's name — #61's exit rule,
# for the same reason: a delete target is judged on text alone, and `/e*` or
# `/*/cache` could be anything. Literal segments compare exactly, as the plain
# `_is_catastrophic_root` does.
_ROOT_SEGMENT_SHAPES = {name: _shape(name)
                        for root in _CATASTROPHIC_ROOTS | set(_HOME_PARENTS)
                        for name in root.strip("/").split("/") if name}


def _spells_segment(segment: list[_GlobToken], name: str) -> bool:
    """⚠ CASE-SENSITIVE, unlike #61's credential match. `_is_catastrophic_root`
    compares exactly, and bash's glob does too: `/ET?` never matches `etc`, so
    the witness must BE the name, not a case-folded look-alike of it."""
    if all(t.kind == "lit" for t in segment):
        return "".join(t.raw for t in segment) == name
    shape = _ROOT_SEGMENT_SHAPES[name]
    return _intersect(segment, shape.tokens, shape.need) == name


def _root_witnesses(tokens: list[_GlobToken]) -> list[str]:
    """The catastrophic targets an ABSOLUTE pattern could name: a root, a root's
    contents (`<root>/*`, a lone `*`, as `_is_catastrophic_root` reads it), or a
    home directory under a home parent."""
    segments = _segments(tokens)
    while len(segments) > 2 and not segments[-1]:
        segments = segments[:-1]                    # `/et?/` is `/et?`
    if len(segments) < 2 or segments[0]:
        return []
    names = segments[1:]
    found: list[str] = []
    for root in sorted(_CATASTROPHIC_ROOTS - {"/", "/HOME"}):
        parts = root.strip("/").split("/")
        if not all(map(_spells_segment, names[:len(parts)], parts)):
            continue
        if len(names) == len(parts):
            found.append(root)
        elif (len(names) == len(parts) + 1 and len(names[-1]) == 1
              and names[-1][0].kind == "star" and names[-1][0].raw == "*"):
            found.append(root + "/*")
    if len(names) == 2 and names[1]:
        child = "".join(t.raw for t in names[1])
        found += [f"{parent}/{child}" for parent in _HOME_PARENTS
                  if _spells_segment(names[0], parent.strip("/"))]
    return found


def _anchored(tokens: list[_GlobToken], base: str | None) -> list[_GlobToken]:
    """The pattern made absolute the way `_abs` makes a path: `~` is the `/HOME`
    sentinel, a relative pattern hangs off `base` (nothing to match without one)."""
    if tokens and tokens[0].kind == "lit" and tokens[0].raw == "/":
        return tokens
    if tokens and tokens[0].kind == "lit" and tokens[0].raw == "~":
        return [_lit(c) for c in "/HOME"] + tokens[1:]
    if base is None:
        return []
    return [_lit(c) for c in base.rstrip("/") + "/"] + tokens


def _destructive_forms(token: str, base: str | None, lenient: bool) -> list[str]:
    """What bash could expand one delete operand to: its brace expansions as
    text, and each glob among them as the catastrophic roots it could name."""
    if not lenient and not _EXPANSION_CHARS.search(token):
        return []

    def roots(tokens: list[_GlobToken]) -> list[str]:
        return _root_witnesses(_anchored(tokens, base))

    forms: list[str] = []
    for _start, _end, word in _marked_words(token, lenient):
        forms += _word_expansions(word, lenient, witnesses=roots)
    return forms


# ⚠ DESTRUCTION THAT IS NOT DELETION. A target set cannot catch these, because
# what they destroy is not named as a path being removed — but each still NAMES
# the thing it destroys, and that is what these rest on.
#
# ⚠ RULE-5 CHECK, RUN PER MEMBER, AND ONE MEMBER WAS DROPPED BECAUSE OF IT.
# The question is whether the same EFFECT can be had while avoiding the SIGNAL:
#
#   zeroing a disk      every spelling names the DEVICE. dd of=, a redirect,
#                       mkfs, tee, cp, shred — the verb varies, /dev/sda does
#                       not. KEPT: the invariant is the target.
#   deleting under /    every spelling names the ROOT. `-delete` and `-exec rm`
#                       are the canonical destructive flags; `-exec sh -c` and
#                       `| xargs rm` escape. KEPT as a backstop against the
#                       common form, and that limit is stated rather than
#                       claimed away.
#   chmod -R 000 /      DROPPED. `chmod -R a-r /` is the SAME command with one
#                       argument respelled and evades entirely, as does
#                       `chmod -R u-r,g-r,o-r /`. A signal defeated by rewriting
#                       the command's own argument buys a false sense of
#                       coverage and costs whatever false positives it creates.

_BLOCK_DEVICE = re.compile(r"^/dev/r?(?:disk|sd|hd|nvme|vd|xvd|md|loop)\w*$")

_DD_OF = re.compile(rf"\bdd\b{_NOT_SEGMENT_END}*?\bof=(?P<t>[^\s;&|]+)")
_DEV_REDIRECT = re.compile(r"(?:\d*|&)>(?:>|\|)?\s*(?P<t>/dev/[^\s;&|]+)")
_MKFS = re.compile(
    rf"\b(?:mkfs(?:\.\w+)?|newfs(?:_\w+)?)\b{_NOT_SEGMENT_END}*?(?P<t>/dev/[^\s;&|]+)")

# `cp SRC DST` / `mv SRC DST` — only the LAST operand is written. A device as
# the SOURCE is a backup (`dd if=/dev/sda of=disk.img`) and must not fire.
_WRITES_LAST = re.compile(rf"\b(?:cp|mv|install)\b(?P<args>{_NOT_SEGMENT_END}*)")
# Verbs where every device operand is written to.
_WRITES_ANY = re.compile(rf"\b(?:tee|shred|wipefs|blkdiscard)\b(?P<args>{_NOT_SEGMENT_END}*)")

# `find <path> … -delete` / `… -exec rm`. Without a destructive action `find` is
# a listing, so the flag is what makes it a destruction — but the PATH is what
# makes it catastrophic. Within one segment. THE DEFINITION, kept as the
# reference `_find_destroys` reproduces (and for the shared segment class it is
# built on, tests/test_segment_boundary_is_shared.py):
_FIND_DESTROYS = re.compile(
    rf"\bfind\b(?P<args>{_NOT_SEGMENT_END}*?)(?:-delete\b|-exec(?:dir)?\s+rm\b)")
# ⚠ READ IN LINEAR TIME, NOT WITH THAT PATTERN (item E, docs/110 §E). Its lazy
# `*?` walked from every `find` to the end of the segment when no `-delete`
# followed, so a run of `(find …` — `(` ends no segment — cost O(n²): 33, 109,
# 389 ms at 4, 8, 16 KB. `_find_destroys` returns exactly its `finditer`
# matches from two precomputed lists, the positions `_NOT_SEGMENT_END` cannot
# step over and the destroy words; tests/test_the_find_check_is_linear.py
# checks the two agree on the pinned cases and on random commands.
_FIND_WORD = re.compile(r"\bfind\b")
_FIND_DESTROY_WORD = re.compile(r"-delete\b|-exec(?:dir)?\s+rm\b")
_SEGMENT_CHAR = re.compile(r"[;|&\n]")


def _segment_stops(text: str) -> list[int]:
    """Every position `{_NOT_SEGMENT_END}` cannot consume: a `;`, `|`, `&` or
    newline, except a `|` after `>` (`>|`), a `&` after `<`/`>` or before `>`
    (`2>&1`, `&>`), and a newline after a backslash (a line continuation)."""
    stops = []
    for match in _SEGMENT_CHAR.finditer(text):
        i, char = match.start(), match.group()
        before, after = text[i - 1:i], text[i + 1:i + 2]
        if char == "|" and before == ">":
            continue
        if char == "&" and (before in ("<", ">") or after == ">"):
            continue
        if char == "\n" and before == "\\":
            continue
        stops.append(i)
    return stops


def _find_destroys(command: str) -> list[tuple[int, str]]:
    """(start, args) of each `find … -delete|-exec rm` match, in order: the
    first destroy word after a `find` with no segment stop between them, the
    next search resuming after that word — `finditer`'s own walk."""
    words = list(_FIND_DESTROY_WORD.finditer(command))
    if not words:
        return []
    word_starts = [w.start() for w in words]
    stops = _segment_stops(command)
    found: list[tuple[int, str]] = []
    resume = 0
    for find in _FIND_WORD.finditer(command):
        if find.start() < resume:
            continue
        k = bisect.bisect_left(word_starts, find.end())
        if k == len(words):
            break                       # no destroy word follows any later find
        stop = bisect.bisect_left(stops, find.end())
        if stop < len(stops) and stops[stop] < word_starts[k]:
            continue                    # the segment ends first
        found.append((find.start(), command[find.end():word_starts[k]]))
        resume = words[k].end()
    return found


_FIRST_ABS = re.compile(r"(?<![\w/])(/[^\s;&|]*|~[^\s;&|]*|\$\{?\w+[^\s;&|]*)")


def _code_positions(command: str):
    """(mask, ok) with the same UNPARSED gate every DENY-capable rule uses."""
    mask, _ = code_mask_checked(command)
    return mask, bail_reason(mask) != UNPARSED


def writes_a_raw_block_device(action: Action) -> str | None:
    """The device this command would overwrite, or None.

    ⚠ KEYED ON THE DEVICE, NOT ON `dd`. The premise "to zero a disk you must
    invoke dd or mkfs" is false — `cat /dev/zero > /dev/sda`, `tee /dev/sda`,
    `cp /dev/zero /dev/sda` and `shred /dev/sda` all do it. What none of them
    can avoid is naming the device, so that is the signal.
    """
    command = action.command or ""
    mask, ok = _code_positions(command)
    if not ok:
        return None
    for pattern in (_DD_OF, _DEV_REDIRECT, _MKFS):
        for match in pattern.finditer(command):
            if match.start() >= len(mask) or not mask[match.start()]:
                continue
            target = _norm_path(match.group("t").strip("'\""))
            if _BLOCK_DEVICE.match(target):
                return target
    for pattern, last_only in ((_WRITES_LAST, True), (_WRITES_ANY, False)):
        for match in pattern.finditer(command):
            if match.start() >= len(mask) or not mask[match.start()]:
                continue
            args = [a for a in (match.group("args") or "").split()
                     if not a.startswith("-")]
            for arg in (args[-1:] if last_only else args):
                target = _norm_path(arg.strip("'\""))
                if _BLOCK_DEVICE.match(target):
                    return target
    return None


# find's own options before its starting points, and where its expression begins.
_FIND_GLOBAL_FLAG = re.compile(r"-[HLP]$|-O\d*$")
_FIND_EXPRESSION_STARTS = frozenset("-()!,")


def _find_starting_points(args: str) -> list[str]:
    """find's starting points as written: the words after `-H`/`-L`/`-P`/`-O<n>`
    /`-D <x>` and before the expression's first word. None written is `.`, as
    GNU and BSD find both read it."""
    words = _RAW_WORD.findall(args)
    i = 0
    while i < len(words) and (_FIND_GLOBAL_FLAG.match(words[i]) or words[i] == "-D"):
        i += 2 if words[i] == "-D" else 1
    points = []
    for word in words[i:]:
        first = _bash_unquote(word)[:1]
        if not first or first in _FIND_EXPRESSION_STARTS:
            break
        points.append(word)
    return points or ["."]


def find_destroys_a_catastrophic_root(action: Action) -> str | None:
    """`find <catastrophic root> … -delete`, or `-exec rm`."""
    command = action.command or ""
    mask, ok = _code_positions(command)
    if not ok:
        return None
    assignments = _literal_assignments(command)
    lenient = bool(_SHOPT_WIDENS_GLOB.search(command))
    matches = [(start, args) for start, args in _find_destroys(command)
               if start < len(mask) and mask[start]]
    # ⚠ THE STARTING POINT IS WHERE A LEADING `cd` LEFT US (item C3, docs/101).
    # `cd /etc && find . -delete` was ALLOW while `cd /etc && rm -rf .` is DENY:
    # only the first absolute operand was read, and against `action.cwd`. The
    # same fold the delete check uses (`_cd_bases`), C1's target reading and
    # C2's shell bodies with it — one folder, not a second.
    bases = _cd_bases(command, [start for start, _ in matches], action.cwd, assignments)
    for (_start, args), base in zip(matches, bases):
        # The first path operand, resolved — searched in the args as WRITTEN and,
        # unioned, as bash would read them after decoding ANSI-C quoting, so
        # `find $'\x2f' -delete` resolves its target the same as `find / -delete`.
        # Union: the decode only ADDS a candidate, never hides the literal one.
        for source in _operand_forms(args, None, lenient):
            found = _FIRST_ABS.search(source)
            if not found:
                continue
            target = _norm_path(_abs(_expand(found.group(1), assignments), action.cwd))
            if _is_catastrophic_root(target):
                return target
        # ...and, ADDED beside it, every starting point from the folded directory.
        for point in _find_starting_points(args):
            for form in _operand_forms(point, base, lenient):
                target = _norm_path(_abs(_expand(form, assignments), base))
                if _is_catastrophic_root(target):
                    return target
    return None


def deletes_a_catastrophic_root(action: Action) -> str | None:
    """The resolved root this command would delete, or None.

    ⚠ IT RESTS ON THE RESOLVED TARGET, NEVER ON TEXT, AND THAT IS WHY IT
    SATISFIES WORKING RULE #5. `rm -rf /`, `SP=/ ; rm -rf $SP/` and
    `cd / && rm -rf .` name the same directory three ways, and an attacker picks
    whichever one a pattern misses. To delete the root you must RESOLVE to the
    root — that is the signal they cannot avoid.

    ⚠ TWO GATES, AND BOTH FAIL TOWARD TODAY'S BEHAVIOUR. This escalates an ASK
    to a DENY, so every uncertainty must resolve to "not catastrophic":

    THE PARSE MUST HAVE SUCCEEDED. `code_mask` fails SAFE to all-code on a
    command it cannot parse, which is right for a rule that asks and wrong for
    one that blocks — it would turn every unparseable command that MENTIONS
    `rm -rf /` into a block. Measured: 3 real records in a 2288-record log
    contain that text, all of them commands ABOUT this rule, and the unparsed
    one defeated the code check alone. `code_mask_checked`'s docstring says a
    caller that RELAXES a rule must require a clean parse; a caller that
    escalates one to DENY has the same obligation for the same reason.

    THE VERB MUST BE IN A CODE POSITION. `rm -rf /` inside a Python string in a
    heredoc is documentation, not a deletion.

    ⚠ AND AN UNRESOLVABLE TARGET IS NOT EVIDENCE OF CATASTROPHE. `rm -rf $HOME`
    keeps its `$` because the engine may not read the environment, so it does
    not resolve to a root and stays exactly where it is today: an ASK.
    """
    command = action.command or ""
    if not command:
        return None
    mask, parsed = code_mask_checked(command)
    if not parsed:
        return None
    if not first_code_match(_RM_DESTRUCTIVE, command, mask):
        return None
    # Resolve targets from the command AS WRITTEN and, unioned, as bash reads it
    # after removing line continuations (`rm -rf /\<newline>etc` -> `/etc`). The
    # UNION is what keeps this catch-more-never-less: the raw pass is unchanged, so
    # `rm -rf /etc\<newline>foo` keeps its existing behaviour, while
    # `rm -rf /\<newline>etc` GAINS the joined `/etc` catch it missed before. The
    # code-position gate above is judged on the raw command, so joining changes no
    # detection, only which operand strings are resolved.
    joined = _join_line_continuations(command)
    targets = _deletion_targets(command, action.cwd)
    if joined != command:
        targets = targets + _deletion_targets(joined, action.cwd)
    for target in targets:
        if _is_catastrophic_root(target):
            return target
    return None
