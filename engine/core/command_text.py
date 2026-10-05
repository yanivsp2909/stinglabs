"""How the engine reads a command: its segments, words, quoting, paths,
redirects and variables, the text that actually executes, the shapes of git,
copy and redirect commands, and the evidence span a verdict quotes. No rule
decides anything here; every rule family reads a command through it.

Moved out of core/engine.py; docs/ENGINE_LAYOUT.md.
"""
from __future__ import annotations

import bisect
import dataclasses
import functools
import re
from collections.abc import Callable

from core.shell_scan import TEXT_COMMANDS, code_mask_checked, quoted_text_view
from core.types import Action, ActionKind, SessionState


# Mechanism K — git history is attacker-writable text the agent reads as context.
# A commit MESSAGE is prose the developer wrote, not a command. Scanning it for
# source patterns is a category error: mechanism K is about READING history —
# a stranger's commit message arriving as command OUTPUT — and a commit WRITES
# history.
#
# Found by dogfooding. A real session came back `untrusted: true`, sourced to
# the developer's own commit, because the message discussed `git log`. No corpus
# scenario could produce it: every corpus commit message is 'fix', 'wip' or
# similar, and the bug needs a message that talks about git.
#
# `<<'TAG' … TAG` — a heredoc body is data by definition.
_HEREDOC_BODY = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?^\2[ \t]*$",
                            re.DOTALL | re.MULTILINE)
# `-m 'msg'` / `-m "msg"` / `-m msg`. The quoted forms may span newlines, and
# may themselves contain a command substitution — which is why stripping the
# whole argument matters rather than just its text.
_MESSAGE_ARG = re.compile(
    r"(?:-m\s+|--message(?:=|\s+))('[^']*'|\"[^\"]*\"|\S+)")
# Whose `-m` means a MESSAGE. Matched at a segment start, so `cd x && git …`
# and `foo | git …` both reach it. `sudo git commit -m` and `env X=1 git commit
# -m` do not — the message then survives into the structure text, which costs a
# possible false positive and never a miss, the safe direction for this layer.
_MESSAGE_VERB = re.compile(r"\s*(?:[({]\s*)?(?:git|hg)(?![\w-])")


def executed_text(command: str) -> str:
    """What the shell will actually EXECUTE, with inert payload removed.

    Heredoc bodies and `-m` message arguments are data the command carries, not
    commands the shell runs. `git push` inside a heredoc is a string; `git push`
    outside one is a push.

    THE SPLIT THAT MATTERS. Every rule reading a command asks one of two
    questions, and they need different text:

        STRUCTURE  "what is this command DOING?"      -> executed_text()
                   mark_sources (which verb ran), propagate (what is copied
                   where), check_sinks (is this an exit)

        PAYLOAD    "what is this command CARRYING?"   -> the RAW command
                   _secret_level, _secret_in_argv, carries_secret

    A01 puts a credential *in* a commit message and must still be caught, so the
    payload side must keep seeing the message. Its mirror image — a `git push`
    written *about* in a test file — must not be read as a push, so the
    structure side must not. Same string, opposite requirements.

    This is the same asymmetry as fingerprint_values (store narrowly) versus
    fingerprints_in (match broadly): narrow when recording, broad when
    detecting. Do not collapse the two into one call.

    tests/test_commit_message_is_not_a_command.py asserts both sides.
    """
    return _strip_message_args(_HEREDOC_BODY.sub(" ", command))


def _strip_message_args(command: str) -> str:
    """Remove `-m <arg>` where `-m` means a COMMIT MESSAGE, and nowhere else.

    ⚠ `-m` IS NOT ONE FLAG. It means "message" to git, "module" to an
    interpreter, "mode" to `install`, "max-count" to `grep`, "merge" to `sort`.
    Stripping a message removes DATA the command carries; stripping a module
    name removes part of what the command RUNS — the exact inversion this
    function's own docstring warns about one screen above.

    THE BUG THIS FIXES, from a real session. `head -1 x.jsonl | python3 -m
    json.tool` had its module deleted before any rule saw it, leaving

        head -1 x.jsonl | python3

    which is a bare `| python3` — stdin IS the program, the same shape as
    `| sh`. The pipe-to-shell sink then fired correctly on text the shell would
    never run. Measured over the vendored live sessions, the unscoped strip
    altered the structure text of **118 of 617 commands**, nearly all of them
    `python3 -m pytest`; the corpus contains 0 such commands, which is why this
    could not be found by scoring it.

    ⚠ THE STRIP ALONE DOES NOT FIX THAT DENIAL, and neither does narrowing the
    sink alone. `_pipes_into_interpreter` never inspects what follows the
    interpreter unless the module is still there to inspect, and this function
    only keeps the module visible. The two are one fix; see that function.

    Separators inside quotes are not segment boundaries, so the lookback counts
    only those at a CODE position — `git -c user.name="A | B" commit -m …`
    otherwise reads the quoted pipe as a new segment and loses the verb.
    """
    if "-m" not in command:
        return command
    mask, parsed = code_mask_checked(command)
    # ⚠ THE SEPARATORS ARE FOUND ONCE (docs/113 §3f). Each `-m` re-scanned
    # them all from the start of the text to find its segment: `git commit -m
    # x; ` repeated was quadratic. A message's segment starts after the last
    # code separator before it — a bisection over this one list.
    separators = [(at.start(), at.end()) for at in _SEGMENT_END.finditer(command)
                  if not parsed or (at.start() < len(mask) and mask[at.start()])]
    positions = [at for at, _end in separators]
    pieces: list[str] = []
    last = 0
    for match in _MESSAGE_ARG.finditer(command):
        before = bisect.bisect_left(positions, match.start())
        start = separators[before - 1][1] if before else 0
        if not _MESSAGE_VERB.match(command, start):
            continue
        pieces.append(command[last:match.start()])
        pieces.append(" ")
        last = match.end()
    pieces.append(command[last:])
    return "".join(pieces)


# The original name, from the dogfooding bug that produced this function. Kept
# because it is what the existing tests import, and because "without commit
# message" describes only half of what it strips.
without_commit_message = executed_text


def _structure_text(text: str, state: SessionState) -> str:
    """`text` as a STRUCTURE reader should see it: the quoted pattern of a grep
    and the message of a commit replaced by `x` (`quoted_text_view`, item B,
    docs/100), so a `|`, `;` or `cd` written INSIDE them is not read as one.

    The same length as `text`, so an offset found here names the same byte of
    `text` — evidence is always sliced from `text`, never from this.

    ⚠ NEVER FOR A PAYLOAD READER. `carries_secret`, `_secret_in_argv_span`, the
    canary, policy fingerprints and marking keep the command as written: a key
    pasted into a commit message is still a key.

    ⚠ AN ALIAS ON grep, rg OR git AND THE TEXT IS READ AS WRITTEN. The session
    knows the alias (`state.aliases`, G05), and an alias can make `grep` run
    its argument — whereupon the "pattern" is code.
    """
    if TEXT_COMMANDS & state.aliases.keys():
        return text
    return quoted_text_view(text)


def _structure_action(action: Action, state: SessionState) -> Action:
    """`action` with its command replaced by `_structure_text` of it, for the
    destruction readers (`deletes_a_catastrophic_root`, the find sweep, the raw
    device check, `is_irreversible`). The same action when nothing changes."""
    if action.kind is not ActionKind.EXEC or not action.command:
        return action
    view = _structure_text(action.command, state)
    return action if view == action.command else dataclasses.replace(
        action, command=view)


def _root_is_case_insensitive(world, root: str) -> bool | None:
    """`world.case_insensitive(root)`, or None when the world cannot say.

    ⚠ `getattr`, AND THE REASON IS THE PROTOCOL'S OWN SEMANTICS RATHER THAN
    CONVENIENCE. `World` is a STRUCTURAL protocol — anything with the right
    methods is one — so implementations exist that predate this method: ten
    test doubles in this repo, and any third-party world. A double that does
    not implement it is not broken; it is a world that CANNOT TELL, which is
    exactly what None means and which takes the conservative branch.

    ⚠ THE REAL IMPLEMENTATIONS ARE NOT LET OFF. `RealWorld` and `NullWorld`
    must both provide it, asserted in tests/test_case_carrier.py — otherwise
    this `getattr` would let the one world that does the actual IO quietly stop
    answering, which is the failure it must not hide.
    """
    ask = getattr(world, "case_insensitive", None)
    if ask is None:
        return None
    try:
        return ask(root)
    except Exception:                                            # noqa: BLE001
        # A world that raises is a world that cannot say. The engine may not
        # crash on a boundary check — step 11's fail-closed rule covers the
        # verdict, not the arithmetic that reaches it.
        return None


def is_inside_project(path: str, roots: tuple[str, ...],
                       world: "World | None" = None) -> bool:
    """Set membership across every workspace root, never one prefix check.

    Multi-root workspaces are real — Cursor and Antigravity both send an array.
    A sibling root in a monorepo is INSIDE the project, and treating it as
    outside is the false positive docs/08 predicts under dogfooding.

    ⚠ CASE IS HANDLED, AND IT ARRIVES ON `world` — PER ROOT. The paragraphs
    below describe how it used to be a known gap; they are kept because they
    state the constraint the fix had to satisfy.

    `world.case_insensitive(root)` answers for THAT root, which is the only
    granularity that is correct: Windows has per-directory case sensitivity
    (`fsutil file setCaseSensitiveInfo`, set by WSL on everything it creates)
    and macOS has case-sensitive volumes, so one workspace can span both.

    ⚠ `None` — "could not tell" — IS TREATED AS CASE-SENSITIVE, which is the
    conservative direction here, and the two directions are NOT symmetric:

        wrong "insensitive"   two REAL directories merge, and a path outside
                              the project is judged inside. A BYPASS.
        wrong "sensitive"     one directory looks like two, and an ordinary
                              write is judged outside. A FALSE POSITIVE — noisy,
                              visible, and the developer complains.

    A bypass is silent and a false positive is not, so the unknown case takes
    the noisy branch. `world=None` — every caller that has no world — behaves
    exactly as before.

    ⚠ THE OLD TEXT, KEPT FOR THE CONSTRAINT IT RECORDS:
    On a case-insensitive filesystem (macOS APFS by default) a differently-cased
    path IS the same directory, and this comparison calls it outside the
    project — measured: root `…/case`, path `…/CASE/src/app.py`, judged False
    while both names open the same file. That over-denies, which is the safe
    direction, so it is a false-positive source and not a bypass.

    It is NOT fixed here because detecting a filesystem's case sensitivity is
    IO, and this module may not do IO — `tests/test_hook_entry.py` bans
    `pathlib` outright and pins the engine as a pure function of
    (action, state, world). Comparing case-insensitively WITHOUT detecting would
    fail OPEN on a case-sensitive filesystem by merging two real directories,
    which is the wrong direction for a boundary. So the fix has to arrive as a
    fact on `SessionState` or through the `World` protocol, decided outside.
    """
    # ⚠ EITHER SEPARATOR, BECAUSE A WINDOWS ROOT ENDS WITH NEITHER A `/` NOR
    # NOTHING. `C:\proj` + `/` is `C:\proj/`, which `C:\proj\src\app.py` does
    # not start with — so EVERY path on Windows read as outside the project, and
    # `write_outside` fired on every ordinary write. 44 of those in one real
    # POSIX session was a bad week; on Windows it would be every action.
    #
    # ⚠ AND THE SEPARATOR IS STILL REQUIRED. Comparing bare prefixes would make
    # `C:\projector\x` inside `C:\proj`, which is the opposite error and the
    # unsafe one — a path outside the project judged inside.
    for root in roots:
        if not root:
            continue
        trimmed = root.rstrip("/" + chr(92))
        # ⚠ ASKED PER ROOT, INSIDE THE LOOP. Hoisting it out would give one
        # answer to a workspace that can legitimately have several.
        fold = _root_is_case_insensitive(world, root) is True
        candidate = path.casefold() if fold else path
        target = trimmed.casefold() if fold else trimmed
        exact = root.casefold() if fold else root
        if candidate == target or candidate == exact:
            return True
        if candidate.startswith(target + "/") or candidate.startswith(target + chr(92)):
            return True
    return False

# Where one command in a compound ends: the three shell separators plus a bare
# newline. Used to read a history verb's own flags without borrowing the next
# command's.
#
# ⚠ ONE DEFINITION FOR THE WHOLE CLASS. Every detector that needs "a run that
# stays inside one segment" derives its class from THIS separator set, so a
# per-detector copy cannot quietly drift back to omitting the newline — the drift
# that let `cp /dev/zero /dev/sda\necho done` splice the next line into the copy's
# operands and slip the raw device past. Enforced structurally by
# tests/test_segment_boundary_is_shared.py.
_SEGMENT_SEPARATORS = r";|&\n"
# ⚠ `>|` IS A REDIRECT, NEVER A PIPE. It is bash's noclobber override: `echo x
# >| f` truncates f exactly as `>` does. Read as a pipe, it ended the segment
# there, so the target became a "command" and every redirect reader missed the
# write (`echo x >| ~/.sting/env`, `cat /dev/zero >| /dev/sda`). Written as the
# separator class plus lookarounds, so the scan stays a character-class scan.
#
# ⚠ AND THE `&` OF A REDIRECT (`2>&1`, `&>f`, `<&3`) ENDS NOTHING (python review
# of item C). `rm 2>&1 ~/.sting/env` deletes the file, and a segment cut at that
# `&` hid the operand from every reader. A longer segment can only give a
# reader more words, never fewer.
_SEGMENT_END = re.compile(rf"[{_SEGMENT_SEPARATORS}](?<!>\|)(?<![<>]&)(?!(?<=&)>)")
# One character that stays WITHIN a segment: the separator set, negated — EXCEPT
# a backslash-newline, which bash treats as a LINE CONTINUATION (it erases the
# newline and joins the lines), so a span must cross it. Detectors reach from a
# verb to its operand or flag with `{_NOT_SEGMENT_END}*` (or `*?`). Without the
# continuation branch, `find /etc \<newline>-delete` — one deleting command —
# would stop at the newline and slip past; both behaviours verified against real
# bash. A bare `\n` still ends the segment. The `|` of a `>|` stays too. The
# plain class is the FIRST branch, so an ordinary character costs one test.
_NOT_SEGMENT_END = rf"(?:[^{_SEGMENT_SEPARATORS}\\]|\\\n?|(?<=>)\||(?<=[<>])&|&(?=>))"
# `{_NOT_SEGMENT_END}*`, unrolled: the same strings, read as runs of the plain
# class, for a verb that takes the whole rest of its segment.
_SEGMENT_REST = (rf"[^{_SEGMENT_SEPARATORS}\\]*"
                 rf"(?:(?:\\\n?|(?<=>)\||(?<=[<>])&|&(?=>))"
                 rf"[^{_SEGMENT_SEPARATORS}\\]*)*")


def _join_line_continuations(command: str) -> str:
    r"""`command` with bash's line continuations removed: a backslash-newline is
    erased and the surrounding characters join with NO separator, so
    `rm -rf /\<newline>etc` becomes the single operand `/etc` — the same word bash
    deletes. Reproduce that BEFORE operands are sliced and tokenised, so a target
    or credential path spelled across a continuation resolves like its one-line
    form.

    ⚠ ONLY the backslash-newline PAIR is removed. A BARE newline is left intact so
    `_SEGMENT_END` still ends a segment there — the continuation strip must never
    swallow a real separator (`rm -rf /tmp<newline>echo done` stays two segments).
    Callers UNION this with the raw command, so it can only ADD a resolution, never
    drop one. The naive strip does not special-case an escaped backslash or a pair
    inside single quotes / a heredoc body; the union makes that safe — a mis-join
    can only fabricate a spurious operand (prompts more), never hide a real one.
    """
    return command.replace("\\\n", "")

# `> f`, `>> f`, `>| f`, `2> f`, `&> f` — the destination of a redirect, which is
# written to and never operated on by the verb in front of it. `/dev/null` is the
# case that matters: it appears in ordinary commands constantly and is destroyed
# by nothing. `target` is the word written; `&1` in `2>&1` is a descriptor, not
# a path, and the reader of `target` skips it.
_REDIRECT_TARGET = re.compile(r"(?:\d*|&)>(?:>|\|)?\s*(?P<target>\S+)")


def _split_tokens(text: str) -> list[str]:
    """Shell-ish tokens, with quoted runs kept inside the token they belong to.

    `-c core.hooksPath='/tmp/a b'` is ONE token, not two. Not a shell parser and
    not trying to be — it does not expand, unquote or evaluate anything.
    """
    return [m.group(0) for m in re.finditer(_SHELL_TOKEN, text)]


def _copy_pairs(command: str, cwd: str, verbs: re.Pattern | None = None,
                at_code: Callable[[int], bool] | None = None
                ) -> list[tuple[int, str, str]]:
    """(position, absolute src, absolute dst) for every cp/mv/install here.

    `verbs` defaults to `_COPY_VERB` (a verb that STARTS a command); the
    installed-guard floor passes one that also finds `sudo cp` and `ln`, gated to
    code positions by `at_code`. A redirect in the operands (`2>/dev/null`,
    `>| log`) is the shell's, never the copy's destination.

    WHY A PARSER AND NOT A WIDER REGEX. The operand a copy WRITES is a function
    of the option grammar — `-t` moves it to the front, a third operand moves it
    to the end — and no single regex expresses that. The old one guessed at
    position 2 and was wrong in four distinct ways.

    THE RULES, in the order they are applied:

      1. `--` ends the options; everything after it is an operand.
      2. `-t DIR` / `--target-directory=DIR` REVERSES the shape: the
         destination is the flag's value and every operand is a source.
      3. `install -d` has no source at all — every operand is a directory
         being created. It yields no pairs.
      4. otherwise the destination is the LAST operand, not the second, and
         everything before it is a source.
      5. a destination that is a DIRECTORY receives `dirname/basename(src)`.
         `_level_of_path` is an exact dict lookup, so tainting `/repo/backup/`
         for `cp .env backup/` labels a path nothing ever writes.

    DIRECTION OF ERROR, chosen deliberately. Rule 4 makes the dst robust to an
    unrecognised option: for `install -m 755 .env debug/.env`, failing to
    consume `755` leaves operands `[755, .env, debug/.env]`, whose LAST is still
    the true destination — the value only becomes a spurious SOURCE, and a
    source that is not credential-shaped is inert. Wrongly consuming a value we
    should not have would eat a real operand and lose the secret. So when a
    verb's option set is uncertain, NOT consuming is the safe side, and that is
    why _COPY_VALUE_OPTS may be conservative without becoming a hole.
    """
    pairs: list[tuple[int, str, str]] = []
    for match in (verbs or _COPY_VERB).finditer(command):
        if at_code is not None and not at_code(match.start(1)):
            continue
        shape = _copy_operands(match.group(1), match.group(2))
        if shape is None:
            continue
        sources, destination, to_target_dir = shape
        # rule 5 — a directory destination receives each source by basename.
        #
        # ⚠ `len(sources) > 1` IS NOT A SAFE TEST FOR "the destination is a
        # directory", and assuming it was corrupted the certain answer. POSIX
        # does require a directory when there are more than two operands — but an
        # option value we failed to consume is INDISTINGUISHABLE from a real
        # operand, so `install --some-future-option 755 .env debug/.env` looked
        # like a multi-source copy and produced `debug/.env/.env`: the true
        # destination, mangled. Caught by the direction-of-error test, which is
        # the one that exists to stop exactly this.
        #
        # So only a trailing slash or an explicit `-t` proves a directory. When
        # the operand count merely SUGGESTS one, both readings are recorded
        # rather than guessing: an extra taint on a path nothing writes is inert,
        # while a mangled destination loses the real one.
        into_directory = destination.endswith("/") or to_target_dir
        for source in sources:
            joined = f"{destination.rstrip('/')}/{source.rstrip('/').split('/')[-1]}"
            if into_directory:
                written = [joined]
            elif len(sources) > 1:
                written = [destination, joined]
            else:
                written = [destination]
            for path in written:
                pairs.append((match.start(), _abs(source, cwd), _abs(path, cwd)))
    return pairs


# A redirect operator whose target the segment split took away (`2>&1` ends the
# span at its `&`): the shell's, never an operand.
_DANGLING_REDIRECT = re.compile(r"(?:\d*|&)>[>|]?\s*$")


def _copy_operands(verb: str, rest: str) -> tuple[list[str], str, bool] | None:
    """(sources, destination, destination came from `-t`) AS WRITTEN for one
    cp/mv/install/ln and the rest of its segment, by rules 1-4 of `_copy_pairs`;
    None when nothing is written (`install -d`) or there are too few operands.
    The one grammar: `_copy_pairs` maps it with `_abs`, the installed-guard floor
    with `_resolved`.

    ⚠ A REDIRECT IS NEVER THE DESTINATION. Main read `cp .env /tmp/leak
    2>/dev/null` as a copy INTO `2>/dev/null`, so the taint landed on a path
    nothing writes and `/tmp/leak` went unlabelled; `2>&1` and `>| log` did
    the same."""
    value_opts = _COPY_VALUE_OPTS[verb]
    tokens = _split_tokens(_DANGLING_REDIRECT.sub("", _REDIRECT_TARGET.sub(" ", rest)))
    operands: list[str] = []
    target_dir: str | None = None
    creates_dirs = False
    index = 0
    end_of_options = False
    while index < len(tokens):
        token = tokens[index]
        if end_of_options or not token.startswith("-") or token == "-":
            operands.append(token)
            index += 1
            continue
        if token == "--":
            end_of_options = True
            index += 1
            continue
        name, _, inline = token.partition("=")
        if verb == "install" and name == "-d":
            creates_dirs = True
        if inline:                                   # --target-directory=DIR
            if name in _TARGET_DIR_OPTS:
                target_dir = inline
            index += 1
            continue
        if name in value_opts and index + 1 < len(tokens):
            if name in _TARGET_DIR_OPTS:
                target_dir = tokens[index + 1]
            index += 2                               # the option AND its value
            continue
        index += 1                                   # a plain flag
    if creates_dirs:
        return None                                  # rule 3
    if target_dir is not None:                       # rule 2
        return operands, target_dir, True
    if len(operands) >= 2:                           # rule 4
        return operands[:-1], operands[-1], False
    return None


# The single-character ANSI-C escapes bash decodes inside `$'...'`. `\\x`, the
# octal digits and `\\u`/`\\U` are handled separately below because they consume a
# variable number of following characters. Verified against real bash.
_ANSI_C_NAMED = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
                 "n": "\n", "r": "\r", "t": "\t", "v": "\v",
                 "\\": "\\", "'": "'", '"': '"', "?": "?"}
_HEX_DIGITS = "0123456789abcdefABCDEF"


def _ansi_c_escape(text: str, j: int, n: int) -> tuple[str, int]:
    """Decode ONE `$'...'` escape whose backslash sat at `j - 1`; `text[j]` is the
    character after it. Returns (decoded_piece, index_after_the_escape).

    ⚠ EXACTLY WHAT BASH PRODUCES, AND NO MORE. A recognised escape yields its
    byte(s); an UNRECOGNISED one keeps the backslash literally (`\\z` -> `\\z`,
    `\\x` with no hex digit -> `\\x`), which is bash's own behaviour and fails
    toward MORE text rather than a silent drop. Total — it never raises, so the
    un-quoting path cannot swallow a malformed escape into a silent allow.
    """
    c = text[j]
    if c in "01234567":                              # \nnn octal, 1-3 digits
        k = j
        while k < n and k < j + 3 and text[k] in "01234567":
            k += 1
        return chr(int(text[j:k], 8) & 0xFF), k
    if c == "x":                                     # \xHH hex, 1-2 digits
        k = j + 1
        while k < n and k < j + 3 and text[k] in _HEX_DIGITS:
            k += 1
        if k == j + 1:                               # no hex digit: bash keeps \x
            return "\\x", k
        return chr(int(text[j + 1:k], 16) & 0xFF), k
    if c in "uU":                                    # \uHHHH (4) / \UHHHHHHHH (8)
        width = 4 if c == "u" else 8
        k = j + 1
        while k < n and k < j + 1 + width and text[k] in _HEX_DIGITS:
            k += 1
        if k == j + 1:                               # no hex digit: bash keeps it
            return "\\" + c, k
        try:
            return chr(int(text[j + 1:k], 16)), k
        except (ValueError, OverflowError):          # codepoint out of range
            # Keep the WHOLE escape literal — backslash, `u`/`U`, and the digits
            # we consumed — never a partial decode that silently drops them. The
            # exact bash-≥4.2 output for an over-range `\U` is unverified here, so
            # the conservative fail-toward-MORE form is the one that cannot become
            # a bypass, and the raw token is unioned beside it regardless.
            return "\\" + text[j:k], k
    named = _ANSI_C_NAMED.get(c)
    if named is not None:
        return named, j + 1
    return "\\" + c, j + 1                            # unrecognised: keep backslash


def _decode_ansi_c(text: str, i: int, n: int) -> tuple[str, int]:
    """Decode the body of a `$'...'` run. `i` is just past the opening `$'`;
    returns (decoded_text, index_just_after_the_closing_quote).

    Only an unescaped `'` closes the run — `\\'` is a literal quote. An
    unterminated run resolves what it has and stops at end of text, matching
    `_bash_unquote`'s fail-toward-MORE handling of an unbalanced quote.
    """
    out: list[str] = []
    while i < n:
        ch = text[i]
        if ch == "'":
            return "".join(out), i + 1
        if ch == "\\" and i + 1 < n:
            piece, i = _ansi_c_escape(text, i + 1, n)
            out.append(piece)
            continue
        out.append(ch)
        i += 1
    return "".join(out), n


def _bash_unquote(text: str) -> str:
    """`text` as bash would resolve its quoting and escaping — for RECOGNISING a
    credential path a literal matcher would otherwise miss, never for execution.

    The shell collapses `@.e''nv`, `@.en\\v` and `@".e"'nv'` to `@.env` before
    anything here runs, so a matcher reading the raw token sees a split string
    the network never will. This returns the resolved form; the two extractors
    below scan it BESIDE the raw command and union the hits, so a fix can only
    add recognitions, never drop one.

    ⚠ BASH SEMANTICS, AND ON BASH COMMAND TEXT ONLY. It is called from the two
    command-text extractors and from nowhere near the filesystem-path route
    (`action.paths` against `CREDENTIAL_PATHS`), where a Windows backslash is a
    separator, not an escape. Mixing the two would turn `C:\\Users\\dev\\.env`
    into `C:Usersdev.env` at the very place that must keep matching it. See
    tests/test_credential_paths_survive_shell_glue.py.

    Four states, exactly what a shell removes between two runs of one word:
      unquoted   `\\<c>` -> literal <c>; a quote opens a quoted run; `$'` opens
                 an ANSI-C run
      '...'      everything literal until the next `'` (no escapes inside)
      "..."      `\\` escapes only " \\ $ ` ; every other backslash is literal
      $'...'     ANSI-C quoting: `\\xHH`/`\\nnn`/`\\u`/`\\U` and the named escapes
                 decode to their bytes (`_decode_ansi_c`), so `$'\\x2e\\x65\\x6e\\x76'`
                 resolves to `.env`. Only from the UNQUOTED state — bash leaves
                 `$'...'` literal inside `'...'` and `"..."`, and decoding it there
                 would decode in a context bash would not.
    Whitespace outside quotes is preserved, so word boundaries survive for the
    splitters that consume the result. An unbalanced quote resolves its tail as
    literal — recognition fails safe toward MORE, and the raw pass is unaffected.
    """
    out: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None
    while i < n:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
            else:
                out.append(ch)
        elif quote == '"':
            if ch == '"':
                quote = None
            elif ch == "\\" and i + 1 < n and text[i + 1] in '"\\$`':
                out.append(text[i + 1])
                i += 1
            else:
                out.append(ch)
        elif ch == "$" and i + 1 < n and text[i + 1] == "'":
            # ANSI-C quoting. Decode from just past `$'` to the closing `'`; the
            # decoded bytes are DATA, so a decoded `\n` inside is never a segment
            # boundary — this returns a resolved word, it does not re-split.
            decoded, i = _decode_ansi_c(text, i + 2, n)
            out.append(decoded)
            continue
        elif ch in "'\"":
            quote = ch
        elif ch == "\\" and i + 1 < n:
            out.append(text[i + 1])
            i += 1
        else:
            out.append(ch)
        i += 1
    return "".join(out)

# WHERE A SHELL WOULD ACTUALLY START A COMMAND: the beginning of the string, or
# just after a separator. A real `cp` always sits at one of these positions; a
# `cp` quoted inside a Python string literal, a heredoc body or a comment never
# does.
#
# THIS REPLACED A PROPOSAL TO STRIP `python -c` BODIES, which the corpus
# disproved: E01 hides its exfiltration in `node -e "…require('https').get…"`
# and F01 in `python -c "import os; os.system('curl …')"`. A `-c` body is a
# program, not inert payload — stripping it would have unblocked both and taken
# A4 from 50 to 48. Anchoring the verb instead removes the false extractions
# without touching either body.
# ⚠ `[^\S\n]*`, NOT `\s*`, AFTER THE SEPARATOR (fix/false-positives, the
# second review round): a newline is itself a separator, so after one the
# match starts from it — the same groups — while `\s*` re-swallowed a whole
# run of blank lines from every position in it. `_COPY_VERB` and
# `_TRUNCATING_REDIRECT` read every command in `propagate`: 20,000 newlines
# took 6.9 s.
_CMD_START = r"(?:^|(?<=[;&|\n(])(?<!>\|)(?<![<>]&))[^\S\n]*"   # redirects end nothing

# `cp A B`, `mv A B`, `cat A > B`, `tee B`
# `cp A B`, `mv A B`, `install A B` — the VERB and the rest of its segment.
#
# THIS USED TO BE ONE REGEX THAT ALSO PICKED THE OPERANDS:
#
#     (?:cp|mv|install)\s+(?:-\w+\s+)*(\S+)\s+(\S+)
#
# and it did not fail by missing. It failed by MIS-CAPTURING, which is worse,
# because every consumer believed it:
#
#     install -m 755 .env debug/.env    -> ('755', '.env')            WRONG
#     cp --preserve=mode .env debug/.env-> ('--preserve=mode','.env')  WRONG
#     cp -t debug/ .env                 -> ('debug/', '.env')          REVERSED
#     cp .env other.txt backup/         -> ('.env', 'other.txt')       WRONG dst
#
# `-\w+` matches `-m` but never `--preserve=mode`, because `\w` excludes `-`;
# and it has no notion of an option that takes a SEPARATE value, so `755`
# became the source. WHAT THAT COSTS, measured end to end rather than argued:
# `_copy_destinations()` feeds `mark_sources`, which SUBTRACTS destinations from
# its source candidates — so a mis-captured dst names the real secret as the
# destination and suppresses it. With the copy as the only ingestion point,
# `cp -t debug/ .env` scored ALLOW / ALLOW / ALLOW across read, commit and push
# while `cp .env debug/.env` scored ALLOW / ASK / ASK. Not a precision bug: the
# session forgets it ever held a secret, and the whole ladder goes inert.
#
# The parser below is deliberately small and its errors point one way — see
# _copy_pairs.
_COPY_VERB = re.compile(_CMD_START + rf"(cp|mv|install)\s+({_SEGMENT_REST})")

# Options that take a SEPARATE value token, per verb. VERIFIED against the real
# tools, the way git's seven were: every `install` entry below was run as
# `install <opt> <value> src dst` on this machine (BSD/macOS) and copied the
# file. BSD `cp` and `mv` accept NO separate-value option and no long options at
# all — `cp -t`, `cp -S .bak` and `cp --preserve=mode` are all rejected.
#
# ⚠ THE GNU ENTRIES ARE FROM DOCUMENTATION, NOT MEASURED: this machine has no
# coreutils (`gcp`/`ginstall` absent), so `-t`, `-S` and the `--long` forms could
# not be exercised. They are included because Sting runs on Linux too, and a
# missing entry is the direction that costs a source.
#
# `-f` IS VERB-CONDITIONAL and that matters: `cp -f` / `mv -f` mean *force* and
# take nothing, while BSD `install -f flags` takes a value. Treating `-f` as
# value-taking for cp would eat a real operand.
_COPY_VALUE_OPTS = {
    "cp":      {"-t", "-S", "--target-directory", "--suffix"},
    "mv":      {"-t", "-S", "--target-directory", "--suffix"},
    "install": {"-t", "-S", "-m", "-o", "-g", "-B", "-f", "-M", "-N", "-T", "-h",
                "--target-directory", "--suffix", "--strip-program", "--mode",
                "--owner", "--group"},
    # `ln [-s] TARGET LINK` writes LINK, the copy's shape: the installed-guard
    # floor reads it (swapping `current` repoints the whole guard), taint never
    # matches it (`_COPY_VERB` has no `ln`).
    "ln":      {"-t", "-S", "--target-directory", "--suffix"},
}
_TARGET_DIR_OPTS = {"-t", "--target-directory"}
# ⚠ `>` ONLY, NEVER `>>`. A truncating redirect creates the file's contents; an
# append adds to what somebody else made. That distinction is the whole of the
# deferred rule, so it is drawn in the pattern rather than after it.
# ⚠ `(?:|[^>|]*?(?<!\S))`, NOT `[^>|]*?`, IN BOTH REDIRECT PATTERNS — THE SAME
# MATCHES IN LINEAR TIME (item 4, docs/93). The lazy prefix retried the source
# group at EVERY character of a long run with no `>`, and each try re-scanned the
# run: `cat` + 50,000 `[` took ~58 s. A source group starting inside a run of
# non-space characters succeeds only if one starting at the run's first
# character does (what follows the group is all that decides it), and the lazy
# prefix reaches that first character first — so trying the verb's end, then
# only positions after whitespace, in order, finds the identical leftmost match.
# `tests/test_the_guard_cannot_be_stalled.py` checks it against the old pattern.
# ⚠ AND WINDOWS' READERS, EXACTLY LIKE `cat` (fix/more-masking-and-agent-status,
# item D): cmd's `type`, PowerShell's `Get-Content` and its alias `gc`, in any
# case, as PowerShell and cmd read them. `type A > B` copies A into B. A space
# or a tab follows the verb: `print(type(x) > y)` in a `python -c` is code.
WINDOWS_READERS = r"(?i:type|gc|get-content)(?=[ \t])"
_TRUNCATING_VERBS = (r"(?:cat|base64|xxd|od|strings|head|tail|echo|printf|"
                     + WINDOWS_READERS + r")\b")
_REDIRECT_VERBS = r"(?:cat|base64|xxd|od|strings|head|tail|" + WINDOWS_READERS + r")\b"
_TRUNCATING_REDIRECT = re.compile(_CMD_START + _TRUNCATING_VERBS +
                        r"(?:|[^>|]*?(?<!\S))"
                        # ⚠ `[^\s>|]+` FOR THE SOURCE, NOT `\S+`. With `\S+` the
                        # group happily captured the FIRST `>` of a `>>`, leaving
                        # the second to satisfy `>(?!>)` — so every append read
                        # as a truncating redirect and `echo x >> theirs.sh`
                        # was recorded as authorship. The exclusion that makes
                        # the rule work was defeated by the token that carries it.
                        r"([^\s>|]+)\s*>(?!>)\s*([^\s>|]+)")

_REDIRECT = re.compile(_CMD_START + _REDIRECT_VERBS +
                        r"(?:|[^>|]*?(?<!\S))"
                        r"(\S+)\s*>>?\s*(\S+)")
# Where each pattern above can START — its first half — for `_redirect_matches`.
_TRUNCATING_VERB = re.compile(_CMD_START + _TRUNCATING_VERBS)
_REDIRECT_VERB = re.compile(_CMD_START + _REDIRECT_VERBS)
_REDIRECT_STOP = re.compile(r"[>|]")


def _redirect_matches(pattern: re.Pattern, verb: re.Pattern,
                      text: str) -> list[re.Match]:
    """`list(pattern.finditer(text))` for `_REDIRECT` / `_TRUNCATING_REDIRECT` —
    the identical matches, in linear time (item 4, docs/93).

    ⚠ `finditer` TRIED EVERY VERB, AND EACH FAILED TRY SCANNED TO THE NEXT `>`
    OR `|`, because the prefix crosses `;`. `cat x;` repeated with no `>` is n
    tries of O(n). A try that fails at the stop S rules out every LATER verb
    whose next stop is also S: its prefix reaches only positions the earlier
    try already tried — the verb's end sits inside a run the earlier try tested
    from its start, and what follows the source group is all that decides it.
    So those tries are skipped, the tries made cover disjoint stretches, and
    what is returned is exactly what `finditer` returns. Checked against
    `finditer` in `tests/test_the_guard_cannot_be_stalled.py`.
    """
    stops = [m.start() for m in _REDIRECT_STOP.finditer(text)]
    out: list[re.Match] = []
    resume, dead_stop, k = 0, -1, 0
    for found in verb.finditer(text):
        if found.start() < resume:
            continue
        # verbs arrive in order, so the next stop only ever moves forward
        while k < len(stops) and stops[k] < found.end():
            k += 1
        stop = stops[k] if k < len(stops) else len(text)
        if stop == dead_stop:
            continue
        match = pattern.match(text, found.start())
        if match:
            out.append(match)
            resume, dead_stop = match.end(), -1
        else:
            dead_stop = stop
    return out

# ⚠ WHAT "ABSOLUTE" LOOKS LIKE ON WINDOWS, AND IT IS NOT A LEADING SLASH.
# `C:\proj`, `d:/proj` (Windows accepts either separator after the drive) and
# the UNC form `\\server\share`. Written as a regex rather than with pathlib
# because this module is a PURE FUNCTION of (action, state, world) and
# tests/test_hook_entry.py bans pathlib here outright — pathlib would also give
# the wrong answer, since PurePosixPath and PureWindowsPath disagree about
# exactly this and the engine cannot know which machine it is describing.
_WINDOWS_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")


def _basename(path: str) -> str:
    """The last path component, whichever separator produced it.

    ⚠ ONE HELPER, NOT `os.path.basename`. `os.path` resolves to POSIX rules on
    a POSIX host, so a Windows path arriving in a log being replayed on a Mac —
    which is exactly what `runner/replay_live.py` does — would still be split
    wrongly. The engine has to read a path the way the machine that WROTE it
    would, and that is a property of the string, not of this host.
    """
    return path.rsplit("/", 1)[-1].rsplit(chr(92), 1)[-1]


def _abs(path: str, cwd: str) -> str:
    path = path.strip().strip("'\"")
    if path.startswith("~"):
        return path.replace("~", "/HOME", 1)
    # ⚠ WITHOUT THE SECOND TEST, EVERY WINDOWS ABSOLUTE PATH READ AS RELATIVE
    # and was joined onto the cwd: `C:\proj\app` became `C:\work\C:\proj\app`,
    # which matches no root, no taint entry and no credential pattern. Silent:
    # the action still had paths, they just stopped being the right ones.
    if path.startswith("/") or _WINDOWS_ABSOLUTE.match(path):
        return path
    # Join with the separator the CWD is already using. Mixing them produces
    # `C:\work/src\main.py`, which Windows opens happily and which no string
    # comparison in this file recognises as living under `C:\work`.
    sep = "\\" if ("\\" in cwd or _WINDOWS_ABSOLUTE.match(cwd)) else "/"
    return f"{cwd.rstrip('/' + chr(92))}{sep}{path}"

# `git commit`, but not `git commit --amend --no-edit`-style rewrites of an
# existing commit, which move nothing new into history.
# ANCHORED to a command position. `git commit` and `git push` are things a
# shell RUNS, so a mention of either that is not where a command starts is a
# mention, not an execution. Measured before the change: 0 corpus matches lost,
# 6 (commit) and 5 (push) lost across one 871-action real session.
#
# ONLY THESE TWO. Measured per matcher, and the other candidates cost attacks:
#   _PIPE_TO_SHELL  -7 corpus matches, incl. G01 and G02. Its pattern already
#                   begins with a literal `|`, so it is positional by
#                   construction; anchoring only breaks it.
#   _GUARD_SELFMOD  -20 corpus matches, incl. H05-disable-guard-directly. It
#                   matches NOUNS — `sting`, `hook_entry`, `.sting/` — which
#                   appear as arguments (`rm -rf ~/.sting`), never as a verb.
#                   Anchoring a noun matcher is a category error.
#   _NET_TOOL       deliberately NOT anchored: F01 hides `curl` inside a
#                   `python -c` body and its block depends on matching there.
#
# WHAT THIS DOES NOT FIX. The lookbehind sees a CHARACTER, not a quoting
# context, so `python3 -c "cmd = 'git add -A && git commit x'"` still matches:
# the `&&` inside the string literal is a command separator as far as a regex
# can tell. Closing that needs real tokenisation — it is the strongest evidence
# yet for rule #9's shell-parser escape hatch, and it is recorded as such rather
# than papered over here.
# GIT'S GLOBAL OPTIONS SIT BETWEEN `git` AND THE VERB, AND SEVEN OF THEM TAKE A
# SEPARATE VALUE TOKEN. This closed an exploitable bypass of every sink below:
#
#   git commit -m x                       -> git_commit          (matched)
#   git -c user.email=a@b commit -m x     -> NO SINK AT ALL      (escaped)
#   git push origin main                  -> git_push            (matched)
#   git -c http.proxy=x push origin main  -> NO SINK AT ALL      (escaped)
#
# `_GIT_COMMIT` had no flag tolerance at all; `_GIT_PUSH` had `(?:-\S+\s+)*`,
# which consumes `-c ` and then STOPS, because `user.email=a@b ` does not start
# with `-`. Either way the verb is never reached and the action stops being an
# exit — while still committing and still pushing. An agent bypasses this by
# adding a flag that reads as configuration hygiene, not as evasion, and every
# I02-shaped attack was bypassable that way.
#
# THE SEPARATE-VALUE SET IS ENUMERATED, NOT GUESSED. Verified against real git
# (`git <opt> <value> rev-parse --git-dir` succeeds for each); the synopsis
# writes most of them as `--opt=<value>`, but git's parser accepts the
# two-token form for all of them, and the two-token form is the whole hole:
#
#   -c <name>=<value>   -C <path>          --git-dir <path>    --work-tree <path>
#   --namespace <name>  --exec-path <path> --attr-source <tree-ish>
#
# `--config-env` and `--super-prefix` are included on the same principle: both
# take a value, and a missing entry here is a HOLE while a spurious one is at
# worst a slightly wider sink. The value-taking alternative is listed FIRST so
# it consumes both tokens before the generic single-token branch can eat the
# flag alone — correct under backtracking either way, but not left to it.
#
# DIRECTION OF ERROR: this can only make MORE commands count as commits and
# pushes, so it tightens policy and cannot open a new hole. What it can cost is
# false positives, which is why the blast radius is measured against A4/A5 and
# the standing replay rather than asserted.
#
# THE VALUE MAY CONTAIN SPACES, so it is not `\S+`. The live shape that
# motivated this is `git -c user.name="A B" -c user.email=a@b commit -q -F -`:
# `\S+` stops at the space inside `"A B"`, the loop then fails on `B"`, and the
# verb is missed again — the bypass would have been only half closed. A token
# is therefore any run of non-space characters WITH quoted runs allowed inside
# it, which is what `user.name="A B"` actually is. The three alternatives are
# distinguished by their first character, so the nested quantifier cannot
# backtrack catastrophically.
_SHELL_TOKEN = r"(?:[^\s\"']|\"[^\"]*\"|'[^']*')+"
_GIT_VALUE_OPT = (r"(?:-[cC]|--(?:git-dir|work-tree|namespace|exec-path"
                  r"|attr-source|config-env|super-prefix))")
# ⚠ A VALUE OPTION ALWAYS TAKES THE NEXT WORD, AS GIT ITSELF DOES (docs/113 §3b,
# the round-1 python review). `-\S+` also matched `-c`, so every `-c` had two
# readings — a value option, or a flag of its own — and `git -c -c … x`, which
# matches nothing, tried every one: ×2.6 for each two more words, on main too.
# A value option is never read as a plain flag now; git reads `-c -c` as `-c`
# with the value `-c` the same way.
_GIT_GLOBAL_OPTS = (rf"(?:{_GIT_VALUE_OPT}\s+{_SHELL_TOKEN}\s+"
                    rf"|(?!{_GIT_VALUE_OPT}\s)-\S+\s+)*")

# `commit\b` also matched `git commit-graph write`, because `-` is a word
# boundary — a maintenance command classified as an exit. Pre-existing, found by
# the must-MISS half of the fix's own test table, and narrowed here because it
# is the same matcher and the same confusion of text for structure. This can
# only remove matches, and `commit-graph` is not a commit, so it opens nothing.
# ⚠ `NAME=value` WORDS IN FRONT OF THE VERB LEAVE IT THE VERB (docs/113 §3b).
# `GIT_TOKEN=$X git push` is a push, and `_CMD_START` alone missed it: the
# assignment, not `git`, sits at the command position. A value is any run of
# characters that neither ends the command nor opens a subshell, a quoted run,
# or one `$(…)` or backtick substitution on one line (`GH_TOKEN=$(gh auth
# token) git push`, the round-1 python review); it stops at a separator, so a
# run of `A=x;` is read once per segment.
_ASSIGNED_BEFORE = (r"(?:[A-Za-z_]\w*=(?:\$\([^()\n]*\)|`[^`\n]*`|[^\s;&|()<>\"'`]"
                    r"|\"[^\"]*\"|'[^']*')*[^\S\n]+)*")
_GIT_COMMIT = re.compile(_CMD_START + _ASSIGNED_BEFORE + r"git\s+" + _GIT_GLOBAL_OPTS
                         + r"commit(?![\w-])")

_GIT_PUSH = re.compile(_CMD_START + _ASSIGNED_BEFORE + r"git\s+" + _GIT_GLOBAL_OPTS
                       + r"push(?![\w-])")
# These two are deliberately NOT anchored to a command position — that is the
# standing decision recorded above, and only the flag tolerance changes here.
_GIT_REMOTE_ADD = re.compile(r"\bgit\s+" + _GIT_GLOBAL_OPTS + r"remote\s+add\b")
_GIT_CONFIG_GLOBAL = re.compile(r"\bgit\s+" + _GIT_GLOBAL_OPTS + r"config\s+--global\b")
_NONSTANDARD_INDEX = re.compile(r"--index-url|--extra-index-url|--repository-url")


def _norm_path(path: str) -> str:
    """`..` and `.` collapsed, LEXICALLY. No IO — this module may not do any.

    ⚠ THIS IS WHY THE ESCAPE TRAP IS CLOSED, and `_abs()` alone does not close
    it. `_abs("<scratch>/../src", cwd)` returns `<scratch>/../src`, and
    `is_inside_project` compares by prefix — so the string starts with the
    declared root and the path it names does not. Collapsing first makes the
    comparison ask about the directory rather than about the spelling.

    ⚠ LEXICAL, NOT PHYSICAL, and the difference is a stated limit rather than an
    oversight. Resolving symlinks would need the filesystem, which `decide()` may
    not touch (`tests/test_hook_entry.py` pins it as a pure function). So a
    symlink inside a declared scratch root pointing at `src/` would be exempted.
    That is the same class of gap the adapters already close where they can —
    they resolve symlinks when normalising `action.paths` — and it does not
    reach here, because command text is not `action.paths`.

    ⚠ `_abs()` IS DELIBERATELY LEFT ALONE. It feeds taint propagation, where
    every path in the session flows through it, and normalising there would have
    a blast radius nobody measured. This is a second, narrower notion used by one
    predicate, and it says so.
    """
    # ⚠ AN ALREADY-NORMAL ABSOLUTE PATH COMES BACK AS IT IS, without the walk
    # below — the identical result, since it has no empty, `.` or `..` part to
    # drop. It matters because a `cd` folded onto a long base re-walked every
    # component, which made `cd sub; cat x;` repeated a few hundred times take
    # tens of seconds (item 4, docs/93).
    if (path.startswith("/") and "//" not in path and "/./" not in path
            and "/../" not in path and not path.endswith(("/", "/.", "/.."))):
        return path
    lead = "/" if path.startswith("/") else ""
    out: list[str] = []
    for part in path.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not lead:
                out.append("..")
            continue
        out.append(part)
    return lead + "/".join(out) if (lead or out) else "."


# `NAME=value` where the SHELL would perform it: at the head, after a separator,
# or as a command-prefix assignment. Never `--flag=x` — the character before
# `NAME` would be `-`, which none of the alternatives admit.
# ⚠ `[^\S\n]*`, NOT `\s*`, AFTER THE SEPARATOR (fix/false-positives, the
# reviews): a newline is itself a separator, so a match after one is found
# from it — the same groups — while `\s*` re-swallowed a whole run of blank
# lines from every position in it, quadratic.
_SHELL_ASSIGNMENT = re.compile(
    r"(?:^|[;&|\n][^\S\n]*|\s)(\w+)=('[^']*'|\"[^\"]*\"|[^\s;&|]*)")

# `$NAME` or `${NAME}`.
_VAR_REF = re.compile(r"\$\{(\w+)\}|\$(\w+)")


def _literal_assignments(command: str) -> dict[str, str]:
    """`NAME -> value`, from assignments THIS COMMAND executes. Literals only.

    ⚠ THREE RESTRICTIONS, AND EACH ONE IS LOAD-BEARING.

    FROM A COMMAND POSITION ONLY. `code_mask` says which bytes the shell will
    execute, so an assignment written inside a heredoc body or a quoted string is
    invisible here — the same gate `_code_pairs` applies for G03. That matters
    directly: 12 of 14 records in the neighbouring class are Python heredocs, and
    a Python script's own variables must not become shell facts.

    NEVER FROM THE ENVIRONMENT. Nothing in this module reads `os.environ` — it
    cannot; the module may not import `os` (`tests/test_hook_entry.py`). So a
    variable assigned somewhere the guard never watched is a variable it does not
    know, and an unknown variable leaves its target unresolvable, which leaves the
    deletion non-exempt.

    LITERALS ONLY. A value containing `$` or a backtick is a substitution this
    function would have to evaluate to know, and evaluating it is precisely where
    an attacker would regain control of the answer. Refused.

    ⚠ WITHIN ONE COMMAND, NOT ACROSS THE SESSION, and that is measured rather
    than conservative-by-instinct: of 22 real records whose deletion target
    carries a variable, 21 assign it in the same command. Carrying assignments on
    SessionState would add a field, a mark_sources hook and a cap, to reach one
    more record.
    """
    # ⚠ THIS RELAXES A RULE, WHICH `code_mask_checked` EXPLICITLY REQUIRES A
    # CLEAN PARSE FOR — and it was not doing so. Measured:
    #
    #   python3 - <<PY / SP=/scratch/agent / PY / rm -rf $SP/probe
    #       parses     -> assignment invisible, target unresolved, NOT exempt
    #       + one unbalanced quote anywhere in the command
    #                  -> heredoc body reads as code, assignment observed,
    #                     target resolves, DELETION EXEMPTED
    #
    # The attacker writes the command, so they choose whether it parses. An
    # exemption that turns on an unbalanced quote is an exemption they control,
    # which is working rule #5 exactly. 0 of 2313 live verdicts change.
    mask, parsed = code_mask_checked(command)
    if not parsed:
        return {}
    out: dict[str, str] = {}
    for match in _SHELL_ASSIGNMENT.finditer(command):
        # ⚠ THE POSITION OF THE NAME, NOT OF THE MATCH. The pattern consumes the
        # separator in front of `NAME=`, and for a heredoc that separator is the
        # newline BEFORE the body — which the shell does execute, so the mask
        # marks it code. Gating on `match.start()` therefore admitted an
        # assignment written inside a python heredoc: precisely the thing this
        # function's docstring claims it cannot see. Caught by its own test case,
        # which is why that case is pinned rather than removed.
        start = match.start(1)
        if start >= len(mask) or not mask[start]:
            continue
        value = match.group(2).strip("'\"")
        if not value or "$" in value or "`" in value:
            continue
        out[match.group(1)] = value
    return out


def _expand(token: str, assignments: dict[str, str]) -> str:
    """`$SP/probe` -> `/declared/root/probe`, or left carrying its `$`.

    ⚠ AN UNRESOLVED VARIABLE MUST NOT BECOME EMPTY. A declared root never
    contains `$`, so a token that still carries one can never match one and the
    deletion stays a prompt. Substituting "" would turn `$UNKNOWN/x` into `/x` —
    a real path, silently, chosen by nobody.
    """
    def _one(match):
        name = match.group(1) or match.group(2)
        if name in assignments:
            return assignments[name]
        # ⚠ `$HOME` IS `~` SPELLED DIFFERENTLY, AND MAPPING IT READS NO
        # ENVIRONMENT. `_abs` already sends `~` to the `/HOME` sentinel; `$HOME`
        # is a fixed, well-known name with one meaning, so treating the two the
        # same is a lexical equivalence rather than a lookup.
        #
        # THE OBJECTION, AND IT IS SOUND BUT HARMLESS: an attacker who runs
        # `HOME=/tmp` in a PREVIOUS command and then `rm -rf $HOME` gets a
        # denial for deleting /tmp. That is a false positive in the harmless
        # direction — a prompt about a command that really is a bulk delete —
        # and it is not a bypass, because nothing here can be set to make the
        # rule read a smaller target. An assignment in THIS command wins above,
        # so `HOME=/tmp; rm -rf $HOME` correctly resolves to /tmp.
        if name == "HOME":
            return "/HOME"
        return match.group(0)

    return _VAR_REF.sub(_one, token)

# ------------------------------------------------------------------ EVIDENCE
#
# Which pattern proves each sink. Used ONLY to explain a verdict after the fact
# — never to decide one, so a gap here weakens an explanation and can never
# weaken a decision.
#
# The problem it solves: `command` in the log is clipped to 2048 bytes, and a
# verdict can turn on text past the cut. One did, at byte 10711. The record
# showed a denial with no visible cause, in a log built to be checkable.
# `_SINK_PATTERN` AND `sink_evidence()` WERE DELETED HERE (option B).
# They were a SECOND sink->pattern table, maintained alongside check_sinks's
# if-ladder and consulted after the fact to explain a verdict. Measured before
# removal: it covered 15 of 19 sinks — security_critical, security_weakening,
# write_outside, unknown_tool_call and mcp_tool_call had no entry and therefore
# no explanation — and for secret_in_argv it consulted `_SUBSHELL_READ` while the
# DECISION also turned on CREDENTIAL_PATHS, tainted_paths and tainted_vars, so
# the explanation could name text that never fired the rule.
#
# Evidence now comes from `_sink_hit`, where the match already happens, and rides
# on `Verdict.evidence`. Same objection as the extension recomputing action_hash:
# one decision, one implementation.

_EVIDENCE_CONTEXT = 60
"""Characters of surrounding text kept either side of the match, so the reader
can see WHERE in the command it landed — inside a heredoc body reads very
differently from the end of a pipeline."""


def span_evidence(text: str, start: int, end: int, limit: int = 200) -> str:
    """`@<offset> …matched text with context…`, bounded.

    Shared by sinks and SOURCES. A source used to record `command[:80]` — an
    arbitrary prefix — and when a real `git log` matched at byte 4065 the state
    displayed the heredoc opener at byte 0. Two people read that and concluded
    the match was inside the heredoc. An arbitrary prefix is not evidence; it is
    a different string that happens to come from the same command.
    """
    lo = max(0, start - _EVIDENCE_CONTEXT)
    hi = min(len(text), end + _EVIDENCE_CONTEXT)
    snippet = text[lo:hi].replace("\n", "\\n")
    if lo:
        snippet = "…" + snippet
    if hi < len(text):
        snippet += "…"
    return f"@{start} {snippet}"[:limit]


@functools.lru_cache(maxsize=512)
def _path_token(name: str) -> re.Pattern:
    """`name` as a whole path component, not as a substring.

    The lookbehind excludes word characters, `.` and `-` but DELIBERATELY
    allows `/`: `debug/.env` is a reference to the file `.env`, while
    `prevent.envelope`, `x.env2` and `.env.local` are not.
    """
    return re.compile(r"(?<![\w.\-])" + re.escape(name) + r"(?![\w.\-])")


def mentions_path(command: str, path: str) -> bool:
    """Does this command refer to `path`, by full path or by file name?

    WHY NOT `basename in command`. That is what this replaced, and it was a
    false-positive generator that needed no phantom source and no mangled key
    to fire. Once any `debug/.env` is legitimately tainted its basename is
    `.env`, and `".env" in cmd` is true of *any* command mentioning `.env`
    anywhere — a heredoc body, a comment, a URL. Measured over one real
    session: `config` matched `backup-configs.io` and `tsconfig.json`, `debug`
    matched the branch name `fix/issue-418-debug-env`.

    A basename is still matched — dropping it would lose `cat .env` after a
    `cd` — but only where it stands as a whole component.
    """
    if not command or not path:
        return False
    if _path_token(path).search(command):
        return True
    # ⚠ EITHER SEPARATOR. `rsplit("/", 1)` on `C:\Users\d\.env` returns the
    # WHOLE STRING as the "basename", so a rule keyed on a file's name is
    # matching a full path against a command that contains only the name — it
    # never fires. Silent, like every other site here.
    base = _basename(path)
    return bool(base) and bool(_path_token(base).search(command))


def _verb(names: str, flags: int = 0) -> re.Pattern:
    """A command word: a path may lead it (`/bin/rm`), an option or a longer
    name may not (`docker run --rm`, `git-rm`, `used`)."""
    return re.compile(rf"(?<![\w.-])(?:{names})\b", flags)


def _segment_end(command: str, at: int) -> int:
    """Where the segment holding `at` ends. `_SEGMENT_END` steps over the `&`
    of a redirect itself, so `curl -s URL 2>&1 -o FILE` keeps its `-o`."""
    end = _SEGMENT_END.search(command, at)
    return end.start() if end else len(command)
