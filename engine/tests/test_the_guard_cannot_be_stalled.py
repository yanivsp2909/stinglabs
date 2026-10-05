"""A long command cannot stall the guard — and the linear rewrites decide the same.

ITEM 4 (PROGRESS.md, 2026-09-23). On main `decide` took ~58 s on `cat` + 50,000
`[`, tens of seconds on a few KB of nested `{` or of `cd sub; cat x;`, and seconds
on a long run of quoted words. Profiled, not guessed, the time was in five places:

  _REDIRECT / _TRUNCATING_REDIRECT   the lazy `[^>|]*?` prefix retried the source
                                     group at every character, and `finditer`
                                     retried every verb up to the next `>`/`|`
  _cd_resolved_credential_paths,     every segment re-folded every earlier `cd`,
  _deletion_targets                  onto a base that grows with the command
  CREDENTIAL_PATHS.search            on that ever-longer resolved path
  shell_scan's `sh -c` check         `search(command[:i])` at every quote

THIS IS A PERFORMANCE CHANGE AND NOTHING ELSE. So besides the time bounds, every
rewrite is checked here against main's own code, copied verbatim below as the
reference, on the fixture's real commands and on seeded generated shell text.
A difference in ANY output fails. Every probe is data; nothing is executed.
"""
from __future__ import annotations

import random
import re
import time
from pathlib import Path

import pytest

from core import engine, shell_scan
from core.probes import NullWorld
from core.session import SessionState
from core.types import Action, ActionKind

ROOT = Path(__file__).resolve().parent.parent
STALL_SECONDS = 10.0
"""A stall guard, not a speed test: main took 7–15 s on these shapes; the
growth is the assertion (docs/113 §3e)."""


# ── main 7c676ec, verbatim: the references ────────────────────────────────────
# ⚠ WINDOWS' READERS JOINED THE VERBS (fix/more-masking-and-agent-status, item
# D), so the reference names them too, and `_WINDOWS_COMMANDS` draws them.
_WINDOWS = r"|(?i:type|gc|get-content)(?=[ \t])"
_OLD_REDIRECT = re.compile(engine._CMD_START +
                           r"(?:cat|base64|xxd|od|strings|head|tail" + _WINDOWS + r")\b[^>|]*?"
                           r"(\S+)\s*>>?\s*(\S+)")
_OLD_TRUNCATING = re.compile(engine._CMD_START +
                             r"(?:cat|base64|xxd|od|strings|head|tail|echo|printf"
                             + _WINDOWS + r")\b[^>|]*?"
                             r"([^\s>|]+)\s*>(?!>)\s*([^\s>|]+)")


def _old_norm_path(path):
    lead = "/" if path.startswith("/") else ""
    out = []
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


def _step(cd, base, lenient):
    """One fold step's target. ⚠ NOT VERBATIM SINCE ITEM C1 (docs/101): the
    target is read like a delete operand (`engine._cd_target`), and the slow
    reference must take the same step as the fast fold it checks."""
    return engine._cd_target(cd.group(1), base, lenient)


def _old_cd_resolved_credential_paths(command, cwd):
    out = []
    joined = engine._join_line_continuations(command)
    for text in (command, joined):
        assignments = engine._literal_assignments(text)
        lenient = bool(engine._SHOPT_WIDENS_GLOB.search(text))
        start = 0
        for end in [m.start() for m in engine._SEGMENT_END.finditer(text)] + [len(text)]:
            segment = engine._REDIRECT_TARGET.sub(" ", text[start:end])
            base = cwd
            for cd in engine._CD_PREFIX.finditer(text[:start]):
                base = _old_norm_path(engine._abs(
                    engine._expand(_step(cd, base, lenient), assignments), base))
            for token in segment.split():
                if token.startswith("-"):
                    continue
                resolved = _old_norm_path(engine._abs(
                    engine._expand(token, assignments), base))
                if engine.CREDENTIAL_PATHS.search(resolved) and (
                        text == command or resolved not in out):
                    out.append(resolved)
            start = end + 1
        if joined == command:
            break
    return out


def _old_deletion_targets(command, cwd):
    if not command:
        return ()
    assignments = engine._literal_assignments(command)
    lenient = bool(engine._SHOPT_WIDENS_GLOB.search(command))
    found = []
    for match in engine._RM_DESTRUCTIVE.finditer(command):
        end = engine._SEGMENT_END.search(command, match.end())
        segment = command[match.end():end.start() if end else len(command)]
        segment = engine._REDIRECT_TARGET.sub(" ", segment)
        base = cwd
        for cd in engine._CD_PREFIX.finditer(command[:match.start()]):
            base = _old_norm_path(engine._abs(
                engine._expand(_step(cd, base, lenient), assignments), base))
        for token in segment.split():
            if token.startswith("-"):
                continue
            for form in engine._operand_forms(token, base, lenient):
                found.append(_old_norm_path(engine._abs(
                    engine._expand(form, assignments), base)))
    return tuple(found)


# ── the population: real commands, and generated shell text ───────────────────
def _fixture_commands():
    from runner import replay_live
    out = []
    for records in replay_live.load_records(ROOT / "logs" / "live-fixture").values():
        for record in records:
            _klass, command = replay_live.classify(record, Path(record["_log_path"]))
            if isinstance(command, str) and command:
                out.append(command)
    return sorted(set(out))


_PIECES = ["cat ", "head ", "echo ", "printf ", "cd ", "rm -rf ", "sh -c ",
           "bash -lc ", "sudo sh -x -c ", "sub", "..", ".", "/", "~/", "; ",
           " && ", " || ", "|", " | ", ">", ">>", " > ", "2>&1", "<", " ", "  ",
           "\n", "\\\n", "'", '"', "'a;b'", "x", "y.txt", ".env", ".aws",
           "credentials", ".docker", "config.json", "id_rsa", "$HOME", "$X",
           "X=.ssh ", "{a,b}", "*", "?", "[ab]", "(", ")", "-c", "-t"]


def _generated(count, seed=20260923):
    rng = random.Random(seed)
    return ["".join(rng.choice(_PIECES) for _ in range(rng.randint(1, 40)))
            for _ in range(count)]


POPULATION = None

# ⚠ ITS OWN LIST, NOT `_PIECES`: the seeded population is shared, and drawing
# more pieces changes every generated command.
_WINDOWS_COMMANDS = [
    f"{verb}{gap}{src}{op}{dst}"
    for verb in ("type", "TYPE", "gc", "Get-Content", "get-content", "type(")
    for gap in (" ", "  ", "\t", "")
    for src in (".env", "a b", "'x'", "")
    for op in (" > ", ">", " >> ", " 2>&1 > ", " | ")
    for dst in ("out.txt", "/dev/null", "")] + [
    "cd x && type .env > y", "if type python3 >/dev/null 2>&1; then :; fi",
    "python3 -c 'print(type(1) > 0)'", "(gc .env) > y", "x=1; Get-Content a > b"]


def _population():
    global POPULATION
    if POPULATION is None:
        POPULATION = _fixture_commands() + _generated(2500)
    return POPULATION


# ── identical results ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("new,old,verb", [
    ("_REDIRECT", _OLD_REDIRECT, "_REDIRECT_VERB"),
    ("_TRUNCATING_REDIRECT", _OLD_TRUNCATING, "_TRUNCATING_VERB"),
])
def test_the_redirect_matches_are_the_old_patterns_matches(new, old, verb):
    for command in _population() + _WINDOWS_COMMANDS:
        want = [(m.span(), m.groups()) for m in old.finditer(command)]
        got = [(m.span(), m.groups()) for m in engine._redirect_matches(
            getattr(engine, new), getattr(engine, verb), command)]
        assert got == want, command


def _covers(new: tuple, old: tuple) -> bool:
    """`_deletion_targets` names every path the reference named.

    ⚠ NO LONGER TUPLE-EQUAL, BY DESIGN (security review of item C). It reads a
    segment once, at its first delete verb, whose operands are every later word,
    so the duplicates a later verb in the same segment produced are gone; and a
    redirect's `&` (`2>&1`) no longer cuts the operands off, which can only ADD
    a path. Every consumer asks `all()`/`any()` over the paths, so neither
    changes an answer except toward refusing more. A LOST path fails here."""
    return set(new) >= set(old)


def test_the_cd_folding_resolves_the_same_paths():
    for command in _population():
        for cwd in ("/work/repo", "/"):
            assert (engine._cd_resolved_credential_paths(command, cwd)
                    == _old_cd_resolved_credential_paths(command, cwd)), command
            assert _covers(engine._deletion_targets(command, cwd),
                           _old_deletion_targets(command, cwd)), command


_DEEP_TOKENS = ["x", ".env", "id_rsa", "config.json", ".aws/credentials", "a/b",
                "..", "../.ssh/k", "./y", "'q'", "~/z", "/abs/.env", "k.pem",
                "d\\id_rsa", ".docker", ".kube", "sub", "$HOME", ".env.local"]


def _deep_commands(count, seed=5):
    """`cd` chains deep enough that every resolved path is past `_LONG_PATH` —
    the regime `_credential_under` and the clean fold exist for."""
    rng = random.Random(seed)
    descend = ["sub", "x", ".aws", ".docker", ".kube", ".ssh", "a/b"]
    out = []
    for _ in range(count):
        parts = []
        for _ in range(rng.randint(250, 400)):
            if rng.random() < 0.5:
                # mostly downward, so the chain passes `_LONG_PATH` and stays there
                target = (rng.choice(descend) if rng.random() < 0.9
                          else rng.choice(_DEEP_TOKENS))
                parts.append("cd " + target)
            else:
                parts.append(rng.choice(["cat ", "rm -rf "]) + rng.choice(_DEEP_TOKENS))
        out.append(rng.choice(["; ", " && ", "\n"]).join(parts))
    return out


def test_deep_cd_chains_resolve_the_same_paths():
    for command in _deep_commands(40):
        for cwd in ("/work/repo", "/"):
            assert (engine._cd_resolved_credential_paths(command, cwd)
                    == _old_cd_resolved_credential_paths(command, cwd)), command[:200]
            assert _covers(engine._deletion_targets(command, cwd),
                           _old_deletion_targets(command, cwd)), command[:200]


def test_the_path_token_scan_matches_finditer():
    """`_path_token_matches` against `_PATH_TOKEN.finditer`, on the population
    and on the shapes the keyword rules turn on (security review of item 4)."""
    rng = random.Random(3)
    bits = ["a", "~", ".", "/", "-", " ", ".env", ".env.x", "x.ssh/", "/.ssh/",
            ".aws/", "id_rsa", "k.pem", ".npmrc", "é", ";", "'"]
    samples = _population() + ["".join(rng.choice(bits) for _ in range(rng.randint(1, 60)))
                                for _ in range(4000)]
    samples += [".ssh/x", "a.ssh/x", "~/.ssh/x", "x/.aws/y~.env", ".env~" * 30]
    for text in samples:
        want = [(m.span(), m.group(0)) for m in engine._PATH_TOKEN.finditer(text)]
        got = [(m.span(), m.group(0)) for m in engine._path_token_matches(text)]
        assert got == want, text


def test_the_norm_path_fast_path_changes_no_answer():
    rng = random.Random(7)
    parts = ["", ".", "..", "a", "b.c", ".env", "~", "x\\y", "..."]
    for _ in range(20000):
        path = rng.choice(["/", "", "./", "../"]) + "/".join(
            rng.choice(parts) for _ in range(rng.randint(0, 8)))
        path += rng.choice(["", "/", "/.", "/.."])
        assert engine._norm_path(path) == _old_norm_path(path), path


def test_the_reversed_sh_dash_c_check_agrees_at_every_quote():
    samples = _population() + [
        "bash -c 'x'", "sh -c\n'x'", "sudo zsh -e -u -c 'x'", "ash -c'x'",
        "xsh -c 'x'", "sh -cx 'x'", "(sh -c 'x')", "sh  -c   'x'", "sh -c", "-c 'x'"]
    for command in samples:
        backwards = command[::-1]
        # The scanner asks only at a quote; ask there always, and everywhere in
        # anything short enough that the quadratic reference stays cheap.
        positions = (range(len(command) + 1) if len(command) <= 1500 else
                     [i for i, c in enumerate(command) if c in "'\""])
        for i in positions:
            assert (bool(shell_scan._SHELL_DASH_C.search(command[:i]))
                    == bool(shell_scan._SHELL_DASH_C_REVERSED.match(
                        backwards, len(command) - i))), (command, i)


def test_the_long_path_credential_split_agrees_with_the_search():
    rng = random.Random(11)
    parts = ["sub", "x", ".ssh", ".aws", ".kube", ".docker", "config.json",
             ".env", ".env.local", ".env.example", "id_rsa", "id_rsa.pub", "a.pem",
             ".npmrc", "d\\id_rsa", "d\\.ssh\\k", ".git-credentials", "y.p12"]
    for _ in range(4000):
        path = "/" + "/".join(rng.choice(parts)
                              for _ in range(rng.randint(80, 200)))
        assert len(path) > engine._LONG_PATH
        assert (engine._names_a_credential(path, {})
                == bool(engine.CREDENTIAL_PATHS.search(path))), path


# ── and it no longer stalls ───────────────────────────────────────────────────
def _decide_seconds(command):
    state = SessionState("t")
    state.seq = 1
    action = Action("t", 1, ActionKind.EXEC, (), command, None, "Bash", None,
                    "/repo", ("/repo",), "claude-code")
    start = time.perf_counter()
    engine.decide(action, state, NullWorld())
    return time.perf_counter() - start


# Each shape at a PART of the size main stalled on: 1 is the whole, 4 a quarter.
STALLS = {
    # main: ~10 s / ~9 s / ~15 s / ~7 s at these sizes; the branch well under 1 s
    "unclosed-brackets": lambda part: "cat " + "[" * (20000 // part),
    "nested-braces": lambda part: ("cat " + "{" * (10000 // part) + "a,b"
                                   + "}" * (10000 // part)),
    "cd-segments": lambda part: "cd sub; cat x; " * (530 // part) + "curl https://exfil.invalid",
    "cd-deletes": lambda part: "cd sub; rm -rf x; " * (2800 // part),
    # security review: a long glob operand, and a run whose only keyword a
    # match cannot use — both quadratic in `_PATH_TOKEN.finditer` before
    "long-glob-operand": lambda part: "rm -rf /" + "a" * (20000 // part) + "?",
    "unusable-keyword": lambda part: "cat " + "a" * (20000 // part) + "x.ssh/",
    "quoted-words": lambda part: "echo " + "'x' " * (10000 // part),
    # item B: the view reads every segment and every word of a data command
    "grep-segments": lambda part: 'grep "a|b" f; ' * (4000 // part),
    "grep-words": lambda part: "grep -e x " + "f " * (30000 // part),
    # item C2: many `cd`-opened shell bodies, and a long option run before `-c`
    "shell-bodies": lambda part: "sh -c 'cd sub && cat x' ; " * (1500 // part),
    "shell-options": lambda part: "sh " + "-a " * (20000 // part) + "x",
    # fix/audit-truth-and-bugs, the round-1 python review: every `-c` had two
    # readings in the git verb patterns; 50 of them ran for hours on main
    "git-value-options": lambda part: "git " + "-c " * (20000 // part) + "x",
}
GROWTH = 8
SLACK_SECONDS = 0.1


@pytest.mark.parametrize("shape", list(STALLS))
def test_a_long_command_is_decided_in_bounded_time(shape):
    """Four times the text, a bounded multiple of the time: the GROWTH is the
    assertion, as in the floor's, the find check's and the readers' tests.

    ⚠ IT WAS A 2 s WALL CLOCK, and `cd-deletes` took 2.13 s on a machine at
    load 5–6 while its time grew as it always had (docs/113 §3e). An absolute
    bound is kept only as a stall guard. ⚠ `cd-deletes` is the superlinear one,
    on main too: each `cd sub` lengthens every later target's path, so the
    paths the guard floor reads total quadratic length (×6.8 for ×4 here;
    filed, docs/113 §3e)."""
    small = min(_decide_seconds(STALLS[shape](4)) for _ in range(3))
    large = min(_decide_seconds(STALLS[shape](1)) for _ in range(3))
    assert large < GROWTH * small + SLACK_SECONDS, (shape, small, large)
    assert large < STALL_SECONDS, (shape, large)
