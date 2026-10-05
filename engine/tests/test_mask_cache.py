"""The mask is computed once per command, not once per consumer.

⚠ WHAT IT COST BEFORE. One `decide()` on a 5.2 KiB command asked for a mask NINE
times — `structure_mask` twice, `_sink_hit`, `_secret_in_argv_span`,
`mark_sources`, `_literal_assignments`, `deletes_a_catastrophic_root`, and
`_code_positions` twice — each rescanning the same bytes at 0.097 ms. That was
45% of the case's p50, and it was the same work done nine times.

MEASURED AFTER: p99 on that case 7.370 ms -> 2.022 ms, and A6a's worst-run p99
4.252 ms -> 2.371 ms.

THREE PROPERTIES, EACH ASSERTED BELOW, because a cache that gets any of them
wrong is worse than the rescan it replaces:

  IT CANNOT GO STALE      keyed on the command string itself, so a different
                          command is a different key. There is no invalidation
                          to get wrong because there is no mutable subject. A
                          stale mask on the wrong command is a wrong VERDICT.
  IT CARRIES THE BAIL     PARSED / TOO_LONG / UNPARSED survive a cache hit.
                          Flattening them would collapse "too long to scan" into
                          "could not parse" and reopen the length bypass.
  IT HANDS OUT COPIES     `_Mask` subclasses `bytearray` and is mutable. Sharing
                          one object with nine callers means one future
                          `mask[i] = 0` changes what the other eight see. A copy
                          is 0.0002 ms against a 0.0992 ms scan — 0.2%.
"""
from __future__ import annotations

import sys

import pytest

from core import shell_scan
from core.shell_scan import (PARSED, TOO_LONG, UNPARSED, bail_reason,
                              code_mask, code_mask_checked)


# ------------------------------------------------------------ it cannot stale

def test_a_different_command_is_a_different_key():
    """The staleness question, answered by construction rather than by
    lifecycle management."""
    a = code_mask("git push origin main")
    b = code_mask("echo 'git push origin main'")
    assert bytes(a) != bytes(b)
    # And asking again returns each one's own answer, not the other's.
    assert bytes(code_mask("git push origin main")) == bytes(a)
    assert bytes(code_mask("echo 'git push origin main'")) == bytes(b)


def test_the_cache_is_bounded():
    """Commands run to 64 KiB, so an unbounded cache is an unbounded leak."""
    assert shell_scan._scan_cached.cache_info().maxsize == shell_scan._CACHE_ENTRIES
    assert shell_scan._CACHE_ENTRIES <= 32, "the worst case is entries x 128 KiB"


def test_it_is_actually_a_cache():
    shell_scan._scan_cached.cache_clear()
    command = "git commit -m 'x' && git push origin main"
    code_mask(command)
    misses = shell_scan._scan_cached.cache_info().misses
    for _ in range(8):
        code_mask(command)
    info = shell_scan._scan_cached.cache_info()
    assert info.misses == misses, "a repeat asked the scanner again"
    assert info.hits >= 8


# ------------------------------------------------------- it carries the bail

@pytest.mark.parametrize("command,expected", [
    ("git push origin main", PARSED),
    ("echo 'unclosed", UNPARSED),
    ("z" * 70_000, TOO_LONG),
])
def test_the_bail_reason_survives_a_cache_hit(command, expected):
    """⚠ FLATTENING THIS REOPENS THE LENGTH BYPASS. `code_mask_checked`'s
    boolean goes false for both TOO_LONG and UNPARSED; only the three-way answer
    distinguishes "I did not try" from "I tried and could not", and a rule that
    gates on the boolean hands an attacker a way to switch it off by padding."""
    shell_scan._scan_cached.cache_clear()
    first = bail_reason(code_mask(command))
    cached = bail_reason(code_mask(command))
    assert first == expected
    assert cached == expected, "the reason was lost on the cache hit"


@pytest.mark.parametrize("command,parsed", [
    ("git push origin main", True), ("echo 'unclosed", False),
    ("z" * 70_000, False),
])
def test_code_mask_checked_agrees_across_a_cache_hit(command, parsed):
    shell_scan._scan_cached.cache_clear()
    assert code_mask_checked(command)[1] is parsed
    assert code_mask_checked(command)[1] is parsed


# --------------------------------------------------------- it hands out copies

def test_every_caller_gets_its_own_object():
    command = "git push origin main"
    a, b = code_mask(command), code_mask(command)
    assert a is not b, "nine callers would share one mutable bytearray"


def test_mutating_one_mask_cannot_reach_the_next_caller():
    """⚠ THE HAZARD A SHARED CACHE INTRODUCES, CLOSED BY CONSTRUCTION. Nothing
    mutates a mask today; this asserts that if something ever does, it cannot
    corrupt every other consumer's view of the same command."""
    command = "git push origin main"
    first = code_mask(command)
    original = first[0]
    first[0] = 0 if original else 1
    assert code_mask(command)[0] == original


def test_the_cached_payload_is_immutable():
    """The stored value is `bytes`, so the entry itself cannot be edited at all
    — the copy is made on the way out, not hoped for."""
    shell_scan._scan_cached.cache_clear()
    raw, reason = shell_scan._scan_cached("git push origin main")
    assert isinstance(raw, bytes)
    assert reason in (PARSED, TOO_LONG, UNPARSED)


# ------------------------------------------------------------------- purity

def test_the_cache_did_not_cost_purity():
    """⚠ MEMOISING A PURE FUNCTION LEAVES IT PURE. `_scan` is a function of one
    string and nothing else, so same input gives same output and there is no
    observable state. The module's import set is unchanged apart from
    `functools`, which the engine's allowlist already contains."""
    import ast
    from pathlib import Path

    tree = ast.parse((Path(__file__).parent.parent / "core" / "shell_scan.py")
                      .read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    assert modules <= {"__future__", "re", "functools"}, modules


def test_the_mask_cache_is_in_shell_scan_not_in_the_engine():
    """⚠ THE CACHE LIVES WITH THE SCAN, and that is where a cache of scans
    belongs — the module whose whole job is scanning.

    ⚠ AND "THE ENGINE HOLDS NO CACHE" WOULD BE FALSE. It already memoises
    `_path_token`, a regex compiler, and has since long before this. That is the
    same pattern and was already accepted for the same reason: memoising a pure
    function of one argument leaves it pure. So the property worth asserting is
    not "no cache" — it is that the engine does not grow its own copy of THIS
    one, which would be two caches of the same thing able to disagree.
    """
    import ast
    import inspect

    from core import engine
    from tests import engine_source

    # Every part of the engine (tests/engine_source.py): a cache that moved
    # with its function is still the engine's.
    cached = {n.name for tree in engine_source.trees().values() for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef)
               and any("cache" in ast.dump(d) for d in n.decorator_list)}
    assert cached == {"_path_token"}, (
        f"engine.py's caches are {cached}; a mask cache here would be a second "
        f"copy of shell_scan's, and two caches of one thing can disagree")
    assert shell_scan._scan_cached.cache_info() is not None


def test_the_scan_result_is_identical_with_and_without_the_cache():
    """The property that makes the whole thing safe: a hit and a miss return
    the same answer, for every shape that matters."""
    for command in ("git push origin main", "echo 'git log'", "z" * 70_000,
                     "echo 'unclosed", "python3 - <<PY\nprint(1)\nPY", ""):
        shell_scan._scan_cached.cache_clear()
        cold = bytes(code_mask(command)), bail_reason(code_mask(command))
        warm = bytes(code_mask(command)), bail_reason(code_mask(command))
        assert cold == warm, command[:30]
