"""A delete after a `cd` into a folder named like a verb is resolved from there.

⚠ FOUND BY #78, ON MAIN TOO. Drawing more pieces from the stall test's seeded
population generated

    cd rm -rf gc rm -rf id_rsa)[ab]..sudo sh -x -c ) |  > ) > gc <; …

and `_deletion_targets` no longer named what the reference named for the
second `rm -rf`: `<cwd>/rm/id_rsa)[ab]..sudo`, `<cwd>/rm/sh`, `<cwd>/rm/)`.

⚠ WHY. The security review of item C made it read a segment ONCE, at its first
delete verb, so `rm rm rm …` is not quadratic. `_CD_PREFIX` matches only at a
segment's start, so a segment's directory changes at most once: after its
leading `cd`. Here the first delete verb is the `cd`'s own target (`rm`), which
starts before the `cd` has folded, so the one reading used the outer directory
for every later word, and the later `rm -rf`'s operands were never read from
`<cwd>/rm`, where the reference reads them.

⚠ THE FIX READS A SEGMENT A SECOND TIME, ONLY WHERE ITS DIRECTORY CHANGED:
still linear (at most two readings a segment), and it can only ADD a target.
Measured on the snapshot: the shape occurs in 0 of 19,480 distinct commands.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_the_guard_cannot_be_stalled import _covers, _old_deletion_targets  # noqa: E402

from core import engine                                                     # noqa: E402

GENERATED = "cd rm -rf gc rm -rf id_rsa)[ab]..sudo sh -x -c ) |  > ) > gc <; -t.docker[ab]'~/"


@pytest.mark.parametrize("cwd", ["/work/repo", "/"])
def test_the_generated_command_names_every_path_the_reference_names(cwd):
    got = engine._deletion_targets(GENERATED, cwd)
    want = _old_deletion_targets(GENERATED, cwd)
    assert _covers(got, want), sorted(set(want) - set(got))


def test_the_later_delete_is_read_from_the_folder_the_cd_named():
    got = engine._deletion_targets("cd rm -rf a rm -rf b", "/work/repo")
    assert "/work/repo/rm/b" in got
    assert "/work/repo/b" in got                    # the first reading still counts


def test_a_segment_is_still_read_at_most_twice():
    """Linear: 5,000 delete verbs after one such `cd` cost what 1,000 do, scaled."""
    def cost(n: int) -> float:
        command = "cd rm -rf " + "rm -rf x " * n
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            engine._deletion_targets(command, "/work/repo")
            best = min(best, time.perf_counter() - started)
        return best
    small, large = cost(1000), cost(5000)
    assert large < 1.0
    assert large < 10 * max(small, 1e-3), (small, large)
