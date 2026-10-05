"""Case sensitivity: detected where IO is allowed, carried on World, per root.

⚠ THE DECISION THAT WAS DEFERRED FOR macOS AND THAT WINDOWS FORCES. `is_inside_project`
carried a comment for months saying case was a known gap: on APFS, root `…/case`
and path `…/CASE/src/app.py` are the same directory and it judged them different.
That over-denies, which is safe, so it was left.

Windows removes the option, and the fix gets made ONCE:

    the CARRIER is World          not SessionState (which is per session, and
                                  this is a property of a filesystem) and not
                                  Action (which is per action, and it would be
                                  answered thousands of times)
    the GRANULARITY is per ROOT   Windows has per-DIRECTORY case sensitivity and
                                  macOS has case-sensitive volumes, so one
                                  workspace can span both and a machine-wide
                                  boolean is simply wrong
    DETECTION is IO               so it happens in core/probes.py, where IO is
                                  allowed, and arrives through the protocol.
                                  `pathlib` is banned from core/engine.py
                                  because decide() is a pure function.

⚠ AND A WRONG ANSWER IS NOT SYMMETRIC, which is why the unknown case has a
direction:

    wrong "insensitive"   two REAL directories merge; a path outside the project
                          is judged INSIDE. A BYPASS, and silent.
    wrong "sensitive"     one directory looks like two; an ordinary write is
                          judged outside. A FALSE POSITIVE — noisy and visible.

So `None` (could not tell) takes the noisy branch.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from core import probes
from core.engine import is_inside_project


class Insensitive:
    def case_insensitive(self, root): return True


class Sensitive:
    def case_insensitive(self, root): return False


class Unknown:
    def case_insensitive(self, root): return None


class Ancient:
    """A world written before the method existed. Ten of these are in this
    repo's own test suite, and any third-party World is one too."""


class Angry:
    def case_insensitive(self, root): raise OSError("no")


# ─────────────────────────────────────────────────── the carrier is on World

def test_the_real_world_answers_and_caches_per_root():
    world = probes.RealWorld()
    with tempfile.TemporaryDirectory() as root:
        first = world.case_insensitive(root)
        assert first in (True, False), "a real directory must give a real answer"
        assert world._case[root] is first
        assert world.case_insensitive(root) is first, "not cached"


def test_detection_leaves_nothing_behind():
    """⚠ IT WRITES A PROBE FILE INTO THE DEVELOPER'S OWN PROJECT ROOT. If that
    file survived, the guard would be creating litter in a repository it is
    supposed to be watching — and `git status` would show it."""
    world = probes.RealWorld()
    with tempfile.TemporaryDirectory() as root:
        before = set(os.listdir(root))
        world.case_insensitive(root)
        assert set(os.listdir(root)) == before


def test_an_unreadable_root_is_UNKNOWN_and_not_a_guess():
    """⚠ `None`, NOT `False`. A read-only root, a permission error, a full disk.
    Returning False would be a guess wearing the costume of a measurement."""
    assert probes.RealWorld().case_insensitive("/nonexistent-root-xyz") is None


def test_the_null_world_says_it_cannot_tell():
    assert probes.NullWorld().case_insensitive("/anything") is None


def test_both_real_implementations_provide_the_method():
    """⚠ THE `getattr` IN THE ENGINE MUST NOT LET THESE TWO OFF. It exists so a
    test double that predates the method degrades to "cannot tell"; if it also
    covered `RealWorld`, the one world that does the actual IO could quietly
    stop answering and nothing would notice."""
    for cls in (probes.RealWorld, probes.NullWorld):
        assert callable(getattr(cls, "case_insensitive", None)), cls.__name__


# ────────────────────────────────────────── what the engine does with it

@pytest.mark.parametrize("world,inside", [
    (Insensitive(), True),
    (Sensitive(), False),
    (Unknown(), False),
    (Ancient(), False),
    (Angry(), False),
])
def test_a_differently_cased_path_follows_the_roots_own_filesystem(world, inside):
    """⚠ THE UNKNOWN, THE ANCIENT AND THE ANGRY ALL TAKE THE SAFE BRANCH, and
    that is one claim asserted three ways rather than three claims: whatever the
    reason a world cannot answer, the engine must not merge two directories on
    the strength of it."""
    assert is_inside_project("/proj/CASE/app.py", ("/proj/case",), world) is inside


def test_case_folding_never_makes_a_prefix_into_a_segment():
    """⚠ THE ERROR THAT WOULD BE A BYPASS. Folding case must not also relax the
    separator rule — `C:\\projector` is not inside `C:\\proj` on any
    filesystem."""
    assert is_inside_project(r"C:\PROJECTOR\x.py", (r"C:\proj",),
                              Insensitive()) is False
    assert is_inside_project("/projector/x.py", ("/proj",), Insensitive()) is False


def test_a_matching_path_is_still_inside_when_the_case_matches():
    for world in (Insensitive(), Sensitive(), Unknown(), Ancient()):
        assert is_inside_project("/proj/src/a.py", ("/proj",), world) is True


def test_omitting_world_behaves_exactly_as_before():
    """Every caller that has no world — `tools/preflight.py`, and every existing
    test — keeps its old behaviour rather than silently changing."""
    assert is_inside_project("/proj/src/a.py", ("/proj",)) is True
    assert is_inside_project("/PROJ/src/a.py", ("/proj",)) is False


def test_the_answer_is_asked_PER_ROOT_and_not_once(monkeypatch):
    """⚠ A MULTI-ROOT WORKSPACE CAN SPAN BOTH KINDS OF FILESYSTEM, so hoisting
    the question out of the loop would give one answer to a question that has
    several. Asserted by counting the calls."""
    asked = []

    class PerRoot:
        def case_insensitive(self, root):
            asked.append(root)
            return root == "/insensitive"

    roots = ("/sensitive", "/insensitive")
    assert is_inside_project("/INSENSITIVE/a.py", roots, PerRoot()) is True
    assert asked == list(roots), asked


# ══════════════════════════════ non-vacuity: the detection really detects

def test_the_probe_would_notice_a_case_sensitive_filesystem(monkeypatch):
    """⚠ THE FIX MUST BE SHOWN TO FAIL BEFORE IT PASSES. On this machine the
    real answer is whatever APFS gives; to prove the detector is measuring
    rather than returning a constant, the stat is made to disagree and the
    answer must flip.

    Without this, `case_insensitive` returning a hardcoded True would pass every
    test above — which is exactly what a broken fix to a silent site looks like.
    """
    world = probes.RealWorld()
    with tempfile.TemporaryDirectory() as root:
        honest = world.case_insensitive(root)

        world._case.clear()
        real_exists = Path.exists
        monkeypatch.setattr(Path, "exists",
                             lambda self: False if ".STING-CASE-PROBE" in self.name
                             else real_exists(self))
        assert world.case_insensitive(root) is False, (
            "the detector ignored the filesystem and returned a constant")

        monkeypatch.undo()
        world._case.clear()
        assert world.case_insensitive(root) is honest, "the probe is not repeatable"
