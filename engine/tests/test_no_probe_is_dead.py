"""Every method on the World protocol must be called by something.

⚠ `git_remotes` WAS DEAD IN THREE PLACES AND THE THREE DID NOT AGREE.

It was declared on the `World` protocol in `core/types.py`, implemented for real
in `core/probes.RealWorld` (spawning `git remote -v`), and stubbed in
`core/engine._NoWorld` and `core/probes.NullWorld`. **Nothing in the engine ever
called it.** Removed.

⚠ AND THE PART THAT MAKES IT WORSE THAN MERELY UNUSED. Every fake world in the
test suite, and `runner/replay_live.NeutralWorld`, implements a method called
`remotes` — a DIFFERENT NAME that was never on the protocol. So the day somebody
called `world.git_remotes(cwd)` believing it was covered, it would have worked
against `RealWorld` and raised `AttributeError` against every fake and against
the differential replay. Dead code that looks exercised is a trap; dead code
whose stubs have quietly drifted to a different name is a trap with a delay
fuse.

This test is the guard, so the next one is caught in the same run as the change.
"""
from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import engine_source                                      # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _protocol_methods() -> set[str]:
    """The methods `World` declares, read from the source rather than imported.

    A `Protocol` class does not expose its members in a way that separates them
    from inherited `object` machinery, and reading the AST is exact.
    """
    tree = ast.parse(open(os.path.join(ROOT, "core", "types.py"),
                          encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "World":
            return {n.name for n in node.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and not n.name.startswith("_")}
    raise AssertionError("no `World` protocol in core/types.py — this test is "
                         "not measuring what it thinks it is")


def _callers() -> str:
    """Every part of the engine (tests/engine_source.py), and the hook."""
    return engine_source.text() + open(os.path.join(ROOT, "hook_entry.py"),
                                       encoding="utf-8").read()


def test_the_protocol_is_not_empty():
    """⚠ WORKING RULE 13, FORM F2. The universal below is TRUE over an empty
    set, so a rename or a refactor that made `_protocol_methods()` return
    nothing would turn this file green while checking nothing at all."""
    methods = _protocol_methods()
    assert len(methods) >= 4, f"only found {sorted(methods)}"
    for expected in ("staged_files", "staged_content", "read_text"):
        assert expected in methods, f"{expected} must be findable"


def test_project_roots_is_a_hook_entry_need_and_not_an_engine_one():
    """⚠ DRIFT IN THE OPPOSITE DIRECTION, FOUND BY THE TEST ABOVE FAILING.

    `project_roots` is implemented by `RealWorld` and `NullWorld` and CALLED —
    but by `hook_entry`, not by the engine, and it is NOT on the `World`
    protocol. That is correct as it stands: the protocol types the argument
    `decide()` takes, and `decide()` does not need roots; `hook_entry` resolves
    them once per session, outside the pure function, on purpose.

    It is pinned here because the asymmetry is confusing and was not written
    down anywhere: a fake world handed to `decide()` legitimately need not have
    `project_roots`, while one used to drive `hook_entry` must.
    """
    methods = _protocol_methods()
    hook_source = open(os.path.join(ROOT, "hook_entry.py"),
                       encoding="utf-8").read()

    assert "project_roots" not in methods
    assert ".project_roots(" not in engine_source.text(), \
        "if the engine starts needing it, it belongs on the protocol"
    assert ".project_roots(" in hook_source


def test_every_world_method_is_actually_called():
    """The rule: a probe on the protocol is a promise that something uses it."""
    callers = _callers()
    unused = [m for m in sorted(_protocol_methods())
              if f".{m}(" not in callers]

    assert not unused, (
        f"declared on World and called by nothing: {unused}. Either wire it up "
        f"or delete it — a probe nobody calls is a probe whose stubs drift.")


def test_git_remotes_is_gone_from_every_implementation():
    """Pinned by name, because this one had three implementations and a fourth
    spelling in the fakes. Re-adding it should be a decision, not a copy."""
    engine = [f"core/{part}.py" for part in engine_source.MODULES]
    for name in ("core/types.py", "core/probes.py", *engine):
        source = open(os.path.join(ROOT, name), encoding="utf-8").read()
        assert "def git_remotes" not in source, name


def test_the_real_world_and_the_null_world_offer_the_same_methods():
    """⚠ THE DRIFT THAT MADE THE DEAD CODE DANGEROUS, CAUGHT DIRECTLY.

    `RealWorld` answers from the machine; `NullWorld` answers nothing when state
    is unavailable. If one grows a method the other lacks, the degraded path
    raises `AttributeError` exactly when things are already going wrong.
    """
    from core import probes

    def public(cls):
        return {n for n in dir(cls)
                if not n.startswith("_") and callable(getattr(cls, n))}

    real, null = public(probes.RealWorld), public(probes.NullWorld)
    assert real == null, (
        f"only on RealWorld: {sorted(real - null)}; "
        f"only on NullWorld: {sorted(null - real)}")
