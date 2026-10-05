"""Working rule #13, enforced — the standing guard against the sixth instance.

⚠ THE SHAPE, STATED SO IT CAN BE SEARCHED FOR. Five defects in one week were the
same defect: **a comparison whose two sides can both be ABSENT, so it succeeds
without comparing anything, and the covering test passes while the behaviour is
broken.** Structurally, three forms:

    F1  SYMMETRIC ABSENCE   `a == b` where both sides evaluate to the same
                            default under the fixture — None, "", 0, {}.
                            allow-once: `grant["guard_version"] ==
                            installed_version()` was `None == None`.
    F2  EMPTY UNIVERSAL     `all(...)`, `not [...]`, `for x in xs: assert`,
                            `a <= b` over a collection that can be empty. True
                            of nothing. The label-prompts fixture comparison,
                            and the counted zero from a corpus that could not
                            contain the thing being counted.
    F3  UNARMED GATE        an assertion about what a gate lets through, in an
                            environment where the gate's precondition was never
                            established. The supervisor reporting a plist as a
                            service; the trust boundary passing after looking
                            only beside the checkout.

This file holds the two mechanical guards. The third — arming the gates the
suite would otherwise inherit as absent — lives in `conftest.py`, because it has
to apply to every test rather than be remembered by each one.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
TESTS = ROOT / "tests"
sys.path.insert(0, str(ROOT))

from core import allow_once, version                             # noqa: E402
from installer import place                                      # noqa: E402


# ============================================== 1 · the gates are really armed

def test_the_suite_runs_with_an_install_present():
    """⚠ THE ONE ASSERTION THAT WOULD HAVE CAUGHT ALLOW-ONCE, AS A TEST OF ITS
    OWN. Its two covering tests passed for months because no test environment
    had an install, so `installed_version()` was None, the extension's grant had
    no version, and `None == None` succeeded without comparing anything.

    `conftest.armed_gates` now builds a real INSTALL.json behind a real
    `current` symlink for every test. If that ever stops working, every
    install-gated assertion in the suite quietly goes back to testing nothing —
    so it is asserted here, loudly, once.
    """
    assert allow_once.installed_version() is not None, (
        "the suite is running with no install, so every comparison against "
        "installed_version() is None == None again — see conftest.armed_gates")
    assert allow_once.install_time() is not None
    assert os.environ.get("STING_SCRATCH"), "the scratch gate is not armed"


def test_the_armed_install_is_real_and_not_just_an_environment_variable():
    """`install_time()` reads the `current` symlink's mtime and
    `installed_version()` parses a manifest. A fixture that only set the
    variable would arm the flag and not the mechanism."""
    manifest = Path(os.environ["STING_INSTALL_ROOT"]) / "current" / "INSTALL.json"
    assert manifest.exists()
    assert manifest.parent.is_symlink()


def test_the_suite_does_not_inherit_the_shell_that_ran_it():
    """⚠ THE SAME DISEASE POINTING OUTWARD. One test asserted a tier that
    `STING_TIER` decided, and passed here while failing for anyone who had it
    exported. Settings whose absence is itself the documented behaviour are
    CLEARED rather than set, so the suite's result does not depend on whose
    shell it ran in."""
    for leaky in ("STING_TIER", "STING_COLLECTOR_URL", "STING_DEVICE_TOKEN",
                   "STING_DEVICE_ID", "STING_OBSERVE"):
        assert leaky not in os.environ, (
            f"{leaky} leaked in from the environment; a test that reads it is "
            f"now asserting whatever this shell happens to hold")


# ====================================== 2 · no new unguarded empty universals

_ENVIRONMENTAL = {
    "glob", "rglob", "iterdir", "listdir", "scandir",
    "read_text", "read_bytes", "readlines", "load", "loads",
    "load_records", "read_records", "prompts", "splitlines",
    "findall", "finditer", "check_output",
}
# Ordinary local names as well as environmental ones — `walk` is this suite's
# own scenario helper. Counted only as an attribute call (`os.walk`).
_ATTRIBUTE_ONLY = {"walk", "run", "search", "open", "records"}

# Each of these was examined by hand during the sweep that produced this file
# and found to be guarded by something the scan cannot see — an index that would
# raise, a key lookup that would raise, or a counter asserted further down.
# ⚠ AN ENTRY HERE IS A JUDGEMENT SOMEBODY MADE, NOT A SUPPRESSION: adding one
# means writing down why, in the review that adds it.
KNOWN_GUARDED = {
    # `first = parsed["posix_LF"]` raises KeyError before the loop runs.
    ("test_chain_is_platform_neutral.py", "test_every_terminator_parses_to_the_identical_record"),
    # `assert logs` above it, and `assert checked > 20` below it.
    ("test_located_tier.py", "test_no_located_record_carries_command_text_on_the_real_fixture"),
    # `ast.walk` of a parsed module is never empty; `ast.parse` raises on junk.
    ("test_shipper_isolation.py", "test_no_shipper_module_can_listen"),
    ("test_types.py", "test_the_boundary_dtos_have_no_methods"),
    # ⚠ THE INVERSE CASE, WHICH THIS SCAN CANNOT EXPRESS. The claim there is
    # that a REFUSED install wrote NOTHING, so the collection is expected to be
    # empty and a non-emptiness assertion would be asserting the bug. It earns
    # its place here by running a CONTROL first — a complete source into a
    # sibling prefix, asserted non-empty — which is the guarantee this scan
    # exists to obtain, got the only way an emptiness claim can get it.
    ("test_the_artifact_is_installable.py", "test_a_refusal_leaves_no_half_written_tree"),
}


def _calls(node):
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Attribute):
                out.add(func.attr)
            elif isinstance(func, ast.Name) and func.id not in _ATTRIBUTE_ONLY:
                out.add(func.id)
    return out


def _names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _environmental_names(fn):
    tainted: set = set()
    for _ in range(3):
        before = set(tainted)
        for node in ast.walk(fn):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            if not (_calls(value) & _ENVIRONMENTAL or _names(value) & tainted):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                tainted |= _names(target)
        if tainted == before:
            break
    return tainted


def _guarded_names(fn):
    guarded = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assert):
            continue
        test = node.test
        if isinstance(test, ast.Name):
            guarded.add(test.id)
        elif isinstance(test, ast.Call) and _is_len(test):
            guarded |= _names(test)
        elif isinstance(test, ast.Compare):
            left = test.left
            if isinstance(left, ast.Call) and (_is_len(left) or _is_any(left)):
                guarded |= _names(left)
            elif isinstance(left, ast.Name) and any(
                    isinstance(op, (ast.NotEq, ast.Gt, ast.GtE)) for op in test.ops):
                guarded.add(left.id)
        elif isinstance(test, ast.Call) and _is_any(test):
            guarded |= _names(test)
    return guarded


def _is_len(call):
    return isinstance(call.func, ast.Name) and call.func.id == "len"


def _is_any(call):
    return isinstance(call.func, ast.Name) and call.func.id == "any"


def _universals(fn):
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assert):
            test = node.test
            if isinstance(test, ast.Call) and isinstance(test.func, ast.Name) \
                    and test.func.id == "all":
                found.append(("assert all(...)", node.lineno, _names(test)))
            elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) \
                    and isinstance(test.operand, (ast.ListComp, ast.GeneratorExp,
                                                   ast.SetComp)):
                found.append(("assert not [comprehension]", node.lineno,
                               _names(test.operand)))
            elif isinstance(test, ast.Compare) and any(
                    isinstance(op, (ast.LtE, ast.Lt)) for op in test.ops):
                # ⚠ `a < 2_000_000` IS A MAGNITUDE, NOT A QUANTIFIER, and the
                # first version flagged one — `archive.stat().st_size <
                # 2_000_000` read as set containment over `archive`. A universal
                # over an empty set is vacuous; a number compared to a number is
                # never vacuous. Numeric on either side means this is not the
                # shape being hunted.
                numeric = any(isinstance(n, ast.Constant)
                               and isinstance(n.value, (int, float))
                               and not isinstance(n.value, bool)
                               for n in (test.left, *test.comparators))
                if not numeric:
                    found.append(("assert a <= b", node.lineno, _names(test.left)))
        elif isinstance(node, ast.For) and any(
                isinstance(n, ast.Assert) for n in ast.walk(node)):
            found.append(("for ...: assert", node.lineno, _names(node.iter)))
    return found


def test_no_universal_assertion_runs_over_an_unguarded_environmental_collection():
    """⚠ A UNIVERSAL OVER NOTHING IS TRUE, so a test whose collection came from
    the filesystem and turned out empty passes having checked nothing. One line
    fixes it — `assert xs, "…"` — and this finds every place that lacks it.

    Scoped to collections DERIVED FROM THE ENVIRONMENT. The first version of
    this scan flagged 110 of 126 quantifiers, nearly all over list literals
    written three lines above, and a scan whose output nobody reads is the
    failure mode of the thing it is looking for.
    """
    offenders = []
    for path in sorted(TESTS.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in [n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name.startswith("test")]:
            if (path.name, fn.name) in KNOWN_GUARDED:
                continue
            environmental = _environmental_names(fn)
            guarded = _guarded_names(fn)
            for kind, lineno, names in _universals(fn):
                over = names & environmental
                if over and not over & guarded:
                    offenders.append(
                        f"{path.name}:{lineno} {fn.name} — {kind} over "
                        f"{sorted(over)} with no non-emptiness assertion")
    assert not offenders, (
        "a universal assertion over an environment-derived collection with "
        "nothing establishing it is non-empty:\n  " + "\n  ".join(offenders))


def test_the_scan_can_actually_fail(tmp_path):
    """⚠ AND THE SCAN IS ITSELF CHECKED FOR THE DISEASE IT LOOKS FOR. A detector
    that never fires is indistinguishable from a clean codebase — working rule
    #11's lesson applied to a scanner, and the same reason the publication audit
    validated gitleaks against a canary before believing its zero."""
    def flagged(source: str) -> bool:
        fn = ast.parse(source).body[0]
        environmental = _environmental_names(fn)
        guarded = _guarded_names(fn)
        return any(names & environmental and not (names & environmental & guarded)
                    for _, _, names in _universals(fn))

    bad = ("def test_x():\n"
            "    records = open('x').readlines()\n"
            "    assert all(r.ok for r in records)\n")
    good = ("def test_x():\n"
             "    records = open('x').readlines()\n"
             "    assert records\n"
             "    assert all(r.ok for r in records)\n")
    literal = ("def test_x():\n"
                "    for tier in ('a', 'b'):\n"
                "        assert tier\n")

    magnitude = ("def test_x():\n"
                  "    f = open('x')\n"
                  "    assert f.stat().st_size < 2000000\n")

    assert flagged(bad), "the scan does not fire on the shape it exists for"
    assert not flagged(magnitude), (
        "a size comparison is a magnitude, not a universal over a collection — "
        "flagging it is how a scan stops being read")
    assert not flagged(good), "one guard line must be enough to satisfy it"
    assert not flagged(literal), "a literal collection is not a risk"


# ===================================== 3 · the gap Method C found, closed

def test_installed_version_distinguishes_installed_from_not():
    """⚠ FOUND BY THE SWEEP, NOT BY READING. Forcing
    `installer.place.installed_version()` to return a real version changed the
    outcome of NO test — so nothing in the suite told "installed" from "not",
    and the two branches it drives (the reinstall notice at install step 6, and
    the DRIFT warning in `--status`) were unasserted.
    """
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        prefix = Path(tmp)
        assert place.installed_version(prefix) is None, "nothing is installed yet"

        target = prefix / "v-one"
        target.mkdir()
        (target / "INSTALL.json").write_text(
            json.dumps({"guard_version": "v-one"}), encoding="utf-8")
        (prefix / "current").symlink_to(target)
        assert place.installed_version(prefix) == "v-one"

        (target / "INSTALL.json").write_text("{not json", encoding="utf-8")
        assert place.installed_version(prefix) is None, (
            "an unreadable manifest must not be reported as a version")


def test_the_reinstall_notice_names_both_versions():
    """The message the above value drives. It says what is being replaced, what
    replaces it, and that grants are revoked — a reinstall is the moment a
    human's one-shot approval stops meaning what they approved."""
    from installer import messages

    text = messages.already_installed("v-old", "v-new")
    assert "v-old" in text and "v-new" in text
    assert "REVOKED" in text
