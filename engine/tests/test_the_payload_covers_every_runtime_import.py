"""A list cannot notice its own omission.

⚠ `envfile.py` WAS MISSING FROM `place.PAYLOAD` FOR ITS ENTIRE LIFE, and every
install from the release archive produced a hook that could not run:

    [FAIL] entry point runnable   exit=1
           ModuleNotFoundError: No module named 'envfile'
    [FAIL] synthetic action through the hook   ModuleNotFoundError
    [FAIL] credential exfiltration is denied — the hook ran but recorded no
           decision — the payload never reached the engine

It arrived with the Windows transport as the thing that replaced the env prefix
in `hooks.json`; both entry points import it; nobody added it to the list.

⚠ WHY EVERY EXISTING GUARD MISSED IT, AND EACH FOR A DIFFERENT REASON:

  * `place()`'s missing-payload REFUSAL checks that everything NAMED in PAYLOAD
    exists. The failure was that the name was absent. **A list cannot notice
    its own omission.**
  * `make_release.sh`'s post-archive check does the same, from the same list.
  * `tests/test_the_artifact_is_installable.py` asserts every PAYLOAD item is
    placed — again, from the same list.
  * Every other test runs from the CHECKOUT, where `sys.path` already holds the
    repo root, so `import envfile` resolves to the file beside the entry point
    in the SOURCE tree and never touches what was installed.

So this file does the one thing none of those do: it derives the requirement
from the CODE rather than from the list, and it checks resolution against a
tree that was actually placed.

⚠ THIS IS THE THIRD TIME PAYLOAD DRIFT HAS SHIPPED. `daemon/` and
`sting_hook.py` went missing from `make_release.sh` (fixed by deriving the list
from `place.PAYLOAD`); `sting_hook.py` went missing from an archive whose
builder had drifted (fixed by the refusal); now `envfile.py` went missing from
the list itself. Each fix closed the door the previous one came through. This
one closes the door where the list is authored.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from installer import place

ROOT = Path(__file__).resolve().parent.parent

# The files a hook config or a documented command actually invokes.
ENTRY_POINTS = ("hook_entry.py", "sting_hook.py", "shipper/run.py")

# Modules that are the interpreter's, not ours. Anything not here and not a
# known third party must come out of the placed tree.
STDLIB = set(sys.stdlib_module_names)


def _imported_names(path: Path) -> set[str]:
    """Every TOP-LEVEL module name this file imports, at any depth in the file.

    ⚠ FUNCTION-LOCAL IMPORTS COUNT, AND THAT IS THE WHOLE POINT. Both
    `import envfile` statements are inside `main()` — deliberately, to keep them
    off the cold-start path — so a scan that only read module-level imports
    would have missed exactly the one that broke. `ast.walk` reaches them.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def _project_imports(path: Path) -> set[str]:
    """The imports that must come from the installed tree."""
    return {name for name in _imported_names(path)
            if name not in STDLIB and (ROOT / name).exists()
            or name not in STDLIB and (ROOT / f"{name}.py").exists()}


def _payload_provides() -> set[str]:
    """The top-level importable names `place.PAYLOAD` puts in the tree."""
    provided = set()
    for item in place.PAYLOAD:
        head = item.split("/")[0]
        provided.add(head[:-3] if head.endswith(".py") else head)
    return provided


# ═══════════════════════════════════════════ derived from the CODE ══

@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_every_module_an_entry_point_imports_is_in_the_payload(entry):
    """⚠ THE CHECK THAT WOULD HAVE CAUGHT IT, and it reads the imports rather
    than the list."""
    needed = _project_imports(ROOT / entry)
    missing = sorted(needed - _payload_provides())

    assert not missing, (
        f"{entry} imports {missing}, which place.PAYLOAD does not ship. An "
        f"install from an archive would write a hook config pointing at an "
        f"entry point whose first act is an import that is not there — "
        f"ModuleNotFoundError on every tool call, and in observe mode that is "
        f"a guard that silently decides nothing.")


def test_envfile_specifically_because_it_is_the_one_that_shipped_broken():
    """Named rather than left to the sweep above. A regression here has a
    known, measured cost and deserves to fail by name."""
    assert "envfile.py" in place.PAYLOAD
    assert "envfile" in _project_imports(ROOT / "sting_hook.py")
    assert "envfile" in _project_imports(ROOT / "hook_entry.py")


def test_the_scan_sees_imports_inside_functions():
    """⚠ THE CONTROL. Both `import envfile` statements are function-local, so a
    module-level-only scan would pass while proving nothing. If this ever fails,
    the sweep above has gone blind in exactly the way that let the defect
    through."""
    source = (ROOT / "sting_hook.py").read_text(encoding="utf-8")
    module_level = {
        line.split()[1].split(".")[0]
        for line in source.splitlines()
        if line.startswith("import ") or line.startswith("from ")}
    assert "envfile" not in module_level, (
        "envfile is now a module-level import — this control no longer proves "
        "the scan reaches into functions; point it at another one")
    assert "envfile" in _imported_names(ROOT / "sting_hook.py")


# ═════════════════════════════ and against a tree that was really placed ══

def test_a_placed_tree_can_actually_run_its_own_entry_point(tmp_path):
    """⚠ THE BEHAVIOURAL FORM, AND THE ONLY ONE THAT CANNOT BE FOOLED BY A
    LIST. Runs the placed `sting_hook.py` with the checkout removed from the
    path, so an import that resolves only in the source tree fails here.

    That is precisely the asymmetry that hid this: from a checkout, `sys.path`
    holds the repo root and `import envfile` finds the source file, so the
    installed tree is never asked whether it is complete.
    """
    placed = place.place(prefix=tmp_path / "prefix", source=ROOT,
                          session_root=tmp_path / "sessions")
    entry = placed["current"] / "sting_hook.py"
    assert entry.is_file()

    payload = ('{"session_id":"placed-1","cwd":"/tmp","tool_name":"Bash",'
               '"tool_input":{"command":"echo hi"}}')
    # ⚠ NO DAEMON, AND THIS TEST OF ALL TESTS. Without it the run starts a
    # resident daemon from a pytest tmp directory that pytest then deletes —
    # the exact defect this pass found in preflight, reintroduced by the test
    # written about it. It also keeps the subject honest: what is being checked
    # is that the PLACED TREE can import its own modules, which is an
    # in-process question.
    env = {"HOME": str(tmp_path / "home"),
           "PATH": "/usr/bin:/bin",
           "STING_SESSION_ROOT": str(tmp_path / "sessions"),
           "STING_NO_DAEMON": "1",
           "STING_OBSERVE": "1"}

    done = subprocess.run([sys.executable, str(entry), "--agent", "claude-code"],
                          input=payload, capture_output=True, text=True,
                          env=env, cwd=str(tmp_path), timeout=90)

    assert "ModuleNotFoundError" not in done.stderr, (
        f"the PLACED tree cannot import its own modules:\n{done.stderr}")
    assert "Traceback" not in done.stderr, done.stderr
    logs = list((tmp_path / "sessions").glob("*.jsonl"))
    assert logs, (
        f"the placed hook recorded nothing — it ran and decided nothing, which "
        f"in observe mode is a guard that is silently not there.\n{done.stderr}")


def test_the_release_archive_carries_what_the_entry_points_import(tmp_path):
    """One level further out: the ARCHIVE, not just `place()`. `git archive`
    skips a missing path silently, and that is how `daemon/` shipped absent."""
    import tarfile

    staged = tmp_path / "stage"
    staged.mkdir()
    # Build the same file set make_release.sh does, from the working tree, so
    # this does not need a tag to exist.
    for item in place.PAYLOAD:
        source = ROOT / item
        target = staged / item
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            import shutil
            shutil.copytree(source, target,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            import shutil
            shutil.copy2(source, target)

    for entry in ("hook_entry.py", "sting_hook.py"):
        for name in _project_imports(ROOT / entry):
            assert (staged / name).exists() or (staged / f"{name}.py").exists(), (
                f"the archive would not contain {name!r}, which {entry} imports")


# ═══════════════════════════════════════════════════════════════════════════
# ⚠ THE FOURTH TIME, AND WHY THE CHECKS ABOVE MISSED IT (G2, release audit)
#
# `tools/preflight.py` SHIPS. Its supervisor check did `from installer import
# supervisor`, and `installer/*.py` did NOT ship — PAYLOAD copied only
# `installer/cursor_bridge.ps1`. On every real install the one diagnostic that
# could catch a dead supervisor degraded to "could not be determined:
# ImportError" and preflight exited 0. Two gaps in the checks above let it by:
#
#   scope        `test_every_module_an_entry_point_imports_is_in_the_payload`
#                scans the ENTRY POINTS. tools/*.py — preflight, grade_engine,
#                redact_logs, retention, identity_census — were never read.
#   granularity  `_payload_provides()` yields the TOP-LEVEL name `installer`
#                from the entry `installer/cursor_bridge.ps1`, so `installer`
#                counted as provided and `from installer import supervisor`
#                would have passed even if scanned. A directory with no
#                `__init__.py` is a namespace package: it exists and can define
#                NO names. That is what the ImportError said — "cannot import
#                name 'supervisor' from 'installer' (unknown location)".
#
# So this scans EVERY .py in a tree `place()` actually produced, and resolves
# each project import at the submodule/name level against THAT tree.
#
# ⚠ IT IS A RATCHET. The scan finds more than G2. Those are enumerated in
# KNOWN and the assertion is equality: a new omission fails; a fixed one must
# be deleted here. The list only shrinks. Both directions asserted (rule 13).
#
# ⚠ AND IT MUST NEVER IMPORT THE PLACED TREE IN-PROCESS. The checkout is on
# sys.path and `installer/` is a namespace package, so Python MERGES the placed
# installer/ with the checkout's and the missing name is found anyway. Measured
# while writing this: `python -c` from the checkout found `supervisor` through
# the merge and printed nothing. Static resolution against the placed files
# is the only honest question to ask from inside pytest.
# ═══════════════════════════════════════════════════════════════════════════

KNOWN_OMISSIONS = frozenset({
    # (placed file, imported module, imported name). Same class as G2. Delete
    # an entry when its import is fixed; ADD one only as a decision written
    # down here, because every entry is a shipped tool that dies on install.
    #
    # ⚠ EMPTY SINCE THE PAYLOAD PASS (docs/78). The four that sat here —
    # redact_logs and identity_census -> installer.detect, retention ->
    # installer.recorded, grade_engine -> runner.replay — collapsed to three
    # PAYLOAD files, and this ratchet's "no longer occurs" arm is what proved
    # each of them resolved in a placed tree before its entry was deleted.
})


@pytest.fixture
def placed(tmp_path, monkeypatch):
    """A tree `place()` actually produced — what a stranger's install holds."""
    from core import allow_once
    prefix = tmp_path / "share" / "sting"
    sessions = tmp_path / "state"
    sessions.mkdir(parents=True)
    monkeypatch.setenv("STING_INSTALL_ROOT", str(prefix))
    monkeypatch.setenv("STING_SESSION_ROOT", str(sessions))
    allow_once._install_manifest_version.cache_clear()
    place.place(prefix=prefix, session_root=sessions)
    return (prefix / "current").resolve()


def _is_ours(top: str) -> bool:
    """A top-level import name that means THIS repository, not stdlib or pip."""
    return (ROOT / top).is_dir() or (ROOT / f"{top}.py").is_file()


def _resolves(tree: Path, module: str, name: str | None) -> bool:
    """Would `import module` / `from module import name` find a FILE in `tree`?

    ⚠ FILES, NOT NAMES — two blind spots, both accepted, both stated. When the
    module resolves to a package WITH `__init__.py`, or to a `.py` file, the
    imported `name` is assumed to be defined there; this never opens the file
    to check. What it DOES refuse is the namespace-package case — a directory
    with no `__init__.py` can define no names — which is exactly G2's shape and
    exactly what "cannot import name 'supervisor' from 'installer' (unknown
    location)" means. A name missing from a real package would need the
    package's own tests; this guard is for files that never got copied.
    """
    parts, here = module.split("."), tree
    for i, part in enumerate(parts):
        as_dir, as_file = here / part, here / f"{part}.py"
        if as_dir.is_dir():
            here = as_dir
            continue
        return i == len(parts) - 1 and as_file.is_file()   # a module defines its names
    if name is None or (here / "__init__.py").is_file():
        return True                     # a real package may define the name
    return (here / f"{name}.py").is_file() or (here / name).is_dir()


def _placed_imports(tree: Path) -> Iterator[tuple[str, str, str | None]]:
    """Every (placed file, module, name) a placed .py imports from this repo.
    Function-local and try/except imports included — that shape IS the
    silent degrade this guard exists for."""
    seen = 0
    for py in sorted(tree.rglob("*.py")):
        seen += 1
        node = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        rel = str(py.relative_to(tree))
        for n in ast.walk(node):
            if isinstance(n, ast.Import):
                for alias in n.names:
                    if _is_ours(alias.name.split(".")[0]):
                        yield rel, alias.name, None
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                if _is_ours(n.module.split(".")[0]):
                    for alias in n.names:
                        yield rel, n.module, alias.name
    assert seen > 20, f"only {seen} .py files in the placed tree — nothing scanned"


def test_every_placed_module_imports_only_what_was_placed(placed):
    # ONE walk, materialised: the generator's trailing sanity assert runs when
    # it is exhausted, and a second `any()` over a fresh generator would
    # short-circuit before ever reaching it — re-parsing the whole tree for a
    # fact the first pass already established.
    imports = list(_placed_imports(placed))
    assert imports, "no project imports seen"
    found = {(rel, mod, name) for rel, mod, name in imports
             if not _resolves(placed, mod, name)}

    new = found - KNOWN_OMISSIONS
    assert not new, (
        "a placed module reaches for something PAYLOAD does not place — on a "
        "real install this import fails and whatever it guards degrades "
        "silently:\n  " + "\n  ".join(f"{f}: from {m} import {n}"
                                      for f, m, n in sorted(new)))
    fixed = KNOWN_OMISSIONS - found
    assert not fixed, (
        "these KNOWN omissions no longer occur — delete them from "
        "KNOWN_OMISSIONS so the ratchet only ever shrinks:\n  " +
        "\n  ".join(f"{f}: from {m} import {n}" for f, m, n in sorted(fixed)))


def test_the_placed_tree_resolver_is_not_vacuous(placed):
    """Arm the resolver: a placed name resolves, an unplaced one does not, and
    the namespace-package case — G2's exact shape — is refused."""
    assert _resolves(placed, "core", "engine")
    assert _resolves(placed, "core.engine", "decide")
    assert _resolves(placed, "hook_entry", None)
    assert _resolves(placed, "installer", "supervisor")        # G2: placed
    assert _resolves(placed, "installer", "recorded")          # the PAYLOAD pass: placed
    assert _resolves(placed, "installer.detect", "propose_identity")
    assert _resolves(placed, "runner", "replay")
    # ⚠ THE NEGATIVES MUST BE FILES THAT EXIST IN THE CHECKOUT AND ARE NOT
    # PLACED, or the refusal arm is never exercised. These three are.
    assert not _resolves(placed, "installer", "prepare")       # G2's shape: namespace dir, file not placed
    assert not _resolves(placed, "installer.enrol", "main")
    assert not _resolves(placed, "runner", "replay_live")      # a dir placed for ONE file keeps the rest out
    assert not _resolves(placed, "does_not_exist", None)
