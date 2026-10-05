"""The first command a stranger runs, on the interpreter a stranger has.

⚠ FOUND BY INSTALLING FROM THE ARCHIVE INTO A CLEAN HOME, NOT BY A TEST — and
2,563 tests were green at the time. `install.py` had `check_python()`, which
prints a message naming the exact fix, and NOTHING COULD EVER REACH IT: it is
called from inside `do_install()`, while `from core import wire` at module scope
had already imported `core.types`, which does `from enum import StrEnum` and
raises on anything below 3.11.

So the first command in the README answered a stranger with:

    Traceback (most recent call last):
      File ".../install.py", line 23, in <module>
        from core import wire
      ...
      File ".../core/types.py", line 29, in <module>
        from enum import StrEnum
    ImportError: cannot import name 'StrEnum' from 'enum'
      (/Applications/Xcode.app/.../python3.9/enum.py)

⚠ AND THIS IS THE DEFAULT ON macOS, not an edge case. `/usr/bin/python3` is 3.9
(Xcode's), and it is what `python3` resolves to unless the person has already
installed a newer one AND it precedes on PATH. The message that should have
printed even PREDICTS the failure — *"it fails at IMPORT"* — and it was written
below the import that fails.

⚠ WHY NO TEST COULD SEE IT. Every test in this suite runs under the interpreter
running the suite, which is 3.11+ by necessity — the engine cannot import
otherwise. The guard is therefore invisible to the whole suite by construction.
The only way to test it is to run the entry points as SUBPROCESSES under a
genuinely older interpreter, which is what this file does. There is one on this
machine and on every macOS machine; where there is not, this SKIPS and says so.

THE RULE THIS GENERALISES: a version floor must sit above the first project
import, in every file a person can invoke directly. `hook_entry.py` has had the
correct shape all along and explains why; nobody checked the second and third
entry points against it.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Entry points a PERSON can invoke, and the command that invokes each. All three
# are printed to the user somewhere: install.py by the README, sting_hook.py and
# hook_entry.py by the hook configs, `-m shipper.run` by `install.py
# --no-supervisor`.
ENTRY_POINTS = [
    ("install.py", ["install.py"]),
    ("hook_entry.py", ["hook_entry.py"]),
    ("sting_hook.py", ["sting_hook.py"]),
    ("shipper.run", ["-m", "shipper.run"]),
]


def _old_python() -> str | None:
    """An interpreter genuinely older than the floor, or None.

    ⚠ NOT SIMULATED. A fake `enum` module without StrEnum, or a monkeypatched
    `sys.version_info`, would test the harness's idea of an old interpreter
    rather than an old interpreter — and the defect was precisely that the real
    failure happened somewhere nobody had modelled (at import, in a transitive
    dependency, before any of our code ran).
    """
    for candidate in ("/usr/bin/python3", "python3.9", "python3.10"):
        try:
            out = subprocess.run([candidate, "-c",
                                  "import sys; print(sys.version_info[:2])"],
                                 capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode != 0:
            continue
        major, minor = re.findall(r"\d+", out.stdout)[:2]
        if (int(major), int(minor)) < (3, 11):
            return candidate
    return None


OLD = _old_python()
SKIP_REASON = (
    "NO INTERPRETER BELOW 3.11 ON THIS MACHINE, so the floor that stops a "
    "stranger seeing an ImportError traceback is NOT EXERCISED here. This is "
    "the check that no other test in the suite can perform — every one of them "
    "runs on the 3.11+ interpreter running pytest, which is why the defect "
    "survived 2,563 green tests. The static check below still runs."
)


# ═══════════════════════════════════════ the real thing, on a real 3.9 ══

@pytest.mark.skipif(OLD is None, reason=SKIP_REASON)
@pytest.mark.parametrize("name,argv", ENTRY_POINTS, ids=[n for n, _ in ENTRY_POINTS])
def test_an_old_interpreter_gets_a_sentence_not_a_traceback(name, argv):
    done = subprocess.run([OLD, *argv], cwd=str(ROOT), input="",
                          capture_output=True, text=True, timeout=60)
    output = done.stdout + done.stderr

    assert "Traceback" not in output, (
        f"{name} answers an old interpreter with a traceback:\n{output}")
    assert "StrEnum" in output and "3.11" in output, (
        f"{name} did not say what is wrong or what version is needed:\n{output}")
    assert done.returncode != 0, (
        f"{name} exited 0 on an interpreter it cannot run on — a caller cannot "
        f"tell that from success")


@pytest.mark.skipif(OLD is None, reason=SKIP_REASON)
def test_the_refusal_names_the_interpreter_it_is_running_on():
    """⚠ THE PATH IS THE WHOLE MESSAGE. "Install a newer Python" is useless to
    somebody who HAS one — their problem is that a different one is first on
    PATH, and only naming the offending binary tells them that."""
    done = subprocess.run([OLD, "install.py"], cwd=str(ROOT), input="",
                          capture_output=True, text=True, timeout=60)

    assert OLD in (done.stdout + done.stderr) or "python3" in done.stderr


# ═══════════════════════════════ and the structure, checkable anywhere ══

# ⚠ `sting_hook.py` IS DELIBERATELY NOT IN THIS LIST, AND THE REASON IS THE
# OBSERVE GUARANTEE. It owns no floor: it catches the `SystemExit` that
# `hook_entry`'s floor raises AT IMPORT, inside `main()`'s try, and reports
# "sting: refused to start (…)" without a non-zero exit that would BLOCK the
# developer's tool call. Its own docstring says so. Adding a floor here would
# turn a report into a block on exactly the machine that cannot decide anything
# — the opposite of what observe mode promises. The behavioural test above
# still covers it, which is the point: the PROPERTY is "a sentence, not a
# traceback", and there is more than one right way to hold it.
OWNS_A_FLOOR = [(n, a) for n, a in ENTRY_POINTS if n != "sting_hook.py"]


@pytest.mark.parametrize("name,argv", OWNS_A_FLOOR, ids=[n for n, _ in OWNS_A_FLOOR])
def test_the_floor_sits_above_the_first_project_import(name, argv):
    """⚠ THE STRUCTURAL FORM, so the property holds on a machine with no old
    interpreter. A guard BELOW the first `from core …` is not a guard: the
    import raises first, which is exactly what happened."""
    path = ROOT / (argv[-1].replace(".", "/") + ".py" if argv[0] == "-m" else argv[-1])
    source = path.read_text(encoding="utf-8")

    floor = source.find("sys.version_info < (3, 11)")
    assert floor != -1, f"{name} has no version floor at all"

    first_import = min(
        (i for i in (source.find("\nfrom core "), source.find("\nfrom adapters "),
                     source.find("\nfrom shipper "), source.find("\nfrom installer "))
         if i != -1),
        default=-1)
    assert first_import != -1, f"{name} imports no project module — check this test"
    assert floor < first_import, (
        f"{name}'s version floor is BELOW its first project import, so the "
        f"import raises before the floor can speak. That is the defect this "
        f"file exists for.")


def test_the_floor_uses_no_syntax_newer_than_the_floor():
    """⚠ A GUARD WRITTEN IN 3.11 SYNTAX CANNOT RUN ON 3.9. It would raise a
    SyntaxError before the first line executes — a worse traceback than the one
    it replaced, and one no amount of testing on 3.12 would ever show."""
    for name, argv in OWNS_A_FLOOR:
        path = ROOT / (argv[-1].replace(".", "/") + ".py"
                       if argv[0] == "-m" else argv[-1])
        head = path.read_text(encoding="utf-8").split("sys.version_info < (3, 11)")[0]
        # the whole prologue must parse as 3.9 would read it: no match, no
        # `X | Y` outside `from __future__ import annotations`, no walrus in it.
        assert "match " not in head
        assert ":=" not in head


def test_check_python_still_exists_and_agrees_with_the_floor():
    """The floor did not REPLACE `check_python`; both state one rule. It still
    covers the case where a caller imported this module rather than running it,
    and `messages.wrong_python()` is the long form a person can act on."""
    import install
    from installer import messages

    assert messages.MIN_PYTHON == (3, 11)
    assert hasattr(install, "check_python")
    assert "3.11" in messages.wrong_python()
