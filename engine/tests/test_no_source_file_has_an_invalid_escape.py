"""No Python file in the repo carries an invalid escape sequence.

ITEM 8. `core/known_formats.py`'s docstring wrote `AKIA\\QZXW…` with a single
backslash: `\\Q` is not an escape, so Python kept both characters and printed a
SyntaxWarning on every import — and a future Python makes it a SyntaxError, which
would stop the engine from importing at all. The fix doubles the backslash, so
the docstring's TEXT is unchanged. This test compiles every file the repo ships
or tests with SyntaxWarning turned into a failure, so the next one is caught.
"""
from __future__ import annotations

import warnings
from pathlib import Path

from core import known_formats

ROOT = Path(__file__).resolve().parent.parent
SKIP = {"scratchpad", ".git", "node_modules", "graphify-out"}


def test_every_python_file_compiles_without_a_syntax_warning():
    problems = []
    for path in sorted(ROOT.rglob("*.py")):
        if SKIP & set(path.relative_to(ROOT).parts):
            continue
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        problems += [f"{path.relative_to(ROOT)}:{w.lineno} {w.message}"
                     for w in caught if issubclass(w.category, SyntaxWarning)]
    assert not problems, problems


def test_the_known_formats_docstring_still_reads_the_same():
    """The shell-glue example keeps its literal backslash: `AKIA\\QZXW…`."""
    assert "`AKIA\\QZXW…` are one argument to the shell" in known_formats.__doc__
