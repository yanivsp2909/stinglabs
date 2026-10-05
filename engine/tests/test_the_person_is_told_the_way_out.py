"""The person is told the way out once, at install, not the agent at a block.

⚠ docs/108 §3: an agent handed `python3 …/tools/allow_once.py` could arm its
own grant, so no refusal the MODEL reads names it. Claude Code and Cursor show
it to the person in a field the model does not read; Codex, Copilot and
Antigravity have no such field (docs/108 §1). There, the person has to have
been told before, so the install's closing block says it, and the README does.

Fakes only (tests/install_harness.py): a temp home, --no-supervisor, the fake
launchctl and systemctl.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from install_harness import SAFE, home, no_real_supervisor   # noqa: E402,F401

import install                                                 # noqa: E402
from installer import messages                                 # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def test_the_way_out_names_the_installed_command_and_the_policy_line():
    lines = messages.way_out(Path("/opt/sting/v1/tools/allow_once.py"))
    said = "\n".join(lines)
    assert "python3 /opt/sting/v1/tools/allow_once.py" in said
    assert '{"rules": {"<rule id>": "ask"}}' in said
    assert "your own terminal" in said


def test_the_install_closes_with_the_way_out(home, capsys):
    assert install.main([*SAFE]) == 0
    out = capsys.readouterr().out
    done = out.split("Done", 1)[1]
    assert "allow_once.py" in done and "policy.json" in done
    assert "your own terminal" in done


def test_the_readme_says_it_too():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "tools/allow_once.py" in readme and "policy.json" in readme
    assert "your own terminal" in readme


def test_the_readme_mode_row_says_an_install_enforces():
    """⚠ REVIEW: the Mode row said "observe … Start in observe", and named the
    flag; an install has defaulted to enforce since `recorded.resolve`'s
    fallback became "0". The row an agent may read names no way to observe."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    row = next(line for line in readme.splitlines() if line.startswith("| **Mode**"))
    assert "enforce" in row.lower(), row
    assert "--observe" not in row and "start in observe" not in row.lower(), row
