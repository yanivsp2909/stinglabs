"""STING_ROOTS accepted a directory that does not exist, and nothing said so.

A real Windows install declared `C:\\Users\\alice\\Projects`. It was not
there. `probes.project_roots` keeps only entries that `is_dir()`, so the list
resolved to nothing, the boundary fell back to the single git repo containing
cwd, and that is the 74-of-89 secret-rule denial condition. Observe mode meant
nothing was blocked, so the entire failure was invisible except for one
preflight line — a line that runs after the install and scrolls past.

⚠ THE PARTIAL CASE IS THE ONE WITH NO WITNESS AT ALL, and it is why this checks
per entry rather than answering yes/no. `project_roots` attaches a note ONLY
when nothing survives:

    all four exist          -> (roots, None)
    NONE exist              -> (cwd,   "STING_ROOTS names no existing …")
    three of four exist     -> (roots, None)     <- the boundary silently
                                                    narrowed, and nothing,
                                                    anywhere, ever says so

The installer is the only place that holds the list the human TYPED rather than
the list that survived, so it is the only place that can see the difference.

⚠ AND IT REPORTS RATHER THAN REFUSES. A missing root is a typo, a repo not
cloned yet, or a drive not mounted — none of them an attack. An installer that
dies on one leaves the machine with NO guard rather than a guard with a narrow
boundary, which is strictly worse. The same rule the installer already follows
for a network home and a Windows interpreter.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

import install
from core import probes

ROOT = Path(__file__).resolve().parent.parent


def joined(*paths) -> str:
    """The platform's own separator — never a hand-written ':'."""
    return probes.join_roots([str(p) for p in paths])


# ═══════════════════════════════════════════════ 4.1 · validate each entry ══

def test_every_entry_is_checked_not_just_the_list(tmp_path):
    """⚠ THE PARTIAL CASE. Three of four is the state with no other witness."""
    good, other = tmp_path / "a", tmp_path / "b"
    good.mkdir()
    other.mkdir()
    gone = tmp_path / "not-cloned-yet"

    rows = install.check_roots(joined(good, gone, other))

    assert [r["path"] for r in rows] == [str(good), str(gone), str(other)]
    assert [r["exists"] for r in rows] == [True, False, True]


def test_the_measured_failure_is_reported(tmp_path, capsys):
    """The exact shape from the first native Windows install: a declared root
    that is simply not there."""
    install.report_roots(str(tmp_path / "Projects"))
    out = capsys.readouterr().out

    assert "MISSING" in out
    assert "Projects" in out
    assert "74 of" in out, "the cost of the fallback is not stated"


def test_it_uses_the_engines_splitter_and_not_a_second_copy(tmp_path):
    """⚠ A CHECK THAT RESTATES A PARSER IS A SECOND COPY OF THAT PARSER. That
    is how preflight came to fail a correct Windows value: it asserted a ':'
    split that had stopped being true. This calls `probes.split_roots`, so it
    cannot drift from what actually reads the value."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    body = source.split("def check_roots(", 1)[1].split("\ndef ", 1)[0]
    assert "split_roots" in body
    assert 'split(":")' not in body and "split(':')" not in body

    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert len(install.check_roots(joined(a, b))) == 2


def test_an_empty_or_unset_boundary_produces_no_rows_and_no_noise(capsys):
    """STING_ROOTS declined is a supported state — the installer refuses to
    infer a boundary. It must not be reported as a missing directory."""
    assert install.check_roots("") == []
    assert install.report_roots("") == []
    assert capsys.readouterr().out == ""


# ═══════════════════════════════════ 4.2 · REPORT, DO NOT REFUSE — and where ══

def test_a_missing_root_never_refuses_the_install(tmp_path, capsys):
    """⚠ TASK 4.2. It returns rows; it does not raise, exit, or return a code
    anybody could read as failure."""
    rows = install.report_roots(str(tmp_path / "gone"))

    assert rows and rows[0]["exists"] is False
    out = capsys.readouterr().out
    assert "the install continues" in out
    assert "Nothing is blocked by this" in out


def test_the_remediation_is_a_command_the_person_can_run(tmp_path, capsys):
    install.report_roots(str(tmp_path / "gone"))
    out = capsys.readouterr().out
    assert "install.py --roots" in out


def test_it_is_restated_in_the_block_a_developer_actually_reads():
    """⚠ SAYING IT ONCE, 600 LINES EARLIER, IS THE SAME AS NOT SAYING IT.

    Section 1 prints before agent detection, before the tree is placed, before
    the hook configs, before the shipper and before a full preflight run. The
    `Done` block is what a developer looks at. The installer already restates
    partial coverage and the environment warnings there for exactly this
    reason; the trust boundary is at least as consequential as either.
    """
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    done = source.split('head("Done")', 1)[1].split("def do_status", 1)[0]

    assert "TRUST BOUNDARY" in done
    assert "missing_roots" in done
    assert "install.py --roots" in done


def test_a_whole_install_prints_it_in_the_done_block(tmp_path, monkeypatch,
                                                      capsys):
    """⚠ THE SOURCE CHECK ABOVE IS NOT ENOUGH — it proves the lines exist, not
    that they are reached. `Done` sits behind a preflight run that returns early
    on failure, so this drives the real `do_install` end to end in an isolated
    home with preflight stubbed to pass, and reads the output.
    """
    import argparse
    import subprocess as sp

    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("STING_INSTALL_ROOT", str(home / "prefix"))
    monkeypatch.setattr(install, "ENV_FILE", home / ".sting" / "env")
    monkeypatch.setattr(install.recorded, "ENV_FILE", home / ".sting" / "env")
    # ⚠ THE AGENT IS STUBBED INTO THE TEMP HOME, AND THAT IS A SAFETY
    # REQUIREMENT, NOT A CONVENIENCE. `detect` reads the real `Path.home()`,
    # so an unstubbed run of `do_install` writes a hook entry into the
    # DEVELOPER'S OWN ~/.claude/settings.json. A test may not reconfigure the
    # machine it runs on.
    config = home / ".claude" / "settings.json"
    monkeypatch.setattr(install, "choose_agents", lambda requested: [
        {"agent": "claude-code", "evidence": "stubbed",
         "config": str(config), "user_level": True}])
    # ⚠ ONLY PREFLIGHT IS STUBBED, AND THE NARROWNESS MATTERS. `install` and
    # `installer.detect` share one `subprocess` module object, so a blanket
    # replacement also silences `git config` and `hostname` — which crashed
    # this test on a `None` stdout before it was narrowed. Everything that is
    # not preflight runs for real.
    real_run = sp.run

    def only_preflight(cmd, *a, **k):
        if any("preflight" in str(part) for part in (cmd or [])):
            return sp.CompletedProcess(cmd, 0)
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(install.subprocess, "run", only_preflight)

    good = tmp_path / "declared-and-present"
    good.mkdir()
    gone = tmp_path / "declared-and-absent"

    # ⚠ THROUGH `main`, SO THE REAL PARSER BUILDS THE ARGUMENTS. A hand-rolled
    # Namespace is a second copy of the CLI that drifts from it — it already
    # did, twice, while this test was being written.
    monkeypatch.setattr(install.console, "make_output_safe", lambda: None)
    code = install.main([
        "--yes", "--no-collector", "--no-supervisor",
        "--agent", "claude-code", "--scratch", "",
        "--roots", joined(good, gone)])
    out = capsys.readouterr().out

    assert code == 0, out
    done = out.split("Done", 1)[-1]
    assert "TRUST BOUNDARY" in done, (
        f"the Done block did not restate the missing root:\n{done}")
    assert str(gone) in done
    assert str(good) not in done, "a root that exists is not a warning"


def test_both_reports_name_the_same_paths(tmp_path, capsys):
    """The early report and the restatement must not be able to disagree —
    the second reads the rows the first produced, it does not recompute."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    done = source.split('head("Done")', 1)[1].split("def do_status", 1)[0]
    assert "root_rows" in done, (
        "the Done block recomputes instead of reusing the checked rows")
    assert "check_roots(" not in done


# ══════════════════════════════════════════ the hint, which does not rewrite ══

def test_a_uri_root_is_diagnosed_and_the_value_is_left_alone(tmp_path):
    """⚠ NOT A SECOND NORMALISER. `adapters/_common._from_uri` is CALLED, not
    restated, and nothing here rewrites what the operator declared. Saying "you
    meant this" is help; writing a boundary they did not declare is the
    installer choosing what they trust, which this project does not do."""
    hint = install._root_hint("/C:/Users/alice/project")
    assert "URI" in hint and "C:/Users/alice/project" in hint

    real = tmp_path / "workspace"
    real.mkdir()
    hint = install._root_hint("file://" + str(real))
    assert "The native path exists" in hint and str(real) in hint

    # and a genuine path is not "diagnosed" at all
    assert install._root_hint(str(tmp_path)) == ""

    # THE VALUE IS UNCHANGED — `path` is what the operator typed, verbatim.
    # (Spelled without a `file://` scheme here because on POSIX `os.pathsep` is
    # `:`, so a URI is legitimately shattered by `split_roots` before this ever
    # sees it. On Windows the separator is `;` and the URI arrives whole, which
    # is the platform the hint is for.)
    typed = str(tmp_path / "declared-but-absent")
    rows = install.check_roots(typed)
    assert rows[0]["path"] == typed and rows[0]["exists"] is False


def test_the_hint_calls_the_one_normaliser_rather_than_reimplementing_it():
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    body = source.split("def _root_hint(", 1)[1].split("\ndef ", 1)[0]
    assert "_common._from_uri" in body
    assert "startswith(\"file://" not in body, "a second normaliser"


# ═════════════════════════════════════════ what the runtime does downstream ══

def test_the_runtime_really_does_drop_a_missing_entry_silently(tmp_path,
                                                                monkeypatch):
    """⚠ THE PREMISE, PROVED RATHER THAN ASSERTED. If `project_roots` did note
    a partially-missing list, this whole check would be redundant. It does not:
    the note is attached only when NOTHING survives."""
    good = tmp_path / "a"
    good.mkdir()
    gone = tmp_path / "gone"
    monkeypatch.setenv("STING_ROOTS", joined(good, gone))

    roots, note = probes.RealWorld().project_roots(str(tmp_path))

    assert str(good.resolve()) in roots
    assert str(gone) not in roots
    assert note is None, (
        "project_roots grew a note for the partial case — if that is "
        "deliberate, this test and the installer check should be reconsidered "
        "together rather than one of them being deleted")
