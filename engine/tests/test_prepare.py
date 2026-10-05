"""The five checks, now inside install.py — and they FIX rather than report.

⚠ EVERY ONE EXISTS BECAUSE IT FAILED ON A REAL MACHINE. Three onboardings
produced, in order: a WSL command run in a Windows shell; npm answering 10.9.2
from the WINDOWS PATH while node was not found; a Linux npm whose PREFIX pointed
at Windows, so `npm install -g` installed a Windows package that wrote its config
to the Windows home; an agent sweep that missed Cursor; and a `--scratch` naming
a directory that did not exist, so preflight failed AFTER a clean install.

⚠ AND THE VERIFY-AFTER-FIX LOOP IS THE POINT. `npm install -g` exits 0 while
installing to the wrong operating system. A fix that trusted its own return code
would have declared that machine ready.
"""
from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from installer import prepare                                    # noqa: E402


# ══════════════════════════════════════════════ 1 · platform, and Windows

def test_native_windows_is_supported_and_says_it_is_unproven(monkeypatch):
    """⚠ THIS TEST HAS INVERTED TWICE, AND BOTH TIMES ON PURPOSE.

    First it asserted a refusal citing `fcntl` at module scope. Phase 0 moved
    that behind a seam, so it became a refusal citing the six sites that fail
    SILENTLY. Phase 3 fixed those and Phase 4 replaced the symlink, so the
    refusal has no remaining basis — and a refusal with no basis is exactly the
    stale advice this project keeps finding in the place a new user reads first.

    ⚠ IT MUST NOT BECOME SILENT, THOUGH. Supported and PROVEN are different
    words: no real coding agent has run a real session on Windows, so the check
    passes and says so.
    """
    monkeypatch.setattr(prepare.platform, "system", lambda: "Windows")
    result = prepare.check_platform()
    assert result.ok is True and result.fatal is False
    assert "NOT YET PROVEN" in result.detail
    text = "\n".join(result.lines)
    assert "NATIVE WINDOWS IS NEW" in text
    assert "POINTER FILE" in text, "the layout change must be stated to the user"
    assert "wsl --install" not in text, "WSL is not the Windows plan"


def test_fcntl_is_no_longer_imported_at_module_scope_anywhere_in_core():
    """⚠ THIS TEST USED TO ASSERT THE OPPOSITE, and it was right to: it said
    "if someone moves the import behind a seam, this test says the message
    needs rewriting". The seam landed, so it does.

    `core/locking.py` is the ONE place allowed to name fcntl, and it does so
    inside a platform branch. Anywhere else at module scope is an ImportError
    on Windows before a line of engine code runs.
    """
    import ast
    for path in sorted((ROOT / "core").glob("*.py")):
        if path.name == "locking.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        top = [a.name for n in tree.body if isinstance(n, ast.Import)
                for a in n.names]
        assert "fcntl" not in top, (
            f"core/{path.name} imports fcntl at module scope — the engine will "
            f"not start on Windows")


def test_only_core_locking_USES_fcntl():
    """One platform seam, not three.

    ⚠ PARSED, NOT GREPPED. The first version matched the characters `fcntl.` and
    flagged core/session.py for a DOCSTRING that explains why locking matters.
    A scanner whose false positive is the sentence describing the rule — the
    same shape this repo hit once already. The population is attribute
    accesses, not text.
    """
    import ast
    offenders = []
    for path in sorted((ROOT / "core").glob("*.py")):
        if path.name == "locking.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "fcntl"):
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"fcntl used outside the seam: {offenders}"


def test_an_unrecognised_platform_says_it_cannot_tell(monkeypatch):
    """⚠ THE STOP CONDITION. A bootstrapper that misdiagnoses is worse than one
    that says "I could not tell, here is what to check"."""
    monkeypatch.setattr(prepare.platform, "system", lambda: "Plan9")
    result = prepare.check_platform()
    assert result.fatal and "cannot tell" in "\n".join(result.lines)


# ═════════════════════════════════════════════════════════ 2 · python

def test_the_running_interpreter_is_the_check():
    """install.py IS Python, so if it runs at all a Python exists. What is left
    is whether it is new enough — and /usr/bin/python3 on macOS is 3.9.6."""
    assert prepare.check_python().ok is True
    assert prepare.MIN_PYTHON == (3, 11)


def test_too_old_points_at_a_newer_one_when_it_is_already_installed(monkeypatch):
    """A machine with 3.9 on PATH and 3.12 beside it does not need an install —
    it needs the other command, which is a different sentence."""
    monkeypatch.setattr(prepare.sys, "version_info", (3, 9, 6, "final", 0))
    monkeypatch.setattr(prepare, "_which", lambda n: "/usr/bin/python3.12"
                         if n == "python3.12" else "")
    result = prepare.check_python()
    assert result.ok is False and result.fatal is True
    assert any("re-run with it" in line for line in result.lines)


# ═══════════════════════════════════════════ 3 · node, npm, and the prefix

@pytest.mark.parametrize("path,windows", [
    ("/mnt/c/Program Files/nodejs/node.exe", True),
    ("/c/Windows/py.exe", True),
    ("/usr/bin/node", False),
    ("/opt/homebrew/bin/node", False),
])
def test_which_operating_system_answered(path, windows):
    assert prepare.is_windows_binary(path) is windows
    assert ("WINDOWS" in prepare.side_of(path)) is windows


def test_npm_answering_while_node_does_not_is_named_as_interop(monkeypatch):
    """⚠ CONFIRMED IN THE WILD, BEFORE ANY LINUX PACKAGE EXISTED:
        npm --version  -> 10.9.2   (from the WINDOWS PATH)
        node --version -> not found
    One of a pair through interop and the other absent, so the environment
    looked half-working and nothing named the cause."""
    monkeypatch.setattr(prepare, "_which",
                        lambda n: "/mnt/c/Users/d/AppData/Roaming/npm/npm" if n == "npm" else "")
    result = prepare.check_node()
    assert result.ok is False
    text = "\n".join(result.lines)
    assert "WINDOWS PATH" in text and "interop" in text
    assert "not an install" in text


def test_a_linux_npm_with_a_windows_prefix_is_caught_and_repaired(monkeypatch):
    """⚠ THE ONE THAT BIT, AND THE OLD GUARD DID NOT CHECK IT. node and npm
    BOTH Linux; `npm root -g` returned C:\\Users\\…\\npm\\node_modules. So
    `npm install -g <agent>` installed a WINDOWS package whose binary wrote its
    config to the Windows home — and the agent check then correctly found
    nothing in the Linux home, with no visible cause."""
    monkeypatch.setattr(prepare, "_which",
                        lambda n: f"/usr/bin/{n}" if n in ("node", "npm") else "")
    monkeypatch.setattr(prepare, "_run",
                        lambda argv, timeout=600:
                        (0, "C:\\Users\\dev\\AppData\\Roaming\\npm\n")
                        if "prefix" in argv else (0, "v22.0.0\n"))
    result = prepare.check_node()
    assert result.ok is False
    assert "INSTALLS TO Windows" in result.detail
    assert result.fix and result.fix[0][:3] == ["/usr/bin/npm", "config", "set"]
    assert ".npm-global" in result.fix[0][-1]


@pytest.mark.parametrize("prefix,windows", [
    ("C:\\Users\\dev\\AppData\\Roaming\\npm", True),
    ("/mnt/c/Users/dev/AppData/Roaming/npm", True),
    ("c:/users/dev/appdata/roaming/npm", True),
    ("/usr/local", False),
    ("/home/dev/.npm-global", False),
    ("", False),
])
def test_the_prefix_predicate(prefix, windows):
    assert prepare._prefix_is_windows(prefix) is windows


# ═══════════════════════════════════════════════════════════ 4 · the agent

def test_an_agent_on_the_windows_side_is_reported_and_never_used(monkeypatch):
    """Third instance of one class. NEVER used silently: a config on the Windows
    side belongs to a Windows agent process, and a hook wired there would never
    fire for the Linux session the developer works in."""
    from installer import detect
    monkeypatch.setattr(detect, "agent_survey", lambda: [{
        "agent": "claude-code", "present": False, "evidence": None,
        "windows_side": "/mnt/c/Users/dev/.claude",
        "looked_in": ["/home/dev/.claude"], "config": "x", "user_level": True}])
    result = prepare.check_agent()
    assert result.ok is False
    text = "\n".join(result.lines)
    assert "/mnt/c/Users/dev/.claude" in text
    assert "from your LINUX home" in text
    assert not result.fix, "this one cannot be fixed from here — it opens a browser"


def test_no_agent_at_all_is_fixable_by_installing_one(monkeypatch):
    from installer import detect
    monkeypatch.setattr(detect, "agent_survey", lambda: [{
        "agent": "claude-code", "present": False, "evidence": None,
        "windows_side": None, "looked_in": ["/home/dev/.claude"],
        "config": "x", "user_level": True}])
    monkeypatch.setattr(prepare, "_which", lambda n: "/usr/bin/npm")
    result = prepare.check_agent()
    assert result.fix == [["/usr/bin/npm", "install", "-g",
                            "@anthropic-ai/claude-code"]]


# ═══════════════════════════════════════════════════════════ 5 · scratch

def test_a_missing_scratch_is_created_before_install_not_after_it_fails(tmp_path):
    target = tmp_path / "deep" / "scratch"
    result = prepare.check_scratch(str(target))
    assert result.ok is False
    assert result.fix == [["mkdir", "-p", str(target)]]
    assert any("preflight would fail" in line for line in result.lines)


def test_no_scratch_named_is_not_a_failure():
    assert prepare.check_scratch(None).ok is True


# ═════════════════════════════════ the property that made them worth building

def test_a_survey_writes_nothing(tmp_path):
    """Every check is a question that can be asked again, and asking changes
    nothing — so a half-finished run leaves a machine at a known stage."""
    before = sorted(p.name for p in tmp_path.iterdir())
    prepare.survey(str(tmp_path / "not-created"))
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_a_fix_is_verified_by_re_running_its_check_not_by_an_exit_code(monkeypatch):
    """⚠ THE WHOLE REASON THIS LOOP EXISTS. `npm install -g` exits 0 while
    installing to the wrong operating system. Here the command SUCCEEDS and the
    check still fails, and that must be reported as a failure."""
    said = []
    result = prepare.Result(False, "broken", fix=[["true"]], fix_note="pretend")
    monkeypatch.setattr(prepare, "_run", lambda argv, timeout=600: (0, ""))
    monkeypatch.setattr(prepare, "_recheck",
                        lambda name, scratch: prepare.Result(False, "still broken"))
    out = prepare.apply_fixes({"node": result, **{k: prepare.Result(True)
                                                   for k in prepare.CHECKS
                                                   if k != "node"}},
                               None, said.append)
    assert out["node"].ok is False
    text = "\n".join(said)
    assert "STILL FAILING after the fix" in text
    assert "the command SUCCEEDED and the check still fails" in text


def test_a_verified_fix_says_so(monkeypatch):
    said = []
    result = prepare.Result(False, "broken", fix=[["true"]], fix_note="pretend")
    monkeypatch.setattr(prepare, "_run", lambda argv, timeout=600: (0, ""))
    monkeypatch.setattr(prepare, "_recheck",
                        lambda name, scratch: prepare.Result(True, "fixed"))
    out = prepare.apply_fixes({"node": result, **{k: prepare.Result(True)
                                                   for k in prepare.CHECKS
                                                   if k != "node"}},
                               None, said.append)
    assert out["node"].ok is True
    assert "verified   node" in "\n".join(said)


def test_consent_is_asked_once_for_everything_not_per_step():
    """A person answering four questions in a row stops reading by the third,
    and the fourth is the one that installs a runtime."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    # ⚠ THE LISTING IS NOW SPLIT IN TWO, BY WHAT EACH FIX TOUCHES. Fixes
    # confined to what the operator named are listed as before; fixes that
    # install or reconfigure software OUTSIDE ~/.sting are listed separately
    # and are NOT run under --yes at all. One prompt still covers both.
    assert "This will change your machine, inside what you named:" in source
    assert "INSTALL OR RECONFIGURE SOFTWARE OUTSIDE" in source
    assert source.count("Do all of that?") == 1
    assert "sudo and your shell will ask" in source


def test_the_human_side_is_named_in_the_module_that_decides_it():
    """gh auth login, the agent's own login, and sudo — three, not two. A script
    that silently acquires root on a work laptop is a script that gets banned."""
    doc = prepare.__doc__ or ""
    for human in ("gh auth login", "agent CLI's login", "sudo"):
        assert human in doc


@pytest.mark.skipif(platform.system() == "Windows",
                     reason="install.py REFUSES on native Windows by design — "
                            "asserting on --check-only's normal output there "
                            "tests the refusal, not --check-only")
def test_check_only_changes_nothing_and_says_so():
    result = subprocess.run([sys.executable, "install.py", "--check-only"],
                             cwd=str(ROOT), capture_output=True, text=True)
    # ⚠ TWO WORDINGS, AND BOTH ARE "NOTHING WAS INSTALLED". `--check-only`
    # says it differently when a check is FAILING, and a CI runner has failing
    # checks (no gitleaks, no agent installed) where a developer machine does
    # not. Asserting only the clean-machine wording made the test a statement
    # about the machine rather than about --check-only.
    assert ("Nothing was installed" in result.stdout
            or "nothing installed" in result.stdout), result.stdout
    assert "0 · This machine" in result.stdout


# ══════════════ the Windows claim is DERIVED, not typed (Phase 5, TASK B.3)

def test_windows_says_unproven_until_a_real_session_exists(monkeypatch, tmp_path):
    """⚠ A SENTENCE SOMEBODY MUST REMEMBER TO DELETE IS THE SAME STALENESS AS
    the `wsl --install` advice this file carried for two passes after WSL
    stopped being the plan. So the claim is a query."""
    monkeypatch.setattr(prepare.platform, "system", lambda: "Windows")
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    assert "NOT YET PROVEN" in prepare.check_platform().detail


def test_a_preflight_record_does_NOT_count_as_proof(monkeypatch, tmp_path):
    """⚠ THE DISCRIMINATOR IS `purpose`. Preflight writes a decision record
    every time it runs, so counting FILES would call the machine proven the
    moment somebody checked whether it was."""
    monkeypatch.setattr(prepare.platform, "system", lambda: "Windows")
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    (tmp_path / "p.log.jsonl").write_text(
        json.dumps({"event": "decision", "purpose": "preflight", "seq": 1}) + "\n"
        + json.dumps({"event": "decision", "purpose": "install_probe", "seq": 2}) + "\n",
        encoding="utf-8")
    assert "NOT YET PROVEN" in prepare.check_platform().detail


def test_a_real_work_session_flips_it_to_PROVEN(monkeypatch, tmp_path):
    monkeypatch.setattr(prepare.platform, "system", lambda: "Windows")
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    (tmp_path / "abcdef12.log.jsonl").write_text(
        json.dumps({"event": "decision", "purpose": "work", "seq": 7}) + "\n",
        encoding="utf-8")
    result = prepare.check_platform()
    assert "PROVEN" in result.detail and "NOT YET" not in result.detail
    assert "seq 7" in result.detail
