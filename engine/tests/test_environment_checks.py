"""Three checks, three documented onboarding failures. None of them refuses.

    shell        one of the two named failures was a WSL command run in a
                 Windows shell, and nothing checked it
    interpreter  node and npm each get a SIDE in the interop guard; the
                 interpreter running the installer did not — and it is the one
                 that decides where everything lands
    home         a network or DrvFs $HOME is precisely the "filesystem stops
                 answering" case `core/locking.LOCK_TIMEOUT` was built for, and
                 the only reachable cause of that wedge

⚠ REPORT, DO NOT REFUSE. A network home is a supported configuration with a
named risk. A Windows interpreter is a real problem the person can fix. Neither
is a reason to stop an install that would otherwise work — and `check_platform`
already owns the one case that IS fatal.
"""
from __future__ import annotations

import os
import platform
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from installer import prepare                                        # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_none_of_the_three_can_stop_an_install(monkeypatch, tmp_path):
    """⚠ THE PROPERTY THE WHOLE TASK RESTS ON, asserted for every branch each
    check can take — including the ones that fire on this machine and the ones
    that cannot."""
    monkeypatch.setenv("MSYSTEM", "MINGW64")
    assert prepare.check_shell().fatal is False
    monkeypatch.delenv("MSYSTEM")
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    assert prepare.check_shell().fatal is False
    monkeypatch.undo()

    monkeypatch.setattr(prepare, "_in_wsl", lambda: True)
    monkeypatch.setattr(prepare.sys, "executable", "/mnt/c/Python/python.exe")
    result = prepare.check_python_side()
    assert result.ok is False, "a Windows interpreter is a real problem"
    assert result.fatal is False, "and it still must not stop the install"

    monkeypatch.setattr(prepare, "home_mount", lambda: ("nfs", "server:/home"))
    assert prepare.check_home().fatal is False


def test_all_three_are_in_the_survey_and_in_CHECKS():
    """⚠ A CHECK THAT RUNS AND IS NOT PRINTED IS NOT A CHECK. `install.py`
    iterates `CHECKS`, so a name missing from it is a result computed and
    discarded."""
    results = prepare.survey()
    for name in ("shell", "interpreter", "home"):
        assert name in prepare.CHECKS, f"{name} would never be printed"
        assert name in results, f"{name} is not computed"


# ────────────────────────────────────────────────────────────────── the shell

def test_git_bash_is_caught(monkeypatch):
    """CATCHABLE: MSYSTEM is set by nothing else."""
    monkeypatch.setenv("MSYSTEM", "MINGW64")
    result = prepare.check_shell()

    assert "Git Bash" in result.detail or "MSYS" in result.detail
    assert any("wsl" in line.lower() for line in result.lines), \
        "it must say what to do, not only what is wrong"


def test_wsl_is_named(monkeypatch):
    monkeypatch.delenv("MSYSTEM", raising=False)
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    assert "WSL" in prepare.check_shell().detail


def test_powershell_versus_cmd_is_reported_as_UNKNOWABLE(monkeypatch):
    """⚠ THE HONEST HALF, AND IT IS A TEST BECAUSE IT IS A TEMPTATION.

    `$PSModulePath` is the obvious tell and it is a MACHINE-LEVEL variable on
    modern Windows — set under `cmd.exe` too. A check on it would report
    PowerShell for both, which is worse than reporting neither. This asserts
    the code does not try.
    """
    monkeypatch.delenv("MSYSTEM", raising=False)
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(platform, "system", lambda: "Windows")

    result = prepare.check_shell()

    assert result.ok is True
    assert any("cannot be known" in line.lower() for line in result.lines)

    # ⚠ THE DOCSTRING IS STRIPPED WITH `ast`, NOT WITH A PREFIX FILTER. The
    # first version of this scan matched lines starting with #/"""/⚠ and tripped
    # on the docstring sentence EXPLAINING why PSModulePath proves nothing — a
    # scan failing on its own explanation, for the second time in this repo.
    import ast

    tree = ast.parse(open(os.path.join(ROOT, "installer", "prepare.py"),
                          encoding="utf-8").read())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "check_shell")
    body = fn.body[1:] if ast.get_docstring(fn) else fn.body

    # ⚠ THE ASSERTION IS "IT IS NEVER READ", NOT "THE WORD IS ABSENT". The
    # operator-facing message NAMES PSModulePath to explain why the check does
    # not exist, and a scan for the bare word would forbid saying so — the
    # explanation and the defect are not the same thing.
    for node in body:
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            called = ast.unparse(sub.func)
            if "environ" not in called and "getenv" not in called:
                continue
            for arg in sub.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    assert arg.value.lower() != "psmodulepath", (
                        "PSModulePath is machine-level on modern Windows — "
                        "reading it reports PowerShell for cmd.exe too")


# ────────────────────────────────────────────────────────── the interpreter

def test_a_windows_interpreter_under_wsl_is_reported(monkeypatch):
    monkeypatch.setattr(prepare, "_in_wsl", lambda: True)
    monkeypatch.setattr(prepare.sys, "executable", "/mnt/c/Python312/python.exe")

    result = prepare.check_python_side()

    assert result.ok is False
    assert "WINDOWS" in result.detail
    assert any("apt install python3" in line for line in result.lines), \
        "it must name the fix"


def test_a_linux_interpreter_under_wsl_is_fine(monkeypatch):
    monkeypatch.setattr(prepare, "_in_wsl", lambda: True)
    monkeypatch.setattr(prepare.sys, "executable", "/usr/bin/python3")

    assert prepare.check_python_side().ok is True


def test_outside_wsl_the_question_does_not_arise(monkeypatch):
    """⚠ THE OTHER HALF. Without it, "ok on this machine" could be satisfied by
    a check that always returns ok."""
    monkeypatch.setattr(prepare, "_in_wsl", lambda: False)
    monkeypatch.setattr(prepare.sys, "executable", "/mnt/c/Python312/python.exe")

    assert prepare.check_python_side().ok is True, \
        "a /mnt path outside WSL is just a path"


# ─────────────────────────────────────────────────────────────────── the home

@pytest.mark.parametrize("fstype", ["nfs", "cifs", "drvfs", "9p", "smbfs"])
def test_a_network_or_crossos_home_is_reported_with_its_cost(monkeypatch, fstype):
    monkeypatch.setattr(prepare, "home_mount", lambda: (fstype, "//server/home"))

    result = prepare.check_home()

    assert result.ok is True, "supported, not refused"
    assert fstype in result.detail
    text = " ".join(result.lines)
    assert "STING_LOCK_TIMEOUT" in text, "the named cost must be named"
    assert "labelling is NOT recorded" in text or "not remembered" in text


def test_a_local_home_says_so_quietly(monkeypatch):
    monkeypatch.setattr(prepare, "home_mount", lambda: ("apfs", "/dev/disk3s1"))

    result = prepare.check_home()

    assert result.ok is True
    assert result.lines == [], "a local disk needs no paragraph"


def test_an_unanswerable_mount_is_not_reported_as_a_no(monkeypatch):
    """⚠ "could not answer" IS NOT "answered no". The distinction this repo
    keeps having to relearn, in one more place."""
    monkeypatch.setattr(prepare, "home_mount",
                        lambda: (None, "could not read the mount table"))

    result = prepare.check_home()

    assert result.ok is True
    assert "could not" in result.detail
    assert any("different from answering no" in line for line in result.lines)


def test_home_mount_reads_the_real_table():
    """It answers something on this machine, and the answer is a filesystem."""
    fstype, source = prepare.home_mount()

    assert fstype, f"could not determine the fstype for $HOME: {source}"
    assert isinstance(fstype, str) and fstype


def test_the_longest_matching_mount_wins(monkeypatch, tmp_path):
    """⚠ `/` MATCHES EVERY PATH. Without preferring the longest mount point,
    every home on every machine would be reported as whatever `/` is — which is
    local on almost all of them, so the check would silently never fire."""
    # ⚠ A REAL, RESOLVABLE HOME. The first version used `/home/dev`, which on
    # macOS is under an autofs mount and resolves to something else entirely —
    # so neither entry matched and the test failed against correct code.
    fake_home = prepare.Path(os.path.realpath(tmp_path)) / "dev"
    fake_home.mkdir()
    proc = tmp_path / "mounts"
    proc.write_text(
        f"/dev/root / ext4 rw 0 0\n"
        f"server:/exports/home {fake_home} nfs4 rw 0 0\n", encoding="utf-8")
    monkeypatch.setattr(prepare.Path, "home",
                        classmethod(lambda cls: fake_home))
    real_exists = prepare.Path.exists

    def fake_exists(self):
        if str(self) == "/proc/mounts":
            return True
        return real_exists(self)

    monkeypatch.setattr(prepare.Path, "exists", fake_exists)
    real_read = prepare.Path.read_text

    def fake_read(self, *a, **k):
        if str(self) == "/proc/mounts":
            return proc.read_text()
        return real_read(self, *a, **k)

    monkeypatch.setattr(prepare.Path, "read_text", fake_read)

    fstype, _source = prepare.home_mount()

    assert fstype == "nfs4", "the longest matching mount point must win"
