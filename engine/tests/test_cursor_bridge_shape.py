"""The Windows bridge, checked as far as a machine with no PowerShell can.

⚠ WHAT THIS FILE IS AND IS NOT. It cannot EXECUTE the bridge — that is
`tests/test_cursor_windows_preflight.py`, and on a machine with no PowerShell
that test skips loudly. What it can do is check the bridge's SHAPE: the three
paths that were hardcoded in the developer's working copy, and the fourth that
was hardcoded here and is the dangerous one. Those are claims about text and
about where files land, and they need no shell.

Every failure below produces the same symptom on a real machine: the bridge
cannot start the engine, `failClosed:false` turns the error into an ALLOW, and
the install reports success. A guard that guards nothing, silently. That is why
a text check earns its place — the alternative is finding out from a customer.

    1.1  the interpreter comes from STING_PYTHON, not a guessed C:\\PythonNN
    1.2  the entry resolves through the pointer, which on Windows is a FILE
    1.3  the roots come from the env file
    1.4  no hardcoded install prefix — STING_INSTALL_ROOT is honoured
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import install
from installer import place

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "installer" / "cursor_bridge.ps1"
SOURCE = BRIDGE.read_text(encoding="utf-8")

def _code(text: str) -> str:
    """The bridge with its comments removed — BOTH kinds.

    ⚠ POWERSHELL HAS TWO COMMENT SYNTAXES AND THE HEADER USES THE BLOCK ONE.
    Stripping only `#` lines left the whole `<# … #>` header in, so every
    "does it hardcode X" check below was reading the paragraph that EXPLAINS
    the defect and calling it the defect. A scan that cannot tell a fix from
    the description of a bug is a scan that forbids explaining anything.
    """
    without_block = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(line for line in without_block.splitlines()
                     if not line.strip().startswith("#"))


CODE = _code(SOURCE)


# ═════════════════════════════════════════════ 1.1 · the interpreter ══

def test_the_interpreter_comes_from_what_the_install_recorded():
    assert "$sting[\"STING_PYTHON\"]" in CODE
    assert not re.search(r"C:\\+Python\d", CODE), "a guessed interpreter path"
    assert not re.search(r"Program Files.*[Pp]ython", CODE)


def test_the_last_resort_interpreter_is_announced():
    """⚠ NOT A FORMALITY. A bare `python` on Windows resolves to the Microsoft
    Store alias stub when no Python is on PATH; the stub exits without running
    anything, and a hook that exits without running is a SILENT ALLOW under
    failClosed:false. The old comment promised "it is announced below" and
    nothing announced it."""
    fallback = CODE.split('$python = "python"', 1)
    assert len(fallback) == 2, "the last-resort interpreter is gone entirely"
    assert "Console]::Error.Write" in fallback[1][:600], (
        "the fallback interpreter is taken silently")
    assert "STING_PYTHON" in fallback[1][:600]


def test_install_records_the_interpreter_it_ran_with():
    """The other half: STING_PYTHON has to be WRITTEN, or the bridge's first
    choice is never available."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    assert 'shipper_env["STING_PYTHON"] = sys.executable' in source


# ═══════════════════════════════════════════════ 1.2 · the entry point ══

def test_the_entry_is_the_bridges_own_sibling_and_the_pointer_is_the_fallback():
    """⚠ NOT `<prefix>/current/sting_hook.py`. On Windows `current` is a
    POINTER FILE, so that path cannot exist — three places in this project have
    built it and every one wrote a config naming a file that was never there."""
    assert "$PSScriptRoot" in CODE, "the entry is not derived from this script"
    assert "current.txt" in CODE, "the pointer fallback is gone"
    assert not re.search(r'Join-Path\s+\$prefix\s+"current"', CODE), (
        "`<prefix>/current` is a directory that cannot exist on Windows")
    # read as a FILE, which is what a pointer is
    assert "Get-Content $pointer" in CODE


def test_the_pointer_is_a_file_because_os_replace_is_atomic_for_files():
    """The layout claim the bridge depends on, asserted against place.py rather
    than restated — if POINTER ever stops being `current.txt`, this fails here
    instead of on a Windows machine."""
    assert place.POINTER == "current.txt"
    assert f'"{place.POINTER}"' in CODE or place.POINTER in CODE


# ═══════════════════════════════════════════════════ 1.3 · the roots ══

def test_the_roots_come_from_the_env_file_and_are_not_named_here():
    assert '".sting\\env"' in CODE or ".sting\\env" in CODE
    assert "STING_ROOTS" not in CODE, (
        "the bridge names a root itself; roots are the operator's declaration, "
        "loaded from the env file with everything else")
    assert "Desktop" not in CODE, "a developer's own directory shipped"
    for name in ("alice", "bob"):
        assert name not in SOURCE, f"a developer's home directory: {name}"


def test_the_installer_has_already_checked_those_roots():
    """1.3's other half. The bridge trusts the env file; the file is only worth
    trusting because `install.check_roots` reported every entry that is not a
    directory — including the partial case nothing else witnesses."""
    assert hasattr(install, "check_roots") and hasattr(install, "report_roots")


# ══════════════════════════════════ 1.4 · the prefix, and this was the one ══

def test_no_hardcoded_install_prefix_anywhere_in_the_bridge():
    """⚠ THE DANGEROUS ONE. The bridge hardcoded `$HOME/.local/share/sting`
    while `place.default_prefix()` honours `STING_INSTALL_ROOT`. A custom-prefix
    install therefore resolved no entry point, the hook could not start, and
    `failClosed:false` made that a silent allow — a guard that reported a
    successful install and permitted everything."""
    assert ".local\\share\\sting" not in CODE, (
        "the default prefix is hardcoded in the bridge again")
    assert ".local/share/sting" not in CODE


def test_the_prefix_is_derived_from_the_scripts_own_location():
    """⚠ DERIVED, NOT READ FROM THE VARIABLE, and the difference is the fix.
    Cursor does not inherit the shell the installer ran in, so
    `$env:STING_INSTALL_ROOT` is normally UNSET at hook time — reading it would
    fix nothing. And when it IS set, to a prefix other than the one this bridge
    was placed under, honouring it would make a bridge from one tree spawn an
    engine from another. The variable's job is to tell the INSTALLER where to
    put this file; the file is sitting in the answer."""
    assert "Split-Path -Parent $PSScriptRoot" in CODE
    assert "$env:STING_INSTALL_ROOT" not in CODE


def test_a_custom_prefix_produces_a_command_naming_that_prefix(tmp_path,
                                                                monkeypatch):
    """The behavioural form: the command install.py writes must follow the
    prefix, not the default."""
    monkeypatch.setenv("STING_INSTALL_ROOT", str(tmp_path / "elsewhere"))
    monkeypatch.setattr(install, "_is_windows", lambda: True)

    current = place.default_prefix() / "v-test"
    written = install.write_hook_config(
        "cursor", tmp_path / "never.json", current / "sting_hook.py",
        {}, dry_run=True)

    assert str(tmp_path / "elsewhere").replace("\\", "/") in written["command"]
    assert ".local/share/sting" not in written["command"]


# ═════════════════════════════════ 2 · what install.py must write ══

def test_the_command_shape_on_windows(monkeypatch):
    """Task 2.1, asserted against the string hooks.json will actually hold.

    ⚠ `_is_windows` IS FORCED RATHER THAN SKIPPED. An earlier draft of this
    file skipped on POSIX with "not the Windows branch on this host", which is
    a skip that proves nothing and — since `pytest.ini` prints every skip
    reason — one more line for a reader to discount. The branch is a one-line
    predicate; driving it is better than not testing it.
    """
    monkeypatch.setattr(install, "_is_windows", lambda: True)
    written = install.write_hook_config(
        "cursor", Path("/tmp/never/hooks.json"),
        Path("/opt/sting/v1/sting_hook.py"), {}, dry_run=True)
    command = written["command"]

    assert command.startswith("powershell -NoProfile -ExecutionPolicy Bypass ")
    assert "-File \"" in command
    assert command.rstrip().endswith("-Agent cursor"), command
    # ⚠ FORWARD SLASHES. Git Bash — how a great many Windows developers run
    # anything — backslash-escapes `C:\Users\…` as this string passes through
    # it. .NET and PowerShell both accept `/` on Windows.
    path = command.split('-File "', 1)[1].split('"', 1)[0]
    assert "\\" not in path, f"a backslash Git Bash will eat: {path}"
    assert path.endswith("/installer/cursor_bridge.ps1"), path


def test_the_bridge_is_placed_by_place_and_not_copied_by_the_installer(tmp_path):
    """Task 2.2. Placed with the payload, so it is covered by the same
    missing-payload refusal, removed by the same uninstall, and cannot outlive
    the engine it spawns."""
    assert "installer/cursor_bridge.ps1" in place.PAYLOAD
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    assert "_ship_cursor_bridge" not in source, (
        "a second copy step can succeed or fail independently of the tree")

    placed = place.place(prefix=tmp_path / "p", source=ROOT,
                          session_root=tmp_path / "s")
    bridge = install.cursor_bridge_path(placed["current"])
    assert bridge.is_file()
    assert (bridge.parent.parent / "sting_hook.py").is_file(), (
        "the bridge resolves ../sting_hook.py; the layout must put it there")


def test_an_archive_without_the_bridge_is_REFUSED_not_installed(tmp_path):
    """⚠ THE POINT OF MAKING IT PAYLOAD. Before, a build that dropped the
    bridge installed cleanly and wrote a hooks.json naming a .ps1 that was not
    on disk — and that is a silent allow, not an error anybody sees."""
    import shutil

    fake = tmp_path / "src"
    shutil.copytree(ROOT, fake, symlinks=True,
                    ignore=shutil.ignore_patterns(
                        ".git", "logs", "scenarios", "tests", "docs",
                        "__pycache__", "*.pyc"))
    (fake / "installer" / "cursor_bridge.ps1").unlink()

    with pytest.raises(FileNotFoundError) as caught:
        place.place(prefix=tmp_path / "p", source=fake,
                     session_root=tmp_path / "s")
    assert "cursor_bridge.ps1" in str(caught.value)


def test_uninstall_removes_the_bridge_with_the_tree(tmp_path):
    """⚠ IT USED TO BE LEFT BEHIND. `remove()` deletes DIRECTORIES under the
    prefix; a bare file at `<prefix>/cursor_bridge.ps1` survived, and the
    leftover then made `prefix.rmdir()` fail — so the uninstaller reported
    "something else lives here" about a file it had written itself."""
    prefix = tmp_path / "p"
    place.place(prefix=prefix, source=ROOT, session_root=tmp_path / "s")
    place.remove(prefix=prefix)

    assert not list(prefix.rglob("cursor_bridge.ps1"))
    assert not prefix.exists(), sorted(p.name for p in prefix.iterdir())


# ═══════════════════════════════════════════ 2.3 · POSIX MUST NOT CHANGE ══

@pytest.mark.parametrize("agent",
                          ["claude-code", "cursor", "codex", "copilot", "antigravity"])
def test_posix_commands_are_untouched(agent, monkeypatch):
    """⚠ A WINDOWS FIX THAT ALTERS THE PLATFORM THE PRODUCT RUNS ON IS A BIGGER
    CHANGE THAN IT LOOKS. On macOS and Linux every agent — Cursor included —
    keeps `<python> <entry> --agent <name>` and no bridge."""
    monkeypatch.setattr(install, "_is_windows", lambda: False)
    written = install.write_hook_config(
        agent, Path("/tmp/never/c.json"),
        Path("/opt/sting/v1/sting_hook.py"), {}, dry_run=True)
    command = written["command"]

    assert "powershell" not in command.lower()
    assert "cursor_bridge" not in command
    assert command.endswith(f"--agent {agent}")
    assert "sting_hook.py" in command


def test_the_bridge_ships_on_posix_too_and_that_is_deliberate(tmp_path):
    """⚠ THE ONE POSIX CHANGE, NAMED. Every install now copies a 4 KB
    PowerShell file that nothing on POSIX will ever execute. Making the payload
    conditional would make `compute_version`'s hash and the missing-payload
    refusal platform-dependent, so an archive built on macOS could not be
    installed on Windows. One payload, or the version means two things."""
    placed = place.place(prefix=tmp_path / "p", source=ROOT,
                          session_root=tmp_path / "s")
    assert install.cursor_bridge_path(placed["current"]).is_file()


def test_the_bridge_does_not_version_the_policy():
    """It is TRANSPORT, by the same rule that keeps `daemon/` and
    `sting_hook.py` out of VERSIONED: a grant is a human's approval of a POLICY,
    and a typo in a PowerShell comment must not revoke every outstanding
    one-shot grant on every machine — including the POSIX ones that never run
    it."""
    assert not any("cursor_bridge" in name for name in place.VERSIONED)


# ═══════════════════════════════════ an UPDATE, not a fresh install ══

def test_an_update_reclaims_the_orphan_an_older_installer_left(tmp_path,
                                                                monkeypatch):
    """⚠ B.4. Before the bridge became payload it was copied to
    `<prefix>/cursor_bridge.ps1`, beside the pointer. A reinstall replaced the
    hook entry and ORPHANED that file: `place.remove()` only deletes
    DIRECTORIES under the prefix, so nothing ever took it, and the leftover then
    made `prefix.rmdir()` fail on uninstall.

    ⚠ AND THE ORDER MATTERS. The old hooks.json names that file until
    `write_hook_config` replaces the entry, so deleting it first would open a
    window where a Cursor hook resolves a bridge that is not there — a silent
    allow under failClosed:false. This asserts the reclaim happens AFTER the
    config write, in the source, because a race is not observable in a test.

    ⚠ AND BOTH MARKERS ARE ASSERTED PRESENT BEFORE THEY ARE COMPARED. This was
    written with `str.index`, which raises rather than passing vacuously — but
    `tests/test_absence_is_not_a_default.py` flagged it anyway, and it was
    right to: a comparison between two positions derived from a file is exactly
    the shape that silently means nothing once one of them stops existing. A
    ValueError traceback is also a worse failure message than a sentence.
    """
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    config_write = source.find("write_hook_config(found[\"agent\"]")
    reclaim = source.find("cursor_bridge.ps1\",)")

    assert config_write != -1, (
        "install.py no longer writes the hook configs in the loop this test "
        "anchors on — re-point it rather than deleting it")
    assert reclaim != -1, (
        "install.py no longer reclaims the orphaned bridge at all")
    assert config_write < reclaim, (
        "the orphan is removed BEFORE the hook configs are rewritten — that "
        "leaves a window in which hooks.json names a bridge that is gone")


def test_what_an_update_must_never_reclaim():
    """⚠ B.3. `--uninstall` already states why these survive, and an update
    inherits the reasoning by simply never touching `~/.sting`: the logs are
    EVIDENCE, and the shipper's cursor is what stops a reinstall re-sending
    everything already delivered. Asserted against `place.remove`, which is the
    only thing that removes anything."""
    import inspect

    body = inspect.getsource(place.remove)
    assert ".sting" not in body, (
        "uninstall reaches into ~/.sting; an update copying that would delete "
        "the evidence and the shipper cursor")
    assert "sessions" not in body
    # and place() itself only ever writes under the prefix
    placed = inspect.getsource(place.place)
    assert "session_root" in placed and "revoke_grants(session_root)" in placed, (
        "place() touches the session root for exactly one reason — revoking "
        "one-shot grants — and that is deliberate; see the module docstring")
