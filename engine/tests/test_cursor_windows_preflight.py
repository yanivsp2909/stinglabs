"""The Windows PREFLIGHT the transport never had: run the command hooks.json
contains, THROUGH CURSOR'S OWN PIPELINE, and demand a record.

⚠ WHY THIS FILE IS SEPARATE FROM `test_cursor_windows_transport.py`.

That file proves the ENGINE half — BOM tolerance, env-file loading, URI roots —
by calling `hook_entry.py` directly with clean argv and a string on stdin. Every
assertion in it passes on a machine where the transport is completely broken,
and one was: for the whole life of the Windows port, `hooks.json` held a command
PowerShell parsed as a command NAME, `failClosed:false` turned the resulting
error into a silent allow, and a suite of green tests said nothing. A hook that
is wired, reports success, and can never fire is invisible to any test that does
not USE THE WIRING.

So the property here is deliberately end-to-end and deliberately hostile:

    the string `install.py` WROTE INTO hooks.json, read back OUT of that file,
    executed the way Cursor executes it, fed the bytes Cursor feeds it,
    must leave a new line in the session log.

Nothing is reconstructed. The command is not rebuilt from the parts — it is
parsed out of the JSON the installer produced, because the defect being guarded
against lives in exactly the gap between "what the installer meant" and "what
the file says".

────────────────────────────────────────────────────────────────────────────────
⚠ WHAT CURSOR ACTUALLY DOES, AND WHY PIPING CLEAN JSON PROVES NOTHING
────────────────────────────────────────────────────────────────────────────────

Cursor runs a hook as roughly

    Get-Content '<temp>.json' -Raw | & { $input | <command> }

and BOTH halves of that are the fault, not the JSON:

  * `Get-Content -Raw` on a UTF-8 file emits a BOM, so the child's first
    character is U+FEFF and `json.loads` dies on it.
  * `& { $input | ... }` is a script block whose pipeline delivery to a NATIVE
    process is unreliable — the reported symptom was empty and truncated stdin,
    which is why the fix could not be a `.cmd` wrapper and had to be
    `ProcessStartInfo`.

A test that does `subprocess.run(cmd, input=payload)` reproduces neither. It is
the SHAPE that fails. So this test reproduces the shape: a real temp file with a
real BOM, `Get-Content -Raw`, the script block, and the command verbatim.

────────────────────────────────────────────────────────────────────────────────
⚠ WHERE THIS CAN RUN — TASK 1.2, ANSWERED HONESTLY AND IN THREE TIERS
────────────────────────────────────────────────────────────────────────────────

The requirement is a POWERSHELL, not Windows. PowerShell 7 (`pwsh`) is
cross-platform and runs the same script block, the same `Get-Content -Raw`, and
the same `System.Diagnostics.ProcessStartInfo`. That splits the coverage:

  WINDOWS + `powershell`   the real thing. The command runs VERBATIM, including
                           the `powershell` executable name hooks.json names.
                           This is the only tier that proves the product.

  ANY OS + `pwsh`          proves the PIPELINE and the BRIDGE — BOM, script
                           block, stdin delivery, env-file load, entry
                           resolution. Does NOT prove: `powershell.exe` (5.1,
                           a different engine), Windows path separators, or the
                           cp1252 console codec that has already broken this
                           repo's own tooling once. The executable name is
                           substituted, and the test SAYS it substituted.

  NO POWERSHELL            nothing is proven and the file says so. THIS IS THE
                           DEFAULT ON THE DEVELOPMENT MACHINE (macOS, no pwsh).

⚠ AND THE THIRD TIER SKIPS LOUDLY RATHER THAN PASSING QUIETLY. A skip that
prints as a bare `s` in `pytest -q` is indistinguishable from coverage to
everyone who is not reading the source, and this project has already been bitten
once by a green gate that could not fail. Two things make it loud:

  1. `pytest.ini` sets `-rs`, so EVERY run prints every skip with its reason.
     That is repo-wide on purpose: the four skips that already existed were just
     as invisible.
  2. `test_the_transport_tier_is_reported` ALWAYS runs, on every platform, and
     fails if this module cannot state which tier it is in. The statement itself
     is not allowed to go missing.
"""
from __future__ import annotations

import codecs
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# ── which PowerShell, and therefore which tier ───────────────────────────────
# `powershell` first ONLY on Windows: on macOS a `powershell` on PATH would be
# something else entirely, and on Windows `pwsh` may be installed alongside the
# 5.1 the hook command actually names. The tier must describe what will run.
_IS_WINDOWS = platform.system() == "Windows"
_SHELL = (shutil.which("powershell") if _IS_WINDOWS else None) or shutil.which("pwsh")

VERBATIM = "windows-verbatim"       # the product, exactly as installed
PIPELINE = "pwsh-substituted"       # the pipeline and the bridge, not Windows
UNPROVEN = "no-powershell"          # nothing


def tier() -> str:
    if _SHELL and _IS_WINDOWS and Path(_SHELL).stem.lower() == "powershell":
        return VERBATIM
    if _SHELL:
        return PIPELINE
    return UNPROVEN


SKIP_REASON = (
    "CURSOR-ON-WINDOWS TRANSPORT UNPROVEN ON THIS MACHINE — no PowerShell "
    "(`powershell` or `pwsh`) is on PATH, so the command hooks.json contains "
    "was never executed. The engine half is covered by "
    "test_cursor_windows_transport.py; the TRANSPORT half — the half that made "
    "every Windows install guard nothing — is not covered by anything in this "
    "run. Install PowerShell 7 (`brew install --cask powershell`) to raise this "
    "to the pwsh tier, or run the suite on Windows for the real one."
)


# ═══════════════════════════════════════════ always runs, on every platform ══

def test_the_transport_tier_is_reported():
    """⚠ THE STATEMENT MAY NOT GO MISSING. Everything below can skip; this
    cannot. It fails if the module ever loses its ability to say which of the
    three tiers this run is in — which is the failure that would turn a loud
    skip back into a quiet pass."""
    assert tier() in (VERBATIM, PIPELINE, UNPROVEN)
    if tier() == UNPROVEN:
        assert SKIP_REASON.startswith("CURSOR-ON-WINDOWS TRANSPORT UNPROVEN")
        assert "not covered by anything in this run" in SKIP_REASON


def test_the_installed_command_has_nothing_for_powershell_to_misparse():
    """RC1, as a SHAPE check that needs no PowerShell — so the property is
    pinned even in the UNPROVEN tier.

    A `KEY='value'` prefix is what PowerShell read as a command name. This runs
    everywhere and covers only the shape; it is NOT a substitute for executing
    it, which is the whole reason the rest of this file exists."""
    import install

    written = install.write_hook_config(
        "cursor", Path("/tmp/never-written/hooks.json"),
        Path("/opt/sting/current/sting_hook.py"),
        {"STING_OBSERVE": "1", "STING_ROOTS": "/x",
         "STING_DEVICE_TOKEN": "secret-token"},
        dry_run=True, observe=False)
    command = written["command"]

    first = command.split()[0].strip("'\"")
    assert "=" not in first, (
        f"the command STARTS with {first!r}, which PowerShell reads as a "
        f"command name, not an assignment — this is RC1 verbatim")
    assert "secret-token" not in command
    assert "--agent cursor" in command


# ═══════════════════════════════════════════════════ the preflight itself ══

pytestmark_reason = SKIP_REASON


def _install_into(home: Path) -> tuple[Path, Path, Path]:
    """A complete, isolated install under `home`. Returns (config, sessions, roots).

    ⚠ THE REAL INSTALLER WRITES THE CONFIG. Hand-writing a hooks.json here would
    test a string this file invented; the defect class lives in what install.py
    actually emits, so install.py emits it.
    """
    import install
    from installer import place

    sessions = home / ".sting" / "sessions"
    roots = home / "code"
    roots.mkdir(parents=True, exist_ok=True)

    # ── the 0600 env file: everything the hook needs, none of it on the command
    # line. STING_PYTHON is what the bridge uses instead of guessing a path.
    (home / ".sting").mkdir(parents=True, exist_ok=True)
    env_file = home / ".sting" / "env"
    env_file.write_text(
        f"export STING_SESSION_ROOT='{sessions}'\n"
        f"export STING_ROOTS='{roots}'\n"
        f"export STING_OBSERVE='0'\n"
        f"export STING_PURPOSE='work'\n"
        f"export STING_PYTHON='{sys.executable}'\n",
        encoding="utf-8")
    if os.name != "nt":
        os.chmod(env_file, 0o600)

    # ⚠ THE REAL `place.place()` PUTS THE TREE DOWN, INCLUDING THE BRIDGE.
    # Hand-copying the .ps1 to a path this test chose would prove that path,
    # not the installer's — and "the bridge is where the installer put it" is
    # exactly the claim the Windows blocker turned on. `place` also gives the
    # prefix a NON-DEFAULT location, so `STING_INSTALL_ROOT` is exercised: the
    # bridge has to find its entry point without the variable being set in
    # Cursor's environment, which it never is.
    prefix = home / "custom-prefix"
    placed = place.place(prefix=prefix, source=ROOT, session_root=sessions)
    current = placed["current"]
    bridge = install.cursor_bridge_path(current)
    assert bridge.is_file(), f"place() did not ship the bridge: {bridge}"

    config = home / ".cursor" / "hooks.json"
    install.write_hook_config(
        "cursor", config, current / "sting_hook.py",
        {"STING_SESSION_ROOT": str(sessions)},
        dry_run=False, observe=False)
    return config, sessions, roots


def _command_out_of(config: Path) -> str:
    """The command string as hooks.json actually holds it. Not rebuilt."""
    hooks = json.loads(config.read_text(encoding="utf-8"))["hooks"]
    entries = hooks["beforeShellExecution"]
    assert len(entries) == 1, entries
    return entries[0]["command"]


def _isolate(monkeypatch, home: Path) -> None:
    """One home for the installer, the bridge and the hook — and no inherited
    STING_*, because the environment beats the env file and an inherited value
    would let this pass while proving the file was never read."""
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for key in [k for k in os.environ if k.startswith("STING_")]:
        monkeypatch.delenv(key, raising=False)


def test_everything_the_bridge_resolves_at_runtime_is_actually_on_disk(
        tmp_path, monkeypatch):
    """⚠ RUNS ON EVERY PLATFORM, INCLUDING THE ONE WITH NO POWERSHELL.

    The bridge resolves three things at runtime — itself, the interpreter, and
    the entry point. Each is a path that can be written wrong by the installer
    and produce a hook that "installs fine" and then dies on first use, which
    under `failClosed:false` is a silent allow. None of that needs a shell to
    check: it is a claim about files.

    ⚠ AND THE PREFIX HERE IS NOT THE DEFAULT, which is the whole of task 1.4.
    The bridge used to hardcode `$HOME/.local/share/sting` while the installer
    honoured `STING_INSTALL_ROOT`, so a custom-prefix install resolved no entry
    at all. `_install_into` places under `<home>/custom-prefix`, so anything
    still reaching for the default prefix fails here.

    This is the part of the preflight that is NOT lost when the transport tier
    is UNPROVEN. What remains unproven there is execution — the pipeline, the
    BOM and the stdin delivery — and nothing else.
    """
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    _isolate(monkeypatch, home)
    monkeypatch.setattr("install._is_windows", lambda: True)

    config, sessions, roots = _install_into(home)
    command = _command_out_of(config)

    # the bridge the command names must BE THERE
    bridge = command.split('-File "', 1)[1].split('"', 1)[0]
    assert Path(bridge).is_file(), (
        f"hooks.json points at a bridge that is not on disk: {bridge}")
    assert "custom-prefix" in bridge, (
        f"the command names a bridge outside the chosen prefix: {bridge}")

    # ⚠ THE ENTRY IS THE BRIDGE'S OWN SIBLING-OF-PARENT — that is how the
    # bridge resolves it, so that is what must be on disk. Checking a pointer
    # here instead would check a path the bridge does not use.
    entry = Path(bridge).parent.parent / "sting_hook.py"
    assert entry.is_file(), f"no entry point beside the bridge: {entry}"

    # ⚠ AND THE POINTER FALLBACK MUST LEAD SOMEWHERE REAL — asked through
    # `place.current_dir`, which resolves WHICHEVER layout this platform uses.
    # The literal `current.txt` is a Windows artifact (`os.replace` is atomic
    # for files, not directories); on POSIX the same role is a symlink. Naming
    # the file directly here would make the test pass only on Windows while
    # claiming to check the fallback everywhere.
    from installer import place

    prefix = Path(bridge).parent.parent.parent
    assert (place.current_dir(prefix) / "sting_hook.py").is_file(), (
        f"the pointer under {prefix} does not resolve to an entry point")

    # and the settings must be in the 0600 file, not in the world-readable one
    blob = config.read_text(encoding="utf-8")
    assert "STING_" not in blob, f"a setting is in hooks.json: {blob}"
    if os.name != "nt":
        mode = (home / ".sting" / "env").stat().st_mode & 0o777
        assert mode == 0o600, oct(mode)


@pytest.mark.skipif(_SHELL is None, reason=SKIP_REASON)
def test_a_bom_payload_through_cursors_own_pipeline_reaches_the_session_log(
        tmp_path, monkeypatch):
    """⚠ TASK 1.1. The whole transport, end to end, in Cursor's shape.

    Fails if ANY of these regress: an env prefix returns to the command, the
    bridge stops resolving the entry, `Get-Content -Raw`'s BOM reaches
    `json.loads`, or the script block fails to deliver stdin. Each of those was
    a real defect that shipped, and none of them was visible to a test that
    piped clean JSON into the script.
    """
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    # `Path.home()` reads HOME on POSIX and USERPROFILE on Windows; PowerShell's
    # own `$HOME` follows the same variables. Both are set so the installer, the
    # bridge and the hook all agree on one isolated home.
    _isolate(monkeypatch, home)
    monkeypatch.setattr("install._is_windows", lambda: True)
    config, sessions, roots = _install_into(home)
    command = _command_out_of(config)

    assert "cursor_bridge.ps1" in command, (
        f"the Windows Cursor command is not the bridge: {command}")
    if tier() == VERBATIM:
        assert command.split()[0] == "powershell", (
            "on Windows the command must run verbatim; it names "
            f"{command.split()[0]!r}")
    else:
        # ⚠ SUBSTITUTED, AND SAID SO. `pwsh` is a different executable from the
        # `powershell` the command names. Everything after the first token is
        # untouched.
        head, _, tail = command.partition(" ")
        assert head == "powershell", command
        command = f"{_SHELL} {tail}"

    # ── the payload, as a real file with a real BOM, exactly as Cursor stages it
    payload = {"hook_event_name": "beforeShellExecution",
               "command": "git status",
               "cwd": str(roots),
               "conversation_id": "preflight-conv-1",
               "workspace_roots": [str(roots)]}
    staged = tmp_path / "payload.json"
    staged.write_bytes(codecs.BOM_UTF8 + json.dumps(payload).encode("utf-8"))

    assert not list(sessions.glob("*.jsonl")) if sessions.exists() else True

    # ── CURSOR'S PIPELINE, VERBATIM. `Get-Content -Raw` for the BOM, the script
    # block for the stdin delivery. Single-quoted path so a space in tmp_path
    # cannot become two arguments.
    pipeline = (f"Get-Content '{staged}' -Raw | & {{ $input | {command} }}")
    done = subprocess.run(
        [_SHELL, "-NoProfile", "-Command", pipeline],
        capture_output=True, text=True, timeout=120)

    logs = list(sessions.glob("*.jsonl")) if sessions.exists() else []
    assert logs, (
        "NO SESSION LOG — the hook never decided anything. This is the failure "
        "the whole file exists to make visible: a wired hook that reports "
        f"success and never fires.\nexit={done.returncode}\n"
        f"stdout={done.stdout!r}\nstderr={done.stderr!r}")
    lines = [l for l in logs[0].read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines, f"the session log is empty\nstderr={done.stderr!r}"
    assert done.returncode == 0, done.stderr
    assert "could not parse" not in done.stderr, (
        f"the BOM reached json.loads — RC2\nstderr={done.stderr!r}")

    # The record must be Cursor's, not the reference adapter's: the whole point
    # of `--agent cursor` surviving the pipeline.
    record = json.loads(lines[-1])
    assert record.get("agent") == "cursor", record


@pytest.mark.skipif(_SHELL is None, reason=SKIP_REASON)
def test_the_pipeline_shape_is_what_actually_breaks_a_naive_command(tmp_path):
    """⚠ THE CONTROL. Proves the shape is hostile rather than asserting it.

    The OLD command — a POSIX env prefix — is run through the SAME pipeline. It
    must fail. If this ever passes, the pipeline this test builds is not the one
    that broke the product, and the test above is proving less than it claims.
    """
    staged = tmp_path / "p.json"
    staged.write_bytes(codecs.BOM_UTF8 + b'{"command":"git status"}')
    old_shape = (f"STING_OBSERVE='1' STING_ROOTS='/x' "
                 f"{sys.executable} -c \"import sys; sys.exit(0)\"")

    done = subprocess.run(
        [_SHELL, "-NoProfile", "-Command",
         f"Get-Content '{staged}' -Raw | & {{ $input | {old_shape} }}"],
        capture_output=True, text=True, timeout=60)

    assert done.returncode != 0 or "STING_OBSERVE" in done.stderr, (
        "the POSIX env prefix did NOT fail under PowerShell — either this shell "
        "is not PowerShell, or RC1 was never what it was said to be.\n"
        f"exit={done.returncode} stderr={done.stderr!r}")
