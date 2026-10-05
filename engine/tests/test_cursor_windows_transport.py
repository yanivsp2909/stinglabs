"""The Cursor-on-Windows transport — the test that would have caught all of it.

⚠ FOUR ROOT CAUSES STACKED, AND EVERY WINDOWS INSTALL GUARDED NOTHING:
  RC1  a POSIX `KEY='value'` prefix on the hook command, parsed by PowerShell
       as a command name; `failClosed:false` made the error a silent allow.
  RC2  even a direct call got a BOM-prefixed payload (`Get-Content -Raw`) that
       `json.loads` rejected on the first character.
  RC3  STING_ROOTS pointed at a directory that did not exist.
  RC4  only three of Cursor's events were wired.

A.5 asks for the test that would have caught it: a BOM-prefixed Cursor-shaped
payload, run through the real entry point with NO env on the command line, and
a new line must appear in the session log. That test is worth more than the fix.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hook_entry.py"


def _env_file(home: Path, sessions: Path, roots: Path) -> None:
    home.joinpath(".sting").mkdir(parents=True, exist_ok=True)
    env = home / ".sting" / "env"
    env.write_text(
        f"export STING_SESSION_ROOT='{sessions}'\n"
        f"export STING_OBSERVE='0'\n"
        f"export STING_ROOTS='{roots}'\n"
        f"export STING_PURPOSE='work'\n", encoding="utf-8")
    os.chmod(env, 0o600)


# ═══ RC2 · the BOM ═══

def test_a_bom_prefixed_payload_still_produces_a_record(tmp_path):
    """⚠ THE A.5 TEST. Cursor's `Get-Content -Raw` prepends a UTF-8 BOM, and
    `json.loads` died on it with exactly the error the developer saw. A record
    must appear anyway."""
    home = tmp_path / "home"
    sessions = home / ".sting" / "sessions"
    roots = tmp_path / "code"
    roots.mkdir()
    _env_file(home, sessions, roots)

    payload = json.dumps({"hook_event_name": "beforeShellExecution",
                          "command": "git status",
                          "conversation_id": "conv-1",
                          "workspace_roots": [str(roots)]})
    bom_payload = "\ufeff" + payload            # what Get-Content -Raw sends

    # \u26a0 A CLEAN ENVIRONMENT, so the env FILE is the source. pytest's own
    # STING_SESSION_ROOT would otherwise win (the environment beats the file, by
    # design) and the record would land in the suite's session root, not this
    # test's \u2014 proving nothing about the file being read.
    clean = {k: v for k, v in os.environ.items() if not k.startswith("STING_")}
    clean["HOME"] = str(home)

    done = subprocess.run(
        [sys.executable, str(HOOK), "--agent", "cursor"],
        input=bom_payload, capture_output=True, text=True,
        env=clean, timeout=60)

    assert done.returncode == 0, done.stderr
    assert "could not parse" not in done.stderr, done.stderr
    logs = list(sessions.glob("*.jsonl"))
    assert logs, "no session log was written — the BOM broke the payload"
    lines = [l for l in logs[0].read_text().splitlines() if l.strip()]
    assert lines, "the log is empty — nothing was recorded"


def test_the_normaliser_strips_a_bom_and_leading_noise():
    import hook_entry

    assert hook_entry._normalise_payload("\ufeff{}") == "{}"
    assert hook_entry._normalise_payload("\r\n  {\"a\":1}") == '{"a":1}'
    assert hook_entry._normalise_payload("[1,2]") == "[1,2]"
    # a genuinely malformed payload is not rescued into validity
    assert "not json" in hook_entry._normalise_payload("\ufeffnot json")


def test_a_bom_payload_parses_where_plain_json_loads_would_have_died():
    import hook_entry

    bom = "\ufeff" + json.dumps({"command": "ls"})
    normalised = hook_entry._normalise_payload(bom)
    assert json.loads(normalised)["command"] == "ls"


# ═══ RC1 · the env prefix ═══

def test_the_hook_command_carries_no_environment_prefix():
    """⚠ RC1. The command must be just the invocation — no `KEY='value'` for
    PowerShell to read as a command name, and no settings in a file the agent
    can read."""
    import install

    result = install.write_hook_config(
        "cursor", Path("/tmp/does-not-matter/hooks.json"),
        Path("/opt/sting/current/sting_hook.py"),
        {"STING_OBSERVE": "1", "STING_ROOTS": "/x",
         "STING_DEVICE_TOKEN": "secret-token"},
        dry_run=True)

    command = result["command"]
    assert "STING_OBSERVE=" not in command, "an env prefix is still in the command"
    assert "STING_ROOTS=" not in command
    assert "secret-token" not in command, "a token in hooks.json is RC1's leak"
    assert "--agent cursor" in command
    assert "sting_hook.py" in command


def test_the_hook_reads_the_env_file_and_the_environment_wins(tmp_path):
    import envfile

    env_path = tmp_path / "env"
    env_path.write_text(
        "export STING_ROOTS='/from/the/file'\n"
        "export STING_TIER='verdict_reason_location'\n", encoding="utf-8")
    environ = {"STING_ROOTS": "/from/the/shell"}

    applied = envfile.load(str(env_path), environ)

    assert environ["STING_TIER"] == "verdict_reason_location", "file value missing"
    assert environ["STING_ROOTS"] == "/from/the/shell", "the environment must win"
    assert "STING_TIER" in applied and "STING_ROOTS" not in applied


def test_a_missing_env_file_is_not_an_error(tmp_path):
    import envfile

    assert envfile.load(str(tmp_path / "nope"), {}) == []


def test_a_windows_path_and_a_url_survive_the_env_loader(tmp_path):
    """The values that RC1's separator bug and the shipper's parser both had to
    handle: a Windows path keeps its backslashes, a URL keeps its colons."""
    import envfile

    env_path = tmp_path / "env"
    env_path.write_text(
        "export STING_COLLECTOR_URL='https://host:8787/v1'\n"
        r"export STING_SESSION_ROOT='C:\Users\alice\.sting\sessions'" + "\n",
        encoding="utf-8")
    environ = {}
    envfile.load(str(env_path), environ)

    assert environ["STING_COLLECTOR_URL"] == "https://host:8787/v1"
    assert environ["STING_SESSION_ROOT"] == r"C:\Users\alice\.sting\sessions"


# ═══ the two entry points agree ═══

def test_both_entry_points_load_the_env_file():
    """sting_hook (the daemon client) and hook_entry (the fallback) must both
    load it, or the environment a request runs under depends on which path
    served it."""
    for name in ("sting_hook.py", "hook_entry.py"):
        source = (ROOT / name).read_text(encoding="utf-8")
        assert "envfile" in source and "envfile.load()" in source, (
            f"{name} does not load ~/.sting/env")


# ═══ B.1 · Cursor's URI-style roots ═══

def test_a_uri_style_windows_root_becomes_a_native_path():
    """⚠ B.1. Cursor sends `/C:/Users/…`, a URI, and it was carried verbatim,
    then the engine's normalisation dropped the slash to `C:Users\\…` — a
    separator lost, so the trust boundary silently did not match a native cwd."""
    from adapters import _common

    assert _common._from_uri("/C:/Users/alice/project") == "C:/Users/alice/project"
    assert _common._from_uri("file:///C:/Users/alice/project") == "C:/Users/alice/project"
    assert _common._from_uri("/c:/x/y") == "c:/x/y"


def test_a_posix_path_is_not_mangled_by_the_uri_normaliser():
    """A genuine POSIX path — including one with a colon in a filename — must be
    untouched. The transform only fires on a `/<letter>:/` drive prefix."""
    from adapters import _common

    for p in ("/usr/local/bin", "/private/tmp/x", "relative/path",
              "/home/x/file:with:colons"):
        assert _common._from_uri(p) == p


def test_the_cursor_adapter_normalises_a_uri_root():
    from adapters import cursor

    action = cursor.parse({
        "hook_event_name": "beforeShellExecution", "command": "git status",
        "conversation_id": "c1",
        "workspace_roots": ["/C:/Users/alice/project"]})
    # no root should still carry the URI artefact
    assert not any(r.startswith("/C:/") for r in action.workspace_roots), (
        f"a URI-style root survived into the boundary: {action.workspace_roots}")
