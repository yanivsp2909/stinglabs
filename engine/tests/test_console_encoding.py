"""`⚠` on a cp1252 console: where it raises, and where it provably cannot.

⚠ THE FEARED CASE DOES NOT EXIST, AND THAT IS THE FIRST RESULT. The worry was
that the hook's own stdout would raise while returning a DENY — silently
allowing something it had already decided to block, or crashing the agent's tool
call. **It cannot**, and the reason is structural rather than lucky: every
adapter renders with `json.dumps`, whose default `ensure_ascii=True` escapes
non-ASCII to `\\uXXXX`. The deny path is pure ASCII on every platform.

⚠ WHAT DOES RAISE IS THE HUMAN-FACING TOOLING, measured under
`PYTHONIOENCODING=cp1252`: `install.py --status` died mid-output after printing
"Installed", and `tools/preflight.py` died while reporting. A tool that crashes
while telling a developer what is wrong with their install is worse than one
printing `?`.

These tests drive a real cp1252 stream, so they fail before the fix and pass
after rather than asserting that somebody did it.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from adapters import ADAPTERS_BY_NAME                            # noqa: E402
from core.types import Decision, Verdict                         # noqa: E402

# A reason carrying characters cp1252 cannot encode. Thai because the Windows
# run showed a real fixture failing on `ร`; the arrow because this codebase uses
# `→` in prose as freely as it uses `⚠`.
HOSTILE = "unexpected destination ตรวจสอบ → evil.invalid ⚠"


# ═══════════════════ 1 · the deny path cannot raise, on any console

@pytest.mark.parametrize("name", sorted(ADAPTERS_BY_NAME))
def test_a_deny_renders_as_pure_ascii_whatever_the_reason_says(name):
    """⚠ THE ONE THAT DECIDES THE SEVERITY. If this ever fails, a verdict can be
    lost to a console encoding — and the guard would fail at the exact moment it
    refuses something."""
    rendered = ADAPTERS_BY_NAME[name].render(
        Verdict(Decision.DENY, HOSTILE, "rule"))
    assert rendered.isascii(), f"{name}: non-ASCII escaped into a verdict"
    rendered.encode("cp1252")            # raises if it ever stops being true


@pytest.mark.parametrize("name", sorted(ADAPTERS_BY_NAME))
def test_the_reason_survives_the_escaping_rather_than_being_dropped(name):
    """ASCII-safe must not mean lossy: a reader decoding the JSON gets the
    characters back. `\\uXXXX` is an encoding of the text, not a redaction."""
    rendered = ADAPTERS_BY_NAME[name].render(
        Verdict(Decision.DENY, HOSTILE, "rule"))
    if not rendered.strip():
        pytest.skip(f"{name} renders DENY as empty")
    assert "ตรวจสอบ" in json.dumps(json.loads(rendered), ensure_ascii=False)


def test_the_hook_process_returns_a_deny_under_a_cp1252_stream(tmp_path):
    """End to end, through the real process, with the stream set to cp1252."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".env").write_text("K=AKIA_TEST_enc\n", encoding="utf-8")
    env = {**__import__("os").environ,
           "STING_SESSION_ROOT": str(tmp_path / "s"),
           "STING_ROOTS": str(proj),
           "PYTHONIOENCODING": "cp1252"}
    env.pop("STING_OBSERVE", None)

    out = ""
    for step in ("cat .env", "cp .env debug.env",
                 "git add debug.env && git commit -m x", "git push origin main"):
        payload = json.dumps({"session_id": "enc", "cwd": str(proj),
                               "hook_event_name": "PreToolUse",
                               "tool_name": "Bash",
                               "tool_input": {"command": step}})
        proc = subprocess.run([sys.executable, str(ROOT / "hook_entry.py"),
                               "--agent", "claude-code"],
                              input=payload, capture_output=True, text=True,
                              env=env)
        assert "UnicodeEncodeError" not in proc.stderr, proc.stderr
        out = proc.stdout
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


# ═══════════════════ 2 · and the tooling no longer dies telling you so

def _cp1252_stream():
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")


def test_a_raw_cp1252_stream_really_does_reject_the_character():
    """⚠ THE CONTROL. Without it, the tests below could pass because the stream
    is not what they think it is — which is how a fix to a silent problem looks
    exactly like a broken one."""
    with pytest.raises(UnicodeEncodeError):
        stream = _cp1252_stream()
        stream.write("⚠ warning")
        stream.flush()


def test_make_output_safe_stops_the_write_from_raising(monkeypatch):
    """⚠ FAILS BEFORE THE FIX, PASSES AFTER. `errors="replace"` is the
    guarantee; the UTF-8 console is the cosmetics."""
    from installer import console

    stream = _cp1252_stream()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", _cp1252_stream())
    console.make_output_safe()

    sys.stdout.write("⚠ warning → done")     # must not raise
    sys.stdout.flush()


def test_it_reports_what_it_did_rather_than_leaving_it_a_guess():
    from installer import console
    described = console.make_output_safe()
    assert "errors=" in described and "console=" in described


@pytest.mark.parametrize("tool", [
    ["install.py", "--status"],
    ["tools/preflight.py", "--agent", "claude-code"],
])
def test_the_tools_run_to_completion_on_a_cp1252_console(tool, tmp_path):
    """⚠ MEASURED FAILING BEFORE THE FIX: install.py --status died after
    printing "Installed", preflight died while reporting. Both are diagnostics,
    and a diagnostic that crashes is worse than a wrong one."""
    proc = subprocess.run([sys.executable, *tool], cwd=str(ROOT),
                          capture_output=True, text=True,
                          env={**__import__("os").environ,
                               "PYTHONIOENCODING": "cp1252",
                               "STING_SESSION_ROOT": str(tmp_path)})
    assert "UnicodeEncodeError" not in proc.stderr, proc.stderr[-400:]
    # Exit code is the tool's own verdict about the machine and is not asserted
    # here; what is asserted is that it got to say one.
    assert proc.stdout.strip(), "the tool printed nothing at all"
