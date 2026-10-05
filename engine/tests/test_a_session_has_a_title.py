"""⚠ A SESSION READS AS "book-app / npm run dev", NOT ONLY AS ITS UUID — AND THE
TITLE IS CONTENT-BLIND BY CONSTRUCTION.

ESTABLISHED BEFORE BUILDING (docs/79). The only rich title Claude Code has lives
in the session TRANSCRIPT — the conversation — and Sting's claim is that it
never reads the conversation. Off-limits. Claude Code's sessions-METADATA file
(`~/.claude/sessions/<pid>.json`) carries a `name`, and on a real machine the
values were `book-app-88`, `team-deck-db`, `sting-4d`: the cwd basename
plus two hex characters. That is the folder we already know, made worse, at the
cost of a file read and a Claude-Code-only PID mapping. Not used.

So the title is derived ONCE per session from two things every adapter already
delivers and every record already carries: the basename of the declared project
root (else the cwd), and the session's first command (else the first tool and
path). `core/title.py` is pure — no IO — and `SessionState.title` caches it.

WHAT THE TITLE IS NOT. It is not on the decision path: the engine never reads
it (pinned below, under three session states). It embeds the first command, so
it travels only at the `full` tier, exactly as `command` does. And it is
bounded, single-line, and absent from a body that was not given one — so every
record written before this field is byte-identical to before.
"""
from __future__ import annotations

import builtins
import copy
import io
import json
import os
from pathlib import Path

import pytest

import hook_entry
from core import audit_log, engine, title, wire
from core.audit_log import build_body, default_log_path, read_records
from core.probes import NullWorld
from core.types import Action, ActionKind, SessionState
from tests.test_adapter_conformance import NATIVE_EXEC_PAYLOAD

COMMAND = "npm run dev"


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A declared project root named book-app, the way a real install declares
    one (STING_ROOTS), so the folder half of the title is the ROOT's basename."""
    root = tmp_path / "book-app"
    root.mkdir()
    monkeypatch.setenv("STING_ROOTS", str(root))
    return root


def _claude(cwd: Path, command: str, session: str = "s-title") -> dict:
    return {"session_id": session, "cwd": str(cwd), "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}}


def _records(session: str) -> list[dict]:
    return read_records(default_log_path(session))


# ═══════════════════════════════════════════ 1 · the chosen source, by value

def test_a_claude_code_session_is_titled_folder_slash_first_command(project):
    out, err, code = hook_entry.run(json.dumps(_claude(project, COMMAND)), agent="claude-code")

    assert code == 0, err
    decision = [r for r in _records("s-title") if r["event"] == "decision"][-1]
    assert decision["title"] == f"book-app / {COMMAND}"
    canary = [r for r in _records("s-title") if r["event"] == "session_start"]
    assert canary and canary[0]["title"] == f"book-app / {COMMAND}", (
        "the liveness record is the first thing a session writes; it carries the title too")


def _native(agent: str, cwd: Path, command: str) -> dict:
    """Each agent's OWN payload shape, with the cwd, roots and command rewritten."""
    p = copy.deepcopy(NATIVE_EXEC_PAYLOAD[agent])
    if agent == "cursor":
        p.update(cwd=str(cwd), workspace_roots=[str(cwd)], command=command)
    elif agent == "antigravity":
        p["workspacePaths"] = [str(cwd)]
        p["toolCall"]["args"].update(CommandLine=command, Cwd=str(cwd))
    else:                                                   # claude-code, codex, copilot
        p["cwd"] = str(cwd)
        p["tool_input"]["command"] = command
    return p


@pytest.mark.parametrize("agent", ["cursor", "codex", "copilot", "antigravity"])
def test_every_other_agent_gets_the_same_title_shape(project, agent):
    """CROSS-AGENT, driven through each adapter's own payload, not a relabelled
    Claude Code one. The folder+command source needs nothing Claude Code has."""
    payload = _native(agent, project, COMMAND)

    out, err, code = hook_entry.run(json.dumps(payload), agent=agent)

    assert code == 0, err
    session = hook_entry.ADAPTERS[agent].parse(payload).session_id
    decision = [r for r in _records(session) if r["event"] == "decision"][-1]
    assert decision["title"] == f"book-app / {COMMAND}"


# ═══════════════════════════════════════════ 2 · the security guarantee

def test_the_transcript_and_history_are_never_opened(project, tmp_path, monkeypatch):
    """⚠ THE POINT OF THE DESIGN, PINNED. Decoys are planted exactly where Claude
    Code keeps the conversation — the transcript, the prompt history — and the
    sessions-metadata file too, each carrying a sentinel. Every file open in the
    process is recorded while the hook runs end to end. None may touch
    `~/.claude`, and no sentinel may reach the log."""
    home = tmp_path / "home"
    sid = "s-decoy"
    transcript_dir = home / ".claude" / "projects" / str(project).replace("/", "-")
    transcript_dir.mkdir(parents=True)
    (transcript_dir / f"{sid}.jsonl").write_text(
        json.dumps({"type": "ai-title", "aiTitle": "SENTINEL-TRANSCRIPT", "sessionId": sid}) + "\n",
        encoding="utf-8")
    (home / ".claude" / "history.jsonl").write_text(
        json.dumps({"display": "SENTINEL-HISTORY", "sessionId": sid}) + "\n", encoding="utf-8")
    (home / ".claude" / "sessions").mkdir()
    (home / ".claude" / "sessions" / "4242.json").write_text(
        json.dumps({"name": "SENTINEL-NAME", "sessionId": sid, "pid": 4242}), encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CLAUDE_PID", "4242")
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", sid)

    opened: list[str] = []
    real_open, real_io_open, real_os_open = builtins.open, io.open, os.open

    def spy_open(file, *a, **k):
        opened.append(str(file)); return real_open(file, *a, **k)

    def spy_io_open(file, *a, **k):
        opened.append(str(file)); return real_io_open(file, *a, **k)

    def spy_os_open(path, *a, **k):
        opened.append(str(path)); return real_os_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(io, "open", spy_io_open)
    monkeypatch.setattr(os, "open", spy_os_open)

    out, err, code = hook_entry.run(json.dumps(_claude(project, COMMAND, sid)), agent="claude-code")

    assert code == 0, err
    touched = [p for p in opened if f"{os.sep}.claude{os.sep}" in p]
    assert not touched, f"the hook opened Claude Code's own files: {touched}"
    text = default_log_path(sid).read_text(encoding="utf-8")
    assert "SENTINEL" not in text
    assert [r for r in _records(sid) if r["event"] == "decision"][-1]["title"] == f"book-app / {COMMAND}"


def test_without_any_claude_metadata_the_hook_still_succeeds(project, tmp_path, monkeypatch):
    """No `~/.claude` at all — a Cursor machine, a container, a CI runner. The
    title is the fallback and nothing about the hook changes."""
    monkeypatch.setenv("HOME", str(tmp_path / "bare"))
    (tmp_path / "bare").mkdir()
    monkeypatch.delenv("CLAUDE_PID", raising=False)

    out, err, code = hook_entry.run(json.dumps(_claude(project, COMMAND, "s-bare")), agent="claude-code")

    assert code == 0, err
    assert [r for r in _records("s-bare") if r["event"] == "decision"][-1]["title"] == f"book-app / {COMMAND}"


# ═══════════════════════════════════════════ 3 · not on the decision path

def _action() -> Action:
    return Action(session_id="s", seq=1, kind=ActionKind.EXEC, paths=(),
                  command="git push origin main", url=None, tool_name=None,
                  content=None, cwd="/tmp", workspace_roots=("/tmp",), agent="claude-code")


@pytest.mark.parametrize("state_kind", ["clean", "untrusted", "secret"])
def test_the_title_never_alters_a_decision(state_kind):
    """Checked under three session states, because a rule that read the title
    would most plausibly do it inside the branches with the most conditions."""
    def fresh(with_title: bool) -> SessionState:
        s = SessionState(session_id="s")
        if state_kind == "untrusted":
            s.mark_untrusted(seq=1, kind="read", ref="README.md")
        elif state_kind == "secret":
            s.mark_secret(seq=1, path="/tmp/.env", how="credential path")
        s.title = "book-app / npm run dev" if with_title else ""
        return s

    with_title = engine.decide(_action(), fresh(True), NullWorld())
    without = engine.decide(_action(), fresh(False), NullWorld())

    assert (str(with_title.decision), with_title.rule_id, with_title.reason) == (
        str(without.decision), without.rule_id, without.reason)


# ═══════════════════════════════════════════ 4 · the shape of the string

def test_the_title_is_bounded_and_single_line():
    nasty = "npm run dev\nrm -rf /   \t" + "x" * 5000
    t = title.session_title(("/w/book-app",), "/w/book-app/src", nasty, "Bash", ())

    assert "\n" not in t and "\t" not in t
    assert len(t) <= title.MAX_TITLE
    assert t.startswith("book-app / npm run dev")


def test_no_command_falls_back_to_the_tool_and_the_path():
    assert title.session_title(("/w/book-app",), "/w/book-app", None, "Read",
                               ("/w/book-app/README.md",)) == "book-app / Read README.md"
    assert title.session_title((), "/w/book-app", None, None, ()) == "book-app / session"


def test_the_folder_is_the_declared_root_not_the_cwd():
    """A cwd deep inside the root must not retitle the session by subfolder."""
    assert title.session_title(("/w/book-app",), "/w/book-app/src/pages", "ls", "Bash", ()
                               ) == "book-app / ls"


def test_the_title_is_derived_once_and_shared_by_every_record(project):
    sid = "s-once"
    hook_entry.run(json.dumps(_claude(project, "npm run dev", sid)), agent="claude-code")
    hook_entry.run(json.dumps(_claude(project, "git status", sid)), agent="claude-code")

    titles = {r["title"] for r in _records(sid) if r["event"] == "decision"}
    assert titles == {"book-app / npm run dev"}, titles


# ═══════════════════════════════════════════ 5 · a recorded field like the others

def test_a_body_without_a_title_is_byte_identical_to_before():
    body = build_body("s", seq=1, event="decision", decision="ALLOW", command="ls")
    assert "title" not in body, "clean absence: records written before this field do not change"


def test_the_recorded_title_is_clipped_like_every_bounded_field():
    body = build_body("s", seq=1, event="decision", decision="ALLOW",
                      title="t" * (audit_log._MAX_TITLE + 50))
    assert body["title"].endswith(audit_log.CLIP_MARKER)
    assert len(body["title"]) == audit_log._MAX_TITLE + len(audit_log.CLIP_MARKER)


def test_the_title_ships_masked_like_the_command():
    """It embeds the first command, so it is content: it ships where the
    command ships, every record whole, and masking reads it like the command —
    a value named in the first command is its type in the title too."""
    from shipper import mask
    record = {"ts": 1.0, "session_id": "s", "seq": 1, "event": "decision", "kind": "EXEC",
              "decision": "ALLOW", "rule_id": None,
              "command": "export API_TOKEN=tok3n-f4ke-9a8b7c6d; npm run dev",
              "title": "book-app / export API_TOKEN=tok3n-f4ke-9a8b7c6d; npm run dev",
              "prev": "0" * 64, "hash": "1" * 64}
    shipped = mask.mask_record(record)
    assert shipped["title"] == "book-app / export API_TOKEN=[token]; npm run dev"
    assert "tok3n" not in shipped["command"] and "title" not in wire.UNMASKED
