#!/usr/bin/env python3
"""What the developer ASKED for, recovered from the agent's own transcript.

WHY THIS EXISTS. The labelling tool showed five preceding actions as context, and
that turned out not to be enough to judge anything: five lines of `cd … && git
add -A` tell you what the AGENT did and nothing about what you WANTED. The owner
tried to label and could not, which is a finding about the tool.

A decision log records the agent's side of the conversation only. The other side
— the instruction that caused all of it — is in the transcript, and every session
this repo has logs for has one:

    ~/.claude/projects/<flattened-project-path>/<session-id>.jsonl

**Measured: 5 of 5 log sessions have a transcript of the same name**, and the
largest holds 47 genuine human turns among 1137 `tool_result` messages that also
carry `role: "user"`. Telling those apart is the whole job of `_human_text`.

TWO ROUTES TO THE SAME ANSWER, because a third of the prompts have no command:

    by digest   an EXEC record's command hashes to a `tool_use` block in the
                transcript; the human turn before that block is the instruction.
                Exact — the digest either matches or it does not.
    by time     a WRITE/EDIT names paths and has no command, so there is no
                digest. The record's `ts` locates a position in the transcript
                and the last human turn at or before it is the instruction.
                Approximate, and labelled as such wherever it is shown.

⚠ THIS IS A READ-ONLY, BUILD-TIME CONVENIENCE. Nothing here is evidence: the
transcript is not hash-chained and can be edited freely. It exists to help a
person remember a moment, never to establish what happened — for that, the log is
the record. Nothing in this module is imported by the engine.
"""
from __future__ import annotations

import datetime as dt
import functools
import hashlib
import json
import re
from pathlib import Path

TRANSCRIPTS = Path("~/.claude/projects").expanduser()

# Turns that are machinery rather than instruction: slash commands, the caveat
# banner wrapped around them, injected reminders, and the auto-generated summary
# a continued session opens with. Showing these as "what you asked for" would be
# worse than showing nothing, because they look like an answer.
_NOISE = re.compile(
    r"<local-command-|<command-name>|<system-reminder>|<command-message>"
    r"|^This session is being continued from a previous conversation",
    re.S)


def _human_text(message: dict) -> str | None:
    """The text of a genuine human turn, or None.

    ⚠ `role: "user"` IS NOT ENOUGH. Every tool result comes back as a user
    message — 1137 of them against 47 real turns in the session measured — so a
    naive filter returns the output of the previous command and calls it the
    instruction.
    """
    content = message.get("content")
    if isinstance(content, str):
        return content or None
    if not isinstance(content, list):
        return None
    if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
        return None
    text = " ".join(b.get("text", "") for b in content
                    if isinstance(b, dict) and b.get("type") == "text")
    return text or None


def _epoch(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def transcript_path(session_id: str) -> Path | None:
    if not TRANSCRIPTS.is_dir():
        return None
    for path in TRANSCRIPTS.rglob(f"{session_id}.jsonl"):
        return path
    return None


@functools.lru_cache(maxsize=8)
def index(session_id: str) -> tuple:
    """(turns, by_digest) for one session. Parsed once; the largest is 20 MB.

    turns      [(epoch, text)] for genuine human turns, in order
    by_digest  {sha256(command): index into turns of the turn that preceded it}
    """
    path = transcript_path(session_id)
    if path is None:
        return ((), {})
    turns: list[tuple[float | None, str]] = []
    by_digest: dict[str, int] = {}
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ((), {})
    for line in lines:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = obj.get("type")
        message = obj.get("message") or {}
        if kind == "user":
            text = _human_text(message)
            if text and text.strip() and not _NOISE.search(text.strip()):
                turns.append((_epoch(obj.get("timestamp")), text.strip()))
        elif kind == "assistant":
            for block in (message.get("content") or []):
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                command = (block.get("input") or {}).get("command")
                if isinstance(command, str):
                    digest = hashlib.sha256(command.encode("utf-8")).hexdigest()
                    by_digest.setdefault(digest, len(turns) - 1)
    return (tuple(turns), by_digest)


def asked_for(session_id: str, digest: str | None,
               ts: float | None) -> tuple[str | None, str]:
    """(instruction, how_it_was_found). See the module docstring for the routes."""
    turns, by_digest = index(session_id)
    if not turns:
        return None, "no transcript"
    if digest and digest in by_digest:
        i = by_digest[digest]
        if 0 <= i < len(turns):
            return turns[i][1], "exact — the command hashes to this turn"
    if ts is not None:
        best = None
        for turn_ts, text in turns:
            if turn_ts is not None and turn_ts <= ts:
                best = text
            elif turn_ts is not None and turn_ts > ts:
                break
        if best:
            return best, "by time — the last thing you asked before this ran"
    return None, "not found in the transcript"


def gap_before(record: dict, earlier: list[dict]) -> float | None:
    """Seconds since the previous action in the same session.

    A three-second gap is the agent mid-loop; twenty minutes is you coming back
    to the keyboard. The judgement "was this prompt worth interrupting me" reads
    completely differently across those two, and the record has always carried
    `ts` without anything showing it.
    """
    if not earlier or record.get("ts") is None:
        return None
    prev = earlier[-1].get("ts")
    return None if prev is None else max(0.0, record["ts"] - prev)


def human_gap(seconds: float | None) -> str:
    if seconds is None:
        return ""
    if seconds < 90:
        return f"{seconds:.0f}s after the previous action"
    if seconds < 3600:
        return f"{seconds / 60:.0f} min after the previous action"
    return f"{seconds / 3600:.1f} h after the previous action — you had been away"
