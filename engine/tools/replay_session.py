#!/usr/bin/env python3
"""Replay a real session transcript through engine.decide() and score it. $0.

    python3 tools/replay_session.py --transcript PATH
    python3 tools/replay_session.py --transcript PATH --roots ~/a:~/b

The question this answers: **if the guard had been in enforce mode, what would
it have blocked?** That is not the same question as the decision log answers.
The log records what the engine decided at the time, on the engine of that
moment; this replays the same actions through the engine as it stands now.

Unlike tools/replay_transcript.py, which only exercises labelling on Bash
commands, this reconstructs EVERY tool call through the real adapter and calls
engine.decide(), so the verdict ladder, the sinks and the propagation all run.

WHAT IT CANNOT REPRODUCE. Tool RESULTS are not replayed — a PreToolUse hook
never sees them, so this is faithful in that respect. But `world` is the machine
as it is NOW, not as it was: a file read then and deleted since reads as absent.
Verdicts that turn on file contents are therefore approximate, and are marked.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters import claude_code                                 # noqa: E402
from core import engine, probes                                  # noqa: E402
from core.types import Decision, SessionState                    # noqa: E402


def tool_calls(transcript: Path) -> list[dict]:
    """Every tool_use block, in order, unclipped."""
    out = []
    with transcript.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = entry.get("message") or {}
            content = message.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    out.append({"name": block.get("name"),
                                "input": block.get("input") or {},
                                "ts": entry.get("timestamp")})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript", type=Path, required=True)
    ap.add_argument("--cwd", default=str(Path.cwd()))
    ap.add_argument("--roots", default=None,
                     help="colon-separated, as STING_ROOTS would be set")
    ap.add_argument("--scratch", default=None,
                     help="colon-separated, as STING_SCRATCH would be set")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)

    if args.roots:
        os.environ["STING_ROOTS"] = args.roots

    world = probes.RealWorld()
    state = SessionState(session_id="replay", cwd=args.cwd)
    roots, note = world.project_roots(args.cwd)
    state.workspace_roots = list(roots)
    # ⚠ `probes.split_roots`, NOT `.split(":")`. Every Windows path contains a
    # colon in `C:`, and this was the second of two sites the Windows port's
    # `os.pathsep` fix did not reach.
    state.scratch_roots = [str(Path(d).resolve())
                           for d in probes.split_roots(args.scratch or "")
                            if d and Path(d).is_dir()]
    print(f"scratch roots : {state.scratch_roots}")
    print(f"project roots : {list(roots)}")
    print(f"roots note    : {note or '(confident)'}\n")

    calls = tool_calls(args.transcript)
    if args.limit:
        calls = calls[:args.limit]

    denies, asks = [], []
    kinds = {}
    for seq, call in enumerate(calls, start=1):
        payload = {"session_id": "replay", "cwd": args.cwd,
                   "hook_event_name": "PreToolUse",
                   "tool_name": call["name"], "tool_input": call["input"]}
        try:
            action = claude_code.parse(payload)
        except Exception:                                     # noqa: BLE001
            continue
        action = replace(action, seq=seq,
                          workspace_roots=tuple(state.workspace_roots))
        state.seq = seq
        try:
            verdict = engine.decide(action, state, world)
        except Exception as exc:                              # noqa: BLE001
            print(f"  ENGINE CRASH at seq {seq}: {type(exc).__name__}: {exc}")
            continue
        kinds[str(action.kind)] = kinds.get(str(action.kind), 0) + 1
        row = (seq, call["name"], action, verdict, call["ts"])
        if verdict.decision is Decision.DENY:
            denies.append(row)
        elif verdict.decision is Decision.ASK:
            asks.append(row)

    total = len(calls)
    print(f"actions replayed : {total}   {kinds}")
    print(f"  ALLOW          : {total - len(denies) - len(asks)}")
    print(f"  ASK            : {len(asks)}")
    print(f"  DENY           : {len(denies)}")

    for label, rows in (("DENY", denies), ("ASK", asks)):
        if not rows:
            continue
        print(f"\n================ {label} ({len(rows)}) ================")
        for seq, name, action, verdict, ts in rows:
            target = (action.command or action.url
                      or " ".join(action.paths) or action.tool_name or "")
            print(f"\n  seq {seq}  {name}  [{action.kind}]  {ts}")
            print(f"    rule   : {verdict.rule_id}")
            print(f"    reason : {(verdict.reason or '')[:200]}")
            print(f"    target : {target[:300]!r}")
            ev = engine.sink_evidence(verdict.rule_id, action.command)
            if ev:
                print(f"    matched: {ev}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
