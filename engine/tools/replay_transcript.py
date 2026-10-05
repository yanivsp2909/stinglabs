#!/usr/bin/env python3
"""Replay a real Claude Code transcript through the engine. $0, no network.

    python3 tools/replay_transcript.py                       # the newest one
    python3 tools/replay_transcript.py --transcript PATH
    python3 tools/replay_transcript.py --expect-clean         # exit 1 on a phantom

WHY THIS EXISTS, AND WHY IT IS NOT THE CORPUS.

The corpus is 87 staged scenarios of 1-5 actions each, written to exercise
attacks we already thought of. A real session is hundreds of actions of
ordinary work, and it contains the shapes nobody would think to write down:
heredocs, commit messages that discuss git, test fixtures full of credential
paths, files written about the guard itself.

Measured: 0 of 86 corpus EXEC actions contain a heredoc. Every false positive
found in this project so far — the phantom secret source, the mangled taint
key, the local append classified as a push, the session tainted by its own
commit message — was invisible to the corpus and obvious here.

Transcripts are the agent's own record of what it ran, UNCLIPPED, so this also
sees the text the decision log truncates.

WHAT IT IS NOT. Transcript commands are replayed as EXEC actions against the
CURRENT engine; tool results are not available, so this measures labelling and
sink classification, not the full verdict ladder. Treat a clean run as "no
phantom labels", not as "the engine is correct".
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import probes                                          # noqa: E402
from core.engine import check_sinks, mark_sources, propagate     # noqa: E402
from core.session import SessionState                            # noqa: E402
from core.types import Action, ActionKind                        # noqa: E402

PROJECTS = Path.home() / ".claude/projects"
PUNCTUATION = set("\"'()[],{}`")


def newest_transcript() -> Path | None:
    files = sorted(PROJECTS.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime,
                    reverse=True) if PROJECTS.is_dir() else []
    return files[0] if files else None


def commands(transcript: Path) -> list[str]:
    """Every Bash command the agent ran, in order, unclipped."""
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
                if (isinstance(block, dict) and block.get("type") == "tool_use"
                        and block.get("name") == "Bash"):
                    command = (block.get("input") or {}).get("command")
                    if command:
                        out.append(command)
    return out


def replay(cmds: list[str], cwd: str) -> SessionState:
    state = SessionState("transcript-replay")
    world = probes.RealWorld()
    for seq, command in enumerate(cmds, start=1):
        action = Action(session_id="transcript-replay", seq=seq,
                        kind=ActionKind.EXEC, paths=(), command=command,
                        url=None, tool_name=None, content=None, cwd=cwd,
                        workspace_roots=(cwd,), agent="claude-code")
        check_sinks(state, action, world)     # exercised for crashes
        mark_sources(state, action, world)
        propagate(state, action, world)
    return state


def report(state: SessionState, count: int) -> int:
    """Print the findings. Returns the number of PROBLEMS, not of labels."""
    problems = 0

    print(f"replayed {count} Bash commands\n")
    print(f"  untrusted            : {state.untrusted}"
          f"  (since seq {state.untrusted_since_seq})")
    print(f"  holds_secret         : {state.holds_secret}"
          f"  (since seq {state.holds_secret_since_seq})")
    print(f"  fingerprints         : {len(state.secret_fingerprints)}")
    print(f"  secret sources       : {len(state.secret_sources)}")
    print(f"  tainted paths        : {len(state.tainted_paths)}")

    # 1. A source claiming content, with nothing to show for it.
    phantom = [s for s in state.secret_sources
               if s.get("how") == "content" and not state.secret_fingerprints]
    if phantom:
        problems += len(phantom)
        print(f"\n  PHANTOM SOURCES ({len(phantom)}) — how=content with no fingerprints:")
        for s in phantom:
            print(f"    {s}")

    # 2. A source for a file that is not there.
    missing = [s for s in state.secret_sources
               if s.get("how") == "content" and not Path(s.get("path", "")).exists()]
    if missing:
        problems += len(missing)
        print(f"\n  SOURCES FOR FILES THAT DO NOT EXIST ({len(missing)}):")
        for s in missing:
            print(f"    {s}")

    # 3. A taint key that is not a path.
    mangled = [k for k in state.tainted_paths if set(k) & PUNCTUATION]
    if mangled:
        problems += len(mangled)
        print(f"\n  MANGLED TAINT KEYS ({len(mangled)}) — parse failures, not paths:")
        for k in mangled:
            print(f"    {k!r}")

    if not problems:
        print("\n  no phantom sources, no mangled keys.")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript", type=Path, default=None)
    ap.add_argument("--cwd", default=str(Path.cwd()),
                     help="cwd to resolve relative paths against")
    ap.add_argument("--expect-clean", action="store_true",
                     help="exit 1 if any phantom or mangled key is found")
    args = ap.parse_args(argv)

    transcript = args.transcript or newest_transcript()
    if not transcript or not transcript.is_file():
        print(f"No transcript found under {PROJECTS}", file=sys.stderr)
        return 2

    cmds = commands(transcript)
    if not cmds:
        print(f"No Bash commands in {transcript}", file=sys.stderr)
        return 2

    print(f"transcript: {transcript.name}")
    problems = report(replay(cmds, args.cwd), len(cmds))
    if problems and args.expect_clean:
        print(f"\n{problems} problem(s).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
