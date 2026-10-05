#!/usr/bin/env python3
"""Record the RAW stdin an agent sends, then run the real hook unchanged.

⚠ WHY THIS EXISTS. Four of the five adapters have never seen a payload from the
agent they model — every `probe_payload` for those four was written from vendor
documentation, and this repo has been bitten by that twice: Cursor's entire hook
schema was wrong for weeks, and its `preToolUse` claim had to be corrected from
Cursor's own binary. A captured fixture is the only thing that settles it.

    # wire it in place of hook_entry.py in ONE agent's config, for ONE session
    python3 tools/capture_payload.py --agent cursor -- <the usual hook argv>

────────────────────────────────────────────────────────────────────────────────
⚠ WHAT THIS WRITES, WHO CAN READ IT, AND HOW TO TURN IT OFF
────────────────────────────────────────────────────────────────────────────────

**It writes whatever the agent sent.** On a real session that is the developer's
actual commands and, for read events, file CONTENTS. It is a second copy of
everything, and it sits **entirely outside the masking** — nothing in it is
replaced by its type, as everything a collector receives is. What a developer
agreed may leave does not apply to this file, which is exactly why it must be
deliberate and short-lived.

    WHERE     $STING_CAPTURE_DIR, else ~/.sting/captures/<agent>/
    MODE      the directory is 0700 and every file is 0600, set before the
              first write — not after, which would leave a window
    WHO       the user who owns it, and root. Same as ~/.sting/env
    OFF       delete the wrapper from the agent's config, or unset
              STING_CAPTURE — the tool refuses to record without it

⚠ **IT REFUSES TO RUN SILENTLY.** `STING_CAPTURE=1` must be set explicitly. A
capture tool that records because it was left wired is the failure this warns
about, so being wired is not enough on its own.

⚠ **AND IT NEVER CHANGES THE VERDICT.** stdin is read once, written to disk,
then handed to `hook_entry` verbatim; stdout, stderr and the exit code are
passed through untouched. If anything here raises, the hook still runs — a
capture tool that can block a tool call is worse than no fixture.

Cost: one file write per action, off the verdict path (the hook is spawned
either way). It is NOT for a hot path — it is for one scratch session.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / "hook_entry.py"


def capture_dir(agent: str) -> Path:
    base = os.environ.get("STING_CAPTURE_DIR") or (Path.home() / ".sting" / "captures")
    return Path(base) / agent


def record(agent: str, raw: bytes, result: dict) -> None:
    """One JSON file per action: what arrived, and what the hook did with it.

    ⚠ NEVER RAISES. Wrapped by the caller too; this is the belt to that braces.
    """
    directory = capture_dir(agent)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / f"{time.time():.6f}.json"
    # ⚠ 0600 BEFORE THE FIRST BYTE. Opening then chmod-ing leaves a window in
    # which the file holding a developer's commands is world-readable — the same
    # ordering bug the token file avoids.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({
            "agent": agent,
            "at": time.time(),
            # ⚠ THE RAW BYTES, DECODED BUT NOT PARSED. The whole point is to see
            # what the agent really sent — parsing it here would apply this
            # repo's assumptions to the evidence meant to test them.
            "stdin": raw.decode("utf-8", "replace"),
            "hook": result,
        }, handle, indent=1, sort_keys=True)


def main(argv: list[str]) -> int:
    agent = "unknown"
    passthrough: list[str] = []
    rest = argv[1:]
    if "--" in rest:
        head, rest = rest[:rest.index("--")], rest[rest.index("--") + 1:]
    else:
        head, rest = rest, []
    for i, arg in enumerate(head):
        if arg == "--agent" and i + 1 < len(head):
            agent = head[i + 1]
    passthrough = rest or head

    raw = sys.stdin.buffer.read()

    proc = subprocess.run([sys.executable, str(ENTRY), *passthrough],
                          input=raw, capture_output=True)

    # ⚠ RECORDED ONLY WHEN ASKED, AND FAILING TO RECORD NEVER FAILS THE HOOK.
    if os.environ.get("STING_CAPTURE") == "1":
        try:
            record(agent, raw, {
                "argv": passthrough,
                "exit": proc.returncode,
                "stdout": proc.stdout.decode("utf-8", "replace"),
                "stderr": proc.stderr.decode("utf-8", "replace"),
            })
        except Exception as exc:                                 # noqa: BLE001
            sys.stderr.write(f"sting: capture failed ({type(exc).__name__}); "
                              f"the verdict is unaffected\n")

    # Pass everything through, byte for byte.
    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
