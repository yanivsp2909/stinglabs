"""A diagnostic must not write into the store it is diagnosing.

⚠ THIS IS WHERE THE `unknown` SESSION CAME FROM, AND IT WAS NEVER CURSOR.

The story attached to it was that Cursor names its session `conversation_id`,
the claude-code adapter reads `session_id`, and Cursor's payloads therefore pile
up under the literal fallback `unknown`. The evidence offered was 62 records on
this machine. **The evidence was real and the explanation was wrong.**

What those 62 records actually are, established by exact attribution rather than
by plausibility:

    every one   kind=TOOL · tool_name=None · command=None · paths=[]
                ALLOW with rule_id=None
    every one   cwd = the CHECKOUT, guard_version `uninstalled` or absent
    every one   action_hash b658d97d… — which is EXACTLY
                fingerprint(claude_code.parse({})), the empty payload
    and         running one preflight took the file from 62 lines to 63

`tools/preflight.py::check_entry_runnable` drove the real entry point with empty
stdin and passed **no `env`**, so it inherited `STING_SESSION_ROOT` from
`~/.sting/env` and wrote a decision record into the developer's live store. Once
per preflight — and `install.py` runs a preflight every time.

⚠ AND THE MACHINE HAS 4,262 RECORDS WITH NOT ONE `agent: cursor`. Cursor's hook
has never fired here at all, so the phenomenon the records were said to prove has
never been observed on this machine.

`check_end_to_end` and `check_semantic` already isolate exactly this way. This
was the one probe that did not, which is why nothing caught it: the two checks
that were *about* writing records were careful, and the one that was about
"does it start" was not.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _probe_functions(source: str) -> list:
    """(name, body) for every preflight function that drives the real entry
    point through a subprocess.

    ⚠ PER FUNCTION, NOT PER LINE WINDOW. A fixed window around the `ENTRY`
    reference flagged `check_semantic`, which builds its isolated env a dozen
    lines earlier — a false positive from a scan that could not see the whole
    subject. A function is the unit the env is built in, so it is the unit to
    read.
    """
    import ast

    tree = ast.parse(source)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        body = ast.get_source_segment(source, node) or ""
        if "subprocess.run" in body and "ENTRY" in body:
            out.append((node.name, body))
    return out


def test_every_probe_that_drives_the_entry_point_isolates_its_session_root():
    """⚠ THE STRUCTURAL FORM, over EVERY probe rather than the one that broke.
    Fixing only `check_entry_runnable` would leave the next probe somebody adds
    free to inherit the live store, which is exactly how this one arrived."""
    source = (ROOT / "tools" / "preflight.py").read_text(encoding="utf-8")
    probes = _probe_functions(source)

    assert probes, "no probe found — this test has lost its subject"
    for name, body in probes:
        assert "STING_SESSION_ROOT" in body, (
            f"tools/preflight.py::{name} drives the entry point without naming "
            f"STING_SESSION_ROOT, so it inherits the developer's live store and "
            f"writes a real decision record into it")


def test_a_preflight_run_writes_nothing_into_the_session_root_it_was_given():
    """⚠ THE BEHAVIOURAL FORM, and the only one that could have caught it.
    The structural check above reads text; this runs the thing.

    A session root is supplied and must come back EMPTY — preflight builds its
    own temp roots for the probes that need one, and must not write into the
    root it inherits.
    """
    import tempfile

    given = Path(tempfile.mkdtemp(prefix="sting-preflight-inherit-"))
    env = dict(os.environ,
               STING_SESSION_ROOT=str(given),
               STING_OBSERVE="1",
               HOME=str(given))          # no real ~/.sting/env in the way

    subprocess.run([sys.executable, str(ROOT / "tools" / "preflight.py"),
                    "--agent", "claude-code"],
                   capture_output=True, text=True, env=env, timeout=180)

    written = sorted(p.name for p in given.rglob("*.jsonl"))
    assert not written, (
        f"preflight wrote {written} into the session root it was handed. A "
        f"diagnostic that leaves records behind puts its own probes into the "
        f"evidence a reader is trying to judge.")


def test_the_empty_payload_still_lands_in_the_fallback_session():
    """⚠ THE FALLBACK ITSELF IS UNCHANGED, AND THAT IS DELIBERATE. This pass
    fixed WHO WAS CALLING IT, not the fallback — the adapter change that was
    asked for rests on a Cursor payload nobody has captured. What the fallback
    does is pinned here so the next pass starts from a fact.

    ⚠ AND IT IS NOT ONE ADAPTER. All five emit the same literal `unknown` for a
    payload with no session id, so the bucket aggregates every such failure
    across every agent into one session name — which is indistinguishable from
    a real session that happens to be called `unknown`.
    """
    from adapters import antigravity, claude_code, codex, copilot, cursor

    for module in (claude_code, cursor, codex, copilot, antigravity):
        action = module.parse({})
        assert action.session_id == "unknown", (
            f"{module.AGENT} no longer falls back to 'unknown' — if a "
            f"per-invocation unresolved id landed, re-read "
            f"docs/49-the-unknown-session.md before changing this")


def test_the_62_records_are_the_empty_payload_and_not_a_cursor_payload():
    """⚠ THE ATTRIBUTION, AS AN ASSERTION. The fingerprint of the empty payload
    is what every one of those records carried; a Cursor payload — which names
    its session `conversation_id` and carries a command — cannot produce it."""
    from adapters import claude_code, cursor
    from core.allow_once import fingerprint

    empty = fingerprint(claude_code.parse({}))
    assert empty == ("b658d97d11a13e61de4714f2d45a738a740a73b120b9cf08d3bc92e2"
                      "4e0ffc6b"), (
        "the empty-payload fingerprint changed — the attribution in "
        "docs/49-the-unknown-session.md was made against this value and should "
        "be re-derived rather than trusted")

    real_cursor = cursor.parse({
        "hook_event_name": "beforeShellExecution", "command": "git status",
        "cwd": "/w", "conversation_id": "c1", "workspace_roots": ["/w"]})
    assert fingerprint(real_cursor) != empty
    assert real_cursor.session_id == "c1", (
        "the cursor adapter already reads conversation_id — it is the "
        "claude-code adapter that does not, and that remains UNCONFIRMED as a "
        "cause of anything")
