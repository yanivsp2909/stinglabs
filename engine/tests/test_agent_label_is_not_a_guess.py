"""The agent name answers TWO questions, and it used to answer them with one
value. That is the whole bug.

    the LABEL     what the record CLAIMS ran. Evidence. A reader acts on it.
    the PARSER    which adapter reads the payload. Plumbing. Recoverable.

`DEFAULT_AGENT = "claude-code"` was both. An invocation arriving with no
`--agent` and no `STING_AGENT` got Claude Code's parser — which is the right
fallback, four of the five adapters are modelled on its shape — and Claude
Code's NAME, which is a fabricated observation. The failure mode is a WRONG
name, never a missing one, and wrong is worse: a missing label makes a reader
ask, a wrong one sends an investigation to a tool that was never running.

⚠ THE OTHER HALF, AND IT IS THE TRAP. "Record `unknown`" must not become "have
no adapter". A hook with no parser produces no verdict at all, so a fix that
made the label honest by leaving the payload unparsed would trade a wrong label
for NO GUARD — a strictly worse outcome, and one that would look like a
successful fix in every test that only reads the label.

So there are THREE states, and the middle one is not folded into the third:

    declared and known    --agent cursor    cursor's parser  · label "cursor"
    declared and UNKNOWN  --agent cursur    REFUSED, exit 2  · unchanged
    not declared at all   (nothing)         fallback parser  · label "unknown"

This is the same discipline `core/purpose.py` holds for `purpose`: absence stays
absent all the way to the reader, and is never coerced into the common case.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import hook_entry
import sting_hook
from core import engine
from core.types import Decision, Verdict

ROOT = Path(__file__).resolve().parent.parent


def payload(tool="Bash", tool_input=None):
    return json.dumps({"session_id": "s-label", "cwd": "/tmp",
                       "tool_name": tool,
                       "tool_input": tool_input or {"command": "ls"}})


# ═══════════════════════════════════════════════════════ 2.1 · the label ══

def test_an_unlabelled_invocation_records_unknown_not_a_default(monkeypatch):
    """⚠ TASK 2.1. The claim in the record must be the claim somebody made."""
    seen = []
    monkeypatch.setattr(engine, "decide",
                        lambda a, s, w: seen.append(a) or Verdict(Decision.ALLOW, None, None))

    hook_entry.run(payload(), agent=hook_entry.pick_agent([]))

    assert seen and seen[0].agent == "unknown", (
        f"an invocation that named no agent was labelled {seen[0].agent!r}")


def test_the_label_is_unknown_all_the_way_into_the_written_record(tmp_path,
                                                                   monkeypatch):
    """Not just the in-memory Action. A field that is honest in the object and
    coerced on the way to disk is the same bug one layer down."""
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    monkeypatch.delenv("STING_AGENT", raising=False)

    out, err, code = hook_entry.run(payload(), agent=hook_entry.pick_agent([]))
    assert code == 0, err

    logs = list(tmp_path.glob("*.jsonl"))
    assert logs, err
    records = [json.loads(l) for l in logs[0].read_text().splitlines() if l.strip()]
    assert records, "nothing was recorded"
    assert {r["agent"] for r in records} == {"unknown"}, records


def test_a_declared_agent_is_still_its_own_name(monkeypatch):
    """The fix must not make every label unknown — that would destroy the field
    rather than repair it."""
    seen = []
    monkeypatch.setattr(engine, "decide",
                        lambda a, s, w: seen.append(a) or Verdict(Decision.ALLOW, None, None))

    hook_entry.run(json.dumps({"hook_event_name": "beforeShellExecution",
                               "command": "ls", "cwd": "/tmp",
                               "conversation_id": "c1"}), agent="cursor")

    assert seen and seen[0].agent == "cursor"


# ═════════════════════════════════════ 2.2 · the label and the parser split ══

def test_unknown_labels_the_record_and_still_gets_a_parser():
    """⚠ TASK 2.2, THE TRAP. `unknown` must not leave the hook without an
    adapter — that would be no guard at all, which is worse than a wrong name.
    """
    adapter, label = hook_entry.resolve_agent(hook_entry.UNKNOWN_AGENT)

    assert label == hook_entry.UNKNOWN_AGENT
    assert adapter is not None, "an unlabelled invocation has NO PARSER — no guard"
    assert adapter is hook_entry.ADAPTERS[hook_entry.FALLBACK_ADAPTER]


def test_an_unlabelled_invocation_still_reaches_a_verdict(monkeypatch):
    """The behavioural form of the same property: it must still DECIDE."""
    monkeypatch.setattr(engine, "decide",
                        lambda a, s, w: Verdict(Decision.DENY, "nope", "test_rule"))

    out, err, code = hook_entry.run(payload(), agent=hook_entry.pick_agent([]))

    assert code == 0, err
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny", (
        "an unlabelled invocation stopped blocking — the label change took the "
        "guard with it")


def test_the_two_constants_are_not_the_same_value():
    """⚠ THE STRUCTURAL PIN. If a later pass ever sets these equal again, the
    two questions are one value again and the bug is back in its original
    shape."""
    assert hook_entry.UNKNOWN_AGENT != hook_entry.FALLBACK_ADAPTER
    assert hook_entry.UNKNOWN_AGENT not in hook_entry.ADAPTERS, (
        "`unknown` is a LABEL. Registering it as an adapter key would make it "
        "selectable with `--agent unknown`, which is a declaration of nothing")
    assert not hasattr(hook_entry, "DEFAULT_AGENT"), (
        "`DEFAULT_AGENT` is back — one spelling that answers both questions is "
        "how they were welded together in the first place")


def test_a_typo_is_refused_rather_than_relabelled_unknown():
    """⚠ THE MIDDLE STATE. `--agent cursur` is somebody ASSERTING an agent this
    build cannot parse. Folding it into `unknown` would parse with the wrong
    adapter and record a shrug, hiding a broken install behind a plausible
    label."""
    adapter, label = hook_entry.resolve_agent("cursur")
    assert adapter is None and label == "cursur"

    out, err, code = hook_entry.run(payload(), agent="cursur")
    assert code == 2 and out == "" and "unknown agent" in err


# ═════════════════════════════════════════ both entry points, same answer ══

def test_the_thin_client_and_the_engine_agree_on_the_unlabelled_case():
    """⚠ `sting_hook` DUPLICATES `pick_agent` DELIBERATELY (it must not import
    the engine). If the copies disagree, WHICH PATH SERVED A CALL decides what
    the record claims ran — daemon-served one way, in-process fallback another.
    """
    for argv in ([], ["--agent", "cursor"], ["--agent=codex"], ["--other", "x"]):
        assert sting_hook.pick_agent(argv) == hook_entry.pick_agent(argv), argv
    assert sting_hook.UNKNOWN_AGENT == hook_entry.UNKNOWN_AGENT
    assert not hasattr(sting_hook, "DEFAULT_AGENT")


def test_sting_hook_holds_no_second_copy_of_the_fallback_adapter():
    """One place decides which adapter reads an unlabelled payload. A second
    copy here is a second thing that can disagree about it."""
    source = (ROOT / "sting_hook.py").read_text(encoding="utf-8")
    assert "FALLBACK_ADAPTER" not in source.replace(
        "# ⚠ AND THIS FILE DELIBERATELY HAS NO `FALLBACK_ADAPTER`.", "")


# ═══════════════════════════════════════════ the installer is unaffected ══

def test_every_installed_command_still_declares_its_agent():
    """⚠ WHAT THIS FIX DOES AND DOES NOT CHANGE FOR A REAL MACHINE. install.py
    passes `--agent` for every agent, so nothing an installer wires up becomes
    `unknown`. The label only goes unknown for a hand-run hook or an install
    predating that flag — which is exactly the population that was being
    mislabelled."""
    import install

    for agent in ("claude-code", "cursor", "codex", "copilot", "antigravity"):
        written = install.write_hook_config(
            agent, Path("/tmp/never-written/c.json"),
            Path("/opt/sting/current/sting_hook.py"), {}, dry_run=True)
        assert f"--agent {agent}" in written["command"], written


def test_as_a_real_subprocess_with_no_flag(tmp_path):
    """End to end, through the process boundary — argv and env, not a function
    call."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("STING_")}
    env["STING_SESSION_ROOT"] = str(tmp_path)
    env["STING_OBSERVE"] = "1"
    env["HOME"] = str(tmp_path)          # no real ~/.sting/env in the way

    done = subprocess.run([sys.executable, str(ROOT / "hook_entry.py")],
                          input=payload(), capture_output=True, text=True,
                          env=env, timeout=60)

    assert done.returncode == 0, done.stderr
    logs = list(tmp_path.glob("*.jsonl"))
    assert logs, done.stderr
    records = [json.loads(l) for l in logs[0].read_text().splitlines() if l.strip()]
    assert records and {r["agent"] for r in records} == {"unknown"}, records
