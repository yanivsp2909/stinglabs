#!/usr/bin/env python3
"""Install Sting. One command, and it prints everything it did.

    python3 install.py                    install or reinstall
    python3 install.py --status           what is installed, and any drift
    python3 install.py --uninstall        take it all away
    python3 install.py --dry-run          say what it would do, change nothing

Everything it needs it will ask for or propose. The one thing it will not do is
decide your trust boundary for you — see `--roots`.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ⚠ THE VERSION FLOOR MUST BE HERE, ABOVE THE FIRST PROJECT IMPORT, AND IT WAS
# NOT. `check_python()` exists a few lines below and prints a message that tells
# the person exactly what to install — and NOTHING COULD EVER REACH IT, because
# it is called from inside `do_install()` while `from core import wire` on the
# next line already imported `core.types`, which does `from enum import StrEnum`
# and raises on anything older than 3.11.
#
# ⚠ FOUND BY INSTALLING FROM THE ARCHIVE INTO A CLEAN HOME, NOT BY A TEST, and
# it is the FIRST COMMAND the README tells a stranger to run. On macOS
# `/usr/bin/python3` is 3.9, so unless a newer interpreter precedes it on PATH
# this is what a stranger got:
#
#     Traceback (most recent call last):
#       File ".../install.py", line 23, in <module>
#         from core import wire
#       ...
#       File ".../core/types.py", line 29, in <module>
#         from enum import StrEnum
#     ImportError: cannot import name 'StrEnum' from 'enum'
#       (/Applications/Xcode.app/.../python3.9/enum.py)
#
# A traceback naming Xcode, from a product they have not started using. The
# message that should have printed even PREDICTS this failure — "it fails at
# IMPORT" — and it was written below the import that fails.
#
# `hook_entry.py` has had the correct shape all along and says why; this is the
# same block, in the second entry point, which nobody checked. No syntax newer
# than the oldest interpreter that could reach it, and no project import above
# it. `check_python()` stays: it is the same floor stated once for the
# already-imported case, and `tests/test_install_refuses_an_old_python.py`
# pins the two together.
if sys.version_info < (3, 11):
    sys.stderr.write(
        "sting: needs Python 3.11 or newer (StrEnum); this is %d.%d at %s\n"
        "  fix    install a newer Python and re-run this with it:\n"
        "           python3.12 install.py\n"
        "  why    the engine uses StrEnum, which arrived in 3.11. On an older\n"
        "         interpreter it fails at IMPORT, so nothing here can run.\n"
        % (sys.version_info[0], sys.version_info[1], sys.executable))
    raise SystemExit(2)

from core import hook_configs, org_policy, policy, wire        # noqa: E402
from core.display import visible                                # noqa: E402
from installer import (agent_status, cleanup, console, detect, messages,  # noqa: E402
                       place, prepare, recorded, supervisor)
from installer import enrol as enrol_client                     # noqa: E402
from shipper import service                                     # noqa: E402
from shipper import config as shipper_config                   # noqa: E402
from shipper import fingerprint_key                            # noqa: E402


ENV_FILE = Path.home() / ".sting" / "env"


def say(text=""):
    # ⚠ SHOWN, SO VISIBLE (item C, docs/110 §C): the installer quotes paths and
    # hook commands, which may hold bidi, zero-width or control characters.
    print(visible(text, multiline=True))


def head(title):
    say()
    say(title)
    say("─" * len(title))


# ─────────────────────────────────────────────────────────────────── the steps

def check_python() -> None:
    if sys.version_info[:2] < messages.MIN_PYTHON:
        say(messages.wrong_python())
        raise SystemExit(2)


def choose_agents(requested) -> list:
    found = detect.agents_present()
    if requested:
        named = []
        for a in requested:
            if a in detect.AGENT_CONFIGS:
                config, user_level = detect.config_for(a)
                named.append({"agent": a, "evidence": "named with --agent",
                               "config": str(config), "user_level": user_level})
        found = [f for f in found if f["agent"] in requested] or named
    if not found:
        say(messages.no_agent_found(
            [m for markers in detect.agent_markers().values() for m in markers]))
        raise SystemExit(2)
    return found


def check_roots(value: str) -> list[dict]:
    """Every declared root, and whether it is ACTUALLY A DIRECTORY on this box.

    ⚠ WHAT AN UNCHECKED ROOT COSTS, MEASURED. A real Windows install declared
    `C:\\Users\\<name>\\Projects`, which was not there. `probes.project_roots`
    keeps only entries that `is_dir()`, so the list resolved to nothing and the
    boundary fell back to the single git repo containing cwd — the 74-of-89
    denial condition. In observe mode nothing was blocked, so the whole failure
    was invisible except for one preflight line, and every verdict that machine
    recorded is labelled against the wrong boundary until it re-installs.

    ⚠ AND THE PARTIALLY-MISSING CASE IS WORSE, WHICH IS WHY THIS IS PER ENTRY
    AND NOT A YES/NO. `project_roots` drops missing entries and returns the
    survivors WITH NO NOTE — a note is attached only when NOTHING survives. So
    declaring four roots of which one is a typo silently narrows the boundary to
    three and says nothing, anywhere, ever. This is the only place that can see
    the difference, because it is the only place that has the list the human
    typed rather than the list that survived.

    ⚠ THE SPLITTER IS THE ENGINE'S, NOT A SECOND COPY. A check that restates a
    parser's rule is a second copy of that parser and drifts from it — that is
    exactly how preflight came to fail a correct Windows value.

    Reports; decides nothing. See `report_roots` for the refusal question.
    """
    from core import probes

    out = []
    for path in probes.split_roots(value or ""):
        expanded = Path(path).expanduser()
        out.append({"path": path, "exists": expanded.is_dir(),
                     "hint": _root_hint(path)})
    return out


def _root_hint(path: str) -> str:
    """Why a missing root might be missing, when the shape says something.

    ⚠ IT DIAGNOSES AND DOES NOT REWRITE. Cursor reports a Windows workspace as
    the URI `/C:/Users/<name>/project`, and somebody copying that into `--roots`
    declares a boundary no filesystem has. `adapters/_common._from_uri` is the
    ONE place that converts that form, and it is CALLED here rather than
    restated — a second normaliser could disagree with the first, and the value
    written is deliberately left exactly as it was typed. Saying "you meant
    this" is help; silently writing something the operator did not declare is
    the installer choosing the trust boundary, which this project does not do.
    """
    from adapters import _common

    native = _common._from_uri(path)
    if native != path and Path(native).expanduser().is_dir():
        return (f"this is a Cursor/VS Code URI. The native path exists: "
                f"{native}")
    if native != path:
        return f"this looks like a Cursor/VS Code URI for {native}"
    return ""


def report_roots(value: str, where: str = "") -> list[dict]:
    """Print each declared root and whether it is there. NEVER refuses.

    ⚠ REPORT, DO NOT REFUSE — AND THE REASON IS NOT SOFTNESS. A missing root is
    a typo, a repo not cloned yet, or a drive not mounted. None of those is an
    attack, and an installer that dies on one leaves the machine with NO guard
    at all rather than a guard with a narrow boundary — strictly the worse of
    the two outcomes. The same rule the whole installer already follows for a
    network home and a Windows interpreter: reporting is the whole job.

    Returns the rows so the caller can restate them where they will be read.
    """
    rows = check_roots(value)
    if not rows:
        return rows
    for row in rows:
        mark = "ok     " if row["exists"] else "MISSING"
        say(f"      [{mark}] {row['path']}")
        if row["hint"]:
            say(f"                {row['hint']}")
    missing = [r for r in rows if not r["exists"]]
    if not missing:
        return rows
    say()
    if len(missing) == len(rows):
        say(f"  ⚠ NONE of the {len(rows)} declared root(s) exist, so the trust")
        say(f"    boundary falls back to the single git repository containing")
        say(f"    the working directory. That is the state that produced 74 of")
        say(f"    89 secret-rule denials in one measured period — every edit to")
        say(f"    a sibling repo read as leaving the project.")
    else:
        say(f"  ⚠ {len(missing)} of {len(rows)} declared root(s) DO NOT EXIST.")
        say(f"    They are dropped silently at runtime, so the boundary is")
        say(f"    NARROWER than what you declared and nothing else will say so.")
    say(f"    Nothing is blocked by this — the install continues. Fix it with:")
    say(f"      python3 install.py --roots '<corrected list>'")
    if where:
        say(f"    ({where})")
    return rows


def confirm_roots(args, carried: dict | None = None) -> str:
    """⚠ SHOWN BEFORE IT IS WRITTEN. A trust boundary is a declaration.

    ⚠ A DECLARATION ALREADY MADE IS REMEMBERED, WHICH IS NOT THE SAME AS
    INFERRING ONE. Carrying a previously confirmed boundary forward is not the
    installer choosing what the developer trusts from a directory listing — it
    is the installer not throwing away an answer they gave. A non-interactive
    re-run used to decline and leave the boundary UNSET, at a measured cost of
    74 of 89 denials.
    """
    carried = carried or {}
    proposal = detect.propose_roots()
    head("Trust boundary — STING_ROOTS")
    say("  Repositories found beside this checkout:")
    for path in proposal["proposed"] or ["(none found)"]:
        say(f"      {path}")
    say(f"  searched   {proposal['searched']}")
    say(f"  why        {proposal['why']}")
    say(f"  if declined  {proposal['cost_if_declined']}")

    if args.roots is not None:
        say(f"  → using --roots: {args.roots or '(empty)'}")
        return args.roots
    if carried.get("STING_ROOTS"):
        say(f"  → carried forward from {recorded.ENV_FILE}:")
        say(f"      {carried['STING_ROOTS']}")
        say(f"    pass --roots to change it, or --roots '' to clear it")
        return carried["STING_ROOTS"]
    if args.yes:
        say("  → accepted (--yes)")
        return proposal["value"]
    if not sys.stdin.isatty():
        say("  → NOT accepted: no terminal to ask, and this is never inferred.")
        say(messages.roots_declined(proposal))
        return ""
    answer = input("  Declare these as your project? [y/N] ").strip().lower()
    if answer in ("y", "yes"):
        return proposal["value"]
    say(messages.roots_declined(proposal))
    return ""


def check_collector(url, token, device) -> str:
    """Reachable, and this token works. Returns "" when fine, else it exits."""
    if not url:
        return ""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/healthz", timeout=10):
            pass
    except Exception as exc:                                     # noqa: BLE001
        say(messages.collector_unreachable(url, str(getattr(exc, "reason", exc))))
        raise SystemExit(2)

    # An empty batch is the cheapest authenticated call there is: it proves the
    # token before anything is written into a hook config.
    probe = json.dumps({
        "wire_version": wire.WIRE_VERSION, "device_id": device,
        "session_id": "install-probe",
        "tier": wire.MASKED,
        # ⚠ DECLARED, SO NOTHING DOWNSTREAM HAS TO GUESS FROM THE SESSION NAME.
        # This is the purest case of the problem the field exists for: zero
        # records, one session, and indistinguishable from a real session that
        # happened to ship nothing. A receiver that classified it by the string
        # "install-probe" would be inferring intent from a name the sender chose.
        "purpose": wire.INSTALL_PROBE,
        "seq_range": None, "continues_from": "0" * 64,
        "manifest": {"record_count": 0, "events": {}, "date_range": None,
                      "agent": None, "os": "", "python": "", "guard_ref": "",
                      "canary_present": False},
        "provenance": {}, "records": [],
        "signature": {"alg": None, "key_id": None, "value": None, "covers": ""},
    }).encode()
    request = urllib.request.Request(
        f"{url.rstrip('/')}/v1/batches", data=probe, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"})
    try:
        urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            say(messages.bad_token(url))
            raise SystemExit(2)
    except Exception as exc:                                     # noqa: BLE001
        say(messages.collector_unreachable(url, str(exc)))
        raise SystemExit(2)
    return ""


def _install_fingerprint_key(key_path: Path) -> None:
    """Make the fingerprint key if missing, keep it if present, and say which
    (shipper/fingerprint_key.py). ⚠ A NEW KEY OVER SESSIONS KEYED WITH AN OLD ONE
    OPENS A GAP IN EACH: the shipper never makes one then; a person re-running
    this does, and is told what it costs. Never prints the key."""
    record = fingerprint_key.read_record(key_path)
    try:
        made = fingerprint_key.create_if_missing(key_path)
    except OSError as exc:
        say(f"  ⚠ fingerprint key could not be made at {key_path}: {exc}. The "
            f"shipper makes it before its first send.")
        return
    key = fingerprint_key.load(key_path)
    if key is None:
        say(f"  ⚠ fingerprint key {key_path} does not hold a key (a link is never "
            f"followed) and is not replaced: nothing ships until it does. Move it "
            f"aside and re-run install.py.")
        return
    if record is not None and record["sessions"] is None and not made:
        # ⚠ NOT A NEW KEY: the key was kept. Nothing bridges while the record
        # cannot be read (a session shipped before the key shows one gap), and
        # a person decides whether to start a new one.
        say(f"  ⚠ fingerprint key's record {key_path.parent / fingerprint_key.RECORD_NAME} "
            f"cannot be read and is left as it is: no session bridges to keyed while "
            f"it is so. Move it aside and re-run install.py to start a new one.")
        say(f"  fingerprint key {key_path}  (kept)")
        return
    current = fingerprint_key.key_id(key)
    changed = (record is not None and record["key"] != current
               and record["sessions"] != [])
    if record is None or record["key"] != current:
        try:
            fingerprint_key.reset_record(key_path)
        except OSError as exc:
            say(f"  ⚠ fingerprint key's record {key_path.parent / fingerprint_key.RECORD_NAME} "
                f"could not be written ({type(exc).__name__}): the shipper may hold "
                f"every record until it can be. Re-run install.py then.")
    _say_fingerprint_key(key_path, keyed_with=record["sessions"] if changed else [],
                         made=made)


def _say_fingerprint_key(key_path: Path, *, keyed_with: list | None, made: bool) -> None:
    """What became of the key: made, kept, or NEW over sessions keyed with an
    old one (`keyed_with`: those sessions, None when its record could not be
    read). Never the key."""
    if keyed_with is None:
        say(f"  ⚠ fingerprint key {key_path}: a NEW fingerprint key. Its record "
            f"({fingerprint_key.RECORD_NAME}) could not be read, so which sessions "
            f"were keyed with the old one is not known: each will show a gap at its "
            f"next batch.")
    elif keyed_with:
        say(f"  ⚠ fingerprint key {key_path}: a NEW fingerprint key. The "
            f"{len(keyed_with)} session(s) this laptop shipped keyed with the old one "
            f"will each show a gap at their next batch.")
    elif made:
        say(f"  fingerprint key {key_path}  (made, 0600 — never sent, never printed)")
    else:
        say(f"  fingerprint key {key_path}  (kept — the key this laptop's shipped "
            f"records are keyed with)")


def write_env(values: dict) -> Path:
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"export {k}={_quote(v)}" for k, v in sorted(values.items()))
    ENV_FILE.write_text(
        "# written by install.py — sourced by the hook wrapper and the shipper\n"
        + body + "\n", encoding="utf-8")
    ENV_FILE.chmod(0o600)          # it holds the device token
    return ENV_FILE


def _quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


# ⚠ CURSOR'S SCHEMA IS NOT CLAUDE CODE'S, AND WRITING CLAUDE CODE'S MEANT THE
# HOOK NEVER FIRED. Verified by reading real `hooks.json` files on this machine
# (see docs/25-cursor-hooks.md): a top-level `version`, `hooks` keyed by
# camelCase EVENT NAMES, each an array of `{command, event?, description?}`.
# There is no `matcher` and no `{"type": "command"}` wrapper anywhere.
#
# ⚠ THIS COMMENT USED TO SAY `preToolUse` WAS NOT A CURSOR EVENT. IT IS ONE.
#
# The claim was "it appears in no real Cursor config read, and one comprehensive
# third-party file enumerates fifteen events without it". That was true of the
# CONFIG FILES and false about Cursor. Read out of Cursor 3.7.27's own shipped
# code on this machine — `extensions/cursor-agent-exec/dist/main.js` — the hook
# registry has TWENTY-ONE events and `preToolUse` is among them, with a handler
# that returns a `permission`. It can block.
#
# `PreToolUse` (Claude Code's spelling) is still not a Cursor event: Cursor
# TRANSLATES it, via a map in the same file (`PreToolUse -> preToolUse`,
# `Bash -> Shell`, `Edit -> Write`, …). That map is also the mechanism behind
# the double-log — our Claude Code entry becomes a Cursor hook.
#
# So removing the old `PreToolUse` entry below is still right, and it is right
# for a different reason than the one recorded here for two passes. The full
# evidence, and why `preToolUse` is not wired YET, is docs/45-cursor-events.md.
#
# WHICH EVENTS, AND WHY:
#
#   beforeShellExecution  EXEC. What the engine models, and the entire I02 chain
#                         (cat / cp / git add / git push) arrives here.
#   beforeReadFile        READ. ⚠ WIRED DESPITE THE VOLUME, because this is how
#                         a SOURCE is created. Without it, Cursor's own read of
#                         `.env` is invisible, the session never learns it holds
#                         a credential, and the push is allowed. Rule #2 says
#                         labels restrict exits and never reads — so the engine
#                         SEES this event and does not block on it.
#   beforeMCPExecution    TOOL. MCP is a real egress channel.
#
# NOT WIRED, each for a stated reason rather than by omission:
#
#   preToolUse            A REAL EVENT THAT CAN BLOCK, and the only before-event
#                         that sees a file WRITE — the gap docs/42 A.4 names as
#                         unfixable. NOT WIRED YET, for two reasons that one
#                         capture session settles: whether it ALSO fires
#                         alongside the three above (if so it doubles every
#                         record from one agent), and what `tool_input` holds
#                         per tool, which a WRITE verdict depends on. Wiring it
#                         is a coverage change, not a transport fix.
#                         docs/45-cursor-events.md.
#   after*                CANNOT BLOCK. Wiring one would put a verdict on the
#                         wire that Cursor ignores, which reads as coverage and
#                         is not. Named as a gap in docs/25-cursor-hooks.md.
#   before/afterTab*      Tab completion volume. A real gap, named there too.
# ⚠ EVENTS SPLIT INTO TWO KINDS, AND CONFLATING THEM IS THE MISTAKE A.4 WARNS
# AGAINST: a `before*` event can DENY (prevention); an `after*` event fires once
# the thing has already happened (observation only). Wiring an after* event buys
# a record, never a block, and it must never read as coverage.
#
# PREVENTION — these are where a verdict can stop something, so they are wired:
#   beforeShellExecution   EXEC. The I02 chain (cat / cp / git add / push).
#   beforeReadFile         READ. How a SOURCE is created — an untrusted read.
#   beforeMCPExecution     TOOL. MCP output is attacker-authorable content.
_CURSOR_EVENTS = ("beforeShellExecution", "beforeReadFile", "beforeMCPExecution")

# ⚠ NO `after*` EVENT IS WIRED, AND THE DECISION IS DELIBERATE — A.4.
#
# An after* event cannot block: it fires once the action is done, so a verdict
# there is a record Cursor ignores. Wiring one would read as coverage and would
# not be, which is worse than a gap a reader can see. `tests/
# test_hook_config_shapes.test_no_after_event_is_wired` pins this.
#
#   afterFileEdit   ⚠ AND THIS EXPOSES A REAL PREVENTION GAP, NAMED RATHER THAN
#                   PAPERED OVER WITH A RECORD. Cursor has no `beforeFileEdit`,
#                   so a file WRITE/EDIT is invisible to every before* event —
#                   a Cursor file write CANNOT BE BLOCKED today, on any platform.
#                   Wiring afterFileEdit would only RECORD it, dressing a
#                   prevention gap as observation. The gap belongs in the threat
#                   model (docs/22 §2.1), not behind an event that looks like a
#                   control and is not.
#   afterShellExecution / afterMCPExecution
#                   REDUNDANT — same action as their before* counterparts, which
#                   can also block. Wiring both would log one action TWICE under
#                   the cursor agent: the B.2 double-count, self-inflicted.
#   preToolUse      REDUNDANT with the before* events for the tools the engine
#                   models; same double-log risk.
#   Tab read/edit   inline completions, not tool calls. Payload shape unverified,
#                   volume enormous; capturing it is a measurement task (docs/34).
#   subagent events a subagent's own tool calls already raise the before* events.


def _cursor_entry(command: str, observe: bool) -> dict:
    """One Cursor hook entry.

    ⚠ `failClosed` TRACKS THE MODE, and is not a constant. Cursor treats a hook
    that errors or times out as a DENY when this is true.

        observe mode   failClosed FALSE. Observe mode's whole promise is that it
                       blocks nothing — proved on 7 failure paths including a
                       forced engine crash. `true` here would turn any crash
                       into a block and break that promise from outside the
                       engine, where none of those proofs reach.
        enforce mode   failClosed TRUE. A guard that fails open is not a guard,
                       and in enforce mode the operator has already accepted
                       that a refusal can interrupt them.

    ⚠ UNVERIFIED: `failClosed` was NOT present in any hooks.json read on this
    machine. It is written on the strength of Cursor's own documentation and a
    report of a live file. If Cursor rejects the key, remove it — the events
    above are the part that is verified.
    """
    return {"command": command, "failClosed": not observe}


def _is_windows() -> bool:
    import platform
    return platform.system() == "Windows"


def cursor_bridge_path(current: Path) -> Path:
    """Where the placed bridge is, given the resolved install directory.

    ⚠ INSIDE THE VERSION DIRECTORY, AND IT USED TO BE BESIDE THE POINTER.
    `place.PAYLOAD` now ships `installer/cursor_bridge.ps1`, so the bridge is
    placed by the same code that places the engine, is covered by the same
    missing-payload refusal, and is removed by the same uninstall. It also
    means the bridge and the `sting_hook.py` it spawns are ONE ARTIFACT: the
    bridge resolves its sibling, so a v1 bridge cannot drive a v2 entry.

    `current` is the RESOLVED directory (`place.current_dir()`), never
    `<prefix>/current` — on Windows `current` is a pointer FILE, so that path
    cannot exist, and building it is how a previous install wrote a hook command
    naming a file that was never there.
    """
    return current / "installer" / "cursor_bridge.ps1"


def _cursor_bridge_command(entry: Path, agent: str) -> str:
    """The PowerShell bridge invocation Cursor runs on Windows.

    ⚠ WINDOWS + CURSOR ONLY, AND THE TRANSPORT HALF IS UNVERIFIED HERE. Cursor's
    hook pipeline breaks a plain `python sting_hook.py` two independent ways
    (RC1: a PowerShell-hostile command; RC2: a BOM-corrupted, unreliably-
    delivered stdin). The bridge survives both — see
    `installer/cursor_bridge.ps1`. This command carries NO settings and NO
    secrets: everything is in the 0600 env file.

    ⚠ `entry` IS `<current>/sting_hook.py`, AND THE BRIDGE PATH IS DERIVED FROM
    IT rather than from `place.default_prefix()`. Same reason as everywhere else
    in this installer: two ways of naming the install directory is one chance
    for them to disagree, and the one that reads a global (the prefix) can
    disagree with the one the tree was actually placed at.

    ⚠ FORWARD SLASHES, DELIBERATELY. Git Bash — which is how a great many
    Windows developers run anything — backslash-escapes `C:\\Users\\…` when this
    string passes through it, and `.NET` and PowerShell both accept `/` on
    Windows. The quotes around the path survive a directory with a space.
    """
    bridge = str(cursor_bridge_path(entry.parent)).replace("\\", "/")
    return (f"powershell -NoProfile -ExecutionPolicy Bypass "
            f"-File \"{bridge}\" -Agent {agent}")


def write_hook_config(agent: str, config_path: Path, entry: Path,
                       env: dict, dry_run: bool, observe: bool = True) -> dict:
    """Point one agent at the installed hook. Merges; never overwrites."""
    # ⚠ NO ENVIRONMENT PREFIX ANY MORE. The hook reads `~/.sting/env` itself —
    # see envfile.py — so the command carries only the invocation. This fixes
    # RC1 of the Cursor-on-Windows failure: a POSIX `KEY='value'` prefix is
    # parsed by PowerShell as a command NAME, so every native Windows install
    # errored, and `failClosed:false` made the error a silent allow. It also
    # stops hooks.json — a world-readable file the agent can read — from
    # carrying settings that belong in a 0600 file. `env` is kept as a parameter
    # because the CALLER still writes it to `~/.sting/env`; it is simply no
    # longer inlined into the command.
    #
    # ⚠ `--agent` IS ALWAYS PASSED, FOR EVERY AGENT. `hook_entry.pick_agent`
    # DEFAULTS to claude-code when the flag and STING_AGENT are both absent — it
    # does not sniff the payload — so every record Cursor produced was labelled
    # `claude-code`. A wrong agent label is worse than none: the panel refuses to
    # guess precisely so that a label can be trusted, and a record attributed to
    # the wrong tool sends an investigation to the wrong place.
    command = _cursor_bridge_command(entry, agent) if (
        agent == "cursor" and _is_windows()) else " ".join(
        [_quote(sys.executable), _quote(str(entry)), "--agent", agent])
    # ⚠ D1: A FILE THIS CANNOT READ IS NEVER REWRITTEN. It used to become `{}`
    # plus the guard's entry, which for ~/.claude/settings.json wiped the
    # person's permissions, env and model with no copy. Now it is copied beside
    # itself, left exactly as it was, and this agent is not hooked, which
    # `hook_config_report` says in the line a person reads.
    existing, unreadable = _read_hook_config(config_path)
    if unreadable:
        backup = None if dry_run else _backup(config_path)
        return {"agent": agent, "path": str(config_path), "written": False,
                "command": command, "skipped": unreadable,
                "backup": str(backup) if backup else None}
    if dry_run:
        return {"agent": agent, "path": str(config_path), "written": False,
                 "command": command}
    config_path.parent.mkdir(parents=True, exist_ok=True)
    hooks = existing.setdefault("hooks", {})

    if agent == "cursor":
        existing.setdefault("version", 1)
        for event in _CURSOR_EVENTS:
            entries = hooks.setdefault(event, [])
            # ⚠ REPLACE OUR OWN ENTRY, LEAVE EVERYTHING ELSE. Ours is found by
            # its marker, never by the word "sting" (D2, hook_configs).
            entries[:] = [e for e in entries if not hook_configs.is_sting_entry(e)]
            entries.append(_cursor_entry(command, observe))
        # A stale Claude-Code-shaped entry from a previous install would sit
        # there forever under an event Cursor never raises, looking like
        # coverage. Remove it.
        for dead in ("PreToolUse", "preToolUse"):
            if isinstance(hooks.get(dead), list):
                hooks[dead] = [e for e in hooks[dead]
                                if not hook_configs.is_sting_entry(e)]
                if not hooks[dead]:
                    hooks.pop(dead)
    else:
        entries = hooks.setdefault("PreToolUse", [])
        # ⚠ REPLACE OUR OWN ENTRY, LEAVE EVERYTHING ELSE. An installer that
        # rewrote the file would delete hooks the developer wrote themselves —
        # and they would find out at the worst possible moment.
        #
        # ⚠ BY THE MARKER, NEVER THE WORD (D2). A substring test for "sting"
        # over the dumped entry also matched a person's own `npm run testing`,
        # `existing.sh` or ~/sting/ hook, and deleted it on every reinstall; and
        # it missed the Windows Cursor bridge under a STING_INSTALL_ROOT without
        # that word.
        entries[:] = [e for e in entries if not hook_configs.is_sting_entry(e)]
        entries.append({"matcher": "*",
                         "hooks": [{"type": "command", "command": command}]})

    config_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return {"agent": agent, "path": str(config_path), "written": True,
             "command": command}


def _read_hook_config(config_path: Path) -> tuple[dict | None, str | None]:
    """(the config, why it must not be touched). A missing file is an empty
    config. A file that is not JSON, not an object, or whose `hooks` or any of
    its events is not the shape every agent here uses, is one to leave alone."""
    if not config_path.exists():
        return {}, None
    try:
        existing = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"is not valid JSON (line {exc.lineno}: {exc.msg})"
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"cannot be read ({exc})"
    if not isinstance(existing, dict):
        return None, "is JSON but not an object"
    hooks = existing.get("hooks", {})
    if not isinstance(hooks, dict):
        return None, 'has a "hooks" that is not an object'
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            return None, f'has a "hooks.{event}" that is not a list'
    return existing, None


def _backup(config_path: Path) -> Path | None:
    """A copy beside the file, mode kept (it may hold a token), never over an
    earlier copy. None when even the copy fails."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup = config_path.with_name(f"{config_path.name}.sting-backup-{stamp}")
    count = 1
    while backup.exists():
        backup = config_path.with_name(f"{config_path.name}.sting-backup-{stamp}-{count}")
        count += 1
    # ⚠ PRIVATE FROM ITS FIRST BYTE (security review). `shutil.copy2` creates
    # the copy under the umask and narrows the mode afterwards, so a 0600 file
    # spent a moment as a world-readable copy. Created 0600 and exclusively,
    # then given the original's mode and times.
    try:
        data = config_path.read_bytes()
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        shutil.copystat(config_path, backup)
    except OSError:
        return None
    return backup


def hook_config_report(agent: str, written: dict) -> list[str]:
    """What the installer says about one agent's hook config. A skipped agent
    must not read like a hooked one."""
    if not written.get("skipped"):
        return [f"  {agent:14} {'wrote' if written['written'] else 'would write'}"
                f" {written['path']}"]
    kept = (f"Your file is untouched. A copy is at {written['backup']}."
            if written.get("backup") else "Your file is untouched.")
    return [f"  {agent:14} ✗ NOT HOOKED: {written['path']} {written['skipped']}.",
            f"                 {kept}",
            f"                 {agent} runs without the guard until the file is",
            f"                 fixed and install.py is run again."]


def unreadable_hook_config(config_path: Path) -> str | None:
    """Why uninstall could not clean this config, or None."""
    return _read_hook_config(config_path)[1] if config_path.exists() else None


def remove_hook_config(config_path: Path) -> bool:
    if not config_path.exists():
        return False
    existing, unreadable = _read_hook_config(config_path)
    if unreadable:
        return False
    hooks = existing.get("hooks")
    if not isinstance(hooks, dict):
        return False
    # ⚠ EVERY EVENT, NOT JUST `PreToolUse`. Cursor's entries live under
    # `beforeShellExecution` and friends, so an uninstall that only looked at
    # `PreToolUse` left the guard wired and reported success — the same class of
    # defect as the supervisor that reported a service it had not created.
    removed = False
    for event, entries in list(hooks.items()):
        if not isinstance(entries, list):
            continue
        kept = [e for e in entries if not hook_configs.is_sting_entry(e)]
        if len(kept) != len(entries):
            removed = True
            if kept:
                hooks[event] = kept
            else:
                hooks.pop(event)
    if not removed:
        return False
    config_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return True


# ────────────────────────────────────────────────────────────────── the command

def do_install(args) -> int:
    check_python()

    # ⚠ STAGE 0 — THE MACHINE ITSELF, BEFORE ANY OF THIS INSTALLER'S OWN WORK.
    # These five used to live in bootstrap.sh, a second file a person had to
    # know about and clone the right branch to get. They are the same five
    # questions, asked here, and each is still a question that can be asked
    # again: nothing below is written until they are answered.
    head("0 · This machine")
    checks = prepare.survey(args.scratch)
    for name in prepare.CHECKS:
        result = checks[name]
        say(f"  {name:10} {'OK  ' if result.ok else 'FAIL'}  {result.detail}")
        for line in result.lines:
            say(line)
    fatal = [n for n in prepare.CHECKS if checks[n].fatal]
    if fatal:
        say()
        say(f"  STOPPED at {fatal[0]}. Nothing has been written.")
        return 2
    # ⚠ AN ADVISORY CHECK IS REPORTED AND NEVER GATES, AND IT IS FILTERED HERE
    # RATHER THAN AT EACH USE. `node` failing used to stop the install dead —
    # measured from the release tarball on a clean Mac — over a toolchain the
    # shipped artifact does not contain and this installer never invokes. See
    # `prepare.Result.advisory`. Filtering once means the consent block, the
    # fix loop and the "still failing" gate all agree by construction.
    broken = [n for n in prepare.CHECKS
              if not checks[n].ok and not checks[n].advisory]
    noted = [n for n in prepare.CHECKS
             if not checks[n].ok and checks[n].advisory]
    # ⚠ EVERY ACTION THIS INSTALL TAKES ON THE MACHINE, COLLECTED FOR THE DONE
    # BLOCK. An unattended install must still be honest about what it changed,
    # where a person reads it rather than in scrollback they never see.
    machine_changes: list = []

    if noted:
        say()
        for name in noted:
            say(f"  ⚠ {name}: {checks[name].detail} — REPORTED, NOT BLOCKING.")
        say(f"    The guard is pure Python; the install continues.")
    if broken and not args.check_only:
        # ⚠ ADVISORY CHECKS HAVE FIXES TOO, AND ONE OF THEM INSTALLS A RUNTIME.
        # `broken` deliberately excludes advisory checks so they cannot block an
        # install — but `apply_fixes` walks every check, so `node`'s
        # `brew install node` ran INTERACTIVELY after a consent listing that
        # never mentioned it. The person consented to a shorter list than what
        # ran. Advisory fixes that reach outside our prefix are listed here.
        fixable = [n for n in broken if checks[n].fix]
        fixable += [n for n in prepare.CHECKS
                    if n not in fixable and checks[n].fix
                    and not checks[n].ok and checks[n].installs_software]
        say()
        if fixable:
            # ⚠ CONSENT ONCE, UP FRONT, FOR EVERYTHING — not a prompt per step.
            # A person answering four questions in a row stops reading by the
            # third, and the fourth is the one that installs a runtime.
            # ⚠ NAMED BEFORE IT HAPPENS, INCLUDING UNDER --yes. Split by what
            # each one touches, because they are not the same kind of act.
            outside = [n for n in fixable if checks[n].installs_software]
            confined = [n for n in fixable if not checks[n].installs_software]
            if confined:
                say("  This will change your machine, inside what you named:")
                for name in confined:
                    say(f"    {checks[name].fix_note}")
                    for argv in checks[name].fix:
                        say(f"        $ {' '.join(argv)}")
            if outside:
                say("  ⚠ AND THESE INSTALL OR RECONFIGURE SOFTWARE OUTSIDE")
                say("    ~/.sting — they are NOT run under --yes:")
                for name in outside:
                    say(f"    {checks[name].fix_note}")
                    for argv in checks[name].fix:
                        say(f"        $ {' '.join(argv)}")
                if args.yes:
                    say("    --yes means 'do not ask me'. It does not mean 'do")
                    say("    anything'. A security tool that installs software")
                    say("    on first run is the worst possible first")
                    say("    impression, so these are skipped and named.")
            say("  ⚠ some of these use sudo and your shell will ask for a")
            say("    password. That prompt is yours to answer; this will not.")
            if not args.yes and sys.stdin.isatty():
                if input("  Do all of that? [y/N] ").strip().lower() not in ("y", "yes"):
                    say("  declined — nothing was changed.")
                    return 2
            elif not args.yes:
                say("  → not accepted: no terminal to ask. Re-run with --yes,")
                say("    or run the commands above yourself.")
                return 2
            checks.update(prepare.apply_fixes(
                checks, args.scratch, say,
                unattended=args.yes, changed=machine_changes))
        still = [n for n in prepare.CHECKS
                 if not checks[n].ok and not checks[n].advisory]
        if still:
            say()
            say(f"  {len(still)} check(s) still failing: {', '.join(still)}")
            say("  Nothing has been installed. Fix what is named above and run")
            say("  this same command again — it will pick up here.")
            return 2
    if args.check_only:
        say()
        if broken:
            say(f"  --check-only: {len(broken)} check(s) failing, nothing fixed,")
            say("  nothing installed. Re-run without --check-only to fix them.")
            return 1
        say("  --check-only: all five pass. Nothing was installed.")
        return 0

    head("1 · Agents")
    agents = choose_agents(args.agent)
    chosen = {a["agent"] for a in agents}
    # ⚠ MISSES ARE PRINTED BESIDE HITS, AND THAT IS THE POINT. Reporting only
    # what was found has already cost an evening: a second developer had Cursor
    # installed, this installer did not list it because his marker directory was
    # not where AGENT_MARKERS says, and the run LOOKED successful because two
    # other agents were found. The only clue that `--agent cursor` was needed
    # was knowing the tool well enough to guess. A miss used to be printed only
    # when the count reached zero, which is the one case that is already obvious.
    for row in detect.agent_survey():
        if row["agent"] in chosen:
            say(f"  {row['agent']:14} FOUND      {row['evidence'] or '(named with --agent)'}")
            if not row.get("user_level", True):
                say(f"                 ⚠ this agent has no user-level hook config, "
                     f"so the entry goes in the CURRENT DIRECTORY and applies only "
                     f"to work done here: {row['config']}")
        elif row["present"]:
            say(f"  {row['agent']:14} found, NOT selected — you passed --agent, "
                 f"so only what you named is wired")
        elif row.get("windows_side"):
            # ⚠ FOUND ON THE WRONG SIDE OF THE BOUNDARY. Third instance of this
            # class. Reported, never used: a config on the Windows side belongs
            # to a Windows agent process, and a hook wired there would never
            # fire for the Linux session the developer works in.
            say(f"  {row['agent']:14} not found in Linux — but its config IS on "
                 f"the WINDOWS side:")
            say(f"                 {row['windows_side']}")
            say(f"                 you launched it from /mnt/c/… so it wrote "
                 f"there. The hook must run in Linux.")
            say(f"                 fix: run the agent from your Linux home "
                 f"(cd ~), let it write ~/{Path(row['looked_in'][0]).name}, "
                 f"then re-run this.")
        else:
            say(f"  {row['agent']:14} not found  looked in "
                 f"{', '.join(row['looked_in'])}")
    say("  ⚠ an agent listed as NOT FOUND may still be installed — detection is a")
    say("    marker directory, and yours may be elsewhere. Wire it explicitly:")
    say("        install.py --agent <name>")

    # ⚠ READ ONCE, BEFORE ANYTHING IS PLANNED, so the dry run and the real run
    # resolve from the same values. A --dry-run that shows a different plan from
    # the run that follows it is worse than none.
    carried = recorded.read()
    if carried:
        head("0 · Carried forward from your last install")
        say(f"  source     {recorded.ENV_FILE}")
        say(f"  ⚠ any flag you give BELOW overrides the value beside it. Nothing")
        say(f"    here is inferred — it is what this installer recorded last time.")
        for key in recorded.CARRIED:
            if key in carried:
                shown = "<set>" if "TOKEN" in key else carried[key]
                say(f"  {key:22} {shown}")
        say(f"  not carried  {', '.join(recorded.NEVER_CARRIED)}")
        say(f"  clear it     delete {recorded.ENV_FILE}, or pass the flag you want")

    roots = confirm_roots(args, carried)
    # ⚠ VALIDATED THE MOMENT IT IS DECIDED, WHATEVER DECIDED IT. Printed here
    # rather than inside `confirm_roots` because that function has four exits —
    # --roots, carried forward, --yes, and the interactive answer — and a check
    # that lives on one of four paths is a check three installs skip. Carrying
    # a boundary FORWARD is the path that most needs it: nothing re-examines a
    # value that was correct on the machine where it was first typed.
    root_rows = report_roots(roots, where="section 1, Trust boundary")

    head("2 · Scratch directories — STING_SCRATCH")
    scratch = detect.propose_scratch()
    say(f"  proposed   {scratch['value'] or '(nothing — see below)'}")
    say(f"  why        {scratch['why']}")
    # ⚠ THE EMPTY CASE GETS SENTENCES, NOT A DASH. "(none found)" reads as a gap
    # somebody should close, and the obvious way to close it is /tmp — which is
    # what this installer used to propose to everybody but its author.
    if scratch.get("note"):
        say(f"  note       {scratch['note']}")
    scratch_value, scratch_src = recorded.resolve(
        args.scratch, carried.get("STING_SCRATCH"), scratch["value"],
        key="STING_SCRATCH")
    if scratch_src.startswith("carried"):
        say(f"  using      {scratch_value}   <- {scratch_src}")

    head("3 · Identity, for redacting PUBLISHED artifacts")
    identity = detect.propose_identity()
    for value in identity["identifiers"]:
        say(f"  {value:28} from {identity['sources'][value]}")
    say(f"  used for       {identity['used_for']}")
    say(f"  NOT used for   {identity['not_used_for']}")

    head("4 · Collector")
    # ⚠ ENROLMENT RUNS HERE, BEFORE ANYTHING IS PLACED, AND THAT ORDERING IS THE
    # WHOLE SAFETY PROPERTY. Section 6 copies the tree and section 7 writes the
    # hook configs; a failure at this point therefore leaves the machine
    # UNCHANGED and UNGUARDED rather than installed and unable to ship. This
    # project has shipped a guard that reported success and guarded nothing
    # twice, and both times the cause was a step that failed after the point of
    # no return.
    #
    # ⚠ ONE STRING IS ALL A PERSON PASTES. The URL travels inside it, the org
    # comes from the enrolment document at the collector, and the device id
    # comes from this machine's hostname. Nothing else is typed.
    enrolled = None
    # ⚠ AN UPDATE MUST NOT RE-ENROL A MACHINE THAT ALREADY HAS AN IDENTITY,
    # AND THIS IS THE MISTAKE AN MDM MAKES AT SCALE. A fleet tool pushes ONE
    # command to fifty laptops; the natural command is the one from the rollout
    # runbook, and that one carries `--enrol`. Run again a month later as an
    # UPDATE, unchanged, it used to re-enrol every machine. Two shapes, both
    # bad, and which one you get depends on whether the secret is the same:
    #
    #   the SAME secret       the collector namespaces the device id by the
    #                         enrolment digest, so the id is identical and it
    #                         answers 409. The install then REFUSES AND EXITS 2
    #                         — so the update does not land, and fifty machines
    #                         silently stay on the old build.
    #   a DIFFERENT secret    a new rollout secret is a new digest, so the same
    #                         laptop proposes a DIFFERENT device id, mints a
    #                         second credential, and `enrolled` overwrites the
    #                         carried one. The machine keeps shipping — as a
    #                         NEW DEVICE, with its history split in two and
    #                         nothing anywhere saying they are one machine.
    #
    # And either way it spends a use from the cap, so a cap sized to the fleet
    # is exhausted by the second update and the machines at the end of the
    # rollout get 429.
    #
    # ⚠ SO A CARRIED TOKEN WINS OVER AN ENROLMENT STRING, and the string is
    # ignored rather than obeyed. That is the opposite of the rule everywhere
    # else in this file — an explicit flag normally wins — and the exception is
    # deliberate: every other flag names a SETTING, and this one would replace
    # an IDENTITY that has history behind it. `--re-enrol` is how somebody who
    # genuinely means it says so.
    already = (carried.get("STING_DEVICE_TOKEN") or "").strip()
    if args.enrol and already and not args.re_enrol:
        say(f"  ⚠ ALREADY ENROLLED — the enrolment string was IGNORED.")
        say(f"    this machine already holds a device token"
             + (f" for {carried.get('STING_DEVICE_ID')!r}"
                if carried.get("STING_DEVICE_ID") else "") + ",")
        say(f"    so this is an UPDATE and the credential is kept. Its history")
        say(f"    stays attached to the device it belongs to, and no use is")
        say(f"    spent from the enrolment secret's cap.")
        say(f"    ⚠ to genuinely move this machine to a new org or identity:")
        say(f"        python3 install.py --enrol <string> --re-enrol")
        args = _without_enrolment(args)

    # ⚠ ADDITIVE, PASTE-ONLY SIGNUP ENTRY. On an interactive install with no
    # enrolment string yet and no identity already, offer the browser-based
    # signup and take the enrolment string by PASTE. It only ever fills
    # `args.enrol`; the block below is the same handshake `--enrol` runs, so no
    # new way for a secret to reach install.py is introduced. See
    # `_maybe_browser_signup` for the interactive / no-browser / non-interactive
    # precedence.
    args = _maybe_browser_signup(args, bool(already))

    if args.enrol:
        try:
            enrol_url, enrol_secret = enrol_client.decode(args.enrol)
            proposed = args.device_id or enrol_client.propose_device_id()
            say(f"  enrolling   {enrol_url}")
            say(f"  as device   {proposed}   <- this machine's hostname")
            if args.dry_run:
                say("  would POST  /v1/enrol and store the token it returns")
            else:
                enrolled = enrol_client.enrol(
                    enrol_url, enrol_secret, proposed,
                    label=args.device_label or "")
                say(f"  enrolled    device {enrolled['device_id']!r}"
                     + (f" in org {enrolled['org']!r}" if enrolled["org"] else ""))
                say(f"  ⚠ the enrolment secret is NOT written anywhere. It is "
                     f"not needed again.")
        except enrol_client.Failure as failure:
            say()
            say(failure.render())
            return 2

    # ⚠ THE RULE: an explicit flag wins, an absent one is CARRIED FORWARD from
    # the recorded install, and anything carried is SAID SO rather than implied
    # by its absence. Before this, a re-run read these from the process
    # environment and nowhere else, so `install.py --collector-url <new>` on a
    # fresh shell kept the URL and DROPPED the token — silently, into a plan
    # that looked correct because every value in it was real.
    url, url_src = recorded.resolve(
        args.collector_url, carried.get("STING_COLLECTOR_URL"),
        os.environ.get("STING_COLLECTOR_URL", ""), key="STING_COLLECTOR_URL")
    token, token_src = recorded.resolve(
        args.device_token, carried.get("STING_DEVICE_TOKEN"),
        os.environ.get("STING_DEVICE_TOKEN", ""), key="STING_DEVICE_TOKEN")
    device, device_src = recorded.resolve(
        args.device_id, carried.get("STING_DEVICE_ID"),
        os.environ.get("STING_DEVICE_ID", "") or Path.home().name,
        key="STING_DEVICE_ID")
    if enrolled:
        # ⚠ WHAT WAS JUST MINTED WINS OVER ANYTHING CARRIED. A machine that
        # enrols is declaring a new identity; keeping a previous device id or
        # token beside it is how a machine ends up authenticating as one device
        # and reporting as another.
        url, url_src = enrolled["url"], "the enrolment string"
        token, token_src = enrolled["device_token"], "issued by enrolment"
        device, device_src = enrolled["device_id"], "assigned by the collector"

    # ⚠ HTTPS OR NOTHING (item E, docs/98), whichever source the URL came from —
    # a flag, a saved setting carried forward, or the environment. Refused here,
    # before the reachability probe and before any hook is written, because the
    # probe itself sends the device token.
    refusal = (None if args.no_collector or not url
               else shipper_config.collector_url_refusal(url))
    if refusal:
        say()
        say(f"  ⚠ COLLECTOR REFUSED ({url_src}) — {refusal}.")
        say("  Re-run with an https:// --collector-url, or --no-collector to keep")
        say("  records local. Nothing was installed.")
        return 2

    if args.no_collector or not url:
        say("  none configured — records will accumulate locally and ship when")
        say("  a collector is set. Nothing is lost in the meantime.")
    else:
        say(f"  url        {url}   <- {url_src}")
        say(f"  device     {device}   <- {device_src}")
        say(f"  token      {'set' if token else '(none)'}   <- {token_src}")
        if not args.dry_run:
            check_collector(url, token, device)
            say("  reachable, and this token is accepted")
        else:
            say("  would check    that it answers and that this token is accepted")

    head("5 · What leaves this machine")
    # ⚠ SAID WHERE THE AGREEMENT IS MADE, AND THIS INSTALL IS THE AGREEMENT.
    # There are no tiers any more and nothing to choose (28 Sep 2026): every
    # record ships as one thing. The env file records STING_SHIPS='masked' only
    # after these lines printed, and the shipper sends nothing without it
    # (shipper/config.HELD) — so a machine that agreed to less, under a tier,
    # ships nothing new until a person reads this.
    #
    # ⚠ THE COMMAND TEXT IS THE CUSTOMER'S DATA, AND THE LIMIT IS SAID FIRST.
    # `curl -H "Authorization: Bearer sk-…"` is a command, and so is `psql
    # postgres://user:password@host/db` and a heredoc holding a config file.
    # What Sting recognises leaves as its type; what it does not leaves as
    # written, and a person installing this has to be told which is which.
    for line in messages.what_ships():
        say(line)
    before = (carried.get("STING_TIER") or "").strip()
    if before:
        # ⚠ SAID ONCE: this install rewrites the env file without the line.
        say()
        for line in messages.tier_dropped(before, str(recorded.ENV_FILE)):
            say(line)
    if (os.environ.get("STING_TIER") or "").strip():
        say(f"  ignored    STING_TIER={os.environ['STING_TIER'].strip()!r} in this "
            f"shell: tiers are gone, and nothing reads it")

    head("6 · Install")
    incoming = place.compute_version()
    current = place.installed_version()
    if current:
        say(messages.already_installed(current, incoming))
    if args.dry_run:
        say(f"  would place  {place.default_prefix() / incoming}")
        result = {"version": incoming, "path": place.default_prefix() / incoming,
                   "current": place.default_prefix() / "current", "revoked": [],
                   "previous": current, "dirty": place.is_dirty()}
    else:
        try:
            result = place.place(session_root=Path(
                os.environ.get("STING_SESSION_ROOT")
                or Path.home() / ".sting" / "sessions"))
        except OSError as exc:
            say(messages.no_write_permission(place.default_prefix(), str(exc)))
            return 2
        say(f"  placed     {result['path']}")
        # ⚠ NOT `os.readlink`. Under the Windows layout `current` is a POINTER
        # FILE, not a symlink, and readlink raises WinError 2 on it — measured
        # on the runner, after the tree had already been placed successfully.
        # `place.current_dir` resolves whichever layout this platform uses.
        say(f"  current →  {place.current_dir()}")
        if result["dirty"]:
            say("  ⚠ installed from a DIRTY checkout — the recorded commit does")
            say("    not describe this code. Normal in development, not silent.")
        if result["revoked"]:
            say(f"  ⚠ revoked {len(result['revoked'])} outstanding one-shot "
                 f"grant(s):")
            for grant in result["revoked"]:
                say(f"      {grant['session_id']}  {grant['rule_id'] or ''}")

    # ⚠ THE AGENT IS POINTED AT THE THIN CLIENT, NOT AT THE ENGINE.
    #
    # `sting_hook.py` asks a resident daemon and falls back to `hook_entry.py`
    # in-process when there is not one. Measured on this machine: 57.1 ms per
    # tool call in-process, 29.9 ms warm, 40 of 40 calls verified daemon-served.
    #
    # ⚠ AND IT IS SAFE TO POINT HERE EVEN WHERE NO DAEMON CAN EVER RUN. On a
    # platform with no `AF_UNIX` the client never finds one, never starts one,
    # and decides in-process — which is byte-for-byte the old behaviour plus
    # ~7 ms of the client's own imports. `hook_entry.py` is still installed and
    # still runnable by hand; nothing about it changed.
    entry = result["current"] / "sting_hook.py"
    env = {"STING_SESSION_ROOT": str(Path.home() / ".sting" / "sessions"),
            # ⚠ A DECLARATION, MADE HERE BECAUSE THIS IS WHERE SOMEBODY IS
            # ASKED. Records produced by a wired-up agent hook are this
            # developer's work; every harness that drives the hook for another
            # reason sets its own value in its own invocation. It is the same
            # act as STING_ROOTS below it — written into a config the operator
            # can see, printed in this output, revocable in the same file.
            #
            # ⚠ AND IT IS NOT "absence means work". Absence still means nobody
            # said, all the way to the reader; core/purpose.py refuses to
            # coerce it. What this removes is the case where the ONLY thing
            # that could not declare itself was the thing worth counting.
            "STING_PURPOSE": wire.WORK}
    if roots:
        env["STING_ROOTS"] = roots
    if scratch_value:
        env["STING_SCRATCH"] = scratch_value
    # ⚠ ENFORCEMENT GETS ITS OWN RULE, BECAUSE IT IS THE ONLY SETTING WHOSE
    # REVERSION COSTS THE GUARD. Every other reverted value costs data or
    # disclosure; a machine that was enforcing and comes back observing decides
    # everything and blocks nothing, and the collector cannot tell it from a
    # working one — same heartbeat, same records, and the only difference is
    # that nothing is ever stopped.
    was = recorded.observe_from(carried)
    # ⚠ THE DEFAULT IS ENFORCE — `"0"`, NOT `"1"`. A guard that is born
    # observing is a guard whose first state is "decides everything, stops
    # nothing", and the collector cannot tell that machine from a working one:
    # same heartbeat, same records, and the only difference is that nothing is
    # ever refused. Version 1 cannot ship that as the state a machine arrives in.
    #
    # ⚠ OBSERVE IS STILL AVAILABLE AND IS NOW THE THING SOMEBODY ASKS FOR.
    # `--observe` is unchanged; what changed is which one you get by saying
    # nothing. A carried value still wins over the default, so no machine that
    # chose observe is flipped by an upgrade — that would be the reverse of this
    # block's own rule about reversion.
    observe, observe_src = recorded.resolve(
        args.observe, None if was is None else ("1" if was else "0"),
        "0", key="STING_OBSERVE")
    observe = observe if isinstance(observe, bool) else observe != "0"
    # ⚠ ALWAYS WRITTEN, INCLUDING FOR ENFORCE. It used to be written only in
    # observe mode, so "enforcing", "no install" and "an install predating this
    # key" were one artifact — working rule 13 living inside the installer.
    # `hook_entry` already reads "0" as false, alongside "", "false" and "no".
    env["STING_OBSERVE"] = "1" if observe else "0"

    migration = {}
    head("7 · Hook configuration")
    if was is False and observe:
        # NOT a line among twenty. A downgrade of the guard gets a block.
        say()
        say("  ╭──────────────────────────────────────────────────────────╮")
        say("  │ ⚠ THIS TURNS ENFORCEMENT OFF. The last install ENFORCED; │")
        say("  │   this one will OBSERVE.                                 │")
        say("  ╰──────────────────────────────────────────────────────────╯")
        say("  what it means   the guard still decides and still records, and")
        say("                  it blocks NOTHING. A collector cannot tell this")
        say("                  machine from an enforcing one: same heartbeat,")
        say("                  same records, nothing ever stopped.")
        say("  why it changed  you passed --observe. Nothing else can do this —")
        say("                  a bare re-run keeps enforcement.")
        say("  undo            re-run with --enforce")
        say()
    elif was is False:
        say("  enforcing      carried forward from your last install")
    say(f"  mode           {'observe' if observe else 'ENFORCE'}   <- {observe_src}")
    say(f"  declares   STING_PURPOSE={wire.WORK} — records from this agent hook")
    say(f"             say they are your work. A preflight, a benchmark or any")
    say(f"             other harness overrides it in its own invocation, and")
    say(f"             anything that declares nothing stays UNDECLARED rather")
    say(f"             than being counted as work.")
    observe = env.get("STING_OBSERVE") == "1"
    # ⚠ THE BRIDGE IS NO LONGER SHIPPED HERE — `place.place()` PUT IT THERE.
    # It is a payload item, so it arrived with the engine, it is covered by the
    # same missing-payload refusal, and there is no second copy step that could
    # succeed or fail independently of the tree. What remains is to REPORT it,
    # and to check it is actually on disk before writing a hooks.json that names
    # it: a config naming a bridge that is not there is the "entry point does
    # not exist" defect, and under `failClosed:false` it is a silent allow.
    if any(f["agent"] == "cursor" for f in agents) and _is_windows() \
            and not args.dry_run:
        bridge = cursor_bridge_path(result["current"])
        say(f"  cursor bridge  {bridge}")
        if not bridge.is_file():
            say(f"                 ⚠⚠ NOT ON DISK. The hooks.json below will")
            say(f"                    name a bridge that does not exist, so the")
            f = "                    "
            say(f"{f}hook cannot start — and failClosed=false")
            say(f"{f}makes that a SILENT ALLOW. This install")
            say(f"{f}is not trustworthy; re-run it from a")
            say(f"{f}complete checkout or archive.")
        say(f"                 ⚠ UNVERIFIED transport — the PowerShell bridge")
        say(f"                   has not been run on this machine. See")
        say(f"                   installer/cursor_bridge.ps1 and")
        say(f"                   docs/44-cursor-windows-runbook.md.")
    scoped: list[str] = []
    unhooked: list[str] = []
    wrote: list[dict] = []
    for found in agents:
        written = write_hook_config(found["agent"], Path(found["config"]),
                                     entry, env, args.dry_run, observe=observe)
        for line in hook_config_report(found["agent"], written):
            say(line)
        if written.get("skipped"):
            unhooked.append(found["agent"])
            continue
        if written["written"]:
            wrote.append({"agent": found["agent"], "path": written["path"],
                          "user_level": found.get("user_level", True)})
        # ⚠ SCOPE, ON THE LINE THAT REPORTS THE WRITE. The survey in stage 0
        # already says this, and a developer who scrolls to "Done" never sees
        # it. An install that covers one directory and reads as complete is the
        # silent-failure shape this project keeps refusing — the same
        # distinction preflight draws between "the guard works" and "the guard
        # reports to nobody".
        if not found.get("user_level", True):
            scoped.append(found["agent"])
            say(f"                 ⚠ COVERS THIS DIRECTORY ONLY — "
                 f"{Path(written['path']).parent.parent}")
            say(f"                   {found['agent']} has no user-level hook "
                 f"config, so work in any OTHER repository is UNGUARDED.")
            say(f"                   Re-run install.py inside each project you "
                 f"want covered.")
        if found["agent"] == "cursor":
            say(f"                 events {', '.join(_CURSOR_EVENTS)}")
            # ⚠ BUILT OUTSIDE THE f-STRING ON PURPOSE. A conditional split
            # across lines INSIDE an f-string is PEP 701, i.e. 3.12+, and this
            # file must parse on 3.11 — the floor `check_python` enforces. It
            # would not have failed here; it would have failed on the machine
            # with the older interpreter, at install time.
            why = ("observe mode blocks nothing" if observe
                    else "enforce mode: a hook that dies denies")
            say(f"                 failClosed={str(not observe).lower()} — {why}")
            # ⚠ NOW VERIFIED, AND NOT FROM DOCUMENTATION. Read out of Cursor's
            # own shipped code —
            # Cursor.app/Contents/Resources/app/extensions/cursor-agent-exec/
            # dist/main.js — which branches on it after a hook fails:
            #
            #   failClosed true   -> {permission: "deny"}, logged "fail-closed",
            #                        status "timeout" when it timed out and
            #                        "blocked" otherwise
            #   failClosed false  -> logged "(fail-open)" and the tool proceeds
            #
            # Both an ERROR and a TIMEOUT take the same branch, which is exactly
            # what the observe/enforce split needs.
            say("                 verified against Cursor's own code: on a hook")
            say("                 error OR timeout, true denies and false")
            say("                 fails open. docs/25-cursor-hooks.md")
        # ⚠ NAMED FOR EVERY AGENT THAT IS NOT CLAUDE CODE. Four of the five
        # adapters have never seen a payload from the agent they model. What
        # was checked is one table, which `--status` reads too.
        unchecked = agent_status.never_checked(found["agent"])
        if "schema" in unchecked:
            say(f"                 ⚠ UNVERIFIED schema — Claude Code's shape is")
            say(f"                   assumed for {found['agent']}. No real config")
            say(f"                   has been read. docs/24-adapter-contract.md")
        # ⚠ ONLY claude-code HAS EVER SEEN A REAL PAYLOAD. Cursor's SCHEMA is
        # verified from real config files and its `failClosed` from Cursor's own
        # binary — but what its agent actually SENDS has never been captured,
        # and `parse()` depends on that. Four adapters otherwise carry the same
        # confidence as the one that is proven, with nothing saying so.
        if "payload" in unchecked:
            say(f"                 ⚠ UNVERIFIED payload — no real {found['agent']}")
            say(f"                   payload has ever been captured. One scratch")
            say(f"                   session fixes it: docs/34-capturing-real-payloads.md")

    # ⚠ D3: WHERE EVERY HOOK CONFIG WENT, IN THE TREE UNINSTALL READS. Copilot's
    # is per project; without this, uninstall found it only from that project.
    if wrote and not args.dry_run:
        try:
            place.record_hook_configs(result["path"], wrote)
        except (OSError, ValueError) as exc:
            say(f"  ⚠ could not record the hook configs in {result['path']}: {exc}")
            say("    uninstall will find a per-project entry only from that project.")

    shipper_env = dict(env)
    # ⚠ THE AGREEMENT, WRITTEN BECAUSE SECTION 5 PRINTED WHAT SHIPS — and the
    # only thing that lets the shipper send (shipper/config.HELD). STING_TIER is
    # not written: an old one is dropped here, as section 5 said.
    shipper_env["STING_SHIPS"] = wire.MASKED
    # ⚠ THE INTERPRETER INSTALL RAN WITH, RECORDED — NOT A HARDCODED
    # C:\PythonNN. The Cursor-on-Windows bridge reads this from the env file so
    # it never has to guess a Python path (A.2). Harmless elsewhere: the POSIX
    # hook already carries `sys.executable` in its command, and `envfile.load`
    # will not override an interpreter the environment already names.
    shipper_env["STING_PYTHON"] = sys.executable
    if url and not args.no_collector:
        shipper_env.update({"STING_COLLECTOR_URL": url,
                             "STING_DEVICE_TOKEN": token,
                             "STING_DEVICE_ID": device})
    if not args.dry_run:
        say(f"  env file       {write_env(shipper_env)}  (0600 — holds the token)")
        # ⚠ THE FINGERPRINT KEY: MADE IF MISSING, CARRIED ACROSS REINSTALLS,
        # NEVER PRINTED (shipper/fingerprint_key.py). A new key over an old one
        # would open a gap in every live session, so an existing file is kept.
        _install_fingerprint_key(ENV_FILE.parent / fingerprint_key.FILE_NAME)
        # ⚠ RECLAIM THE ORPHAN AN OLDER INSTALLER LEFT, AND DO IT *AFTER* THE
        # CONFIGS ARE WRITTEN.
        #
        # Before the bridge became payload it was copied to
        # `<prefix>/cursor_bridge.ps1`, beside the pointer. It is now placed
        # inside the version directory, so that copy is dead — and `remove()`
        # only deletes DIRECTORIES under the prefix, so `--uninstall` used to
        # leave it too, and the leftover then made `prefix.rmdir()` fail.
        #
        # ⚠ THE ORDER IS THE WHOLE CARE HERE. The old `hooks.json` still names
        # that file until `write_hook_config` above replaces the entry; deleting
        # it first would open a window in which a Cursor hook resolves a bridge
        # that is not there — and under `failClosed:false` that is a silent
        # allow. Configs first, then the file they no longer name.
        for orphan in (place.default_prefix() / "cursor_bridge.ps1",):
            if orphan.is_file():
                try:
                    orphan.unlink()
                    say(f"  reclaimed      {orphan}")
                    say(f"                 an older install left this beside the")
                    say(f"                 pointer; the bridge now ships inside")
                    say(f"                 the version directory.")
                except OSError as exc:
                    say(f"  ⚠ could not remove {orphan}: {exc}")

    head("8 · The shipper")
    supervisor_leak: list[str] = []
    if args.no_supervisor:
        say("  no supervisor, as asked. Run it yourself:")
        say("      python3 -m shipper.run")
        say("  ⚠ the heartbeat only means something if it is regular. See")
        say("    installer/supervisor.py for why that is the default.")
    elif args.dry_run:
        say(f"  would write  {service.target_path()}")
    else:
        written = supervisor.write(sys.executable,
                                    result["current"] / "shipper" / "run.py",
                                    shipper_env)
        if written["path"]:
            say(f"  {written['kind']:14} {written['path']}")
            # ⚠ THE SUPERVISOR FILE NO LONGER CARRIES THE DEVICE TOKEN — the
            # shipper reads it from the 0600 env file, as it already did. But
            # this rewrite silently DELETES a credential that was sitting in a
            # world-readable file, and a deleted secret is not an un-leaked
            # one. Only the operator can rotate it.
            leaking = supervisor_leak = written.get("was_leaking") or []
            if leaking:
                say()
                say(f"  ⚠ THE PREVIOUS {written['kind']} FILE CONTAINED YOUR "
                     f"{', '.join(leaking)} IN CLEARTEXT.")
                say(f"    It was world-readable ({written['path']}), on the")
                say(f"    machine running the agent being watched. This install")
                say(f"    has just removed it — the shipper reads the token from")
                say(f"    {ENV_FILE} (0600) and always could.")
                say(f"    ⚠ REMOVING IT IS NOT UNDOING IT. Treat that token as")
                say(f"      exposed and ROTATE it: issue a new one at the")
                say(f"      collector and re-run with --device-token <new>.")
                say()
            outcome = supervisor.activate()
            migration = outcome.get("migrated") or {}
            if migration.get("stopped"):
                say(f"  ⚠ migrated     stopped {migration['label']}, the old "
                     f"per-ACCOUNT service")
                for path in migration.get("removed", []):
                    say(f"                 removed {path}")
            if outcome["ok"]:
                say(f"  loaded         {outcome['detail']}"
                     f"   (verified with {service.kind()}, not with the file)")
                if service.kind() in ("launchd", "systemd"):
                    # The shipper reads its settings once, when it starts; a
                    # running one was restarted so the settings above apply.
                    say("  restarted      it now runs with the settings above")
                say(f"  stop it with   {service.stop_command()}")
            else:
                # ⚠ LOUD, AND NOT FATAL. The install is otherwise complete and
                # the hook is already recording; what has failed is the thing
                # that makes SILENCE meaningful at the collector. A failure
                # that scrolls past as one grey line is how a machine ends up
                # reporting nothing while everyone believes it is supervised.
                say()
                say("  ╭──────────────────────────────────────────────────────────╮")
                say("  │ ⚠ THE SUPERVISOR IS NOT LOADED. The file is written and  │")
                say("  │   nothing is running it.                                 │")
                say("  ╰──────────────────────────────────────────────────────────╯")
                say(f"  why            {outcome['detail']}")
                for command in outcome["commands"]:
                    say(f"  ran            {command}")
                say("  what it costs  records still accumulate locally and")
                say("                 nothing is lost — but nothing ships, and")
                say("                 a device that never reports is one the")
                say("                 collector cannot distinguish from a dead")
                say("                 guard. See installer/supervisor.py.")
                # ⚠ THE MANUAL FALLBACK IS FIRST-CLASS, NOT A CONSOLATION
                # LINE. `schtasks /Create` was refused with "Access is denied"
                # on the first native Windows install, and this is the path a
                # customer is left on. A supervisor that cannot register is a
                # bad reason to leave someone with no shipper at all — and
                # DEMANDING ELEVATION AT INSTALL IS NOT THE ANSWER: this product
                # installs in a minute, and a UAC prompt at install is a
                # different product.
                say("  ▸ RUN IT BY HAND — this works, and it is supported:")
                say(f"        {sys.executable} -m shipper.run")
                say("    Leave it in a terminal, or add it to your own startup.")
                if service.kind() == "schtasks":
                    # ⚠ WIRED, NOT PRINTED. This used to be four lines telling a
                    # person how to build a shipper themselves, on the one
                    # platform where the supervisor is known to be refused. A
                    # paragraph is not a fallback; a file in the Startup folder
                    # is. It needs no elevation, no UAC prompt and no registry.
                    say()
                    shortcut = supervisor.install_startup_shortcut(
                        service.task_paths()[1])
                    if shortcut["written"]:
                        say("  ▸ DONE FOR YOU — WITHOUT ELEVATION. A Startup")
                        say("    shortcut now ships this machine at logon:")
                        say(f"        {shortcut['path']}")
                        say("    It calls the wrapper this install already wrote,")
                        say("    so it carries the same environment as the task")
                        say("    would have:")
                        say(f"        {service.task_paths()[1]}")
                        say("    ⚠ WHAT IT COSTS: a Startup shortcut runs AT")
                        say("      LOGON. A machine that has rebooted and is")
                        say("      sitting at the login screen ships NOTHING —")
                        say("      a scheduled task would have run. That gap")
                        say("      looks the same at the collector as an")
                        say("      overnight sleep, and for the same reason.")
                        say("    remove it   delete that file; nothing else")
                        say("                references it.")
                    else:
                        say("  ▸ WINDOWS, WITHOUT ELEVATION — the Startup-folder")
                        say(f"    fallback could not be written: {shortcut['reason']}")
                        say("    Put a .cmd calling this in your Startup folder:")
                        say(f"        {service.task_paths()[1]}")
                    say()
                    say("  ▸ OR REGISTER THE TASK FROM AN ELEVATED SHELL, ONCE.")
                    say("    Not required, and not asked for at install:")
                    for command in outcome["commands"]:
                        say(f"        {command}")
                say("  then re-check with:  python3 install.py --status")
                say()
            if service.kind() == "systemd":
                say("  ⚠ on Linux a --user unit stops at logout unless you run:")
                say("      loginctl enable-linger $USER")
                say("    Not run for you: lingering changes how the whole")
                say("    account behaves, not just this service.")
        else:
            say(f"  {written['note']}")
        say("  ⚠ neither supervisor runs while the machine is ASLEEP. Data is")
        say("    safe — the cursor resumes — but an overnight sleep looks")
        say("    identical to a dead guard at the collector. See")
        say("    installer/supervisor.py.")

        # ══ IS IT SHIPPING NOW — not "will something run it later" ══
        #
        # ⚠ TWO DIFFERENT CLAIMS, AND ONLY ONE MEANS RECORDS ARE MOVING.
        # `loaded` above answers "does the supervisor hold this job". On
        # launchd and systemd that also starts it — bootstrap+RunAtLoad, and
        # `enable` + `restart` — both verified. On WINDOWS NEITHER PATH STARTS
        # ANYTHING: the task's only trigger is <LogonTrigger> and the Startup
        # folder fires at logon too, so between here and the next sign-in this
        # machine ships NOTHING. On a box that stays logged in, that is days.
        if service.kind() == "schtasks":
            started = supervisor.start_now()
            if started["started"]:
                say(f"  ▸ AND STARTED NOW — {started['detail']}. Windows would")
                say("    otherwise have waited for your next sign-in, because")
                say("    both the scheduled task and the Startup shortcut are")
                say("    LOGON-triggered. It is detached, so it survives this")
                say("    window closing.")
            else:
                say(f"  ⚠ COULD NOT START IT NOW: {started['detail']}")
                say("    Nothing ships until your next sign-in. To start it")
                say("    immediately instead:")
                say(f"        {sys.executable} -m shipper.run")

        # ⚠ THE CHILD IS STILL IMPORTING. `start_now()` returns as soon as the
        # process exists; the shipper reaches its lock only after importing
        # core.wire, shipper.client and shipper.cursor. Asking immediately
        # printed "AND STARTED NOW" followed by "shipping now ⚠ NO" — two true
        # statements that read as a contradiction at exactly the moment somebody
        # is deciding whether to trust the line.
        running = service.shipper_running()
        deadline = time.monotonic() + 3.0
        while running.get("running") is False and time.monotonic() < deadline:
            time.sleep(0.1)
            running = service.shipper_running()
        if running["running"] is True:
            say(f"  shipping now   YES — {running['detail']}")
        elif running["running"] is False:
            say(f"  shipping now   ⚠ NO — {running['detail']}")
            say("                 Records are being RECORDED and are safe on")
            say("                 disk; nothing is leaving this machine yet.")
        else:
            say(f"  shipping now   unknown — {running['detail']}")

    # ⚠ "UPDATE" IS DECIDED FROM WHAT WAS ALREADY HERE, NOT FROM A FLAG. An MDM
    # pushes the same command every time; nothing on the command line
    # distinguishes the first install from the fiftieth, and asking the operator
    # to remember which one this is would be asking them to get it wrong.
    sessions = Path.home() / ".sting" / "sessions"
    cursor = Path.home() / ".sting" / "shipper" / "cursor.json"
    updating = bool(carried) or sessions.is_dir() or cursor.is_file()
    kept: list[str] = []
    if already:
        kept.append(f"the device credential"
                     + (f" — still {carried.get('STING_DEVICE_ID')!r}"
                        if carried.get("STING_DEVICE_ID") else "")
                     + ", not re-issued")
    if sessions.is_dir():
        count = sum(1 for _ in sessions.rglob("*.jsonl"))
        kept.append(f"{sessions}  ({count} log file(s)) — untouched")
    if cursor.is_file():
        kept.append(f"{cursor} — untouched, so nothing is re-sent")

    # ⚠ ABOVE THE PREFLIGHT GATE, AND THE WALK IS WHY. This block first sat in
    # `Done`, which sits behind `return 1` on a preflight failure — so an MDM
    # update run with `--no-supervisor` (one FAIL, by design) printed a preflight
    # failure and NEVER SAID THE CREDENTIAL HAD BEEN KEPT. That is the exact
    # moment an admin needs to know it: something looks wrong, and the first
    # question is "did the update just re-identify fifty machines".
    if updating:
        head("What this UPDATE kept")
        for line in kept:
            say(f"  {line}")
        # ⚠ NO POINTER TO THE UNINSTALL (item 2): an agent may make a dry run
        # and reads this.
        say("  why: the logs are EVIDENCE, and the cursor is what stops a")
        say("  reinstall re-sending everything you already shipped.")

    head("9 · Preflight")
    if args.dry_run:
        say("  skipped (dry run)")
        return 0
    code = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "tools" / "preflight.py"),
         "--agent", agents[0]["agent"]],
        env={**os.environ, **shipper_env}).returncode
    if code != 0:
        say(messages.preflight_failed())
        return 1

    head("Done")
    # ⚠ AN UPDATE SAYS WHAT IT KEPT, BECAUSE THE THING A REINSTALL IS MOST
    # LIKELY TO HAVE QUIETLY BROKEN IS THE THING IT DID NOT TOUCH. The
    # reasoning is `--uninstall`'s and is not restated here: that block argues
    # why `~/.sting` survives removing the guard, and every word of it applies
    # harder to an update, which is not even trying to remove anything. What is
    # added here is only the fact that this run WAS an update and what carried.
    # ⚠ THE TRUST BOUNDARY, RESTATED FIRST, because it is the one thing here
    # that decides what the guard considers "the project" — and because section
    # 1 is 600 lines up and behind a preflight run. A missing root does not
    # fail: it narrows the boundary silently, and in observe mode that produces
    # no visible symptom at all, which is exactly how it survived on a real
    # machine. Reporting it once, early, is the same as not reporting it.
    # ⚠ A CREDENTIAL THAT WAS EXPOSED IS THE ONE THING HERE THAT NEEDS AN
    # ACTION FROM THE PERSON, so it goes above everything else in this block.
    # Section 8 said it 100 lines ago and section 9 ran a preflight over it.
    if supervisor_leak:
        say()
        say(f"  ⚠ ROTATE YOUR {', '.join(supervisor_leak)} — it was sitting in")
        say(f"    cleartext in the world-readable supervisor file until this")
        say(f"    install removed it. Removal is not rotation.")
        say(f"    Issue a new token, then:  python3 install.py --device-token <new>")
        say()
    missing_roots = [r for r in root_rows if not r["exists"]]
    if missing_roots:
        say()
        say(f"  ⚠ TRUST BOUNDARY — {len(missing_roots)} of {len(root_rows)} "
             f"declared root(s) DO NOT EXIST on this machine:")
        for row in missing_roots:
            say(f"      {row['path']}")
            if row["hint"]:
                say(f"        {row['hint']}")
        say(f"    They are dropped at runtime, so the project is NARROWER than")
        say(f"    what you declared. Nothing blocked this install.")
        say(f"    Fix:  python3 install.py --roots '<corrected list>'")
        say()
    if unhooked:
        say(f"  ⚠ NOT HOOKED — {', '.join(unhooked)}: the hook config could not "
            f"be read, was left")
        say("    untouched and copied beside itself. See above; fix the file and "
            "run this again.")
    if scoped:
        say(f"  ⚠ PARTIAL COVERAGE — {', '.join(scoped)} " 
             f"{'is' if len(scoped) == 1 else 'are'} wired for THIS DIRECTORY")
        say(f"    ONLY. Every other project you open with "
             f"{'it' if len(scoped) == 1 else 'them'} is unguarded until you")
        say(f"    run this again there. Check any project with:")
        say(f"      python3 tools/preflight.py --agent {scoped[0]}")
    # ⚠ THE ENVIRONMENT WARNINGS, RESTATED HERE FOR THE SAME REASON AS ABOVE.
    # Each of these maps to a documented onboarding failure, each was printed in
    # section 0, and section 0 is 200 lines up. None of them stops an install —
    # a network home is a supported configuration and a Windows interpreter is
    # something the person can fix — so REPORTING is the whole job, and a report
    # nobody reaches is not one.
    warned = [name for name in ("shell", "interpreter", "home")
              if checks.get(name) is not None
              and (not checks[name].ok or "⚠" in checks[name].detail)]
    if warned:
        say()
        for name in warned:
            result_line = checks[name]
            say(f"  ⚠ {name.upper()}   {result_line.detail}")
            for line in result_line.lines:
                if "⚠" in line or "fix" in line or "what to do" in line:
                    say(f"    {line.strip()}")
        say("    (full detail in section 0 above)")
        say()

    if migration and migration.get("stopped"):
        say(f"  ⚠ MIGRATED the supervisor off the old per-ACCOUNT label")
        say(f"    stopped   {migration['label']} (it served every install on")
        say(f"              this account; labels are now per install prefix)")
        for path in migration.get("removed", []):
            say(f"    removed   {path}")
        say(f"    why       a second install used to boot the first one out")
        say(f"              silently. They can now run side by side.")

    # ⚠ TASK 1.3 — AN UNATTENDED INSTALL MUST STILL BE HONEST. What it did to
    # the machine goes HERE, in the block a person actually reads, not only in
    # the scrollback of a fleet push nobody opens.
    if machine_changes:
        say("  ⚠ WHAT THIS CHANGED ON YOUR MACHINE, outside ~/.sting:")
        for line in machine_changes:
            say(f"      {line}")
    else:
        # ⚠ NARROWED, BECAUSE THE WIDE VERSION WAS FALSE ON ALMOST EVERY RUN.
        # This install DOES write outside ~/.sting: the agent's hook config
        # (~/.claude/settings.json and friends) and the supervisor's own file
        # (a launchd plist, a systemd unit, a scheduled task). Both are the
        # guard registering ITSELF and both are printed line by line above.
        # What this line claims is only the thing that was actually at issue.
        say("  machine   no third-party software was installed, downloaded or")
        say("            reconfigured. The hook config and the supervisor file")
        say("            named above are this guard's own, and are the install.")
    say(f"  version   {result['version']}")
    say(f"  hook      {entry}")
    say(f"  logs      {env['STING_SESSION_ROOT']}")
    say(f"  service   {service.label()}")
    say("  Edits to this checkout do nothing until you re-run install.py.")
    say("  Check for drift any time:  python3 install.py --status")
    # ⚠ THE PERSON'S WAY OUT, HERE AND NOT IN WHAT AN AGENT READS (docs/108 §3).
    for line in messages.way_out(result["current"] / "tools" / "allow_once.py"):
        say(line)

    # ⚠ THE ONLY CLEANUP CALL, AND IT IS HERE ON PURPOSE — reached only after the
    # preflight-passed gate above, so it is structurally unreachable from the
    # dry-run (return 0), check-only (return 0) and preflight-failed (return 1)
    # exits. "Genuine success" is this position, not a boolean. cleanup.run is a
    # no-op unless the flag is on, the source carries the .sting-release marker,
    # AND no .git sits at or above it — see installer/cleanup.py.
    cleanup.run(Path(__file__).resolve().parent,
                getattr(args, "cleanup_after_install", False), say)
    return 0


def do_status(args) -> int:
    # ⚠ READ BEFORE `envfile.load()` BELOW copies the file into the environment,
    # or a malformed number in the file would be named as the environment's.
    problems = shipper_config.setting_problems(env_file=ENV_FILE)
    current = place.installed_version()
    checkout = place.compute_version()
    head("Installed")
    say(f"  version    {current or '(nothing installed)'}")
    say(f"  checkout   {checkout}")
    if current and current != checkout:
        say("  ⚠ DRIFT — the checkout differs from what is installed, so your")
        say("    edits are not what the guard is running. Re-run install.py.")
    elif current:
        say("  in sync")
    # ⚠ THE FILE AND THE SERVICE ARE PRINTED AS TWO LINES BECAUSE THEY ARE TWO
    # FACTS. This used to be one line driven by `installed`, which was `the
    # plist exists` — so a machine whose shipper launchd had never heard of
    # printed a path and looked healthy.
    state = service.status()
    say(f"  supervisor {state['kind']}: "
         f"{state['path'] if state['file_present'] else '(no file)'}")
    if state["loaded"] is True and state.get("is_this_install") is False:
        say(f"  service    LOADED, BUT NOT THIS INSTALL'S")
        say(f"             running   {state['running_file']}")
        say(f"             this one  {state['path']}")
        say(f"             the {state['kind']} label is per USER, not per")
        say(f"             install, so another install under this account holds")
        say(f"             it. They cannot both run — re-run the install.py of")
        say(f"             whichever one you want shipping.")
    elif state["loaded"] is True:
        say(f"  service    LOADED"
             + (f", pid {state['pid']}" if state["pid"] else " (no pid)"))
    elif state["loaded"] is False and state.get("startup_shortcut"):
        # ⚠ THE THIRD MEANING. Task Scheduler having no task is not evidence
        # that nothing ships: on the machine where `schtasks /Create` is refused
        # the installer wires a Startup shortcut instead, and reading that as a
        # FAIL trains an operator to ignore the line that matters.
        say(f"  service    SHIPPING AT LOGON — no scheduled task, by design")
        say(f"             {service.startup_shortcut_path()}")
        say(f"             Task Scheduler refused registration on this machine")
        say(f"             (unelevated shell or domain policy), so the install")
        say(f"             wired the no-elevation path instead.")
        say(f"             ⚠ it runs at LOGON — a machine sitting at the login")
        say(f"               screen after a reboot ships nothing until somebody")
        say(f"               signs in.")
    elif state["loaded"] is False and state.get("legacy_loaded"):
        # ⚠ A FOURTH STATE, AND WITHOUT IT THIS LINE WAS A FALSE STATEMENT.
        # Measured on this machine: the per-install label was not loaded while
        # `dev.sting.shipper` — the pre-per-prefix label — was RUNNING at pid
        # 79781. `--status` said "nothing ships until it is", on a machine that
        # was shipping.
        say(f"  service    THE LEGACY SERVICE IS RUNNING, this install's is not")
        say(f"             {service.LEGACY_LABEL} is loaded and shipping — from")
        say(f"             an install that predates per-prefix labels. Records ARE")
        say(f"             leaving this machine; they are not leaving it from HERE.")
        say(f"             ⚠ so the settings above may not be the ones in force.")
        say(f"             fix    re-run install.py — it migrates the old service")
        say(f"                    and boots it out, once.")
    elif state["loaded"] is False:
        # ⚠ THREE STATES, THREE MEANINGS — and this branch is only ONE of them.
        # `--no-supervisor` is a deliberate choice to ship by hand, and reading
        # that as a failure trains an operator to ignore the line.
        say(f"  service    NOT LOADED — {state['detail']}")
        if not state["file_present"]:
            say(f"             no supervisor file exists either. Either this was")
            say(f"             installed with --no-supervisor and you ship by hand,")
            say(f"             or registration never happened.")
        else:
            say(f"             the file is written and the supervisor has not taken")
            say(f"             it — registration failed. That is different from")
            say(f"             never having tried.")
        say(f"             nothing ships until one of these is true. Load it:")
        say(f"                 {reload_command()}")
        say(f"             or run it by hand:  {sys.executable} -m shipper.run")

    else:
        say(f"  service    cannot tell — {state['detail']}")
    # ⚠ EVERY BRANCH ABOVE ANSWERS "WHAT WILL RUN IT LATER". THIS ANSWERS
    # "IS ANYTHING SHIPPING RIGHT NOW", which is a different question and the
    # only one that means records are moving. They have drifted into different
    # answers twice, so both readers — this and tools/preflight.py — now take
    # this fact from the same place: the lock the shipper process itself holds.
    # `service.loaded()` cannot answer it, because it asks launchd, systemd
    # or Task Scheduler, and none of them knows about a shipper started from a
    # Startup .cmd, from a terminal, or by the installer.
    # ══ THE TRUST BOUNDARY, AND WHETHER IT STILL MATCHES THE DISK ══
    #
    # ⚠ ROOTS ARE SET ONCE AT INSTALL AND THE DISK MOVES ON. A repo cloned
    # after the install is not in them, so every edit there is `write_outside`
    # and the guard is useless on exactly the work somebody is doing now. And a
    # declared root that no longer exists is DROPPED SILENTLY at runtime, so the
    # project is narrower than what was declared, with nothing saying so.
    #
    # ⚠ REPORTED, NEVER ADDED. A trust boundary that widens itself is not a
    # boundary — the installer prints, the operator decides. That is the same
    # rule `installer/detect.py` states for the install-time proposal.
    from core import probes

    # ⚠ READ THE WAY THE HOOK READS IT. `STING_ROOTS` lives in `~/.sting/env`,
    # not in the operator's shell — reading os.environ alone reported every
    # sibling as unlisted on a machine whose boundary was correct.
    import envfile

    envfile.load()
    declared = [r for r in probes.split_roots(
        os.environ.get("STING_ROOTS", "")) if r]
    if declared:
        gone = [r for r in declared if not Path(r).is_dir()]
        say(f"  roots      {len(declared)} declared, "
             f"{len(declared) - len(gone)} exist")
        for r in gone:
            say(f"             ⚠ MISSING {r}")
        if gone:
            say(f"             a missing root is dropped at runtime, so the")
            say(f"             project is NARROWER than what you declared.")
    else:
        say("  roots      ⚠ NONE DECLARED — STING_ROOTS is unset. Measured: "
             "that produced")
        say("             74 of 89 secret-rule denials in one period, all of")
        say("             them ordinary edits read as leaving the project.")

    try:
        proposal = detect.propose_roots()
        known = {str(Path(r).resolve()) for r in declared}
        unlisted = [p for p in proposal["proposed"]
                    if str(Path(p).resolve()) not in known]
    except (OSError, RuntimeError, ValueError) as exc:
        unlisted, proposal = [], {"searched": f"(scan failed: {exc})"}
    if unlisted:
        say(f"  ⚠ {len(unlisted)} repositor(y/ies) beside your checkout are NOT")
        say(f"    in the trust boundary. Every edit in them is judged as")
        say(f"    writing OUTSIDE the project:")
        for path in unlisted:
            say(f"        {path}")
        say(f"    NOT added for you — a boundary that widens itself is not a")
        say(f"    boundary. If they are yours:")
        say(f"        python3 install.py --roots "
             f"'{os.pathsep.join(declared + unlisted)}'")

    running = service.running_shipper()
    if running["running"] is True:
        say(f"  shipping   NOW — {running['detail']}")
        if running.get("since"):
            say(f"             started {_when(running['since'])}")
        # ⚠ THE LINES ABOVE AND BELOW READ THE SETTINGS FRESH; THE SHIPPER READ
        # THEM ONCE, WHEN IT STARTED. On the Azure VM this screen said `full`
        # for 6.5 hours over a process shipping at the old tier.
        if running["predates_settings"]:
            say(f"  ⚠ {service.STALE_SETTINGS}")
            say(f"             {running['settings']} changed "
                 f"{_when(running['settings_changed'])}, after it started")
            say(f"             restart    {running['restart']}")
    elif running["running"] is False and state.get("pid"):
        # ⚠ NOT "NOTHING IS SHIPPING". A shipper started before the lock existed
        # holds none, so an empty lock is not an empty machine.
        say(f"  shipping   the lock is free, but {state['kind']} reports pid "
             f"{state['pid']}")
        say(f"             — a shipper predating this version holds no lock.")
        say(f"             It takes one the next time it restarts.")
    elif running["running"] is False:
        say(f"  shipping   ⚠ NOTHING IS SHIPPING RIGHT NOW — {running['detail']}")
        say(f"             Whatever the service line says above is about what")
        say(f"             will run it LATER. Records are safe on disk.")
    else:
        say(f"  shipping   unknown — {running['detail']}")
    say(f"  env file   {ENV_FILE if ENV_FILE.exists() else '(none)'}")
    # ⚠ SAY WHAT IS WRONG AND CARRY ON (#76's open list). A malformed number
    # raised out of the one command a person runs to find out what is wrong.
    for problem in problems:
        where = ("the environment" if problem["where"] == "the environment"
                 else f"in {problem['where']}")
        value = problem["value"]
        # ⚠ A MASKED VIEW (security review): a secret pasted into the wrong
        # variable would be printed with it, in the output people paste.
        shown = repr(value) if len(value) <= 4 else f"'{value[:4]}…' ({len(value)} characters)"
        say(f"  ⚠ setting  {problem['setting']}={shown} ({where}) is not a whole "
            f"number:")
        say(f"             the shipper will not start until it is")

    # ⚠ WHAT THIS MACHINE SENDS, FROM THE FILE THE SHIPPER READS IT FROM, and a
    # tier nothing reads any more, named so nobody believes it still decides.
    ships = shipper_config.from_env(env_file=ENV_FILE, strict=False).what_ships()
    if ships["ships"] == shipper_config.HELD:
        say(f"  ships      ⚠ NOTHING YET — {ships['detail']}")
    else:
        say(f"  ships      {ships['detail']}")
    for ignored in ships["ignored"]:
        say(f"  ignored    {ignored['setting']}={ignored['value']!r} "
            f"({ignored['where']}): tiers are gone; nothing reads it")
    key_path = ENV_FILE.parent / fingerprint_key.FILE_NAME
    key_state = fingerprint_key.state(key_path)
    held = fingerprint_key.why_held(key_path)
    say(f"  key        {key_path}: {key_state}"
        + (f" — ⚠ it {held}" if held else
           {"present": " (keys what ships; never sent, never printed)",
            "missing": " — the shipper makes it before its first send",
            # changed between the two reads: never a traceback in --status
            "damaged": " — ⚠ nothing ships until it holds a key"}[key_state]))

    # ⚠ THE ESCAPE HATCH, MADE FINDABLE. Carrying settings forward is only
    # honest if a developer can SEE what would be carried and knows the one
    # flag that overrides each. An escape hatch that requires reading the
    # source is not an escape hatch.
    # ⚠ EVERY AGENT, AND NEVER MORE THAN THE INSTALLER CAN SHOW: wired or
    # not, and how far that wiring was ever checked (installer/agent_status).
    head("Agents")
    try:
        agent_lines = agent_status.agent_lines()
    except (OSError, RuntimeError, ValueError) as exc:
        # ⚠ NEVER A TRACEBACK IN --status (python review): `Path.home()`
        # raises RuntimeError where no home resolves; the rest still stands.
        agent_lines = []
        say(f"  could not be read ({type(exc).__name__}); the rest of the status stands")
    for agent, line in agent_lines:
        say(f"  {agent:12} {line}")
    carried = recorded.read()
    if carried:
        say()
        say("  Carried into your next install unless you pass the flag beside it:")
        for key, flag in (("STING_COLLECTOR_URL", "--collector-url / --no-collector"),
                           ("STING_DEVICE_ID", "--device-id"),
                           ("STING_DEVICE_TOKEN", "--device-token"),
                           ("STING_OBSERVE", "--enforce"),
                           ("STING_ROOTS", "--roots"),
                           ("STING_SCRATCH", "--scratch")):
            if key in carried:
                shown = "<set>" if "TOKEN" in key else carried[key]
                if key == "STING_OBSERVE":
                    # ⚠ ONLY THE WAY BACK TO ENFORCE (item 2): an agent may run
                    # --status and reads this, so it never names the way out
                    # of enforce. The person has it in `--help`.
                    observing = recorded.observe_from(carried)
                    shown = "observe" if observing else "ENFORCE"
                    flag = flag if observing else ""
                say(f"    {key:22} {shown[:58]:58} {flag}".rstrip())
        say(f"    reset everything:  rm {recorded.ENV_FILE}")
    return 0


def _when(stamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(stamp))


def reload_command() -> str:
    if service.kind() == "launchd":
        return (f"launchctl bootstrap gui/{os.getuid()} "
                 f"{service.plist_path()}")
    if service.kind() == "systemd":
        return f"systemctl --user enable --now {service.label()}.service"
    return "start the shipper yourself"


def stop_daemons() -> list[str]:
    """Ask any resident daemon to go away, and say what happened. Never raises.

    ⚠ BY ITS SOCKET, NEVER BY A PROCESS NAME. `pkill -f daemon/server.py` is the
    obvious implementation and it is wrong twice: it would kill a daemon serving
    a DIFFERENT store (a second checkout, another developer's tree under the
    same account), and it matches on a command line that any process can carry.
    The socket in this install's session root names exactly the daemon this
    install is responsible for.

    ⚠ AND IT DOES NOT KILL. The socket is renamed, which is the same circuit
    breaker `daemon/client.trip_breaker` uses: the daemon's accept loop notices
    its socket is no longer the one on disk and exits on its own, within a poll
    interval. An uninstaller that sends signals to processes it did not start is
    a bigger claim than this needs, and a daemon mid-write would be interrupted
    rather than allowed to finish its record.
    """
    notes = []
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from daemon import protocol
    except Exception as exc:                      # noqa: BLE001 — deliberate
        return [f"daemon             not checked ({type(exc).__name__}: {exc})"]

    for root in {str(Path.home() / ".sting" / "sessions"),
                 protocol.session_root()}:
        sock = protocol.socket_path(root)
        if not os.path.exists(sock):
            continue
        try:
            os.rename(sock, sock + ".uninstalled")
            notes.append(f"stopped daemon       {sock}")
            notes.append( "                     (it exits within a poll "
                          "interval; it is not signalled)")
        except OSError as exc:
            notes.append(f"⚠ could not stop the daemon at {sock}: {exc}")
            notes.append(f"  stop it by hand:   pkill -f daemon/server.py")
    if not notes:
        notes.append("daemon               none running")
    return notes


def _without_enrolment(args):
    """`args` with `--enrol` cleared. ⚠ THE FLAG IS DROPPED, NOT THE BRANCH.

    The alternative — an `if` around every later use of `args.enrol` — is the
    shape that leaves one use behind, and the one left behind would be the one
    that mints. Clearing it once means every later reader sees "no enrolment
    string was given", which is exactly what is true after this point.
    """
    import copy

    dropped = copy.copy(args)
    dropped.enrol = None
    return dropped


def _with_enrolment(args, enrol_string: str):
    """`args` with `--enrol` set to a pasted string — the mirror of
    `_without_enrolment`, and a COPY rather than a mutation for the same reason.

    ⚠ THIS ADDS NO NEW ACCEPTANCE PATH. It only fills the SAME `args.enrol`
    field the `--enrol` flag fills, so the pasted string is decoded and verified
    by `enrol_client.decode` / `enrol_client.enrol` exactly as a flag value is.
    The browser never hands install.py a secret; the paste does, through the one
    unchanged handler.
    """
    import copy

    filled = copy.copy(args)
    filled.enrol = enrol_string
    return filled


# ⚠ THE REAL SIGNUP URL IS UNCONFIRMED (see LOGIN_ESTABLISH). It is left as a
# dashed marker rather than invented: until it is set (via `--signup-url` or
# `STING_SIGNUP_URL`) the interactive path prints the paste prompt WITHOUT
# opening a browser. Replace this marker with the real URL when it is known.
_SIGNUP_URL_UNSET = "—"

# Browsers that render inside the terminal. Launching one would SEIZE this TTY,
# so their presence sends the caller to the paste fallback instead.
_TERMINAL_BROWSERS = frozenset({
    "www-browser", "links", "links2", "elinks", "lynx", "w3m",
})


def _is_terminal_browser(command: str) -> bool:
    first = command.split()[0] if command.strip() else ""
    return os.path.basename(first) in _TERMINAL_BROWSERS


def _gui_browser_available() -> bool:
    """Decide from the ENVIRONMENT whether opening a browser would raise a GUI,
    BEFORE calling `webbrowser.open`.

    ⚠ `webbrowser.open`'s RETURN VALUE IS NOT PROOF a GUI appeared — a terminal
    browser 'succeeds' and takes the TTY. So the decision is made here, from the
    environment, and it ERRS TOWARD False, which routes to the paste fallback
    that always works. False when: `$BROWSER` names a terminal browser, Linux has
    no `DISPLAY`/`WAYLAND_DISPLAY`, or `webbrowser` resolves to a terminal
    browser (or to nothing).
    """
    for candidate in os.environ.get("BROWSER", "").split(os.pathsep):
        if candidate.strip():
            # `webbrowser` uses the first `$BROWSER` entry; so do we.
            return not _is_terminal_browser(candidate)
    if platform.system() == "Linux" and not (
            os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        controller = webbrowser.get()
    except webbrowser.Error:
        return False
    name = getattr(controller, "name", "") or getattr(controller, "basename", "")
    return not _is_terminal_browser(str(name))


def _resolve_signup_url(args) -> str:
    """The signup URL from `--signup-url`, then `STING_SIGNUP_URL`, then the
    dashed marker. Config only — a URL, never a secret."""
    return (getattr(args, "signup_url", None)
            or os.environ.get("STING_SIGNUP_URL", "")
            or _SIGNUP_URL_UNSET).strip()


def _maybe_browser_signup(args, already: bool):
    """Interactive, PASTE-ONLY browser signup entry. Returns `args`, possibly
    with `args.enrol` filled from a paste — never anything else.

    ⚠ ADDITIVE, AND IT NEVER BLOCKS A PATH THAT WORKS TODAY. It opens at most a
    web page and, on the interactive path, asks for a paste; the secret still
    arrives ONLY through `args.enrol` and the unchanged enrol handler. A blank
    paste (or no TTY) leaves `args` exactly as it was, which installs without
    enrolment exactly as running with no `--enrol` does today.

    PRECEDENCE, in order (each stated where it is handled):
      0. NOT ASKING TO ENROL HERE — a string already given, a token brought by
         flag, `--no-collector`, a dry run, or a machine already enrolled — is
         left untouched.
      1. NOT INTERACTIVE (no TTY on stdin AND stdout): no browser, no prompt.
         The existing non-interactive path runs; enrolment is `--enrol` only, and
         its absence is not an error (records accumulate locally). Never hangs.
      2. INTERACTIVE, but no usable GUI browser OR the URL is the unset marker /
         not a web URL: print the URL if known, then prompt for the paste. No
         browser that could seize the TTY is launched. This is the fallback.
      3. INTERACTIVE AND a GUI browser AND a web URL: open it, then prompt.
    """
    # 0 — nothing to offer.
    if (args.enrol or already or args.device_token or args.no_collector
            or args.dry_run):
        return args
    # 1 — no person present. Defer to the existing non-interactive path. The
    # guard is a REAL TTY on BOTH stdin AND stdout (decided here, at the prompt,
    # not from argv): a server/CI install has neither, and an input() on an
    # inherited pipe that never closes would HANG a fleet rollout with no error.
    # isatty on both is what keeps this prompt — and the browser-open — off that
    # path; its absence is not an error, enrolment is simply left to `--enrol`.
    try:
        interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:                                           # noqa: BLE001
        interactive = False
    if not interactive:
        return args

    signup_url = _resolve_signup_url(args)
    url_is_web = (signup_url != _SIGNUP_URL_UNSET
                  and signup_url.startswith(("https://", "http://")))

    head("Sign up")
    # 3 vs 2 — a browser is attempted ONLY when the environment says a GUI one
    # would answer and the URL is a real web address.
    if url_is_web and _gui_browser_available():
        try:
            webbrowser.open(signup_url)          # a URL argument, never a shell
            say(f"  opened your browser at {signup_url}")
        except Exception as exc:                 # noqa: BLE001
            # A browser that will not open is not fatal — the paste is what
            # completes enrolment. Say so rather than swallow it, then fall
            # through to the same prompt.
            say(f"  could not open a browser ({type(exc).__name__}); open this "
                f"yourself:")
            say(f"    {signup_url}")
    elif url_is_web:
        say("  open this in a browser to sign up:")
        say(f"    {signup_url}")
    else:
        say("  a signup URL is not configured for this build — set it with "
            "--signup-url or STING_SIGNUP_URL.")
        say("  sign up the way your team directs, then paste the string below.")

    say("  the signup page shows an enrolment string (it starts with "
        "sting-enrol-v1.).")
    try:
        pasted = input("  paste it here, or leave blank to skip enrolment: ").strip()
    except EOFError:
        # stdin closed under us despite an initial TTY — treat as a skip, never
        # a crash.
        return args
    if not pasted:
        say("  nothing pasted — continuing without enrolment. Enrol later with:")
        say("    python3 install.py --enrol <string>")
        return args
    return _with_enrolment(args, pasted)


def clean_hook_configs(prefix: Path | None = None) -> list[str]:
    """Take the guard's entry out of every hook config it may be in: each one
    the installed tree recorded (D3: Copilot's is per project, written wherever
    install ran), then every default location, relative ones from here as
    before. Says what it could not clean. Returns what it cleaned."""
    cleaned: list[str] = []
    seen: set[str] = set()
    candidates = [Path(path) for path in place.recorded_hook_configs(prefix)]
    candidates += [Path(path) for paths in detect.agent_configs().values()
                   for path in paths]
    for path in candidates:
        key = os.path.abspath(path)
        if key in seen:
            continue
        seen.add(key)
        if remove_hook_config(path):
            say(f"  removed hook entry   {path}")
            cleaned.append(str(path))
            continue
        why = unreadable_hook_config(path)
        if why:
            say(f"  ⚠ NOT CLEANED        {path} {why}.")
            say("                       The guard's entry may still be in it. "
                "Fix the file and")
            say("                       run install.py --uninstall again.")
    return cleaned


def do_uninstall(args) -> int:
    head("Uninstalling")
    clean_hook_configs()
    state = supervisor.remove()
    for path in state["removed"]:
        say(f"  removed supervisor   {path}")

    # ⚠ THE DAEMON IS NOT SUPERVISED, SO `supervisor.remove()` DOES NOT TOUCH
    # IT, AND UNTIL NOW NOTHING DID. It is demand-started by the first hook and
    # idles out after 30 minutes — so an uninstall left a resident process
    # holding an imported engine, still deciding, still WRITING RECORDS, for up
    # to half an hour after the developer had been told the guard was gone.
    #
    # ⚠ THE ORDER IS LOAD-BEARING. The hook configs are removed FIRST, above,
    # so nothing can start a replacement in the gap between stopping this one
    # and finishing. Stopping it first would leave a window in which one more
    # tool call brings a fresh daemon up against a tree that is being deleted.
    stopped = stop_daemons()
    for line in stopped:
        say(f"  {line}")
    for path in place.remove()["removed"]:
        say(f"  removed              {path}")
    if ENV_FILE.exists():
        ENV_FILE.unlink()
        say(f"  removed              {ENV_FILE}")
    # ⚠ BOTH POLICY FILES GO, AT THEIR OWN PATHS AND NO OTHER: the relaxations
    # configured the guard being removed, and the org cache is a copy the
    # collector still holds. Neither is a record of what the guard decided,
    # which is what stays (below). An override path (STING_POLICY /
    # STING_POLICY_CACHE) is never followed here: uninstall deletes only files
    # it can name.
    for path in (Path(policy.home_path()), org_policy.home_cache_path()):
        if path.is_file() or path.is_symlink():
            path.unlink()
            say(f"  removed              {path}")

    head("Deliberately left behind")
    say(f"  {Path.home() / '.sting'}")
    say("      your decision LOGS, your session state, the shipper's")
    say(f"      cursor, and its fingerprint key ({fingerprint_key.FILE_NAME}: a")
    say("      reinstall keys what ships the same way, so a live session")
    say("      continues without a gap). (Its two policy files, policy.json and")
    say("      org_policy.json, were removed above: they configure a guard")
    say("      that is gone.) Three reasons, and they are not squeamishness:")
    say()
    say("      1 · the logs are EVIDENCE. An uninstaller that deletes the")
    say("          record of what a guard decided is an uninstaller an")
    say("          attacker would love to run. Removing the guard must not")
    say("          also remove the history of what it saw.")
    say("      2 · the cursor is what stops a REINSTALL re-sending every")
    say("          record you already shipped. Deleting it costs a duplicate")
    say("          upload of everything — harmless, because the collector")
    say("          deduplicates, and pointless.")
    say("      3 · they are yours. Uninstalling a tool is not consent to")
    say("          delete the data it produced.")
    say()
    say(f"  Delete them yourself when you want to:  rm -rf {Path.home() / '.sting'}")
    return 0


def main(argv=None) -> int:
    # ⚠ HERE, NOT AT IMPORT. Reconfiguring `sys.stdout` is a global side effect,
    # and doing it when the MODULE loads reached into pytest's captured streams
    # and broke unrelated tests three files later. A library import must not
    # touch a stream it does not own; an entry point may.
    console.make_output_safe()
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check-only", action="store_true",
                     help="report the machine checks and stop")
    ap.add_argument("--yes", "-y", action="store_true",
                     help="accept the proposed STING_ROOTS without asking")
    ap.add_argument("--agent", action="append", default=[])
    ap.add_argument("--roots", default=None,
                     help="colon-separated; '' declares none")
    ap.add_argument("--scratch", default=None)
    ap.add_argument("--collector-url", default=None)
    ap.add_argument("--device-token", default=None)
    # ⚠ ONE STRING. The URL is inside it; the org comes from the collector; the
    # device id comes from the hostname. See installer/enrol.py.
    ap.add_argument("--enrol", default=None,
                     help="an enrolment string (sting-enrol-v1.…) — the only "
                          "thing a person needs to paste")
    # ⚠ NOT A CONVENIENCE. Without it, the ONLY way to move an already-enrolled
    # machine to a new identity would be to delete `~/.sting/env` by hand — and
    # a documented "delete this file first" step is how a fleet ends up with a
    # script that deletes it every time.
    ap.add_argument("--re-enrol", action="store_true",
                     help="use the enrolment string even though this machine "
                          "already holds a device token. ⚠ This mints a NEW "
                          "identity: the history under the old device id stays "
                          "where it is and does not follow.")
    # ⚠ CONFIG, NOT A SECRET, AND UNSET BY DEFAULT. The interactive install
    # opens this page for signup; the URL is the only thing it carries. The real
    # address is unconfirmed (see LOGIN_ESTABLISH), so the default is a dashed
    # marker and, until it is set, the install just prints the paste prompt.
    ap.add_argument("--signup-url", default=None,
                     help="web page to open for signup on an interactive "
                          "install; also STING_SIGNUP_URL. Unset by default — "
                          "you paste the enrolment string when prompted.")
    ap.add_argument("--device-label", default=None,
                     help="an optional human label for this device, stored on "
                          "the collector beside the credential")
    ap.add_argument("--device-id", default=None)
    ap.add_argument("--no-collector", action="store_true")
    ap.add_argument("--no-supervisor", action="store_true")
    # ⚠ TRI-STATE, AND THE DEFAULT IS None RATHER THAN True. With
    # `default=True` there was no way to tell "the operator asked for
    # observe" from "the operator said nothing" — so a bare re-run was
    # indistinguishable from an explicit downgrade, and silently reverted
    # an enforcing machine. None is the third state that makes the rule
    # implementable at all.
    ap.add_argument("--observe", dest="observe", action="store_true",
                     default=None)
    ap.add_argument("--enforce", dest="observe", action="store_false")
    # ⚠ GONE, AND SAID SO RATHER THAN VANISHING. argparse would reject an
    # unknown flag with a usage error that reads like a typo; a script that
    # passes `--tier` is told in one line that tiers were removed.
    ap.add_argument("--tier", default=None, help=argparse.SUPPRESS)
    # ⚠ OPT-IN, DEFAULT OFF, AND DELIBERATELY DANGEROUS TO NAME. On genuine
    # success ONLY, delete the unpacked release source this ran from — the raw
    # .py, tests/, docs/, everything that was in the zip. What install.py already
    # wrote elsewhere (~/.sting and ~/.local/share/sting/<version>) is untouched.
    # Refuses unless the source carries make_release.sh's .sting-release marker
    # AND has no .git at or above it, so it can never fire in a clone. See
    # installer/cleanup.py.
    ap.add_argument("--cleanup-after-install", action="store_true",
                     help="off by default. On a SUCCESSFUL install only, delete "
                          "the unpacked release-archive folder this ran from (the "
                          ".py/tests/docs you unzipped). Your install — ~/.sting "
                          "and ~/.local/share/sting — is elsewhere and untouched. "
                          "Refuses unless the folder is a real unpacked archive "
                          "AND has no .git at or above it, so it can never delete "
                          "a git checkout.")
    args = ap.parse_args(argv)

    if args.tier is not None:
        say(messages.TIERS_ARE_GONE)
        return 2
    if args.status:
        return do_status(args)
    if args.uninstall:
        return do_uninstall(args)
    return do_install(args)


if __name__ == "__main__":
    raise SystemExit(main())
