#!/usr/bin/env python3
"""Does Sting actually work on THIS machine? PASS/FAIL per line, non-zero on any FAIL.

    python3 tools/preflight.py                 # checks Claude Code by default
    python3 tools/preflight.py --agent cursor

⚠ WHY THIS EXISTS, AND WHY IT IS THE FIRST THING A SECOND MACHINE RUNS.
A hook that never fires and a hook that fires and allows everything produce
byte-identical evidence: none. Nothing in this repo has ever run on another
machine, and nothing has ever run on Windows. So the default assumption is that
the guard is dead, and this is the only thing that can disprove it.

⚠ IT MUST SURVIVE ITS OWN SUBJECT BEING BROKEN. Every check is wrapped, and the
engine is imported LAZILY inside a check rather than at module scope — because
on Windows `import fcntl` raises at import time (core/session.py, core/audit_log.py,
core/allow_once.py), and a preflight that dies on the thing it is meant to
report is worse than none. This file imports only the stdlib and only names that
exist on every supported platform.

WHAT IT CANNOT TELL YOU. It proves the hook RUNS when invoked directly. It
cannot prove the agent actually invokes it — that needs the agent to run, and
the settings check below is the closest available proxy.
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
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import probes                                              # noqa: E402


# ⚠ THE NAMES THE INSTALLER MAY HAVE WRITTEN, AND WHY THERE ARE TWO.
#
# `install.py` points agents at `sting_hook.py` — the thin client that asks the
# resident daemon and falls back in-process. `hook_entry.py` is that fallback,
# still installed and still runnable on its own, and it is what every install
# before the daemon wrote.
#
# ⚠ THIS LIST USED TO BE THE SINGLE STRING "hook_entry.py", AND PREFLIGHT
# THEREFORE FAILED ON EVERY CORRECT INSTALL the moment the installer moved. It
# was found by walking a clean install end to end rather than by a test, which
# is the argument for walking one: three separate places named the entry point
# and the other two had already drifted.
ENTRY_NAMES = ("sting_hook.py", "hook_entry.py")
ENTRY = ROOT / "sting_hook.py"
MIN_PYTHON = (3, 11)

# Documented per agent. ⚠ These are `~`- and project-relative and are the SAME
# string on every OS — no adapter encodes an OS-specific location, and the docs
# give none. On Windows an agent may ALSO look in %APPDATA%; that is unverified
# here and is one of the lines only he can confirm.
SETTINGS = {
    "claude-code": [Path(".claude/settings.json"), Path.home() / ".claude/settings.json"],
    "cursor":      [Path(".cursor/hooks.json"),    Path.home() / ".cursor/hooks.json"],
    "codex":       [Path(".codex/hooks.json"),     Path.home() / ".codex/hooks.json"],
    "copilot":     [Path(".github/hooks/hooks.json"), Path(".claude/settings.json")],
    "antigravity": [Path(".agents/hooks.json"),
                     Path.home() / ".gemini/config/hooks.json"],
}

ENV_VARS = ["STING_OBSERVE", "STING_SESSION_ROOT", "STING_ROOTS", "STING_SCRATCH"]

_failed = 0


def line(ok: bool | None, label: str, detail: str = "") -> None:
    """ok True -> PASS, False -> FAIL, None -> INFO (never fails the run)."""
    global _failed
    tag = "INFO" if ok is None else ("PASS" if ok else "FAIL")
    if ok is False:
        _failed += 1
    print(f"  [{tag}] {label}" + (f"  —  {detail}" if detail else ""))


_unconfigured = False


def _note_unconfigured() -> None:
    """Remember that a collector was never configured, so the summary can say
    what is true — the guard works here and reports to nobody — instead of
    claiming it is not known to work."""
    global _unconfigured
    _unconfigured = True


_unproven_supervisor = ""


def _note_unproven_supervisor(why: str) -> None:
    """⚠ THE MIRROR OF `_note_unconfigured`, AND WHY IT IS NEEDED NOW.

    Before this pass a Windows machine on the Startup-folder fallback always
    contributed a FAIL, so the closing line was unreachable from that state.
    Making those states INFO — correctly, they are not failures — hands that
    machine "all checks passed", with the supervisor axis resting on evidence
    the INFO line itself calls NOT PROOF two sentences earlier.

    "The summary must not contradict the lines above it" cuts both ways: it must
    not announce breakage on a working machine, AND it must not announce
    everything-passed on an unproven one.
    """
    global _unproven_supervisor
    _unproven_supervisor = why


def check_platform() -> None:
    line(None, "operating system",
         f"{platform.system()} {platform.release()} ({platform.machine()})")
    line(None, "interpreter", f"{sys.version.split()[0]} at {sys.executable}")
    line(sys.version_info >= MIN_PYTHON, "python floor",
         f"need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]} (StrEnum), have "
         f"{sys.version_info[0]}.{sys.version_info[1]}")


def check_imports() -> None:
    """The Windows tripwire. `fcntl` is POSIX-only and three core modules import
    it at module scope, so this is where a Windows machine stops today."""
    try:
        sys.path.insert(0, str(ROOT))
        import core.audit_log  # noqa: F401
        import core.session    # noqa: F401
        line(True, "engine imports", "core.session, core.audit_log")
    except Exception as exc:
        line(False, "engine imports", f"{type(exc).__name__}: {exc}")


def check_settings(agent: str) -> None:
    candidates = SETTINGS.get(agent, [])
    found = [p for p in candidates if p.is_file()]
    if not found:
        line(False, f"{agent} settings file",
             "none of " + ", ".join(str(p) for p in candidates))
        return
    path = found[0]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        line(False, f"{agent} settings file", f"{path}: {exc}")
        return
    line(True, f"{agent} settings file", str(path))

    # Does it point at an entry point that exists? Look for any absolute or
    # relative path ending in one of the names the installer writes.
    referenced = [tok.strip("\"',") for tok in text.replace(",", " ").split()
                  if tok.strip("\"',").endswith(ENTRY_NAMES)]
    if not referenced:
        line(False, "settings names an entry point",
             f"none of {', '.join(ENTRY_NAMES)} mentioned in the settings file")
        return
    target = Path(referenced[0]).expanduser()
    if not target.is_absolute():
        target = (path.parent / target).resolve()
    line(target.is_file(), "entry point exists", str(target))


def check_entry_runnable() -> None:
    """Runnable UNDER THE INTERPRETER THAT WILL ACTUALLY RUN IT — sys.executable
    here, which is the one the settings command string should also name."""
    if not ENTRY.is_file():
        line(False, "entry point runnable", f"missing: {ENTRY}")
        return
    # ⚠ AN ISOLATED SESSION ROOT, AND THIS PROBE IS WHY THE `unknown` SESSION
    # EXISTS AT ALL.
    #
    # It passed no `env`, so it inherited `STING_SESSION_ROOT` from the env file
    # and wrote a real decision record into the DEVELOPER'S LIVE STORE — once per
    # preflight, and `install.py` runs a preflight every time. Empty stdin parses
    # to an Action with no session id, so every one of them landed in a session
    # named by the fallback: `unknown`.
    #
    # ⚠ MEASURED, AND THE ATTRIBUTION IS EXACT rather than circumstantial. On
    # this machine `~/.sting/sessions/unknown.log.jsonl` held 62 records — every
    # one `kind=TOOL`, `tool_name=None`, `command=None`, ALLOW with no rule,
    # `cwd` the checkout, `guard_version` `uninstalled` — spanning 44 hours. All
    # 62 carry `action_hash b658d97d…`, which is `fingerprint(claude_code.parse({}))`
    # EXACTLY. Running one preflight took the file from 62 lines to 63.
    #
    # ⚠ SO IT WAS NEVER CURSOR, AND THAT MATTERED. The story attached to those
    # records was that Cursor names its session `conversation_id`, the
    # claude-code adapter reads `session_id`, and Cursor's payloads therefore
    # pile up under `unknown`. This machine has 4,262 records and NOT ONE with
    # `agent: cursor` — Cursor's hook has never fired here. A diagnostic writing
    # into the evidence store had been mistaken for a defect in an adapter.
    #
    # `check_end_to_end` and `check_semantic` already isolate exactly this way;
    # this was the one probe that did not. Same rule as STING_NO_DAEMON above:
    # a diagnostic must not leave anything behind in what it is diagnosing.
    root = Path(tempfile.mkdtemp(prefix="sting-preflight-entry-"))
    try:
        proc = subprocess.run(
            [sys.executable, str(ENTRY), "--agent", "claude-code"],
            input="", capture_output=True, text=True,
            env=dict(os.environ, STING_SESSION_ROOT=str(root),
                      STING_PURPOSE="preflight"))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    # ⚠ EMPTY STDIN NOW EXITS 2 BY DESIGN — it used to be treated as a
    # well-formed no-op that decided ALLOW, which became a silent permit once
    # ALLOW was rendered explicitly. Both 0 and 2 are accepted here because
    # what this probe asks is "did the entry point run at all", not "what did
    # it decide"; a Traceback is the failure it is looking for.
    ok = proc.returncode in (0, 2) and "Traceback" not in proc.stderr
    line(ok, "entry point runnable",
         f"exit={proc.returncode}" +
         ("" if ok else f" stderr={proc.stderr.strip().splitlines()[-1:]}"))


def check_env() -> None:
    for name in ENV_VARS:
        value = os.environ.get(name)
        line(None, f"env {name}", value if value is not None else "(unset)")

    # ⚠ THIS CHECK WAS STALE AND FAILED A CORRECT VALUE ON THE FIRST NATIVE
    # WINDOWS INSTALL.
    #
    # It asserted that STING_ROOTS "is split on ':'", which stopped being true
    # when the Windows port changed `split_roots` to `os.pathsep`. So on
    # Windows it reported `C:\Users\...` as unresolvable — a real path, on a
    # platform where `;` is the separator — and the user could not work around
    # it, because every Windows path contains a colon in `C:`.
    #
    # ⚠ THE CHECK NOW ASKS THE ENGINE'S OWN SPLITTER instead of restating its
    # rule. A check that describes a parser is a second copy of that parser and
    # will drift from it; one that CALLS it cannot.
    for name in ("STING_ROOTS", "STING_SCRATCH"):
        value = os.environ.get(name) or ""
        if not value:
            continue
        parts = probes.split_roots(value)
        missing = [p for p in parts if not Path(p).expanduser().is_dir()]
        line(not missing, f"{name} resolves",
             f"{len(parts)} path(s) split on {os.pathsep!r}"
             + (f", missing: {missing}" if missing else ""))


def check_trust_boundary() -> None:
    """⚠ IS THE PROJECT BOUNDARY NARROWER THAN THE WORK?

    THE FAILURE THIS CATCHES, measured on this machine: with STING_ROOTS unset,
    `project_roots` resolves to the ONE git repo containing cwd. A developer
    working across several sibling repos under one parent —
    then has every edit to a sibling judged OUTSIDE the project. In a session
    that also held a credential that produced 74 `secret_derived_external:
    write_outside` denials, the largest single class in that period.

    Multi-root is NOT missing from the engine: `state.workspace_roots` is a
    list, `is_inside_project` tests membership across all of it, and Cursor and
    Antigravity both send an array. Only the SETTING was absent — which is the
    whole reason this is a preflight line and not an engine change.

    Silence is the wrong default here. A narrow boundary does not fail; it
    over-denies, and in observe mode it does not even do that visibly. So this
    reports FAIL and names the exact export that fixes it.
    """
    sys.path.insert(0, str(ROOT))
    try:
        from core import engine, probes
    except Exception as exc:
        line(False, "trust boundary", f"engine unavailable: {exc}")
        return
    roots, note = probes.RealWorld().project_roots(str(ROOT))
    line(None, "project roots in use", ", ".join(roots) or "(none)")

    # Sibling git repositories under the same parent are the shape that bites.
    # ⚠ WRAPPED, because preflight must survive its own subject being broken —
    # an unreadable or absent parent is a listing failure, not a boundary
    # finding, and raising here would take the whole run down with it.
    parent = ROOT.parent
    try:
        siblings = sorted(
            str(p.resolve()) for p in parent.iterdir()
            if p.is_dir() and (p / ".git").exists() and p.resolve() != ROOT.resolve())
    except OSError as exc:
        siblings = []
        line(None, "sibling repositories", f"could not list {parent}: {exc}")
    if not siblings:
        # ⚠ NOT A PASS, AND THE DIFFERENCE IS THE POINT. This check can only see
        # repositories beside the CHECKOUT. Somebody who clones into ~/dev and
        # works in ~/code has no siblings here and gets a green line saying the
        # boundary covers their work — which this has not looked at and cannot.
        # "I found nothing to check" is not "there is nothing wrong": that is
        # the same vacuity that let allow-once pass while broken.
        declared = os.environ.get("STING_ROOTS")
        line(None, "trust boundary covers the work",
                f"no repositories beside the checkout, so this line checked "
                f"NOTHING about where you actually work. "
                + (f"Declared roots: {declared}. Confirm they contain the "
                    f"repositories you edit."
                    if declared else
                    "STING_ROOTS IS UNSET, so the boundary is the single repo "
                    "containing the cwd — the state that produced 74 of 89 "
                    "secret-rule denials in one measured period. Set it to "
                    "the repositories you work in."))
        return
    missing = [s for s in siblings if not engine.is_inside_project(s, tuple(roots))]
    if not missing:
        line(True, "trust boundary covers the work",
             f"{len(siblings)} sibling repo(s), all inside the declared roots")
        return
    # ⚠ THE REMEDIATION MUST NOT CONTAIN THE DEFECT IT DESCRIBES. This line
    # printed `export STING_ROOTS='C:\a:C:\b'` on Windows — a colon separator,
    # produced by the tool whose neighbouring check exists to catch colon
    # separators on Windows. The fifth time a message describing a defect has
    # contained it.
    want = probes.join_roots([str(ROOT.resolve())] + siblings)
    line(False, "trust boundary covers the work",
         f"{len(missing)} sibling repo(s) are OUTSIDE the declared roots — every "
         f"edit to them is a write_outside. Set:  export STING_ROOTS='{want}'")


def session_root() -> Path:
    return Path(os.environ.get("STING_SESSION_ROOT")
                 or "~/.sting/sessions").expanduser()


def check_session_root_writable() -> None:
    """⚠ THE MESSAGE MATTERS MORE HERE THAN THE CHECK, because this is the one
    failure that leaves the guard RUNNING and USELESS.

    Everything else on this list either works or stops. An unwritable session
    root does neither: the hook still fires, still decides, and then cannot
    write the record or the state — so it degrades to fail-closed at sinks and
    open everywhere else, and the evidence the whole product is about is not
    kept. It used to report `{root}: [Errno 13] Permission denied: {root}` —
    the raw exception, the path twice, no cause and no remedy, while the
    token-rejected message four lines below names both.
    """
    root = session_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".preflight-write-probe"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        line(True, "session root writable", str(root))
    except OSError as exc:
        line(False, "session root writable",
                f"{root}\n"
                f"             cost     the hook still runs and still decides, "
                f"and then keeps NOTHING — no session state, no decision log, "
                f"no chain. It degrades to closed at sinks and open elsewhere.\n"
                f"             cause    {_why_unwritable(root, exc)}\n"
                f"             fix      {_fix_unwritable(root)}")


def _why_unwritable(root: Path, exc: OSError) -> str:
    """The specific reason, from the errno and the filesystem — never the raw
    exception. `Permission denied` on its own does not say WHICH directory
    denied it, and the blocking one is usually a parent that already exists."""
    import errno

    blocker = root
    while not blocker.exists() and blocker != blocker.parent:
        blocker = blocker.parent

    if exc.errno == errno.EACCES:
        if blocker.is_dir():
            return (f"{blocker} exists and this user cannot write in it "
                     f"(mode {oct(blocker.stat().st_mode & 0o777)}, "
                     f"owner uid {blocker.stat().st_uid}, you are uid "
                     f"{getattr(os, 'getuid', lambda: '?')()})")
        return f"{blocker} denied it"
    if exc.errno == errno.EROFS:
        return f"{blocker} is on a READ-ONLY filesystem"
    if exc.errno == errno.ENOSPC:
        return "the filesystem is full"
    if exc.errno == errno.ENOTDIR:
        return f"{blocker} is a FILE, and a path component must be a directory"
    if exc.errno == errno.ENAMETOOLONG:
        return "the path is longer than this filesystem allows"
    return f"{type(exc).__name__} errno {exc.errno} at {blocker}"


def _fix_unwritable(root: Path) -> str:
    where = os.environ.get("STING_SESSION_ROOT")
    if where:
        return (f"STING_SESSION_ROOT points here. Either make it writable, or "
                 f"point it somewhere you own and re-run install.py:\n"
                 f"                        install.py  (it writes "
                 f"STING_SESSION_ROOT into your agent's hook config)\n"
                 f"                      then re-check:  "
                 f"STING_SESSION_ROOT=<dir> python3 tools/preflight.py")
    return (f"STING_SESSION_ROOT is unset, so this is the default "
             f"~/.sting/sessions. Usually a stale root-owned directory from a "
             f"`sudo` run:\n"
             f"                        ls -ld {root}\n"
             f"                        sudo chown -R $(id -u):$(id -g) "
             f"{root.parent}")


def check_end_to_end(agent: str) -> None:
    """One synthetic action through the REAL entry point, as a subprocess.

    Into a TEMPORARY session root, so a preflight can never append to a real
    session's chain — a diagnostic that writes into the evidence is not a
    diagnostic. The real root's writability is checked separately above.
    """
    payloads = {
        "claude-code": {"session_id": "preflight", "cwd": str(ROOT),
                         "hook_event_name": "PreToolUse", "tool_name": "Bash",
                         "tool_input": {"command": "git status"}},
        "cursor": {"conversation_id": "preflight", "workspace_roots": [str(ROOT)],
                    "hook_event_name": "beforeShellExecution",
                    "command": "git status"},
    }
    payload = payloads.get(agent, payloads["claude-code"])
    tmp = Path(tempfile.mkdtemp(prefix="sting-preflight-"))
    try:
        # ⚠ DECLARED IN THE INVOCATION, WHICH IS THE ONE PLACE THAT KNOWS.
        # Without this the probe inherits the installed hook's STING_PURPOSE
        # and every preflight record claims to be the developer's work.
        env = dict(os.environ, STING_SESSION_ROOT=str(tmp), STING_OBSERVE="1",
                    STING_PURPOSE="preflight")
        proc = subprocess.run(
            [sys.executable, str(ENTRY), "--agent", agent],
            input=json.dumps(payload), capture_output=True, text=True, env=env)
        if "Traceback" in proc.stderr or proc.returncode not in (0, 2):
            line(False, "synthetic action through the hook",
                 f"exit={proc.returncode} {proc.stderr.strip().splitlines()[-1:]}")
            return
        logs = sorted(tmp.rglob("*.log.jsonl"))
        if len(logs) != 1:
            line(False, "synthetic action through the hook",
                 f"expected 1 log file, found {len(logs)}")
            return
        parsed = [json.loads(l) for l in
                  logs[0].read_text(encoding="utf-8").splitlines() if l.strip()]
        # ⚠ 1 canary + 1 decision. The `session_start` record is written once per
        # session (hook_entry._canary), so counting raw lines here asserts the
        # pre-canary contract — this check failed on a healthy engine the moment
        # the canary landed.
        canaries = [r for r in parsed if r.get("event") == "session_start"]
        decisions = [r for r in parsed if r.get("event") == "decision"]
        line(len(canaries) == 1, "liveness canary written",
             f"{len(canaries)} session_start record(s)")
        line(len(decisions) == 1, "exactly one decision recorded",
             f"{len(decisions)} decision(s) in {logs[0].name}")

        sys.path.insert(0, str(ROOT))
        from core import audit_log
        ok, bad, detail = audit_log.verify_chain(logs[0])
        line(ok, "chain verifies", detail if ok else f"broke at record {bad}: {detail}")
    except Exception as exc:
        line(False, "synthetic action through the hook", f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_semantic(agent: str) -> None:
    """⚠ THE LINE THAT STOPS THIS PASSING ON A BLIND ENGINE.

    Every other check answers "did the hook run". A guard whose credential
    matcher never fires runs perfectly, writes a verifiable chain, and allows
    an exfiltration — and every line above this one still says PASS. That was
    not hypothetical: on a case-insensitive filesystem `cat .ENV` read the same
    bytes as `cat .env` and left the session unlabelled, and the whole I02
    sequence went ALLOW.

    So drive the product's own flagship result end to end, through the real
    hook process, in enforce mode, and require a DENY that names a secret rule.

    ⚠ AND IT RUNS FOR EVERY AGENT NOW. It used to run for claude-code and print
    "skipped — no I02 payload shape for <agent>" on the other four, so on the
    first machine that was not Claude Code, THE GUARD AGAINST A BLIND GUARD DID
    NOT RUN. Each adapter now states its own payload shape (`probe_payload`),
    which is the adapter's job — the shape is agent knowledge, and agent
    knowledge belongs in the adapter.

    ⚠ THE VERDICT IS READ FROM THE DECISION LOG, NOT FROM STDOUT. Every vendor
    renders a refusal in its own vocabulary, so parsing stdout would mean a
    sixth parser here that has to be updated for every new agent — and it would
    check the wrong thing. What matters is what was RECORDED: the log is the
    evidence the product sells, and reading it also proves the record carries
    the right `agent` label, which is the defect that made Cursor's records say
    claude-code.
    """
    sys.path.insert(0, str(ROOT))
    try:
        from adapters import ADAPTERS_BY_NAME
        adapter = ADAPTERS_BY_NAME.get(agent)
    except Exception as exc:                                     # noqa: BLE001
        line(False, "semantic check", f"adapters unavailable: {exc}")
        return
    if adapter is None or not hasattr(adapter, "probe_payload"):
        # ⚠ A FAILURE, NOT A SKIP. An adapter with no probe cannot be checked
        # for blindness, and "cannot be checked" must never read like "fine".
        line(False, "credential exfiltration is denied",
             f"adapter {agent!r} exposes no probe_payload — see "
             f"docs/24-adapter-contract.md")
        return
    tmp = Path(tempfile.mkdtemp(prefix="sting-semantic-"))
    proj, root = tmp / "proj", tmp / "sessions"
    proj.mkdir(); root.mkdir()
    (proj / ".env").write_text("FAKE_AWS_KEY=AKIA_TEST_PREFLIGHT_probe\n",
                                encoding="utf-8")
    env = dict(os.environ, STING_SESSION_ROOT=str(root), STING_ROOTS=str(proj),
                STING_PURPOSE="preflight")
    # ⚠ SET TO "0", NOT POPPED — AND THE DIFFERENCE IS EVERY DEFAULT INSTALL.
    #
    # `env.pop("STING_OBSERVE")` was correct when settings rode on the hook
    # command line. Since the Windows transport pass moved them into
    # `~/.sting/env`, POPPING A VARIABLE NO LONGER REMOVES IT: `envfile.load`
    # fills any key the environment does not already hold, so the file's
    # `STING_OBSERVE='1'` — which `install.py` has just written, because observe
    # is the DEFAULT — walked straight back in. The probe then ran in observe
    # mode, the adapter rendered ALLOW as observe mode promises, and this check
    # reported:
    #
    #     [FAIL] credential exfiltration is denied — the engine recorded DENY
    #            but the adapter rendered nothing
    #     1 FAIL — the guard is not known to be working on this machine.
    #
    # So a correct, working, default install ended by telling a stranger it was
    # NOT KNOWN TO BE WORKING, and `install.py` exited 1. Measured by installing
    # from the release tarball into a clean HOME.
    #
    # ⚠ THE ENVIRONMENT WINS OVER THE FILE — that is the one rule that makes an
    # explicit "0" work where an absence does not. `runner/replay.py` learned
    # exactly this when the env file nearly broke the A4 checkpoint; the lesson
    # was never swept through the other harnesses that drive the real hook.
    env["STING_OBSERVE"] = "0"          # a real verdict, not an observation
    # ⚠ THE COMMIT IS PART OF THE SHAPE, not padding. Without it the push
    # carries nothing traceable and the engine correctly returns ASK — a first
    # version of this check omitted it and reported a FAIL against a healthy
    # engine, which in a preflight is worse than a false pass: it teaches the
    # reader to ignore the line.
    steps = ["cat .env", "cp .env debug.env",
              "git add debug.env && git commit -m 'feat: debug config'",
              "git push origin main"]
    session = f"semantic-{agent}"
    rendered_last = ""
    try:
        for step_idx, step in enumerate(steps):
            payload = adapter.probe_payload(step, cwd=str(proj),
                                             session=session, step=step_idx)
            proc = subprocess.run(
                [sys.executable, str(ENTRY), "--agent", agent],
                input=json.dumps(payload), capture_output=True, text=True, env=env)
            rendered_last = proc.stdout.strip()

        from core import audit_log
        log = Path(audit_log.default_log_path(session)) if not root.exists() else None
        logs = sorted(root.glob("*.jsonl"))
        records = []
        for path in logs:
            for raw in path.read_text(encoding="utf-8").splitlines():
                if raw.strip():
                    records.append(json.loads(raw))
        decisions = [r for r in records if r.get("event") == "decision"]
        if not decisions:
            line(False, "credential exfiltration is denied",
                 "the hook ran but recorded no decision — "
                 "the payload never reached the engine")
            return
        final = str(decisions[-1].get("decision") or "").upper()
        reason = str(decisions[-1].get("reason") or "")
        labels = {r.get("agent") for r in decisions}
        ok = final == "DENY"
        # ⚠ THE LABEL IS PART OF THE ASSERTION. A record produced under
        # `--agent cursor` that says `claude-code` is a record nobody can act
        # on, and the panel refuses to guess for exactly that reason.
        mislabelled = labels - {agent}
        detail = (f"push after reading .env -> {final}"
                   + (f": {reason[:60]}" if ok else
                      "  — the engine boots but cannot see a credential"))
        if ok and mislabelled:
            ok = False
            detail = (f"DENY, but {len(decisions)} record(s) are labelled "
                       f"{sorted(mislabelled)} instead of {agent!r}")
        if ok and not rendered_last:
            ok = False
            detail = "the engine recorded DENY but the adapter rendered nothing"
        line(ok, "credential exfiltration is denied", detail)
    except Exception as exc:
        line(False, "credential exfiltration is denied", f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ───────────────────────────────────────── the three lines that close the loop

def check_supervisor_loaded() -> None:
    """⚠ A THIN GUARD, AND THE SECOND ATTEMPT AT IT.

    Every access in `_check_supervisor_loaded` is a bracket, and every test that
    drives it supplies its own dict — so renaming one key in
    `shipper/service.py` would pass the entire suite and raise KeyError out
    of `main()`, taking EVERY REMAINING CHECK with it, on a tool whose one
    invariant is that it survives its own subject being broken.

    ⚠ THE FIRST ATTEMPT VALIDATED THE WHOLE KEY SET UP FRONT AND WAS WORSE THAN
    THE BUG. Branches do not all read all ten keys — the takeover branch returns
    before most of them — so demanding them turned a real
    `[FAIL] another install owns this label` into an
    `[INFO] could not be determined`. A guard that downgrades a true FAIL is not
    a guard. Caught where it actually occurs, so only genuine drift is reported.
    """
    try:
        _check_supervisor_loaded()
    except KeyError as exc:                                      # noqa: BLE001
        line(None, "the shipper's supervisor is loaded",
                f"service.status() no longer returns the key {exc} that "
                f"preflight reads — the two have drifted. This is a preflight "
                f"defect, not a verdict about this machine")


def _check_supervisor_loaded() -> None:
    """⚠ THE OTHER TWO PROVE THE CHAIN WORKED ONCE. THIS ONE ASKS WHETHER IT
    WILL STILL BE WORKING TOMORROW.

    A record can round-trip to the collector from a shipper somebody started in
    a terminal an hour ago, which dies with that terminal — and then the two
    lines below stay green while the machine goes quiet forever. That is not
    hypothetical: on the first real end-to-end run the plist was written,
    launchd had never heard of the label, and the process doing the shipping
    was a hand-started one running from a checkout.

    THE THREE OUTCOMES ARE NOT THE SAME FINDING and are not reported as one:

        loaded                     PASS
        a file, but no service     FAIL — the contradiction. Somebody installed
                                   a supervisor and does not have one.
        no file at all             INFO — `--no-supervisor`, a deliberate
                                   choice. It still says what that costs,
                                   because the collector cannot tell an
                                   unsupervised machine from a dead guard.

    Imported inside the function like the engine, for the reason at the top of
    this file: preflight must survive its own subject being broken.
    """
    try:
        sys.path.insert(0, str(ROOT))
        from shipper import service
        state = service.status()
    except Exception as exc:                                     # noqa: BLE001
        line(None, "the shipper's supervisor is loaded",
                f"could not be determined: {type(exc).__name__}: {exc}")
        return

    # ⚠ ASKED FIRST, AND FROM THE SAME PLACE `install.py --status` ASKS.
    # Every branch below reports what WILL run the shipper; this reports whether
    # one is running NOW. The two are different claims and this file has been
    # the one that got it wrong.
    # ⚠ WHICH TREE IS ACTUALLY DECIDING. A daemon outlives the directory that
    # started it, so a resident one can answer from a tree that has since been
    # replaced — "loaded, running, doing the wrong thing", the fifth instance in
    # this project. An install ends that state (`daemon/server.superseded`
    # refuses and exits), but until now nobody could SEE it.
    try:
        from daemon import server as _daemon

        seen = _daemon.status()
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        seen = {"running": None, "detail": f"{type(exc).__name__}: {exc}"}
    if seen.get("running") is True and seen.get("declared"):
        if not seen.get("tree_exists"):
            line(False, "the daemon serves a tree that still exists",
                    f"⚠ pid {seen.get('pid')} is answering from {seen['tree']}, "
                    f"WHICH NO LONGER EXISTS. It is deciding with code nobody "
                    f"can read. Stop it and let the next call start a fresh "
                    f"one: kill {seen.get('pid')}")
        elif seen.get("tree_is_this_one") is False:
            line(None, "the daemon serves a tree that still exists",
                    f"pid {seen.get('pid')} answers from {seen['tree']}, which "
                    f"is not this checkout. Expected when you run the installed "
                    f"copy; a surprise if you are editing here")
        else:
            line(True, "the daemon serves a tree that still exists",
                    f"pid {seen.get('pid')} from {seen['tree']}")
    elif seen.get("running") is True:
        line(None, "the daemon serves a tree that still exists",
                "a daemon is running but declares no tree — it predates this "
                "check, which makes it exactly the one most likely to be "
                "stale. It will declare one when it next restarts")

    live = service.shipper_running()
    if live.get("running") is True:
        line(None, "a shipper is running right now",
                f"{live['detail']} — this is the lock the process itself holds, "
                f"so it counts a shipper started by the supervisor, by the "
                f"installer, by a Startup .cmd or by hand")
    elif live.get("running") is False and state.get("pid"):
        # ⚠ AND THIS IS NOT "NOTHING IS SHIPPING". A shipper started before the
        # lock existed holds no lock, so the absence of one is not the absence
        # of a shipper — saying otherwise would be this file's own bug in a new
        # place. The supervisor names a live pid; that is the stronger evidence.
        line(None, "a shipper is running right now",
                f"the lock is free, BUT {state['kind']} reports pid "
                f"{state['pid']} for this install. A shipper started before "
                f"this version does not hold one, so an empty lock is not "
                f"evidence of an empty machine. It will take the lock the next "
                f"time it restarts")
    elif live.get("running") is False:
        line(None, "a shipper is running right now",
                f"⚠ NO — {live['detail']}. Records are being recorded and are "
                f"safe on disk; nothing is leaving this machine at this moment. "
                f"The supervisor line below says what will run one LATER")
    else:
        line(None, "a shipper is running right now", live.get("detail", "unknown"))

    if state["kind"] == "unsupported":
        line(None, "the shipper's supervisor is loaded",
                f"{platform.system()} has no supported supervisor — run "
                f"`python3 -m shipper.run` yourself and keep it running")
        return
    if state["loaded"] is True and state.get("is_this_install") is False:
        # ⚠ A LOADED SERVICE THAT IS NOT YOURS IS WORSE THAN NO SERVICE, because
        # it looks like one. The label is per USER, so a second install under
        # the same account takes it — and the first install then has a green
        # supervisor line for a process shipping somebody else's logs.
        line(False, "the shipper's supervisor is loaded",
                f"{state['kind']} has {service.label()}, but it was loaded "
                f"from {state['running_file']} — NOT this install's "
                f"{state['path']}. The label is per USER, not per install, so a "
                f"second install under this account has taken it. Whichever of "
                f"the two you want, re-run its install.py; they cannot both "
                f"run.")
        return
    if state["loaded"] is True:
        line(True, "the shipper's supervisor is loaded",
                f"{state['kind']} has {service.label()}"
                + (f", pid {state['pid']}" if state["pid"] else " (no pid yet)")
                + (f", from {state['running_file']}" if state.get("running_file")
                    else ""))
        return
    if state["loaded"] is None:
        line(None, "the shipper's supervisor is loaded", state["detail"])
        return
    # ⚠ THE FALLBACK IS A CARRIER, AND PREFLIGHT DID NOT KNOW IT EXISTED.
    #
    # On the one real Windows machine `schtasks /Create` is REFUSED — at the
    # `\Sting\` folder and at the root, which the discriminator established is
    # an unelevated shell or a domain policy and not something an installer can
    # fix. `install.py` therefore WIRES a Startup-folder `.cmd` (it writes the
    # file; it does not merely print instructions), and that machine ships at
    # every logon.
    #
    # This function asked Task Scheduler and nothing else, so it reported
    # `FAIL … Re-run install.py` on a machine that was shipping perfectly well —
    # and `install.py --status`, which grew four states in the same pass, said
    # something different about the identical `service.status()` dict. TWO
    # ANSWERS TO ONE QUESTION, and the one a person reads first was the wrong
    # one. Same defect as the guard message that said "Phase 0 has not landed"
    # when Phase 0 had landed.
    if state.get("startup_shortcut"):
        # ⚠ A SHORTCUT WITHOUT THE INSTALL'S OWN FILE IS AN ORPHAN, NOT A
        # FALLBACK. `--uninstall` deletes the task XML and the wrapper .cmd and
        # NEVER CALLS `remove_startup_shortcut()` — it has no callers anywhere
        # in this repo — so an uninstalled machine keeps a Startup .cmd whose
        # `start "" /min "{wrapper}"` points at a file uninstall removed. Routing
        # that into the fallback report would tell somebody who deliberately
        # removed Sting that "schtasks refused to register a task" and, a week
        # later, to go and run the shipper by hand.
        if state["file_present"]:
            _report_startup_fallback(state)
            return
        line(None, "the shipper's supervisor is loaded",
                f"no {state['kind']} file, but a Startup shortcut is still "
                f"present at {service.startup_shortcut_path()}. That is an "
                f"ORPHAN — `--uninstall` removes the task and the wrapper it "
                f"calls, and does not remove this. It starts nothing. Delete "
                f"it, or re-run install.py if you meant this machine to be "
                f"guarded")
        return

    if not state["file_present"]:
        line(None, "the shipper's supervisor is loaded",
                f"no {state['kind']} file — installed with --no-supervisor, or "
                f"not installed at all. Whatever ships has to be kept running "
                f"by hand, and a machine that stops reporting looks identical "
                f"to a dead guard at the collector")
        return
    # ⚠ THE ONLY STATE THAT IS STILL A FAIL, AND IT IS CORRECT. No service, no
    # shortcut: nothing on this machine is carrying the shipper.
    #
    # ⚠ AND THE REMEDY IS NO LONGER "re-run install.py" ALONE. On a machine
    # where `schtasks` was refused once it will be refused again, so the same
    # command produces the same nothing. The Startup fallback is what that
    # machine needs, and naming it is the difference between an instruction and
    # a loop.
    remedy = ("Re-run install.py"
               if state["kind"] != "schtasks" else
               "Re-run install.py — it will retry the scheduled task and, if "
               "Windows refuses it again, write a Startup-folder .cmd that "
               "needs no elevation. If that is also refused, run "
               "`python3 -m shipper.run` and keep it running")
    line(False, "the shipper's supervisor is loaded",
            f"{state['path']} exists but {state['kind']} has no such service "
            f"— {state['detail']}. Anything shipping now was started by hand "
            f"and dies with its terminal. {remedy}")


def _shipper_last_moved() -> tuple:
    """(seconds since the shipper's cursor advanced, path) or (None, path).

    ⚠ THIS IS EVIDENCE, AND IT IS WEAKER THAN IT LOOKS. The cursor moving means
    *some* process advanced it. It does NOT mean the supervisor did, and it does
    not even mean a batch was accepted:

      * a shipper somebody started in a terminal advances it identically — which
        is the exact failure `check_supervisor_loaded` exists to catch, so
        treating a fresh cursor as proof of supervision would reintroduce it;
      * `Shipper._split` advances the cursor for a single record too large to
        send, after writing it to `undeliverable.jsonl`. No collector round trip
        happens at all.

    So this answers "has anything shipped recently", never "is the supervisor
    working". The caller must not upgrade it into the second claim.

    ⚠ THE PATH COMES FROM THE SHIPPER'S OWN CONFIG, NOT FROM `os.environ`.
    `Settings.state_root` reads the environment and then `~/.sting/env`, and a
    check that re-derives it from the environment alone silently inspects a
    different file the day somebody sets it in the file. A check that describes
    a parser is a second copy of that parser; one that CALLS it cannot drift.
    """
    cursor = None
    try:
        from shipper import config as scfg                        # noqa: E402
        cursor = scfg.from_env().state_root / "cursor.json"
        return time.time() - cursor.stat().st_mtime, cursor
    except (OSError, RuntimeError, ValueError, ImportError) as exc:
        # ⚠ RuntimeError AND ValueError, NOT JUST OSError. `Path.home()` raises
        # RuntimeError with no resolvable home — a service account, a broken
        # USERPROFILE — and that is not an OSError. The first version of this
        # function built the path OUTSIDE the try and claimed "never raises",
        # which was false on exactly the machines this check is for.
        return None, cursor or f"(path unresolved: {type(exc).__name__})"


# The keys `_check_supervisor_loaded()` indexes with brackets. ⚠ NOT ENFORCED AT
# RUNTIME — see the note on `check_supervisor_loaded`; requiring all ten before
# any branch runs downgraded a real FAIL. A test asserts `status()` still
# returns exactly this set, so drift is caught at development time instead.
_SUPERVISOR_KEYS = frozenset({
    "kind", "path", "startup_shortcut", "file_present", "loaded", "pid",
    "running_file", "is_this_install", "legacy_loaded", "detail"})


# How recently the cursor must have moved for it to be worth reporting as
# "something is shipping". ⚠ NOT "a live shipper touches it every heartbeat" —
# THAT IS FALSE AND AN EARLIER VERSION OF THIS COMMENT SAID IT. `should_flush`
# returns False when nothing is pending, and `Heartbeat` only ever READS the
# cursor (`cursor.summary()`), so an idle shipper never moves the file at all.
# This is three heartbeat intervals: an upper bound on how long a shipper WITH
# WORK TO DO stays quiet, and no evidence whatsoever about one without.
_CURSOR_FRESH_SECONDS = 3 * 900

# ⚠ AND THE POINT AT WHICH "IT HAS NOT RUN YET" STOPS BEING PLAUSIBLE. A Startup
# shortcut runs at LOGON, so a machine that has not been signed into since the
# install is innocently silent for hours or a day. It is not innocently silent
# for a week — by then the shortcut is either broken, quarantined, or was never
# executed, and INFO forever would be this check quietly giving up.
_FALLBACK_GRACE_SECONDS = 7 * 86400


def _age(seconds: float) -> str:
    """A duration an operator can act on. ⚠ `int(x // 3600)` printed '0h' for a
    46-minute-old cursor, which reads as nonsense at the moment somebody is
    troubleshooting one."""
    seconds = max(0.0, seconds)   # a restored-from-backup mtime can be ahead
    if seconds < 3600:
        return f"{int(seconds // 60)} min"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f} days"


def _report_startup_fallback(state: dict) -> None:
    """The Startup-folder carrier. ⚠ INFO, NOT PASS — and here is why.

    A PASS here would be a claim about the MECHANISM: "the Startup shortcut is
    carrying it." Nothing available locally supports that claim. The cursor
    cannot distinguish the shortcut from a shipper somebody started by hand in a
    terminal — and a hand-started shipper dying with its terminal is the precise
    failure this whole check was written for, found on the first real end-to-end
    run. Printing PASS on that evidence would make this the FIFTH defect in this
    repo of the shape "reports success while shipping nothing", introduced by
    the patch meant to stop a false failure.

    So the states are:

        the shortcut is a carrier and something is shipping   INFO, with both
                                                              facts and the gap
                                                              between them named
        the shortcut is a carrier and nothing has shipped     INFO while "not
                                                              signed in yet" is
                                                              plausible …
        … and it has been implausible for a week              FAIL
        the shortcut file is empty or unreadable              FAIL — it carries
                                                              nothing

    ⚠ AND FAIL IS REACHABLE FROM HERE ON PURPOSE. An INFO that can never become
    a FAIL is a check that has stopped checking, and this one's whole subject is
    whether the machine will still be shipping tomorrow.
    """
    from shipper import service

    try:
        where = service.startup_shortcut_path()
        body = where.read_text(encoding="utf-8", errors="replace")
        written_ago = time.time() - where.stat().st_mtime
    except (OSError, RuntimeError, ValueError) as exc:
        line(False, "the shipper's supervisor is loaded",
                f"{state['kind']} has no service, and the Startup shortcut that "
                f"should be carrying it could not be read "
                f"({type(exc).__name__}: {exc}). Nothing here is known to be "
                f"shipping. Run `python3 -m shipper.run` and keep it running")
        return

    # ⚠ `is_file()` IS NOT "IS A CARRIER". `install_startup_shortcut` returns
    # {"written": False} on an OSError, and a crash mid-write leaves a truncated
    # file that `startup_shortcut_present()` still counts. An empty .cmd starts
    # nothing.
    if not body.strip():
        line(False, "the shipper's supervisor is loaded",
                f"the Startup shortcut at {where} is EMPTY, so it starts "
                f"nothing at logon and {state['kind']} has no service either. "
                f"Re-run install.py to rewrite it; if that fails, run "
                f"`python3 -m shipper.run` and keep it running")
        return

    moved, cursor = _shipper_last_moved()
    shipping = moved is not None and moved <= _CURSOR_FRESH_SECONDS

    if shipping:
        _note_unproven_supervisor(
            "a Startup shortcut is carrying it, and a moved cursor "
            "cannot prove the shortcut is what moved it")
        line(None, "the shipper's supervisor is loaded",
                f"{state['kind']} refused to register a task, and a STARTUP "
                f"SHORTCUT is in place to carry it ({where}). The shipper's "
                f"cursor at {cursor} ADVANCED {_age(moved)} ago, so something "
                f"is running. ⚠ That is not the same as a batch being accepted: "
                f"`_split` also advances it for one record too large to send. "
                f"⚠ THIS IS NOT PROOF THE SHORTCUT IS WHAT MOVED IT: a shipper "
                f"started by hand in a terminal looks identical here and dies "
                f"with that terminal. To tell them apart, close every terminal "
                f"you started one in, wait {_CURSOR_FRESH_SECONDS // 60} min, "
                f"and run this again. ⚠ The shortcut also starts at LOGON, so a "
                f"machine sitting at the login screen ships nothing")
        return

    stale = (f"the cursor at {cursor} has not moved for {_age(moved)}"
              if moved is not None else f"there is no cursor at {cursor} yet")

    if written_ago > _FALLBACK_GRACE_SECONDS:
        line(False, "the shipper's supervisor is loaded",
                f"{state['kind']} has no service, a Startup shortcut has been "
                f"in place for {_age(written_ago)} ({where}), and {stale}. "
                f"A logon shortcut that has carried nothing in that long is "
                f"either broken, or this machine has had no agent activity to "
                f"ship at all — the cursor only moves when there is a batch, so "
                f"an idle machine looks identical to a dead one here. Check "
                f"whether {where} still exists and antivirus has not "
                f"quarantined it, then run "
                f"`python3 -m shipper.run` and keep it running")
        return

    _note_unproven_supervisor(
        "a Startup shortcut is carrying it and has not been seen "
        "to run yet")
    line(None, "the shipper's supervisor is loaded",
            f"{state['kind']} refused to register a task, and a STARTUP "
            f"SHORTCUT is in place to carry it ({where}, written "
            f"{_age(written_ago)} ago) — but {stale}, so nothing here shows "
            f"whether it has run. ⚠ THE PROOF IS TWO RUNS AND A GAP, because "
            f"it starts at LOGON and the cursor only moves when there is "
            f"something to ship: run ONE action through your coding agent "
            f"(anything — `git status` will do), then sign out and back in, "
            f"touch NOTHING, and run this again. A cursor that moved across "
            f"that gap was carried with nobody running a command. This line "
            f"becomes a FAIL if it is still silent in "
            f"{_age(_FALLBACK_GRACE_SECONDS)}")


def check_reaches_collector() -> None:
    """⚠ A GREEN INSTALL THAT REPORTS TO NOTHING IS THE FAILURE THIS WHOLE
    DESIGN EXISTS TO PREVENT, and until now it was assumed rather than tested.

    Everything above proves the guard decides and writes HERE. None of it proves
    a single byte reaches a collector — and every check passing while the
    collector has never heard of this machine is exactly the state an operator
    would read as healthy.

    So a record is BUILT HERE, shipped through the real shipper, and then read
    back OUT of the collector. Round trip, not a POST that returned 200.
    """
    import json as _json
    import urllib.error
    import urllib.request

    url = (os.environ.get("STING_COLLECTOR_URL") or "").rstrip("/")
    token = os.environ.get("STING_DEVICE_TOKEN") or ""
    device = os.environ.get("STING_DEVICE_ID") or ""
    if not (url and token and device):
        # ⚠ INFO, NOT FAIL, AND THE SUMMARY DEPENDS ON THE DIFFERENCE. An
        # unconfigured collector is a CONFIGURATION STATE somebody chose —
        # `--no-collector` is a supported install. Reporting it as a failure
        # made the summary say "the guard is not known to be working on this
        # machine" about a machine whose every local check had just passed, and
        # a summary that contradicts its own detail teaches people to skim the
        # detail. A collector that IS configured and does not answer is still a
        # FAIL, below.
        _note_unconfigured()
        line(None, "a record built here reached the collector",
                "NO COLLECTOR CONFIGURED (STING_COLLECTOR_URL / "
                "STING_DEVICE_TOKEN / STING_DEVICE_ID are not all set). The "
                "guard decides and records locally; nothing leaves this "
                "machine, and nobody can see that it is alive. Re-run "
                "install.py with a collector, or accept that this machine "
                "reports to nobody.")
        return

    sys.path.insert(0, str(ROOT))
    from core import audit_log, wire                            # noqa: E402
    from shipper import client, fingerprint_key, mask           # noqa: E402
    from shipper import config as scfg                          # noqa: E402

    # ⚠ THE SHIPPER'S FIRST QUESTION, ASKED HERE TOO (security review). This is
    # a second path that posts a batch; its record is a fixed probe, not the
    # developer's data, and it still sends nothing a machine did not agree to.
    settings = scfg.from_env()
    ships = settings.what_ships()
    if not ships["agreed"]:
        line(None, "a record built here reached the collector",
                f"NOT SENT: this machine has not agreed to what ships — "
                f"{ships['detail']}")
        return
    # ⚠ KEYED LIKE EVERY BATCH (core/wire.py): the laptop's own key, which the
    # install that runs this has made. Without one nothing is sent, as the
    # shipper sends nothing.
    key = fingerprint_key.load(settings.fingerprint_key_path)
    if key is None:
        line(None, "a record built here reached the collector",
                f"NOT SENT: no usable fingerprint key at "
                f"{settings.fingerprint_key_path} ({ships['fingerprint_key']})")
        return

    session = f"preflight-{int(time.time())}"
    body = audit_log.build_body(session, seq=1, event="decision", decision="ALLOW",
                                 kind="EXEC", command="sting preflight probe",
                                 cwd=str(ROOT), agent="preflight", ts=time.time())
    record = dict(body)
    record["prev"] = audit_log.GENESIS
    record["hash"] = audit_log.record_hash(audit_log.GENESIS, body)

    # ⚠ DECLARED AT THE SOURCE. This is a real record with a real chain, sent on
    # every install, and it is not work — a rate measured over a store that
    # pools these with a developer's sessions is measuring the installer.
    # ⚠ MASKED LIKE EVERY RECORD, through the shipper's own masking: a probe
    # that took another path would prove a path nothing else ships through.
    batch = wire.build_batch([record], device_id=device, session_id=session,
                              mask=mask.mask_record, purpose=wire.PREFLIGHT,
                              fingerprint=wire.fingerprinter(key))
    outcome = client.post(f"{url}/v1/batches", token,
                           _json.dumps(batch, sort_keys=True).encode(), timeout=15)
    if not outcome.advances:
        line(False, "a record built here reached the collector",
                f"the collector answered {outcome.kind} ({outcome.status}): "
                f"{outcome.detail or 'no detail'}")
        return

    # ⚠ READ IT BACK. A 200 says the collector accepted bytes; it does not say a
    # reader can find them. Needs the READER token, which the sender does not
    # hold — so its absence is reported as an incomplete check, never as a pass.
    reader = os.environ.get("STING_COLLECTOR_READER_TOKEN") or ""
    if not reader:
        line(True, "a record built here reached the collector",
                f"stored as batch {outcome.body.get('batch_ref')} in session "
                f"{session} — accepted, but not read back "
                f"(set STING_COLLECTOR_READER_TOKEN to close the loop fully)")
        return
    try:
        request = urllib.request.Request(
            f"{url}/v1/sessions/{device}/{session}",
            headers={"Authorization": f"Bearer {reader}"})
        with urllib.request.urlopen(request, timeout=15) as response:
            found = _json.loads(response.read())
        line(found.get("record_count", 0) >= 1,
                "a record built here reached the collector",
                f"read back from the collector: {found.get('record_count')} "
                f"record(s) in session {session}, chain_continuous="
                f"{found.get('chain_continuous')}")
    except Exception as exc:                                     # noqa: BLE001
        line(False, "a record built here reached the collector",
                f"stored, but could not be read back: {exc}")


def check_device_is_alive() -> None:
    """⚠ AND THE COLLECTOR MUST SAY SO ITSELF. Sending a heartbeat proves this
    process can reach a URL. Asking the collector whether it considers this
    device alive is the only thing that proves the two agree — and disagreement
    is the interesting case: a device that heartbeats to a collector which files
    it under a different id is silent as far as any reader is concerned.
    """
    import json as _json
    import urllib.request

    url = (os.environ.get("STING_COLLECTOR_URL") or "").rstrip("/")
    token = os.environ.get("STING_DEVICE_TOKEN") or ""
    device = os.environ.get("STING_DEVICE_ID") or ""
    if not (url and token and device):
        _note_unconfigured()
        line(None, "the collector reports this device as alive",
                "no collector configured — liveness cannot be established, and "
                "silence from this machine will mean nothing to anybody")
        return

    sys.path.insert(0, str(ROOT))
    from shipper import config as scfg                          # noqa: E402
    from shipper.cursor import Cursor                           # noqa: E402
    from shipper.heartbeat import Heartbeat                     # noqa: E402
    from shipper import client                                  # noqa: E402

    settings = scfg.from_env()
    beat = Heartbeat(settings, Cursor(settings.state_root / "cursor.json"))
    body = beat.payload()
    outcome = client.post(f"{url}/v1/heartbeat", token,
                           _json.dumps(body, sort_keys=True).encode(),
                           timeout=15)
    if outcome.kind == client.UNSUPPORTED:
        line(False, "the collector reports this device as alive",
                "this collector has no /v1/heartbeat route — it is older than "
                "this shipper. Batches still work; liveness does not.")
        return
    if not outcome.advances:
        line(False, "the collector reports this device as alive",
                f"the heartbeat was not accepted: {outcome.kind} "
                f"({outcome.status}) {outcome.detail}")
        return

    reader = os.environ.get("STING_COLLECTOR_READER_TOKEN") or ""
    if not reader:
        line(True, "the collector reports this device as alive",
                f"heartbeat accepted (count={outcome.body.get('heartbeat_count')}) "
                f"— set STING_COLLECTOR_READER_TOKEN to confirm from the "
                f"collector's own view")
        return
    try:
        request = urllib.request.Request(
            f"{url}/v1/devices/{device}",
            headers={"Authorization": f"Bearer {reader}"})
        with urllib.request.urlopen(request, timeout=15) as response:
            view = _json.loads(response.read())
        # `stale` is True, False, or None for "cannot yet be determined". Only
        # True is a failure: None on a first heartbeat is honest, not broken.
        line(view.get("stale") is not True,
                "the collector reports this device as alive",
                f"via={view.get('last_heard_via')} "
                f"stale={view.get('stale')} "
                f"basis={view.get('interval_basis')} — "
                f"{view.get('stale_reason', '')[:80]}")
    except Exception as exc:                                     # noqa: BLE001
        line(False, "the collector reports this device as alive",
                f"heartbeat accepted, but the device view could not be "
                f"read: {exc}")


def main(argv: list[str] | None = None) -> int:
    # ⚠ AT THE ENTRY POINT, NOT AT IMPORT — reconfiguring sys.stdout when the
    # module loads reaches into whatever imported it. Measured: it broke
    # pytest's capture for unrelated tests.
    try:
        from installer import console as _console
        _console.make_output_safe()
    except Exception:                                            # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", default="claude-code", choices=sorted(SETTINGS))
    args = ap.parse_args(argv)

    # ⚠ NO RESIDENT DAEMON, FOR THE WHOLE RUN AND EVERY CHILD OF IT.
    #
    # `install.py` runs this file from the UNPACKED ARCHIVE, and the first real
    # hook call starts a RESIDENT daemon from whatever directory it was invoked
    # in. That daemon then serves every later hook on the machine — from a
    # temporary directory the person is about to delete — and because the
    # archive has no `INSTALL.json` it stamps every record it writes
    # `guard_version: uninstalled`. Measured by installing from the release
    # tarball into a clean HOME:
    #
    #     sting: served by the daemon
    #     …/sessions/probe.log.jsonl   "guard_version": "uninstalled"
    #
    # `daemon/server.should_exit` treats a boot version of None as "a
    # developer's checkout, never superseded", so it does not stand down when
    # the real install lands either.
    #
    # ⚠ SET ONCE, HERE, RATHER THAN PER PROBE. There are three subprocess sites
    # and a fourth would forget; every child inherits `os.environ`.
    #
    # ⚠ AND IT NARROWS WHAT THIS FILE PROVES, WHICH IS SAID RATHER THAN HIDDEN:
    # the verdict path is identical (the daemon runs the same `hook_entry.run`),
    # but the DAEMON TRANSPORT is not exercised by a preflight. The line below
    # says so in the output.
    os.environ["STING_NO_DAEMON"] = "1"

    print(f"sting preflight — agent={args.agent}  checkout={ROOT}\n")
    check_platform()
    check_imports()
    check_settings(args.agent)
    check_entry_runnable()
    check_env()
    check_session_root_writable()
    check_trust_boundary()
    check_end_to_end(args.agent)
    check_semantic(args.agent)
    # ⚠ A LIMIT, STATED WHERE THE RESULT IS READ. Every probe above ran with
    # the daemon disabled, so what is proven is the VERDICT and not the warm
    # transport. Saying so here costs one line; leaving it out would let a green
    # preflight read as "the daemon works", which nothing here checked.
    line(None, "daemon transport",
         "NOT EXERCISED — every probe ran with STING_NO_DAEMON=1 so this "
         "diagnostic leaves no resident process behind. The verdict path is "
         "identical; the socket is not tested.")

    # ⚠ LAST, AND THEY ARE THE POINT. Everything above proves the guard works
    # HERE. These three prove the chain is real — that something built on this
    # machine arrived somewhere, that the collector agrees this device exists
    # and is alive, and that what carried it will still be there tomorrow.
    # Preflight is step one of setup, not a debugger.
    print()
    check_reaches_collector()
    check_device_is_alive()
    check_supervisor_loaded()

    # ⚠ THE SUMMARY MUST NOT CONTRADICT THE LINES ABOVE IT. It used to count
    # "no collector configured" as a failure and then announce that the guard
    # was not known to be working — on a machine where every local check had
    # just passed. A reader who catches a summary lying once stops reading the
    # detail, and the detail is the entire value of this tool.
    print()
    if _failed:
        print(f"{_failed} FAIL — the guard is not known to be working on this machine.")
        return 1
    if _unconfigured:
        print("the guard works on this machine, and it reports to NOBODY.")
        print("  Every local check passed: the hook fires, decides, and writes a")
        print("  verifiable record here. No collector is configured, so nothing")
        print("  leaves this machine and its silence tells no one anything.")
        print("  That is a choice, not a fault — re-run install.py with")
        print("  --collector-url, --device-id and --device-token to change it.")
        return 0
    if _unproven_supervisor:
        print("the guard works on this machine, and NOTHING HERE PROVES IT KEEPS")
        print("  SHIPPING WHEN YOU WALK AWAY.")
        print("  Every local check passed: the hook fires, decides, and writes a")
        print("  verifiable record here. But no scheduled task is carrying the")
        print(f"  shipper — {_unproven_supervisor}.")
        print("  ⚠ Read the supervisor line above and settle it the way it says:")
        print("  one action through your agent, sign out and back in, touch")
        print("  nothing, run this again, and see whether the cursor moved.")
        return 0
    print("all checks passed — the hook runs and writes a verifiable record here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
