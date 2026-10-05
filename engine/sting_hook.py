#!/usr/bin/env python3
"""The thin client. Read stdin, ask the daemon, print, exit.

    stdin ──> daemon/client.ask ──> stdout, stderr, exit code
                   │
                   └── None (no daemon, wrong daemon, slow daemon, any failure)
                       ──> import hook_entry ──> decide in-process, as before

⚠ THIS FILE MAY NOT IMPORT `core`, `adapters` OR `hook_entry` AT MODULE SCOPE,
AND THAT IS THE ENTIRE POINT. Measured on this machine: a bare interpreter costs
~16 ms and reaching the engine costs ~24 ms more, against an `engine.decide()`
of ~2 ms. An entry point that imported the engine to find out it did not need it
would have bought nothing at all. `tests/test_daemon_client_is_cheap.py` pins
the module list this process is allowed to load.

⚠ WHY A NEW FILE AND NOT A FLAG ON hook_entry.py. `hook_entry.py` imports the
engine on line 62, before anything it could branch on. Making that lazy would
mean moving every import inside every function of the module the whole test
suite drives — and `hook_entry.run()` is deliberately a pure function of its
input so tests can exercise it without a subprocess. Splitting the process from
the pipeline leaves both simple: this file is a transport, that one is the
guard.

────────────────────────────────────────────────────────────────────────────────
⚠ THE OBSERVE GUARANTEE IS ENFORCED HERE, LAST, AND OVER EVERYTHING
────────────────────────────────────────────────────────────────────────────────

`hook_entry.main()` has always had one choke point: in observe mode, whatever
happened, stdout is emptied and the exit code becomes 0. That choke point now
lives at the END of this file and applies to:

    a verdict from the daemon                          including exit 2
    a verdict decided in-process                       the old path, unchanged
    a daemon that returned something unparseable
    an ImportError, a SyntaxError or a SystemExit raised while trying to
      reach the engine at all
    a missing daemon, a stale socket, a wedged daemon, a refused request

⚠ INCLUDING THE PYTHON FLOOR, WHICH IS A REAL FIX AND NOT A RESTATEMENT.
`hook_entry.py` raises `SystemExit(2)` at import time on Python 3.10 — before
`main()` exists to suppress it. On an observe-mode install that exit BLOCKS the
tool call, which is the one thing observe mode promises never to happen. Here
the import is inside the `try`, so the floor check reports on stderr and the
call proceeds. Found by moving the import, not by looking for it.
"""
from __future__ import annotations

import os
import sys

# ⚠ `os.path`, NOT `pathlib`. Measured on this machine: importing `pathlib`
# costs +7.7 ms, `os.path` +0.4 ms, against a warm round trip of ~24 ms. A
# convenience worth a third of the budget is not a convenience.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ⚠ THE LABEL FOR "NOBODY SAID". Duplicated from hook_entry for the same reason
# `observing` and `pick_agent` are — importing hook_entry would import the
# engine, which is the whole cost this file exists to avoid — and pinned to it
# by tests/test_daemon_fails_open.py.
#
# ⚠ AND THIS FILE DELIBERATELY HAS NO `FALLBACK_ADAPTER`. It does not parse
# anything: it forwards a name to the daemon or to hook_entry.run, and BOTH ends
# resolve the parser through `hook_entry.resolve_agent`. A second copy of the
# fallback here would be a second place that could disagree about which adapter
# reads an unlabelled payload.
UNKNOWN_AGENT = "unknown"


def observing() -> bool:
    """⚠ DUPLICATED FROM hook_entry.observing(), AND PINNED TO IT BY A TEST.

    Importing it would mean importing the engine, which is the cost this file
    exists to avoid. `tests/test_daemon_fails_open.py` asserts the two agree on
    every spelling that has ever mattered — "", "0", "false", "no", "1".
    """
    return os.environ.get("STING_OBSERVE", "").strip() not in ("", "0", "false", "no")


def pick_agent(argv: list[str]) -> str:
    """⚠ DUPLICATED FROM hook_entry.pick_agent(), same reason, same pinning.

    It returns `unknown` for an undeclared invocation, never a real agent's
    name. The two copies must agree, or which path served a call would decide
    what the record CLAIMS ran — a daemon-served call labelled one way and an
    in-process fallback labelled another.
    """
    for i, arg in enumerate(argv):
        if arg == "--agent" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--agent="):
            return arg.split("=", 1)[1]
    return os.environ.get("STING_AGENT") or UNKNOWN_AGENT


def _in_process(payload: str, agent: str,
                hook_env: dict | None = None) -> tuple[str, str, int]:
    """The old path, imported only when the daemon could not answer."""
    import hook_entry
    return hook_entry.run(payload, agent, hook_env)


def _trace(note: str, err: str) -> str:
    """⚠ WHICH PATH SERVED THIS CALL — OFF BY DEFAULT, AND NOT COSMETIC.

    Without it, "the daemon is fast" is measured by timing calls and checking
    the socket still exists afterwards, which is a population that can contain
    fallbacks and cannot say so. `tools/bench_startup.py --daemon` turns this on
    and refuses to report unless EVERY call in the sample was daemon-served.

    Silent unless asked, because an extra line on stderr for every tool call is
    noise in the agent's transcript, and this guard already has notes worth
    reading there.
    """
    if os.environ.get("STING_DAEMON_TRACE", "").strip() in ("", "0", "false", "no"):
        return err
    return f"{err}\n{note}" if err else note


def no_daemon() -> bool:
    """STING_NO_DAEMON: decide in-process, and never START one.

    ⚠ THIS EXISTS BECAUSE A DAEMON OUTLIVES THE DIRECTORY THAT STARTED IT.
    `install.py` runs `tools/preflight.py` from the UNPACKED ARCHIVE, preflight
    drives the real `sting_hook.py`, and the first such call starts a resident
    daemon **from that temporary directory**. Measured by installing from the
    release tarball into a clean HOME:

        sting: served by the daemon
        …/sessions/probe.log.jsonl:  "guard_version": "uninstalled"

    The archive has no `INSTALL.json`, so the daemon answers `uninstalled` for
    every record it writes — the exact provenance defect `core/version.py`
    exists to prevent — and `daemon/server.should_exit` treats a boot version of
    `None` as "a developer's checkout, never superseded", so it does not stand
    down when the real install lands. The stranger then deletes the archive
    directory and a daemon keeps serving from it.

    ⚠ AND THE GENERAL PROBLEM IS BIGGER THAN THIS FLAG. The socket is per-HOME,
    not per-tree, so ANY daemon that claims it serves every hook on the machine
    whatever tree it came from. Making the client refuse a daemon of a different
    version is a protocol change on the hot path, and it is NOT made here — see
    docs/46-distribution-walk.md. This flag removes the one case that reaches a
    stranger: a diagnostic must not leave a resident process behind.

    The in-process path is the same code the daemon would run — `hook_entry.run`
    either way — so a preflight under this flag proves the same verdict and
    simply does not prove the transport. That limit is stated in preflight's own
    output rather than left for a reader to infer.
    """
    return os.environ.get("STING_NO_DAEMON", "").strip() not in ("", "0", "false", "no")


def decide(payload: str, agent: str,
           hook_env: dict | None = None) -> tuple[str, str, int]:
    """Daemon first, in-process second. Never raises.

    `hook_env` is this process's environment as the agent started it, before
    `~/.sting/env` was loaded (item B, docs/110 §B); it goes to whichever path
    decides, because the daemon's own environment is not the caller's."""
    if no_daemon():
        return _in_process(payload, agent, hook_env)

    from daemon import client

    reply = client.ask(payload, agent, hook_env=hook_env)
    if reply is not None:
        return (str(reply.get("stdout") or ""),
                _trace("sting: served by the daemon",
                       str(reply.get("stderr") or "")),
                int(reply["exit"]))

    # ⚠ START IT, THEN SERVE THIS CALL OURSELVES. Waiting for a daemon we just
    # spawned would put its whole boot on the latency of whichever tool call
    # happened to be first. It is started for the NEXT call, not this one.
    #
    # ⚠ AND A FAILURE TO START IS NOT AN ERROR ANYONE HERE SHOULD SEE. A
    # machine that can never start a daemon simply pays what it pays today, on
    # every call, forever — which is the current product.
    try:
        client.start()
    except Exception:                             # noqa: BLE001 — deliberate
        pass
    out, err, code = _in_process(payload, agent, hook_env)
    return out, _trace("sting: decided in-process (no daemon answered)", err), code


# ⚠ DUPLICATED FROM adapters/antigravity.render_failure, because this file may
# not import `adapters` — and on the Python floor it could not. Pinned to it by
# tests/test_antigravity_honours_the_answer.py. Antigravity reads exit 2 as a
# hook ERROR, which one of its two paths ignores and runs the call (docs/110 §A);
# a deny with exit 0 blocks on both. Every other agent keeps exit 2.
_DENY_ON_FAILURE = {"antigravity": '{"decision": "deny", "reason": '
                                   '"Sting could not decide, so this is blocked."}'}


def failed(agent: str, err: str) -> tuple[str, str, int]:
    """A guard that could not decide, told in the shape `agent` blocks on. The
    reason is fixed text: the exception's own stays on stderr."""
    deny = _DENY_ON_FAILURE.get(agent)
    return (deny, err, 0) if deny else ("", err, 2)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # ⚠ THE AGENT'S ENVIRONMENT, TAKEN BEFORE STING ADDS ITS OWN (item B,
    # docs/110 §B). A copy of a small dict; no import.
    hook_env = dict(os.environ)
    # ⚠ THE ENVIRONMENT IS LOADED FROM ~/.sting/env, NOT THE COMMAND LINE, so
    # hooks.json carries no settings and no secrets — see envfile.py. Done
    # BEFORE `decide`, so the daemon this starts inherits the values (client
    # passes os.environ to the child) and so the client sends the right carried
    # vars. Cheap: one small file read, no expensive import.
    import envfile
    envfile.load()
    agent = UNKNOWN_AGENT
    try:
        agent = pick_agent(argv)
        out, err, code = decide(sys.stdin.read(), agent, hook_env)
    except SystemExit as exc:
        # ⚠ CAUGHT ON PURPOSE — see the Python-floor note in the docstring.
        # hook_entry raises this at import on an interpreter below 3.11.
        out, err, code = failed(agent, f"sting: refused to start ({exc})")
    except BaseException as exc:                  # noqa: BLE001 — deliberate
        # Nothing above this line may take the process down. In observe mode a
        # traceback becomes a non-zero exit, and a non-zero exit blocks.
        out, err, code = failed(agent, f"sting: {type(exc).__name__}: {exc}")

    if observing():
        if out or code:
            note = f"sting: OBSERVE suppressed a blocking result (exit={code})"
            err = f"{err}\n{note}" if err else note
        out, code = "", 0

    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
