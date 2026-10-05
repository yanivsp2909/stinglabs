"""Starting and stopping a real daemon, for the tests that need one.

⚠ A REAL PROCESS, NOT A MOCK, AND THAT IS THE POINT. Everything the daemon
changes — the socket's mode, the fallback when it is absent, the race between
two starters, whether a reinstall reaches a process that booted before it — is a
property of processes and files. A test double would assert the design instead
of the behaviour, which is how `allow_once` stayed broken for months behind two
green tests.

Not named `test_*`, so pytest imports it rather than collecting it.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from daemon import protocol                                          # noqa: E402

HOOK = os.path.join(ROOT, "sting_hook.py")
SERVER = os.path.join(ROOT, "daemon", "server.py")


def payload(command: str = "git status", session: str = "t",
            cwd: str | None = None, tool: str = "Bash", **extra) -> str:
    body = {"session_id": session, "cwd": cwd or ROOT,
            "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": {"command": command, **extra}}
    return json.dumps(body)


def env_for(root: str, **overrides) -> dict:
    """The environment a hook would have, with this test's store pinned."""
    env = dict(os.environ)
    env["STING_SESSION_ROOT"] = root
    env["STING_LOG"] = os.path.join(root, "decisions.jsonl")
    # ⚠ NO SHIPPED RELAXATIONS. These tests assert on the DECISION the engine
    # reaches through the real hook — several use a DENY as a precondition —
    # and the shipped default turns the `untrusted_unexpected:*` family down to
    # ASK. Without this they would be measuring the OVERLAY while claiming to
    # measure the daemon. `core/policy.py` supports declining the default for
    # exactly this reason; a harness is its first caller.
    env["STING_POLICY"] = os.path.join(root, "no-relaxations.json")
    os.makedirs(root, exist_ok=True)
    with open(env["STING_POLICY"], "w", encoding="utf-8") as handle:
        handle.write('{"shipped_default": false}')
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = str(value)
    return env


def start_daemon(root: str, env: dict | None = None,
                 timeout: float = 20.0) -> subprocess.Popen:
    """Boot a daemon and WAIT until its socket answers.

    ⚠ THE WAIT IS A LOOP ON THE SOCKET, NOT A SLEEP. A fixed sleep is a test
    that fails on a loaded machine and passes on an idle one, which is the
    same class of unreliability this repo's benchmark harness already had to
    fix by deciding on the worst of five runs.
    """
    os.makedirs(root, exist_ok=True)
    proc = subprocess.Popen([sys.executable, SERVER],
                            env=env or env_for(root),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sock = protocol.socket_path(root)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(sock):
            from daemon import client
            conn = client._connect(sock)
            if conn is not None:
                conn.close()
                return proc
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(f"daemon exited {proc.returncode}: "
                               f"{err.decode('utf-8', 'replace')[:500]}")
        time.sleep(0.02)
    stop_daemon(proc)
    raise RuntimeError(f"daemon never published a socket at {sock}")


def stop_daemon(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:                              # noqa: BLE001
        try:
            proc.kill()
        except Exception:                          # noqa: BLE001
            pass


def stop_declared(root: str) -> None:
    """Stop the daemon THIS store declared, and only that one.

    ⚠ NEVER `pkill -f daemon/server.py`. That pattern names every daemon this
    user runs: the installed guard's, and every daemon another worktree's test
    run started, which then fails for a reason that lives in this run. The
    daemon serving `root` writes its pid into `root`'s declaration
    (`daemon/server._declare`), so that pid is the one to stop.
    """
    from daemon.server import DECLARATION
    try:
        with open(os.path.join(root, DECLARATION), encoding="utf-8") as handle:
            said = json.load(handle)
        pid, booted_at = int(said["pid"]), float(said["booted_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return                                   # nothing declared, nothing to stop
    probe = subprocess.run(["ps", "-o", "lstart=,command=", "-p", str(pid)],
                           capture_output=True, text=True,
                           env={**os.environ, "LC_ALL": "C"}).stdout.strip()
    if "daemon/server.py" not in probe:
        return                                   # already gone, and the pid is not ours
    # ⚠ AND IT STARTED BEFORE IT DECLARED. A pid is reused: a process that
    # started after the declaration is not the daemon that wrote it. When the
    # start cannot be read, leave it: a suite's daemon idles out in seconds.
    try:
        started = time.mktime(time.strptime(" ".join(probe.split()[:5]),
                                            "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        return
    if started > booted_at + 1:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


def hook(stdin: str, env: dict, entry: str = HOOK,
         args: list[str] | None = None) -> subprocess.CompletedProcess:
    """One tool call, through the real entry point, as an agent would make it."""
    return subprocess.run([sys.executable, entry, *(args or [])],
                          input=stdin, capture_output=True, text=True,
                          env=env, timeout=60)


def records(root: str) -> list[dict]:
    path = os.path.join(root, "decisions.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out
