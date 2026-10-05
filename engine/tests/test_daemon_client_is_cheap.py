"""TASK 5 and the start race — the client's floor, and two hooks racing to boot.

⚠ THE CLIENT'S IMPORT LIST IS A BUDGET, NOT A STYLE PREFERENCE. The daemon
exists because reaching the engine costs ~35 ms of a ~51 ms tool call. Measured
on this machine, `pathlib` costs +7.7 ms to import and `subprocess` +8.9 ms —
either one, added casually to the warm path, hands back a third of the saving.
This file fails when that happens, in the same run as the change.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import daemon_harness as H                                # noqa: E402

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"),
                                 reason="the daemon is POSIX-only; see TASK 6")


def _modules_after(source: str) -> set[str]:
    """Top-level modules a fresh interpreter has loaded after running `source`."""
    probe = (source + "\nimport sys\n"
             "print(' '.join(sorted({m.split('.')[0] for m in sys.modules})))\n")
    done = subprocess.run([sys.executable, "-c", probe],
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return set(done.stdout.split())


def test_the_client_does_not_import_the_engine():
    """⚠ THE ONE PROPERTY THAT MAKES THE DAEMON WORTH BUILDING.

    If `daemon.client` reached `core` or `adapters`, the warm path would pay
    the exact cost the daemon exists to remove, and every latency number in
    this pass would be a measurement of nothing.
    """
    loaded = _modules_after(
        f"import sys; sys.path.insert(0, {H.ROOT!r})\nfrom daemon import client")

    assert "core" not in loaded
    assert "adapters" not in loaded
    assert "hook_entry" not in loaded


def test_the_client_does_not_import_the_expensive_stdlib():
    """`pathlib` +7.7 ms, `subprocess` +8.9 ms, against a warm call of ~26 ms."""
    loaded = _modules_after(
        f"import sys; sys.path.insert(0, {H.ROOT!r})\nfrom daemon import client")

    assert "pathlib" not in loaded, "pathlib costs more than the message layer"
    assert "subprocess" not in loaded, "subprocess is only needed to START one"


def test_the_entry_point_does_not_import_the_engine_to_ask():
    """The same property, one level up: `sting_hook` imported, not run."""
    loaded = _modules_after(
        f"import sys; sys.path.insert(0, {H.ROOT!r})\nimport sting_hook")

    assert "core" not in loaded
    assert "adapters" not in loaded
    assert "pathlib" not in loaded


def test_hook_entry_still_imports_the_engine_at_module_scope():
    """⚠ THE OTHER HALF, WITHOUT WHICH THE THREE ABOVE PROVE NOTHING.

    They assert that a module does NOT load the engine. That is only
    meaningful if loading the engine is what the old path does — otherwise
    they would pass against a tree where `core` had been deleted. Working rule
    13: a negative is not a measurement until the positive is established.
    """
    loaded = _modules_after(
        f"import sys; sys.path.insert(0, {H.ROOT!r})\nimport hook_entry")

    assert "core" in loaded
    assert "adapters" in loaded


# ────────────────────────────────────────────────────────────── the start race

def test_only_one_of_many_racing_starters_spawns_a_daemon(tmp_path):
    """TASK 4's race, run for real with concurrent processes.

    ⚠ THE LOSERS MUST NOT WAIT, AND MUST NOT FAIL. Both outcomes are correct
    behaviour: the winner spawned, the losers found the lock held and returned
    immediately to decide in-process. What must never happen is two daemons for
    one store — the shape that produces two answers for one action.
    """
    root = str(tmp_path / "store")
    os.makedirs(root, exist_ok=True)
    probe = (
        f"import sys, json; sys.path.insert(0, {H.ROOT!r})\n"
        f"from daemon import client\n"
        f"print(json.dumps(client.start({root!r})))\n")

    running = [subprocess.Popen([sys.executable, "-c", probe],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=H.env_for(root), text=True)
               for _ in range(8)]
    results = []
    try:
        for proc in running:
            out, err = proc.communicate(timeout=60)
            assert proc.returncode == 0, err
            results.append(out.strip() == "true")
    finally:
        H.stop_declared(root)

    assert sum(results) == 1, f"exactly one starter must win, got {results}"


def test_a_second_daemon_refuses_to_shadow_the_first(tmp_path):
    """Two daemons for one store is the shape that must not exist at all.

    ⚠ IT IS REFUSED AT THE LOCK, NOT RESOLVED AT THE SOCKET. An earlier design
    let the second bind and rename its socket over the first's, and the first
    then noticed and exited. That converges, but it means a live daemon can be
    displaced by any process that starts one — and there is a window where two
    are answering. Refusing at the lock removes both.
    """
    root = str(tmp_path / "store")
    env = H.env_for(root)
    first = H.start_daemon(root, env)
    try:
        second = subprocess.Popen([sys.executable, H.SERVER], env=env,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        _out, err = second.communicate(timeout=60)
        assert second.returncode == 0, "declining is not an error"
        assert "refusing to become a second one" in err

        assert first.poll() is None, "the incumbent must be untouched"
        done = H.hook(H.payload("git status", session="two"), env)
        assert done.returncode == 0, done.stderr
    finally:
        H.stop_daemon(first)


def test_the_lock_is_released_when_the_daemon_dies(tmp_path):
    """⚠ OTHERWISE ONE CRASH WOULD MEAN NO DAEMON EVER AGAIN.

    A lifetime lock is only safe if death releases it. It does, because the
    kernel closes the fd — but that is a property worth a test, since the
    alternative failure is silent and permanent: every later hook would see the
    lock held, decline to start anything, and pay the full cold cost forever.
    """
    root = str(tmp_path / "store")
    env = H.env_for(root)
    first = H.start_daemon(root, env)
    first.kill()
    first.wait(timeout=10)
    try:
        os.unlink(os.path.join(root, "daemon.sock"))
    except OSError:
        pass

    second = H.start_daemon(root, env)      # raises if the lock were stuck
    try:
        done = H.hook(H.payload("git status", session="revive"), env)
        assert done.returncode == 0, done.stderr
    finally:
        H.stop_daemon(second)


# ───────────────────────────────────────────── the daemon answers identically

@pytest.mark.parametrize("command,session", [
    ("git status", "eq1"),
    ("rm -rf /tmp/does-not-exist-sting", "eq2"),
    ("python3 -c 'print(1)'", "eq3"),
    ("cd /tmp && ls -la | head -20", "eq4"),
])
def test_the_daemon_and_the_fallback_give_the_same_answer(tmp_path, command,
                                                           session):
    """⚠ THE TRANSPORT MUST NOT BE A POLICY CHANGE.

    The same payload, decided once through a warm daemon and once in-process,
    must produce the same stdout and the same exit code. Two stores, so neither
    run's session history can influence the other.
    """
    warm_root = str(tmp_path / "warm")
    cold_root = str(tmp_path / "cold")
    warm_env = H.env_for(warm_root)
    cold_env = H.env_for(cold_root)

    proc = H.start_daemon(warm_root, warm_env)
    try:
        warm = H.hook(H.payload(command, session=session), warm_env)
    finally:
        H.stop_daemon(proc)
    cold = H.hook(H.payload(command, session=session), cold_env,
                  entry=os.path.join(H.ROOT, "hook_entry.py"))

    assert warm.stdout == cold.stdout, f"{command}: {warm.stderr}"
    assert warm.returncode == cold.returncode


# ─────────────────────────────────────────────────── the single-threaded rule

def test_the_server_is_single_threaded():
    """⚠ `_environment()` SWAPS `os.environ` AROUND ONE REQUEST.

    That is safe in a single-threaded accept loop and a data race the moment it
    is not. "Add a thread pool for throughput" is the obvious next change and
    this is the thing it breaks, so the constraint is a test rather than a
    paragraph somebody may not read.
    """
    source = open(os.path.join(H.ROOT, "daemon", "server.py"),
                  encoding="utf-8").read()
    code = "\n".join(line for line in source.splitlines()
                     if not line.strip().startswith("#"))
    for forbidden in ("import threading", "ThreadPool", "concurrent.futures",
                      "import asyncio", "os.fork"):
        assert forbidden not in code, (
            f"{forbidden} in the server: _environment() is not thread-safe")


def test_the_default_residency_is_the_documented_one(monkeypatch):
    """⚠ THE SUITE RUNS WITH A 5 s RESIDENCY, SO THE REAL DEFAULT NEEDS ITS OWN
    TEST OR NOTHING EVER EXERCISES IT.

    `conftest.armed_gates` sets STING_DAEMON_IDLE=5 for every test, because a
    suite that leaves fourteen half-hour processes behind is not acceptable —
    and that is measured, it happened. But arming a value suite-wide means the
    shipped default becomes a number nothing checks, which is the same shape as
    a gate nothing arms.
    """
    import importlib

    monkeypatch.delenv("STING_DAEMON_IDLE", raising=False)
    from daemon import server
    importlib.reload(server)
    try:
        assert server.IDLE_EXIT == 1800
    finally:
        importlib.reload(server)


def test_a_leaked_daemon_goes_away_on_its_own(tmp_path):
    """The residency bound, exercised rather than trusted.

    ⚠ THIS IS THE PROPERTY THE WHOLE "what got worse" LIST RESTS ON. "Memory
    that stays allocated, bounded by STING_DAEMON_IDLE" is only true if the
    bound works. A daemon nobody talks to must exit.
    """
    root = str(tmp_path / "store")
    env = H.env_for(root, STING_DAEMON_IDLE="1")
    proc = H.start_daemon(root, env)
    try:
        proc.wait(timeout=60)
        assert proc.returncode == 0, "an idle daemon exits cleanly"
        assert not os.path.exists(os.path.join(root, "daemon.sock")), \
            "and it takes its socket with it"
    finally:
        H.stop_daemon(proc)
