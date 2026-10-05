"""A daemon that never answers, and an uninstall that leaves one running.

Two items from the daemon pass's own "what got worse" list, closed — and the
first of them was UNDERSTATED BY SIXTY TIMES when it was written down.

    written      "a wedged daemon costs every caller 0.25 s per call"
    measured     15.1 SECONDS for one tool call

0.25 s is `CONNECT_TIMEOUT`, and a wedged daemon does not refuse connections. It
ACCEPTS them and never replies, so the caller waits out `READ_TIMEOUT`, which is
15 s and deliberately generous. Guessing which timeout applied, instead of
building the case and timing it, produced a number that was wrong by more than
the thing it was describing.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon import client, protocol                                  # noqa: E402
from tests import daemon_harness as H                                # noqa: E402

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"),
                                 reason="the daemon is POSIX-only; see TASK 6")


class WedgedDaemon:
    """Accepts every connection and answers none. The failure being defended.

    ⚠ NOT "a socket with nothing behind it" — that is the STALE case, it is
    refused instantly, and it costs nothing. The expensive one accepts.
    """

    def __init__(self, root: str):
        os.makedirs(root, exist_ok=True)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        here = os.getcwd()
        try:
            os.chdir(root)
            self.sock.bind(protocol.SOCKET_NAME)
        finally:
            os.chdir(here)
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.held: list[socket.socket] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.held.append(conn)          # and never, ever reply

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        for conn in self.held:
            try:
                conn.close()
            except OSError:
                pass
        self.sock.close()


def test_a_wedged_daemon_is_tripped_out_after_one_slow_call(tmp_path):
    """⚠ ONE CALL PAYS; THE REST MUST NOT.

    Before the breaker, every call cost READ_TIMEOUT forever, with nothing on
    stderr. The measured cost of that is 15.1 s per tool call.

    This test uses a short timeout so it does not take 15 s itself — the
    behaviour under test is the breaker, not the constant.
    """
    root = str(tmp_path / "store")
    wedged = WedgedDaemon(root)
    original = client.READ_TIMEOUT
    client.READ_TIMEOUT = 0.4
    try:
        sock = protocol.socket_path(root)
        assert os.path.exists(sock), "precondition: a socket is published"

        first = time.perf_counter()
        assert client.ask(H.payload(), "claude-code", root) is None
        slow = time.perf_counter() - first

        assert slow >= 0.4, "the first call must actually have waited"
        assert not os.path.exists(sock), "the breaker must remove the address"
        assert os.path.exists(sock + client.WEDGED_SUFFIX), \
            "and keep the inode as evidence rather than unlinking it"

        second = time.perf_counter()
        assert client.ask(H.payload(), "claude-code", root) is None
        assert (time.perf_counter() - second) < slow / 2, \
            "the second call must not pay the timeout again"
    finally:
        client.READ_TIMEOUT = original
        wedged.close()


def test_a_wedged_daemon_still_produces_a_verdict(tmp_path):
    """⚠ SLOW IS NOT BLOCKED. The whole point of the fallback is that a broken
    daemon costs time and never costs a decision."""
    root = str(tmp_path / "store")
    wedged = WedgedDaemon(root)
    try:
        env = H.env_for(root, STING_OBSERVE="0", STING_DAEMON_TRACE="1")
        done = H.hook(H.payload("git status", session="w"), env)

        assert done.returncode == 0, done.stderr
        assert "decided in-process" in done.stderr
        assert H.records(root), "the fallback must still record the decision"
    finally:
        wedged.close()


def test_a_refused_connection_does_not_trip_the_breaker(tmp_path):
    """⚠ THE OTHER HALF, AND IT IS THE ONE THAT KEEPS THE BREAKER HONEST.

    A stale socket is refused in microseconds and the next call retries
    harmlessly. Tripping on that would delete the address of a daemon that is
    merely restarting — turning a transient into a permanent fallback.
    """
    root = str(tmp_path / "store")
    os.makedirs(root, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    here = os.getcwd()
    try:
        os.chdir(root)
        sock.bind(protocol.SOCKET_NAME)
    finally:
        os.chdir(here)
    sock.close()                            # bound then closed: the file remains

    path = protocol.socket_path(root)
    assert client.ask(H.payload(), "claude-code", root) is None
    assert os.path.exists(path), "a refused connection must not trip the breaker"
    assert not os.path.exists(path + client.WEDGED_SUFFIX)


def test_a_healthy_daemon_is_never_tripped(tmp_path):
    """⚠ THE BREAKER MUST NOT FIRE ON THE PATH IT IS MEANT TO LEAVE ALONE.

    A first draft of this test asserted the shape of the `except` clause in the
    source, which is a test of how the code is spelled rather than of what it
    does — and it failed on its own regular expression while the behaviour was
    correct. What actually matters is that thirty real calls to a working daemon
    leave the socket exactly where it was.
    """
    root = str(tmp_path / "store")
    env = H.env_for(root)
    proc = H.start_daemon(root, env)
    try:
        sock = protocol.socket_path(root)
        before = os.stat(sock).st_ino

        for i in range(30):
            reply = client.ask(H.payload(f"echo {i}", session="healthy"),
                               "claude-code", root, env)
            assert reply is not None, f"call {i} was not served"

        assert os.path.exists(sock)
        assert os.stat(sock).st_ino == before, "the socket must not be replaced"
        assert not os.path.exists(sock + client.WEDGED_SUFFIX)
    finally:
        H.stop_daemon(proc)


# ────────────────────────────────────────────────────────── uninstall

def test_uninstall_stops_a_running_daemon(tmp_path, monkeypatch):
    """⚠ IT LEFT ONE RUNNING, HOLDING AN IMPORTED ENGINE, STILL WRITING.

    The daemon is not supervised — it is demand-started and idles out after 30
    minutes — so `supervisor.remove()` never touched it and nothing else did.
    """
    import install

    root = str(tmp_path / "sessions")
    env = H.env_for(root)
    proc = H.start_daemon(root, env)
    try:
        monkeypatch.setenv("STING_SESSION_ROOT", root)
        sock = protocol.socket_path(root)
        assert os.path.exists(sock), "precondition: a daemon is listening"

        notes = install.stop_daemons()

        assert any("stopped daemon" in n for n in notes), notes
        assert not os.path.exists(sock)
        assert os.path.exists(sock + ".uninstalled")
        proc.wait(timeout=30)
        assert proc.returncode == 0, "it exits on its own, unsignalled"
    finally:
        H.stop_daemon(proc)


def test_uninstall_says_so_when_no_daemon_is_running(tmp_path, monkeypatch):
    """⚠ SILENCE WOULD BE THE WRONG ANSWER. "none running" and "I did not look"
    are different facts, and an uninstaller that prints nothing for both is the
    absence-shaped bug this repo keeps finding."""
    import install

    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path / "empty"))
    monkeypatch.setattr(install.Path, "home", classmethod(lambda cls: tmp_path))

    notes = install.stop_daemons()

    assert notes == ["daemon               none running"]


def test_uninstall_does_not_kill_by_process_name():
    """⚠ `pkill -f daemon/server.py` IS THE OBVIOUS IMPLEMENTATION AND IT IS
    WRONG TWICE: it kills a daemon serving a different store, and it matches on
    a command line any process can carry. The socket names the one daemon this
    install is responsible for."""
    source = open(os.path.join(H.ROOT, "install.py"), encoding="utf-8").read()
    body = source[source.index("def stop_daemons("):source.index("def do_uninstall(")]

    assert "os.kill" not in body
    assert "SIGKILL" not in body and "SIGTERM" not in body
    # It may PRINT the pkill line as manual advice when the rename fails; it may
    # not run one.
    assert "subprocess" not in body


def test_uninstall_removes_hook_configs_before_stopping_the_daemon():
    """⚠ ORDER, AND IT IS NOT COSMETIC. Stopping the daemon first leaves a
    window in which one more tool call starts a fresh one against a tree that is
    being deleted."""
    source = open(os.path.join(H.ROOT, "install.py"), encoding="utf-8").read()
    body = source[source.index("def do_uninstall("):]

    # The hook configs are cleaned by `clean_hook_configs()` (D3: it also
    # visits every config the installed tree recorded), called first.
    assert body.index("clean_hook_configs(") < body.index("stop_daemons()")
    assert body.index("stop_daemons()") < body.index("place.remove()")
