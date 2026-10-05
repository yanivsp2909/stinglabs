"""Ask the resident daemon, or say plainly that you could not.

⚠ THIS MODULE IMPORTS NOTHING FROM `core`, AND NOTHING EXPENSIVE FROM THE
STANDARD LIBRARY EITHER. The daemon exists because reaching the engine costs
~35 ms of every ~51 ms tool call. Measured on this machine, `pathlib` costs
+7.7 ms to import and `subprocess` +8.9 ms — so a client that used them
casually would hand back half of what the daemon saves. Paths here are strings,
and `subprocess` is imported inside `start()`, which is the only function that
spawns anything and is not on the warm path at all.

⚠ EVERY FAILURE HERE RETURNS `None`, AND `None` MEANS "DECIDE IT YOURSELF".
It never means allow, it never means deny, and it is never rendered. A daemon
that is missing, refusing, slow, wedged or speaking a different wire version is
the same event to the caller: this call gets decided in-process, the slow way,
with the answer it would have had before the daemon existed.
"""
from __future__ import annotations

import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon import protocol                                          # noqa: E402

CONNECT_TIMEOUT = 0.25
"""Long enough for a listening daemon on local IPC, short enough that a wedged
one costs less than the in-process path it falls back to."""

READ_TIMEOUT = 15.0
"""⚠ GENEROUS ON PURPOSE, AND THE REASON IS A DUPLICATE RECORD RATHER THAN A
WRONG VERDICT. A commit verdict spends ~40 ms inside `git`, and a request queued
behind two of them waits. If this timeout fires after the daemon has already
committed its record, the fallback decides the same action again and the log
carries two records for one tool call at consecutive seqs. That is a real cost
of a timeout, it is visible rather than silent, and it is much cheaper than the
alternative — a short timeout would make it routine.

⚠ AND IT IS WHY A WEDGED DAEMON IS EXPENSIVE, WHICH WAS UNDERSTATED ONCE.
`docs/36-daemon.md` first said a wedged daemon costs "0.25 s per call" — that is
CONNECT_TIMEOUT, and a wedged daemon does not refuse connections, it ACCEPTS
them and never answers. Measured against a daemon that accepts and never
replies: **one tool call took 15.1 seconds.** Sixty times the figure that was
written down, on every call, silently. Hence the breaker below."""

WEDGED_SUFFIX = ".wedged"
"""Where a socket goes when it stopped answering. Renamed rather than unlinked:
the inode is evidence, and a developer asking "what happened" should find
something."""


def _connect(sock_path: str) -> socket.socket | None:
    if not hasattr(socket, "AF_UNIX"):        # pragma: no cover — Windows
        return None
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError:
        return None
    conn.settimeout(CONNECT_TIMEOUT)
    try:
        # ⚠ CONNECT FROM INSIDE THE DIRECTORY when the absolute path would not
        # fit in `sun_path` (104 bytes on macOS). Same trick as `server.bind`,
        # same reason; a pytest tmpdir alone can exceed it.
        if len(sock_path.encode()) >= protocol.SUN_PATH_MAX:
            here = os.getcwd()
            try:
                os.chdir(os.path.dirname(sock_path))
                conn.connect(os.path.basename(sock_path))
            finally:
                os.chdir(here)
        else:
            conn.connect(sock_path)
    except OSError:
        conn.close()
        return None
    return conn


def trip_breaker(sock_path: str) -> bool:
    """Take a non-answering daemon's ADDRESS away. Returns True if we did.

    ⚠ THE CLIENT DETECTS THIS, NOT THE SUPERVISOR, AND THE REASON IS WHAT EACH
    ONE CAN SEE. A supervisor sees a live process with an open socket — which is
    exactly what a healthy idle daemon looks like too. **Only the caller knows a
    request went unanswered.** No amount of process supervision distinguishes
    "waiting for work" from "never going to reply"; one timed-out request does
    it immediately.

    ⚠ IT COSTS NOTHING WHEN HEALTHY. This runs only after a read timeout, so the
    warm path pays zero extra syscalls. Measured, for comparison, the two things
    a per-call health check WOULD have cost: `connect`+`close` to a healthy
    daemon is 0.025 ms p50 / 0.215 ms p99, and `os.stat` on the socket is
    0.0037 ms. Both are affordable — and both are useless here, because a
    wedged daemon accepts connections and its socket exists. A pre-flight check
    that a wedged daemon passes is a check that measures nothing.

    ⚠ RENAME, NOT KILL. Killing another process from a tool-call hook is a large
    step and it is not needed: with the address gone every later call falls
    straight through to the in-process path (~57 ms, which is what last week
    cost), and the daemon's own accept loop notices the socket is no longer its
    own and exits. One call pays the 15 s; the rest pay nothing.

    ⚠ AND 15 s IS NOT "SLOW", IT IS BROKEN. The worst measured verdict — a
    commit against a dirty index, three git spawns — is 56 ms warm. A daemon
    that has not answered in 15 seconds is not busy.
    """
    try:
        os.rename(sock_path, sock_path + WEDGED_SUFFIX)
        return True
    except OSError:
        # Somebody else already tripped it, or the socket is gone. Either way
        # the address is not there any more, which is the outcome we wanted.
        return False


def ask(payload: str, agent: str, root: str | None = None,
        env=None, hook_env=None) -> dict | None:
    """Send one request, return the response dict, or None to decide locally.

    `hook_env`: the caller's environment as its agent started it (item B,
    docs/110 §B); `protocol.request` sends only the names that may look secret."""
    sock_path = protocol.socket_path(root)
    conn = _connect(sock_path)
    if conn is None:
        return None
    try:
        conn.settimeout(READ_TIMEOUT)
        conn.sendall(protocol.encode(protocol.request(payload, agent, env, hook_env)))
        try:
            conn.shutdown(socket.SHUT_WR)     # EOF, so the server never blocks
        except OSError:
            pass
        chunks, size = [], 0
        while True:
            got = conn.recv(65536)
            if not got:
                break
            size += len(got)
            if size > protocol.MAX_MESSAGE:
                return None
            chunks.append(got)
    except socket.timeout:
        # ⚠ A TIMEOUT IS THE ONE FAILURE THAT REPEATS. A refused connection or a
        # closed socket costs microseconds and the next call retries harmlessly;
        # a daemon that accepts and never answers costs the full READ_TIMEOUT
        # every single time, forever, with nothing on stderr. This is the only
        # branch that trips the breaker, and it is deliberately not tripped by
        # the others.
        trip_breaker(sock_path)
        return None
    except OSError:
        return None
    finally:
        conn.close()

    if not chunks:
        return None
    try:
        reply = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(reply, dict) or reply.get("wire") != protocol.WIRE:
        return None
    if reply.get("refused"):
        # A refusal is not a verdict. The daemon is telling us it is not the
        # right daemon for this request; deciding in-process is the answer.
        return None
    if not isinstance(reply.get("exit"), int):
        return None
    return reply


def start(root: str | None = None, python: str | None = None) -> bool:
    """Try to become the process that starts the daemon. True if we spawned it.

    ⚠ TWO HOOKS WILL RACE HERE, AND THE LOSER MUST NOT WAIT. Both find no
    socket in the same millisecond. The winner takes an exclusive, NON-BLOCKING
    lock and spawns; the loser fails to take it and returns False immediately.

    ⚠ THE LOCK IS HANDED TO THE DAEMON AND HELD FOR ITS LIFETIME. The first
    version released it as soon as the spawn returned, which serialises the
    INSTANT of spawning and nothing else — measured with eight concurrent
    starters, FIVE of them won, because each took the lock in the gap after the
    previous one let go. The daemon takes a few tens of milliseconds to bind,
    and every hook arriving in that window started another one. Four then
    stood down on the socket check, so the end state was correct and the cost
    was four wasted interpreters.

    `flock` belongs to the OPEN FILE DESCRIPTION, and that survives `fork` and
    `exec`. So the fd is passed to the child and the PARENT CLOSES ITS COPY
    WITHOUT UNLOCKING — closing one fd does not release a lock another process
    still holds through the same description, but an explicit `LOCK_UN` would
    release it for both. The lock therefore stands from the instant the starter
    takes it until the daemon exits, however it exits.

    ⚠ AND THE WINNER DOES NOT WAIT EITHER. It spawns and returns, and its own
    call is then decided in-process. Waiting for the daemon to become ready
    would put the daemon's whole boot — the same ~35 ms of import, plus a bind
    — on the latency of the tool call that happened to be first. The first call
    after a boot costs what every call costs today; the second one is fast.

    ⚠ `subprocess` AND `fcntl` ARE IMPORTED HERE, NOT AT MODULE SCOPE.
    `subprocess` costs +8.9 ms to import, which is a third of the warm path's
    whole budget, and this function does not run on the warm path.
    """
    if not hasattr(socket, "AF_UNIX"):        # pragma: no cover — Windows
        return False
    try:
        import fcntl
        import subprocess
    except ImportError:                       # pragma: no cover — Windows
        return False

    root = root or protocol.session_root()
    try:
        os.makedirs(root, exist_ok=True)
        os.chmod(root, 0o700)
    except OSError:
        return False

    try:
        fd = os.open(protocol.lock_path(root), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return False
    spawned = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # ⚠ HELD — by a daemon that is running, or by one that is still
            # binding. Either way this process must not start a second one, and
            # must not wait for the first.
            return False
        entry = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "server.py")
        os.set_inheritable(fd, True)
        try:
            subprocess.Popen(
                [python or sys.executable, entry],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                # The locked fd travels to the daemon, which never closes it.
                pass_fds=(fd,),
                # ⚠ ITS OWN SESSION, so the daemon does not die when the agent
                # that happened to start it exits, and so a Ctrl-C in the
                # developer's terminal is not delivered to it.
                start_new_session=True,
                # The environment is INHERITED, deliberately: the hook's env is
                # the one `install.py` declared into the agent's hook config,
                # so the daemon boots pinned to exactly the store this client
                # was configured for. A daemon booted from a different shell
                # would refuse this client's requests rather than serve them
                # from the wrong root — see protocol.PINNED.
                env=dict(os.environ, STING_DAEMON_LOCK_FD=str(fd)),
                cwd=root)
        except OSError:
            return False
        spawned = True
        return True
    finally:
        # ⚠ CLOSED, NEVER UNLOCKED, WHEN THE SPAWN SUCCEEDED. `LOCK_UN` would
        # release the lock for the daemon too, since both hold the same open
        # file description. Closing this copy leaves the daemon holding it.
        #
        # ⚠ AND UNLOCKED WHEN IT DID NOT. A failed spawn must not leave a lock
        # nobody owns — that would mean no hook could ever start a daemon again
        # until this fd happened to be closed.
        try:
            if not spawned:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            os.close(fd)
