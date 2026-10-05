#!/usr/bin/env python3
"""The resident guard. Boots once, imports once, decides many times.

    python3 daemon/server.py            serve until idle
    python3 daemon/server.py --status   is one running, and where

────────────────────────────────────────────────────────────────────────────────
WHAT MOVED, AND WHAT DELIBERATELY DID NOT
────────────────────────────────────────────────────────────────────────────────

This process calls `hook_entry.run()` — the same function the standalone hook
calls, with the same session lock, the same audit-chain append and the same
fsync. **That is the design, not an intermediate step.** Three things follow,
and each was argued rather than inherited:

⚠ 1 · THE FILE LOCK STAYS, AND "one writer now" IS NOT A REASON TO REMOVE IT.
      The daemon is NOT the only writer and cannot become one:

          the fallback path        every call the daemon cannot serve is
                                   decided in-process, by a process that
                                   opens the same files. That path is
                                   permanent — it is what TASK 4 requires.
          the VS Code extension    writes allow-once grants
          install.py               sweeps grants on reinstall
          a second daemon          a client pinned to a different store runs
                                   its own, and `tools/` read the same logs

      The lock was proved load-bearing with real processes on Windows. Removing
      it on the strength of a single writer would be removing it on the strength
      of a claim this design does not make.

⚠ 2 · SESSION STATE IS NOT CACHED IN MEMORY, AND THE NUMBER SAYS WHY.
      `open_session()` — read, parse, yield, serialise, write, fsync — measures
      at ~1.0 ms p50 against ~50 ms of per-call cost. Caching it would buy
      that 1 ms and take on a staleness class with no upper bound on its cost:
      the extension, a second daemon and every fallback call write the same
      file, and an in-memory copy that missed one of those writes would decide
      against a session that no longer exists. `authored_paths` and its 512 cap
      live in that state too, and `from_dict` rebuilding `_authored_index` per
      request is exactly the behaviour that already had to be fixed once when
      an in-memory index went stale between actions.

      ⚠ So the daemon removes the IMPORT, which is 24 ms, and not the STATE
      READ, which is 1 ms. Those are separate claims and only the first is made.

⚠ 3 · OBSERVE MODE IS NOT DECIDED HERE. `hook_entry.main()` keeps its choke
      point and applies it to whatever this returns — including an exit 2 and
      including a response this process never sent. See TASK 4 in
      `docs/36-daemon.md`.

────────────────────────────────────────────────────────────────────────────────
⚠ WHO CAN CONNECT, AND WHAT THEY CAN DO — READ BEFORE CHANGING THE SOCKET
────────────────────────────────────────────────────────────────────────────────

The socket is 0600 inside a 0700 directory, so the kernel restricts it to the
owning user. That is the SAME boundary that already protects the session files
and the audit log, which any process running as this user can read today with
`cat`. **The daemon adds no confidentiality that the filesystem did not already
grant, and takes none away.**

What it does add is a way to make the daemon act on a session. A local process
— and the agent IS a local process, that is the premise — can send an action
naming any session id and cause it to be labelled. It matters enormously that
this is a ONE-WAY door:

    mark_untrusted / mark_secret / taint   set flags and never clear them
    taint()                                never downgrades a level
    authored / truncated                   never shrinks, never resets

So an attacker with the socket can make a session MORE restricted, never less.
The reachable outcome is denial of service against the developer, not a bypass
of the guard. Verified by `tests/test_daemon_socket_surface.py`, which asserts
the absence of any clearing path rather than trusting this paragraph.

⚠ WHAT IT DOES NOT DEFEND AGAINST, STATED PLAINLY. A process running as this
user can already read every session file, append forged records to the audit log
(the chain is unkeyed — it is tamper-EVIDENT against later editing, not against a
live local writer), and write its own allow-once grant. `core/allow_once.py`
documents that last one as a deliberate Solo-tier gap: any secret this process
could check, the agent could read. The socket sits at the same boundary. Closing
it needs a signature over a key the agent cannot reach, which is control-plane
work.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hook_entry                                                    # noqa: E402
from core import allow_once                                          # noqa: E402
from daemon import protocol                                          # noqa: E402

IDLE_EXIT = float(os.environ.get("STING_DAEMON_IDLE") or 1800)
"""⚠ A RESIDENT PROCESS THAT NEVER LEAVES IS A COST, so this one leaves. After
this many seconds with no request it exits, and the next tool call pays one
cold start to bring it back. Bounding the residency is the answer to "memory
that stays allocated" — not a promise that it is small."""

POLL = 1.0
"""How often the accept loop wakes to check the clock and its own socket."""

REFUSED_SUPERSEDED = "superseded-by-a-reinstall"


def superseded(booted_with) -> bool:
    """Has an install happened since this process imported its policy?

    ⚠ THE PROBLEM THIS SOLVES IS "WHICH CODE IS DECIDING", AND IT IS NOT THE
    SAME QUESTION AS ALLOW-ONCE'S.

    `core.allow_once.install_time()` is re-read per request, so a reinstall
    correctly revokes outstanding grants even against a daemon that booted
    before it. But the daemon's `core` and `adapters` are the ones it IMPORTED,
    and nothing re-imports them. A developer who changes a rule, re-runs
    `install.py` and tries again would be answered by the OLD policy until the
    daemon idled out half an hour later — with the log recording the old
    `guard_version` and everything looking healthy.

    So a superseded daemon REFUSES the request and then exits. Refusing rather
    than serving it is the point: the client falls back in-process, which
    imports the NEW code, so the very request that noticed the reinstall is
    answered by the policy the reinstall put there.

    ⚠ `None` means no install, which is the normal state of a checkout during
    development. It is not "superseded", and treating it as such would make the
    daemon exit after every request on a developer's machine.
    """
    if booted_with is None:
        return False
    now = allow_once.install_time()
    return now is not None and now > booted_with


@contextmanager
def _environment(carried: dict):
    """Apply the CALLER's per-invocation settings for the length of one request.

    ⚠ WHY THE ENVIRONMENT AND NOT AN ARGUMENT. `STING_ROOTS`, `STING_SCRATCH`
    and `STING_OBSERVE` are read from `os.environ` by `hook_entry` and
    `core.probes` today. Threading them through as parameters would mean
    changing the signature of the pure decision path to serve a transport, and
    the standing rule for this pass is that `core/` barely changes. Swapping the
    process environment around a single request is honest about what it is: the
    daemon pretending, for one call, to be the process that asked.

    ⚠ SAFE ONLY BECAUSE THIS SERVER IS SINGLE-THREADED. If it ever grows a
    thread pool this becomes a data race between concurrent requests, and the
    settings would have to be threaded through properly. Stated here because
    "add threads for throughput" is the obvious next change and this is the
    thing it breaks. `tests/test_daemon_is_single_threaded.py` pins it.
    """
    before = {name: os.environ.get(name) for name in protocol.CARRIED}
    try:
        for name in protocol.CARRIED:
            value = carried.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = str(value)
        yield
    finally:
        for name, value in before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _peer_is_us(conn: socket.socket) -> bool:
    """Defence in depth. The real boundary is the 0700 directory.

    ⚠ AVAILABLE ON LINUX ONLY, AND THE ABSENCE IS NOT A FAILURE. `SO_PEERCRED`
    does not exist on macOS, so this returns True there and the file mode is the
    whole of the enforcement — which is also true of every session file beside
    it. Reporting a missing syscall as a hostile peer would refuse every request
    on the platform this is developed on.
    """
    opt = getattr(socket, "SO_PEERCRED", None)
    if opt is None:
        return True
    try:
        import struct
        raw = conn.getsockopt(socket.SOL_SOCKET, opt,
                              struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
    except OSError:
        return True
    return uid == os.getuid()


def handle(raw: bytes) -> dict:
    """One request in, one response out. Never raises.

    The pin check is the whole of the access decision that is not the file mode:
    a request configured for a different store is REFUSED rather than served
    from this daemon's, and the client then decides it in-process.
    """
    try:
        message = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return protocol.refusal(protocol.REFUSED_WIRE, f"unparseable: {exc}")
    if not isinstance(message, dict):
        return protocol.refusal(protocol.REFUSED_WIRE, "not an object")
    if message.get("wire") != protocol.WIRE:
        return protocol.refusal(
            protocol.REFUSED_WIRE,
            f"client speaks {message.get('wire')!r}, this daemon speaks "
            f"{protocol.WIRE}")

    mine, theirs = protocol.pins(), message.get("pins")
    if not isinstance(theirs, dict) or theirs != mine:
        # ⚠ NOT SERVED, AND NOT AN ERROR EITHER. The honest outcome is that this
        # is the wrong daemon for this client. Serving it would mean writing one
        # configuration's audit chain into another's store.
        return protocol.refusal(
            protocol.REFUSED_PINS,
            f"daemon pinned to {mine}, request declares {theirs}")

    payload = message.get("payload")
    agent = message.get("agent")
    if not isinstance(payload, str) or not isinstance(agent, str):
        return protocol.refusal(protocol.REFUSED_WIRE, "payload/agent missing")

    carried = message.get("carried")
    # THE CALLER'S ENVIRONMENT (item B, docs/110 §B): handed to the engine for
    # this request only, as an argument — never merged into this process's.
    # Anything but a str-to-str object is no view at all.
    hook_env = message.get("hook_env")
    if not (isinstance(hook_env, dict) and all(
            isinstance(k, str) and isinstance(v, str) for k, v in hook_env.items())):
        hook_env = None
    with _environment(carried if isinstance(carried, dict) else {}):
        out, err, code = hook_entry.run(payload, agent, hook_env=hook_env)
    return {"wire": protocol.WIRE, "stdout": out, "stderr": err, "exit": code}


def bind(root: str) -> tuple[socket.socket, str] | tuple[None, str]:
    """Publish a listening socket at <root>/daemon.sock, atomically.

    ⚠ BOUND TO A TEMPORARY NAME AND RENAMED INTO PLACE. `bind` fails on an
    existing path, so the naive sequence is unlink-then-bind — which has a
    window where no socket exists and every client in it falls back. `rename`
    over the old inode has no such window, and a client holding the old socket
    keeps talking to the old daemon until it closes.

    ⚠ BOUND FROM INSIDE THE DIRECTORY. `sun_path` is 104 bytes on macOS and a
    test's tmpdir plus this filename can exceed that. Binding against the bare
    filename with the cwd set to the directory makes the limit apply to the
    name, not the path. The cwd is restored immediately.
    """
    if not hasattr(socket, "AF_UNIX"):        # pragma: no cover — Windows
        return None, ("this platform has no AF_UNIX; the daemon is POSIX-only "
                      "and Windows uses the in-process path — see TASK 6")
    try:
        os.makedirs(root, exist_ok=True)
        os.chmod(root, 0o700)
    except OSError as exc:
        return None, f"cannot prepare {root}: {exc}"

    final = protocol.socket_path(root)
    temporary = f".{protocol.SOCKET_NAME}.{os.getpid()}"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    here = os.getcwd()
    # 0600 on the socket itself. The directory is already 0700; both, because
    # a socket published into a directory somebody later relaxes must not
    # become world-reachable by that act alone.
    old_umask = os.umask(0o177)
    try:
        os.chdir(root)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        sock.bind(temporary)
        sock.listen(64)
        os.rename(temporary, os.path.basename(final))
    except OSError as exc:
        sock.close()
        return None, f"cannot bind {final}: {exc}"
    finally:
        os.umask(old_umask)
        try:
            os.chdir(here)
        except OSError:                       # pragma: no cover
            pass
    return sock, final


def _still_ours(path: str, ino: int) -> bool:
    """Has another daemon renamed its socket over ours? Then stand down.

    Two daemons for one store is the shape that produces two answers for one
    action. The loser exits rather than lingering with a socket nobody can
    reach.
    """
    try:
        return os.stat(path).st_ino == ino
    except OSError:
        return False


def hold_the_lock(root: str) -> tuple[int | None, str]:
    """Own `daemon.lock` for this process's lifetime, or say who already does.

    ⚠ TWO ENTRY PATHS, AND BOTH END WITH THE LOCK HELD BY THIS PROCESS.

        started by a hook   `client.start()` already took it and passed the fd
                            through `exec`. `flock` belongs to the open file
                            description, which survives, so the lock is
                            continuously held from before the spawn until this
                            process exits — there is no window in which a
                            second hook can decide to start a second daemon.
        started by hand     nothing holds it, so take it here. A person running
                            `python3 daemon/server.py` while one is already
                            running gets told, rather than quietly becoming a
                            second daemon for the same store.

    ⚠ RETURNING THE fd MATTERS. The lock is released when every fd referring to
    that description is closed, so the caller has to keep it. A local variable
    that went out of scope would release the lock and leave the daemon running
    unprotected — which is the same bug as the starter's, one level down.
    """
    inherited = os.environ.get("STING_DAEMON_LOCK_FD")
    if inherited:
        try:
            fd = int(inherited)
            os.fstat(fd)              # it really is open in this process
            return fd, "inherited from the hook that started it"
        except (ValueError, OSError):
            pass                      # fall through and take it ourselves

    try:
        import fcntl
    except ImportError:                                              # pragma: no cover
        return None, "no fcntl on this platform"
    try:
        fd = os.open(protocol.lock_path(root), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        return None, f"cannot open the lock: {exc}"
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None, ("another daemon already holds this store's lock — "
                      "refusing to become a second one")
    return fd, "taken directly"


def serve(root: str | None = None, idle: float = IDLE_EXIT,
          max_requests: int | None = None) -> int:
    root = root or protocol.session_root()
    try:
        os.makedirs(root, exist_ok=True)
    except OSError as exc:
        sys.stderr.write(f"sting-daemon: cannot prepare {root}: {exc}\n")
        return 2

    # ⚠ HELD FOR THE WHOLE FUNCTION. `lock_fd` is never closed on purpose: the
    # process exiting is what releases it, which is exactly the signal the next
    # hook needs.
    lock_fd, why = hold_the_lock(root)
    if lock_fd is None:
        sys.stderr.write(f"sting-daemon: {why}\n")
        return 0                      # not an error: one daemon is the goal

    # ⚠ DECLARED BEFORE ANYTHING LISTENS. The invariant is `running ⇒ declared`:
    # `status()` reads `running` from the socket and `declared` from
    # daemon.json, and `bind()` is the moment the socket becomes observable —
    # it renames a listening socket onto the final path. This used to declare
    # AFTER that, so a status read in the gap said "running, and it says
    # nothing about its tree" (it did, on a loaded CI runner). The declaration
    # needs nothing the socket has — the pid is this process and the path is
    # known — so it goes first, atomically, and a declaration that cannot be
    # written stops the daemon before it listens rather than leaving one
    # running that no status read can account for. "Declared but not yet
    # running" is the only intermediate state, and it is the harmless one.
    where = protocol.socket_path(root)
    booted_with = allow_once.install_time()
    try:
        _declare(root, where, booted_with)
    except OSError as exc:
        sys.stderr.write(f"sting-daemon: cannot write its declaration in {root} "
                         f"({exc}); not starting\n")
        return 2
    sock, bound = bind(root)
    if sock is None:
        sys.stderr.write(f"sting-daemon: {bound}\n")
        _undeclare(root)              # nothing is serving what it just declared
        return 2
    where = bound
    try:
        ino = os.stat(where).st_ino
    except OSError:
        ino = -1

    # ⚠ THE POLICY THIS PROCESS IMPORTED, PINNED AT BOOT. See `superseded`.

    sock.settimeout(POLL)
    last, served, standing_down = time.monotonic(), 0, False
    try:
        while True:
            if time.monotonic() - last > idle:
                return 0
            if not _still_ours(where, ino):
                return 0
            # ⚠ CHECKED ON THE IDLE TICK TOO, not only when a request arrives.
            # A reinstall on a quiet machine should not leave a superseded
            # daemon sitting there until somebody happens to run a tool.
            if superseded(booted_with):
                return 0
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                continue
            try:
                if not _peer_is_us(conn):
                    continue
                conn.settimeout(protocol.MAX_MESSAGE and 10.0)
                chunks, size = [], 0
                while True:
                    try:
                        got = conn.recv(65536)
                    except OSError:
                        chunks = []
                        break
                    if not got:
                        break
                    size += len(got)
                    if size > protocol.MAX_MESSAGE:
                        chunks = None
                        break
                    chunks.append(got)
                if chunks is None:
                    reply = protocol.refusal(protocol.REFUSED_TOO_BIG,
                                             f"over {protocol.MAX_MESSAGE} bytes")
                elif not chunks:
                    continue
                elif superseded(booted_with):
                    # ⚠ REFUSED RATHER THAN SERVED, so the client falls back and
                    # imports the policy the reinstall just put there. Serving
                    # it would answer with the code this process imported before
                    # the install, which is the whole defect.
                    standing_down = True
                    reply = protocol.refusal(
                        REFUSED_SUPERSEDED,
                        "an install happened after this daemon booted; it is "
                        "standing down so the next call loads the new policy")
                else:
                    reply = handle(b"".join(chunks))
                try:
                    conn.sendall(protocol.encode(reply))
                except OSError:
                    # The client gave up — it will decide in-process. Nothing
                    # to do, and certainly nothing to crash over.
                    pass
            finally:
                conn.close()
            if standing_down:
                return 0
            served += 1
            last = time.monotonic()
            if max_requests is not None and served >= max_requests:
                return 0
    finally:
        sock.close()
        # ⚠ ONLY IF IT IS STILL OURS. Unlinking unconditionally would delete a
        # successor daemon's socket on the way out.
        if _still_ours(where, ino):
            try:
                os.unlink(where)
            except OSError:
                pass


DECLARATION = "daemon.json"
"""What tree this daemon is SERVING, written beside its socket at boot — and
BEFORE the socket is published, atomically, or the daemon does not start:
`running ⇒ declared` is the invariant `serve()` keeps (docs/80).

⚠ "LOADED, RUNNING, DOING THE WRONG THING" IS THE FIFTH INSTANCE IN THIS
PROJECT, and a daemon is the easiest place for it: the process outlives the
directory it was started from. A resident daemon answering from a tree that has
since been replaced looks perfectly healthy from outside — a live socket, fast
replies, a log full of decisions — while deciding with code nobody can find.

`superseded()` already makes an INSTALL end that state: the daemon refuses the
request and exits, and the client falls back in-process to the new code. What
was missing is the ability to SEE which tree is answering, before something goes
wrong, from `--status` and preflight. A claim nobody can check is not a claim.
"""


def _declare(root: str, socket_path: str, booted_with) -> None:
    """Write the declaration atomically, or raise OSError.

    ⚠ FATAL NOW, AND ATOMIC NOW. It used to swallow every error as "observability,
    not the guard" — which is how a daemon could listen forever undeclared. It
    runs BEFORE the socket is published (see serve), so raising here stops a
    daemon that nobody could account for. Temp file + rename, so a reader never
    sees half a declaration: the ordering race must not become a torn-read one.
    """
    tree = str(Path(__file__).resolve().parent.parent)
    payload = json.dumps({"pid": os.getpid(), "tree": tree,
                           "booted_at": time.time(),
                           "booted_with_install_time": booted_with,
                           "socket": socket_path}, sort_keys=True)
    final = Path(root, DECLARATION)
    temporary = Path(root, f".{DECLARATION}.tmp")
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, final)
    except OSError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _undeclare(root: str) -> None:
    """Remove a declaration nothing is serving — bind() failed after it was
    written. Best effort: a stale declaration is only ever read behind a
    socket that answers, and that socket does not exist."""
    try:
        Path(root, DECLARATION).unlink()
    except OSError:
        pass


def declaration(root: str | None = None) -> dict:
    """What the running daemon says it is serving, or why that is unknown."""
    root = root or protocol.session_root()
    try:
        return json.loads(Path(root, DECLARATION).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # ⚠ ABSENT IS NOT "FINE". A daemon predating this declaration writes
        # none, and that is exactly the daemon most likely to be stale.
        return {}


def status(root: str | None = None) -> dict:
    """Is one running, and where. For preflight and for a bug report."""
    root = root or protocol.session_root()
    path = protocol.socket_path(root)
    if not os.path.exists(path):
        return {"running": False, "socket": path, "detail": "no socket"}
    from daemon import client
    conn = client._connect(path)
    if conn is None:
        return {"running": False, "socket": path,
                "detail": "socket present but nothing is listening (stale)"}
    conn.close()
    try:
        mode = oct(os.stat(path).st_mode & 0o777)
    except OSError:
        mode = "?"
    said = declaration(root)
    here = str(Path(__file__).resolve().parent.parent)
    serving = said.get("tree")
    return {"running": True, "socket": path, "mode": mode,
            "pins": protocol.pins(),
            "tree": serving,
            # ⚠ THE COMPARISON, MADE HERE SO EVERY READER GETS THE SAME ANSWER.
            "tree_exists": bool(serving) and Path(serving).is_dir(),
            "tree_is_this_one": serving == here if serving else None,
            "declared": bool(said),
            "pid": said.get("pid")}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--status" in argv:
        print(json.dumps(status(), indent=2))
        return 0
    return serve()


if __name__ == "__main__":
    sys.exit(main())
