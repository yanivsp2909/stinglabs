"""What goes over the socket, where the socket lives, and what may not travel.

⚠ THIS MODULE IS IMPORTED BY THE CLIENT, SO ITS IMPORT LIST IS A BUDGET.
The daemon exists because reaching the engine costs ~35 ms of every ~51 ms tool
call. A client that spent that saving on its own imports would have moved the
cost rather than removed it, and this is not hypothetical — the first version of
this file imported `pathlib` and `subprocess`, measured on this machine at:

    bare interpreter                        15.9 ms
      + json                                 +5.9 ms
      + socket                               +5.9 ms
      + os, sys, time                         ~0
      + pathlib                              +7.7 ms    ⬅ removed
      + subprocess                           +8.9 ms    ⬅ made lazy
      os + socket + json together            +7.4 ms

So `pathlib` alone costs more than the entire message layer. **Every path here
is a plain string handled with `os.path`,** which costs +0.4 ms, and
`subprocess` is imported inside the one function that spawns anything.
`tests/test_daemon_client_is_cheap.py` pins the module list and fails if the
floor drifts back up.

────────────────────────────────────────────────────────────────────────────────
THE MESSAGE, AND WHY THE ENVIRONMENT IS SPLIT IN TWO
────────────────────────────────────────────────────────────────────────────────

Today every setting reaches the engine through the hook process's OWN
environment, declared by `install.py` into the agent's hook config. A resident
daemon has one environment, fixed when it booted, and the calls arriving at it
come from processes with their own. Something has to give, and which way it
gives is a security decision rather than a convenience one.

    PINNED    STING_SESSION_ROOT, STING_LOG, STING_INSTALL_ROOT
              These say WHERE THE STATE AND THE AUDIT CHAIN LIVE. They are
              fixed at boot and NEVER read off the wire. A request whose pins
              disagree with the daemon's is REFUSED — see `REFUSED_PINS` — and
              the client then runs the verdict in-process, which is the same
              answer by a slower route. It is never served from the wrong store.

    CARRIED   STING_ROOTS, STING_SCRATCH, STING_OBSERVE, and the agent name
              These are per-invocation policy inputs. They do not relocate
              anything; they describe the call. They travel, because a daemon
              that answered from its own boot-time copy would serve one shell's
              trust boundary to every other shell on the machine.

⚠ THE ASYMMETRY IS THE WHOLE ARGUMENT. A carried value can make a verdict wrong
for the caller. A pinned value could make the daemon write somebody's audit
chain into a directory the caller chose. The first is a policy input the caller
already controls today; the second would be a new capability, so it does not
travel.

────────────────────────────────────────────────────────────────────────────────
⚠ WHERE THE SOCKET LIVES, AND WHY IT IS NOT A FIXED PATH
────────────────────────────────────────────────────────────────────────────────

The socket sits INSIDE the session root. That is not tidiness — it is what makes
the pin check almost always unnecessary: a client configured for a different
store looks for a socket in that store and finds a different daemon, or none.
The store is not a field to be validated; it is the address.

⚠ NEVER AN ABSTRACT SOCKET. Linux's abstract namespace (`\\0`-prefixed) is
reachable by every process in the network namespace and carries NO FILESYSTEM
PERMISSIONS AT ALL. A path-based socket in a 0700 directory is restricted to the
owning user by the same mechanism that already restricts the session files. That
mechanism is the entire access-control story here and it must not be traded away
for the convenience of not having a path to clean up.

⚠ AND THE 104-BYTE LIMIT IS REAL. macOS `sun_path` is 104 bytes, Linux 108. A
pytest tmpdir plus `/sessions/daemon.sock` exceeds it easily, so `bind` and
`connect` are both done from inside the directory against the bare filename —
see `server.bind` and `client._connect`.
"""
from __future__ import annotations

import json
import os

WIRE = 1
"""Bumped when a field changes meaning. A client and daemon that disagree fall
back to in-process rather than guessing — see `REFUSED_WIRE`."""

SOCKET_NAME = "daemon.sock"
LOCK_NAME = "daemon.lock"

MAX_MESSAGE = 8 << 20
"""8 MiB. Live commands reach 2048 chars routinely and a Write payload can be
far larger; 8 MiB is well past anything observed and still bounded. An unbounded
read from a local socket is a memory-exhaustion primitive handed to any process
on the machine."""

SUN_PATH_MAX = 100
"""Below the real limit (104 on macOS, 108 on Linux) on purpose. Past this the
directory-relative form is used instead of the absolute path."""

# ⚠ The names, in one place, because two lists of environment variables is one
# list that can be missing an entry — and the missing entry would be a setting
# the daemon silently answered from its own boot environment.
PINNED = ("STING_SESSION_ROOT", "STING_LOG", "STING_INSTALL_ROOT")
CARRIED = ("STING_ROOTS", "STING_SCRATCH", "STING_OBSERVE",
           # ⚠ THE COLLECTOR HOST IS NOW READ ON THE DECISION PATH
           # (`core/session._collector_hosts`), so a daemon that
           # snapshotted it at spawn would keep treating a ROTATED
           # collector's old host as expected for its whole lifetime —
           # up to IDLE_EXIT, and longer if requests keep it alive.
           "STING_COLLECTOR_URL",
           # ⚠ THE CANARY FINGERPRINT IS READ ON THE DECISION PATH
           # (`core/session._add_canary`) for the same reason: a canary
           # RE-PLANTED mid-lifetime must take effect, so it is carried
           # per request rather than snapshotted at spawn. Hash-only — this
           # is the fingerprint, never the decoy value.
           "STING_CANARY_FP")

REFUSED_PINS = "pins-mismatch"
REFUSED_WIRE = "wire-mismatch"
REFUSED_TOO_BIG = "too-big"


def session_root() -> str:
    """Where state lives, resolved WITHOUT importing core.session.

    ⚠ A DUPLICATED DEFAULT, AND THE DUPLICATION IS DELIBERATE. `core.session`
    owns this expression and the client may not import `core`. The alternative
    is a client that pays 35 ms to learn a path. One line, pinned by
    `tests/test_daemon_protocol.py` against `core.session.default_root`, so the
    two cannot drift without a test saying so.
    """
    return os.path.expanduser(os.environ.get("STING_SESSION_ROOT")
                              or "~/.sting/sessions")


def socket_path(root: str | None = None) -> str:
    return os.path.join(root or session_root(), SOCKET_NAME)


def lock_path(root: str | None = None) -> str:
    return os.path.join(root or session_root(), LOCK_NAME)


def pins(env=None) -> dict:
    """The store-defining settings, as this process sees them.

    Absent stays absent: `None` means "this process did not say", which is a
    different claim from "this process said the empty string". Collapsing them
    would make a daemon booted with no STING_LOG indistinguishable from one
    booted with STING_LOG="" — working rule 13, in an environment dict.
    """
    env = os.environ if env is None else env
    return {name: env.get(name) for name in PINNED}


def carried(env=None) -> dict:
    env = os.environ if env is None else env
    return {name: env.get(name) for name in CARRIED}


def encode(message: dict) -> bytes:
    """One JSON object, one line. `json.dumps` escapes every newline in the
    payload, so a command containing 40 lines is still one frame."""
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


# ⚠ THE CALLER'S ENVIRONMENT, FOR ONE PURPOSE (item B, docs/110 §B). A command
# that prints secret-looking variables has their values fingerprinted from the
# HOOK's environment — and a daemon's own is the one it booted with, another
# process's. So the client sends its own, taken before `~/.sting/env` was
# loaded. Only names that MAY look secret travel: a SUPERSET of the engine's
# rule (`core/env_reads.looks_secret`), pinned by
# tests/test_the_hook_sees_the_agents_environment.py, so nothing the engine
# would fingerprint is dropped and `HOME`, `LANG`, … never leave the process.
# A plain substring test: the client may not import `core`, and this costs
# microseconds. It is a policy input that can only make a verdict stricter,
# like CARRIED — never a pin.
_MAY_LOOK_SECRET = ("KEY", "TOKEN", "SECRET", "PASS", "CREDENTIAL", "PRIVATE",
                    "AUTH", "PAT", "WEBHOOK")


def may_look_secret(name: str) -> bool:
    upper = name.upper()
    return any(word in upper for word in _MAY_LOOK_SECRET)


def request(payload: str, agent: str, env=None, hook_env=None) -> dict:
    message = {"wire": WIRE, "payload": payload, "agent": agent,
               "pins": pins(env), "carried": carried(env)}
    if hook_env is not None:
        message["hook_env"] = {name: value for name, value in hook_env.items()
                               if isinstance(name, str) and isinstance(value, str)
                               and may_look_secret(name)}
    return message


def refusal(why: str, detail: str = "") -> dict:
    """A REFUSAL IS NOT A VERDICT AND MUST NEVER BE RENDERED AS ONE.

    It carries no stdout and no exit code — the client is expected to go and
    decide in-process. Giving it an exit code would let a daemon that cannot
    serve a request answer it anyway.
    """
    return {"wire": WIRE, "refused": why, "detail": detail}
