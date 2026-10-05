"""
Session persistence — the locking and the file, nothing else.

SessionState itself lives in core/types.py, because it is pure data and the
engine must be able to reason about it without importing anything that touches
a filesystem. This module is the only place that opens the file.

One JSON file per session at ~/.sting/sessions/<session_id>.json, schema per
docs/02-engine-spec.md Part 1.

WHY A FILE. The hook is a fresh process for every tool call, so there is no
process to hold state in. The file IS the memory. The production daemon will
hold this in RAM and the file becomes a checkpoint; until then, correctness
matters more than the syscalls.

WHY LOCKING IS NOT OPTIONAL. Agents run tools in parallel, so two hooks WILL
race. Without an exclusive lock held across the whole read-modify-write, the
second writer overwrites the first's changes and a fingerprint recorded by one
call silently disappears — the guard forgets a secret it had already seen, which
is exactly the failure the session memory exists to prevent. docs/02 flags this:
"must use fcntl.flock on every read-modify-write or get silent corrupted state".

Everything mutating goes through open_session(), which holds LOCK_EX from before
the read until after the write:

    with open_session(action.session_id) as state:
        state.seq = state.next_seq(action.seq)
        ...
    # lock released here, file already durable
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time

# ⚠ THE PLATFORM SEAM. `import fcntl` used to sit at module scope here,
# which is an ImportError on Windows before any code runs — the engine did
# not start at all. See core/locking.py.
from core import canary, locking
from contextlib import contextmanager
from pathlib import Path

from core.types import SessionState

def default_root() -> Path:
    """Where session state lives.

    STING_SESSION_ROOT overrides it. Tests need that so they never touch the
    real ~/.sting, and the replay runner needs it so each scenario starts from
    a clean session — without isolation, scenario N would inherit scenario
    N-1's taint and the whole benchmark would be meaningless.
    """
    return Path(os.environ.get("STING_SESSION_ROOT") or "~/.sting/sessions").expanduser()

# A session id arrives from the agent, so it is untrusted input that must never
# become a path. Anything outside this set is replaced by a hash of the original.
_SAFE_ID = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")


def safe_session_id(session_id: str) -> str:
    """A session id that cannot escape the sessions directory.

    `../../.ssh/authorized_keys` as a session id would otherwise have us
    truncate and rewrite that file. Ids we cannot vouch for become a hash, which
    is stable (the same session keeps the same file) without being a path.
    """
    if isinstance(session_id, str) and _SAFE_ID.match(session_id) and ".." not in session_id:
        return session_id
    raw = session_id if isinstance(session_id, str) else repr(session_id)
    return "sha-" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]


def session_path(session_id: str, root: Path | None = None) -> Path:
    return (root or default_root()) / f"{safe_session_id(session_id)}.json"


def _ensure_root(root: Path) -> None:
    # 0700: the state names paths that were read and carries secret
    # fingerprints. Other users on the machine have no business reading it.
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass


@contextmanager
def open_session(session_id: str, root: Path | None = None):
    """Yield the session state under an exclusive lock, then write it back.

    The lock is held from before the read until after the write and fsync, so
    two concurrent hooks serialise instead of clobbering each other. Yielding
    inside the locked window is the whole point — a read-then-write with the
    lock released in between is the bug this is designed to prevent.
    """
    root = root or default_root()
    _ensure_root(root)
    path = session_path(session_id, root)

    # r+ if it exists, else create. Never "w", which would truncate before the
    # lock is taken and lose a concurrent writer's state.
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        locking._acquire(fd, shared=False)
        raw = os.read(fd, 64 * 1024 * 1024).decode("utf-8", "replace")
        try:
            data = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            data = {}          # corrupt file: start fresh rather than refuse to run

        state = SessionState.from_dict(data, session_id=safe_session_id(session_id))
        if not state.started_at:
            state.started_at = time.time()
        _add_collector_host(state)
        _add_canary(state)

        yield state

        payload = json.dumps(state.to_dict(), indent=2).encode()
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        try:
            locking._release(fd)
        finally:
            os.close(fd)


def _collector_hosts() -> tuple:
    """The collector's own host, from the setting the hook already loads.

    ⚠ KNOWABLE BY CONSTRUCTION — NOT A MAINTAINED LIST. `envfile` loads
    `~/.sting/env` into `os.environ` before this runs, so `STING_COLLECTOR_URL`
    is simply there. A hardcoded hostname would be wrong for every customer, and
    a list somebody maintains is a list that goes stale.

    ⚠ AND IT IS PARSED HERE, NOT IN THE ENGINE. The first version read the
    environment from inside `engine._is_expected`, and four architectural tests
    refused it at once: the engine performs no IO, imports no network module,
    and holds no cache. They were right — a decision function that reads the
    environment cannot be REPLAYED, and replay is how every rate in this project
    is measured. This file is already the IO boundary for session state.
    """
    url = os.environ.get("STING_COLLECTOR_URL", "")
    if not url:
        return ()
    # ⚠ PARSED BY HAND BECAUSE `core/` MAY NOT IMPORT A NETWORK MODULE.
    # `tests/test_shipper_isolation.py` refuses `urllib.parse` here, and it is
    # right: `core/` is the part that must be replayable and must not be able
    # to reach the network by accident. Four lines of string handling is a
    # smaller price than an import that makes that guarantee arguable.
    rest = url.split("://", 1)[-1]
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    authority = authority.rsplit("@", 1)[-1]            # strip any userinfo
    if authority.startswith("["):                       # IPv6 literal
        host = authority[1:].split("]", 1)[0]
    else:
        host = authority.split(":", 1)[0]               # strip any port
    host = host.strip().lower()
    # A "host" with whitespace or a slash is not one; adding it would widen the
    # expected set on a value we could not parse, which is the wrong direction.
    if not host or any(c.isspace() for c in host) or "/" in host:
        return ()
    # ⚠ AND A SINGLE-LABEL HOST IS REFUSED. `installer/enrol.py` validates only
    # that the URL starts with http(s)://, so a typo or a malformed enrolment
    # payload really can produce `STING_COLLECTOR_URL=https://com/…`.
    #
    # ⚠ THIS GUARD OUTLIVED THE HOLE IT WAS WRITTEN FOR, AND IT STAYS. It was
    # written because `engine._is_expected` matched `host.endswith("." + k)`, so
    # a value parsing to `com` made EVERY `.com` host expected in an untrusted
    # session. That match is now EXACT, so `com` would admit only the literal
    # host `com` — no longer a public suffix. Kept anyway: a bare label is still
    # a value we could not parse into a destination, admitting it is still the
    # wrong direction, and this is the last line of defence if the matcher is
    # ever widened again. Defence in depth, not the only defence.
    if "." not in host.strip("."):
        return ()
    return (host,)


def _add_collector_host(state: SessionState) -> None:
    """⚠ OUR OWN COLLECTOR IS NOT AN UNEXPECTED DESTINATION.

    Measured over 6,942 real recorded actions on this machine: 24 records
    DENIED as `untrusted_unexpected` at the collector host, and ZERO `secret_*`
    denials there. Every one was a health check, a probe or a deploy — refused
    as an "unexpected destination" by the tool that chose the destination. A
    customer whose agent ever touches their own collector URL hits the same wall.

    ⚠ THIS DOES NOT TOUCH THE `secret_*` FAMILY, which fires higher up the
    ladder and asks a different question: not "is this destination recognised"
    but "is a traced credential LEAVING". `curl -d @.env <collector>` in a
    session that read `.env` is still a DENY.
    """
    for host in _collector_hosts():
        if host not in state.expected_hosts:
            state.expected_hosts.append(host)


def _add_canary(state: SessionState) -> None:
    """Seed the planted canary fingerprint(s) into the session — HASH-ONLY, from the
    setting the boundary already loads, the same shape as `_add_collector_host`.

    ⚠ THE ENGINE STAYS IO-FREE. `STING_CANARY_FP` holds the FINGERPRINT (a hash),
    never the value; `~/.sting/env` already reaches `os.environ` here, so the engine
    only ever reads `state.canary_fingerprints`. The plaintext decoy VALUE lives
    wherever the operator planted it for an attacker to find — never here.

    ⚠ FAIL LOUD ON A DISARMED CANARY. A decoy that was configured but did not load
    (a corrupt store) is worse than none — it gives false confidence — so we set
    `state.canary_unarmed` AND print to stderr; it is never silent. A canary that
    was never configured stays silent: there is no protection being claimed."""
    raw = os.environ.get("STING_CANARY_FP", "")
    fingerprints, unarmed = canary.parse_fingerprints(raw)
    for fp in fingerprints:
        if fp not in state.canary_fingerprints:
            state.canary_fingerprints.append(fp)
    if unarmed:
        state.canary_unarmed = unarmed
        print(f"⚠ STING CANARY DISARMED: {unarmed}", file=sys.stderr)


def capture_preexisting_remotes(state: SessionState, cwd: str, world) -> None:
    """FREEZE the remote URLs configured in `cwd`'s repo, once, at session start.

    ⚠ CALLED FROM `hook_entry` BEFORE `engine.decide`, AND BEFORE THE ACTION'S
    COMMAND RUNS (PreToolUse). So the very first action in a repo — even one
    whose command is `git remote add origin <evil>` — is snapshotted AROUND:
    the capture reads the config as it was before that command executes, and the
    once-per-toplevel gate below means the command's effect can never re-open it.

    ⚠ ONCE PER REPO, READ-ONLY THEREAFTER. A toplevel already present is left
    exactly as captured, so a later `set-url`/`remote add` in the session cannot
    rewrite the frozen set. Keyed per toplevel, so moving between repositories
    captures each independently. Stores URLs, never names.

    Fail-safe: a world that cannot answer (not a repo, git missing, any error)
    leaves `preexisting_remotes` untouched, which the engine reads as "no
    exemption" — today's DENY. This function NEVER raises into the hook.
    """
    resolve = getattr(world, "configured_remotes", None)
    if resolve is None:
        return
    try:
        info = resolve(cwd)
    except Exception:
        return
    if not info:
        return
    toplevel = info.get("toplevel")
    if not toplevel or toplevel in state.preexisting_remotes:
        return
    urls = sorted({u for u in (info.get("remotes") or {}).values() if u})
    state.preexisting_remotes[toplevel] = urls


def load_session(session_id: str, root: Path | None = None) -> SessionState:
    """Read-only snapshot. For the VS Code extension and for tests.

    Takes a shared lock so it cannot read a half-written file.
    """
    path = session_path(session_id, root)
    if not path.exists():
        fresh = SessionState(session_id=safe_session_id(session_id))
        _add_collector_host(fresh)
        _add_canary(fresh)
        return fresh
    fd = os.open(path, os.O_RDONLY)
    try:
        locking._acquire(fd, shared=True)
        raw = os.read(fd, 64 * 1024 * 1024).decode("utf-8", "replace")
    finally:
        try:
            locking._release(fd)
        finally:
            os.close(fd)
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        data = {}
    loaded = SessionState.from_dict(data, session_id=safe_session_id(session_id))
    _add_collector_host(loaded)      # the read-only path must agree with open_session
    _add_canary(loaded)
    return loaded
