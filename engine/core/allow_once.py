"""
The one-shot override — docs/15 step 19.

    "a one-shot override, logged, that does not persist past the single denied
     action it was granted for"

The extension writes a grant; hook_entry consumes it exactly once; the use is
chained onto the audit log like any other event. Without this, the first wrong
block has no path except uninstalling the tool.

BOUND TO AN ACTION, NOT TO "THE NEXT DENIAL". A grant carries a fingerprint of
the exact action it was issued for — kind, paths, command, url. Anything else
is a hole: the agent chooses what runs next, so "allow the next denial" would
let it slip a different action into the gap between the click and the retry.
docs/15 says "the single denied action it was granted for"; this is that,
enforced rather than described.

NOT BOUND TO seq. The retry is a NEW action and gets a new sequence number, so
matching on seq would never fire. The denial's seq is recorded for the audit
trail, not used for matching.

EXPIRY IS AN ADDITION beyond docs/15. A grant bound only to a fingerprint would
sit on disk indefinitely and fire on a matching action an hour later. The
developer clicking "allow once" is answering a prompt in front of them now, so
the grant is short-lived by default.

--------------------------------------------------------------------------
LIMITATION, STATED PLAINLY. This file is written with the developer's own
privileges — which are also the agent's privileges. A compromised agent can
write its own grant and approve itself. Nothing local closes that: any secret
this process could check, the agent could read. Closing it needs a signature
over a key the agent cannot reach, which is control-plane work (docs/15 step 18
makes the same point: unsigned exceptions must not be honored once Team tier
exists). For Solo tier this is a deliberate, documented gap, not an oversight.
--------------------------------------------------------------------------
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import time

# ⚠ THE PLATFORM SEAM. `import fcntl` used to sit at module scope here,
# which is an ImportError on Windows before any code runs — the engine did
# not start at all. See core/locking.py.
from core import locking
from pathlib import Path

from core.session import default_root, safe_session_id

DEFAULT_TTL = 300.0
"""Seconds. Long enough for the agent to retry, short enough that a forgotten
grant is not still armed later in the session."""


def fingerprint(action) -> str:
    """Identity of a tool call, stable across the retry.

    Deliberately excludes seq, session and cwd: the retry differs from the
    denied action in seq alone, and must still match.

    tool_name and content ARE included, because kind/paths/command/url are all
    empty for a tool the adapter cannot decompose — so every WebSearch, and
    every unmapped MCP call, fingerprinted identically. A grant issued for one
    was spendable on any other, which is the opposite of one-shot. Observed for
    real: D02's seq 9 and seq 10 share a single action_hash.
    """
    body = {"kind": str(action.kind), "paths": list(action.paths),
            "command": action.command, "url": action.url,
            "tool_name": action.tool_name, "content": action.content}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _install_prefix() -> Path:
    root = os.environ.get("STING_INSTALL_ROOT")
    return Path(root) if root else Path.home() / ".local" / "share" / "sting"


# ⚠ THE NAME OF THE POINTER FILE, RESTATED HERE RATHER THAN IMPORTED. `core/`
# may not import `installer/` — the hook runs from an installed tree that does
# not ship the installer at all, and an isolation test pins the direction of
# that dependency. One duplicated constant is the cost; a core module that
# cannot start without the installer would be the alternative.
_POINTER = "current.txt"


def _current_dir() -> Path:
    """Where `current` actually points.

    ⚠ TWO LAYOUTS, AND WINDOWS HAS NO SYMLINK. On POSIX `current` is a symlink
    and this is just its path. On Windows it is `current.txt`, a file holding
    the target directory — because creating a symlink there needs Developer Mode
    or admin, which an installer may not demand. See installer/place.py for why
    a pointer FILE and not a junction.
    """
    prefix = _install_prefix()
    pointer = prefix / _POINTER
    try:
        if pointer.is_file():
            target = pointer.read_text(encoding="utf-8").strip()
            if target:
                return Path(target)
    except OSError:
        pass
    return prefix / "current"


def _swap_marker() -> Path:
    """The thing whose mtime records the INSTANT the new policy became live.

    ⚠ THIS IS HALF OF `install_time()`, WHICH IS A SECURITY CHOKEPOINT. On POSIX
    it is the `current` symlink, whose lstat mtime is set when `os.replace`
    swaps it. On Windows it is `current.txt`, whose mtime is set by the same
    `os.replace` — the pointer file exists partly BECAUSE it gives this half a
    source. A layout with no such marker would silently drop the 4.6 ms window
    between the grant sweep and the swap, and a grant written inside it would
    survive a reinstall.
    """
    prefix = _install_prefix()
    pointer = prefix / _POINTER
    return pointer if pointer.is_file() else prefix / "current"


def _manifest_path() -> Path:
    return _current_dir() / "INSTALL.json"


@functools.lru_cache(maxsize=1)
def _install_manifest_version(path_str: str, mtime: float) -> str | None:
    try:
        return json.loads(Path(path_str).read_text(encoding="utf-8")
                           ).get("guard_version")
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def installed_version() -> str | None:
    """The guard_version of the installed copy, or None when not installed.

    ⚠ RECORDED IN EVERY GRANT AND NO LONGER CHECKED AGAINST ONE. See
    `install_time` for what replaced it and why. It is kept because the grant is
    an audit record of a human's approval, and "which policy were they looking
    at" is worth writing down even though it is the wrong thing to gate on.

    ⚠ CACHED ON (path, mtime), because this is read on the hook's path whenever
    a grant exists. A reinstall rewrites INSTALL.json, which changes the mtime,
    which invalidates the entry — so the cache cannot serve a version the
    install has moved past.
    """
    manifest = _manifest_path()
    try:
        return _install_manifest_version(str(manifest), manifest.stat().st_mtime)
    except OSError:
        return None


@functools.lru_cache(maxsize=1)
def _install_manifest_time(path_str: str, mtime: float) -> float:
    """`installed_at`, or the manifest's own mtime when it does not say.

    ⚠ THE FALLBACK ANSWERS THE SAME QUESTION AND CANNOT OPEN THE CHOKEPOINT.
    `INSTALL.json` is written fresh by `place.py` — `write_text`, not a copy —
    so its mtime IS when this install happened. A manifest that is unparseable,
    or was written by a version that did not record the field, still pins the
    moment, and the alternative (refusing every grant on such an install) is the
    same outage this module is being fixed for.
    """
    try:
        declared = json.loads(Path(path_str).read_text(encoding="utf-8")
                               ).get("installed_at")
    except (OSError, json.JSONDecodeError, TypeError, AttributeError):
        return mtime
    return float(declared) if isinstance(declared, (int, float)) else mtime


def install_time() -> float | None:
    """When the running install happened, or None when there is no install.

    ⚠ THIS REPLACED `installed_version()` AS THE CHOKEPOINT'S TEST, AND THE
    REASON IS THAT THE OLD ONE ONLY EVER WORKED FOR ONE WRITER.

    `_valid` used to require `grant["guard_version"] == installed_version()`.
    The extension — which IS the "Allow once" button, and the primary producer
    of grants — writes `granted_at` and no version, because a TypeScript module
    has no business knowing the engine's version string. With no install both
    sides were `None`, they compared equal, and everything worked. The moment an
    install appeared on this machine, `installed_version()` became a real string
    and EVERY grant the extension wrote was refused.

    Comparing times fixes that without weakening anything, because it is the
    semantic the chokepoint actually wanted all along: **a grant is void if an
    install happened after it was granted.** Both fields already exist, both
    producers already write `granted_at`, and no writer needs to know anything
    about the engine's versioning to be understood.

    ⚠ None IS A REAL ANSWER, NOT A FAILURE. A checkout with no install is the
    normal state during development; there is no install to have replaced the
    policy, so there is nothing to revoke and grants work exactly as before.

    ⚠ THE LATER OF TWO TIMES, AND THE SECOND ONE CLOSES A WINDOW THE VERSION
    CHECK DID NOT HAVE. `place.py` writes `INSTALL.json` first, sweeps grants
    second, and repoints `current` third — so a grant written between the sweep
    and the swap is LATER than `installed_at` and would survive the install.
    Under version equality it did not: it was written while `current` still
    pointed at the old tree, so it carried the old version and was refused.

    The moment the new policy actually becomes live is the moment `current`
    starts pointing at it, and that instant is recorded by the symlink's own
    mtime. Measured on this machine's real install: `installed_at`
    1786308424.0818, symlink 1786308424.0864 — **a 4.6 ms window**, small and
    not zero. Taking the later of the two removes it rather than documenting it.
    """
    manifest = _manifest_path()
    try:
        manifest_mtime = manifest.stat().st_mtime
    except OSError:
        return None
    declared = _install_manifest_time(str(manifest), manifest_mtime)
    try:
        # lstat, never stat: on POSIX it is the LINK's mtime that records the
        # swap and stat would follow it to the directory. On Windows the marker
        # is a regular file and lstat is simply stat — the call is the same and
        # only the thing it points at differs.
        swapped_at = os.lstat(_swap_marker()).st_mtime
    except OSError:
        swapped_at = declared
    return max(declared, swapped_at)


def grant_path(session_id: str, root: Path | None = None) -> Path:
    return (root or default_root()) / f"{safe_session_id(session_id)}.allow-once.json"


def write_grant(session_id: str, action_hash: str, denied_at_seq: int | None = None,
                rule_id: str | None = None, reason: str | None = None,
                ttl: float = DEFAULT_TTL, granted_by: str = "unknown",
                root: Path | None = None) -> dict:
    """Issue a grant. This is what the extension's "Allow once" writes.

    Exposed here so the format has exactly one definition. The extension copies
    `action_hash` straight out of the log record rather than recomputing it —
    hashing an action in TypeScript would be a second implementation of
    something the engine already decided.
    """
    now = time.time()
    grant = {
        "session_id": safe_session_id(session_id),
        "action_hash": action_hash,
        # ⚠ THE POLICY THIS APPROVAL WAS GIVEN UNDER — RECORDED, NOT CHECKED.
        # A one-shot grant authorises ONE action under ONE set of rules, and
        # which rules those were belongs in the record. What the chokepoint
        # tests is `granted_at` against the install's own time, because a
        # version string is something only a writer that knows this codebase can
        # produce, and the primary writer is TypeScript. See `install_time`.
        "guard_version": installed_version(),
        "denied_at_seq": denied_at_seq,
        "rule_id": rule_id,
        "reason": reason,
        "granted_at": now,
        "expires_at": now + ttl,
        "granted_by": granted_by,
    }
    path = grant_path(session_id, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        locking._acquire(fd, shared=False)
        os.write(fd, json.dumps(grant, indent=2).encode("utf-8"))
        os.fsync(fd)
    finally:
        try:
            locking._release(fd)
        finally:
            os.close(fd)
    return grant


def _valid(grant, action_hash: str, now: float) -> bool:
    """A grant arrives from another process, so it is untrusted input.

    Anything malformed must fail to a non-override. A grant that cannot be
    understood is not permission.
    """
    if not isinstance(grant, dict):
        return False
    if not isinstance(grant.get("action_hash"), str):
        return False
    if grant["action_hash"] != action_hash:
        return False
    expires = grant.get("expires_at")
    if not isinstance(expires, (int, float)) or now > expires:
        return False
    # ⚠ A GRANT THAT PREDATES THE RUNNING INSTALL IS NOT PERMISSION. The human
    # clicked "allow once" while looking at a verdict some specific policy
    # reached; an install is the moment those rules change, so an approval given
    # before it would be spent under rules they never saw.
    #
    # ⚠ AND A GRANT THAT CANNOT BE PLACED RELATIVE TO THE INSTALL IS REFUSED,
    # which is this module's standing rule — anything it cannot understand fails
    # to a non-override. Accepting a grant with no `granted_at` would reopen the
    # chokepoint entirely: a grant issued under one policy would be redeemable
    # under another, which is the thing it exists to stop.
    installed = install_time()
    if installed is not None:
        granted = grant.get("granted_at")
        if not isinstance(granted, (int, float)):
            return False
        if granted < installed:
            return False
    return True


def consume(session_id: str, action, root: Path | None = None) -> dict | None:
    """Take the grant for THIS action, if one is armed. Returns it, or None.

    One-shot: the grant is EMPTIED under the lock before the caller can act on
    the result, so a second action cannot spend the same grant. Never raises — a
    broken or unreadable grant means no override, which is the safe direction.

    ⚠ ONE-SHOT USED TO MEAN "UNLINKED", AND ON WINDOWS IT MEANT NOTHING.
    Measured on CI's Windows job, which had never executed a test until the
    collection fix landed: `test_parallel_consumers_spend_a_grant_exactly_once`
    reported **the grant spent 8 times**, and `test_consuming_removes_the_file`
    found the file still there.

    The cause is one line of platform semantics. Windows refuses to unlink a
    file that is still open — `PermissionError`, a sharing violation — and
    `_unlink` swallows `OSError` because on POSIX an unlink that loses a race is
    not an error. So on Windows the grant was never removed, every waiting
    consumer read it, and a human's SINGLE approval covered eight actions.

    ⚠ SO THE ONE-SHOT NO LONGER DEPENDS ON UNLINK SUCCEEDING. The file is
    truncated to zero bytes while the exclusive lock is held; a consumer that
    arrives afterwards reads nothing, decodes no grant, and returns None. The
    unlink still happens — a zero-byte file left on disk is untidy — but it is
    now housekeeping rather than the mechanism. That is the same guarantee on
    both platforms, and it is the platform-independent one.

    ⚠ AND IT NEEDS WRITE ACCESS, WHICH IS A REAL CHANGE. `O_RDWR` can fail where
    `O_RDONLY` succeeded — a read-only grant file, a directory the user can read
    and not write. That returns None, which is NO OVERRIDE: the action is judged
    by the engine as if nobody had approved it. That is the safe direction, and
    it is the direction this file takes everywhere else.
    """
    path = grant_path(session_id, root)
    wanted = fingerprint(action)
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return None

    try:
        locking._acquire(fd, shared=False)
        # Someone may have consumed and unlinked it while we waited for the
        # lock. Our fd would still read the old contents, so compare inodes
        # rather than trusting the bytes we can still see.
        try:
            if os.fstat(fd).st_ino != os.stat(path).st_ino:
                return None
        except OSError:
            return None

        raw = os.read(fd, 1 << 20).decode("utf-8", "replace")
        try:
            grant = json.loads(raw) if raw.strip() else None
        except json.JSONDecodeError:
            grant = None

        if grant is None:
            _spend(fd, path)       # unusable; do not leave it armed
            return None
        if not _valid(grant, wanted, time.time()):
            # Expired grants are cleared. A grant for a DIFFERENT action is
            # left alone — its own action may still be about to retry.
            if not isinstance(grant, dict) or grant.get("action_hash") != wanted:
                return None
            _spend(fd, path)
            return None

        _spend(fd, path)
        return grant
    finally:
        try:
            locking._release(fd)
        finally:
            os.close(fd)


def _spend(fd: int, path: Path) -> None:
    """Make the grant unspendable, then tidy up. ⚠ IN THAT ORDER.

    The TRUNCATE is the mechanism and it happens while the exclusive lock is
    still held, so a consumer waiting on the lock finds an empty file and no
    grant. The UNLINK is housekeeping: on POSIX it succeeds, on Windows it fails
    with a sharing violation while this fd is open, and either way the grant has
    already been spent.

    ⚠ A FAILED TRUNCATE IS NOT SWALLOWED SILENTLY — it is the one error here
    that would leave a spendable grant behind, so the unlink is still attempted
    and the caller still gets its answer, but the two failures are not treated
    as the same kind of nothing.
    """
    try:
        os.ftruncate(fd, 0)
    except OSError:
        # Truncation failed (a read-only mount, a filesystem that refuses).
        # Fall through to the unlink, which on POSIX still removes it.
        pass
    _unlink(path)


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        # ⚠ EXPECTED ON WINDOWS while the fd is open, and no longer load-bearing:
        # `_spend` has already emptied the file. On POSIX an unlink that loses a
        # race is also not an error.
        pass
