"""The per-laptop key the shipped fingerprints are keyed with. Never leaves it.

⚠ WHY A KEY AT ALL. Every record carries `hash` and `prev`, sha256 over the
RAW record — the local chain the collector's gap detection follows. With the
command shipping masked, a raw digest beside the masked text is a check for a
GUESS: fill in a weak password or a colleague's email, hash, compare. So the
shipped copy carries HMAC-SHA256 of each under this key instead
(`core.wire.fingerprinter`): every equality the collector relies on still
holds, and nothing can be checked without the key.

⚠ WHERE IT LIVES, AND WHY THAT NAME. `~/.sting/.env.fingerprint`, one dotenv
line, `STING_FINGERPRINT_KEY=<64 hex>`, 0600. The name is a credential path
the engine already recognises (`.env.<anything>`, `core/credentials.py`), so an
agent that reads it taints its session and the key's value is fingerprinted
like any other secret it read — no new rule on the hook for it.

⚠ MADE ONCE, NEVER REMADE. `install.py` makes it if it is missing, and so does
the shipper if a machine was upgraded without reinstalling. It is carried
across reinstalls: a new key would give a live session's next batch a
`continues_from` the collector has never seen, which reads as a gap. A file
that exists but does not hold a key is NEVER overwritten: `load` answers None
and the shipper holds every record until a person looks.

⚠ NEVER SHIPPED, LOGGED OR PRINTED. Nothing here returns the key as text; the
caller holds 32 bytes and hands them to `core.wire.fingerprinter`.

⚠ NEVER FOLLOWED THROUGH A LINK (security review, HIGH). A symlink at the
key's path would let whoever made it choose the key; `load` reads a regular
file only. The guard denies an agent any write under ~/.sting, this path too.

⚠ ITS RECORD, BESIDE IT AND OUTSIDE THE SHIPPER'S STATE (security review,
MEDIUM): `fingerprint-record.json` names the key (`key_id`, a digest of it)
and every session shipped keyed with it. A cursor restored from a backup then
cannot bridge a session again (the bridge would ship a raw hash of a record
the collector holds keyed), and a key that is gone or not the one the record
names holds every record: made anew, it would open a gap in each of those
sessions, so only a person re-running install.py makes one.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path

FILE_NAME = ".env.fingerprint"
"""Under `~/.sting`. A credential path by the engine's existing rule."""
RECORD_NAME = "fingerprint-record.json"
"""Beside the key: which key, and which sessions shipped keyed with it."""
VARIABLE = "STING_FINGERPRINT_KEY"
KEY_BYTES = 32
_LINE = re.compile(rf"\s*(?:export\s+)?{VARIABLE}\s*=\s*['\"]?([0-9a-f]{{64}})['\"]?\s*")


def path_under(home: Path) -> Path:
    """Where the key lives for the user whose home is `home`."""
    return Path(home) / ".sting" / FILE_NAME


def _regular_file_text(path: Path) -> str | None:
    """The text of `path` if it is a regular file — never through a link."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


def load(path: Path) -> bytes | None:
    """The key, or None when the file is missing, not a regular file (a link is
    never followed), unreadable, or does not hold exactly one well-formed key
    line. Never raises; never repairs."""
    text = _regular_file_text(Path(path))
    if text is None:
        return None
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    match = _LINE.fullmatch(lines[0])
    return bytes.fromhex(match.group(1)) if match else None


def create_if_missing(path: Path) -> bool:
    """Make the key if no file is there: 0600, created exclusively, so two
    writers racing cannot both write one. True when this call made it. A file
    already there — a key, or anything else — is left as it is."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(f"{VARIABLE}={secrets.token_hex(KEY_BYTES)}\n")
    return True


def born(path: Path) -> float | None:
    """When the key was made (its file is written once and never again), or
    None. Everything a session stored before it was stored raw."""
    try:
        return Path(path).stat().st_mtime
    except OSError:
        return None


def state(path: Path) -> str:
    """"present", "missing" or "damaged" — what a status line may say. Never
    the key. A link at the key's path is damaged, never followed."""
    if not os.path.lexists(path):
        return "missing"
    return "present" if load(path) is not None else "damaged"


DAMAGED = ("does not hold a key (a link is never followed) and is never replaced "
           "over what is there; move it aside and re-run install.py")


def why_held(path: Path) -> str | None:
    """Why the shipper holds every record rather than key with what is at
    `path`, or None when it does not. The one answer the shipper,
    `Settings.what_ships()` (the heartbeat) and `install.py --status` give.

    A missing key the shipper may make is not held. One that sessions were
    keyed with is: made anew, it opens a gap in each, so a person decides —
    and so is a key that is not the one the record names. Never the key."""
    record = read_record(path)
    sessions = None if record is None else record["sessions"]
    were = "some sessions were" if sessions is None else f"{len(sessions)} session(s) were"
    if not os.path.lexists(path):
        if record is None or sessions == []:
            return None
        return (f"is gone, and {were} keyed with it: restore it, or re-run "
                f"install.py to make a new one knowingly")
    key = load(path)
    if key is None:
        return DAMAGED
    if (record is not None and record["key"] is not None and sessions
            and record["key"] != key_id(key)):
        return (f"is not the key {were} keyed with: restore it, or re-run "
                f"install.py to start a new one knowingly")
    return None


def key_id(key: bytes) -> str:
    """Which key, without the key: a digest of it, kept only in its record."""
    return hashlib.sha256(b"sting fingerprint key id\0" + key).hexdigest()[:16]


def _record_path(path: Path) -> Path:
    return Path(path).parent / RECORD_NAME


def read_record(path: Path) -> dict | None:
    """The record beside the key at `path`: {"key": its key_id, "sessions":
    [ids shipped keyed]}; None when there is none. A record that cannot be read
    has `sessions` None — UNKNOWN — and the caller must neither bridge nor
    make a key while that is so."""
    record = _record_path(path)
    if not os.path.lexists(record):
        return None
    text = _regular_file_text(record)
    try:
        data = json.loads(text) if text is not None else None
    except ValueError:
        data = None
    if (not isinstance(data, dict) or not isinstance(data.get("sessions"), list)
            or not all(isinstance(x, str) for x in data["sessions"])):
        return {"key": None, "sessions": None}
    return {"key": data.get("key") if isinstance(data.get("key"), str) else None,
            "sessions": list(data["sessions"])}


def _write_record(path: Path, data: dict) -> None:
    record = _record_path(path)
    tmp = record.with_name(f".{RECORD_NAME}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(data, out, sort_keys=True)
    os.replace(tmp, record)


def reset_record(path: Path) -> None:
    """A record for the key now at `path`, with no session keyed yet."""
    key = load(path)
    _write_record(path, {"key": key_id(key) if key else None, "sessions": []})


def note_keyed(path: Path, session_id: str, key: str) -> None:
    """Add `session_id` to the record beside `path`: it shipped keyed with the
    key whose `key_id` is `key`.

    ⚠ A RECORD WITH NO SESSION IN IT NAMES THE KEY IN USE. A key remade before
    anything was keyed with the old one left the record naming the old key,
    and the next start held every record as keyed with another key. A record
    naming another key WITH sessions is never merged into: the shipper holds
    then, and a person decides. ⚠ AND ONLY UNDER THE KEY ON DISK: a process
    still holding a key install.py has since replaced never writes over the
    record reset for the new one."""
    on_disk = load(path)
    if on_disk is None or key_id(on_disk) != key:
        return
    record = read_record(path)
    if record is not None and record["sessions"] is None:
        return                                   # unknown: never rewritten
    if record is None or (not record["sessions"] and record["key"] != key):
        record = {"key": key, "sessions": []}
    if record["key"] != key or session_id in record["sessions"]:
        return
    _write_record(path, {**record, "sessions": [*record["sessions"], session_id]})
