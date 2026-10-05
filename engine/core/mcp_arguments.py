"""Do an MCP call's arguments carry anything a secret could ride in?

fix/false-positives, the maintainer's decision of 30 Sep, item 3 (docs/112) — ⚠ THE ONE
SECRET RULE THIS PASS LOOSENS. Once a session holds a secret, every MCP call
was an exit the engine could not inspect, so it asked
(`secret_session_unverified:mcp_tool_call`). It now asks only when the call's
arguments, SEEN WHOLE (`Action.tool_arguments`, from
`adapters._common.complete_tool_arguments`), carry something:

    a traced value      a fingerprint of a value the session read, or a canary —
                        also once decoded (base64, base32, hex, %-escapes), with
                        invisible characters removed, and with the string values
                        joined (a value split across fields)
    a tainted file or   a file a secret was written into, a variable one was put
    variable            in
    a secret reference  `secret_reference` (a secret-named variable, a password
                        in a URL, a deferred-execution write …)
    a place a secret    a credential path or folder (`~/.ssh`, `.env`), a folder
    lives               that holds a secret the session read or wrote, a glob,
                        the home directory (`~`), `.` or `..`

⚠ AND ONLY WHEN EVERY SECRET THE SESSION HOLDS WAS FINGERPRINTED (the
reviews). A confidential path, a file that could not be read, an environment
value too plain to fingerprint — nothing in the arguments CAN match those, so
"nothing traceable" would prove nothing: today's verdict.

Arguments not visible whole (None) keep today's verdict. Residual, stated: a
secret the model re-types, reverses, re-cases or encodes some other way from
its context passes, as it passes every other exit; so does a value split
across fields that are not adjacent.
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import re

from core.command_text import _abs, _norm_path
from core.credentials import CREDENTIAL_PATHS, carries_canary, carries_secret
from core.secret_reference import secret_references
from core.types import Action, SessionState

_WORD = re.compile(r"[^\s\"',;()\[\]{}<>=]+")
# A word that can be a path: name characters, `/`-separated.
_PATHISH = re.compile(r"[\w.@+-]*(?:/[\w.@+-]*)*")
# A bare `*`, `**`, `*.ext`: a glob with no `/` that is still a path's.
_BARE_GLOB = re.compile(r"\*{1,2}(?:\.[\w.-]+)?")


def _is_glob(word: str) -> bool:
    """A glob shaped like a PATH — with a `/` (`**/*`, `src/*.py`), or a bare
    `*`, `**`, `*.ext` — so markdown's `*bold*` and a question's `?` are not
    one. Substring tests and one anchored pattern: linear in the word."""
    return ("/" in word and ("*" in word or "?" in word)) or bool(_BARE_GLOB.fullmatch(word))
_VARIABLE = re.compile(r"\$\{?([A-Za-z_]\w*)")
# Characters a screen does not show, which split a token without changing it.
_INVISIBLE_RANGES = ((0x00AD, 0x00AD), (0x180E, 0x180E), (0x200B, 0x200F),
                     (0x202A, 0x202E), (0x2060, 0x2064), (0xFEFF, 0xFEFF))
_INVISIBLE = re.compile("[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _INVISIBLE_RANGES) + "]")
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_BASE32 = re.compile(r"[A-Z2-7]{16,}={0,6}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_PERCENT_BYTE = re.compile(r"%([0-9A-Fa-f]{2})")
# `file:///p`, `file://host/p`, `file:/p`: the path.
_FILE_URL = re.compile(r"(?i)file:(?://[^/]*)?(/.*)")


def _text(raw: bytes) -> str | None:
    text = raw.decode("utf-8", errors="replace")
    return text if text.isprintable() or "\n" in text else None


_DECODE_LAYERS = 3
"""An encoding inside an encoding (base64 of base64, hex of base64) is read to
this depth (the second review round). Each layer is smaller than the one it
came from, so the whole reading stays a bounded multiple of the arguments."""


def _decoded(args: str) -> list[str]:
    """What the arguments decode to, layer after layer."""
    found: list[str] = []
    layer = [args]
    for _ in range(_DECODE_LAYERS):
        layer = [text for source in layer for text in _decoded_once(source)]
        if not layer:
            break
        found += layer
    return found


def _decoded_once(args: str) -> list[str]:
    """What the encoded-looking tokens in this text decode to. Linear: each
    pattern is found once, and each token decoded once."""
    found: list[str] = []
    for match in _BASE64.finditer(args):
        token = match.group(0)
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                text = _text(decode(token + "=" * (-len(token) % 4)))
            except (binascii.Error, ValueError):
                continue
            if text:
                found.append(text)
    for match in _BASE32.finditer(args):
        token = match.group(0)
        try:
            text = _text(base64.b32decode(token + "=" * (-len(token) % 8)))
        except (binascii.Error, ValueError):
            continue
        if text:
            found.append(text)
    found += [t for t in (_text(bytes.fromhex(m.group(0))) for m in _HEX.finditer(args)) if t]
    for match in _PERCENT.finditer(args):
        raw = bytes(int(b, 16) for b in _PERCENT_BYTE.findall(match.group(0)))
        if text := _text(raw):
            found.append(text)
    return found


def _carries_traced_value(args: str, state: SessionState) -> bool:
    forms = (args, _INVISIBLE.sub("", args), "\n".join(_decoded(args)))
    return any(carries_secret(t, state) or carries_canary(t, state) for t in forms if t)


def _secret_places(state: SessionState) -> set[str]:
    """Every folder that holds a secret this session read or wrote, and the
    files themselves: a tool given one of them ships what is in it."""
    places: set[str] = set()
    paths = list(state.tainted_paths) + [str(s.get("path") or "") for s in state.secret_sources]
    for path in paths:
        if not path.startswith("/"):
            continue                                # `$NAME`, the environment
        parts = _norm_path(path).rstrip("/").split("/")
        places.update("/".join(parts[:i]) or "/" for i in range(1, len(parts) + 1))
    return places


def _local_path(url: str) -> str | None:
    """The file a `file:` link names, its query dropped and `%XX` decoded;
    None for any other URL (the fourth review round)."""
    found = _FILE_URL.match(url)
    if not found:
        return None
    path = found.group(1).split("?", 1)[0].split("#", 1)[0]
    return _PERCENT_BYTE.sub(lambda m: chr(int(m.group(1), 16)), path)


def _names_a_secret_place(args: str, action: Action, state: SessionState) -> bool:
    places = _secret_places(state)
    tainted = set(state.tainted_paths)
    tainted_names = {p.rsplit("/", 1)[-1] for p in tainted}
    for word in _WORD.findall(args):
        if word in tainted or word.rsplit("/", 1)[-1] in tainted_names:
            return True
        is_file = word[:5].lower() == "file:"
        if "://" in word or is_file:
            # ⚠ A `file:` LINK IS THE FILE IT NAMES: `file:///…/.aws/credentials`
            # is read like `/…/.aws/credentials`. Any other URL's `?` is a query.
            local = _local_path(word)
            if local is not None:
                word = local
                if word in tainted:
                    return True
            elif is_file:
                # ⚠ A `file:` LINK WITH NO `//` (`file:.env`, `file:~/.ssh`,
                # `file:../.env`) is the relative or `~` path after the scheme
                # (P5, round 6): strip `file:` and fall through to the checks
                # below, as before round 5 — not a skip.
                word = word[5:]
            else:
                continue                            # a non-`file:` URL
        if _is_glob(word) or word.startswith("~") or word in (".", ".."):
            return True
        bare = "/" + word.strip("/")
        if CREDENTIAL_PATHS.search(bare) or CREDENTIAL_PATHS.search(bare + "/"):
            return True                             # `.env`; `~/.ssh`, `.aws`: the folder too
        # A path, absolute or relative (`config`, `./out` — the second review
        # round), that names a folder holding a secret, or the file itself.
        if _PATHISH.fullmatch(word):
            if (_norm_path(_abs(word, action.cwd)).rstrip("/") or "/") in places:
                return True
    return False


def _every_secret_fingerprinted(state: SessionState) -> bool:
    """`how == "content"` is the one read that always carries fingerprints;
    `unread` and `path_policy` never do (`sources.mark_sources`,
    `env_reads.marks`). A secret held with no source recorded (a state file
    read under schema skew is labelled maximally) is not one either."""
    sources = state.secret_sources
    return (bool(sources) and bool(state.secret_fingerprints)
            and all(s.get("how") == "content" for s in sources)
            # ⚠ `content` means SOME value was fingerprinted, not every one: a
            # secret-looking value too plain to fingerprint keeps the ask too
            # (the second review round; `SessionState.unprinted_secret`).
            and not state.unprinted_secret)


def carries_nothing(action: Action, state: SessionState) -> bool:
    """True only when the call's arguments are visible whole and carry nothing
    above — the one case item 3 lets an MCP call after a secret read through."""
    args = action.tool_arguments
    if args is None or not _every_secret_fingerprinted(state):
        return False
    if _carries_traced_value(args, state):
        return False
    if any(m.group(1) in state.tainted_vars for m in _VARIABLE.finditer(args)):
        return False
    if _names_a_secret_place(args, action, state):
        return False
    probe = dataclasses.replace(action, content=args, command=None, url=None)
    return not secret_references(probe, state.aliases)
