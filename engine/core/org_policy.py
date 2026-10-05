"""The engine's local, cached copy of its org's policy.

This module gets the org's policy onto the machine — fetched out-of-band by the
shipper, cached to a local file, versioned, and fail-safe — and the decision
path reads it through `load_cached()` (step 3a, #57).

⚠ ITS OWN FILE: `~/.sting/org_policy.json`, NEVER `~/.sting/policy.json`. That
one is a person's LOCAL relaxation file (`core/policy.py`), and the two used to
be one path. The first org policy newer than the local file's `version` then
overwrote a person's relaxations; a local `"version": 1` froze out an org's
version 1; and an org document, stored with unknown keys kept, was read by
`policy.load()` as relaxations, so it could loosen a verdict. `store()` refuses
to write through the local file's path, even when an override points there.

⚠ WHERE IT SITS IN THE ISOLATION MODEL. `core/` may import no network module and
no part of the shipper (`tests/test_shipper_isolation.py`), and the decision hot
path may open no socket. So this module is stdlib-only — `json`, `os`,
`tempfile`, `pathlib` — and does pure LOCAL FILE work: the shipper's out-of-band
poll fetches over the network and calls `store()`; the engine (step 3) calls
`load()` on the decision path with zero network.

────────────────────────────────────────────────────────────────────────────────
⚠ FAIL SAFE IN ONE DIRECTION ONLY: TOWARD LESS DECLARED, NEVER MORE ALLOWED
────────────────────────────────────────────────────────────────────────────────

Every failure here degrades to "nothing extra declared", which is exactly today's
behaviour — never to "weaker than today", because there is no state weaker than
today that this schema can express:

  * `load()` VALIDATES ON READ, not only on write. A `policy.json` written by any
    other local process — a poisoned or hand-edited cache — is sanitised here:
    bad JSON, a wrong-shaped document, or a malformed entry yields the EMPTY
    policy or drops the entry. A bad cache is never trusted as-is. The worst it
    can do is declare nothing (today's behaviour) or declare MORE (stricter),
    since a source only ESCALATES.
  * `store()` REFUSES a malformed fetched policy wholesale (raises), so the caller
    keeps the last-known-good cache rather than overwriting it with garbage.
  * The schema has no "off" switch. A `sensitive_source` carries a severity of
    `log`, `ask` or `deny` — an escalation ladder — and nothing else. There is no
    field that turns the guard off, allow-lists a path, or downgrades an existing
    catch. Absence, an empty policy, a fetch failure, and a poisoned cache all
    collapse to the same safe floor: today's protection, plus at most stricter.

The file is written 0600 (owner only), atomically (tmp + `os.replace`), so a
reader never sees a partial write and a non-owner cannot write it. A local
attacker who CAN write it has already lost the machine (they could uninstall the
guard outright); even then, the no-weaken invariant holds — a hostile cache can
only add stricter sources or be sanitised away, never disable a catch.

The shape is the contract of the collector's `GET /v1/policy` (PR #4),
restated here because the two repos deploy apart — the schema is the shared
contract, not shared code.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import tempfile
from pathlib import Path

from core.policy import default_path as local_relaxation_path

# ── the contract (must match the collector's policy endpoint) ─
SOURCE_TYPES = ("path", "db", "bucket")
SEVERITY = ("log", "ask", "deny")
"""The escalation ladder, lowest first. There is NO value below `log` and NO
value that means 'allow' — a source can only raise scrutiny, never lower it."""
_MAX_SOURCES = 1000
_MAX_VALUE = 1024
_MAX_CACHE_BYTES = 4_000_000
"""A ceiling on the cache file the decision path will parse. The collector bounds
a policy to 1000 sources of 1024 bytes, so a real one is well under this; a file
above it is not one of ours and is not parsed — empty policy, today's behaviour —
so a huge (even well-formed) planted file cannot burn CPU on the hot path."""
MAX_VERSION = 1_000_000_000
"""A generous ceiling on the monotonic version. The collector bumps it by ONE per
write, so a real version is small; a value above this is a poisoned cache or a
bogus response, not a billion legitimate edits. ⚠ CAPPING IT STOPS A HUGE PLANTED
VERSION FROM FREEZING OUT EVERY FUTURE (STRICTER) UPDATE: `sanitise` floors an
out-of-range version to 0, so a poisoned cache SELF-HEALS on the next fetch (the
real version is then greater and is applied), and the fetch path refuses a
response whose version is out of range."""
_WRITER_OWNED = ("version", "updated_at", "updated_by")

_CACHE_ENV = "STING_POLICY_CACHE"
"""Full path override, mirroring `STING_SESSION_ROOT`, so replay and tests
isolate the cache instead of touching a real `~/.sting/org_policy.json`."""


class PolicyRejected(Exception):
    """A fetched policy that is not well-formed and must not be cached, so the
    last-known-good cache is kept."""


def home_cache_path() -> Path:
    """`~/.sting/org_policy.json`: where the cache lives when nothing overrides
    it, and what uninstall removes."""
    return Path.home() / ".sting" / "org_policy.json"


def cache_path() -> Path:
    override = os.environ.get(_CACHE_ENV)
    if override:
        return Path(override).expanduser()
    return home_cache_path()


def _is_the_local_relaxation_file(path: Path) -> bool:
    """Does `path` name the file a person's relaxations live in? Compared after
    resolving links, so an override or a symlink cannot alias the two."""
    local = os.path.realpath(os.path.expanduser(local_relaxation_path()))
    return os.path.realpath(str(path)) == local


def empty_policy() -> dict:
    """A well-formed policy that declares nothing — the value every failure and
    every unset org collapses to. `version` 0 is the floor a poll compares
    against, so 'no policy' and 'version 0' are the same state."""
    return {"version": 0, "updated_at": None, "updated_by": "",
            "sensitive_sources": []}


def _valid_source(entry) -> bool:
    """One `sensitive_sources` entry, well-formed by the contract's vocabulary."""
    if not isinstance(entry, dict):
        return False
    if entry.get("type") not in SOURCE_TYPES:
        return False
    value = entry.get("value")
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_VALUE:
        return False
    return entry.get("severity") in SEVERITY


def is_well_formed(doc) -> bool:
    """The WRITE-side gate: True only when EVERY declared source is valid. A
    fetched policy that fails this is refused whole (last-good kept) rather than
    silently trimmed — a partial store of a corrupted fetch is the wrong kind of
    'fail safe'. `sanitise` is the more forgiving READ-side backstop."""
    if not isinstance(doc, dict):
        return False
    sources = doc.get("sensitive_sources", [])
    if not isinstance(sources, list) or len(sources) > _MAX_SOURCES:
        return False
    return all(_valid_source(entry) for entry in sources)


def sanitise(doc) -> dict:
    """A trusted-shape policy from ANYTHING — the READ-side backstop. A non-dict
    or empty input becomes the empty policy; a bad `version` is floored to 0;
    every malformed source is DROPPED, never surfaced; unknown top-level keys
    (future sections) pass through untouched. The result is always well-formed
    and always safe to trust, because the worst it can carry is stricter."""
    if not isinstance(doc, dict) or not doc:
        return empty_policy()
    version = doc.get("version")
    if (not isinstance(version, int) or isinstance(version, bool)
            or version < 0 or version > MAX_VERSION):
        # ⚠ A NEGATIVE OR IMPLAUSIBLY-HUGE VERSION FLOORS TO 0, so a poisoned
        # cache that planted a giant version cannot freeze out real updates —
        # `cached_version()` reads through here, so `?since=0` fetches the real
        # policy next poll and it applies.
        version = 0
    sources = []
    raw = doc.get("sensitive_sources")
    if isinstance(raw, list):
        for entry in raw[:_MAX_SOURCES]:
            if _valid_source(entry):
                sources.append({"type": entry["type"],
                                "value": entry["value"].strip(),
                                "severity": entry["severity"]})
    updated_by = doc.get("updated_by")
    out = {"version": version,
           "updated_at": doc.get("updated_at"),
           "updated_by": updated_by if isinstance(updated_by, str) else "",
           "sensitive_sources": sources}
    for key, value in doc.items():
        if key not in out and key not in _WRITER_OWNED:
            # A future section, kept untouched. ⚠ NOT VALIDATED HERE — this
            # sanitiser only knows `sensitive_sources`. When step 3 (or a later
            # feature) starts READING a new section, that reader must validate it
            # itself and preserve the no-weaken invariant; passthrough here is
            # inert (nothing reads these keys today) and must stay that way until
            # a validator for the section exists.
            out[key] = value
    return out


def load() -> dict:
    """The cached policy, ALWAYS well-formed and safe to trust — the empty policy
    when there is no cache, the file is unreadable, the JSON is bad, or the shape
    is wrong. ⚠ VALIDATED ON READ: a `policy.json` another local process wrote is
    sanitised, never trusted as-is. No network; safe on the decision path.

    -- Step 3 will call this on the hot path and should memoise on the file's
    mtime; step 2 does not call it from `decide()`, so a plain read is correct."""
    try:
        raw = cache_path().read_text(encoding="utf-8")
    except (OSError, ValueError):
        return empty_policy()
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        # ⚠ RecursionError (a RuntimeError, NOT a ValueError) is how a hostile
        # deeply-nested-JSON cache would crash the decoder — caught here so a
        # poisoned cache degrades to the empty policy, never a crash on the
        # decision path.
        return empty_policy()
    return sanitise(parsed)


def cached_version() -> int:
    """The version the cache currently holds, or 0. What the poll sends as
    `?since=` so the collector can answer `unchanged` cheaply."""
    version = load().get("version")
    return version if isinstance(version, int) and not isinstance(version, bool) else 0


# ── the DECISION-PATH read: memoised on the cache file's (path, mtime, size) ───
_MEMO: dict = {"key": None, "policy": None}


def load_cached() -> dict:
    """`load()`, memoised on the cache file's identity so the DECISION PATH pays a
    `stat`, not a JSON parse, after the first read.

    ⚠ HOT-PATH SAFE. A `stat` and a dict return, no network; it re-reads only when
    the file changed (a newer policy was fetched) or first appears. ⚠ NEVER
    FAIL-OPEN: a missing/unreadable file is the EMPTY policy, exactly as `load()`,
    and a stat failure is not cached, so the file appearing later reloads cleanly.
    The memo lives for the process; in the resident daemon that is one parse then
    stats, and in a per-hook process it is one parse per action — either is cheap.
    """
    path = cache_path()
    try:
        info = path.stat()
        key = (str(path), info.st_mtime_ns, info.st_size)
    except OSError:
        _MEMO["key"] = None
        return empty_policy()
    if _MEMO["key"] == key and _MEMO["policy"] is not None:
        return _MEMO["policy"]
    if info.st_size > _MAX_CACHE_BYTES:
        policy = empty_policy()                    # too large to be ours; skip
    else:
        # ⚠ NEVER RAISES. `load()` returns the empty policy on every error it
        # anticipates; a broad guard here keeps the module's "always well-formed,
        # never raises on the decision path" contract even against an unforeseen
        # one, so a poisoned cache can never crash `engine.decide`.
        try:
            policy = load()
        except Exception:                          # noqa: BLE001
            policy = empty_policy()
    _MEMO["key"], _MEMO["policy"] = key, policy
    return policy


def _boundary_token(value: str, text: str) -> bool:
    """`value` appears in `text` as a whole token — not glued to a word character
    on either side. The deterministic command-text match for `db` (and the
    fallback for `bucket`): a declared identifier mentioned in a command, never
    fuzzy and never a substring of a longer name."""
    if not value or not text:
        return False
    return re.search(r"(?<![\w.$-])" + re.escape(value) + r"(?![\w-])",
                     text) is not None


_GLOB_META = re.compile(r"[*?\[\]]")


def _degenerate(source_type: str, value: str) -> bool:
    """A declared value that would match (nearly) EVERYTHING and turn one fat-
    fingered entry into a silent deny-all. Such a value must match NOTHING. True in
    two cases:

      1. NOTHING LITERAL survives — after dropping a `scheme://` prefix (a bucket)
         and removing glob metacharacters and slashes, no text is left to pin the
         match: `/`, `//`, `*`, `/*`, `**`, `s3://`, `[?]`.
      2. AN UNANCHORED PATH GLOB — a `path` value with a `*`/`?`/`[` whose literal
         text BEFORE the first wildcard (slashes removed) is empty: `*`, `*.env`,
         `*e*`, `*/x`. `fnmatch`'s `*` spans `/`, so a leading/floating wildcard
         matches across EVERY directory — a deny-almost-all from one glob typo
         (`*.*` matches every dotted file, `*e*` almost every path). An ANCHORED
         glob (`/etc/*`, `/data/pii/*.csv`, `~/.aws/*`) is bounded by its literal
         directory prefix and is fine.

    `s3://acme` (→ `acme`) and `/etc/secrets` (no glob) are real and NOT degenerate.
    ⚠ THIS IS THE AUTHORITATIVE 'matches nothing' GATE — a trailing-slash trim
    misses `s3://` (→ `s3:`) and `*` (no slash), and the literal-survives check
    alone misses `*.env`/`*e*` (a literal DOES survive, but the wildcard floats)."""
    if source_type == "bucket":
        value = value.split("://", 1)[-1]
    if _GLOB_META.sub("", value).replace("/", "").strip() == "":
        return True
    if source_type == "path" and any(ch in value for ch in "*?["):
        anchor = re.split(r"[*?\[]", value, maxsplit=1)[0]   # literal before wildcard
        if anchor.replace("/", "").strip() == "":
            return True
    return False


def _path_matches(candidate: str, value: str) -> bool:
    """A resolved read path matches a declared `path` source: EXACT, a DIRECTORY
    PREFIX at a boundary, or a GLOB. ⚠ CONSERVATIVE — `/etc/secrets` matches
    `/etc/secrets` and `/etc/secrets/x` but NOT `/etc/secrets-public`, so the
    escalation only fires on the declared tree, never a sibling that shares a
    prefix. (A degenerate value is refused upstream by `_degenerate`; the trim here
    is a cheap secondary guard.)

    ⚠ THE CANDIDATE IS NORMALISED FIRST (`..`/`.` collapsed) — a naive prefix check
    let `<decl>/data/../../secret` string-match `<decl>/data/` and, in step 3b where
    a match drives a real `world.read_text`, read a file OUTSIDE the declared tree.
    normpath is lexical (no symlink resolution) but closes the `..` traversal; a
    native READ operand is already absolute+resolved, and this makes a command-text
    token safe too."""
    candidate = os.path.normpath(candidate)
    trimmed = os.path.normpath(value.rstrip("/")) if value.rstrip("/") else ""
    if not trimmed:
        return False
    if candidate == trimmed:
        return True
    if candidate.startswith(trimmed + "/"):
        return True
    # A GLOB is matched against the NORMALISED candidate but the RAW value (normpath
    # would mangle `**`/`*` segments); `_degenerate` already refused a floating glob.
    if any(ch in value for ch in "*?[") and fnmatch.fnmatch(candidate, value):
        return True
    return False


def _bucket_matches(candidate: str, value: str) -> bool:
    """A `bucket` source matches a read path/URL at a boundary: `s3://pii` matches
    `s3://pii` and `s3://pii/obj`, not `s3://pii-2`."""
    trimmed = value.rstrip("/")
    if not trimmed:
        return False                               # `s3://` etc. — matches nothing
    return candidate == trimmed or candidate.startswith(trimmed + "/")


# A FILESYSTEM path token in a command: a `/…`/`~/…` run. `_URL_SPAN` first deletes
# every `scheme://…` run WHOLE (host, path AND query), so a path-shaped url piece —
# a `/data` host path OR a `?ref=/etc/pii` query value — can never be read as a
# local file of the same name. The `(?<![\w:/])` lookbehind then keeps a `/x` glued
# to a word from being split off mid-token. Used to catch a shell read of a declared
# file (`cat /pii/x`) precisely, without a url false-match escalating a bare egress.
# ⚠ THE SCHEME IS BOUNDED `\w{1,32}` — an unbounded `\w+` before `://` backtracks
# catastrophically (O(n²)) on a long punctuation-free token (a hex blob, a JWT
# payload) that never reaches `://`, stalling this hot path for seconds. Every real
# scheme (https, s3, gs, file, data) is far under 32; the bound keeps the scan linear.
_URL_SPAN = re.compile(r"\w{1,32}://\S+")
_CMD_PATH = re.compile(r"(?<![\w:/])~?/[\w./~-]+")


def _command_paths(text: str) -> list:
    """Filesystem-path tokens mentioned in a command, url spans removed first."""
    return _CMD_PATH.findall(_URL_SPAN.sub(" ", text or ""))


def match(candidates, command: str = "") -> list:
    """The declared sources this read touched, or []. Deterministic and conservative
    (no content inspection, no fuzzy match). `command` is scanned as text; the caller
    passes it commit-message-stripped and bash-unquoted (see `mark_sources`), so a
    commit message naming a source in prose does not count as a read and a quote-
    split token is not evaded:

      path    a resolved read path (a READ operand, a FETCH url, or a filesystem
              path token in the command — url spans excluded) exact / under / glob-
              matching the value — so a shell `cat /declared/pii | curl …` is caught,
              not only a native READ, and `curl https://h/declared/pii` is not.
      bucket  a read path/URL prefixed by the bucket, or the bucket mentioned as a
              whole token in the command (`s3://…`/`gs://…` URI form).
      db      the identifier mentioned as a whole token in the command text.

    A degenerate value (`/`, `*`, `s3://`) is refused by `_degenerate` and matches
    NOTHING — never deny-all.

    ⚠ KNOWN STEP-3a LIMITS (coarse, command-level): a `db` source is command-line
    SQL only — an in-code query the engine never sees does not match. A `bucket`
    named `s3://acme` is not matched in the VIRTUAL-HOST url form
    (`https://acme.s3.amazonaws.com/…`), only the `s3://` URI. A `TOOL` (MCP) call's
    arguments are not scanned for sources here. These are false-negatives (under-
    catch), never a weakening — a refinement for a later step, not a floor break.

    Empty policy or no match -> [] -> the caller marks nothing -> today's behaviour.
    """
    sources = load_cached().get("sensitive_sources") or []
    if not sources:
        return []
    paths = [c for c in (candidates or []) if isinstance(c, str)]
    text = command or ""
    hits = []
    for source in sources:
        source_type, value = source.get("type"), source.get("value")
        if not isinstance(value, str) or not value:
            continue
        if source_type in ("path", "bucket") and _degenerate(source_type, value):
            # ⚠ A degenerate `/`, `*`, `/*` or `s3://` would match (nearly) every
            # read — a 'deny all egress' from one fat-fingered entry. It must match
            # NOTHING. Guarded HERE (before the command fallback), not only inside
            # the matchers, so neither the candidate check nor the command/glob
            # fallback can resurrect it.
            continue
        if source_type == "path":
            # ⚠ THE COMMAND-TEXT FALLBACK closes the gap the review found: a shell
            # read of a declared NON-credential file (`cat /pii/x`) never enters
            # `candidates` (only credential-shaped paths are parsed from a command).
            # Match FILESYSTEM path tokens in the command — url paths excluded — so
            # `curl https://h/data/pii` does NOT spuriously match local `/data/pii`.
            touched = (any(_path_matches(p, value) for p in paths)
                       or any(_path_matches(cp, value) for cp in _command_paths(text)))
        elif source_type == "bucket":
            touched = (any(_bucket_matches(p, value) for p in paths)
                       or _boundary_token(value, text))
        elif source_type == "db":
            touched = _boundary_token(value, text)
        else:
            touched = False
        if touched:
            hits.append(source)
    return hits


def readable_paths(candidates, command: str = "") -> list:
    """The concrete filesystem paths this action read that fall under a declared
    PATH source — the files whose CONTENT step 3b fingerprints. A native READ operand
    or a filesystem path token in the command (url spans excluded) that matches a
    declared `path` source, deduplicated in first-seen order.

    ⚠ PATH SOURCES ONLY. A `bucket`/`db` match, or a FETCH url, names no local file
    the engine can read here, so it yields nothing — those stay coarse-taint only
    (step 3a). A degenerate value is refused by `_degenerate`, exactly as in `match`,
    so a fat-fingered `/`/`*` never turns into 'fingerprint every file'.

    Empty policy or no path source -> [] -> the caller reads and fingerprints nothing
    -> byte-identical to a machine with no policy.
    """
    sources = load_cached().get("sensitive_sources") or []
    path_sources = [s.get("value") for s in sources
                    if s.get("type") == "path" and isinstance(s.get("value"), str)
                    and s.get("value") and not _degenerate("path", s["value"])]
    if not path_sources:
        return []
    concrete = [c for c in (candidates or []) if isinstance(c, str)]
    concrete += _command_paths(command or "")
    out, seen = [], set()
    for p in concrete:
        if p in seen:
            continue
        if any(_path_matches(p, value) for value in path_sources):
            seen.add(p)
            out.append(p)
    return out


def store(doc) -> dict:
    """Validate `doc` and write it to the cache ATOMICALLY (0600). Returns the
    stored, sanitised policy; raises `PolicyRejected` if the fetched policy is not
    well-formed, so the caller keeps the last-known-good cache.

    ⚠ THE ONLY WRITER IS THE OUT-OF-BAND SHIPPER POLL. The engine never writes
    policy; the device only reads it from the collector. The write is a plain
    file replace with no network, so this stays a `core/` module the isolation
    test allows."""
    if not is_well_formed(doc):
        raise PolicyRejected("fetched policy is not well-formed")
    clean = sanitise(doc)
    path = cache_path()
    if _is_the_local_relaxation_file(path):
        # ⚠ NEVER THROUGH THE OTHER FILE'S PATH. Stored there, an org document
        # would replace a person's relaxations, and its unknown keys would be
        # read back as relaxations.
        raise PolicyRejected(f"refusing to cache the org policy at {path}: that "
                             f"is the local relaxation file")
    tmp = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".org_policy-",
                                       suffix=".tmp")
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(clean, out, sort_keys=True)
        os.chmod(tmp, 0o600)                 # mkstemp is already 0600; explicit
        os.replace(tmp, path)                # atomic: reader sees old or new only
    except OSError as exc:
        # ⚠ ANY WRITE FAILURE IS A CALLER-VISIBLE 'KEEP LAST-GOOD', NEVER AN
        # UNCLASSIFIED EXCEPTION. A full disk (ENOSPC), an unwritable `~/.sting`,
        # or a POISONED INODE — `policy.json` swapped for a directory, so
        # `os.replace` raises IsADirectoryError — must not crash the shipper loop.
        # It is raised as `PolicyRejected` so the poll keeps the last-good cache
        # and logs, exactly as it does for a malformed body. (`load()` already
        # returns the empty policy for an unreadable file, so protection stays at
        # today's floor even while the poison sits there.)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise PolicyRejected(f"could not write policy cache: {exc}") from exc
    return clean
