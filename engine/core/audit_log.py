"""
The tamper-evident local decision log — docs/15 step 16.

    H(n) = SHA-256(H(n-1) + record)

One JSON object per line, each carrying the previous record's hash. Editing or
deleting any record breaks every hash after it, so a quiet edit stops being
quiet. That is the whole mechanism: one hash per write, no server, no key.

WHAT THIS DOES AND DOES NOT GIVE YOU. It detects *quiet edits* — someone who
changes one record and leaves the rest alone. It does NOT stop someone with
write access to the file from recomputing the entire chain from the edit
forward; nothing local can, because the attacker has everything the writer had.
Real tamper-PROOFING needs an anchor this machine cannot forge — a remote
witness, or a signature over a key the agent cannot read. docs/15 says as much
("even before any control plane exists to verify it remotely"). Until that
exists, this is tamper-EVIDENT, and the honest claim is the smaller one.

WHY EVERY DECISION, NOT JUST DENIALS. The panel only needs denials, but a log
that records only denials cannot show a gap. Logging every decision means `seq`
tracks the action stream closely, so a deleted record tends to leave a hole in
the numbering as well as a break in the chain.

WHAT `seq` IS, AND THE TWO PLACES IT CHECKS OUT. `seq` numbers the ACTION, not
the record. One action writes two records in exactly one case: a DENY the
developer overrides with a one-shot grant is logged as a `decision` and then,
immediately after, as an `allow_once_used` at the SAME seq — so the log shows
both what the policy decided and that a human overruled it (hook_entry
`_apply_allow_once`).

    verify_chain / verify_records — the HASH check, and it reads only the
        prev/hash links, never `seq`. A doubled log (two racing hooks, or an
        older engine) chains correctly and so VERIFIES here: the chain is
        genuinely intact. Collisions are deliberately NOT this function's job,
        because a collision is not a quiet edit — conflating the two would make
        a settings-scope misconfiguration read as tampering.
    duplicate_events / tools/verify_log.py — the DOUBLING check, keyed on
        (session_id, seq, event). The `decision`+`allow_once_used` pair has two
        DIFFERENT events, so it is not a duplicate; two records of the SAME
        event at one seq is the collision, reported as DOUBLED with its
        settings-scope cause. Cross-session seq reuse and seq=None records are
        not duplicates.

A SKIPPED seq (a GAP) is flagged by neither: a refused, fail-open, or abstained
action legitimately leaves a hole (docs/76), and real logs contain them, so gap
detection would false-positive — still the owner's call. The hash chain is the
tamper-evidence; the seq checks are a second, narrower signal for doubling.

WHY NOT IN engine.py. This opens a file, and engine.decide() is a pure function
of (action, state, world) — tests/test_hook_entry.py enforces that it imports no
IO module at all. So the engine decides and hook_entry records.
"""
from __future__ import annotations

import hashlib
import json
import os
import time

# ⚠ THE PLATFORM SEAM. `import fcntl` used to sit at module scope here,
# which is an ImportError on Windows before any code runs — the engine did
# not start at all. See core/locking.py.
from core import locking
from pathlib import Path

from core import purpose as _purpose
from core import version
from core.session import default_root, safe_session_id

LOG_SUFFIX = ".log.jsonl"
"""Appended to the safe session id. The extension mirrors this in
extension/src/paths.ts, and a test asserts the two agree."""

GENESIS = "0" * 64
"""H(0). The first record chains from this."""

UNREADABLE = "UNREADABLE"
"""Recorded as `prev` when the preceding record could not be parsed. Better than
silently restarting from GENESIS, which would make a corrupted tail look like a
fresh, valid log."""

# Bounds. A record must stay below _TAIL so that reading the tail always
# contains a COMPLETE final line; see _last_hash(). ⚠ IF A LINE EVER EXCEEDED
# _TAIL, `_tail_lines` would return a fragment of it as the last line, it would
# fail to parse, and EVERY SUBSEQUENT APPEND WOULD CHAIN FROM `UNREADABLE` — the
# chain broken permanently on a log that is otherwise intact. Two things now
# stand between these constants and that outcome: `worst_record_bytes()`
# derives the largest possible line from them and a test holds it under _TAIL,
# and `append()` refuses (RecordTooLarge) any line the window could not hold
# whole, before a byte of it is written.
#
# ⚠ THE INVARIANT WAS FALSE TWICE, AND THE SECOND TIME IT HAD A TEST. The first
# sizing said "far below" and held only because real data escapes at 1.04x (p50
# over 6,117 real commands). The second sizing (docs/64) priced JSON escaping at
# 6 bytes per character and summed six of the twelve bounded fields — no
# `workspace_roots`, no `url`/`cwd`/`tool_name`, no `relaxed` — and its test
# built exactly that record. Either mistake alone still fit the 512 KiB window
# (344 KB in the six-byte character with all 32 roots; 491 KB in the twelve-byte
# one with none). Both together did not: 688 KB, and the record after it chained
# from UNREADABLE without a word to anyone. docs/76 has the numbers.
_MAX_COMMAND = 16_384
_MAX_REASON = 1024
_MAX_PATH = 512
_MAX_PATHS = 32
_MAX_EVIDENCE = 200
# An agent id is a short constant an adapter declares ("claude-code", "cursor").
# Bounded anyway rather than trusted: it arrives from an adapter, and the point
# of every other bound in this list is that a record's size is ours to decide.
_MAX_AGENT = 64

_MAX_RULE_ID = 80
"""A rule id is ours, not a sender's — but `relaxed` is read from a file a
person edits, so the bound is here rather than assumed. Longest real rule id
today is 38 characters."""
_WORST_ESCAPE = 12
"""⚠ BYTES ONE CODE POINT CAN COST IN `canonical()`, AND IT IS NOT SIX.

`ensure_ascii=True` writes a code point outside the Basic Multilingual Plane —
most emoji — as a surrogate PAIR, `\\ud83d\\ude00`: twelve bytes. Six is what a
control character or an accented letter costs, and six was the number the
window above was sized from. Every bound in this file is in code points
(`_clip` uses `len()`), so a field at its cap can be made entirely of
twelve-byte characters, and `worst_record_bytes()` prices it that way."""

_MAX_RELAXED = 64
"""Rule ids one record may list as relaxed. Was a literal inside build_body,
which is how a bound stays out of the arithmetic that sizes the window."""

_ANSWERS = ("ALLOW", "ASK", "DENY")
"""What `enforced` may hold: the answer the hook handed the agent's adapter.
Our own enum, priced in `_SPINE_BYTES` like `decision`."""

_MAX_TITLE = 96
"""A session's human title (`book-app / npm run dev`), derived once per session
by hook_entry from the declared root and the first command — core/title.py,
docs/79. Content-blind by construction; bounded here like every text field, and
counted in worst_record_bytes() like every text field."""
_MAX_WHY_PHRASE = 96
"""`action` and `value_type` on a DENY or ASK record (docs/108): phrases this
engine writes, the longest a format name. `destination`, `source_file` and
`location` are paths or hosts, `_MAX_PATH`; `sentence` is `_MAX_REASON`."""

_SPINE_BYTES = 4096
"""Everything in a line of the log that is not a bounded text field: key
names, numbers, enum strings, a session id (at most 128 characters, ASCII by
construction — see safe_session_id), an 80-character rule id, `prev`, `hash`,
and json.dumps' default separators on disk. Measured at ~1.5 KB for a record at
every bound; the test asserts this allowance is not slack beyond its own size."""


def worst_record_bytes() -> int:
    """An upper bound on ONE LINE of the log, derived from the bounds above.

    Every field build_body() clips, at its cap, in the twelve-byte character,
    plus a clip marker per clipped field, plus the spine. `_TAIL` must exceed
    this, or the record AFTER such a line chains from UNREADABLE. A test
    restates this sum independently and measures a real line against it, so
    neither the formula nor the constants can drift on their own.
    """
    bounded_chars = (
        _MAX_COMMAND + _MAX_REASON + _MAX_EVIDENCE
        + 2 * _MAX_PATHS * _MAX_PATH            # paths, workspace_roots
        + 3 * _MAX_PATH                         # url, cwd, tool_name
        + 3 * _MAX_AGENT                        # agent, guard_version, granted_by
        + _MAX_TITLE                            # title
        + _MAX_RELAXED * _MAX_RULE_ID           # relaxed
        + 2 * _MAX_WHY_PHRASE                   # action, value_type
        + 3 * _MAX_PATH                         # destination, source_file, location
        + _MAX_REASON)                          # sentence
    # reason, command, evidence, url, cwd, tool_name, agent, guard_version,
    # granted_by, title, and the six why texts — sixteen scalars — plus every
    # path and workspace root.
    clipped_fields = 16 + 2 * _MAX_PATHS        # each may carry CLIP_MARKER
    marker_bytes = len(json.dumps(CLIP_MARKER, ensure_ascii=True)) - 2
    return _WORST_ESCAPE * bounded_chars + clipped_fields * marker_bytes + _SPINE_BYTES


_TAIL = 1024 * 1024
"""⚠ SIZED FROM THE BOUNDS ABOVE, NOT CHOSEN — AND THE COST OF THE SIZE IS
MEASURED, NOT ASSUMED. `worst_record_bytes()` is 726,160 for every field at
its cap in the twelve-byte character (693,046 before a block's why fields,
docs/108); 1 MiB is 1.44x that.

Why not more: the window is O(1) in session length but LINEAR in _TAIL, because
`append()` json-parses every line in it for the duplicate check. Measured on a
3 MiB log of real records (the 1,181 records of logs/live-fixture, p50 883
bytes, repeated), one append costs

    512 KiB     2.5 ms   (410 lines parsed)
      1 MiB     5.3 ms   (784 lines)
      2 MiB    10.5 ms   (1,638 lines)

against a 12 ms budget for the whole hook (A6a). 2 MiB would spend nearly all
of it on a long session; 1 MiB spends 2.7 ms more than before, and only on
sessions past 1 MiB. Not one of the 1,181 real records contains a twelve-byte
character (escape ratio p50 1.000, max 1.235), so the 1.5x is headroom over a
bound that is already the worst case, not over an estimate of it."""

# ---- Option D: the command sidecar ----------------------------------------
# `command` is clipped, so a verdict on a long command cannot be RE-RUN from the
# log. `command_sha256` proves which string was judged but cannot recover it —
# one real investigation only succeeded because the clipped tail happened to be a
# commit message that still existed in git. Nothing guarantees that.
#
# Content-addressed, so the same long command recurring in a session is stored
# once. Measured on the real logs: 77 clipped records, 61 distinct hashes.
SIDECAR_SUFFIX = ".commands"
_MAX_SIDECAR_BYTES = 1024 * 1024          # per command
_MAX_SIDECAR_FILES = 512                  # per session
_MAX_SIDECAR_TOTAL = 32 * 1024 * 1024     # per session

# ---- Option E: derived (redacted) logs -------------------------------------
REDACTION_MANIFEST = "_redaction.json"
"""Present in a directory => every log beside it is DERIVED, not evidence.

A redacted log is a regression-test input. Its chain is recomputed over the
rewritten bytes, so it can attest exactly one thing — "unmodified since it was
derived" — and nothing whatever about the session it came from. That is a real
property and a much weaker one, and the ONLY dishonesty available is failing to
say which of the two is meant.

⚠ `verify_log.py` MUST NOT print a plain OK for a log beside this file. Without
that refusal a reader sees a verified chain and reasonably concludes the real
session is attested. See `tests/test_redaction_is_declared.py`, which fails if a
redacted log can ever produce a clean OK.
"""

# ---- Option F: pruning a log whose head has been acknowledged ---------------
PRUNE_MANIFEST = "_pruned.json"
"""Beside a log => its OLDEST records were deleted after the collector said it
had them. Named per log, because sessions are pruned independently.

⚠ WITHOUT THIS FILE, PRUNING IS INDISTINGUISHABLE FROM TAMPERING. `verify_chain`
starts at GENESIS and requires record 1 to chain from it. Delete the head and
the surviving first record chains from a hash that no longer exists anywhere —
the verifier reports a BREAK, which is exactly what it should report when it
cannot tell the difference. So the manifest records the hash the log now starts
from, and the verifier accepts a start it declares.

⚠ AND THIS IS STRICTLY WEAKER THAN AN UNPRUNED LOG, WHICH IS THE POINT OF
SAYING IT OUT LOUD. Anyone who can write the log can write the manifest beside
it. What the manifest buys is not proof against an attacker — the chain never
had that locally, see `verify_log.py` on wholesale truncation — it is that an
HONEST prune stops looking like a dishonest one, and that what was removed, how
much, and WHICH COLLECTOR RECEIPT authorised it are written down instead of
inferred from a gap.
"""


def prune_manifest_for(log_path: Path) -> Path:
    """The prune record for this log, whether or not it exists."""
    return log_path.parent / f"{log_path.name}{PRUNE_MANIFEST}"


def pruned_start(log_path: Path) -> str | None:
    """The hash this log legitimately starts from, or None if never pruned."""
    manifest = prune_manifest_for(log_path)
    if not manifest.is_file():
        return None
    try:
        entries = json.loads(manifest.read_text(encoding="utf-8")).get("prunes")
        return str(entries[-1]["starts_from"]) if entries else None
    except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError):
        # ⚠ AN UNREADABLE MANIFEST IS NOT PERMISSION. Returning None sends
        # verify_chain back to demanding GENESIS, so a corrupt manifest makes
        # the log report a break rather than silently excusing one.
        return None


ORIGINAL_DIGEST_FIELD = "original_sha256"
"""Provenance ONLY. Inert by construction: never an address, never verified.

`command_sha256` addresses the sidecar and proves wholeness; `original_sha256`
records what the digest was BEFORE redaction, so that anyone holding the real log
can prove the fixture derives from it. Nothing here can check it — the original
bytes are deliberately destroyed — and a reader who used it to look up a sidecar
would get a miss on a file that exists under its real name.

**Two hashes with different meanings is exactly where a future reader picks the
wrong one**, so the separation is enforced structurally rather than by comment:
the string `original_sha256` does not occur anywhere in `core/` or `runner/`
outside this docstring, and `tests/test_redaction_is_declared.py` fails if it
ever does. The addressing path cannot pick the wrong hash because it cannot see
it.
"""


def redaction_manifest_for(log_path: Path) -> Path:
    """The manifest governing this log, whether or not it exists."""
    return log_path.parent / REDACTION_MANIFEST


def is_derived(log_path: Path) -> bool:
    """Is this log a derived artifact rather than a recorded session?"""
    return redaction_manifest_for(log_path).is_file()

# The three states a reader must tell apart. ABSENT IS NOT TAMPERING — it is the
# normal result of a cap, a copy without the directory, or a deliberate cleanup.
SIDECAR_ABSENT = "absent"
SIDECAR_RECOVERED = "recovered"
SIDECAR_CORRUPT = "corrupt"


def default_log_path(session_id: str, root: Path | None = None) -> Path:
    """Beside the session state, sharing its isolation.

    STING_LOG overrides it outright. STING_SESSION_ROOT moves both together,
    which is what makes each replay scenario and each test get its own log
    without either having to know this module exists.
    """
    override = os.environ.get("STING_LOG")
    if override:
        return Path(override).expanduser()
    return (root or default_root()) / f"{safe_session_id(session_id)}{LOG_SUFFIX}"


CLIP_MARKER = "…[clipped]"
"""Appended to a truncated value so a human reading the log sees the cut.

⚠ IT IS A COURTESY, NOT A SIGNAL. A marker that lives INSIDE the value cannot be
trusted to report on the value: a command that genuinely contains this text is
indistinguishable from a truncated one, and a reader who does not know the marker
sees a complete-looking command. `command_clipped` and `command_len` are the
signal; this is the annotation. Nothing should branch on it — see
`test_a_command_containing_the_marker_is_not_reported_as_clipped`.
"""


def _clip(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit] + CLIP_MARKER


def sidecar_dir(log_path: Path) -> Path:
    """Where full commands live, named FROM the log rather than the session root.

    `STING_LOG` therefore moves the sidecar with the log it belongs to. Deriving
    it from the session root instead would let a redirected log point at another
    log's evidence.
    """
    return log_path.parent / (log_path.name + SIDECAR_SUFFIX)


def store_full_command(log_path: Path, command: str | None) -> str | None:
    """Write the full command, content-addressed. Returns the digest, or None.

    NEVER raises, for the same reason `_log` never raises: losing the ability to
    re-run a verdict is an observability failure, and a guard that fails closed
    because a directory is unwritable protects nothing.

    OVER `_MAX_SIDECAR_BYTES`, NOTHING IS WRITTEN. A truncated sidecar would be a
    file whose content does not hash to its own name — indistinguishable from
    tampering. Absence is honest; a wrong hash is not.

    OVER THE COUNT OR TOTAL CAP, WRITING STOPS AND NOTHING IS DELETED. Pruning
    oldest-first would destroy evidence to make room for evidence, and the older
    record is the one more likely to be under investigation.
    """
    if command is None or len(command) <= _MAX_COMMAND:
        return None                       # already whole in the record
    try:
        payload = command.encode("utf-8")
        if len(payload) > _MAX_SIDECAR_BYTES:
            return None
        digest = hashlib.sha256(payload).hexdigest()
        directory = sidecar_dir(log_path)
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / digest
        if target.exists():
            return digest                 # content-addressed: already stored
        files = total = 0
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_file():
                    files += 1
                    total += entry.stat().st_size
        if files >= _MAX_SIDECAR_FILES or total + len(payload) > _MAX_SIDECAR_TOTAL:
            return None
        # Same-directory temp then rename, so a reader never sees a partial file
        # under a name that claims to be its hash.
        tmp = directory / f".{digest}.{os.getpid()}.tmp"
        tmp.write_bytes(payload)
        os.replace(tmp, target)
        return digest
    except Exception:                     # noqa: BLE001 — deliberate, see docstring
        return None


def stored_command_is_whole(record: dict) -> bool | None:
    """Is `record["command"]` the entire command, or only the front of it?

    True / False / None, where None means the record cannot say. THE ONE PLACE
    THIS QUESTION IS ANSWERED — `load_full_command` and the differential's
    `classify()` both call it, because when they answered it separately they
    disagreed about the same nine records and one of them returned a WRONG
    answer rather than no answer.

    Four tests, in descending order of authority:

      1. `command_sha256` MATCHES the stored text -> whole, proven. Content
         addressing, so a command that genuinely contains CLIP_MARKER is whole
         and says so — the case that motivated the marker never being a signal.
      2. `command_clipped` — the recorded FACT, computed from the true length
         before clipping and inside the hashed body.
      3. CLIP_MARKER present — only for records predating the flag entirely.
      4. length >= _MAX_COMMAND — for records predating flag AND marker.

    ⚠ A DIGEST MISMATCH IS NOT EVIDENCE OF CLIPPING, which is why test 1 can
    only prove wholeness and never disprove it. The vendored fixture is
    REDACTED: its text was rewritten after the digest was computed, so 397 of
    617 records mismatch while only 203 are truly clipped. Reading a mismatch as
    truncation would have mislabelled 194 whole commands. Provenance and
    integrity are different questions and this function only answers one.
    """
    command = record.get("command")
    if command is None:
        return None
    digest = record.get("command_sha256")
    if digest and hashlib.sha256(command.encode("utf-8")).hexdigest() == digest:
        return True
    clipped = record.get("command_clipped")
    if clipped is not None:
        return not clipped
    if CLIP_MARKER in command:
        return False
    if len(command) >= _MAX_COMMAND:
        return False
    return None


def load_full_command(record: dict, log_path: Path) -> tuple[str, str | None]:
    """Recover the exact command a record was judged on.

    Returns one of three states, which a caller MUST distinguish:

        (SIDECAR_ABSENT,    None)  recovery impossible, integrity intact
        (SIDECAR_RECOVERED, text)  the exact string that was judged
        (SIDECAR_CORRUPT,   None)  the stored bytes do not match the attested
                                   digest — the sidecar is lying

    THE TRUST COMES FROM THE CHAIN, NOT FROM THE FILE. `command_sha256` is inside
    the hashed body, so the chain already attests the digest; this compares the
    file against that. A forged sidecar is caught by content-addressing, which is
    why the sidecar needs no chain coverage of its own.

    ⚠ WHOLENESS IS DECIDED BY `stored_command_is_whole`, NOT HERE. This used to
    read `command_clipped` alone. Nine records in a real session predate that
    field and carry only the marker, so they took the early return and came back
    as (SIDECAR_RECOVERED, <truncated text>) — all nine at exactly 2058 bytes,
    2048 plus the marker. **A wrong answer, not a missing one**, which is the one
    outcome the three states exist to rule out. The differential's `classify()`
    already had the full ladder; the two now share it and a test asserts they
    cannot drift apart again.
    """
    digest = record.get("command_sha256")
    if not digest:
        return SIDECAR_ABSENT, None       # predates the field; unverifiable
    if stored_command_is_whole(record):
        stored = record.get("command")
        return ((SIDECAR_RECOVERED, stored) if stored is not None
                else (SIDECAR_ABSENT, None))
    target = sidecar_dir(log_path) / digest
    try:
        payload = target.read_bytes()
    except OSError:
        return SIDECAR_ABSENT, None
    if hashlib.sha256(payload).hexdigest() != digest:
        return SIDECAR_CORRUPT, None
    return SIDECAR_RECOVERED, payload.decode("utf-8", errors="replace")


def command_for(record: dict, log_path: Path) -> tuple[str | None, bool]:
    """THE ONE CALL ANY ANALYSIS SHOULD MAKE. `(command, whole)`.

    ⚠ READING `record["command"]` DIRECTLY IS A BUG, AND IT HAS ALREADY COST A
    WRONG CONCLUSION. An audit measured "262 of 1698 live commands (15.4%) fail
    to parse cleanly" from the raw field and used it to reject a fix. Re-measured
    through this function: 266 of 266 of those failures are CLIPPED records —
    every one at the 2048 bound — and the sidecar restores 250 of them. The true
    rate on complete commands is 0 of 1713.
    
    Clipping happens when the log BODY IS BUILT (`_clip(command, _MAX_COMMAND)`
    below), which is AFTER the verdict. The engine always saw the whole command.
    So a parse failure on the stored text is a fact about the log, and reporting
    it as a fact about the command is the error this function exists to prevent.

    `whole` is False when the text is a prefix the sidecar could not restore.
    A caller must not derive STRUCTURE from a prefix — see `structure_mask`.
    """
    command = record.get("command")
    if not isinstance(command, str):
        return command, True
    if stored_command_is_whole(record) is not False:
        return command, True
    state, recovered = load_full_command(record, log_path)
    if state == SIDECAR_RECOVERED and recovered is not None:
        return recovered, True
    return command, False


def canonical(body: dict) -> str:
    """The exact bytes that get hashed.

    sort_keys and no whitespace, so the hash depends on the content and not on
    how any particular Python version happened to order a dict.
    """
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def record_hash(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + canonical(body)).encode("utf-8")).hexdigest()


def _tail_lines(fd: int) -> list[str]:
    """The last _TAIL bytes of the file, as non-empty lines.

    Bounded on purpose: everything that reads the log during an append must
    stay O(1) in session length, or a long session gets quadratically slower.
    """
    size = os.lseek(fd, 0, os.SEEK_END)
    if size == 0:
        return []
    back = min(size, _TAIL)
    os.lseek(fd, size - back, os.SEEK_SET)
    chunk = os.read(fd, back).decode("utf-8", "replace")
    return [ln for ln in chunk.splitlines() if ln.strip()]


def _last_hash(fd: int) -> str:
    """The hash of the final record, read from a bounded tail of the file."""
    if os.lseek(fd, 0, os.SEEK_END) == 0:
        return GENESIS
    lines = _tail_lines(fd)
    if not lines:
        return UNREADABLE
    try:
        return json.loads(lines[-1]).get("hash") or UNREADABLE
    except json.JSONDecodeError:
        # A half-written or edited final line — and, since append() refuses a
        # line the window cannot hold whole, no longer a record that was merely
        # too large. Chaining from UNREADABLE leaves a permanent, visible break
        # rather than papering over it. ⚠ VISIBLE IN THE FILE IS NOT VISIBLE TO
        # A PERSON: the sentinel is contractual, the silence around it was not.
        # hook_entry._log() says so on stderr when its record carries it.
        return UNREADABLE


def identity(record: dict) -> tuple:
    """What makes two records the same EVENT rather than two events.

    `event` is part of the key, not an afterthought: allow-once deliberately
    writes a SECOND record for the same action — same session, same seq, same
    action_hash — with event="allow_once_used", so that the log shows both what
    the policy decided and that a human overruled it. Keying on
    (session_id, seq, action_hash) alone would reject that record and destroy
    the audit trail the override exists to create.
    """
    return (record.get("session_id"), record.get("seq"),
            record.get("action_hash"), record.get("event"))


# ⚠ AN NTP STEP IS BOUNDED AND A CLOCK ATTACK IS NOT. `ntpd` refuses to step at
# all beyond 1000 s and panics; a routine correction is milliseconds, and macOS
# `sntp` steps sub-second. A laptop waking from sleep does not move epoch time
# backwards at all, and neither does a daylight-saving change — `ts` is UTC
# epoch seconds, which timezones do not touch. Q03's attack sets the clock to
# 2020: about 200,000,000 seconds.
#
# Five seconds is ~40× a typical step and seven orders of magnitude below the
# attack, and it is a THRESHOLD rather than a guess because the two populations
# do not overlap anywhere near it.
#
# ⚠ MEASURED FIRST: 0 backwards pairs in 5,028 consecutive real records on this
# machine. A strict "never backwards" rule would have fired on nothing here —
# but zero is also the empty-population answer, so the threshold stays.
CLOCK_STEP_TOLERANCE = 5.0


def clock_contradictions(records: list[dict],
                          tolerance: float = CLOCK_STEP_TOLERANCE) -> list[tuple]:
    """(seq_before, seq_after, seconds_backwards) for every record whose
    timestamp precedes the record it CHAINS to.

    ⚠ THE CHAIN IS THE WITNESS, AND THAT IS THE WHOLE MECHANISM. Ordering comes
    from `prev`/`hash`, which does not read a clock; the timestamp comes from
    the clock. A record the chain says came AFTER, carrying a time that says
    BEFORE, is the two disagreeing — and the chain is the half an attacker
    cannot rewrite without breaking every hash after it.

    ⚠ IT DETECTS AND CANNOT PREVENT, WHICH IS THE SAME CONCLUSION
    SELF-PROTECTION REACHED. The guard runs as the developer. It cannot stop the
    machine's owner moving the clock any more than it can stop them deleting the
    log; what it can do is make the move leave a mark that survives in the
    evidence.

    ⚠ AND THE AUTHORITATIVE VERSION IS NOT HERE. This compares a device's clock
    against ITSELF. Only the receiver holds an independent one — see
    docs/60 for what the collector should do with `ts` against its own arrival
    time, which is the half a compromised machine cannot forge.
    """
    out = []
    ordered = [r for r in records if isinstance(r.get("ts"), (int, float))]
    for before, after in zip(ordered, ordered[1:]):
        drift = float(after["ts"]) - float(before["ts"])
        if drift < -tolerance:
            out.append((before.get("seq"), after.get("seq"), drift))
    return out


def duplicate_events(records: list[dict]) -> list[tuple]:
    """(session_id, seq, event, count) for every event logged more than once.

    The audit key is deliberately COARSER than the write-time key in
    identity(): it drops action_hash. append() needs action_hash to be sure two
    records describe the same action before refusing one; an audit only needs to
    know that one sequence number produced two records of the same event, which
    cannot happen legitimately. Dropping it means the audit still catches a
    doubled log written by an older engine, or by two hooks that disagreed about
    the fingerprint.

    Records with seq=None are ignored, for the reason append() skips them:
    without a sequence number, repeats are indistinguishable from duplicates.
    """
    counts: dict[tuple, int] = {}
    for record in records:
        if record.get("seq") is None:
            continue
        key = (record.get("session_id"), record.get("seq"), record.get("event"))
        counts[key] = counts.get(key, 0) + 1
    return [(*key, n) for key, n in sorted(counts.items(), key=lambda kv: str(kv[0]))
            if n > 1]


class RecordTooLarge(Exception):
    """⚠ THE CAUSE OF A CHAIN BREAK, REFUSED BEFORE IT IS WRITTEN.

    A line longer than `_TAIL` cannot be read back whole by `_last_hash()`, so
    the record AFTER it — and every one after that — would chain from
    UNREADABLE. `build_body()` cannot produce such a line (`worst_record_bytes()`
    says so and a test holds it), so this fires only for a body built some other
    way, or if a bound is ever raised without the window. Nothing is written
    when it is raised: the chain stays intact, and the decision it carried is
    the one record lost — loudly, by name, on the hook's stderr.
    """


class DuplicateRecord(Exception):
    """Raised when a record identical to a recent one is appended.

    Two hook processes firing per tool call is a real configuration people hit
    — a guard installed at user scope plus one wired by a harness at project
    scope — and Claude Code merges hook scopes rather than overriding. Both
    processes chain correctly onto the current tail, so the resulting log
    verifies perfectly while containing every action twice. Chain verification
    is structurally unable to detect it.

    Raising is the point: hook_entry._log() catches this and reports it on
    stderr without failing the action, so the operator sees the misconfiguration
    instead of silently collecting a log with doubled counts.
    """


def build_body(session_id: str, seq: int | None, event: str, decision: str,
               reason: str | None = None, rule_id: str | None = None,
               kind: str | None = None, paths: tuple | list = (),
               command: str | None = None, url: str | None = None,
               action_hash: str | None = None, ts: float | None = None,
               evidence: str | None = None, duration_ms: float | None = None,
               cwd: str | None = None, tool_name: str | None = None,
               workspace_roots: tuple | list = (),
               agent: str | None = None,
               guard_version: str | None = None,
               purpose: str | None = None,
               relaxed: tuple | list = (),
               granted_by: str | None = None,
               title: str | None = None,
               why: dict | None = None,
               enforced: str | None = None) -> dict:
    """The unhashed record. Bounded, because an unbounded record could exceed
    the tail window and break _last_hash()'s guarantee.

    `action_hash` is the allow-once fingerprint of the action. It is in the
    record so the viewer can issue a grant by copying it, instead of
    reimplementing the hash — see core/allow_once.py.

    WHY `command_sha256` AND `evidence` EXIST.
    `command` is clipped to _MAX_COMMAND, and a verdict can turn on text past
    that cut. A real one did: a local file append was denied as a git push
    because the file's own content contained `command="git push"` at byte
    10711, while the record stopped at 2048. The log recorded a denial it could
    not justify, in a log whose entire purpose is being checkable.

        command_sha256  covers the FULL command, unclipped. It cannot show you
                        what matched, but it proves which exact string was
                        judged — so a stored command that was truncated, or
                        edited afterwards, is detectable.
        evidence        the text that actually fired the rule, with a little
                        context, bounded to _MAX_EVIDENCE. This is what makes a
                        verdict explain itself.

    Both are inside the hashed body, so neither can be altered without breaking
    the chain.
    """
    return {
        "ts": time.time() if ts is None else ts,
        "session_id": safe_session_id(session_id),
        "seq": seq,
        "event": event,
        "kind": kind,
        "decision": decision,
        "rule_id": rule_id,
        "reason": _clip(reason, _MAX_REASON),
        "paths": [_clip(str(p), _MAX_PATH) for p in list(paths)[:_MAX_PATHS]],
        "command": _clip(command, _MAX_COMMAND),
        "command_sha256": (hashlib.sha256(command.encode("utf-8")).hexdigest()
                            if command is not None else None),
        # Truncation as a FACT, not as a marker inside the value it describes.
        # Both are inside the hashed body, so neither can be edited without
        # breaking the chain, and `command_len` gives the full length even though
        # the full text is gone — enough to know how much is missing before
        # deciding whether to go looking for it.
        "command_len": len(command) if command is not None else None,
        "command_clipped": (len(command) > _MAX_COMMAND
                             if command is not None else None),
        "evidence": _clip(evidence, _MAX_EVIDENCE),
        # How long the VERDICT took, in milliseconds — decide() only, excluding
        # interpreter startup and excluding this log write. Every session
        # becomes a latency sample at no cost, which is what A6 needed and did
        # not have: measuring it once required a purpose-built benchmark
        # because the log carried `ts` and nothing about duration. Rounded to
        # microseconds so a record stays small and diffable.
        "duration_ms": (round(duration_ms, 3) if duration_ms is not None else None),
        "url": _clip(url, _MAX_PATH),
        # WITHOUT cwd THE RECORD CANNOT BE REPLAYED. A relative path in a command
        # resolves against it, so `_abs()`, `is_inside_project()` and every
        # path-based rule are unreproducible without it — the log recorded a
        # decision it could not reproduce, which is the same defect the clipping
        # work fixed for command text. Inside the hashed body like the rest.
        "cwd": _clip(cwd, _MAX_PATH),
        # A TOOL action's identity IS its name — an MCP call has no command and no
        # paths, so without this the record cannot say which tool ran and a TOOL
        # verdict cannot be replayed at all. Same family as `cwd`: the log recorded
        # a decision whose input it did not keep.
        "tool_name": _clip(tool_name, _MAX_PATH),
        # THE TRUST BOUNDARY THE VERDICT WAS DECIDED AGAINST. `cwd` says where the
        # command ran; this says what counted as "the project", and the two are
        # not the same — a session rooted in three repos judges a write to the
        # second as inside, while a replay that derives roots from cwd alone judges
        # it outside and manufactures a `write_outside` denial that never happened.
        # Fourth input of this kind after cwd, tool_name and content: the log
        # recorded a decision without recording what it was decided against.
        "workspace_roots": [_clip(str(r), _MAX_PATH)
                             for r in list(workspace_roots)[:_MAX_PATHS]],
        # WHICH AGENT PRODUCED THIS. `Action.agent` has been set by all five
        # adapters since they were written and was never recorded, so a log could
        # not answer "was this Claude Code or Cursor?" at all — and one developer
        # on Claude Code plus one on Cursor writing into the same log directory is
        # the case this repo is now actually in.
        #
        # ⚠ TELEMETRY, AND IT MUST STAY TELEMETRY. `Action.agent`'s own docstring
        # says the engine must never branch on it, and nothing does — no rule
        # reads it, so this field cannot move a verdict. That is also why it is
        # SAFE to record: an attacker who forges it changes an attribution, not a
        # decision. If a rule ever wants to read this, the normalisation is wrong
        # and the adapter is the thing to fix.
        #
        # Inside the hashed body like cwd, tool_name and workspace_roots — an
        # attribution that can be edited after the fact attributes nothing.
        "agent": _clip(agent, _MAX_AGENT),
        # WHICH COPY OF THE POLICY DECIDED THIS. Fifth field of the same family
        # as cwd, tool_name, workspace_roots and agent: the log recorded a
        # decision without recording what decided it.
        #
        # ⚠ IT IS NOT `manifest.guard_ref`, WHICH NAMES THE SENDING TREE. That
        # field is `git describe` run where a batch is packed, and on the first
        # real end-to-end run the two were different commits — so every verdict
        # was attributed to a policy that had not made it. Two facts, two
        # fields; a reader asking "which rules produced this verdict" must read
        # THIS one. See core/version.py.
        #
        # Passed rather than only looked up, so a caller rebuilding a historical
        # record can state the version that applied then instead of silently
        # stamping it with today's. Inside the hashed body like the rest — an
        # attribution that can be edited afterwards attributes nothing.
        # ⚠ BOTH BRANCHES CLIPPED (found by review). The fallback reads the
        # guard's own INSTALL.json, which only a rewritten guard tree can
        # lengthen — but a bound that worst_record_bytes() relies on cannot
        # depend on who wrote the value.
        "guard_version": _clip(guard_version if guard_version is not None
                               else version.running_version(), _MAX_AGENT),
        # WHAT THIS SESSION IS, DECLARED BY WHATEVER WROTE IT. Sixth field of
        # the family that includes cwd, tool_name, workspace_roots, agent and
        # guard_version: the log recorded a decision without recording the one
        # thing that says whether it should be counted at all.
        #
        # ⚠ ABSENT IS A VALUE AND IS WRITTEN AS ONE — the key is present with a
        # null, unlike the batch envelope where it is dropped. The two are
        # different artifacts for a reason: a record body is HASHED, and a key
        # that appears only sometimes would make the canonical form depend on
        # whether anyone happened to declare, so two readers could disagree
        # about what bytes a record is. Null here means "nobody said", exactly
        # as it does everywhere else in this body, and `core/purpose.py` refuses
        # to turn that into `work`.
        #
        # In the hashed body for guard_version's reason: an attribution that can
        # be edited afterwards attributes nothing. A probe relabelled as work
        # after the fact would be a lie the chain should refuse to carry.
        "purpose": (purpose if purpose in _purpose.PURPOSES
                     else _purpose.declared()),
        # ⚠ WHICH RULES WERE RELAXED WHEN THIS WAS DECIDED — THE SAME REASON
        # `purpose` AND THE TIER ARE ON THE RECORD. A verdict reached under a
        # modified policy is not the same verdict, and a reader who cannot tell
        # is reading a number that means something other than what they think.
        #
        # ⚠ THE WHOLE OVERLAY, NOT JUST THE RULE THAT FIRED. A record saying
        # "nothing was relaxed for me" is worth nothing if three other rules
        # were off at the time: what a reader needs to judge a SESSION is which
        # policy it ran under, and that is the set, not the intersection.
        #
        # Absent when empty rather than `[]`, so an unrelaxed machine — every
        # machine, by default — pays no bytes for it at any tier.
        **({"relaxed": sorted(str(r)[:_MAX_RULE_ID] for r in relaxed)[:_MAX_RELAXED]}
           if relaxed else {}),
        # ⚠ WHAT THE AGENT WAS TOLD, BESIDE WHAT THE RULE DECIDED (docs/108 §6,
        # docs/113 §1). `decision` stays the engine's own verdict — the standing
        # replay compares against it — but the agent is answered after the
        # relaxations above, a one-shot grant, or observe mode (which enforces
        # nothing: ALLOW). A reader counting DENY records counted what the rules
        # decided, not what was stopped. One of the three answers, on every DENY
        # and ASK record; an ALLOW can only have been answered ALLOW, so an
        # ALLOW record carries none and stays byte-identical (as the why fields
        # below). On a DENY or ASK, absence means "not said" (an older engine),
        # never "the same as `decision`".
        # ⚠ AND NEVER STRICTER THAN `decision` (the round-1 security review):
        # a relaxation only weakens, so a stricter "answer" is not one.
        **({"enforced": str(enforced)}
           if (enforced in _ANSWERS and decision in _ANSWERS[1:]
               and _ANSWERS.index(enforced) <= _ANSWERS.index(decision)) else {}),
        # ⚠ WHO APPROVED A HUMAN OVERRIDE — present ONLY on an `allow_once_used`
        # record, and dropped when absent, FOLLOWING `relaxed` ABOVE RATHER THAN
        # `purpose`. On an engine-decided ALLOW a `granted_by` is not "nobody
        # said" the way `purpose: null` is — it is a category error, because the
        # engine grants nothing and a human does, so the honest encoding of "no
        # override here" is no key at all. That is also what keeps an ordinary
        # ALLOW record BYTE-IDENTICAL, which the pass that added this required:
        # only the record an actual override produces carries the field.
        #
        # `event="allow_once_used"` and `rule_id` already say THAT a human
        # overrode and WHICH rule; this is the only override fact that was being
        # dropped — WHO. It lived in the grant file and the stderr note and
        # reached the collector on no record. Bounded like `agent`, and inside
        # the hashed body so the name cannot be edited off after the fact.
        **({"granted_by": _clip(granted_by, _MAX_AGENT)}
           if granted_by is not None else {}),
        # ⚠ THE SESSION'S HUMAN TITLE, ONCE PER SESSION, CONTENT-BLIND. Clean
        # absence like `granted_by`: a body not given one is byte-identical to
        # before. Inside the hashed body like `agent` — a label that can be
        # edited afterwards labels nothing. Full-tier content on the wire,
        # because it embeds the first command (core/wire.py). core/title.py.
        **({"title": _clip(title, _MAX_TITLE)} if title is not None else {}),
        # ⚠ WHY A DENY OR AN ASK, AS FIELDS (docs/108): action, destination,
        # source_file, source_step, location, value_type, sentence. Clean
        # absence like `granted_by`: the hook passes them only for a DENY or an
        # ASK, and drops each it does not know, so an ALLOW record is
        # byte-identical to before. Never the value (`core/why.py`).
        **_why_fields(why),
        "action_hash": action_hash,
    }


_WHY_CAPS = {"action": _MAX_WHY_PHRASE, "value_type": _MAX_WHY_PHRASE,
             "destination": _MAX_PATH, "source_file": _MAX_PATH, "location": _MAX_PATH,
             "sentence": _MAX_REASON}


def _why_fields(why: dict | None) -> dict:
    """The why fields a record may carry, each bounded; `source_step` an int."""
    if not why:
        return {}
    out = {key: _clip(str(why[key]), cap) for key, cap in _WHY_CAPS.items()
           if why.get(key) is not None}
    step = why.get("source_step")
    if isinstance(step, int) and not isinstance(step, bool):
        out["source_step"] = step
    return out


_REOPEN_BOUND = 3
"""How many times `append` will follow the log's NAME to a new inode after
acquiring the lock, before refusing. One is the real case (a prune replaced
the file while we waited); the bound exists so a name that keeps moving fails
loudly instead of spinning."""


def append(session_id: str, body: dict, root: Path | None = None,
           path: Path | None = None) -> dict:
    """Chain one record onto the log and return it, hashes included.

    Locked for the whole read-tail/compute/append window, for the same reason
    open_session() is: two hooks running in parallel would otherwise read the
    same `prev` and write two records claiming the same predecessor, which is
    indistinguishable from tampering.

    Raises DuplicateRecord if an identical record is already in the tail window.
    """
    log_path = path or default_log_path(session_id, root)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        log_path.parent.chmod(0o700)
    except OSError:
        pass

    # The log names paths that were read and the commands that were run. 0600.
    fd = os.open(log_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        locking._acquire(fd, shared=False)

        # ⚠ THE NAME MAY HAVE MOVED WHILE WE WAITED FOR THE LOCK. flock binds to
        # the open file DESCRIPTION — this inode — but prune_shipped rewrites
        # the log with tmp+rename, which points the NAME at a NEW inode. A hook
        # that opened the old one and then blocked here would acquire an orphan
        # the moment prune released it, and its record would go into a file
        # nothing can find: lost, with the lock held, with no error. The same
        # check allow_once.consume() makes on the grant, for the same reason.
        # Bounded, and LOUD past the bound: a name that keeps moving is not a
        # race to win by spinning, and `_log()` reports the raise on stderr
        # rather than the record vanishing quietly.
        reopened = 0
        while True:
            try:
                if os.fstat(fd).st_ino == os.stat(log_path).st_ino:
                    break
            except OSError:
                # The name is gone altogether (not a replace — prune always
                # leaves a name). Appending to what we hold is the pre-existing
                # behaviour for a deleted log and is not changed here.
                break
            if reopened >= _REOPEN_BOUND:
                raise RuntimeError(
                    f"{log_path} was replaced under this append {reopened} "
                    f"times; refusing to write into a file with no name")
            reopened += 1
            locking._release(fd)
            os.close(fd)
            fd = os.open(log_path, os.O_RDWR | os.O_CREAT, 0o600)
            locking._acquire(fd, shared=False)

        # Inside the lock, so a racing second hook cannot pass this check and
        # then append anyway — which is precisely the race being defended
        # against. Skipped when seq is None: without a sequence number two
        # genuinely different actions can share an action_hash (an unrecognised
        # tool carries no command, no path and no url, so every one of them
        # fingerprints identically), and dropping a real record is worse than
        # keeping a duplicate.
        if body.get("seq") is not None:
            key = identity(body)
            for line in _tail_lines(fd):
                try:
                    if identity(json.loads(line)) == key:
                        raise DuplicateRecord(
                            f"record already logged for session "
                            f"{body.get('session_id')} seq {body.get('seq')} "
                            f"event {body.get('event')!r} — another hook is "
                            f"probably registered at a different settings scope")
                except json.JSONDecodeError:
                    continue          # a torn tail line is _last_hash's problem

        prev = _last_hash(fd)
        entry = dict(body)
        entry["prev"] = prev
        entry["hash"] = record_hash(prev, body)

        # ⚠ THE LINE, NOT THE BODY, IS WHAT MUST FIT THE WINDOW — prev, hash,
        # json.dumps' default separators and the newline included. Refused
        # before any write: a line the window cannot hold whole would make the
        # NEXT record, and every one after it, chain from UNREADABLE. For a
        # build_body() body this cannot fire — worst_record_bytes() is the
        # proof and a test holds it — so when it does, something else built
        # the body, or a bound was raised without the window.
        line = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
        if len(line) > _TAIL:
            raise RecordTooLarge(
                f"record for session {body.get('session_id')} seq "
                f"{body.get('seq')} event {body.get('event')!r} is "
                f"{len(line):,} bytes and the tail window _TAIL is {_TAIL:,} "
                f"— refused unwritten, so the chain stays intact")

        size = os.lseek(fd, 0, os.SEEK_END)
        if size:
            # A previous write that died mid-line would otherwise be glued to
            # this one, corrupting both.
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                os.lseek(fd, 0, os.SEEK_END)
                os.write(fd, b"\n")
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, line)
        os.fsync(fd)
        return entry
    finally:
        try:
            locking._release(fd)
        finally:
            os.close(fd)


def read_fd(fd: int) -> bytes:
    """Everything in the file behind `fd`, from the start.

    Exposed so a caller that already HOLDS the lock on this fd — prune, which
    must read, decide and rewrite under one exclusive lock — reads through it
    rather than opening the path again. A second `os.open` is a second file
    description, and a shared lock on it waits on the exclusive one the caller
    itself holds: a deadlock, not a race.
    """
    os.lseek(fd, 0, os.SEEK_SET)
    raw = b""
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        raw += chunk
    return raw


def parse_records(text: str) -> list[dict]:
    """Every parseable record in `text`, oldest first; an unparseable line
    becomes `{"_unparseable": line}` so verify can name it rather than skip it.

    ONE parser. `read_records` and prune must agree line-for-line about what a
    record is, because prune rewrites `lines[count:]` on the strength of having
    counted `records[:count]` — two parsers is one off-by-one waiting to delete
    the wrong record.
    """
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"_unparseable": line})
    return out


def read_records(path: Path) -> list[dict]:
    """Every parseable record, oldest first. For the viewer and for verify.

    Shared lock, so it cannot read a line that is still being written.
    """
    if not path.exists():
        return []
    fd = os.open(path, os.O_RDONLY)
    try:
        locking._acquire(fd, shared=True)
        raw = read_fd(fd)
    finally:
        try:
            locking._release(fd)
        finally:
            os.close(fd)
    return parse_records(raw.decode("utf-8", "replace"))


def verify_records(records: list, start: str | None = None
                   ) -> tuple[bool, int | None, str]:
    """Recompute every hash over records ALREADY READ. Returns
    (ok, first_bad_record_number, detail). `start` is the hash a pruned log
    legitimately begins from (`pruned_start`), or None for GENESIS.

    Factored out of `verify_chain` so prune can verify the bytes it read under
    its OWN exclusive lock. `verify_chain(path)` opens a second fd and takes a
    shared lock on it — called from inside prune's exclusive lock that waits on
    prune itself. One loop, used by both, so there is one notion of "intact".
    """
    if not records:
        return True, None, "empty log"

    prev = GENESIS
    pruned_note = ""
    if start:
        # ⚠ ONLY IF THE MANIFEST'S DECLARED START IS THE ONE THE LOG ACTUALLY
        # HAS. A manifest naming some other hash does not excuse the log it
        # sits beside; that mismatch is itself the break, and it is reported
        # as one below rather than papered over here.
        prev = start
        pruned_note = " (starts from a declared prune point, not GENESIS)"
    for i, rec in enumerate(records, start=1):
        if "_unparseable" in rec:
            return False, i, f"record {i} is not valid JSON"
        if rec.get("prev") != prev:
            return (False, i,
                    f"record {i} chains from {rec.get('prev')!r}, "
                    f"expected {prev!r}")
        body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
        expected = record_hash(prev, body)
        if rec.get("hash") != expected:
            return False, i, f"record {i} content does not match its hash"
        prev = rec["hash"]
    return True, None, f"{len(records)} records, chain intact{pruned_note}"


def verify_chain(path: Path) -> tuple[bool, int | None, str]:
    """Recompute every hash. Returns (ok, first_bad_record_number, detail).

    Record numbers are 1-based, so "record 4 is where it broke" reads the way a
    human would count lines. The loop lives in `verify_records`; this is the
    path-taking form for callers that hold no lock of their own.
    """
    return verify_records(read_records(path), pruned_start(path))
