#!/usr/bin/env python3
"""Produce a vendorable fixture from real decision logs. $0, no network.

    python3 tools/redact_logs.py --out logs/live-fixture
    python3 tools/redact_logs.py --out /tmp/x --check      # verify only

WHY A SCRIPT AND NOT A ONE-OFF `sed`. A fixture nobody can regenerate is a
fixture nobody can trust: when the next session is added, or a substitution turns
out to be wrong, the only way to know what the fixture contains is to be able to
rebuild it. The substitution list is data in git, reviewable in a diff.

WHAT MAKES THIS SAFE TO DO AT ALL — measured, not assumed:

  * Redaction is VERDICT-PRESERVING. One snapshot replayed twice, original vs
    redacted, gave an identical difference set and zero disagreeing verdicts.
    That is structural rather than lucky: every path rule tests a RELATIONSHIP
    (inside/outside the project, credential-shaped or not) and never the specific
    username, so a consistent global rename INCLUDING cwd leaves every
    relationship intact. `--check` re-proves it on every run.

  * The identifiers removed are already public. `/Users/<name>`, the git email
    and the author name appear in every commit of this repo, so the fixture adds
    no exposure that `git log` does not already carry.

  * No real credential is present. The `AKIA…EXAMPLE` string is AWS's own
    published documentation key and the rest are corpus fixtures. `gitleaks`
    should still be run over the output before the commit that adds it — a
    census written here is not a scanner written elsewhere.

WHAT THIS DOES NOT DO. It does not synthesise. Generated commands could only ever
contain shapes someone already thought of, and the nineteen shapes the corpus
cannot see were found precisely by nobody choosing them. The real commands stay;
only the people are renamed.

⚠ WHOLE SESSIONS ONLY. Dropping records within a session changes verdicts —
measured: removing the 193 records the differential never compares made one
difference vanish, because an uncompared WRITE still runs mark_sources and puts
taint into the session every later verdict depends on. The session is the unit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import audit_log                                            # noqa: E402

ROOT = Path(__file__).parent.parent

# The substitution list. Order matters only in that longer patterns come first;
# each is applied globally to the raw JSON line, so a value is renamed identically
# wherever it appears — in `command`, in `paths`, in `cwd`, in `reason`.
#
# ⚠ EVERY ENTRY MUST BE IDENTITY-ONLY. Renaming anything the POLICY reads —
# a credential path, a hostname, a git verb — would change verdicts and the
# fixture would then assert something the engine never decided. `--check` is what
# stops that being a matter of care.
# ⚠ AN IDENTIFIER THAT IS A COMMON WORD IS NOT AN IDENTIFIER, and substituting
# one CORRUPTS the artifact it was meant to clean. Two ways this fires:
#
#   * a real user whose home directory is `dev`, `user` or `ubuntu` — every
#     occurrence of that word in every command would be replaced;
#   * this repo's own test suite, which isolates `$HOME` to a temp directory, so
#     `Path.home().name` is literally `home` and the checker then reports the
#     word "home" as a leak in every file that mentions a home directory.
#
# Both were observed. The second is how it was found.
#
# ⚠ THE LAST ROW ARRIVES FROM THE GIT HISTORY, NOT FROM A HOME DIRECTORY.
# `tools/identity_census.py` reads every author and committer, and a commit made
# through the GitHub web UI is committed by `GitHub <noreply@github.com>` and a
# workflow commit by `github-actions[bot]`. Treating `GitHub` as an identity
# would flag every file in the tree that mentions GitHub — a checker that fires
# on the word "GitHub" is a checker somebody deletes.
_TOO_GENERIC = frozenset({
    "home", "user", "users", "root", "admin", "dev", "developer", "tmp", "temp",
    "runner", "build", "test", "tests", "local", "shared", "name", "ubuntu",
    "debian", "macos", "linux", "windows", "docker", "guest", "default",
    "github", "github-actions", "github-actions[bot]", "web-flow", "noreply",
    "actions", "unknown", "none", "null", "anonymous",
})


def _derived_identities() -> list:
    """This machine's owner, from `installer.detect.propose_identity()`.

    ⚠ THIS IS THE LIVE-LOG HALF, AND IT IS DELIBERATELY THE RUNNING USER ONLY.
    Redacting a log on a person's machine wants THEIR identity and nobody
    else's: substituting a name belonging to someone else silently rewrites a
    real command that happens to contain that word, and on a receiver's machine
    this repo's git history is a list of OUR developers — precisely the wrong
    list for THEIR log.

    ⚠ IT IS THEREFORE THE WRONG LIST FOR A RELEASE ARCHIVE, and using it there
    was a real regression: the archive check became machine-dependent, scanning
    for `runner` on a runner while the developer's username sat in the bytes.
    `tools/identity_census.py` is the archive half.

    ⚠ THESE USED TO BE FOUR HARDCODED STRINGS AND THAT WAS TWO BUGS AT ONCE.
    `tools/` is in `place.PAYLOAD`, so this file SHIPS — which meant the release
    archive carried a developer's username, email token and author name to
    every stranger who unpacked it. And it was broken for its actual purpose on
    their machine, because it redacted THIS developer's name and never theirs.
    A redaction tool whose identity list belongs to somebody else is worse than
    no tool: it produces a fixture that LOOKS redacted.

    ⚠ DERIVED FROM THE SAME PLACE THE INSTALLER ALREADY ASKS. `install.py`
    section 3 prints exactly these — the home directory name, `git config
    user.name`, `git config user.email`, the hostname — and it is the one moment
    a person is present to see them. One derivation, two readers.

    ⚠ AND THE EMAIL IS REDUCED TO ITS LOCAL PART, deliberately: the address also
    appears JSON-ESCAPED inside commands that themselves contained a regex, and
    a pattern written for a literal dot missed every one of those. Substituting
    the identifying TOKEN is escaping-proof; what is left identifies nobody.
    """
    try:
        from installer.detect import propose_identity
        found = propose_identity().get("identifiers") or []
    except Exception:                                            # noqa: BLE001
        # ⚠ AN EMPTY LIST IS NOT A QUIET PASS. `--check` runs over the OUTPUT
        # and refuses on anything still matching, so a machine where detection
        # failed produces a REFUSAL rather than an unredacted fixture.
        return []
    out = []
    for value in found:
        out.append(value)
        if "@" in value:
            local = value.split("@", 1)[0]
            if local:
                out.append(local)
    # ⚠ LONGEST FIRST, so a longer identifier is replaced before a shorter one
    # that overlaps it — an email's local part sits inside the address.
    #
    # ⚠ AND THE TIE-BREAK IS THE VALUE, NOT SET ORDER. `sorted(set, key=len)`
    # leaves equal-length entries in hash order, which varies per process. That
    # made the ORDER unstable, and anything naming a pattern by its position —
    # a failure message, a test id — named a different identifier on each run.
    seen = {v for v in out if len(v) >= 4 and v.lower() not in _TOO_GENERIC}
    return sorted(seen, key=lambda v: (-len(v), v))


IDENTITY_PLACEHOLDER = "dev"
"""What every identifier becomes. ⚠ NAMED, BECAUSE THE VENDORED FIXTURE IS
WRITTEN IN IT. `logs/live-fixture` holds `/Users/dev/…` in every path, so a
replay of it has to be given a cwd in the same spelling — and computing that cwd
by running THIS machine's redaction over one developer's real path made the
standing replay gate machine-dependent. It is fixture data, not a live
derivation."""


def _identity_substitutions() -> list:
    """(pattern, replacement) for every derived identifier."""
    return [(re.escape(value), IDENTITY_PLACEHOLDER)
            for value in _derived_identities()]


# ⚠ STRUCTURAL ONLY — NOT ONE PERSON'S NAME. Everything identity-shaped is
# derived above; what is left here is a SHAPE that is the same on every machine.
# `claude-<uid>` is the harness's per-uid directory, and the uid is matched
# rather than assumed for the same reason `_SCRATCH_TEMPLATES` substitutes it.
SUBSTITUTIONS: list[tuple[str, str]] = [
    (r"claude-\d+", "claude-000"),
]

# Anything matching these in the OUTPUT is a redaction failure, not a warning.
#
# ⚠ THIS LIST IS THE ONLY THING STANDING BETWEEN A REAL SESSION AND A PUBLIC
# REPO, AND IT IS A CLOSED LIST. It cannot catch a shape nobody added to it. The
# four identity entries below are each a fact about THIS machine; anything the
# developer types that identifies them by some other name — a client, a private
# host, a second account — is invisible here. Add to it rather than assume.
LEAK_PATTERNS: list[tuple[str, str]] = [
    # ⚠ THE IDENTITY ENTRIES ARE APPENDED AT RUNTIME by `leak_patterns()` — see
    # `_derived_identities`. They used to be five literal strings naming this
    # developer, in a file that SHIPS in the release archive.
    # ⚠ THE PLACEHOLDER MUST NOT MATCH THE DETECTOR. `claude-\d+` flagged its
    # own replacement `claude-000`, so a correctly redacted file reported a
    # leak — a checker that fails on its own output is a checker nobody can use.
    ("harness uid path", r"claude-(?!000\b)\d+"),
    # BARE, not `/Users/`-anchored — see the substitution note above. This is the
    # detector half of the 115-occurrence miss, and anchoring it on a path
    # separator is what let the flattened form through.
    # Neither of these was ever checked. Both appear in real sessions the moment
    # the developer runs `hostname`, `scutil` or `id -F` — which an audit of this
    # very file did, and which is how they came to be listed.
    # The CLOSING dashes are required. Without them this matched prose ABOUT
    # scanning for keys — a census table row reading `-----BEGIN PRIVATE KEY  0`
    # tripped it, which is a detector crying wolf at its own report.
    ("private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("github token", r"\bghp_[A-Za-z0-9]{20,}"),
    ("stripe-style key", r"\bsk_live_[A-Za-z0-9]{10,}"),
    ("slack token", r"\bxox[bpsa]-[A-Za-z0-9\-]{10,}"),
]


def substitutions() -> list:
    """`SUBSTITUTIONS` plus this machine's derived identifiers.

    ⚠ ONE DERIVATION, TWO READERS — and `leak_patterns()` is the other. They
    drifted once, with the substituter fixed to match a bare username while the
    checker stayed anchored on `/Users/`, so both halves looked for a shape that
    was no longer there while the name sat in plain text between them.
    """
    return list(SUBSTITUTIONS) + _identity_substitutions()


def redact(text: str) -> str:
    for pattern, replacement in substitutions():
        text = re.sub(pattern, replacement, text)
    return text


def redacted_cwd(cwd: str) -> str:
    """The cwd a replay of the fixture must be given.

    The fixture's paths are renamed, so replaying it against the REAL cwd would
    put every action outside the project and manufacture `write_outside` denials
    that never happened. This is the one place the rename leaks out of the file.
    """
    return redact(cwd)


def source_logs(roots: list[Path]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        if root.is_dir():
            found += sorted(root.rglob("*.jsonl"))
    return found


def leaks_in(text: str) -> list[str]:
    return [name for name, pattern in leak_patterns() if re.search(pattern, text)]


DEFAULT_TRANSCRIPTS = Path("~/.claude/projects").expanduser()


def transcript_index(roots: list[Path]) -> dict[str, str]:
    """digest -> command, over every tool call in every transcript found.

    The agent's own transcript records the command it asked to run, so it holds
    the text the log had to clip. It is a BUILD-TIME source only: the recovered
    command is written into the vendored sidecar, so the fixture stays
    self-contained and replays identically on a machine with no transcripts.
    """
    index: dict[str, str] = {}

    def walk(node) -> None:
        if isinstance(node, dict):
            if node.get("type") == "tool_use":
                command = (node.get("input") or {}).get("command")
                if isinstance(command, str):
                    index[hashlib.sha256(command.encode("utf-8")).hexdigest()] = command
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.jsonl")):
            try:
                lines = path.read_text(errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                if not line.strip():
                    continue
                try:
                    walk(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return index


def recover_by_digest(digest: str | None, index: dict[str, str]) -> str | None:
    """The attested command, or None. **DIGEST MATCH OR NOTHING.**

    ⚠ THIS IS THE HARD RULE, AND IT IS WHY RECOVERY IS SAFE AT ALL.
    `command_sha256` lives inside the hashed body, so the chain already attests
    it. A candidate that hashes to it IS the command that was judged — not a
    guess, not a near match, not "the only command at that timestamp". Anything
    weaker would put unproven text into a fixture that later gets quoted as
    evidence of what the engine decided.

    The lookup is keyed by digest, so re-hashing the hit looks redundant. It is
    not: it makes the rule a property of THIS function rather than of however the
    index was built, so a future index keyed on anything else still cannot
    smuggle text past it. 14 records in the vendored logs carry no digest at all
    and are therefore unrecoverable, permanently and correctly.
    """
    if not digest:
        return None
    candidate = index.get(digest)
    if candidate is None:
        return None
    if hashlib.sha256(candidate.encode("utf-8")).hexdigest() != digest:
        return None
    return candidate


def substitutions_digest() -> str:
    """A hash of the substitution list, so the manifest names the exact rules."""
    material = "\n".join(f"{p}\t{r}" for p, r in substitutions())
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _rehash_record(record: dict, log: Path, out: Path, stats: Counter,
                    transcripts: dict[str, str] | None = None) -> dict:
    """Re-address one record onto its redacted bytes. Provenance kept, inert.

    THE THREE CASES, and the third is the one with a trap in it:

      whole            digest recomputed over the redacted command.
      clipped, sidecar the FULL command is redacted, re-hashed, and rewritten
                       under its new digest, so addressing works again.
      clipped, none    `command_sha256` is set to null.

    ⚠ THE TRAP, AND IT WAS LIVE FOR ONE RUN. For the third case it is tempting to
    hash the redacted CLIPPED text so that every record has a digest. That makes
    `stored_command_is_whole`'s first rung — a matching digest PROVES wholeness —
    return True for a command missing most of itself, turning honestly
    unjudgeable records into confidently wrong ones.

    Reading `command_clipped` directly does exactly that by accident. The nine
    records that predate the flag have `command_clipped: None`, which is falsy,
    so they took the whole branch and were about to be stamped with a digest over
    2048 bytes of a much longer command. **A digest is a CLAIM, and this function
    may only write one it can justify** — hence `stored_command_is_whole`, which
    consults the marker and the length too, and `None` (cannot say) writing no
    digest at all rather than manufacturing a proof of wholeness.
    """
    command = record.get("command")
    if command is None:
        return record
    original = record.get("command_sha256")
    if original:
        record[audit_log.ORIGINAL_DIGEST_FIELD] = original

    whole = audit_log.stored_command_is_whole(record)
    if whole is None:
        # No evidence either way. Leave it unaddressable rather than assert.
        record["command_sha256"] = None
        stats["wholeness_unknown"] += 1
        return record
    if whole:
        record["command_sha256"] = hashlib.sha256(command.encode("utf-8")).hexdigest()
        record["command_len"] = len(command)
        stats["whole_rehashed"] += 1
        return record

    payload = None
    if original:
        source = audit_log.sidecar_dir(log) / original
        if source.is_file():
            payload = redact(source.read_bytes().decode("utf-8", errors="replace"))
    if payload is None:
        # SECOND SOURCE: the agent's transcript. Only ever consulted for a record
        # the sidecar cannot serve, and only ever accepted on an exact digest —
        # see `recover_by_digest`. Records predating `command_sha256` have
        # nothing to match against and stay unrecovered, which is correct.
        recovered = recover_by_digest(original, transcripts or {})
        if recovered is not None:
            payload = redact(recovered)
            stats["recovered_from_transcript"] += 1
    if payload is None:
        record["command_sha256"] = None
        stats["clipped_without_sidecar"] += 1
        return record

    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    target = audit_log.sidecar_dir(out / log.name)
    target.mkdir(parents=True, exist_ok=True)
    (target / digest).write_text(payload)
    record["command_sha256"] = digest
    record["command_len"] = len(payload)
    record["command"] = payload[:audit_log._MAX_COMMAND] + audit_log.CLIP_MARKER
    stats["sidecars_rekeyed"] += 1
    return record


def build(roots: list[Path], out: Path,
           transcripts: dict[str, str] | None = None) -> dict:
    """Redact, re-address onto the redacted bytes, re-chain, declare.

    THE CHAIN IS RECOMPUTED, which is the whole reason the manifest exists.
    Redaction rewrites bytes the original chain attests, so the derived log
    cannot verify against it — and until this landed the checker reported that as
    BROKEN, a false alarm on the one signal that is supposed to mean tampering.
    The recomputed chain attests exactly "unmodified since derived", and
    `REDACTION_MANIFEST` is what stops a reader mistaking it for more.
    """
    out.mkdir(parents=True, exist_ok=True)
    stats: Counter = Counter()
    sessions: list[str] = []
    for log in source_logs(roots):
        lines = [line for line in log.read_text(errors="replace").splitlines()
                 if line.strip()]
        if not lines:
            continue
        rebuilt: list[str] = []
        prev = audit_log.GENESIS
        for line in lines:
            try:
                record = json.loads(redact(line))
            except json.JSONDecodeError:
                rebuilt.append(redact(line))       # kept verbatim; chain will flag it
                stats["unparseable"] += 1
                continue
            record = _rehash_record(record, log, out, stats, transcripts)
            body = {k: v for k, v in record.items() if k not in ("prev", "hash")}
            record = dict(body)
            record["prev"] = prev
            record["hash"] = audit_log.record_hash(prev, body)
            prev = record["hash"]
            rebuilt.append(json.dumps(record, sort_keys=True,
                                      separators=(",", ":"), ensure_ascii=True))
            sid = record.get("session_id")
            if sid and sid not in sessions:
                sessions.append(sid)
        # Whole sessions, one file each, name preserved so the differential's
        # session grouping and the archive/live de-duplication both still work.
        (out / log.name).write_text("\n".join(rebuilt) + "\n")
        stats["files"] += 1
        stats["records"] += len(lines)

    manifest = {
        "derived": True,
        "tool": "tools/redact_logs.py",
        "substitutions_sha256": substitutions_digest(),
        "substitution_count": len(substitutions()),
        "sessions": sessions,
        "files": stats["files"],
        "records": stats["records"],
        "whole_rehashed": stats["whole_rehashed"],
        "sidecars_rekeyed": stats["sidecars_rekeyed"],
        "recovered_from_transcript": stats["recovered_from_transcript"],
        "clipped_without_sidecar": stats["clipped_without_sidecar"],
        "wholeness_unknown": stats["wholeness_unknown"],
        "attests": ("The chain over these files is recomputed and attests only "
                    "that they are unmodified SINCE REDACTION. It attests "
                    "nothing about the recorded session. Each record carries "
                    "original_sha256 for provenance; it is inert here and can "
                    "only be checked against the real log."),
    }
    (out / audit_log.REDACTION_MANIFEST).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return dict(stats) | {"manifest": manifest}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, action="append", default=None,
                     help="log directory to read; repeatable")
    ap.add_argument("--out", type=Path, default=ROOT / "logs" / "live-fixture")
    ap.add_argument("--transcripts", type=Path, action="append", default=None,
                     help="transcript directory to recover clipped commands "
                          "from; repeatable. Default ~/.claude/projects")
    ap.add_argument("--no-transcripts", action="store_true",
                     help="do not consult transcripts at all")
    ap.add_argument("--check", action="store_true",
                     help="only verify the existing fixture, write nothing")
    args = ap.parse_args(argv)

    roots = args.root or [Path("~/.sting/dogfood").expanduser(),
                          Path("~/sting/sting-logs-archive").expanduser()]

    if not args.check:
        index: dict[str, str] = {}
        if not args.no_transcripts:
            index = transcript_index(args.transcripts or [DEFAULT_TRANSCRIPTS])
        stats = build(roots, args.out, index)
        print(f"wrote {stats['files']} session file(s), {stats['records']} records "
              f"to {args.out}")

    if not args.out.is_dir():
        print(f"nothing at {args.out}", file=sys.stderr)
        return 2

    # ⚠ EVERY FILE WRITTEN, not every file matching *.jsonl.
    #
    # This globbed `*.jsonl` alone, which was correct until option E started
    # vendoring sidecar payloads — 73 files, 290 KB of real command text, holding
    # exactly the long commands most likely to contain a path or an address, and
    # NONE of it was being checked. It happened to be clean; that is luck, not a
    # property. A leak check that does not cover everything the tool writes is a
    # check that reports on the wrong thing.
    checked = sorted(p for p in args.out.rglob("*") if p.is_file())
    body = "\n".join(p.read_text(errors="replace") for p in checked)
    found = leaks_in(body)
    if found:
        print(f"REDACTION FAILED — still present: {', '.join(found)}", file=sys.stderr)
        return 1
    print(f"no identifier from LEAK_PATTERNS survives in {len(checked)} file(s) "
          f"under {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


def leak_patterns() -> list:
    """`LEAK_PATTERNS` plus this machine's derived identifiers.

    ⚠ THE DETECTOR AND THE SUBSTITUTER MUST READ THE SAME LIST. They drifted
    once — the substituter was fixed to match the bare username and the checker
    was left anchored on `/Users/`, so both halves were looking for a shape that
    was no longer there while the name sat in plain text between them. One
    derivation, consumed twice.
    """
    # ⚠ NAMED BY WHERE IT CAME FROM, NOT BY POSITION AND NOT BY VALUE. A
    # position is unstable (see `_derived_identities`) and prints a different
    # identifier each run; the VALUE would put the identity into every failure
    # message and every CI log, which is the thing being prevented. The SOURCE —
    # "git config user.email", "the home directory name" — is stable, says what
    # to go and look at, and names nobody.
    try:
        from installer.detect import propose_identity
        sources = propose_identity().get("sources") or {}
    except Exception:                                            # noqa: BLE001
        sources = {}
    named = []
    for value in _derived_identities():
        where = sources.get(value)
        if where is None and "@" in value:
            where = sources.get(value)
        if where is None:
            # a local part split out of an address: name its parent
            parent = next((k for k in sources if k.startswith(value + "@")), "")
            where = sources.get(parent, "derived from an identifier")
        named.append((f"identity from {where}", re.escape(value)))
    return list(LEAK_PATTERNS) + named
