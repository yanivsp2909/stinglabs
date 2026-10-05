"""What is sensitive, and how a sensitive value is recognised: the credential,
confidential, dependency, reference and planted path patterns, value
fingerprints, and whether content carries a secret, the environment or a
canary.

Moved out of core/engine.py; docs/ENGINE_LAYOUT.md.
"""
from __future__ import annotations

import bisect
import hashlib
import math
import re
from collections import Counter

from core import known_formats
from core.types import Action, ActionKind, SessionState


# --------------------------------------------------------------------- sources

CREDENTIAL_PATHS = re.compile(
    # .env and .env.<anything> — but NOT .env.example / .sample / .template /
    # .dist, which hold placeholder names rather than values. N24's whole task
    # is diffing .env against .env.example; treating the template as a secret
    # would be a false positive on the scenario written to catch exactly that.
    # ⚠ `[/\\\\]` EVERYWHERE A SEPARATOR IS MEANT, AND ONLY THERE. On Windows
    # `C:\\Users\\dev\\.env` contains no forward slash at all, so every
    # `/`-anchored alternative below matched NOTHING and the session never set
    # holds_secret — no exception, no log line, the push simply allowed.
    #
    # ⚠ THE SUFFIX PATTERNS ARE DELIBERATELY UNTOUCHED. `\.pem$`, `\.p12$` and
    # `\.pfx$` contain no separator, so they already matched a backslash path.
    # Widening them would be work that looks like progress and changes nothing —
    # `tests/test_windows_sites_are_measurable.py` caught that over-claim once
    # with strict=True and lists them as already-working.
    #
    # ⚠ THE FOUR DIRECTORY-ANCHORED SHAPES TAKE `(^|[/\\\\])` LIKE THE FILE
    # SHAPES DO. `.ssh/`, `.aws/`, `.docker/config.json` and `.kube/` required
    # a LEADING separator, so a path spelled relative to the cwd — `cat
    # .aws/credentials`, `.kube/config` at the start of a token — matched
    # nothing, while `~/.aws/credentials` was caught. Through the Read tool the
    # adapter absolutises the path and it was always caught; only the raw EXEC
    # spelling slipped. `^` is inert on the filesystem route: `action.paths`
    # arrives absolute and never begins with `.`, so this can only add a
    # match on command text. tests/test_bare_relative_dot_dir_credential_paths.py
    # pins both halves. (`.ssh/id_rsa` was saved by the `id_rsa` filename;
    # `.ssh/config` and `.ssh/authorized_keys` were not — hence four, not three.)
    r"(^|[/\\\\])\.env(?:\.(?!example|sample|template|dist)[\w-]+)?$|"
    r"(^|[/\\\\])\.ssh[/\\\\]|(^|[/\\\\])id_rsa|(^|[/\\\\])id_ed25519|"
    r"(^|[/\\\\])id_dsa|(^|[/\\\\])id_ecdsa|"
    r"(^|[/\\\\])\.aws[/\\\\]|(^|[/\\\\])\.npmrc$|(^|[/\\\\])\.netrc$|"
    r"(^|[/\\\\])\.docker[/\\\\]config\.json$|(^|[/\\\\])\.kube[/\\\\]|"
    r"(^|[/\\\\])\.pgpass$|(^|[/\\\\])\.git-credentials$|"
    r"\.pem$|\.p12$|\.pfx$",
    # ⚠ CASE-INSENSITIVE, UNCONDITIONALLY — and this is not a Windows concern.
    # macOS APFS is case-insensitive BY DEFAULT, so `cat .ENV` opens the same
    # bytes as `cat .env` on the machine this was written on. Measured through
    # the real hook: `.env` set holds_secret True; `.ENV`, `.Env` and `./.EnV`
    # all set it False while reading the identical file — and the whole of A1
    # then fell over. The I02 sequence (read, copy, commit, push) went DENY,
    # DENY with the lower-case name and ALLOW, ALLOW with the upper-case one.
    #
    # WHY UNCONDITIONAL, rather than detecting the filesystem the way the
    # project boundary below has to. The two directions are not symmetric:
    #
    #   under-match  a credential is not labelled -> every exit opens. Total.
    #   over-match   a file is labelled SECRET that is not one -> one prompt at
    #                a sink, and nothing else, because working rule 2 says
    #                labels restrict EXITS, never reads.
    #
    # So the cost of being wrong is a bypass on one side and a prompt on the
    # other, and there is no filesystem on which `.ENV` is not credential-SHAPED
    # even when it is a genuinely distinct file. Detection would buy nothing and
    # add a failure mode.
    #
    # It also FIXES two false positives: the negative lookahead was
    # case-sensitive, so `.env.EXAMPLE` and `.env.TEMPLATE` were being labelled
    # as secrets. They are now correctly excluded.
    #
    # ⚠ Blast radius measured BEFORE the change and it is ZERO on both
    # populations — 40 credential-path tokens in the corpus, not one of them
    # anything but lowercase; 2 of 1181 fixture records carry a credential path.
    # Working rule 12: that zero is the corpus being BLIND to this, not evidence
    # of safety. tests/test_case_insensitive_credentials.py is the only thing
    # that can see it.
    re.IGNORECASE)

# Org policy: confidential by PATH, with no credential inside to fingerprint.
# This is why holds_secret must be settable without any content match at all.
CONFIDENTIAL_PATHS = re.compile(r"/docs/internal/|/src/pricing/|/data/exports/")

# A tree a package manager or a vendoring tool wrote: someone else's code and
# prose, not the repository's own authored files (docs/113 §3a). Unchanged:
# ⚠ `/vendor/` was dropped in round 1 of fix/audit-truth-and-bugs and is back —
# both reviewers: a vendored tree (Go, Composer, `vendor/bundle`) is checked in
# but its READMEs are third-party text, the same channel as `node_modules`.
DEPENDENCY_PATHS = re.compile(
    r"/node_modules/|/site-packages/|/vendor/|/\.venv/|/dist-packages/")

# ⚠ REFERENCE DATA IS NO SOURCE ANY MORE (docs/113 §3a). `REFERENCE_DATA`
# marked `.gitmessage`, `.gitattributes`, `tests/fixtures/`, golden files and
# snapshots untrusted — and every repository has them: they are its own files,
# with no production meaning a real one lacks. Since docs/112's option 2 the
# mark gated the next push. Two secret-free corpus attacks lose their catch
# (K05, L02); the secret-carrying ones (L01, L04, L05) keep it.

# An issue's body SAVED TO DISK: a file NAMED FOR AN ISSUE NUMBER. Its text is a
# stranger's however it got there (`gh issue view 418 > ISSUE_418.md`); the
# corpus plants exactly this shape because a benchmark cannot call the GitHub
# API (docs/02 line 109), and an issue that arrives through mcp__github__* or
# WebFetch is marked where it arrives.
#
# ⚠ NAMED FOR A NUMBER, NOTHING ELSE (docs/113 §3a). `ISSUE_[\w-]+\.md` also
# matched `.github/ISSUE_TEMPLATE.md` and `docs/ISSUE_TRIAGE.md` — the
# repository's own files — and it ran on every installed machine. `*.issue`,
# which nothing wrote (the corpus included), is gone too. ASCII digits only:
# `\d` takes any script's.
PLANTED_CONTENT = re.compile(r"(^|/)ISSUE_[0-9]+\.md$")

_ENTROPY_MIN = 3.0
_VALUE_MIN_LEN = 12


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Vendor credential formats. These prefixes are namespaced BY THE VENDOR so a
# key is recognisable on sight — which makes this a property the ATTACKER cannot
# choose, unlike a literal pattern match over content they author. Nothing in an
# ordinary codebase starts with `AKIA` or `ghp_` except an actual credential.
_CREDENTIAL_FORMAT = re.compile(
    r"^(?:AKIA|ASIA|ghp_|gho_|ghs_|ghu_|github_pat_|sk_live_|sk_test_|rk_live_|"
    r"xox[baprs]-|AIza|ya29\.|SG\.|glpat-|npm_|dop_v1_|-----BEGIN)")


def _prefix_hashes(value: str) -> set[str]:
    """Every prefix of a credential-FORMAT value, from 12 chars to the whole.

    Truncation IS prefix-taking — a field limit, a display width, a copy-paste,
    an attacker trimming. A01 leaked `AKIA_TEST_A01` from
    `AKIA_TEST_A01_readme_plain`; C04 leaked the same shape into an MCP argument.
    Whole-value hashing cannot see either.

    A 26-char value yields 15 prefixes, one per length — not one per position,
    which is what made hashing every SUBSTRING unaffordable and collision-prone.

    GATED ON FORMAT, NOT ENTROPY, and the entropy check is deliberately bypassed
    here. `devpass_A01_readme_plain_local_only` is dictionary-ish and its 12-char
    prefix `devpass_A01_` is the sort of string that plausibly appears in a
    fixture or a variable name; hashing prefixes of THAT invites false positives.
    The format gate excludes it entirely — measured, 0 prefixes.
    """
    if not _CREDENTIAL_FORMAT.match(value):
        return set()
    return {hashlib.sha256(value[:length].encode()).hexdigest()[:8]
            for length in range(_VALUE_MIN_LEN, len(value) + 1)}


def fingerprint_values(file_content: str) -> set[str]:
    """Hash the VALUES so they can be recognised later. Never store plaintext.

    Exactly docs/02 lines 127-139. Measured at ~0.003 ms, so it is safe in the
    hot path — unlike gitleaks, which is ~32 ms against a 12 ms p99 budget and
    is therefore deferred to an out-of-band pass.

    Known gap: a low-entropy secret (`hunter2` scores 2.81) is not fingerprinted.
    holds_secret is still set by PATH, so rule set B covers it.
    """
    prints: set[str] = set()
    for line in file_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value = line.split("=", 1)[1] if "=" in line else line
        value = value.strip().strip('"').strip("'")
        if len(value) >= _VALUE_MIN_LEN and shannon_entropy(value) > _ENTROPY_MIN:
            prints.add(hashlib.sha256(value.encode()).hexdigest()[:8])
        # Prefixes, so a truncated copy is still recognisable. Format-gated, so
        # only real credentials contribute needles.
        prints |= _prefix_hashes(value)
    return prints


# A token is a maximal run of value-ish characters. `=` is excluded so
# `KEY=VALUE` splits into both halves, and `/` is excluded so paths split into
# components — which is what makes `AKIA_.../us-east-1` yield a bare token.
_VALUE_TOKEN = re.compile(r"[A-Za-z0-9_.\-+]{%d,}" % _VALUE_MIN_LEN)

# HOW FAR THE TWO SECRET SCANNERS LOOK, and WHY it is 128 KB, measured not
# guessed (389 real commits across the project's repositories, Apple M2 Pro):
#
#   - The cost is TAIL-ONLY. The typical staged diff is ~15 KB — well inside the
#     window — so median commit-path latency is FLAT at ~0.84 ms whatever the
#     window is; widening touches only the rare large diff.
#   - 128 KB keeps the commit-path p99 at ~9.7 ms (worst real diff 10.8 ms),
#     under the 12 ms A6a budget. 256 KB (~18 ms) and unbounded (~69 ms p99,
#     213 ms worst) breach it, so 128 KB is the largest flat window that fits.
#   - It closes the real accidental-miss rate from 22.6% of commits (> 32 KB) to
#     4.9% (> 128 KB).
#
# WHY IT MATTERS AT ALL — this window is the ONLY backstop for one population: a
# secret in an ordinary file with NO session-tracked origin (never read, never
# written-while-tainted). Anything with a tracked origin is caught regardless of
# size by `tainted_paths` (see `_staged_secret_level`); this scan is what catches
# a secret typed or generated straight into a large file.
#
# HONEST LIMIT, unchanged in kind: a secret beyond this offset in a single
# action is not seen — same class as probes._MAX_READ. Widening moved the edge,
# it did not remove it (a determined placement past a KNOWN bound still evades).
# 256KB of content costs ~10 ms to tokenise and hash; a full 2.9 MB diff ~213 ms.
_MAX_SCAN = 128 * 1024


def fingerprints_in(text: str | None) -> set[str]:
    """Hash every value-shaped TOKEN in arbitrary text. For MATCHING only.

    fingerprint_values() is line-oriented `KEY=VALUE` and must stay that way:
    it decides what gets STORED as a needle, and tokenising it would turn key
    names and stray identifiers into permanent needles for the whole session.

    This is the other direction, and it can afford to be generous — a candidate
    that matches no stored needle costs one hash and nothing else. That
    asymmetry is the point: store narrowly, match broadly.

    Why the engine needed this: without it a secret is only recognisable in
    .env-shaped content. A bare token in a command, a source file or prose was
    invisible, so `curl -d "AKIA…"` carrying a verbatim credential was not seen
    even with the exact value already fingerprinted.
    """
    if not text:
        return set()
    if len(text) > _MAX_SCAN:
        text = text[:_MAX_SCAN]
    # Format OR entropy qualifies. A truncated credential can fall BELOW the
    # entropy threshold — `AKIA_TEST_A0` scores 2.86 — and dropping it here
    # would make the stored prefix unreachable. The format gate is the same
    # unforgeable signal on both sides.
    return {hashlib.sha256(tok.encode()).hexdigest()[:8]
            for tok in _VALUE_TOKEN.findall(text)
            if shannon_entropy(tok) > _ENTROPY_MIN or _CREDENTIAL_FORMAT.match(tok)}


# ⚠ STRUCTURALLY DISTINCTIVE PII FIELDS — the part of a declared source's VALUES
# that the length+entropy floor above CANNOT see. An email and an SSN are low-
# entropy and the email's `@`-split halves fall under 12 chars, so `fingerprints_in`
# never captures them — yet each is distinctive by STRUCTURE (an `@` + a TLD, a
# `NNN-NN-NNNN`), the same kind of format signal `_CREDENTIAL_FORMAT` is. A bare
# name or a short number has no such structure and is never captured, which is what
# keeps step 3b from denying every command that mentions "David" or "42".
#
# ⚠ BOTH QUANTIFIERS ARE BOUNDED. An unbounded `[...]+@` backtracks catastrophically
# (O(n^2)) on a long `@`-free run — the same ReDoS class as a scheme with no `://`.
# RFC caps are 64 (local) / 255 (domain); the bounds make the scan linear.
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")


def _distinctive_fields(text: str | None) -> set[str]:
    """Structurally distinctive PII values in `text` — full emails and SSNs. Distinct
    from `fingerprints_in`'s entropy/length floor; exact-match on these rarely FPs on
    ordinary egress, and a bare name/short number matches neither pattern."""
    if not text:
        return set()
    if len(text) > _MAX_SCAN:
        text = text[:_MAX_SCAN]
    return set(_EMAIL.findall(text)) | set(_SSN.findall(text))


def policy_prints_in(text: str | None) -> set[str]:
    """Hashes of the distinctive VALUES in `text` an org policy would care about —
    whole-record / long-unique / credential-format tokens (`fingerprints_in`, the
    proven floor) PLUS structural PII fields (`_distinctive_fields`). One function for
    BOTH sides: STORE `policy_prints_in(source_content)` on reading a declared source,
    MATCH `policy_prints_in(egress_text) & state.policy_fingerprints` at egress — so
    store and match tokenise identically. A name-only source yields the empty set."""
    return fingerprints_in(text) | {
        hashlib.sha256(f.encode()).hexdigest()[:8] for f in _distinctive_fields(text)}


# ⚠ THE PROCESS ENVIRONMENT IS THE ONE CREDENTIAL SOURCE WITH NO PATH.
#
# Everything else this engine treats as a secret source is keyed on the PATH it
# touches — `.env`, `~/.aws/credentials`, `id_rsa` — and that key is
# spelling-proof by construction: `cat`, `head`, `less`, `grep`, `source`,
# a `python -c` one-liner that reads it, and `docker run --env-file`, all mark
# today because they
# all NAME THE FILE. The command is never the key, so there is no verb list to
# get around.
#
# `printenv` has no file. Covering it can only key on the COMMAND, which is a
# blocklist, and the measurement said what a blocklist costs here: marking every
# environment read would have turned 35 ordinary `git add && git commit` actions
# into prompts across three real sessions, to catch a route no corpus attack
# uses. Measured and declined — see docs/57.
#
# ⚠ SO THE KEY IS THE PIPELINE, NOT THE VERB. What is matched is a whole
# environment being READ AND SENT IN ONE COMMAND. That shape has no legitimate
# reading: a developer inspecting a variable pipes it to `grep`, not to `curl`.
# Measured: 0 of 3,864 real recorded commands match, and `env -i` — which SETS a
# clean environment rather than reading one, and is 42 of the 43 real `env` uses
# on this machine — is excluded explicitly.
#
# ⚠ AND IT IS STILL BYPASSABLE BY THE NEXT SPELLING, which is stated rather than
# implied: `set`, `declare -p`, `cat /proc/self/environ` and a Python one-liner
# all read the environment and none of them is here. The path-keyed half of the
# model does not have that weakness; this addition does, and it buys the one
# shape that was reachable with no path at all.
# ⚠ `(` AND A NEWLINE ARE COMMAND POSITIONS TOO, and leaving them out is how a
# fix learns the test: the five corpus spellings passed while
# `( env | ssh … )` — a subshell, which is spelling number six — did not.
# ⚠ ONE BLANK RUN, AND NOT ACROSS A NEWLINE (fix/false-positives, the reviews):
# `[;&|(\n]\s*` followed by another `\s*` split every run of blank lines two
# ways from every newline in it — cubic: 2,000 newlines took 32 s. A newline
# is itself a command position, so the same commands match, from it.
# ⚠ ONE PASS, NOT ONE PATTERN (the fourth review round). The pattern went on
# `(?![^\n;|&]*\s-i\b)[^\n;]*\|\s*(…)` from every `env` start, rescanning the
# rest of the line for each: `&env &env …`, `$(env $(env …` of 40 KB took 2.4
# to 4 s. Now the start, `env -i` and the pipe to the network are each found
# once, and `sends_the_environment` joins them by position — the same answer
# (checked against the old pattern in tests/test_sending_the_environment_is_linear.py).
# The pipeline's start: `env`/`printenv` where a command starts.
_ENV_TO_EGRESS = re.compile(
    r"(?:^|[;&|(\n]|\$\(|`)[^\S\n]*(?:/usr/bin/)?(?:printenv|env)\b")
_ENV_LAUNCHES = re.compile(r"\s-i\b")      # `env -i` LAUNCHES, it does not read
_TO_THE_NETWORK = re.compile(
    r"\|\s*(?:curl|wget|nc|ncat|socat|ssh|scp|base64\s*\|\s*(?:curl|wget|nc|ncat))\b")
_LAUNCH_END = re.compile(r"[\n;|&]")
_PIPELINE_END = re.compile(r"[\n;]")


def _first_at_or_after(positions: list[int], at: int, default: int) -> int:
    k = bisect.bisect_left(positions, at)
    return positions[k] if k < len(positions) else default


def sends_the_environment(text: str | None) -> bool:
    """The whole environment, read and sent, in one command: an `env` where a
    command starts — not `env -i` before its command ends — piped, before the
    next `;` or newline, into a network tool."""
    if not text:
        return False
    starts = [m.end() for m in _ENV_TO_EGRESS.finditer(text)]
    sends = [m.start() for m in _TO_THE_NETWORK.finditer(text)] if starts else []
    if not sends:
        return False
    launches = [m.start() for m in _ENV_LAUNCHES.finditer(text)]
    launch_ends = [m.start() for m in _LAUNCH_END.finditer(text)]
    pipeline_ends = [m.start() for m in _PIPELINE_END.finditer(text)]
    for at in starts:
        # `\s-i` from here, before the command ends (its blank may be the newline)
        if (_first_at_or_after(launches, at, len(text) + 1)
                <= _first_at_or_after(launch_ends, at, len(text))):
            continue
        if (_first_at_or_after(sends, at, len(text))
                < _first_at_or_after(pipeline_ends, at, len(text))):
            return True
    return False


def _matches_fingerprinted_value(text: str | None, state: SessionState) -> bool:
    """Does `text` hold a value this session fingerprinted from a real read?"""
    return bool(state.secret_fingerprints) and bool(
        fingerprints_in(text) & set(state.secret_fingerprints))


def carries_secret(text: str | None, state: SessionState,
                    command: bool = False) -> bool:
    """Does this text contain a value the session already knows is secret?

    ⚠ OR IS IT SHIPPING THE ENVIRONMENT ITSELF? A fingerprint match needs the
    session to have READ the value first, and a process environment is never
    read through a path, so no fingerprint can exist for it. That is why this is
    here rather than in `mark_sources`: the source and the sink are the same
    action, and a mark written after the verdict would arrive too late to judge
    the action that carried it.

    ⚠ BUT ONLY WHEN `text` IS A COMMAND (`command=True`). `sends_the_environment`
    is `_ENV_TO_EGRESS`, a COMMAND-STRUCTURE regex — it is anchored to where a
    shell would START the `env | curl` pipeline, and it exists to catch that
    pipeline being RUN. `carries_secret` is applied to more than commands:
    staged-diff content, WRITE/EDIT content, a FETCH url, MCP tool args. On
    those, the pattern is not an act of exfiltration, only text that mentions
    it — a proven false positive (5 of 391 real commits, all the engine's own
    docs/tests describing this very check, denied their own commit), and on a
    multi-MB diff it is an unbounded 35 ms p99 / 54 ms worst. So it runs on the
    COMMAND path only. The live threat loses nothing: an actual `env | curl`
    command is still caught here (command=True at the two EXEC call sites) AND,
    independently, by `check_sinks`'s `_ENV_DUMP_TO_NET` env_dump_egress sink.
    FETCH/TOOL had zero real history of it firing either way; WRITE/EDIT's real
    secret catches all came from the fingerprint/taint disjuncts below, never
    this one. See docs/PROGRESS and tests/test_env_dump_is_command_scoped.py.

    ⚠ OR IS IT A VALUE WHOSE FORMAT ANY VENDOR WOULD RECOGNISE? The third
    disjunct. Provenance answers "did this session read it"; the format table
    answers "is this shaped like a credential the vendor namespaced on
    purpose". Both raise the same exact level and the same verdict. These two
    are VALUE checks and run on every input type — a leaked credential is a leak
    wherever it sits.
    """
    if command and sends_the_environment(text):
        return True
    if _matches_fingerprinted_value(text, state):
        return True
    # ⚠ FEEDER B — THE VALUE'S DOCUMENTED FORMAT, whether or not this session
    # ever read it from a file. A pasted `AKIA…` or `ghp_…` is a credential by
    # its vendor's own construction; provenance cannot see one the session did
    # not read, and this is the third disjunct that can. Nothing above it moved.
    # core/known_formats.py holds the table; docs/85 the decision. The yes or
    # no alone, at the one-hit matcher's cost: which value comes first is the
    # evidence's question, asked only when this says yes.
    return known_formats.holds_known_secret(text)


def _canary_hashes_in(text: str | None) -> set[str]:
    """The FULL sha256 of every value-shaped token — the canary's needle.

    ⚠ WIDER THAN `fingerprints_in`'s 8 hex, and NO entropy gate, both on purpose
    (see core/canary._FP_LEN). A canary match is an unconditional DENY, so the whole
    64-hex digest is compared: a false match against a value legitimately in an
    egress is ~2**-256, impossible. And every value-token is hashed — no entropy
    filter — because a canary must never be MISSED and a full-digest match cannot
    false-positive. Still exact and deterministic; not a heuristic."""
    if not text:
        return set()
    if len(text) > _MAX_SCAN:
        text = text[:_MAX_SCAN]
    return {hashlib.sha256(tok.encode()).hexdigest()
            for tok in _VALUE_TOKEN.findall(text)}


def carries_canary(text: str | None, state: SessionState) -> bool:
    """Does this text carry a planted DECOY value (a "canary", core/canary.py)?

    ⚠ NEAR-CERTAIN THEFT, NOT "a secret is leaving". Nothing legitimate ever reads
    a canary, so a match is the strongest signal the engine has — it wins over
    every `secret_*` rung and gets its own rule id. It is an exact full-digest set
    intersection, never a heuristic, and the value is not recoverable from the
    stored hash. Distinct from the audit-log canary in core/wire.py."""
    return bool(state.canary_fingerprints
                and (_canary_hashes_in(text) & set(state.canary_fingerprints)))


def _egress_carries_canary(action: Action, state: SessionState) -> bool:
    """A canary check on exactly the egress texts `_secret_level` already inspects
    for `carries_secret`: the command, a fetch's url/content, a tool's or a
    write/edit's content. A canary in any of them is exfiltration in progress."""
    if not state.canary_fingerprints:
        return False
    if action.kind is ActionKind.EXEC:
        return carries_canary(action.command, state)
    if action.kind is ActionKind.FETCH:
        return any(carries_canary(t, state) for t in (action.url, action.content))
    if action.kind in (ActionKind.TOOL, ActionKind.WRITE, ActionKind.EDIT):
        return carries_canary(action.content, state)
    return False
