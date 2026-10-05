"""Why a DENY or an ASK: the facts, the sentence, and nothing guessed.

docs/108. The engine attaches a `Why` where only the deciding branch knows a
fact: the secret ladder's source (`secret_ladder.why_of_secret`), the step a
session first held a secret. `completed` adds, at the engine's single exit,
what every block has: its action, where it goes, and the session source its
rule turned on. `record_fields` is what a DENY or ASK record carries, and
`sentence` is the line an agent reads first:

    I didn't allow this because you're trying to send <value_type> to <destination>.
    Asking because you're trying to send <value_type> to <destination>.

⚠ UNKNOWN IS ABSENT, NEVER GUESSED. A part the engine doesn't know is left out
of the sentence, and its field is left off the record. docs/108 §4 is the table
of what the engine knows per rule family, and its gaps.

⚠ NEVER THE VALUE. `destination`, `location` and `source_file` go through the
known-format mask (`masked`) before anything stores or renders them, for the
reason `adapters/_common` never renders evidence: a key in a DNS name is a key.

⚠ PURE: text in, text out. No IO, no git: the one fact that costs a spawn (a
named remote's host) is known only inside the branch that paid for it, so a
push names its remote as written (`origin/main`).
"""
from __future__ import annotations

import dataclasses
import re

from core import known_formats, rule_names
from core.command_text import _GIT_PUSH, _segment_end
from core.egress import _destinations, _is_expected, _remote_url_host
from core.types import Action, ActionKind, Decision, SessionState, Verdict, Why

# ─────────────────────────────────────────────────────────── the value types
CANARY = "a Sting canary value"
COPIED = "data copied from a credential file"
CREDENTIAL_FILE = "a credential file"
FILLED = "a variable filled from a credential file"
ENVIRONMENT = "the process environment"
READ_VALUE = "a value read from a credential file"
DERIVED = "content written while the session held a secret"
POLICY_VALUE = "a value your org policy declares sensitive"

RECORD_KEYS = ("action", "destination", "source_file", "source_step", "location",
               "value_type", "sentence")
"""What a DENY or ASK record carries, each dropped when unknown."""

REMEDIES = {
    "environment": ("Don't write the key into the command: read it from the "
                    "environment at runtime."),
}
"""What to change, when the rule knows it. Only one rule does: a key written
into a command bound for a host the guard recognises. To any other host, moving
the key where the guard can't see it would be the evasion this guard exists to
stop, so the agent is told to stop instead."""

DENIED = "I didn't allow this because you're trying to send"
ASKED = "Asking because you're trying to send"


def masked(text: str | None) -> str | None:
    """`text` with every known-format value replaced by what it is:
    `<an AWS access key ID, 20 chars>`. Never the value."""
    if not text:
        return text
    hits = known_formats.find_known_secrets(text)
    pieces, cursor = [], 0
    for hit in hits:
        if hit.start < cursor:
            continue
        pieces += [text[cursor:hit.start], known_formats.stand_in(hit.name, hit.end - hit.start)]
        cursor = hit.end
    return "".join(pieces) + text[cursor:]


def path_display(path: str) -> str:
    """A path as the developer spelled it: the internal `/HOME` sentinel is `~`."""
    return "~" + path[len("/HOME"):] if path.startswith("/HOME/") else path


# ───────────────────────────────────────────────────── where, in a staged diff
_HUNK = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def diff_position(diff: str | None, offset: int) -> tuple[str, int] | None:
    """(file, line in the new file) of `offset` in `git diff --cached` output,
    or None when it is not on a line of a new file: a header, a removed line.
    Read up to `offset` only, once."""
    if not diff or not 0 <= offset < len(diff):
        return None
    target = diff.rfind("\n", 0, offset) + 1
    path, line, in_hunk, at = None, 0, False, 0
    while at <= target:
        stop = diff.find("\n", at)
        stop = len(diff) if stop == -1 else stop
        text = diff[at:stop]
        if at == target:
            if in_hunk and path and text[:1] in ("+", " "):
                return path, line
            return None
        if text.startswith("diff --git "):
            path, in_hunk = None, False
        elif not in_hunk and text.startswith("+++ "):
            named = text[4:].strip()
            path = None if named == "/dev/null" else (named[2:] if named.startswith("b/") else named)
        elif hunk := _HUNK.match(text):
            line, in_hunk = int(hunk.group(1)), True
        elif in_hunk and (text[:1] in ("+", " ") or not text):
            # ⚠ AN EMPTY LINE IS CONTEXT TOO: an editor or a mail client strips
            # the space `git diff` writes before an empty context line.
            line += 1
        at = stop + 1
    return None


# ───────────────────────────────────────────────────────── where a push goes
_WORD = re.compile(r"'[^']*'|\"[^\"]*\"|\S+")
_PUSH_VALUE_FLAGS = frozenset({"-o", "--push-option", "--repo", "--receive-pack", "--exec"})
_URL_USERINFO = re.compile(r"://[^/\s]*@")
"""A URL's `user:password@`, up to its last `@` before the path."""


def push_destination(command: str) -> str | None:
    """`<remote>/<ref>` as a `git push` writes them, a URL remote's host, or
    None for a bare push (its upstream is not in the text)."""
    push = _GIT_PUSH.search(command or "")
    if push is None:
        return None
    rest = command[push.end():_segment_end(command, push.end())]
    words = [word.strip("'\"") for word in _WORD.findall(rest)]
    names, skip = [], False
    for word in words:
        if skip:
            skip = False
        elif word.startswith("-"):
            skip = word in _PUSH_VALUE_FLAGS
        else:
            names.append(word)
    if not names:
        return None
    host = _remote_url_host(names[0]) if ("://" in names[0] or "@" in names[0]) else None
    if host:
        return host
    # A URL the host reader does not parse (`ftp://`) keeps no user or
    # password (security review, LOW).
    remote = _URL_USERINFO.sub("://", names[0])
    if len(names) < 2:
        return remote
    spec = names[1].lstrip("+")
    ref = spec.rpartition(":")[2] or spec.rstrip(":")
    return f"{remote}/{ref.removeprefix('refs/heads/')}"


_DNS_TOOL = re.compile(r"(?<![\w.-])(?:nslookup|dig|host)[ \t]+")
_DNS_VALUE_FLAGS = frozenset({"-t", "-c", "-p", "-q", "-k", "-y", "-b", "-f", "-W", "-R",
                              "-type", "-class", "-port", "-timeout", "-retry"})
"""Options of `dig`, `host` and `nslookup` whose next word is their value."""


def dns_name(command: str) -> str | None:
    """The name a DNS lookup resolves: the first word after `nslookup`, `dig`
    or `host` holding a `.` that is not an option (`-t`, `+short`), an
    option's value (`-t txt`) or a server (`@8.8.8.8`). A record type or class
    (`TXT`, `IN`) holds no dot and is never the name (python review). A DNS
    name carries whatever is written into it, so it is the destination."""
    tool = _DNS_TOOL.search(command or "")
    if tool is None:
        return None
    skip = False
    for word in command[tool.end():_segment_end(command, tool.end())].split():
        word = word.strip("'\"")
        if skip:
            skip = False
        elif word[:1] in ("-", "+", "@"):
            skip = word.split("=", 1)[0] in _DNS_VALUE_FLAGS and "=" not in word
        elif "." in word.strip("."):
            return word
    return None


def dns_domain(name: str) -> str:
    """The domain a lookup of `name` is sent to: its last two labels, `*.`
    before them when there are more. ⚠ NEVER THE LABELS BEFORE THEM (security
    review, MEDIUM): they are what a lookup carries, an encoded chunk as
    readily as a key, and a destination is stored and shown."""
    labels = name.strip(".").split(".")
    domain = ".".join(labels[-2:])
    return f"*.{domain}" if len(labels) > 2 else domain


# ─────────────────────────────────────────────── what every block has, at exit
def _one(sources: list[dict]) -> tuple[str | None, int | None]:
    """The source, when exactly one distinct one was read; else unknown.

    By distinct `ref`: an org-policy source is recorded once per (ref,
    severity), so one file can appear twice. `secret_ladder._only` counts
    entries, because `secret_sources` is recorded once per path already."""
    refs = {src.get("ref") for src in sources}
    if len(refs) != 1:
        return None, None
    return sources[0].get("ref"), sources[0].get("seq")


_FILE_KINDS = frozenset({"web", "issue", "dependency", "reference-data", "outside"})
"""The untrusted sources whose `ref` names a file or a URL. `git-history` keeps
an evidence window of the command there, and `mcp` a tool's name: neither is
a file, so only their step is told."""


def _session_source(family: str, state: SessionState) -> tuple[str | None, int | None]:
    """The session read the rule turned on: the last untrusted read (as the
    reason names it), or the one org-policy source at the rule's severity."""
    if family.startswith("untrusted_") and state.untrusted_sources:
        last = state.untrusted_sources[-1]
        return (last.get("ref") if last.get("kind") in _FILE_KINDS else None,
                last.get("seq"))
    if family in ("policy_source_deny", "policy_source_ask"):
        severity = family.rpartition("_")[2]
        return _one([s for s in state.policy_sources if s.get("severity") == severity])
    if family == "policy_value_exfil":
        return _one(state.policy_sources)
    return None, None


def _sends(rule_id: str | None) -> str | None:
    """The rule's sink, when it is one that sends; else None."""
    family, _, sink = (rule_id or "").partition(":")
    if family in rule_names.FAMILY_ACTIONS or sink not in rule_names.SENDS:
        return None
    return sink


def _destination(action: Action, state: SessionState, sink: str | None) -> str | None:
    if sink is None:
        return None
    if sink == "git_push":
        return push_destination(action.command or "")
    if sink == "git_commit":
        return "this repository's history"
    if sink == "clipboard_egress":
        return "the clipboard"
    if sink == "dns_lookup" and (name := dns_name(action.command or "")):
        return dns_domain(name)
    if action.kind in (ActionKind.WRITE, ActionKind.EDIT):
        return action.paths[0] if action.paths else None
    hosts = _destinations(action, state)
    return hosts[0] if hosts else None


def _remedy_holds(action: Action, state: SessionState, sink: str | None) -> bool:
    """The environment remedy, only for a command bound for hosts the guard
    recognises (see REMEDIES)."""
    if action.kind is not ActionKind.EXEC or sink is None:
        return False
    hosts = _destinations(action, state)
    return bool(hosts) and all(_is_expected(host, state) for host in hosts)


def completed(verdict: Verdict, action: Action, state: SessionState) -> Verdict:
    """`verdict` with its `why` filled in, for a DENY or an ASK: the facts the
    deciding branch attached, plus the action, where it goes and the session
    source its rule turned on. An ALLOW is returned as it came."""
    if verdict.decision is Decision.ALLOW:
        return verdict
    facts = verdict.why or Why()
    family = (verdict.rule_id or "").partition(":")[0]
    sink = _sends(verdict.rule_id)
    source_file, source_step = facts.source_file, facts.source_step
    if source_file is None and source_step is None:
        source_file, source_step = _session_source(family, state)
    remedy = facts.remedy if facts.remedy and _remedy_holds(action, state, sink) else None
    return dataclasses.replace(verdict, why=Why(
        action=rule_names.action_of(verdict.rule_id),
        destination=masked(facts.destination or _destination(action, state, sink)),
        source_file=masked(path_display(source_file)) if source_file else None,
        source_step=source_step,
        location=masked(facts.location),
        value_type=facts.value_type,
        remedy=remedy))


# ─────────────────────────────────────────────────── the sentence, the record
def sentence(decision: Decision, why: Why | None, rule_id: str | None) -> str | None:
    """The one line an agent reads first, or None when the block sends nothing
    or the engine knows neither what nor where."""
    if why is None or decision is Decision.ALLOW or _sends(rule_id) is None:
        return None
    if not (why.value_type or why.destination):
        return None
    lead = DENIED if decision is Decision.DENY else ASKED
    what = f" {why.value_type}" if why.value_type else ""
    where = f" to {why.destination}" if why.destination else ""
    return f"{lead}{what}{where}."


def came_from(verdict: Verdict) -> str | None:
    """Where the value came from, or the read the rule turned on, in words that
    fit the rule's family; None when the engine does not know. Told to the
    agent after the sentence (`adapters/_common.told`)."""
    why = verdict.why
    if why is None or (why.source_file is None and why.source_step is None):
        return None
    family = (verdict.rule_id or "").partition(":")[0]
    what, step = why.source_file, why.source_step
    at = f" at step {step}" if step is not None else ""
    if family.startswith("untrusted_"):
        return (f"This session read {what}{at}, which someone else wrote." if what
                else f"This session read content someone else wrote{at}.")
    if family.startswith("policy_source_"):
        return (f"This session read {what}{at}, which your org policy marks sensitive."
                if what else None)
    if family == "secret_session_unverified":
        return f"This session read the credential {what}{at}." if what else None
    if what and step is not None:
        return f"It came from {what}, read at step {step}."
    return f"It came from {what}." if what else f"It was read at step {step}."


def remedy_text(why: Why | None) -> str | None:
    """What to change, in words, when the rule knows it."""
    return REMEDIES.get(why.remedy or "") if why is not None else None


def record_fields(verdict: Verdict) -> dict | None:
    """What a DENY or ASK record carries (`RECORD_KEYS`), each dropped when
    unknown; None for an ALLOW or a verdict with no facts."""
    if verdict.decision is Decision.ALLOW or verdict.why is None:
        return None
    why = verdict.why
    fields = {"action": why.action, "destination": why.destination,
              "source_file": why.source_file, "source_step": why.source_step,
              "location": why.location, "value_type": why.value_type,
              "sentence": sentence(verdict.decision, why, verdict.rule_id)}
    return {key: value for key, value in fields.items() if value is not None}
