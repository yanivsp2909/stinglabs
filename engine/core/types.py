"""
The normalised event. Design this first, change it rarely.

This module is the boundary between the six agents and the one engine. Adapters
translate an agent's payload into an `Action`; the engine consumes `Action` and
returns a `Verdict`; adapters translate that back. Nothing else crosses.

The rule that keeps it clean, from docs/25-stage1-sensor-layer.md:

    The engine must never see the word `hookSpecificOutput`, `tool_name`, or
    `.cursor/hooks.json`. It sees only the normalised shape below.

This module holds three things, all pure data:

  Action / Verdict   the boundary DTOs. No methods, ever — they are what the
                     adapters produce and consume, and behaviour on them would
                     be behaviour outside the engine.
  SessionState       the session's memory. A state machine, so it does have
                     helpers, but it touches nothing outside itself.
  World              a Protocol for what the engine needs FROM outside, so the
                     engine can stay a pure function. Implemented in probes.py.

It imports nothing from this project and nothing that performs IO. If it ever
needs to, the boundary has moved and something is wrong.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Protocol


class ActionKind(StrEnum):
    """What the agent is trying to do, independent of what it calls the tool."""
    READ = "READ"       # open a file for reading
    WRITE = "WRITE"     # create or overwrite a file
    EDIT = "EDIT"       # modify an existing file in place
    EXEC = "EXEC"       # run a shell command
    FETCH = "FETCH"     # retrieve a URL
    TOOL = "TOOL"       # call an MCP tool


class Decision(StrEnum):
    """The three answers the engine can give."""
    ALLOW = "ALLOW"
    ASK = "ASK"
    DENY = "DENY"


@dataclass(frozen=True)
class Action:
    """One normalised tool call, agent-agnostic."""

    session_id: str
    """Stable across the whole session."""

    seq: int
    """Monotonic within the session. Some agents supply this (Antigravity's
    stepIdx); where they don't, the session layer assigns it."""

    kind: ActionKind

    paths: tuple[str, ...]
    """Absolute, resolved, symlinks followed.

    Spec'd as `list[str]`. A tuple is used instead because `frozen=True` does
    not freeze a list's contents — `action.paths.append(...)` would mutate a
    supposedly immutable Action, and this is the object every policy decision
    is made from. Same interface, honest immutability.
    """

    command: str | None
    """Raw shell string. EXEC only."""

    url: str | None
    """FETCH only."""

    tool_name: str | None
    """The MCP tool identifier. TOOL only."""

    content: str | None
    """WRITE/EDIT payload, for fingerprint matching."""

    cwd: str

    workspace_roots: tuple[str, ...]
    """Every directory that counts as "the project", absolute and resolved.

    An ARRAY, not a single root, because multi-root workspaces are real: Cursor
    sends `workspace_roots` and Antigravity sends `workspacePaths`, both lists.
    "Inside the project" is therefore a set membership test, never one prefix
    check.

    Deliberately has no default. An adapter that forgot to populate it would
    otherwise silently yield an empty tuple, and every path would look like it
    was outside the project — the trust boundary drawn wrong, quietly. Agents
    that expose only one directory send a single-element tuple.
    """

    agent: str
    """"claude-code" | "cursor" | ... — telemetry only. The engine must never
    branch on this. If it starts wanting to, the normalisation is wrong."""

    tool_origin: str = ""
    """"mcp" | "builtin" | "" — WHERE a TOOL action came from, declared by the
    adapter that knows its own agent's conventions.

    Exists because the engine was testing `tool_name.startswith("mcp__")`, and
    that prefix is Claude Code's naming leaking across the boundary this module
    defines. Other agents name MCP tools differently; five adapters already hold
    five sets of agent-specific knowledge, and this is a sixth.

    "builtin" means the ADAPTER did not recognise the tool — a statement about
    our knowledge, not about the tool. `Task` spawns a subagent. So a builtin is
    never treated as known-safe.

    The default is "" and the engine treats anything that is not "builtin" as
    external, so an adapter that forgets to set it fails towards the STRICTER
    answer rather than the laxer one.
    """

    malformed: str = ""
    """Why this payload cannot be judged at all — "" when it can. Set by an
    adapter, read ONLY by `hook_entry.run`, which refuses to decide (exit 2).

    Exists because an adapter must never raise, yet a shell tool whose `command`
    is `7`, `null` or `{…}` names nothing the engine can judge — and parsing it
    to "EXEC with no command" was an ALLOW. The engine never reads this field:
    what the guard does with a payload it could not read is the hook's call,
    not policy's (docs/90)."""

    replaced: str | None = None
    """The text an EDIT replaces (`old_string`, each MultiEdit `old_string`),
    when the tool names it; None when it does not. `content` is the new text.

    Exists because the engine reads no file, so an edit is judged on its own
    two sides: without this one, deleting the guard's hook entry from
    ~/.claude/settings.json arrived as an edit whose new text was empty
    (item C step 3b). An adapter that cannot supply it leaves it None, and
    the engine refuses an edit it must judge but cannot see."""

    tool_arguments: str | None = None
    """EVERY string of an MCP call's arguments, flattened — set only by an
    adapter whose agent is established to deliver the arguments whole, and
    only when they arrived as an object small enough to read in full
    (`_common.complete_tool_arguments`). None otherwise: not this agent, not
    an MCP call, or not visible whole.

    Distinct from `content`, which the secret rules read and which keeps a
    single named field when an MCP call has one: this is what an MCP call
    after a secret read is judged by (fix/false-positives item 3, docs/112),
    and None there keeps today's verdict."""


@dataclass(frozen=True)
class Why:
    """What a DENY or an ASK is about, as the facts the engine held when it
    decided (docs/108 §4). Never the value: a type, a destination, a file, a
    step and a place, each through the known-format mask (`core/why.py`).

    ⚠ UNKNOWN IS NONE, NEVER A GUESS. Which read a fingerprint came from, which
    file filled a variable, where a canary sits: the engine does not record
    them, so nothing here says them."""

    action: str | None = None
    """What the action does: "a network send", "git push"."""
    destination: str | None = None
    """Where it goes: a host, `<remote>/<ref>`, a written path."""
    source_file: str | None = None
    """The file the traced value was read from, or whose content was read."""
    source_step: int | None = None
    """The step it was read at."""
    location: str | None = None
    """Where the value sits in what is sent: "offset 11 in the command"."""
    value_type: str | None = None
    """What the value is: "an AWS access key ID"."""
    remedy: str | None = None
    """What to change, when the rule knows it (`core/why.py` REMEDIES). Told
    to the agent; not on the record."""


@dataclass(frozen=True)
class Verdict:
    """What the engine decided, before any agent-specific rendering."""

    decision: Decision

    reason: str | None
    """Human-readable, and it names the source step — "this carries data from
    .env, read at step 4". A reason that doesn't name its cause is not
    actionable for the developer staring at the prompt."""

    rule_id: str | None
    """Which rule fired, for the audit log and for traceability back to policy."""

    evidence: str | None = None
    """WHAT the rule matched, and where — `@<offset> …matched text with context…`.

    THIS IS A POLICY OUTCOME, LIKE THE OTHER TWO FIELDS. `reason` is prose about
    why the policy fired and `rule_id` is the rule's name, so this type already
    carries policy explanation; a span is the machine-checkable form of the same
    thing. The boundary this file protects is AGENT concepts — no
    `hookSpecificOutput`, no `tool_name` — not policy ones.

    WHY IT MUST TRAVEL WITH THE VERDICT. Only the code that decided knows what
    matched. It used to be reconstructed afterwards from a parallel sink->pattern
    table that covered 15 of 19 sinks and, for `secret_in_argv`, consulted a
    DIFFERENT predicate than the one that decided — so the explanation could name
    text that never fired the rule. Same objection as the extension recomputing
    `action_hash`: a second implementation of one decision.

    THREE VALUES, and the distinction is the point:

        None                  nothing to explain — ALLOW, no rule fired
        "@<offset> …text…"    this is what matched, and where
        EVIDENCE_UNRECORDED   a rule fired and no span was captured

    Optional so no construction site is forced to supply one, and appended last so
    positional construction keeps working.

    ⚠ A span explains what a rule matched IN TEXT. It does not explain a verdict
    that turned on session state — where a secret came from is `reason`'s job.
    """

    beneath: "Verdict | None" = None
    """The verdict under this one, for a relaxation to give back: under a FLOOR
    (`installed_guard:guard_selfmod`), what the rest of the engine reached
    before the floor replaced it; and where a secret rung and the rest of the
    ladder both answered, the one that lost — the STRICTEST wins, on a tie the
    first reached (`engine._strictest`). Relaxing this verdict's rule id in a
    person's `~/.sting/policy.json` gives THIS back, judged by the same
    overlay, never a blanket ALLOW (`policy.Overlay.enforce`). None everywhere
    else, and never on the record: the record keeps the engine's verdict."""

    why: "Why | None" = None
    """For a DENY or an ASK: what it is about, as facts (`Why`, docs/108). None
    on an ALLOW, which keeps an ALLOW record byte-identical. Appended last, so
    positional construction keeps working."""


EVIDENCE_UNRECORDED = "@unrecorded"
"""A rule fired and no span was captured — NOT the same as nothing to explain.

Without a distinct value the two are indistinguishable in the log, which is how
`evidence` reached 26 of 475 records while looking like a field that was merely
often inapplicable. A greppable sentinel makes a coverage gap visible, and lets a
test assert that every non-ALLOW verdict carries a real span instead of this.
"""


# ---------------------------------------------------------------- session state
SCHEMA_VERSION = 1
"""The shape of a persisted SessionState. Bump it when a field changes MEANING.

⚠ WHAT THIS EXISTS TO STOP. `from_dict` is tolerant by design — it discards keys
it does not recognise, which is right for a hand-edited file and right for one
written by an older build. It is WRONG across a mid-session upgrade: a session
that had accumulated `untrusted` under one field name would load clean under
another, and an untrusted session would silently become a trusted one with no
error, no prompt and nothing in the log to say it happened. Silent taint loss is
the worst failure this state machine has, because everything downstream then
behaves correctly on a premise that is false.

⚠ ABSENCE OF THE KEY IS NOT A MISMATCH, AND THAT IS DELIBERATE. Every state file
written before this constant existed was written by schema 1 — this one — so
treating absence as skew would relabel every live session on every machine at
upgrade time for no information. The check that catches those is the SHAPE check
in `from_dict`: a file carrying keys this class does not have is skew whatever
its version says, and that is the exact condition — "discards keys it does not
recognise" — the bug is made of.
"""


# ⚠ 16x THE LARGEST REAL SESSION'S WRITE COUNT, so the cap is a backstop rather
# than a limit anybody meets. A measured session wrote ~30 files across 120
# actions; the bound exists because a set of every path a session touched is
# unbounded, and an unbounded set on the hot path is a memory leak.
_MAX_AUTHORED = 512


@dataclass
class SessionState:
    """What this session already knows.

    Mutable by design, unlike Action and Verdict. This is a state machine
    persisted across processes, and every mutation happens inside the locked
    window open_session() opens — the one place where mutation is safe.
    """

    session_id: str = ""
    started_at: float = 0.0
    seq: int = 0
    cwd: str = ""

    workspace_roots: list[str] = field(default_factory=list)
    """Every directory that counts as "the project", resolved ONCE per session.

    Cached here rather than recomputed per action because resolving it shells
    out to git, and CLAUDE.md rule #8's principle applies: derive once, then it
    is a set lookup. Empty means "not resolved yet", not "no roots".
    """
    roots_note: str | None = None
    """Why the roots are a fallback, if they are. Surfaced once, on stderr."""
    scratch_roots: list[str] = field(default_factory=list)
    """Agent-owned ephemeral workspace — a LOCATION, not an exit.

    Writing here is not `write_outside`: it does not leave the machine, the
    directory is owner-only (0700 under a sticky /tmp), and it belongs to the
    agent rather than to the project or the developer.

    Reading here is STILL untrusted, deliberately. The hazard is not another
    local user — they cannot write to a 0700 directory — it is the AGENT, which
    is the thing this engine does not trust. Were the scratchpad a project root,
    an injected agent could write poisoned content there and read it back
    laundered as trusted. So the asymmetry is the whole design: an exit
    exemption, never a trust extension.
    """
    roots_env: str | None = None
    """The STING_ROOTS value the cached roots were derived from, "" if unset.

    Exists because a cache that never re-checks its inputs is a cache that
    silently ignores a config change. A real session cached git-derived roots
    at its first action, the developer set STING_ROOTS afterwards, and every
    subsequent action kept the stale single root and said nothing — the same
    silence that let workspace_roots: null go unnoticed for 181 actions.
    """

    title: str = ""
    """`book-app / npm run dev` — the session's human title, derived ONCE by
    hook_entry from the declared root and the first command (core/title.py) and
    recorded on every record after that. ⚠ NOT ON THE DECISION PATH: nothing in
    core/engine.py reads it, and a test decides the same action with and without
    it. Content-blind by construction — never from the transcript. docs/79."""

    schema_version: int = SCHEMA_VERSION
    """Written on every save so a future reader can tell what it is reading."""

    schema_skew: str = ""
    """Non-empty when this state was loaded under a DIFFERENT schema.

    ⚠ IT IS PERSISTED AND IT IS LOUD ON PURPOSE. A session that ran under the
    maximal-labelling fallback must be identifiable AFTERWARDS — otherwise the
    log shows a session that was untrusted and holding secrets from its first
    action with no explanation, and a reader would reasonably conclude the
    developer did something. `hook_entry` writes this into the record's
    `degraded` note, so the reason travels with the verdicts it caused.
    """

    # --- UNTRUSTED: "a stranger wrote this" -------------------------------
    untrusted: bool = False
    untrusted_since_seq: int | None = None
    untrusted_sources: list[dict] = field(default_factory=list)

    # --- SECRET: "this must not leave" ------------------------------------
    holds_secret: bool = False
    holds_secret_since_seq: int | None = None
    secret_fingerprints: list[str] = field(default_factory=list)
    """Hashes of VALUES, never plaintext. Never transmitted anywhere."""
    canary_fingerprints: list[str] = field(default_factory=list)
    """Hashes of DECOY values Sting planted (core/canary.py) — never plaintext, and
    never a real secret this session read. Nothing legitimate reads a canary, so a
    match on an egress is near-certain exfiltration. Seeded at the session boundary
    (`_add_canary`), checked by `engine.carries_canary`. Distinct from the audit-log
    canary in core/wire.py."""
    canary_unarmed: str = ""
    """Non-empty when a canary was CONFIGURED but failed to load (a corrupt store) —
    set and surfaced loudly so a disarmed decoy is never mistaken for protection."""
    secret_sources: list[dict] = field(default_factory=list)
    """{"seq":5,"path":".env","how":"content"|"path_policy"|"unread"}.

    `how` records WHY this counts as a secret. The three cases are not
    interchangeable, and two of them used to be indistinguishable:

        content      the read succeeded and yielded fingerprints. NEVER empty:
                     `content` with no fingerprints described a read that never
                     happened, and one such phantom source held holds_secret
                     for 166 actions of a real session.
        path_policy  the read succeeded but nothing inside was fingerprintable,
                     or the path is confidential with no credential to
                     fingerprint. The path itself is the signal.
        unread       a real read operand the guard could not read. Fails closed
                     on the path alone — and says that is what it did.
    """

    policy_sources: list[dict] = field(default_factory=list)
    """{"seq":5,"ref":"/etc/secrets","type":"path","severity":"log"|"ask"|"deny"}.

    ⚠ A SEPARATE, SEVERITY-CARRYING TAINT, DISTINCT FROM `secret_sources`. A read
    matching a source the ORG POLICY declared (core/org_policy.py) marks the
    session here, carrying the declared severity — because `holds_secret` forces
    the single `secret_exact` DENY and cannot express `log`/`ask`. On egress the
    escalation is the STRICTEST severity across these, and it can only RAISE a
    verdict, never lower one (see engine `_policy_escalate`). Additive and
    versioned in: an empty policy marks nothing, so this list stays empty and the
    session is byte-identical to a machine with no policy. Coarse (step 3a): the
    SOURCE was touched; step 3b adds value fingerprinting."""

    policy_fingerprints: list[str] = field(default_factory=list)
    """Hashes of distinctive VALUES read from an org-policy declared source, never
    plaintext — the PRECISE half (step 3b) on top of `policy_sources`' coarse taint.
    Whole records / long-unique tokens (the same length+entropy floor as
    `secret_fingerprints`) plus structural PII fields (email, SSN). On egress, an
    exact value match here is a CONFIRMED exfiltration -> DENY (`policy_value_exfil`),
    the certain tier, regardless of the source's coarse severity. Empty policy or no
    distinctive value read -> empty -> byte-identical (see engine
    `_policy_value_escalate`). Distinct from `secret_fingerprints` so the DENY reason
    names an org-policy value leak, not a credential, and the secret path is
    untouched."""

    # ⚠ AUTHORSHIP, AND IT IS DELIBERATELY NOT BESIDE `tainted_paths`.
    #
    # They answer different questions and conflating them breaks both:
    #
    #     tainted_paths    did a SECRET reach this file?
    #     authored_paths   did THIS SESSION create this file?
    #
    # `deploy.sh` written with `curl … -d @.env` inside it is AUTHORED and NOT
    # tainted — it carries a command MENTIONING a credential, not the credential.
    # Reusing the taint carrier would make every tainted write an authored path
    # and every authored path look labelled, which is exactly backwards for the
    # two rules this exists to serve.
    authored_paths: list = field(default_factory=list)
    """Absolute paths this session CREATED. See `mark_authored`."""

    _authored_index: set = field(default_factory=set, repr=False, compare=False)
    """In-memory membership index for `authored_paths`. Never persisted
    meaningfully — `from_dict` rebuilds it."""

    authored_truncated: bool = False
    """⚠ THREE STATES, NOT TWO, the way `purpose` and the chain have three.
    A set of every path a long session touched is unbounded — a real session ran
    120 actions and the live median is 106 records — so it is capped. Past the
    cap the FLAG goes true and stays true, and every consumer must read
    "authored" as UNKNOWN rather than FALSE from that point on. A rule that read
    a truncated set as "this session did not write that" would silently invert
    on exactly the long sessions most worth watching."""

    downloaded_paths: list = field(default_factory=list)
    """Absolute paths this session wrote from a download (`curl -o`, `wget`, a
    redirect of either): OUTSIDE CONTENT whoever wrote the file (docs/112), so
    running one keeps today's verdict. See `mark_downloaded`."""

    downloads_truncated: bool = False
    """Past `_MAX_AUTHORED` downloads the set stops growing and this goes true:
    from then on any file may have been downloaded, and running one is judged
    as running outside content — the verdict it had before docs/112. So it does
    when a download went to a command whose writes cannot be followed
    (`lose_track_of_downloads`)."""

    created_paths: list = field(default_factory=list)
    """Absolute, collapsed paths this session CREATED: a Write, a copy, a move,
    a `>` or a `mkdir` of a path the World said was not there yet (docs/112,
    item C). Deleting one, or anything under a folder in it, loses nothing that
    was there before the session.

    ⚠ NOT `authored_paths`, deliberately (the reviews): authorship is marked
    for any write, so an overwrite the user was asked about — and may have
    declined — made the old file "authored", and a later delete of it looked
    like the session's own. Authorship keeps its meaning for the rules that
    read it (`sinks`' deferred-exec target, `outside_content`)."""

    created_truncated: bool = False
    """Past `_MAX_AUTHORED` created paths the set stops growing and this goes
    true: from then on nothing more is exempt — a delete is asked about."""

    unprinted_secret: bool = False
    """True once the session read a secret-looking value that nothing
    fingerprinted (`env_reads.unprinted_secret`): a `.env` line or an
    environment variable too short or too plain. Item 3 (docs/112) lets an
    MCP call after a secret read through only on fingerprints, so from then on
    it does not. No secret rule reads this."""

    tainted_paths: dict[str, dict] = field(default_factory=dict)
    """path -> {"label","level","from_seq"}. level is "exact" or "derived"."""

    tainted_vars: dict[str, int] = field(default_factory=dict)
    """shell var name -> the seq it was tainted at. Mechanism G03: `X=$(cat .env)`
    in one tool call, `curl -d "$X"` in the next. The taint has to survive
    between two separate hook processes or the chain is invisible."""

    aliases: dict[str, str] = field(default_factory=dict)
    """alias name -> definition. Mechanism G05: the decisive action is a bare
    `ls -la`, dangerous only because of an alias defined two calls earlier."""

    expected_hosts: list[str] = field(default_factory=list)
    approved_hosts: list[str] = field(default_factory=list)
    staged_secret_files: list[str] = field(default_factory=list)

    preexisting_remotes: dict[str, list[str]] = field(default_factory=dict)
    """repo toplevel -> the remote URLs configured there AT SESSION START.

    ⚠ FROZEN, AND THE FREEZING IS THE WHOLE SECURITY PROPERTY. Captured once per
    repository, before that repo's first action's command has run (the hook is
    PreToolUse), and never overwritten — so a remote the session itself ADDS or
    `set-url`s mid-task is absent from, or differs from, this set. At push time
    the command's target remote is resolved to its CURRENT url and admitted only
    if that url is IN this frozen set, which is why a planted/rewritten remote
    cannot buy the exemption. Keyed per toplevel, never one flat global set, so a
    session that moves between repositories judges each against its own start.

    Stores URLs, never the name `origin`: the name is attacker-renamable, the
    URL that existed before the session is not. Empty or missing ⇒ no exemption
    (today's DENY), the fail-safe direction."""

    warned_undeclared_root: bool = False
    """Has this session already said its cwd is inside no declared root?

    ⚠ A NOTE-ONCE LATCH, PERSISTED BECAUSE EACH HOOK CALL IS A FRESH PROCESS.
    When a write is judged `write_outside` and the cwd is inside none of the
    declared roots, that is the book-app case: a project never added to
    STING_ROOTS, where every write is flagged and nothing else says why. The
    hook says so once, then sets this — a note on all 200 writes of such a
    session is the keystroke tax the project refuses to levy. Not a taint field:
    it restricts nothing and is safe to lose (a fresh session simply says it
    again). SCHEMA_VERSION is unchanged — an older file merely lacks the key and
    defaults False, which is 'not yet warned', the correct start."""

    # ------------------------------------------------------------------ seq
    def next_seq(self, supplied: int | None = None) -> int:
        """The sequence number for the action being decided.

        Some agents supply one — Antigravity's stepIdx arrives already
        monotonic, so it is used as-is rather than recomputed. For everyone
        else the session assigns the next number.
        """
        if isinstance(supplied, int) and supplied > 0:
            return max(supplied, self.seq)
        return self.seq + 1

    # -------------------------------------------------------------- labels
    def mark_authored(self, path: str) -> None:
        """Record that this session created `path`. Idempotent, and bounded.

        ⚠ THE CAP IS THE POINT. `_MAX_AUTHORED` paths is ~16x the largest real
        session's writes; beyond it the set stops growing and
        `authored_truncated` goes true, so the fact degrades to UNKNOWN rather
        than to a wrong answer. It never shrinks and never resets: a session
        that exceeded the cap cannot later claim it did not write something.
        """
        if not path:
            return
        if path in self._authored_index:
            return
        if len(self.authored_paths) >= _MAX_AUTHORED:
            self.authored_truncated = True
            return
        self.authored_paths.append(path)
        self._authored_index.add(path)

    def authored(self, path: str) -> bool | None:
        """True, False, or None when the set was truncated and cannot say.

        ⚠ `None` IS NOT `False`, AND EVERY CALLER MUST BRANCH ON THAT. Both
        rules built on this take the QUIET branch on None: an unknown authorship
        must not make a run look dangerous, nor make a write look foreign.

        ⚠ THE INDEX IS REBUILT WHEN IT DISAGREES WITH THE LIST, and forgetting
        this made the fact useless while every in-memory test passed: the state
        is reloaded from disk on EVERY action, `_authored_index` does not
        persist, and a lookup against an empty index answered False for a path
        the session had definitely written. Authorship would have silently died
        between actions — the exact silent shape this whole class is about.
        """
        if len(self._authored_index) != len(self.authored_paths):
            self._authored_index = set(self.authored_paths)
        if path in self._authored_index:
            return True
        return None if self.authored_truncated else False

    def mark_downloaded(self, path: str) -> None:
        """Record that this session wrote `path` from a download. Idempotent,
        and bounded like `mark_authored`."""
        if not path or path in self.downloaded_paths:
            return
        if len(self.downloaded_paths) >= _MAX_AUTHORED:
            self.downloads_truncated = True
            return
        self.downloaded_paths.append(path)

    def lose_track_of_downloads(self) -> None:
        """A download went to a command whose writes cannot be followed — an
        unpacker, a run of it (`downloads.carried_downloads`, the fourth review
        round): from now on any file may be a download, as past the cap."""
        self.downloads_truncated = True

    def mark_created(self, path: str) -> None:
        """Record that this session created `path` (it was not there before).
        Idempotent, and bounded like `mark_authored`."""
        if not path or path in self.created_paths:
            return
        if len(self.created_paths) >= _MAX_AUTHORED:
            self.created_truncated = True
            return
        self.created_paths.append(path)

    def downloaded(self, path: str) -> bool | None:
        """True, False, or None when the set was truncated and cannot say."""
        if path in self.downloaded_paths:
            return True
        return None if self.downloads_truncated else False

    def mark_untrusted(self, seq: int, kind: str, ref: str) -> None:
        """Record that a stranger's text entered the session. Idempotent on the
        flag; every source is still recorded, because a deny reason has to be
        able to name which one."""
        if not self.untrusted:
            self.untrusted = True
            self.untrusted_since_seq = seq
        self.untrusted_sources.append({"seq": seq, "kind": kind, "ref": ref})

    def mark_secret(self, seq: int, path: str, how: str,
                     fingerprints: list[str] | None = None) -> None:
        if not self.holds_secret:
            self.holds_secret = True
            self.holds_secret_since_seq = seq
        # Deduplicated by PATH, keeping the FIRST read. The list means
        # "distinct secrets this session read", which is what a deny reason
        # needs to name. A live run recorded /repo/.env at seqs 3, 5, 8, 13 and
        # 14 — noise that made picking the wrong entry easy.
        if not any(src["path"] == path for src in self.secret_sources):
            self.secret_sources.append({"seq": seq, "path": path, "how": how})
        for fp in fingerprints or []:
            if fp not in self.secret_fingerprints:
                self.secret_fingerprints.append(fp)

    def mark_policy_source(self, seq: int, ref: str, source_type: str,
                           severity: str) -> None:
        """Record that this session read a source the ORG POLICY declared, with
        the declared severity. Deduplicated by (ref, severity), keeping the first
        read — the list names which declared sources an egress escalation is for.
        Adds only; it can never clear a stricter mark and never touches
        `holds_secret`/`untrusted`, so a policy source escalates on its OWN terms
        (see engine `_policy_escalate`) and cannot weaken any existing catch."""
        if not any(src.get("ref") == ref and src.get("severity") == severity
                   for src in self.policy_sources):
            self.policy_sources.append({"seq": seq, "ref": ref,
                                        "type": source_type, "severity": severity})

    def mark_policy_value(self, seq: int, ref: str,
                          fingerprints: list[str] | None = None) -> None:
        """Record the distinctive VALUES read from a declared source (step 3b), by
        hash only. Additive and deduplicated; NEVER touches `holds_secret` or
        `untrusted` — a confirmed value leak escalates on its OWN terms (engine
        `_policy_value_escalate`), and this is stored separately from
        `secret_fingerprints` so a leak reason names the org-policy source, not a
        credential. `ref` is the path the values were read from, for the reason."""
        for fp in fingerprints or []:
            if fp not in self.policy_fingerprints:
                self.policy_fingerprints.append(fp)

    def taint(self, path: str, level: str, seq: int, label: str = "SECRET") -> None:
        """Label a destination path.

        Never downgrades: a path already known to hold an exact copy of a secret
        does not become merely "derived" because it was written to again.
        """
        existing = self.tainted_paths.get(path)
        if existing and existing.get("level") == "exact" and level != "exact":
            return
        self.tainted_paths[path] = {"label": label, "level": level, "from_seq": seq}

    def is_clean(self) -> bool:
        return not self.untrusted and not self.holds_secret

    # --------------------------------------------------------- persistence
    def to_dict(self) -> dict:
        # ⚠ PRIVATE FIELDS DO NOT CROSS THE JSON BOUNDARY. `_authored_index` is
        # an in-memory set for O(1) membership; `asdict` swept it into the state
        # file and 22 tests died on "Object of type set is not JSON
        # serializable". Stripping by prefix rather than by name so the next
        # derived field cannot reintroduce it.
        return {k: v for k, v in asdict(self).items() if not k.startswith("_")}

    @classmethod
    def from_dict(cls, data: dict, session_id: str = "") -> "SessionState":
        """Tolerant by design — but never SILENTLY tolerant about taint.

        A state file from an older build, or one a user hand-edited, must not
        crash the hook: a guard that cannot load its state should keep running,
        not fail to run.

        ⚠ ON SCHEMA SKEW THE SESSION IS TREATED AS MAXIMALLY LABELLED.
        Neither obvious option is right. Starting fresh discards real taint,
        which is precisely the failure this check exists to prevent. Refusing to
        run turns a version skew into a blocked developer, which is how a guard
        gets uninstalled. So the session is assumed to hold everything it might
        have held: untrusted, and holding a secret.

        FAIL CLOSED AT SINKS, OPEN EVERYWHERE ELSE — the same phrasing
        `hook_entry` already uses for its own fallback. Reads, edits and local
        work continue untouched; it is exits that ask or deny. The developer
        keeps working and nothing leaves on a premise nobody checked.

        TWO WAYS TO DETECT SKEW, and the second is the one that fires today:

          an explicit `schema_version` that differs from SCHEMA_VERSION
          a key in the file that this class does not have — which IS the bug,
          stated as a condition: `from_dict` would discard it, and discarding a
          key that carried taint is how the taint disappears
        """
        if not isinstance(data, dict):
            data = {}
        known = {f for f in cls.__dataclass_fields__}
        found_version = data.get("schema_version")
        unknown = sorted(set(data) - known - {"schema_version"})
        skewed = bool(unknown) or (found_version is not None
                                    and found_version != SCHEMA_VERSION)

        clean = {k: v for k, v in data.items() if k in known}
        state = cls(**clean) if clean else cls()
        if session_id:
            state.session_id = session_id

        if skewed:
            # ⚠ MAXIMALLY LABELLED. Not "keep what loaded" — what loaded is
            # exactly what cannot be trusted to be complete.
            state.untrusted = True
            state.holds_secret = True
            # ⚠ AND THE VERSION IS STAMPED TO CURRENT, because the file this
            # session writes NEXT is current-shaped — carrying the old number
            # forward would label a file that is not that schema. The evidence
            # that skew happened does not live in the number; it lives in
            # `schema_skew` and in the labels, all three of which persist.
            state.schema_version = SCHEMA_VERSION
            state.schema_skew = (
                f"state file schema {found_version if found_version is not None else 'unversioned'}"
                f" != {SCHEMA_VERSION}"
                + (f"; unrecognised key(s): {', '.join(unknown)}" if unknown else "")
                + " — session assumed untrusted and holding secrets")
        return state


# --------------------------------------------------------------------- the world
class World(Protocol):
    """Everything the engine needs from outside itself.

    The engine is a pure function of (action, state, world). It opens no files,
    spawns no processes and imports nothing that does — so the entire policy is
    testable without a git repo or a temp directory, and the one place that
    touches the real machine is core/probes.py.

    This also keeps the engine honest about its own cost: every call through
    this interface is visible in the signature rather than hidden in a helper.
    """

    def read_text(self, path: str) -> str | None:
        """File contents, or None if unreadable. Used to fingerprint values."""
        ...

    def sync_roots(self) -> tuple[str, ...] | None:
        """Directories a cloud client uploads from — OneDrive, Dropbox, iCloud,
        Google Drive.

        ⚠ A SECOND CARRIER, AND THE UNKNOWN DIRECTION IS THE OPPOSITE OF
        `case_insensitive`'s, WHICH LOOKS INCONSISTENT AND IS NOT.

            wrong case-insensitive   two REAL directories MERGE, and a path
                                     outside the project reads as inside.
                                     A BYPASS, and silent. So None -> the noisy
                                     branch (treat as case-sensitive).
            missed sync root         a copy that should have been flagged is
                                     not. UNDER-denies. So None -> the quiet
                                     branch (treat as not a sync root).

        The rule is the same in both: **`None` takes whichever branch cannot
        create a silent bypass.** For case that means denying more; here it
        means denying less, because the failure directions are mirrored.

        Detection is IO, so it lives in core/probes.py — `decide()` is a pure
        function of (action, state, world).
        """
        ...

    def case_insensitive(self, root: str) -> bool | None:
        """Does THIS root's filesystem treat `A.txt` and `a.txt` as one file?

        ⚠ PER ROOT, NOT PER MACHINE, AND THAT IS THE WHOLE REASON IT IS A
        METHOD AND NOT A FLAG. A boolean per machine is wrong on both platforms
        this runs on:

            Windows   per-DIRECTORY case sensitivity has existed since 1803
                      (`fsutil file setCaseSensitiveInfo`), and WSL sets it on
                      the directories it creates. A repo checked out there is
                      case-SENSITIVE on a case-INSENSITIVE machine.
            macOS     APFS defaults to case-insensitive, and a case-sensitive
                      volume is one `diskutil` away. Developers who work on
                      Linux servers make them on purpose.

        A multi-root workspace can therefore span both, which is exactly the
        configuration a single flag cannot describe.

        ⚠ `None` MEANS "COULD NOT TELL", AND IT IS NOT `False`. Detection is IO
        and IO fails — an unwritable root, a permission error, a race. The
        caller must decide what to do with an unknown rather than inherit a
        guess, and the engine treats None as case-SENSITIVE because that is the
        conservative direction for a boundary. See `is_inside_project`.
        """
        ...

    def staged_files(self, cwd: str) -> tuple[str, ...] | None:
        """Absolute paths actually staged in the index — `git diff --cached`.

        CLAUDE.md rule #7: at push time inspect what is really in the commit,
        not a staged list we maintained ourselves. That handles .gitignore
        correctly and catches `git add -f`.

        Returns None when the index could not be inspected at all (not a repo,
        git missing, timeout) and () when it was inspected and nothing is
        staged. Those are different facts: the first means fall back to what we
        tracked, the second means there is genuinely nothing to carry. Folding
        them together would make an empty index look like a stale taint list.
        """
        ...

    def staged_content(self, cwd: str) -> str | None:
        """The actual staged diff text — `git diff --cached`.

        Fingerprinting this catches a secret in a file we never saw written:
        `git add -f` on an ignored file, or an edit made outside the agent's
        tool calls. The path list alone cannot see that.
        """
        ...

    def environment(self) -> dict[str, str]:
        """The environment the hook was started with (item B, docs/110 §B).

        Read only when a command prints environment variables, to fingerprint
        the values of the secret-looking ones. OPTIONAL: a World without it
        (replay, and every World written before it) is read as `{}` by
        `core/sources._hook_environment` — the session is still marked, and no
        value is known.
        """
        ...

    def configured_remotes(self, cwd: str) -> dict | None:
        """The repo's configured remotes, for the pre-existing-remote exemption.

        Returns `{"toplevel": <abs repo root>, "remotes": {name: url, ...},
        "upstream_remote": <name|None>}`, or None when it cannot be determined
        (not a repo, git missing, any error) — and None is the fail-safe that
        keeps today's DENY. Read once at session start to FREEZE the URL set
        into `SessionState.preexisting_remotes`, and again (live) at push time
        so the command's target can be resolved to its CURRENT url and checked
        against that frozen set. `upstream_remote` is the remote the current
        branch tracks, so a bare `git push` resolves like a spelled-out one.
        """
        ...

