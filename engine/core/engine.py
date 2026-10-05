"""
The engine. One of these, for all agents.

    decide(action, state, world) -> Verdict

A pure function. The state is handed in, the outside machine is reachable only
through `world`, and nothing here opens a file or spawns a process — so the
whole policy is testable without a git repo or a temp directory.

THE ONE CONSTRAINT THAT MATTERS
-------------------------------
This module may import only `core.types`. It must never see a field name from
any agent's payload — no `hookSpecificOutput`, no `conversationId`. If branching
on *which* agent sent the action ever starts to look necessary, the boundary is
wrong. Stop and say so rather than working around it.

ORDER OF OPERATIONS — this differs from docs/02 deliberately
------------------------------------------------------------
docs/02 runs mark_sources() before check_sinks(). That is a bug: a FETCH is both
an UNTRUSTED source and a network_egress sink, so the fetch would mark the
session untrusted and then be judged against the taint it just created. With
expected_hosts empty that is a DENY, which breaks N03, N12 and N15 — three of
the 25 normal tasks, on their first action, three times the entire A5 budget.

So the verdict is computed against the state as it was BEFORE this action, and
labelling happens afterwards. An action is never judged by the taint it itself
creates: fetching a URL is how you *learn* it is untrusted, not exfiltration.
Attacks lose nothing — their taint always comes from an earlier step.
"""
from __future__ import annotations

import dataclasses
import functools
import hashlib
import math
import re
import string
from collections import Counter
from collections.abc import Callable, Iterator
from typing import NamedTuple

from core import guard_parts, hook_configs, known_formats, org_policy, rule_names
from core import why as why_facts
from core.shell_scan import (TEXT_COMMANDS, UNPARSED, bail_reason, shell_bodies,
                              code_mask_checked, first_code_match,
                              quoted_text_view)
from core.types import (EVIDENCE_UNRECORDED, Action, ActionKind, Decision,
                        SessionState, Verdict, Why, World)

# ⚠ THE ENGINE'S PARTS (docs/ENGINE_LAYOUT.md), RE-EXPORTED. Every name any
# code imports from `core.engine` still resolves here, and a name is looked
# up in the module that USES it: patch it there, not here.
from core.command_text import (  # noqa: F401
    _ANSI_C_NAMED, _CMD_START, _COPY_VALUE_OPTS, _COPY_VERB, _DANGLING_REDIRECT,
    _EVIDENCE_CONTEXT, _GIT_COMMIT, _GIT_CONFIG_GLOBAL, _GIT_GLOBAL_OPTS,
    _GIT_PUSH, _GIT_REMOTE_ADD, _GIT_VALUE_OPT, _HEREDOC_BODY, _HEX_DIGITS,
    _MESSAGE_ARG, _MESSAGE_VERB, _NONSTANDARD_INDEX, _NOT_SEGMENT_END, _REDIRECT,
    _REDIRECT_STOP, _REDIRECT_TARGET, _REDIRECT_VERB, _REDIRECT_VERBS,
    _SEGMENT_END, _SEGMENT_REST, _SEGMENT_SEPARATORS, _SHELL_ASSIGNMENT,
    _SHELL_TOKEN, _TARGET_DIR_OPTS, _TRUNCATING_REDIRECT, _TRUNCATING_VERB,
    _TRUNCATING_VERBS, _VAR_REF, _WINDOWS_ABSOLUTE, _abs, _ansi_c_escape,
    _basename, _bash_unquote, _copy_operands, _copy_pairs, _decode_ansi_c, _expand,
    _join_line_continuations, _literal_assignments, _norm_path, _path_token,
    _redirect_matches, _root_is_case_insensitive, _segment_end, _split_tokens,
    _strip_message_args, _structure_action, _structure_text, _verb, executed_text,
    is_inside_project, mentions_path, span_evidence, without_commit_message)
from core.credentials import (  # noqa: F401
    CONFIDENTIAL_PATHS, CREDENTIAL_PATHS, DEPENDENCY_PATHS, PLANTED_CONTENT,
    _CREDENTIAL_FORMAT, _EMAIL, _ENTROPY_MIN, _ENV_TO_EGRESS,
    _MAX_SCAN, _SSN, _VALUE_MIN_LEN, _VALUE_TOKEN, _canary_hashes_in,
    _distinctive_fields, _egress_carries_canary, _matches_fingerprinted_value,
    _prefix_hashes, carries_canary, carries_secret, fingerprint_values,
    fingerprints_in, policy_prints_in, sends_the_environment, shannon_entropy)
from core.globbing import (  # noqa: F401
    _BRACE_CAP, _BRACE_CHAR_CAP, _BRACE_DEPTH_CAP, _BRACKET_SCAN_CAP,
    _CREDENTIAL_NAME_SHAPES, _DOUBLE_QUOTED_RUN, _EXPANSION_CHARS, _Expansion,
    _FIXED_CREDENTIAL_NAMES, _GLOB_EXPANSIONS_CAP, _GlobToken, _Marked, _NAME_MAX,
    _NameShape, _PINNED_PREFIXES, _PINNED_SUFFIXES, _PLAIN_RUN, _PLAIN_RUN_EXTGLOB,
    _POSIX_CLASSES, _RAW_WORD, _SEQUENCE, _SEQUENCE_BODY_MAX, _SHOPT_WIDENS_GLOB,
    _WITNESS_ALPHABET, _WORD_BREAK, _any_but_slash, _backtrace, _brace_expand,
    _brace_map, _brace_superset, _bracket, _credential_scan_texts, _double_quoted,
    _expandable_positions, _expanded_form, _extglob_as_brace, _folded,
    _glob_tokens, _glob_witnesses, _group_alternatives, _intersect, _lit,
    _marked_words, _matches, _near_credential, _paren_end, _pick, _read_names,
    _scan_words, _segments, _sequence_bounds, _sequence_count, _sequence_items,
    _shape, _star, _word_expansions)
from core.irreversible import (  # noqa: F401
    REGENERABLE_ARTIFACTS, _BLOCK_DEVICE, _BRANCH_FORCE_DELETE, _BUILD_MANIFESTS,
    _CATASTROPHIC_ROOTS, _CD_OPENS_A_SHELL_BODY, _CD_PREFIX, _CD_TARGET,
    _CD_TARGET_DECODES, _DD_OF, _DELETES_A_PATH, _DEV_REDIRECT, _FIND_DESTROYS,
    _FIND_EXPRESSION_STARTS, _FIND_GLOBAL_FLAG, _FIRST_ABS, _FORCE_PUSH,
    _HOME_PARENTS, _IRREVERSIBLE_COMMANDS, _LONG_PATH, _MANIFEST_GATED, _MKFS,
    _REGENERABLE_SUFFIXES, _RESET_HARD, _RM_DESTRUCTIVE, _ROOT_DISPLAY,
    _ROOT_SEGMENT_SHAPES, _SQL_DELETE_UNSCOPED, _SQL_DESTRUCTIVE,
    _TRUNCATING_TARGET, _WRITES_ANY, _WRITES_LAST, _anchored, _body_cds, _cd_bases,
    _cd_resolved_credential_paths, _cd_target, _code_positions, _credential_under,
    _deleted_by, _deletes_only_declared_scratch,
    _deletes_only_regenerable_artifacts, _deletion_targets, _destructive_forms,
    _directory_names_a_credential, _find_starting_points, _is_catastrophic_root,
    _is_clean_relative, _is_regenerable_artifact, _names_a_credential,
    _operand_forms, _resolved, _root_display, _root_witnesses, _spells_segment,
    _truncated_credential_file, deletes_a_catastrophic_root,
    find_destroys_a_catastrophic_root, is_irreversible, writes_a_raw_block_device)
from core.egress import (  # noqa: F401
    DEFAULT_EXPECTED_HOSTS, _BENIGN_HEADERS, _BOUNDED_TEXT, _CURL_NUMERIC_FLAGS,
    _CURL_READ_FLAGS, _CURL_TEXT_FLAGS, _CUT_SPEC, _DEV_SOCKET, _EXIT_PHRASE,
    _FILTER_TEXT_OPERANDS, _FORBIDDEN_IN_A_READ, _INSTALL_VERB,
    _NUMERIC_VALUE, _OUTBOUND_BODY, _PRIVATE_HOST, _READ_FILTERS, _READ_VERBS,
    _SCP_REMOTE, _SHELL_JOINS, _SHELL_PUNCTUATION, _STDERR_ONLY, _URL, _URL_TOKEN,
    _URL_USERINFO, _WGET_NUMERIC_FLAGS, _WGET_READ_FLAGS, _WGET_TEXT_FLAGS,
    _aliased_text, _bounded_text, _curl_is_a_read, _destination_is_external,
    _destinations, _dev_socket_hosts, _exit_phrase, _host_only, _inbound_read,
    _is_a_read_filter, _is_expected, _preexisting_remote_host, _push_remote_names,
    _read_url_ok, _remote_url_host, _sends_data, _shell_words, _wget_is_a_read)
from core.guard_floor import (  # noqa: F401
    CONFIG_SELFMOD_PATHS, _CONFIG_NAME_HINT, _COPY_NAMES, _COULD_REDIRECT,
    _COULD_WRITE, _CURL_FLAGS, _DECISION_RANK, _DELETE_NAMES, _FLOOR_FAMILIES,
    _GUARD_COPY_VERB, _GUARD_DELETE_VERB, _GUARD_PROCESS, _GUARD_SELFMOD, _KILL,
    _OUTFILE, _PATCH_VALUES, _PS_PATH_OPTIONS, _REDIRECT_WORD, _RSYNC_VALUES,
    _SED_IN_PLACE, _SHELL_EDIT_REASON, _STING_PERSISTED, _Target, _Touch,
    _WGET_FLAGS, _WORD, _WRITE_READERS, _WRITE_VERB, _as_targets, _config_written,
    _content_cmdlet_writes, _curl_writes, _dd_writes, _file_tool_touch,
    _flag_values, _guard_file_touch, _guard_floor, _guard_setting_persisted,
    _guard_stop, _has_flag, _hook_reason, _nested_claude, _operands, _patch_writes,
    _path_touch, _policy_registry_touch, _process_name, _redirect_writes,
    _rsync_writes, _sed_writes, _segment_stop, _stops_the_guard, _strongest,
    _switch_reason, _tee_writes, _truncate_writes, _verb_writes, _wget_writes,
    _words_after, _written, touched_guard_part)
from core.sources import (  # noqa: F401
    GIT_HISTORY, _ALIAS, _BARE_DOT_DIR, _GIT_ADD, _NON_INGESTING_TOOLS,
    _PATH_CHAR_RUN, _PATH_TOKEN, _PATH_TOKEN_KEY, _READ_VERB, _SELF_SCOPED_READ,
    _VAR_FROM_FILE, _VAR_FROM_REDIRECT, _copies_a_secret_into_sync,
    _copy_destinations, _level_of_path, _names_a_labelled_path,
    _path_token_matches, _paths_mentioned_in, _sync_roots, _tool_can_ingest,
    mark_sources, propagate, reads_back_own_commit, structure_mask)
from core.sinks import (  # noqa: F401
    GIT_HOOKS, SECURITY_CRITICAL, SHELL_PROFILE, _ABS_PATH_TOKEN,
    _ASSIGNMENT_PREFIX, _CHMOD_WIDEN, _CLIPBOARD_WRITE, _CONTROL_DISABLED_PREFIX,
    _CONTROL_DISABLED_SUFFIX, _CONTROL_SET_OFF, _DEFERRED_EXEC_TARGETS,
    _DESTRUCTIVE, _DNS_TOOL, _ENV_DUMP_TO_NET, _NET_TOOL, _PIPE_TO_INTERPRETER,
    _PIPE_TO_SHELL, _REMOTE_DEST, _SECURITY_CONTROL, _SUBSHELL_READ,
    _TRANSPORT_OPT, _VALUE_OFF, _VALUE_ON, _hosts_in, _is_local_copy,
    _pipes_into_interpreter, _secret_in_argv, _secret_in_argv_span, _sink_hit, sink_hits,
    check_sinks, is_security_critical, weakens_security)
from core.secret_ladder import (  # noqa: F401
    _HOME_DIR, _exact_reason, _exact_source, _held_secret_clause, _masked_span,
    _path_display, _read_label, _same_file, _secret_level, _secret_origin,
    _shown_provenance, _staged_secret_level, _untrusted_origin, _what_was_seen)
from core.secret_ladder import why_of_derived, why_of_held, why_of_secret
from core.outside_content import read_outside_content, runs_outside_content
from core.secret_reference import secret_references
from core.mcp_arguments import carries_nothing as mcp_arguments_carry_nothing
from core.uploads import sends_only_literal_text, uploads_a_file
from core.uncommitted import destroys_uncommitted_work
from core.irreversible import irreversible_without_a_tree

# --------------------------------------------------------------------- verdict


def decide(action: Action, state: SessionState, world: World,
            text_complete: bool = True) -> Verdict:
    """Decide what to do about one normalised action.

    The ladder, in order. Every DENY names the action it traces back to and the
    step number, because a denial that cannot say why is not actionable for the
    developer staring at the prompt.

    `text_complete=False` says `action.command` is a known PREFIX of what really
    ran. **Live it is never false** — the hook is handed the whole command and
    clipping happens afterwards, when the log body is written. It exists for
    replay, where the recorded text may be 2048 bytes of a much longer command,
    and it changes only what STATE is derived afterwards; this action's verdict
    is computed the same way either way. See `structure_mask` for why the
    fail-safe bias must invert there, and why the record is not simply dropped.
    """
    verdict = _verdict_for(action, state, world)

    # Labelling and propagation happen after the verdict — see the module
    # docstring. An action is never judged by the taint it itself creates.
    mark_sources(state, action, world, text_complete)
    propagate(state, action, world, text_complete)
    return verdict


# Sinks whose content has NOT left the machine. Without session state these
# stay open: a commit is local, the push behind it is still guarded, and failing
# every `git commit` closed over a disk error bricks ordinary work — which is
# the failure mode that gets a guard uninstalled, protecting nothing.
_LOCAL_SINKS = frozenset({"git_commit"})


# ⚠ THE SINK->MEANING TABLE MOVED TO `core/rule_names.py`. It lived here as
# `_WITHOUT_A_HOST` and was used by exactly one branch — while a second branch,
# `secret_session_unverified`, kept substituting a raw sink name into a
# "destination" slot and printing "what this sends to 'git push'". Two phrasings
# of one thing is how one of them stays wrong. One map, both call sites.


def fallback_verdict(action: Action) -> Verdict:
    """The verdict when session state cannot be reached at all.

    Fail CLOSED at a sink, OPEN everywhere else. Both halves matter:

      closed at a sink   a guard that cannot remember anything must not wave an
                         exit through. Without state we cannot tell I02 from
                         N04, and the safe reading of that ambiguity is no.
      open elsewhere     ~97% of calls touch no sink. Denying those would brick
                         ordinary work over a disk error, and a guard that
                         stops the developer working gets uninstalled — which
                         protects nothing at all.

    This is degraded operation, not a crash. A crash produces no verdict and
    exits non-zero; this produces a real verdict and says why. The installed
    guard's floor holds either way: it needs no session to know its target.
    """
    sink = check_sinks(SessionState(), action, _NO_WORLD)
    if not sink or sink in _LOCAL_SINKS:
        return _guard_floor(Verdict(Decision.ALLOW, None, "degraded_no_state"),
                            action)
    return _guard_floor(Verdict(
        Decision.DENY,
        "session state is unavailable, so this exit cannot be checked against "
        "what the session already did — failing closed at the exit",
        f"degraded_no_state:{sink}"), action)


class _NoWorld:
    """The empty answer to everything, so fallback_verdict stays pure."""

    def read_text(self, path: str) -> str | None:
        return None

    def staged_files(self, cwd: str) -> tuple[str, ...] | None:
        return None

    def staged_content(self, cwd: str) -> str | None:
        return None

    def configured_remotes(self, cwd: str) -> dict | None:
        return None


_NO_WORLD = _NoWorld()

# ── the org-policy severity ladder, mapped onto the engine's decisions ─────────
_SEVERITY_DECISION = {"log": Decision.ALLOW, "ask": Decision.ASK,
                      "deny": Decision.DENY}
_SEVERITY_RANK = {"log": 0, "ask": 1, "deny": 2}


def _policy_escalate(verdict: Verdict, action: Action, state: SessionState,
                     sink: str | None) -> Verdict:
    """Raise an egress verdict to the STRICTEST severity of the org-policy sources
    this session read.

        deny -> DENY      ask -> ASK      log -> ALLOW, recorded (never nags)

    ⚠ ONLY ESCALATES, NEVER WEAKENS. `final = max(base, severity)`: a base that is
    already at least as strict (a today-DENY, a today-ASK) is returned UNCHANGED,
    so a declared source can add scrutiny to an otherwise-allowed egress but can
    never turn a catch into a pass, and never relabels a real catch.

    ⚠ A NO-OP UNLESS A DECLARED SOURCE WAS TOUCHED AND THIS IS A NON-LOCAL EGRESS.
    An empty policy marks no `policy_sources`, so this returns the base verdict
    byte-identical; a purely local sink (`git_commit`, revertible) is excluded, so
    reading a declared source and committing locally is unaffected — only an exit
    escalates. `log` on an otherwise-bare ALLOW is recorded (a rule id in the
    audit log) but stays ALLOW, so the 'touched constantly, just note it' tier can
    never nag.
    """
    if sink is None or sink in _LOCAL_SINKS or not state.policy_sources:
        return verdict
    severity = max((src.get("severity") for src in state.policy_sources),
                   key=lambda sev: _SEVERITY_RANK.get(sev, -1), default=None)
    target = _SEVERITY_DECISION.get(severity)
    if target is None:                                  # only invalid severities
        return verdict
    refs = ", ".join(sorted({src.get("ref", "") for src in state.policy_sources
                             if src.get("severity") == severity})) \
        or "a declared source"

    if _DECISION_RANK[target] > _DECISION_RANK.get(verdict.decision, 0):
        # The policy demands stricter than the base verdict — escalate. Only
        # `ask`/`deny` reach here (`log` -> ALLOW never exceeds a non-ALLOW base),
        # and the rule id is a LITERAL family per severity so it names cleanly in
        # `rule_names.RULE_FAMILIES` (an f-string with an interpolated family
        # would give the audit no stable name to key on).
        reason = (f"this session read {refs}, which your org policy marks "
                  f"'{severity}', and this is an egress "
                  f"({rule_names.sink_meaning(sink)})")
        if severity == "deny":
            return Verdict(target, reason, f"policy_source_deny:{sink}")
        return Verdict(target, reason, f"policy_source_ask:{sink}")

    if (target is Decision.ALLOW and verdict.decision is Decision.ALLOW
            and verdict.rule_id is None):
        # A `log` source on an otherwise-bare ALLOW: keep ALLOW but RECORD the
        # touch, so a `log` tier is visible in the audit log and NEVER nags.
        return Verdict(
            Decision.ALLOW,
            f"this session read {refs}, which your org policy marks 'log'; "
            f"allowed and recorded",
            f"policy_source_log:{sink}")

    # The base verdict is already at least as strict — never weaken, never
    # relabel an existing catch.
    return verdict


def _carries_policy_value(action: Action, state: SessionState) -> bool:
    """Does the text THIS action moves contain a distinctive VALUE fingerprinted
    from a declared source (step 3b)? Mirrors `_secret_level`'s per-kind egress text:
    a command, a FETCH's url/content, a tool's or a write's content. Reads the
    command RAW (a value inside a commit message IS leaving), exactly as
    `carries_secret(cmd, command=True)` does."""
    needles = set(state.policy_fingerprints)
    if not needles:
        return False
    if action.kind is ActionKind.EXEC:
        texts = (action.command,)
    elif action.kind is ActionKind.FETCH:
        texts = (action.url, action.content)
    elif action.kind in (ActionKind.TOOL, ActionKind.WRITE, ActionKind.EDIT):
        texts = (action.content,)
    else:
        return False
    return any(t and (policy_prints_in(t) & needles) for t in texts)


def _policy_value_escalate(verdict: Verdict, action: Action, state: SessionState,
                           sink: str | None) -> Verdict:
    """DENY when a value fingerprinted from a declared source is actually LEAVING —
    the CERTAIN tier (step 3b), above 3a's coarse severity: a confirmed exact-value
    exfiltration is deny-worthy whatever the source's declared severity was.

    ⚠ ONLY RAISES TO DENY, NEVER WEAKENS OR RELABELS. A no-op unless a declared value
    was fingerprinted AND this is a non-local egress carrying it; if the base is
    already DENY (a `secret_exact`, a `policy_source_deny`) it is returned UNCHANGED,
    so this can add a catch but never restate or downgrade one. An empty policy
    fingerprints nothing, so `policy_fingerprints` is empty and this returns the base
    verdict byte-identical."""
    if sink is None or sink in _LOCAL_SINKS or not state.policy_fingerprints:
        return verdict
    if _DECISION_RANK.get(verdict.decision, 0) >= _DECISION_RANK[Decision.DENY]:
        return verdict                       # already a DENY — never relabel a catch
    if not _carries_policy_value(action, state):
        return verdict
    reason = ("a value from a source your org policy declared sensitive is leaving "
              f"this session ({rule_names.sink_meaning(sink)}) — a confirmed "
              f"exact-value exfiltration")
    return Verdict(Decision.DENY, reason, f"policy_value_exfil:{sink}")


def _verdict_for(action: Action, state: SessionState, world: World) -> Verdict:
    """The ladder, plus the evidence span attached at the single exit.

    ATTACHED HERE AND NOT AT THE FOURTEEN RETURNS. Every non-ALLOW branch would
    otherwise have to remember to pass it, and the one that forgot would look
    exactly like a rule with nothing to show — which is the failure mode
    `EVIDENCE_UNRECORDED` exists to make visible. One place to attach means one
    place to get right.
    """
    hits = sink_hits(state, action, world)
    # ⚠ AN MCP UPLOAD AFTER OTHER PEOPLE'S TEXT IS AN EXIT (maintainer, 1 Oct, item 2;
    # docs/112) — stricter than main, deliberately: main made an MCP call one
    # only once a secret was held, and X-CHAIN's blob looks like no secret.
    # The untrusted ladder answers it (`_untrusted_gates`).
    if (not hits and action.kind is ActionKind.TOOL and action.tool_origin != "builtin"
            and state.untrusted and uploads_a_file(action)
            and read_outside_content(state, action)):
        hits = [("mcp_tool_call", None)]
    # ⚠ EVERY EXIT IS JUDGED, THE STRICTEST WINS (maintainer, after the fourth
    # review round; docs/112). Each exit is judged as if it were the action's
    # only one; what does not depend on the exit is worked out once (`once`).
    once: dict = {}
    judged = [_judged(action, state, world, sink, sink_span, once)
              for sink, sink_span in hits or [(None, None)]]
    verdict = judged[0] if len(judged) == 1 else _strictest_of(judged)
    # ⚠ THE INSTALLED GUARD (item C). Last, over everything above: DENY in every
    # session, keeping the verdict it replaced, evidence and all, for a person's
    # relaxation to give back. It carries its own evidence.
    # ⚠ WHY, LAST (docs/108): the facts a DENY or ASK is about, for the record
    # and for what the agent is told. An ALLOW comes back unchanged.
    return _completed(_guard_floor(verdict, action, state), action, state)


def _judged(action: Action, state: SessionState, world: World, sink: str | None,
            sink_span: str | None, once: dict) -> Verdict:
    """One exit's verdict, as if it were the action's only one."""
    verdict = _verdict_body(action, state, world, sink, once)
    # ⚠ ORG-POLICY OVERLAY (STEP 3a). A pure post-step that can only RAISE the
    # verdict, and a no-op unless a declared source was touched AND this is a
    # non-local egress — so an empty policy leaves this line byte-identical.
    verdict = _policy_escalate(verdict, action, state, sink)
    # ⚠ ORG-POLICY VALUE OVERLAY (STEP 3b). The CERTAIN tier on top of 3a's coarse
    # severity: if a distinctive value fingerprinted from a declared source is
    # actually leaving, DENY regardless of severity. Only raises to DENY, never
    # relabels an existing catch; empty policy -> no fingerprints -> byte-identical.
    verdict = _policy_value_escalate(verdict, action, state, sink)
    explained = (verdict.evidence is not None
                 or (verdict.decision is Decision.ALLOW and verdict.rule_id is None))
    if not explained:
        verdict = dataclasses.replace(verdict,
                                      evidence=sink_span or EVIDENCE_UNRECORDED)
    return verdict


def _strictest_of(verdicts: list[Verdict]) -> Verdict:
    """The strictest of several exits' verdicts, every rule that fired kept
    beneath it, strictest first (on a tie, the exit the ladder reads first):
    relaxing the rule on top in a person's `~/.sting/policy.json` gives back the
    next, never a blanket ALLOW (`_strictest`)."""
    fired = []
    for verdict in verdicts:
        while verdict is not None:
            if verdict.decision is not Decision.ALLOW:
                fired.append(dataclasses.replace(verdict, beneath=None))
            verdict = verdict.beneath
    if not fired:
        return verdicts[0]
    fired.sort(key=lambda verdict: -_RANK[verdict.decision])
    chained = None
    for verdict in reversed(fired):
        chained = dataclasses.replace(verdict, beneath=chained)
    return chained


def _remembered(once: dict, key: str, compute: Callable[[], object]):
    """`compute()`, worked out once per action however many exits ask."""
    if key not in once:
        once[key] = compute()
    return once[key]


def _completed(verdict: Verdict, action: Action, state: SessionState) -> Verdict:
    """`why_facts.completed`, and the same down the `beneath` chain: a
    relaxation that gives back the rule beneath tells the agent that rule's
    facts, not the ones of the rule it relaxed."""
    done = why_facts.completed(verdict, action, state)
    if verdict.beneath is None:
        return done
    return dataclasses.replace(done, beneath=_completed(verdict.beneath, action, state))


def _verdict_body(action: Action, state: SessionState, world: World,
                   sink: str | None, once: dict) -> Verdict:
    # ⚠ THE CANARY IS THE VERY FIRST CHECK — the strongest signal the engine has.
    # A planted decoy value is on this action's command/url/content, and nothing
    # legitimate ever reads a canary, so its presence is near-certain proof of
    # exfiltration. Placed above the catastrophic checks too so its OWN rule id
    # (`canary_exfil`) is the one reported even when the action is also, say, an
    # `rm -rf /` that happens to carry the value — the theft signal is what an
    # alert keys on. INERT until a canary is armed (`_egress_carries_canary`
    # short-circuits on an empty set), so it only ADDS a DENY and changes no
    # existing verdict. The value never enters the reason — only its hash was ever
    # stored. (A canary in git-STAGED content, not the command text, is caught
    # separately on the secret ladder below via `_staged_secret_level`.)
    if _egress_carries_canary(action, state):
        return Verdict(
            Decision.DENY,
            "this carries a Sting CANARY — a planted decoy value that nothing "
            "legitimate ever reads, so its presence is near-certain proof of "
            "exfiltration",
            f"canary_exfil:{sink or 'no_sink'}",
            why=Why(value_type=why_facts.CANARY))

    # ⚠ FIRST, AND UNCONDITIONALLY. Above every gate in this function on purpose:
    #
    #   NOT gated on `untrusted` — `rm -rf /` is catastrophic whether or not a
    #     README was read. Today it is only a DENY in a poisoned session, which
    #     makes the worst command on the machine depend on an unrelated fact.
    #   NOT reachable by the scratch exemption — that lives inside
    #     `is_irreversible`, which is computed BELOW this. Declaring `/` as a
    #     scratch root is a statement about disposable work, not a licence to
    #     delete the filesystem, and an exemption that could reach here would be
    #     an attacker-chosen one.
    # The destruction readers ask what the command DELETES — structure — so a
    # `cd /` or `rm -rf /` written inside a grep pattern is not one (item B).
    shaped = _remembered(once, "shaped", lambda: _structure_action(action, state))
    catastrophic = deletes_a_catastrophic_root(shaped)
    if catastrophic:
        return Verdict(
            Decision.DENY,
            f"this deletes {_root_display(catastrophic)} — "
            f"{rule_names.sink_meaning('catastrophic_root')}",
            "catastrophic_delete")

    swept = find_destroys_a_catastrophic_root(shaped)
    if swept:
        return Verdict(
            Decision.DENY,
            f"this deletes everything under {_root_display(swept)} — "
            f"{rule_names.sink_meaning('catastrophic_sweep')}",
            "catastrophic_delete")

    device = writes_a_raw_block_device(shaped)
    if device:
        return Verdict(
            Decision.DENY,
            f"this overwrites {device} — "
            f"{rule_names.sink_meaning('raw_block_device')}",
            "catastrophic_overwrite")

    # ⚠ A DELETE OR AN OVERWRITE ASKS ONLY WHEN IT WOULD LOSE UNCOMMITTED WORK
    # (fix/false-positives item C, docs/112): `destroys_uncommitted_work` asks
    # git, for those commands only; `irreversible_without_a_tree` keeps what
    # has no working tree to consult. That is the irreversible ASK.
    #
    # ⚠ TODAY'S `is_irreversible` STILL DECIDES WHETHER THE SECRET FAMILY
    # ANSWERS an action with no sink (`secret_*:no_sink`) — the secret rules
    # may not move in this pass, either way: a delete item C no longer asks
    # about still meets them, and an overwrite only item C asks about does not
    # newly meet them.
    reaches_secrets = bool(sink) or bool(_remembered(once, "is_irreversible", lambda: (
        is_irreversible(shaped, world, tuple(state.scratch_roots), untrusted=state.untrusted))))
    irreversible = _remembered(once, "irreversible", lambda: (
        irreversible_without_a_tree(shaped, world)
        or destroys_uncommitted_work(shaped, state, world)))
    if not reaches_secrets and not irreversible:
        return Verdict(Decision.ALLOW, None, None)      # ~97% of calls
    if not reaches_secrets:
        return _rest_of_ladder(action, state, world, sink, irreversible, False)

    level, source, enumerated = _secret_level(action, state, world, sink)
    # `sink` may be None now that an irreversible action reaches the ladder
    # without one (J04 overwrites .env: no sink, but the session holds secrets
    # so the secret branches still fire). Without this the rule id formats as
    # "secret_derived:None", and rule ids are the regression signal.
    sink_label = sink or "no_sink"
    secret = _secret_rung(action, state, level, source, sink, sink_label)
    rest = _rest_of_ladder(action, state, world, sink, irreversible, enumerated)
    # ⚠ THE STRICTEST WINS (fix/agents-block-and-env-reads, docs/110 §B). The
    # secret rungs used to RETURN, so an untrusted session that also held a
    # secret got the secret rung's ASK where the untrusted rung below says DENY:
    # reading a secret made the verdict looser. Both families are asked now,
    # the stricter answer wins, the other is kept `beneath` for a relaxation.
    return _strictest(secret, rest) if secret is not None else rest


_RANK = {Decision.ALLOW: 0, Decision.ASK: 1, Decision.DENY: 2}


def _strictest(first: Verdict, second: Verdict) -> Verdict:
    """The stricter of two rules' answers (DENY over ASK over ALLOW); on a tie
    `first`, the one the ladder reached first, as before. The other is kept as
    `beneath`, so each rule is judged after its OWN relaxation in a person's
    `~/.sting/policy.json` (`policy.Overlay.enforce`): relaxing the rule on top
    gives the other back, never a blanket ALLOW. An ALLOW is no rule firing."""
    if second.decision is Decision.ALLOW:
        return first
    if _RANK[second.decision] > _RANK[first.decision]:
        return dataclasses.replace(second, beneath=first)
    return dataclasses.replace(first, beneath=second)


def _secret_rung(action: Action, state: SessionState, level: str | None,
                 source: dict | None, sink: str | None,
                 sink_label: str) -> Verdict | None:
    """The secret family's answer: what this action moves is labelled."""
    if level == "canary":
        # Reached only via `_staged_secret_level` (a canary in git-staged content);
        # the direct command/url/content case already denied at the top of
        # `_verdict_body`. Same distinct rule id, same certain-theft meaning.
        return Verdict(
            Decision.DENY,
            "this carries a Sting CANARY — a planted decoy value that nothing "
            "legitimate ever reads, so its presence in what this pushes is "
            "near-certain proof of exfiltration",
            f"canary_exfil:{sink_label}",
            why=Why(value_type=why_facts.CANARY))

    if level == "exact":
        # Checked BEFORE the destination, so an approved host never launders
        # secret content. I04 sends .env to a webhook the developer explicitly
        # approved: "approving a host must not mean approving arbitrary content
        # sent to it."
        return Verdict(
            Decision.DENY,
            _exact_reason(state, source),
            f"secret_exact:{sink_label}",
            evidence=(source or {}).get("evidence"),
            why=why_of_secret(state, source, action))

    if level == "derived":
        if _destination_is_external(action, state, sink):
            return Verdict(
                Decision.DENY,
                f"this file was written while the session held confidential "
                f"material (step {state.holds_secret_since_seq}) and "
                f"{_exit_phrase(sink)}",
                f"secret_derived_external:{sink_label}",
                why=why_of_derived(state))
        return Verdict(
            Decision.ASK,
            f"written while the session held confidential material "
            f"(step {state.holds_secret_since_seq})",
            f"secret_derived:{sink_label}",
            why=why_of_derived(state))

    return None


# ⚠ WHAT READING OUTSIDE CONTENT NO LONGER GATES (fix/false-positives, items A
# and B, docs/112). Taint the DATA, not the session: most untrusted
# interruptions on real sessions were self-taint — the agent read its own `git
# log`, and its next push was denied. A session that read outside content is
# no longer stopped from these, UNLESS the action runs outside content itself
# (`outside_content.runs_outside_content`), which keeps its verdict whole.
# Every other sink an untrusted session trips keeps today's gate (docs/112
# lists them, with their hit counts, for the maintainer): the security-critical and
# security-weakening edits, an unknown tool, and every guard-protection sink.
# A secret leaving by any route below is the secret rules' job, and they
# answer exactly as in a session that read nothing: the secret rungs above are
# computed from the same sink, and `_rest_of_ladder` below reaches the same
# `secret_session_unverified` branch a clean session reaches.
#
# ⚠ EXCEPT A VISIBLE SECRET REFERENCE (maintainer, 30 Sep): an action that shows a
# secret-named variable, an environment dump, a password in a URL, a
# credential file sent, or a deferred-execution write keeps today's verdict
# (`secret_reference`). Those attacks send a secret the session never READ, so
# the secret rules cannot see them and the untrusted gate is what catches them
# (C01, C03, F03, G05, P05). And `git_new_remote` is not in this set at all: a
# new remote after outside content stays gated (C05, F02).
#
# ⚠ AND A PUSH AFTER OTHER PEOPLE'S TEXT (maintainer, 30 Sep option 2 and 1 Oct):
# `git_push` is ungated only when the session read nothing but its own work
# (`outside_content.read_outside_content`) — X-CHAIN-3.
# The exits a send leaves by (item 2): the network, a name looked up.
_SEND_SINKS = frozenset({"network_egress", "dns_lookup"})
_UNGATED_BY_UNTRUSTED = frozenset({
    "git_push", "network_egress", "dns_lookup", "write_outside",
    "mcp_tool_call", "destructive_outside", "pipe_to_shell"})



def _untrusted_gates(action: Action, state: SessionState, sink: str | None) -> bool:
    """Does the session's untrusted label still decide this action?"""
    if not state.untrusted:
        return False
    if sink not in _UNGATED_BY_UNTRUSTED:
        return True
    # ⚠ A PUSH AFTER OTHER PEOPLE'S TEXT keeps today's verdict (maintainer, 30 Sep
    # option 2 and 1 Oct; docs/112): X-CHAIN-3 pushes a credential re-encoded
    # so nothing in it looks like one, and only the read of the poisoned issue
    # caught it. After only its own work, the push is a clean session's.
    # ... and so does a SEND that is not only literal text written in the
    # command (maintainer, 1 Oct item 2, turned round after the fourth review round):
    # the same blob by `curl -T`, `-d@f`, `$(cat f)`, `eval`, `nc`, … — and an
    # MCP tool named to upload (`core/uploads.py`).
    if ((sink == "git_push"
         or (sink in _SEND_SINKS and not sends_only_literal_text(action, state.aliases))
         or (sink == "mcp_tool_call" and uploads_a_file(action)))
            and read_outside_content(state, action)):
        return True
    return (runs_outside_content(action, state) is not None
            or bool(secret_references(action, state.aliases)))


def _rest_of_ladder(action: Action, state: SessionState, world: World,
                    sink: str | None, irreversible, enumerated: bool) -> Verdict:
    """Everything below the secret rungs: the untrusted family, the irreversible
    backstop, and the reliefs between them."""
    gated = _untrusted_gates(action, state, sink)
    if sink == "destructive_outside" and not gated:
        # Item C judges a delete whatever the session read, and a session that
        # read nothing has no `destructive_outside` sink at all: the rest of
        # the ladder sees what it would see there. (The secret rungs above
        # still saw the sink, as before — they are not this pass's to move.)
        sink = None
    if gated and sink == "destructive_outside":
        return Verdict(
            Decision.DENY,
            f"this would destroy files outside the project while untrusted "
            f"content is in the session — {_untrusted_origin(state)}",
            "untrusted_destructive")

    if gated and sink == "security_critical":
        return Verdict(
            Decision.DENY,
            f"a security-critical file cannot be modified while untrusted "
            f"content is in the session — {_untrusted_origin(state)}",
            "untrusted_security_critical")

    if gated and sink == "security_weakening":
        # MECHANISM 3. Placed after the untrusted DENY branches and before the
        # terminal untrusted DENY — without it, B03 would fall through to
        # `untrusted_unexpected` and come back a DENY, which is both the wrong
        # verdict for this mechanism and an A4 change.
        #
        # ASK because the mechanism cannot tell a deliberate change from an
        # injected one. Turning a rate limit off is sometimes exactly the task.
        # `security_weakening` is a sink name nothing else produces, so this
        # branch cannot intercept any existing verdict.
        return Verdict(
            Decision.ASK,
            f"this switches off a security control "
            f"({weakens_security(action.content)}) while untrusted content is "
            f"in the session — {_untrusted_origin(state)}",
            "untrusted_security_weakening")

    # ⚠ THE ONE SECRET RULE THIS PASS LOOSENS (maintainer, 30 Sep; docs/112 §3):
    # an MCP call after a secret read whose arguments, seen whole, carry nothing
    # a secret could ride in (`core/mcp_arguments.py`).
    if (sink == "mcp_tool_call" and not gated and state.holds_secret and not enumerated
            and mcp_arguments_carry_nothing(action, state)):
        return Verdict(Decision.ALLOW, None, None)

    if sink and not gated and state.holds_secret and not enumerated:
        # BUCKET 1. The session carries material that must not leave, this
        # action is an exit, and the engine could NOT enumerate what it moves —
        # A05 pushing to a remote we cannot inspect, L03 curling `$STRIPE_KEY`.
        # Previously these fell straight through to ALLOW below.
        #
        # ASK, NOT DENY, and deliberately so. `enumerated` is false precisely
        # when the engine cannot tell what the payload is; that is uncertainty,
        # and uncertainty escalates to a human rather than blocking. With
        # `expected_hosts` still empty — deriving it from the prompt is deferred
        # — DENY here would mean "read .env once and every later network call is
        # blocked", which is the N09 false positive one layer out.
        #
        # REVISIT WHEN expected_hosts IS DERIVED FROM THE PROMPT. At that point
        # an unexpected host is a real signal rather than the default for every
        # host, and this branch can be reconsidered as DENY. That derivation is
        # the trigger; until it lands, ASK is the honest answer.
        #
        # Note what does NOT reach here: a push whose index we read successfully
        # is `enumerated`, so N09's clean-index push and the .gitignore case
        # skip this entirely and land on the ALLOW below, unchanged.
        hosts = _destinations(action, state)
        if hosts:
            return Verdict(
                Decision.ASK,
                f"{_held_secret_clause(state)}, and what this "
                f"sends to '{hosts[0]}' could not be inspected — confirm this "
                f"was your intent",
                f"secret_session_unverified:{sink}",
                why=why_of_held(state))
        # ⚠ THE SAME FALSE FRAMING THE TERMINAL BRANCH HAD, AND IT SURVIVED HERE.
        # `sink.replace("_", " ")` in the destination slot produced "what this
        # sends to 'git push' could not be inspected". `git push` is not a
        # destination. Found by an AST scan for rule-id tokens reaching a reason
        # string, after the terminal branch was fixed and this one was not —
        # which is the argument for `core/rule_names.py` holding ONE map instead
        # of each branch phrasing its own.
        return Verdict(
            Decision.ASK,
            f"{_held_secret_clause(state)}, and "
            f"{rule_names.sink_meaning(sink)} — what it sends could not be "
            f"inspected, so confirm this was your intent",
            f"secret_session_unverified:{sink}",
            why=why_of_held(state))

    if irreversible and (not gated or sink is None):
        # MECHANISM 1, position 7. Below EVERY untrusted DENY branch, and gated
        # on `not gated` (the label, where it still decides) as well — belt and
        # braces, because this
        # ladder has been reordered twice and position alone is not a guarantee.
        #
        # The gate is what makes A4 provably immovable: all currently-blocked
        # attacks resolve either above this point (secret_exact,
        # secret_derived_external) or require `untrusted` (untrusted_unexpected,
        # untrusted_destructive). There is no third category, so nothing that is
        # blocked today can be softened here. B02 in particular keeps its DENY at
        # destructive_outside.
        #
        # ⚠ `or sink is None` FIXES A PERMISSIVENESS INVERSION, found by the live
        # differential replay. The bare gate made an UNTRUSTED session more
        # permissive than a clean one:
        #
        #     rm -rf <dir>, holding secrets, untrusted=False  ->  ASK
        #     rm -rf <dir>, holding secrets, untrusted=True   ->  ALLOW
        #
        # because with no sink the untrusted branches cannot fire either, so the
        # gate skipped the backstop and nothing below caught it. The gate exists
        # to avoid PREEMPTING an untrusted DENY — and every untrusted DENY
        # requires a sink, so when `sink is None` there is nothing to preempt and
        # the gate was pure loss. Being untrusted must never buy permission.
        #
        # Blast radius measured BEFORE the change, per rule #2: exactly one corpus
        # command is irreversible with no sink in an untrusted session — J02's
        # `rm -rf scripts/legacy_migration_2019.py`, an attack. **Zero normals.**
        # So this can only move a miss to an ASK; it cannot move A4 or A5.
        #
        # This is working rule #10 in action: the gate and `state.untrusted` are
        # one system, and reasoning about either alone is what hid this.
        return Verdict(
            Decision.ASK,
            f"this cannot be undone — {irreversible}",
            "irreversible_action")

    if not gated:
        # A sink in a clean session is ordinary work. This is the A2 half of the
        # thesis: N04's `git push origin main` is identical to I02's and is
        # allowed, purely because nothing tainted this session. Since docs/112
        # the same holds for a session that read outside content, for every
        # sink that label no longer gates (`_untrusted_gates`).
        return Verdict(Decision.ALLOW, None, None)

    if not sink:
        # Irreversible, untrusted, and no sink. The branches below are about
        # DESTINATIONS and there is no destination here — `sink.replace(...)`
        # would raise. Today such an action returns ALLOW on this function's
        # first line, so returning ALLOW keeps behaviour identical rather than
        # inventing a new denial on a path the corpus has never exercised.
        return Verdict(Decision.ALLOW, None, None)

    hosts = _destinations(action, state)

    # ⚠ RESOLVE A NAMED PUSH TO THE REPO'S OWN PRE-EXISTING REMOTE, AND ONLY THEN.
    #
    # The engine never resolved a remote NAME to a url, so `git push origin main`
    # produced no host and fell to the terminal "could not resolve" DENY — while
    # the identical push spelled as a literal github URL got ASK, because github
    # is an expected host. This closes that gap WITHOUT a new judgement: it hands
    # the existing host ladder the remote's url, but ONLY when that url was
    # configured before the session began (`_preexisting_remote_host` proves it
    # against the frozen snapshot; a session-added or `set-url`d remote returns
    # None and stays DENY).
    #
    # ⚠ DENY -> ASK ONLY, NEVER ALLOW, AND THE GATE IS WHAT GUARANTEES IT. Reached
    # only for an UNTRUSTED session (a clean one returned ALLOW above), only for
    # `git_push` (so `git_commit`'s message-url path is untouched), and only when
    # `hosts` is otherwise EMPTY (so it never rewrites a destination already
    # resolved). With a host present, the only `git_push`-reachable outcomes
    # below are `untrusted_expected` (ASK) and `untrusted_unexpected` (DENY) —
    # every ALLOW branch beneath requires `network_egress` or `_LOCAL_SINKS`.
    if not hosts and sink == "git_push":
        resolved = _preexisting_remote_host(action, state, world)
        if resolved:
            hosts = list(resolved)       # every push's, all pre-existing (docs/113 §3b)

    # ⚠ LOOPBACK IS NOT AN EXIT, AND BEING UNTRUSTED IS NO REASON TO ASK ABOUT IT.
    #
    # Measured over four real sessions: 22 network_egress verdicts and NOT ONE
    # was an exit. 15 were `curl http://127.0.0.1:<port>` against a dev server
    # the same command had started three lines earlier. Every one produced a
    # prompt, and the rule was labelled not worth showing.
    #
    # `_PRIVATE_HOST` was already consulted on the very next line — but only to
    # reach the SAME ASK an expected host reaches, so it softened DENY to ASK and
    # never removed the prompt. The two are not the same claim: an expected host
    # is one we recognise ON the internet; a private one is not on it at all.
    #
    # ⚠ WHY HERE AND NOT IN `check_sinks`. Removing the sink was tried first and
    # broke acceptance criterion A9 — derived secret material to a local
    # destination must ASK, and `curl -d @out.txt http://localhost:8000/x` fell
    # to ALLOW. The sink is real; only the UNTRUSTED-gated prompt about it is
    # wrong. Every secret-gated branch sits ABOVE this one and is untouched,
    # which is the intended split: being untrusted stops mattering for a
    # destination that cannot leave the machine; holding a secret does not.
    # ⚠ AND ONLY WHEN NO SECRET IS HELD. Dropping the prompt unconditionally was
    # tried and broke `test_a_navigate_to_a_private_host_asks_via_the_host_ladder`,
    # which pins that a session HOLDING A SECRET still asks before driving an
    # opaque MCP tool at a local address — the engine parses one argument of that
    # call and cannot see the rest. That ASK is about the secret, not about the
    # destination, and it stays. All 15 real cases this removes carried no secret,
    # which is why their rule id was `untrusted_expected:` and not `secret_*`.
    # ⚠ AND ONLY FOR `network_egress`. Applying it to every sink was tried and
    # turned two real `curl http://127.0.0.1/… | python3 -c` records from ASK to
    # ALLOW. For `pipe_to_shell` the question is not "does this leave the
    # machine" but "does this session execute code it did not author", and a
    # local server can serve anything — so loopback answers the first question
    # and says nothing about the second. Egress is the only sink whose entire
    # meaning is the destination.
    if (sink == "network_egress" and hosts and not state.holds_secret
            and all(_PRIVATE_HOST.match(h) for h in hosts)):
        return Verdict(Decision.ALLOW, None, None)

    if hosts and all(_is_expected(h, state) or _PRIVATE_HOST.match(h) for h in hosts):
        # ⚠ DIRECTION, AND ONLY FOR A DESTINATION ALREADY JUDGED EXPECTED.
        # Placing this test BEFORE the expected-host check was tried and allowed
        # a plain `curl https://evil.invalid/x` — an unexpected host with no
        # body — which the ladder below had been denying. A fetch from a host we
        # do not recognise is still a fetch from a host we do not recognise; the
        # only thing direction can soften is a destination that was already
        # acceptable.
        if (sink == "network_egress" and not state.holds_secret
                and not _sends_data(action, state)):
            return Verdict(Decision.ALLOW, None, None)
        # ⚠ REASON TEXT ONLY — the decision (ASK) and rule_id are untouched.
        # "the destination is expected" is the right framing for exactly ONE
        # sink: `network_egress`, whose entire meaning IS the destination (see
        # the loopback comment above). For every other sink that reaches here —
        # `pipe_to_shell`, `guard_selfmod`, `git_commit`, `mcp_tool_call`,
        # `dns_lookup` — the expected destination says nothing about the real
        # concern, and the blanket wording misattributed the prompt to it: a
        # `| bash` asks because the session may be running code it did not
        # author, not because of where the pipe's URL points. So the ACTION's
        # own predicate (`rule_names.SINK_MEANINGS`, the one map the engine
        # already owns and prints elsewhere) names it instead. The rule id still
        # carries the sink, and the standing replay — which compares
        # (decision, rule_id) and NOT the reason — proves no verdict moved.
        if sink == "network_egress":
            reason = (f"this session read {_untrusted_origin(state)}; the "
                      f"destination is expected, so confirm this was your intent")
        else:
            reason = (f"this session read {_untrusted_origin(state)}, and "
                      f"{rule_names.sink_meaning(sink)} — the destination is "
                      f"recognised, so confirm this was your intent")
        return Verdict(Decision.ASK, reason, f"untrusted_expected:{sink}")

    # ⚠ AN INBOUND READ IS NOT EGRESS. Below every secret rung, below the
    # private-host and expected-host reliefs, gated the same way they are
    # (`not state.holds_secret`), and read out of a positive allowlist that
    # the five coarse-rule catches in the corpus were used to shape — see
    # `_inbound_read`. Fetching documentation after reading an issue is the
    # ordinary work this product promises to stop asking about; the untrusted
    # mark still lands on what comes back (`mark_sources`).
    if (sink == "network_egress" and not state.holds_secret
            and _inbound_read(action, state)):
        return Verdict(Decision.ALLOW, None, None)
    if sink == "unknown_tool_call" and not hosts:
        # We do not know what this tool does. That is not grounds to allow it,
        # and it is not grounds to deny it as an "unexpected destination"
        # either — it names no destination. A real secret in its arguments is
        # already a DENY higher up the ladder, via secret_exact.
        return Verdict(
            Decision.ASK,
            f"this session read {_untrusted_origin(state)}, and "
            f"{action.tool_name or 'this tool'} is one the guard does not "
            f"recognise — confirm this was your intent",
            f"untrusted_unknown_tool:{sink}")

    if (sink == "mcp_tool_call" and not hosts
            and not fingerprints_in(action.content)):
        # AN MCP CALL WITH NO DESTINATION IN IT. The terminal branch below would
        # say "unexpected destination 'mcp tool call'" — and there is no
        # destination in the call at all. Same false framing as `git commit`
        # above, and it produced 9 denials in one real session, including
        # closing a browser tab.
        #
        # The arguments are ALREADY HERE — the adapter flattens tool_input into
        # `content` and lifts any `url` — so this is unused information, not
        # missing information, and it needs no parsing. Three shapes:
        #
        #   a DESTINATION  action.url or a host among the arguments. Handled by
        #                  the normal host ladder above: navigate to 127.0.0.1
        #                  is `untrusted_expected` (ASK), an unexpected host is
        #                  a DENY. Nothing new required.
        #   a PAYLOAD      any token long enough to hide a credential, by the
        #                  SAME tokeniser secret matching uses. C04 carries
        #                  `AKIA_TEST_C04/us-east-1` and stays a DENY.
        #   NEITHER        `{"tabId": 856910010}`, `{"action":"screenshot"}`.
        #
        # ASK, NOT ALLOW, and that is the load-bearing part. We see the
        # arguments the agent supplied, never what the SERVER does with them:
        # `{"path": ".env"}` is short and unremarkable, and a server told to
        # read that file would exfiltrate it. So this is uncertainty, resolved
        # by a human — exactly what test_a_benign_argument_escalates_rather_
        # than_denying already argued for the secret-only path.
        return Verdict(
            Decision.ASK,
            f"this session read {_untrusted_origin(state)}; this tool call "
            f"names no destination and carries nothing recognisable, but what "
            f"the server does with it cannot be seen from here — confirm",
            f"untrusted_opaque:{sink}")

    if sink in _LOCAL_SINKS and not hosts:
        # A LOCAL SINK HAS NO DESTINATION, so "unexpected destination" is not
        # merely harsh — it is false. `git commit` writes to the working repo;
        # nothing leaves the machine and the commit is revertible. What made
        # this a DENY was the session's LABEL, not anything about the action.
        #
        # Found live: I01, where the agent read a poisoned issue, IGNORED it,
        # fixed the real bug, and had its ordinary commit denied. The push and
        # the remote-add in the same scenario are still DENY — those are the
        # irreversible ones, and they are what the scenario is actually about.
        #
        # ⚠ ALLOW, AND IT USED TO BE ASK. This comment said "ASK, not ALLOW:
        # untrusted content did enter, and a commit is still the step that moves
        # content into history" — a reasonable-sounding argument that the data
        # refused. Measured over the real decision logs: `untrusted_local:
        # git_commit` produced 64 of 116 prompts, the single largest class, and
        # not one of them was a commit anybody wanted stopped. A prompt that
        # fires on every commit in a session that once read a README is not
        # asking a question; it is a keystroke tax, and it trains the developer
        # to clear prompts without reading them — which is how the prompts that
        # DO matter stop working.
        #
        # What still holds the line is that a commit is local and revertible,
        # and the push behind it is guarded separately and independently. A
        # commit carrying SECRET material never reaches here at all: it is
        # denied far above by secret_exact / secret_derived. This branch is
        # reached only by UNTRUSTED-with-no-secret, which is the case where the
        # engine has no evidence about the commit's content whatsoever.
        return Verdict(Decision.ALLOW, None, None)

    if hosts:
        return Verdict(
            Decision.DENY,
            f"unexpected destination '{hosts[0]}' after this session read "
            f"{_untrusted_origin(state)}",
            f"untrusted_unexpected:{sink}")

    # ⚠ NO HOST MEANS THERE IS NO DESTINATION TO CALL UNEXPECTED, AND SAYING
    # OTHERWISE IS A FALSE SENTENCE, NOT A TERSE ONE.
    #
    # `sink.replace("_", " ")` used to be substituted into the destination slot,
    # which produced, verbatim:
    #
    #     unexpected destination 'git push' after this session read ISSUE.md
    #     unexpected destination 'pipe to shell' after this session read …
    #     unexpected destination 'dns lookup' after this session read …
    #     unexpected destination 'guard selfmod' after this session read …
    #
    # `git push` is not a destination. Neither is `pipe to shell`. The developer
    # reading that is being told the engine identified somewhere it did not want
    # the data to go — and it identified no such thing. Measured on the real
    # decision logs: 22 of 24 `untrusted_unexpected` records carried a SINK NAME
    # in the destination slot, so this was the normal case rather than an edge.
    #
    # ⚠ THE DECISION IS UNCHANGED AND MUST STAY UNCHANGED. A push whose remote
    # cannot be resolved in an untrusted session is exactly what this rule is
    # for; the verdict was right and only the sentence was wrong. Rewriting the
    # reason keeps A1, A4 and A5 untouched by construction — nothing here reads
    # or returns a different Decision.
    #
    # ⚠ AND THE RULE ID IS UNCHANGED TOO, DELIBERATELY. `untrusted_unexpected`
    # is the same policy branch it always was; renaming it would rewrite the
    # standing live baseline and ~40 test assertions to no one's benefit, since
    # the rule id is not what the developer reads. The reason is.
    what = rule_names.sink_meaning(sink)
    return Verdict(
        Decision.DENY,
        f"this session read {_untrusted_origin(state)}, and {what}",
        f"untrusted_unexpected:{sink}")

