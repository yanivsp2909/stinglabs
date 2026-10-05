"""What a rule id MEANS, in words. One definition, in the repo that mints them.

────────────────────────────────────────────────────────────────────────────────
WHY IT LIVES HERE, AND NOWHERE ELSE
────────────────────────────────────────────────────────────────────────────────

`untrusted_local:git_commit` is unreadable to anyone new, and anyone new is the
entire point of the next month. So something has to translate it.

⚠ THE ENGINE MINTS RULE IDS, SO THE ENGINE OWNS THEIR NAMES. A second list in
the panel, or in the collector, or in a dashboard, is a list that can disagree
with the ids it describes — and the copy a READER sees would be the wrong one. A
rule renamed here and not there shows a stale name beside a live verdict, which
is worse than showing the raw id: the raw id is obviously machine text and
invites a lookup, while a confident wrong sentence does not.

This is the same argument the collector's `collector/report.py` already makes
about tiers, and it reaches the same conclusion from the other side: the
collector holds no tier vocabulary because the SENDER owns tiers, and it holds
no rule vocabulary because the ENGINE owns rules.

⚠ THE RULE ID ITSELF NEVER CHANGES. It is the standing live baseline's key and
~40 test assertions depend on it. What changes is only what a HUMAN reads.
`tests/test_rule_names.py` asserts the ids are untouched.

⚠ HOW ANOTHER REPO GETS THIS WITHOUT KEEPING A COPY: `tools/export_rule_names.py`
generates `rule_names.json` from this file. A consumer reads the generated
artifact. That is a copy that cannot drift, because nobody types it.
"""
from __future__ import annotations

# ─────────────────────────────────────────────────── what a SINK actually is
#
# ⚠ THESE ARE NOT DESTINATIONS AND MUST NEVER BE PRINTED AS ONE. Substituting a
# sink name into a "destination" slot produced, verbatim, in shipped code:
#
#     unexpected destination 'git push' after this session read ISSUE.md
#     what this sends to 'git push' could not be inspected
#
# `git push` is not a destination. The developer is being told the engine
# identified somewhere it did not want the data to go, and it identified no such
# thing. Each entry below is a PREDICATE — a thing the action does — so it can
# only be dropped into a sentence that is about the action.
SINK_MEANINGS = {
    "deferred_exec_target":
        "a file that something OTHER than the agent will execute — a "
        "package.json postinstall, a Makefile recipe — was written by a session "
        "that did not create it. The payload runs later, in a process with no "
        "hook attached, so the write is the only moment anything can see it.",

    "clipboard_egress":
        "a credential was written to the system clipboard, which every "
        "application on the machine can read. No network call is involved, so "
        "no egress rule applies — the exit is the OS itself.",
    "sync_folder_egress":
        "a labelled file was copied into a cloud-sync folder (OneDrive, "
        "Dropbox, iCloud, Google Drive). The sync client uploads it; the agent "
        "opened no socket, so nothing the network sinks model would see it.",

    "git_push":        "this pushes commits to a remote the command does not "
                       "name and the guard could not resolve",
    "git_new_remote":  "this adds a new push destination to the repository",
    "git_commit":      "this moves content from the working tree into history",
    "pipe_to_shell":   "this executes code that this session did not author",
    "dns_lookup":      "a DNS lookup carries whatever is in the name it "
                       "resolves, so it is a way out even with no data flag",
    "network_egress":  "this sends data off the machine",
    "env_dump_egress": "this reads the whole environment, which is where "
                       "credentials usually are",
    "config_selfmod":  "this edits the agent's own configuration, which "
                       "changes what every later session is allowed to do",
    "guard_selfmod":   "this edits the guard watching this session",
    "settings_shell_edit": "this edits Claude Code's settings by shell, where "
                           "the guard cannot see what the edit leaves in place",
    "git_hooks":       "this installs a git hook, which then runs on its own "
                       "at every future commit",
    "shell_profile":   "this edits a shell profile, which then runs in every "
                       "future shell",
    "chmod_widen":     "this widens who may read or execute a file",
    "nonstandard_index": "this installs packages from an index that is not the "
                         "default one",
    "write_outside":   "this writes outside every declared project root",
    "destructive_outside": "this destroys something outside every declared "
                           "project root",
    "secret_in_argv":  "the command itself names a credential file",
    "unknown_tool_call": "this calls a tool the guard does not recognise",
    "mcp_tool_call":   "this drives an MCP tool whose server-side effect cannot "
                       "be seen from here",
    "security_weakening": "this weakens a security setting",
    "security_critical": "this touches something security-critical",
    "catastrophic_root": "the directory itself, not anything inside it, and no "
                         "task ever does that",
    "raw_block_device": "the whole disk, not a file on it — every filesystem it "
                        "holds goes with it",
    "catastrophic_sweep": "the same event as deleting the directory itself, "
                          "and no task ever does that",
}


def sink_meaning(sink: str) -> str:
    """What this sink IS, as a predicate. Never a destination."""
    return SINK_MEANINGS.get(sink, f"this is a {str(sink).replace('_', ' ')}")


# ─────────────────────────────────────── what a block's ACTION is, in a phrase
#
# The `action` a DENY or ASK record carries (docs/108): a noun phrase, so the
# agent is told "a network send" and not a rule id. By the rule's sink, and for
# a family that names none, by the family. A test pins one per sink.
SINK_ACTIONS = {
    "deferred_exec_target": "a write to a file something else will run",
    "clipboard_egress": "a copy to the clipboard",
    "sync_folder_egress": "a copy into a cloud-sync folder",
    "git_push": "git push",
    "git_new_remote": "adding a git remote",
    "git_commit": "git commit",
    "pipe_to_shell": "running downloaded code",
    "dns_lookup": "a DNS lookup",
    "network_egress": "a network send",
    "env_dump_egress": "sending the environment",
    "config_selfmod": "an edit of the agent's own configuration",
    "guard_selfmod": "a change to the guard",
    "settings_shell_edit": "a shell edit of Claude Code's settings",
    "git_hooks": "installing a git hook",
    "shell_profile": "an edit of a shell profile",
    "chmod_widen": "widening a file's permissions",
    "nonstandard_index": "a package install from a non-default index",
    "write_outside": "a write outside the project",
    "destructive_outside": "a delete outside the project",
    "secret_in_argv": "a command carrying a credential",
    "unknown_tool_call": "a call to an unrecognised tool",
    "mcp_tool_call": "an MCP tool call",
    "security_weakening": "switching off a security control",
    "security_critical": "an edit of a security-critical file",
    "catastrophic_root": "deleting a directory nothing ever deletes",
    "raw_block_device": "overwriting a whole disk",
    "catastrophic_sweep": "deleting everything under a directory nothing ever deletes",
}

FAMILY_ACTIONS = {
    "installed_guard": "a change to the installed guard",
    "catastrophic_delete": "deleting a directory nothing ever deletes",
    "catastrophic_overwrite": "overwriting a whole disk",
    "irreversible_action": "an action that cannot be undone",
    "untrusted_destructive": "a delete outside the project",
    "untrusted_security_critical": "an edit of a security-critical file",
    "untrusted_security_weakening": "switching off a security control",
}
"""A family whose phrase is not its sink's: the floor (whatever it touched, it
is the guard) and the families whose rule id names no sink."""

SENDS = frozenset({"network_egress", "git_push", "git_commit", "dns_lookup",
                   "env_dump_egress", "clipboard_egress", "sync_folder_egress",
                   "mcp_tool_call", "unknown_tool_call", "write_outside",
                   "secret_in_argv", "git_new_remote"})
"""The sinks that move data somewhere, so "you're trying to send … to …" is a
true sentence about them. `pipe_to_shell` takes code IN; a delete sends
nothing."""


def action_of(rule_id: str | None, sink: str | None = None) -> str | None:
    """The action a rule id is about, as a phrase, or None."""
    family, _, suffix = (rule_id or "").partition(":")
    if family in FAMILY_ACTIONS:
        return FAMILY_ACTIONS[family]
    return SINK_ACTIONS.get(suffix or sink or "")


# ────────────────────────────────────────────────── what a RULE ID means
#
# The FAMILY prefix carries most of the meaning; the suffix after `:` is a sink,
# translated above. So a name is composed rather than enumerated — otherwise
# every new sink would need a row in every family and the table would rot.
RULE_FAMILIES = {
    "canary_exfil":
        ("Canary decoy leaving", "a planted decoy value that nothing legitimate "
         "ever reads is in this action, so its presence is near-certain "
         "exfiltration — the strongest signal the guard has"),
    "secret_exact":
        ("Credential leaving", "a value read from a credential file is in this "
         "action, and this action is an exit"),
    "secret_derived":
        ("Secret-derived content leaving", "content traced back to a credential "
         "read earlier in this session is in this action"),
    "secret_derived_external":
        ("Secret-derived content leaving the project", "content traced from a "
         "credential is being written outside every declared project root"),
    "secret_session_unverified":
        ("Unverifiable send, session holds a secret", "this session read a "
         "credential and what this action sends could not be inspected"),
    "policy_source_deny":
        ("Org-policy source leaving", "this session read a source your "
         "organisation's policy marks 'deny', and this action sends it off the "
         "machine"),
    "policy_source_ask":
        ("Org-policy source leaving — confirm", "this session read a source your "
         "organisation's policy marks 'ask', and this action is an egress, so "
         "confirm this was intended"),
    "policy_source_log":
        ("Org-policy source, recorded", "this session read a source your "
         "organisation's policy marks 'log'; this egress is allowed and recorded "
         "for the audit trail"),
    "policy_value_exfil":
        ("Org-policy value exfiltration", "a distinctive value read from a source "
         "your organisation's policy declared sensitive is present in what this "
         "action sends off the machine — a confirmed exact-value leak"),
    "untrusted_unexpected":
        ("Untrusted session, unrecognised destination", "this session read "
         "content a stranger wrote, and this action leaves for somewhere the "
         "guard does not recognise"),
    "untrusted_expected":
        ("Untrusted session, recognised destination", "this session read "
         "content a stranger wrote; the destination is one the guard "
         "recognises, so this is a confirmation rather than a block"),
    "untrusted_local":
        ("Untrusted session, local action", "this session read content a "
         "stranger wrote, and this action does not leave the machine"),
    "untrusted_destructive":
        ("Untrusted session, destructive action", "this session read content a "
         "stranger wrote, and this action destroys something"),
    "untrusted_security_critical":
        ("Untrusted session, security-critical action", "this session read "
         "content a stranger wrote, and this action changes a security control"),
    "untrusted_security_weakening":
        ("Untrusted session, security weakened", "this session read content a "
         "stranger wrote, and this action makes something less safe"),
    "untrusted_unknown_tool":
        ("Untrusted session, unrecognised tool", "this session read content a "
         "stranger wrote, and this tool is one the guard does not know"),
    "untrusted_opaque":
        ("Untrusted session, opaque tool call", "this session read content a "
         "stranger wrote, and what the tool's server does cannot be seen"),
    "installed_guard":
        ("Changing the installed guard", "no agent may write, delete, move, "
         "stop, unload or uninstall any part of the installed Sting guard, in "
         "any session; a person can do it from their own terminal"),
    "catastrophic_overwrite":
        ("Overwriting a whole disk", "this writes over a raw block device "
         "rather than a file, so every filesystem on it is destroyed"),
    "catastrophic_delete":
        ("Deleting a directory nothing ever deletes", "the resolved target of "
         "this deletion IS the filesystem root, a home directory, or a "
         "directory the operating system lives in — not a path inside one"),
    "irreversible_action":
        ("Cannot be undone", "this action destroys something that cannot be "
         "recovered, whatever else is true of the session"),
    "fallback":
        ("Guard degraded", "the guard could not evaluate normally and fell "
         "back to a safe answer"),
    "degraded_no_state":
        ("Guard degraded — no session state", "the session file could not be "
         "read, so this action was judged with no memory of the session"),

    # ⚠ RETIRED, AND KEPT ON PURPOSE. The engine no longer emits these, but they
    # are in stored history — `runner/live_baseline.json` references
    # `untrusted_local:git_commit` 28 times. Deleting the name would leave a
    # reader of an old record with a raw id and no way to look it up, so a
    # retired rule keeps its meaning and SAYS it is retired.
    "untrusted_local":
        ("Untrusted session, local action (RETIRED)", "this session read "
         "content a stranger wrote, and this action did not leave the machine. "
         "Retired: it produced 64 of 116 prompts on real logs and not one was "
         "a commit anybody wanted stopped"),
}

RETIRED = frozenset({"untrusted_local"})
"""Families the engine no longer emits. Named for readers of stored history."""


def describe(rule_id: str | None) -> dict:
    """`{title, why, rule_id}` for a rule id. Never raises, never invents.

    ⚠ AN UNKNOWN ID RETURNS THE ID, NOT A GUESS. A rule this table has not been
    told about is exactly the case where a confident sentence would be wrong,
    and the raw id at least invites a lookup.
    """
    if not rule_id:
        return {"rule_id": None, "title": "Allowed", "why": "no rule fired"}
    family, _, sink = str(rule_id).partition(":")
    known = RULE_FAMILIES.get(family)
    if not known:
        return {"rule_id": rule_id, "title": rule_id,
                "why": "this rule has no description yet"}
    title, why = known
    if sink:
        return {"rule_id": rule_id, "title": f"{title} — {sink_meaning(sink)}",
                "why": f"{why}; {sink_meaning(sink)}"}
    return {"rule_id": rule_id, "title": title, "why": why}


def title(rule_id: str | None) -> str:
    return describe(rule_id)["title"]
