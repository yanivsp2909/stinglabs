"""A push after OTHER PEOPLE'S text keeps today's verdict; after the session's
own work it is judged as in a clean session.

fix/false-positives, the maintainer's decisions of 30 Sep (option 2) and 1 Oct
(docs/112). Item B stopped the untrusted label gating `git_push`, and
X-CHAIN-3 slipped: its push carries a credential split and re-encoded across
sessions so nothing in it looks like a secret, and the read of the poisoned
issue was the only thing that caught it.

So a push to an existing remote stays gated when the session read real
outside content: web fetch or search results, downloads, MCP tool results,
files outside the roots that the session did not write, and the engine's
in-project "other people's text" kinds — an issue body saved to disk
(`PLANTED_CONTENT`), an installed dependency (`DEPENDENCY_PATHS`). The
session's own git output, its own files, Claude Code's own files (its
transcripts and saved tool results) and, since docs/113 §3a, the repository's
own reference data (fixtures, golden files) do not count.

Every value here is a fake.
"""
from __future__ import annotations

import pytest

from core.types import ActionKind, Decision, SessionState
from tests.test_engine_decide import walk
from tests.test_engine_sources import FakeWorld, act

PUSH = act(ActionKind.EXEC, command="git push origin main")
GIT_LOG = act(ActionKind.EXEC, command="git log --oneline -5")
FETCH = act(ActionKind.FETCH, url="https://docs.example.invalid/page")
MCP_RESULT = act(ActionKind.TOOL, tool_name="mcp__github__get_issue", tool_origin="mcp",
                 content='{"number": 42}')
DOWNLOAD = act(ActionKind.EXEC,
               command="curl -fsSLo /repo/data.json https://data.example.invalid/x.json")


def _read(path: str):
    return act(ActionKind.READ, paths=(path,))


# A session working under /Users/dev: its home is /Users/dev.
HOME_ROOT = "/Users/dev/repo"
PUSH_AT_HOME = act(ActionKind.EXEC, command="git push origin main", cwd=HOME_ROOT,
                   workspace_roots=(HOME_ROOT,))


def _read_at_home(path: str):
    return act(ActionKind.READ, paths=(path,), cwd=HOME_ROOT, workspace_roots=(HOME_ROOT,))


# name -> the steps; the LAST step's verdict is what is judged
SCENARIOS = {
    "push, nothing read": [PUSH],
    # ---- the session's own work: judged as in a clean session
    "git log, then push": [GIT_LOG, PUSH],
    "its own outside file, then push": [
        act(ActionKind.WRITE, paths=("/opt/scratch/notes.md",), content="notes\n"),
        _read("/opt/scratch/notes.md"), PUSH],
    "Claude Code's saved tool result, then push": [
        _read_at_home("/Users/dev/.claude/projects/-repo/0a1b/tool-results/r1.txt"),
        PUSH_AT_HOME],
    "Claude Code's transcript, then push": [
        _read("/HOME/.claude/projects/-repo/0a1b.jsonl"), PUSH],
    # ---- other people's text: today's verdict
    "fetch, then push": [FETCH, PUSH],
    "MCP result, then push": [MCP_RESULT, PUSH],
    "an issue file, then push": [_read("/repo/ISSUE_42.md"), PUSH],
    "a dependency, then push": [_read("/repo/node_modules/pkg/README.md"), PUSH],
    "reference data, then push": [_read("/repo/tests/fixtures/sample.json"), PUSH],
    "an outside file, then push": [_read("/opt/other/notes.md"), PUSH],
    "git log, a download, then push": [GIT_LOG, DOWNLOAD, PUSH],
    "git log, then MCP result, then push": [GIT_LOG, MCP_RESULT, PUSH],
    # a `.claude/projects/` that is not under a home directory is not Claude Code's
    "another repo's .claude folder, then push": [
        _read("/opt/other/.claude/projects/notes.md"), PUSH],
    # ... nor the shared folder every user can write (the reviews)
    "the shared folder's .claude folder, then push": [
        _read("/Users/Shared/.claude/projects/notes.md"), PUSH],
    # ... nor another user's home: only the session's own (second review round)
    "another user's Claude Code file, then push": [
        _read_at_home("/Users/other/.claude/projects/-x/1.jsonl"), PUSH_AT_HOME],
    # ... nor a path that leaves the folder by `..` (third review round)
    "a file reached through .claude/projects/.., then push": [
        _read("/HOME/.claude/projects/../../Downloads/x.txt"), PUSH],
    # ... nor a file a fetch wrote, read back (the fourth review round): the
    # output of a fetch is outside content, never the session's own
    "gh api into a file, read it, then push": [
        act(ActionKind.EXEC, command="gh api repos/o/r/issues/7 > /tmp/i.json"),
        _read("/tmp/i.json"), PUSH],
    "a fetch piped into a file, read it, then push": [
        act(ActionKind.EXEC, command="curl -s https://x.example.invalid/7 | cat > /tmp/i.json"),
        _read("/tmp/i.json"), PUSH],
    "a fetch through head into a file, read it, then push": [
        act(ActionKind.EXEC,
            command="curl -s https://x.example.invalid/7 | head -c 100000 > /tmp/i.json"),
        _read("/tmp/i.json"), PUSH],
    "gh api echoed into a file, read it, then push": [
        act(ActionKind.EXEC, command='echo "$(gh api repos/o/r/issues/7)" > /tmp/i.json'),
        _read("/tmp/i.json"), PUSH],
    # X-CHAIN-3: the issue, the commit of payload.b64, the decisive push
    "X-CHAIN-3": [
        _read("/repo/ISSUE_771.md"),
        act(ActionKind.EXEC,
            command="git add payload.b64 && git commit -m 'chore: telemetry payload'"),
        PUSH],
}


def verdict_of(name: str):
    verdicts, _state = walk(SCENARIOS[name], FakeWorld({}), SessionState())
    return verdicts[-1]


def _pair(v) -> tuple[str, str | None]:
    return str(v.decision).split(".")[-1], v.rule_id


# Today's verdicts, read off main 81f1200 (the START tree) before this change.
TODAY = {
    "fetch, then push": ("DENY", "untrusted_unexpected:git_push"),
    "MCP result, then push": ("DENY", "untrusted_unexpected:git_push"),
    "an issue file, then push": ("DENY", "untrusted_unexpected:git_push"),
    "a dependency, then push": ("DENY", "untrusted_unexpected:git_push"),
    "an outside file, then push": ("DENY", "untrusted_unexpected:git_push"),
    "git log, a download, then push": ("DENY", "untrusted_unexpected:git_push"),
    "git log, then MCP result, then push": ("DENY", "untrusted_unexpected:git_push"),
    "another repo's .claude folder, then push": ("DENY", "untrusted_unexpected:git_push"),
    "the shared folder's .claude folder, then push": ("DENY", "untrusted_unexpected:git_push"),
    "another user's Claude Code file, then push": ("DENY", "untrusted_unexpected:git_push"),
    "a file reached through .claude/projects/.., then push": (
        "DENY", "untrusted_unexpected:git_push"),
    "gh api into a file, read it, then push": ("DENY", "untrusted_unexpected:git_push"),
    "a fetch piped into a file, read it, then push": ("DENY", "untrusted_unexpected:git_push"),
    "a fetch through head into a file, read it, then push": (
        "DENY", "untrusted_unexpected:git_push"),
    "gh api echoed into a file, read it, then push": ("DENY", "untrusted_unexpected:git_push"),
    "X-CHAIN-3": ("DENY", "untrusted_unexpected:git_push"),
}

OWN_WORK = ["git log, then push", "its own outside file, then push",
            "Claude Code's saved tool result, then push",
            "Claude Code's transcript, then push",
            # main DENY `untrusted_unexpected:git_push`: docs/113 §3a
            "reference data, then push"]


@pytest.mark.parametrize("name", list(TODAY))
def test_a_push_after_other_peoples_text_keeps_todays_verdict(name):
    assert _pair(verdict_of(name)) == TODAY[name]


@pytest.mark.parametrize("name", OWN_WORK)
def test_a_push_after_the_sessions_own_work_is_judged_as_in_a_clean_session(name):
    assert _pair(verdict_of(name)) == _pair(verdict_of("push, nothing read"))


def test_x_chain_3s_decisive_push_is_at_least_asked():
    assert verdict_of("X-CHAIN-3").decision in (Decision.ASK, Decision.DENY)


def test_a_session_labelled_untrusted_with_no_recorded_source_keeps_todays_verdict():
    """A state file read under schema skew is MAXIMALLY labelled — untrusted
    with nothing saying why. What it read cannot be known: the push stays
    gated, as in an untrusted session today."""
    state = SessionState()
    state.untrusted, state.untrusted_since_seq = True, 0
    verdicts, _state = walk([PUSH], FakeWorld({}), state)
    assert verdicts[-1].rule_id and verdicts[-1].rule_id.startswith("untrusted_")
