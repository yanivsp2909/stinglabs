"""A source must name what fired it, and the engine must not know agent naming.

Two fixes, both from one wrong diagnosis. A session was marked untrusted with

    kind: git-history
    ref:  "cd .../sting-engine && python3 - <<'PYEOF'\\nimport io\\np='PROGRES"

which reads as GIT_HISTORY matching inside a python heredoc. It was not: the
heredoc closed at byte 3951 and a real `git log --oneline -1` matched at 4065.
`ref` was the first 80 characters of the command — an arbitrary prefix, not
evidence — and it produced the same wrong conclusion twice.
"""
import pytest

from adapters import antigravity, claude_code, codex, copilot, cursor
from core.engine import check_sinks, decide, mark_sources, span_evidence
from core.probes import NullWorld
from core.session import SessionState
from core.types import Action, ActionKind, Decision


def exec_action(command, cwd="/repo"):
    return Action("s", 6, ActionKind.EXEC, (), command, None, "Bash", None,
                   cwd, (cwd,), "claude-code")


# --------------------------------------------------------------- the evidence
def test_a_git_history_source_records_the_span_not_a_prefix():
    """The reported shape, verbatim: a heredoc followed by a real git log."""
    command = ("cd /r && python3 - <<'PYEOF'\n"
                + "filler = 1\n" * 200
                # `-20`, not `-1`: a self-read of the new commit no longer
                # creates a source at all, and this test is about the SPAN the
                # ref records, not about whether the source exists.
                + "PYEOF\ngit add -A && git commit -q -F - <<'MSG' && git log --oneline -20\n"
                  "message body\nMSG")
    st = SessionState(session_id="s")
    st.seq = 6
    mark_sources(st, exec_action(command), NullWorld())
    ref = st.untrusted_sources[0]["ref"]
    assert "git log" in ref, ref
    assert ref.startswith("@"), ref
    assert "import io" not in ref and "PYEOF" not in ref.split("git log")[0][-20:]


def test_the_evidence_is_bounded():
    st = SessionState(session_id="s")
    st.seq = 1
    mark_sources(st, exec_action("x" * 9000 + " && git log --oneline"), NullWorld())
    assert len(st.untrusted_sources[0]["ref"]) <= 210


def test_span_evidence_marks_where_it_clipped():
    text = "a" * 300 + "MATCH" + "b" * 300
    ev = span_evidence(text, 300, 305)
    assert ev.startswith("@300 …") and ev.endswith("…")
    assert "MATCH" in ev


def test_a_source_with_an_exact_ref_is_left_alone():
    """FETCH and READ sources record a url or a path — already exact, not a
    prefix of something longer. Only git-history had the defect."""
    st = SessionState(session_id="s")
    st.seq = 1
    a = Action("s", 1, ActionKind.FETCH, (), None, "https://x.test/page", None,
                None, "/repo", ("/repo",), "claude-code")
    mark_sources(st, a, NullWorld())
    assert st.untrusted_sources[0]["ref"] == "https://x.test/page"


# ------------------------------------------------------------- tool_origin
@pytest.mark.parametrize("adapter,payload,expect", [
    (claude_code, {"session_id": "s", "cwd": "/r", "tool_name": "mcp__x__y",
                    "tool_input": {}}, "mcp"),
    (claude_code, {"session_id": "s", "cwd": "/r", "tool_name": "ToolSearch",
                    "tool_input": {"query": "x"}}, "builtin"),
    (claude_code, {"session_id": "s", "cwd": "/r", "tool_name": "Bash",
                    "tool_input": {"command": "ls"}}, ""),
])
def test_the_adapter_declares_the_origin(adapter, payload, expect):
    assert adapter.parse(payload).tool_origin == expect


def test_every_adapter_sets_tool_origin():
    """Five adapters hold five sets of agent-specific knowledge. This is a
    sixth, and it must not be left to one of them."""
    import inspect
    for mod in (claude_code, cursor, codex, copilot, antigravity):
        assert "tool_origin=" in inspect.getsource(mod.parse), mod.__name__


def test_the_engine_never_tests_the_mcp_prefix_itself():
    """`mcp__` is Claude Code's convention. engine.py used to test it directly,
    which is this project's boundary rule broken in the one module that defines
    it.

    Comments and docstrings are excluded: the file may still EXPLAIN the
    convention it no longer branches on, and a test that forbids naming it would
    force the explanation out of the code that needs it.
    """
    import ast

    from tests import engine_source
    for tree in engine_source.trees().values():    # every part of the engine
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                # a docstring or a literal; only literals used in code matter
                if "mcp__" in node.value and not _is_docstring(tree, node):
                    raise AssertionError(f"engine branches on agent naming: {node.value!r}")


def _is_docstring(tree, target):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and body[0].value is target:
                return True
    return False


import ast  # noqa: E402  (used by the test above)


def test_an_unset_origin_fails_towards_the_stricter_answer():
    """An adapter that forgets must not silently trust its tool calls."""
    st = SessionState(session_id="s")
    st.seq = 1
    a = Action("s", 1, ActionKind.TOOL, (), None, None, "something", None,
                "/repo", ("/repo",), "x")          # tool_origin defaults to ""
    mark_sources(st, a, NullWorld())
    assert st.untrusted, "an undeclared tool origin must still mark untrusted"


# ------------------------------------------------- the unrecognised built-in
def _held_untrusted():
    st = SessionState(session_id="s", holds_secret=True, holds_secret_since_seq=1,
                      untrusted=True, untrusted_since_seq=1,
                      untrusted_sources=[{"seq": 1, "kind": "mcp", "ref": "x"}])
    return st


def test_an_unrecognised_builtin_is_a_sink_but_asks():
    """Not known-safe — falling through to TOOL means the ADAPTER did not know
    it, and `Task` spawns a subagent. Not an "unexpected destination" either:
    it names no destination."""
    a = claude_code.parse({"session_id": "s", "cwd": "/r",
                            "tool_name": "ToolSearch",
                            "tool_input": {"query": "select:Read,Edit,Grep"}})
    assert check_sinks(_held_untrusted(), a, NullWorld()) == "unknown_tool_call"
    v = decide(a, _held_untrusted(), NullWorld())
    assert v.decision is Decision.ASK, v
    assert v.rule_id == "untrusted_unknown_tool:unknown_tool_call"


def test_an_mcp_call_is_still_an_mcp_call():
    a = claude_code.parse({"session_id": "s", "cwd": "/r",
                            "tool_name": "mcp__weather__get_alerts",
                            "tool_input": {"arg": "us-east-1"}})
    assert check_sinks(_held_untrusted(), a, NullWorld()) == "mcp_tool_call"


def test_a_builtin_carrying_a_real_secret_is_still_denied():
    """ASK is for 'we do not know'. A known secret is not that."""
    from core.engine import fingerprint_values
    st = _held_untrusted()
    st.secret_fingerprints = sorted(fingerprint_values(
        "K=AKIA_TEST_BUILTIN_VALUE_000\n"))
    a = claude_code.parse({"session_id": "s", "cwd": "/r",
                            "tool_name": "ToolSearch",
                            "tool_input": {"query": "AKIA_TEST_BUILTIN_VALUE_000"}})
    assert decide(a, st, NullWorld()).decision is Decision.DENY
