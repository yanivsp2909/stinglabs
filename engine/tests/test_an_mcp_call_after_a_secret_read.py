"""An MCP call after a secret read asks only when its arguments carry something.

fix/false-positives, the maintainer's decision of 30 Sep, item 3 (docs/112): the ONE
secret rule this pass may loosen. `secret_session_unverified:mcp_tool_call`
asked for every MCP call once the session held a secret — #80 measured 195 such
asks after an environment read. It now asks only when the call's arguments
carry a traced value (a fingerprint of a value the session read, a tainted
file, a tainted variable) or a visible secret reference (`secret_reference`);
otherwise it allows.

What the hook sees of an MCP call's arguments, per agent (docs/112 §3):

    Claude Code   tool_input, the arguments object; tool_name mcp__<server>__<tool>
    Codex         tool_input, the arguments parsed from JSON (a plain string when
                  they are not JSON — then nothing is visible)
    Cursor, Copilot, Antigravity
                  not established from their code in this pass: today's verdict

An agent whose payload does not show the arguments whole keeps today's verdict.

Residual (docs/112): a secret the model re-types or re-encodes from its context
into an MCP call passes, the same residual as every other exit.

Every value here is a fake from the existing fixtures.
"""
from __future__ import annotations

import pytest

from adapters import claude_code, codex, cursor
from core.types import ActionKind, SessionState
from tests.test_engine_decide import walk
from tests.test_engine_sources import act
from tests.test_env_reads_mark_the_session import AWS_SECRET, _World

READ_ENV = act(ActionKind.EXEC, command="printenv AWS_SECRET_ACCESS_KEY")
FETCH = act(ActionKind.FETCH, url="https://docs.example.invalid/page")


def _claude(args: dict):
    return claude_code.parse({"session_id": "s", "cwd": "/repo", "hook_event_name": "PreToolUse",
                              "tool_name": "mcp__notes__save", "tool_input": args})


def _codex(tool_input):
    return codex.parse({"session_id": "s", "cwd": "/repo", "hook_event_name": "PreToolUse",
                        "tool_name": "mcp__notes__save", "tool_input": tool_input})


def _cursor(args: dict):
    return cursor.parse({"conversation_id": "s", "hook_event_name": "beforeMCPExecution",
                         "tool_name": "notes__save", "tool_input": args,
                         "workspace_roots": ["/repo"]})


def _last(*steps):
    verdicts, _state = walk(list(steps), _World(), SessionState())
    v = verdicts[-1]
    return str(v.decision).split(".")[-1], v.rule_id


TODAY = ("ASK", "secret_session_unverified:mcp_tool_call")


def test_harmless_arguments_after_an_env_read_are_allowed():
    assert _last(READ_ENV, _claude({"text": "meeting notes", "tags": ["weekly"]})) == ("ALLOW", None)


def test_the_same_after_outside_content_too():
    """#80's 195: the session had read outside content AND the environment."""
    assert _last(FETCH, READ_ENV, _claude({"text": "meeting notes"})) == ("ALLOW", None)


def test_the_read_value_in_the_arguments_keeps_todays_verdict():
    v = _last(READ_ENV, _claude({"text": f"key={AWS_SECRET}"}))
    assert v[0] != "ALLOW", v


@pytest.mark.parametrize("args", [
    {"text": "use $AWS_SECRET_ACCESS_KEY"}, {"text": "${GITHUB_TOKEN}"},
    {"url": "https://user:pw@x.example.invalid/"},
    # a credential-shaped path: a server told to read it would send it
    {"path": ".env"}, {"files": ["notes.md", "~/.aws/credentials"]},
])
def test_a_secret_reference_in_the_arguments_keeps_todays_verdict(args):
    assert _last(READ_ENV, _claude(args)) == TODAY


def test_codex_arguments_are_read_as_well():
    assert _last(READ_ENV, _codex({"text": "meeting notes"})) == ("ALLOW", None)


def test_codex_arguments_that_are_not_json_are_not_visible():
    assert _last(READ_ENV, _codex("not json {")) == TODAY


def test_an_agent_whose_arguments_are_not_established_keeps_todays_verdict():
    """Cursor sets no `tool_arguments`, so its MCP call is not relieved: still
    asked, by the rule that asked before (its name has no `mcp__` prefix, so it
    reaches the engine as an unknown tool — the rule this pass leaves alone)."""
    v = _last(READ_ENV, _cursor({"text": "meeting notes"}))
    assert v[0] == "ASK", v
    assert v[1].startswith("secret_session_unverified:"), v


def test_arguments_too_long_to_read_whole_keep_todays_verdict():
    assert _last(READ_ENV, _claude({"text": "x" * 20000})) == TODAY


def test_an_mcp_call_with_no_secret_held_is_untouched():
    assert _last(_claude({"text": "meeting notes"})) == ("ALLOW", None)


# ── the reviews (docs/112): what "carries nothing traceable" must not miss
def _after(state: SessionState, *steps):
    verdicts, _state = walk(list(steps), _World(), state)
    v = verdicts[-1]
    return str(v.decision).split(".")[-1], v.rule_id


@pytest.mark.parametrize("how", ["path_policy", "unread"])
def test_a_secret_with_no_fingerprint_keeps_todays_verdict(how):
    """A confidential path, a file that could not be read, an environment value
    too plain to fingerprint: nothing in the arguments CAN match it, so 'nothing
    traceable' proves nothing."""
    state = SessionState()
    state.mark_secret(1, "/repo/config/secrets.yml", how, [])
    assert _after(state, _claude({"text": "meeting notes"})) == TODAY


def test_a_secret_held_with_no_recorded_source_keeps_todays_verdict():
    state = SessionState()
    state.holds_secret, state.holds_secret_since_seq = True, 0
    assert _after(state, _claude({"text": "meeting notes"})) == TODAY


def _b64(text: str) -> str:
    import base64
    return base64.b64encode(text.encode()).decode()


def _b32(text: str) -> str:
    import base64
    return base64.b32encode(text.encode()).decode()


@pytest.mark.parametrize("args", [
    {"body": _b64(AWS_SECRET)},
    {"body": _b32(AWS_SECRET)},
    {"body": AWS_SECRET.encode().hex()},
    {"a": AWS_SECRET[:20], "b": AWS_SECRET[20:]},
    {"parts": [AWS_SECRET[:13], AWS_SECRET[13:27], AWS_SECRET[27:]]},
    {"body": AWS_SECRET[:10] + chr(0x200B) + AWS_SECRET[10:]},
    {"body": "%".join([""] + [f"{b:02X}" for b in AWS_SECRET.encode()])},
])
def test_the_read_value_encoded_or_split_keeps_todays_verdict(args):
    assert _last(READ_ENV, _claude(args)) != ("ALLOW", None), args


@pytest.mark.parametrize("args", [
    {"path": "~"}, {"dir": "~/.ssh"}, {"path": "/home/dev/.aws"}, {"glob": "**/*"},
    {"path": "."}, {"path": ".."}, {"dir": "/repo/config/"},
    # the fourth review round: a `file:` link is the file it names
    {"uri": "file:///home/dev/.aws/credentials"}, {"uri": "file:///home/dev/.ssh/id_rsa"},
    {"uri": "file://localhost/repo/config/.env"}, {"uri": "file:/repo/config"},
    {"uri": "file:///repo/config/%2Eenv"}, {"uri": "FILE:///home/dev/.aws/credentials?x=1"},
    # round 5 regressed a `file:` link with no `//` (P5): fall through to the
    # credential, glob, `~` and relative-path checks, as before round 5.
    {"uri": "file:.env"}, {"uri": "file:~/.aws/credentials"}, {"uri": "file:../.env"},
    {"uri": "file:~/.ssh/id_rsa"},
])
def test_a_place_a_secret_lives_keeps_todays_verdict(args):
    """A directory, a glob or the home directory: an upload, sync or zip tool
    given one ships what is in it."""
    state = SessionState()
    state.mark_secret(1, "/repo/config/.env", "content", ["0" * 16])
    assert _after(state, _claude(args)) == TODAY, args


@pytest.mark.parametrize("args", [
    {"file": "/repo/out/debug.env"}, {"dir": "/repo/out"}, {"v": "$MYCOPY"},
])
def test_a_tainted_file_or_variable_keeps_todays_verdict(args):
    state = SessionState()
    state.mark_secret(1, "/repo/.env", "content", ["0" * 16])
    state.tainted_paths = {"/repo/out/debug.env": {"label": "SECRET", "level": "derived",
                                                    "from_seq": 1}}
    state.tainted_vars = {"MYCOPY": 1}
    assert _after(state, _claude(args)) == TODAY, args


PLAIN = "hunter2"          # docs' own example of a value too plain to fingerprint


def test_a_file_only_partly_fingerprinted_keeps_todays_verdict():
    """The second review round: a `.env` with one random value and one plain
    one is `content`, but the plain one was never fingerprinted and can pass."""
    from tests.test_engine_sources import FakeWorld
    world = FakeWorld({"/repo/.env": f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\nDB_PASSWORD={PLAIN}\n"})
    read = act(ActionKind.READ, paths=("/repo/.env",))
    verdicts, _state = walk([read, _claude({"text": f"pw is {PLAIN}"})], world, SessionState())
    assert str(verdicts[-1].decision).split(".")[-1] == "ASK"


def test_an_environment_only_partly_fingerprinted_keeps_todays_verdict():
    environ = {"AWS_SECRET_ACCESS_KEY": AWS_SECRET, "DB_PASSWORD": PLAIN, "HOME": "/home/dev"}
    verdicts, _state = walk([act(ActionKind.EXEC, command="env"), _claude({"text": PLAIN})],
                            _World(environ), SessionState())
    assert str(verdicts[-1].decision).split(".")[-1] == "ASK"


@pytest.mark.parametrize("args", [
    {"body": _b64(_b64(AWS_SECRET))},
    {"body": _b64(AWS_SECRET).encode().hex()},
])
def test_the_read_value_encoded_twice_keeps_todays_verdict(args):
    assert _last(READ_ENV, _claude(args)) != ("ALLOW", None), args


def test_a_relative_folder_holding_a_secret_keeps_todays_verdict():
    state = SessionState()
    state.mark_secret(1, "/repo/config/.env", "content", ["0" * 16])
    assert _after(state, _claude({"dir": "config"})) == TODAY


def test_markdown_and_questions_are_not_globs():
    """Item 3's relief is for ordinary arguments: a message with `*bold*` or a
    question carries nothing."""
    args = {"text": "**Release** is *done* — any questions? see notes", "channel": "eng"}
    assert _last(READ_ENV, _claude(args)) == ("ALLOW", None)


def test_reading_an_argument_full_of_stars_is_linear():
    import time
    start = time.perf_counter()
    _last(READ_ENV, _claude({"text": "*" * 8000}))
    assert (time.perf_counter() - start) < 1.0


def test_arguments_nested_deeper_than_read_keep_todays_verdict():
    nested: dict = {"text": "meeting notes"}
    for _ in range(8):
        nested = {"x": nested}
    assert _last(READ_ENV, _claude(nested)) == TODAY


def test_reading_the_arguments_is_linear():
    """A list of empty strings never grew the size check: the walk was
    quadratic, and the hook hung past two minutes."""
    import time
    from adapters import _common
    start = time.perf_counter()
    whole = _common.complete_tool_arguments("mcp__x__y", {"x": ["a"] * 8000 + [""] * 200000})
    assert (time.perf_counter() - start) < 1.0
    assert whole is None
