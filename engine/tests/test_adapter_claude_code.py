"""
Step 2 — the Claude Code adapter.

docs/25 step 4 sets the bar: "Cover every ActionKind, plus missing tool_input,
unknown tool name, relative path, symlinked path, and a Bash command containing
quotes and newlines. Assert the adapter never raises — it returns a well-formed
Action or a documented error."

This adapter never raises. Malformed input yields a degenerate but well-formed
Action rather than an exception, because an action that fails to parse must
still reach the engine — dropping it silently would be a bypass, which is the
one outcome a guard cannot have.
"""
import json
import os

import pytest

from adapters import claude_code
from core.types import Action, ActionKind, Decision, Verdict


def ev(tool, tool_input=None, **extra):
    base = {"session_id": "sess-1", "cwd": "/tmp", "hook_event_name": "PreToolUse",
            "tool_name": tool}
    if tool_input is not None:
        base["tool_input"] = tool_input
    base.update(extra)
    return base


# ------------------------------------------------------------- every ActionKind
@pytest.mark.parametrize("tool,tool_input,expected", [
    ("Read",     {"file_path": "/tmp/a.txt"},              ActionKind.READ),
    ("Write",    {"file_path": "/tmp/a.txt", "content": "x"}, ActionKind.WRITE),
    ("Edit",     {"file_path": "/tmp/a.txt", "new_string": "x"}, ActionKind.EDIT),
    ("MultiEdit", {"file_path": "/tmp/a.txt", "edits": []},  ActionKind.EDIT),
    ("NotebookEdit", {"notebook_path": "/tmp/a.ipynb"},      ActionKind.EDIT),
    ("Bash",     {"command": "ls"},                          ActionKind.EXEC),
    ("WebFetch", {"url": "https://example.com"},             ActionKind.FETCH),
    ("mcp__weather__get_alerts", {"arg": "x"},               ActionKind.TOOL),
])
def test_tool_maps_to_kind(tool, tool_input, expected):
    assert claude_code.parse(ev(tool, tool_input)).kind is expected


def test_every_action_kind_is_reachable():
    """If a kind cannot be produced, either the map or the enum is wrong."""
    produced = {
        claude_code.parse(ev(t, i)).kind
        for t, i in [("Read", {"file_path": "/a"}), ("Write", {"file_path": "/a"}),
                     ("Edit", {"file_path": "/a"}), ("Bash", {"command": "ls"}),
                     ("WebFetch", {"url": "http://x"}), ("mcp__x__y", {})]
    }
    assert produced == set(ActionKind)


# ------------------------------------------------------------------- the fields
def test_bash_carries_the_command_and_no_paths():
    a = claude_code.parse(ev("Bash", {"command": "git push origin main"}))
    assert a.command == "git push origin main"
    assert a.paths == () and a.url is None


def test_webfetch_carries_the_url():
    a = claude_code.parse(ev("WebFetch", {"url": "https://evil.io/x"}))
    assert a.url == "https://evil.io/x" and a.command is None


def test_write_carries_content_for_fingerprint_matching():
    a = claude_code.parse(ev("Write", {"file_path": "/tmp/d.env",
                                        "content": "AKIA_TEST_1234"}))
    assert a.content == "AKIA_TEST_1234"


def test_edit_content_comes_from_new_string():
    a = claude_code.parse(ev("Edit", {"file_path": "/tmp/a", "new_string": "secret"}))
    assert a.content == "secret"


def test_multiedit_collects_every_edit_payload_and_path(tmp_path):
    a = claude_code.parse(ev("MultiEdit", {
        "file_path": str(tmp_path / "a.py"),
        "edits": [{"file_path": str(tmp_path / "b.py"), "new_string": "one"},
                  {"file_path": str(tmp_path / "c.py"), "new_string": "two"}]}))
    assert len(a.paths) == 3
    assert "one" in a.content and "two" in a.content


def test_session_id_and_agent_are_carried():
    a = claude_code.parse(ev("Bash", {"command": "ls"}, session_id="abc123"))
    assert a.session_id == "abc123"
    assert a.agent == "claude-code"


def test_seq_is_left_for_the_session_layer():
    """Claude Code does not supply a sequence number. Antigravity does."""
    assert claude_code.parse(ev("Bash", {"command": "ls"})).seq == 0


def test_tool_name_is_preserved_even_when_the_kind_is_not_tool():
    """The only record of which tool produced an action classified by fallback."""
    assert claude_code.parse(ev("Bash", {"command": "ls"})).tool_name == "Bash"


# --------------------------------------------------------------- path resolution
def test_relative_paths_resolve_against_cwd(tmp_path):
    a = claude_code.parse(ev("Read", {"file_path": "src/login.py"}, cwd=str(tmp_path)))
    assert a.paths == (str(tmp_path / "src" / "login.py"),)
    assert os.path.isabs(a.paths[0])


def test_symlinks_are_followed(tmp_path):
    real = tmp_path / "real.env"
    real.write_text("SECRET=1")
    link = tmp_path / "link.env"
    link.symlink_to(real)
    a = claude_code.parse(ev("Read", {"file_path": str(link)}))
    assert a.paths == (str(real.resolve()),), "a symlink must not hide the target"


def test_home_relative_paths_expand(tmp_path):
    a = claude_code.parse(ev("Read", {"file_path": "~/.ssh/id_rsa"}))
    assert a.paths[0].startswith(os.path.expanduser("~"))
    assert "~" not in a.paths[0]


def test_paths_for_a_file_that_does_not_exist_yet(tmp_path):
    """A Write's destination does not exist at decision time."""
    a = claude_code.parse(ev("Write", {"file_path": str(tmp_path / "new" / "f.txt"),
                                        "content": "x"}))
    assert a.paths and os.path.isabs(a.paths[0])


def test_duplicate_paths_are_collapsed(tmp_path):
    a = claude_code.parse(ev("MultiEdit", {
        "file_path": str(tmp_path / "a.py"),
        "edits": [{"file_path": str(tmp_path / "a.py"), "new_string": "x"}]}))
    assert len(a.paths) == 1


# ------------------------------------------------------ never raises, ever
@pytest.mark.parametrize("raw", [
    {},                                              # nothing at all
    {"tool_name": "Bash"},                           # missing tool_input
    {"tool_name": "Bash", "tool_input": None},       # tool_input wrong type
    {"tool_name": "Bash", "tool_input": "a string"},
    {"tool_name": None, "tool_input": {}},           # tool_name wrong type
    {"tool_name": "TotallyUnknownTool", "tool_input": {"x": 1}},
    {"tool_name": "Read", "tool_input": {"file_path": None}},
    {"tool_name": "Read", "tool_input": {"file_path": ""}},
    {"tool_name": "Read", "tool_input": {"file_path": "\0bad"}},
    {"tool_name": "Bash", "tool_input": {"command": 12345}},
    {"tool_name": "Write", "tool_input": {"content": ["not", "a", "string"]}},
    {"tool_name": "MultiEdit", "tool_input": {"edits": ["not a dict"]}},
    {"tool_name": "Bash", "tool_input": {}, "cwd": None},
    {"tool_name": "Bash", "tool_input": {}, "session_id": 999},
    "not a dict at all",
    None,
    [],
], ids=lambda r: str(r)[:44])
def test_parse_never_raises(raw):
    a = claude_code.parse(raw)
    assert isinstance(a, Action)
    assert isinstance(a.kind, ActionKind)
    assert isinstance(a.paths, tuple)
    assert isinstance(a.session_id, str) and a.session_id
    assert isinstance(a.cwd, str) and a.cwd
    assert a.agent == "claude-code"


def test_unknown_tool_falls_through_to_tool_not_dropped():
    """An unrecognised tool must still reach the engine. Silently dropping it
    would be a bypass, which is the one outcome a guard cannot have."""
    a = claude_code.parse(ev("SomeNewToolShipped2027", {"x": 1}))
    assert a.kind is ActionKind.TOOL
    assert a.tool_name == "SomeNewToolShipped2027"


def test_bash_with_quotes_and_newlines_survives_intact():
    cmd = 'git commit -m "fix: it\'s broken\nsecond line" && echo $\'a\\tb\''
    a = claude_code.parse(ev("Bash", {"command": cmd}))
    assert a.command == cmd, "the raw shell string must not be mangled"


# ------------------------------------------------------------------- rendering
def test_allow_renders_an_explicit_allow_not_an_empty_string():
    # ⚠ CONTRACT CHANGED: ALLOW is an explicit `permissionDecision:
    # "allow"`, not the empty string. Empty output is NO OPINION, and
    # Claude Code then runs its own permission flow — which in manual
    # mode PROMPTS. See tests/test_the_verdict_reaches_the_user.py.
    assert json.loads(claude_code.render(Verdict(Decision.ALLOW, None, None)))["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_deny_renders_the_nested_hook_specific_output():
    out = claude_code.render(Verdict(Decision.DENY, "carries data from .env (step 4)",
                                      "secret_exact"))
    d = json.loads(out)["hookSpecificOutput"]
    assert d["hookEventName"] == "PreToolUse"
    assert d["permissionDecision"] == "deny"
    # ⚠ STARTS WITH THE ENGINE'S REASON (no send is named here, so no
    # sentence), then what to do next — see adapters/_common.told. Asserted as
    # a PROPERTY rather than a literal: the engine's words are the contract.
    reason = d["permissionDecisionReason"]
    # ⚠ PREFIXED so it is obviously Sting's — Claude Code prints this verbatim.
    assert "STING BLOCKED" in reason.upper(), reason
    assert "carries data from .env (step 4)" in reason, reason
    # ⚠ RE-PINNED (docs/108): the rule id and the way out are the human's, in
    # `systemMessage`; the model reads neither.
    assert "secret_exact" not in reason and "policy.json" not in reason
    human = json.loads(out)["systemMessage"]
    assert "secret_exact" in human, "the refusal does not name its rule"
    assert "policy.json" in human, "the refusal offers no way forward"


def test_ask_renders_as_ask():
    out = claude_code.render(Verdict(Decision.ASK, "confirm the destination", "derived"))
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_deny_with_no_reason_still_renders_valid_json():
    out = claude_code.render(Verdict(Decision.DENY, None, None))
    # ⚠ A DENY WITH NO REASON STILL SAYS WHO STOPPED IT. It used to render an
    # empty string, which in Claude Code's UI is indistinguishable from the
    # agent's own refusal.
    # ⚠ RE-PINNED (docs/108): what to do next follows it, so the agent is told
    # to stop rather than left with a bare headline.
    assert json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"] == (
        "⛔ STING BLOCKED THIS — the action was NOT run.\n"
        "  Don't retry, split or re-encode this.\n"
        "  Stop and tell the user this was blocked.")


# --------------------------------------------------------- the architecture rule
def _code_without_docstrings(module) -> str:
    """Executable code only — comments and docstrings stripped.

    Prose may legitimately mention a policy concept to explain why a field is
    extracted. Code may not.
    """
    import ast
    from pathlib import Path

    tree = ast.parse(Path(module.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def test_adapter_contains_no_policy_logic():
    """Adapters do exactly three jobs: parse, render, and state their own probe
    shape. No decisions.

    A rule name or a verdict-construction here would mean policy has leaked out
    of the engine, and every future agent would need the same rule re-written.

    ⚠ `probe_payload` IS PART OF THE CONTRACT AND IS STILL NOT POLICY. It emits
    one payload in this vendor's own shape so `tools/preflight.py` can drive the
    I02 sequence through THIS adapter; the sequence and the verdict both belong
    to the engine. Before it existed the semantic check ran for claude-code only
    and printed "skipped" for the other four — see docs/24-adapter-contract.md.
    """
    import ast
    from pathlib import Path

    tree = ast.parse(Path(claude_code.__file__).read_text())
    funcs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    # `_stings_own` composes the refusal TEXT; it makes no policy decision.
    funcs.discard("_stings_own")
    # `_extract_replaced` is parsing too: the text an Edit replaces, which the
    # engine needs to judge an edit it cannot read the file for (item C step 3b).
    assert funcs == {"_extract_paths", "_extract_content", "_extract_replaced",
                     "parse", "render", "probe_payload"}, (
        f"unexpected functions: {funcs}")

    code = _code_without_docstrings(claude_code)
    # It may name Decision in order to render it, but must never build a Verdict.
    assert "Verdict(" not in code, "an adapter must not construct verdicts"
    for policy_word in ("SECRET", "UNTRUSTED", "fingerprint", "sink", "tainted",
                        "credential", "holds_secret"):
        assert policy_word not in code, \
            f"policy concept '{policy_word}' leaked into adapter CODE"


def test_adapter_imports_only_types_from_core():
    """An adapter that imports the engine has inverted the dependency."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(claude_code.__file__).read_text())
    core_imports = {n.module for n in ast.walk(tree)
                    if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("core")}
    # ⚠ NON-EMPTY FIRST. `set() <= {"core.types"}` is true, so an adapter that
    # imported nothing from core at all — or a file this failed to parse
    # meaningfully — would pass a test whose whole subject is WHICH core module
    # it reaches into.
    assert core_imports, "the adapter imports nothing from core, so this proves nothing"
    assert core_imports <= {"core.types"}, f"adapter reaches into: {core_imports}"


def test_shared_helpers_contain_no_policy():
    """_common.py is translation plumbing. Path resolution lives there so five
    adapters cannot drift into five different symlink behaviours."""
    from adapters import _common
    code = _code_without_docstrings(_common)
    for policy_word in ("SECRET", "UNTRUSTED", "fingerprint", "sink", "tainted",
                        "credential", "Verdict", "Decision"):
        assert policy_word not in code, f"policy concept '{policy_word}' in _common"
