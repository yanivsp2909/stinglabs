"""
The contract EVERY adapter must meet, applied to all of them.

⚠ THIS FILE IS THE SPECIFICATION, NOT AN INTERNAL CHECK. A new agent is added by
writing `adapters/<name>.py` and one line in `adapters/__init__.py`; every test
here is parametrised over that REGISTRY, so a contributor does not write these
tests — they pass them. What a pass means, and what it does not, is written out
in docs/24-adapter-contract.md.

    python3 -m pytest tests/test_adapter_conformance.py \
                      tests/test_semantic_probe.py -q

Written once and parametrised rather than copy-pasted per vendor, because the
whole premise is that adapters are interchangeable translators. A property that
holds for only three of the four is a property the engine cannot rely on.

Per-vendor payload mapping is tested in test_adapter_<vendor>.py; this file is
about the shared contract.
"""
import ast
import inspect
import json
from pathlib import Path

import pytest

import hook_entry
from adapters import ADAPTERS_BY_NAME
from adapters import _common, antigravity, claude_code, codex, copilot, cursor
from core.types import Action, ActionKind, Decision, Verdict

# ⚠ THE REGISTRY, NOT A LIST RESTATED HERE. A hand-written copy is a list that
# can be missing the newest adapter — and the missing one is precisely the one
# nobody has checked. Add a module to `adapters/__init__.py` and every test in
# this file applies to it without another edit.
ADAPTERS = ADAPTERS_BY_NAME

# Payloads shaped like each vendor actually sends, all describing the same act:
# run `git push origin main`.
NATIVE_EXEC_PAYLOAD = {
    "claude-code": {"session_id": "s1", "cwd": "/tmp", "hook_event_name": "PreToolUse",
                    "tool_name": "Bash", "tool_input": {"command": "git push origin main"}},
    "copilot": {"session_id": "s1", "cwd": "/tmp", "hook_event_name": "PreToolUse",
                "tool_name": "bash", "tool_input": {"command": "git push origin main"}},
    "cursor": {"conversation_id": "s1", "cwd": "/tmp",
               "hook_event_name": "beforeShellExecution",
               "workspace_roots": ["/tmp"], "command": "git push origin main"},
    "codex": {"session_id": "s1", "cwd": "/tmp", "tool_name": "bash",
              "tool_input": {"command": "git push origin main"}},
    "antigravity": {"conversationId": "s1", "stepIdx": 7,
                    "workspacePaths": ["/tmp"],
                    "toolCall": {"name": "run_command",
                                 "args": {"CommandLine": "git push origin main",
                                          "Cwd": "/tmp"}}},
}

MALFORMED = [
    {}, None, [], "not a dict", 42,
    {"tool_name": None}, {"tool_input": "nope"}, {"toolCall": "nope"},
    {"toolCall": {"args": None}}, {"tool_input": {"command": 123}},
    {"workspace_roots": "not-a-list"}, {"workspacePaths": 5},
    {"stepIdx": "not-an-int"}, {"conversationId": 999},
    {"tool_input": {"file_path": "\0bad"}},
]

ALL = list(ADAPTERS.items())
IDS = list(ADAPTERS)


# ------------------------------------------------------------------ interface
@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_adapter_exposes_parse_and_render(name, mod):
    assert callable(mod.parse) and callable(mod.render)
    assert list(inspect.signature(mod.parse).parameters) == ["raw"]
    # `action` says which event a verdict answers, where an agent's answer
    # differs by event (Cursor; docs/110 §A). Optional: every caller that has
    # no action still gets the answer it always did.
    assert list(inspect.signature(mod.render).parameters) == ["verdict", "action"]
    assert inspect.signature(mod.render).parameters["action"].default is None
    assert mod.AGENT == name


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_every_adapter_is_registered_in_hook_entry(name, mod):
    assert hook_entry.ADAPTERS[name] is mod


# --------------------------------------------------- the same act, same Action
@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_the_same_act_normalises_to_the_same_action(name, mod):
    """Five payload shapes, one normalised result. This is the whole premise:
    the engine sees `git push origin main` identically regardless of vendor."""
    a = mod.parse(NATIVE_EXEC_PAYLOAD[name])
    assert a.kind is ActionKind.EXEC
    assert a.command == "git push origin main"
    assert a.session_id == "s1"
    assert a.agent == name


def test_no_two_adapters_disagree_about_the_same_act():
    actions = {n: m.parse(NATIVE_EXEC_PAYLOAD[n]) for n, m in ALL}
    kinds = {a.kind for a in actions.values()}
    commands = {a.command for a in actions.values()}
    assert kinds == {ActionKind.EXEC}, f"kinds diverged: {kinds}"
    assert commands == {"git push origin main"}, f"commands diverged: {commands}"


# -------------------------------------------------------------- never raises
@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
@pytest.mark.parametrize("raw", MALFORMED, ids=lambda r: str(r)[:30])
def test_parse_never_raises(name, mod, raw):
    a = mod.parse(raw)
    assert isinstance(a, Action)
    assert isinstance(a.kind, ActionKind)
    assert isinstance(a.paths, tuple)
    assert isinstance(a.seq, int)
    assert isinstance(a.session_id, str) and a.session_id
    assert isinstance(a.cwd, str) and a.cwd
    assert a.agent == name


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_parse_always_returns_absolute_paths(name, mod, tmp_path):
    raw = dict(NATIVE_EXEC_PAYLOAD[name])
    a = mod.parse(raw)
    assert all(p.startswith("/") for p in a.paths), a.paths


# --------------------------------------------------------- workspace roots
@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_every_adapter_populates_workspace_roots(name, mod):
    """Never empty. An empty tuple would make every path look like it was
    outside the project, drawing the trust boundary wrong and silently."""
    a = mod.parse(NATIVE_EXEC_PAYLOAD[name])
    assert a.workspace_roots, f"{name} left workspace_roots empty"
    assert isinstance(a.workspace_roots, tuple)
    assert all(r.startswith("/") for r in a.workspace_roots), a.workspace_roots


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
@pytest.mark.parametrize("raw", MALFORMED, ids=lambda r: str(r)[:24])
def test_workspace_roots_survives_malformed_input(name, mod, raw):
    assert mod.parse(raw).workspace_roots, f"{name} produced no roots"


@pytest.mark.parametrize("name", ["claude-code", "copilot", "codex"])
def test_single_directory_agents_report_exactly_one_root(name):
    a = ADAPTERS[name].parse(NATIVE_EXEC_PAYLOAD[name])
    assert len(a.workspace_roots) == 1
    assert a.workspace_roots[0] == a.cwd or a.workspace_roots[0].endswith("tmp")


def test_cursor_reports_every_root_of_a_multi_root_workspace():
    a = cursor.parse({"conversation_id": "s1",
                      "hook_event_name": "beforeShellExecution",
                      "workspace_roots": ["/repo/api", "/repo/web", "/repo/shared"],
                      "command": "pytest"})
    assert a.workspace_roots == ("/repo/api", "/repo/web", "/repo/shared")


def test_antigravity_reports_every_root_of_a_multi_root_workspace():
    a = antigravity.parse({"conversationId": "s1", "stepIdx": 3,
                           "workspacePaths": ["/repo/api", "/repo/web"],
                           "toolCall": {"name": "run_command",
                                        "args": {"CommandLine": "pytest"}}})
    assert a.workspace_roots == ("/repo/api", "/repo/web")


@pytest.mark.parametrize("mod,payload", [
    (cursor, {"conversation_id": "s1", "hook_event_name": "beforeShellExecution",
              "cwd": "/only/here", "command": "ls"}),
    (antigravity, {"conversationId": "s1",
                   "toolCall": {"name": "run_command",
                                "args": {"CommandLine": "ls", "Cwd": "/only/here"}}}),
], ids=["cursor", "antigravity"])
def test_multi_root_agents_fall_back_to_cwd_when_no_roots_declared(mod, payload):
    a = mod.parse(payload)
    assert a.workspace_roots == ("/only/here",)


def test_a_sibling_root_is_inside_the_project_not_outside():
    """The false positive this field exists to prevent: in a monorepo, reading
    from a sibling root must not read as 'outside the project'.

    docs/08 lists it as a dogfooding signal — "A monorepo or sibling-repo read
    flagged as untrusted | The trust boundary is drawn wrong."
    """
    a = cursor.parse({"conversation_id": "s1", "hook_event_name": "beforeReadFile",
                      "workspace_roots": ["/repo/api", "/repo/web"],
                      "cwd": "/repo/api",
                      "file_path": "/repo/web/src/index.ts"})
    sibling = a.paths[0]
    assert not sibling.startswith(a.cwd), "precondition: it is outside cwd"
    assert any(sibling.startswith(root) for root in a.workspace_roots), \
        "but it IS inside the project — set membership, not one prefix"


# ------------------------------------------------------------------ rendering
@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_allow_always_renders_empty(name, mod):
    """⚠ NO LONGER TRUE OF CLAUDE CODE, AND DELIBERATELY STILL TRUE OF THE
    OTHER FOUR.

    Empty stdout plus exit 0 was believed to mean "proceed" everywhere. Read
    against Claude Code's shipped binary it means NO OPINION — the agent then
    runs its own permission flow, which in manual mode prompts. Claude Code now
    gets an explicit `permissionDecision: "allow"`.

    ⚠ AND NOT OF CURSOR (docs/110 §A). Read in Cursor 3.7.27's shipped code,
    an empty stdout is a FAILED hook, and with the `failClosed: true` enforce
    mode writes it is blocked: every command Sting allowed was refused. Cursor
    gets `{"permission": "allow"}`, which approves nothing Cursor would ask
    about (tests/test_cursor_honours_the_answer.py).

    Codex, Copilot and Antigravity read an empty stdout as "no say", in their
    source and docs (docs/110 §A), so theirs stays empty.
    """
    if name == "claude-code":
        decision = json.loads(mod.render(Verdict(Decision.ALLOW, None, None)))
        assert decision["hookSpecificOutput"]["permissionDecision"] == "allow"
        return
    if name == "cursor":
        assert json.loads(mod.render(Verdict(Decision.ALLOW, None, None))) == {
            "permission": "allow"}
        return
    assert mod.render(Verdict(Decision.ALLOW, None, None)) == ""


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_deny_renders_valid_json_carrying_the_reason(name, mod):
    out = mod.render(Verdict(Decision.DENY, "carries data from .env (step 4)", "r1"))
    assert out, "a deny must produce output"
    assert "carries data from .env (step 4)" in json.dumps(json.loads(out))


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_deny_with_no_reason_still_renders_valid_json(name, mod):
    json.loads(mod.render(Verdict(Decision.DENY, None, None)))


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_ask_never_renders_as_allow(name, mod):
    """ASK is not universal — Codex honours only `deny`. Whatever each adapter
    does with ASK, it must never come out meaning 'go ahead'."""
    out = mod.render(Verdict(Decision.ASK, "confirm the destination", "r2"))
    assert out != "", f"{name} rendered ASK as allow"
    body = json.dumps(json.loads(out))
    assert "allow" not in body, f"{name} rendered ASK as an allow: {body}"


def test_codex_downgrades_ask_to_deny_and_says_so():
    """Codex's parser rejects `ask`, so wanting a human and not getting one must
    fail safe, and the developer must be told why they got a hard block."""
    # ⚠ RE-PINNED (docs/108 §5): nested, the shape Codex reads.
    out = json.loads(codex.render(Verdict(Decision.ASK, "confirm", "r")))["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "cannot prompt" in out["permissionDecisionReason"]


# ------------------------------------------------- the documented response shapes
def test_response_shapes_match_each_vendors_documentation():
    deny = Verdict(Decision.DENY, "because", "r")

    # Nested — Claude Code; Copilot nested AND flat (VS Code reads the one,
    # the CLI and the cloud agent document the other: docs/110 §A)
    assert json.loads(claude_code.render(deny))["hookSpecificOutput"]["permissionDecision"] == "deny"
    cp = json.loads(copilot.render(deny))
    assert cp["hookSpecificOutput"]["permissionDecision"] == cp["permissionDecision"] == "deny"
    assert cp["hookSpecificOutput"]["hookEventName"] == "PreToolUse"

    # Cursor — its own vocabulary, snake_case
    cur = json.loads(cursor.render(deny))
    # ⚠ THE SHAPE IS THE SUBJECT HERE, NOT THE PROSE. `user_message` is what
    # the MODEL is told (docs/110 §A), composed once in `_common.told`; it
    # carries no way out.
    assert cur["permission"] == "deny"
    assert cur["user_message"].startswith("because"), cur["user_message"]
    assert "hookSpecificOutput" not in cur

    # Codex — NESTED. ⚠ RE-PINNED (docs/108 §5): it was flat, a shape Codex's
    # own parser refuses, and a refused parse lets the call run — confirmed
    # live on 29 Sep 2026. tests/test_codex_reads_the_block.py applies Codex's
    # parsing to this output.
    cx = json.loads(codex.render(deny))
    assert cx["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert cx["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert "permissionDecision" not in cx

    # Antigravity — flat, different key again
    ag = json.loads(antigravity.render(deny))
    assert ag["decision"] == "deny"
    assert ag["reason"].startswith("because"), ag["reason"]
    assert "permissionOverrides" not in ag, "a guard must not hand out permissions"


def test_antigravity_uses_step_idx_as_seq_without_recomputing():
    a = antigravity.parse(NATIVE_EXEC_PAYLOAD["antigravity"])
    assert a.seq == 7, "stepIdx is already monotonic — do not recompute it"


def test_multi_root_workspaces_do_not_silently_take_element_zero():
    """Both Cursor and Antigravity send an ARRAY of roots. All of them are the
    project, so "inside the project" is set membership, not one prefix."""
    assert _common.workspace_roots(["/a", "/b"], "") == ("/a", "/b")


@pytest.mark.parametrize("value,fallback,expected", [
    (["/a", "/b"],   "",           ("/a", "/b")),      # the documented shape
    (["/a", "/a"],   "",           ("/a",)),           # duplicates collapse
    ("/single/root", "/fallback",  ("/single/root",)), # a bare string is one root
    ([],             "/fallback",  ("/fallback",)),    # empty list -> fallback
    (None,           "/fallback",  ("/fallback",)),
    (5,              "/fallback",  ("/fallback",)),
    ({"a": 1},       "/fallback",  ("/fallback",)),
    ([None, "/a"],   "",           ("/a",)),           # junk entries dropped
])
def test_workspace_roots_is_defensive(value, fallback, expected):
    assert _common.workspace_roots(value, fallback) == expected


# ------------------------------------------------------- the architecture rule
def _code_without_docstrings(mod) -> str:
    tree = ast.parse(Path(mod.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            b = getattr(node, "body", [])
            if b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant) \
                    and isinstance(b[0].value.value, str):
                node.body = b[1:] or [ast.Pass()]
    return ast.unparse(tree)


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_no_adapter_contains_policy(name, mod):
    code = _code_without_docstrings(mod)
    assert "Verdict(" not in code, f"{name} constructs verdicts"
    for word in ("SECRET", "UNTRUSTED", "fingerprint", "tainted", "holds_secret",
                 "credential"):
        assert word not in code, f"policy concept '{word}' leaked into {name}"


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_no_adapter_imports_the_engine(name, mod):
    tree = ast.parse(Path(mod.__file__).read_text())
    modules = {n.module for n in ast.walk(tree)
               if isinstance(n, ast.ImportFrom) and n.module}
    # ⚠ BOTH ASSERTIONS BELOW ARE TRUE OF AN EMPTY SET, so an adapter that
    # imported nothing — or a parse that produced nothing — would pass a test
    # about what it is allowed to import.
    assert modules, f"{name} parsed to no imports at all"
    assert "core.engine" not in modules, f"{name} imports the engine"
    core = {m for m in modules if m.startswith("core")}
    assert core, f"{name} imports nothing from core, so the next line is vacuous"
    assert core <= {"core.types"}


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_adapters_reach_the_engine_through_hook_entry(name, mod):
    """End to end: the vendor's own payload shape produces an allow.

    ⚠ WHAT "AN ALLOW" LOOKS LIKE NOW DIFFERS BY AGENT. Claude Code gets an
    explicit `permissionDecision: "allow"`, because empty output there means NO
    OPINION and the agent falls back to its own prompt. The other four still
    render empty and are deliberately untouched — see
    `test_allow_always_renders_empty`.
    """
    out, err, code = hook_entry.run(json.dumps(NATIVE_EXEC_PAYLOAD[name]), agent=name)
    assert code == 0 and err == ""
    if name == "claude-code":
        assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "allow"
    elif name == "cursor":
        assert json.loads(out) == {"permission": "allow"}
    else:
        assert out == ""


# ═════════════ the contract as a SPECIFICATION — what a sixth agent must meet

def test_the_suite_covers_every_registered_adapter():
    """⚠ THE GUARD ON THE GUARD. Every test here is parametrised over
    `ADAPTERS`, so this only means something if `ADAPTERS` really is the
    registry rather than a copy that drifted from it."""
    assert ADAPTERS is ADAPTERS_BY_NAME
    assert set(ADAPTERS) == set(hook_entry.ADAPTERS), (
        "hook_entry dispatches over a different set than this suite checks")


def test_every_adapter_is_keyed_by_its_own_AGENT_constant():
    """⚠ ONE STRING, NOT THREE THAT HAPPEN TO MATCH. The registry key, the
    `--agent` value and the label stamped into every record are the same value.
    Two spellings would route correctly and label wrongly — the guard works and
    the evidence points at the wrong tool."""
    for name, mod in ADAPTERS.items():
        assert mod.AGENT == name, f"{mod.__name__}.AGENT is {mod.AGENT!r}, keyed {name!r}"


def test_every_adapter_exposes_the_whole_contract():
    """parse, render, probe_payload, AGENT. Nothing else is required, and
    nothing less is enough — see docs/24-adapter-contract.md."""
    for name, mod in ADAPTERS.items():
        for required in ("AGENT", "parse", "render", "probe_payload"):
            assert hasattr(mod, required), f"{name} is missing {required}"


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_an_adapter_never_supplies_its_own_seq(name, mod):
    """⚠ THE SESSION LAYER ASSIGNS `seq`, AND AN ADAPTER MUST NOT PRE-EMPT IT.

    Antigravity is the one that carries a sequence number in its payload, and it
    passes it through as a CLAIM — `hook_entry` still runs it through
    `state.next_seq`, which is `max(supplied, self.seq)`. So the guarantee is
    MONOTONE, not increasing: a supplied number can never take the session
    BACKWARDS, which is what would let a record overwrite an earlier one in the
    chain by reusing its number.

    ⚠ Asserted as `>=`, not `>`, because that is the property that actually
    holds — `max(7, 41)` is 41. Writing `>` here would have been a test that
    demanded something the code never promised, which is how a correct
    implementation gets "fixed" into a broken one.
    """
    from core.types import SessionState

    action = mod.parse(NATIVE_EXEC_PAYLOAD[name])
    assert SessionState(seq=41).next_seq(action.seq) >= 41, (
        f"{name}: an adapter-supplied seq moved the session backwards")
    # and a hostile one cannot either
    for hostile in (-5, 0, 1):
        assert SessionState(seq=41).next_seq(hostile) >= 41, hostile


@pytest.mark.parametrize("name,mod", ALL, ids=IDS)
def test_an_adapter_cannot_forge_an_allow_once_grant(name, mod):
    """⚠ THE FINGERPRINT IS COMPUTED ENGINE-SIDE, over the parsed Action. An
    adapter that supplied one could mint a grant for an action a human never
    approved — so a fingerprint field in the payload must change nothing."""
    from core import allow_once

    honest = mod.parse(NATIVE_EXEC_PAYLOAD[name])
    lying = dict(NATIVE_EXEC_PAYLOAD[name])
    lying.update({"action_hash": "f" * 64, "fingerprint": "f" * 64,
                  "allow_once": True, "grant": "f" * 64})
    assert allow_once.fingerprint(mod.parse(lying)) == allow_once.fingerprint(honest), (
        f"{name}: a payload field influenced the action fingerprint")
