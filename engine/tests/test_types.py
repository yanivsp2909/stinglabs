"""
Step 1 — the types exist, are genuinely frozen, and carry no logic.

The last point is the one worth testing. types.py is the boundary the whole
architecture rests on; the moment it imports an adapter or the engine, the
separation is gone and every future agent costs a change to the policy code.
"""
import dataclasses

import pytest

from core.types import Action, ActionKind, Decision, Verdict


def make_action(**overrides) -> Action:
    base = dict(
        session_id="01J8ZQ9K7X2V4M6N8P0R2T4W6Y",
        seq=1,
        kind=ActionKind.EXEC,
        paths=(),
        command="git push origin main",
        url=None,
        tool_name=None,
        content=None,
        cwd="/workspace/project",
        workspace_roots=("/workspace/project",),
        agent="claude-code",
    )
    return Action(**{**base, **overrides})


def test_construct_an_action():
    a = make_action()
    assert a.kind is ActionKind.EXEC
    assert a.command == "git push origin main"
    assert a.agent == "claude-code"


def test_construct_a_verdict():
    v = Verdict(decision=Decision.DENY,
                reason="this carries data from .env, read at step 4",
                rule_id="secret_exact")
    assert v.decision is Decision.DENY
    assert "step 4" in v.reason


def test_verdict_allows_empty_reason_and_rule():
    v = Verdict(decision=Decision.ALLOW, reason=None, rule_id=None)
    assert v.decision is Decision.ALLOW and v.reason is None


@pytest.mark.parametrize("kind", list(ActionKind))
def test_every_action_kind_is_constructible(kind):
    assert make_action(kind=kind).kind is kind


def test_action_kinds_are_exactly_the_six_specified():
    assert {k.name for k in ActionKind} == {
        "READ", "WRITE", "EDIT", "EXEC", "FETCH", "TOOL"}


def test_decisions_are_exactly_the_three_specified():
    assert {d.name for d in Decision} == {"ALLOW", "ASK", "DENY"}


def test_enums_are_strings_so_they_serialise_without_a_custom_encoder():
    assert ActionKind.EXEC == "EXEC"
    assert Decision.DENY == "DENY"
    assert f"{Decision.ASK}" == "ASK"


# ------------------------------------------------------------------ immutability
def test_action_is_frozen():
    a = make_action()
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.command = "rm -rf /"


def test_verdict_is_frozen():
    v = Verdict(Decision.ALLOW, None, None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.decision = Decision.DENY


def test_workspace_roots_has_no_default_so_it_cannot_be_silently_empty():
    """An adapter that forgot to populate roots would otherwise yield (), and
    every path would look like it was outside the project — the trust boundary
    drawn wrong, quietly. Omitting it must be a TypeError, not a default."""
    import dataclasses as dc
    field = {f.name: f for f in dc.fields(Action)}["workspace_roots"]
    assert field.default is dc.MISSING and field.default_factory is dc.MISSING


def test_workspace_roots_is_a_tuple_of_every_root():
    a = make_action(workspace_roots=("/repo/api", "/repo/web"))
    assert a.workspace_roots == ("/repo/api", "/repo/web")
    assert not hasattr(a.workspace_roots, "append")


def test_paths_cannot_be_mutated_through_the_field():
    """Why paths is a tuple and not the spec's list: frozen=True does not
    freeze a list's contents, and Action is the object every policy decision
    reads from."""
    a = make_action(paths=("/workspace/project/.env",))
    assert not hasattr(a.paths, "append")
    with pytest.raises((TypeError, AttributeError)):
        a.paths[0] = "/etc/passwd"


# ------------------------------------------------------- the architecture rule
def test_types_module_imports_nothing_from_this_project():
    """core/types.py is the boundary. If it grows a project import, the
    separation the whole design rests on has already leaked."""
    import ast
    from pathlib import Path

    src = Path(__file__).parent.parent / "core" / "types.py"
    tree = ast.parse(src.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    local = {"core", "adapters", "runner", "hook_entry", "tests"}
    assert not (imported & local), f"types.py imports project modules: {imported & local}"
    assert imported <= {"__future__", "dataclasses", "enum", "typing"}, f"unexpected: {imported}"


def test_the_boundary_dtos_have_no_methods():
    """Action and Verdict are what adapters produce and consume. Behaviour on
    them would be behaviour living outside the engine.

    SessionState is exempt — it is a state machine and its helpers touch nothing
    outside themselves. World is a Protocol, so method signatures are the point.
    """
    import ast
    from pathlib import Path

    tree = ast.parse((Path(__file__).parent.parent / "core" / "types.py").read_text())
    top_level_funcs = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
    assert not top_level_funcs, f"types.py grew module-level logic: {top_level_funcs}"
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name in ("Action", "Verdict"):
            methods = [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
            assert not methods, f"{node.name} grew methods: {methods}"


def test_types_module_performs_no_io():
    """The engine imports this. If a type can touch the filesystem, the engine
    can too, and the pure-function property is gone."""
    import ast
    from pathlib import Path

    tree = ast.parse((Path(__file__).parent.parent / "core" / "types.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for io_module in ("os", "subprocess", "pathlib", "shutil", "socket", "fcntl"):
        assert io_module not in imported, f"types.py imports {io_module}"
