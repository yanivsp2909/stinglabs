"""
Step 3 — the single entry point, and the stub engine behind it.

Two things are being pinned here:

1. The exit-code contract. 0 means a verdict was produced; 2 means the guard
   could not decide and the caller must NOT read that as an allow. This is the
   contract the runner scores against, and getting it wrong is how a fully
   broken guard reports a clean-looking 0/60.

2. The architecture. engine.py imports only core.types, references no agent
   field name, and never touches stdin/stdout/JSON.
"""
import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

import hook_entry
from core import engine
from core.probes import NullWorld
from core.types import Action, ActionKind, Decision, SessionState, Verdict
from tests import engine_source

ROOT = Path(__file__).parent.parent


def payload(tool="Bash", tool_input=None, **extra):
    d = {"session_id": "s1", "cwd": "/tmp", "hook_event_name": "PreToolUse",
         "tool_name": tool, "tool_input": tool_input or {"command": "ls"}}
    d.update(extra)
    return json.dumps(d)


# ------------------------------------------------- shape of a clean verdict
def test_a_clean_session_doing_ordinary_work_is_allowed():
    """Was `test_engine_stub_allows_everything`, from step 3 when the engine
    was a stub. Its example command was `rm -rf /`, which mechanism 1 now
    escalates — see the test below. The structural check it was really making
    (decide returns a well-formed Verdict) is kept with a benign command."""
    a = Action("s", 0, ActionKind.EXEC, (), "ls -la", None, None, None,
               "/tmp", ("/tmp",), "x")
    v = engine.decide(a, SessionState(), NullWorld())
    assert isinstance(v, Verdict)
    assert v.decision is Decision.ALLOW


def test_rm_rf_root_now_escalates_even_in_a_clean_session():
    """Mechanism 1. Irreversibility is a property of the action, so it does not
    need a label or a sink — this session has neither.

    ⚠ THE VERDICT MOVED FROM ASK TO DENY, and this test moved with it rather
    than being loosened. `rm -rf /` is now caught by `catastrophic_delete`
    ABOVE mechanism 1, because the resolved target IS the filesystem root. What
    this test guards is unchanged and still guarded: a clean session, no label,
    no sink, and the action is still escalated on its own properties. It is
    escalated further than it was."""
    a = Action("s", 0, ActionKind.EXEC, (), "rm -rf /", None, None, None,
               "/tmp", ("/tmp",), "x")
    v = engine.decide(a, SessionState(), NullWorld())
    assert v.decision is Decision.DENY
    assert v.rule_id == "catastrophic_delete"


@pytest.mark.parametrize("kind", list(ActionKind))
def test_engine_returns_a_verdict_for_every_kind(kind):
    a = Action("s", 0, kind, ("/tmp/x",), "c", "u", "t", "content",
               "/tmp", ("/tmp",), "x")
    assert engine.decide(a, SessionState(), NullWorld()).decision is Decision.ALLOW


# --------------------------------------------------------------- the pipeline
def test_allow_produces_empty_stdout_and_exit_zero():
    out, err, code = hook_entry.run(payload())
    assert (out, err, code) == ('{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": "Sting: allowed"}}', "", 0)


def test_deny_is_rendered_through_the_adapter(monkeypatch):
    """The entry point must not format verdicts itself — that is the adapter's
    job, and it differs per agent."""
    monkeypatch.setattr(engine, "decide",
                        lambda a, s, w: Verdict(Decision.DENY, "nope", "test_rule"))
    out, err, code = hook_entry.run(payload())
    assert code == 0 and err == ""
    d = json.loads(out)["hookSpecificOutput"]
    assert d["permissionDecision"] == "deny"
    # The entry point still formats nothing itself — the adapter composes this,
    # and what the agent is told comes from `_common.told`. What this test owns
    # is that the ENGINE'S words reach the agent UNALTERED.
    #
    # ⚠ THEY ARE NO LONGER FIRST, AND THAT IS DELIBERATE. Claude Code prints
    # this string verbatim, so without a name in front of it a refusal reads as
    # the agent's own — which is exactly what the operator reported. The
    # headline is Sting's; everything after it is still the engine's, unedited.
    reason = d["permissionDecisionReason"]
    assert reason.startswith("⛔ STING BLOCKED THIS")
    assert reason.splitlines()[1].strip() == "nope"
    # ⚠ RE-PINNED (docs/108): the rule id keys `~/.sting/policy.json`, so it is
    # the human's, in `systemMessage`, and not in what the model reads.
    assert "test_rule" not in reason
    assert "test_rule" in json.loads(out)["systemMessage"]


def test_the_action_reaching_the_engine_is_normalised(monkeypatch):
    seen = []

    def capture(action, state, world):
        seen.append(action)
        return Verdict(Decision.ALLOW, None, None)

    monkeypatch.setattr(engine, "decide", capture)
    # ⚠ THE AGENT IS NAMED. It used to be omitted, and `run()` defaulted to
    # claude-code — so this assertion read as "the adapter stamps its name"
    # while actually asserting the default. Declaring it makes the claim the
    # one the test means; the undeclared case is covered separately below.
    hook_entry.run(payload("Read", {"file_path": "/tmp/x.txt"}),
                    agent="claude-code")

    assert len(seen) == 1
    action = seen[0]
    assert isinstance(action, Action)
    assert action.kind is ActionKind.READ
    assert action.agent == "claude-code"
    # Resolved, symlinks followed — on macOS /tmp is itself a symlink to
    # /private/tmp, so comparing against the literal input would be wrong.
    assert action.paths == (str(Path("/tmp/x.txt").resolve()),)


# ------------------------------------------------ failures are NOT allows
def test_unknown_agent_fails_closed():
    out, err, code = hook_entry.run(payload(), agent="windsurf")
    assert code == 2 and out == "" and "unknown agent" in err


def test_unparseable_json_fails_closed():
    out, err, code = hook_entry.run("{not json at all")
    assert code == 2 and out == ""
    assert "could not parse" in err


def test_an_engine_crash_fails_closed_not_open(monkeypatch):
    """The whole point of the exit-code contract."""
    def boom(action, state, world):
        raise RuntimeError("engine exploded")
    monkeypatch.setattr(engine, "decide", boom)
    out, err, code = hook_entry.run(payload())
    assert code == 2, "a crashed guard must never read as an allow"
    assert out == ""
    assert "RuntimeError" in err and "engine exploded" in err


def test_empty_stdin_fails_closed():
    """⚠ THIS ASSERTED `code == 0` AND THAT WAS THE HOLE.

    An empty payload became `{}`, parsed into an action naming nothing, and the
    engine allowed it. Harmless while ALLOW rendered as empty output — Claude
    Code applied its own rules. The moment ALLOW became explicit it turned into
    the guard PERMITTING an action on a payload it never received.

    "I was sent nothing" is not "go ahead".
    """
    out, err, code = hook_entry.run("")
    assert code == 2, "an empty payload was answered with a verdict"
    assert out == ""
    assert "failed to decide" in err and "NOT a policy refusal" in err


@pytest.mark.parametrize("argv,expected", [
    # ⚠ `[]` USED TO EXPECT "claude-code", AND THAT LINE WAS THE BUG PINNED.
    # An invocation that names no agent is not a Claude Code invocation; it is
    # an invocation nobody labelled. The failure mode of the old value was a
    # WRONG name, never a missing one — every record a Cursor install produced
    # before `--agent` was always passed says claude-code, and a reader has no
    # way to tell those from the real ones.
    ([], "unknown"),
    (["--agent", "cursor"], "cursor"),
    (["--agent=codex"], "codex"),
    (["--other", "x", "--agent", "copilot"], "copilot"),
])
def test_pick_agent_from_argv(argv, expected):
    assert hook_entry.pick_agent(argv) == expected


def test_pick_agent_from_env(monkeypatch):
    monkeypatch.setenv("STING_AGENT", "antigravity")
    assert hook_entry.pick_agent([]) == "antigravity"


def test_argv_beats_env(monkeypatch):
    monkeypatch.setenv("STING_AGENT", "antigravity")
    assert hook_entry.pick_agent(["--agent", "cursor"]) == "cursor"


# ------------------------------------------------- as a real subprocess
def run_proc(stdin_text, *args):
    return subprocess.run([sys.executable, str(ROOT / "hook_entry.py"), *args],
                           input=stdin_text, capture_output=True, text=True)


def test_subprocess_allow_is_silent_exit_zero():
    p = run_proc(payload())
    # ⚠ an ALLOW is now an explicit permissionDecision, not empty stdout — empty means NO OPINION and Claude Code prompts
    assert p.returncode == 0
    assert json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_subprocess_unknown_agent_exits_two():
    p = run_proc(payload(), "--agent", "nope")
    assert p.returncode == 2 and p.stdout.strip() == ""


def test_subprocess_is_runnable_from_any_cwd(tmp_path):
    """Hook configs invoke this by absolute path from the project directory."""
    p = subprocess.run([sys.executable, str(ROOT / "hook_entry.py")],
                        input=payload(), capture_output=True, text=True, cwd=tmp_path)
    assert p.returncode == 0, p.stderr


# --------------------------------------------------------- the architecture rule
# Pure computation only. Anything that can reach the filesystem, the network or
# another process is banned — that is what the World protocol is for.
_PURE_STDLIB = {"__future__", "hashlib", "math", "re", "collections", "typing",
                "dataclasses", "enum", "functools", "itertools", "string",
                # CRC32 is arithmetic; core/known_formats.py uses it for the
                # GitHub/npm token checksum and nothing else.
                "zlib",
                # A binary search over a list; core/guard_runs.py uses it to
                # find a run it already read (item 1).
                "bisect",
                # Decoding, bytes to bytes, like zlib: core/mcp_arguments.py
                # reads base64/base32 in an MCP call's arguments (docs/112 §3).
                "base64", "binascii"}
_IO_MODULES = {"os", "subprocess", "pathlib", "shutil", "socket", "fcntl", "io",
               "json", "sys", "urllib", "requests", "tempfile", "glob"}


def test_engine_imports_only_core_types_and_pure_stdlib():
    """The engine may compute. It may not reach outside itself.

    Every file the engine is made of (tests/engine_source.py), each held to the
    same allowlist: a part of the engine is the engine."""
    modules = set()
    imported_names = set()
    for tree in engine_source.trees().values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules |= {n.name.split(".")[0] for n in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
            # `from core import rule_names` records the module as "core", so
            # name the symbol explicitly rather than letting a bare "core" wave
            # anything through.
            if isinstance(node, ast.ImportFrom) and node.module == "core":
                imported_names |= {a.name for a in node.names}

    project = {m for m in modules if m.split(".")[0] in
               {"core", "adapters", "runner", "hook_entry"}}
    # core.shell_scan and core.rule_names are allowed because each is itself
    # pure — one computes a mask from a string, the other is a lookup table with
    # no imports at all. The next two tests enforce that, so this is a widening
    # of the ALLOWLIST and not of the boundary. The engine's own parts are the
    # engine (docs/ENGINE_LAYOUT.md), held to this same test.
    # `why` (docs/108): the facts a DENY or ASK is about, composed from the
    # verdict, the action and the state — pure, and a part like the rest.
    # `guard_runs` (item 1): what runs a part of the guard, read in linear
    # time; regexes and string work only, a part like the rest.
    # `outside_content`, `secret_reference` and `downloads` (fix/false-positives,
    # docs/112): what an action runs, what secret it visibly carries, what a
    # command downloads — regexes and string work on the action, parts like the
    # rest. `uncommitted` and `deletes_in_text` (item C): what a delete or an
    # overwrite names, asked of the World as every probe is, and whether a
    # delete written in text is data — parts like the rest. `mcp_arguments`
    # (item 3): what an MCP call's arguments carry — string work and decoding.
    parts = {"core.command_text", "core.credentials", "core.globbing",
             "core.irreversible", "core.egress", "core.guard_runs", "core.guard_floor",
             "core.sources", "core.sinks", "core.secret_ladder", "core.why",
             "core.outside_content", "core.secret_reference", "core.downloads",
             "core.uncommitted", "core.deletes_in_text", "core.mcp_arguments",
             "core.uploads"}
    assert parts == {f"core.{m}" for m in engine_source.MODULES if m != "engine"}
    assert project <= {"core.types", "core.shell_scan", "core"} | parts, \
        f"engine.py reaches into: {project}"
    # `known_formats` is pure too — its own purity test is in
    # tests/test_known_formats.py, so this widens the allowlist and not the
    # boundary, as `rule_names` and `shell_scan` did before it. `org_policy` (step
    # 3a: the engine reads the org's cached policy on the decision path) is pure
    # stdlib and does LOCAL file work only — no network, no shipper — proven by
    # tests/test_org_policy_apply.py::test_org_policy_still_imports_no_network_or_shipper,
    # so it is the same kind of allowlist widening. `guard_parts` (item C: what
    # the installed guard is made of) is patterns and string functions only,
    # proven by `test_guard_parts_is_pure_too` below.
    # `env_reads` (item B, docs/110 §B): which commands print environment
    # variables, and what a read of them records — regexes, string work and
    # the credential fingerprinter; it reads no environment itself (the World
    # hands it one), so the same kind of allowlist widening.
    assert imported_names <= {"rule_names", "known_formats", "org_policy",
                              "guard_parts", "guard_runs", "hook_configs", "why",
                              "env_reads"}, \
        f"engine.py imports from core: {imported_names}"

    stdlib = {m.split(".")[0] for m in modules} - {"core"}
    assert not (stdlib & _IO_MODULES), f"engine.py imports IO: {stdlib & _IO_MODULES}"
    assert stdlib <= _PURE_STDLIB, f"unexpected engine imports: {stdlib - _PURE_STDLIB}"


def test_rule_names_is_pure_too():
    """It is imported by the engine, so it inherits the engine's constraint.

    ⚠ A LOOKUP TABLE IS THE EASIEST PLACE TO SNEAK IO IN — "just read the names
    from a JSON file" is one line and it would put an open() on the hot path of
    every verdict. This module has NO imports at all beyond `__future__`, which
    is the strongest form of the guarantee.
    """
    tree = ast.parse((ROOT / "core" / "rule_names.py").read_text())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    assert modules <= {"__future__"}, f"core/rule_names.py imports: {modules}"
    src = (ROOT / "core" / "rule_names.py").read_text()
    assert "open(" not in src and "Path" not in src


def test_guard_parts_is_pure_too():
    """Imported by the engine, so it inherits the engine's constraint: it says
    what a path or a command segment IS, and never looks at the machine. A home
    is matched by its spelling, never by reading $HOME."""
    source = (ROOT / "core" / "guard_parts.py").read_text()
    tree = ast.parse(source)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    # `fnmatch.fnmatchcase` is a pure string match (no case folding by OS).
    # `bisect` (item E, docs/110 §E): `service_stop` finds a `schtasks`
    # flag by position — the standard library's sorted-list search.
    assert modules <= {"__future__", "re", "fnmatch", "functools", "bisect"}, \
        f"core/guard_parts.py imports: {modules}"
    code = ast.unparse(tree)
    for forbidden in ("open(", "Path(", "environ", "getenv", "expanduser", "fnmatch.fnmatch("):
        assert forbidden not in code, f"'{forbidden}' in core/guard_parts.py"


def test_hook_configs_is_pure_too():
    """Imported by the engine and by the installer. `json` is here to PARSE the
    text an agent is writing, never to read or write a file."""
    source = (ROOT / "core" / "hook_configs.py").read_text()
    tree = ast.parse(source)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    assert modules <= {"__future__", "re", "json", "functools", "core"}, modules
    for node in ast.walk(tree):  # prose may name these; code may not
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    code = ast.unparse(tree)
    for forbidden in ("open(", "Path(", "environ", "getenv", "expanduser",
                      "json.load(", "json.dump(", "subprocess"):
        assert forbidden not in code, f"'{forbidden}' in core/hook_configs.py"


def test_engine_never_names_an_agent_field_or_touches_io():
    """The engine must not be able to tell which agent sent an action. Every
    part of it (tests/engine_source.py)."""
    for part, tree in engine_source.trees().items():
        for node in ast.walk(tree):  # strip docstrings; prose may name these
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                b = getattr(node, "body", [])
                if b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant) \
                        and isinstance(b[0].value.value, str):
                    node.body = b[1:] or [ast.Pass()]
        code = ast.unparse(tree)

        # Agent payload field names. The engine must not be able to tell who sent it.
        for forbidden in ("hookSpecificOutput", "conversationId", "workspacePaths",
                          "tool_input", "CommandLine", "stepIdx", "permissionDecision",
                          "user_message", "toolCall"):
            assert forbidden not in code, \
                f"agent field name '{forbidden}' leaked into core/{part}.py"

        # IO *usage*, checked as calls rather than substrings — `.docker/config.json`
        # is a credential path, not the engine serialising JSON.
        for forbidden in ("open(", "json.", "sys.stdin", "sys.stdout", "print(",
                          "subprocess.", "Path("):
            assert forbidden not in code, f"IO call '{forbidden}' in core/{part}.py"


def test_engine_signature_is_action_state_world_to_verdict():
    """A pure function of its inputs — no hidden state, no hidden IO.

    THE PROPERTY IS PURITY, NOT ARITY, and this now asserts that in both
    directions. `decide` gained `text_complete`, which says whether
    `action.command` is the whole command or a known prefix. It is an explicit,
    defaulted input, so nothing becomes hidden and no existing caller changes —
    live it is never anything but the default, because the hook is handed the
    whole command and clipping happens later, when the log body is written.

    The assertions below are STRICTER than the ones they replace, not looser: the
    first three parameters must still be exactly `action, state, world` in that
    order, and anything added after them must carry a default. A future change
    making a fourth argument required would silently break every adapter, and is
    caught here; one that reintroduced hidden state is caught by the IO tests.
    """
    tree = ast.parse((ROOT / "core" / "engine.py").read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "decide")
    names = [a.arg for a in fn.args.args]
    assert names[:3] == ["action", "state", "world"]
    assert len(fn.args.defaults) >= len(names) - 3, (
        f"parameters after (action, state, world) must have defaults: {names}")
    assert ast.unparse(fn.returns) == "Verdict"


def test_engine_performs_no_io_itself():
    """Everything from outside comes through the World protocol. If the engine
    can open a file or spawn a process, the pure-function property is gone and
    the policy is no longer testable without a real machine. Every part of it
    (tests/engine_source.py)."""
    for part, tree in engine_source.trees().items():
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {n.name.split(".")[0] for n in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for io_module in ("os", "subprocess", "pathlib", "shutil", "socket", "fcntl", "io"):
            assert io_module not in imported, f"core/{part}.py imports {io_module}"
    for part, src in engine_source.sources().items():
        assert "open(" not in src, f"core/{part}.py opens files directly"


def test_shell_scan_is_pure_too():
    """It is imported by the engine, so it inherits the engine's constraint.

    A scanner that opened a file would put IO back inside decide() through the
    side door, and the boundary would be gone without any test noticing.
    """
    tree = ast.parse((ROOT / "core" / "shell_scan.py").read_text())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    assert not (modules & _IO_MODULES), f"shell_scan reaches outside: {modules}"
    assert modules <= _PURE_STDLIB, f"shell_scan imports: {modules}"
