"""Antigravity does what Sting's verdict means.

Item A of fix/agents-block-and-env-reads (docs/110 §A). `antigravity_outcome`
is how Antigravity turns a PreToolUse hook's (stdout, stderr, exit code) into a
decision, read from its shipped binaries — CLI 1.2.13 and IDE 2.5.5's
`language_server_macos_arm`, disassembled, never run — and its docs
(antigravity.google/docs/hooks):

    R1  a timeout (30 s) or ANY non-zero exit, 2 included, is a hook ERROR;
        stdout is dropped            Cmd.Output @0x1017ca284, @0x1017ca404
    R2  empty stdout: the hook has no say; Antigravity's own rules apply
                                     @0x1017ca488, callHookAs @0x1017c1888
    R3  strict protojson: an object with known keys only (`decision`,
        `reason`, …); an unknown key or a wrong type is an ERROR  @0x1017c18d0
    R4  a missing decision is the deprecated `allowTool`, false by default:
        `{}` is a DENY                pretoolhooks.NewProviderHook @0x10193ef2c
    R5  `deny` blocks on both paths   runPreToolHooks @0x101264c5c
    R6  `ask` is skipped when a cached "Always Allow" grant covers it (docs:
        "respects Always Allow settings"); `force_ask` ignores cached
        permissions; headless soft-denies both   EnsurePermissions @0x101490b30
    R8  an ERROR fails the tool call on the consolidated path, and is logged
        and IGNORED on the legacy one — which path a session takes is unknown

What was wrong: an ASK was `ask`, which a person's standing "Always Allow" lets
through unasked, so it is `force_ask` now; and a guard that could not decide
answered with exit 2, an ERROR the legacy path ignores, so it answers with a
JSON deny and exit 0, which blocks on both paths.
"""
from __future__ import annotations

import json

import pytest

import hook_entry
from adapters import antigravity
from core.types import Decision, Verdict

_KNOWN = {"decision", "reason", "overwrite", "permissionOverrides", "permission_overrides",
          "allowTool", "allow_tool", "denyReason", "deny_reason"}
_DECISIONS = {"allow", "ask", "force_ask", "deny_unless_prior_grant", "deny"}


def antigravity_outcome(stdout: str, exit_code: int, *, path: str = "consolidated",
                        cached_grant: bool = False, interactive: bool = True) -> str:
    failed = "failed-closed" if path == "consolidated" else "failed-open"   # R8
    if exit_code != 0:                                                      # R1
        return failed
    body = stdout.strip()
    if not body:                                                            # R2
        return "allowed"
    try:
        obj = json.loads(body)
    except ValueError:
        return failed                                                       # R3
    if not isinstance(obj, dict) or set(obj) - _KNOWN:
        return failed                                                       # R3
    decision = obj.get("decision") or ("allow" if obj.get("allowTool") else "deny")  # R4
    if decision not in _DECISIONS:
        return failed
    if decision == "deny":                                                  # R5
        return "blocked"
    if decision in ("ask", "force_ask"):                                    # R6
        if decision == "ask" and cached_grant:
            return "allowed"
        return "asked" if interactive else "blocked"
    return "allowed"


@pytest.mark.parametrize("stdout,code,path,expect", [
    ('{"decision":"deny","reason":"no"}', 0, "legacy", "blocked"),
    ("{}", 0, "consolidated", "blocked"),
    ("", 2, "consolidated", "failed-closed"),
    ("", 2, "legacy", "failed-open"),
    ('{"decision":"deny","extra":1}', 0, "consolidated", "failed-closed"),
    ("", 0, "legacy", "allowed"),
])
def test_the_fixture_reads_as_the_binaries_say(stdout, code, path, expect):
    assert antigravity_outcome(stdout, code, path=path) == expect


DENY = Verdict(Decision.DENY, "this sends the file off the machine",
               "untrusted_unexpected:network_egress")
ASK = Verdict(Decision.ASK, "this cannot be undone", "irreversible_action")


@pytest.mark.parametrize("path", ["consolidated", "legacy"])
def test_a_deny_blocks_on_both_paths(path):
    assert antigravity_outcome(antigravity.render(DENY), 0, path=path) == "blocked"


def test_an_ask_is_asked_even_with_a_standing_always_allow():
    assert antigravity_outcome(antigravity.render(ASK), 0, cached_grant=True) == "asked"


def test_an_allow_leaves_the_call_to_antigravity():
    assert antigravity_outcome(antigravity.render(Verdict(Decision.ALLOW, None, None)),
                               0) == "allowed"


@pytest.mark.parametrize("path", ["consolidated", "legacy"])
def test_a_guard_that_cannot_decide_still_blocks_on_both_paths(path):
    """An unparseable payload is the guard failing to decide: exit 2 elsewhere,
    and here the deny Antigravity reads on either path."""
    out, err, code = hook_entry.run("not json at all", "antigravity")
    assert antigravity_outcome(out, code, path=path) == "blocked", (out, code)
    assert "could not parse" in json.loads(out)["reason"]
    assert "could not parse" in err


def _main(monkeypatch, capsys, module, agent, fail):
    import io
    import sys
    monkeypatch.setenv("STING_OBSERVE", "0")
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    fail(monkeypatch)
    code = module.main(["--agent", agent])
    out = capsys.readouterr().out
    return code, out


@pytest.mark.parametrize("agent", ["antigravity", "claude-code"])
def test_a_failure_before_the_pipeline_answers_in_the_agents_shape(monkeypatch, capsys,
                                                                   agent):
    """The review: `run()` was the only place a guard failure became
    Antigravity's deny; the entry points' own last-resort branches (the Python
    floor in sting_hook, a crash reading stdin in hook_entry) still exited 2."""
    import sting_hook

    def floor(mp):
        def refuse(*_a, **_k):
            raise SystemExit(2)
        mp.setattr(sting_hook, "decide", refuse)

    def crash(mp):
        def boom(*_a, **_k):
            raise RuntimeError("stdin broke")
        mp.setattr(hook_entry, "run", boom)

    for module, fail in ((sting_hook, floor), (hook_entry, crash)):
        code, out = _main(monkeypatch, capsys, module, agent, fail)
        if agent == "antigravity":
            assert code == 0 and antigravity_outcome(out, code) == "blocked", (module, out)
        else:
            assert (code, out) == (2, ""), (module, out)
        monkeypatch.undo()


def test_the_thin_clients_copy_is_the_adapters_answer():
    """sting_hook may not import adapters, so it keeps its own copy: the same
    agents, the same deny."""
    import sting_hook
    from adapters import ADAPTERS_BY_NAME
    answering = {name for name, adapter in ADAPTERS_BY_NAME.items()
                 if hasattr(adapter, "render_failure")}
    assert set(sting_hook._DENY_ON_FAILURE) == answering
    for name in answering:
        assert (json.loads(sting_hook._DENY_ON_FAILURE[name])
                == json.loads(ADAPTERS_BY_NAME[name].render_failure("")))


def test_every_other_agent_keeps_exit_2_for_a_guard_that_cannot_decide():
    for agent in ("claude-code", "codex", "cursor", "copilot"):
        out, _err, code = hook_entry.run("not json at all", agent)
        assert (out, code) == ("", 2), agent
