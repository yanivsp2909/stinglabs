"""The I02 sequence, driven through EVERY adapter, and proved non-vacuous.

⚠ WHY THIS FILE EXISTS. `tools/preflight.py`'s semantic check is the one line
that proves the engine can SEE a credential rather than merely boot. It ran for
claude-code and printed `skipped — no I02 payload shape for <agent>` on the
other four — so on the first machine that was not Claude Code, **the guard
against a blind guard did not run.**

Two claims are made here and they are different:

    1 · every adapter reaches the same verdict on the same act    (test 1)
    2 · that verdict is produced BY THE MATCHER, not by luck      (test 2)

⚠ CLAIM 2 IS THE ONE THAT MATTERS, and it is the absence pattern this project
has now found five times: an assertion that passes because the thing it checks
never ran. So the credential matcher is BLINDED and the same sequence must come
back ALLOW. A test that cannot fail is not evidence, and the only way to know a
semantic check can fail is to make it fail.
"""
from __future__ import annotations

import re

import pytest

from adapters import ADAPTERS_BY_NAME
from core import (engine, globbing, irreversible, mcp_arguments, secret_ladder,
                  secret_reference, sinks, sources)
from core.types import Decision
from tests import engine_source

# ⚠ BLINDED WHERE IT IS LOOKED UP. A name is read in the module whose code uses
# it (docs/ENGINE_LAYOUT.md): a patch on any other module blinds nothing, and
# the proof below would pass while proving nothing.
_MATCHER_READERS = (globbing, irreversible, sources, sinks, secret_ladder,
                    secret_reference, mcp_arguments)


def _blind_the_matcher(monkeypatch):
    patched = {module.__name__.rpartition(".")[2] for module in _MATCHER_READERS}
    assert patched == engine_source.readers("CREDENTIAL_PATHS"), (
        "CREDENTIAL_PATHS is read in a module this test does not blind")
    for module in _MATCHER_READERS:
        monkeypatch.setattr(module, "CREDENTIAL_PATHS", re.compile(r"(?!x)x"))

# The flagship sequence: read a credential, copy it, commit the copy, push.
# ⚠ THE COMMIT IS PART OF THE SHAPE, not padding. Without it the push carries
# nothing traceable and the engine correctly returns ASK.
I02_STEPS = ["cat .env",
             "cp .env debug.env",
             "git add debug.env && git commit -m 'feat: debug config'",
             "git push origin main"]

IDS = sorted(ADAPTERS_BY_NAME)


def run_sequence(name, proj):
    """Drive I02 through one adapter, in-process, against the REAL world.

    ⚠ THE REAL `probes.RealWorld`, not a fake. The point of this file is that a
    credential on disk is SEEN; a FakeWorld answering from a dict would prove
    the dict was populated. `RealWorld` performs no writes and swallows its own
    OSErrors, so the only thing it touches is the temp project.

    State is carried across the four steps by hand — one `SessionState`, seq
    advanced per step — because that IS the session, and the whole claim is
    that step 4 is decided by what step 1 saw.
    """
    from core import probes
    from core.types import SessionState

    adapter = ADAPTERS_BY_NAME[name]
    state = SessionState(session_id=f"probe-{name}", cwd=str(proj),
                          workspace_roots=[str(proj)])
    world = probes.RealWorld()
    out = []
    for step_idx, step in enumerate(I02_STEPS):
        payload = adapter.probe_payload(step, cwd=str(proj),
                                         session=f"probe-{name}", step=step_idx)
        action = adapter.parse(payload)
        state.seq = state.next_seq(action.seq)
        out.append(engine.decide(action, state, world))
    return out


@pytest.fixture
def project(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".env").write_text("FAKE_AWS_KEY=AKIA_TEST_probe\n", encoding="utf-8")
    return proj


# ───────────────────────────────────────────── 1 · the same verdict, everywhere

@pytest.mark.parametrize("name", IDS)
def test_every_adapter_denies_the_credential_exfiltration(name, project):
    """⚠ THE SAME SEQUENCE MUST PRODUCE THE SAME VERDICT WHICHEVER ADAPTER
    PARSED IT. A difference is not a tolerance — it is a finding about that
    adapter, because the engine is supposed to be looking at one act."""
    verdicts = run_sequence(name, project)
    assert verdicts[-1].decision is Decision.DENY, (
        f"{name}: push after reading .env -> {verdicts[-1].decision}")


def test_no_two_adapters_reach_a_different_verdict(project):
    by_agent = {name: [v.decision for v in run_sequence(name, project)]
                for name in IDS}
    distinct = {tuple(v) for v in by_agent.values()}
    assert len(distinct) == 1, (
        f"adapters disagree about one act: "
        f"{ {k: [str(d) for d in v] for k, v in by_agent.items()} }")


def test_every_adapter_exposes_a_probe_payload():
    """⚠ REQUIRED, NOT OPTIONAL. An adapter with no probe cannot be checked for
    blindness, and preflight now FAILS rather than skipping when one is
    missing — "cannot be checked" must never read like "fine"."""
    for name, mod in ADAPTERS_BY_NAME.items():
        assert callable(getattr(mod, "probe_payload", None)), name
        payload = mod.probe_payload("git push origin main", cwd="/tmp",
                                     session="s", step=0)
        assert isinstance(payload, dict) and payload, name
        assert mod.parse(payload).command == "git push origin main", (
            f"{name}: its own probe does not survive its own parse")


# ══════════════ 2 · AND IT IS THE MATCHER DOING IT — blind it and watch it fail

@pytest.mark.parametrize("name", IDS)
def test_blinding_the_credential_matcher_makes_every_adapter_ALLOW(
        name, project, monkeypatch):
    """⚠ THE NON-VACUITY PROOF, PER ADAPTER.

    `CREDENTIAL_PATHS` is what turns `cat .env` into a SECRET source. Blinded,
    the session never learns it holds a credential, the push carries nothing
    traceable, and the sequence must come back ALLOW.

    If this test ever FAILS — i.e. the sequence still denies with the matcher
    blinded — the DENY above is coming from somewhere else, and the semantic
    check is no longer testing what it claims to test.
    """
    _blind_the_matcher(monkeypatch)
    verdicts = run_sequence(name, project)
    assert verdicts[-1].decision is not Decision.DENY, (
        f"{name}: still DENY with the credential matcher blinded — the verdict "
        f"is not coming from the matcher this check claims to exercise")


def test_the_blinding_is_the_only_thing_that_changed(project, monkeypatch):
    """⚠ AND THE BLINDING MUST BE REVERSIBLE, or the test above could be passing
    because the fixture is broken rather than because the matcher was removed.
    Same project, same steps, matcher restored: DENY returns."""
    _blind_the_matcher(monkeypatch)
    assert run_sequence(IDS[0], project)[-1].decision is not Decision.DENY
    monkeypatch.undo()
    assert run_sequence(IDS[0], project)[-1].decision is Decision.DENY
