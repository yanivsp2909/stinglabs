"""⚠ `rm -rf __pycache__` IS NOT AN IRREVERSIBLE ACT — AND `rm -rf src` STILL IS.

MEASURED, on the real logs of one machine: 128 `irreversible_action` ASKs
across 62 sessions, 48 of them with `__pycache__` as the first operand; one
session alone asked 41 times for the same regenerable cache. With
`STING_OBSERVE='0'` those were live prompts, on throwaway build junk, in a
product whose pitch is that ordinary work stops asking.

THE RULE, BEFORE. `_RM_DESTRUCTIVE` keys on command SHAPE — any `rm` with
`-r`/`-f` — and the only target-aware exemption was `STING_SCRATCH`, which
deliberately excludes project roots: "the answer does not improve because the
target was yours". That argument is right for `src/`. It is wrong for a
directory the interpreter regenerates on the next import.

THE FIX SHARPENS, IT DOES NOT LOOSEN. A second exemption, read out of KNOWN
ARTIFACT IDENTITY and nothing else: every path the command deletes must be
strictly inside a declared project root AND have an allowlisted basename
(`__pycache__`, `node_modules`, `dist`, `*.pyc`, …). ALL targets, never ANY;
an unparseable or variable-bearing target is a prompt; an untrusted session
gets no exemption; the project root itself never qualifies even when it is
called `build`; and every other irreversible pattern — force-push, `branch
-D`, `reset --hard`, SQL — is untouched.
"""
from __future__ import annotations

import pytest

from core import engine
from core.engine import is_irreversible
from core.probes import NullWorld
from core.types import Action, ActionKind, Decision, SessionState

PROJECT = "/work/repo"


def ex(command: str, cwd: str = PROJECT, roots=(PROJECT,)) -> Action:
    return Action("s", 1, ActionKind.EXEC, (), command, None, None, None,
                  cwd, tuple(roots), "claude-code")


def verdict(command: str, *, cwd: str = PROJECT, roots=(PROJECT,),
            untrusted: bool = False, world=None):
    state = SessionState(session_id="s")
    if untrusted:
        state.mark_untrusted(seq=1, kind="issue", ref="ISSUE_1.md")
    return engine.decide(ex(command, cwd, roots), state, world or NullWorld())


class _WithManifest(NullWorld):
    """A World where the named files exist — `read_text` returns content for
    them and None for everything else — so a `target`/`out` sitting beside one
    reads as build output. Manifests are small; existence IS the signal."""

    def __init__(self, *present):
        self._present = set(present)

    def read_text(self, path):
        return "manifest\n" if path in self._present else None


# ═══════════════════════════════════════════ 1 · regenerable junk stops asking

@pytest.mark.parametrize("command", [
    "rm -rf __pycache__",
    "rm -rf ./__pycache__",
    "rm -rf __pycache__/",
    "rm -rf src/__pycache__",
    "rm -rf **/__pycache__",
    "rm -f app.pyc",
    "rm -rf *.pyc",
    "rm -rf .pytest_cache .mypy_cache .ruff_cache",
    "rm -rf node_modules",
    "rm -rf .next",
    "rm -rf dist build",
    "rm -rf .venv",
    "rm -rf venv",
    "rm -rf -- __pycache__",
    "cd /work/repo && rm -rf build",
    "cd /work/repo/pkg && rm -rf __pycache__",
    "rm -rf __pycache__ 2>/dev/null",
    "rm -rf /work/repo/node_modules",
])
def test_deleting_a_known_artifact_inside_the_project_is_allowed(command):
    v = verdict(command)
    assert (v.decision, v.rule_id) == (Decision.ALLOW, None), (command, v)
    assert is_irreversible(ex(command), NullWorld()) is None


def test_the_allowlist_is_explicit_names_not_a_shape():
    """The set is the contract; a reader can see exactly what is forgiven."""
    assert {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
            "node_modules", ".next", "dist", "build", ".venv", "venv"} <= engine.REGENERABLE_ARTIFACTS
    assert "src" not in engine.REGENERABLE_ARTIFACTS
    assert "config.py" not in engine.REGENERABLE_ARTIFACTS


# ═════════════ 1b · tool-specific output stops asking on the name alone

@pytest.mark.parametrize("command", [
    "rm -rf coverage", "rm -rf ./coverage", "rm -rf coverage/",
    "rm -rf htmlcov", "rm -rf .coverage", "rm -rf .nyc_output",
    "rm -rf coverage htmlcov .coverage .nyc_output",
    "rm -rf .gradle", "rm -rf .parcel-cache",
    "rm -rf coverage .pytest_cache dist",
    "cd /work/repo && rm -rf coverage", "rm -rf /work/repo/htmlcov",
])
def test_deleting_tool_specific_output_is_allowed_on_the_name_alone(command):
    """coverage.py / nyc / Gradle / Parcel names are never anything but
    regenerable output — forgiven on the basename, no manifest needed. (docs/86)"""
    v = verdict(command)
    assert (v.decision, v.rule_id) == (Decision.ALLOW, None), (command, v)


# ══════════ 1c · `target` / `out` are English words — a manifest is required

_CARGO = _WithManifest("/work/repo/Cargo.toml")
_POM = _WithManifest("/work/repo/pom.xml")
_GRADLE = _WithManifest("/work/repo/build.gradle")
_GRADLE_KTS = _WithManifest("/work/repo/build.gradle.kts")
_NEXT = _WithManifest("/work/repo/next.config.js")
_TSCONFIG = _WithManifest("/work/repo/tsconfig.json")
_PKG = _WithManifest("/work/repo/package.json")


@pytest.mark.parametrize("command,world", [
    ("rm -rf target", _CARGO), ("rm -rf target", _POM),
    ("rm -rf target", _GRADLE), ("rm -rf target", _GRADLE_KTS),
    ("rm -rf ./target", _CARGO), ("rm -rf target/", _CARGO),
    ("cd /work/repo && rm -rf target", _CARGO),
    ("rm -rf out", _NEXT), ("rm -rf out", _TSCONFIG), ("rm -rf out", _PKG),
    ("rm -rf /work/repo/out", _NEXT),
])
def test_target_and_out_are_allowed_with_a_sibling_build_manifest(command, world):
    v = verdict(command, world=world)
    assert (v.decision, v.rule_id) == (Decision.ALLOW, None), (command, v)


@pytest.mark.parametrize("command", [
    "rm -rf target", "rm -rf out", "rm -rf ./target",
    "cd /work/repo && rm -rf out", "rm -rf /work/repo/target",
])
def test_target_and_out_still_ask_without_a_build_manifest(command):
    """⚠ THE GAP A FOLLOW-UP CHECK MEASURED THROUGH THE REAL ENGINE (after docs/86). Un-gated, `rm -rf out`
    silently deleted a week of computed results in a repo with NO build tool.
    With no sibling manifest, `target`/`out` is just a directory that shares a
    build dir's name — it asks, exactly like `src`."""
    v = verdict(command)      # NullWorld: no manifest exists
    assert v.decision is Decision.ASK and v.rule_id == "irreversible_action", (command, v)


def test_an_untrusted_session_deletes_build_output_like_a_clean_one():
    """fix/false-positives, items B and C (docs/112): "destructive commands are
    judged by item C, whatever the session read". The exemption used to be
    withheld from an untrusted session; a delete now asks only when it would
    lose uncommitted work, and regenerable output is not work — in either
    session. A planted manifest vouches for `target`/`out` beside it, as in a
    clean session; nothing it vouches for is anything but build output."""
    for command, world in (("rm -rf target", _CARGO), ("rm -rf out", _NEXT)):
        assert verdict(command, untrusted=True, world=world) == verdict(command, world=world)
        assert verdict(command, world=world).decision is Decision.ALLOW


def test_the_manifest_must_be_a_sibling_of_the_target_not_elsewhere():
    """A manifest in a DIFFERENT directory does not vouch for this target."""
    v = verdict("rm -rf target", world=_WithManifest("/work/repo/pkg/Cargo.toml"))
    assert v.decision is Decision.ASK, v                     # not beside /work/repo/target
    v = verdict("rm -rf pkg/target", world=_WithManifest("/work/repo/pkg/Cargo.toml"))
    assert (v.decision, v.rule_id) == (Decision.ALLOW, None), v   # beside the nested target


def test_the_new_test_output_names_are_listed_and_generic_ones_are_not():
    assert {"coverage", "htmlcov", ".coverage", ".nyc_output",
            "target", "out", ".gradle", ".parcel-cache"} <= engine.REGENERABLE_ARTIFACTS
    assert engine._MANIFEST_GATED == {"target", "out"}
    for generic in ("results", "output", "data", "artifacts", "reports"):
        assert generic not in engine.REGENERABLE_ARTIFACTS


def test_the_new_names_do_not_loosen_the_safety_controls():
    """The additions change WHICH names, not WHEN. Manifest-present is used for
    the two gated names so the SAFETY condition, not the manifest, is the reason."""
    _still_asks("rm -rf coverage src/")                     # mixed with a real target
    _still_asks("rm -rf src/ coverage")
    _still_asks("rm -rf target src/", world=_CARGO)         # gated name + a real target
    _still_asks("rm -rf /tmp/coverage")                     # outside the declared root
    _still_asks("rm -rf ../target", world=_CARGO)           # escapes the root
    _still_asks("rm -rf coverage", roots=())                # no declared root
    _still_asks("rm -rf $BUILD/coverage")                   # a substitution names nothing
    _still_asks("rm -rf coverage", cwd="/somewhere/else")
    _still_asks("rm -rf /work/target", cwd="/work/target", roots=("/work/target",),
                world=_WithManifest("/work/Cargo.toml"))    # the root itself, even with a manifest


# ═══════════════════════════════════════════ 2 · SAFETY CONTROLS — still ASK

def _still_asks(command: str, **kw) -> None:
    v = verdict(command, **kw)
    assert v.decision is Decision.ASK and v.rule_id == "irreversible_action", (command, v)


def test_a_real_file_or_directory_inside_the_project_still_asks():
    _still_asks("rm -rf src")
    _still_asks("rm -rf src/")
    _still_asks("rm -f config.py")
    _still_asks("rm -rf scripts/legacy_migration_2019.py")      # J02, the corpus


def test_outside_the_declared_root_still_asks_whatever_the_name():
    _still_asks("rm -rf ~/node_modules")
    _still_asks("rm -rf /tmp/__pycache__")
    _still_asks("rm -rf ../__pycache__")                           # escapes the root
    _still_asks("cd /work/repo && rm -rf ../../__pycache__")
    _still_asks("rm -rf __pycache__", cwd="/somewhere/else")


def test_an_untrusted_session_gets_the_same_exemption():
    """It used to forfeit it (the attacker who writes the README writes the
    command). Since fix/false-positives (items B and C, docs/112) a delete is
    judged by what it would lose, whatever the session read: build junk loses
    nothing, and a real target still asks in both sessions."""
    for command in ("rm -rf __pycache__", "rm -rf node_modules"):
        assert verdict(command, untrusted=True) == verdict(command)
        assert verdict(command).decision is Decision.ALLOW
    _still_asks("rm -rf node_modules src", untrusted=True)


def test_a_target_nobody_can_determine_still_asks():
    _still_asks("rm -rf $X/__pycache__")                           # unknown variable
    _still_asks("rm -rf $(find . -name __pycache__)")              # a substitution
    _still_asks("rm -rf `find . -name __pycache__`")
    _still_asks("find . -name __pycache__ -exec rm -rf {} +")      # `{}` is not a name


def test_a_delete_mixing_junk_and_a_real_target_still_asks():
    """ALL targets, never ANY: the real one wins."""
    _still_asks("rm -rf __pycache__ src/")
    _still_asks("rm -rf src/ __pycache__")
    _still_asks("rm -rf dist build config.py")


def test_the_project_root_itself_never_qualifies_even_when_it_is_called_build():
    _still_asks("rm -rf /work/build", cwd="/work/build", roots=("/work/build",))
    _still_asks("rm -rf .", cwd="/work/repo/node_modules", roots=("/work/repo/node_modules",))


def test_a_declared_root_is_required():
    """No roots declared, no exemption — absence of a setting is never permission."""
    _still_asks("rm -rf __pycache__", roots=())


def test_every_other_irreversible_pattern_is_untouched():
    """With a World that cannot ask git (NullWorld), `git reset --hard` and
    `shred` ask as before. A force-push no longer asks (maintainer, docs/112)."""
    for command in ("git branch -D feature",
                    "git reset --hard HEAD~3",
                    "psql -c 'DROP TABLE users'",
                    "shred -u secrets.txt"):
        _still_asks(command)
    for command in ("git push --force origin main",              # J03
                    "rm -rf __pycache__ && git push --force origin main"):
        assert verdict(command).decision is Decision.ALLOW, command


def test_a_declared_scratch_root_still_works_as_before():
    """The two exemptions compose; neither widens the other."""
    state = SessionState(session_id="s")
    state.scratch_roots = ["/scratch/agent"]
    v = engine.decide(ex("rm -rf /scratch/agent/anything"), state, NullWorld())
    assert (v.decision, v.rule_id) == (Decision.ALLOW, None)
    v = engine.decide(ex("rm -rf /scratch/agent/x /work/repo/src"), state, NullWorld())
    assert v.rule_id == "irreversible_action"
