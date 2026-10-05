"""The install shape, and the allow-once chokepoint it creates."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core import allow_once
from core.types import Action, ActionKind
from installer import detect, messages, place, supervisor
from shipper import service

ROOT = Path(__file__).parent.parent


def action():
    return Action("s1", 4, ActionKind.EXEC, (), "git push origin main", None,
                   None, None, "/work/repo", ("/work/repo",), "claude-code")


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """A real install into a temp prefix, with a temp session root."""
    prefix = tmp_path / "share" / "sting"
    sessions = tmp_path / "state"
    sessions.mkdir(parents=True)
    monkeypatch.setenv("STING_INSTALL_ROOT", str(prefix))
    monkeypatch.setenv("STING_SESSION_ROOT", str(sessions))
    allow_once._install_manifest_version.cache_clear()
    result = place.place(prefix=prefix, session_root=sessions)
    return prefix, sessions, result


# ------------------------------------------------------------ 1 · the shape

def test_current_is_a_symlink_to_a_versioned_copy(installed):
    """⚠ TWO DIFFERENT THINGS, and conflating them is the mistake.

    `current` is a SYMLINK — it has to be, because it is what the agent's hook
    config points at, and repointing it is how a new version takes effect
    without editing five settings files.

    What it points AT is a COPY. If that were a link to the checkout, the
    running guard would again BE the file being edited, which is the collision
    the whole install shape exists to remove."""
    prefix, _, result = installed
    current = prefix / "current"
    assert current.is_symlink(), "current must be a symlink"
    assert not (current.resolve() / "core" / "engine.py").is_symlink()
    assert current.resolve() == result["path"]
    assert result["path"].parent == prefix


def test_the_installed_tree_is_a_copy_not_the_checkout(installed):
    """Editing the checkout must not change what is installed."""
    prefix, _, result = installed
    installed_engine = result["path"] / "core" / "engine.py"
    assert installed_engine.exists()
    assert installed_engine.read_bytes() == (ROOT / "core" / "engine.py").read_bytes()
    # Same bytes, different inode — a copy, not a hard or soft link.
    assert not installed_engine.is_symlink()
    assert installed_engine.stat().st_ino != (ROOT / "core" / "engine.py").stat().st_ino


def test_the_version_changes_when_the_policy_changes(tmp_path):
    """A git ref alone cannot tell a dirty checkout from a clean one, so the
    version carries a content hash of the files that decide policy."""
    first = place.compute_version()
    scratch = tmp_path / "src"
    scratch.mkdir()
    (scratch / "core").mkdir()
    (scratch / "core" / "engine.py").write_text("x = 1")
    (scratch / "adapters").mkdir()
    (scratch / "hook_entry.py").write_text("y = 2")
    changed = place.compute_version(scratch)
    (scratch / "core" / "engine.py").write_text("x = 2")
    assert place.compute_version(scratch) != changed
    assert first != changed


def test_install_json_records_provenance(installed):
    _, _, result = installed
    manifest = json.loads((result["path"] / "INSTALL.json").read_text())
    assert manifest["guard_version"] == result["version"]
    assert "source_commit" in manifest
    assert isinstance(manifest["source_dirty"], bool)
    assert manifest["installed_by"]


def test_no_tests_or_git_are_copied(installed):
    """An install is not a checkout."""
    _, _, result = installed
    for absent in ("tests", ".git", "logs", "scenarios", "PROGRESS.md"):
        assert not (result["path"] / absent).exists(), absent


def test_repointing_current_never_leaves_it_missing(installed):
    """⚠ os.symlink THEN os.replace, never unlink-then-link. A hook firing in
    the window where `current` did not exist gets "no such file", which every
    adapter turns into a failure the developer sees."""
    import ast
    import inspect
    import textwrap

    # The AST, not a substring search: `_repoint`'s own docstring contains the
    # word "unlink" while explaining that it does not call it, and the first
    # version of this test failed on exactly that.
    tree = ast.parse(textwrap.dedent(inspect.getsource(place._repoint)))
    called = {n.func.attr for n in ast.walk(tree)
               if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "replace" in called, "the swap is not atomic"
    assert "unlink" not in called, "current is unlinked before being relinked"


# --------------------------------------------- 2 · the allow-once chokepoint

def test_a_grant_issued_before_a_reinstall_is_not_redeemable_after_it(installed):
    """⚠ THE CHOKEPOINT, AND THE WHOLE REASON REINSTALL IS ONE.

    A one-shot grant authorises ONE action under ONE policy — a human clicked
    "allow once" while looking at a verdict some specific set of rules reached.
    A reinstall is precisely the moment those rules change. Redeeming the grant
    afterwards would spend that approval under rules they never saw."""
    prefix, sessions, _ = installed
    act = act_hash = None
    act = action()
    act_hash = allow_once.fingerprint(act)

    allow_once.write_grant("s1", act_hash, granted_by="test", root=sessions)
    assert allow_once.consume("s1", act, root=sessions) is not None, (
        "the grant did not work BEFORE the reinstall — this test proves nothing")

    # Arm it again, then reinstall.
    allow_once.write_grant("s1", act_hash, granted_by="test", root=sessions)
    assert (sessions / "s1.allow-once.json").exists()

    allow_once._install_manifest_version.cache_clear()
    result = place.place(prefix=prefix, session_root=sessions)

    assert result["revoked"], "the reinstall reported revoking nothing"
    assert not (sessions / "s1.allow-once.json").exists(), "the grant file survived"
    allow_once._install_manifest_version.cache_clear()
    assert allow_once.consume("s1", act, root=sessions) is None


def test_a_grant_that_survives_deletion_is_still_not_redeemable(installed):
    """⚠ THE SECOND HALF, AND IT IS NOT REDUNDANT. Deleting alone loses to a
    grant written between the sweep and the swap. So a grant also carries the
    guard_version it was issued under, and `consume` refuses one that does not
    match — which makes a survivor unredeemable rather than merely absent."""
    prefix, sessions, first = installed
    act = action()
    allow_once.write_grant("s2", allow_once.fingerprint(act), root=sessions)
    grant = json.loads((sessions / "s2.allow-once.json").read_text())
    assert grant["guard_version"] == first["version"]

    # Simulate the race: reinstall, then put the OLD grant back by hand.
    allow_once._install_manifest_version.cache_clear()
    place.place(prefix=prefix, session_root=sessions)
    (sessions / "s2.allow-once.json").write_text(json.dumps(grant))

    allow_once._install_manifest_version.cache_clear()
    # Version differs only if the content changed; force the mismatch directly.
    grant["guard_version"] = "some-older-version-00000000"
    (sessions / "s2.allow-once.json").write_text(json.dumps(grant))
    allow_once._install_manifest_version.cache_clear()
    assert allow_once.consume("s2", act, root=sessions) is None


def test_a_grant_with_no_version_at_all_is_refused(installed):
    """This module's own rule: anything it cannot understand fails to a
    non-override. "Issued by a version that did not record one" is that case."""
    _, sessions, _ = installed
    act = action()
    (sessions / "s3.allow-once.json").write_text(json.dumps({
        "session_id": "s3", "action_hash": allow_once.fingerprint(act),
        "expires_at": 9_999_999_999.0}))
    allow_once._install_manifest_version.cache_clear()
    assert allow_once.consume("s3", act, root=sessions) is None


def test_grants_still_work_with_no_install_at_all(tmp_path, monkeypatch):
    """⚠ None IS A REAL ANSWER. Running from a checkout with nothing installed
    is the normal development state; there the grant and the lookup both say
    None, they match, and allow-once behaves exactly as it always did."""
    monkeypatch.setenv("STING_INSTALL_ROOT", str(tmp_path / "nothing"))
    allow_once._install_manifest_version.cache_clear()
    act = action()
    allow_once.write_grant("s4", allow_once.fingerprint(act), root=tmp_path)
    assert allow_once.consume("s4", act, root=tmp_path) is not None


# ---------------------------------------------------------- 6 · uninstalling

def test_uninstall_removes_the_tree_and_the_pointer(installed):
    prefix, _, _ = installed
    place.remove(prefix=prefix)
    assert not (prefix / "current").exists()
    assert not prefix.exists() or not any(prefix.iterdir())


def test_uninstall_leaves_the_logs_alone(installed):
    """⚠ AN UNINSTALLER THAT DELETES THE RECORD OF WHAT A GUARD DECIDED IS ONE
    AN ATTACKER WOULD LOVE TO RUN. Removing the guard must not remove the
    history of what it saw."""
    prefix, sessions, _ = installed
    (sessions / "keeper.log.jsonl").write_text('{"seq": 1}\n')
    place.remove(prefix=prefix)
    assert (sessions / "keeper.log.jsonl").exists()


# ----------------------------------------------------- 3 · the supervisor

def test_the_supervisor_file_is_written_where_the_platform_expects():
    import platform as plat
    if service.kind() == "unsupported":
        pytest.skip(f"{plat.system()} has no supervisor here")
    assert service.target_path().name.startswith("dev.sting.shipper")


def test_the_supervisor_body_restarts_and_runs_at_login(tmp_path):
    if service.kind() == "unsupported":
        pytest.skip("no supervisor on this platform")
    body = (supervisor._plist("/usr/bin/python3", tmp_path / "run.py", {"A": "b"})
             if service.kind() == "launchd"
             else supervisor._unit("/usr/bin/python3", tmp_path / "run.py", {"A": "b"}))
    assert "A" in body and "b" in body
    assert ("KeepAlive" in body and "RunAtLoad" in body) or \
           ("Restart=always" in body and "WantedBy=default.target" in body)


def test_the_supervisor_names_what_sleep_costs():
    """⚠ AN OVERNIGHT SLEEP IS INDISTINGUISHABLE FROM A DEAD GUARD, and that is
    stated rather than tuned around — raising the staleness multiple until sleep
    stops triggering it would mean a genuinely dead guard also takes a working
    day to notice."""
    import inspect
    # Whitespace-normalised: the claim is real but wraps across a line, and a
    # naive substring search failed on the line break rather than on the claim.
    doc = " ".join((inspect.getdoc(supervisor) or "").split())
    assert "asleep" in doc.lower()
    assert "indistinguishable from a dead guard" in doc
    assert "NOT BUILT" in doc


# -------------------------------------------------------- 7 · the messages

@pytest.mark.parametrize("text", [
    messages.wrong_python(),
    messages.no_agent_found([Path("/a"), Path("/b")]),
    messages.collector_unreachable("http://x:1", "refused"),
    messages.bad_token("http://x:1"),
    messages.no_write_permission(Path("/nope/x"), "denied"),
    messages.roots_declined(detect.propose_roots()),
    messages.preflight_failed(2),
])
def test_every_failure_message_names_something_to_do(text):
    """⚠ A TRACEBACK IS NOT A MESSAGE. Each of these must name the thing to fix,
    not merely report that something broke."""
    assert len(text.splitlines()) >= 4, text
    lowered = text.lower()
    assert any(word in lowered for word in ("fix", "check", "re-run", "install")), text
    assert "traceback" not in lowered
    assert "errno" not in lowered


def test_the_roots_message_carries_the_measured_cost():
    text = messages.roots_declined(detect.propose_roots())
    assert "74 of 89" in text
    assert "confirmed and never inferred" in text


# ------------------------------------------------------------ 2 · detection

def test_sibling_discovery_finds_the_real_repos():
    """⚠ THIS ASSERTS ON THE DEVELOPER'S OWN LAYOUT, so it can only run where
    that layout exists. A CI checkout has ONE repo and no siblings, and the
    assertion `count(":") >= 1` was reading as a failure of discovery rather
    than as an absence of anything to discover. Skipped loudly there — a red CI
    job that says nothing about the code is what makes a Windows number
    unreadable."""
    proposal = detect.propose_roots()
    assert str(ROOT) in proposal["proposed"]
    assert "74 of 89" in proposal["why"]

    siblings = [d for d in ROOT.parent.iterdir()
                if d.is_dir() and d != ROOT and (d / ".git").exists()]
    if not siblings:
        pytest.skip("no sibling repositories beside this checkout — "
                     "nothing for discovery to find")
    assert proposal["value"].count(":") >= 1


def test_identity_discovery_says_what_it_is_and_is_not_for():
    identity = detect.propose_identity()
    assert identity["identifiers"]
    assert "redact_logs" in identity["used_for"]
    # ⚠ RE-PINNED (item E): there are no tiers since 28 Sep 2026. What bounds
    # what the shipper sends is masking every record by value type, which does
    # not read this list.
    assert "tier" not in identity["not_used_for"].lower()
    assert "masked" in identity["not_used_for"]
    assert "shipper/mask.py" in identity["not_used_for"]


# ══════════ partial coverage must READ as partial, not as a successful install

def test_copilot_has_no_user_level_config_and_detect_says_so():
    """⚠ ESTABLISHED, NOT ASSUMED. Every other agent's `AGENT_CONFIGS` list has
    a `Path.home()` entry; copilot's two candidates are BOTH project-relative.
    Checked on this machine: `~/.copilot/` exists and holds `config.json`, `ide`
    and `logs` — and no hook configuration of any kind, anywhere.

    So there is nothing to point a user-level install at, and inventing a path
    would be writing a config against documentation nobody verified.
    """
    from installer import detect

    assert not any(p.is_absolute() for p in detect.AGENT_CONFIGS["copilot"]), (
        "copilot gained an absolute config path — if that is a REAL user-level "
        "location, config_for() will now use it and this test should be deleted")
    _config, user_level = detect.config_for("copilot")
    assert user_level is False


@pytest.mark.parametrize("agent", ["claude-code", "cursor", "codex", "antigravity"])
def test_every_other_agent_is_user_level(agent):
    """The contrast is the point: copilot is the only one that guards a single
    directory, so it is the only one that needs the warning."""
    from installer import detect

    _config, user_level = detect.config_for(agent)
    assert user_level is True, agent


def test_a_partial_install_says_so_in_the_block_a_developer_reads():
    """⚠ SAYING IT ONCE, 200 LINES EARLIER, IS THE SAME AS NOT SAYING IT. The
    stage-0 survey already warned; the write line and the `Done` block did not,
    so an install covering one repository printed `Done` and read as complete.
    """
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    assert "COVERS THIS DIRECTORY ONLY" in source
    assert "PARTIAL COVERAGE" in source
    # and the Done block is where the second one lives
    done = source[source.index('head("Done")'):]
    assert "PARTIAL COVERAGE" in done, (
        "the warning is not in the block a developer actually reads")
