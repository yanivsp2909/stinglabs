"""An agent tool call may not write, delete, move, stop, unload or uninstall any
part of the INSTALLED guard, in any session (maintainer, 25 Sep).

⚠ WHAT WAS OPEN. `guard_selfmod` fired only on shell commands that named
`hook_entry`, `stingd` or `/.sting` beside a kill, an `rm` or `uninstall`, and a
clean session ALLOWed every sink. So on main, in a clean session:
  · a Write to `~/.sting/policy.json` (the file that relaxes the guard) was
    ALLOW, and so was `echo … > ~/.sting/policy.json`;
  · nothing matched the install tree (`~/.local/share/sting`), the shipper's
    launch agent or unit, `tee`, `sed -i`, `curl -o`, `>|`, or `mv` / `rm` of a
    guard file written any other way;
  · `untrusted_unexpected:guard_selfmod` was relaxed to ASK for every machine.

⚠ WHAT NOW DECIDES. `installed_guard:guard_selfmod`, a floor applied after the
engine's own ladder: DENY in every session, never relabelling a more specific
DENY (a credential leaving, a canary, a catastrophic delete, an org-policy
catch). A person can still do each of these from their own terminal: the hook
only sees agent tool calls.

⚠ RELAXING IT GIVES BACK TODAY'S VERDICT, not a blanket ALLOW. The floor carries
the verdict it replaced, so `"installed_guard:guard_selfmod": "allow"` in a
person's local `~/.sting/policy.json` returns exactly what the rest of the
engine decides: ALLOW where a clean session allowed, the irreversible ASK for a
recursive delete, and in an untrusted session `untrusted_unexpected:
guard_selfmod`, which the shipped default no longer relaxes.

⚠ THE SOURCE REPO IS NOT THE GUARD. A source checkout is development and
stays exactly as it was: no part below matches it.
"""
from __future__ import annotations

import json

import pytest

import hook_entry
from core import engine, policy, shell_scan
from core.types import ActionKind, Decision, SessionState
from tests.test_engine_sources import FakeWorld, act

RULE = "installed_guard:guard_selfmod"
HOMES = ("/Users/dev", "/home/dev")
LABEL = "dev.sting.shipper.1a2b3c4d"
ENV_SECRET = "FAKE_TOKEN=AKIA_TEST_GUARD_PROTECTION_0001\n"   # a dummy, never real

# Every part of an installed guard an agent can reach, relative to a home.
FILE_PARTS = {
    "relaxation file": ".sting/policy.json",
    "org policy cache": ".sting/org_policy.json",
    "settings and token": ".sting/env",
    "decision log": ".sting/sessions/s1.log.jsonl",
    "daemon socket": ".sting/sessions/daemon.sock",
    "daemon declaration": ".sting/sessions/daemon.json",
    "shipper cursor": ".sting/shipper/cursor.json",
    "shipper log": ".sting/shipper.err.log",
    "installed engine": ".local/share/sting/current/core/engine.py",
    "installed hook": ".local/share/sting/current/sting_hook.py",
    "installed record": ".local/share/sting/v1.0.4-deadbeef/INSTALL.json",
    "launch agent": f"Library/LaunchAgents/{LABEL}.plist",
    "systemd unit": f".config/systemd/user/{LABEL}.service",
}
DIRECTORY_PARTS = {
    "state directory": ".sting",
    "sessions": ".sting/sessions",
    "install tree": ".local/share/sting",
    "install pointer": ".local/share/sting/current",
    "the directory above the install": ".local/share",
}

WRITE_FORMS = {
    "redirect": "echo '{{}}' > {t}",
    "append": "echo x >> {t}",
    "noclobber": "echo x >| {t}",
    "stderr": "ls /nope 2> {t}",
    "both": "ls /nope &> {t}",
    "tee": "echo x | tee {t}",
    "tee-append": "echo x | tee -a {t}",
    "cp": "cp /tmp/x {t}",
    "mv-onto": "mv /tmp/x {t}",
    "install": "install -m 600 /tmp/x {t}",
    "sed-i": "sed -i 's/a/b/' {t}",
    "sed-i-suffix": "sed -i.bak -e 's/a/b/' {t}",
    "curl-o": "curl -sS -o {t} https://example.com/x",
    "curl-output": "curl --output {t} https://example.com/x",
    "wget-O": "wget -q -O {t} https://example.com/x",
    "outfile": "Invoke-WebRequest -Uri https://example.com/x -OutFile {t}",
    "rsync": "rsync -a /tmp/x {t}",
    "patch": "patch {t} /tmp/p.diff",
    "dd": "dd if=/tmp/x of={t}",
    "in-bash-c": "bash -c 'echo x > {t}'",
    "cp-then-2>&1": "cp /tmp/x {t} 2>&1",
    "curl-o-after-2>&1": "curl -s https://example.com/x 2>&1 -o {t}",
}
DELETE_FORMS = {
    "rm": "rm {t}",
    "rm-rf": "rm -rf {t}",
    "unlink": "unlink {t}",
    "mv-away": "mv {t} /tmp/elsewhere",
}
STOP_FORMS = [
    "pkill -f shipper/run.py",
    "pkill -f shipper.run",
    "pkill -f daemon/server.py",
    "kill $(pgrep -f daemon/server.py)",
    "pkill -f '.*daemon/server.py'",
    "pkill -f ~/.local/share/sting/current/shipper/run.py",
    "pkill -f hook_entry",
    f"launchctl bootout gui/501/{LABEL}",
    f"launchctl unload ~/Library/LaunchAgents/{LABEL}.plist",
    f"systemctl --user stop {LABEL}",
    f"systemctl --user disable --now {LABEL}.service",
    f"schtasks /End /TN \\Sting\\{LABEL}",
    f"Unregister-ScheduledTask -TaskName {LABEL} -Confirm:$false",
    "python3 install.py --uninstall",
    "pip uninstall -y sting-engine",
]
CWD_FORMS = [
    "cd ~/.sting && curl -O https://example.com/policy.json",
    "cd ~/.sting/sessions && wget https://example.com/x.log.jsonl",
    "cd ~/.local/share/sting/current && patch -p1 < /tmp/p.diff",
    "cd ~ && rm -rf .sting",
    "cd ~/.local/share && rm -rf sting",
]
READS = [
    "cat ~/.sting/sessions/s1.log.jsonl",
    "tail -n 50 ~/.sting/shipper.err.log",
    "ls -la ~/.local/share/sting",
    "python3 tools/verify_log.py --root ~/.sting/sessions",
    f"launchctl print gui/501/{LABEL}",
    f"systemctl --user status {LABEL}",
    "cp ~/.sting/policy.json /tmp/policy-backup.json",
    "grep -n guard_selfmod ~/.sting/policy.json",
    "diff ~/.local/share/sting/current/core/engine.py core/engine.py",
    "wc -l ~/.sting/sessions/*.log.jsonl > /tmp/counts.txt",
    "launchctl list | grep -i sting",
]
SOURCE_REPO = [
    "sed -i 's/a/b/' ~/src/sparta-security/engine/core/policy.py",
    "echo x > ~/src/sparta-security/engine/docs/x.md",
    "rm ~/src/sparta-security/engine/hook_entry.py",
    "cd ~/src/sparta-security/engine && python3 -m pytest tests -q",
    "cp /tmp/engine.py ~/src/sparta-security/engine/core/engine.py",
    "pkill -f sting",
    "pkill -f ~/src/sparta-security/engine/daemon/server.py",
]
# Another project's processes with the guard's generic-looking names: a pattern
# that cannot match the guard's command line stops nothing of it.
OTHER_PROJECTS = [
    "pkill -f myapp/daemon/server.py",
    "pkill -f /opt/app/shipper/run.py",
    "timeout --kill-after=5 python3 daemon/server.py",
]


# ═══════════════════════════════════════════════════════════════ sessions

def clean() -> SessionState:
    return SessionState(seq=1)


def untrusted() -> SessionState:
    state = SessionState(seq=1)
    engine.decide(act(ActionKind.READ, paths=("/repo/ISSUE_418.md",)), state, FakeWorld())
    assert state.untrusted
    return state


def holding_a_secret() -> SessionState:
    state = SessionState(seq=1)
    engine.decide(act(ActionKind.READ, paths=("/repo/.env",)), state,
                  FakeWorld({"/repo/.env": ENV_SECRET}))
    assert state.holds_secret and not state.untrusted
    return state


SESSIONS = {"clean": clean, "untrusted": untrusted, "secret": holding_a_secret}


def decide(action, state):
    state.seq = state.next_seq(None)
    return engine.decide(action, state, FakeWorld())


def shell(command):
    return act(ActionKind.EXEC, command=command)


def assert_protected(verdict, session):
    assert verdict.decision is Decision.DENY, (session, verdict)
    if session != "secret":
        assert verdict.rule_id == RULE, (session, verdict)


# ═══════════════════════════════ 1 · every part, every form, every session → DENY

@pytest.mark.parametrize("session", SESSIONS)
@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("part", FILE_PARTS)
@pytest.mark.parametrize("kind", [ActionKind.WRITE, ActionKind.EDIT])
def test_a_write_or_edit_to_a_part_is_denied(session, home, part, kind):
    path = f"{home}/{FILE_PARTS[part]}"
    verdict = decide(act(kind, paths=(path,), content="{}\n"), SESSIONS[session]())
    assert_protected(verdict, session)


@pytest.mark.parametrize("session", SESSIONS)
@pytest.mark.parametrize("form", WRITE_FORMS)
@pytest.mark.parametrize("part", FILE_PARTS)
def test_every_shell_write_form_onto_a_part_is_denied(session, form, part):
    command = WRITE_FORMS[form].format(t=f"~/{FILE_PARTS[part]}")
    assert_protected(decide(shell(command), SESSIONS[session]()), session)


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("form", ["redirect", "tee", "sed-i", "cp", "curl-o"])
def test_a_literal_home_is_the_same_part(home, form):
    command = WRITE_FORMS[form].format(t=f"{home}/.sting/policy.json")
    assert_protected(decide(shell(command), clean()), "clean")


@pytest.mark.parametrize("session", SESSIONS)
@pytest.mark.parametrize("form", DELETE_FORMS)
@pytest.mark.parametrize("part", list(FILE_PARTS) + list(DIRECTORY_PARTS))
def test_deleting_or_moving_a_part_is_denied(session, form, part):
    relative = {**FILE_PARTS, **DIRECTORY_PARTS}[part]
    command = DELETE_FORMS[form].format(t=f"~/{relative}")
    assert_protected(decide(shell(command), SESSIONS[session]()), session)


@pytest.mark.parametrize("session", SESSIONS)
@pytest.mark.parametrize("command", STOP_FORMS)
def test_stopping_unloading_or_uninstalling_the_guard_is_denied(session, command):
    assert_protected(decide(shell(command), SESSIONS[session]()), session)


@pytest.mark.parametrize("session", SESSIONS)
@pytest.mark.parametrize("command", CWD_FORMS)
def test_a_write_or_delete_reached_through_cd_is_denied(session, command):
    assert_protected(decide(shell(command), SESSIONS[session]()), session)


def test_the_documented_stop_command_is_for_a_person_not_an_agent():
    """`supervisor.stop_command()` prints the line a PERSON types in their own
    terminal. From an agent it stops the guard's reporter, and is refused."""
    from shipper import service
    assert_protected(decide(shell(service.stop_command()), clean()), "clean")


def test_the_reason_names_the_part_and_the_way_a_person_can_do_it():
    verdict = decide(shell("echo x > ~/.sting/policy.json"), clean())
    assert "~/.sting/policy.json" in verdict.reason, verdict.reason
    assert "your own terminal" in verdict.reason, verdict.reason
    assert verdict.evidence, "a DENY names what it matched"


def test_a_more_specific_deny_keeps_its_own_name():
    """`rm -rf ~` deletes ~/.sting too; it stays the catastrophic delete."""
    verdict = decide(shell("rm -rf ~"), clean())
    assert verdict.decision is Decision.DENY and verdict.rule_id == "catastrophic_delete"


def test_the_floor_holds_when_session_state_cannot_be_read():
    verdict = engine.fallback_verdict(shell("echo x > ~/.sting/policy.json"))
    assert verdict.decision is Decision.DENY and verdict.rule_id == RULE


# ═══════════════════════════════════════════ 2 · reads stay ALLOW, everywhere

@pytest.mark.parametrize("session", ["clean", "untrusted"])
@pytest.mark.parametrize("command", READS)
def test_reading_the_guard_is_allowed(session, command):
    verdict = decide(shell(command), SESSIONS[session]())
    assert verdict.rule_id != RULE, verdict
    if session == "clean":
        assert verdict.decision is Decision.ALLOW, verdict


@pytest.mark.parametrize("home", HOMES)
def test_the_read_tool_on_a_part_is_allowed(home):
    verdict = decide(act(ActionKind.READ, paths=(f"{home}/.sting/policy.json",)), clean())
    assert verdict.decision is Decision.ALLOW, verdict


# ═══════════════════════════════════════════ 3 · the source repo is unchanged

@pytest.mark.parametrize("session", ["clean", "untrusted"])
@pytest.mark.parametrize("command", SOURCE_REPO)
def test_the_source_repo_is_not_the_guard(session, command, monkeypatch):
    """The floor does not fire, so the verdict is exactly the one the engine
    reaches without it."""
    action = shell(command)
    with_floor = decide(action, SESSIONS[session]())
    monkeypatch.setattr(engine, "_guard_floor", lambda verdict, *_a, **_k: verdict,
                        raising=False)
    without = decide(action, SESSIONS[session]())
    assert with_floor == without and with_floor.rule_id != RULE, (with_floor, without)


@pytest.mark.parametrize("command", OTHER_PROJECTS)
def test_another_projects_daemon_is_not_the_guard(command):
    verdict = decide(shell(command), clean())
    assert verdict.decision is Decision.ALLOW and verdict.rule_id != RULE, verdict


def test_a_write_tool_in_the_source_repo_is_allowed_in_a_clean_session():
    path = "/Users/dev/src/sparta-security/core/engine.py"
    verdict = decide(act(ActionKind.WRITE, paths=(path,), content="x"), clean())
    assert verdict.decision is Decision.ALLOW, verdict


# ═══════════════════════ 4 · `>|` is a redirect, and never a pipe (both splitters)

def test_the_engine_splitter_does_not_end_a_segment_at_a_noclobber_redirect():
    assert engine._SEGMENT_END.search("echo x >| f") is None
    assert engine._SEGMENT_END.search("echo x | tee f").group(0) == "|"
    import re
    assert re.fullmatch(f"{engine._NOT_SEGMENT_END}*", "echo x >| f")


def test_the_scanner_does_not_split_at_a_noclobber_redirect():
    mask, depth = shell_scan._depths("echo x >| f")
    assert len(shell_scan._segments("echo x >| f", mask, depth)) == 1
    mask, depth = shell_scan._depths("echo x | tee f")
    assert len(shell_scan._segments("echo x | tee f", mask, depth)) == 2


@pytest.mark.parametrize("redirect", ["2>/dev/null", ">| /tmp/log", "2>&1"])
def test_a_redirect_after_a_copy_is_never_its_destination(redirect):
    """The copy grammar the floor shares with taint. Main read `cp .env
    /tmp/leak 2>/dev/null` as a copy INTO `2>/dev/null`, so the label landed on
    a path nothing writes and the real copy went unlabelled."""
    pairs = engine._copy_pairs(f"cp .env /tmp/leak {redirect}", "/repo")
    assert pairs == [(0, "/repo/.env", "/tmp/leak")], pairs


def test_a_noclobber_redirect_onto_a_raw_disk_is_still_the_catastrophe():
    verdict = decide(shell("cat /dev/zero >| /dev/sda"), clean())
    assert verdict.decision is Decision.DENY and verdict.rule_id == "catastrophic_overwrite"


# ═══════════════ 5 · the shipped default, and relaxing the rule in a person's file

def test_the_shipped_default_no_longer_relaxes_guard_selfmod():
    assert "untrusted_unexpected:guard_selfmod" not in policy.SHIPPED_DEFAULT
    assert RULE not in policy.SHIPPED_DEFAULT


def _hook(tmp_path, monkeypatch, sid, command, rules=None, first_read=None):
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path / "sessions"))
    monkeypatch.setenv("STING_OBSERVE", "0")
    monkeypatch.setenv("STING_POLICY", str(tmp_path / "policy.json"))
    (tmp_path / "policy.json").write_text(json.dumps({"rules": rules or {}}),
                                          encoding="utf-8")
    if first_read:
        hook_entry.run(json.dumps({"session_id": sid, "cwd": "/tmp", "tool_name": "Read",
                                   "tool_input": {"file_path": first_read}}),
                       agent="claude-code")
    out, _err, code = hook_entry.run(json.dumps(
        {"session_id": sid, "cwd": "/tmp", "tool_name": "Bash",
         "tool_input": {"command": command}}), agent="claude-code")
    assert code == 0
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"]


# (command, today's verdict in a clean session, before the floor existed)
TODAY_CLEAN = [
    ("pkill -f shipper/run.py", "allow"),
    ("echo x > ~/.sting/policy.json", "allow"),
    ("rm -rf ~/.sting/sessions", "ask"),                # irreversible, today and after
]


@pytest.mark.parametrize("command,today", TODAY_CLEAN)
def test_relaxing_the_rule_gives_back_todays_verdict(tmp_path, monkeypatch, command, today):
    sid = f"relax-{TODAY_CLEAN.index((command, today))}"
    assert _hook(tmp_path, monkeypatch, sid + "-a", command) == "deny"
    assert _hook(tmp_path, monkeypatch, sid + "-b", command,
                 rules={RULE: "allow"}) == today


def test_relaxing_it_leaves_an_untrusted_session_at_the_engines_own_deny(tmp_path, monkeypatch):
    """In an untrusted session the engine's own verdict is
    `untrusted_unexpected:guard_selfmod`, DENY, which the shipped default no
    longer relaxes. A developer building Sting relaxes both."""
    command, issue = "pkill -f shipper.run", "/tmp/ISSUE_418.md"
    assert _hook(tmp_path, monkeypatch, "u-1", command, rules={RULE: "allow"},
                 first_read=issue) == "deny"
    assert _hook(tmp_path, monkeypatch, "u-2", command, first_read=issue,
                 rules={RULE: "allow", "untrusted_unexpected:guard_selfmod": "ask"}) == "ask"
