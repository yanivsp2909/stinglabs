"""The hook is untouched by the shipper, and the shipper listens for nothing.

⚠ WHY THIS IS ASSERTED ON THE SOURCE AND NOT ON BEHAVIOUR. "The hook does not
wait on the network" cannot be shown by timing a test — a fast test proves the
network happened to be fast. It is shown by proving the code CANNOT reach a
network at all: hook_entry and core/ import no networking module and no part of
`shipper`. That is a property a future edit breaks loudly instead of quietly.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
NETWORK = {"socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx",
           "asyncio", "selectors", "smtplib", "ftplib", "telnetlib",
           "xmlrpc", "webbrowser"}


def imports_of(path: Path) -> set:
    modules = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    return modules


# -------------------------------------------------- 1.1 · the hook is untouched

def test_hook_entry_imports_no_network_module():
    """⚠ THE 12 ms BUDGET IS THE REASON. A captive-portal Wi-Fi hangs a TCP
    connect for ~75 seconds. If that could ever happen inside the hook, the
    developer would feel it on a tool call — and a guard that makes the agent
    slow is a guard that gets uninstalled."""
    found = imports_of(ROOT / "hook_entry.py") & NETWORK
    assert not found, f"hook_entry.py imports {found}"


def test_hook_entry_does_not_import_the_shipper():
    """Nothing connects the two but the filesystem. An import would put the
    shipper's code — and one day its settings, its retries, its timeouts — on
    the path of every tool call."""
    assert "shipper" not in imports_of(ROOT / "hook_entry.py")


@pytest.mark.parametrize("module", sorted(
    p.name for p in (ROOT / "core").glob("*.py")))
def test_no_core_module_imports_the_shipper_or_a_network_module(module):
    found = imports_of(ROOT / "core" / module) & (NETWORK | {"shipper"})
    assert not found, f"core/{module} imports {found}"


def test_the_shipper_is_not_referenced_anywhere_on_the_hook_path():
    """A subprocess spawn would be an import this test cannot see, and spawning
    a process on a tool call puts process CREATION on the 12 ms path even if
    nothing is waited on.

    ⚠ IT LOOKS FOR A DEPENDENCY, NOT FOR A WORD, AND THAT DISTINCTION COST A
    PASS. The text scan it replaces failed on `core/engine.py` for naming
    `dev.sting.shipper` and `shipper.run` inside a REGEX — the guard's own
    service and module names, which a rule about killing the reporter must
    contain in order to recognise it. That is the opposite of a dependency: the
    engine names the process precisely so it never has to reach it.

    ⚠ AND IT IS THE FOURTH TIME THIS SHAPE HAS APPEARED HERE — after `.delete(`
    in a docstring, `fcntl` in prose, and two Windows-site signatures matching
    unrelated messages. A scanner over TEXT flags the sentence describing the
    rule; a scanner over the parse tree cannot.
    """
    import ast

    checked = 0
    files = [ROOT / "hook_entry.py"] + sorted((ROOT / "core").glob("*.py"))
    # ⚠ ARMED. Caught by this repo's own rule-13 scanner while being written: a
    # `for … assert` over `ast.walk` passes for free if nothing is walked, which
    # is the same vacuity this file exists to prevent one level up.
    assert len(files) > 5, f"only {len(files)} files to check"
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        nodes = list(ast.walk(tree))
        assert nodes, f"{path.name} parsed to nothing"
        for node in nodes:
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [a.name for a in node.names]
            else:
                continue
            checked += 1
            for name in names:
                assert "shipper" not in name, (
                    f"{path.name} imports {name} — the hook path may not depend "
                    f"on the shipper")
            # A spawn is the other way in, and it is an ATTRIBUTE access rather
            # than an import: subprocess.run([... 'shipper.run']).
        source = ast.dump(tree)
        assert "subprocess" not in source or "shipper" not in path.read_text(), (
            f"{path.name} both imports subprocess and names the shipper")
    assert checked > 20, f"only {checked} imports inspected — the walk found nothing"


def test_the_hook_still_writes_its_log_with_no_shipper_present(tmp_path,
                                                                monkeypatch):
    """The behavioural half: records accumulate whether or not anything ships.
    That is what makes "logs accumulate locally and ship later" true rather
    than aspirational."""
    monkeypatch.setenv("STING_SESSION_ROOT", str(tmp_path))
    from core import audit_log

    body = audit_log.build_body("s-alone", seq=1, event="decision",
                                 decision="ALLOW", ts=1.0)
    audit_log.append("s-alone", body)
    assert audit_log.read_records(audit_log.default_log_path("s-alone"))


# ------------------------------------------------ 1.5 · outbound only

@pytest.mark.parametrize("module", ["config.py", "cursor.py", "client.py",
                                     "run.py", "heartbeat.py"])
def test_no_shipper_module_can_listen(module):
    """⚠ NOTHING ON THE DEVELOPER'S MACHINE ACCEPTS A CONNECTION. The shipper
    opens them and never accepts one, so there is no port for anyone to reach
    and no listen address to misconfigure. Asserted on the AST rather than by
    scanning for the word, because `bind` is a common enough identifier that a
    substring search would be noise."""
    tree = ast.parse((ROOT / "shipper" / module).read_text(encoding="utf-8"))
    banned = {"bind", "listen", "accept", "create_server", "socketpair"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr not in banned, f"shipper/{module} calls .{node.attr}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in banned, f"shipper/{module} calls {node.func.id}"


def test_only_the_client_opens_a_connection_at_all():
    """One module reaches the network. Everything else is pure, which is what
    makes the rest testable without a collector."""
    for module in ("config.py", "cursor.py", "heartbeat.py"):
        assert not (imports_of(ROOT / "shipper" / module) & {"socket", "http"}), \
            f"shipper/{module} reaches for a socket"
    assert "urllib" in imports_of(ROOT / "shipper" / "client.py")


def test_the_collector_url_and_token_are_settings_not_constants():
    from shipper import config

    settings = config.from_env({"HOME": "/tmp"})
    assert settings.collector_url == ""
    assert settings.device_token == ""
    assert not settings.configured
    assert "STING_COLLECTOR_URL" in settings.why_not_configured()

    live = config.from_env({"HOME": "/tmp",
                             "STING_COLLECTOR_URL": "http://100.64.0.1:8787/",
                             "STING_DEVICE_TOKEN": "t", "STING_DEVICE_ID": "d"})
    assert live.configured
    assert live.collector_url == "http://100.64.0.1:8787", "trailing / not trimmed"


# ═══════════════ the supervisor's environment — found by a walk ══

def test_the_supervisor_pins_HOME_to_the_install_that_wrote_it(tmp_path,
                                                                monkeypatch):
    """⚠ REMOVING THE TOKEN FROM THIS FILE CREATED A DEPENDENCY NOBODY STATED.

    The device token is no longer in the world-readable supervisor file — right,
    and the shipper reads it from `~/.sting/env` (0600) instead. But that means
    the credential is now found THROUGH `HOME`, and a supervisor file that does
    not say which home it means gets whatever the supervisor's session has.

    ⚠ MEASURED on a walk: an install into an isolated home produced a launchd
    agent with `STING_SESSION_ROOT` = the install's sessions and
    `HOME=/Users/<logged-in user>` — so the resident shipper read a DIFFERENT
    env file than the install wrote, another install's token and another
    install's collector URL, while reading this install's records. It shipped
    nothing for twelve minutes with an empty log, which is the failure shape
    this project keeps refusing: running, reporting nothing wrong, sending
    nothing.
    """
    from installer import supervisor
    from shipper import service

    target = tmp_path / "sup.plist"
    monkeypatch.setattr(service, "target_path", lambda: target)
    monkeypatch.setattr(service, "kind", lambda: "launchd")

    supervisor.write("/py", Path("/e/run.py"),
                      {"STING_TIER": "x", "STING_DEVICE_TOKEN": "SECRET"})
    body = target.read_text(encoding="utf-8")

    assert "<key>HOME</key>" in body, (
        "the supervisor file does not pin HOME — the shipper finds its "
        "credential through it, so an install whose home differs from the "
        "supervisor's session silently ships nothing")
    assert "SECRET" not in body, "the token came back into the public file"


def test_pinning_home_did_not_reintroduce_the_credential(tmp_path, monkeypatch):
    """HOME is not a credential. The leak that was fixed stays fixed."""
    from installer import supervisor

    assert "HOME" not in supervisor.SECRETS
    assert supervisor.public_env(
        {"HOME": "/h", "STING_DEVICE_TOKEN": "t"}) == {"HOME": "/h"}
