"""A collector URL must be https:// — or http:// on loopback only (item E).

⚠ THE BUG. `installer/enrol.py` accepted `http://`, and nothing later refused
it, so one mistyped URL sent the enrolment secret, the device token and every
batch in cleartext. The rule is now one function, `shipper.config.
collector_url_refusal`, enforced where a URL is accepted (the enrolment string,
`install.py`'s resolved flag / saved setting / environment) and where anything
is sent (`shipper.client`, and the shipper loop, which says so once and keeps
every record).

⚠ LOOPBACK STAYS. This repo's own shipper tests drive a real collector on
`http://127.0.0.1:<port>` (tests/test_shipper_against_collector.py and others),
and a loopback socket never leaves the machine.

⚠ TWO COPIES, ON PURPOSE, KEPT EQUAL HERE. The collector's contract test loads
`installer/enrol.py` by path, standalone, so that file cannot import the shipper
rule; it carries a mirror, and the parity test below pins them together.
"""
from __future__ import annotations

import base64
import json
import urllib.request

import pytest

from installer import enrol
from shipper import client, config

ACCEPTED = [
    "https://collector.example",
    "https://collector.example/ingest/",
    "HTTPS://collector.example",
    "http://127.0.0.1:8080",
    "http://localhost:9",
    "http://[::1]:8443/x",
]
REFUSED = [
    "http://collector.example",
    "http://collector.example.invalid/ingest",
    "HTTP://collector.example",
    "http://127.0.0.2",               # only the loopback NAMES, exactly
    "http://localhost.example.com",
    "ftp://collector.example",
    "collector.example",
    "https://",
    "https:///path",
    "",
]


@pytest.mark.parametrize("url", ACCEPTED)
def test_https_and_loopback_http_are_accepted(url):
    assert config.collector_url_refusal(url) is None


@pytest.mark.parametrize("url", REFUSED)
def test_every_other_url_is_refused_with_a_reason(url):
    reason = config.collector_url_refusal(url)
    assert reason and "https://" in reason, reason


def test_the_refusal_never_echoes_the_url():
    """A URL can carry userinfo; the reason names only the problem."""
    reason = config.collector_url_refusal("http://user:pw@collector.example")
    assert reason and "pw" not in reason and "collector.example" not in reason


@pytest.mark.parametrize("url", ACCEPTED + REFUSED)
def test_the_enrol_mirror_agrees_with_the_shipper_rule(url):
    assert (enrol.collector_url_refusal(url) is None) == (
        config.collector_url_refusal(url) is None)


def _string(url: str) -> str:
    blob = json.dumps({"url": url, "secret": "s3cr3t"}).encode()
    return enrol.PREFIX + base64.urlsafe_b64encode(blob).decode().rstrip("=")


def test_an_enrolment_string_naming_http_is_refused():
    with pytest.raises(enrol.Failure) as caught:
        enrol.decode(_string("http://collector.example"))
    assert "https://" in str(caught.value.render())


def test_an_enrolment_string_naming_https_or_loopback_still_decodes():
    assert enrol.decode(_string("https://collector.example/")) == (
        "https://collector.example", "s3cr3t")
    assert enrol.decode(_string("http://127.0.0.1:8080"))[0] == "http://127.0.0.1:8080"


def test_enrol_never_opens_a_connection_to_an_http_collector():
    def opener(*_a, **_k):
        raise AssertionError("the enrolment secret was about to be sent")
    with pytest.raises(enrol.Failure):
        enrol.enrol("http://collector.example", "s3cr3t", "laptop", opener=opener)


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("a socket was opened for a refused URL")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)


def test_client_post_to_http_sends_nothing_and_loses_nothing(no_network):
    outcome = client.post("http://collector.example/v1/batches", "tok", b"{}")
    assert outcome.kind == client.UNAVAILABLE      # retried later, never dropped
    assert "https://" in outcome.detail


def test_client_get_to_http_sends_nothing(no_network):
    outcome = client.get("http://collector.example/v1/policy", "tok")
    assert outcome.kind == client.UNAVAILABLE
    assert "https://" in outcome.detail


# ═══════════════════════════════ a SAVED http:// URL on an existing install


def _write_log(root, session: str, n: int):
    import os
    from core import audit_log
    os.environ["STING_SESSION_ROOT"] = str(root)
    for i in range(n):
        audit_log.append(session, audit_log.build_body(
            session, seq=1 + i, event="decision", decision="ALLOW",
            kind="EXEC", command=f"pytest -q # {i}", cwd="/work/repo",
            agent="claude-code", ts=1_786_000_000.0 + i, rule_id=None,
            reason=None, evidence=f"@0 pytest -q # {i}"))
    return audit_log.default_log_path(session, root)


def test_the_shipper_refuses_to_send_keeps_every_record_and_says_so_once(
        tmp_path, no_network):
    from shipper.run import Shipper
    log = _write_log(tmp_path / "logs", "sess-http", 3)
    before = log.read_bytes()
    said: list[str] = []
    settings = config.Settings(
        collector_url="http://collector.example", device_token="tok",
        device_id="laptop", log_root=tmp_path / "logs",
        state_root=tmp_path / "state", flush_seconds=0, flush_records=1)
    shipper = Shipper(settings, log=lambda *parts: said.append(" ".join(map(str, parts))))
    assert shipper.pending() == 3, "precondition: there is something to ship"

    first, second = shipper.tick(), shipper.tick()

    assert "https://" in first["skipped"] and first["shipped"] == 0
    assert second["shipped"] == 0
    assert shipper.pending() == 3, "nothing may be marked shipped"
    assert log.read_bytes() == before, "nothing may be deleted or rewritten"
    warnings = [line for line in said if "https://" in line]
    assert len(warnings) == 1, said


def test_install_refuses_an_http_collector_before_any_network(tmp_path, monkeypatch,
                                                                capsys):
    import subprocess as sp

    import install

    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("STING_INSTALL_ROOT", str(home / "prefix"))
    monkeypatch.setattr(install, "ENV_FILE", home / ".sting" / "env")
    monkeypatch.setattr(install.recorded, "ENV_FILE", home / ".sting" / "env")
    config_file = home / ".claude" / "settings.json"
    # The agent is stubbed into the temp home: an unstubbed run would write a
    # hook into the developer's own ~/.claude/settings.json.
    monkeypatch.setattr(install, "choose_agents", lambda requested: [
        {"agent": "claude-code", "evidence": "stubbed",
         "config": str(config_file), "user_level": True}])
    real_run = sp.run

    def only_preflight(cmd, *a, **k):
        if any("preflight" in str(part) for part in (cmd or [])):
            return sp.CompletedProcess(cmd, 0)
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(install.subprocess, "run", only_preflight)

    def no_probe(*_a, **_k):
        raise AssertionError("the collector was contacted over http")

    monkeypatch.setattr(install, "check_collector", no_probe)
    monkeypatch.setattr(install.console, "make_output_safe", lambda: None)
    code = install.main([
        "--yes", "--no-supervisor", "--agent", "claude-code", "--scratch", "",
        "--collector-url", "http://collector.example",
        "--device-token", "tok", "--device-id", "laptop"])
    out = capsys.readouterr().out
    assert code == 2, out
    assert "https://" in out
    assert not config_file.exists(), "no hook may be written after a refusal"
