"""The org policy cache and the local relaxation file are two files.

⚠ THE BUG. `core/policy.py` `default_path()` (a person's relaxations) and
`core/org_policy.py` `cache_path()` (the org document the shipper fetches) both
resolved to `~/.sting/policy.json`, and nothing told the two apart:
  · the first org policy newer than the file's `version` overwrote it, and a
    person's relaxations were gone (collector #19 serves versions at 1,000,000+,
    so the first served policy always would);
  · a local file carrying `"version": 1` made an org's version 1 read as "not
    newer", so it never applied on that machine;
  · an org document is stored with unknown keys passed through, so one carrying
    `"rules"` was then read by `policy.load()` as relaxations: an org document
    could loosen a verdict, which `core/org_policy.py` says it can never do.

The org cache is now `~/.sting/org_policy.json`; the relaxation file stays
`~/.sting/policy.json`. Neither is ever written through the other's path, and
uninstall removes both.

⚠ THESE TESTS SET NEITHER STING_POLICY NOR STING_POLICY_CACHE. Every earlier org
policy test set the cache override, which is exactly what hid the collision. The
suite's HOME is a temp directory (conftest), so the default paths are the ones
under test.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import install
from core import org_policy, policy
from shipper import client, config
from shipper.client import Outcome
from shipper.policy_poll import PolicyPoll

RELAXED_RULE = "untrusted_unexpected:git_push"
SOURCE = {"type": "path", "value": "/srv/customers.db", "severity": "deny"}


@pytest.fixture(autouse=True)
def defaults(monkeypatch):
    monkeypatch.delenv("STING_POLICY", raising=False)
    monkeypatch.delenv("STING_POLICY_CACHE", raising=False)


def local_file() -> Path:
    return Path.home() / ".sting" / "policy.json"


def org_file() -> Path:
    return Path.home() / ".sting" / "org_policy.json"


def write_local(doc: dict) -> bytes:
    local_file().parent.mkdir(parents=True, exist_ok=True)
    local_file().write_text(json.dumps(doc), encoding="utf-8")
    return local_file().read_bytes()


def poll(monkeypatch, version: int, **extra) -> str:
    """One poll of the real shipper loop against a collector serving `version`."""
    doc = {"version": version, "updated_at": 1.0, "updated_by": "org-admin",
           "sensitive_sources": [SOURCE], **extra}
    monkeypatch.setattr(client, "get", lambda url, token, timeout=30.0: Outcome(
        client.STORED, 200, {"org": "o", "version": version, "policy": doc}))
    settings = config.Settings(collector_url="https://c.invalid", device_token="tok",
                               device_id="dev", policy_seconds=900)
    return PolicyPoll(settings, now=lambda: 1e9).maybe_fetch(log=lambda *_: None)


def test_an_org_doc_lands_in_its_own_file(monkeypatch):
    assert poll(monkeypatch, 3) == "stored"
    assert json.loads(org_file().read_text())["sensitive_sources"] == [SOURCE]
    assert not local_file().exists(), "the org document was written as the local file"
    assert org_policy.cache_path() == org_file()
    assert Path(policy.default_path()) == local_file()


@pytest.mark.parametrize("version", [1, 2, 1_000_000, org_policy.MAX_VERSION])
@pytest.mark.parametrize("local", [
    {"rules": {RELAXED_RULE: "allow"}},
    {"version": 1, "rules": {RELAXED_RULE: "allow"}},
], ids=["documented-shape", "with-version-1"])
def test_a_local_relaxation_survives_an_org_policy_of_any_version(monkeypatch, local, version):
    before = write_local(local)
    poll(monkeypatch, version)
    assert local_file().read_bytes() == before, "the org policy overwrote the relaxations"
    assert policy.load().rules.get(RELAXED_RULE) == policy.RELAX["allow"]


def test_an_org_version_1_applies_on_a_machine_that_has_a_local_file(monkeypatch):
    write_local({"version": 1, "rules": {RELAXED_RULE: "allow"}})
    assert poll(monkeypatch, 1) == "stored"
    assert org_policy.load()["version"] == 1
    assert org_policy.load()["sensitive_sources"] == [SOURCE]


def test_an_org_doc_can_never_relax_a_rule(monkeypatch):
    """⚠ A DENY NEVER LOOSENS. An org document is stored with unknown keys kept,
    so one carrying `rules` or `shipped_default` must not reach `policy.load()`."""
    poll(monkeypatch, 5, rules={RELAXED_RULE: "allow"}, shipped_default=False)
    assert policy.load().rules == dict(policy.SHIPPED_DEFAULT), (
        "the org document changed the relaxations in force")


def test_the_org_cache_is_never_written_through_the_local_path(monkeypatch):
    """Neither file is ever written through the other's path, even when an
    override points them at one file."""
    before = write_local({"rules": {RELAXED_RULE: "allow"}})
    monkeypatch.setenv("STING_POLICY_CACHE", str(local_file()))
    with pytest.raises(org_policy.PolicyRejected):
        org_policy.store({"version": 9, "sensitive_sources": [SOURCE]})
    assert local_file().read_bytes() == before


def test_uninstall_removes_both_policy_files(monkeypatch):
    write_local({"rules": {RELAXED_RULE: "allow"}})
    org_policy.store({"version": 2, "sensitive_sources": [SOURCE]})
    assert local_file().exists() and org_file().exists()
    home = Path.home()
    monkeypatch.setattr(install, "ENV_FILE", home / ".sting" / "env")
    monkeypatch.setattr(install.detect, "agent_configs", lambda: {})
    monkeypatch.setattr(install.supervisor, "remove", lambda: {"removed": []})
    monkeypatch.setattr(install, "stop_daemons", lambda: [])
    monkeypatch.setattr(install.place, "remove", lambda: {"removed": []})
    (home / ".sting" / "sessions").mkdir(parents=True)
    (home / ".sting" / "sessions" / "keeper.log.jsonl").write_text('{"seq": 1}\n')

    assert install.do_uninstall(argparse.Namespace()) == 0
    assert not local_file().exists() and not org_file().exists()
    assert (home / ".sting" / "sessions" / "keeper.log.jsonl").exists(), (
        "the decision logs are evidence and stay")
