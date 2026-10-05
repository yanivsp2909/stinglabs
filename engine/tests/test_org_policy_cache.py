"""The engine-side policy fetch/cache/fail-safe — step 2, which changes NO verdict.

Two layers:
  · core/org_policy — the local cache: validate on read AND write, always
    well-formed, fail toward 'nothing declared' (today's behaviour), never toward
    weaker. Includes the poisoning defence (a hand-written cache is sanitised).
  · shipper/policy_poll — the out-of-band poll: `unchanged` keeps the cache, a
    newer version replaces it, older/equal (incl. a deleted doc's version 0) and
    every fetch failure keep the last-good, a malformed fetch is refused whole.

Plus the two structural proofs the change is safe: `core/org_policy` imports no
network module or the shipper, and `core/engine.py` does not read the cache yet.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import org_policy                                      # noqa: E402
from shipper import client, config                              # noqa: E402
from shipper.client import Outcome                              # noqa: E402
from shipper.policy_poll import PolicyPoll                      # noqa: E402


@pytest.fixture
def cache(tmp_path, monkeypatch):
    path = tmp_path / "policy.json"
    monkeypatch.setenv("STING_POLICY_CACHE", str(path))
    return path


# ═══════════════════════════════════════════════════ core/org_policy — schema

def test_empty_policy_is_well_formed_version_zero():
    empty = org_policy.empty_policy()
    assert empty["version"] == 0 and empty["sensitive_sources"] == []


def test_sanitise_drops_malformed_floors_version_keeps_future_sections():
    out = org_policy.sanitise({"version": -5, "sensitive_sources": [
        {"type": "path", "value": "/ok", "severity": "deny"},
        {"type": "BAD", "value": "x", "severity": "deny"},
        "not-a-dict"], "severity_table": {"AKIA": "deny"}})
    assert out["version"] == 0
    assert out["sensitive_sources"] == [
        {"type": "path", "value": "/ok", "severity": "deny"}]
    assert out["severity_table"] == {"AKIA": "deny"}          # future section kept


@pytest.mark.parametrize("doc,ok", [
    ({"sensitive_sources": [{"type": "path", "value": "/x", "severity": "deny"}]}, True),
    ({"sensitive_sources": []}, True),
    ({"sensitive_sources": [{"type": "path", "value": "/x", "severity": "nuke"}]}, False),
    ({"sensitive_sources": [{"type": "kafka", "value": "x", "severity": "deny"}]}, False),
    ({"sensitive_sources": [{"type": "path", "value": "", "severity": "deny"}]}, False),
    ({"sensitive_sources": "not-a-list"}, False),
    ("not-a-dict", False),
])
def test_is_well_formed(doc, ok):
    assert org_policy.is_well_formed(doc) is ok


# ═══════════════════════════════════════════════ core/org_policy — cache file

def test_store_then_load_roundtrip_and_version(cache):
    org_policy.store({"version": 3, "sensitive_sources": [
        {"type": "db", "value": "pg", "severity": "ask"}]})
    got = org_policy.load()
    assert got["version"] == 3
    assert got["sensitive_sources"] == [{"type": "db", "value": "pg", "severity": "ask"}]
    assert org_policy.cached_version() == 3


def test_store_refuses_a_malformed_policy_and_writes_nothing(cache):
    with pytest.raises(org_policy.PolicyRejected):
        org_policy.store({"sensitive_sources": [
            {"type": "x", "value": "y", "severity": "z"}]})
    assert org_policy.load() == org_policy.empty_policy()


def test_load_of_no_cache_is_the_empty_policy(cache):
    assert org_policy.load() == org_policy.empty_policy()


def test_load_of_bad_json_is_the_empty_policy(cache):
    cache.write_text("{ not json", encoding="utf-8")
    assert org_policy.load() == org_policy.empty_policy()


def test_load_sanitises_a_hand_written_poisoned_cache(cache):
    # ⚠ POISONING DEFENCE — VALIDATED ON READ. A malformed cache another process
    # wrote is sanitised: bad entries dropped, never trusted as-is.
    cache.write_text(json.dumps({"version": 9, "sensitive_sources": [
        {"type": "EVIL", "value": "x", "severity": "deny"}, {"bad": "row"}]}),
        encoding="utf-8")
    assert org_policy.load()["sensitive_sources"] == []
    # A valid-but-hostile source can only ESCALATE (deny is stricter), never
    # weaken — kept, but it makes protection tighter, not looser.
    cache.write_text(json.dumps({"version": 9, "sensitive_sources": [
        {"type": "path", "value": "/anything", "severity": "deny"}]}),
        encoding="utf-8")
    assert org_policy.load()["sensitive_sources"] == [
        {"type": "path", "value": "/anything", "severity": "deny"}]


def test_store_writes_the_cache_0600(cache):
    org_policy.store({"version": 1, "sensitive_sources": []})
    assert oct(cache.stat().st_mode & 0o777) == "0o600"


# ═══════════════════════════════════════════════════════ structural safety

def test_org_policy_imports_no_network_module_or_shipper():
    tree = ast.parse((ROOT / "core" / "org_policy.py").read_text())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    network = {"urllib", "http", "socket", "ssl", "requests", "asyncio", "httplib"}
    assert not (modules & (network | {"shipper"})), modules


def test_engine_reads_the_cache_via_the_local_match_seam():
    # ⚠ SUPERSEDED BY STEP 3a. Step 2 asserted the engine did NOT read the cache;
    # step 3a APPLIES the policy, so the engine now reads it — via the LOCAL
    # `org_policy.match()` seam in mark_sources (match() calls the memoised
    # load_cached internally), never any network. Empty policy is still
    # byte-identical (tests/test_org_policy_apply.py); this pins the read is local.
    from tests import engine_source
    assert "org_policy.match(" in engine_source.text()


# ═══════════════════════════════════════════════ shipper/policy_poll — ladder

def _settings(**kw):
    base = dict(collector_url="https://c.invalid", device_token="tok",
                device_id="dev", policy_seconds=900)
    base.update(kw)
    return config.Settings(**base)


def _poll(monkeypatch, outcome, *, at=1e9):
    def fake_get(url, token, timeout=30.0):
        return outcome
    monkeypatch.setattr(client, "get", fake_get)
    poll = PolicyPoll(_settings(), now=lambda: at)
    logs = []
    kind = poll.maybe_fetch(log=logs.append)
    return poll, kind, logs


def test_poll_stores_a_newer_policy(cache, monkeypatch):
    body = {"org": "o", "version": 4, "policy": {
        "version": 4, "updated_at": 1.0, "updated_by": "a",
        "sensitive_sources": [{"type": "path", "value": "/x", "severity": "deny"}]}}
    _, kind, _ = _poll(monkeypatch, Outcome(client.STORED, 200, body))
    assert kind == "stored" and org_policy.cached_version() == 4


def test_poll_unchanged_keeps_the_cache(cache, monkeypatch):
    org_policy.store({"version": 2, "sensitive_sources": []})
    _, kind, _ = _poll(monkeypatch,
                       Outcome(client.STORED, 200, {"version": 2, "unchanged": True}))
    assert kind == "unchanged" and org_policy.cached_version() == 2


def test_poll_older_version_is_ignored_never_rewinds(cache, monkeypatch):
    org_policy.store({"version": 5, "sensitive_sources": [
        {"type": "path", "value": "/keep", "severity": "deny"}]})
    body = {"version": 2, "policy": {"version": 2, "sensitive_sources": []}}
    _, kind, _ = _poll(monkeypatch, Outcome(client.STORED, 200, body))
    assert kind == "not_newer" and org_policy.cached_version() == 5
    assert org_policy.load()["sensitive_sources"] == [
        {"type": "path", "value": "/keep", "severity": "deny"}]


def test_poll_deleted_doc_version_zero_keeps_last_good(cache, monkeypatch):
    # ⚠ A DELETED COLLECTOR DOC ANSWERS version 0 — older than any real cache, so
    # it is ignored and protection never silently drops. A real clear is a BUMPED
    # empty-sources policy, which is newer and IS applied.
    org_policy.store({"version": 7, "sensitive_sources": [
        {"type": "db", "value": "pg", "severity": "ask"}]})
    body = {"version": 0, "policy": org_policy.empty_policy()}
    _, kind, _ = _poll(monkeypatch, Outcome(client.STORED, 200, body))
    assert kind == "not_newer" and org_policy.cached_version() == 7


def test_poll_unreachable_keeps_last_good_and_logs(cache, monkeypatch):
    org_policy.store({"version": 3, "sensitive_sources": []})
    _, kind, logs = _poll(monkeypatch,
                          Outcome(client.UNAVAILABLE, 0, {}, detail="no route"))
    assert kind == client.UNAVAILABLE and org_policy.cached_version() == 3
    assert any("failing" in line for line in logs)


def test_poll_no_cache_and_unreachable_is_empty_not_fail_open(cache, monkeypatch):
    _poll(monkeypatch, Outcome(client.UNAVAILABLE, 0, {}))
    # no cache + unreachable -> the engine reads the EMPTY policy (today's
    # behaviour), never a crash and never fail-open to allow-all.
    assert org_policy.load() == org_policy.empty_policy()


def test_poll_malformed_200_keeps_last_good(cache, monkeypatch):
    org_policy.store({"version": 4, "sensitive_sources": []})
    _, kind, _ = _poll(monkeypatch,
                       Outcome(client.STORED, 200, {"version": 9, "policy": "nope"}))
    assert kind == "malformed" and org_policy.cached_version() == 4


def test_poll_refuses_a_malformed_fetched_policy_keeps_last_good(cache, monkeypatch):
    org_policy.store({"version": 4, "sensitive_sources": [
        {"type": "path", "value": "/keep", "severity": "deny"}]})
    body = {"version": 9, "policy": {"version": 9, "sensitive_sources": [
        {"type": "BAD", "value": "x", "severity": "deny"}]}}
    _, kind, _ = _poll(monkeypatch, Outcome(client.STORED, 200, body))
    assert kind == "rejected" and org_policy.cached_version() == 4
    assert org_policy.load()["sensitive_sources"] == [
        {"type": "path", "value": "/keep", "severity": "deny"}]


def test_poll_404_announces_once_then_stops(cache, monkeypatch):
    monkeypatch.setattr(client, "get",
                        lambda u, t, timeout=30.0: Outcome(client.UNSUPPORTED, 404, {}))
    poll = PolicyPoll(_settings(), now=lambda: 1e9)
    logs = []
    poll.maybe_fetch(log=logs.append)
    assert poll.supported is False and any("no /v1/policy" in x for x in logs)
    assert poll.due() is False                                 # stops polling


def test_poll_is_not_due_when_not_configured():
    assert PolicyPoll(config.Settings(), now=lambda: 1e9).due() is False


def test_store_on_a_poisoned_inode_raises_policyrejected_not_oserror(cache):
    # ⚠ FINDING A: policy.json swapped for a DIRECTORY. os.replace would raise
    # IsADirectoryError; store() must classify it as PolicyRejected so the poll
    # keeps last-good and the shipper loop never crashes. load() stays empty.
    cache.mkdir()
    with pytest.raises(org_policy.PolicyRejected):
        org_policy.store({"version": 1, "sensitive_sources": []})
    assert org_policy.load() == org_policy.empty_policy()


def test_load_floors_a_huge_planted_version_and_self_heals(cache):
    # ⚠ FINDING B: a poisoned cache with a giant version must not freeze updates.
    cache.write_text(json.dumps({"version": org_policy.MAX_VERSION + 1,
                                 "sensitive_sources": []}), encoding="utf-8")
    assert org_policy.cached_version() == 0        # floored -> next fetch wins


def test_poll_refuses_an_out_of_range_version_keeps_last_good(cache, monkeypatch):
    org_policy.store({"version": 4, "sensitive_sources": []})
    body = {"version": 10 ** 18,
            "policy": {"version": 10 ** 18, "sensitive_sources": []}}
    _, kind, _ = _poll(monkeypatch, Outcome(client.STORED, 200, body))
    assert kind == "malformed" and org_policy.cached_version() == 4


def test_poll_store_failure_degrades_and_does_not_crash(cache, monkeypatch):
    # ⚠ FINDING A backstop: an unforeseen error from store() must degrade to
    # keep-last-good, never propagate out of the loop.
    org_policy.store({"version": 4, "sensitive_sources": []})

    def boom(doc):
        raise RuntimeError("disk gremlin")

    monkeypatch.setattr(org_policy, "store", boom)
    body = {"version": 9, "policy": {"version": 9, "sensitive_sources": []}}
    _, kind, logs = _poll(monkeypatch, Outcome(client.STORED, 200, body))
    assert kind == "store_failed" and org_policy.cached_version() == 4
    assert any("could not be cached" in line for line in logs)


def test_poll_not_newer_is_logged_once_for_visibility(cache, monkeypatch):
    org_policy.store({"version": 5, "sensitive_sources": []})
    body = {"version": 3, "policy": {"version": 3, "sensitive_sources": []}}
    _, kind, logs = _poll(monkeypatch, Outcome(client.STORED, 200, body))
    assert kind == "not_newer" and any("not newer" in line for line in logs)


def test_poll_sends_since_equal_to_cached_version(cache, monkeypatch):
    org_policy.store({"version": 6, "sensitive_sources": []})
    seen = {}

    def fake_get(url, token, timeout=30.0):
        seen["url"] = url
        return Outcome(client.STORED, 200, {"version": 6, "unchanged": True})

    monkeypatch.setattr(client, "get", fake_get)
    PolicyPoll(_settings(), now=lambda: 1e9).maybe_fetch(log=lambda *_: None)
    assert "since=6" in seen["url"]
