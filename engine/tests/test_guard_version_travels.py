"""Which policy DECIDED a verdict, carried by the record that verdict is in.

⚠ THE STATE THAT PRODUCED THIS FILE. Every batch carried `manifest.guard_ref`,
which is `git describe` run in the tree that PACKS the batch, under a docstring
claiming it was there "so a verdict can be tied to a policy". On the first real
end-to-end run those were two different trees: the hook was executing an
installed copy at `…-17-g1263dd3` while the sending process ran from a checkout
at `…-19-g75e36c6`. Every verdict was therefore attributed to two commits that
had not made it.

**Provenance that is wrong is worse than provenance that is absent**, because a
reader acts on it — they open the named commit and read a rule that was not the
rule. And the deciding version was, at that moment, nowhere: not in the record
body, not in the session state, not derivable from either.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import audit_log, version, wire                        # noqa: E402


@pytest.fixture(autouse=True)
def uncached():
    """`running_version` is cached for the life of a process — one read per
    hook invocation is the point. Tests move the manifest, so they clear it."""
    version.running_version.cache_clear()
    yield
    version.running_version.cache_clear()


def at(tmp_path, monkeypatch, payload):
    manifest = tmp_path / "INSTALL.json"
    if payload is not None:
        manifest.write_text(payload, encoding="utf-8")
    monkeypatch.setattr(version, "manifest_path", lambda: manifest)
    return manifest


# ------------------------------------------------------- 1 · what it resolves

def test_the_installed_version_is_read_from_the_manifest_beside_the_code(
        tmp_path, monkeypatch):
    at(tmp_path, monkeypatch, json.dumps({"guard_version": "v9-test"}))
    assert version.running_version() == "v9-test"


def test_a_checkout_with_no_install_says_uninstalled_rather_than_guessing(
        tmp_path, monkeypatch):
    """⚠ AND IT DOES NOT FALL BACK TO `git describe`. Not for tidiness — for a
    budget. This runs on the hook path, where a subprocess spawn is ~10 ms
    against a 12 ms p99 and A6b-ii caps git spawns at two per verdict for
    probes that must exist. A cheap wrong identifier is the defect this whole
    module fixes."""
    at(tmp_path, monkeypatch, None)
    assert version.running_version() == version.UNINSTALLED


def test_an_unreadable_manifest_is_unknown_and_not_uninstalled(tmp_path,
                                                                monkeypatch):
    """Two different situations lead two different places: "not installed" is
    ordinary, "installed and the manifest is broken" is someone's afternoon."""
    at(tmp_path, monkeypatch, "{not json")
    assert version.running_version() == version.UNKNOWN


def test_it_names_the_code_that_is_running_not_the_code_that_is_installed_now(
        tmp_path, monkeypatch):
    """⚠ THE MID-REINSTALL CASE, WHICH IS THE ONE THAT MATTERS.

    `installer.place.installed_version()` reads `…/sting/current`, which is what
    is installed AT THIS MOMENT. During a reinstall the process still executing
    is the previous copy, and the honest answer to "what decided this record" is
    the version of the bytes that ran — resolved relative to this module's own
    location, so it cannot be changed underneath a running process by a symlink
    being repointed.
    """
    source = Path(version.__file__).resolve()
    assert version.manifest_path() == source.parent.parent / "INSTALL.json"
    assert "current" not in str(version.manifest_path())


def test_it_never_raises_whatever_is_there(tmp_path, monkeypatch):
    at(tmp_path, monkeypatch, json.dumps([1, 2, 3]))
    assert version.running_version() in (version.UNKNOWN, version.UNINSTALLED)


# ------------------------------------------------------ 2 · it is in the record

def test_every_record_carries_the_deciding_version(tmp_path, monkeypatch):
    at(tmp_path, monkeypatch, json.dumps({"guard_version": "v9-test"}))
    body = audit_log.build_body("s1", seq=1, event="decision", decision="ALLOW")
    assert body["guard_version"] == "v9-test"


def test_a_caller_may_state_the_version_that_applied_then(tmp_path, monkeypatch):
    """A record rebuilt from history must not be stamped with today's policy."""
    at(tmp_path, monkeypatch, json.dumps({"guard_version": "v9-test"}))
    body = audit_log.build_body("s1", seq=1, event="decision", decision="ALLOW",
                                 guard_version="v1-ancient")
    assert body["guard_version"] == "v1-ancient"


def test_the_version_is_inside_the_hashed_body(tmp_path, monkeypatch):
    """⚠ AN ATTRIBUTION THAT CAN BE EDITED AFTERWARDS ATTRIBUTES NOTHING.

    Same argument as `agent`, `cwd` and `workspace_roots`: a field a reader
    trusts must be one the chain covers, or a log can be made to blame a policy
    that never ran.
    """
    body = audit_log.build_body("s1", seq=1, event="decision", decision="ALLOW",
                                 guard_version="v1")
    honest = audit_log.record_hash(audit_log.GENESIS, body)
    tampered = audit_log.record_hash(audit_log.GENESIS,
                                      dict(body, guard_version="v2"))
    assert honest != tampered


# -------------------------------------------------------- 3 · it survives the wire

def test_the_version_reaches_a_collector_unmasked():
    """⚠ "WHICH RULES WERE THESE?" HAS TO BE ANSWERABLE FROM EVERY RECORD. It is
    in the spine: every record ships it, and masking never reads it, whatever a
    version string happens to look like."""
    from shipper import mask
    body = audit_log.build_body("s1", seq=1, event="decision", decision="DENY",
                                 command="git push --password=hunter2-horse",
                                 reason="because", guard_version="v9-test")
    shipped = mask.mask_record(body)
    assert shipped["guard_version"] == "v9-test"
    assert "guard_version" in wire.UNMASKED and "hunter2-horse" not in shipped["command"]


def test_it_is_a_different_field_from_the_one_that_names_the_sender():
    """Two facts, two fields, never one field that means whichever the reader
    assumes. `manifest.guard_ref` answers "which build packed this batch";
    `record.guard_version` answers "which policy decided this verdict". They
    differ the moment anything is installed — which is always, in production."""
    body = audit_log.build_body("s1", seq=1, event="decision", decision="ALLOW",
                                 guard_version="v-decided")
    from shipper import mask
    batch = wire.build_batch([body], device_id="d1", session_id="s1",
                              mask=mask.mask_record,
                              fingerprint=wire.fingerprinter(bytes(range(32))))
    assert batch["records"][0]["guard_version"] == "v-decided"
    assert batch["manifest"]["guard_ref"] != "v-decided", (
        "the sender's describe and the deciding version are the same string "
        "here, so this test cannot tell the two fields apart")
    assert "guard_version" not in batch["manifest"], (
        "a session-level union of deciding versions would have to be taught to "
        "the collector — see the stop condition recorded in PROGRESS.md")


def test_the_docstring_no_longer_claims_guard_ref_ties_a_verdict_to_a_policy():
    """The false claim is the reason a reader trusted the wrong field."""
    doc = " ".join((wire.guard_ref.__doc__ or "").split())
    assert "Not the one that decided anything" in doc
