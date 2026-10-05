"""The shared chain vector, run through the engine's own chain code.

`tests/vectors/chain-v1.json` holds made-up records whose canonical strings
and digests came from this engine's `audit_log.canonical` / `record_hash` and
`wire.chain_at_tier`. Any independent verifier of the chain (in another
language, say) can check itself against the same file; this suite checks the
engine against it, so neither implementation can drift without one of the
two suites failing.

⚠ THE DIGEST BELOW PINS THE FILE. A change to the canonical form regenerates
the file from the engine, updates this digest, and every other verifier
re-checks against the new bytes.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from core import audit_log, wire

VECTOR = Path(__file__).parent / "vectors" / "chain-v1.json"
VECTOR_SHA256 = "6dc464bd3ed7a9d38e4ecc64969c82c4482433caa1ddb3ea9ee0648cba94afce"
_TIER_FIELDS = ("tier_chain", "tier_prev", "tier_hash")


def _vector() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_the_vector_is_the_pinned_file():
    digest = hashlib.sha256(VECTOR.read_bytes()).hexdigest()
    assert digest == VECTOR_SHA256, (
        "tests/vectors/chain-v1.json changed: every other verifier must "
        "re-check against the new bytes, and this digest must be updated")


def test_each_canonical_string_is_the_engines():
    entries = _vector()["canonical"]
    assert entries
    for number, entry in enumerate(entries, 1):
        assert audit_log.canonical(entry["value"]) == entry["canonical"], number


def test_the_local_chain_is_the_engines():
    chain = _vector()["local_chain"]
    assert chain["genesis"] == audit_log.GENESIS
    prev = chain["genesis"]
    for number, record in enumerate(chain["records"], 1):
        body = {k: v for k, v in record.items() if k not in ("prev", "hash")}
        assert record["prev"] == prev, number
        assert audit_log.record_hash(prev, body) == record["hash"], number
        prev = record["hash"]
    ok, bad, detail = audit_log.verify_records(chain["records"])
    assert ok, (bad, detail)


def test_the_tier_chain_is_the_engines():
    tier = _vector()["tier_chain"]
    unchained = [{k: v for k, v in r.items() if k not in _TIER_FIELDS}
                 for r in tier["records"]]
    assert wire.chain_at_tier(unchained, tier["start"]) == tier["records"]
    assert wire.tier_chain_content(tier["records"], tier["start"], wire.FULL) == (
        "verified", [])


def test_an_edited_record_breaks_both_chains():
    """The vector's digests attest content: one changed byte is caught."""
    vector = _vector()
    local = copy.deepcopy(vector["local_chain"]["records"])
    local[1]["decision"] = "ALLOW"
    assert not audit_log.verify_records(local)[0]
    tier = copy.deepcopy(vector["tier_chain"])
    tier["records"][0]["command"] = "ls"
    assert wire.tier_chain_content(tier["records"], tier["start"], wire.FULL)[0] == "tampered"
