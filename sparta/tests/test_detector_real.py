"""RealSpartaDetector on the shipped files. Skipped unless they are in models/ (git-ignored; download them from the GitHub Release).

    models/sparta-secrets/tokenizer.json
    models/sparta-secrets/tags-int8-dynamic-keepmlp/model.onnx   (x86)
    models/sparta-secrets/tags-fp16/model.onnx                   (Mac)
    models/sparta-intent/…                                       optional

The files must be the ones EVAL-005/006 measured (sha256 pinned below), so the published numbers hold.
"""

import hashlib
import random
from pathlib import Path

import pytest

from sparta import fakes, sting_detector
from sparta.detector import MODELS, RealSpartaDetector, intent_files, machine, secrets_files
from sparta.spans import CONFIDENCE_THRESHOLD, TYPES, Span

SECRETS, INTENT = secrets_files(MODELS), intent_files(MODELS)
# the measured files: the clean 6-layer student's, the intent-only model's, their one tokenizer
PINNED = {
    "tokenizer.json": "9fd55248d51d33976b324fc11592e28071da7d41e0e9401dfb7082e30574b7b1",
    "tags-int8-dynamic-keepmlp": "708f51e89cbf1d6bd497cc63670d0b142d354515a4534e5ba277d8083eba1acc",
    "tags-fp16": "e788ef3159cc6fb8a9f1b58199b657541e460746404bbe7fd384e3f8e625985b",
    "intent-int8-dynamic-keepmlp": "ee81ab440ca847e92798abe52d0777a5acb844f20bc4adfa436a7645f030982f",
    "intent-fp16": "137531ab823db9973519488f901917a0fe413b3204417e3c1e41964ff01476b5",
}

needs_secrets = pytest.mark.skipif(not SECRETS.present(), reason=f"shipped student not in {MODELS} ({machine()} file)")
needs_intent = pytest.mark.skipif(not (SECRETS.present() and INTENT.present()),
                                  reason=f"intent model not in {MODELS} (optional, not shipped)")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


@pytest.fixture(scope="module")
def detector():
    pytest.importorskip("tokenizers")
    pytest.importorskip("onnxruntime")
    return RealSpartaDetector(MODELS)


@needs_secrets
def test_the_secrets_files_are_the_measured_ones():
    assert sha256(SECRETS.tokenizer) == PINNED["tokenizer.json"]
    assert sha256(SECRETS.onnx) == PINNED[SECRETS.onnx.parent.name]


@needs_secrets
def test_a_planted_secret_comes_back_as_a_secret_span(detector):
    token = fakes.github_token(random.Random(0))
    text = f"export GITHUB_TOKEN={token} && ./deploy.sh --prod"
    start = text.index(token)
    spans = detector.detect(text)
    assert detector.loaded
    assert any(s.type == "SECRET" and s.start < start + len(token) and start < s.end for s in spans), spans


@needs_secrets
def test_spans_keep_the_contract_on_a_long_text(detector):
    rng = random.Random(1)
    lines = [f"step {i}: curl -H 'Authorization: Bearer {fakes.secret(rng)[0]}' https://api.example.com/v{i}"
             for i in range(60)]
    text = "\n".join(lines)
    spans = detector.detect(text)
    assert spans
    assert all(isinstance(s, Span) for s in spans)
    assert all(s.type in TYPES and 0 <= s.start < s.end <= len(text) for s in spans)
    assert all(CONFIDENCE_THRESHOLD <= s.confidence <= 1.0 for s in spans)
    assert spans == sorted(spans, key=lambda s: (s.start, s.end, s.type))


@needs_secrets
def test_no_text_no_spans(detector):
    assert detector.detect("") == []
    assert detector.detect("   \n") == []


@needs_secrets
def test_the_engines_door_answers_a_planted_secret_as_secret_at_code_point_offsets():
    pytest.importorskip("tokenizers")
    pytest.importorskip("onnxruntime")
    token = fakes.github_token(random.Random(2))
    text = f"🙂 é שלום: export GITHUB_TOKEN={token} && ./deploy.sh"     # characters before it, of 1 to 4 bytes
    start = text.index(token)
    d = sting_detector.make_detector()
    spans = d.detect(text)
    assert any(s.type == "secret" and s.start < start + len(token) and start < s.end for s in spans), spans
    assert all(s.type in sting_detector.TYPES and 0 <= s.start < s.end <= len(text) for s in spans)
    assert not hasattr(d, "intent")


@needs_intent
def test_the_intent_files_are_the_measured_ones():
    assert sha256(INTENT.tokenizer) == PINNED["tokenizer.json"]
    assert sha256(INTENT.onnx) == PINNED[INTENT.onnx.parent.name]


@needs_intent
def test_intent_gives_a_probability_only_when_asked_for():
    pytest.importorskip("tokenizers")
    task, action = "Fix the login test", "Bash: pytest tests/test_login.py -q"
    assert RealSpartaDetector(MODELS).intent_score(task, action) is None
    score = RealSpartaDetector(MODELS, intent=True).intent_score(task, action)
    assert isinstance(score, float) and 0.0 <= score <= 1.0
