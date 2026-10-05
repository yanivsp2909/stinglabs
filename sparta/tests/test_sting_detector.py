"""sparta.sting_detector: the engine's door to Sparta, on synthetic logits (no weights).

The contract is the engine's (engine/shipper/sparta_iface.py, with its six span types):
`import sparta.sting_detector; sparta.sting_detector.make_detector()` with no arguments, then
`detect(text) -> list[Span]`, a span being `type` (one of six lower-case types), `start`, `end` (code-point indices,
0 <= start < end <= len(text)) and `confidence` in [0, 1]. These tests check that shape the way the engine reads it.
"""

import importlib
import inspect
import math
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest
from detector_fakes import SURE, install, make_files, tag_chars

import sparta.sting_detector as sd
from sparta.detector import RealSpartaDetector, SpartaModelMissing, intent_files, secrets_files
from sparta.spans import TYPES

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_TYPES = {"secret", "name", "email", "phone", "id", "address"}
CHAR_TYPES = {"s": "SECRET", "n": "NAME", "e": "EMAIL", "p": "PHONE", "i": "ID", "a": "ADDRESS"}
TEXT = "x sss nn eee pppp ii aaaaa x"        # one run of each type's character


@pytest.fixture
def models(tmp_path, monkeypatch):
    """The adapter's models folder, holding (empty) secrets files; the fakes read nothing."""
    make_files(secrets_files(tmp_path))
    monkeypatch.setattr(sd, "MODELS", tmp_path)
    return tmp_path


@pytest.fixture
def opened(monkeypatch):
    return install(monkeypatch, tag_chars(CHAR_TYPES))


def runs(text: str) -> list[tuple[str, int, int]]:
    """(lower-case type, start, end) of every run of a typed character, by position: what the fake model tags."""
    return [(CHAR_TYPES[m.group()[0]].lower(), m.start(), m.end())
            for m in re.finditer("|".join(f"{c}+" for c in CHAR_TYPES), text)]


def engine_accepts(span, text: str) -> bool:
    """The engine's checks on one answered span (shipper/sparta_iface.Span and sparta_enrich._valid)."""
    def whole(v):
        return isinstance(v, int) and not isinstance(v, bool)
    conf = span.confidence
    return (isinstance(span.type, str) and span.type in CONTRACT_TYPES
            and whole(span.start) and whole(span.end) and 0 <= span.start < span.end <= len(text)
            and isinstance(conf, float) and math.isfinite(conf) and 0.0 <= conf <= 1.0)


# ---------------------------------------------------------------------------------------------- where it is


def test_make_detector_is_where_the_engine_looks_and_takes_no_arguments():
    module = importlib.import_module("sparta.sting_detector")
    assert callable(module.make_detector)
    assert inspect.signature(module.make_detector).parameters == {}


def test_importing_it_loads_no_runtime():
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import sparta.sting_detector; print(sorted(m for m in "
            "('onnxruntime', 'onnx', 'tokenizers', 'transformers', 'torch') if m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code, str(ROOT)], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_the_type_names_are_the_students_six_lower_cased():
    assert set(sd.ENGINE_TYPES) == set(TYPES)
    assert all(v == k.lower() for k, v in sd.ENGINE_TYPES.items())
    assert set(sd.ENGINE_TYPES.values()) == CONTRACT_TYPES


# ---------------------------------------------------------------------------------------------- what it answers


def test_all_six_types_come_back_lower_case_with_offsets_intact(models, opened):
    spans = sd.make_detector().detect(TEXT)
    assert [(s.type, s.start, s.end) for s in spans] == runs(TEXT)
    assert {s.type for s in spans} == CONTRACT_TYPES
    assert [TEXT[s.start:s.end] for s in spans] == ["sss", "nn", "eee", "pppp", "ii", "aaaaa"]
    assert all(s.confidence == pytest.approx(SURE) for s in spans)


def test_only_the_type_changes_and_nothing_is_dropped(models, opened):
    rng = random.Random(3)
    text = "".join(rng.choice("snepiax  \n") for _ in range(3000))     # 32 windows: spans cross window edges
    inner = RealSpartaDetector(models).detect(text)
    outer = sd.make_detector().detect(text)
    assert len(outer) == len(inner) > 100
    assert [(s.type, s.start, s.end, s.confidence) for s in outer] == [
        (s.type.lower(), s.start, s.end, s.confidence) for s in inner]
    assert [(s.type, s.start, s.end) for s in outer] == runs(text)


def test_every_span_passes_the_engines_checks_and_the_answer_is_a_list(models, opened):
    rng = random.Random(4)
    text = "".join(rng.choice("snepiax é🙂\n") for _ in range(1500))
    spans = sd.make_detector().detect(text)
    assert isinstance(spans, list) and spans
    assert all(engine_accepts(s, text) for s in spans)


def test_nothing_found_is_an_empty_list(models, opened):
    d = sd.make_detector()
    assert d.detect("") == []
    assert d.detect("x x x") == []


# ---------------------------------------------------------------------------------------------- loading


def test_make_detector_loads_the_model_so_no_detect_call_waits_for_it(models, opened):
    d = sd.make_detector()
    assert [p for p, _, _ in opened.sessions] == [secrets_files(models).onnx]
    d.detect(TEXT)
    assert len(opened.sessions) == 1


def test_absent_weights_make_make_detector_raise(tmp_path, monkeypatch, opened):
    monkeypatch.setattr(sd, "MODELS", tmp_path)
    with pytest.raises(SpartaModelMissing) as err:
        sd.make_detector()
    assert isinstance(err.value, FileNotFoundError)
    assert opened.sessions == []


# ---------------------------------------------------------------------------------------------- intent


def test_no_intent_is_offered_even_with_its_files_present(models, opened):
    make_files(intent_files(models))
    d = sd.make_detector()
    assert not hasattr(d, "intent")
    assert getattr(d, "intent", None) is None              # how the engine looks for it
    d.detect(TEXT)
    assert all("intent" not in p.parent.name for p, _, _ in opened.sessions)
