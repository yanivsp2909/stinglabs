"""Sparta's contract, as the engine owns it (shipper/sparta_iface.py), and the
fail-open way the shipper asks it (shipper/sparta_enrich.py `Guarded`).

No model, no network, no sparta package: the real detector's import path is
pointed away from it in every test that turns the flag on, and conftest makes
the package unimportable for the whole suite besides.
"""
from __future__ import annotations

import math
import sys
import threading
import types
from collections.abc import Mapping
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sparta_fixtures as fx                                       # noqa: E402


@pytest.fixture
def iface():
    """Imported per test, so a missing module fails each test on its own line."""
    from shipper import sparta_iface
    return sparta_iface


@pytest.fixture
def enrich():
    from shipper import sparta_enrich
    return sparta_enrich


ON = {"STING_SPARTA": "1"}


# ═══════════════════════════════════════════════════════════ the span

def test_the_span_types_are_six_lower_case_held_once(iface, enrich):
    assert iface.SPAN_TYPES == frozenset(
        {"secret", "name", "email", "phone", "id", "address"})
    assert set(enrich.MARKERS) == set(iface.SPAN_TYPES), "a marker for every type, no other"


def test_an_id_is_masked_with_the_label_the_code_already_ships_for_one(enrich):
    """`id` maps to the deterministic masking's own ID label, read from the
    engine rather than written twice: the code masks an issued SSN and an
    Israeli ID passing its check digit with it."""
    from shipper import mask
    for text in ("SSN 123-45-6789", "ID 123456782"):
        masked, counts = mask.mask_text(text)
        assert masked.endswith(f"[{enrich.MARKERS['id']}]"), masked
        assert dict(counts) == {enrich.MARKERS["id"]: 1}
    assert enrich.MARKERS["id"] == "id-number"


def test_a_span_inside_the_contract_is_made(iface):
    span = iface.Span("name", 3, 9, 0.5)
    assert (span.type, span.start, span.end, span.confidence) == ("name", 3, 9, 0.5)
    assert iface.Span("secret", 0, 1, 1).confidence == 1
    assert iface.Span("id", 3, 12, 0.9).type == "id"


@pytest.mark.parametrize("args", [
    ("person", 0, 4, 0.5),           # not one of the six
    ("NAME", 0, 4, 0.5),             # the types are lower-case
    ("ID", 0, 4, 0.5),
    ("id-number", 0, 4, 0.5),        # a marker is not a type
    ("name", 4, 4, 0.5),             # empty
    ("name", 5, 4, 0.5),             # backwards
    ("name", -1, 4, 0.5),            # before the text
    ("name", True, 4, 0.5),          # a bool is not an offset
    ("name", 0, 4.0, 0.5),           # a float is not an offset
    ("name", 0, 4, 1.5),             # confidence past 1
    ("name", 0, 4, -0.1),
    ("name", 0, 4, math.nan),
    ("name", 0, 4, True),
    ("name", 0, 4, "0.5"),
])
def test_a_span_outside_the_contract_is_refused(iface, args):
    with pytest.raises(ValueError):
        iface.Span(*args)


def test_the_null_detector_finds_nothing(iface):
    assert iface.NULL.detect("Dana Fakeperson at 12 Herzl Street") == []
    assert isinstance(iface.NULL, iface.SpartaDetector)


def test_the_fake_detector_answers_by_pattern_the_same_every_time(iface):
    text = ("call Dana Fakeperson at 12 Herzl Street, +972-54-123-4567, "
            "noa.example@example.invalid, sparta-secret-q7w8e9r0t1, "
            f"ID {fx.ISRAELI_ID}, SSN {fx.SSN_9XX}")
    fake = iface.FakeSpartaDetector()
    first, second = fake.detect(text), fake.detect(text)
    assert first == second
    ids = sorted(text[span.start:span.end] for span in first if span.type == "id")
    assert ids == sorted([fx.ISRAELI_ID, fx.SSN_9XX])
    found = {span.type: text[span.start:span.end] for span in first if span.type != "id"}
    assert found == {"name": "Dana Fakeperson", "address": "12 Herzl Street",
                     "phone": "+972-54-123-4567", "email": "noa.example@example.invalid",
                     "secret": "sparta-secret-q7w8e9r0t1"}
    assert isinstance(fake, iface.SpartaDetector)
    assert fake.intent(text) is None
    assert iface.FakeSpartaDetector(intent_score=0.3).intent(text) == 0.3


def test_the_fake_detector_is_named_nowhere_that_ships_but_its_own_file():
    """⚠ TESTS ONLY. No module outside sparta_iface.py names it, so nothing that
    runs on a laptop can hand a pattern list to the masking as if it were Sparta."""
    shipped = [*ROOT.glob("*.py"), *ROOT.glob("core/*.py"), *ROOT.glob("shipper/*.py"),
               *ROOT.glob("daemon/*.py"), *ROOT.glob("adapters/*.py"),
               *ROOT.glob("installer/*.py"), *ROOT.glob("tools/*.py")]
    assert len(shipped) > 50, "the scan reads the tree"
    naming = sorted(str(p.relative_to(ROOT)) for p in shipped
                    if "FakeSpartaDetector" in p.read_text(encoding="utf-8"))
    assert naming == ["shipper/sparta_iface.py"], naming


# ═══════════════════════════════════════════════════════════ the flags

@pytest.mark.parametrize("value,on", [
    (None, False), ("", False), ("0", False), ("true", False), ("yes", False),
    ("on", False), ("2", False), ("1", True), (" 1 ", True),
])
def test_only_1_turns_sparta_on(iface, value, on):
    environ = {} if value is None else {"STING_SPARTA": value}
    assert iface.enabled(environ) is on
    assert iface.taint_enabled({**environ, "STING_SPARTA_TAINT": "1"}) is on


class _Watched(Mapping):
    """A mapping that remembers which keys were read."""

    def __init__(self, data: dict) -> None:
        self.data, self.read = data, []

    def __getitem__(self, key):
        self.read.append(key)
        return self.data[key]

    def get(self, key, default=None):
        self.read.append(key)
        return self.data.get(key, default)

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)


@pytest.mark.parametrize("sparta,taint,want", [
    ("0", "1", False), (None, "1", False), ("1", "0", False), ("1", None, False),
    ("1", "1", True),
])
def test_the_taint_flag_is_consulted_only_behind_sparta(iface, sparta, taint, want):
    data = {k: v for k, v in (("STING_SPARTA", sparta), ("STING_SPARTA_TAINT", taint))
            if v is not None}
    watched = _Watched(data)
    assert iface.taint_enabled(watched) is want
    assert "STING_SPARTA" in watched.read, "the gate is read"
    if not iface.enabled(data):
        assert "STING_SPARTA_TAINT" not in watched.read


def test_the_defaults_are_off(iface, monkeypatch):
    monkeypatch.delenv("STING_SPARTA", raising=False)
    monkeypatch.delenv("STING_SPARTA_TAINT", raising=False)
    assert not iface.enabled() and not iface.taint_enabled()


def test_the_suite_does_not_inherit_the_flags():
    """conftest clears both, as it clears STING_TIER: a developer with
    STING_SPARTA=1 exported must run the same suite as everyone else."""
    import os
    assert "STING_SPARTA" not in os.environ and "STING_SPARTA_TAINT" not in os.environ


def test_the_real_detector_cannot_be_imported_in_the_suite(iface):
    """⚠ NO MODEL IN A TEST. conftest blocks the real package's name, so a test
    that forgot to point the import away fails instead of loading a model."""
    package = iface.DETECTOR_MODULE.split(".")[0]
    assert sys.modules.get(package, "missing") is None, "blocked by conftest"
    with pytest.raises(ImportError):
        __import__(iface.DETECTOR_MODULE)


# ═══════════════════════════════════════════════════════ getting a detector

def test_with_the_flag_off_get_detector_imports_nothing(iface, monkeypatch):
    def refuse(name, *a, **k):
        raise AssertionError(f"imported {name} with the flag off")
    monkeypatch.setattr(iface.importlib, "import_module", refuse)
    said: list[str] = []
    for environ in ({}, {"STING_SPARTA": "0"}, {"STING_SPARTA": "true"}):
        assert iface.get_detector(environ, log=said.append) is iface.NULL
    assert said == []


def test_get_detector_loads_the_named_factory(iface, monkeypatch):
    """The positive control for the loader: a factory that answers is used."""
    fake = iface.FakeSpartaDetector()
    fx.install_factory(monkeypatch, lambda: fake)
    said: list[str] = []
    assert iface.get_detector(ON, log=said.append) is fake
    assert said == []


def test_a_missing_detector_falls_back_to_null_and_says_so(iface, monkeypatch):
    monkeypatch.setattr(iface, "DETECTOR_MODULE", "sting_no_such_sparta_module")
    said: list[str] = []
    assert iface.get_detector(ON, log=said.append) is iface.NULL
    assert len(said) == 1 and "ModuleNotFoundError" in said[0], said
    assert "deterministic masking only" in said[0]


@pytest.mark.parametrize("factory", [
    lambda: (_ for _ in ()).throw(RuntimeError("no weights")),
    lambda: object(),
    lambda: types.SimpleNamespace(detect="not callable"),
])
def test_a_detector_that_cannot_be_had_falls_back_to_null(iface, monkeypatch, factory):
    fx.install_factory(monkeypatch, factory)
    said: list[str] = []
    assert iface.get_detector(ON, log=said.append) is iface.NULL
    assert len(said) == 1, said
    assert "no weights" not in said[0], "the error's type, never its text"


def test_a_load_that_hangs_falls_back_to_null(iface, monkeypatch):
    release = threading.Event()
    fx.install_factory(monkeypatch, lambda: release.wait(10))
    said: list[str] = []
    try:
        assert iface.get_detector(ON, log=said.append, seconds=0.05) is iface.NULL
    finally:
        release.set()
    assert len(said) == 1 and "within" in said[0], said


# ═══════════════════════════════════════════════════════ asking it, fail-open

class _Scripted:
    """A detector whose every answer the test chooses."""

    def __init__(self, answer=None, *, raises=None, intent=None, block=None):
        self.answer, self.raises, self.score, self.block = answer, raises, intent, block
        self.calls = 0

    def detect(self, text):
        self.calls += 1
        if self.block is not None:
            self.block.wait(10)
        if self.raises is not None:
            raise self.raises
        return self.answer

    def intent(self, text):
        if self.raises is not None:
            raise self.raises
        return self.score


def test_a_detector_that_raises_gives_nothing_and_is_said_once(enrich):
    said: list[str] = []
    detector = _Scripted(raises=ValueError("Dana Fakeperson broke it"))
    guarded = enrich.Guarded(detector, log=said.append)
    assert guarded.spans("one") == () and guarded.spans("two") == ()
    assert guarded.intent("three") is None
    assert detector.calls == 2, "an error does not stop the asking"
    assert len(said) == 1 and "ValueError" in said[0], said
    assert "Dana" not in said[0], "the error's type, never its text"


def test_a_detector_that_hangs_is_given_up_on(enrich):
    said: list[str] = []
    release = threading.Event()
    detector = _Scripted([], block=release)
    guarded = enrich.Guarded(detector, log=said.append, seconds=0.05)
    try:
        assert guarded.spans("one") == ()
        assert guarded.spans("two") == ()
        assert guarded.intent("three") is None
    finally:
        release.set()
    assert detector.calls == 1, "not asked again once it timed out"
    assert len(said) == 1 and "within" in said[0], said


@pytest.mark.parametrize("answer", ["Dana", {"type": "name"}, 7, None])
def test_an_answer_that_is_not_a_list_gives_nothing(enrich, answer):
    said: list[str] = []
    assert enrich.Guarded(_Scripted(answer), log=said.append).spans("Dana x") == ()
    assert len(said) == 1 and "not a list" in said[0], said
    assert "Dana" not in said[0], "the answer's type, never its text"


def test_spans_outside_the_contract_are_dropped_and_the_rest_kept(enrich, iface):
    text = "call Dana Fakeperson now"
    good = iface.Span("name", 5, 20, 0.9)
    duck = types.SimpleNamespace(type="name", start=5, end=9, confidence=0.4)
    answer = [good, duck,
              types.SimpleNamespace(type="name", start=5, end=99, confidence=0.9),
              types.SimpleNamespace(type="person", start=5, end=9, confidence=0.9),
              types.SimpleNamespace(type="name", start=5),
              "Dana"]
    said: list[str] = []
    kept = enrich.Guarded(_Scripted(answer), log=said.append).spans(text)
    assert kept == (good, iface.Span("name", 5, 9, 0.4))
    assert len(said) == 1 and "dropped" in said[0], said


def test_a_models_numeric_types_are_kept_and_shipped_as_plain_numbers(enrich, iface):
    """⚠ A MODEL ANSWERS IN ITS OWN NUMBERS. An ONNX detector's offsets are
    numpy ints and its confidences float32: not `int`, not `float`, and not
    JSON. Kept, as the plain Python numbers they are, never dropped and never
    shipped as a type `json.dumps` refuses (security review)."""
    import json
    np = pytest.importorskip("numpy")
    text = "call Dana Fakeperson now"
    answer = [types.SimpleNamespace(type=np.str_("name"), start=np.int64(5),
                                    end=np.int32(20), confidence=np.float32(0.75))]
    said: list[str] = []
    guarded = enrich.Guarded(_Scripted(answer, intent=np.float32(0.25)), log=said.append)
    (span,) = guarded.spans(text)
    assert span == iface.Span("name", 5, 20, 0.75) and said == []
    assert (type(span.type), type(span.start), type(span.end), type(span.confidence)) \
        == (str, int, int, float)
    assert guarded.intent("curl x") == 0.25
    json.dumps({"start": span.start, "confidence": span.confidence,
                "intent": guarded.intent("curl x")})


def test_a_fraction_is_a_number_too(enrich, iface):
    from fractions import Fraction
    answer = [types.SimpleNamespace(type="name", start=0, end=4, confidence=Fraction(1, 2))]
    (span,) = enrich.Guarded(_Scripted(answer), log=print).spans("Dana")
    assert span == iface.Span("name", 0, 4, 0.5) and type(span.confidence) is float


@pytest.mark.parametrize("score,want", [
    (0.123456, 0.1235), (0, 0.0), (1, 1.0), (None, None),
    (1.5, None), (-0.1, None), (math.nan, None), (True, None), ("0.5", None),
])
def test_an_intent_score_is_kept_only_inside_0_to_1(enrich, score, want):
    said: list[str] = []
    got = enrich.Guarded(_Scripted([], intent=score), log=said.append).intent("curl x")
    assert got == want
    assert len(said) == (1 if want is None and score is not None else 0), said


def test_a_detector_without_intent_gives_no_score(enrich, iface):
    assert enrich.Guarded(iface.NULL, log=print).intent("curl x") is None


# ═════════════════════════════════════════════════ the masking socket

def test_the_model_slot_adds_masks_and_never_removes_one():
    """A model span beside a code span: both masked; on the same span the code
    provider's type names it (`_RANK`); with no model, nothing of the model."""
    from shipper import mask
    text = "mail noa.example@example.invalid about Dana Fakeperson"
    at = text.index("Dana")

    def model(t):
        return [mask.Span("person", at, at + len("Dana Fakeperson"), "model"),
                mask.Span("secret", t.index("noa"), t.index(" about"), "model")]
    masked, counts = mask.mask_text(text, model=model)
    assert masked == "mail [email] about [person]"
    assert counts == {"email": 1, "person": 1}
    plain, _ = mask.mask_text(text)
    assert plain == "mail [email] about Dana Fakeperson"
