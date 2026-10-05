"""RealSpartaDetector without weights: lazy loading, the files it picks, batching, the intent guard.

The ONNX session and the tokenizer are replaced by fakes (sparta.detector opens both through two module-level
functions), so these tests run anywhere; tests/test_detector_real.py runs the real files when they are present.
"""

import subprocess
import sys
import threading
import time
from pathlib import Path

import numpy as np
import pytest
from detector_fakes import CLS, PAD, SURE, FakeSession, FakeTokenizer, install, make_files, tag_chars

import sparta.detector as det
from sparta.detector import RealSpartaDetector, SpartaModelMissing, intent_files, machine, secrets_files
from sparta.spans import CONFIDENCE_THRESHOLD, LABELS, Span

ROOT = Path(__file__).resolve().parent.parent
tag_digits = tag_chars({d: "SECRET" for d in "0123456789"})     # every digit SECRET, one span per run


@pytest.fixture
def models(tmp_path):
    """A models folder holding (empty) secrets files for this machine; the fakes never read them."""
    make_files(secrets_files(tmp_path))
    return tmp_path


def add_intent(models: Path) -> None:
    make_files(intent_files(models))


@pytest.fixture
def opened(monkeypatch):
    """Replace the two openers; record what was opened. `log.tagger` gives the tags session's logits."""
    return install(monkeypatch, tag_digits)


# ---------------------------------------------------------------------------------------------- import and load


def test_importing_the_detector_loads_no_runtime():
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import sparta.detector; "
            "print(sorted(m for m in ('onnxruntime', 'tokenizers', 'transformers', 'torch') if m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code, str(ROOT)], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_constructing_opens_nothing(models, opened):
    d = RealSpartaDetector(models)
    assert not d.loaded
    assert opened.sessions == [] and opened.tokenizers == []


def test_the_first_detect_loads_once(models, opened):
    d = RealSpartaDetector(models)
    d.detect("pin 1234")
    d.detect("pin 5678")
    assert d.loaded
    assert [p for p, _, _ in opened.sessions] == [secrets_files(models).onnx]
    assert opened.tokenizers == [(secrets_files(models).tokenizer, None)]


def test_load_opens_the_model_before_any_detect(models, opened):
    d = RealSpartaDetector(models)
    d.load()
    assert d.loaded and len(opened.sessions) == 1
    d.detect("pin 1234")
    assert len(opened.sessions) == 1


def test_concurrent_first_calls_load_once(models, opened, monkeypatch):
    slow = det._open_session

    def slow_open(path, threads):
        time.sleep(0.05)
        return slow(path, threads)

    monkeypatch.setattr(det, "_open_session", slow_open)
    d = RealSpartaDetector(models)
    results, start = [], threading.Barrier(8)

    def call():
        start.wait()
        results.append(d.detect("code 42"))

    threads = [threading.Thread(target=call) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(opened.sessions) == 1
    assert all(r == results[0] for r in results) and len(results) == 8


def test_missing_weights_fail_on_use_and_name_the_files(tmp_path, opened):
    d = RealSpartaDetector(tmp_path)                 # constructing still works
    with pytest.raises(SpartaModelMissing, match="model.onnx") as err:
        d.detect("pin 1234")
    assert isinstance(err.value, FileNotFoundError)
    assert str(secrets_files(tmp_path).onnx) in str(err.value)
    assert opened.sessions == []


def test_a_tokenizer_without_the_students_special_tokens_is_refused(models, monkeypatch):
    class NoSep(FakeTokenizer):
        def token_to_id(self, token):
            return None if token == "[SEP]" else super().token_to_id(token)

    monkeypatch.setattr(det, "_open_tokenizer", lambda path, truncation=None: NoSep())
    monkeypatch.setattr(det, "_open_session", lambda path, threads: FakeSession())
    with pytest.raises(ValueError, match=r"\[SEP\]"):
        RealSpartaDetector(models).load()


def test_a_file_with_the_wrong_number_of_labels_is_refused(models, monkeypatch):
    monkeypatch.setattr(det, "_open_tokenizer", lambda path, truncation=None: FakeTokenizer())
    monkeypatch.setattr(det, "_open_session", lambda path, threads: FakeSession(n_labels=5))
    with pytest.raises(ValueError, match="13"):
        RealSpartaDetector(models).load()


def test_a_file_without_tag_logits_is_refused(models, monkeypatch):
    monkeypatch.setattr(det, "_open_tokenizer", lambda path, truncation=None: FakeTokenizer())
    monkeypatch.setattr(det, "_open_session", lambda path, threads: FakeSession(output="intent_logits"))
    with pytest.raises(ValueError, match="tag_logits"):
        RealSpartaDetector(models).load()


# ---------------------------------------------------------------------------------------------- files and threads


def test_each_machine_gets_its_measured_file(tmp_path):
    assert secrets_files(tmp_path, "mac").onnx == tmp_path / "sparta-secrets" / "tags-fp16" / "model.onnx"
    assert secrets_files(tmp_path, "x86").onnx == tmp_path / "sparta-secrets" / "tags-int8-dynamic-keepmlp" / "model.onnx"
    assert intent_files(tmp_path, "mac").onnx == tmp_path / "sparta-intent" / "intent-fp16" / "model.onnx"
    assert intent_files(tmp_path, "x86").onnx == tmp_path / "sparta-intent" / "intent-int8-dynamic-keepmlp" / "model.onnx"
    assert secrets_files(tmp_path, "mac").tokenizer == tmp_path / "sparta-secrets" / "tokenizer.json"


def test_machine_is_mac_on_darwin_and_x86_elsewhere(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert machine() == "mac"
    monkeypatch.setattr(sys, "platform", "linux")
    assert machine() == "x86"
    monkeypatch.setattr(sys, "platform", "win32")
    assert machine() == "x86"


def test_an_unknown_machine_is_refused(tmp_path):
    with pytest.raises(ValueError, match="arm"):
        secrets_files(tmp_path, "arm")


def test_threads_default_per_machine_and_can_be_set(models, opened, monkeypatch):
    RealSpartaDetector(models, threads=3).load()
    assert opened.sessions[-1][1] == 3
    RealSpartaDetector(models).load()
    assert opened.sessions[-1][1] == det.default_threads()
    monkeypatch.setattr(sys, "platform", "darwin")
    assert det.default_threads() == 4
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(det.os, "cpu_count", lambda: 32)
    assert det.default_threads() == 8
    monkeypatch.setattr(det.os, "cpu_count", lambda: 2)
    assert det.default_threads() == 2


# ---------------------------------------------------------------------------------------------- detect


def test_detect_returns_character_spans(models, opened):
    text = "pin 1234 and 56"
    assert RealSpartaDetector(models).detect(text) == [
        Span("SECRET", 4, 8, pytest.approx(SURE)), Span("SECRET", 13, 15, pytest.approx(SURE))]


def test_detect_on_nothing_returns_nothing_without_loading(models, opened):
    d = RealSpartaDetector(models)
    assert d.detect("") == []
    assert not d.loaded


def test_detect_refuses_what_is_not_text(models, opened):
    with pytest.raises(TypeError, match="str"):
        RealSpartaDetector(models).detect(b"pin 1234")


def test_a_long_text_runs_in_batches_with_padding_masked(models, opened):
    rng = np.random.default_rng(0)
    text = "".join(rng.choice(list("abc ")) for _ in range(4000))
    text = text[:1000] + "77777" + text[1005:3990] + "8888888888"
    spans = RealSpartaDetector(models).detect(text)
    assert spans == [Span("SECRET", 1000, 1005, pytest.approx(SURE)), Span("SECRET", 3990, 4000, pytest.approx(SURE))]
    feeds = opened.sessions[0][2].feeds
    n_windows = sum(len(f["input_ids"]) for f in feeds)
    assert n_windows == 43                              # 126 content tokens a window, 94 apart
    assert [len(f["input_ids"]) for f in feeds] == [min(det.MAX_BATCH, n_windows - k)
                                                    for k in range(0, n_windows, det.MAX_BATCH)]
    assert len(feeds) > 1
    for f in feeds:
        ids, mask = f["input_ids"], f["attention_mask"]
        assert ids.dtype == np.int64 and mask.dtype == np.int64 and ids.shape == mask.shape
        assert ids.shape[1] <= 128
        assert np.all(ids[:, 0] == CLS)
        assert np.all((ids == PAD) == (mask == 0))      # every pad is masked, nothing else is


def test_spans_under_the_threshold_are_not_returned(models, opened):
    weak = CONFIDENCE_THRESHOLD / 2

    def weak_logits(ids):
        lg = tag_digits(ids)
        digit = (ids >= ord("0")) & (ids <= ord("9"))
        p = np.full(lg.shape, (1 - weak) / (len(LABELS) - 2))
        p[..., LABELS.index("B-SECRET")] = weak
        p[..., LABELS.index("I-SECRET")] = 1e-9
        return np.where(digit[..., None], np.log(p), lg).astype(np.float32)

    opened.tagger = weak_logits
    assert RealSpartaDetector(models).detect("pin 1234") == []


# ---------------------------------------------------------------------------------------------- intent


def test_intent_is_off_by_default_even_with_its_files_present(models, opened):
    add_intent(models)
    d = RealSpartaDetector(models)
    d.load()
    assert d.intent_score("Fix the login test", "Bash: pytest -q") is None
    assert not d.has_intent
    assert all("intent" not in p.parent.name for p, _, _ in opened.sessions)


def test_intent_asked_for_but_absent_gives_none_and_secrets_still_work(models, opened):
    d = RealSpartaDetector(models, intent=True)
    d.load()
    assert d.intent_score("Fix the login test", "Bash: pytest -q") is None
    assert not d.has_intent
    assert d.detect("pin 1234") == [Span("SECRET", 4, 8, pytest.approx(SURE))]


def test_intent_present_and_asked_for_gives_p_fits(models, opened):
    add_intent(models)
    d = RealSpartaDetector(models, intent=True)
    assert opened.sessions == []
    assert d.intent_score("Fix the login test", "Bash: pytest -q") == pytest.approx(0.75)
    assert d.has_intent
    (path, _, sess), = [s for s in opened.sessions if "intent" in s[0].parent.name]
    assert path == intent_files(models).onnx
    assert (intent_files(models).tokenizer, det.INTENT_TOKENS) in opened.tokenizers
    (feed,) = sess.feeds
    assert feed["input_ids"].shape == (1, len("Fix the login test") + len("Bash: pytest -q") + 3)


def test_intent_loads_lazily_and_load_opens_both_when_asked_for(models, opened):
    add_intent(models)
    d = RealSpartaDetector(models, intent=True)
    d.detect("pin 1234")
    assert len(opened.sessions) == 1                    # secrets only: intent waits for its first score
    d.intent_score("a", "b")
    assert len(opened.sessions) == 2
    e = RealSpartaDetector(models, intent=True)
    before = len(opened.sessions)
    e.load()
    assert len(opened.sessions) == before + 2


def test_intent_refuses_what_is_not_text(models, opened):
    add_intent(models)
    with pytest.raises(TypeError, match="str"):
        RealSpartaDetector(models, intent=True).intent_score("task", None)
