"""Fakes for RealSpartaDetector's two openers (sparta.detector._open_session and _open_tokenizer), shared by the
detector's tests and the engine adapter's: a tokenizer of one token per character and an ONNX session that
answers synthetic tag logits. No weights, no tokenizer file, no runtime."""

from pathlib import Path
from types import SimpleNamespace

import numpy as np

import sparta.detector as det
from sparta.spans import LABELS

CLS, SEP, PAD = 50281, 50282, 50283
SPECIALS = {"[CLS]": CLS, "[SEP]": SEP, "[PAD]": PAD}
N_LABELS = len(LABELS)
SURE = 0.99 + 0.01 / (N_LABELS - 1)       # tag_chars' type probability: 0.99 on its B or I, 0.01 shared by the rest


class FakeTokenizer:
    """One token per character (its code point), offsets in characters; a pair is [CLS] a [SEP] b [SEP]."""

    def __init__(self):
        self.truncation = None

    def token_to_id(self, token):
        return SPECIALS.get(token)

    def encode(self, text, pair=None, add_special_tokens=True):
        if pair is None and not add_special_tokens:
            return SimpleNamespace(ids=[ord(c) for c in text], offsets=[(i, i + 1) for i in range(len(text))])
        ids = [CLS] + [ord(c) for c in text] + [SEP] + [ord(c) for c in pair or ""] + [SEP]
        return SimpleNamespace(ids=ids[:self.truncation] if self.truncation else ids, offsets=[])


def tag_chars(types: dict[str, str]):
    """A tagger: tag logits that give each character in `types` its type (B- on the first of a run of one type,
    I- after it), O to every other token; the chosen label gets 0.99, the 12 others 0.01 between them."""
    codes = {ord(c): t for c, t in types.items()}

    def tagger(ids: np.ndarray) -> np.ndarray:
        p = np.full(ids.shape + (N_LABELS,), 0.01 / (N_LABELS - 1))
        for r, row in enumerate(ids):
            prev = None
            for k, tid in enumerate(row):
                typ = codes.get(int(tid))
                label = "O" if typ is None else ("I-" if typ == prev else "B-") + typ
                p[r, k, LABELS.index(label)] = 0.99
                prev = typ
        return np.log(p).astype(np.float32)

    return tagger


class FakeSession:
    """Stands in for onnxruntime.InferenceSession over a tags file (or an intent file)."""

    def __init__(self, output="tag_logits", n_labels=N_LABELS, tagger=None):
        self.output, self.n_labels, self.tagger, self.feeds = output, n_labels, tagger, []

    def get_inputs(self):
        return [SimpleNamespace(name="input_ids"), SimpleNamespace(name="attention_mask")]

    def get_outputs(self):
        shape = ["batch", "seq", self.n_labels] if self.output == "tag_logits" else ["batch", 2]
        return [SimpleNamespace(name=self.output, shape=shape)]

    def run(self, names, feed):
        assert names == [self.output]
        self.feeds.append(feed)
        if self.output == "intent_logits":
            return [np.array([[0.0, np.log(3.0)]] * len(feed["input_ids"]), dtype=np.float32)]   # P(fits) 0.75
        return [self.tagger(feed["input_ids"])]


def make_files(files: det.ModelFiles) -> None:
    """Empty stand-ins for a model's files: the detector only checks they are there; the fakes read nothing."""
    for f in (files.onnx, files.tokenizer):
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"")


def install(monkeypatch, tagger) -> SimpleNamespace:
    """Replace the detector's two openers with the fakes; the log records what was opened, and `log.tagger`
    (`tagger` at first, settable) gives every tags session's logits."""
    log = SimpleNamespace(sessions=[], tokenizers=[], tagger=tagger)

    def open_session(path, threads):
        sess = FakeSession("intent_logits" if "intent" in Path(path).parent.name else "tag_logits",
                           tagger=lambda ids: log.tagger(ids))
        log.sessions.append((Path(path), threads, sess))
        return sess

    def open_tokenizer(path, truncation=None):
        tok = FakeTokenizer()
        tok.truncation = truncation
        log.tokenizers.append((Path(path), truncation))
        return tok

    monkeypatch.setattr(det, "_open_session", open_session)
    monkeypatch.setattr(det, "_open_tokenizer", open_tokenizer)
    return log
