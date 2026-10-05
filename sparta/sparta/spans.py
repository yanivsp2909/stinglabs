"""The secrets student's token predictions as character spans: RealSpartaDetector's post-processing, no model.

The steps are the decode EVAL-005 measured (its evaluation code, not in this repository), with a confidence added:

1. windows: the text is tokenised once and cut into windows of 126 tokens + [CLS] + [SEP], 32 overlapping
   (sparta.windows); offsets are the tokenizer's, so every window's spans are already in the text's characters;
2. per window: the argmax label of each token, decoded BIO to character spans exactly as sparta.tagging.decode
   does (span edges trimmed of whitespace). A span's confidence is the mean, over its tokens, of the probability
   of its type (its B- and I- labels together);
3. merge: spans of one type that overlap or touch become one span, whose confidence is the highest of its parts:
   a span is kept if any window that saw it was sure of it. (EVAL-005's merge joined overlaps only.)
4. drop: spans under CONFIDENCE_THRESHOLD.

Only numpy and sparta's pure-Python helpers are imported, so this module loads no model and no runtime.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .candidates import plain
from .tagging import TYPES4, labels_for

TYPES = TYPES4                          # SECRET, NAME, EMAIL, PHONE, ID, ADDRESS: the student's six
LABELS = tuple(labels_for(TYPES))       # O, then B-/I- of each type: the student's 13 outputs, in order
WINDOW_TOKENS = 128                     # a window, [CLS] and [SEP] included (what EVAL-005 measured)
WINDOW_OVERLAP = 32                     # tokens two neighbouring windows share
# A span is returned only when its type is more likely than not. Not tuned: EVAL-005/006 measured the argmax
# decode with no threshold, so what this costs in recall is measured only once the real files are run.
CONFIDENCE_THRESHOLD = 0.5

Offsets = list[tuple[int, int]]
Window = tuple[list[int], Offsets]      # (input ids, character offsets), as sparta.windows builds them


@dataclass(frozen=True)
class Span:
    """A typed character range of the text: text[start:end] is the value, confidence is in [0, 1]."""
    type: str
    start: int
    end: int
    confidence: float


def token_windows(ids: list[int], offsets: Offsets, cls_id: int, sep_id: int, max_len: int = WINDOW_TOKENS,
                  overlap: int = WINDOW_OVERLAP) -> list[Window]:
    """The windows sparta.windows cuts from a text's tokens (no special tokens in `ids`); none for no tokens.
    [CLS] and [SEP] get the offset (0, 0), as the tokenizer gives special tokens."""
    size = max_len - 2
    if not 0 <= overlap < size:
        raise ValueError(f"overlap {overlap} must be below the {size} content tokens of a window")
    if len(ids) != len(offsets):
        raise ValueError(f"{len(ids)} ids but {len(offsets)} offsets")
    if not ids:
        return []
    return [([cls_id] + ids[lo:hi] + [sep_id], [(0, 0)] + offsets[lo:hi] + [(0, 0)])
            for lo, hi in plain(ids, offsets, size, overlap)]


def softmax(logits: np.ndarray) -> np.ndarray:
    z = np.asarray(logits, dtype=np.float64)
    e = np.exp(z - z.max(-1, keepdims=True))
    return e / e.sum(-1, keepdims=True)


# columns of each type's B- and I- labels
_TYPE_COLUMNS = {t: (LABELS.index(f"B-{t}"), LABELS.index(f"I-{t}")) for t in TYPES}


def _pieces(label_ids: np.ndarray, offsets: Offsets) -> list[tuple[str, int, int, tuple]]:
    """(type, start, end, token indices) per BIO span, before trimming: sparta.tagging.decode's rules (a token
    with no characters is skipped without closing a span; an I- with no open span of its type starts one)."""
    pieces: list[tuple[str, int, int, tuple]] = []
    open_ = False
    for i, ((a, b), lid) in enumerate(zip(offsets, label_ids)):
        if b <= a:
            continue
        label = LABELS[lid]
        if label == "O":
            open_ = False
            continue
        bio, typ = label.split("-", 1)
        if open_ and bio == "I" and pieces[-1][0] == typ:
            t, start, _, toks = pieces[-1]
            pieces[-1] = (t, start, b, toks + (i,))
        else:
            pieces.append((typ, a, b, (i,)))
            open_ = True
    return pieces


def _trim(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def decode_window(logits: np.ndarray, offsets: Offsets, text: str) -> list[Span]:
    """Spans of one window from its tag logits [tokens, labels] (pad rows already cut off) and its offsets."""
    logits = np.asarray(logits)
    if logits.ndim != 2 or logits.shape[0] != len(offsets) or logits.shape[1] != len(LABELS):
        raise ValueError(f"logits of shape {logits.shape} for {len(offsets)} offsets and {len(LABELS)} labels")
    probs = softmax(logits)
    spans = []
    for typ, start, end, toks in _pieces(logits.argmax(-1), offsets):
        start, end = _trim(text, start, end)
        if end > start:
            b, i = _TYPE_COLUMNS[typ]
            spans.append(Span(typ, start, end, float(np.mean(probs[list(toks), b] + probs[list(toks), i]))))
    return spans


def merge_spans(spans: list[Span]) -> list[Span]:
    """Spans of one type that overlap or touch, joined; each joined span keeps its parts' highest confidence.
    Sorted by position."""
    merged: list[Span] = []
    for s in sorted(spans, key=lambda s: (s.type, s.start, s.end)):
        last = merged[-1] if merged else None
        if last is not None and last.type == s.type and s.start <= last.end:
            merged[-1] = Span(s.type, last.start, max(last.end, s.end), max(last.confidence, s.confidence))
        else:
            merged.append(s)
    return sorted(merged, key=lambda s: (s.start, s.end, s.type))


def drop_low(spans: list[Span], threshold: float = CONFIDENCE_THRESHOLD) -> list[Span]:
    return [s for s in spans if s.confidence >= threshold]


def spans_from_windows(windows: list[Window], window_logits: list[np.ndarray], text: str) -> list[Span]:
    """The text's spans from every window's tag logits ([tokens, labels], rows past the window's own tokens,
    i.e. padding, are ignored): decoded per window, merged, the weak ones dropped."""
    if len(windows) != len(window_logits):
        raise ValueError(f"{len(windows)} windows but {len(window_logits)} logit arrays")
    spans = [s for (ids, offsets), lg in zip(windows, window_logits)
             for s in decode_window(np.asarray(lg)[:len(ids)], offsets, text)]
    return drop_low(merge_spans(spans))
