"""RealSpartaDetector's post-processing, on synthetic logits: no model weights, no tokenizer.

Logits are built from chosen probabilities (log p), so the softmax gives those probabilities back and every
confidence below is known exactly.
"""

import random

import numpy as np
import pytest

from sparta.spans import (CONFIDENCE_THRESHOLD, LABELS, TYPES, WINDOW_OVERLAP, WINDOW_TOKENS, Span, decode_window,
                          drop_low, merge_spans, spans_from_windows, token_windows)
from sparta.tagging import TYPES4, decode, labels_for
from sparta.windows import windows

CLS, SEP = 50281, 50282
TINY = 1e-9


def row(label: str, p: float = 0.9, also: dict | None = None) -> np.ndarray:
    """One token's logits: `label` gets probability `p` and `also` {label: p} theirs; `label`'s B/I sibling gets
    (almost) nothing unless `also` names it, so the type's probability is `p` plus what `also` gives it; what is
    left is spread evenly over the other labels (`label` stays the argmax for any p above about 0.08)."""
    probs = {label: p, **(also or {})}
    typ = label.split("-")[-1]
    probs.update({lab: TINY for lab in LABELS if lab not in probs and lab != "O" and lab.split("-")[1] == typ})
    rest = [lab for lab in LABELS if lab not in probs]
    share = (1.0 - sum(probs.values())) / len(rest)
    return np.log(np.array([probs.get(lab, share) for lab in LABELS]))


def logits(*rows: np.ndarray) -> np.ndarray:
    return np.stack(rows)


# ---------------------------------------------------------------------------------------------- labels


def test_labels_are_the_students_thirteen_in_training_order():
    assert LABELS == tuple(labels_for(TYPES4))
    assert len(LABELS) == 13
    assert TYPES == ("SECRET", "NAME", "EMAIL", "PHONE", "ID", "ADDRESS")


def test_span_is_immutable_with_the_four_contract_fields():
    s = Span("SECRET", 0, 4, 0.9)
    assert (s.type, s.start, s.end, s.confidence) == ("SECRET", 0, 4, 0.9)
    with pytest.raises(AttributeError):
        s.start = 1


# ---------------------------------------------------------------------------------------------- windows


class CharTokenizer:
    """One token per character: enough to drive sparta.windows (the measured windowing) without a model."""
    cls_token_id, sep_token_id = CLS, SEP

    def __call__(self, texts, add_special_tokens, return_offsets_mapping):
        return {"input_ids": [[ord(c) for c in t] for t in texts],
                "offset_mapping": [[(i, i + 1) for i in range(len(t))] for t in texts]}


@pytest.mark.parametrize("n", [1, 5, 125, 126, 127, 220, 221, 500, 1000])
def test_windows_are_the_measured_windows(n):
    text = "".join(random.Random(n).choice("ab c") for _ in range(n))
    ids, offs = [ord(c) for c in text], [(i, i + 1) for i in range(n)]
    assert token_windows(ids, offs, CLS, SEP) == windows(CharTokenizer(), text, WINDOW_TOKENS, WINDOW_OVERLAP)


def test_windows_cover_every_token_and_overlap_by_32():
    n = 400
    wins = token_windows(list(range(n)), [(i, i + 1) for i in range(n)], CLS, SEP)
    assert all(len(ids) <= WINDOW_TOKENS and ids[0] == CLS and ids[-1] == SEP for ids, _ in wins)
    assert all(offs[0] == (0, 0) and offs[-1] == (0, 0) for _, offs in wins)
    covered = {o for _, offs in wins for o in offs[1:-1]}
    assert covered == {(i, i + 1) for i in range(n)}
    first, second = wins[0][0][1:-1], wins[1][0][1:-1]
    assert first[-WINDOW_OVERLAP:] == second[:WINDOW_OVERLAP]


def test_no_tokens_means_no_windows():
    assert token_windows([], [], CLS, SEP) == []


def test_windows_refuse_an_overlap_as_wide_as_a_window_and_ids_without_offsets():
    with pytest.raises(ValueError, match="overlap"):
        token_windows([1, 2], [(0, 1), (1, 2)], CLS, SEP, max_len=10, overlap=8)
    with pytest.raises(ValueError, match="offsets"):
        token_windows([1, 2], [(0, 1)], CLS, SEP)


# ---------------------------------------------------------------------------------------------- decoding


def test_decode_maps_tokens_to_character_spans_and_trims_leading_space():
    text = "key sk_abc and Dana Levi"
    #       012345678901234567890123
    offs = [(0, 3), (3, 6), (6, 10), (10, 14), (14, 19), (19, 24)]   # byte-level BPE: a token holds its space
    lg = logits(row("O"), row("B-SECRET", 0.8), row("I-SECRET", 0.6), row("O"), row("B-NAME", 0.9),
                row("I-NAME", 0.7))
    spans = decode_window(lg, offs, text)
    assert [(s.type, s.start, s.end) for s in spans] == [("SECRET", 4, 10), ("NAME", 15, 24)]
    assert [text[s.start:s.end] for s in spans] == ["sk_abc", "Dana Levi"]


def test_confidence_is_the_mean_probability_of_the_spans_type_over_its_tokens():
    text = "abcdef"
    offs = [(0, 2), (2, 4), (4, 6)]
    # token 1: B-SECRET 0.5 + I-SECRET 0.2 -> 0.7; token 2: I-SECRET 0.6 + B-SECRET 0.3 -> 0.9; token 3: O
    lg = logits(row("B-SECRET", 0.5, {"I-SECRET": 0.2}), row("I-SECRET", 0.6, {"B-SECRET": 0.3}), row("O"))
    (span,) = decode_window(lg, offs, text)
    assert (span.type, span.start, span.end) == ("SECRET", 0, 4)
    assert span.confidence == pytest.approx((0.7 + 0.9) / 2)


def test_special_tokens_are_skipped_without_breaking_a_span():
    text = "abcdef"
    offs = [(0, 0), (0, 3), (0, 0), (3, 6), (0, 0)]
    lg = logits(row("O"), row("B-ID"), row("B-NAME"), row("I-ID"), row("O"))
    assert [(s.type, s.start, s.end) for s in decode_window(lg, offs, text)] == [("ID", 0, 6)]


def test_an_i_label_of_another_type_or_with_no_open_span_starts_a_span():
    text = "aabbccdd"
    offs = [(0, 2), (2, 4), (4, 6), (6, 8)]
    lg = logits(row("I-EMAIL"), row("I-PHONE"), row("O"), row("I-PHONE"))
    assert [(s.type, s.start, s.end) for s in decode_window(lg, offs, text)] == [
        ("EMAIL", 0, 2), ("PHONE", 2, 4), ("PHONE", 6, 8)]


def test_a_span_of_whitespace_only_is_dropped():
    text = "a   b"
    offs = [(0, 1), (1, 4), (4, 5)]
    lg = logits(row("O"), row("B-ADDRESS"), row("O"))
    assert decode_window(lg, offs, text) == []


def test_fp16_logits_are_accepted():
    text = "abcd"
    lg = logits(row("B-SECRET"), row("I-SECRET")).astype(np.float16)
    (span,) = decode_window(lg, [(0, 2), (2, 4)], text)
    assert (span.type, span.start, span.end) == ("SECRET", 0, 4)
    assert 0.0 <= span.confidence <= 1.0


def test_logits_and_offsets_of_different_lengths_are_refused():
    with pytest.raises(ValueError, match="2 offsets"):
        decode_window(logits(row("O")), [(0, 1), (1, 2)], "ab")


@pytest.mark.parametrize("seed", range(40))
def test_decode_matches_the_measured_decoder_on_random_labels(seed):
    """Span edges are exactly sparta.tagging.decode's (what EVAL-005 measured); only the confidence is new."""
    rng = random.Random(seed)
    text = "".join(rng.choice("ab  c\n") for _ in range(120))
    offs, pos = [(0, 0)], 0
    while pos < len(text):
        step = rng.randint(1, 4)
        offs.append((pos, min(len(text), pos + step)))
        pos += step
    offs.append((0, 0))
    label_ids = [rng.randrange(len(LABELS)) for _ in offs]
    lg = logits(*[row(LABELS[i]) for i in label_ids])
    got = [(s.start, s.end, s.type) for s in decode_window(lg, offs, text)]
    want = [(s["start"], s["end"], s["label"]) for s in decode(offs, label_ids, text, list(LABELS))]
    assert got == want


# ---------------------------------------------------------------------------------------------- merging


def test_overlapping_spans_of_one_type_merge_into_their_union_with_the_highest_confidence():
    merged = merge_spans([Span("SECRET", 10, 30, 0.95), Span("SECRET", 20, 40, 0.3)])
    assert merged == [Span("SECRET", 10, 40, 0.95)]


def test_touching_spans_of_one_type_merge():
    assert merge_spans([Span("SECRET", 5, 9, 0.6), Span("SECRET", 0, 5, 0.8)]) == [Span("SECRET", 0, 9, 0.8)]


def test_spans_apart_or_of_different_types_stay_apart_sorted_by_position():
    spans = [Span("NAME", 20, 30, 0.9), Span("SECRET", 0, 5, 0.9), Span("SECRET", 6, 9, 0.9),
             Span("EMAIL", 3, 8, 0.9)]
    assert merge_spans(spans) == [Span("SECRET", 0, 5, 0.9), Span("EMAIL", 3, 8, 0.9), Span("SECRET", 6, 9, 0.9),
                                  Span("NAME", 20, 30, 0.9)]


def test_a_chain_of_overlaps_merges_into_one():
    spans = [Span("ID", 0, 4, 0.5), Span("ID", 3, 8, 0.7), Span("ID", 8, 12, 0.6), Span("ID", 11, 15, 0.2)]
    assert merge_spans(spans) == [Span("ID", 0, 15, 0.7)]


def test_merging_does_not_change_its_input():
    spans = [Span("SECRET", 0, 5, 0.8), Span("SECRET", 4, 9, 0.6)]
    before = list(spans)
    merge_spans(spans)
    assert spans == before


# ---------------------------------------------------------------------------------------------- threshold


def test_spans_under_the_threshold_are_dropped_and_the_threshold_itself_is_kept():
    spans = [Span("SECRET", 0, 4, CONFIDENCE_THRESHOLD - 1e-9), Span("NAME", 5, 9, CONFIDENCE_THRESHOLD),
             Span("EMAIL", 10, 20, 0.99)]
    assert drop_low(spans) == spans[1:]


def test_the_threshold_is_a_probability():
    assert 0.0 < CONFIDENCE_THRESHOLD < 1.0


# ---------------------------------------------------------------------------------------------- whole path


def char_windows(text: str) -> list:
    return token_windows([ord(c) for c in text], [(i, i + 1) for i in range(len(text))], CLS, SEP)


def window_logits(wins: list, text: str, gold: list[tuple[str, int, int, float]]) -> list[np.ndarray]:
    """Per window, logits that tag each character of a gold (type, start, end, p) span."""
    out = []
    for ids, offs in wins:
        rows = []
        for a, b in offs:
            hit = next(((t, s, p) for t, s, e, p in gold if b > a and s <= a < e), None)
            rows.append(row("O") if hit is None else row(("B-" if a == hit[1] else "I-") + hit[0], hit[2]))
        out.append(logits(*rows))
    return out


def test_a_span_in_a_later_window_maps_to_its_place_in_the_whole_text():
    text = "x" * 300
    gold = [("SECRET", 250, 270, 0.9)]
    wins = char_windows(text)
    assert len(wins) == 3                               # characters 0-126, 94-220, 188-300
    assert spans_from_windows(wins, window_logits(wins, text, gold), text) == [
        Span("SECRET", 250, 270, pytest.approx(0.9))]


def test_a_span_seen_by_two_overlapping_windows_comes_out_once():
    text = "y" * 300
    wins = char_windows(text)
    first_end = wins[0][1][-2][1]                       # the last character of window 1
    gold = [("NAME", first_end - 10, first_end, 0.9)]   # inside the 32-token overlap: windows 1 and 2 both see it
    assert sum(any(b > a and gold[0][1] <= a < gold[0][2] for a, b in offs) for _, offs in wins) == 2
    assert spans_from_windows(wins, window_logits(wins, text, gold), text) == [
        Span("NAME", first_end - 10, first_end, pytest.approx(0.9))]


def test_a_span_cut_by_a_window_edge_is_joined_with_the_next_windows_part():
    text = "z" * 300
    wins = char_windows(text)
    end_1 = wins[0][1][-2][1]
    # the window that holds the whole span is weak about it, the one that ends inside it is sure:
    # merged, the span is whole and keeps the sure window's confidence
    lg = window_logits(wins, text, [("SECRET", end_1 - 5, end_1 + 10, 0.3)])
    lg[0] = window_logits(wins[:1], text, [("SECRET", end_1 - 5, end_1 + 10, 0.95)])[0]
    assert spans_from_windows(wins, lg, text) == [Span("SECRET", end_1 - 5, end_1 + 10, pytest.approx(0.95))]


def test_padding_rows_past_a_windows_tokens_are_ignored():
    text = "abcdef"
    wins = char_windows(text)
    (lg,) = window_logits(wins, text, [("PHONE", 0, 6, 0.9)])
    padded = np.concatenate([lg, logits(row("B-SECRET"), row("I-SECRET"))])      # 2 pad positions, tagged
    assert spans_from_windows(wins, [padded], text) == [Span("PHONE", 0, 6, pytest.approx(0.9))]


def test_weak_spans_are_dropped_after_merging():
    text = "q" * 50
    wins = char_windows(text)
    lg = window_logits(wins, text, [("SECRET", 0, 10, 0.9), ("NAME", 20, 30, 0.2)])
    assert spans_from_windows(wins, lg, text) == [Span("SECRET", 0, 10, pytest.approx(0.9))]


def test_window_and_logit_counts_must_agree():
    text = "abc"
    with pytest.raises(ValueError, match="1 windows"):
        spans_from_windows(char_windows(text), [], text)


def test_every_span_lies_inside_the_text_with_a_known_type():
    rng = random.Random(7)
    text = "".join(rng.choice("abc \n") for _ in range(700))
    wins = char_windows(text)
    lg = [logits(*[row(rng.choice(LABELS), 0.9) for _ in ids]) for ids, _ in wins]
    spans = spans_from_windows(wins, lg, text)
    assert spans
    assert all(s.type in TYPES and 0 <= s.start < s.end <= len(text) for s in spans)
    assert all(CONFIDENCE_THRESHOLD <= s.confidence <= 1.0 for s in spans)
    assert spans == sorted(spans, key=lambda s: (s.start, s.end, s.type))
