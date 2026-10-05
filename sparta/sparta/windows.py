"""Sliding token windows over a whole text.

The tokenizer's own overflow windowing (`return_overflowing_tokens=True` with a `stride`) is not used:
with tokenizers 0.23.2 and ModernBERT's tokenizer it returns only ONE overflow window, which reaches just
two tokens past the first window, so everything after about one window is silently dropped (EVAL-003
found this; EVAL-002's real-work tagging relied on it). Here the text is tokenised once, the tokens are
cut into windows, and the special tokens are added by hand.
"""

from __future__ import annotations

Window = tuple[list[int], list[tuple[int, int]]]


def windows(tok, text: str, max_len: int, overlap: int) -> list[Window]:
    """[(input_ids, offsets)] covering every token of `text`: windows of `max_len` tokens including
    [CLS] and [SEP], each starting `max_len - 2 - overlap` content tokens after the previous one.
    Special tokens get the offset (0, 0), as the tokenizer gives them."""
    return windows_many(tok, [text], max_len, overlap)[0]


def windows_many(tok, texts: list[str], max_len: int, overlap: int, chunk: int = 512) -> list[list[Window]]:
    """`windows` for many texts, tokenised a chunk at a time by the tokenizer's batch path."""
    size = max_len - 2
    if not 0 <= overlap < size:
        raise ValueError(f"overlap {overlap} must be below the {size} content tokens of a window")
    cls, sep = tok.cls_token_id, tok.sep_token_id
    out = []
    for c in range(0, len(texts), chunk):
        enc = tok(list(texts[c:c + chunk]), add_special_tokens=False, return_offsets_mapping=True)
        for ids, offs in zip(enc["input_ids"], enc["offset_mapping"]):
            offs = [tuple(o) for o in offs]
            wins, start = [], 0
            while True:
                wins.append(([cls] + ids[start:start + size] + [sep], [(0, 0)] + offs[start:start + size] + [(0, 0)]))
                if start + size >= len(ids):
                    break
                start += size - overlap
            out.append(wins)
    return out
