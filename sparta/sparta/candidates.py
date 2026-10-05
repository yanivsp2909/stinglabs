"""Code that finds candidates for the secrets check: anything that COULD be a secret or personal data, by shape
and context only (never randomness). Used by sparta.prefilter (what it costs in recall) and sparta.speed (what it
costs in time); only `re`, so it runs under the OpenVINO build too."""

from __future__ import annotations

import re

CANDIDATE = re.compile("|".join([
    r"(?=[A-Za-z0-9_\-+/=.~]*[A-Za-z])(?=[A-Za-z0-9_\-+/=.~]*\d)[A-Za-z0-9_\-+/=.~]{8,}",
    r"[A-Za-z0-9_\-+/=]{16,}",
    r"(?=\S*[A-Za-z])(?=\S*\d)\S{8,}",                                   # any 8+ run with a letter and a digit
    r"\S*[a-z][A-Z]\S*|\S*[A-Za-z][!#$%^&*~][A-Za-z]\S*",
    r"@",
    r"\b[A-ZÀ-ÖØ-ÞĀĂĄĆČĎĐĒĖĘĚĞĢĪĮİĶĹĻĽŁŃŅŇŌŐŒŔŘŚŞŠŢŤŪŮŰŲŹŻŽ][^\W\d_]+",
    r"(?:/Users/|/home/|C:(?:\\){1,2}Users(?:\\){1,2}|-Users-)\S+",     # also C:\\Users\\ as JSON writes it
    r"\+?\(?\d[\d ().\-/]{6,}\d",                                       # phone and ID numbers, any separators
]))


def candidates(text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in CANDIDATE.finditer(text)]


def plain(ids, offs, size=126, overlap_=32):
    out, start = [], 0
    while True:
        out.append((start, min(len(ids), start + size)))
        if start + size >= len(ids):
            return out
        start += size - overlap_


def centred(ids, offs, cands, size=62):
    """64-token windows (62 + [CLS] + [SEP]) centred on each candidate, merged when they overlap."""
    spans = []
    for a, b in cands:
        toks = [i for i, (x, y) in enumerate(offs) if x < b and a < y]
        if not toks:
            continue
        mid = (toks[0] + toks[-1]) // 2
        lo = max(0, min(mid - size // 2, len(ids) - size))
        spans.append((lo, min(len(ids), lo + size)))
    merged = []
    for lo, hi in sorted(spans):
        if merged and lo < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    out = []
    for lo, hi in merged:                               # a merged run longer than 62 tokens is cut in 62s again
        while lo < hi:
            out.append((lo, min(hi, lo + size)))
            lo += size
    return out


def kept(wins: list[tuple[int, int]], offs: list, cands: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The token windows [(lo, hi)] whose characters hold at least one candidate."""
    out = []
    for lo, hi in wins:
        a, b = offs[lo][0] if lo < len(offs) else 0, offs[hi - 1][1] if hi else 0
        if any(x < b and a < y for x, y in cands):
            out.append((lo, hi))
    return out
