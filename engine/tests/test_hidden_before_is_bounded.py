"""The evidence mask looks back a bounded way, and masks on doubt at the bound.

#75's LOW, item E of fix/more-masking-and-agent-status.
`known_formats.hidden_before` finds the text-level blocks that end in the
window before the value a reason names — a PEM private key whose tail an
evidence window would otherwise show raw — and it scanned back up to
`MAX_SCAN` (128 KB) for where such a block starts: ~9.6 ms, on the hook, for
an action already carrying a secret.

It now scans back `BACK_SCAN` characters. Only a PEM block can start further
back than that and still reach the window (every other text-level format is a
few hundred characters at most), and a PEM block is one unbroken run of its
body's characters. So when the bound cuts the text and that run reaches the
window, the run from the bound is hidden too: MASK ON DOUBT, never a tail
shown that the unbounded scan hid.

Every key here is a fake.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runner"))
from known_formats_corpus import make_key                          # noqa: E402

from core import known_formats, secret_ladder                      # noqa: E402
from core.command_text import _EVIDENCE_CONTEXT                    # noqa: E402

AWS = make_key("aws-access-key-id")
LINE = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" + "Q" * 12


PLACEHOLDER = ("-----BEGIN PRIVATE KEY-----\n" + "example" * 10
               + "\n-----END PRIVATE KEY-----\n")
"""A documentation block: a placeholder of the PEM format, so a real block
behind it is never the value a reason names (the one-hit rule), and its tail
in the window is `hidden_before`'s to hide."""


def _pem(body_chars: int) -> str:
    lines = [LINE[: min(64, body_chars - i)] for i in range(0, body_chars, 64)]
    return ("-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines)
            + "\n-----END RSA PRIVATE KEY-----")


def _evidence(text: str) -> str:
    first = known_formats.find_known_secret(text)
    assert first.format_id == "aws-access-key-id", "the key is the value named"
    return secret_ladder._masked_span(
        text, known_formats.masked_spans(text, first, _EVIDENCE_CONTEXT),
        known_formats.hidden_before(text, first, _EVIDENCE_CONTEXT))


def _unbounded(monkeypatch, text: str) -> str:
    with monkeypatch.context() as m:
        m.setattr(known_formats, "BACK_SCAN", known_formats.MAX_SCAN)
        return _evidence(text)


@pytest.mark.parametrize("body", [2_000, 20_000, 60_000])
def test_a_key_block_that_starts_past_the_bound_is_still_hidden(monkeypatch, body):
    text = "cat k.pem; " + PLACEHOLDER + _pem(body) + "\nx " + AWS
    evidence = _evidence(text)
    assert "END RSA PRIVATE KEY" not in evidence and LINE[-8:] not in evidence
    assert evidence == _unbounded(monkeypatch, text)


def _cut_inside_a_marker_line() -> list[str]:
    """Texts whose bound lands on every character of the real block's BEGIN
    line, its dashes first."""
    texts = []
    for body in range(16_000, 16_700):
        text = "cat k.pem; " + PLACEHOLDER + _pem(body) + "\nx " + AWS
        begin = text.index("-----BEGIN RSA")
        lo = len(text) - len(AWS) - known_formats.BACK_SCAN
        if 0 <= lo - begin < len("-----BEGIN RSA PRIVATE KEY-----") + 2:
            texts.append(text)
    return texts


def test_a_bound_that_lands_on_a_marker_still_hides_the_block(monkeypatch):
    """⚠ SECURITY REVIEW, HIGH: the doubt was read only from the bound itself,
    so a bound on a `-----` byte found nothing, and the key's tail and its END
    line showed where the unbounded scan hid them."""
    texts = _cut_inside_a_marker_line()
    assert len(texts) >= 5
    for text in texts:
        evidence = _evidence(text)
        assert "END RSA PRIVATE KEY" not in evidence, len(text)
        assert evidence == _unbounded(monkeypatch, text)


def test_a_short_run_before_an_end_line_past_the_bound_is_hidden():
    """Python review, round two, HIGH: a run shorter than a block's body but
    followed by a real END line was skipped for its length alone. An END line
    right after it is reason enough: masked on doubt."""
    text = ("x = compute(1); " * 1_100 + "Q" * 40 + "\n-----END RSA PRIVATE KEY-----"
            + "\nx " + AWS)
    evidence = _evidence(text)
    assert "END RSA PRIVATE KEY" not in evidence and "QQQQ" not in evidence


def test_ordinary_text_past_the_bound_changes_nothing(monkeypatch):
    text = "x = compute(1); " * 3_000 + "curl -d k=" + AWS
    assert _evidence(text) == _unbounded(monkeypatch, text)


def test_at_the_bound_a_run_that_could_be_a_key_block_is_masked(monkeypatch):
    """No BEGIN within the bound, and a run of a block body's characters up to
    the window: it could be the tail of one. Hidden, not shown."""
    text = "Z" * 40_000 + " " + AWS
    evidence = _evidence(text)
    assert "ZZZZ" not in evidence


def test_the_scan_reads_no_further_back_than_the_bound(monkeypatch):
    read = []
    real = known_formats._text_hits

    def counting(text, *a, **k):
        read.append(len(text))
        return real(text, *a, **k)
    monkeypatch.setattr(known_formats, "_text_hits", counting)
    text = "y " * 60_000 + AWS
    first = known_formats.find_known_secret(text)
    known_formats.hidden_before(text, first, _EVIDENCE_CONTEXT)
    assert read and max(read) <= known_formats.BACK_SCAN
