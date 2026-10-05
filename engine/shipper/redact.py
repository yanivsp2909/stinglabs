"""The pieces of the old redaction layers the one masking path still uses, and
the marks they left in records that already shipped.

⚠ ONE MASKING PATH, AND IT IS `shipper/mask.py`. Until 28 Sep 2026 this module
rewrote an outbound record in two layers: Layer A replaced every value the
engine had FINGERPRINTED with `[REDACTED:secret]`, and Layer B (opt-in,
`STING_REDACT_PII`) replaced emails and person names with `[REDACTED:pii]`.
Both are providers of the masking socket now, and write a TYPE instead:

    Layer A   [secret-from-<file>]   by the same needle, `_fingerprint` below
    emails    [email]                always on, no longer opt-in
    Layer B   [person]               still opt-in, through the analyzer below

What stays here: the needle, so it has one definition; Layer B's analyzer,
which plugs into the socket as it is; and the two old marks, because an export
shipped before this change still carries them and `tools/verify_log.py
--export` must read its records as rewritten, never as broken.

⚠ OFF-HOOK, DOWNSTREAM OF THE DECISION, as before: the shipper imports this; the
engine and the hook never do.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterator

# The marks the old layers wrote. Nothing writes them any more.
SECRET_MARK = "[REDACTED:secret]"
PII_MARK = "[REDACTED:pii]"

# The free-text fields the old layers rewrote, and so the only fields an old
# mark can be in. A mark anywhere else was never written by them.
_TEXT_FIELDS = ("command", "reason", "evidence", "url", "granted_by",
                "cwd", "title", "tool_name")
_LIST_TEXT_FIELDS = ("paths", "workspace_roots")


class RedactionUnavailable(RuntimeError):
    """Layer B was enabled but its NER dependency is missing. Raised, never
    swallowed — the shipper FAILS LOUD rather than ship names unmasked."""


def _fingerprint(token: str) -> str:
    """The engine's needle: sha256(token) truncated to 8 hex. Layer A matches a
    token by it, and so does the org-policy match (`shipper/mask.py`)."""
    return hashlib.sha256(token.encode()).hexdigest()[:8]


# ────────────────────────────────────────────────────────────── Layer B (opt-in)
class _SpacyAnalyzer:
    """Adapter over an operator-installed spaCy pipeline. Contract: `person_spans`
    returns (start, end) char spans of PERSON entities — which is the socket's
    shape already, so the masking reads it as one more provider (tested with a
    stub; the spaCy call itself is validated by the operator who installs the
    model)."""

    def __init__(self, nlp):
        self._nlp = nlp

    def person_spans(self, text: str):
        return [(e.start_char, e.end_char) for e in self._nlp(text).ents
                if getattr(e, "label_", "") == "PERSON"]


def load_pii_analyzer():
    """Lazy-load the NER analyzer — imported ONLY here, ONLY when Layer B is on, so
    a default install never loads spaCy and never requires it. FAILS LOUD if the
    dependency (or its model) is absent.

    ⚠ CALL ONCE PER PROCESS, NOT PER RECORD. `spacy.load` is expensive (model load
    + memory); the shipper caches this and passes the analyzer to the masking,
    so a 1000-record batch loads the model once, not a thousand times.

    ⚠ DEP: spaCy + an English model (`en_core_web_sm`) — operator-installed, NOT in
    the default 'pure stdlib, no pip' install. Marked here rather than pinned: the
    exact model is the operator's choice; this only needs a pipeline exposing
    `.ents` with a `PERSON` label."""
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
    except Exception as exc:                       # ImportError, OSError (no model)
        raise RedactionUnavailable(
            "STING_REDACT_PII is enabled but the NER dependency is unavailable "
            f"({type(exc).__name__}: {exc}). Install spaCy and a model "
            "(pip install spacy && python -m spacy download en_core_web_sm), or "
            "unset STING_REDACT_PII — refusing to ship names unmasked.") from exc
    return _SpacyAnalyzer(nlp)


# ─────────────────────────────────────────────── reading an old export back
def _texts(record: dict) -> Iterator[str]:
    """Every string in a field the old layers rewrote."""
    for f in _TEXT_FIELDS:
        if isinstance(record.get(f), str):
            yield record[f]
    for f in _LIST_TEXT_FIELDS:
        if isinstance(record.get(f), list):
            yield from (p for p in record[f] if isinstance(p, str))


def carries_a_mark(record: dict) -> bool:
    """Did the old Layer A or B rewrite this record? True when a field either
    rewrote holds SECRET_MARK or PII_MARK, the only trace a rewrite left.

    For a verifier (tools/verify_log.py --export) reading an export from before
    28 Sep 2026: a rewritten record's local hash covers text that never
    shipped, so it cannot be checked from what did. A record masked since
    carries `masked` instead (`core.wire.carries_masks`).
    ⚠ A MARK IS TEXT IN THE FILE. Whoever can edit the file can write one, and a
    developer can type one; nothing here tells either from a real rewrite."""
    return any(mark in text for text in _texts(record)
               for mark in (SECRET_MARK, PII_MARK))
