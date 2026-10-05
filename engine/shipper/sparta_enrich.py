"""Sparta in the shipper: more masks and two fields on what ships, and nothing else.

    "command": "curl -d note=\\"call [person] at [address]\\" https://x.invalid"
    "sparta_suspected": [{"field": "command", "item": 0, "type": "name",
                          "start": 19, "end": 34, "confidence": 0.91}, …]
    "sparta_intent": 0.42

Only with `STING_SPARTA=1` (shipper/sparta_iface.py). With it off the shipper
never reaches this module: `Shipper._masker` hands `build_batch` the masker it
always did.

⚠ WHERE IT RUNS IS THE WHOLE SAFETY ARGUMENT. In the shipper, while a batch is
built, after the hook decided and wrote the record. Its answers go into the
SHIPPED copy only: the local log, the session state the hook reads and every
verdict are untouched, so no answer of Sparta's can change an allow or a block.

⚠ ADDITIVE. Sparta's spans join the masking socket as the `model` provider
(shipper/mask.py), merged like every other: they can widen a mask and add one,
never remove one, and on a span a code provider also found, the code
provider's type names it.

⚠ FAIL-OPEN (`Guarded`). A detector that raises, answers malformed or too late
gives this record no spans and no score, and it still ships with every
deterministic mask. Each kind of failure is said once; one that does not
answer in time is not asked again by this process.
"""
from __future__ import annotations

import functools
from collections.abc import Callable

from core import wire
from shipper import mask, sparta_iface
from shipper.sparta_iface import Span

CALL_SECONDS = 2.0
"""The longest one `detect` or `intent` call may take. EVAL-005 measured 37 to
175 ms per action; a call this late is a hang, and the process stops asking."""

MAX_SUSPECTED = 64
"""The most spans `sparta_suspected` lists for one record, in reading order.
`masked` still counts every mask: this bounds the record, not the masking."""

MARKERS = {"secret": "secret", "email": "email", "name": "person",
           "address": "address", "phone": "phone", "id": "id-number"}
"""The `[type]` a Sparta span is masked as: the names masking already ships,
so a reader meets no new marker (`[person]` is Layer B's, `[id-number]` the
code's for an Israeli ID or an SSN)."""


_FAILED = object()
"""What `Guarded._call` answers when the detector raised or was too late: not
None, which a detector can answer, and which then reads as malformed."""


class Guarded:
    """One detector, asked fail-open: a failure is never the record's."""

    def __init__(self, detector: sparta_iface.SpartaDetector, *,
                 log: Callable[[str], None], seconds: float | None = None) -> None:
        self._detect = detector.detect
        intent = getattr(detector, "intent", None)
        self._intent = intent if callable(intent) else None
        self._log = log
        self._seconds = CALL_SECONDS if seconds is None else seconds
        self._tripped = False
        self._said: set[str] = set()

    def spans(self, text: str) -> tuple[Span, ...]:
        """Every well-formed span the detector answers for `text`; () on any failure."""
        found = self._call(self._detect, text)
        if found is _FAILED:
            return ()
        if not isinstance(found, (list, tuple)):
            self._say("malformed", f"answered a {type(found).__name__}, not a list of spans")
            return ()
        kept = tuple(span for span in map(functools.partial(_valid, text=text), found)
                     if span is not None)
        if len(kept) < len(found):
            self._say("dropped", "answered spans outside the contract (type, "
                                 "offsets or confidence); they were dropped")
        return kept

    def intent(self, text: str) -> float | None:
        """The detector's score for `text`, rounded; None when it gives none."""
        if self._intent is None:
            return None
        score = self._call(self._intent, text)
        if score is _FAILED or score is None:
            return None
        if not sparta_iface.is_unit(score):
            self._say("intent", "answered an intent score outside [0, 1]; it was dropped")
            return None
        return round(float(score), 4)

    def _call(self, fn: Callable, text: str):
        """`fn(text)`'s answer, or `_FAILED` when it raised or was too late."""
        if self._tripped:
            return _FAILED
        try:
            return sparta_iface.call_within(self._seconds, fn, text)
        except sparta_iface.SpartaTimeout:
            self._tripped = True
            self._say("timeout", f"did not answer within {self._seconds:g}s; it is "
                                 f"not asked again until the shipper restarts")
        except sparta_iface.SpartaFailure as failure:
            self._say("error", f"raised {failure}")
        return _FAILED

    def fault(self, exc: Exception) -> None:
        """The enrichment's OWN code failed on a record (`enrich_record`)."""
        if "fault" not in self._said:
            self._said.add("fault")
            self._log(f"  ⚠ the Sparta enrichment failed on a record "
                      f"({type(exc).__name__}); it ships with deterministic masking, "
                      f"as every record does when it fails. Said once.")

    def _say(self, kind: str, what: str) -> None:
        if kind in self._said:
            return
        self._said.add(kind)
        self._log(f"  ⚠ the Sparta detector {what}. Records ship with deterministic "
                  f"masking regardless. Said once.")


def _valid(span: object, *, text: str) -> Span | None:
    """`span` as the engine's `Span`, when it keeps the contract and fits
    `text`: checked by `Span`, then REBUILT as plain `str`, `int` and `float`,
    so a model's numpy numbers ship as JSON numbers (security review)."""
    try:
        given = Span(span.type, span.start, span.end, span.confidence)
        span = Span(str(given.type), int(given.start), int(given.end),
                    float(given.confidence))
    except Exception:                    # any object, any attribute: never the record's problem
        return None
    return span if span.end <= len(text) else None


CAN_LEAK = ("with STING_SPARTA=1, per record: where Sparta suspected a value "
            "(sparta_suspected: the field, the offsets and so the value's length, "
            "the type and a confidence) and Sparta's score for the command "
            "(sparta_intent); never the value")
"""What a batch built with the enrichment can reveal beyond `wire.can_leak()`,
stated as that list states things: a capability, at its worst."""


def disclosed(batch: dict) -> dict:
    """`batch` as a NEW dict whose `can_leak` also says what the enrichment
    adds. Only for a batch whose records went through `enrich_record`."""
    provenance = batch["provenance"]
    return {**batch, "provenance": {**provenance,
                                    "can_leak": [*provenance["can_leak"], CAN_LEAK]}}


def enrich_record(record: dict, known: mask.SessionValues = mask.NO_SESSION, *,
                  analyzer=None, guarded: Guarded) -> dict:
    """`mask.mask_record`, with Sparta's spans as its `model` provider, and the
    record's `sparta_suspected` and `sparta_intent` written beside.

    ⚠ THE TWO FIELDS ARE THIS FUNCTION'S TO WRITE, as `masked` is masking's:
    a local record that arrives carrying one (an edited log) loses it, so what
    ships says what Sparta said. ⚠ ONE CALL PER DISTINCT TEXT: the answers
    the mask used are the ones the provenance lists. ⚠ FAIL-OPEN FOR THIS
    CODE TOO, not only the detector's: any fault here ships the record as
    `mask.mask_record` alone would, said once (security review)."""
    record = {key: value for key, value in record.items()
              if key not in sparta_iface.FIELDS}
    try:
        return _enriched(record, known, analyzer, guarded)
    except Exception as exc:
        guarded.fault(exc)
        return mask.mask_record(record, known, analyzer=analyzer)


def _enriched(record: dict, known: mask.SessionValues, analyzer,
              guarded: Guarded) -> dict:
    answers: dict[str, tuple[Span, ...]] = {}

    def model(text: str) -> list[mask.Span]:
        if text not in answers:
            answers[text] = guarded.spans(text)
        return [mask.Span(MARKERS[span.type], span.start, span.end, "model")
                for span in answers[text]]

    out = mask.mask_record(record, known, analyzer=analyzer, model=model)
    suspected = _suspected(record, answers)
    if suspected:
        out[sparta_iface.SUSPECTED_FIELD] = suspected
    command = record.get("command")
    score = guarded.intent(command) if isinstance(command, str) and command else None
    if score is not None:
        out[sparta_iface.INTENT_FIELD] = score
    return out


def _suspected(record: dict, answers: dict[str, tuple[Span, ...]]) -> list[dict]:
    """Where each answer sits in the LOCAL record: the field, which of its
    strings (`item`, in the order masking reads them), the type, the offsets
    into that string and the confidence. Never the value; at most
    `MAX_SUSPECTED`."""
    out: list[dict] = []
    for key, value in record.items():
        if key in wire.UNMASKED or key == wire.MASKED_FIELD:
            continue
        for item, text in enumerate(mask._texts(value)):
            for span in answers.get(text, ()):
                if len(out) == MAX_SUSPECTED:
                    return out
                out.append({"field": key, "item": item, "type": span.type,
                            "start": span.start, "end": span.end,
                            "confidence": round(float(span.confidence), 4)})
    return out
