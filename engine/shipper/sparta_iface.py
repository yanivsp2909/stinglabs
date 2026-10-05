"""Sparta, from the engine's side: the whole contract, and nothing that runs a model.

Sparta (the sparta/ package in this repository) reads a text and answers where a value that must
not leave sits in it, and what it is. This module is that question as the
ENGINE asks it. ⚠ THE ENGINE OWNS IT: nothing here imports the sparta package.
The real detector is found by NAME, inside `get_detector`, only when
`STING_SPARTA=1`, and it is expected to match this file, never the other way
round. PROGRESS.md carries the same contract for the other side to copy.

⚠ OFF THE HOOK, AFTER THE VERDICT, AND NEVER A VERDICT. Only the shipper reads
this, while a batch is built (shipper/sparta_enrich.py). The hook, the daemon,
the adapters and `core/` never import it and never name Sparta, and a test
scans them for the word. A Sparta answer can add a mask and a field to what
ships; it cannot remove a mask, and it cannot reach a decision.

⚠ FAIL-OPEN, THE OPPOSITE OF THE HOOK. A detector that cannot be imported,
raises, answers malformed or too late costs the record nothing but Sparta's
part: it ships with every deterministic mask, and the operator is told once.

    STING_SPARTA        "1" turns the enrichment on. Anything else, or unset,
                        is off: no import, no call, the shipper exactly as it
                        was. Default "0".
    STING_SPARTA_TAINT  read only when STING_SPARTA is "1". Reserved for
                        seeding next-action taint from Sparta, which is NOT
                        built: on, the shipper says so once and seeds nothing.
                        Default "0".
"""
from __future__ import annotations

import importlib
import math
import numbers
import os
import re
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

FLAG = "STING_SPARTA"
TAINT_FLAG = "STING_SPARTA_TAINT"
ON = "1"
"""The one value that turns a flag on. Not "true", not "yes": an operator who
means it writes the documented value, and a typo stays off."""

SPAN_TYPES = frozenset({"secret", "name", "email", "phone", "id", "address"})
"""The types a span may carry: EVAL-005's six, lower-case (`id` is an Israeli
ID or an SSN). ⚠ THE ONE COPY. A span of any other type, an upper-case one
included, is dropped where it is read (`Span` refuses it)."""

DETECTOR_MODULE = "sparta.sting_detector"
"""Where the real detector lives, imported by name inside `get_detector`."""
DETECTOR_FACTORY = "make_detector"
"""`DETECTOR_MODULE.make_detector()`: called once per shipper process, with no
arguments, and answering an object with `detect` (and, optionally, `intent`)."""

LOAD_SECONDS = 120.0
"""How long the factory may take: loading a model is slow, a hang is not."""

SUSPECTED_FIELD = "sparta_suspected"
"""On a shipped record: the spans Sparta found, `[{"field", "item", "type",
"start", "end", "confidence"}]`. Offsets and types, never the value."""
INTENT_FIELD = "sparta_intent"
"""On a shipped record: the detector's score for the record's command, in
[0, 1], when it gave one. Recorded beside `decision`; nothing reads it."""
FIELDS = (SUSPECTED_FIELD, INTENT_FIELD)
"""Every field the enrichment writes. Absent from every record with the flag off."""


# ══════════════════════════════════════════════════════════════ the contract

def _is_offset(value: object) -> bool:
    """A whole number that is not a `bool` (`True` is an int to Python, not
    an offset). Any `numbers.Integral`: a model's numpy int is one."""
    return isinstance(value, numbers.Integral) and not isinstance(value, bool)


def is_unit(value: object) -> bool:
    """A real number in [0, 1]: not a bool, not NaN, not infinite. Any
    `numbers.Real`: a model's float32 is one, and is not a `float`."""
    return (isinstance(value, numbers.Real) and not isinstance(value, bool)
            and math.isfinite(value) and 0.0 <= value <= 1.0)


@dataclass(frozen=True)
class Span:
    """Where a suspected value sits in ONE text, what it is, how sure Sparta is.

    `start` and `end` are Python string indices into the text `detect` was
    given (code points, end exclusive): `text[start:end]` is the value.
    Refused on construction unless `type` is one of `SPAN_TYPES`,
    `0 <= start < end`, and `confidence` is a number in [0, 1]. Whether `end`
    fits the text is checked where the text is known, and every answer is
    rebuilt there as plain `str`, `int` and `float` (sparta_enrich.py)."""
    type: str
    start: int
    end: int
    confidence: float

    def __post_init__(self) -> None:
        if self.type not in SPAN_TYPES:
            raise ValueError(f"span type {self.type!r} is not one of {sorted(SPAN_TYPES)}")
        if not (_is_offset(self.start) and _is_offset(self.end)
                and 0 <= self.start < self.end):
            raise ValueError("a span needs integer offsets with 0 <= start < end")
        if not is_unit(self.confidence):
            raise ValueError("a span's confidence is a number in [0, 1]")


@runtime_checkable
class SpartaDetector(Protocol):
    """What the engine calls. `detect` answers every span it suspects in
    `text`, overlaps allowed, in any order, `[]` for none.

    OPTIONAL: `intent(text: str) -> float | None`, a score in [0, 1] for an
    action's command, None for no score. A detector without it gives none."""

    def detect(self, text: str) -> list[Span]:
        ...


class NullSpartaDetector:
    """The default: finds nothing, scores nothing."""

    def detect(self, text: str) -> list[Span]:
        return []


NULL = NullSpartaDetector()


class FakeSpartaDetector:
    """⚠ FOR TESTS ONLY. Deterministic, by pattern, no model: what a real
    detector's answers look like, so the enrichment can be tested without one.
    `get_detector` never returns it, and a test pins that nothing shipped
    outside this file names it."""

    PATTERNS = (
        ("secret", re.compile(r"\bsparta-secret-[a-z0-9]{8,32}\b"), 0.97),
        ("email", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}"
                             r"(?:\.[A-Za-z0-9-]{1,63}){1,8}\b"), 0.99),
        ("name", re.compile(r"\b(?:Dana|Noa|Avi) [A-Z][a-z]{1,30}\b"), 0.91),
        ("address", re.compile(r"\b\d{1,5} [A-Z][a-z]{1,30} Street\b"), 0.88),
        ("phone", re.compile(r"\+\d{3}-\d{2}-\d{3}-\d{4}\b"), 0.93),
        ("id", re.compile(r"\b\d{3}-\d{2}-\d{4}\b|(?<=ID )\d{9}\b"), 0.9),
    )

    def __init__(self, intent_score: float | None = None) -> None:
        self.intent_score = intent_score
        self.calls: list[str] = []

    def detect(self, text: str) -> list[Span]:
        self.calls.append(text)
        return [Span(kind, m.start(), m.end(), confidence)
                for kind, pattern, confidence in self.PATTERNS
                for m in pattern.finditer(text)]

    def intent(self, text: str) -> float | None:
        return self.intent_score if text else None


# ═════════════════════════════════════════════════════════════════ the flags

def _environ(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Is `STING_SPARTA` exactly "1"?"""
    return (_environ(environ).get(FLAG) or "").strip() == ON


def taint_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """`STING_SPARTA_TAINT` is "1" AND `STING_SPARTA` is. ⚠ THE SECOND FLAG IS
    NOT READ AT ALL unless the first is on: the gate is the first flag."""
    env = _environ(environ)
    return enabled(env) and (env.get(TAINT_FLAG) or "").strip() == ON


# ════════════════════════════════════════════════════════ calling it at all

class SpartaFailure(Exception):
    """The detector raised, or could not be loaded. Carries the error's TYPE
    only: its message is the detector's text and could quote the input."""


class SpartaTimeout(SpartaFailure):
    """The detector did not answer within its time."""


def call_within(seconds: float, fn: Callable, *args):
    """`fn(*args)` on a daemon thread, waited on for `seconds`.

    ⚠ A HUNG CALL IS LEFT BEHIND, NOT KILLED: Python cannot stop a thread. It
    is a daemon, so the process still exits (`--once`), and the caller stops
    asking (`Guarded` trips), so at most one is ever left. Anything the call
    raises, `SystemExit` included, comes back as `SpartaFailure`."""
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = fn(*args)
        except BaseException as exc:                 # a worker thread: nothing to interrupt
            box["error"] = type(exc).__name__

    worker = threading.Thread(target=run, name="sting-sparta", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise SpartaTimeout(f"no answer within {seconds:g}s")
    if "error" in box:
        raise SpartaFailure(box["error"])
    return box.get("value")


def _stderr(line: str) -> None:
    sys.stderr.write(line + "\n")


def _load() -> object:
    module = importlib.import_module(DETECTOR_MODULE)
    return getattr(module, DETECTOR_FACTORY)()


def get_detector(environ: Mapping[str, str] | None = None, *,
                 log: Callable[[str], None] | None = None,
                 seconds: float = LOAD_SECONDS) -> SpartaDetector:
    """`NULL` unless `STING_SPARTA` is "1"; then the real detector, imported by
    name HERE and nowhere else, or `NULL` again when it cannot be had.

    ⚠ NOTHING IS IMPORTED WITH THE FLAG OFF: the import statement is inside
    this function, behind the flag. ⚠ AND A FAILED LOAD SAYS SO, ONCE PER
    CALL, which the shipper makes once per process: what failed by type, and
    that shipping goes on with deterministic masking only."""
    if not enabled(environ):
        return NULL
    say = log or _stderr
    try:
        detector = call_within(seconds, _load)
    except SpartaFailure as failure:
        say(f"  ⚠ {FLAG}=1, but the Sparta detector could not be loaded "
            f"({failure}); records ship with deterministic masking only. Said once.")
        return NULL
    if not callable(getattr(detector, "detect", None)):
        say(f"  ⚠ {FLAG}=1, but {DETECTOR_MODULE}.{DETECTOR_FACTORY}() gave an "
            f"object with no detect(); records ship with deterministic masking "
            f"only. Said once.")
        return NULL
    return detector
