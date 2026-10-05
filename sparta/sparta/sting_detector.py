"""The engine's door to Sparta: `sparta.sting_detector.make_detector()`, as the engine's contract has it.

The contract is the engine's (engine/shipper/sparta_iface.py, with its six span types).
With STING_SPARTA=1 the shipper imports this module by name and calls `make_detector()` once per process, with no
arguments, giving it LOAD_SECONDS = 120 s; then `detect(text)` once per string it masks, each call cut off at
CALL_SECONDS = 2 s (one late call and that process stops asking). A span is any object with `type` (one of TYPES),
`start` and `end` (code-point indices into the text, end exclusive) and `confidence` in [0, 1].

This module only adapts RealSpartaDetector (sparta/detector.py) to that: each type lower-cased, nothing dropped,
offsets and confidences as they are. The model is opened inside make_detector(), where the engine waits for it,
so no detect() call pays for loading; with its files absent make_detector() raises (SpartaModelMissing) and the
engine ships with deterministic masking alone. No intent: the detector here has no `intent`, so the engine records
no score; RealSpartaDetector(intent=True) stays for a later pass.
"""

from __future__ import annotations

from .detector import MODELS, RealSpartaDetector
from .spans import Span

ENGINE_TYPES = {"SECRET": "secret", "NAME": "name", "EMAIL": "email", "PHONE": "phone", "ID": "id",
                "ADDRESS": "address"}
"""The student's type -> the engine's name for it."""
TYPES = tuple(ENGINE_TYPES.values())


class StingDetector:
    """RealSpartaDetector's spans under the engine's type names."""

    def __init__(self, detector: RealSpartaDetector):
        self._detector = detector

    def detect(self, text: str) -> list[Span]:
        return [Span(ENGINE_TYPES[s.type], s.start, s.end, s.confidence) for s in self._detector.detect(text)]


def make_detector() -> StingDetector:
    """The secrets student from models/, opened now. Raises SpartaModelMissing when its files are absent."""
    detector = RealSpartaDetector(MODELS)
    detector.load()
    return StingDetector(detector)
