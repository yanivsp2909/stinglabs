"""RealSpartaDetector: the shipped secrets student behind `detect(text) -> list[Span]`.

    d = RealSpartaDetector()            # opens nothing
    d.detect("export TOKEN=…")          # the first call opens the student
    [Span(type='SECRET', start=13, end=…, confidence=0.99)]

Sparta only returns data, a type and a position; code decides. Nothing is loaded when this module is imported or
the detector built: the files are opened on the first `detect()` (or `load()`), once, under a lock.

Files (git-ignored, in models/ beside this package; downloaded from the repository's GitHub Release, see
sparta/README.md), or in the folder named by SPARTA_MODELS_DIR:

    models/sparta-secrets/tokenizer.json, tags-int8-dynamic-keepmlp/model.onnx (x86), tags-fp16/model.onnx (Mac)
        the clean 6-layer secrets student (internal evaluations EVAL-005/006)
    models/sparta-intent/tokenizer.json, intent-int8-dynamic-keepmlp/model.onnx (x86), intent-fp16/model.onnx (Mac)
        optional, and off unless asked for (below)

The x86 file is int8 dynamic with the MLP output projections in fp32; the Mac file is fp16 (EVAL-005/006), both on
ONNX Runtime's CPU provider (the CoreML path is not proven: EVAL-006 section 6). Threads: 4 on a Mac, 8 elsewhere
(EVAL-006's fastest on its x86 test machine), never more than the CPUs there are. Resident memory once open: 420 MB
on that x86 machine (int8 file); 450-580 MB on an M2 Pro Mac (fp16 file, random weights of the same shape).

Intent: `intent_score(task, action)` is P(the action fits the task) from the intent-only model, or None. It is not
shippable (test AUC 0.836), so it is off by default and never required: only `RealSpartaDetector(intent=True)`
looks for its files, and with them absent the score is None and detection works as before. With it open too, a
process held 820 MB on EVAL-006's x86 test machine.
"""

from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .spans import LABELS, Span, Window, spans_from_windows, token_windows

MODELS = Path(os.environ.get("SPARTA_MODELS_DIR") or Path(__file__).resolve().parent.parent / "models")
"""Where the model folders live: SPARTA_MODELS_DIR when set, else `models/` beside this package."""
SECRETS_DIR, INTENT_DIR = "sparta-secrets", "sparta-intent"
SECRETS_FILES = {"x86": "tags-int8-dynamic-keepmlp", "mac": "tags-fp16"}
INTENT_FILES = {"x86": "intent-int8-dynamic-keepmlp", "mac": "intent-fp16"}
THREADS = {"x86": 8, "mac": 4}
# Windows per ONNX run. An action averages 2.5 windows, so it runs in one batch, as EVAL-005 timed it; a long text
# runs in several. A 60-window text (Mac, fp16 file, random weights) peaked at 581 MB resident in batches of 8 and
# 937 MB in batches of 32, in the same time.
MAX_BATCH = 8
INTENT_TOKENS = 128         # an intent pair is cut to this, longest side first, as in training


def p_fits(intent_logits: np.ndarray) -> np.ndarray:
    """P(the action fits the task): softmax over the intent head's two logits, column 1."""
    z = intent_logits - intent_logits.max(-1, keepdims=True)
    e = np.exp(z)
    return e[:, 1] / e.sum(-1)


class SpartaModelMissing(FileNotFoundError):
    """The secrets student's files are not where the detector looks."""


@dataclass(frozen=True)
class ModelFiles:
    onnx: Path
    tokenizer: Path

    def missing(self) -> list[Path]:
        return [p for p in (self.onnx, self.tokenizer) if not p.is_file()]

    def present(self) -> bool:
        return not self.missing()


def machine() -> str:
    """'mac' on macOS, 'x86' elsewhere: which measured file this machine runs."""
    return "mac" if sys.platform == "darwin" else "x86"


def _files(models_dir: Path | str, folder: str, names: dict[str, str], platform: str | None) -> ModelFiles:
    platform = platform or machine()
    if platform not in names:
        raise ValueError(f"no Sparta file for machine {platform!r}; known: {sorted(names)}")
    root = Path(models_dir) / folder
    return ModelFiles(root / names[platform] / "model.onnx", root / "tokenizer.json")


def secrets_files(models_dir: Path | str = MODELS, platform: str | None = None) -> ModelFiles:
    return _files(models_dir, SECRETS_DIR, SECRETS_FILES, platform)


def intent_files(models_dir: Path | str = MODELS, platform: str | None = None) -> ModelFiles:
    return _files(models_dir, INTENT_DIR, INTENT_FILES, platform)


def default_threads() -> int:
    return min(THREADS[machine()], os.cpu_count() or 1)


def _open_session(path: Path, threads: int):
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads, so.inter_op_num_threads, so.log_severity_level = threads, 1, 3
    return ort.InferenceSession(str(path), so, providers=["CPUExecutionProvider"])


def _open_tokenizer(path: Path, truncation: int | None = None):
    """The shipped runtime tokenises with `tokenizers` alone (tests/test_runtime_tokenizer.py: the same ids as
    training's). Truncation and padding are set here, never taken from the file."""
    from tokenizers import Tokenizer
    tok = Tokenizer.from_file(str(path))
    tok.no_padding()
    if truncation:
        tok.enable_truncation(truncation)
    else:
        tok.no_truncation()
    return tok


def _token_id(tok, token: str, path: Path) -> int:
    tid = tok.token_to_id(token)
    if tid is None:
        raise ValueError(f"{path} has no {token} token; it is not the student's tokenizer")
    return tid


def _check_session(sess, output: str, last_dim: int, path: Path) -> None:
    inputs = {i.name for i in sess.get_inputs()}
    outputs = {o.name: o.shape for o in sess.get_outputs()}
    if inputs != {"input_ids", "attention_mask"} or output not in outputs:
        raise ValueError(f"{path}: inputs {sorted(inputs)}, outputs {sorted(outputs)}; "
                         f"a Sparta file takes input_ids and attention_mask and gives {output}")
    if outputs[output][-1] != last_dim:
        raise ValueError(f"{path}: {output} has {outputs[output][-1]} values a row, the student's {last_dim} expected")


class _Model:
    """One opened ONNX file, its tokenizer, and how it runs a padded batch."""

    def __init__(self, files: ModelFiles, output: str, last_dim: int, threads: int, truncation: int | None):
        missing = files.missing()
        if missing:
            raise SpartaModelMissing(f"Sparta model files not found: {', '.join(map(str, missing))}")
        self.tokenizer = _open_tokenizer(files.tokenizer, truncation)
        self.cls = _token_id(self.tokenizer, "[CLS]", files.tokenizer)
        self.sep = _token_id(self.tokenizer, "[SEP]", files.tokenizer)
        self.pad = _token_id(self.tokenizer, "[PAD]", files.tokenizer)
        self.session = _open_session(files.onnx, threads)
        _check_session(self.session, output, last_dim, files.onnx)
        self.output = output

    def run(self, rows: list[list[int]]) -> np.ndarray:
        n = max(map(len, rows))
        ids = np.array([r + [self.pad] * (n - len(r)) for r in rows], dtype=np.int64)
        mask = np.array([[1] * len(r) + [0] * (n - len(r)) for r in rows], dtype=np.int64)
        return self.session.run([self.output], {"input_ids": ids, "attention_mask": mask})[0]


class RealSpartaDetector:
    """detect(text) -> list[Span]: SECRET, NAME, EMAIL, PHONE, ID and ADDRESS spans in characters of `text`."""

    def __init__(self, models_dir: Path | str = MODELS, *, intent: bool = False, threads: int | None = None):
        self._secrets_files = secrets_files(models_dir)
        self._intent_files = intent_files(models_dir) if intent else None
        self._threads = threads or default_threads()
        self._lock = threading.Lock()
        self._tags: _Model | None = None
        self._intent: _Model | None = None
        self._intent_tried = False

    @property
    def loaded(self) -> bool:
        """Whether the secrets student is open."""
        return self._tags is not None

    @property
    def has_intent(self) -> bool:
        """Whether the intent model is open (only once asked for, and present)."""
        return self._intent is not None

    def load(self) -> None:
        """Open the secrets student now, and the intent model when asked for and present; normally the first
        call does it. Raises SpartaModelMissing when the student's files are absent."""
        self._load_tags()
        self._load_intent()

    def _load_tags(self) -> _Model:
        with self._lock:
            if self._tags is None:
                self._tags = _Model(self._secrets_files, "tag_logits", len(LABELS), self._threads, None)
            return self._tags

    def _load_intent(self) -> _Model | None:
        with self._lock:
            if self._intent_files is not None and not self._intent_tried:
                if self._intent_files.present():          # a file that fails to open raises, on every call
                    self._intent = _Model(self._intent_files, "intent_logits", 2, self._threads, INTENT_TOKENS)
                self._intent_tried = True
            return self._intent

    def detect(self, text: str) -> list[Span]:
        if not isinstance(text, str):
            raise TypeError(f"detect() takes a str, not {type(text).__name__}")
        if not text:
            return []
        tags = self._load_tags()
        enc = tags.tokenizer.encode(text, add_special_tokens=False)
        windows: list[Window] = token_windows(list(enc.ids), [tuple(o) for o in enc.offsets], tags.cls, tags.sep)
        logits = [row for b in range(0, len(windows), MAX_BATCH)
                  for row in tags.run([ids for ids, _ in windows[b:b + MAX_BATCH]])]
        return spans_from_windows(windows, logits, text)

    def intent_score(self, task: str, action: str) -> float | None:
        """P(the action fits the task) in [0, 1]; low is suspicious. None unless the detector was built with
        intent=True and the intent model's files are present."""
        if not isinstance(task, str) or not isinstance(action, str):
            raise TypeError("intent_score() takes a task and an action, both str")
        model = self._load_intent()
        if model is None:
            return None
        ids = list(model.tokenizer.encode(task, action).ids)
        return float(p_fits(model.run([ids]).astype(np.float64))[0])
