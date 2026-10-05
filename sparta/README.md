# Sparta: the model package

Sparta is a small local model that reads a piece of text, such as an agent's command or a file it wrote, and
answers **where** a value that must not leave sits in it, and **what** it is:

| type | example of what it tags |
|---|---|
| `SECRET` | an API key, a token, a password in a connection string, including shapes with no known prefix |
| `NAME` | a person's name |
| `EMAIL` | an e-mail address |
| `PHONE` | a phone number |
| `ID` | a national ID number or SSN |
| `ADDRESS` | a postal address |

It returns data only: `Span(type, start, end, confidence)` in characters of the text. **It never decides
anything.** In this repository its one consumer is the engine's *shipper*, which uses the spans to mask more
of a record before it leaves the machine. The guard's allow / ask / deny decision never waits for Sparta,
never reads it, and works the same with Sparta absent. See [`../docs/sparta.md`](../docs/sparta.md).

## What is here, and what is not

| here | not here |
|---|---|
| `sparta/detector.py`: `RealSpartaDetector`, which opens the ONNX file and the tokenizer and returns spans | the trained weights: they are **not in git**. Download them from the repository's GitHub Release |
| `sparta/sting_detector.py`: `make_detector()`, the door the engine imports by name | the training pipeline, data generators and evaluation harness |
| `sparta/spans.py`, `tagging.py`, `candidates.py`, `windows.py`: windowing and span decoding, no model | training data and corpora (never published: they could hold real examples) |
| `sparta/fakes.py`: runtime generators of synthetic secrets, used by the tests | evaluation reports |
| `tests/`: everything above, on synthetic logits; the real-model tests skip until the weights are present | |

## Install

Python 3.10+ (the engine needs 3.11+, so use the same interpreter for both).

```bash
cd sparta
python3 -m pip install -e .          # numpy, onnxruntime, tokenizers
python3 -m pytest tests -q           # model-free tests; real-model tests skip without the files
```

`-e` (editable) matters: the detector looks for its files in `models/` **beside this package**
(`sparta/models/`), and an editable install keeps the package where that folder is. To keep the files
elsewhere, set `SPARTA_MODELS_DIR=/path/to/models`.

## The model files

Download the release assets and place them like this (the paths are what the code looks for):

```
sparta/models/
  sparta-secrets/
    tokenizer.json
    tags-int8-dynamic-keepmlp/model.onnx    # Linux / x86 (int8 dynamic, MLP output projections in fp32)
    tags-fp16/model.onnx                    # macOS (fp16)
  sparta-intent/                            # OPTIONAL, off by default, not needed
    tokenizer.json
    intent-int8-dynamic-keepmlp/model.onnx
    intent-fp16/model.onnx
```

The detector picks the file by platform: `tags-fp16` on macOS, `tags-int8-dynamic-keepmlp` everywhere else.
You only need the one for your machine, plus `tokenizer.json`.

Verify what you downloaded. These are the files the internal evaluations measured, and
`tests/test_detector_real.py` checks the same values:

| file | sha256 |
|---|---|
| `sparta-secrets/tokenizer.json` | `9fd55248d51d33976b324fc11592e28071da7d41e0e9401dfb7082e30574b7b1` |
| `sparta-secrets/tags-int8-dynamic-keepmlp/model.onnx` | `708f51e89cbf1d6bd497cc63670d0b142d354515a4534e5ba277d8083eba1acc` |
| `sparta-secrets/tags-fp16/model.onnx` | `e788ef3159cc6fb8a9f1b58199b657541e460746404bbe7fd384e3f8e625985b` |
| `sparta-intent/intent-int8-dynamic-keepmlp/model.onnx` | `ee81ab440ca847e92798abe52d0777a5acb844f20bc4adfa436a7645f030982f` |
| `sparta-intent/intent-fp16/model.onnx` | `137531ab823db9973519488f901917a0fe413b3204417e3c1e41964ff01476b5` |

```bash
shasum -a 256 sparta/models/sparta-secrets/tokenizer.json sparta/models/sparta-secrets/*/model.onnx
python3 -m pytest tests/test_detector_real.py -q     # now runs instead of skipping
```

## Use it directly

```python
from sparta.sting_detector import make_detector

detector = make_detector()            # opens the model now; raises SpartaModelMissing if the files are absent
for span in detector.detect("export DB_URL=postgres://admin:<your password here>@db.internal/app"):
    print(span.type, span.start, span.end, round(span.confidence, 2))
```

`make_detector()` returns the engine's lower-case types (`secret`, `name`, `email`, `phone`, `id`, `address`).
`sparta.detector.RealSpartaDetector` returns the upper-case ones and opens the model lazily on the first
`detect()`.

## How it works

1. The text is tokenised once and cut into windows of 128 tokens (`[CLS]` and `[SEP]` included), 32 tokens
   overlapping, so a long text is covered end to end.
2. A 6-layer token classifier labels each token `O` or `B-`/`I-` of one of the six types.
3. Labels are decoded to character spans. A span's confidence is the mean probability of its type over its
   tokens. Overlapping spans of one type from neighbouring windows are merged.
4. Spans under 0.5 confidence are dropped.

## Measured, and honest limits

These numbers come from internal evaluations whose reports are not published here. Treat them as indicative.

- Resident memory once open: about 420 MB on an x86 Linux machine (int8 file), and 450 to 580 MB on an M2 Pro
  Mac (fp16 file).
- Threads: 4 on a Mac and 8 elsewhere, never more than the machine has.
- It is a statistical model. It misses some values and flags some that are not sensitive. That is why it only
  ever **adds** masking to what the shipper sends, and never takes part in a decision.
- The confidence threshold (0.5) is not tuned.
- The optional intent model (`RealSpartaDetector(intent=True)`, "does this action fit the task?") is **not
  shippable**: test AUC 0.836. It is off by default and the engine never asks for it.
- The CoreML path on macOS is not proven. The runtime uses ONNX Runtime's CPU provider everywhere.
