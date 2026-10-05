# Running the engine with Sparta

Sparta is the optional local model in [`sparta/`](../sparta/README.md). Before enabling it, know where it sits:

- **It is not in the decision path.** The hook, the daemon, the adapters and `engine/core/` never import it.
  A test (`engine/tests/test_sparta_never_decides.py`) scans them for the name. Allow / ask / deny is decided
  by deterministic code alone, the same with or without Sparta.
- **It runs in the shipper, after the decision**, while a batch of records is built to send to *your*
  collector. It can **add** masks to what leaves the machine and record where it suspected something
  (`sparta_suspected`: field, offsets, type, confidence, never the value). It cannot remove a mask, and it
  cannot change a verdict.
- **It fails open.** If the package cannot be imported, the model files are missing, the model raises, or it
  answers late (load budget 120 s, 2 s per call), records ship with deterministic masking only and the shipper
  says so once.

Because the shipper only runs when a collector is configured, **Sparta has no effect on a machine without a
collector.** You can still run the detector directly (below).

## 1. Install the package into the guard's Python

The shipper imports `sparta.sting_detector` by name, so the package must be importable **by the same Python
interpreter that ran `install.py`** (the installer records that interpreter for the hook and the shipper).

```bash
cd sparta-security
python3.12 -m pip install -e ./sparta        # use the interpreter you ran install.py with
```

Use `-e` (editable) so the package stays beside its `models/` folder, or set `SPARTA_MODELS_DIR` instead.

## 2. Put the model files in place

⚠ **The trained weights are distributed as GitHub Release assets, not in git.** Download them from this
repository's Releases page and lay them out as `sparta/models/sparta-secrets/…`. The exact layout and the
sha256 of every file are in [`sparta/README.md`](../sparta/README.md#the-model-files). You need
`tokenizer.json` plus the one model file for your platform (`tags-fp16` on macOS, `tags-int8-dynamic-keepmlp`
elsewhere).

Check the model opens:

```bash
python3.12 -c "from sparta.sting_detector import make_detector; d = make_detector(); print(d.detect('export TOKEN=abc123def456ghi789'))"
python3.12 -m pytest sparta/tests/test_detector_real.py -q     # runs (rather than skips) once the files are there
```

## 3. Turn it on

Add to `~/.sting/env`:

```bash
export STING_SPARTA='1'
```

Then restart the shipper so it reads the setting. Re-running `python3 install.py` from `engine/` does that and
keeps your settings. `python3 install.py --status` shows the shipper's state.

## 4. Turn it off

Remove the line, or set `export STING_SPARTA='0'`, and restart the shipper the same way. With the flag off,
nothing is imported and the shipper behaves exactly as if Sparta did not exist.

## `STING_SPARTA_TAINT`

Reserved for a future step: seeding the *next* action's taint from what Sparta found. **It is not built.** With
`STING_SPARTA=1` and `STING_SPARTA_TAINT=1`, the shipper says once that taint seeding is not implemented, and
does nothing else. It is read only when `STING_SPARTA=1`.

## What is tested, and what is not

| | status |
|---|---|
| the engine-side contract (`engine/shipper/sparta_iface.py`): flags, span validation, fail-open loading, time limits | tested, with a fake detector (`engine/tests/test_sparta_*.py`) |
| the adapter `sparta.sting_detector`: shape of answers, offsets, types | tested on synthetic logits, no weights (`sparta/tests/`) |
| the real model's output on real text | `sparta/tests/test_detector_real.py`, which runs only when the weights are present |
| Sparta seeding taint (`STING_SPARTA_TAINT`) | **not built** |
| the intent model | **not shippable** (test AUC 0.836), off by default, never requested by the engine |
