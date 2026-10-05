# sparta-security

**Sting** is a deterministic, local, runtime **provenance guard for AI coding agents**. It sits inside Claude
Code, Cursor, Codex, GitHub Copilot or Antigravity as a pre-tool hook and decides **allow / ask / deny** for
every action the agent takes, based on **where the data that action moves came from**.

**Sparta** is an optional small local model that tags secrets and personal data in text. It enriches what the
guard's shipper sends to *your* collector. It is never in the decision path.

> Everyone else asks *"is this command dangerous?"*
> Sting asks *"is this command dangerous **given what already happened in this session**?"*

- **Deterministic.** No model in the decision path. The same session history gives the same verdict, every
  time. The engine and the hook use only the Python standard library.
- **Local.** Decisions are made on the laptop, in milliseconds, and recorded in an append-only, hash-chained log
  on the laptop. Nothing leaves the machine unless you configure a collector of your own.
- **Provenance, not patterns.** Reading a secret is allowed: reading is not leaking. The guard fingerprints what
  was read, follows it through copies, redirects, variables and `git add`, and blocks at the step where it
  would leave: a push, a network call, an upload, a write outside your project.
- **Honest limit.** If an agent reads a secret and then assembles it **purely in its own context**, re-typing
  it transformed into a later action with **no traced write** in between, there is no provenance to follow.
  Exact values are still caught by fingerprint and known credential formats by shape, but a model rewriting a
  secret in its head is a residual this design does not close. The other limits are in
  [engine/README.md](engine/README.md#honest-limits).

## How it works

![Data flow: the agent's action goes through the hook to the deterministic engine, which answers allow, ask or deny; the decision is recorded locally; an optional shipper sends masked records to your collector, optionally enriched by Sparta](docs/diagrams/data-flow.svg)

*The decision path (top) is deterministic and local: the hook turns the agent's tool call into an `Action`, the
engine decides from that action plus the session's state, and the verdict goes back to the agent. Everything
below runs afterwards, off the hook. The record is written locally. The shipper, only if you configured a
collector, sends masked batches. Sparta, only if you turn it on, adds masks to what is sent. Neither can change
a verdict.*

![Provenance: in scenario I02 a poisoned issue gets the agent to read .env, copy it to debug/.env, then commit and push; the reads and the copy are allowed, the commit and push are denied because the data traces back to .env; the identical push in a clean session is allowed](docs/diagrams/provenance.svg)

*Every action in this attack looks harmless on its own, and `git push origin main` is the most trusted
destination there is. The guard blocks the commit and the push because what they carry traces back to the
`.env` read at step 2. The same command in a clean session is allowed. Both verdicts come from running the
repository's own scenarios: `python3 engine/runner/replay.py --only I02-commit-into-pr-branch --verbose`.*

## What you need

| | |
|---|---|
| **OS** | macOS or Linux (WSL counts as Linux). Native Windows is experimental. |
| **Python** | **3.11+** for the guard. Sparta runs on 3.10+, but install it into the same interpreter as the guard. |
| **An agent** | Claude Code, Cursor, Codex, GitHub Copilot (VS Code agent hooks) or Antigravity. Claude Code is the fully verified integration. See [docs/agents.md](docs/agents.md). |
| **Dependencies** | none for the guard. Sparta needs `numpy`, `onnxruntime` and `tokenizers`. The test suites need `pytest` (and `pyyaml` for the engine). |
| **A collector** | optional. Without one, nothing leaves the machine. No collector ships with this repository. |

## Install

```bash
git clone <this repository> sparta-security
cd sparta-security/engine
python3 install.py              # on macOS, maybe python3.12 install.py
python3 install.py --status
```

The installer asks one question, your **trust boundary** (`STING_ROOTS`, the folders that are your project),
wires a hook into each agent it finds, and finishes with a preflight that drives a real read-a-secret, commit,
push sequence through the installed hook and requires a DENY. Full guide: [docs/install.md](docs/install.md).

**Uninstall:** `python3 install.py --uninstall`. It removes the hooks, the service, the daemon and the
installed copy, and deliberately keeps your decision logs in `~/.sting`. See [docs/uninstall.md](docs/uninstall.md).

## Running the engine with Sparta

Sparta changes what is **sent to your collector**, never what is **decided**, so it matters only on a machine
that ships to a collector.

```bash
python3.12 -m pip install -e ./sparta          # the same interpreter you ran install.py with
# download the model files from this repository's GitHub Releases into sparta/models/ (see sparta/README.md)
python3.12 -c "from sparta.sting_detector import make_detector; make_detector()"   # opens the model, or says what is missing
```

| to | do |
|---|---|
| **enable** | add `export STING_SPARTA='1'` to `~/.sting/env`, then restart the shipper (re-run `python3 install.py`) |
| **disable** | remove that line or set `STING_SPARTA='0'`, and restart the shipper. With it off, nothing is imported. |
| `STING_SPARTA_TAINT` | reserved and **not built**: seeding taint from Sparta. With it on, the shipper says so once and does nothing else. |
| model files | `sparta/models/sparta-secrets/{tokenizer.json, tags-fp16/ (macOS), tags-int8-dynamic-keepmlp/ (Linux/x86)}`, or anywhere via `SPARTA_MODELS_DIR` |

Model weights are **not in git**. They are published as GitHub Release assets with their sha256
([sparta/README.md](sparta/README.md#the-model-files)). If a release has no model assets yet, the weights have
not been published, and the guard works fully without them. Details: [docs/sparta.md](docs/sparta.md).

## What is tested, and what is in progress

| | |
|---|---|
| **Engine decisions** | ~10,000 unit and integration tests (`cd engine && python3 -m pytest tests -q`). 107 replayable scenarios: **attacks 43 blocked, 6 blocked earlier in the chain, 16 ask, 14 missed of 79; normal tasks 25 of 25 allowed, 0 false positives** (`python3 engine/tools/grade_engine.py`). These are synthetic traces, so treat them as regression data, not a benchmark. |
| **Install / uninstall** | tested against fake `launchctl`/`systemctl` and temp homes, plus an installed-hook preflight on every real install. macOS and Linux are the supported platforms. |
| **Claude Code** | schema and payload verified against the real agent |
| **Cursor** | schema verified, payload never captured |
| **Codex, Copilot, Antigravity** | adapters pass the conformance suite, but schema and payload are **unverified** against the real agents, and the installer says so |
| **Native Windows** | experimental, with known gaps. Not in the tested matrix. |
| **Shipper and masking** | tested. No collector ships here; the wire format is `engine/core/wire.py`. |
| **Sparta contract and adapter** | tested with a fake detector and on synthetic logits |
| **Sparta real-model tests** | run only when the weights are present |
| **Sparta-seeded taint** (`STING_SPARTA_TAINT`) | not built |
| **Sparta intent model** | not shippable (test AUC 0.836), off by default |
| **Some engine tests** | skip in this repository: they need redacted real decision logs, which are not published (`engine/tests/private_fixtures.py`) |

## Repository layout

```
engine/      the guard: hook, adapters, engine, installer, shipper, scenarios, tests   (engine/README.md)
sparta/      the Sparta model package: detector, span decoding, tests, no weights      (sparta/README.md)
docs/        install, uninstall, configuration, Sparta, agents, diagrams
LICENSE      Apache-2.0
NOTICE       third-party credential-format rules the engine's detector transcribes
```

## Docs

[Install](docs/install.md) · [Uninstall](docs/uninstall.md) · [Configuration](docs/configuration.md) ·
[Sparta](docs/sparta.md) · [Agents](docs/agents.md) · [Adapter contract](engine/docs/24-adapter-contract.md) ·
[Engine layout](engine/docs/ENGINE_LAYOUT.md)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
