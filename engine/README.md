# Sting engine: the guard

This is the developer's view of the guard. For installing and using it, start at the
[repository README](../README.md) and [docs/install.md](../docs/install.md).

The engine decides **allow / ask / deny** for every tool call a coding agent makes, using **session memory**,
not a static rule list:

> Everyone else asks *"is this command dangerous?"*
> Sting asks *"is this command dangerous **given what already happened in this session**?"*

```
I02   git push origin main   ->  DENY
N04   git push origin main   ->  ALLOW
```

Same command, opposite verdicts, decided by session history alone. In `I02` a poisoned GitHub issue talked the
agent into copying `.env` into `debug/.env` and committing it. In `N04` the agent fixed a bug and pushed.

## Sensor and engine

One engine, thin adapters. The engine never sees an agent's vocabulary, and the adapters never see policy.

```
  Claude Code ──┐
  Cursor ───────┤
  Copilot ──────┼──►  adapter  ──►  Action  ──►  engine  ──►  Verdict  ──►  adapter  ──► agent
  Codex ────────┤   (per agent)   (normalised)   (one)                    (per agent)
  Antigravity ──┘
```

| layer | file(s) | job |
|---|---|---|
| **sensor** | `hook_entry.py`, `sting_hook.py` | the single process every agent's hook config invokes (with a resident daemon to avoid interpreter start-up on every call) |
| **adapters** | `adapters/*.py` | vendor payload ⟷ normalised `Action` / `Verdict`. No policy, ever. See [docs/24-adapter-contract.md](docs/24-adapter-contract.md) |
| **engine** | `core/engine.py` and the modules it re-exports | `decide(action, state, world) -> Verdict`, a **pure function**. See [docs/ENGINE_LAYOUT.md](docs/ENGINE_LAYOUT.md) |
| **state** | `core/session.py`, `core/types.py` | what this session already knows, persisted per session under a lock |
| **the machine** | `core/probes.py` | the only module in `core/` that touches the filesystem or git |
| **record** | `core/audit_log.py` | the append-only, hash-chained decision log |
| **shipper** | `shipper/` | optional, off the hook: masks records and sends them to a collector you configure |

Tests enforce two boundaries:

- **`engine.py` imports no IO module at all**: no `os`, `subprocess`, `pathlib`, no `open(`. Everything from
  outside arrives through the `World` protocol, so the whole policy is testable without a git repo.
- **No adapter contains policy vocabulary.** An adapter that needs to know *why* something was denied means the
  boundary is wrong.

### How a decision is made

1. **`check_sinks`**: is this action an *exit*? A push, a network call, a write outside the project, an MCP
   tool call, a destructive delete.
2. **`_secret_level`**: is the data *this action moves* labelled, by credential path, by a fingerprint of a
   value read earlier, or by a known credential format?
3. **the ladder**: the verdict, strongest reason first. An exact secret trace outranks a derived one, which
   outranks an untrusted destination.
4. **`mark_sources` / `propagate`**: labelling happens **after** the verdict, so an action is never judged by
   the taint it creates itself.

Labels restrict **exits**, never reads. Reading is not leaking.

## Settings at a glance

| | |
|---|---|
| **Mode** | **enforce**: it decides, records, and blocks what its rules refuse. An install enforces by default, and an update keeps the mode the machine already has. Changing the mode is yours, from your own terminal (`install.py --help`). |
| **When Sting blocks** | the agent is told what was being sent and where, where it came from, and not to retry, split or re-encode it. It is never told how to turn the guard down. From your own terminal (the hook does not run there): `python3 <install>/tools/allow_once.py` allows the last refusal once, and `~/.sting/policy.json` `{"rules": {"<rule id>": "ask"}}` turns one rule down. |

The full list is in [docs/configuration.md](../docs/configuration.md).

## Running it

```bash
pip3 install -r requirements.txt        # pyyaml + pytest, for the harness only
python3 runner/make_traces.py           # generate the synthetic traces (git-ignored)
python3 -m pytest tests -q              # the suite
python3 tools/grade_engine.py           # every scenario through the real replay path, with a reconciliation gate
python3 runner/replay.py --only I02-commit-into-pr-branch --verbose
python3 tools/verify_log.py <session.log.jsonl>   # check a decision log's hash chain
```

**The engine and the hook need nothing beyond the standard library.** The hook runs on every tool call, so a
dependency there would be a dependency in the hot path. `pyyaml` is used only by the runner, to read each
scenario's `expect.yaml`.

A few tests check the engine against redacted copies of real decision logs (`logs/live-fixture`,
`runner/live_baseline.json`). Those hold real commands from real work and are **not published**, so those tests
skip and say why (`tests/private_fixtures.py`).

## Current numbers

From `python3 tools/grade_engine.py` on this tree: synthetic traces of the scenarios in `scenarios/` (79 attacks, 25 normal tasks, 3 multi-session chains), the
actions each scenario *intends*. That makes them good for regression and rule work. **They are not a benchmark.**

```
attacks  43 blocked / 6 blocked earlier in the chain / 16 ask / 14 missed   (of 79)
normals  25 allowed / 0 false positive                                       (of 25)
```

These are two rates and are never averaged. An ASK is a prompt, not a block, and is counted separately.

## Honest limits

- **Pure in-context assembly is a residual.** If the agent reads a secret and then *types* it, transformed,
  into a later action with no traced write in between, the guard has no provenance to follow. Exact values are
  still caught by fingerprint, and known credential formats by shape. A model rewriting a secret in its own
  context is not.
- **Opaque execution.** The agent writes a script and runs it, and the exfiltration happens inside the
  subprocess, which no hook sees. Catching it needs a syscall-level sensor.
- **No data flow, no catch.** A typosquatted `pip install`, or a lockfile repointed at a hostile host, involve
  no secret and no provenance. They need package reputation and lockfile integrity, which are different
  subsystems.
- **Intent.** An agent editing files nobody asked it to touch needs a judgement about what the developer
  wanted. That is unsolved here.
- **Bounded scans.** Command and file reads are scanned up to fixed sizes. Past them is a blind spot.
- **Adapters.** Only Claude Code's hook schema *and* payload have been checked against the real agent. See
  [docs/agents.md](../docs/agents.md).

## Layout

```
hook_entry.py   sting_hook.py   the entry point every agent invokes
core/           the engine: decide(), session state, probes, audit log, allow-once
adapters/       one per agent, plus shared translation helpers
daemon/         the resident decision process the hook talks to
installer/      install.py's parts: detection, placement, the shipper's supervisor
shipper/        masking and batching for an optional collector; Sparta's hook-in
runner/         replay.py (free, offline), make_traces.py, run_corpus.py (drives a real agent)
scenarios/      107 attack and normal scenarios, each a tiny repo plus an expect.yaml
tools/          verify_log, allow_once, grade_engine, benches, preflight
tests/          the suite
```
