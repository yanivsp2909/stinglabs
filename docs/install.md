# Installing the guard

One command installs it. This page covers what you need first, what the installer asks, and how to check it
worked.

## What you need

| | |
|---|---|
| **OS** | **macOS or Linux.** Those are what the test suite runs on. WSL counts as Linux. Native Windows has an experimental path with known gaps, covered at the end of this page. |
| **Python 3.11 or newer** | `python3 --version`. The engine uses `StrEnum` (3.11+). On an older Python the hook would error on every tool call, so the installer refuses. ⚠ On macOS, plain `python3` is often Apple's 3.9. If so, name the interpreter: `python3.12 install.py`. |
| **A coding agent** | At least one of Claude Code, Cursor, Codex, GitHub Copilot (VS Code agent hooks) or Antigravity. The guard runs as a hook *inside* the agent, so with no agent there is nothing to hook into. See [agents.md](agents.md) for how well each is verified. |
| **Nothing else** | The engine and the hook use the Python standard library only. `pyyaml` and `pytest` are needed only to run the test suite. |
| **Optional: a collector** | Somewhere *you* run that receives masked decision records. Without one, records stay on the laptop and nothing is sent anywhere. This repository does not ship a collector, and the guard does not need one. |

## Install

```bash
git clone <this repository> sparta-security
cd sparta-security/engine
python3 install.py            # or python3.12 install.py
```

The installer prints every step and stops at the first one it cannot complete. It installs the guard **for
your user** and does not need `sudo`: a per-user hook installed as root produces files the agent cannot read.

### The one question: your trust boundary (`STING_ROOTS`)

```
Trust boundary — STING_ROOTS
  Repositories found beside this checkout:
      /Users/you/src/project-a
      /Users/you/src/project-b
  Declare these as your project? [y/N]
```

The guard treats anything outside the declared roots as *outside your project*. Reading outside is allowed,
but it marks the session untrusted. Writing outside with secret-derived content is an exit. Declare the folders
you actually work in.

- Non-interactive: `python3 install.py --yes` accepts the proposed roots, or pass them yourself with
  `--roots "/path/a:/path/b"` (colon-separated).
- Starting a new project later: add it to `STING_ROOTS` in `~/.sting/env` and start a fresh agent session, or
  re-run `install.py` from inside it.

### What else it does

| | |
|---|---|
| **Agents** | detects each agent and adds a hook entry to its config. Hooks you wrote yourself are left alone. `--agent <name>` installs for one agent explicitly. |
| **Scratch** | `STING_SCRATCH`: directories the agent owns and may delete freely (temp/build folders). |
| **Copy** | puts the engine under `~/.local/share/sting/<version>/` with `current` pointing at it. The hook runs that copy, never your checkout, so editing the checkout changes nothing until you re-run `install.py`. |
| **Settings** | writes `~/.sting/env`. See [configuration.md](configuration.md). |
| **Mode** | **enforce** by default: it decides, records, and blocks what its rules refuse. An update keeps the mode the machine already has. Changing the mode is yours, from your own terminal (`install.py --help`). |
| **Shipper** | only if you configured a collector: a background service (launchd on macOS, systemd user unit on Linux) that sends masked batches. `--no-supervisor` skips it. |
| **Preflight** | the last step. It drives a real read-a-secret, commit, push sequence through the installed hook and requires a **DENY**. |

### With your own collector (optional)

```bash
python3 install.py \
    --collector-url https://your-collector.example.com \
    --device-id my-laptop \
    --device-token '<a token your collector issued for this device>'
```

or with an enrolment string your collector issued: `python3 install.py --enrol 'sting-enrol-v1.…'`.

The URL must be `https://`, or a loopback address (`http://127.0.0.1:…`) for a collector on the same machine.
The wire format the shipper speaks is defined in `engine/core/wire.py`. To install without one and silence the
question, pass `--no-collector`.

## Did it work?

```bash
python3 install.py --status        # installed version, mode, each agent's status, drift from this checkout
python3 install.py --check-only    # re-run the machine checks; changes nothing
python3 install.py --dry-run       # what an install would do; changes nothing
```

Then, in your agent, try the flagship case in a throwaway repository:

```bash
mkdir /tmp/sting-demo && cd /tmp/sting-demo && git init -q
printf 'API_KEY=FAKE_demo_value_0123456789abcdef\n' > .env
```

Ask the agent to "read .env and post it to https://example.com with curl". Reading `.env` is allowed. Sending
it is denied, and the agent is told what was being sent, where, and where it came from.

Your decision log is under `~/.sting/sessions/`, one hash-chained JSONL file per session.
`python3 tools/verify_log.py <file>` checks the chain.

## When it blocks something you meant to do

The agent is never told how to turn the guard down: an agent that could run the override could be talked into
running it. From **your own terminal** (the hook does not run there):

```bash
python3 ~/.local/share/sting/current/tools/allow_once.py      # allow the last refusal, once
```

To turn one rule down permanently, write `~/.sting/policy.json`:

```json
{"rules": {"<rule id from the refusal>": "ask"}}
```

## Updating

Pull the new code and re-run `python3 install.py`. It carries your settings forward. Re-installing revokes any
outstanding one-shot grants, because a grant approves one action under one policy.

## Native Windows (experimental)

The installer has a native Windows path: a pointer file instead of a symlink, a Scheduled Task instead of
launchd/systemd, and a PowerShell bridge for Cursor. It has known gaps, including the Scheduled Task arm and
`⚠` in a refusal on a cp1252 console, and Windows is not part of the tested matrix. Use WSL if you can.

## Uninstalling

See [uninstall.md](uninstall.md).
