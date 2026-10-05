# Supported agents, and how far each is verified

The guard runs as a **pre-tool hook** inside the agent: the agent hands it each tool call before running it, and
does what the guard answers. One adapter per agent translates that agent's JSON into the engine's `Action`, and
the verdict back.

| agent | `--agent` | hook config written | schema checked against the real agent | payload checked against the real agent |
|---|---|---|---|---|
| **Claude Code** | `claude-code` | `~/.claude/settings.json` (or `.claude/settings.json` in a project) | ✅ | ✅ captured payloads |
| **Cursor** | `cursor` | `~/.cursor/hooks.json` (or `.cursor/hooks.json`) | ✅ real configs + Cursor's own code | ❌ never captured |
| **Codex** | `codex` | `~/.codex/hooks.json` (or `.codex/hooks.json`) | ❌ assumed | ❌ |
| **GitHub Copilot** (VS Code agent hooks) | `copilot` | `.github/hooks/hooks.json`, **per project** | ❌ assumed | ❌ |
| **Antigravity** | `antigravity` | `~/.gemini/config/hooks.json` (or `.agents/hooks.json`) | ❌ assumed | ❌ |

`python3 install.py --status` prints the same thing per agent: `protected`, `unverified` (wired, but its schema
or payload was never checked, and it says which), `partial` (Copilot, wired for some projects only),
`not wired`, or `not found`.

**What "unverified" means in practice.** Every adapter passes the conformance suite: it never crashes on
malformed input, never renders an *ask* as *allow*, and the read-secret, commit, push sequence DENIES through it.
What has not been proven for the unverified agents is that the agent really sends the fields the adapter reads.
If it does not, the failure is **degraded coverage** (the engine does not see a command) and not a defeated
guard: an adapter can fail to show the engine something, but it cannot tell the engine that something
dangerous is safe. Details are in [the adapter contract](../engine/docs/24-adapter-contract.md).

## Per-agent notes

- **Claude Code**: the reference integration. A refusal also shows *you* (not the model) how to override it,
  through `systemMessage`.
- **Cursor**: wired on `beforeShellExecution`, `beforeReadFile` and `beforeMCPExecution`. Cursor has no
  pre-edit hook, so a file *write* through Cursor's native edit tool is invisible to the engine. The push at the
  end is still judged, but a taint established only through native edits is lost. `failClosed` is written as
  `true` in enforce mode, so a crashed or timed-out guard denies.
- **Codex**: an agent with no "ask" concept gets *ask* downgraded to *deny*, and the reason says so.
- **Copilot**: has no user-level hook config, so it is installed per project. Run `install.py` from each
  project, or pass `--agent copilot` there.
- **Antigravity**: the adapter uses the payload's `stepIdx` as the sequence number. That it is monotonic is
  assumed, not verified.

## Adding an agent

One module in `engine/adapters/` with `AGENT`, `parse`, `render` and `probe_payload`, one line in
`engine/adapters/__init__.py`, and the conformance suites:

```bash
cd engine
python3 -m pytest tests/test_adapter_conformance.py tests/test_semantic_probe.py -q
```

The whole contract: [engine/docs/24-adapter-contract.md](../engine/docs/24-adapter-contract.md).
