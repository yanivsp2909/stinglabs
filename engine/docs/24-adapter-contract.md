# Writing an adapter

**For someone who has never read `core/engine.py`, and should not have to.**

An adapter is a translator. It turns one coding agent's hook payload into the
engine's `Action`, and the engine's `Verdict` back into that agent's response
vocabulary. **It contains no policy.** If you find yourself deciding whether
something is dangerous, you are in the wrong file.

```
stdin (your agent's JSON) → adapter.parse → engine.decide → adapter.render → stdout
```

---

## The three functions

A module in `adapters/` exposing these three, plus one line in
`adapters/__init__.py`, is a complete adapter. Nothing else needs editing —
`hook_entry`, `tools/preflight.py` and the conformance suite all read the
registry.

```python
AGENT = "my-agent"          # the string a user types after --agent

def parse(raw: dict) -> Action: ...
def render(verdict: Verdict) -> str: ...
def probe_payload(command: str, *, cwd: str, session: str, step: int = 0) -> dict: ...
```

### `AGENT`

⚠ **This one string is the registry key, the `--agent` value, and the label
stamped into every record.** They must be one value, not three that happen to
match — `adapters/__init__.py` keys the registry off `mod.AGENT` for exactly
that reason. Two spellings would route correctly and label wrongly, which is the
worst kind of bug here: the guard works and the evidence points at the wrong
tool.

### `parse(raw) -> Action`

**Must never raise.** Not on `{}`, not on `None`, not on a list, not on a string,
not on `{"tool_input": {"command": 123}}`. A hook that crashes is a hook the
agent may swallow whole, leaving a guard that silently never runs. Use the
helpers in `adapters/_common.py`: `as_dict`, `as_str`, `first_str`,
`resolve_path`, `workspace_roots`.

Mandatory fields on the `Action` you return:

| field | must be |
|---|---|
| `session_id` | the agent's conversation/session id, or `"unknown"` |
| `kind` | one of `ActionKind` — how you map your events is your job |
| `cwd` | **absolute, symlinks resolved** — use `_common.resolve_cwd` |
| `paths` | **absolute, symlinks resolved** — use `_common.resolve_paths` |
| `workspace_roots` | never empty; fall back to `cwd` |
| `agent` | `AGENT` |

⚠ **Absolute and symlink-resolved is not a style preference.** On macOS `/tmp`
is a symlink to `/private/tmp`, so an adapter that left `cwd` raw while
resolving `paths` put them in two different namespaces and a taint lookup missed
silently. `_common` exists so this is written once.

⚠ **Never invent a field.** If your agent does not send a command, `command` is
`None` — not `""`, not a reconstruction from other fields. The engine
distinguishes "absent" from "empty", and a guess becomes evidence the moment it
is recorded.

### `render(verdict) -> str`

Your agent's response vocabulary. Rules:

- **ALLOW renders as the empty string.** Say nothing when there is nothing to
  say; every agent treats no output as permission.
- **DENY must render valid JSON carrying the reason**, including when the reason
  is empty.
- ⚠ **ASK must never render as ALLOW.** If your agent has no "ask" concept,
  downgrade it to DENY and *say so in the reason* — Codex does this. Silently
  turning a prompt into permission is the one translation that loses the
  product.

### `probe_payload(...) -> dict`

**One EXEC action in your agent's own shape**, carrying `command`.

⚠ **This is what proves the engine is not blind on your agent.**
`tools/preflight.py` drives the I02 sequence — read a credential, copy it,
commit it, push — through the real hook process and requires a DENY. Before this
existed the check ran for Claude Code and printed `skipped` everywhere else, so
**on the first machine that was not Claude Code, the guard against a blind guard
did not run.** An adapter without it is a FAIL, not a skip.

`step` matters if your agent's payload carries a sequence number (Antigravity
uses `stepIdx` as `seq`); ignore it otherwise.

---

## ⚠ What an adapter must NEVER be trusted to do

**An adapter parses attacker-influenced text.** A poisoned README, an issue body,
a tool result — all of it flows through your `parse`. A third-party adapter may
also simply be wrong. So the engine treats everything an adapter says as a
*claim*, and re-derives the things a wrong claim could defeat.

**The engine re-derives these regardless of what an adapter says:**

| an adapter claims | the engine does not trust it because |
|---|---|
| **the command's structure** | the engine re-tokenises `command` itself. Every blind spot found so far has been in the text→structure layer, not in a rule. An adapter that pre-split a command into "safe parts" would be deciding policy |
| **what is staged for a commit** | read from `git diff --cached` at push time, never from a payload field. Handles `.gitignore` and catches `git add -f` |
| **whether a path is a credential** | `CREDENTIAL_PATHS` runs on the resolved path. An adapter cannot mark or unmark a secret |
| **the session's taint state** | held in `SessionState`, keyed by `session_id`, written only by the engine |
| **`seq`** | the session layer assigns it. `next_seq` is authoritative |
| **workspace roots** | resolved once per session from `STING_ROOTS` and git, in `hook_entry` — not from the payload |
| **the action fingerprint** | `allow_once.fingerprint(action)` is computed engine-side; an adapter that supplied one could forge a grant |

**What a bad adapter CAN cost you — and this is the honest limit:**

- ⚠ **Coverage.** If your `parse` returns `command=None` for a real command, the
  engine sees nothing and allows it. **An adapter cannot be prevented from being
  blind**, only from being believed.
- **A wrong `kind`** sends an action down the wrong branch.
- **A wrong `agent`** mislabels records.

**So the failure mode of a badly written third-party adapter is DEGRADED
COVERAGE, not a defeated guard.** It can fail to show the engine something; it
cannot tell the engine that something dangerous is safe. That distinction is the
reason this interface can be opened to contributors at all.

⚠ **The one thing that would break it** is an adapter that returns a *plausible
but wrong* action — say, reporting `cat README.md` when the payload said
`cat .env`. Nothing here detects that, and nothing can: the adapter is the only
witness to what the agent sent. **An adapter is trusted to be honest about what
it received, and about nothing else.**

---

## ⚠ How you prove it — the conformance suite IS the specification

```bash
python3 -m pytest tests/test_adapter_conformance.py tests/test_semantic_probe.py -q
```

Add your module to `adapters/__init__.py` and both suites pick it up
automatically — every test is parametrised over the registry, so **you do not
write these tests, you pass them.**

**What a pass means, concretely:**

| | |
|---|---|
| `parse` never raises | on 15 malformed payloads, including `None`, `[]`, `42` |
| paths are absolute | and symlink-resolved |
| `workspace_roots` is never empty | even on malformed input |
| ALLOW renders empty | DENY renders valid JSON with the reason |
| ASK never renders as ALLOW | |
| no policy words in the module | `SECRET`, `tainted`, `fingerprint`, `Verdict(` |
| **the same act normalises identically** | your adapter and every other must produce the same `Action` for "run `git push origin main`" |
| ⚠ **the I02 sequence DENIES** | through your adapter, against the real filesystem |
| ⚠ **and ALLOWs when the matcher is blinded** | proving the DENY came from the engine seeing the credential, not from luck |

**What a pass does NOT mean.** It does not mean your event mapping is right for
your agent — that needs a real payload from a real session, and four of the five
adapters in this repo have never seen one. A conformance pass says the adapter is
*well-formed and honest*, not that it is *complete*.

---

## Checklist

- [ ] `adapters/<name>.py` with `AGENT`, `parse`, `render`, `probe_payload`
- [ ] one line in `adapters/__init__.py`
- [ ] both suites green
- [ ] a real config file from the real agent, read — not written from docs
- [ ] if any of it is unverified, **say UNVERIFIED in the docs and in the
      installer's own output**. `install.py` does this today for Cursor's
      `failClosed` and for the whole schema of Copilot, Codex and Antigravity
