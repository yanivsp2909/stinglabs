# Uninstalling the guard

```bash
cd sparta-security/engine
python3 install.py --uninstall
```

Run it from your own terminal. The guard refuses to let an agent run `install.py` for anything but `--status`,
`--dry-run` or `--check-only`.

## What it removes, in this order

1. **The hook entries** in every agent config it wrote (Claude Code, Cursor, Codex, Copilot, Antigravity),
   leaving any hooks you wrote yourself alone. This goes first, so no new tool call can start the guard again
   while the rest is removed.
2. **The shipper service**: the launchd agent (macOS), systemd user unit (Linux) or Scheduled Task (Windows),
   if one was installed.
3. **The resident daemon**, if one is running. It is started on demand by the hook and would otherwise idle
   for up to 30 minutes.
4. **The installed copy** under `~/.local/share/sting/`.
5. **`~/.sting/env`** (your settings), and the two policy files: `~/.sting/policy.json` and the cached org
   policy.

## What it deliberately leaves

Everything else under `~/.sting/`:

- **your decision logs** (`~/.sting/sessions/`): the record of what the guard saw and decided;
- the session state, the shipper's cursor, and the shipper's per-laptop fingerprint key
  (`~/.sting/.env.fingerprint`).

An uninstaller that deletes the record of what a guard decided is one an attacker would like to run, and
uninstalling a tool is not consent to delete the data it produced. Delete them yourself when you want to:

```bash
rm -rf ~/.sting
```

## Copilot's per-project hooks

GitHub Copilot keeps its hook config per project (`.github/hooks/hooks.json`). The installer records each
project it wrote one into, and uninstall uses that record to find them. If you moved or copied a project
afterwards, check its `.github/hooks/hooks.json` by hand.

## Sparta

Sparta is a separate Python package, and the guard's uninstall does not touch it:

```bash
python3 -m pip uninstall sparta
rm -rf sparta-security/sparta/models      # the downloaded model files
```
