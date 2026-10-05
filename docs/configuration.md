# Configuration

The guard is configured by `~/.sting/env`, a file of `export KEY='value'` lines that `install.py` writes and
re-running `install.py` carries forward. An exported environment variable overrides the file for every setting
except `STING_SHIPS` (below). After editing the file, start a fresh agent session. For shipper settings,
restart the shipper or re-run `install.py`.

Nothing in the guard points at any particular company's infrastructure. With no collector configured, nothing
leaves the machine.

## The trust boundary

| setting | meaning |
|---|---|
| `STING_ROOTS` | Colon-separated directories that are *your project*. Reads outside are allowed but mark the session untrusted. Writes outside, and exits of secret-derived data, are judged. **The most important setting.** |
| `STING_SCRATCH` | Colon-separated directories the agent owns (temp/build output). Deleting inside them is not "irreversible". |

## Mode

| setting | meaning |
|---|---|
| `STING_OBSERVE` | `1`: observe mode, which decides and records but never blocks. `0` or unset: enforce (the default). Changing the mode is yours, from your own terminal (`install.py --help`). The guard refuses an agent that tries to change it. |
| `~/.sting/policy.json` | Per-rule overrides, e.g. `{"rules": {"irreversible_action": "ask"}}`. The rule id is printed in every refusal. `STING_POLICY` points at another file. |

## Where things live

| setting | default | meaning |
|---|---|---|
| `STING_SESSION_ROOT` | `~/.sting/sessions` | decision logs and per-session state |
| `STING_INSTALL_ROOT` | `~/.local/share/sting` | the installed copy the hook runs |
| `STING_SHIPPER_STATE` | `~/.sting/shipper` | the shipper's cursor |
| `STING_AGENT` | (from `--agent`) | the agent label stamped on records. The installer writes `--agent <name>` into each hook command. |

## Shipping to your own collector (optional)

All of these are empty by default, and then the shipper does not run and nothing is sent.

| setting | meaning |
|---|---|
| `STING_COLLECTOR_URL` | e.g. `https://your-collector.example.com`. Must be `https://`, or loopback `http://127.0.0.1:…` for a collector on the same machine. The collector's own host is the one host a session may reach without it counting as unexpected egress. |
| `STING_DEVICE_ID` | this machine's name at the collector |
| `STING_DEVICE_TOKEN` | the credential your collector issued for this device. ⚠ Treat it like any secret. `~/.sting/env` is created `0600`. |
| `STING_SHIPS` | **read from the file only, never the environment.** `install.py` writes `masked` after showing you what ships. Without it, the shipper holds every record on disk and sends nothing. |
| `STING_SHIP_INTERVAL`, `STING_SHIP_RECORDS` | flush every N seconds or N records |
| `STING_HEARTBEAT_INTERVAL` | seconds between heartbeats |
| `STING_POLICY_SECONDS` | how often the shipper polls the collector for an org policy (default 900) |
| `STING_REDACT_PII` | `1` adds person-name masking (`[person]`) through spaCy and `en_core_web_sm`, which you install yourself. If it is on and spaCy is missing, the shipper refuses to send rather than ship names unmasked. E-mails are always masked. |

**What ships:** every record whole, with every value the guard recognises replaced by its type, e.g.
`curl -H "Authorization: Bearer [token]" … owner=[email]`, plus `[phone]`, `[card]`, `[ip]`, `[id-number]`,
`[bank-account]`, and `/Users/[user]/…` for home folders. A record's `hash` and `prev` are sent as HMAC under a
per-laptop key (`~/.sting/.env.fingerprint`) that never leaves the machine, so nobody can check a guess of a
masked value against them. A value the guard does not recognise leaves as written. That gap is what Sparta is
for.

## Sparta (optional)

| setting | meaning |
|---|---|
| `STING_SPARTA` | `1` turns Sparta enrichment on in the **shipper**. Anything else, or unset, is off: no import, no model, the shipper exactly as without it. Default off. |
| `STING_SPARTA_TAINT` | read only when `STING_SPARTA=1`. Reserved for seeding taint from Sparta's findings. **Not built**: when on, the shipper says so once and does nothing more. Default off. |
| `SPARTA_MODELS_DIR` | where Sparta's model folders are, if not `sparta/models/` beside the package |

See [sparta.md](sparta.md).

## Rarely needed

| setting | meaning |
|---|---|
| `STING_NO_DAEMON` | `1`: decide in the hook process and never start the resident daemon (slower per call, simpler) |
| `STING_LOCK_TIMEOUT` | how long the hook waits for a session's lock |
| `STING_SIGNUP_URL` | a page `install.py` opens to obtain an enrolment string from *your* collector. Unset by default. |
