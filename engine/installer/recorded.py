"""What the LAST install recorded — read back, so a partial re-run keeps it.

⚠ THE DEFECT THIS EXISTS FOR, MEASURED ON THIS MACHINE RATHER THAN IMAGINED.
`install.py` read the collector URL, the device token and the device id from
flags or from the process ENVIRONMENT, and never from the `~/.sting/env` it had
written itself. `--tier` defaulted to LOCATED and `--observe` defaulted to True.
So a developer re-running the installer for one reason — a changed tunnel URL,
which the runbook says WILL happen — got:

    the collector      DROPPED, unless it happened to be exported in that shell
    enforce mode       SILENTLY REVERTED to observe
    the tier           SILENTLY RESET to the default

and the plan printed on the way looked right, because every value in it was a
real value. It just was not theirs. This machine is the proof: at 20:49 its
`~/.sting/env` and its supervisor plist both carried STING_COLLECTOR_URL,
STING_DEVICE_ID and STING_DEVICE_TOKEN. After a reinstall at 23:47 neither does,
and nothing said so. The device has been configured to ship to nothing since.

────────────────────────────────────────────────────────────────────────────────
THE RULE, AND THE OBJECTION IT HAS TO SURVIVE
────────────────────────────────────────────────────────────────────────────────

    a flag given EXPLICITLY always wins
    a setting NOT given is CARRIED FORWARD from the recorded install
    anything carried forward is PRINTED as carried, in the plan, with its source

⚠ THE OBJECTION: an installer that trusts its own previous output is how a WRONG
value becomes permanent — a bad URL would survive every reinstall meant to fix
it. That objection is real and it is answered by the first line rather than
dismissed: **every carried setting has an explicit flag that overrides it**, and
overriding is precisely what a developer re-running the installer is doing.
`--collector-url` replaces a bad URL, `--no-collector` removes it, and
`--observe` and `--enforce` each state a mode outright.

⚠ THE TIER IS NO LONGER CARRIED, BECAUSE THERE IS NONE (28 Sep 2026). A file
that still holds `STING_TIER` has it dropped by the next install, which says so
once; what ships is `STING_SHIPS`, written fresh by every install after it
prints what ships, and never carried.

⚠ AND THE ESCAPE HATCH MUST NOT REQUIRE READING THIS FILE. `install.py --status`
prints every recorded value and the flag that overrides it, and the env file is
a documented 0600 file the operator may edit or delete — deleting it makes the
next install start from proposals again. An escape hatch nobody can find is not
one.

⚠ PARSED, NEVER SOURCED. The file is `export KEY='value'`, written by this
installer, and sourcing it would execute whatever a later editor put in it —
the same rule `shipper/config.read_env_file` already follows.
"""
from __future__ import annotations

from pathlib import Path

ENV_FILE = Path.home() / ".sting" / "env"

# Everything this installer writes into the env file, and therefore everything a
# re-run could silently discard. Order is the order they are reported in.
CARRIED = ("STING_COLLECTOR_URL", "STING_DEVICE_ID", "STING_DEVICE_TOKEN",
            "STING_OBSERVE", "STING_ROOTS", "STING_SCRATCH")

# ⚠ WHAT A REINSTALL MUST *NOT* CARRY, so the boundary is a decision and not an
# omission. These are not preferences; they are facts about the install being
# made, and carrying one forward would be recording something untrue:
#
#   guard_version / installed_at / source_commit   recomputed from the tree
#   one-shot grants                                REVOKED, deliberately — a
#       grant approves ONE action under ONE policy, and a reinstall is the
#       moment the policy changes. See installer/place.py; this is the one
#       reset that is load-bearing rather than incidental.
#   STING_SESSION_ROOT                             a constant this installer
#       owns; it is written fresh every time and there is nothing to remember.
#   STING_PURPOSE                                  a constant declaration, not
#       an operator preference — see core/purpose.py.
#   STING_SHIPS                                    the agreement to what ships,
#       written by the install that printed it; an agreement carried from a
#       run nobody read would be no agreement (shipper/config.HELD).
NEVER_CARRIED = ("guard_version", "installed_at", "one-shot grants",
                  "STING_SESSION_ROOT", "STING_PURPOSE", "STING_SHIPS")


def read(path: Path | None = None) -> dict:
    """`{KEY: value}` from the env file, or `{}` when there is no install.

    Never raises: a missing file is the first install, and an unreadable one is
    reported by the caller as "nothing to carry" rather than as a crash.
    """
    path = ENV_FILE if path is None else path
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip("'\"")
    return values


def resolve(given, carried_value, fallback, *, key: str):
    """(value, source) — the rule, in one place so nothing implements it twice.

    `given` is None when the flag was absent. It is NOT `""`: an explicitly
    empty flag is a real answer and must beat a carried value, which is how a
    setting gets cleared.
    """
    if given is not None:
        return given, "given on the command line"
    if carried_value not in (None, ""):
        return carried_value, f"carried forward from {ENV_FILE}"
    return fallback, "the default"


def observe_from(carried: dict) -> bool | None:
    """The recorded mode: True observe, False enforce, None never recorded.

    ⚠ ENFORCE USED TO BE RECORDED AS THE ABSENCE OF A KEY, which is working rule
    13 living inside the installer: `STING_OBSERVE='1'` was written only in
    observe mode, so "enforcing" and "no install at all" and "an install from
    before this key existed" were the same artifact. The installer now writes
    `'0'` for enforce — a value `hook_entry` already reads as false, alongside
    "", "false" and "no" — so the three states are three.
    """
    if "STING_OBSERVE" not in carried:
        return None
    return carried["STING_OBSERVE"].strip() not in ("", "0", "false", "no")
