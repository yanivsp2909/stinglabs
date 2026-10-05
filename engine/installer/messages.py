"""Every way this can fail, and what to do about it.

⚠ A TRACEBACK IS NOT A MESSAGE. It tells the reader that software broke, in the
vocabulary of the software rather than of the person. Every function here names
the THING TO FIX and, where there is one, the exact command that fixes it.

Kept in one file so the failures can be read as a set. Scattered through the
code they drift into five different tones, and the fifth one is always a raw
exception somebody forgot.
"""
from __future__ import annotations

import platform
import sys
from pathlib import Path

MIN_PYTHON = (3, 11)


def wrong_python() -> str:
    running = ".".join(str(n) for n in sys.version_info[:3])
    need = ".".join(str(n) for n in MIN_PYTHON)
    hint = ("brew install python@3.12" if platform.system() == "Darwin"
             else "your distribution's python3.12 package")
    return (
        f"Python {running} is too old — this needs {need} or newer.\n"
        f"\n"
        f"  why      the engine uses StrEnum, which arrived in 3.11. On an older\n"
        f"           interpreter it fails at IMPORT, which in a hook means every\n"
        f"           tool call errors rather than being decided.\n"
        f"  fix      install a newer Python ({hint}) and re-run this with it:\n"
        f"             python3.12 install.py\n"
        f"  running  {sys.executable}")


def no_agent_found(searched) -> str:
    lines = "\n".join(f"             {p}" for p in searched)
    return (
        "No coding agent was found on this machine.\n"
        "\n"
        "  why      the guard runs as a HOOK inside an agent. With no agent\n"
        "           there is nothing to hook into, and installing would leave\n"
        "           files that never run.\n"
        "  looked   for a marker directory belonging to each supported agent:\n"
        f"{lines}\n"
        "  fix      install one of: Claude Code, Cursor, Codex, Copilot,\n"
        "           Antigravity — then re-run this.\n"
        "  or       if an agent IS installed somewhere unusual, pass it\n"
        "           explicitly:  install.py --agent claude-code")


def collector_unreachable(url: str, detail: str) -> str:
    return (
        f"The collector at {url} did not answer.\n"
        f"\n"
        f"  detail   {detail}\n"
        f"  why      nothing is lost — the hook still decides and still writes,\n"
        f"           and the shipper keeps records locally until it can send\n"
        f"           them. But nothing will reach a collector until this works.\n"
        f"  check    is it running?      curl -s {url}/healthz\n"
        f"           right address?      on Tailscale, `tailscale ip -4` on the\n"
        f"                               COLLECTOR machine, not this one\n"
        f"           can you see it?     tailscale ping <that address>\n"
        f"  fix      correct the URL and re-run, or pass --no-collector to\n"
        f"           install everything else and set it up later.")


def bad_token(url: str) -> str:
    return (
        f"The collector at {url} rejected this device's token.\n"
        f"\n"
        f"  why      the collector answers 401 for a missing header, an unknown\n"
        f"           token and a wrong one, deliberately — it will not tell a\n"
        f"           caller which, because that is a device-enumeration oracle.\n"
        f"           So this cannot say which of the three it was either.\n"
        f"  check    on the COLLECTOR machine, the token file it loaded:\n"
        f"             cat <the collector's device-token store>\n"
        f"           the device id in it must match the one given here, and the\n"
        f"           token must match character for character.\n"
        f"  fix      re-run with the right value:\n"
        f"             install.py --device-token '<token>' --device-id '<id>'")


def no_write_permission(path: Path, detail: str) -> str:
    return (
        f"Cannot write to {path}.\n"
        f"\n"
        f"  detail   {detail}\n"
        f"  why      the install needs its own directory under your home. It\n"
        f"           does NOT need sudo, and if it seems to, something is\n"
        f"           wrong with the path rather than with the permissions —\n"
        f"           installing a per-user hook as root produces files the\n"
        f"           agent cannot read.\n"
        f"  check    ls -ld {path.parent}\n"
        f"  fix      make it writable, or choose another location:\n"
        f"             STING_INSTALL_ROOT=~/somewhere-else install.py")


def roots_declined(proposal: dict) -> str:
    siblings = "\n".join(f"             {p}" for p in proposal["proposed"])
    return (
        "STING_ROOTS was left unset, and that has a measured cost.\n"
        "\n"
        "  what      the guard treats anything outside the declared roots as\n"
        "            OUTSIDE your project, so an ordinary edit to a sibling\n"
        "            repository reads as writing secret-derived content out.\n"
        "  measured  74 of 89 secret-rule denials in one real period were\n"
        "            exactly that, and every one was ordinary work.\n"
        "  declined  " + (f"these were offered and not accepted:\n{siblings}"
                           if proposal["proposed"] else "nothing was found to offer") + "\n"
        "  fix       re-run and accept, or set it yourself:\n"
        f"              export STING_ROOTS='{proposal['value']}'\n"
        "  note      this is deliberate. A trust boundary is a declaration, so\n"
        "            it is confirmed and never inferred — the installer will\n"
        "            not widen it for you.")


def preflight_failed(count: int = 0) -> str:
    """⚠ IT DOES NOT CLAIM A COUNT. The first version printed preflight's EXIT
    CODE as though it were the number of failures — "Preflight reported 1
    failure(s)" when two lines had failed. A number that is not a measurement is
    worse than no number, and this file exists to say true things."""
    return (
        "Preflight reported failures above, so the install is NOT known to\n"
        "be working.\n"
        f"\n"
        f"  why      a green install that reports to nothing is the failure this\n"
        f"           whole design exists to prevent. Each line above names what\n"
        f"           it checked; fix those and re-run:\n"
        f"             python3 tools/preflight.py\n"
        f"  note     everything that was placed is still placed. This is a\n"
        f"           report, not a rollback.")


def already_installed(current: str, incoming: str) -> str:
    return (
        f"Reinstalling over {current}.\n"
        f"  new version   {incoming}\n"
        f"  ⚠ outstanding one-shot grants will be REVOKED — a grant approves one\n"
        f"    action under one policy, and this changes the policy.")


# ──────────────────────────────────────────── what leaves this machine
#
# ⚠ ONE DISCLOSURE, BECAUSE THERE IS ONE THING THAT SHIPS (28 Sep 2026). The
# installer prints it in section 5, and writes the agreement only after it has.

TIERS_ARE_GONE = ("sting: --tier is gone: there are no tiers any more, and every "
                  "record ships whole with every value Sting recognises replaced "
                  "by its type; nothing was changed, run install.py without --tier")


def what_ships() -> list[str]:
    """Section 5's lines: what ships, what Sting recognises, and what it does
    not — the limit stated as plainly as the promise."""
    return [
        "  every record ships whole — the command, the cwd, the paths, the",
        "  reason — with every value Sting recognises replaced by its type:",
        '      curl -H "Authorization: Bearer [token]" https://api.… -d owner=[email]',
        "  recognised   credentials by their vendor's format ([aws-key],",
        "               [github-token], …), values this session read from a",
        "               secret file ([secret-from-.env]), values your org's",
        "               policy declares ([org-sensitive]), email addresses,",
        "               phone numbers ([phone]), card numbers ([card]), IP",
        "               addresses ([ip]), ID numbers ([id-number]: an Israeli",
        "               ID, a US SSN), bank accounts ([bank-account]: an IBAN),",
        "               MAC addresses ([mac]), and values named as secrets:",
        "               Authorization:, user:pass@host, --password, api_key=,",
        "               \"token\":",
        "  by its key   a value a key names as personal: passport=",
        "               ([passport]), dob: ([birth-date]), account_number=,",
        "               iban=, swift= ([bank-account]), ssn=, tax_id=",
        "               ([id-number]), address:, zip= ([address]), ת.ז:,",
        "               מספר חשבון: — a key only, never the word in a sentence",
        "  folders      the account name in a home folder ships as [user]",
        "               (/Users/[user]/project), unless your org's policy says",
        "               folder_names: send",
        "  ⚠ a value Sting does not recognise leaves AS WRITTEN: a password in",
        "    an unusual spot (mysql -pX, a positional argument), a person's",
        "    name, a hostname, and anything else a heredoc carries.",
        "  fingerprints a record's `hash` and `prev` are keyed with a secret that",
        "               never leaves this laptop (~/.sting/.env.fingerprint), so",
        "               nothing can check a guess of a masked value against them;",
        "               the raw command's own digest is not sent at all.",
    ]


def way_out(allow_once: object) -> list[str]:
    """The person's way out of a refusal, said at install (docs/108 §3).

    ⚠ NOT IN WHAT AN AGENT READS. An agent handed the allow-once command could
    arm its own grant, and the floor refuses an agent that runs it. Claude Code
    and Cursor show it to the person at the refusal, in a field the model does
    not read; the other three agents have none, so the person reads it here."""
    return [
        "  blocked?  the agent is told to stop and tell you. You can act",
        "            from your own terminal, where the hook does not run:",
        f"              python3 {allow_once}   allow the last refusal once",
        '              ~/.sting/policy.json  {"rules": {"<rule id>": "ask"}}',
        "            (Claude Code and Cursor also show you this at the refusal.)",
    ]


def tier_dropped(before: str, env_file: str) -> list[str]:
    """What this install changes for a machine that recorded a tier. Said once:
    the env file is rewritten without it."""
    if before.strip().casefold() == "full":
        return [
            f"  your last install recorded STING_TIER={before!r}, which sent every",
            "  value as written. From this install on, what ships is the above:",
            "  less than before.",
            f"  dropped    STING_TIER, from {env_file}: tiers are gone",
        ]
    return [
        "  ⚠ THIS SENDS MORE THAN YOUR LAST INSTALL AGREED TO.",
        f"    It recorded STING_TIER={before!r}: no command text, no cwd, no",
        "    paths. From this install on, every command ships, masked as above.",
        "    Until this install, the shipper sent nothing new from this machine",
        "    rather than send that without you seeing it.",
        f"  dropped    STING_TIER, from {env_file}: tiers are gone",
    ]
