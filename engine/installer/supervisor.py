"""Keeping the shipper running. The decision, and what it costs.

────────────────────────────────────────────────────────────────────────────────
THE THREE OPTIONS, AND WHY A SUPERVISOR WINS
────────────────────────────────────────────────────────────────────────────────

⚠ THE DECIDING ARGUMENT IS NOT DATA LOSS. The shipper is built so that not
running costs nothing but delay: the hook writes regardless, the cursor
remembers, and a week of backlog goes out in capped batches on the next run.
Judged on data alone, "the developer runs it" would be fine.

It is decided by the HEARTBEAT. The collector's entire liveness claim rests on
absence being meaningful — a device that stops reporting is a device to go and
look at. If the shipper only runs when someone remembers, then silence means
"they forgot", every alert is noise, and within a week nobody looks. **An
unsupervised shipper does not lose data; it destroys the signal.**

  A · A SUPERVISOR — launchd (macOS) / systemd --user (Linux)     ← CHOSEN
      adds        one plist or unit file, ~20 lines, written by install.py
      leaves      nothing, if uninstall removes it — and it does
      logout      macOS: a `gui/<uid>` agent stops at logout, restarts at login.
                  Linux: a --user unit stops at logout UNLESS the operator runs
                  `loginctl enable-linger`, which install.py PRINTS rather than
                  running, because enabling lingering changes how that account
                  behaves for every service, not just this one.
      reboot      restarts at login on both. RunAtLoad / WantedBy=default.target
      crash       restarted. KeepAlive / Restart=always.
      cost        the operator has a background process they did not write, and
                  they must be told it exists — which is why install.py prints
                  the exact path and the exact command to stop it.

  B · `--once` FROM cron
      adds        a crontab line
      leaves      a crontab line, which uninstall must edit — and editing
                  another tool's config file to remove one line is how an
                  uninstaller corrupts something
      reboot      survives, which is genuinely better than A
      cost        on macOS, cron needs Full Disk Access to read ~/.sting under
                  recent releases, and the failure is SILENT — the job runs and
                  reads nothing. A liveness mechanism whose failure mode is
                  "looks fine, reports nothing" is the exact thing being built
                  against.

  B′ · `--once` FROM THE HOOK — REJECTED OUTRIGHT
      Spawning a process on a tool call puts process CREATION on the 12 ms
      budget, even if nothing is waited on. `tests/test_shipper_isolation.py`
      asserts the hook does not so much as mention the shipper, and that test
      exists because this is the tempting shortcut.

  C · NOTHING, the developer runs it
      adds        nothing, leaves nothing, and needs no uninstall
      cost        the signal, as argued above. Kept as `--no-supervisor` for
                  someone who genuinely wants to run it by hand — the option is
                  offered, it is just not the default.

────────────────────────────────────────────────────────────────────────────────
⚠ WHAT BREAKS WHEN THE MACHINE SLEEPS, AND IT IS NOT SMALL
────────────────────────────────────────────────────────────────────────────────

Neither launchd nor systemd runs a timer while the machine is asleep. A laptop
closed at 18:00 and opened at 09:00 sends no heartbeat for fifteen hours.

  THE DATA IS FINE. The cursor resumes and the backlog ships. Nothing is lost.

  THE SIGNAL IS NOT. At the shipper's 900 s interval the collector marks a
  device STALE after 2700 s — so **an overnight sleep is indistinguishable from
  a dead guard**, and every laptop is stale every morning.

That is a real limitation and it is stated rather than tuned around. Raising the
multiple until sleep stops triggering it would mean a genuinely dead guard also
takes a working day to notice, which trades the whole point away. The honest fix
is a sleep/wake notice from the sender — the shipper would say "I am going away"
and "I am back" — and that needs a platform hook this does not have. NOT BUILT,
and named here so nobody reads a morning full of STALE devices as a bug.

────────────────────────────────────────────────────────────────────────────────
WHAT LIVES HERE, AND WHAT DOES NOT
────────────────────────────────────────────────────────────────────────────────

This module WRITES the supervisor file, LOADS the job, MIGRATES the legacy
label and REMOVES all of it. Everything that only ASKS — the label, the file
paths, `loaded()`, `status()`, `stop_command()`, `shipper_running()` — lives in
`shipper/service.py`, because that ships and this does not need to (docs/84).

⚠ EVERY REFERENCE GOES THROUGH `service.`, NEVER `from shipper.service import`.
That is what lets one monkeypatch on `shipper.service` reach `status()` and
`activate()` alike. A name imported into this module's globals would be a copy
the patch cannot see, and the test would pass against the real `launchctl`.
"""
from __future__ import annotations

import os
import platform
import subprocess
import time
from pathlib import Path
from xml.sax.saxutils import escape

from shipper import service


def _unit_escape(value: str) -> str:
    """Inside a systemd double-quoted value, `"` and `\\` are the only two
    characters that still need a backslash. Nothing here strips or rejects: a
    path is the operator's, and mangling one quietly is how a trust boundary
    ends up naming a directory that does not exist."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


# ⚠ NEVER WRITTEN INTO A SUPERVISOR FILE, ON ANY PLATFORM.
#
# All three supervisor artifacts are WORLD-READABLE and none of them needs to
# be otherwise: a launchd plist is `-rw-r--r--`, a systemd user unit the same,
# and the Task Scheduler wrapper `.cmd` inherits whatever `%LOCALAPPDATA%`
# gives it. Measured on this machine before the fix:
#
#     -rw-r--r--  ~/Library/LaunchAgents/dev.sting.shipper.plist
#         <key>STING_DEVICE_TOKEN</key><string>&lt;the real token&gt;</string>
#
# That is the credential authenticating this machine to the collector, in
# cleartext, on the machine running the agent being watched — readable by the
# agent, by every process the user runs, and by anything that walks $HOME.
#
# ⚠ AND IT IS PURE REDUNDANCY, WHICH IS WHY REMOVING IT COSTS NOTHING.
# `shipper/config.from_env` already reads EVERY setting from `~/.sting/env`
# (0600), with the environment winning where both exist — that stopped being
# tier-only when the first native Windows install found the shipper reading one
# key from its own file. So the token reaches the shipper by the private route
# whether or not the public file repeats it.
#
# The same reasoning that took the env prefix out of `hooks.json`, applied to
# the file nobody swept when that was fixed: a setting the guard needs does not
# belong in a file the thing being guarded can read.
SECRETS = ("STING_DEVICE_TOKEN",)


def public_env(env: dict) -> dict:
    """`env` minus anything that authenticates this machine.

    ⚠ A DENY-LIST, AND THE CHOICE IS DELIBERATE RATHER THAN LAZY. An allow-list
    would silently DROP any setting a later pass adds — and a shipper missing a
    setting fails in ways nobody traces back to here, while a shipper carrying
    one variable too few of a NON-secret still works, because the env file
    supplies it. The list is short, closed, and named; a new credential must be
    added to it, and the test beside it fails on a value that looks like one
    and is not listed.
    """
    return {k: v for k, v in env.items() if k not in SECRETS}


def _cmd_wrapper(python: str, entry: Path, env: dict) -> str:
    """The .cmd the task runs. `set` per variable, then the shipper.

    ⚠ QUOTED THE WAY `cmd.exe` NEEDS, WHICH IS NOT HOW A SHELL DOES IT. `set
    "K=v"` puts the quotes OUTSIDE the assignment, so a value containing a
    space does not truncate and a trailing space does not become part of the
    value. `set K="v"` — the spelling that looks right — stores the quotes.
    """
    lines = ["@echo off", "rem Generated by sting install.py. Do not edit."]
    for key in sorted(env):
        value = str(env[key]).replace("%", "%%")
        lines.append(f'set "{key}={value}"')
    lines.append(f'"{python}" "{entry}"')
    return "\r\n".join(lines) + "\r\n"


def _task_xml(wrapper: Path) -> str:
    """⚠ ONLOGON, AND EVERY BATTERY DEFAULT TURNED OFF EXPLICITLY.

    Task Scheduler's DEFAULTS are hostile to a background guard:
    `DisallowStartIfOnBatteries` and `StopIfGoingOnBatteries` are both true
    unless stated, so on a laptop — which is every machine this runs on — the
    shipper would stop the moment the charger came out, and the collector would
    read that as a machine gone quiet. They are set false here, in the file,
    rather than left to a default somebody would have to know to check.

    `ExecutionTimeLimit` is PT0S = no limit; the shipper is a long-running loop
    and the default would kill it after 72 hours.
    """
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>sting shipper — sends decision records to the collector</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{wrapper}</Command></Exec>
  </Actions>
</Task>
"""


def _plist(python: str, entry: Path, env: dict) -> str:
    # ⚠ ESCAPED, BECAUSE A PATH IS NOT XML-SAFE. `/home/a&b/x` produced a plist
    # launchd refuses to parse, and the failure surfaces as a service that does
    # not load rather than as anything mentioning the ampersand.
    lines = "".join(f"    <key>{escape(k)}</key><string>{escape(str(v))}</string>\n"
                     for k, v in sorted(env.items()))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{service.label()}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{python}</string>
    <string>{entry}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
{lines}  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{Path.home()}/.sting/shipper.out.log</string>
  <key>StandardErrorPath</key><string>{Path.home()}/.sting/shipper.err.log</string>
</dict>
</plist>
"""


def _unit(python: str, entry: Path, env: dict) -> str:
    # ⚠ QUOTED, AND THIS IS THE LINE A WSL USER BREAKS FIRST. systemd splits an
    # unquoted `Environment=` value on whitespace and reads each piece as
    # another assignment, so `STING_ROOTS=/mnt/c/Users/John Smith/code` becomes
    # STING_ROOTS=/mnt/c/Users/John and a second, malformed one. Windows home
    # directories under /mnt/c routinely contain a space, and the symptom would
    # be a trust boundary silently half its intended size — which the installer
    # itself says costs 74 of 89 denials.
    lines = "\n".join(f'Environment="{k}={_unit_escape(str(v))}"'
                       for k, v in sorted(env.items()))
    return f"""[Unit]
Description=sting shipper — sends decision-log batches to a collector
After=network-online.target

[Service]
Type=simple
ExecStart={python} {entry}
{lines}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
"""


def leaked_secret_in(path: Path, env: dict) -> list[str]:
    """Which SECRETS an EXISTING supervisor file still contains.

    ⚠ REMOVING A LEAKED CREDENTIAL IS NOT THE SAME AS UNDOING THE LEAK, AND
    THIS IS THE DIFFERENCE. Every install rewrites this file, so an upgrade
    silently drops the token out of it and the operator never learns it was
    there — on a machine where it may have sat in a world-readable file for
    weeks, through backups, through a screen share, through anything that
    walked $HOME. A credential that was exposed needs ROTATING, and only the
    person can do that.

    Read BEFORE the rewrite, reported after it. Returns key names, never
    values: this is a report about a secret, and it must not become another
    copy of one.
    """
    if not path or not path.exists():
        return []
    try:
        body = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [key for key in SECRETS
            if str(env.get(key) or "") and str(env[key]) in body]


def write(python: str, entry: Path, env: dict) -> dict:
    """Write the supervisor file. Does NOT load it — see `activate`."""
    flavour = service.kind()
    if flavour == "unsupported":
        return {"kind": flavour, "path": None, "was_leaking": [],
                 "note": (f"{platform.system()} has no supported supervisor here. "
                           f"Run `python3 -m shipper.run` yourself, or use the "
                           f"platform's own service manager to run it.")}
    path = service.target_path()
    # ⚠ READ BEFORE THE REWRITE OVERWRITES THE EVIDENCE. On schtasks the secret
    # lives in the wrapper, not the XML that `target_path` returns.
    leaked = leaked_secret_in(
        service.task_paths()[1] if flavour == "schtasks" else path, env)
    path.parent.mkdir(parents=True, exist_ok=True)
    # ⚠ ONE FILTER, AT THE ONE PLACE ALL THREE FLAVOURS PASS THROUGH. Filtering
    # inside `_plist`/`_unit`/`_cmd_wrapper` would be three copies, and the
    # fourth flavour somebody adds would be the one that forgot.
    env = public_env(env)
    # ⚠ `HOME` IS PINNED, AND ITS ABSENCE WAS A DEFECT THIS PASS'S WALK FOUND.
    #
    # Removing `STING_DEVICE_TOKEN` from this file was right — it is
    # world-readable and the shipper reads the token from `~/.sting/env` (0600)
    # anyway. But it created a dependency nobody stated: the shipper now finds
    # its credential THROUGH `HOME`, and a supervisor file that does not say
    # which home it means gets whatever the supervisor's session has.
    #
    # ⚠ MEASURED. An install into an isolated home produced a launchd agent with
    #
    #     STING_SESSION_ROOT = <the install's sessions>
    #     HOME               = /Users/<the logged-in user>
    #
    # so the resident shipper read a DIFFERENT env file than the install wrote —
    # another install's token, and another install's collector URL — while
    # reading this install's records. It shipped nothing for twelve minutes and
    # its log stayed empty, which is the failure shape this project keeps
    # refusing: running, reporting nothing wrong, and sending nothing.
    #
    # On an ordinary machine the two homes coincide and this changes nothing.
    # It is the case where they DIFFER that was silent, and `HOME` is not a
    # credential, so pinning it reintroduces no leak.
    env.setdefault("HOME", str(Path.home()))
    if flavour == "schtasks":
        xml, wrapper = service.task_paths()
        wrapper.write_text(_cmd_wrapper(python, entry, env), encoding="utf-8")
        # ⚠ UTF-16, BECAUSE THE XML DECLARES IT. `schtasks /Create /XML` reads
        # the encoding from the declaration and refuses a file whose bytes do
        # not match it — a UTF-8 file declaring UTF-16 fails with a parse error
        # that names neither.
        xml.write_text(_task_xml(wrapper), encoding="utf-16")
        return {"kind": flavour, "path": str(xml), "note": "",
                 "was_leaking": leaked}
    body = (_plist(python, entry, env) if flavour == "launchd"
             else _unit(python, entry, env))
    path.write_text(body, encoding="utf-8")
    return {"kind": flavour, "path": str(path), "note": "",
             "was_leaking": leaked}


# How long to wait for a boot-out to finish before bootstrapping over it.
# launchd tears a job down asynchronously, and bootstrapping a label that is
# still going away is one of the ways `bootstrap` returns 5: Input/output error.
_SETTLE_SECONDS = 3.0
_SETTLE_POLL = 0.1


def _settle(now=time.monotonic) -> bool:
    """Wait for the label to stop existing. True if it is gone."""
    deadline = now() + _SETTLE_SECONDS
    while now() < deadline:
        if service.loaded().get("loaded") is not True:
            return True
        time.sleep(_SETTLE_POLL)
    return service.loaded().get("loaded") is not True


def install_startup_shortcut(wrapper: Path) -> dict:
    r"""Ship at logon with no elevation. Windows only.

    ⚠ WIRED RATHER THAN PRINTED, AND THAT IS THE WHOLE POINT. `schtasks /Create`
    was refused at BOTH `\Sting\` and the root on the first native Windows
    install, and the discriminator established the cause is an unelevated shell
    or a domain policy — NOT the task folder. That is a machine we cannot
    change, so the installer has to leave a working shipper on it rather than a
    paragraph explaining how the person could build one.

    ⚠ AND IT DEMANDS NOTHING. A file in the per-user Startup folder needs no
    administrator, no UAC prompt and no registry write. This product installs in
    a minute; a UAC prompt at install is a different product, so elevation stays
    an OFFER and this is what happens when it is not taken.

    ⚠ WHAT IT COSTS, AND IT IS NOT NOTHING: a Startup shortcut runs AT LOGON.
    A machine that has rebooted and is sitting at the login screen ships
    NOTHING — a scheduled task would have run, and this will not. The gap is
    invisible at the collector in exactly the way an overnight sleep is, and
    for the same reason. It is the price of not demanding elevation, and it is
    stated at install rather than discovered.

    ⚠ IT CALLS THE `.cmd` THE INSTALL ALREADY WROTE rather than composing a
    second command line. That wrapper carries the environment — it exists
    because Task Scheduler has no environment block — so there is one statement
    of "how the shipper is started" and the Startup path cannot drift from the
    task path.
    """
    if service.kind() != "schtasks":
        return {"written": False, "reason": "Startup folder is Windows only"}
    try:
        folder = service.startup_dir()
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / service.STARTUP_NAME
        # `start ""` so the console window closes rather than sitting on the
        # desktop for the length of the session; the wrapper is a .cmd, so it is
        # invoked through cmd rather than executed directly.
        target.write_text(
            "@echo off\r\n"
            "rem Generated by sting install.py — ships decision batches at logon.\r\n"
            "rem Remove this file to stop it. Nothing else references it.\r\n"
            f'start "" /min "{wrapper}"\r\n',
            encoding="utf-8")
        return {"written": True, "path": str(target)}
    except OSError as exc:
        return {"written": False, "reason": f"{type(exc).__name__}: {exc}"}


def remove_startup_shortcut() -> bool:
    try:
        path = service.startup_shortcut_path()
        if path.is_file():
            path.unlink()
            return True
    except OSError:
        pass
    return False


def migrate_legacy() -> dict:
    """Stop and remove the per-ACCOUNT service, once, on the way to per-install.

    ⚠ THIS IS A MIGRATION, NOT A RENAME, AND THE DIFFERENCE IS AN ORPHAN.
    Every machine installed before this change runs `dev.sting.shipper`. The new
    label is a different name, so a plain bootstrap would leave the old service
    RUNNING — shipping from the old tree, holding the old cursor — while every
    command this installer prints names the new one. A process nobody can find
    is a process nobody stops, which is the stop condition for this whole
    change.

    ⚠ IT RUNS ON EVERY ACTIVATE AND IS A NO-OP AFTER THE FIRST. `legacy_loaded`
    answers from the service manager, not from a marker file, so a half-finished
    migration finishes on the next install rather than being remembered as done.

    ⚠ AND IT REMOVES THE FILE TOO. Booting out a service whose plist is still on
    disk means the next login loads it again — the orphan coming back by itself,
    which is worse than the orphan, because by then nobody is looking.
    """
    result = {"stopped": False, "removed": [], "label": service.LEGACY_LABEL,
              "detail": ""}
    # ⚠ THE FILE IS ASKED FIRST, AND IT COSTS NOTHING. A machine that never had
    # the per-account service has no plist, no unit and no task XML — which is
    # every machine installed after this change, and every test environment. So
    # the common path runs zero subprocesses and the service manager is only
    # consulted where there is something to consult it about.
    #
    # ⚠ THE ONE CASE THIS MISSES, NAMED: a legacy service still LOADED whose
    # file was deleted by hand. `launchctl` would keep running it until logout
    # and nothing here would see it. `siblings()` cannot see it either — it also
    # enumerates files. Recovering that needs asking the service manager to list
    # everything, which is a different and much noisier operation.
    if not _legacy_files():
        return result
    if not service.legacy_loaded():
        # The file can outlive the service — a boot-out without a delete, or a
        # machine that never logged back in. Remove it anyway, or it reloads.
        for path in _legacy_files():
            try:
                path.unlink()
                result["removed"].append(str(path))
            except OSError:
                pass
        return result

    flavour = service.kind()
    uid = service._uid_or_none()
    if flavour == "launchd":
        code, detail = service._run(["launchctl", "bootout",
                                     f"gui/{uid}/{service.LEGACY_LABEL}"])
    elif flavour == "systemd":
        code, detail = service._run(["systemctl", "--user", "disable", "--now",
                             f"{service.LEGACY_LABEL}.service"])
    else:
        code, detail = service._run(["schtasks", "/Delete", "/TN",
                                     service.LEGACY_TASK_NAME, "/F"])
    result["stopped"] = code == 0
    result["detail"] = detail
    for path in _legacy_files():
        try:
            path.unlink()
            result["removed"].append(str(path))
        except OSError:
            pass
    return result


def _legacy_files() -> list:
    """Where the per-account service's files were written, by platform."""
    candidates = [
        Path.home() / "Library" / "LaunchAgents" / f"{service.LEGACY_LABEL}.plist",
        (Path.home() / ".config" / "systemd" / "user"
         / f"{service.LEGACY_LABEL}.service"),
    ]
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "sting"
    candidates += [base / f"{service.LEGACY_LABEL}.xml",
                   base / f"{service.LEGACY_LABEL}.cmd"]
    return [p for p in candidates if p.exists()]


def siblings() -> list:
    """Every sting supervisor file under this account, whichever install wrote it.

    ⚠ `--status` MUST FIND A SERVICE WHOSE NAME IT NO LONGER PREDICTS. With one
    label per install prefix, this install cannot compute another install's
    label — so "is anything else shipping under this account?" stops being
    answerable by asking about a name and becomes a question about the
    directory. Enumeration is the only honest way to ask it.
    """
    found = []
    seen = set()
    for directory, suffix in (
            (Path.home() / "Library" / "LaunchAgents", ".plist"),
            (Path.home() / ".config" / "systemd" / "user", ".service"),
            (Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "sting",
             ".xml")):
        try:
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob(f"{service.LEGACY_LABEL}*{suffix}")):
                name = path.name[:-len(suffix)]
                if name in seen:
                    continue
                seen.add(name)
                found.append({"label": name, "path": str(path),
                              "mine": name == service.label(),
                              "legacy": name == service.LEGACY_LABEL})
        except OSError:
            continue
    return found


def activate(dry_run: bool = False) -> dict:
    """Load it, then CHECK that it loaded. Separated from `write` so the file
    can be inspected first.

    ⚠ NEVER FATAL, AND THAT IS STILL RIGHT. A supervisor that will not load is
    a real problem and a bad reason to fail an install that is otherwise
    complete — the shipper can be run by hand, and the printed command says how.
    ⚠ BUT NEVER QUIET EITHER. `ok` is now the answer to "does launchd have this
    service", asked after the fact, not "did the command run". The two came
    apart on a real machine and the install said nothing.

    BOOT OUT BEFORE BOOTSTRAP, AND WAIT FOR IT. `launchctl` refuses to
    bootstrap a label that is already bootstrapped, and a teardown that is
    still in flight produces the same refusal — `5: Input/output error` — so
    the boot-out is followed by a bounded wait for the label to disappear
    rather than by an immediate retry. A boot-out of something that was never
    loaded exits 3 and is expected on every first install; only the final
    verification decides the outcome.
    """
    flavour = service.kind()
    if flavour == "unsupported":
        return {"ok": False, "detail": "no supervisor on this platform",
                 "commands": [], "verified": False}
    # ⚠ `os.getuid` IS NOT CALLED UNCONDITIONALLY ANY MORE. Windows has no uid,
    # and the bare call raised AttributeError before any platform branch was
    # reached — 15 failures on the runner, all of them before this line could
    # decide it did not need a uid at all.
    uid = service._uid_or_none()
    # ⚠ THE MIGRATION HAPPENS HERE, BEFORE ANYTHING NEW IS LOADED, AND IT IS
    # WHAT KEEPS THE OLD SERVICE FROM BECOMING AN ORPHAN. Every machine
    # installed before this change is running `dev.sting.shipper`; the new label
    # is a different name, so bootstrapping it would leave TWO shippers running
    # and only one of them findable by any command this installer prints.
    migrated = migrate_legacy()
    if flavour == "launchd":
        commands = [["launchctl", "bootout", f"gui/{uid}/{service.label()}"],
                     ["launchctl", "bootstrap", f"gui/{uid}",
                      str(service.plist_path())]]
    elif flavour == "schtasks":
        # `/F` overwrites an existing registration, which is what a reinstall
        # is. There is no boot-out step: `/Create /F` replaces atomically, so
        # the launchd settle-wait has no analogue here.
        #
        # ⚠ TWO ATTEMPTS, AND THE SECOND ONE IS A DIAGNOSTIC AS MUCH AS A FIX.
        #
        # The first native Windows install failed here with `ERROR: Access is
        # denied.` Three causes were possible and they need different fixes: an
        # unelevated shell, a domain policy, or the `\Sting\` TASK FOLDER —
        # which this project chose so an operator could see at a glance what put
        # the task there. Creating a folder under the Task Scheduler Library
        # writes to `C:\Windows\System32\Tasks\<Folder>`, which a standard
        # user cannot do; a task at the ROOT is ordinarily allowed.
        #
        # So it tries the folder, and on failure retries at the root under a
        # name that is still unmistakably ours. **Which one succeeds is the
        # answer**: root-only means it was the folder (our choice, our fix);
        # both failing means elevation or policy (the machine's, and named as
        # such). That turns a guess into a measurement taken on the next real
        # Windows machine rather than reasoned about on this one.
        commands = [["schtasks", "/Create", "/TN", service.task_name(),
                      "/XML", str(service.task_paths()[0]), "/F"],
                     ["schtasks", "/Create", "/TN", service.root_task_name(),
                      "/XML", str(service.task_paths()[0]), "/F"]]
    else:
        # ⚠ RESTART, NOT `enable --now`. The shipper reads its settings once,
        # when it starts, and `--now` starts a stopped unit and leaves a
        # running one alone. So a re-run that changed the tier or rotated the
        # token left the old process shipping on the old settings: 6.5 hours
        # at the old tier on the Azure VM while `--status` read the new one.
        # `restart` starts a stopped unit and restarts a running one, after
        # `daemon-reload` has read the unit just written. launchd needs no such
        # step: bootout + bootstrap above already ends the old process and
        # starts one on the new plist.
        unit = f"{service.label()}.service"
        commands = [["systemctl", "--user", "daemon-reload"],
                     ["systemctl", "--user", "enable", unit],
                     ["systemctl", "--user", "restart", unit]]
    printed = [" ".join(c) for c in commands]
    if dry_run:
        return {"ok": True, "detail": "not run (dry run)", "commands": printed,
                 "verified": False, "migrated": migrated}

    failures = []
    if flavour == "schtasks":
        # ⚠ FIRST SUCCESS WINS, AND STOPPING IS NOT AN OPTIMISATION. Running
        # both would register the task TWICE — once in `\Sting\` and once at
        # the root — and two supervisors for one shipper is the per-account
        # label bug wearing a different hat.
        attempted = []
        for command in commands:
            code, detail = service._run(command)
            attempted.append((" ".join(command[:4]), code, detail))
            if code == 0:
                break
        if all(code != 0 for _c, code, _d in attempted):
            for what, code, detail in attempted:
                failures.append(f"{what} exited {code}"
                                 + (f": {detail}" if detail else ""))
            failures.append(
                "⚠ BOTH the \\Sting\\ folder AND the root were refused, so "
                "this is NOT the task-folder permission — it is an unelevated "
                "shell or a domain policy. The XML is written and nothing runs "
                "it; see the manual fallback printed by install.py.")
        elif attempted[0][1] != 0:
            # The folder was refused and the root was accepted. That IS the
            # answer to which of the three causes it was, recorded rather than
            # inferred.
            failures.append(
                f"⚠ NOT A FAILURE, A FINDING: the \\Sting\\ task folder was "
                f"refused ({attempted[0][2] or 'access denied'}) and the task "
                f"registered at the Task Scheduler ROOT instead, as "
                f"{service.root_task_name()}. Creating a folder there needs rights a "
                f"standard user does not have; the task itself does not.")
    else:
        for index, command in enumerate(commands):
            code, detail = service._run(command)
            first = index == 0
            if code != 0 and not (first and flavour == "launchd"):
                failures.append(f"{' '.join(command[:2])} exited {code}"
                                 + (f": {detail}" if detail else ""))
            if first and flavour == "launchd" and not _settle():
                failures.append(f"{service.label()} was still loaded "
                                 f"{_SETTLE_SECONDS:.0f}s after boot-out; "
                                 f"bootstrapping over it usually "
                                 f"fails with 5: Input/output error")

    after = service.loaded()
    if migrated.get("stopped"):
        # Reported on the result rather than logged from here: this module does
        # not own the operator's console, and a migration is a fact the Done
        # block has to be able to print.
        pass
    if after.get("loaded") is True and not failures:
        return {"ok": True, "verified": True, "commands": printed,
                 "detail": f"pid {after['pid']}" if after.get("pid")
                            else after.get("detail", "")}

    # ⚠ A LOADED SERVICE AFTER A FAILED BOOTSTRAP IS THE OLD ONE, AND SAYING
    # "loaded" HERE WOULD BE THE SAME BUG ONE LEVEL UP. If the boot-out did not
    # take and the bootstrap was refused, launchd is still running the job it
    # was running before — quite possibly an earlier version, from an earlier
    # path — and the install has changed nothing about what is executing.
    reason = "; ".join(failures) or after.get("detail", "reason unknown")
    if after.get("loaded") is True:
        reason += (f" — and {service.label()} IS loaded, so what is running is the "
                    f"PREVIOUS job, not what was just written")
    return {"ok": False, "verified": True, "commands": printed, "detail": reason}


def start_now(wrapper: Path | None = None) -> dict:
    """Start the shipper NOW, detached, and report what happened.

    ⚠ WHY THIS EXISTS: LOADING A SERVICE AND STARTING ONE ARE THE SAME ACT ON
    TWO PLATFORMS AND NOT ON THE THIRD.

        launchd    `bootstrap` + RunAtLoad=true  -> starts immediately
        systemd    `enable` + `restart`          -> `restart` IS the start
        Windows    the task's ONLY trigger is <LogonTrigger>, and the Startup
                   folder fires at logon too — so BOTH Windows paths wait for
                   the next sign-in, which on a machine that stays logged in is
                   days. Installed, reporting success, shipping nothing.

    ⚠ DETACHED, BECAUSE A CHILD THAT DIES WITH THE INSTALLER IS WORSE THAN NONE:
    `--status` would then report a pid that is already gone.

        POSIX    `start_new_session=True` — setsid, so it leaves the process
                 group and survives the installer's terminal closing.
        Windows  DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, and no console is
                 inherited, so closing the install window does not signal it.

    ⚠ IT DOES NOT CHECK WHETHER ONE IS ALREADY RUNNING, ON PURPOSE. That race
    cannot be won from out here — a shipper can start between the check and the
    spawn. The started process takes `shipper/singleton.Lock` and exits 0 if
    another holds it, so the exclusion is decided by the thing that can actually
    decide it. This function only reports what it launched.
    """
    if wrapper is None:
        wrapper = service.task_paths()[1]
    wrapper = Path(wrapper)
    if not wrapper.is_file():
        return {"started": False, "pid": None,
                 "detail": f"no wrapper at {wrapper} to run"}

    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
               "stderr": subprocess.DEVNULL, "close_fds": True,
               "cwd": str(wrapper.parent)}
    if os.name == "nt":
        # 0x00000008 DETACHED_PROCESS | 0x00000200 CREATE_NEW_PROCESS_GROUP
        kwargs["creationflags"] = 0x00000008 | 0x00000200
        command = [str(wrapper)]
    else:
        kwargs["start_new_session"] = True
        command = ["/bin/sh", str(wrapper)]
    try:
        child = subprocess.Popen(command, **kwargs)          # noqa: S603
    except (OSError, ValueError) as exc:
        # ⚠ NEVER FATAL. An install that wired everything correctly must not
        # fail because the process would not spawn; the shipper can be run by
        # hand and the printed command says how.
        return {"started": False, "pid": None,
                 "detail": f"{type(exc).__name__}: {exc}"}
    return {"started": True, "pid": child.pid,
             "detail": f"detached, pid {child.pid}"}


def remove() -> dict:
    """Unload and delete. Uninstall must leave nothing behind."""
    flavour = service.kind()
    if flavour == "schtasks":
        code, detail = service._run(["schtasks", "/Delete", "/TN",
                                     service.task_name(), "/F"])
        xml, wrapper = service.task_paths()
        gone = [str(f) for f in (xml, wrapper) if f.exists()]
        for f in (xml, wrapper):
            try:
                f.unlink()
            except OSError:
                pass
        # ⚠ AND THE STARTUP SHORTCUT, WHICH THIS NEVER REMOVED. `install.py`
        # writes one whenever `schtasks /Create` is refused, and
        # `remove_startup_shortcut()` had ZERO CALLERS anywhere in this repo —
        # so "uninstall must leave nothing behind" was false on exactly the
        # Windows machines that needed the fallback.
        #
        # WHAT THE ORPHAN DOES WHEN IT RUNS, which is the reason this matters:
        # the shortcut is `start "" /min "<wrapper>.cmd"`, and the two lines
        # above have just deleted that wrapper. So at EVERY LOGON, FOREVER,
        # Windows runs a command that fails to find its target and exits — with
        # no window, because it is `/min`, and no log, because the thing that
        # would have written one is what was uninstalled. It ships nothing and
        # says nothing. ⚠ A person who uninstalled Sting and then found this
        # file has no way to tell it apart from a guard that is still running.
        if remove_startup_shortcut():
            gone.append(str(service.startup_shortcut_path()))
        # ⚠ VERIFIED BY ASKING, exactly as the other two are. A `/Delete` that
        # printed SUCCESS and left the task registered would be the file-versus-
        # fact mistake in its other direction.
        after = service.loaded()
        return {"ok": after.get("loaded") is not True,
                 "removed": gone,
                 "detail": (f"schtasks /Delete exited {code}: {detail}"
                             if after.get("loaded") is True else
                             f"Task Scheduler no longer has {service.task_name()}")}
    removed, detail = [], ""
    if flavour == "launchd":
        try:
            subprocess.run(["launchctl", "bootout",
                            f"gui/{os.getuid()}/{service.label()}"],
                            capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as exc:
            detail = str(exc)
    elif flavour == "systemd":
        try:
            subprocess.run(["systemctl", "--user", "disable", "--now",
                             f"{service.label()}.service"], capture_output=True,
                            text=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as exc:
            detail = str(exc)
    path = service.target_path() if flavour != "unsupported" else None
    if path and path.exists():
        path.unlink()
        removed.append(str(path))
    return {"removed": removed, "detail": detail}
