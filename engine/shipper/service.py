"""The shipper as a SERVICE: what it is called, where its file is, and what the
supervisor says about it. Read-only. Nothing here writes a file, loads a job or
removes one — that is `installer/supervisor.py`, which calls through here.

────────────────────────────────────────────────────────────────────────────────
WHY THIS LIVES WITH THE SHIPPER AND NOT WITH THE INSTALLER
────────────────────────────────────────────────────────────────────────────────

Supervisor status is not a file fact. `loaded()` ASKS `launchctl print`,
`systemctl show` or `schtasks /Query`, because a plist on disk and a loaded
service disagreed for hours on a real machine (its docstring has the story). So
the code that asks has to be on the INSTALLED machine — `tools/preflight.py`
ships and reads it there, and `install.py --status` reads it from the checkout —
and the two must answer from one oracle. The installer is what a stranger runs
once from the archive; the shipper is what stays. This is G2's "(b)" from
docs/74, done as its own pass in docs/84.

────────────────────────────────────────────────────────────────────────────────
⚠ THE TRAP, NAMED BEFORE THE MOVE WAS MADE
────────────────────────────────────────────────────────────────────────────────

Every function here resolves its neighbours from THIS module's globals —
`status()` calls `loaded()`, which calls `_run()` — and `installer/supervisor.py`
reaches them as `service.kind()`, `service._run()`, never by importing the
names into its own namespace. So ONE patch on `shipper.service._run` reaches
`status()` and `activate()` alike, while a patch on `installer.supervisor._run`
would reach neither and the test would pass against the real `launchctl`.
Patch this module. docs/84 carries the table proving every re-pointed patch is
still reached.

⚠ ONE IMPORT GOES THE OTHER WAY, AND IT IS STATED RATHER THAN HIDDEN.
`_prefix_tag()` asks `installer.place.default_prefix()` for the prefix the
per-install label is derived from — inside the function, exactly as before the
move. `installer/place.py` ships for this reason (see `place.PAYLOAD`), so the
import resolves on an installed tree. Moving `default_prefix` is a second
change with its own callers; this pass moves code and changes nothing.
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path


LEGACY_LABEL = "dev.sting.shipper"
"""What every install before this one used — for ALL of them, on one account.

⚠ KEPT BECAUSE EVERY EXISTING MACHINE IS STILL RUNNING IT. It is not a fallback
and it is never written again; it is the thing a migration has to find and boot
out. See `legacy_loaded` and `activate`.
"""


def _prefix_tag(prefix=None) -> str:
    """8 hex of the install prefix's ABSOLUTE path.

    ⚠ THE ABSOLUTE PATH, NOT "is this the default prefix". Two accounts — or an
    account and a sandboxed HOME — each have their own default prefix, and those
    are DIFFERENT DIRECTORIES sharing a relative name. Deriving from "default or
    not" would give both the same label, which is exactly the defect: installing
    into a sandboxed HOME booted out this machine's real shipper and took its
    label.
    """
    import hashlib

    if prefix is None:
        from installer import place
        prefix = place.default_prefix()
    resolved = str(Path(prefix).expanduser().resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:8]


def label(prefix=None) -> str:
    """The supervisor label for ONE install.

    ⚠ PER INSTALL PREFIX, AND THIS FIXES A DEFECT THAT FIRED LIVE.
    `dev.sting.shipper` was per ACCOUNT, so a second install could not coexist
    with the first — it silently booted the first out and took the label. A
    customer piloting Sting on a machine that already runs it would have stopped
    the incumbent and been told nothing.

    ⚠ IT DOES NOT CHANGE ON AN UPGRADE, WHICH IS WHAT KEEPS THIS FROM
    ORPHANING ANYTHING. The PREFIX is stable across versions —
    `~/.local/share/sting` — while `current` moves INSIDE it. So an ordinary
    reinstall computes the same label it computed last time, and the only label
    change any machine ever sees is the single migration off `LEGACY_LABEL`.
    """
    return f"{LEGACY_LABEL}.{_prefix_tag(prefix)}"


# ⚠ THE MODULE-LEVEL `LABEL` CONSTANT IS GONE ON PURPOSE. It was read at import
# time by nine call sites, which is how one name came to mean every install; a
# function forces each caller to say which install it means.


def kind() -> str:
    system = platform.system()
    if system == "Darwin":
        return "launchd"
    if system == "Linux":
        return "systemd"
    if system == "Windows":
        return "schtasks"
    return "unsupported"


def task_name(name: str | None = None) -> str:
    return rf"\Sting\{name or label()}"


def root_task_name(name: str | None = None) -> str:
    r"""The same task, at the Task Scheduler ROOT rather than in a folder.

    ⚠ THE FALLBACK, AND IT COSTS TIDINESS TO BUY AN INSTALL THAT WORKS. A task
    in `\Sting\` is easier for an operator to find and safer to delete by
    name. A task at the root needs no folder to be created, which is the
    permission a standard user does not have. When the folder is refused, a
    working supervisor under a longer name is worth more than a tidy one that
    does not exist.
    """
    return name or label()


LEGACY_TASK_NAME = r"\Sting\dev.sting.shipper"
"""The Scheduled Tasks path every install before this one used. A folder rather
than the root so an operator can see at a glance what put it there, and so
`schtasks /Delete` cannot be aimed at something else by a typo in a bare name.
Kept for the same reason as LEGACY_LABEL: it is what a migration must find."""


def _uid_or_none():
    """`os.getuid` where it exists.

    ⚠ WINDOWS HAS NO uid, AND CALLING IT RAISED AttributeError IN 15 TESTS.
    Nothing on the Windows path needs one — `gui/<uid>/` is launchd's address
    space and nothing else — so this returns None rather than inventing a value
    that would then be formatted into a command.
    """
    getuid = getattr(os, "getuid", None)
    return getuid() if getuid else None


def plist_path(name: str | None = None) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{name or label()}.plist"


def unit_path(name: str | None = None) -> Path:
    return (Path.home() / ".config" / "systemd" / "user"
            / f"{name or label()}.service")


def task_paths(name: str | None = None) -> tuple[Path, Path]:
    """(the task XML, the wrapper .cmd).

    ⚠ TWO FILES, BECAUSE SCHEDULED TASKS HAS NO ENVIRONMENT BLOCK. A launchd
    plist has `EnvironmentVariables` and a systemd unit has `Environment=`;
    Task Scheduler has neither, so the variables have to be set by something
    the task runs. The wrapper is that something, and it is generated rather
    than hand-written so the values come from the same `env` dict the other two
    platforms are given.
    """
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "sting"
    name = name or label()
    return base / f"{name}.xml", base / f"{name}.cmd"


def target_path() -> Path:
    flavour = kind()
    if flavour == "launchd":
        return plist_path()
    if flavour == "schtasks":
        return task_paths()[0]
    return unit_path()


def _run(command: list[str], timeout: float = 20) -> tuple[int, str]:
    """(returncode, first non-empty of stderr/stdout). Never raises.

    ⚠ THE RETURN CODE IS RETURNED, WHICH IS THE WHOLE POINT OF THIS HELPER.
    The previous version of `activate` called `subprocess.run` and read only
    its output, so `launchctl` could print "Bootstrap failed: 5: Input/output
    error" and exit 5 while the caller reported success. A command's exit
    status is the one part of it that cannot be mistaken for prose.
    """
    try:
        out = subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout)
        return out.returncode, (out.stderr or out.stdout).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, f"{command[0]}: {exc}"


# launchd's own code for "no such service in this domain". `launchctl print`
# exits with it when the label is not loaded, which is how `loaded()` tells
# "not there" from "there and broken" without parsing English.
_NO_SUCH_SERVICE = 113


def loaded() -> dict:
    """Ask the supervisor whether the service exists. Never the filesystem.

    ⚠ A PLIST ON DISK IS A FILE; A LOADED SERVICE IS A FACT, and for one real
    install they disagreed for hours: the plist was written, `status()` said
    `installed: true`, and `launchctl print` said "Could not find service". The
    shipper that was actually running had been started by hand from a terminal.
    Every claim this module makes about a service now comes from asking the
    thing that would know.

    Returns `loaded`, and `pid` when the supervisor reports one. A loaded
    service with no pid is a real state — launchd holds the job and is not
    running it — so the two are separate keys and never collapsed into one.
    """
    flavour = kind()
    if flavour == "launchd":
        code, detail = _run(["launchctl", "print", f"gui/{os.getuid()}/{label()}"])
        if code == _NO_SUCH_SERVICE:
            return {"loaded": False, "pid": None, "file": None,
                     "detail": f"launchd has no service {label()} in gui/{os.getuid()}"}
        if code != 0:
            return {"loaded": None, "pid": None, "file": None,
                     "detail": f"launchctl print exited {code}: {detail}"}
        return {"loaded": True, "pid": _field(detail, "pid"),
                 "file": _text_field(detail, "path"),
                 "detail": f"state = {_field(detail, 'state') or 'unknown'}"}
    if flavour == "systemd":
        code, detail = _run(["systemctl", "--user", "show", f"{label()}.service",
                              "--property=LoadState", "--property=ActiveState",
                              "--property=MainPID", "--property=FragmentPath"])
        if code != 0:
            return {"loaded": None, "pid": None, "file": None,
                     "detail": f"systemctl show exited {code}: {detail}"}
        values = dict(line.split("=", 1) for line in detail.splitlines()
                       if "=" in line)
        is_loaded = values.get("LoadState") == "loaded"
        pid = values.get("MainPID")
        return {"loaded": is_loaded,
                 "pid": int(pid) if (pid or "0").isdigit() and pid != "0" else None,
                 "file": values.get("FragmentPath") or None,
                 "detail": f"LoadState={values.get('LoadState')} "
                            f"ActiveState={values.get('ActiveState')}"}
    if flavour == "schtasks":
        # ⚠ ASK TASK SCHEDULER, NEVER THE FILE. This module already made that
        # mistake once — `installed = bool(path.exists())` reported a plist as a
        # running shipper for hours, and a failed bootstrap was indistinguishable
        # from success. The XML on disk is an input to `/Create`; it is not
        # evidence that `/Create` was ever run, or that it succeeded.
        # ⚠ BOTH NAMES. A task that fell back to the root is a WORKING
        # supervisor, and a `loaded()` that only asked about the folder would
        # report it missing — "written and not running" is the one thing this
        # must never get wrong, and it would have got it wrong in the safe
        # direction's opposite.
        code, detail = _run(["schtasks", "/Query", "/TN", task_name(), "/FO", "LIST",
                              "/V"])
        if code != 0:
            # schtasks exits non-zero for "does not exist" AND for real errors,
            # and distinguishes them only in prose. The text is matched for the
            # absent case and anything else stays UNKNOWN rather than being
            # called absent — "cannot tell" must not read as "not there".
            missing = ("cannot find the file specified" in detail.lower()
                        or "does not exist" in detail.lower()
                        or "ERROR: The system cannot find" in detail)
            if missing:
                return {"loaded": False, "pid": None, "file": None,
                         "detail": f"Task Scheduler has no task {task_name()}"}
            return {"loaded": None, "pid": None, "file": None,
                     "detail": f"schtasks /Query exited {code}: {detail}"}
        values = {}
        for line in detail.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                values.setdefault(key.strip(), value.strip())
        # ⚠ "Task To Run" IS THE `file` FIELD, and it is what makes
        # `is_this_install` work on Windows exactly as it does elsewhere: two
        # installs share one task name, so "a task exists" and "MY task exists"
        # are different questions.
        return {"loaded": True,
                 # Task Scheduler reports no pid. None is the honest answer, and
                 # `loaded` without a pid is already a real state here — launchd
                 # holds jobs it is not running, and this is the same shape.
                 "pid": None,
                 "file": values.get("Task To Run") or None,
                 "detail": f"Status={values.get('Status', 'unknown')} "
                            f"Last Result={values.get('Last Result', '?')}"}
    return {"loaded": None, "pid": None, "file": None,
             "detail": "no supervisor on this platform"}


def _field(text: str, name: str) -> int | None:
    """`launchctl print` emits `key = value` lines; pull one integer out."""
    value = _text_field(text, name)
    return int(value) if value and value.isdigit() else None


def _text_field(text: str, name: str) -> str | None:
    """The same, unparsed. `path = …` is how launchd names the plist it loaded,
    which is the only way to tell whose service is holding this label."""
    for line in text.splitlines():
        left, _, right = line.partition("=")
        if left.strip() == name:
            return right.strip() or None
    return None


STARTUP_NAME = "sting-shipper.cmd"
"""What the Startup-folder fallback is called. One name, so `status` can find
what `install` wrote without being told."""


def startup_dir() -> Path:
    """The per-user Startup folder. NO ELEVATION, and no registry."""
    base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    return (Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            / "Startup")


def startup_shortcut_path() -> Path:
    return startup_dir() / STARTUP_NAME


def startup_shortcut_present() -> bool:
    """⚠ SO `--status` DOES NOT REPORT FAIL ON A MACHINE THAT IS SHIPPING. A
    Startup shortcut is a real supervisor for this purpose; Task Scheduler
    having no task is not evidence that nothing ships."""
    try:
        return kind() == "schtasks" and startup_shortcut_path().is_file()
    except OSError:
        return False


def legacy_loaded() -> bool:
    """Is the pre-per-install service still registered under this account?"""
    flavour = kind()
    try:
        if flavour == "launchd":
            code, _ = _run(["launchctl", "print",
                            f"gui/{_uid_or_none()}/{LEGACY_LABEL}"])
            return code == 0
        if flavour == "systemd":
            code, out = _run(["systemctl", "--user", "show",
                              f"{LEGACY_LABEL}.service", "--property=LoadState"])
            return code == 0 and "LoadState=loaded" in out
        if flavour == "schtasks":
            code, _ = _run(["schtasks", "/Query", "/TN", LEGACY_TASK_NAME])
            return code == 0
    except Exception:                              # noqa: BLE001 — deliberate
        return False
    return False


def shipper_running(state_root=None) -> dict:
    """Is a shipper running RIGHT NOW — whoever started it.

    ⚠ `loaded()` CANNOT ANSWER THIS. It asks launchd/systemd/schtasks, and none
    of them knows about a shipper started from a Startup-folder `.cmd`, from a
    terminal, or by `start_now()` above. The lock is held by the process itself,
    so it answers for every way one can be started.
    """
    try:
        from shipper import config as scfg
        from shipper import singleton

        # ⚠ NOT STRICT: a malformed interval is not where the state lives, and
        # `--status` names it on its own line (`config.setting_problems`).
        root = (state_root if state_root is not None
                else scfg.from_env(strict=False).state_root)
        return singleton.running(root)
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        return {"running": None, "pid": None, "since": None,
                 "detail": f"could not be determined: {type(exc).__name__}: {exc}"}


STALE_SETTINGS = "the running shipper predates your settings: restart it"

# ⚠ A GRACE, BECAUSE THE TWO TIMES COME FROM DIFFERENT CLOCKS. `since` is the
# shipper's own `time.time()`; the file's mtime is the filesystem's, and some
# filesystems round it (FAT to 2 s). The install writes the file and THEN
# restarts, so a rounded-up mtime must not read as newer than that restart
# (python review). An edit within 2 s of a start goes unflagged: negligible.
STALE_GRACE_SECONDS = 2.0


def running_shipper(state_root=None) -> dict:
    """`shipper_running()`, plus whether that shipper predates its settings.

    ⚠ EVERY STATUS LINE READS THE SETTINGS FILE FRESH; THE SHIPPER READ IT ONCE.
    On the Azure VM `--status` said `full` for 6.5 hours while the process that
    started before the change shipped at the old tier. So a running shipper
    whose start (`since`, from its lock) is older than the last write of
    ~/.sting/env is named as stale, with the command that fixes it.

    Adds `settings` (the file), `settings_changed` (its mtime),
    `predates_settings` (True only when both times are known and the file is
    newer), `restart` and `message` (None unless stale)."""
    running = shipper_running(state_root)
    try:
        from shipper import config as scfg

        settings = scfg.settings_file()
        changed = settings.stat().st_mtime
    except (ImportError, OSError, RuntimeError, ValueError):
        settings, changed = None, None
    since = running.get("since")
    stale = (running.get("running") is True and isinstance(since, (int, float))
             and changed is not None and changed > since + STALE_GRACE_SECONDS)
    restart = restart_command()
    return {**running, "settings": str(settings) if settings else None,
            "settings_changed": changed, "predates_settings": stale,
            "restart": restart,
            "message": f"{STALE_SETTINGS}: {restart}" if stale else None}


def status() -> dict:
    """Two facts, two keys, and the file is never allowed to stand in for the
    service.

        file_present   a plist/unit exists at `path`
        loaded         the supervisor says it has this service (None = cannot tell)

    ⚠ THE KEY `installed` IS GONE ON PURPOSE. It meant "the file exists" and was
    read as "the shipper is running" — including by `install.py --status`, which
    printed a path for a service launchd had never heard of. A name that invites
    the wrong reading is worse than a missing one, so callers now have to say
    which of the two they mean.
    """
    flavour = kind()
    path = target_path() if flavour != "unsupported" else None
    # ⚠ WHAT THE SUPERVISOR RUNS IS NOT ALWAYS WHAT THE INSTALLER WROTE. On
    # Windows the task's own "Task To Run" is the .cmd WRAPPER, while `path` is
    # the .xml that registered it — so comparing them made `is_this_install`
    # false for an install that had just succeeded. Measured on the runner:
    # loaded true, running_file the .cmd, is_this_install FALSE. That is the
    # "a service exists" versus "MY service exists" check answering wrongly,
    # which is the one thing it exists to get right.
    runs = task_paths()[1] if flavour == "schtasks" else path
    service = loaded()
    # ⚠ THE LABEL USED TO BE PER USER, NOT PER INSTALL, so "a service exists" and "MY
    # service exists" are different questions and the second one is the one a
    # caller means. Both installs write `dev.sting.shipper`; a second install
    # boots out the first and takes the label, and until this compared the two
    # paths the first install's `--status` reported LOADED with a pid, for a
    # service running somebody else's plist against somebody else's home
    # directory. Measured during the clean-clone rehearsal, which is exactly
    # what happened.
    running_file = service.get("file")
    mine = None
    if service["loaded"] is True and running_file and runs:
        mine = Path(running_file).resolve() == Path(runs).resolve()
    # ⚠ A LEGACY SERVICE IS A FOURTH STATE, AND WITHOUT IT `--status` LIES.
    # Measured on this machine: `loaded` False for the per-install label while
    # `launchctl` showed `dev.sting.shipper` RUNNING at pid 79781 from a
    # pre-per-prefix install. `--status` therefore printed "nothing ships until
    # it is [loaded]" on a machine that was shipping — a false statement to an
    # operator, and precisely the class of defect `installed = path.exists()`
    # was removed for. `legacy_loaded()` already existed and nothing called it.
    legacy = legacy_loaded() if service["loaded"] is not True else False
    return {"kind": flavour, "path": str(path) if path else None,
             "startup_shortcut": startup_shortcut_present(),
             "file_present": bool(path and path.exists()),
             "loaded": service["loaded"], "pid": service["pid"],
             "running_file": running_file, "is_this_install": mine,
             "legacy_loaded": legacy,
             "detail": service["detail"]}


def stop_command() -> str:
    flavour = kind()
    if flavour == "schtasks":
        return f'schtasks /End /TN "{task_name()}"'
    if flavour == "launchd":
        return f"launchctl bootout gui/{_uid_or_none()}/{label()}"
    if kind() == "systemd":
        return f"systemctl --user stop {label()}.service"
    return "stop the process you started"


def restart_command() -> str:
    """What a person types to make the running shipper read its settings again.

    ⚠ THE SHIPPER READS ITS SETTINGS ONCE, WHEN IT STARTS (`shipper/run.py`
    `main`), so a changed agreement or a rotated token is not in force until
    it restarts. `install.py` restarts it; this is the line for everything else.

    ⚠ launchd's `kickstart -k` ends the running process and starts the LOADED
    job again: ~/.sting/env is read afresh, the plist is not. A changed plist is
    re-read by `install.py`, which boots the job out and bootstraps it.
    ⚠ schtasks: `/End` then `/Run`, UNVERIFIED on a Windows machine, where the
    install run does not restart a running shipper either (a filed issue)."""
    flavour = kind()
    if flavour == "launchd":
        return f"launchctl kickstart -k gui/{_uid_or_none()}/{label()}"
    if flavour == "systemd":
        return f"systemctl --user restart {label()}.service"
    if flavour == "schtasks":
        return f'schtasks /End /TN "{task_name()}" && schtasks /Run /TN "{task_name()}"'
    return "stop the shipper you started and start it again"
