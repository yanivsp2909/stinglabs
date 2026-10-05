"""Get this machine into a state `install.py` can succeed in — and FIX it.

⚠ THE CHANGE FROM `bootstrap.sh`: THIS DOES THINGS RATHER THAN DESCRIBING THEM.
Node, the npm prefix, the agent CLI and the scratch directory are all
deterministic. Reporting them was the right first move because it was safe;
keeping it that way would be asking a person to type four commands a program
knows exactly how to run. Consent is asked ONCE, up front, for everything.

⚠ AND EVERY FIX IS VERIFIED BY RE-RUNNING THE CHECK, NEVER BY AN EXIT CODE.
That is the whole lesson of this class of bug. On a real machine `npm` reported
10.9.2 while answering from the Windows PATH, and `npm install -g` **exited 0**
while installing to the wrong operating system. A zero here means "the process
ended", not "the thing is true".

────────────────────────────────────────────────────────────────────────────────
⚠ WINDOWS, SAID PLAINLY, BECAUSE THE ALTERNATIVE IS THE SILENT-FAILURE SHAPE
────────────────────────────────────────────────────────────────────────────────

The engine CANNOT START on native Windows. `fcntl` is imported at module scope
in `core/session.py`, `core/audit_log.py` and `core/allow_once.py` — verified,
three of three — and six further path sites fail silently even if that import is
patched. So on Windows this file is a BOOTSTRAPPER that names WSL and stops. It
does not install a guard, because there is no guard it could install that would
run.

A file that appears to install on Windows and leaves something that cannot start
is exactly what this project keeps refusing, so the refusal is loud and early.

────────────────────────────────────────────────────────────────────────────────
WHAT STAYS ON THE HUMAN SIDE, AND WHY EACH ONE
────────────────────────────────────────────────────────────────────────────────

    gh auth login         opens a browser and blocks on a device code
    the agent CLI's login  the same
    sudo                   a privilege grant, and a TTY prompt this must not
                           try to answer. Package installs need it, so the
                           consent block names them and the shell asks.

Three, not two. `sudo` belongs on the list because a script that silently
acquires root on a work laptop is a script that gets banned, and because a
password prompt inside a captured subprocess hangs with no explanation.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

MIN_PYTHON = (3, 11)


@dataclass
class Result:
    ok: bool
    detail: str = ""
    lines: list = field(default_factory=list)
    fix: list = field(default_factory=list)      # argv lists, run in order
    fix_note: str = ""
    fatal: bool = False                          # stop; no fix can help here
    installs_software: bool = False
    """⚠ THIS FIX CHANGES THE MACHINE OUTSIDE OUR OWN PREFIX, so `--yes` MUST
    NOT RUN IT.

    `--yes` means "do not ask me". It has never meant "do anything". A walk of
    the release archive into a clean HOME globally npm-installed
    `@anthropic-ai/claude-code` on the machine that ran it — under `--yes`, with
    no further consent. On a stranger's machine that is an unconsented change to
    their environment made by a SECURITY TOOL on first run: the thing that
    watches what your agent installs, installing something.

    Fixes marked here are named and SKIPPED under `--yes`, with the exact
    command printed so a person can run it deliberately. Fixes not marked here
    are confined to `~/.sting`, our own prefix, or a path the operator named on
    the command line — and are still announced before they run.
    """
    advisory: bool = False
    """REPORTED, NEVER A GATE — the guard installs and works without it.

    ⚠ THIS EXISTS BECAUSE `node` STOPPED A STRANGER'S INSTALL DEAD, over a
    dependency the shipped artifact does not contain. Measured by installing
    from the release tarball into a clean HOME on a Mac with no Node:

        node       FAIL  no usable Linux node
        fixing     install Node inside this OS
          $ brew install node
          ⚠ exited -1   [Errno 2] No such file or directory: 'brew'
        1 check(s) still failing: node
        Nothing has been installed.

    Nothing in `place.PAYLOAD` is JavaScript, `install.py` never invokes node
    or npm, and the archive contains no `extension/` at all — Node is needed
    only to BUILD the VS Code extension, which does not ship in it. So the
    installer refused to install a Python program because a JavaScript
    toolchain it does not use was absent, and offered to `brew install node`
    on a machine with no brew.

    The same rule the installer already applies to a network home, a Windows
    interpreter and a missing trust-boundary root: reporting is the whole job.
    An installer that dies leaves the machine with NO guard, which is strictly
    worse than a guard plus a note.
    """


def _which(name: str) -> str:
    return shutil.which(name) or ""


def side_of(path: str) -> str:
    """⚠ WHICH OPERATING SYSTEM ANSWERED. A version proves a tool answered; only
    a path says which OS did. Its own output once read `[ OK ] npm 9.2.0` — a
    version with no path — and that is what let a Windows npm through."""
    if not path:
        return "not found"
    return "WINDOWS (via WSL interop)" if is_windows_binary(path) else "linux"


def is_windows_binary(path: str) -> bool:
    return path.startswith("/mnt/") or path.startswith("/c/")


def in_wsl() -> bool:
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8")
    except OSError:
        return bool(os.environ.get("WSL_DISTRO_NAME"))
    return ("microsoft" in release.lower() or "wsl" in release.lower()
            or bool(os.environ.get("WSL_DISTRO_NAME")))


def platform_name() -> str:
    system = platform.system()
    if system == "Windows":
        return "windows-native"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        return "wsl" if in_wsl() else "linux"
    return "unknown"


def _run(argv: list, timeout: int = 600) -> tuple:
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return out.returncode, (out.stdout or "") + (out.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, str(exc)


# ══════════════════════════════════════════════════════════ 1 · the platform

def _windows_has_a_real_session() -> tuple[bool, str]:
    """Has a REAL agent session ever produced a decision record here?

    ⚠ `purpose` IS THE DISCRIMINATOR, and it is why this can be checked at all.
    A preflight writes `purpose: preflight` and an install probe writes
    `install_probe`; only an agent hook running under `STING_PURPOSE=work`
    writes `work`. So "a real session happened" is a query, not a memory.

    ⚠ AND IT IS DELIBERATELY NOT "a session file exists". Preflight creates one
    every time it runs, so counting files would call the machine proven the
    moment somebody checked whether it was.
    """
    import json as _json
    root = Path(os.environ.get("STING_SESSION_ROOT")
                 or Path.home() / ".sting" / "sessions")
    try:
        logs = sorted(root.glob("*.log.jsonl"))
    except OSError:
        return False, ""
    for log in logs:
        try:
            for raw in log.read_text(encoding="utf-8", errors="replace").splitlines():
                if not raw.strip():
                    continue
                record = _json.loads(raw)
                if (record.get("event") == "decision"
                        and record.get("purpose") == "work"):
                    return True, f"{log.name[:8]}… seq {record.get('seq')}"
        except (OSError, ValueError):
            continue
    return False, ""


def check_platform() -> Result:
    where = platform_name()
    if where == "windows-native":
        # ⚠ THE CLAIM IS DERIVED, NOT TYPED. "SUPPORTED, NOT YET PROVEN" was a
        # sentence somebody would have to remember to delete, which is the same
        # class of staleness as the `wsl --install` advice this file carried for
        # two passes after WSL stopped being the plan.
        #
        # What would change it is ONE checkable fact: a decision record written
        # on THIS machine by a REAL agent session — not by preflight, not by an
        # install probe. `purpose` already distinguishes them, which is exactly
        # what that field exists for.
        proven, evidence = _windows_has_a_real_session()
        if proven:
            return Result(True, f"native Windows (PROVEN — {evidence})", lines=[
                "  A real agent session has run on this machine and left a",
                f"  decision record: {evidence}",
            ])
        # ⚠ NO LONGER FATAL. Phases 0–4 landed: the engine imports, the lock is
        # proven on a Windows runner, the five path sites are fixed, the case
        # carrier arrived on World, and `current` is a pointer file because
        # Windows cannot make a symlink without Developer Mode.
        #
        # ⚠ BUT IT IS NOT SILENT EITHER, and the difference matters. What has
        # NOT happened is a real Windows agent running a real session end to
        # end. An install here is supported and unproven, and saying so is the
        # whole of the honesty this project has spent four passes on.
        return Result(True, "native Windows (SUPPORTED, NOT YET PROVEN)", lines=[
            "  ⚠ NATIVE WINDOWS IS NEW. The engine imports, the lock is proven",
            "    on a Windows runner, and the path sites are fixed and tested.",
            "    What has NOT been done is a real coding agent running a real",
            "    session on Windows end to end.",
            "",
            "  ⚠ `current` is a POINTER FILE here, not a symlink — Windows needs",
            "    Developer Mode for symlinks. Atomicity is preserved (os.replace",
            "    on a file), and install_time()'s swap marker is that file.",
            "",
            "  Known gaps: the Scheduled Task arm, and `⚠` in a deny reason on a",
            "  cp1252 console. See docs/29-windows-phase-4.md.",
        ])
    if where == "unknown":
        return Result(False, f"unrecognised platform ({platform.system()})",
                       fatal=True, lines=[
            "  Supported: macOS and Linux (and WSL, which is no longer the",
            "  Windows plan). This has not failed because",
            "  something is broken — it has stopped because it cannot tell,",
            "  which is the honest answer.",
        ])
    detail = f"{where}   python {platform.python_version()} at {sys.executable}"
    lines = []
    if where == "wsl":
        lines.append("  inside WSL — every tool below is checked for being a "
                      "LINUX tool, not a Windows one reached through interop")
    return Result(True, detail, lines=lines)


# ════════════════════════════════════════════════════════════ 2 · python

def check_python() -> Result:
    """⚠ THIS FILE IS THE CHECK. `install.py` is Python, so if it is running at
    all a Python exists — what is left is whether it is NEW enough.
    `/usr/bin/python3` on macOS is 3.9.6, measured, so this fires on a Mac."""
    if sys.version_info[:2] >= MIN_PYTHON:
        return Result(True, ".".join(map(str, sys.version_info[:3])))
    newer = next((p for p in ("python3.13", "python3.12", "python3.11")
                   if _which(p)), "")
    lines = [f"  running     {platform.python_version()} at {sys.executable}",
              f"  need        {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ — the engine uses "
              f"StrEnum, which arrived there"]
    if newer:
        lines.append(f"  ⚠ a newer one IS here: re-run with it —")
        lines.append(f"        {newer} {Path(sys.argv[0]).name}")
    else:
        lines.append("  fix         " + ("brew install python@3.12"
                                          if platform_name() == "macos" else
                                          "sudo apt install -y python3"))
    return Result(False, f"python {platform.python_version()} is too old",
                   lines=lines, fatal=True)


# ═════════════════════════════════════════════════ 3 · node, npm, and the prefix

def check_node() -> Result:
    node, npm = _which("node"), _which("npm")

    # ⚠ THE INTEROP CHECKS BELOW ARE ABOUT WSL, AND ONLY WSL. Every one asks
    # "is this a WINDOWS binary reached from a LINUX shell" — which is a real
    # and invisible defect inside WSL, and is simply the normal state on native
    # Windows, where `C:\Program Files\nodejs\node.EXE` is the right answer.
    #
    # Measured: on windows-latest they fired, `install.py` exited 2 with
    # "1 check(s) still failing: node", and a native Windows install could not
    # complete for a reason that does not exist there. WSL is no longer the
    # Windows plan, so this guard must not police the plan that replaced it.
    if platform_name() == "windows-native":
        if not node:
            return Result(False, "no node", lines=[
                "  node   (not found)",
                "  ⚠ ADVISORY — for building the VS Code extension only.",
                "    The guard is pure Python and never runs node.",
                "  Install Node for Windows: https://nodejs.org/en/download"],
                fix_note="install Node", advisory=True)
        return Result(True, f"node {node}", lines=[
            f"  node   {node}",
            f"  npm    {npm or '(not found)'}",
            "  (WSL interop checks skipped — they describe a Linux shell "
            "reaching Windows binaries, which is not this)"])

    lines = [f"  node   {node or '(not found)'}   [{side_of(node)}]",
              f"  npm    {npm or '(not found)'}   [{side_of(npm)}]"]

    # ⚠ THE ASYMMETRY, CONFIRMED IN THE WILD. `npm --version` answered 10.9.2
    # from the WINDOWS PATH while `node --version` was not found. One of a pair
    # through interop and the other absent: the environment looked half-working
    # and nothing named the cause.
    if npm and is_windows_binary(npm) or (npm and not node):
        lines += ["  ⚠ npm answers and node does not, or npm is under /mnt —",
                   "    npm is answering from the WINDOWS PATH through WSL",
                   "    interop. That is not an install."]
    if (node and is_windows_binary(node)) or (npm and is_windows_binary(npm)) \
            or not node:
        return Result(False, "no usable Linux node", lines=lines + [
                           "  ⚠ ADVISORY, NOT A BLOCKER — the guard is pure",
                           "    Python and never runs node. This is only for",
                           "    building the VS Code extension, which is not",
                           "    in the release archive at all."],
                       fix=[_node_install_argv()], installs_software=True,
                       fix_note="install Node inside this OS",
                       advisory=True)

    # ⚠ THE ONE THAT BIT. node and npm were BOTH Linux and `npm root -g`
    # returned C:\Users\…\npm\node_modules, so `npm install -g <agent>`
    # installed a WINDOWS package whose binary wrote its config to the Windows
    # home — and the agent check then correctly found nothing in Linux.
    code, prefix = _run([npm, "config", "get", "prefix"], timeout=60)
    prefix = prefix.strip().splitlines()[-1] if prefix.strip() else ""
    lines.append(f"  npm prefix   {prefix or '(unreadable)'}")
    if _prefix_is_windows(prefix):
        target = str(Path.home() / ".npm-global")
        return Result(False, "npm is Linux but INSTALLS TO Windows",
                       advisory=True,
                       lines=lines + [
                           "  ⚠ `npm install -g` would install a WINDOWS package.",
                           "    Its binary would write its config to the WINDOWS",
                           "    home, and the agent check would then find nothing",
                           "    in Linux with no visible cause."],
                       fix=[[npm, "config", "set", "prefix", target]],
                       installs_software=True,
                       fix_note=f"point npm's prefix at {target}")
    return Result(True, f"node {_version(node)}, npm {_version(npm)}", lines=lines)


def _prefix_is_windows(prefix: str) -> bool:
    if not prefix:
        return False
    lowered = prefix.lower()
    return (prefix.startswith("/mnt/") or lowered.startswith("c:")
            or "\\appdata\\" in lowered or ":\\" in prefix)


def _version(path: str) -> str:
    code, out = _run([path, "--version"], timeout=30)
    return out.strip().splitlines()[0] if out.strip() else "?"


def _node_install_argv() -> list:
    if platform_name() == "macos":
        return ["brew", "install", "node"]
    return ["sudo", "apt-get", "install", "-y", "nodejs", "npm"]


# ═══════════════════════════════════════════════════════════ 4 · the agent

def check_agent() -> Result:
    from installer import detect

    survey = detect.agent_survey()
    lines, hits, windows_side = [], [], []
    for row in survey:
        if row["present"]:
            hits.append(row["agent"])
            lines.append(f"  {row['agent']:14} found   {row['evidence']}   [linux]")
        elif row.get("windows_side"):
            windows_side.append(row)
            lines.append(f"  {row['agent']:14} NOT in your Linux home — its "
                          f"config is on the WINDOWS side:")
            lines.append(f"                 {row['windows_side']}")
        else:
            lines.append(f"  {row['agent']:14} not found   looked in "
                          f"{', '.join(row['looked_in'])}")
    if hits:
        return Result(True, f"{len(hits)} agent(s): {', '.join(hits)}", lines=lines)
    if windows_side:
        # ⚠ NEVER USED SILENTLY, AND NOT FIXABLE FROM HERE. A config on the
        # Windows side belongs to a Windows agent process; a hook wired there
        # would never fire for the Linux session the developer works in. The
        # person has to launch the agent from their Linux home once, and that
        # opens a browser — so it is on the human side by construction.
        return Result(False, "an agent's config is on the Windows side",
                       lines=lines + [
                           "  fix         cd ~ && <agent>    (from your LINUX home,",
                           "              so it writes ~/.<agent>), then re-run this."])
    npm = _which("npm")
    return Result(False, "no coding agent found", lines=lines,
                   fix=[[npm, "install", "-g", "@anthropic-ai/claude-code"]]
                        if npm else [],
                   installs_software=True,
                   fix_note="install Claude Code")


# ══════════════════════════════════════════════════════════ 5 · scratch

def check_scratch(scratch: str | None) -> Result:
    """⚠ CREATED BEFORE install.py RUNS, NOT AFTER IT FAILS. A real install
    named a `--scratch` that did not exist; the install SUCCEEDED and preflight
    failed afterwards, which points at the guard rather than at the flag."""
    if not scratch:
        return Result(True, "none named — install.py will propose or decline")
    target = Path(scratch).expanduser()
    if target.is_dir():
        return Result(True, f"{target} exists")
    return Result(False, f"{target} does not exist",
                   lines=["  ⚠ install.py would SUCCEED and preflight would fail",
                           "    afterwards, which points at the guard, not at this."],
                   fix=[["mkdir", "-p", str(target)]],
                   fix_note=f"create {target}")


# ═══════════════════════════════════════════════════ running them, and fixing

# ─────────────────────────────────────────────────── three checks, three failures

NETWORK_FSTYPES = {
    "nfs", "nfs4", "cifs", "smbfs", "afpfs", "webdav", "fuse.sshfs", "9p",
    # ⚠ DrvFs IS THE WSL ONE AND IT IS THE POINT OF THIS CHECK. `~` on /mnt/c
    # means every session file, every lock and every fsync crosses the Windows
    # filesystem driver — which is the "filesystem stops answering" case
    # `core/locking.LOCK_TIMEOUT` was built for, and the only reachable cause of
    # that wedge.
    "drvfs", "drv_fs", "v9fs", "virtiofs",
}


def home_mount() -> tuple:
    """(fstype, source) for the mount that holds $HOME, or (None, why).

    ⚠ READ, NEVER GUESSED FROM THE PATH. `/mnt/c/Users/...` is the obvious
    shape and it is not the only one: a bind mount, an automounted home, or an
    SMB share mounted anywhere all look local by name.
    """
    home = str(Path.home().resolve())
    try:
        mounts = Path("/proc/mounts")
        if mounts.exists():
            best = (None, None, -1)
            for line in mounts.read_text(errors="replace").splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                source, point, fstype = parts[0], parts[1], parts[2]
                if (home == point or home.startswith(point.rstrip("/") + "/")) \
                        and len(point) > best[2]:
                    best = (fstype, source, len(point))
            if best[0]:
                return best[0], best[1]
            return None, "no mount in /proc/mounts covers $HOME"
        # macOS and the BSDs: `mount` is the only portable answer, and it is a
        # subprocess — measured below, and this runs once per install.
        code, out = _run(["/sbin/mount"], timeout=10)
        if code != 0:
            return None, "could not run mount"
        best = (None, None, -1)
        for line in out.splitlines():
            if " on " not in line or " (" not in line:
                continue
            point = line.split(" on ", 1)[1].rsplit(" (", 1)[0]
            fstype = line.rsplit("(", 1)[1].split(",")[0].strip(") ")
            if (home == point or home.startswith(point.rstrip("/") + "/")) \
                    and len(point) > best[2]:
                best = (fstype, line.split(" on ")[0], len(point))
        if best[0]:
            return best[0], best[1]
        return None, "no mount covers $HOME"
    except (OSError, IndexError) as exc:
        return None, f"could not read the mount table ({exc})"


def check_home() -> Result:
    """⚠ A NETWORK HOME IS SUPPORTED AND CARRIES A NAMED RISK. It never stops an
    install: plenty of enterprises put `$HOME` on NFS and the guard works there.
    What it does is tell the person, because the failure it leads to is silent —
    a filesystem that stops answering holds the session lock, and every hook then
    waits out `STING_LOCK_TIMEOUT` and decides from NO STATE, which means that
    action's labelling is never recorded.
    """
    fstype, source = home_mount()
    if not fstype:
        return Result(True, f"could not determine ({source})", lines=[
            "  not a failure — the check could not answer, which is different "
            "from answering no"])
    if fstype.lower() in NETWORK_FSTYPES:
        return Result(True, f"⚠ {fstype} — a NETWORK or CROSS-OS filesystem", lines=[
            f"  $HOME        {Path.home()}  on {source} ({fstype})",
            "  ⚠ this is SUPPORTED and it has a named cost. Sting's session",
            "    state is lock-protected, and a filesystem that stops",
            "    answering holds that lock. Every hook then waits out",
            "    STING_LOCK_TIMEOUT (5s) and decides from NO SESSION STATE:",
            "    the verdict still fails closed at sinks, but that action's",
            "    labelling is NOT recorded — a secret read in that window is",
            "    not remembered later.",
            "  what to do   nothing is required. If you can, point",
            "               STING_SESSION_ROOT at a local disk.",
        ])
    return Result(True, f"{fstype} (local)", lines=[])


def check_shell() -> Result:
    """Which shell/environment is running this, as far as it CAN be known.

    ⚠ WHAT IS CATCHABLE AND WHAT IS NOT, STATED RATHER THAN IMPLIED.

    CATCHABLE, because each sets a variable nothing else does:
        Git Bash / MSYS2   `MSYSTEM` (MINGW64, MSYS…) — and this is the one
                           worth catching: it looks like bash, it is not WSL,
                           and paths it hands to a Windows python are
                           translated in ways neither side expects.
        WSL                `WSL_DISTRO_NAME`, plus `microsoft` in the kernel
                           release.
        Cygwin             `OSTYPE=cygwin` / `uname -o`.

    ⚠ NOT CATCHABLE, AND THIS IS THE HONEST HALF: **PowerShell versus cmd.exe
    cannot be told apart from inside a child process on modern Windows.**
    `$PSModulePath` is the obvious tell and it is a MACHINE-LEVEL environment
    variable there, so it is present under `cmd.exe` too — a check on it would
    report PowerShell for both, which is worse than reporting neither. There is
    no inherited variable that distinguishes them, and walking the parent
    process tree needs a dependency this installer does not have.

    So: one of the two named onboarding failures — a WSL command run in a
    Windows shell — is only partly detectable, and the part that is detectable
    is the part that matters, because a Windows python is what actually decides
    where everything lands. `check_python_side` is the check that catches it.
    """
    system = platform.system()
    msystem = os.environ.get("MSYSTEM")
    if msystem:
        return Result(True, f"⚠ Git Bash / MSYS ({msystem})", lines=[
            "  ⚠ this is a POSIX-looking shell on Windows, and it is NOT WSL.",
            "    Paths it passes to a Windows python are translated on the way",
            "    through, so an installer run here can write config in one",
            "    path shape and an agent read it in another.",
            "  what to do   run this from a WSL shell instead:",
            "               wsl  ->  cd /path/to/sting  ->  python3 install.py",
        ])
    if os.environ.get("WSL_DISTRO_NAME"):
        return Result(True, f"WSL ({os.environ['WSL_DISTRO_NAME']})", lines=[])
    if (os.environ.get("OSTYPE") or "").startswith("cygwin"):
        return Result(True, "⚠ Cygwin", lines=[
            "  ⚠ same class as Git Bash: a POSIX shell on Windows, not WSL."])
    if system == "Windows":
        return Result(True, "a native Windows shell", lines=[
            "  ⚠ WHICH ONE CANNOT BE KNOWN FROM HERE. PowerShell and cmd.exe",
            "    are indistinguishable to a child process on modern Windows —",
            "    PSModulePath is machine-level, so it is set under both. This",
            "    line says what is true and stops there.",
        ])
    return Result(True, f"{os.environ.get('SHELL') or 'unknown shell'}", lines=[])


def check_python_side() -> Result:
    """⚠ THE INTERPRETER RUNNING THIS INSTALLER IS THE ONE THAT DECIDES WHERE
    EVERYTHING LANDS, AND IT WAS THE ONE TOOL WITH NO SIDE.

    node and npm are each reported with a SIDE and a PATH by the interop guard,
    because a Windows npm installed a Windows package once. The interpreter was
    not — and it is strictly more consequential: `Path.home()`, the install
    prefix, the session root and every path written into an agent's hook config
    all come from THIS process. A Windows python running under WSL writes a
    guard into the Windows home that the Linux agent will never load.
    """
    executable = sys.executable or ""
    if not _in_wsl():
        return Result(True, f"{executable}", lines=[])
    if is_windows_binary(executable):
        return Result(False, "⚠ this is the WINDOWS python, seen from WSL", lines=[
            f"  python3      {executable}   [{side_of(executable)}]",
            f"  home         {Path.home()}",
            "  ⚠ EVERYTHING THIS INSTALLER WRITES WOULD LAND ON THE WINDOWS",
            "    SIDE — the install prefix, the session root, and the hook",
            "    command inside your agent's config. A Linux agent would never",
            "    load it, and nothing later would say why.",
            "  fix          use the distro's interpreter:",
            "               sudo apt install python3      # once",
            "               /usr/bin/python3 install.py",
        ])
    return Result(True, f"linux python at {executable}", lines=[])


def _in_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in platform.uname().release.lower()
    except Exception:                                  # noqa: BLE001
        return False


CHECKS = ("platform", "python", "shell", "interpreter", "node", "home",
          "agent", "scratch")


def survey(scratch: str | None = None) -> dict:
    """Every check, asked. Nothing is written and nothing is fixed."""
    return {"platform": check_platform(), "python": check_python(),
            "shell": check_shell(), "interpreter": check_python_side(),
            "node": check_node(), "home": check_home(),
            "agent": check_agent(), "scratch": check_scratch(scratch)}


def _recheck(name: str, scratch: str | None) -> Result:
    return survey(scratch)[name]


def apply_fixes(results: dict, scratch: str | None, say,
                 *, unattended: bool = False, changed: list | None = None) -> dict:
    """Run each fix, then RE-RUN ITS CHECK. Never trust an exit code.

    ⚠ THE ENTIRE REASON THIS FUNCTION EXISTS IN THIS SHAPE. `npm install -g`
    exits 0 while installing to the wrong operating system. A fix that reports
    success from its own return value would have declared that machine ready.

    ⚠ AND `unattended` IS NOT "DO ANYTHING". `--yes` means "do not ask me".
    Under it, any fix marked `installs_software` — one that changes the machine
    outside our own prefix — is NAMED AND SKIPPED, never run. See
    `Result.installs_software` for the walk that made this necessary.

    `changed` collects a line per action actually taken, so the Done block can
    report what an unattended run did to the machine where a person reads it.
    """
    outcome = {}
    for name in CHECKS:
        result = results[name]
        if result.ok or not result.fix:
            continue
        if unattended and result.installs_software:
            # ⚠ NAMED, NOT SILENTLY DROPPED. A skipped step that nobody is told
            # about is the same class of problem as an unconsented one.
            say(f"  ⚠ NOT RUN under --yes: {result.fix_note}")
            say(f"    This would change your machine outside ~/.sting, and")
            say(f"    --yes means 'do not ask me', not 'do anything'. Run it")
            say(f"    yourself if you want it:")
            for argv in result.fix:
                say(f"        $ {' '.join(argv)}")
            outcome[name] = result
            if changed is not None:
                changed.append(f"NOT done (needs your consent): {result.fix_note}")
            continue
        say(f"  fixing     {result.fix_note}")
        failed = False
        for argv in result.fix:
            say(f"    $ {' '.join(argv)}")
            code, out = _run(argv)
            # ⚠ RECORDED AFTER THE FACT, NOT BEFORE IT. Appending before `_run`
            # reported a failed `brew install node` as something that CHANGED
            # the machine — reporting success from an exit code, which is the
            # exact defect the rest of this file was written against,
            # reintroduced in the ledger meant to be the honest one.
            if changed is not None:
                changed.append(" ".join(argv) if code == 0
                                else f"ATTEMPTED AND FAILED (exit {code}): "
                                      f"{' '.join(argv)}")
            if code != 0:
                say(f"    ⚠ exited {code}")
                for line in (out or "").strip().splitlines()[-4:]:
                    say(f"      {line}")
                failed = True
                break
        again = _recheck(name, scratch)
        outcome[name] = again
        if again.ok:
            say(f"  verified   {name}: {again.detail}")
        else:
            # ⚠ STOP. Reporting a fix as done because its process ended is the
            # defect this whole file is built against.
            say(f"  ⚠ STILL FAILING after the fix: {name} — {again.detail}")
            for line in again.lines:
                say(line)
            if not failed:
                say("    the command SUCCEEDED and the check still fails, which")
                say("    is the shape this verifies for: something answered, and")
                say("    it was the wrong thing.")
    return outcome
