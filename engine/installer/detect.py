"""What is on this machine. Everything here PROPOSES; nothing here decides.

⚠ THE TRUST BOUNDARY IS A DECLARATION, SO IT IS CONFIRMED AND NEVER INFERRED.
`STING_ROOTS` unset produced 74 of 89 secret-rule denials in one measured period
— every one an ordinary edit to a sibling repository that the guard read as
leaving the project. The fix is not to guess harder. Auto-widening to every
sibling directory would be the installer deciding what the developer trusts,
from the shape of a directory listing, and a boundary chosen by software is a
boundary nobody agreed to.

So `propose_roots()` returns a proposal with its reasoning attached, the
installer PRINTS it, and the operator says yes. A declined sibling is a real
answer and the installer says what it will cost.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from core import probes

# Where each agent keeps hook configuration. Project-local first, then the
# user-level file — the same order preflight already uses, so the installer and
# the checker cannot disagree about where an agent was found.
#
# ⚠ `~` IS LEFT UNEXPANDED, AND THIS IS THE FIX FOR A REAL TRAP. These were
# written as `Path.home() / ".claude"`, which resolves AT IMPORT. So a test that
# sets `$HOME` to a temp directory — believing it has isolated the installer,
# and saying so in a comment — was silently still pointed at the developer's own
# home. It passed anyway, because he HAS a `~/.claude`; on a CI runner, which
# has none, the same test failed with "no coding agent found" naming the
# RUNNER's home rather than the temp one the test had set.
#
# ⚠ EXPANDED BY `expand()` AT CALL TIME. `Path("~/x").is_absolute()` is FALSE,
# so anything asking that question must expand first — `config_for` does, and
# that is what separates a user-level config from a project-local one.
AGENT_CONFIGS = {
    "claude-code": [Path(".claude/settings.json"),
                     Path("~/.claude/settings.json")],
    "cursor":      [Path(".cursor/hooks.json"),
                     Path("~/.cursor/hooks.json")],
    "codex":       [Path(".codex/hooks.json"),
                     Path("~/.codex/hooks.json")],
    "copilot":     [Path(".github/hooks/hooks.json"),
                     Path(".claude/settings.json")],
    "antigravity": [Path(".agents/hooks.json"),
                     Path("~/.gemini/config/hooks.json")],
}

# A directory whose presence means the agent is installed, even when it has no
# hook config yet — which is the normal state before this installer runs.
AGENT_MARKERS = {
    "claude-code": [Path("~/.claude")],
    "cursor":      [Path("~/.cursor")],
    "codex":       [Path("~/.codex")],
    "copilot":     [Path("~/.copilot"), Path("~/.config/github-copilot")],
    "antigravity": [Path("~/.antigravity"), Path("~/.gemini")],
}


def expand(path) -> Path:
    """`~` against the CURRENT `$HOME`, and an absolute path untouched.

    An already-absolute path passes through unchanged, so a caller that has
    resolved one — or a test that monkeypatches `AGENT_MARKERS` with a temp
    directory — keeps working.
    """
    return Path(path).expanduser()


def agent_markers() -> dict:
    """`AGENT_MARKERS`, expanded now rather than at import."""
    return {agent: [expand(p) for p in paths]
            for agent, paths in AGENT_MARKERS.items()}


def agent_configs() -> dict:
    """`AGENT_CONFIGS`, expanded now rather than at import."""
    return {agent: [expand(p) for p in paths]
            for agent, paths in AGENT_CONFIGS.items()}


def config_for(agent: str) -> tuple:
    """Where to WRITE this agent's hook config, and whether it is user-level.

    ⚠ PREFER AN ABSOLUTE PATH. `AGENT_CONFIGS` lists project-local candidates
    first because that is where preflight should LOOK for one — but writing to a
    relative path means writing into whatever directory the installer happened
    to be run from. For `copilot` BOTH candidates are relative, so the naive
    "last entry" rule dropped `.claude/settings.json` into the checkout. Found
    by running the published instructions in a clean shell, which is the only
    reason it was found at all.

    When no absolute candidate exists the project-local one is used and the
    caller is told, so "this config only applies inside this directory" is
    stated rather than discovered later.
    """
    candidates = [expand(p) for p in AGENT_CONFIGS[agent]]
    for path in candidates:
        if path.is_absolute():
            return path, True
    return (Path.cwd() / candidates[0]).resolve(), False


# ⚠ THE WINDOWS HOME, WHEN WE ARE IN WSL. THIRD INSTANCE OF ONE CLASS.
#
#   machine 2   Cursor installed, marker not where AGENT_MARKERS says
#   machine 3   Claude Code launched from /mnt/c/Users/<user>, printed a Windows
#               cwd, and wrote its config to the WINDOWS home. `~/.claude` did
#               not exist, so the sweep correctly reported it did not find one —
#               and the developer, who had just used Claude Code, read that as
#               the tool being broken.
#
# So on WSL a miss in the Linux home is not the end of the search. If the marker
# is on the Windows side we SAY SO and give the fix.
#
# ⚠ AND IT IS NEVER SILENTLY USED. `present` stays False, so nothing installs
# into it. The hook must run in Linux: a config on the Windows side belongs to a
# Windows agent process, and a hook wired there would never fire for the Linux
# session the developer is actually working in. Reporting it is help; using it
# would be the misdiagnosis one level deeper.
def in_wsl() -> bool:
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8")
    except OSError:
        return bool(os.environ.get("WSL_DISTRO_NAME"))
    return "microsoft" in release.lower() or "wsl" in release.lower() \
        or bool(os.environ.get("WSL_DISTRO_NAME"))


def windows_homes() -> list:
    """Every plausible Windows home directory, seen from inside WSL."""
    if not in_wsl():
        return []
    users = Path("/mnt/c/Users")
    if not users.is_dir():
        return []
    named = os.environ.get("USER") or ""
    homes = [users / named] if named and (users / named).is_dir() else []
    try:
        homes += [d for d in sorted(users.iterdir())
                   if d.is_dir() and d.name not in ("Public", "Default",
                                                     "Default User", "All Users")
                   and d not in homes]
    except OSError:
        pass
    return homes


def _windows_side_marker(markers) -> str | None:
    """The same marker NAME, under a Windows home. None when there is none."""
    for home in windows_homes():
        for marker in markers:
            candidate = home / marker.name
            try:
                if candidate.exists():
                    return str(candidate)
            except OSError:
                continue
    return None


def agent_survey() -> list:
    """EVERY supported agent, found or not, with the paths that decided it.

    ⚠ REPORTING ONLY WHAT WAS FOUND HAS ALREADY COST AN EVENING. A second
    developer had Cursor installed and this installer did not list it, because
    detection is a marker DIRECTORY and his was not where `AGENT_MARKERS` says.
    The output named the agents it found and said nothing about the one it
    missed, so the only clue that `--agent cursor` was needed was knowing the
    tool well enough to guess.

    A miss is only printed today when the count reaches ZERO — `no_agent_found`
    lists every path it tried. That is the wrong trigger: the confusing case is
    finding SOME agents, because then the run looks successful. So the survey is
    always complete and the caller prints the misses beside the hits.

    Same shape as working rule 13: "I found nothing to check" is not "there is
    nothing to find", and a report that only carries hits cannot tell them apart.
    """
    survey = []
    for agent, markers in agent_markers().items():
        hit = next((m for m in markers if m.exists()), None)
        config, user_level = config_for(agent)
        # Only asked when the Linux home missed — the answer is a diagnosis, not
        # a fallback, and asking always would cost a /mnt walk on every install.
        windows_side = None if hit else _windows_side_marker(markers)
        survey.append({
            "agent": agent,
            "present": hit is not None,
            "evidence": str(hit) if hit else None,
            "windows_side": windows_side,
            "looked_in": [str(m) for m in markers],
            "config": str(config),
            "user_level": user_level,
        })
    return survey


def agents_present() -> list:
    """Which agents this machine appears to have, and what said so.

    Kept as the found-only view because callers that only want to install into
    something should not have to filter; `agent_survey` is what REPORTS.
    """
    return [{k: v for k, v in row.items() if k not in ("present", "looked_in")}
             for row in agent_survey() if row["present"]]


# ------------------------------------------------------------ sibling repos

def propose_roots(start: Path | None = None) -> dict:
    """Sibling git repositories, as a PROPOSAL with its reasoning.

    Looks one level up from the checkout — `~/sting/sting-engine` implies
    `~/sting/*`. That is the shape the measured failure had, and it is the only
    shape guessed at: an installer that walked the filesystem looking for `.git`
    would find node_modules, vendored copies, and other people's work.
    """
    start = Path(start or Path(__file__).resolve().parent.parent)
    parent = start.parent
    siblings = []
    if parent.is_dir():
        for child in sorted(parent.iterdir()):
            if child.is_dir() and (child / ".git").exists():
                siblings.append(child)
    return {
        "proposed": [str(p) for p in siblings],
        # ⚠ `os.pathsep`, NOT ":". This is the value install.py WRITES as the
        # trust boundary, so a colon here on Windows produces a STING_ROOTS
        # that `split_roots` reads as one path that does not exist — the
        # 74-of-89-denial condition, written by the installer itself.
        "value": probes.join_roots(siblings),
        "searched": str(parent),
        "why": ("every git repository beside the checkout. STING_ROOTS unset "
                 "produced 74 of 89 secret-rule denials in one measured period, "
                 "all of them ordinary edits to a sibling read as leaving the "
                 "project"),
        "cost_if_declined": ("edits to any repo not listed will be judged as "
                              "writing OUTSIDE the project, so ordinary work in "
                              "it will be denied by secret_derived_external"),
    }


# ---------------------------------------------------------------- identity

_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def propose_identity() -> dict:
    """The strings that identify this machine's owner, for log redaction.

    ⚠ THIS IS FOR PUBLISHED ARTIFACTS ONLY — a vendored fixture, a demo. It is
    NOT applied to what the shipper sends: a manager seeing which developer ran
    a command is the product, not a leak. Collected here because the installer
    is the one moment someone can be asked, and asking later never happens.
    """
    import subprocess

    found, sources = [], {}

    def add(value, where):
        value = (value or "").strip()
        if value and value not in found:
            found.append(value)
            sources[value] = where

    add(Path.home().name, "the home directory name")
    add(os.environ.get("USER"), "$USER")
    for key, flag in (("name", "user.name"), ("email", "user.email")):
        try:
            out = subprocess.run(["git", "config", "--get", flag],
                                  capture_output=True, text=True, timeout=5)
            add(out.stdout.strip(), f"git config {flag}")
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        add(subprocess.run(["hostname"], capture_output=True, text=True,
                            timeout=5).stdout.strip().split(".")[0], "hostname")
    except (OSError, subprocess.SubprocessError):
        pass

    return {
        "identifiers": found,
        "sources": sources,
        "used_for": ("tools/redact_logs.py, when building a fixture that will "
                      "be published or shared"),
        "not_used_for": ("what the shipper sends to a collector — every record "
                          "ships masked by the type of each value Sting "
                          "recognises (shipper/mask.py), which does not read "
                          "this list"),
    }


# ------------------------------------------------------------------ scratch

# Agent scratch directories, as a template per agent. The uid is SUBSTITUTED,
# never assumed: the previous version wrote this developer's own macOS uid into
# both candidate paths, so on any other account both missed and it fell through
# to a third entry — a bare `TMPDIR or /tmp` — and the installer proposed ALL of
# /tmp to everybody but its author.
_SCRATCH_TEMPLATES = ("claude-{uid}",)

# Where those live. `/private/tmp` is macOS's real /tmp; TMPDIR is per-user on
# macOS and usually unset on Linux.
_TMP_ROOTS = ("/private/tmp", "/tmp")


def _owned_directory(path: Path, uid: int) -> bool:
    """A directory, existing, owned by this user, and not a symlink to one.

    `lstat`, so a symlink planted at a predictable name cannot point the
    exemption somewhere else — the whole /tmp family is world-writable, which is
    exactly where that trick lives.
    """
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and info.st_uid == uid


def propose_scratch() -> dict:
    """Directories the agent treats as disposable, for the deletion exemption.

    ⚠ A WRONG PROPOSAL HERE IS WORSE THAN NO PROPOSAL, WHICH IS WHY THE
    FALLBACK IS GONE. `STING_SCRATCH` is not a hint: every path under it is
    exempt from the `irreversible_action` prompt, so `rm -rf <it>/anything` goes
    through without asking. Proposing `/tmp` wholesale handed that exemption
    over a whole shared directory to anyone who accepted a proposal without
    reading it — and the people most likely to accept without reading are
    exactly the people a proposal exists for.

    ⚠ PROPOSING NOTHING IS A LEGITIMATE ANSWER, AND IT IS NOW WHAT HAPPENS WHEN
    NOTHING PLAUSIBLE IS FOUND. Unset means no exemption. That costs prompts —
    23 of 52 real `irreversible_action` prompts were an agent deleting its own
    scratch files — and a prompt is the safe direction. A missing exemption is
    friction; a wrong one is a deletion nobody was asked about.

    ⚠ OWNERSHIP IS CHECKED. `/tmp/claude-1000` on a shared machine may belong to
    somebody else, and an exemption for `rm -rf` inside another user's directory
    is not friction, it is a weapon. Anything not owned by the caller is not
    proposed, however well its name matches.
    """
    uid = getattr(os, "getuid", lambda: None)()
    candidates: list[str] = []
    if uid is not None:
        roots = [Path(r) for r in _TMP_ROOTS]
        env_tmp = os.environ.get("TMPDIR")
        if env_tmp:
            roots.append(Path(env_tmp))
        for root in roots:
            for template in _SCRATCH_TEMPLATES:
                path = root / template.format(uid=uid)
                if str(path) in candidates or not _owned_directory(path, uid):
                    continue
                candidates.append(str(path))

    why = ("STING_SCRATCH declares which directories are agent-owned and "
            "recreatable. Without it, `rm -rf` of the agent's own scratch "
            "files prompts — 23 of 52 real irreversible_action prompts "
            "were exactly that")
    if candidates:
        return {"proposed": candidates[:1], "value": candidates[0],
                 "why": why, "note": ""}
    return {
        "proposed": [], "value": "", "why": why,
        # Said out loud, because "(none found)" on its own reads as a gap to be
        # worked around — and the thing people work around it with is /tmp.
        "note": ("nothing was proposed, and that is the safe answer rather "
                  "than a gap. An unset STING_SCRATCH means NO deletion "
                  "exemption: you are prompted before an `rm -rf`, which is "
                  "friction and not a risk. Set it only for a directory you "
                  "would be content for an agent to delete without asking:\n"
                  "             install.py --scratch /path/you/own"),
    }
