"""Placing the installed copy, and taking it away again.

────────────────────────────────────────────────────────────────────────────────
WHAT `current` ACTUALLY IS, AND WHY THE TREE IS A COPY
────────────────────────────────────────────────────────────────────────────────

    ~/.local/share/sting/<version>/    a COPY of the code. Never a link.
    ~/.local/share/sting/current  ->   a SYMLINK to one of those directories
    ~/.sting/                          state, logs, grants. Untouched by this.

Two different things, and conflating them is the mistake this file exists to
avoid:

  THE TREE IS A COPY. If the installed path were a symlink to the checkout, the
  running guard would once again BE the file being edited — which is the exact
  collision the install shape was designed to remove. Editing `core/engine.py`
  would change the policy mid-session, so a developer debugging a rule would be
  debugging a moving target, and a half-written file would be a half-written
  policy. A copy means the checkout can be edited freely and the guard keeps
  deciding by the version it was installed with.

  `current` IS A SYMLINK, and it must be, because it is the one thing the
  agent's hook config points at. Repointing it is how a new version takes
  effect without editing five agents' settings files. It is swapped ATOMICALLY —
  a new link is made at a temp name and `os.replace`d over the old one — so
  there is no instant where a hook could follow a `current` that does not exist.

  THE COST, STATED: an install step. `core/engine.py` edits do nothing until
  `install.py` runs again. That is deliberate friction at a rare moment instead
  of constant friction at a routine one, and `--status` exists to make the drift
  visible rather than mysterious.

────────────────────────────────────────────────────────────────────────────────
⚠ REINSTALL IS THE allow_once CHOKEPOINT
────────────────────────────────────────────────────────────────────────────────

A one-shot grant authorises ONE action under ONE policy. Carrying it across a
reinstall would let a human's approval of "this exact command, under the rules I
was looking at" be spent under rules they never saw — and the reinstall itself
is the moment the rules change.

So every install REVOKES outstanding grants, and does it two ways because one
of them is racy on its own:

  1. it deletes every `*.allow-once.json` under the session root, and
  2. it records WHEN it happened — `installed_at` in INSTALL.json, and the
     `current` symlink's own mtime — and `allow_once.consume` refuses any grant
     issued before that moment.

(1) alone loses to a grant written between the sweep and the swap. (2) alone
leaves stale files on disk that a reader would reasonably think are live. Both
together mean an outstanding grant is neither present nor redeemable.

⚠ (2) USED TO BE A VERSION EQUALITY, AND IT BROKE THE APPROVE BUTTON. It
required `grant["guard_version"] == installed_version()`, which only a writer
that knows this codebase's version string can satisfy — and the primary producer
of grants is `extension/src/allowOnce.ts`, which writes `granted_at` and no
version. With no install both sides were `None` and everything worked; the day
an install appeared on the machine, every grant the extension wrote was refused.
A time comparison is the semantic this always wanted, and it holds for a grant
written in any language. See `core/allow_once.install_time`.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path

# What gets copied. Everything the hook needs at runtime and nothing else —
# no tests, no logs, no .git, no corpus. An install is not a checkout.
#
# ⚠ `sting_hook.py` IS THE ENTRY POINT AND `daemon/` IS HOW IT IS FAST, so both
# are payload. Shipping one without the other would leave an entry point whose
# first act is an import that is not there — and because its fallback still
# works, the failure would be a silent doubling of latency rather than an error
# anybody sees.
# ⚠ `installer/cursor_bridge.ps1` IS PAYLOAD, AND IT IS THE ONE FILE HERE THAT
# ONLY ONE PLATFORM EXECUTES. It is copied on macOS and Linux too, deliberately:
#
#   * ONE PAYLOAD, OR THE VERSION MEANS TWO THINGS. Making the list conditional
#     would make `compute_version`'s content hash and the missing-payload
#     refusal below platform-dependent, so an archive built on macOS could not
#     be installed on Windows without the refusal firing on a file the builder
#     never had. A payload that differs by host is a release nobody can check.
#   * IT COSTS 4 KB AND EXECUTES NOTHING. Nothing on POSIX ever names it; the
#     hook command there is unchanged.
#
# ⚠ AND IT MUST BE HERE RATHER THAN COPIED INTO `<prefix>/` BESIDE THE POINTER,
# WHICH IS WHERE IT USED TO GO. Three things follow from being in the version
# directory, and each was a live defect:
#
#   1. THE BRIDGE AND THE ENGINE IT SPAWNS ARE NOW ONE ARTIFACT. The bridge
#      resolves `sting_hook.py` as its own SIBLING, so a v1 bridge can never
#      drive a v2 entry point. Beside the pointer it outlived every upgrade.
#   2. THE MISSING-PAYLOAD REFUSAL NOW COVERS IT. An archive without the bridge
#      used to install cleanly and write a `hooks.json` naming a `.ps1` that was
#      not on disk — the hook then cannot start, and `failClosed:false` turns
#      that into a SILENT ALLOW.
#   3. UNINSTALL NOW REMOVES IT. `remove()` deletes directories under the
#      prefix; a bare FILE at `<prefix>/cursor_bridge.ps1` was skipped, and the
#      leftover then made `prefix.rmdir()` fail, so the uninstaller reported
#      "something else lives here" about a file it had written itself.
# ⚠ `envfile.py` WAS MISSING FROM THIS LIST FOR THE WHOLE OF ITS LIFE, AND
# EVERY INSTALL FROM THE ARCHIVE PRODUCED A HOOK THAT COULD NOT RUN.
#
# It arrived in `db2aaca` — the Windows transport pass — as the thing that
# replaced the env prefix in `hooks.json`, and BOTH entry points import it:
# `sting_hook.py:151` and `hook_entry.py:532`. It was never added here. Measured
# by installing from the release tarball into a clean HOME:
#
#     [FAIL] entry point runnable   exit=1
#            ModuleNotFoundError: No module named 'envfile'
#     [FAIL] synthetic action through the hook   ModuleNotFoundError
#     [FAIL] credential exfiltration is denied — the hook ran but recorded
#            no decision — the payload never reached the engine
#
# ⚠ AND IT IS INVISIBLE ON A DEVELOPER'S MACHINE, which is why nothing caught
# it. From a checkout, `sys.path` already contains the repo root, so `import
# envfile` resolves to the file sitting beside the entry point in the SOURCE
# tree — not to anything the installer placed. Only a real install into a clean
# HOME separates the two.
#
# ⚠ THE MISSING-PAYLOAD REFUSAL BELOW COULD NOT HAVE CAUGHT IT EITHER: it
# checks that everything NAMED here exists, and this file's whole failure was
# that the name was absent. A list cannot notice its own omission — which is
# what `tests/test_the_payload_covers_every_runtime_import.py` is for: it walks
# the entry points' imports and demands each resolve inside the placed tree.
PAYLOAD = ("core", "adapters", "daemon", "shipper", "tools",
           "hook_entry.py", "sting_hook.py", "envfile.py",
           "installer/cursor_bridge.ps1",
           # ⚠ G2. `tools/preflight.py` SHIPS and its supervisor check does
           # `from installer import supervisor` — which did NOT ship, so on
           # every real install the one diagnostic that could catch a dead
           # supervisor degraded to "could not be determined: ImportError" and
           # preflight still exited 0. A list cannot notice its own omission;
           # tests/test_the_payload_covers_every_runtime_import.py now can —
           # it scans every .py in a PLACED tree, not the entry points only.
           #
           # Supervisor status is not a file fact — it ASKS launchctl / systemd
           # / schtasks — so the query code must ship somewhere. Since docs/84
           # that code is `shipper/service.py`, which ships with `shipper/`, and
           # the installed preflight and `install.py --status` answer from that
           # ONE oracle. This entry is now the WRITE half, which nothing in a
           # placed tree imports any more. Kept so that the move changed no
           # install's contents; dropping it is (b)'s "~800 fewer lines" and is
           # a one-line decision about what ships, not a code move.
           "installer/supervisor.py",
           "installer/console.py",
           # ⚠ TRANSITIVE, AND THE GUARD FOUND IT, NOT A READ. `shipper/service.py`'s
           # module-level imports are stdlib-only, but `_prefix_tag()` does
           # `from installer import place` inside the function — for
           # `default_prefix()`, which the per-install LABEL is derived from.
           # `loaded()` cannot ask launchd the right question without it, so it
           # is load-bearing for a correct status, not decorative. `place.py`
           # imports only stdlib; the chain ends here (test-proven, per run).
           "installer/place.py",
           # ⚠ THE FOUR RATCHETED OMISSIONS — SAME CLASS AS G2 — COLLAPSED TO
           # THREE FILES. `tools/redact_logs.py` and `tools/identity_census.py`
           # both do `from installer.detect import propose_identity` inside a
           # function; `tools/retention.py` does `from installer import
           # recorded`; `tools/grade_engine.py` does `from runner import
           # replay`. Verified in a PLACED tree from a neutral cwd — not the
           # checkout, where the namespace package merges with the source —
           # all three failed to import while `installer.supervisor` (G2's
           # fix) passed as the control. Transitively: `detect.py` imports
           # only core.probes, `recorded.py` only stdlib, `runner/replay.py`
           # core.audit_log and the third-party `yaml`, which this list cannot
           # ship and the guard does not check. grade_engine on an install
           # therefore RESOLVES but still cannot RUN without PyYAML and the
           # scenarios/ corpus; stated here, not fixed here — this pass ships
           # what is imported and restructures nothing.
           "installer/detect.py",
           "installer/recorded.py",
           "runner/replay.py")

# Files inside those whose CONTENT decides the version. Tools and the shipper
# are copied but do not version the policy: changing a report's wording must not
# invalidate every outstanding grant.
#
# ⚠ `daemon/` AND `sting_hook.py` ARE DELIBERATELY NOT VERSIONED. They are
# TRANSPORT — which process decides, and how the answer travels. The policy is
# what `core/` and `adapters/` say, and a grant is a human's approval of a
# policy. A change to the socket framing must not revoke every outstanding
# one-shot grant on the machine. If transport ever starts changing verdicts,
# that is the bug rather than a reason to version it, and
# `tests/test_daemon_client_is_cheap.py` is where it would be caught.
#
# ⚠ `cursor_bridge.ps1` IS NOT VERSIONED EITHER, BY THAT SAME RULE AND NOT BY
# OVERSIGHT. It is the Windows stand-in for the shell that invokes
# `sting_hook.py` — pure transport, deciding nothing. Versioning it would mean
# a typo in a PowerShell comment revoked every outstanding one-shot grant on
# every machine, including the POSIX ones that never run it.
VERSIONED = ("core", "adapters", "hook_entry.py")


def default_prefix() -> Path:
    return Path(os.environ.get("STING_INSTALL_ROOT")
                 or Path.home() / ".local" / "share" / "sting")


def source_root() -> Path:
    return Path(__file__).resolve().parent.parent


def compute_version(root: Path | None = None) -> str:
    """`<git-ref>-<8 hex of the policy's content>`.

    BOTH HALVES EARN THEIR PLACE. The git ref names a commit a human can go and
    read. The content hash changes when the files change, which the ref does not
    — a dirty checkout keeps the same ref while meaning something different, and
    an install that cannot tell those apart is an install that silently reuses a
    directory holding different code.
    """
    root = root or source_root()
    digest = hashlib.sha256()
    for name in VERSIONED:
        target = root / name
        for path in sorted(target.rglob("*.py")) if target.is_dir() else [target]:
            if "__pycache__" in path.parts:
                continue
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes())
    ref = _git_ref(root)
    return f"{ref}-{digest.hexdigest()[:8]}"


VERSION_FILE = "VERSION"
"""Written INTO a release archive by tools/make_release.sh. See `_git_ref`."""


def _git_ref(root: Path) -> str:
    """Best effort, and an unpacked ARCHIVE is not a worse case than a checkout.

    ⚠ WITHOUT THE FALLBACK BELOW, A ZIP CANNOT NAME ITSELF. `git describe` needs
    a `.git`, and a `git archive` tarball has none — so an unpacked release
    reported `nogit-<content hash>`, which is honest and useless: a receiver
    could not tell 0.7 from 0.8 without asking the sender. That is a direct
    problem for this product rather than a cosmetic one, because `guard_version`
    is on every record now and a version nobody can resolve to a commit
    attributes nothing.

    So a release archive carries a one-line `VERSION` file written at build time
    from the tag it was cut from, and it is used ONLY when git cannot answer.
    Git wins whenever it can, because a checkout that also has a stale VERSION
    file must not be believed over the repository it is sitting in.

    ⚠ AND THE CONTENT HASH STILL DECIDES. `compute_version` appends 8 hex of the
    policy's own bytes, so a VERSION file that claims the wrong tag produces a
    version string whose two halves disagree — measured: a clone at HEAD and an
    unpacked v0.8 archive both hash to `a96e98e1`, because the policy files are
    identical. The label is a convenience; the hash is the fact.
    """
    import subprocess
    try:
        out = subprocess.run(["git", "describe", "--always", "--tags"],
                              cwd=str(root), capture_output=True, text=True,
                              timeout=5)
        ref = out.stdout.strip()
        if ref:
            return ref
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        declared = (root / VERSION_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return "nogit"
    # One line, no whitespace, or it is not a ref this wrote.
    first = declared.splitlines()[0].strip() if declared else ""
    return first if first and " " not in first else "nogit"


def is_dirty(root: Path | None = None) -> bool:
    import subprocess
    try:
        out = subprocess.run(["git", "status", "--porcelain"],
                              cwd=str(root or source_root()), capture_output=True,
                              text=True, timeout=5)
        return bool(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return False


# ------------------------------------------------------------------ the grants

def revoke_grants(session_root: Path) -> list:
    """Delete every outstanding one-shot grant. Returns what was revoked.

    ⚠ SEE THE MODULE DOCSTRING. This is half of the chokepoint; the other half is
    the version stamped into each grant, which makes a survivor unredeemable
    rather than merely absent.
    """
    if not session_root.is_dir():
        return []
    revoked = []
    for path in sorted(session_root.glob("*.allow-once.json")):
        try:
            grant = json.loads(path.read_text(encoding="utf-8"))
            revoked.append({"session_id": grant.get("session_id"),
                             "action_hash": grant.get("action_hash"),
                             "rule_id": grant.get("rule_id")})
        except (OSError, json.JSONDecodeError):
            revoked.append({"session_id": path.stem, "action_hash": None,
                             "rule_id": None})
        try:
            path.unlink()
        except OSError:
            pass
    return revoked


def current_dir(prefix: Path | None = None) -> Path:
    """Where `current` points, whichever layout this platform uses."""
    prefix = Path(prefix or default_prefix())
    pointer = prefix / POINTER
    try:
        if pointer.is_file():
            target = pointer.read_text(encoding="utf-8").strip()
            if target:
                return Path(target)
    except OSError:
        pass
    return prefix / "current"


# ------------------------------------------------------------------ placing

def installed_version(prefix: Path | None = None) -> str | None:
    prefix = prefix or default_prefix()
    # ⚠ `current_dir`, NOT `prefix / "current"`. On Windows `current` is a
    # POINTER FILE holding a path, not a directory symlink, so
    # `current/INSTALL.json` is not a path that can exist and every install
    # read as "nothing installed".
    manifest = current_dir(prefix) / "INSTALL.json"
    if not manifest.exists():
        return None
    try:
        return json.loads(manifest.read_text(encoding="utf-8")).get("guard_version")
    except (OSError, json.JSONDecodeError):
        return None


# ------------------------------------------------------- the hook configs (D3)
#
# ⚠ COPILOT'S CONFIG IS PER PROJECT, AND NOTHING SAID WHICH. The installer writes
# `<the directory it ran in>/.github/hooks/hooks.json`, while uninstall walked
# relative paths from wherever IT ran, so an uninstall from anywhere else left
# Copilot calling a guard that was being removed. The installed tree now says
# where every hook config went.

def _recorded_entries(prefix: Path | None = None) -> list[dict]:
    manifest = current_dir(prefix) / "INSTALL.json"
    try:
        entries = json.loads(manifest.read_text(encoding="utf-8")).get("hook_configs", [])
    except (OSError, ValueError, AttributeError):
        return []
    return [e for e in entries if isinstance(e, dict) and isinstance(e.get("path"), str)]


def record_hook_configs(tree: Path, configs: list[dict]) -> None:
    """Add the hook configs an install wrote to its tree's INSTALL.json, once
    each, keeping what earlier installs recorded."""
    manifest_path = Path(tree) / "INSTALL.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        # One exception for every caller to report, not an OSError for one.
        raise ValueError(f"{manifest_path} cannot be read ({exc})") from exc
    if not isinstance(manifest, dict):
        raise ValueError(f"{manifest_path} is not a JSON object")
    recorded = [e for e in manifest.get("hook_configs", []) if isinstance(e, dict)]
    known = {e.get("path") for e in recorded}
    for config in configs:
        if config["path"] not in known:
            recorded.append({"agent": config["agent"], "path": str(config["path"]),
                             "user_level": bool(config.get("user_level", True))})
            known.add(config["path"])
    manifest["hook_configs"] = recorded
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True),
                             encoding="utf-8")


def recorded_hook_entries(prefix: Path | None = None) -> list[dict]:
    """Every hook config the installed guard recorded, as {"agent", "path",
    "user_level"}, oldest first; empty without a readable manifest."""
    return _recorded_entries(prefix)


def recorded_hook_configs(prefix: Path | None = None) -> list[str]:
    """Every hook config path the installed guard recorded, oldest first; empty
    when there is no readable manifest (an install from before the record)."""
    return [entry["path"] for entry in _recorded_entries(prefix)]


def place(*, prefix: Path | None = None, source: Path | None = None,
           session_root: Path | None = None, installed_by: str = "install.py") -> dict:
    """Copy the tree, write INSTALL.json, repoint `current`, revoke grants."""
    prefix = Path(prefix or default_prefix())
    source = Path(source or source_root())
    session_root = Path(session_root or Path.home() / ".sting" / "sessions")

    version = compute_version(source)
    target = prefix / version
    previous = installed_version(prefix)
    # ⚠ READ BEFORE ANYTHING IS REPLACED (D3). A same-content reinstall removes
    # `target`, which is where the current manifest lives.
    carried = _recorded_entries(prefix)

    prefix.mkdir(parents=True, exist_ok=True)
    if target.exists():
        # Same content, same directory. Replace it rather than merging: a
        # partial previous copy plus new files is a tree nobody designed.
        shutil.rmtree(target)
    target.mkdir(parents=True)

    # ⚠ A MISSING PAYLOAD ITEM IS A REFUSAL, NOT A `continue`.
    #
    # This used to skip silently, and that is how a broken archive installed
    # cleanly. Measured on an archive whose builder had drifted from this list:
    # `sting_hook.py` was absent, the copy skipped it, `place()` returned
    # successfully, `install.py` exited 0 and wrote every agent's hook config
    # pointing at `<current>/sting_hook.py` — a file that was not on disk. Every
    # tool call would have invoked a path that does not exist.
    #
    # It is the same principle as "a partial install must not read as a complete
    # one", in the one place that had been left out of it. Checked BEFORE
    # anything is copied, so a refusal does not leave half a tree behind.
    missing = [name for name in PAYLOAD if not (source / name).exists()]
    if missing:
        raise FileNotFoundError(
            f"cannot install from {source}: it is missing "
            f"{', '.join(missing)}. This is not a checkout or an archive of "
            f"this version — installing what is here would write a hook "
            f"config pointing at files that are not there.")

    for name in PAYLOAD:
        origin = source / name
        destination = target / name
        if origin.is_dir():
            shutil.copytree(origin, destination,
                             ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            # ⚠ PARENTS FIRST. A payload entry may name a file INSIDE a package
            # that is not itself payload — `installer/cursor_bridge.ps1` is one,
            # and the whole `installer/` package is not shipped because nothing
            # at runtime imports it. Without this, `copy2` raises
            # FileNotFoundError on the missing directory and the install dies
            # after the refusal check has already passed, which is the worst
            # moment for it: half a tree placed and no error anybody predicted.
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, destination)

    manifest = {
        "guard_version": version,
        "source_commit": _git_ref(source),
        "source_dirty": is_dirty(source),
        "source_path": str(source),
        "installed_at": time.time(),
        "installed_by": installed_by,
        "payload": list(PAYLOAD),
        # Every hook config an install wrote, carried from one install to the
        # next and appended to by `record_hook_configs`. Uninstall reads it.
        "hook_configs": carried,
    }
    (target / "INSTALL.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    # ⚠ REVOKE BEFORE THE SWAP. A grant spent against the OLD policy in the
    # window between them is at least a grant spent against the policy the human
    # was looking at. Revoking after the swap would allow the opposite.
    revoked = revoke_grants(session_root)

    _repoint(prefix / "current", target)

    # ⚠ AFTER THE SWAP, NEVER BEFORE. Pruning first would delete a tree while
    # `current` still points into it, and a hook firing in that window resolves
    # a file that is no longer there. The pointer moves, then the old trees go.
    pruned = prune(prefix, keep=KEEP_VERSIONS)

    # ⚠ `current` IS THE RESOLVED DIRECTORY, NOT THE POINTER. `install.py`
    # builds the hook command and the shipper's entry from this value, so
    # returning the pointer path put `…\current\sting_hook.py` into every
    # Windows agent's settings file — a path that cannot exist, which is what
    # the first native Windows install reported.
    return {"version": version, "previous": previous, "path": target,
             "current": current_dir(prefix), "revoked": revoked,
             "pruned": pruned, "dirty": manifest["source_dirty"]}


KEEP_VERSIONS = 2
"""How many version trees survive an update. ⚠ TWO, AND NEITHER ONE NOR ZERO.

**Not zero, and not one.** `current` is a POINTER, so the only rollback this
product has is a pointer flip back to the tree that worked — there is no
auto-updater and no download to re-run offline. Keeping only the live tree
removes the entire recovery path to save 1.4 MB, which is a rounding error of
disk against the one thing you want at 3am.

**Not unbounded either, which is what it was.** `place()` never deleted a
previous tree, so a machine updated weekly accumulated one 1.4 MB directory per
distinct content hash, forever, with nothing naming it as a leak. Measured on
the update walk: two trees at 1.4 MB each after a single update.

Two is the smallest number that keeps a rollback.
"""


def prune(prefix: Path | None = None, keep: int = KEEP_VERSIONS) -> list:
    """Delete the oldest version trees, keeping `keep` of them. Never `current`.

    ⚠ THE LIVE TREE IS EXCLUDED BY IDENTITY, NOT BY ORDER. Sorting by mtime and
    keeping the newest would delete the tree `current` points at the moment a
    clock is wrong, a copy is restored, or an update rolls BACK to an older
    version — which is exactly when this matters most. It is resolved and
    removed from the candidate list first.

    ⚠ AND IT NEVER RAISES. A prune that fails is disk left behind, which is a
    cost; a prune that throws is an install that reports failure after it has
    already succeeded, which is a machine somebody re-runs.
    """
    prefix = Path(prefix or default_prefix())
    if not prefix.is_dir():
        return []
    try:
        live = current_dir(prefix).resolve()
    except OSError:                                              # pragma: no cover
        live = None

    trees = []
    for child in sorted(prefix.iterdir()):
        if not child.is_dir() or child.name == "current":
            continue
        try:
            if live is not None and child.resolve() == live:
                continue
        except OSError:                                          # pragma: no cover
            continue
        try:
            trees.append((child.stat().st_mtime, child))
        except OSError:                                          # pragma: no cover
            continue

    # newest first, so what survives is the most recent non-live tree(s)
    trees.sort(key=lambda pair: pair[0], reverse=True)
    doomed = [child for _, child in trees[max(0, keep - 1):]]

    removed = []
    for child in doomed:
        try:
            shutil.rmtree(child)
            removed.append(str(child))
        except OSError:
            continue
    return removed


POINTER = "current.txt"
"""Windows' stand-in for the `current` symlink: a file holding the target path.

⚠ WHY A POINTER FILE AND NOT A JUNCTION, WHICH WAS THE OBVIOUS CANDIDATE.
`mklink /J` needs no elevation for directories, so it clears the blocker — but
it cannot be swapped atomically. `os.replace` on Windows is `MoveFileEx` with
`MOVEFILE_REPLACE_EXISTING`, and **that flag does not apply to directories**: a
junction has to be deleted and recreated, which reopens exactly the window this
function exists to close. A hook firing inside it gets "no such file".

`os.replace` on a FILE *is* atomic on Windows. So the pointer file preserves the
property the symlink was chosen for, and it also gives `install_time()` its
second half — the file's mtime records the instant the swap happened, which is
what the symlink's lstat mtime does on POSIX.

⚠ WHAT IT COSTS: one indirection. Anything resolving `current` has to read the
file rather than follow a link, so `core/allow_once.py` carries a resolver and
this constant is stated in both places — `core/` may not import `installer/`,
because the hook runs from an installed tree that does not ship it.

⚠ AND THE THIRD OPTION, REJECTED: requiring Developer Mode. It is one toggle,
and it is a toggle on the DEVELOPER'S machine that an install would have to
demand before it could run at all — for a guard whose whole pitch is that it
installs in a minute. It also fails silently in the wrong direction: an
unelevated `os.symlink` raises OSError, which an installer catching broadly
would report as "install failed" without naming the cause.
"""


def _repoint(link: Path, target: Path) -> None:
    """Atomically. Never unlink-then-relink.

    ⚠ THE ORDER IS THE WHOLE POINT. Unlinking first leaves a window in which
    `current` does not exist, and a hook firing in that window gets "no such
    file" — which every adapter turns into a failure the developer sees. The
    temp name is generated, so two concurrent installs cannot collide on it.

    Both platforms end in `os.replace`, which is the atomic primitive on each;
    only the thing being replaced differs.
    """
    import secrets
    if os.name == "nt":
        pointer = link.parent / POINTER
        tmp = link.parent / f".{POINTER}.{secrets.token_hex(4)}"
        tmp.write_text(str(target), encoding="utf-8")
        os.replace(tmp, pointer)
        return
    tmp = link.parent / f".current.{secrets.token_hex(4)}"
    os.symlink(target, tmp)
    os.replace(tmp, link)




# ---------------------------------------------------------------- uninstalling

def remove(*, prefix: Path | None = None) -> dict:
    """Take the installed tree and the `current` pointer away. Nothing else."""
    prefix = Path(prefix or default_prefix())
    removed = []
    for link in (prefix / "current", prefix / POINTER):
        if link.is_symlink() or link.exists():
            link.unlink()
            removed.append(str(link))
    if prefix.is_dir():
        for child in sorted(prefix.iterdir()):
            if child.is_dir():
                shutil.rmtree(child)
                removed.append(str(child))
        try:
            prefix.rmdir()
            removed.append(str(prefix))
        except OSError:
            # Something else lives here. Leave it rather than guessing.
            pass
    return {"removed": removed}
