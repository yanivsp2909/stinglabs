#!/usr/bin/env python3
"""Blast radius: every recorded action through one engine tree, as data, from a
FROZEN SNAPSHOT of the log roots. docs/PARALLEL.md.

    python3 runner/blast_radius.py snapshot DEST [ROOT ...]
    python3 runner/blast_radius.py replay DEST OUT.json [--engine TREE]
    python3 runner/blast_radius.py diff BEFORE.json AFTER.json

`snapshot` copies the log roots ONCE (default: this machine's, see
`default_roots`) and writes a manifest of every file's hash. `replay` reads only
that copy, and refuses one that no longer matches its manifest. Run it once per
engine tree — a main worktree, then the branch — against the same snapshot, and
`diff` lists every action whose verdict moved.

⚠ NEVER THE LIVE ROOTS. The installed guard keeps appending to them while agents
work, so two replays of "the same" roots, minutes apart, read different records
and the diff shows movement no engine made. One snapshot, taken once per
comparison, is what both sides read.

⚠ EACH LOG IS COPIED UNDER THE SHARED LOCK ITS READERS TAKE
(`core/audit_log.read_records`, `core.locking`): the hook appends under the
exclusive one, so a copy cannot catch a record half-written, and a writer that
never lets go fails the snapshot instead of hanging it.

Nothing is executed. Commands are fed to `engine.decide` as data, with the
replay's NeutralWorld (answers nothing, reads no file). Two views per record:

    session    replayed in seq order, state carried: what the hook would do
    isolated   an EXEC alone in a fresh session: the command's own verdict

A verdict is compared whole: decision, rule, reason, evidence and what the
installed-guard floor kept beneath it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

MANIFEST = "MANIFEST.json"
COPIES = "roots"


def default_roots(home: Path, repo: Path) -> list[Path]:
    """This machine's decision-log roots, resolved when asked, never at import."""
    return [home / ".sting" / "sessions", home / ".sting" / "dogfood",
            home / ".sting" / "dogfood _old",
            repo.parent / "sting-logs-archive", repo / "logs" / "live-fixture"]


def _private_write(target: Path, data: bytes, *, replace: bool = False) -> None:
    """0600, like the logs themselves: they hold the commands an agent ran,
    and a replay's reasons and evidence quote them. A replaced file is set
    back to 0600, whatever it was."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if replace else os.O_EXCL)
    fd = os.open(target, flags, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _mkdir_private(path: Path) -> None:
    """Every directory it creates is 0700: `mkdir -p` would leave the ones
    between at the umask's default."""
    if path.is_dir():
        return
    _mkdir_private(path.parent)
    path.mkdir(mode=0o700)


def _copy_locked(source: Path, target: Path) -> None:
    """`source`, read under the shared lock its readers take, into `target`.

    `core.locking`'s lock, not a bare `flock`: its wait is bounded, so a writer
    that never lets go raises `LockUnavailable` instead of hanging the
    snapshot (and the test run that asked for it), and it has a Windows arm.
    Imported here, not at the top: a module-level `core` import would pin this
    tree's engine in a process asked to replay another's.
    """
    from core import locking
    fd = os.open(source, os.O_RDONLY)
    try:
        with locking.shared(fd), os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read()
    finally:
        os.close(fd)
    _private_write(target, data)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(roots: list[Path], dest: Path) -> dict[str, Path]:
    """Copy every existing root into `dest` once. Returns {root: its copy}.

    A missing root is recorded as missing and gets no copy. `dest` must not
    exist: a snapshot is taken, never topped up."""
    dest.mkdir(mode=0o700, parents=True)
    copies: dict[str, Path] = {}
    manifest = {"taken_at": time.time(), "roots": []}
    for index, root in enumerate(roots):
        root = Path(root)
        entry = {"source": str(root), "copy": None, "files": {}}
        if root.is_dir():
            copy = dest / COPIES / str(index)
            for path in sorted(root.rglob("*")):
                if path.is_symlink() or not path.is_file():
                    continue
                relative = path.relative_to(root)
                target = copy / relative
                _mkdir_private(target.parent)
                if path.suffix in {".jsonl", ".log"}:
                    _copy_locked(path, target)
                else:
                    _private_write(target, path.read_bytes())
                entry["files"][relative.as_posix()] = _digest(target)
            _mkdir_private(copy)
            entry["copy"] = str(copy.relative_to(dest))
            copies[str(root)] = copy
        manifest["roots"].append(entry)
    _private_write(dest / MANIFEST, json.dumps(manifest, indent=1).encode("utf-8"))
    return copies


def verify(dest: Path) -> list[Path]:
    """The copied roots, after checking every file against the manifest.

    Raises ValueError on any difference: a snapshot that changed is not frozen,
    and a comparison read from it would be the defect this tool exists for."""
    manifest = json.loads((dest / MANIFEST).read_text(encoding="utf-8"))
    copies = []
    for entry in manifest["roots"]:
        if entry["copy"] is None:
            continue
        copy = dest / entry["copy"]
        found = {p.relative_to(copy).as_posix(): p for p in copy.rglob("*") if p.is_file()}
        if set(found) != set(entry["files"]):
            raise ValueError(f"{copy}: files differ from the manifest")
        for name, digest in entry["files"].items():
            if _digest(found[name]) != digest:
                raise ValueError(f"{copy / name}: changed since the snapshot")
        copies.append(copy)
    return copies


def _whole(verdict) -> dict:
    beneath = getattr(verdict, "beneath", None)
    return {"decision": str(verdict.decision), "rule_id": verdict.rule_id,
            "reason": verdict.reason, "evidence": verdict.evidence,
            "beneath": None if beneath is None else _whole(beneath)}


def replay(dest: Path, engine_tree: Path, cwd: str) -> list[dict]:
    """Every record in the snapshot through the engine in `engine_tree`."""
    copies = verify(dest)
    sys.path.insert(0, str(engine_tree.resolve()))
    from core import engine                                       # noqa: E402
    from core.types import SessionState                           # noqa: E402
    from runner import replay_live as rl                          # noqa: E402
    # ⚠ A PROCESS THAT ALREADY IMPORTED `core` FROM ANOTHER TREE KEEPS IT, and
    # the "comparison" would replay one engine twice and find nothing moved.
    if not Path(engine.__file__).resolve().is_relative_to(engine_tree.resolve()):
        raise RuntimeError(f"core.engine came from {engine.__file__}, not from "
                           f"{engine_tree}: replay each tree in its own process")

    sessions: dict[str, dict] = {}
    for copy in copies:
        for sid, records in rl.load_records(copy).items():
            bucket = sessions.setdefault(sid, {})
            for record in records:
                prev = bucket.get(record.get("seq"))
                if prev is None or len(str(record.get("command") or "")) > len(
                        str(prev.get("command") or "")):
                    bucket[record.get("seq")] = record
    world = rl.NeutralWorld()
    rows = []
    for sid, bucket in sorted(sessions.items()):
        state = SessionState(session_id=sid)
        state.cwd = cwd
        state.workspace_roots = [cwd]
        for record in sorted(bucket.values(), key=lambda r: r.get("seq") or 0):
            klass, command = rl.classify(record, Path(record["_log_path"]))
            action = rl.action_from(record, command, cwd)
            state.seq = record.get("seq") or (state.seq + 1)
            complete = klass != rl.TRUNCATED
            verdict = engine.decide(action, state, world, text_complete=complete)
            row = {"key": f"{sid}:{record.get('seq')}", "session": _whole(verdict)}
            if record.get("kind") == "EXEC" and isinstance(command, str):
                fresh = SessionState(session_id="isolated")
                fresh.cwd = cwd
                fresh.workspace_roots = [cwd]
                fresh.seq = 1
                row["isolated"] = _whole(engine.decide(action, fresh, world,
                                                       text_complete=complete))
            rows.append(row)
    return rows


def diff(before: list[dict], after: list[dict]) -> list[str]:
    """One line per record and view whose verdict differs, or is on one side only."""
    a = {row["key"]: row for row in before}
    b = {row["key"]: row for row in after}
    moved = [f"{key}  only in {'before' if key in a else 'after'}"
             for key in sorted(set(a) ^ set(b))]
    for key in sorted(set(a) & set(b)):
        for view in ("session", "isolated"):
            if a[key].get(view) != b[key].get(view):
                was, now = a[key].get(view) or {}, b[key].get(view) or {}
                fields = ", ".join(f for f in ("decision", "rule_id", "reason",
                                               "evidence", "beneath")
                                   if was.get(f) != now.get(f)) or "present"
                moved.append(f"{key}  {view} ({fields}): {was.get('decision')} "
                             f"{was.get('rule_id')} -> {now.get('decision')} "
                             f"{now.get('rule_id')}")
    return moved


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    take = sub.add_parser("snapshot")
    take.add_argument("dest", type=Path)
    take.add_argument("roots", nargs="*", type=Path)
    run = sub.add_parser("replay")
    run.add_argument("dest", type=Path)
    run.add_argument("out", type=Path)
    run.add_argument("--engine", type=Path, default=here,
                     help="the engine tree to replay through (default: this one)")
    run.add_argument("--cwd", default=None,
                     help="the workspace every replayed session runs in; the same "
                          "for both sides (default: the tree the snapshot was taken "
                          "from)")
    compare = sub.add_parser("diff")
    compare.add_argument("before", type=Path)
    compare.add_argument("after", type=Path)
    args = ap.parse_args(argv)

    if args.command == "snapshot":
        sys.path.insert(0, str(here))            # this tree's core.locking
        roots = args.roots or default_roots(Path.home(), here)
        copies = snapshot(roots, args.dest)
        _private_write(args.dest / "CWD", str(here).encode("utf-8"))
        print(f"{len(copies)} of {len(roots)} roots copied to {args.dest}")
        return 0
    if args.command == "replay":
        cwd = args.cwd or (args.dest / "CWD").read_text(encoding="utf-8")
        rows = replay(args.dest, args.engine, cwd)
        _private_write(args.out, json.dumps(rows).encode("utf-8"), replace=True)
        print(f"{len(rows)} records through {args.engine} -> {args.out}")
        return 0
    moved = diff(json.loads(args.before.read_text(encoding="utf-8")),
                 json.loads(args.after.read_text(encoding="utf-8")))
    print("\n".join(moved) if moved else "no verdict moved")
    print(f"{len(moved)} moved")
    return 1 if moved else 0


if __name__ == "__main__":
    sys.exit(main())
