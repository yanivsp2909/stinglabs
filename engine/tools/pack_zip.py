#!/usr/bin/env python3
"""
Pack an already-staged directory into a .zip, beside the .tar.gz of the SAME
bytes.

    python3 tools/pack_zip.py <stage-dir> <top-level-name> <out.zip>

⚠ WHY A SECOND ARCHIVE AT ALL. `.tar.gz` needs nothing installed anywhere —
Windows has shipped bsdtar since 2018, so `tar -xf` works natively on all three
platforms. But DOUBLE-CLICKING a `.tar.gz` in Windows Explorer does nothing
useful, and a `.zip` extracts. For a stranger on Windows that is a wall at the
exact moment we least want one: before they have run anything.

⚠ AND WHY THIS TAKES A STAGE DIRECTORY RATHER THAN A TAG. Two `git archive`
invocations are two chances to diverge, and the divergence would be invisible
until somebody on Windows got a different product from somebody on macOS. The
staging is built once, both identity checks run over it once, and then it is
packed twice. This packs; it never selects.

WHAT IT PRESERVES, AND WHAT THAT IS WORTH:

  file modes     ⚠ MEASURED, AND THE ANSWER IS THAT NOTHING BREAKS WITHOUT
                 THEM. Exactly one file in the staged payload carries the
                 executable bit — `tools/make_release.sh` — and 21 files have a
                 shebang without one. Every entry point is invoked as
                 `python3 install.py` / `python3 tools/x.py`, never executed, so
                 a stranger on Windows loses nothing. The bit is carried anyway
                 because it costs three lines and makes the two archives agree;
                 it is NOT load-bearing, and this note exists so nobody later
                 believes it is.

  line endings   ⚠ NOT CONVERTED, AND THAT ONE IS LOAD-BEARING. A zip tool that
                 helpfully rewrote LF to CRLF would change every file's hash,
                 break `installer/cursor_bridge.ps1` and break every shebang.
                 Bytes are read `rb` and written verbatim; nothing here has a
                 text mode to get wrong.

  the top name   identical to the tarball's, so `cd sting-v1.0` works the same
                 after either.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
import zipfile
from pathlib import Path

# ⚠ A FIXED TIMESTAMP, NOT `now`. Two builds of the same tag should differ only
# where the inputs differ; a wall clock inside the archive makes every rebuild a
# different file and makes "is this the archive I sent?" unanswerable. 1980-01-01
# is the earliest a zip can express.
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def _entries(stage: Path, name: str) -> list:
    """Every file and directory under `stage/name`, sorted, relative to `stage`.

    Sorted because a zip's order is part of its bytes, and `os.walk` order is
    the filesystem's business, not ours.
    """
    root = stage / name
    found = []
    for path in sorted(root.rglob("*"), key=lambda p: str(p).encode("utf-8")):
        if path.is_symlink():
            # ⚠ REFUSED RATHER THAN FOLLOWED OR SKIPPED. A zip can hold a
            # symlink, Windows will not honour it, and silently storing the
            # target's bytes would make the two archives differ in content while
            # both claiming to be the same product. Nothing in the payload is a
            # symlink today; if one appears, this stops the build.
            raise ValueError(f"symlink in the staged payload: {path}")
        found.append(path)
    return found


def pack(stage: Path, name: str, out: Path) -> dict:
    """Write `out` from `stage/name`. Returns what it wrote, for the caller."""
    stage, out = Path(stage), Path(out)
    root = stage / name
    if not root.is_dir():
        raise NotADirectoryError(f"no staged directory at {root}")
    # ⚠ THE OUTPUT MUST NOT BE INSIDE WHAT IS BEING PACKED. `ZipFile(out, "w")`
    # creates the file before the walk runs, so an `out` under the stage would
    # be globbed and packed into itself mid-write — not a symlink, so the guard
    # below never sees it, and nothing raises. Latent in this script (it always
    # writes to $OUT) but the standalone CLI invites it.
    if out.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"the output {out} is inside the staged tree {root}")

    written, executable = 0, []
    # ⚠ WRITTEN TO A TEMPORARY AND RENAMED ONLY ON SUCCESS, SO THAT "THE FILE
    # EXISTS" MEANS "THE PACK SUCCEEDED".
    #
    # `ZipFile.__exit__` calls `close()` on the way out of ANY exception, which
    # finalises the central directory over whatever was written so far. The
    # result is a structurally valid, openable, `testzip()`-clean, SILENTLY
    # INCOMPLETE archive — the release-shaped failure this whole tool exists to
    # avoid, arriving through the error path instead of the happy one. Catching
    # a broader exception would not help: the partial file is created by the
    # cleanup, not by the error.
    tmp = out.with_name(out.name + f".partial{os.getpid()}")
    try:
        _write(tmp, stage, name, executable)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    written = _count(stage, name)
    os.replace(tmp, out)
    return {"files": written, "executable": executable, "path": out}


def _count(stage: Path, name: str) -> int:
    return sum(1 for p in _entries(stage, name) if p.is_file())


def _write(out: Path, stage: Path, name: str, executable: list) -> None:
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in _entries(stage, name):
            arcname = str(path.relative_to(stage))
            mode = path.stat().st_mode
            if path.is_dir():
                info = zipfile.ZipInfo(arcname + "/", date_time=FIXED_TIME)
                info.external_attr = ((mode & 0xFFFF) << 16) | 0x10
                archive.writestr(info, b"")
                continue
            info = zipfile.ZipInfo(arcname, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            # ⚠ THE MODE GOES IN THE HIGH 16 BITS OF external_attr. Python's
            # `ZipFile.write()` does this for you; `writestr` with a ZipInfo you
            # built does NOT, and that is the exact way the executable bit gets
            # dropped without anybody noticing.
            info.external_attr = (mode & 0xFFFF) << 16
            if mode & stat.S_IXUSR:
                executable.append(arcname)
            archive.writestr(info, path.read_bytes())      # rb -> verbatim


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage")
    ap.add_argument("name")
    ap.add_argument("out")
    args = ap.parse_args(argv)
    try:
        result = pack(Path(args.stage), args.name, Path(args.out))
    except Exception as exc:                                  # noqa: BLE001
        # ⚠ NON-ZERO, LOUDLY. A release script that produces an incomplete
        # archive and exits 0 is how `daemon/` was left out of a release.
        print(f"REFUSING TO PACK: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"{result['files']} files -> {result['path']}")
    if result["executable"]:
        print("  executable bit carried on: "
               + ", ".join(result["executable"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
