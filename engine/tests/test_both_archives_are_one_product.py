"""⚠ TWO ARCHIVES THAT ARE NEARLY THE SAME PRODUCT IS WORSE THAN ONE.

Nobody would know which one a customer ran. So the two are packed from ONE
staging — not two `git archive` invocations — and this unpacks both and compares
them file by file, on every run, instead of a person doing it once.

⚠ AND A RELEASE SCRIPT THAT PRODUCES AN INCOMPLETE ARCHIVE AND EXITS 0 IS THE
SUBJECT HERE. This repo has shipped one: `git archive` skips a path that does
not exist at the tag without complaining, which is how `daemon/` and
`sting_hook.py` were left out of a release whose install completed, exited 0,
and wrote a hook config naming a file that was not on disk.

⚠ AND A MAC'S OWN METADATA IS NOT PART OF THE PRODUCT. On a build host that
gives staged files an extended attribute, bsdtar wrote an AppleDouble `._*`
entry beside each one, plus the attribute as a pax header, and the .zip has
neither: this file failed, and a founder unpacking the .tar.gz on Linux got
junk files. So the fixture packs with the release script's OWN tar step, read
from the script, with an attribute set on a staged file and on the top
directory.
"""
from __future__ import annotations

import gzip
import hashlib
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NAME = "sting-testpack"
SCRIPT = ROOT / "tools" / "make_release.sh"
TAR_STEP = 'tar -czf "$OUT/$NAME.tar.gz"'
FIXED_MTIME = 1_700_000_000


def release_tar_step() -> tuple[dict, list[str]]:
    """(environment, long options) of the tar step `make_release.sh` runs.

    ⚠ READ FROM THE SCRIPT, NEVER RESTATED HERE. A copy of the command in this
    file is how the fixture could keep packing with a plain `tar -czf` while the
    release did something else, and then compare the wrong tarball."""
    lines = [line for line in SCRIPT.read_text(encoding="utf-8").splitlines()
             if TAR_STEP in line and not line.lstrip().startswith("#")]
    assert len(lines) == 1, f"expected one tar step in make_release.sh, found {lines}"
    # comments=True, as bash reads it: a trailing `# … --no-xattrs` is not an
    # option the script passes (security review).
    words = shlex.split(lines[0], comments=True)
    at = words.index("tar")
    env = dict(word.split("=", 1) for word in words[:at])
    return env, [word for word in words[at + 1:] if word.startswith("--")]


def release_tar(stage: Path, out: Path) -> Path:
    """Pack `stage` exactly as the release's tar step does."""
    env, options = release_tar_step()
    subprocess.run(["tar", "-czf", str(out), *options, "-C", str(stage), NAME],
                   check=True, env={**os.environ, **env})
    return out


def stage_tree(stage: Path) -> Path:
    """A staging directory shaped like a real one, every mtime fixed so two
    stagings pack to the same bytes."""
    root = stage / NAME
    (root / "core").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)

    (root / "install.py").write_text("#!/usr/bin/env python3\nprint('x')\n",
                                      encoding="utf-8")
    (root / "core" / "engine.py").write_text("DECIDE = 1\n", encoding="utf-8")
    (root / "VERSION").write_text("v9.9-test\n", encoding="utf-8")
    # a file with LF that must stay LF, and one with a real CR that must stay CR
    (root / "installer.ps1").write_bytes(b"Write-Host 'a'\nWrite-Host 'b'\n")
    (root / "already-crlf.txt").write_bytes(b"one\r\ntwo\r\n")
    exe = root / "tools" / "make_release.sh"
    exe.write_text("#!/usr/bin/env bash\necho hi\n", encoding="utf-8")
    exe.chmod(0o755)
    for path in sorted(root.rglob("*"), reverse=True) + [root]:
        os.utime(path, (FIXED_MTIME, FIXED_MTIME))
    return stage


def give_an_xattr(path: Path) -> bool:
    """Set an extended attribute on `path`, as a Mac does to files its own
    processes write (provenance, quarantine, Finder). False where the host
    cannot, so the caller can say so rather than pass vacuously."""
    if hasattr(os, "setxattr"):                                   # Linux
        try:
            os.setxattr(path, "user.sting-test", b"staged")
            return True
        except OSError:
            return False
    try:                                                          # macOS
        subprocess.run(["xattr", "-w", "com.example.sting-test", "staged", str(path)],
                       check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


@pytest.fixture(scope="module")
def staged(tmp_path_factory):
    """A staging directory shaped like a real one, packed both ways.

    Built from a fixture rather than a tag so the comparison runs on every
    machine and in CI, where the tag may not be fetched. The tar step is the
    script's own (`release_tar_step`), and a staged file and the top directory
    carry an extended attribute wherever the host can set one.
    """
    stage = stage_tree(tmp_path_factory.mktemp("stage"))
    marked = all([give_an_xattr(stage / NAME / "install.py"),
                  give_an_xattr(stage / NAME)])

    tar_path = release_tar(stage, stage.parent / f"{NAME}.tar.gz")
    zip_path = stage.parent / f"{NAME}.zip"
    sys.path.insert(0, str(ROOT))
    from tools import pack_zip

    pack_zip.pack(stage, NAME, zip_path)
    return {"stage": stage, "tar": tar_path, "zip": zip_path, "marked": marked}


def _from_tar(path: Path, into: Path) -> dict:
    with tarfile.open(path, "r:gz") as archive:
        archive.extractall(into)
    return _hash_tree(into)


def _from_zip(path: Path, into: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        archive.extractall(into)
    return _hash_tree(into)


def _hash_tree(root: Path) -> dict:
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out[str(path.relative_to(root))] = hashlib.sha256(
                path.read_bytes()).hexdigest()
    return out


# ════════════════════ 3.1 · the comparison this pass exists for ══

def test_both_archives_hold_the_same_files(staged, tmp_path):
    """Same file list. A missing file in one is the `daemon/` defect again."""
    from_tar = _from_tar(staged["tar"], tmp_path / "t")
    from_zip = _from_zip(staged["zip"], tmp_path / "z")

    assert set(from_tar) == set(from_zip), (
        f"only in .tar.gz: {sorted(set(from_tar) - set(from_zip))}\n"
        f"only in .zip:    {sorted(set(from_zip) - set(from_tar))}")
    assert from_tar, "both archives are empty — the comparison proves nothing"


def test_every_file_has_the_same_content_in_both(staged, tmp_path):
    """⚠ SAME LIST IS NOT SAME PRODUCT. This is the byte comparison."""
    from_tar = _from_tar(staged["tar"], tmp_path / "t")
    from_zip = _from_zip(staged["zip"], tmp_path / "z")

    differing = {name: (from_tar[name], from_zip[name])
                 for name in sorted(set(from_tar) & set(from_zip))
                 if from_tar[name] != from_zip[name]}
    assert not differing, f"same name, different bytes: {differing}"


# ════════════════════ 2 · what the zip must not lose ══

def test_line_endings_are_not_converted(staged, tmp_path):
    """⚠ THE LOAD-BEARING ONE. A zip tool that rewrote LF to CRLF would change
    every file's hash and break the .ps1 bridge and every shebang."""
    _from_zip(staged["zip"], tmp_path / "z")

    lf = (tmp_path / "z" / NAME / "installer.ps1").read_bytes()
    assert b"\r\n" not in lf, "LF was rewritten to CRLF inside the .zip"
    assert lf == b"Write-Host 'a'\nWrite-Host 'b'\n"

    # and the reverse: a file that genuinely holds CRLF keeps it
    crlf = (tmp_path / "z" / NAME / "already-crlf.txt").read_bytes()
    assert crlf == b"one\r\ntwo\r\n", "existing CRLF was normalised away"


def test_the_top_level_directory_name_is_identical(staged, tmp_path):
    """TASK 2.2 — `cd sting-v1.0` works the same after either."""
    _from_tar(staged["tar"], tmp_path / "t")
    _from_zip(staged["zip"], tmp_path / "z")

    assert [p.name for p in (tmp_path / "t").iterdir()] == [NAME]
    assert [p.name for p in (tmp_path / "z").iterdir()] == [NAME]


def test_the_executable_bit_is_recorded_in_the_zip(staged):
    """⚠ MEASURED, NOT LOAD-BEARING, AND IT DOES NOT SURVIVE EXTRACTION ANYWAY.

    Exactly one staged file carries the bit (`tools/make_release.sh`) and 21
    have a shebang without one, because every entry point is invoked as
    `python3 install.py` — never executed. So nothing breaks without it.

    ⚠ AND THE FIRST VERSION OF THIS TEST ASSERTED THE WRONG THING: it extracted
    with `ZipFile.extractall` and checked the mode on disk. Python's extractall
    DISCARDS permissions, so that assertion failed even though the bit was
    correctly stored. It is asserted where it actually lives — in the archive's
    `external_attr` — and the fact that a given extractor may drop it is exactly
    why nothing is allowed to depend on it.
    """
    with zipfile.ZipFile(staged["zip"]) as archive:
        modes = {info.filename: (info.external_attr >> 16)
                 for info in archive.infolist()}

    assert modes[f"{NAME}/tools/make_release.sh"] & stat.S_IXUSR, (
        "the executable bit was not stored — writestr with a hand-built "
        "ZipInfo does not set external_attr the way ZipFile.write does")
    assert not modes[f"{NAME}/core/engine.py"] & stat.S_IXUSR


def test_the_tarball_carries_the_same_modes_as_the_zip(staged):
    """The two archives must agree about modes as well as bytes."""
    with tarfile.open(staged["tar"], "r:gz") as archive:
        tar_modes = {m.name: m.mode & 0o777
                     for m in archive.getmembers() if m.isfile()}
    with zipfile.ZipFile(staged["zip"]) as archive:
        zip_modes = {i.filename: (i.external_attr >> 16) & 0o777
                     for i in archive.infolist() if not i.is_dir()}

    assert tar_modes == zip_modes, (
        f"modes differ between the archives: "
        f"{ {k: (tar_modes.get(k), zip_modes.get(k)) for k in set(tar_modes) | set(zip_modes) if tar_modes.get(k) != zip_modes.get(k)} }")


# ════════════════════ the real script, not a fixture ══

def test_the_release_script_packs_both_and_checksums_both():
    """Reads the script rather than running it — building needs a tag, which a
    shallow CI clone may not have. ⚠ A source read is a weak test and is used
    here only for the ORDERING claim, which the file-by-file comparison above
    cannot make: both identity checks must run BEFORE either archive is packed,
    or one archive is checked and the other is not.
    """
    script = (ROOT / "tools" / "make_release.sh").read_text(encoding="utf-8")

    census = script.index("identity_census.py")
    tar_at = script.index('tar -czf "$OUT/$NAME.tar.gz"')
    zip_at = script.index("pack_zip.py")
    assert census < tar_at and census < zip_at, (
        "an archive is packed before the staged bytes are checked for an "
        "identity — one archive would be checked and the other would not")

    # one checksum file, both archives in it
    assert 'shasum -a 256 "$NAME.tar.gz" "$NAME.zip" > "$NAME.sha256"' in script

    # ⚠ AND BOTH ARE PACKED FROM THE SAME STAGING, NOT FROM THE TAG TWICE.
    # The first version of this counted the string "git archive", which appears
    # only in COMMENTS — the real invocation is `git -C "$ROOT" archive`. It
    # therefore measured the prose and never the code. Counted over
    # non-comment lines, matching how the command is actually written.
    invocations = [line for line in script.splitlines()
                   if not line.lstrip().startswith("#") and "archive" in line
                   and line.lstrip().startswith("git")]
    assert len(invocations) == 1, (
        f"expected exactly one `git ... archive` invocation, found "
        f"{len(invocations)}: {invocations} — two builds are two chances to "
        f"diverge, which is the whole reason this pass staged once")


def test_pack_zip_refuses_a_symlink(tmp_path):
    """A zip can hold one, Windows will not honour it, and storing the target's
    bytes would make the archives differ in content while both claim to be the
    same product."""
    sys.path.insert(0, str(ROOT))
    from tools import pack_zip

    root = tmp_path / NAME
    root.mkdir()
    (root / "real.txt").write_text("x", encoding="utf-8")
    os.symlink(root / "real.txt", root / "link.txt")

    with pytest.raises(ValueError, match="symlink"):
        pack_zip.pack(tmp_path, NAME, tmp_path / "out.zip")


def test_pack_zip_reports_a_missing_stage_rather_than_writing_an_empty_zip(tmp_path):
    """⚠ THE `daemon/` SHAPE. An empty archive that exits 0 is the failure this
    whole file is about."""
    sys.path.insert(0, str(ROOT))
    from tools import pack_zip

    with pytest.raises(NotADirectoryError):
        pack_zip.pack(tmp_path, "not-staged", tmp_path / "out.zip")

    assert pack_zip.main([str(tmp_path), "not-staged",
                          str(tmp_path / "out.zip")]) == 2


# ════════════════════ what the review found ══

def test_a_failed_pack_leaves_no_zip_at_all(tmp_path, monkeypatch):
    """⚠ THE RELEASE-SHAPED FAILURE ARRIVING THROUGH THE ERROR PATH.

    `ZipFile.__exit__` calls `close()` on the way out of ANY exception, which
    finalises the central directory over whatever was written — leaving a
    structurally valid, openable, `testzip()`-clean, SILENTLY INCOMPLETE
    archive. Catching a broader exception would not have helped: the partial
    file is created by the cleanup, not by the error.
    """
    sys.path.insert(0, str(ROOT))
    from tools import pack_zip

    root = tmp_path / NAME
    root.mkdir()
    for i in range(5):
        (root / f"f{i}.txt").write_text("x" * 100, encoding="utf-8")

    calls = {"n": 0}
    real = Path.read_bytes

    def explode(self):
        calls["n"] += 1
        if calls["n"] == 3:
            raise MemoryError("out of memory mid-pack")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", explode)
    out = tmp_path / "out.zip"
    with pytest.raises(MemoryError):
        pack_zip.pack(tmp_path, NAME, out)

    assert not out.exists(), (
        "a truncated .zip survived a failed pack — it would open cleanly and "
        "be missing files, which is the daemon/ defect with a valid CRC")
    assert not list(tmp_path.glob("*.partial*")), "the temporary was left behind"


def test_the_output_may_not_be_written_inside_the_staged_tree(tmp_path):
    """`ZipFile(out, "w")` creates the file before the walk, so an `out` under
    the stage would be globbed and packed into itself mid-write."""
    sys.path.insert(0, str(ROOT))
    from tools import pack_zip

    (tmp_path / NAME).mkdir()
    (tmp_path / NAME / "a.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="inside the staged tree"):
        pack_zip.pack(tmp_path, NAME, tmp_path / NAME / "self.zip")


def test_everything_the_script_ships_is_verified_to_have_landed():
    """⚠ THE `daemon/` DEFECT, FOUND AGAIN IN A WORSE PLACE.

    `git archive` was invoked with `$PAYLOAD` PLUS four extras — `install.py`,
    `installer`, `requirements.txt`, `README.md` — and the loop that verifies
    what landed walked only `$PAYLOAD`. `install.py` IS THE ENTRY POINT and
    `installer/` is the package it imports, while `place.PAYLOAD` names only
    `installer/cursor_bridge.ps1`. A tag where any of them was renamed or gained
    `export-ignore` would have built both archives, passed the census, written
    both checksums and exited 0, and the receiver's first command would raise
    ModuleNotFoundError.
    """
    script = (ROOT / "tools" / "make_release.sh").read_text(encoding="utf-8")

    # one list feeds the archive AND the check
    assert 'SHIPPED="$PAYLOAD install.py installer requirements.txt README.md"' in script
    assert 'git -C "$ROOT" archive --format=tar "$TAG" $SHIPPED' in script
    assert "for item in $SHIPPED; do" in script
    assert "for item in $PAYLOAD; do" not in script, (
        "the verification loop walks a narrower list than what is shipped")


# ════════════════════ the build host's own metadata ══

def test_a_mac_really_marks_the_staged_tree(staged):
    """⚠ ARMED. On macOS the fixture must carry an attribute, or every comparison
    above passes with nothing to strip."""
    if sys.platform == "darwin":
        assert staged["marked"], "could not set an extended attribute on a Mac"


def test_the_tarball_carries_no_mac_metadata(staged):
    """No AppleDouble `._*` entry and no attribute as a pax header: the .zip has
    neither, and on Linux a `._*` file unpacks as junk beside the real one.
    Skipped, never passed, where nothing could be marked (python review)."""
    if not staged["marked"]:
        pytest.skip("this host cannot set an extended attribute")
    with tarfile.open(staged["tar"], "r:gz") as archive:
        members = archive.getmembers()
    assert not [m.name for m in members if Path(m.name).name.startswith("._")]
    assert not [(m.name, key) for m in members for key in m.pax_headers
                if "xattr" in key.lower() or "mac-metadata" in key.lower()]


def test_the_tarball_is_the_same_whatever_the_hosts_xattrs(tmp_path):
    """One tree staged twice, the second copy carrying attributes: the tar
    streams are byte for byte the same."""
    clean = stage_tree(tmp_path / "clean")
    marked = stage_tree(tmp_path / "marked")
    if not (give_an_xattr(marked / NAME / "install.py") and give_an_xattr(marked / NAME)):
        pytest.skip("this host cannot set an extended attribute")
    a = release_tar(clean, tmp_path / "clean.tar.gz")
    b = release_tar(marked, tmp_path / "marked.tar.gz")
    assert gzip.decompress(a.read_bytes()) == gzip.decompress(b.read_bytes())


def test_the_release_tar_step_strips_mac_metadata():
    """Pinned on the source too: only a Mac shows the behaviour, and CI's other
    runner has GNU tar, which writes neither. COPYFILE_DISABLE=1 stops bsdtar's
    AppleDouble `._*` entries and --no-xattrs stops the pax headers; each alone
    leaves the other (measured, docs/66). GNU tar ignores the first and knows
    the second, so one line builds on either."""
    env, options = release_tar_step()
    assert env.get("COPYFILE_DISABLE") == "1", env
    assert "--no-xattrs" in options, options
    assert not {"--xattrs", "--mac-metadata"} & set(options), (
        f"an option turns the metadata back on: {options}")


# A build host whose `tar` gives every file it stages an extended attribute, as a
# Mac can: the real tar, then after `tar xf - -C DIR` it marks DIR and everything
# under it, and leaves a note that it did.
MARKING_TAR = """#!/bin/bash
{real} "$@" || exit $?
if [ "${{1:-}}" = xf ]; then
  dir="" prev=""
  for arg in "$@"; do [ "$prev" = -C ] && dir="$arg"; prev="$arg"; done
  [ -n "$dir" ] && find "$dir" -exec xattr -w com.example.sting-test staged {{}} + \\
    && touch {note}
fi
"""


@pytest.mark.skipif(sys.platform != "darwin", reason="only a Mac's tar writes mac metadata")
@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs a checkout")
def test_the_real_script_ships_none_of_a_marking_hosts_metadata(tmp_path):
    """⚠ END TO END (security review). The fixture above rebuilds the script's tar
    step from its text, and a parse that drifted from what bash runs would test
    the wrong command. Here `make_release.sh` itself builds at HEAD, on a host
    whose `tar` marks every file the script stages."""
    shim = tmp_path / "bin" / "tar"
    shim.parent.mkdir()
    note = tmp_path / "marked"
    shim.write_text(MARKING_TAR.format(real=shlex.quote(shutil.which("tar")),
                                       note=shlex.quote(str(note))), encoding="utf-8")
    shim.chmod(0o755)
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()
    out = subprocess.run(["bash", "tools/make_release.sh", head, str(tmp_path / "out")],
                         cwd=ROOT, capture_output=True, text=True,
                         env={**os.environ,
                              "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}"})
    assert out.returncode == 0, out.stderr
    assert note.exists(), "the host never marked the staged tree: nothing below is a test"
    with tarfile.open(next((tmp_path / "out").glob("*.tar.gz")), "r:gz") as archive:
        members = archive.getmembers()
    with zipfile.ZipFile(next((tmp_path / "out").glob("*.zip"))) as archive:
        in_zip = {info.filename for info in archive.infolist() if not info.is_dir()}
    assert not [m.name for m in members if Path(m.name).name.startswith("._")]
    assert not [(m.name, key) for m in members for key in m.pax_headers
                if "xattr" in key.lower()]
    assert {m.name for m in members if m.isfile()} == in_zip
