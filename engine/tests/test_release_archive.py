"""A release archive has to answer four questions before it is a good idea.

⚠ AND THE FIRST IS THE GATE. A clone knows what it is; a zip does not. Since
`guard_version` is on every record, an install that cannot name itself
attributes nothing — so if an unpacked archive could not say what it was, the
right answer was to keep the clone and not build this at all.
"""
from __future__ import annotations

import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from installer import place                                      # noqa: E402


def test_an_unpacked_archive_reports_a_version_a_receiver_can_read(tmp_path):
    """⚠ THE STOP CONDITION, ANSWERED. Without VERSION this read
    `nogit-a96e98e1` — honest and useless, because a receiver could not tell 0.7
    from 0.8 without asking the sender."""
    root = tmp_path / "unpacked"
    (root / "core").mkdir(parents=True)
    (root / "adapters").mkdir()
    (root / "core" / "x.py").write_text("x = 1\n")
    (root / "hook_entry.py").write_text("y = 2\n")
    (root / place.VERSION_FILE).write_text("v0.9-one-archive\n")

    version = place.compute_version(root)
    assert version.startswith("v0.9-one-archive-"), version
    assert "nogit" not in version


def test_a_checkout_ignores_a_stale_version_file(tmp_path):
    """⚠ GIT WINS WHENEVER IT CAN ANSWER. A checkout carrying a stale VERSION
    must not be believed over the repository it is sitting in — otherwise an
    archive unpacked INTO a working tree would relabel it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["init", "-q"], ["config", "user.email", "t@t"],
                 ["config", "user.name", "t"]):
        subprocess.run(["git", *cmd], cwd=repo, capture_output=True)
    (repo / "f").write_text("x")
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "c"], cwd=repo, capture_output=True)
    subprocess.run(["git", "tag", "real-tag"], cwd=repo, capture_output=True)

    (repo / place.VERSION_FILE).write_text("a-lie-from-an-archive\n")
    assert place._git_ref(repo) == "real-tag", (
        "a stale VERSION beat the repository it sits in")


def test_a_version_file_that_is_not_a_ref_is_refused(tmp_path):
    """Anything with whitespace was not written by the release builder, and a
    label nobody can resolve to a commit is worse than admitting there is none."""
    (tmp_path / place.VERSION_FILE).write_text("built by hand on tuesday\n")
    assert place._git_ref(tmp_path) == "nogit"


def test_the_content_hash_still_decides_when_the_label_lies(tmp_path):
    """⚠ THE LABEL IS A CONVENIENCE; THE HASH IS THE FACT. Two trees claiming
    the same tag with different policy bytes produce different versions."""
    versions = []
    for body in ("x = 1\n", "x = 2\n"):
        root = tmp_path / f"t{len(versions)}"
        (root / "core").mkdir(parents=True)
        (root / "adapters").mkdir()
        (root / "core" / "engine.py").write_text(body)
        (root / "hook_entry.py").write_text("h = 0\n")
        (root / place.VERSION_FILE).write_text("v0.9-one-archive\n")
        versions.append(place.compute_version(root))
    assert versions[0] != versions[1]
    assert all(v.startswith("v0.9-one-archive-") for v in versions)


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs a checkout")
def test_the_builder_ships_the_runtime_and_not_the_repo(tmp_path):
    """⚠ WHAT SHIPS IS A DECISION. The checkout is 32 MB; the guard needs under
    1 MB of it. Tests, the corpus and the vendored session fixture are most of
    the bytes and none of them run the guard — and the fixture is redacted
    session data with no business on a stranger's disk."""
    tag = subprocess.run(["git", "describe", "--tags", "--abbrev=0"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    if not tag:
        pytest.skip("no tag to build from")
    out = subprocess.run(["bash", "tools/make_release.sh", tag, str(tmp_path)],
                          cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr

    archives = list(tmp_path.glob("*.tar.gz"))
    assert archives, "the builder produced no archive — nothing below is a test"
    archive = archives[0]
    names = {Path(n).parts[1] for n in tarfile.open(archive).getnames()
              if len(Path(n).parts) > 1}
    assert names, "the archive is empty; every assertion below would be vacuous"
    # ⚠ install.py IS THE ENTRY POINT NOW. bootstrap.sh was absorbed into it:
    # a second file to know about was one more thing that could be on the wrong
    # branch, which is exactly how machine three lost an hour.
    for needed in ("core", "adapters", "hook_entry.py", "install.py",
                    "installer", "VERSION"):
        assert needed in names, f"{needed} missing from the archive"
    for excluded in ("tests", "scenarios", "logs", "PROGRESS.md", "extension",
                      "bootstrap.sh"):
        assert excluded not in names, f"{excluded} should not ship"
    assert archive.stat().st_size < 2_000_000, "the archive grew past a megabyte"


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs a checkout")
def test_the_notice_ships_from_the_commit_that_introduced_it(tmp_path):
    """⚠ THE NOTICE IS A LICENCE OBLIGATION, NOT DECORATION. core/known_formats.py
    transcribes its pattern table from MIT and Apache-2.0 rulesets (docs/85),
    and both licences travel with the copy or the copy is not lawful. The
    builder asks the TAG for it — so an archive built at a commit that has one
    carries it, and a rehearsal from an older tag still builds.

    ARMED both ways: built at HEAD the archive must carry NOTICE; built at the
    last tag (which predates it) the builder must not fabricate one."""
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    assert head, "no HEAD to build from"
    assert (ROOT / "NOTICE").is_file(), "NOTICE is gone from the repository root"
    out = subprocess.run(["bash", "tools/make_release.sh", head, str(tmp_path / "head")],
                          cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    archives = list((tmp_path / "head").glob("*.tar.gz"))
    assert archives, "the builder produced no archive at HEAD"
    names = {Path(n).parts[1] for n in tarfile.open(archives[0]).getnames()
             if len(Path(n).parts) > 1}
    assert "NOTICE" in names, "the archive built at HEAD does not carry NOTICE"

    tag = subprocess.run(["git", "describe", "--tags", "--abbrev=0"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    has_notice_at_tag = subprocess.run(
        ["git", "cat-file", "-e", f"{tag}:NOTICE"], cwd=ROOT).returncode == 0
    if tag and not has_notice_at_tag:
        out = subprocess.run(["bash", "tools/make_release.sh", tag, str(tmp_path / "tag")],
                              cwd=ROOT, capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        old_names = {Path(n).parts[1] for n in
                     tarfile.open(next((tmp_path / "tag").glob("*.tar.gz"))).getnames()
                     if len(Path(n).parts) > 1}
        assert "NOTICE" not in old_names, "the builder fabricated a NOTICE the tag lacks"


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs a checkout")
def test_a_digest_ships_beside_it_and_the_note_says_what_it_does_not_prove(tmp_path):
    """⚠ A CHECKSUM PROVES THE BYTES ARE THE BYTES. It proves nothing about who
    sent them — anyone who can replace the archive can replace the digest beside
    it. For a security tool that is not a footnote."""
    tag = subprocess.run(["git", "describe", "--tags", "--abbrev=0"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    if not tag:
        pytest.skip("no tag to build from")
    out = subprocess.run(["bash", "tools/make_release.sh", tag, str(tmp_path)],
                          cwd=ROOT, capture_output=True, text=True)
    assert list(tmp_path.glob("*.sha256")), "no digest beside the archive"
    assert "It proves NOTHING" in out.stdout
    assert "who they think" in out.stdout

    source = (ROOT / "tools" / "make_release.sh").read_text(encoding="utf-8")
    assert "different channel" in source
