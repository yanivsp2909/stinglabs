"""The entry point is named in four places, and three of them had drifted.

⚠ FOUND BY WALKING A CLEAN INSTALL END TO END, NOT BY A TEST. That is the whole
argument for walking one: the suite was green, 2402 tests, while the artifact a
customer receives could not install.

    installer/place.PAYLOAD    what an install COPIES        had sting_hook.py
    tools/make_release.sh      what an archive CONTAINS      ⚠ hardcoded, stale
    install.py                 what the hook COMMAND names   sting_hook.py
    tools/preflight.py         what preflight LOOKS FOR      ⚠ hook_entry.py

So an archive built from HEAD omitted `sting_hook.py` and `daemon/`;
`place()` skipped the missing files SILENTLY; `install.py` exited 0 and wrote
every agent's hook config pointing at a file that was not on disk; and preflight
would have failed on a correct install anyway, because it was still looking for
the old name.

**Three separate single-sources-of-truth, none of them single.** These tests
make the four agree, in the run that changes any one of them.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import install as install_module                                     # noqa: E402
from installer import place                                          # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _entry_name_install_writes() -> str:
    """The basename `install.py` points every agent's hook at."""
    source = open(os.path.join(ROOT, "install.py"), encoding="utf-8").read()
    match = re.search(r'entry\s*=\s*result\["current"\]\s*/\s*"([^"]+)"', source)
    assert match, "install.py no longer names its entry point in one place"
    return match.group(1)


def test_the_entry_point_install_writes_is_one_the_payload_copies():
    """⚠ THE ONE TEST THAT WOULD HAVE CAUGHT THE BROKEN ARCHIVE.

    Pointing an agent's hook at a file the install does not copy produces a hook
    command naming a path that does not exist — on every tool call, forever, on
    a machine that was told the install succeeded.
    """
    entry = _entry_name_install_writes()
    assert entry in place.PAYLOAD, (
        f"install.py points hooks at {entry!r}, which place.PAYLOAD does not "
        f"copy: {place.PAYLOAD}")


def test_preflight_recognises_the_entry_point_install_writes():
    """⚠ THE SECOND ONE IT WOULD HAVE CAUGHT.

    Preflight is the check that tells a developer whether the install worked. A
    preflight that fails on every correct install teaches people to ignore it,
    which costs more than the check is worth.
    """
    from tools import preflight

    entry = _entry_name_install_writes()
    assert entry in preflight.ENTRY_NAMES, (
        f"preflight looks for {preflight.ENTRY_NAMES}, the installer writes "
        f"{entry!r}")


def test_preflight_still_recognises_the_older_entry_point():
    """⚠ AND THE OLD NAME STAYS, because installs predating the daemon wrote it.

    A developer whose machine was set up two weeks ago has `hook_entry.py` in
    their settings file and a working guard. Preflight must not tell them it is
    broken.
    """
    from tools import preflight

    assert "hook_entry.py" in preflight.ENTRY_NAMES


def test_the_release_builder_does_not_restate_the_payload():
    """⚠ IT DID, AND THE COPY WENT STALE THE DAY THE DAEMON LANDED.

    The list is now read out of `installer/place.py` AT THE TAG BEING BUILT —
    at the tag, because an archive of v0.9 must ship what v0.9's installer
    copies, and reading today's list would build yesterday's release against
    tomorrow's manifest.
    """
    script = open(os.path.join(ROOT, "tools", "make_release.sh"),
                  encoding="utf-8").read()
    body = "\n".join(line for line in script.splitlines()
                     if not line.lstrip().startswith("#"))

    assert "installer/place.py" in body, \
        "the payload must be derived from place.py, not restated"
    assert "$PAYLOAD" in body
    for name in place.PAYLOAD:
        if name == "installer/place.py":
            # ⚠ THE ONE NAME THIS TEST REQUIRES TO BE PRESENT. Since G2,
            # `installer/place.py` is itself a PAYLOAD item (the supervisor's
            # per-install label needs `default_prefix()`), and the assertion
            # three lines up demands the script name it — as the file the list
            # is READ FROM at the tag. That appearance is the derivation, not a
            # restatement, and forbidding it here would contradict the check
            # that exists to enforce it. Every other item stays forbidden.
            # Residual, accepted: a literal RE-hardcode of this one name would
            # now be indistinguishable from the derivation reference. A file
            # that goes MISSING is still caught — by the script's shipped-file
            # loop and by test_every_placed_module_imports_only_what_was_placed.
            continue
        assert f" {name} " not in body.replace("\n", " "), (
            f"{name!r} appears literally in make_release.sh — that is the "
            f"duplication that drifted")


def test_the_release_builder_verifies_what_it_shipped():
    """`git archive` skips a path that does not exist at the tag WITHOUT
    complaining, so deriving the list is not the same as shipping it."""
    script = open(os.path.join(ROOT, "tools", "make_release.sh"),
                  encoding="utf-8").read()

    assert "REFUSING TO SHIP" in script
    # ⚠ THIS ASSERTED `for item in $PAYLOAD`, AND THAT WAS THE NARROWER LIST.
    # The script also shipped `install.py`, `installer`, `requirements.txt` and
    # `README.md` — none of them verified. `install.py` IS the entry point and
    # `installer/` is the package it imports, while `place.PAYLOAD` names only
    # `installer/cursor_bridge.ps1`. The loop now walks everything shipped, and
    # this test would have passed the whole time the gap existed.
    assert "for item in $SHIPPED; do" in script
    assert 'SHIPPED="$PAYLOAD install.py installer requirements.txt README.md"' in script


# ──────────────────────────────────────────── a partial source must refuse

def test_placing_from_a_source_missing_a_payload_item_refuses(tmp_path):
    """⚠ IT USED TO `continue`, AND THAT IS HOW A BROKEN ARCHIVE INSTALLED
    CLEANLY.

    `place()` returned successfully, `install.py` exited 0, the hook config was
    written, and only preflight noticed — on a machine where preflight was also
    broken, nothing would have.
    """
    source = tmp_path / "partial"
    source.mkdir()
    for name in place.PAYLOAD:
        if name == "sting_hook.py":
            continue                      # exactly the file that went missing
        target = source / name
        # ⚠ A PAYLOAD ENTRY IS NOT ALWAYS A TOP-LEVEL PACKAGE. Since the Windows
        # bridge became payload, one entry is a FILE INSIDE a directory that is
        # not itself payload (`installer/cursor_bridge.ps1`). This builder used
        # to assume "not .py" meant "package", so it tried to mkdir a .ps1 whose
        # parent did not exist — the fixture broke, not the product.
        if "/" in name or name.endswith(".py"):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# stub\n", encoding="utf-8")
        else:
            target.mkdir()
            (target / "__init__.py").write_text("", encoding="utf-8")

    with pytest.raises(FileNotFoundError) as caught:
        place.place(prefix=tmp_path / "prefix", source=source,
                    session_root=tmp_path / "sessions")

    assert "sting_hook.py" in str(caught.value)


def test_a_refusal_leaves_no_half_written_tree(tmp_path):
    """⚠ CHECKED BEFORE ANYTHING IS COPIED. A refusal that had already written
    half a tree would be the partial install it exists to prevent, one level
    down.

    ⚠ THIS ASSERTS A COLLECTION IS EMPTY, WHICH IS THE INVERSE OF WHAT
    `test_absence_is_not_a_default` POLICES — and it caught this test, correctly.
    "No files were written" passes just as well when the measurement is blind, so
    a CONTROL runs first: a complete source into a sibling prefix, asserted
    non-empty. That proves `rglob` can see a placed file here, on this
    filesystem, in this test — and only then does the empty result mean
    something.
    """
    control_prefix = tmp_path / "control"
    place.place(prefix=control_prefix, source=ROOT,
                session_root=tmp_path / "sessions")
    control = [p for p in control_prefix.rglob("*") if p.is_file()]
    assert control, "the control placed nothing — this test cannot see files"

    source = tmp_path / "partial"
    source.mkdir()
    (source / "core").mkdir()

    prefix = tmp_path / "prefix"
    with pytest.raises(FileNotFoundError):
        place.place(prefix=prefix, source=source,
                    session_root=tmp_path / "sessions")

    leftovers = [p for p in prefix.rglob("*") if p.is_file()] \
        if prefix.exists() else []
    assert not leftovers, f"a refused install left files behind: {leftovers}"


def test_a_complete_source_still_places(tmp_path):
    """⚠ THE OTHER HALF. Without it the two tests above are satisfied by a
    `place()` that refuses everything."""
    placed = place.place(prefix=tmp_path / "prefix", source=ROOT,
                         session_root=tmp_path / "sessions")

    current = placed["current"]
    for name in place.PAYLOAD:
        assert (current / name).exists(), f"{name} was not placed"
