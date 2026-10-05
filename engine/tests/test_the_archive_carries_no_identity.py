"""Nothing in the shipped archive may identify a person.

⚠ THE SWEEP IS NOT THE FIX — THIS IS. A sweep done once decays: the next comment
quoting a real path, the next defect note naming the machine it was found on,
puts it back. What was in the tarball when this was written:

    tools/redact_logs.py   this developer's username, email token, author name,
                           hostname and full name — HARDCODED, in a file that
                           SHIPS. It also meant the tool redacted the WRONG name
                           on a receiver's machine, so it was broken for its
                           actual purpose as well as leaky.
    install.py             a CUSTOMER's username, twice, in defect comments
    adapters/_common.py    the same customer's username, twice
    installer/supervisor.py six characters of a REAL device token

None is exploitable on its own. All four are a third party's identity in a
stranger's copy, and the token fragment is a fragment of a live credential.

⚠ THIS SCANS THE FILE SET `place.PAYLOAD` SHIPS, not the repo. The repo may hold
a real name — `logs/live-fixture` is redacted session data and `PROGRESS.md` is
a work journal — and neither is in the archive. Scanning everything would make
this fail on files that are deliberately excluded, and a check that cries wolf
is a check somebody deletes.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from installer import place                                        # noqa: E402


def _shipped_files() -> list[Path]:
    """Every file the archive contains, derived from `place.PAYLOAD` plus the
    three the release script adds. ⚠ DERIVED, NEVER RESTATED — a hardcoded list
    here would drift from what actually ships, which is the exact defect that
    put `daemon/` and `sting_hook.py` out of an archive twice."""
    names = list(place.PAYLOAD) + ["install.py", "installer", "requirements.txt",
                                   "README.md"]
    out: list[Path] = []
    for name in names:
        target = ROOT / name
        if target.is_dir():
            out += [p for p in target.rglob("*")
                    if p.is_file() and "__pycache__" not in p.parts]
        elif target.is_file():
            out.append(target)
    return sorted(out)


def _identities() -> list[str]:
    """Every identity the TREE could carry — not the one the builder has.

    ⚠ THIS WAS `propose_identity()` AND THAT WAS A REGRESSION. Deriving the list
    from the BUILD HOST made the check machine-dependent: on a runner it scanned
    for `runner` and an ephemeral runner hostname, so an archive built anywhere
    but one specific Mac passed while carrying that developer's username — the
    exact leak this file exists to prevent, now conditional on where the build
    ran. "0 identity hits across 64 files" was true on one machine and said
    nothing about any other.

    The census is the git history (every author and committer, name and email)
    plus the build host as ONE entry. It travels with the clone, so it is the
    same set on every machine. ⚠ IT CANNOT SEE A USERNAME — a username never
    appears in a commit — and that half is the SHAPE test below.
    """
    from tools.identity_census import tree_identities

    return sorted(tree_identities(ROOT))


# ════════════════════════════════ every identity the tree could carry ══

def test_no_shipped_file_names_anybody_who_has_worked_on_it():
    """⚠ THE SAME ANSWER ON EVERY MACHINE, which is the property that broke.
    A check whose input is the build host reports on the build host; this one
    reports on the archive."""
    identities = _identities()
    if not identities:
        pytest.skip("no identities could be derived here — neither a git "
                     "history nor a host identity, so this check has no input "
                     "rather than a clean result")

    offenders = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for value in identities:
            if value in text:
                line = next((i + 1 for i, l in enumerate(text.splitlines())
                             if value in l), 0)
                offenders.append(f"{path.relative_to(ROOT)}:{line} — {value!r}")

    assert not offenders, (
        "the release archive would carry somebody's identity:\n  "
        + "\n  ".join(offenders))


def test_the_census_does_not_change_when_the_building_machine_does(
        tmp_path, monkeypatch):
    """⚠ THE PROPERTY THE REGRESSION BROKE, PINNED DIRECTLY.

    This is what "machine-independent" means operationally: move the build host
    and the set of identities the archive is checked against must not shrink.
    The old derivation failed exactly here — under a different `$HOME` it
    returned that home's name and the local hostname, and the names in the
    history stopped being looked for at all.
    """
    from tools import identity_census

    here = identity_census.git_identities(ROOT)
    assert here, ("no identity could be read from the git history — the census "
                  "would fall back to the build host, which is the defect")

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("USER", "somebody-else")

    assert here == identity_census.git_identities(ROOT), (
        "the census moved with the machine — a build on another host would be "
        "checked against a different set")
    assert here <= identity_census.tree_identities(ROOT)


def test_a_degraded_census_refuses_rather_than_reporting_clean():
    """⚠ `actions/checkout` CLONES SHALLOW BY DEFAULT, so on CI `git log` sees
    ONE commit. A census over one commit is not a smaller census, it is a
    different claim — and reporting it as "no identity found" is the machine
    dependence being fixed, wearing a new coat."""
    from tools import identity_census

    state = identity_census.completeness(ROOT)
    assert set(state) >= {"git_available", "shallow", "commits_scanned",
                          "complete", "why_not"}
    assert state["complete"] is (state["git_available"] and not state["shallow"])
    if not state["complete"]:
        assert state["why_not"], "incomplete and silent about why"

    source = (ROOT / "tools" / "identity_census.py").read_text(encoding="utf-8")
    assert "return 1" in source, (
        "an incomplete census must be a non-zero exit, or a release script "
        "cannot gate on it")


def test_the_census_names_nobody_in_its_own_output(capsys):
    """⚠ A CHECKER THAT PRINTS THE NAMES IT LOOKS FOR PUBLISHES THEM. It runs in
    CI, whose logs anyone with the repo can read, so it reports COUNTS and
    SOURCES and never values — the same reason `redact_logs.leak_patterns` names
    a pattern by where it came from."""
    from tools import identity_census

    identity_census.main([])
    printed = capsys.readouterr()
    for value in identity_census.git_identities(ROOT):
        assert value not in printed.out and value not in printed.err, (
            "the census printed an identity it was looking for")


def test_the_release_script_runs_the_gate_over_the_STAGED_bytes():
    """⚠ A TEST SCANS THE WORKING TREE; A RELEASE SHIPS A STAGED COPY. Those are
    two different questions, and only the second is the one a stranger receives.
    `git archive` at a TAG can carry bytes the working tree no longer has."""
    script = (ROOT / "tools" / "make_release.sh").read_text(encoding="utf-8")
    # ⚠ `.find()` AND AN EXPLICIT `!= -1`, NOT `.index()` — the repo's own
    # meta-test flags a comparison between two positions read out of a file with
    # nothing establishing they were found, and it is right for the third time.
    # Two offsets stop meaning anything the day one marker moves, and a
    # ValueError traceback is a worse message than a sentence naming what went.
    checking = script.find("identity_census.py")
    packing = script.find("tar -czf")
    assert checking != -1, (
        "the release build does not check the archive it just staged")
    assert "--scan" in script, "the census runs but scans nothing"
    assert packing != -1, "the release script no longer builds a tarball"
    assert checking < packing, (
        "the check runs after the tarball is written, which is not a gate")


# ═══════════════════════════════ shapes that identify SOMEBODY ELSE ══

# ⚠ THE SHAPE LIST LIVES IN `tools/identity_census.py` NOW, NOT HERE. It is the
# only half that can see a USERNAME — a username never appears in a commit, so
# the census cannot derive one — and a release build has to run it over the
# staged bytes. A copy in a test file is a copy the release script cannot reach.
from tools.identity_census import ALLOWED, LEAK_SHAPES     # noqa: E402,F401


def test_no_shipped_file_carries_a_third_partys_identity_or_a_token():
    offenders = []
    for path in _shipped_files():
        if path.suffix not in (".py", ".md", ".ps1", ".txt", ".sh", ""):
            continue
        for number, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for what, pattern in LEAK_SHAPES:
                for hit in pattern.findall(line):
                    text = hit if isinstance(hit, str) else hit[0]
                    if ALLOWED.fullmatch(text) or ALLOWED.search(text):
                        continue
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{number} — {what}: {text!r}")

    assert not offenders, (
        "the release archive would carry an identifier that is not ours to "
        "ship. Replace it with a placeholder — `<name>`, `/Users/dev` — the "
        "sentence usually reads better without a real one anyway:\n  "
        + "\n  ".join(sorted(set(offenders))[:40]))


# ═════════════════════════════════ and the tool itself, which SHIPS ══

def test_redact_logs_derives_its_identities_and_hardcodes_none():
    """⚠ TWO BUGS IN ONE PLACE. `tools/` is payload, so a hardcoded identity
    list shipped the developer's name to every receiver AND redacted the wrong
    name on theirs — a fixture that LOOKS redacted is worse than no tool."""
    from tools import redact_logs

    source = (ROOT / "tools" / "redact_logs.py").read_text(encoding="utf-8")
    for value in _identities():
        assert value not in source, (
            f"redact_logs.py hardcodes {value!r} — derive it from "
            f"installer.detect.propose_identity() instead")

    assert redact_logs._derived_identities(), (
        "nothing was derived — the tool would redact nothing at all")


def test_the_substituter_and_the_checker_read_the_same_list():
    """⚠ THEY DRIFTED ONCE: the substituter was fixed to match a bare username
    while the checker stayed anchored on `/Users/`, so both halves looked for a
    shape that was no longer there while the name sat in plain text between
    them."""
    from tools import redact_logs

    derived = set(redact_logs._derived_identities())
    substituted = {re.sub(r"\\(.)", r"\1", p)
                   for p, _ in redact_logs.substitutions()}
    checked = {re.sub(r"\\(.)", r"\1", p) for _, p in redact_logs.leak_patterns()}

    assert derived <= substituted, f"not substituted: {derived - substituted}"
    assert derived <= checked, f"not checked: {derived - checked}"


def test_the_checker_does_not_flag_its_own_replacement():
    """A checker that fails on correctly redacted output is a checker nobody
    can use — measured: `claude-\\d+` matched its own placeholder `claude-000`."""
    from tools.redact_logs import leaks_in, redact

    sample = "/private/tmp/claude-501/x and " + "/Users/" + _identities()[0]
    assert leaks_in(redact(sample)) == [], redact(sample)
    assert leaks_in("/private/tmp/claude-501/x"), (
        "a real uid path is no longer detected at all")
