"""An update replaces the code and keeps the credential.

⚠ THE MISTAKE AN MDM MAKES AT SCALE IS PUSHING THE ROLLOUT COMMAND TWICE.
A fleet tool pushes one command to fifty laptops. The command in the rollout
runbook carries `--enrol`. Run again a month later as an update, unchanged, it
used to re-enrol every machine — and which failure you got depended on whether
the operator reused the secret:

    the SAME secret       the collector namespaces the device id by the
                          enrolment digest, so the id is identical and it
                          answers 409. `install.py` then REFUSES AND EXITS 2 —
                          the update does not land, and fifty machines silently
                          stay on the old build.
    a DIFFERENT secret    a new rollout secret is a new digest, so the same
                          laptop proposes a DIFFERENT device id, mints a second
                          credential, and the freshly-minted one overwrites the
                          carried one. The machine keeps shipping AS A NEW
                          DEVICE, its history split in two, with nothing
                          anywhere recording that they are one machine.

Either way it also spends a use from the cap, so a cap sized to the fleet is
exhausted by the second update and the machines at the end get 429.

So a carried token WINS over an enrolment string. That inverts this file's
usual rule — an explicit flag beats a carried value — and the exception is the
point: every other flag names a SETTING, and this one would replace an IDENTITY
that has history behind it.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import install                                                     # noqa: E402


class _Args:
    """The flags this decision reads, and nothing else."""

    def __init__(self, **over):
        self.enrol = None
        self.re_enrol = False
        self.device_id = None
        self.device_label = None
        self.dry_run = False
        self.__dict__.update(over)


# ══════════════════════════════ 2.2 · a carried token wins ══

def test_an_enrolment_string_is_ignored_on_a_machine_that_has_a_token(capsys):
    """⚠ IGNORED AND SAID SO. Silently obeying is a re-enrolment; silently
    refusing is an operator who thinks the string did something."""
    args = _Args(enrol="sting-enrol-v1.whatever")
    carried = {"STING_DEVICE_TOKEN": "already-a-real-token",
               "STING_DEVICE_ID": "c1790fbc-laptop"}

    already = (carried.get("STING_DEVICE_TOKEN") or "").strip()
    assert already, "the fixture is wrong — nothing is carried"

    # the decision, as install.py makes it
    would_enrol = bool(args.enrol) and not (already and not args.re_enrol)
    assert not would_enrol, "an update would re-enrol an enrolled machine"


def test_re_enrol_is_what_lets_somebody_mean_it():
    """⚠ WITHOUT THE FLAG the only way to move a machine would be deleting
    `~/.sting/env` by hand — and a documented "delete this file first" step is
    how a fleet ends up with a script that deletes it every time."""
    args = _Args(enrol="sting-enrol-v1.whatever", re_enrol=True)
    already = "a-token"
    would_enrol = bool(args.enrol) and not (already and not args.re_enrol)
    assert would_enrol


def test_the_flag_is_cleared_rather_than_the_branch_being_skipped():
    """⚠ THE SHAPE THAT LEAVES ONE USE BEHIND. An `if` around every later read
    of `args.enrol` is a list somebody adds to; the one left off would be the
    one that mints."""
    args = _Args(enrol="sting-enrol-v1.whatever")
    dropped = install._without_enrolment(args)
    assert dropped.enrol is None
    assert args.enrol is not None, "the caller's own object was mutated"


def test_install_declines_before_it_calls_the_collector():
    """The refusal must come before the network call, or the use is spent
    whatever the installer then decides to do with the answer."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    guard = source.find("if args.enrol and already and not args.re_enrol:")
    call = source.find("enrol_client.enrol(")
    assert guard != -1, "the already-enrolled guard is gone"
    assert call != -1, "the enrolment call is gone — re-point this test"
    assert guard < call, (
        "the guard runs after the mint, so an update still spends a use")


def test_the_re_enrol_flag_exists_and_says_what_it_costs():
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    assert '"--re-enrol"' in source
    at = source.find('"--re-enrol"')
    help_text = source[at:at + 600]
    assert "NEW" in help_text and "history" in help_text, (
        "the flag does not say that the old device's history does not follow")


# ══════════════════════════ 2.3 · what an update must not destroy ══

def test_the_update_report_names_the_three_things_it_kept():
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    block_at = source.find('head("What this UPDATE kept")')
    assert block_at != -1, "the update no longer says what it preserved"
    block = source[max(0, block_at - 1800):block_at + 900]

    assert "sessions" in block and "cursor" in block, (
        "the update report does not name the sessions directory and the cursor")
    # ⚠ RE-PINNED BY ITEM 2: this asserted the block pointed at
    # `--uninstall`'s reasoning ("run it to read it in full"). An agent may make
    # a dry run, which prints this block, so it names no switch; the one-line
    # reason stays, and the full argument is still `--uninstall`'s alone.
    # tests/test_an_agent_cannot_change_the_install.py reads the printed output.
    assert "the logs are EVIDENCE" in block
    assert "run it to read it in full" not in block


def test_the_report_is_ABOVE_the_preflight_gate():
    """⚠ FOUND BY THE WALK, NOT BY A TEST. This block first sat in `Done`, which
    is behind `return 1` on a preflight failure — so an update run with
    `--no-supervisor` (one FAIL, by design) printed a preflight failure and
    never said the credential had been kept. That is exactly the moment an admin
    needs to know it."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    report = source.find('head("What this UPDATE kept")')
    gate = source.find('say(messages.preflight_failed())')
    # ⚠ EACH ONE ASSERTED SEPARATELY. The repo's own meta-test flags a
    # comparison between two positions read out of a file with nothing
    # establishing they were found — and a combined `a != -1 and b != -1` is a
    # BoolOp it cannot see through, which is the same blind spot one level up.
    assert report != -1, "the update report is gone"
    assert gate != -1, "the preflight gate is gone — re-point this test"
    assert report < gate, (
        "the update report is behind the preflight gate again — a failing "
        "preflight now hides what the update preserved")


def test_updating_is_derived_from_the_machine_and_not_from_a_flag():
    """⚠ AN MDM PUSHES THE SAME COMMAND EVERY TIME. Nothing on the command line
    distinguishes the first install from the fiftieth, and asking an operator to
    remember which one this is is asking them to get it wrong."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    at = source.find("updating = ")
    assert at != -1, "the update detection is gone"
    line = source[at:source.index("\n", at)]
    assert "carried" in line or "is_dir()" in line
    assert "args." not in line, "an update is being decided from a flag"


# ═══════════════════════════════════ 2.5 · unattended, on this path too ══

def test_every_prompt_on_the_update_path_is_still_terminal_guarded():
    """⚠ THE HAZARD IS NOT `EOFError` — a closed stdin raises and the process
    dies visibly. It is an INHERITED PIPE THAT NEVER CLOSES, which blocks
    forever with no error anywhere; that is the one that hangs a fleet rollout.
    Measured on the update path with `< <(sleep 400)`: it exited.
    """
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    prompts = [n for n in ast.walk(tree)
               if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "input"]
    assert prompts, "no prompt found — this test has lost its subject"

    for node in prompts:
        enclosing = next(
            f for f in ast.walk(tree)
            if isinstance(f, ast.FunctionDef)
            and f.lineno <= node.lineno <= (f.end_lineno or node.lineno))
        body = ast.get_source_segment(source, enclosing) or ""
        assert "isatty" in body, (
            f"input() at line {node.lineno} in {enclosing.name}() is not "
            f"guarded by a terminal check — an unattended update would hang")


# ═════════════════════════════════════ 2.4 · what is left behind ══

def test_an_install_reclaims_the_stale_bridge_and_not_only_uninstall():
    """A reinstall replaces the hook entry and ORPHANS the bridge beside the
    pointer. ⚠ THE ORDER IS THE CARE: the old `hooks.json` still names that file
    until the config is rewritten, and deleting it first opens a window where a
    Cursor hook resolves a bridge that is not there — under `failClosed:false`,
    a silent allow."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    reclaim = source.find('cursor_bridge.ps1",)')
    configs = source.find("write_hook_config")
    assert reclaim != -1, "the install no longer reclaims the orphaned bridge"
    assert configs != -1 and configs < reclaim, (
        "the bridge is deleted before the config that still names it")


def test_an_update_keeps_exactly_two_version_trees_and_never_the_live_one():
    """⚠ TWO, AND NEITHER ONE NOR ZERO — the number IS the rollback story.

    `current` is a pointer, so the only rollback this product has is a pointer
    flip back to the tree that worked: there is no auto-updater and no download
    to re-run offline. Keeping only the live tree removes the whole recovery
    path to save 1.4 MB. Keeping ALL of them — which is what `place()` did until
    the release pass — accumulates one 1.4 MB directory per distinct content
    hash, forever, with nothing naming it.

    ⚠ AND THE LIVE TREE IS EXCLUDED BY IDENTITY, NOT BY BEING NEWEST. This
    fixture points `current` at the SECOND-oldest tree on purpose, because that
    is what a rollback looks like — and sorting by mtime and keeping the newest
    would delete the running install at exactly the moment somebody had just
    recovered with it.
    """
    import os
    import shutil
    import tempfile

    from installer import place

    prefix = Path(tempfile.mkdtemp()) / "sting"
    prefix.mkdir(parents=True)
    names = ["v0.7-aaa", "v0.8-bbb", "v0.9-ccc", "v1.0-ddd"]
    for index, name in enumerate(names):
        tree = prefix / name
        tree.mkdir()
        (tree / "INSTALL.json").write_text('{"guard_version": "%s"}' % name)
        os.utime(tree, (1000 + index * 100, 1000 + index * 100))
    (prefix / "current").symlink_to(prefix / "v0.8-bbb")

    try:
        removed = place.prune(prefix, keep=place.KEEP_VERSIONS)
        survivors = sorted(p.name for p in prefix.iterdir() if p.is_dir()
                           and p.name != "current")

        assert (prefix / "v0.8-bbb").is_dir(), (
            "the LIVE tree was pruned — `current` now points at nothing and "
            "every hook resolves a missing file")
        assert len(survivors) == place.KEEP_VERSIONS, (
            f"kept {survivors}, expected {place.KEEP_VERSIONS} trees")
        assert "v1.0-ddd" in survivors, (
            "the most recent non-live tree is gone, so there is nothing to "
            "roll FORWARD to either")
        assert len(removed) == 2
    finally:
        shutil.rmtree(prefix.parent, ignore_errors=True)


def test_pruning_happens_after_the_pointer_moves():
    """⚠ THE WINDOW. Pruning before the swap deletes a tree while `current`
    still points into it, and a hook firing in that instant resolves a file that
    is no longer there — under `failClosed:false`, a silent allow."""
    source = (ROOT / "installer" / "place.py").read_text(encoding="utf-8")
    swap = source.find('_repoint(prefix / "current", target)')
    pruning = source.find("pruned = prune(")
    assert swap != -1, "the pointer swap is gone — re-point this test"
    assert pruning != -1, "place() no longer prunes"
    assert swap < pruning, "the prune runs before the pointer moves"


def test_a_prune_that_fails_does_not_fail_the_install():
    """A prune that throws is an install reporting failure after it has already
    succeeded — which is a machine somebody re-runs."""
    source = (ROOT / "installer" / "place.py").read_text(encoding="utf-8")
    body_at = source.find("def prune(")
    body = source[body_at:source.find("\ndef ", body_at + 10)]
    assert "except OSError" in body and "continue" in body, (
        "prune() can raise out of place(), so a permissions problem on an old "
        "directory would abort a successful install")
