"""The class of defect that CANNOT fail on the machine that wrote it.

⚠ THIS IS THE THIRD TIME, WHICH IS WHY IT HAS A FILE. Everything below was green
locally and red on a runner, and each time the local pass was for a reason
unrelated to what the test claimed to check:

    the /tmp substring     an assertion on a substring of a temp directory PATH.
                           macOS gives `/private/var/folders/…`, Linux `/tmp/…`,
                           so the assertion was reading the platform.

    the identity sweep     the tool derived its identity list from the BUILD
                           HOST, so on a runner the archive check scanned for
                           `runner` and an ephemeral hostname — an archive built
                           anywhere but one laptop passed while carrying that
                           developer's username. The tests then hardcoded the
                           username, which is the same defect from the other
                           side: they passed on one machine for a reason
                           unrelated to the property.

    the stubbed HOME       `AGENT_MARKERS` resolved `Path.home()` AT IMPORT, so
                           a test that set `$HOME` to a temp directory — and
                           said so in a comment — was still pointed at the
                           developer's real home. It passed because he HAS a
                           `~/.claude`. A runner has none, so the installer
                           reported "no coding agent found" and exited 2.

The shape they share: **the test's outcome depends on a property of the author's
machine that the test does not name.** A username, a filesystem layout, an
installed application. Nothing in the test says "this passes because my laptop
has X", so nothing fails when X goes away — until the machine changes.

There is no general detector for that. What CAN be pinned is the two mechanisms
that produced it here, and both are pinned below.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# ══════════════════ 1 · a home resolved at IMPORT cannot be isolated by $HOME ══

# ⚠ AN INVENTORY, NOT A BAN. A module constant computed from `Path.home()` is
# fine as long as everyone knows it is FROZEN AT IMPORT and isolates it by
# monkeypatching the constant. The trap is the ones nobody knows about — the
# test that sets `$HOME`, believes that is enough, and is silently reading the
# developer's real home. So each one is listed here with how a test must isolate
# it, and a NEW one fails this test until somebody writes that sentence down.
FROZEN_AT_IMPORT = {
    ("install.py", "ENV_FILE"):
        "monkeypatch `install.ENV_FILE` — `setenv('HOME')` does NOT move it. "
        "tests/conftest.py points it at each test's home for every test",
    ("installer/recorded.py", "ENV_FILE"):
        "monkeypatch `install.recorded.ENV_FILE` as well; they are two names. "
        "tests/conftest.py points it at each test's home for every test",
    ("shipper/config.py", "ENV_FILE"):
        "monkeypatch `shipper.config.ENV_FILE`. tests/conftest.py points it at "
        "each test's home for every test",
    ("tools/corpus_1000.py", "_ROOTS"):
        "the live decision logs the normals are mined from: a test reads this "
        "run's copy of them instead (tests/conftest.py `live_logs`)",
    ("tools/corpus_1000.py", "SOURCES"):
        "scenario DATA, not a location: the path a generated attack reads. "
        "Nothing opens it",
    ("tools/corpus_1000.py", "DISAGREEMENT"):
        "scenario DATA, not a location, as SOURCES",
    ("tools/session_context.py", "TRANSCRIPTS"): "read-only; pass a root instead",
    ("tools/replay_transcript.py", "PROJECTS"): "read-only; pass a root instead",
    ("tools/redact_logs.py", "DEFAULT_TRANSCRIPTS"): "overridden by --transcripts",
    ("tools/label_prompts.py", "LIVE_ROOTS"): "overridden by the CLI",
    ("runner/replay_live.py", "DEFAULT_LOG_ROOT"): "overridden by --root",
    ("tools/preflight.py", "SETTINGS"):
        "preflight normally runs as a SUBPROCESS, so it reads $HOME at start "
        "and this is not frozen from the caller's point of view — but an "
        "in-process test must monkeypatch `preflight.SETTINGS`",
}

_SCANNED = ["install.py", "installer", "core", "adapters", "shipper", "tools",
            "daemon", "runner"]


def _module_level_home_constants() -> dict:
    found = {}
    for name in _SCANNED:
        target = ROOT / name
        paths = ([target] if target.is_file()
                 else [p for p in target.rglob("*.py")
                       if "__pycache__" not in p.parts])
        for path in paths:
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                continue
            for node in tree.body:
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                text = ast.get_source_segment(
                    path.read_text(encoding="utf-8"), node) or ""
                # ⚠ `expanduser(`, NOT `expanduser()`: `os.path.expanduser("~/x")`
                # freezes the home as surely as `Path("~/x").expanduser()`, and
                # the narrower match let `tools/corpus_1000.py:_ROOTS` through.
                if "Path.home()" not in text and "expanduser(" not in text:
                    continue
                targets = ([node.target] if isinstance(node, ast.AnnAssign)
                            else node.targets)
                for t in targets:
                    if isinstance(t, ast.Name):
                        # ⚠ `as_posix()`, BECAUSE THE KEYS ARE WRITTEN WITH `/`.
                        # `str(relative_to())` gives `installer\config.py` on
                        # Windows, so every entry missed its inventory row and
                        # this test reported three false leaks on the Windows
                        # job — a path-separator assumption, which is the same
                        # family of defect as the file it lives in.
                        found[(path.relative_to(ROOT).as_posix(), t.id)] = text
    return found


def test_every_frozen_home_constant_says_how_to_isolate_it():
    found = _module_level_home_constants()
    unlisted = sorted(set(found) - set(FROZEN_AT_IMPORT))
    assert not unlisted, (
        "these resolve the home directory AT IMPORT, so a test that sets "
        "$HOME does NOT isolate them — and that silently pointed a test at the "
        "developer's own machine once already. Either resolve it at call time "
        "(see `installer.detect.expand`) or add it to FROZEN_AT_IMPORT with the "
        "sentence a test author needs:\n  "
        + "\n  ".join(f"{f}:{n}" for f, n in unlisted))


def test_the_inventory_has_not_gone_stale():
    """⚠ AN INVENTORY NOBODY PRUNES BECOMES A LIST OF THINGS THAT USED TO BE
    TRUE, and the next reader trusts it."""
    found = _module_level_home_constants()
    gone = sorted(set(FROZEN_AT_IMPORT) - set(found))
    assert not gone, (
        f"FROZEN_AT_IMPORT names constants that no longer exist or no longer "
        f"read the home directory: {gone}")


def test_agent_detection_is_not_frozen_at_import():
    """The one that was actually wrong, pinned so it cannot come back.

    ⚠ THE PROPERTY IS OBSERVED, NOT READ OUT OF THE SOURCE. Asserting that the
    file contains no `Path.home()` would pass the day somebody wrote
    `_HOME = Path.home()` two lines up.
    """
    import os

    from installer import detect

    # ⚠ BOTH VARIABLES, BECAUSE `expanduser()` READS A DIFFERENT ONE PER
    # PLATFORM. On Windows it prefers `USERPROFILE` and ignores `HOME`, so
    # setting only HOME moved nothing and this test failed on the Windows job
    # while asserting that something had moved — a test that cannot tell "the
    # code is frozen" from "I set the wrong variable".
    keys = ("HOME", "USERPROFILE")
    elsewhere = str(Path("/nowhere-in-particular").resolve())

    before = detect.agent_markers()["claude-code"][0]
    original = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ[k] = elsewhere
        after = detect.agent_markers()["claude-code"][0]
    finally:
        for k, value in original.items():
            if value is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = value

    assert before != after, (
        "agent detection did not follow the home directory — a test that "
        "isolates itself by setting HOME is reading the developer's real "
        "machine, and it passes or fails on whether HE has an agent installed")
    assert str(after).startswith(elsewhere)


# ═══════════════════ 2 · a check whose INPUT is the machine checks the machine ══

def test_the_archive_census_does_not_come_from_the_build_host_alone():
    """⚠ THE REGRESSION IN ONE LINE. `propose_identity()` is the RUNNING USER,
    which is right for redacting their log and wrong for checking an archive:
    it made "0 identity hits" a claim about the build host."""
    from tools import identity_census

    from_history = identity_census.git_identities(ROOT)
    from_host = identity_census.host_identities()

    assert from_history, "the census has no machine-independent half at all"
    assert not from_history <= from_host, (
        "every identity in the history is also this host's — the census cannot "
        "be distinguished from the build host here, so this test cannot tell "
        "whether it is machine-independent. Run it where the two differ.")
    assert from_history <= identity_census.tree_identities(ROOT)
