"""Sites 2 and 5, measured — and they never needed a Windows runner.

⚠ THE FINDING THAT CHANGES PHASE 3'S STRATEGY. Sites 2 and 5 measured ZERO
failures on `windows-latest` both before and after the corpus was put on CI. The
first reading was "the corpus is missing". The corpus is now there and they are
STILL zero, which means the corpus was necessary and not sufficient:

    the 88-scenario corpus is ENTIRELY POSIX-SHAPED — grepping every fixture
    for a `C:\\` path finds nothing — so replaying it on Windows exercises
    POSIX paths on a Windows machine, which is not the failing case at all.

And once that is said, the other half follows: **these sites are pure functions
of a path STRING.** `CREDENTIAL_PATHS.search("C:\\\\Users\\\\x\\\\.env")` returns the
same answer on macOS as it does on Windows. They do not need the platform; they
need the platform's INPUTS. Every test below runs everywhere.

⚠ EACH IS `xfail(strict=True)`, WHICH IS THE POINT. The defect exists today, so
these pass as expected-failures and the suite stays green. The day somebody
fixes a site, its test FAILS as an unexpected pass — turning this file into
Phase 3's acceptance criteria rather than a list of complaints. Nothing here
touches the seven sites, which is Phase 3's job.
"""
from __future__ import annotations

import pytest

from core.engine import CREDENTIAL_PATHS

# Windows spellings of the paths `CREDENTIAL_PATHS` is meant to catch. Every one
# of these is a real place a credential lives on a Windows developer machine.
WINDOWS_CREDENTIALS = [
    r"C:\Users\dev\project\.env",
    r"C:\Users\dev\project\.env.production",
    r"C:\Users\dev\.ssh\id_rsa",
    r"C:\Users\dev\.ssh\id_ed25519",
    r"C:\Users\dev\.aws\credentials",
    r"C:\Users\dev\.npmrc",
    r"C:\Users\dev\.netrc",
    r"C:\Users\dev\.docker\config.json",
    r"C:\Users\dev\.kube\config",
    r"\\fileserver\share\team\.env",
]

# ⚠ THESE ALREADY WORK ON WINDOWS, AND FINDING THAT OUT WAS THE POINT OF
# `strict=True`. `\.pem$`, `\.p12$` and `\.pfx$` are SUFFIX patterns with no
# `/` in them, so they match a backslash path unchanged. Site 2 is not "the
# matcher fails on Windows" — it is "the `/`-anchored ALTERNATIVES fail", which
# is a smaller and more precise claim. Listed here so Phase 3 does not
# "fix" something that is not broken and call the extra work progress.
WINDOWS_ALREADY_MATCHED = [
    r"C:\Users\dev\certs\server.pem",
    r"C:\Users\dev\certs\client.p12",
    r"C:\keys\bundle.pfx",
]


@pytest.mark.parametrize("path", WINDOWS_ALREADY_MATCHED)
def test_the_suffix_patterns_already_survive_a_windows_path(path):
    assert CREDENTIAL_PATHS.search(path), path

POSIX_CONTROL = [
    "/home/dev/project/.env",
    "/home/dev/.ssh/id_rsa",
    "/home/dev/.aws/credentials",
]


@pytest.mark.parametrize("path", POSIX_CONTROL)
def test_the_matcher_works_on_posix_paths(path):
    """⚠ THE CONTROL, AND IT IS NOT DECORATION. Without it, an xfail below could
    be passing because the matcher is broken for everything rather than for
    Windows specifically — the two have identical symptoms and opposite scopes."""
    assert CREDENTIAL_PATHS.search(path), path


@pytest.mark.parametrize("path", WINDOWS_CREDENTIALS)
def test_site_2_the_matcher_should_see_a_windows_credential(path):
    """⚠ THIS IS THE WHOLE SECRET HALF, AND IT FAILS SILENTLY.

    No exception, no log line, no failing test on the platform — the session
    simply never sets `holds_secret`, so the copy is not tainted, the commit is
    not blocked, and the push is ALLOWED. A Windows install would boot, write a
    verifiable chain, ship to the collector, and catch nothing:
    **indistinguishable in observe mode from a clean week.**
    """
    assert CREDENTIAL_PATHS.search(path), path


def test_the_corpus_cannot_reach_these_sites(request):
    """⚠ WHY THE CORPUS DID NOT MOVE THE NUMBER. Stated as a test so the claim
    is checked rather than asserted in a document — if somebody adds a
    Windows-shaped fixture, this fails and the strategy note above is stale."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "scenarios"
    if not root.is_dir():
        pytest.skip("no corpus in this checkout")

    windows_shaped = re.compile(r"[A-Za-z]:\\\\|[A-Za-z]:\\[A-Za-z]")
    hits = []
    for path in root.rglob("*"):
        if not path.is_file() or "__pycache__" in str(path):
            continue
        try:
            if windows_shaped.search(path.read_text(encoding="utf-8")):
                hits.append(str(path.relative_to(root)))
        except (UnicodeDecodeError, OSError):
            continue
    assert not hits, (
        f"the corpus now contains Windows-shaped paths ({hits[:3]}) — "
        f"sites 2 and 5 may now be reachable through it, and "
        f"docs/27-corpus-on-ci.md needs updating")


def test_site_5_a_basename_split_handles_a_backslash():
    """The same shape as site 2 and the same silence: a basename that is really
    the entire path matches nothing, so a rule keyed on the file's name never
    fires.

    ⚠ TESTS THE ENGINE'S HELPER, NOT `str.rsplit`. The first version asserted on
    `path.rsplit("/")` directly, which is a test of Python rather than of this
    codebase — it could never have failed for the right reason or passed for it.
    """
    from core.engine import _basename
    assert _basename(r"C:\Users\dev\project\.env") == ".env"
    assert _basename("/home/dev/project/.env") == ".env"
    assert _basename(r"\\server\share\.env") == ".env"
    assert _basename(".env") == ".env"
    # ⚠ A MIXED PATH IS REAL: `_abs` can join a Windows cwd with a POSIX-ish
    # operand, and Windows opens both. The LAST separator of either kind wins.
    assert _basename(r"C:\work/src\main.py") == "main.py"
    assert _basename(r"C:\work\src/main.py") == "main.py"


# ═══════════════ the remaining path sites — written FAILING, then fixed
#
# ⚠ EACH IS ADDED AS xfail(strict=True) BEFORE THE FIX EXISTS, run once with
# `--runxfail` to watch it fail honestly, and only then fixed. Six of the seven
# sites fail SILENTLY, so "the tests pass" is exactly what a broken fix looks
# like — the same discipline as blinding CREDENTIAL_PATHS for the semantic probe.

WINDOWS_ABSOLUTE = [
    r"C:\projects\app\src\main.py",
    r"D:\work\.env",
    r"\\fileserver\share\project\config.json",
]


@pytest.mark.parametrize("path", WINDOWS_ABSOLUTE)
def test_site_4_abs_leaves_an_already_absolute_windows_path_alone(path):
    """⚠ `_abs` TESTED `path.startswith("/")`, so every Windows absolute path
    read as RELATIVE and was joined onto the cwd: `C:\\projects\\app` became
    `C:\\work\\C:\\projects\\app`. That path matches no root, no taint entry and
    no credential pattern — a whole action's paths silently stop resolving."""
    from core.engine import _abs
    assert _abs(path, r"C:\work") == path


def test_site_4_abs_joins_a_relative_windows_path_with_a_backslash():
    from core.engine import _abs
    assert _abs("src\\main.py", r"C:\work") == r"C:\work\src\main.py"


def test_site_4_abs_still_does_posix():
    from core.engine import _abs
    assert _abs("/etc/passwd", "/home/d") == "/etc/passwd"
    assert _abs("src/main.py", "/home/d") == "/home/d/src/main.py"


@pytest.mark.parametrize("path,root,inside", [
    (r"C:\proj\src\app.py", r"C:\proj", True),
    (r"C:\proj\.env", r"C:\proj", True),
    (r"C:\other\x.py", r"C:\proj", False),
    (r"C:\projector\x.py", r"C:\proj", False),   # ⚠ prefix, not a path segment
])
def test_site_3_is_inside_project_understands_a_windows_root(path, root, inside):
    """⚠ EVERY WINDOWS PATH READ AS OUTSIDE THE PROJECT, which turns every
    ordinary write into a `write_outside` denial — 44 of them in one real POSIX
    session when the roots were merely wrong. On Windows it was all of them."""
    from core.engine import is_inside_project
    assert is_inside_project(path, (root,)) is inside


def test_site_6_sting_roots_does_not_shatter_a_windows_path():
    """⚠ `C:\\proj` SPLIT ON `":"` BECOMES `["C", "\\proj"]` — two paths that do
    not exist, so the project has no roots at all and every write is outside it.
    `os.pathsep` is `;` on Windows and `:` on POSIX, which is the whole fix."""
    from core.probes import split_roots
    assert split_roots(r"C:\proj;D:\other", sep=";") == [r"C:\proj", r"D:\other"]
    assert split_roots("/a:/b", sep=":") == ["/a", "/b"]
    # a lone Windows path must survive intact
    assert split_roots(r"C:\proj", sep=";") == [r"C:\proj"]


# ═══════════ a scenario that misses because of the MACHINE, not the rule

def _has_a_sync_root() -> bool:
    from core import probes
    return bool(probes.RealWorld().sync_roots())


@pytest.mark.xfail(strict=True, reason="X01 needs a machine with a cloud-sync "
                                        "root. This one has iCloud only, so "
                                        "`~/OneDrive/backup/.env` matches no "
                                        "detected root and the scenario misses "
                                        "for an environmental reason.")
def test_x01_needs_a_machine_with_a_onedrive_folder():
    """⚠ THE SCENARIO IS RIGHT AND THE MACHINE CANNOT SEE IT — pinned the way
    the Windows sites were, so it fails as an UNEXPECTED PASS the day somebody
    runs the corpus on a machine with OneDrive installed.

    Without this the miss reads as a gap in the rule. The sink is proved against
    a world that HAS the root in test_engine_sources-style unit tests; what is
    absent here is the world, not the logic.
    """
    from pathlib import Path

    from core import probes
    roots = probes.RealWorld().sync_roots() or ()
    assert any("onedrive" in r.lower() for r in roots), (
        f"no OneDrive root on this machine; detected: {roots}")


def test_the_machine_is_reported_rather_than_assumed():
    """⚠ WHAT A SCENARIO WOULD NEED TO DECLARE THE WORLD IT RUNS IN, and this
    test is the smallest version of it: state what the machine actually has, so
    a miss can be attributed to the machine or to the rule.

    The general fix is a `requires:` block in expect.yaml — `sync_root:
    onedrive`, `platform: windows`, `tool: npm` — which the runner reads and
    reports as NOT APPLICABLE rather than MISSED. A scenario that cannot run
    here scoring as a miss is the same error class as a zero from a population
    that cannot contain the thing.
    """
    from core import probes
    roots = probes.RealWorld().sync_roots()
    assert roots is not None or roots == (), "sync_roots must answer, even emptily"
