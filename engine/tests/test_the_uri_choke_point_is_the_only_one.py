"""BUG 5 WAS ALREADY FIXED. This file is the finding, not a second fix.

THE REPORT: Cursor's `/C:/Users/…` roots log as `C:Users\\…` — a separator lost,
capture still working, so nothing looks broken while the trust boundary may be
silently wrong.

THE ANSWER, of the three possible ones: **the fix covers it and that install is
old.** Evidence, in order:

  1. `adapters/_common._from_uri` converts `/C:/…` and `file:///C:/…` to a
     native path. Run, not read:

         _from_uri("/C:/Users/alice/Projects")       -> "C:/Users/alice/…"
         _from_uri("file:///C:/Users/alice/Projects") -> "C:/Users/alice/…"
         PureWindowsPath("C:/Users/alice/…")            -> "C:\\Users\\alice\\…"

     and the losing shape it replaced is reproducible for comparison:

         PureWindowsPath("/C:/Users/alice/…")           -> "\\C:\\Users\\alice\\…"

  2. It is reached by EVERY path an adapter produces. `resolve_path` is the
     only path constructor in `adapters/_common`, `_from_uri` is its first
     statement, and `resolve_paths`, `resolve_cwd` and `workspace_roots` all
     route through it. The five adapters build no path any other way — asserted
     below rather than grepped once and forgotten.

  3. It landed in `db2aaca` (11 Aug 2026), the Cursor-on-Windows transport
     pass, WHICH WAS WRITTEN FROM THAT MACHINE'S REPORT. The report is the
     input to the fix, so it necessarily predates it. Nothing has been captured
     from a Windows Cursor install since.

⚠ NO SECOND NORMALISER IS ADDED, AND THAT IS THE POINT OF THE WHOLE ARRANGEMENT.
`_from_uri` sits at one choke point precisely so a second one cannot disagree
with it — two normalisers that differ by one shape produce a boundary that
matches on one code path and misses on another, which is the original defect
with more places to hide. What this file adds is a test that the choke point
cannot be bypassed.

────────────────────────────────────────────────────────────────────────────────
⚠ THE ONE RESIDUAL, WHICH IS A DIFFERENT ROUTE AND NOT THIS BUG
────────────────────────────────────────────────────────────────────────────────

Roots reach the boundary two ways, and only one of them is the adapter:

    PAYLOAD   Cursor's `workspace_roots`  -> _common -> _from_uri     covered
    ENV       STING_ROOTS from ~/.sting/env -> core/probes            NOT covered

`core.probes` cannot call `_from_uri` — `adapters` imports `core`, so the
reverse is a cycle — and it should not: `STING_ROOTS` is not something Cursor
sends, it is a value a human typed into an installer. A URI there is a typo, and
a typo is caught where typos are caught: `install.check_roots` reports it as a
root that does not exist, and `install._root_hint` says "this looks like a
Cursor/VS Code URI for …" by CALLING `_from_uri` rather than restating it. The
installer diagnoses; it does not rewrite. See
`tests/test_declared_roots_are_checked.py`.
"""
from __future__ import annotations


from pathlib import Path, PureWindowsPath

import pytest

from adapters import _common, antigravity, claude_code, codex, copilot, cursor

ROOT = Path(__file__).resolve().parent.parent
ADAPTERS = (antigravity, claude_code, codex, copilot, cursor)


# ══════════════════════════════════════════════ 1 · the fix does convert ══

def test_the_reported_shape_produces_a_native_windows_path():
    """⚠ ASSERTED IN WINDOWS SEMANTICS, on any host. `PureWindowsPath` is pure
    string logic, so the claim "this becomes C:\\Users\\… on Windows" can be
    checked from macOS instead of being reasoned about."""
    converted = _common._from_uri("/C:/Users/alice/Projects")
    assert str(PureWindowsPath(converted)) == r"C:\Users\alice\Projects"

    converted = _common._from_uri("file:///C:/Users/alice/Projects")
    assert str(PureWindowsPath(converted)) == r"C:\Users\alice\Projects"


def test_the_unfixed_shape_really_did_lose_the_separator():
    """⚠ THE CONTROL. Without this the fix is asserted against a defect nobody
    reproduced — and a fix for a defect that was never demonstrated is a change,
    not a fix. Carried through verbatim, the URI is not a drive path at all."""
    raw = PureWindowsPath("/C:/Users/alice/Projects")
    assert raw.drive == "", "the drive letter was still recognised"
    assert str(raw) != r"C:\Users\alice\Projects"


def test_a_posix_path_is_untouched():
    for p in ("/usr/local/bin", "/private/tmp/x", "relative/x",
              "/home/x/file:with:colons", "/Users/alice/Projects"):
        assert _common._from_uri(p) == p


# ═════════════════════════════════════ 2 · and it cannot be gone around ══

def test_from_uri_is_the_first_thing_resolve_path_does():
    source = (ROOT / "adapters" / "_common.py").read_text(encoding="utf-8")
    body = source.split("def resolve_path(", 1)[1].split("\ndef ", 1)[0]
    first = [l.strip() for l in body.splitlines()
             if l.strip() and not l.strip().startswith(('"""', "#", "strict"))]
    assert any("_from_uri(raw_path)" in l for l in first[:6]), body


def test_no_adapter_builds_a_path_without_the_choke_point():
    """⚠ THE PROPERTY THE WHOLE ARRANGEMENT RESTS ON. A single adapter calling
    `Path(...)` or `os.path.abspath` on a payload value re-opens the bug for
    that one agent, and it would look exactly like working code."""
    for module in ADAPTERS:
        source = Path(module.__file__).read_text(encoding="utf-8")
        code = "\n".join(l for l in source.splitlines()
                         if not l.strip().startswith("#"))
        for forbidden in ("os.path.abspath", "os.path.realpath",
                          "os.path.normpath", "Path("):
            assert forbidden not in code, (
                f"{module.__name__} constructs a path itself ({forbidden}) "
                f"instead of going through adapters/_common — that path never "
                f"reaches _from_uri")


@pytest.mark.parametrize("module", ADAPTERS, ids=lambda m: m.AGENT)
def test_every_adapter_reaches_resolve_path_for_its_paths(module):
    """Weaker than the scan above and complementary to it: the scan proves no
    adapter builds a path ITSELF, this proves each one builds paths AT ALL
    through the shared helpers. An adapter that did neither would produce an
    action with no paths, which fails open in a way nothing else here notices.
    """
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "_common.resolve_paths(" in source or "resolve_paths(" in source
    assert "_common.resolve_cwd(" in source
    assert "_common.workspace_roots(" in source


# ═══════════════════════ 3 · the shape end to end, through a real adapter ══

def test_a_cursor_payload_of_uri_roots_carries_no_uri_artefact():
    action = cursor.parse({
        "hook_event_name": "beforeShellExecution", "command": "git status",
        "conversation_id": "c1",
        "workspace_roots": ["/C:/Users/alice/Projects",
                            "file:///C:/Users/alice/other"]})

    assert not any(r.startswith(("/C:/", "file://"))
                   for r in action.workspace_roots), action.workspace_roots
    assert not action.cwd.startswith(("/C:/", "file://")), action.cwd


@pytest.mark.skipif(
    __import__("platform").system() != "Windows",
    reason="THE BOUNDARY CONSEQUENCE OF A WINDOWS URI ROOT IS NOT CHECKED HERE. "
           "After _from_uri, `C:/Users/…` is ABSOLUTE on Windows and RELATIVE "
           "on POSIX, so on this host resolve_path joins it to the process cwd "
           "and the comparison measures the harness, not the fix. The shape "
           "checks above are platform-independent and do run; this one needs "
           "Windows. Not a passing test — an absent one.")
def test_the_roots_and_the_cwd_land_in_the_same_namespace():
    """⚠ THE ACTUAL FAILURE WAS A MISMATCH, NOT AN UGLY STRING. `is_inside_project`
    is a prefix test, so normalising one side and not the other is what makes a
    boundary silently miss. Both sides come from the same function, and this
    asserts the consequence rather than the mechanism."""
    from core import engine

    action = cursor.parse({
        "hook_event_name": "beforeShellExecution", "command": "git status",
        "conversation_id": "c1", "cwd": "/C:/Users/alice/Projects",
        "workspace_roots": ["/C:/Users/alice/Projects"]})

    assert engine.is_inside_project(action.cwd, action.workspace_roots), (
        f"cwd {action.cwd!r} is not inside roots {action.workspace_roots!r} — "
        f"the two sides were normalised differently")
