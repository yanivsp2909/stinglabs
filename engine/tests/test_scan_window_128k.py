"""The secret-scan window is 128 KB, and both edges are pinned.

`_MAX_SCAN` / `MAX_SCAN` bound how far into one action's text the two secret
scanners look. It was widened 32 KB -> 128 KB after a real measurement pass:
median commit-path latency is flat regardless of the window (the typical diff
is ~15 KB, well inside it), the cost is tail-only, and 128 KB keeps the p99
under the 12 ms A6a budget while closing the accidental-miss rate from 22.6% to
4.9% on 389 real commits. This window is the ONLY backstop for one population —
a secret in an ordinary file with no session-tracked origin (never read, never
written-while-tainted), which `tainted_paths` cannot catch. Everything with a
tracked origin is caught regardless of size.

The number was previously untested at its own edge. These tests pin it: a
secret just under 128 KB is now caught (it was silently missed at 32 KB), one
just past 128 KB is still missed (a documented residual, not silent), and the
must-not-flag negatives stay held now that more content is in the window.
"""
import sys
import dataclasses
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))

from core import engine, known_formats                              # noqa: E402
from core.known_formats import find_known_secret                    # noqa: E402
from core.types import Action, ActionKind, SessionState             # noqa: E402
from known_formats_corpus import NEGATIVES, make_key                # noqa: E402

KB = 1024


# ───────────────────────────────────────────── the window value, pinned equal
def test_the_window_is_128kb_in_both_scanners():
    assert engine._MAX_SCAN == known_formats.MAX_SCAN == 128 * KB


# ─────────────────────────────────────── failing-first: the corpus2.json shape
class _StagedWorld:
    """A fresh session (no read/write history) that commits a staged diff whose
    ORDINARY-file content carries a secret — the corpus2.json shape. The path is
    not credential-shaped and not tainted, so only the content scan can see it."""
    def __init__(self, staged_content):
        self._sc = staged_content
    def read_text(self, p): return None
    def sync_roots(self): return None
    def case_insensitive(self, r): return None
    def project_roots(self, c): return ((c,) if c else ()), None
    def staged_files(self, c): return ("/repo/notes.md",)
    def staged_content(self, c): return self._sc


def _commit_verdict(staged_content):
    st = SessionState(session_id="s", workspace_roots=["/repo"], cwd="/repo")
    st.seq = 1
    action = Action(session_id="s", seq=1, kind=ActionKind.EXEC, paths=(),
                    command='git commit -m "update notes"', url=None,
                    tool_name="Bash", content=None, cwd="/repo",
                    workspace_roots=("/repo",), agent="cc")
    return engine.decide(action, st, _StagedWorld(staged_content))


def test_a_secret_past_32kb_within_128kb_is_caught_at_commit():
    """corpus2.json shape: a real known-format key sits at ~64 KB into an
    ordinary staged file with no session history. At 32 KB this ALLOWed (the
    documented miss); at 128 KB it must DENY. Fresh session => taint cannot help,
    so this is the content scan alone."""
    key = make_key("github-token")
    content = "# notes\n" + ("filler line\n" * 4200)  # ~50 KB of prose
    assert 32 * KB < len(content) < 128 * KB, len(content)
    content += "\ndeploy_token = " + key + "\n"
    v = _commit_verdict(content)
    assert v.decision.value == "DENY", (v.decision.value, v.rule_id)
    assert v.rule_id == "secret_exact:git_commit", v.rule_id


# ─────────────────────────────────────────────── the two edges of the window
def test_a_secret_just_under_128kb_is_now_caught():
    """~100 KB in — beyond the old 32 KB window, inside the new one."""
    key = make_key("github-token")
    padding = "a" * (100 * KB)
    assert find_known_secret(padding + " " + key) is not None


def test_a_secret_just_past_128kb_is_still_missed_documented_residual():
    """~130 KB in — beyond even the widened window. Still a miss, by design:
    widening moves the edge, it does not remove it (docs/PROGRESS state this)."""
    key = make_key("github-token")
    padding = "a" * (130 * KB)
    assert find_known_secret(padding + " " + key) is None


def test_the_exact_edge_is_128kb():
    """A key ending exactly at the 128 KB boundary is seen; one pushed a token
    past it is not — the cut is where the constant says it is."""
    key = make_key("github-token")
    # key placed so its LAST byte is the 128 KB-th byte -> fully inside
    prefix = "a" * (128 * KB - len(key))
    assert find_known_secret(prefix + key) is not None
    # same key shifted one byte past the cut -> its tail is truncated away
    assert find_known_secret(("a" * (128 * KB)) + key) is None


# ─────────────────────────────────── negatives stay held at the wider window
@pytest.mark.parametrize("name,text", NEGATIVES, ids=[n for n, _ in NEGATIVES])
def test_every_negative_is_still_held(name, text):
    """Widening only extends what is scanned; it must not turn a look-alike into
    a hit. Each negative is asserted None both bare and placed at ~64 KB — a
    position the old window never reached and the new one does."""
    assert find_known_secret(text) is None, name
    at_new_depth = ("benign filler. " * (5 * KB)) + text
    assert 32 * KB < len(at_new_depth) < 128 * KB
    assert find_known_secret(at_new_depth) is None, f"{name} at 64 KB offset"
