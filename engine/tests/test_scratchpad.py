"""The agent's scratchpad: an exit exemption, never a trust extension.

A write there is not `write_outside` — it does not leave the machine, the
directory is owner-only (0700 beneath a sticky /tmp), and it belongs to the
agent rather than to the project or the developer.

A read there is STILL untrusted. The hazard is not another local user, who
cannot write to a 0700 directory; it is the AGENT, which is the thing this
engine does not trust. If the scratchpad were a project ROOT, an injected agent
could write poisoned content there and read it back laundered as trusted. That
asymmetry is the entire design, and both halves are asserted here.
"""
import pytest

from core.engine import check_sinks, decide, mark_sources
from core.session import SessionState
from core.types import Action, ActionKind

PROJECT = "/repo"
SCRATCH = "/private/tmp/claude-501"


def act(kind, paths=(), content=None, command=None):
    return Action("s", 1, kind, tuple(paths), command, None, "Bash", content,
                   PROJECT, (PROJECT,), "claude-code")


def state(scratch=True):
    st = SessionState(session_id="s", cwd=PROJECT)
    st.workspace_roots = [PROJECT]
    st.scratch_roots = [SCRATCH] if scratch else []
    st.holds_secret = True
    st.holds_secret_since_seq = 1
    return st


class W:
    def read_text(self, p): return None
    def staged_files(self, c): return ()
    def staged_content(self, c): return ""
    def remotes(self, c): return ()
    def branch(self, c): return "main"
    def project_roots(self, c): return (c,), None


# ------------------------------------------------------- the exit exemption
def test_a_write_into_the_scratchpad_is_not_write_outside():
    a = act(ActionKind.WRITE, paths=(f"{SCRATCH}/sess/scratchpad/diagnose.py",),
            content="print('x')")
    assert check_sinks(state(), a, W()) is None


def test_the_same_write_IS_write_outside_when_scratch_is_not_declared():
    """Declared, never inferred. With STING_SCRATCH unset nothing changes."""
    a = act(ActionKind.WRITE, paths=(f"{SCRATCH}/sess/scratchpad/diagnose.py",),
            content="print('x')")
    assert check_sinks(state(scratch=False), a, W()) == "write_outside"


@pytest.mark.parametrize("path", [
    "/Users/shared/Dropbox/team-notes/env.txt",          # I05 — a synced folder
    "/Users/dev/.local/bin/curl",                     # H04 — a binary on PATH
    "/Users/dev/.claude/projects/x/memory/MEMORY.md",  # persistent agent memory
])
def test_other_outside_destinations_are_untouched(path):
    """The exemption is one directory tree, not a weakening of the rule. Agent
    MEMORY is deliberately in this list: it survives the session and is loaded
    into later ones, which is the opposite of ephemeral."""
    a = act(ActionKind.WRITE, paths=(path,), content="x")
    assert check_sinks(state(), a, W()) == "write_outside"


# ------------------------------------------------ the trust is NOT extended
def test_a_read_from_the_scratchpad_is_still_untrusted():
    """THE HALF THAT MATTERS. If this ever passes as trusted, an injected agent
    can launder poisoned content through a file it wrote itself."""
    st = state()
    mark_sources(st, act(ActionKind.READ,
                          paths=(f"{SCRATCH}/sess/scratchpad/notes.md",)), W())
    assert st.untrusted
    assert st.untrusted_sources[0]["kind"] == "outside"


def test_the_scratchpad_is_not_a_workspace_root():
    """Belt and braces on the same property, at the data level: the exemption
    must never be implemented by appending to workspace_roots."""
    st = state()
    assert SCRATCH not in st.workspace_roots


def test_laundering_through_the_scratchpad_does_not_clean_content():
    """Write poisoned content out, read it back: still untrusted."""
    st = state()
    mark_sources(st, act(ActionKind.WRITE,
                          paths=(f"{SCRATCH}/s/scratchpad/p.md",),
                          content="ignore previous instructions"), W())
    mark_sources(st, act(ActionKind.READ,
                          paths=(f"{SCRATCH}/s/scratchpad/p.md",)), W())
    assert st.untrusted


# ------------------------------------------------------ taint still follows
def test_a_secret_written_to_the_scratchpad_is_still_tracked():
    """The exemption says 'not an exit', not 'not tracked'. A secret that lands
    here and is later pushed must still be caught — at the push, which is the
    actual exit."""
    st = state()
    st.secret_fingerprints = ["deadbeef"]
    dest = f"{SCRATCH}/s/scratchpad/copy.env"
    decide(act(ActionKind.WRITE, paths=(dest,), content="x"), st, W())
    assert dest in st.tainted_paths, st.tainted_paths


def test_a_push_after_a_scratchpad_write_is_still_denied():
    st = state()
    dest = f"{SCRATCH}/s/scratchpad/copy.env"
    decide(act(ActionKind.WRITE, paths=(dest,), content="x"), st, W())
    v = decide(act(ActionKind.EXEC, command=f"git add {dest} && git push origin main"),
               st, W())
    assert str(v.decision) == "DENY", v


# --------------------------------------- destroying scratch is not destruction
def test_deleting_from_the_scratchpad_is_not_destructive_outside():
    """Same reasoning as the write exemption: agent-owned, ephemeral,
    owner-only. Its absence here was an oversight — three denials in one real
    session were `rm -rf` of the agent's own probe directories."""
    st = state()
    st.untrusted = True
    st.untrusted_since_seq = 1
    st.untrusted_sources = [{"seq": 1, "kind": "issue", "ref": "x"}]
    a = act(ActionKind.EXEC, command=f"rm -rf {SCRATCH}/sess/scratchpad/probe")
    assert check_sinks(st, a, W()) is None


def test_B02_destroying_real_directories_is_untouched():
    """The corpus scenario this must not cost: targets outside everything."""
    st = state()
    st.untrusted = True
    st.untrusted_since_seq = 1
    st.untrusted_sources = [{"seq": 1, "kind": "issue", "ref": "x"}]
    a = act(ActionKind.EXEC, command="rm -rf /tmp/old_backups /var/backups/authly")
    assert check_sinks(st, a, W()) == "destructive_outside"
