"""Recovering clipped commands, and refusing to invent structure from a prefix.

TWO CHANGES ANSWERING ONE PROBLEM: a record the differential refuses to JUDGE is
still run through `decide()` to advance state — because skipping it would judge
every later verdict against a session that never happened — so an unjudgeable
record can poison every record after it.

`83aea8bb:117` did exactly that. Clipped, no sidecar, heredoc terminator gone, so
`shell_scan` failed SAFE to all-code and `propagate` read its COMMIT MESSAGE —
prose describing `_copy_pairs` test cases like `install -m 755 .env debug/.env` —
as real copy operations. Three fixture paths tainted; six later verdicts denied
`secret_exact`. Measured: with 117 advancing state, 0 of those 6 matched the live
recording; with its structure suppressed, 4 of 6 did.

  PIECE 3  recover the text. `command_sha256` is inside the hashed body, so a
           candidate that hashes to it IS the judged command. 48 of 62 truncated
           records were recoverable from transcripts this way. **Digest match or
           nothing** — anything weaker puts unproven text into a fixture that
           later gets quoted as evidence.

  PIECE 4  for what cannot be recovered, stop deriving structure from it. The
           fail-safe bias is right for a VERDICT and wrong for STATE
           RECONSTRUCTION: live, "cannot parse, treat as code" costs a false
           positive and never a miss; in a replay it INVENTS structure.

⚠ 14 records carry no `command_sha256` at all and are permanently unrecoverable.
Piece 4 is what makes those harmless rather than poisonous, which is the whole
reason it exists — so its value is NOT visible in the fixture's verdict counts
(piece 3 already fixed 117). Measured there, it removes 7 manufactured untrusted
sources in `1f089cfa` and changes no verdict. The mechanism is pinned below
instead, where the fixture cannot hide it.
"""
import hashlib

import pytest

from core import engine
from core.audit_log import CLIP_MARKER, _MAX_COMMAND
from core.types import Action, ActionKind, SessionState
from tools.redact_logs import recover_by_digest

ROOT = "/repo"


class _World:
    def __getattr__(self, _name):
        return lambda *a, **k: None


def exec_action(command: str) -> Action:
    return Action(session_id="t", seq=2, kind=ActionKind.EXEC, paths=(),
                  command=command, url=None, tool_name="Bash", content=None,
                  cwd=ROOT, workspace_roots=(ROOT,), agent="claude-code")


# ================================================ piece 3: digest match or nothing
def test_an_exact_digest_match_is_recovered():
    command = "cd /repo && git commit -q -F - <<'MSG'\nfix: x\nMSG"
    digest = hashlib.sha256(command.encode()).hexdigest()
    assert recover_by_digest(digest, {digest: command}) == command


def test_a_record_with_no_digest_can_never_be_recovered():
    """THE 14. They predate `command_sha256`, so there is nothing to match
    against and no way to prove any candidate is the right text."""
    assert recover_by_digest(None, {"a" * 64: "anything"}) is None
    assert recover_by_digest("", {"": "anything"}) is None


def test_a_digest_with_no_candidate_is_not_recovered():
    assert recover_by_digest("b" * 64, {}) is None


def test_an_index_that_lies_about_its_own_key_is_refused():
    """THE RULE IS A PROPERTY OF THE FUNCTION, NOT OF THE INDEX.

    The lookup is keyed by digest, so re-hashing the hit looks redundant — until
    someone builds the index by timestamp, or by "the only long command in that
    session", and every caller silently starts trusting unproven text. This is
    that future change, failing here instead of in the fixture.
    """
    honest = "echo hello"
    wrong_key = hashlib.sha256(b"something else entirely").hexdigest()
    assert recover_by_digest(wrong_key, {wrong_key: honest}) is None


# ================================================ piece 4: the mask
def test_a_command_that_parses_is_unaffected_either_way():
    command = "cd /repo && git status"
    complete = engine.structure_mask(command, True)
    prefix = engine.structure_mask(command, False)
    assert bytes(complete) == bytes(prefix)
    assert any(complete), "a parseable command has code bytes"


def test_an_unparseable_but_COMPLETE_command_still_fails_safe_to_code():
    """The live behaviour, unchanged. A real command we cannot read is treated as
    entirely executable: that costs a false positive and never a miss."""
    command = "cat <<'EOF'\nno terminator here"
    mask = engine.structure_mask(command, True)
    assert all(mask), "a complete unparseable command must be all code"


def test_an_unparseable_INCOMPLETE_command_derives_nothing():
    """The inversion. The text is a known prefix, so the missing terminator is an
    artifact of the RECORD — treating the remainder as code invents structure."""
    command = "cat <<'EOF'\nno terminator here"
    mask = engine.structure_mask(command, False)
    assert not any(mask), "a known prefix must derive no structure"


# ================================================ the 117 shape, end to end
# 117's shape AS THE RECORD HOLDS IT: the clip fell inside the commit message,
# so the `MSG` terminator is gone. That is the entire mechanism — the heredoc
# cannot close, `shell_scan` bails, every byte reads as code, and the message
# becomes shell.
POISON = (
    "cd /repo && git add -A && git commit -q -F - <<'MSG'\n"
    "fix(engine): a copy's operands were mis-captured\n\n"
    "The shape that broke it:\n"
    "install -m 755 .env debug/.env"
)
# The same command as it actually RAN, terminator intact.
WHOLE = POISON + "\nMSG\ngit log --oneline -1"


def poisoned_taint(text_complete: bool) -> set:
    """Replay a session that holds a credential, then the 117-shaped command."""
    state = SessionState(session_id="t")
    state.holds_secret = True
    state.taint(f"{ROOT}/.env", "exact", 1)
    before = set(state.tainted_paths)
    engine.decide(exec_action(POISON), state, _World(), text_complete=text_complete)
    return set(state.tainted_paths) - before


def test_a_commit_message_read_as_shell_taints_a_path_that_was_never_written():
    """THE BUG, reproduced. The heredoc is unterminated because the command is a
    prefix, so every byte reads as code and the MESSAGE becomes a copy."""
    assert f"{ROOT}/debug/.env" in poisoned_taint(text_complete=True)


def test_the_same_message_taints_nothing_when_the_text_is_known_incomplete():
    assert poisoned_taint(text_complete=False) == set()


def test_the_command_that_actually_ran_taints_nothing_either_way():
    """THE CONTROL, and the point of the whole exercise. With the terminator
    present the message is data, so the live engine — which always saw this — was
    right and the replay was wrong. Recovering the text (piece 3) reaches this
    row; suppressing structure (piece 4) reaches the row above it."""
    for complete in (True, False):
        state = SessionState(session_id="t")
        state.holds_secret = True
        state.taint(f"{ROOT}/.env", "exact", 1)
        engine.decide(exec_action(WHOLE), state, _World(), text_complete=complete)
        assert f"{ROOT}/debug/.env" not in state.tainted_paths, complete


# ================================================ live is never affected
def test_decide_treats_text_as_complete_by_default():
    """LIVE IT IS NEVER FALSE. The hook is handed the whole command; clipping
    happens afterwards, when the log body is written. Every adapter and the hook
    call `decide()` without this argument, so the default is the live contract."""
    state = SessionState(session_id="t")
    state.holds_secret = True
    state.taint(f"{ROOT}/.env", "exact", 1)
    engine.decide(exec_action(POISON), state, _World())
    assert f"{ROOT}/debug/.env" in state.tainted_paths


def test_the_hook_does_not_pass_the_flag():
    """If the hook ever started supplying it, a live verdict could be computed
    against state derived from text the engine was told to distrust."""
    from pathlib import Path
    source = (Path(__file__).parent.parent / "hook_entry.py").read_text()
    assert "text_complete" not in source


@pytest.mark.parametrize("marker_only", [True, False])
def test_wholeness_still_comes_from_the_audit_log_ladder(marker_only):
    """Piece 4 does not invent a second definition of "incomplete". It reuses
    `stored_command_is_whole`, whose rungs are ordered by authority: a matching
    digest and the `command_clipped` fact cannot lie inside an intact chain,
    while the marker and a bare length can, and are consulted only when the first
    two are absent."""
    from core.audit_log import stored_command_is_whole
    record = {"kind": "EXEC", "command": "x" * _MAX_COMMAND + (CLIP_MARKER if marker_only else "")}
    assert stored_command_is_whole(record) is False
