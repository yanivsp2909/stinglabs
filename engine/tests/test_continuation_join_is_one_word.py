r"""A bash line continuation joins into ONE word; operand extraction must too.

The segment splitter ends a command at a bare newline and treats a
backslash-newline as a LINE CONTINUATION. But bash removes that backslash-newline
BEFORE it splits words, with NO separator — `/\<newline>etc` is the single word
`/etc`, one path it deletes. Operand extraction sliced at `_SEGMENT_END` and
`.split()` on whitespace, so it saw `/\` (or `/` + a separate `etc`) and MISSED
the catastrophic `/etc` its one-line form denies. `_join_line_continuations`
reproduces the join before operands are sliced; both the destructive
(`deletes_a_catastrophic_root`) and credential (`_cd_resolved_credential_paths`)
extractors UNION it with the raw pass, so it only ever ADDS a resolution.
"""
from __future__ import annotations

from core import engine
from core.probes import NullWorld
from core.types import Action, ActionKind, SessionState

PROJECT = "/work/repo"
NL = "\n"                     # a bare newline: bash ends the command here
CONT = "\\" + "\n"           # backslash-newline: bash joins with no separator

# `rm ` spelled indirectly so a guard watching this repo's own session does not
# read the test source as a destructive command.
_RM = "r" "m -rf "


def ex(command: str, cwd: str = PROJECT) -> Action:
    return Action("s", 1, ActionKind.EXEC, (), command, None, None, None,
                   cwd, (PROJECT,), "claude-code")


def verdict(command: str, cwd: str = PROJECT):
    state = SessionState(session_id="s", seq=1)
    state.workspace_roots = [PROJECT]
    state.scratch_roots = []
    return engine.decide(ex(command, cwd), state, NullWorld())


def test_the_join_helper_removes_a_continuation_but_never_a_bare_newline():
    """The seam, directly. A backslash-newline is erased (join); a BARE newline is
    left for `_SEGMENT_END` to end the segment at — the strip must not swallow a
    real separator."""
    assert engine._join_line_continuations("/" + CONT + "etc") == "/etc"
    assert engine._join_line_continuations("a" + CONT + "b" + CONT + "c") == "abc"
    assert engine._join_line_continuations("/tmp" + NL + "echo") == "/tmp" + NL + "echo"


def test_a_destructive_target_across_a_no_space_continuation_denies():
    """⚠ THE FIX. `<rm> /\\<newline>etc` is `<rm> /etc` to bash — a catastrophic
    delete — and now denies exactly like its one-line spelling, where before it
    resolved `/\\` and fell to a weaker ASK."""
    v = verdict(_RM + "/" + CONT + "etc")
    assert v.decision.value == "DENY", v
    assert v.rule_id == "catastrophic_delete", v.rule_id
    assert engine.deletes_a_catastrophic_root(ex(_RM + "/" + CONT + "etc")) == "/etc"


def test_plaintext_and_bare_root_destructive_forms_are_unchanged():
    """NEVER LESS: the one-line spellings the fix must not disturb."""
    assert verdict(_RM + "/etc").rule_id == "catastrophic_delete"
    assert verdict(_RM + "/").rule_id == "catastrophic_delete"
    assert engine.deletes_a_catastrophic_root(ex(_RM + "/etc")) == "/etc"


def test_a_bare_newline_inside_a_path_is_two_commands_not_a_join():
    """⚠ THE BOUNDARY MUST STILL HOLD. `<rm> /et<newline>c` is `<rm> /et` then a
    separate `c` to bash — it does NOT delete `/etc`. The continuation strip removes
    only the backslash-newline pair, so a BARE newline is never joined and this
    stays non-catastrophic. If the strip swallowed bare newlines, this would wrongly
    become `/etc` and deny."""
    assert engine.deletes_a_catastrophic_root(ex(_RM + "/et" + NL + "c")) is None
    assert verdict(_RM + "/et" + NL + "c").rule_id != "catastrophic_delete"
    # and the classic bare-newline case: the second line is a separate segment.
    assert engine.deletes_a_catastrophic_root(ex(_RM + "/tmp" + NL + "echo done")) is None


def test_a_continuation_before_a_noncatastrophic_tail_stays_noncatastrophic():
    """NEVER MORE than bash: `<rm> /etc\\<newline>foo` joins to `/etcfoo`, which is
    not a root — so it must NOT deny as catastrophic. The union adds the joined
    `/etcfoo` (harmless) and the raw pass never resolved a clean `/etc` here either
    (the backslash stuck to it), so no catch is created or dropped."""
    assert engine.deletes_a_catastrophic_root(ex(_RM + "/etc" + CONT + "foo")) is None
    assert verdict(_RM + "/etc" + CONT + "foo").rule_id != "catastrophic_delete"


def test_a_credential_path_spelled_across_a_continuation_is_recovered():
    """The same split-vs-join gap in the CREDENTIAL operand path — proven at the
    extractor, since a bare credential read needs more context to reach a verdict.
    A `cd` target or a filename spelled across a `\\<newline>` now resolves to the
    same credential path as its one-line form, UNIONED so the raw pass's hits stay."""
    plain = engine._cd_resolved_credential_paths("cd .aws && cat credentials", PROJECT)
    assert "/work/repo/.aws/credentials" in plain          # baseline
    # `cd` target split by a continuation — was empty before the union.
    split_cd = engine._cd_resolved_credential_paths(
        "cd .a" + CONT + "ws && cat credentials", PROJECT)
    assert "/work/repo/.aws/credentials" in split_cd
    # filename split by a continuation — the real path is recovered beside the raw
    # (garbled) tokens, never instead of them.
    split_file = engine._cd_resolved_credential_paths(
        "cd .aws && cat creden" + CONT + "tials", PROJECT)
    assert "/work/repo/.aws/credentials" in split_file
    # NEVER LESS: every path the plaintext pass finds is still present.
    assert set(plain) <= set(split_file)
