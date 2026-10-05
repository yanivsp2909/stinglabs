"""The remaining spellings of a catastrophic act — resolution, not new verbs.

⚠ WHAT THIS CLOSES, from the delete rule's own "what remains" list:

    rm -rf /*                     ASK -> DENY   the glob is the root's contents
    rm -rf $HOME                  ASK -> DENY   `$HOME` is `~` spelled another way
    find / -delete              ALLOW -> DENY   the root is still named
    dd if=/dev/zero of=/dev/sda ALLOW -> DENY   the device is still named

⚠ AND ONE MEMBER WAS DROPPED ON ITS RULE-5 CHECK. `chmod -R 000 /` stays ALLOW,
because `chmod -R a-r /` is the SAME command with one argument respelled and
evades entirely — a signal defeated by rewriting the command's own argument
buys a false sense of coverage. See test_chmod_was_dropped_and_why.

BLAST RADIUS, MEASURED BEFORE IT LANDED: 0 of 25 corpus normals, 0 of 63 corpus
attacks, 0 of 1783 live commands.

⚠ THE TWO ZEROS ARE DIFFERENT KINDS. The corpus contains 0 globs, 0 `find`,
0 `chmod -R`, 0 `dd`, 0 `mkfs` and 0 `/dev/` paths — it is structurally
incapable of seeing any of this, so its zero is pure blindness. The live log
contains 48 globs, 69 `find` (4 with -delete/-exec), 3 `chmod -R`, 12 `dd`,
3 `mkfs` and 262 `/dev/` paths, and NONE matched — that zero is a real
discrimination over 400+ near-misses.
"""
from __future__ import annotations

import pytest

from core import engine
from core.probes import NullWorld
from core.shell_scan import UNPARSED, bail_reason, code_mask
from core.types import Action, ActionKind, SessionState

PROJECT = "/work/repo"


def ex(command: str, cwd: str = PROJECT) -> Action:
    return Action("s", 1, ActionKind.EXEC, (), command, None, None, None,
                   cwd, (PROJECT,), "claude-code")


def verdict(command: str, *, untrusted=False, scratch=(), cwd=PROJECT):
    state = SessionState(session_id="s", seq=1)
    state.workspace_roots = [PROJECT]
    state.scratch_roots = list(scratch)
    if untrusted:
        state.mark_untrusted(seq=0, kind="issue", ref="ISSUE.md")
    return engine.decide(ex(command, cwd), state, NullWorld())


# ─────────────────────────────────────────────── PART 1 · the root spellings

@pytest.mark.parametrize("command", [
    "rm -rf /*", "rm -rf /usr/*", "rm -rf /etc/*", "rm -rf /Users/*",
    "cd / && rm -rf *",
])
def test_a_glob_directly_under_a_root_is_that_root(command):
    """⚠ `rm -rf /*` EXPANDS TO EVERY ENTRY OF `/`. The directory inode survives
    and nothing else does, which is materially the same event as `rm -rf /`. The
    glob is never expanded — a `*` that is the ENTIRE last component means
    "everything in the parent" whatever the entries happen to be."""
    result = verdict(command)
    assert result.decision is engine.Decision.DENY, (command, result)
    assert result.rule_id == "catastrophic_delete"


@pytest.mark.parametrize("command", [
    "rm -rf /tmp/*",          # /tmp is not a catastrophic root
    "rm -rf ~/projects/*",
    "rm -rf ./build/*",
    "rm -rf /usr/l*",         # a PREFIX glob is a selection, not everything
    "rm -rf /usr/local/*",
])
def test_a_glob_that_is_not_a_root_s_whole_contents_is_untouched(command):
    assert verdict(command).rule_id != "catastrophic_delete", command
    assert verdict(command).decision is engine.Decision.ASK, command


@pytest.mark.parametrize("command", ["rm -rf $HOME", "rm -rf ${HOME}",
                                      "cd $HOME && rm -rf ."])
def test_home_variable_resolves_like_tilde(command):
    """⚠ NO ENVIRONMENT IS READ. `_abs` already sends `~` to the `/HOME`
    sentinel; `$HOME` is a fixed, well-known name with one meaning, so treating
    them alike is a lexical equivalence rather than a lookup."""
    assert verdict(command).rule_id == "catastrophic_delete", command


def test_an_in_command_assignment_beats_the_home_convention():
    """⚠ THE OBJECTION, AND IT RESOLVES THE HARMLESS WAY. An attacker who sets
    `HOME=/tmp` and then deletes `$HOME` gets a verdict about /tmp, not about a
    home directory — because an assignment observed in THIS command wins. And
    setting HOME cannot make the rule read a SMALLER target, so it is not a
    bypass in either direction."""
    assert verdict("HOME=/tmp; rm -rf $HOME").rule_id != "catastrophic_delete"
    assert verdict("HOME=/; rm -rf $HOME").rule_id == "catastrophic_delete"


# ──────────────────────────────── PART 2 · destruction that is not deletion

@pytest.mark.parametrize("command", [
    "dd if=/dev/zero of=/dev/sda",
    "dd if=/dev/urandom of=/dev/nvme0n1 bs=1M",
    "cat /dev/zero > /dev/disk0",
    "mkfs.ext4 /dev/sda1",
    "newfs_hfs /dev/disk2",
    "tee /dev/sda < /dev/zero",
    "cp /dev/zero /dev/sda",
    "shred /dev/sda",
])
def test_writing_a_raw_block_device_denies(command):
    """⚠ KEYED ON THE DEVICE, NOT ON `dd`. "To zero a disk you must invoke dd or
    mkfs" is false — a redirect, tee, cp and shred all do it. What none of them
    avoids is NAMING the device."""
    result = verdict(command)
    assert result.decision is engine.Decision.DENY, (command, result)
    assert result.rule_id == "catastrophic_overwrite"


@pytest.mark.parametrize("command", [
    "dd if=/dev/sda of=backup.img",        # the device is the SOURCE: a backup
    "cp /dev/sda /tmp/backup.img",
    "ls -la /dev/disk0",
    "diskutil info /dev/disk0",
    "echo x > /dev/null",
    "cat /dev/urandom | head -c 16",
    "dd if=/dev/zero of=./out.img bs=1M count=10",
    "tee /tmp/log.txt",
])
def test_reading_a_device_or_writing_a_file_is_untouched(command):
    assert verdict(command).rule_id != "catastrophic_overwrite", command


@pytest.mark.parametrize("command", [
    "find / -delete",
    "find / -name '*.log' -delete",
    "find / -exec rm -rf {} +",
    "find ~ -delete",
    "find $HOME -delete",
])
def test_find_sweeping_a_catastrophic_root_denies(command):
    result = verdict(command)
    assert result.decision is engine.Decision.DENY, (command, result)
    assert result.rule_id == "catastrophic_delete"


@pytest.mark.parametrize("command", [
    "find /tmp -delete",
    "find . -name '*.pyc' -delete",
    "find ./build -exec rm -rf {} +",
    "find / -name '*.log'",              # no destructive action at all
    "find / -type f -print",
])
def test_find_without_a_root_or_without_destruction_is_untouched(command):
    assert verdict(command).rule_id != "catastrophic_delete", command


def test_chmod_was_dropped_and_why():
    """⚠ THE MEMBER THAT FAILED ITS RULE-5 CHECK, PINNED SO IT IS NOT ADDED BACK
    WITHOUT ANSWERING THIS. `chmod -R 000 /` would have been catchable — but
    `chmod -R a-r /` is the same command with one argument respelled, and
    `chmod -R u-r,g-r,o-r /` likewise. A signal defeated by rewriting the
    command's own argument is not a signal; it buys a false sense of coverage
    and costs whatever false positives it creates.

    If someone adds it, they must first say what stops `a-r`."""
    for command in ("chmod -R 000 /", "chmod -R a-r /", "chmod -R 700 /"):
        assert verdict(command).rule_id != "catastrophic_overwrite", command
        assert verdict(command).rule_id != "catastrophic_delete", command


# ───────────────────────────────────────────────────────── TASK 4 · the traps

@pytest.mark.parametrize("command", [
    "rm -rf /tmp/foo", "rm -rf ~/projects/x", "chmod -R 755 ./build",
    "rm -rf /usr/local/lib/node_modules/x", "cd /tmp && rm -rf x",
])
def test_a_path_under_a_root_is_untouched(command):
    for rule in ("catastrophic_delete", "catastrophic_overwrite"):
        assert verdict(command).rule_id != rule, command


@pytest.mark.parametrize("command", [
    "rm -rf $UNSET_VAR", "rm -rf $(cat targets.txt)", "find $UNKNOWN -delete",
    "dd if=/dev/zero of=$TARGET",
])
def test_unresolvable_stays_where_it_is_today(command):
    """Never upgraded to DENY. A command this cannot resolve is not evidence of
    catastrophe."""
    result = verdict(command)
    assert result.rule_id not in ("catastrophic_delete", "catastrophic_overwrite")
    assert result.decision is not engine.Decision.DENY, (command, result)


@pytest.mark.parametrize("scratch", [("/",), ("/dev/sda",), ("/Users",)])
def test_the_scratch_exemption_does_not_reach_a_catastrophic_target(scratch):
    """An exemption is a declaration about disposable work, not a licence."""
    for command in ("rm -rf /*", "find / -delete", "dd if=/dev/zero of=/dev/sda"):
        assert verdict(command, scratch=scratch).decision is engine.Decision.DENY, (
            command, scratch)


def test_data_position_does_not_count():
    """A command QUOTING `dd if=/dev/zero` inside a heredoc is not running it."""
    documented = """python3 - <<'PY'
cases = ["dd if=/dev/zero of=/dev/sda", "find / -delete", "rm -rf /*"]
for c in cases:
    print(c)
PY"""
    assert engine.writes_a_raw_block_device(ex(documented)) is None
    assert engine.find_destroys_a_catastrophic_root(ex(documented)) is None
    assert verdict(documented).decision is not engine.Decision.DENY


def test_an_unparseable_command_is_not_escalated():
    """⚠ GATE ON UNPARSED, NEVER ON THE BOOLEAN — the length bypass is two
    passes old, and this rule DENIES, so it must fail toward today's answer."""
    broken = 'echo "dd if=/dev/zero of=/dev/sda" ; echo \'unclosed'
    assert bail_reason(code_mask(broken)) == UNPARSED
    assert engine.writes_a_raw_block_device(ex(broken)) is None


def test_a_long_command_keeps_its_catch():
    """TOO_LONG is not UNPARSED. Padding past 64 KiB must not switch the rule
    off — that was the regression the previous pass nearly shipped."""
    from core.shell_scan import TOO_LONG
    padded = "z" * 70_000 + " ; dd if=/dev/zero of=/dev/sda"
    assert bail_reason(code_mask(padded)) == TOO_LONG
    assert engine.writes_a_raw_block_device(ex(padded)) == "/dev/sda"


# ─────────────────────────────────────────────────────────── TASK 5 · reasons

def test_every_reason_reads_without_a_rule_id():
    cases = {
        "rm -rf /*": "this deletes /* — the directory itself, not anything "
                      "inside it, and no task ever does that",
        "find / -delete": "this deletes everything under the filesystem root — "
                           "the same event as deleting the directory itself, "
                           "and no task ever does that",
        "dd if=/dev/zero of=/dev/sda": "this overwrites /dev/sda — the whole "
                                        "disk, not a file on it — every "
                                        "filesystem it holds goes with it",
    }
    for command, expected in cases.items():
        assert verdict(command).reason == expected, command


def test_no_internal_sentinel_reaches_a_developer():
    for command in ("rm -rf ~", "rm -rf $HOME", "find ~ -delete"):
        assert "/HOME" not in verdict(command).reason, command
        assert "your home directory" in verdict(command).reason, command


def test_the_phrasing_comes_from_rule_names():
    from core import rule_names
    assert rule_names.describe("catastrophic_overwrite")["title"] == \
        "Overwriting a whole disk"
    assert rule_names.sink_meaning("raw_block_device") in \
        verdict("dd if=/dev/zero of=/dev/sda").reason
