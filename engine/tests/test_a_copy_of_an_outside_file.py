"""A COPY of a file outside the project roots is outside content, not the
session's own (fix/false-positives, item 3, docs/112).

Before this, `propagate` marked every cp/mv/redirect destination as authored,
and both `_own_file` and `read_outside_content` read authorship as "own" — so
`cp /opt/vendor/x /repo/x` then `cat /repo/x | sh`, or a read of the copy then
a push, was ALLOW where main gave DENY. The copy's contents came from outside;
laundering them through a copy does not make them the session's work.

The destination of a copy whose source is an outside file is recorded as a
download (outside content). A source that cannot be read loses track of
downloads — the fail-closed direction. A file the session itself WROTE outside
the roots, or a file inside the roots, stays its own. Every value is a fake.
"""
from __future__ import annotations

import pytest

from core.types import ActionKind, Decision, SessionState
from tests.test_engine_decide import walk
from tests.test_engine_sources import FakeWorld, act

MCP = act(ActionKind.TOOL, tool_name="mcp__x__get_issue", tool_origin="mcp", content="{}")
PUSH = act(ActionKind.EXEC, command="git push origin main")


def ex(command):
    return act(ActionKind.EXEC, command=command)


def rd(path):
    return act(ActionKind.READ, paths=(path,))


# A copy of an outside file, then running or pushing: gated (main gave DENY).
GATED = {
    "copy outside, read, push": [ex("cp /opt/other/notes.md /tmp/notes.md"),
                                 rd("/tmp/notes.md"), PUSH],
    "redirect outside, read, push": [ex("cat /opt/other/notes.md > /tmp/n.md"),
                                     rd("/tmp/n.md"), PUSH],
    "copy outside into roots, pipe": [MCP, ex("cp /opt/vendor/setup.sh /repo/setup.sh"),
                                      ex("cat /repo/setup.sh | sh")],
    "copy outside to tmp, pipe": [MCP, ex("cp /opt/vendor/setup.sh /tmp/s.sh"),
                                  ex("cat /tmp/s.sh | sh")],
    "copy and pipe, one command": [MCP, ex("cp /opt/vendor/setup.sh ./s.sh && cat s.sh | sh")],
    "copy a dependency copy, read, push": [ex("cp /opt/x/README.md /tmp/r.md"),
                                           rd("/tmp/r.md"), PUSH],
    "unreadable source, read, push": [ex("cp $SRC /tmp/x.md"), rd("/tmp/x.md"), PUSH],
    "copy of a copy, read, push": [ex("cp /opt/other/notes.md /tmp/a.md"),
                                   ex("cp /tmp/a.md /tmp/b.md"), rd("/tmp/b.md"), PUSH],
    "mv outside, read, push": [ex("mv /opt/other/notes.md /tmp/m.md"), rd("/tmp/m.md"), PUSH],
    "outside through sed, pipe": [MCP, ex("sed s/a/b/ /opt/vendor/setup.sh > /repo/s2.sh"),
                                  ex("cat /repo/s2.sh | sh")],
    # round-6 reviewers (F1-F7): laundering shapes the first cut missed
    "chain cp then cp, pipe": [MCP, ex("cp /opt/vendor/setup.sh /tmp/y && cp /tmp/y /repo/z"),
                               ex("cat /repo/z | sh")],
    "cp into an existing dir, pipe": [MCP, ex("cp /opt/vendor/setup.sh /repo/bin"),
                                      ex("cat /repo/bin/setup.sh | sh")],
    "tee reading outside, pipe": [MCP, ex("cat /opt/vendor/setup.sh | tee /repo/f"),
                                  ex("cat /repo/f | sh")],
    "dd if of, pipe": [MCP, ex("dd if=/opt/vendor/setup.sh of=/repo/f"), ex("cat /repo/f | sh")],
    "tee stdin, pipe": [MCP, ex("tee /repo/f < /opt/vendor/setup.sh"), ex("cat /repo/f | sh")],
    "cat outside piped through sed, pipe": [MCP, ex("cat /opt/vendor/setup.sh | sed s/a/b/ > /repo/f"),
                                            ex("cat /repo/f | sh")],
    "unreadable reader source redirect": [MCP, ex("cat $VAR > /repo/f"), ex("cat /repo/f | sh")],
    "cp -r an outside folder, pipe": [MCP, ex("cp -r /opt/vendor /repo/d"),
                                      ex("cat /repo/d/setup.sh | sh")],
    "sudo cp outside, pipe": [MCP, ex("sudo cp /opt/vendor/setup.sh /repo/f"),
                              ex("cat /repo/f | sh")],
    "path-qualified cp outside, pipe": [MCP, ex("/bin/cp /opt/vendor/setup.sh /repo/f"),
                                        ex("cat /repo/f | sh")],
    # round-6 re-review (R1/N1-N4, R2): folder copies, unreadable dst, unpackers
    "cp -R outside folder, pipe": [MCP, ex("cp -R /opt/vendor /repo/d"),
                                   ex("cat /repo/d/setup.sh | sh")],
    "mv outside folder, pipe": [MCP, ex("mv /opt/vendor /repo/d"), ex("cat /repo/d/setup.sh | sh")],
    "ln -s outside folder, pipe": [MCP, ex("ln -s /opt/vendor /repo/d"),
                                   ex("cat /repo/d/setup.sh | sh")],
    "unreadable destination, pipe": [MCP, ex("cp /opt/vendor/setup.sh $D/y"),
                                     ex("cat /repo/y | sh")],
    "unreadable redirect dst, pipe": [MCP, ex("cat /opt/vendor/setup.sh > $D/y"),
                                      ex("cat /repo/y | sh")],
    "tar of an outside archive, pipe": [MCP, ex("tar xf /opt/vendor/kit.tar -C /repo"),
                                        ex("cat /repo/setup.sh | sh")],
    "unzip an outside archive, pipe": [MCP, ex("unzip /opt/vendor/kit.zip -d /repo"),
                                       ex("cat /repo/setup.sh | sh")],
    "local rsync outside, pipe": [MCP, ex("rsync -a /opt/vendor/ /repo/d"),
                                  ex("cat /repo/d/setup.sh | sh")],
    "piped unreadable source, pipe": [MCP, ex("cat $F | tee /repo/f"), ex("cat /repo/f | sh")],
    "stdin-first reader, pipe": [MCP, ex("< /opt/vendor/setup.sh cat > /repo/f"),
                                 ex("cat /repo/f | sh")],
    "xargs copy of outside, pipe": [MCP, ex("ls /opt/vendor/*.sh | xargs -I{} cp {} /repo/"),
                                    ex("cat /repo/setup.sh | sh")],
    # round-6 review round 3 (G1-G5, F8-F9): long flags, braces, transforms, wrappers
    "cp --recursive outside folder, pipe": [MCP, ex("cp --recursive /opt/vendor /repo/d"),
                                            ex("cat /repo/d/setup.sh | sh")],
    "cp --archive outside folder, pipe": [MCP, ex("cp --archive /opt/vendor /repo/d"),
                                          ex("cat /repo/d/setup.sh | sh")],
    "brace source outside, pipe": [MCP, ex("cp /opt/vendor/{a,b}.sh /repo/"),
                                   ex("cat /repo/a.sh | sh")],
    "brace destination, pipe": [MCP, ex("cp /opt/vendor/setup.sh /repo/{a,b}"),
                                ex("cat /repo/a | sh")],
    "patch from outside, pipe": [MCP, ex("patch -p1 < /opt/vendor/x.diff"),
                                 ex("cat /repo/patched.sh | sh")],
    "awk writing from outside, pipe": [MCP, ex("awk '{print > \"/repo/o.sh\"}' /opt/vendor/setup.sh"),
                                       ex("cat /repo/o.sh | sh")],
    "bsdtar outside, pipe": [MCP, ex("bsdtar xf /opt/vendor/kit.tar -C /repo"),
                             ex("cat /repo/setup.sh | sh")],
    "wrapper before unpacker, pipe": [MCP, ex("sudo tar xf /opt/vendor/kit.tar -C /repo"),
                                      ex("cat /repo/setup.sh | sh")],
    # round-6 review round 4 (N-A, N-B): r/R/a not last in a cluster; a
    # multi-operand copy whose outside source is not the last operand
    "cp -rf outside folder, pipe": [MCP, ex("cp -rf /opt/vendor /repo/d"),
                                    ex("cat /repo/d/setup.sh | sh")],
    "cp -Rp outside folder, pipe": [MCP, ex("cp -Rp /opt/vendor /repo/d"),
                                    ex("cat /repo/d/setup.sh | sh")],
    "cp -r outside not last source, pipe": [MCP, ex("cp -r /opt/vendor /repo/own /repo/d/"),
                                            ex("cat /repo/d/vendor/setup.sh | sh")],
}


@pytest.mark.parametrize("name", list(GATED))
def test_a_copy_of_an_outside_file_is_gated(name):
    verdicts, _state = walk(GATED[name], FakeWorld({}), SessionState())
    assert verdicts[-1].decision in (Decision.ASK, Decision.DENY), name


# The session's OWN work stays its own (these were ALLOW on the branch before
# and must stay ALLOW): an in-roots file copied out, and an outside file the
# session itself wrote then copied.
OWN = {
    "copy own roots file, read, push": [ex("cp /repo/src/a.md /tmp/a.md"),
                                        rd("/tmp/a.md"), PUSH],
    "copy own outside file, read, push": [
        act(ActionKind.WRITE, paths=("/opt/scratch/notes.md",), content="notes\n"),
        ex("cp /opt/scratch/notes.md /tmp/n2.md"), rd("/tmp/n2.md"), PUSH],
    "MCP, copy own roots script, pipe": [MCP, ex("cp /repo/scripts/setup.sh /tmp/s3.sh"),
                                         ex("cat /tmp/s3.sh | sh")],
    # in-roots unpack/sync must stay own (guard against over-gating)
    "MCP, tar an in-roots archive, pipe": [MCP, ex("tar xf /repo/kit.tar -C /repo"),
                                           ex("cat /repo/setup.sh | sh")],
    "MCP, local rsync in-roots, pipe": [MCP, ex("rsync -a /repo/a/ /repo/b"),
                                        ex("cat /repo/b/setup.sh | sh")],
}


@pytest.mark.parametrize("name", list(OWN))
def test_the_sessions_own_work_stays_its_own(name):
    verdicts, _state = walk(OWN[name], FakeWorld({}), SessionState())
    assert verdicts[-1].decision is Decision.ALLOW, name


def test_the_session_records_a_copy_of_an_outside_file_as_outside():
    from core.sources import propagate
    state = SessionState()
    state.seq += 1
    propagate(state, ex("cp /opt/other/notes.md /tmp/notes.md"), FakeWorld())
    assert state.downloaded("/tmp/notes.md") is True


def test_an_unreadable_copy_source_loses_track():
    from core.sources import propagate
    state = SessionState()
    state.seq += 1
    propagate(state, ex("cp $SRC /tmp/x.md"), FakeWorld())
    assert state.downloads_truncated is True


def test_a_copy_within_the_roots_is_not_outside():
    from core.sources import propagate
    state = SessionState()
    state.seq += 1
    propagate(state, ex("cp /repo/src/a.md /repo/src/b.md"), FakeWorld())
    assert state.downloaded("/repo/src/b.md") is False
    assert state.downloads_truncated is False


# linear in the command
import time  # noqa: E402

_SIZE = 128 * 1024
_BOUND_MS = 150


@pytest.mark.parametrize("unit", [
    "cp /opt/a /repo/b; ", "cat /opt/a > /repo/b; ", "sed s/a/b/ /opt/a > /repo/b; ",
    "cp $X /repo/b; ",
    # round-6 F11: many copies with NO separator must not re-scan to the end
    "cp /opt/a /x ", "cat /opt/a | tee /repo/b | ", "tar xf /opt/a -C /repo; "])
def test_the_outside_copy_reader_is_linear(unit):
    from core.downloads import copied_outside_files
    state = SessionState()

    def best(size):
        command = unit * (size // len(unit))
        b = float("inf")
        for _ in range(3):
            t = time.perf_counter()
            copied_outside_files(command, "/repo", ("/repo",), FakeWorld(), state)
            b = min(b, (time.perf_counter() - t) * 1000)
        return b
    small = best(_SIZE // 4)
    assert small < _BOUND_MS, (unit, small)
    assert best(_SIZE) < 6 * small + 3, unit
