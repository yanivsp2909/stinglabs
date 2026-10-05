"""ESTABLISH — the write_outside storm on book-app, reproduced and discriminated.

⚠ THIS IS A CHARACTERISATION TEST, NOT A FIX. It answers the one question the
investigation turns on: for a WRITE inside the cwd, what root set does the code
deciding `write_outside` actually evaluate against, and is it the SAME set the
record's `workspace_roots` field reports?

THE REAL SIGNAL that prompted this: a session in /Users/dev/book-app logged
163 writes DENY `untrusted_unexpected:write_outside`, every record's
`workspace_roots` reading ["/Users/dev/book-app"] — which, if that were the
set the decision used, would put every target INSIDE and make the rule
unreachable. The installed env declares STING_ROOTS as the four sting repos and
NOT book-app, so the real decision was made against those four, and book-app is
correctly outside them. The record naming book-app is the mislead.

These tests reproduce that hermetically with STING_ROOTS (project_roots returns
it verbatim when set, so no git layout is needed) and print the three values
side by side. They assert the CURRENT reality, including the mismatch — so when
the record is fixed to report the effective set, the one test that pins the bug
flips and must be updated deliberately.
"""
import json
from pathlib import Path

import pytest

import hook_entry
from core import probes
from core.engine import is_inside_project
from core.audit_log import default_log_path, read_records
from core.session import open_session

SESSION = "book-app-repro"


def payload(kind_input, cwd, session=SESSION, tool="Bash"):
    return json.dumps({"session_id": session, "cwd": str(cwd),
                       "hook_event_name": "PreToolUse", "tool_name": tool,
                       "tool_input": kind_input})


def write_payload(path, cwd, session=SESSION, content="x = 1\n"):
    return json.dumps({"session_id": session, "cwd": str(cwd),
                       "hook_event_name": "PreToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(path), "content": content}})


# ⚠ SINCE fix/false-positives (docs/112) THE STORM IS GONE: an untrusted session
# is no longer refused a write outside the roots unless the write shows a
# secret reference. The characterisation below still holds for a write that IS
# refused, so the tests that need one write this.
SECRET_CONTENT = "token = '$GITHUB_TOKEN'\n"


def decision_of(out):
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"].upper() if out else "ALLOW"


def engine_verdict(session=SESSION):
    """The ENGINE's decision, off the record — NOT the rendered output.

    ⚠ THE DISTINCTION IS LOAD-BEARING HERE. This machine carries a policy
    overlay relaxing `untrusted_unexpected:write_outside` DENY→ASK, so the
    RENDERED output is ASK while the engine's verdict, written to the record
    unchanged, is DENY. The real book-app records show DENY — the engine verdict
    — so that is what "the storm" is and what these tests assert. Reading the
    rendered decision would couple the test to whatever policy.json happens to
    say on the box it runs on.
    """
    return last_record(session).get("decision")


def last_record(session=SESSION):
    return read_records(default_log_path(session))[-1]


def effective_roots(session=SESSION):
    """What decide() actually evaluated against — read from persisted state."""
    with open_session(session) as state:
        return tuple(state.workspace_roots)


@pytest.fixture
def project(tmp_path):
    """A project directory with a file to read and a file to write.

    NOT a git repo and NOT under any declared root by default — exactly
    book-app's situation relative to STING_ROOTS.
    """
    proj = tmp_path / "book-app"
    proj.mkdir()
    (proj / "README.md").write_text("a book app\n", encoding="utf-8")
    return proj


@pytest.fixture
def declared_elsewhere(tmp_path, monkeypatch):
    """STING_ROOTS points at a REAL directory that is NOT the project.

    This is the installed machine's shape: the four sting repos declared, the
    cwd (book-app) outside all of them.
    """
    root = tmp_path / "declared-root"
    root.mkdir()
    monkeypatch.setenv("STING_ROOTS", str(root))
    return root


# --------------------------------------------------------------------------
# The reproduction, and the side-by-side the investigation asked for.
# --------------------------------------------------------------------------

def test_the_storm_reproduces_when_the_cwd_is_outside_the_declared_root(
        project, declared_elsewhere, capsys):
    """A read then a write inside a cwd that no declared root contains → DENY.

    This is the storm. It requires the session to be untrusted (the read of a
    file outside every root supplies that) and the write target to be outside
    every root (the cwd is).
    """
    # A prior read inside the project — allowed, but it marks the session
    # untrusted because the file is outside every declared root.
    hook_entry.run(payload({"file_path": str(project / "README.md")},
                            project, tool="Read"))

    # The storm itself no longer happens (docs/112): a plain write is allowed.
    hook_entry.run(write_payload(project / "plain.py", project))
    assert engine_verdict() == "ALLOW"

    target = project / "config.py"
    out, _note, _code = hook_entry.run(write_payload(target, project, content=SECRET_CONTENT))

    rec = last_record()
    eff = effective_roots()
    recorded = tuple(rec.get("workspace_roots") or ())
    contained = is_inside_project(str(target), eff, probes.RealWorld())

    print("\n--- write to", target)
    print("(i)   effective roots decide() used :", eff)
    print("(ii)  workspace_roots in the record :", recorded)
    print("(iii) is_inside_project(target, eff):", contained)
    print("      verdict / rule                :",
          decision_of(out), "/", rec.get("rule_id"))

    # The storm reproduces — at the RECORD (engine verdict), which is what the
    # real book-app session shows: 206/206 WRITE/EDIT are DENY on the record.
    assert engine_verdict() == "DENY"
    assert rec["rule_id"] == "untrusted_unexpected:write_outside"
    # (iii) confirms WHY: against the roots decide used, the target is outside.
    assert contained is False
    # decide() used the DECLARED root, not the cwd — the storm is CORRECT.
    assert str(declared_elsewhere) in eff


def test_the_record_reports_the_roots_the_decision_used(
        project, declared_elsewhere):
    """⚠ BUG 1, PINNED. The record's `workspace_roots` must be the set decide()
    evaluated against — the effective roots — not the cwd the adapter filled in.

    Before the fix, every book-app record read `["…/book-app"]` (the cwd) while
    the decision was made against the four declared sting repos, which is what
    made a correct `write_outside` look like a containment bug. `_decide`
    resolved the roots into a LOCAL action and returned only the verdict, so
    `run()` logged its original, unresolved action.
    """
    hook_entry.run(payload({"file_path": str(project / "README.md")},
                            project, tool="Read"))
    hook_entry.run(write_payload(project / "config.py", project))

    eff = effective_roots()
    recorded = tuple(last_record().get("workspace_roots") or ())

    assert recorded == eff, (
        f"the record must report the roots the decision used {eff}, "
        f"not {recorded}")
    assert recorded != (str(project),), "must not report the cwd fallback"
    # The session_start canary is logged from the same action — it too must
    # carry the effective roots, not the cwd.
    canary = read_records(default_log_path(SESSION))[0]
    assert canary["event"] == "session_start"
    assert tuple(canary.get("workspace_roots") or ()) == eff


def test_a_write_outside_an_undeclared_cwd_is_announced(project, declared_elsewhere):
    """⚠ BUG 2. When a WRITE is judged write_outside because the cwd is in no
    declared root, the hook must SAY so — that is the book-app case, otherwise
    silent in observe and a bare prompt in enforce with no hint of the fix.

    Gated on the WRITE, not the session: project_roots returned STING_ROOTS
    confidently (roots_note is None) and the 'not honoured' warning cannot fire
    (the declared roots parse — they just do not contain this cwd), so the write
    verdict is the first place the truth can be told.
    """
    # Taint the session (a read outside every root marks it untrusted), exactly
    # as the real book-app session was tainted by its first `git log`. Without an
    # untrusted session a write-outside is not refused, so there is nothing to
    # explain.
    hook_entry.run(payload({"file_path": str(project / "README.md")},
                            project, tool="Read"))
    _out, note, _code = hook_entry.run(write_payload(project / "config.py", project,
                                                      content=SECRET_CONTENT))
    assert "not inside any declared project root" in note
    assert "STING_ROOTS" in note
    assert str(project) in note


def test_a_read_only_session_in_an_odd_directory_is_NOT_nagged(
        project, declared_elsewhere):
    """The note is about writes that get flagged, not about where you stand. A
    session that only reads/execs outside the declared roots writes nothing that
    is refused, so nagging it is the noise the project refuses to make. This is
    exactly the shape of the foundational 'an allow is silent' tests."""
    _out, note, _code = hook_entry.run(payload(
        {"file_path": str(project / "README.md")}, project, tool="Read"))
    assert "not inside any declared project root" not in note
    assert note == "" or "OBSERVE" in note  # nothing of ours added


def test_a_write_inside_a_declared_root_is_not_announced(project, monkeypatch):
    """Control: an ordinary in-root write is silent — the note is a signal about
    undeclared projects, not about every write."""
    monkeypatch.setenv("STING_ROOTS", str(project))
    _out, note, _code = hook_entry.run(write_payload(project / "config.py", project,
                                                      content=SECRET_CONTENT))
    assert "not inside any declared project root" not in note


def test_the_undeclared_root_note_is_said_once_not_on_every_write(
        project, declared_elsewhere):
    """A note on all 200 writes is a keystroke tax that trains people to ignore
    stderr. Latched in state after the first."""
    hook_entry.run(payload({"file_path": str(project / "README.md")},
                            project, tool="Read"))    # taint → writes get flagged
    first = hook_entry.run(write_payload(project / "a.py", project, content=SECRET_CONTENT))[1]
    second = hook_entry.run(write_payload(project / "b.py", project, content=SECRET_CONTENT))[1]
    assert "not inside any declared project root" in first
    assert "not inside any declared project root" not in second


def test_it_does_NOT_reproduce_when_the_declared_root_IS_the_cwd(project, monkeypatch):
    """⚠ THE 'IF IT DOES NOT REPRODUCE' ARM.

    With effective roots = the cwd (as the record's ["…/book-app"] would imply),
    the in-cwd write is ALLOWED. So the record's roots are NOT the roots that
    produced the DENY — proving the decision was made against a different set.
    This is the arm the investigation said to check and STOP on.
    """
    monkeypatch.setenv("STING_ROOTS", str(project))

    hook_entry.run(payload({"file_path": str(project / "README.md")},
                            project, tool="Read"))
    target = project / "config.py"
    out, _note, _code = hook_entry.run(write_payload(target, project))

    eff = effective_roots()
    assert eff == (str(project),), eff
    assert is_inside_project(str(target), eff, probes.RealWorld()) is True
    assert engine_verdict() == "ALLOW", (
        "with the cwd declared, the in-root write does NOT fire write_outside — "
        "so the storm's roots were not the cwd the record shows")
    assert last_record()["rule_id"] != "untrusted_unexpected:write_outside"


def test_write_outside_is_not_vacuous_a_genuinely_outside_write_still_denies(
        project, tmp_path, monkeypatch):
    """POSITIVE CONTROL (working rule 13). Even with the cwd declared, a write to
    a path that IS outside every root must still deny — or the rule is dead."""
    monkeypatch.setenv("STING_ROOTS", str(project))
    outside = tmp_path / "somewhere-else"
    outside.mkdir()

    # Taint the session with a read outside every root.
    hook_entry.run(payload({"file_path": str(outside / "x")}, project, tool="Read"))
    out, _note, _code = hook_entry.run(write_payload(outside / "config.py", project,
                                                      content=SECRET_CONTENT))

    rec = last_record()
    assert engine_verdict() == "DENY"
    assert rec["rule_id"] == "untrusted_unexpected:write_outside"


def test_read_and_write_share_one_containment_function_and_one_root_set(
        project, declared_elsewhere):
    """The read path and the write path ask the SAME question the SAME way.

    Both call is_inside_project(path, action.workspace_roots, world). So a read
    inside book-app and a write inside book-app get the same containment answer —
    which is why this is NOT a write-side containment bug. The read is allowed
    only because reads are allowed regardless of containment; it is still judged
    'outside' and still marks the session untrusted.
    """
    world = probes.RealWorld()
    hook_entry.run(payload({"file_path": str(project / "README.md")},
                            project, tool="Read"))
    eff = effective_roots()
    read_target = str(project / "README.md")
    write_target = str(project / "config.py")
    # Same function, same roots → same answer for two paths in the same dir.
    assert is_inside_project(read_target, eff, world) == \
           is_inside_project(write_target, eff, world) == False
