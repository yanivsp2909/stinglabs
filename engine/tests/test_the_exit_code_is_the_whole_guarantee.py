"""⚠ ONE EXIT CODE IS THE ONLY THING BETWEEN A DEFECT AND A SILENT PERMIT.

Measured in a real `claude -p --permission-mode manual` session, with stub hooks
standing in for Sting:

    exit 2                   -> BLOCKED  ("a PreToolUse hook blocked it by
                                           crashing")
    malformed JSON + exit 0  -> ⚠ THE COMMAND RAN
    no output + exit 0       -> ⚠ THE COMMAND RAN

Claude Code fails OPEN on bad or absent stdout and CLOSED only on a non-zero
exit. Now that Sting emits an explicit `allow` — replacing the agent's
permission system rather than adding to it — that exit code is the entire
guarantee.

⚠ SO EVERY TEST HERE DRIVES THE REAL HOOK AS A SUBPROCESS AND ASSERTS THE EXIT
CODE. A test that inspects the returned string is testing the wrong half: the
string is what Claude Code IGNORES when it cannot parse it.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "sting_hook.py"

PAYLOAD = json.dumps({"session_id": "exitcode", "tool_name": "Bash",
                      "tool_input": {"command": "git status --short"}})


def run_hook(payload: str = PAYLOAD, env: dict | None = None,
             timeout: float = 60) -> subprocess.CompletedProcess:
    """The real hook, as a real subprocess, exactly as an agent invokes it."""
    base = {
        **os.environ,
        "STING_OBSERVE": "0",
        "STING_NO_DAEMON": "1",
        "STING_ROOTS": str(ROOT),
        "PYTHONPATH": str(ROOT),
    }
    base.update(env or {})
    return subprocess.run(
        [sys.executable, str(HOOK), "--agent", "claude-code"],
        input=payload, capture_output=True, text=True, env=base, timeout=timeout)


def _injector(tmp_path: Path, body: str) -> dict:
    """A `sitecustomize.py` that breaks the hook from the inside.

    ⚠ THIS IS HOW AN UNHANDLED EXCEPTION IS PRODUCED HONESTLY. Monkeypatching
    in-process would test a different program; Python imports `sitecustomize`
    automatically at interpreter start, so the failure happens inside the real
    subprocess, on the real path, before anything is decided.
    """
    (tmp_path / "sitecustomize.py").write_text(body, encoding="utf-8")
    return {"PYTHONPATH": f"{tmp_path}{os.pathsep}{ROOT}"}


def _assert_blocks(proc, what: str):
    assert proc.returncode != 0, (
        f"{what}: exited 0, and Claude Code RUNS THE TOOL on a zero exit "
        f"whenever it cannot use stdout. stdout={proc.stdout!r}")
    # and if anything WAS printed, it must still be the whole verdict, not a
    # fragment — see test_nothing_is_printed_before_the_verdict_is_final
    if proc.stdout.strip():
        json.loads(proc.stdout)


# ════════════════════ 1.1 · every failure shape, real subprocess ══

def test_an_unhandled_exception_exits_non_zero(tmp_path):
    env = _injector(tmp_path, (
        "import builtins\n"
        "_real = builtins.__import__\n"
        "def _boom(name, *a, **k):\n"
        "    mod = _real(name, *a, **k)\n"
        "    if name == 'hook_entry':\n"
        "        def explode(*_a, **_k):\n"
        "            raise RuntimeError('engine blew up mid-decision')\n"
        "        mod.run = explode\n"
        "    return mod\n"
        "builtins.__import__ = _boom\n"))
    _assert_blocks(run_hook(env=env), "an unhandled exception")


def test_an_import_failure_exits_non_zero(tmp_path):
    """A shadowed module that raises at import — a broken install, a partial
    unpack, a half-written file."""
    env = _injector(tmp_path, (
        "import builtins\n"
        "_real = builtins.__import__\n"
        "def _boom(name, *a, **k):\n"
        "    if name == 'hook_entry':\n"
        "        raise ImportError('hook_entry is not importable')\n"
        "    return _real(name, *a, **k)\n"
        "builtins.__import__ = _boom\n"))
    _assert_blocks(run_hook(env=env), "an import failure")


def test_a_system_exit_from_the_python_floor_exits_non_zero(tmp_path):
    env = _injector(tmp_path, (
        "import builtins\n"
        "_real = builtins.__import__\n"
        "def _boom(name, *a, **k):\n"
        "    mod = _real(name, *a, **k)\n"
        "    if name == 'hook_entry':\n"
        "        def bail(*_a, **_k):\n"
        "            raise SystemExit('python 3.10 is below the floor')\n"
        "        mod.run = bail\n"
        "    return mod\n"
        "builtins.__import__ = _boom\n"))
    _assert_blocks(run_hook(env=env), "a refused interpreter")


def test_malformed_stdin_exits_non_zero():
    """⚠ THE AGENT'S OWN PAYLOAD CAN BE WRONG, and "I could not read what you
    sent me" is not permission to proceed.

    ⚠ THIS IS THE PASS'S FINDING. Before it, `''`, `null` and `[]` each produced
    exit 0 with an explicit `permissionDecision: "allow"` — the guard PERMITTING
    an action on a payload it never received. Harmless while allow rendered as
    empty output; a silent permit the moment allow became explicit.
    """
    for payload in ("", "not json at all", "{", "[]", "null"):
        _assert_blocks(run_hook(payload=payload), f"stdin {payload!r}")


def test_a_payload_naming_no_tool_abstains_rather_than_permitting():
    """⚠ SILENCE, NOT PERMISSION. A payload with no tool describes no action.
    Refusing outright would block everything the day Claude Code ships a shape
    this adapter cannot read; permitting tells it to proceed on something we did
    not understand. Empty stdout is "no opinion" — the state every verdict was
    in before this pass, and Claude Code applies its own rules.
    """
    proc = run_hook(payload='{"session_id": "x"}')
    assert proc.returncode == 0
    assert proc.stdout.strip() == "", (
        "a payload naming no tool was answered with a verdict")
    assert "NO OPINION" in proc.stderr
    assert "not a policy refusal" in proc.stderr.lower()


def test_a_missing_env_file_does_not_become_a_zero_exit(tmp_path):
    """`~/.sting/env` absent — a fresh machine, or a HOME the hook cannot read.

    ⚠ THIS ONE IS ALLOWED TO SUCCEED. A missing env file is not a failure: the
    hook falls back to defaults and still DECIDES. What it must never do is
    exit 0 having decided nothing, so the assertion is on the pair.
    """
    proc = run_hook(env={"HOME": str(tmp_path)})
    if proc.returncode == 0:
        decision = json.loads(proc.stdout)["hookSpecificOutput"]
        assert decision["permissionDecision"] in ("allow", "deny", "ask"), (
            "exited 0 with no usable decision — Claude Code would run the tool")
    else:
        _assert_blocks(proc, "a missing env file")


def test_an_unreadable_session_log_still_produces_a_decision(tmp_path):
    """A log that cannot be written must not stop the guard deciding, and must
    not produce a zero exit with nothing usable."""
    blocked = tmp_path / "nowhere"
    blocked.mkdir()
    blocked.chmod(0o500)
    try:
        proc = run_hook(env={"STING_SESSION_ROOT": str(blocked / "sub")})
        if proc.returncode == 0:
            json.loads(proc.stdout)          # must be a whole verdict
        else:
            _assert_blocks(proc, "an unreadable session log")
    finally:
        blocked.chmod(0o700)


# ════════════════════ the daemon, which answers for the hook ══

@pytest.fixture
def rogue_daemon():
    """A listener on the daemon's socket that misbehaves on demand."""
    sys.path.insert(0, str(ROOT))
    from daemon import protocol

    # ⚠ NOT tmp_path: an AF_UNIX path is capped near 104 bytes and pytest's
    # tmp_path is longer than that on macOS, so binding raises "path too long".
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="/tmp/sd"))
    path = Path(protocol.socket_path(str(root)))
    path.parent.mkdir(parents=True, exist_ok=True)
    servers = []

    def start(handler):
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(path))
        srv.listen(4)
        servers.append(srv)

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=handler, args=(conn,),
                                  daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()
        return str(root)

    yield start
    for srv in servers:
        srv.close()


def test_a_daemon_that_answers_garbage_does_not_produce_a_zero_exit(rogue_daemon):
    def garbage(conn):
        try:
            conn.recv(65536)
            conn.sendall(b"this is not a protocol frame at all\n")
        finally:
            conn.close()

    root = rogue_daemon(garbage)
    proc = run_hook(env={"STING_NO_DAEMON": "", "STING_SHIPPER_STATE": root,
                          "STING_SESSION_ROOT": root})
    # Either it refuses, or it falls back and decides in-process. Both are fine;
    # exiting 0 with unusable stdout is not.
    if proc.returncode == 0:
        json.loads(proc.stdout)
    else:
        _assert_blocks(proc, "a daemon answering garbage")


def test_a_daemon_that_never_answers_does_not_hang_forever(rogue_daemon):
    """⚠ A HOOK THAT NEVER RETURNS IS ITS OWN FAILURE. Claude Code has its own
    timeout, and what happens after it is not ours to decide — so the guarantee
    here is that the hook itself gives up and still answers."""
    def silence(conn):
        time.sleep(120)          # accept, then never reply
        conn.close()

    root = rogue_daemon(silence)
    started = time.time()
    proc = run_hook(env={"STING_NO_DAEMON": "", "STING_SHIPPER_STATE": root,
                          "STING_SESSION_ROOT": root}, timeout=90)
    assert time.time() - started < 60, "the hook hung on a silent daemon"
    if proc.returncode == 0:
        json.loads(proc.stdout)


# ════════════════════ 1.2 · nothing is printed before the verdict ══

def test_nothing_is_printed_before_the_verdict_is_final():
    """⚠ THE ONE NOBODY WRITES: partial stdout, then a crash.

    If anything reaches stdout before the decision is final, Claude Code sees
    malformed JSON — and it does not need a zero exit for that to be unusable.

    Established by reading the source rather than by sampling: stdout is written
    in exactly ONE place, `sting_hook.main`'s `print(out)`, after `decide()` has
    returned. Every subprocess the decision path can spawn captures its own
    output — `core/probes.py` and `core/wire.py` pass `capture_output=True`,
    `daemon/client.py` passes `stdout=subprocess.DEVNULL` — so nothing a git
    probe prints can land in the hook's stdout.
    """
    source = (ROOT / "sting_hook.py").read_text(encoding="utf-8")
    writes = [ln.strip() for ln in source.splitlines()
              if "print(" in ln and "file=sys.stderr" not in ln
              and not ln.strip().startswith("#")]
    assert writes == ["print(out)"], (
        f"more than one thing writes stdout in the hook: {writes}")

    for module, needle in (("core/probes.py", "capture_output=True"),
                            ("core/wire.py", "capture_output=True"),
                            ("daemon/client.py", "stdout=subprocess.DEVNULL")):
        text = (ROOT / module).read_text(encoding="utf-8")
        assert needle in text, f"{module} may leak a subprocess into our stdout"


def test_stdout_is_one_line_so_a_fragment_cannot_look_whole():
    """A verdict spanning lines could be read as a complete first line plus
    junk. `json.dumps` without indent gives exactly one."""
    proc = run_hook()
    assert proc.returncode == 0
    assert len(proc.stdout.strip().splitlines()) == 1
    json.loads(proc.stdout)


# ════════════════════ 1.3 · what a person sees ══

def test_a_crash_does_not_read_like_a_policy_refusal(tmp_path):
    """⚠ A CRASH MUST NOT BE MISTAKEN FOR A RULE FIRING. One sends somebody to
    `policy.json` to turn off a rule that never ran."""
    env = _injector(tmp_path, (
        "import builtins\n"
        "_real = builtins.__import__\n"
        "def _boom(name, *a, **k):\n"
        "    mod = _real(name, *a, **k)\n"
        "    if name == 'hook_entry':\n"
        "        def explode(*_a, **_k):\n"
        "            raise RuntimeError('engine blew up mid-decision')\n"
        "        mod.run = explode\n"
        "    return mod\n"
        "builtins.__import__ = _boom\n"))
    proc = run_hook(env=env)

    assert proc.returncode != 0
    told = proc.stdout + proc.stderr
    assert "sting" in told.lower(), "nothing says the guard was involved at all"
    assert "STING BLOCKED" not in told.upper(), (
        "a crash was dressed up as a policy refusal")
    assert "policy.json" not in told, (
        "a crash pointed somebody at a rule that never fired")


# ════════════════════ 2 · the stale daemon ══

def test_the_daemon_declares_which_tree_it_is_serving(tmp_path):
    """⚠ "LOADED, RUNNING, DOING THE WRONG THING" — the fifth instance here, and
    a daemon is the easiest place for it: the process outlives the directory it
    was started from, and from outside it looks perfectly healthy.
    """
    import tempfile
    import threading

    sys.path.insert(0, str(ROOT))
    from daemon import server

    root = tempfile.mkdtemp(prefix="/tmp/decl")
    threading.Thread(target=lambda: server.serve(root, idle=6), daemon=True).start()
    for _ in range(50):
        if server.status(root).get("running"):
            break
        time.sleep(0.1)

    seen = server.status(root)
    assert seen["running"] is True
    assert seen["declared"] is True, "a daemon that says nothing about its tree"
    assert seen["tree"] == str(ROOT)
    assert seen["tree_exists"] is True
    # `serve()` runs in a thread here, so the pid IS this process — what
    # matters is that a pid is declared at all, so a reader can find and stop it.
    assert seen["pid"] == os.getpid()


def test_a_daemon_whose_tree_is_gone_is_visible_as_such(tmp_path):
    """The state that matters: it answers, it is fast, and the code it decides
    with cannot be read by anybody."""
    sys.path.insert(0, str(ROOT))
    from daemon import server

    (tmp_path / server.DECLARATION).write_text(json.dumps({
        "pid": 4242, "tree": str(tmp_path / "a-tree-that-was-replaced"),
        "booted_at": 0, "socket": "x"}), encoding="utf-8")

    said = server.declaration(str(tmp_path))
    assert said["tree"].endswith("a-tree-that-was-replaced")
    assert not Path(said["tree"]).is_dir(), (
        "precondition: the tree is gone, which is the whole point")


def test_an_install_after_boot_makes_the_daemon_stand_down():
    """⚠ TASK 2.1, AND THE PREMISE WAS HALF WRONG. An UPDATE does restart it:
    `superseded()` compares `allow_once.install_time()` — derived from
    INSTALL.json and the `current` symlink's mtime, both moved by a real install
    — against the value pinned at boot, refuses the request, and exits. The
    client then falls back IN-PROCESS, importing the tree the install just put
    there, so the very request that noticed is answered by the new policy.

    What did NOT restart it last pass was a WORKING-TREE edit with no install:
    `install_time()` never moved, so nothing was superseded. That is a
    development-only state, not what a customer's update produces.
    """
    sys.path.insert(0, str(ROOT))
    from daemon import server

    assert server.superseded(None) is False, (
        "a checkout with no install must not be treated as superseded — that "
        "would make the daemon exit after every request on a dev machine")

    booted = server.__dict__["allow_once"].install_time()
    if booted is None:
        pytest.skip("no install on this machine, so there is no time to move")
    assert server.superseded(booted) is False, "steady state must not stand down"
    assert server.superseded(booted - 1) is True, (
        "an install AFTER boot did not supersede the daemon")


def test_standing_down_refuses_before_it_decides_so_nothing_is_double_logged():
    """⚠ TASK 2.3 — WHAT HAPPENS TO ANYTHING IN FLIGHT.

    The refusal is issued INSTEAD of `handle(...)`, not after it, so a
    superseded daemon never decides, never writes a decision record, and never
    consumes an allow-once grant. The client re-decides in-process and writes
    exactly one record. Nothing in flight is dropped and nothing is duplicated;
    the cost is one extra round trip on the first call after an install.
    """
    source = (ROOT / "daemon" / "server.py").read_text(encoding="utf-8")
    body = source[source.index("elif superseded(booted_with):"):]
    refusal = body[:body.index("else:")]
    assert "handle(" not in refusal, (
        "a superseded daemon decided the request before standing down — that "
        "record would be written by the OLD policy and then again by the new")
