"""⚠ THE INVARIANT: running ⇒ declared. At no observable moment may the daemon
read as running while its declaration is not on disk.

WHAT BROKE. `serve()` called `bind()` — which binds a temporary name, listens,
and renames it onto the final socket path, the exact moment `status()` starts
answering `running: True` — and only THEN wrote `daemon.json`, after a stat, a
file read and a non-atomic `write_text` that swallowed every error. A status
read in that window said "running, and it says nothing about its tree". It
happened on a loaded CI runner (PR #17) in a test that polled for `running`
and asserted `declared` in the same breath; the test was right and the daemon
was wrong.

THE FIX IS ORDER, NOT TOLERANCE. `daemon.json` needs nothing the socket has —
the pid is this process, the socket path is known before any bind — so the
declaration is written first, atomically (temp + rename), and a declaration
that cannot be written fails startup before anything is listening. "Declared
but not yet running" is the only intermediate state, and it is the harmless
direction.

These tests pin the ORDER, never the clock: `serve(root, idle=0)` runs the
whole startup and returns on its first loop, synchronously; spies on the two
steps record the sequence and, at the moment the socket is about to be
published, whether the declaration already exists.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from daemon import protocol, server  # noqa: E402


@pytest.fixture
def root(tmp_path):
    """⚠ SHORT, because `sun_path` is 104 bytes on macOS and bind() defends the
    NAME, not the tmpdir; a long pytest tmp_path makes the daemon refuse to
    bind for a reason that has nothing to do with the test."""
    import tempfile
    return tempfile.mkdtemp(prefix="/tmp/decl")


# ═══════════════════════════════════════════ 1 · the invariant, by sequence

def test_the_declaration_is_on_disk_before_the_socket_is_published(root, monkeypatch):
    order: list[str] = []
    seen_at_bind: dict = {}
    real_bind, real_declare = server.bind, server._declare

    def spy_declare(*a, **k):
        order.append("declare")
        return real_declare(*a, **k)

    def spy_bind(r):
        # ⚠ THE MOMENT BEFORE THE SOCKET EXISTS: this is what an observer could
        # see at the transition to running. Both facts recorded, no waiting.
        seen_at_bind["declared"] = bool(server.declaration(r))
        seen_at_bind["running"] = server.status(r)["running"]
        order.append("bind")
        return real_bind(r)

    monkeypatch.setattr(server, "_declare", spy_declare)
    monkeypatch.setattr(server, "bind", spy_bind)

    code = server.serve(root, idle=0)          # startup, one loop, return

    assert code == 0
    assert order == ["declare", "bind"], order
    assert seen_at_bind == {"declared": True, "running": False}, (
        "at the instant the socket is about to be published, the declaration "
        "must already exist and nothing may yet read as running")


def test_once_running_the_declaration_names_this_process_and_tree(root):
    """The declared facts, read the way `status()` reads them — after a full
    startup, with the socket then torn down by serve()'s own exit."""
    assert server.serve(root, idle=0) == 0
    said = server.declaration(root)

    assert said["pid"] == os.getpid()
    assert said["tree"] == str(ROOT)
    assert said["socket"] == protocol.socket_path(root)
    assert "booted_at" in said and "booted_with_install_time" in said


# ═══════════════════════════════════════════ 2 · a declaration that cannot be written

def test_a_declaration_that_cannot_be_written_fails_startup_before_listening(root, capsys):
    """⚠ NOT "listen forever, undeclared". A directory squatting on the
    declaration's name makes the atomic rename fail; the daemon must say so,
    exit non-zero, and leave NO socket behind — a client must not find a
    daemon that a status read cannot account for."""
    Path(root, server.DECLARATION).mkdir()

    code = server.serve(root, idle=0)

    assert code == 2
    assert "declar" in capsys.readouterr().err.lower()
    assert server.status(root)["running"] is False
    assert not os.path.exists(protocol.socket_path(root)), "it listened anyway"


# ═══════════════════════════════════════════ 3 · the write is atomic

def test_the_declaration_is_written_by_rename_and_leaves_no_temp_file(root, monkeypatch):
    """No torn read was traded for the ordering race: the reader can only ever
    see a complete file, because the bytes land under a temporary name and are
    renamed into place."""
    replaced: list[tuple[str, str]] = []
    real_replace = os.replace

    def spy_replace(src, dst, *a, **k):
        replaced.append((str(src), str(dst)))
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(os, "replace", spy_replace)

    assert server.serve(root, idle=0) == 0

    final = str(Path(root, server.DECLARATION))
    assert any(dst == final for _, dst in replaced), replaced
    src = next(s for s, d in replaced if d == final)
    assert not os.path.exists(src), "the temporary file must not outlive the rename"
    json.loads(Path(final).read_text(encoding="utf-8"))       # and it parses whole


def test_a_reader_ignores_the_temporary_name(root):
    """A half-written temp file is not a declaration."""
    Path(root).mkdir(exist_ok=True)
    Path(root, f".{server.DECLARATION}.tmp").write_text("{not json", encoding="utf-8")
    assert server.declaration(root) == {}
