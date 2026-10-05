"""B2 — prune_shipped.py rewrote the audit log without a lock, and a hook append
that landed during a prune was annihilated.

`tools/prune_shipped.py` did `lines = log.read_text()` (unlocked) then
`_rewrite()` → tmp + `os.replace()` (unlocked). Every OTHER writer of this file
— `core/audit_log.append()` — holds an exclusive flock across its whole
read-tail/compute/append window. Prune held nothing, so a hook record appended
between prune's read and its replace was overwritten by the stale snapshot.
Silent, irreversible, in the file that exists to be evidence.

⚠ TWO HALVES, AND THE SECOND ONE IS NOT OBVIOUS. flock binds to the OPEN FILE
DESCRIPTION (the inode). `os.replace` swaps the directory name to a NEW inode.
So a hook that opened the log before the replace and acquired the lock after
prune released it would append into an orphan with no name — still lost, lock
or no lock. `append()` has to re-check the inode after it locks, the way
`allow_once.consume()` already does. The tests below pin both halves
separately, so a lock-only "fix" fails the second one.

The oracle throughout is `audit_log.append()`: same lock, same pattern.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from core import locking
from core.audit_log import (append, build_body, prune_manifest_for,
                            pruned_start, read_records, verify_chain)
from tools import prune_shipped


@pytest.fixture
def session(tmp_path):
    """A real log with a real chain — the same shape test_pruning_needs_a_receipt
    builds, so prune has genuinely-shipped records to remove."""
    log = tmp_path / "s1.log.jsonl"
    old = time.time() - 30 * 86400
    for seq in range(1, 11):
        body = build_body("s1", seq=seq, event="decision", decision="allow",
                          command=f"git status {seq}")
        body["ts"] = old + seq
        append("s1", body, path=log)
    return log


def _position(**kw):
    base = {"shipped": 999, "gaps": 0, "acked_seq": 10, "acked_records": 10,
            "last_batch_ref": "batches/abc123", "acked_at": time.time(),
            "skipped_seqs": []}
    base.update(kw)
    return {"s1": base}


def _seqs(log: Path) -> list:
    return [r.get("seq") for r in read_records(log)]


def _hook_append(log: Path, seq: int, errors: list):
    """What a hook does: one append, through the real locked path."""
    try:
        append("s1", build_body("s1", seq=seq, event="decision", decision="allow",
                                command=f"echo hook {seq}"), path=log)
    except Exception as exc:                      # noqa: BLE001 — surfaced below
        errors.append(exc)


# ═══════════════════════════ the race, end to end ═══════════════════════════

def test_a_hook_append_that_lands_during_a_prune_survives(session, monkeypatch):
    """The stale-snapshot clobber, and the positive control in the same test.

    Prune is paused at its `os.replace`; a hook appends; prune is released.
    Before the lock: the hook's append succeeds immediately (nobody holds the
    file), then prune replaces the log with the snapshot it read BEFORE the
    append — the record is gone and nothing said so.
    After: prune holds the exclusive lock from its read to its replace, so the
    hook blocks until prune is done and then appends to the NEW file.

    ⚠ The pause point is the replace, not the read, on purpose: a lock that only
    guards the replace still lets the append land after prune's unlocked read,
    and this test catches that variant too. The lock has to cover the read.
    """
    real_replace = os.replace
    at_replace, go = threading.Event(), threading.Event()

    def paused_replace(src, dst):
        if not at_replace.is_set():
            at_replace.set()
            assert go.wait(10), "test harness: prune never released"
        return real_replace(src, dst)

    monkeypatch.setattr(prune_shipped.os, "replace", paused_replace)

    result, errors = {}, []
    pruner = threading.Thread(
        target=lambda: result.update(
            prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)))
    pruner.start()
    assert at_replace.wait(10), "prune never reached its replace"

    hook = threading.Thread(target=_hook_append, args=(session, 11, errors))
    hook.start()
    time.sleep(0.3)          # let the hook open the file and reach the lock
    go.set()
    pruner.join(15)
    hook.join(15)
    assert not pruner.is_alive() and not hook.is_alive()
    assert not errors, errors

    seqs = _seqs(session)
    # THE RECORD SURVIVES.
    assert 11 in seqs, f"the hook's append was annihilated by the prune: {seqs}"
    # And the chain it landed on is intact — no torn or reordered records.
    ok, _n, detail = verify_chain(session)
    assert ok, detail
    # POSITIVE CONTROL: the prune still removed the genuinely-shipped prefix.
    assert result["removed"] > 0, result
    assert seqs[0] > 1, "prune removed nothing — the lock made it vacuous"
    assert prune_manifest_for(session).is_file()
    assert pruned_start(session) is not None


def test_append_reopens_when_the_log_was_replaced_under_it(session):
    """⚠ HALF TWO, ISOLATED FROM PRUNE. Holding a lock across the replace is not
    enough on its own: a hook that opened the OLD inode and then waited for the
    lock acquires the orphan once it is released, and its record goes into a
    file that no longer has a name.

    Here the test IS the replacer: hold the exclusive lock, start a hook append
    (it opens the old file and blocks), swap the name to a new inode, release.
    The append must land in the file the NAME now points at.
    """
    fd = os.open(session, os.O_RDWR)
    locking._acquire(fd, shared=False)
    errors = []
    hook = threading.Thread(target=_hook_append, args=(session, 99, errors))
    try:
        hook.start()
        time.sleep(0.3)      # the hook has opened the old inode and is waiting
        # Swap the name to a NEW inode carrying the same bytes — what a
        # crash-safe prune does — while the hook is still blocked on the old one.
        tmp = session.with_suffix(".tmp-swap")
        tmp.write_bytes(session.read_bytes())
        os.replace(tmp, session)
    finally:
        locking._release(fd)
        os.close(fd)
    hook.join(15)
    assert not hook.is_alive() and not errors, errors

    assert 99 in _seqs(session), (
        "the append went into the orphaned inode: after acquiring the lock the "
        "hook must re-check that the name still points at the file it holds")
    ok, _n, detail = verify_chain(session)
    assert ok, detail


def test_prune_refuses_rather_than_proceeds_when_the_lock_is_held(session, monkeypatch):
    """A hook mid-append holds the lock. Prune must WAIT for it, and when it
    cannot get it, refuse — never read-modify-write around it. Before the fix
    prune took no lock at all and simply proceeded.

    `core/locking.LockUnavailable` says it plainly: a caller that swallowed it
    would be performing an unserialised read-modify-write on the audit chain.
    Refusing to rewrite is failing the action honestly.
    """
    monkeypatch.setenv("STING_LOCK_TIMEOUT", "0.3")
    before = session.read_bytes()
    fd = os.open(session, os.O_RDWR)
    locking._acquire(fd, shared=False)          # "a hook is mid-append"
    try:
        r = prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)
    finally:
        locking._release(fd)
        os.close(fd)

    assert r["removed"] == 0, "prune rewrote the log while another writer held it"
    assert "lock" in r["why"].lower(), r["why"]
    assert session.read_bytes() == before


# ═════════════════════ crash safety — the guard rail ════════════════════════

def test_a_prune_that_fails_at_the_LOG_replace_leaves_log_and_manifest_consistent(
        session, monkeypatch):
    """⚠ TWO PROPERTIES, AND THE SECOND IS THE ONE THE SECURITY REVIEW ADDED.

    1. The live log is never touched until the atomic replace, so a failure
       anywhere before it leaves the file byte-identical. This is why the fix
       keeps tmp+rename: an in-place truncate-and-write under the lock would
       let a dying prune leave the evidence file cut in half.
    2. The manifest is written BEFORE the log is replaced. A replace that
       RAISES (a Windows mandatory lock refusing it, ENOSPC, EPERM) would leave
       a manifest claiming a prune the log never got — and `verify_chain` then
       reports a break at record 1, a loud false tamper, on every such run.
       The manifest must be rolled back.

    ⚠ The failure is injected on the SECOND `os.replace` — the LOG's. The
    first is the manifest's own tmp+rename; failing there proves nothing about
    the window this test is for. An earlier version of this test crashed the
    first call and passed for that wrong reason.
    """
    before = session.read_bytes()
    assert pruned_start(session) is None       # no manifest yet — arm the gate
    real_replace = os.replace
    calls = {"n": 0}

    def fail_on_the_logs_replace(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("simulated failure at the log's replace")
        return real_replace(src, dst)

    monkeypatch.setattr(prune_shipped.os, "replace", fail_on_the_logs_replace)
    with pytest.raises(OSError):
        prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)
    assert calls["n"] >= 2, "the failure never reached the log's replace"

    assert session.read_bytes() == before, "a failed prune altered the log"
    assert pruned_start(session) is None, (
        "the manifest still claims a prune the log did not get — the next "
        "verify would report a false tamper at record 1")
    ok, _n, detail = verify_chain(session)
    assert ok, detail


@pytest.mark.skipif(not hasattr(os, "O_RDWR") or os.name == "nt",
                    reason="POSIX shared locks; Windows has no shared mode")
def test_a_report_takes_a_shared_lock_and_an_apply_takes_the_exclusive_one(
        session, monkeypatch):
    """The default invocation is report-only and writes nothing, so it must not
    stall every hook on the machine for a full read-and-verify. Shared locks
    coexist; an exclusive one does not. Both arms asserted, so the mode split
    is real rather than a comment."""
    monkeypatch.setenv("STING_LOCK_TIMEOUT", "0.3")
    fd = os.open(session, os.O_RDWR)
    locking._acquire(fd, shared=True)           # a concurrent READER holds it
    try:
        report = prune_shipped.prune(session, _position(acked_seq=6), 7, apply=False)
        apply = prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)
    finally:
        locking._release(fd)
        os.close(fd)

    assert report["removed"] > 0 and "lock" not in report["why"].lower(), report
    assert apply["removed"] == 0 and "lock" in apply["why"].lower(), apply


# ══════════════════ the verifier refactor did not fork ═══════════════════════

def test_verify_records_is_verify_chain_over_the_same_records(session):
    """prune has to verify the bytes it read UNDER its own lock — calling
    `verify_chain(path)` there would open a second fd and wait on prune itself.
    So the loop is factored out. One implementation, pinned here, pruned and
    unpruned, so it cannot drift into a second notion of "intact"."""
    from core.audit_log import verify_records

    assert verify_records(read_records(session), pruned_start(session)) == \
        verify_chain(session)
    prune_shipped.prune(session, _position(acked_seq=6), 7, apply=True)
    assert verify_records(read_records(session), pruned_start(session)) == \
        verify_chain(session)
    assert verify_chain(session)[0] is True
