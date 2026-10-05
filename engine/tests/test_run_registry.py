"""A latency bench of this repository refuses to start while another test run
or bench of this repository is running, in any of its worktrees — and never
because of another repository. docs/PARALLEL.md, tools/run_registry.py.

Every case runs against a throwaway repository with a real linked worktree,
and every "other run" is a real process holding a real registration, so the
lock semantics under test are the kernel's, not a stand-in's.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
from contextlib import contextmanager
from pathlib import Path

import pytest

pytest.importorskip("fcntl")             # POSIX: Windows has no registry

from tools import bench_latency, bench_startup, run_registry as rr   # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

_GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull}

# A process that registers as a run of the repository holding argv[3] and
# holds it until its stdin closes.
_HOLDER = textwrap.dedent("""
    import sys
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    from tools import run_registry
    registration = run_registry.register(sys.argv[2], Path(sys.argv[3]))
    print("ready", flush=True)
    sys.stdin.read()
""")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env=_GIT_ENV)


def _repository(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    (path / "f").write_text("x", encoding="utf-8")
    _git(path, "add", "f")
    _git(path, "-c", "user.email=a@b", "-c", "user.name=c", "commit", "-q", "-m", "init")
    return path


@pytest.fixture
def repo(tmp_path):
    """(main checkout, a detached linked worktree of it)."""
    main = _repository(tmp_path / "repo")
    worktree = tmp_path / "wt"
    _git(main, "worktree", "add", "-q", "--detach", str(worktree))
    return main, worktree


@contextmanager
def holding(kind: str, root: Path):
    proc = subprocess.Popen([sys.executable, "-c", _HOLDER, str(ROOT), kind, str(root)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "ready"
        yield proc
    finally:
        if proc.poll() is None:
            proc.stdin.close()
            proc.wait(timeout=30)


def test_a_worktree_and_its_checkout_share_one_registry_and_no_other_repo_does(
        repo, tmp_path):
    main, worktree = repo
    other = _repository(tmp_path / "other")
    assert rr.common_dir(main) is not None
    assert rr.common_dir(worktree) == rr.common_dir(main)
    assert rr.common_dir(worktree / "nested" / "dir") == rr.common_dir(main)
    assert rr.common_dir(other) != rr.common_dir(main)


def test_outside_a_checkout_nothing_registers(tmp_path):
    loose = tmp_path / "unpacked-archive"
    loose.mkdir()
    assert rr.common_dir(loose) is None
    assert rr.register(rr.SUITE, loose) is None
    assert rr.claim_bench(loose) == (None, None)


def test_a_test_run_in_another_worktree_refuses_the_bench_and_says_where(repo):
    main, worktree = repo
    with holding(rr.SUITE, worktree) as other:
        registration, refusal = rr.claim_bench(main, lineage={os.getpid()})
    assert registration is None
    assert refusal.startswith("REFUSED")
    assert "a test run" in refusal and str(worktree) in refusal
    assert f"pid {other.pid}" in refusal


def test_a_bench_in_another_worktree_refuses_the_bench_too(repo):
    main, worktree = repo
    with holding(rr.BENCH, worktree):
        registration, refusal = rr.claim_bench(main, lineage={os.getpid()})
    assert registration is None and "a bench" in refusal


def test_another_repositorys_test_run_does_not_count(repo, tmp_path):
    main, _worktree = repo
    other = _repository(tmp_path / "other")
    with holding(rr.SUITE, other):
        registration, refusal = rr.claim_bench(main, lineage={os.getpid()})
    assert refusal is None and registration is not None
    registration.close()


_CLAIMANT = textwrap.dedent("""
    import sys
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    from tools import run_registry
    registration, refusal = run_registry.claim_bench(Path(sys.argv[2]), lineage=set())
    print("refused" if refusal else "granted")
""")


def _second_bench(root: Path) -> str:
    return subprocess.run([sys.executable, "-c", _CLAIMANT, str(ROOT), str(root)],
                          capture_output=True, text=True, check=True).stdout.strip()


def test_nothing_running_means_the_bench_registers_and_releases(repo):
    main, worktree = repo
    registration, refusal = rr.claim_bench(main, lineage={os.getpid()})
    assert refusal is None and registration is not None
    directory = rr.registry_dir(worktree)
    assert [e["kind"] for e in rr._live_locked(directory)] == [rr.BENCH]
    # While it holds, a second bench from the other worktree is refused...
    assert _second_bench(worktree) == "refused"
    registration.close()
    assert rr._live_locked(directory) == []
    # ...and once it is released, the next one goes ahead.
    assert _second_bench(worktree) == "granted"


def test_a_crashed_run_does_not_refuse_forever(repo):
    """A pid can be reused; a lock the kernel released is never held again."""
    main, worktree = repo
    with holding(rr.SUITE, worktree) as other:
        entries = list(rr.registry_dir(main).glob("*.json"))
        assert len(entries) == 1
        other.send_signal(signal.SIGKILL)
        other.wait(timeout=30)
        assert entries[0].exists(), "the crash left its entry behind"
        registration, refusal = rr.claim_bench(main, lineage={os.getpid()})
    assert refusal is None and registration is not None
    assert not entries[0].exists(), "the stale entry is cleared, not reported"
    registration.close()


def test_the_bench_a_test_run_starts_is_its_smoke_test_and_is_never_refused(repo):
    """`tests/test_bench_robustness.py` runs the bench inside the suite. With a
    second worktree's suite running beside it, a refusal there would be the
    phantom failure this whole mechanism exists to prevent."""
    main, worktree = repo
    with holding(rr.SUITE, worktree), holding(rr.SUITE, main) as mine:
        assert rr.claim_bench(main, lineage={os.getpid(), mine.pid}) == (None, None)


def test_this_test_run_is_registered_while_it_runs():
    directory = rr.registry_dir(ROOT)
    if directory is None:
        pytest.skip("not a git checkout: nothing registers here")
    mine = [e for e in rr._live_locked(directory) if e.get("pid") == os.getpid()]
    assert [e["kind"] for e in mine] == [rr.SUITE]
    assert Path(mine[0]["worktree"]) == ROOT


def test_ancestors_are_this_process_and_its_parents():
    lineage = rr.ancestors()
    assert os.getpid() in lineage and os.getppid() in lineage


@pytest.mark.parametrize("bench, measured", [
    (bench_latency, "bench_in_process"),
    (bench_startup, "measure"),
])
def test_a_refused_bench_measures_nothing_and_exits_distinctly(
        bench, measured, monkeypatch, capsys):
    monkeypatch.setattr(rr, "claim_bench",
                        lambda root: (None, "REFUSED: a test run is here"))

    def must_not_run(*_a, **_k):
        raise AssertionError("a refused bench measured anyway")

    monkeypatch.setattr(bench, measured, must_not_run)
    assert bench.main(["--calls", "1"]) == rr.REFUSED_BUSY
    assert "REFUSED: a test run is here" in capsys.readouterr().out
    assert rr.REFUSED_BUSY not in (0, 1, 2)
