"""replay.py's defaults and its error messages.

The messages matter more than they look: this tool's whole point is that
iterating is free, and a message that sends you to a ~$30 live capture to get
started undoes that.
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
REPLAY = ROOT / "runner" / "replay.py"

sys.path.insert(0, str(ROOT))
from runner import replay  # noqa: E402


def run_cli(*args, cwd=None):
    return subprocess.run([sys.executable, str(REPLAY), *args],
                           capture_output=True, text=True, cwd=cwd or ROOT)


# ------------------------------------------------------------------ defaults
def test_mode_is_optional():
    """There is one engine now, so requiring --mode was asking for a choice
    that no longer exists."""
    r = run_cli("--only", "N04-push-open-pr")
    assert r.returncode == 0, r.stderr
    assert f"mode={replay.DEFAULT_MODE}" in r.stdout


def test_the_default_mode_names_the_engine_being_scored():
    assert replay.DEFAULT_MODE == "taint"


def test_the_default_recordings_are_the_free_ones():
    assert replay.DEFAULT_RECORDINGS == "logs/synthetic"


def test_running_with_no_arguments_at_all_works():
    r = run_cli("--only", "I02-commit-into-pr-branch")
    assert r.returncode == 0, r.stderr
    assert "blocked" in r.stdout


# ------------------------------------------------------------------- scoring
def test_the_class_comes_from_expect_yaml_not_the_filename():
    """The old scorer inferred attack/normal from `sid.startswith("N")`. The
    scenario declares it; that declaration is authoritative."""
    assert replay.load_expect("I02-commit-into-pr-branch")["class"] == "attack"
    assert replay.load_expect("N04-push-open-pr")["class"] == "normal"


def test_a_missing_expect_yaml_is_empty_not_fatal():
    assert replay.load_expect("does-not-exist") == {}


def test_ask_is_reported_separately_from_deny():
    """An ASK is a prompt, not a block. The old scorer classified any non-empty
    stdout as a denial, so a prompt counted as a catch."""
    r = run_cli("--only", "I02-commit-into-pr-branch")
    assert r.returncode == 0, r.stderr
    # Asserts the FORMAT, not any scenario's verdict. This test was pinned to
    # E02 twice and broke twice when policy improved E02 — which scenario
    # happens to ASK is a policy detail, not a property of the scorer.
    header = [ln for ln in r.stdout.splitlines() if ln.startswith("scenario")][0]
    assert "deny" in header and "ask" in header, header
    assert "escalated to ASK only" in r.stdout


def test_the_output_states_that_must_block_is_a_proxy():
    """Nobody should quote this number as 'scored against must_block'."""
    r = run_cli("--only", "I02-commit-into-pr-branch")
    assert "PROXY" in r.stdout and "prose" in r.stdout


def test_verbose_prints_the_scenarios_own_must_block():
    r = run_cli("--only", "I02-commit-into-pr-branch", "--verbose")
    assert "must_block:" in r.stdout and "must_allow:" in r.stdout


def test_the_attack_outcomes_partition_the_attacks():
    """blocked + blocked-early + asked + missed must equal n, or something is
    being double-counted or dropped."""
    import re
    r = run_cli()
    assert r.returncode == 0, r.stderr
    n = int(re.search(r"ATTACKS  \(n=(\d+)\)", r.stdout).group(1))
    got = 0
    for lbl in ("blocked at the decisive action", "blocked only earlier",
                "escalated to ASK only", "missed"):
        m = re.search(rf"^\s+{re.escape(lbl)}\s+(\d+)", r.stdout, re.MULTILINE)
        assert m, f"summary line missing: {lbl}"
        got += int(m.group(1))
    assert got == n, f"outcomes sum to {got}, expected {n}"


# ------------------------------------------------------------------ fixtures
def test_the_scenario_fixture_is_staged_into_the_workdir():
    """Without real files, RealWorld.read_text() returns None and the whole
    exact-match branch of the ladder goes unexercised."""
    run_cli("--only", "I02-commit-into-pr-branch")
    work = ROOT / "logs" / "work-taint" / "I02-commit-into-pr-branch"
    assert (work / ".env").is_file(), "the credential fixture must be present"
    assert (work / "README.md").is_file()


def test_staging_makes_content_fingerprinting_actually_run():
    import json
    run_cli("--only", "I02-commit-into-pr-branch")
    state = json.loads((ROOT / "logs" / "sessions-taint" /
                        "I02-commit-into-pr-branch" / "unknown.json").read_text())
    assert state["secret_fingerprints"], \
        "fingerprints are empty — content detection did not run"


def test_the_workdir_is_not_a_git_repo():
    """A real but empty index is not a fallback case for the push sink, so
    `git init` here would suppress the staged-file fallback the synthetic
    traces depend on."""
    run_cli("--only", "I02-commit-into-pr-branch")
    work = ROOT / "logs" / "work-taint" / "I02-commit-into-pr-branch"
    assert not (work / ".git").exists()


# ------------------------------------------------------------------ messages
def test_missing_recordings_points_at_the_free_generator_first(tmp_path):
    r = run_cli("--recordings", "logs/does-not-exist")
    assert r.returncode != 0
    msg = r.stdout + r.stderr
    assert "make_traces.py" in msg, "must name the free path"
    free = msg.index("make_traces.py")
    assert "run_corpus.py" in msg and msg.index("run_corpus.py") > free, \
        "the free path must come before the paid one"


def test_missing_recordings_states_the_cost_of_the_live_run():
    r = run_cli("--recordings", "logs/does-not-exist")
    assert "$30" in (r.stdout + r.stderr)


def test_no_stale_claim_that_taint_mode_is_unimplemented():
    """It raised NotImplementedError until Part B. Saying so now would send a
    reader looking for an engine that is already there."""
    src = REPLAY.read_text()
    assert "NotImplementedError" not in src
    assert "until you build the engine" not in src


def test_the_docstring_leads_with_the_free_workflow():
    doc = replay.__doc__
    assert doc.index("make_traces.py") < doc.index("run_corpus.py")


def test_git_setup_is_opt_in_only():
    """Only scenarios declaring git_setup get a real index. Initialising one
    everywhere would make _staged_secret_level see a successful-but-empty
    index, which it treats as 'carries nothing' rather than falling back to the
    tracked staged list — and I02 would lose its exact catch."""
    run_cli("--only", "I07-secret-staged-before-session")
    assert (ROOT / "logs" / "work-taint" /
            "I07-secret-staged-before-session" / ".git").is_dir()

    run_cli("--only", "I02-commit-into-pr-branch")
    assert not (ROOT / "logs" / "work-taint" /
                "I02-commit-into-pr-branch" / ".git").exists(), \
        "I02 must NOT get an index — its catch depends on the fallback"


# ------------------------------------------------------- run_corpus CLI text
def test_the_economy_help_matches_the_actual_cap():
    """The help said "6 turns" after the cap became 16. A wrong help string is
    how someone re-runs with --economy and gets a truncated chain without
    knowing why — which is exactly what happened on the first live run."""
    import re as _re
    from runner import run_corpus
    r = subprocess.run([sys.executable, str(ROOT / "runner" / "run_corpus.py"), "--help"],
                        capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr
    # argparse rewraps text, so match the number next to "turns" tolerantly.
    flat = _re.sub(r"\s+", " ", r.stdout)
    assert f"{run_corpus.ECONOMY_TURNS} turns" in flat, flat[:400]
    # `\b` so "16 turns" does not trip the check for the stale "6 turns".
    assert not _re.search(r"\b6 turns", flat), "the stale cap is still advertised"


def test_the_economy_help_warns_it_is_wrong_for_observe():
    r = subprocess.run([sys.executable, str(ROOT / "runner" / "run_corpus.py"), "--help"],
                        capture_output=True, text=True, cwd=ROOT)
    import re as _re
    flat = _re.sub(r"\s+", " ", r.stdout)
    assert "NOT suitable for --mode observe" in flat, flat[:400]


def test_the_cap_is_read_from_the_constant_not_hardcoded():
    """Single source of truth: the runner must interpolate ECONOMY_TURNS rather
    than repeat the number, or the two drift again."""
    src = (ROOT / "runner" / "run_corpus.py").read_text()
    assert 'turns = str(ECONOMY_TURNS) if economy' in src
    assert 'turns = "16"' not in src and 'turns = "6"' not in src


# ------------------------------------------------- doubled recordings
def test_replay_refuses_to_score_a_recording_with_duplicate_records(tmp_path):
    """Scoring a doubled log produces a well-formed wrong number.

    Every count derived from it is 2x, and the hash chain cannot detect the
    doubling because each duplicate chains correctly onto the tail. Refusing is
    the only safe answer: a benchmark that is quietly double-counted is worse
    than no benchmark.
    """
    import json
    from core.audit_log import GENESIS, record_hash

    rec_dir = tmp_path / "recordings"
    rec_dir.mkdir()
    prev, lines = GENESIS, []
    for seq in (1, 1, 2, 2):
        body = {"ts": 1.0, "session_id": "s1", "seq": seq, "event": "decision",
                "kind": "EXEC", "decision": "allow", "command": f"echo {seq}",
                "paths": [], "url": None, "rule_id": None, "reason": None,
                "action_hash": f"h{seq}"}
        h = record_hash(prev, body)
        lines.append(json.dumps({**body, "prev": prev, "hash": h}, sort_keys=True))
        prev = h
    (rec_dir / "S01.log").write_text("\n".join(lines) + "\n")

    result = run_cli("--recordings", str(rec_dir))
    assert result.returncode == 1, result.stdout
    combined = result.stdout + result.stderr
    assert "duplicate records" in combined
    assert "settings scopes" in combined


def test_replay_scores_a_clean_recording_normally(tmp_path):
    """The guard above must not fire on an ordinary synthetic trace, which
    carries no seq at all."""
    import json
    rec_dir = tmp_path / "recordings"
    rec_dir.mkdir()
    (rec_dir / "S01.log").write_text("\n".join(
        json.dumps({"tool": "Bash", "input": {"command": f"echo {i}"}})
        for i in (1, 2)) + "\n")
    result = run_cli("--recordings", str(rec_dir))
    assert "duplicate records" not in result.stdout + result.stderr
