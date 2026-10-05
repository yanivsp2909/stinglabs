"""A derived log must never be able to pass as a recorded one.

OPTION E IN ONE SENTENCE: a redacted fixture's chain is recomputed over the
rewritten bytes, so it verifies — and attests only "unmodified since redaction".
Printing the plain OK a real session gets would let a reader conclude the SESSION
is attested, which is a WRONG answer rather than a missing one.

⚠ THE REFUSAL IS THE WHOLE SAFETY PROPERTY. Without it, option E is option A —
re-hash and hope nobody notices the chain now means something weaker. So it is
pinned here as a hard guarantee rather than left to the reviewer of a future
patch: `test_a_derived_log_can_never_produce_a_clean_OK` builds a redacted log,
runs the real verifier over it, and fails if the word OK appears as a verdict.

The second property is the two hashes. `command_sha256` ADDRESSES the sidecar;
`original_sha256` is PROVENANCE and is inert — unverifiable here by construction,
because the original bytes are deliberately destroyed. Two hashes with different
meanings is exactly where a future reader picks the wrong one, so the separation
is enforced structurally rather than by comment: nothing in core/ or runner/ ever
READS the provenance field, and a test fails if anything starts to.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from core import audit_log
from core.audit_log import (ORIGINAL_DIGEST_FIELD, REDACTION_MANIFEST,
                             is_derived, redaction_manifest_for, verify_chain)

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "logs" / "live-fixture"


def run_verifier(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "verify_log.py"), "--root", str(root)],
        capture_output=True, text=True, cwd=str(ROOT))
    return proc.returncode, proc.stdout + proc.stderr


def make_derived(tmp_path: Path) -> Path:
    """A minimal derived log whose chain is intact over its own bytes."""
    out = tmp_path / "derived"
    out.mkdir()
    prev = audit_log.GENESIS
    lines = []
    for seq in (1, 2):
        body = audit_log.build_body(
            session_id="s1", seq=seq, event="decision", kind="EXEC",
            decision="ALLOW", rule_id=None, reason="", paths=(),
            command=f"git status {seq}", ts=1000.0 + seq)
        record = dict(body)
        record["prev"] = prev
        record["hash"] = audit_log.record_hash(prev, body)
        prev = record["hash"]
        lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
    (out / f"s1{audit_log.LOG_SUFFIX}").write_text("\n".join(lines) + "\n")
    (out / REDACTION_MANIFEST).write_text(json.dumps({"derived": True}) + "\n")
    return out


# ============================================== the refusal, as a hard guarantee
def test_a_derived_log_can_never_produce_a_clean_OK(tmp_path):
    """THE LOAD-BEARING TEST. If this passes for the wrong reason, E is A.

    The log below has a genuinely intact chain — `verify_chain` says so on the
    line above — so the verifier has every excuse to print OK. The presence of
    the manifest must override that and nothing else may.
    """
    out = make_derived(tmp_path)
    log = out / f"s1{audit_log.LOG_SUFFIX}"
    ok, _bad, _detail = verify_chain(log)
    assert ok, "precondition: the derived chain must actually verify"
    assert is_derived(log)

    code, text = run_verifier(out)
    verdicts = [line.strip().split()[0] for line in text.splitlines()
                if line.startswith("  ")]
    assert "OK" not in verdicts, (
        f"a derived log produced a clean OK — option E has collapsed into "
        f"option A:\n{text}")
    assert "REDACTED" in verdicts, text
    assert code == 0, "an intact derived chain is not a failure"


def test_the_derived_report_says_what_it_does_and_does_not_attest(tmp_path):
    _code, text = run_verifier(make_derived(tmp_path))
    lowered = text.lower()
    assert "derived" in lowered
    assert "provenance not verifiable" in lowered
    assert "redaction is not tampering" in lowered


def test_the_summary_line_does_not_launder_the_distinction(tmp_path):
    """One line at the end saying "1 logs verified" would undo the per-log
    refusal for anyone who reads only the last line."""
    _code, text = run_verifier(make_derived(tmp_path))
    tail = text.strip().splitlines()[-1].lower()
    assert "redacted" in tail, tail
    assert "0 recorded log(s) verified" in tail, tail


def test_a_derived_log_with_a_real_break_is_still_BROKEN(tmp_path):
    """Declaring a log derived must not become a way to silence the alarm."""
    out = make_derived(tmp_path)
    log = out / f"s1{audit_log.LOG_SUFFIX}"
    lines = log.read_text().splitlines()
    record = json.loads(lines[1])
    record["command"] = "git push --force"          # edited in place, hash stale
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n")

    code, text = run_verifier(out)
    assert "BROKEN" in text, text
    assert code == 1, "a broken derived chain must still fail"


def test_the_real_fixture_is_declared_and_reports_REDACTED():
    """THE MISREPORT THIS FIXES. Before the manifest, two of three vendored logs
    printed BROKEN — a false alarm on the one signal that is supposed to mean
    tampering, and an alarm that is routinely wrong trains the reader to ignore
    it."""
    if not FIXTURE.is_dir():
        pytest.skip("no vendored fixture")
    assert redaction_manifest_for(FIXTURE / "x.log.jsonl").is_file()
    code, text = run_verifier(FIXTURE)
    assert "BROKEN" not in text, text
    assert "REDACTED" in text, text
    assert code == 0, text


# ============================================== the two hashes stay separate
def test_the_manifest_records_what_produced_it():
    if not FIXTURE.is_dir():
        pytest.skip("no vendored fixture")
    manifest = json.loads((FIXTURE / REDACTION_MANIFEST).read_text())
    assert manifest["derived"] is True
    assert len(manifest["substitutions_sha256"]) == 64
    assert manifest["sessions"]
    assert "attests" in manifest and "unmodified SINCE REDACTION" in manifest["attests"]


def test_provenance_is_carried_on_the_records():
    if not FIXTURE.is_dir():
        pytest.skip("no vendored fixture")
    carrying = 0
    for log in FIXTURE.glob("*.jsonl"):
        for line in log.read_text(errors="replace").splitlines():
            if line.strip() and ORIGINAL_DIGEST_FIELD in json.loads(line):
                carrying += 1
    assert carrying > 100, f"only {carrying} records carry provenance"


def test_nothing_in_core_or_runner_can_even_see_the_provenance_field():
    """THE STRUCTURAL GUARANTEE, and the reason it is structural.

    `original_sha256` must never address a sidecar or stand in for
    `command_sha256`. A comment saying so is worth little against a future reader
    who has two hashes in front of them and picks one. So the addressing code
    simply never mentions the field: it is written by `tools/redact_logs.py` and
    read by nothing.

    Counting the string would count the constant and its own docstring, so this
    asserts the property that matters instead: NOTHING IN core/ OR runner/ READS
    THE FIELD. Naming it is fine; looking it up is not.
    """
    reads = re.compile(
        r"""\.get\(\s*(?:ORIGINAL_DIGEST_FIELD|["']original_sha256["'])"""
        r"""|\[\s*(?:ORIGINAL_DIGEST_FIELD|["']original_sha256["'])\s*\]""")
    offenders = []
    for directory in ("core", "runner"):
        for path in sorted((ROOT / directory).rglob("*.py")):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if reads.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, (
        f"the addressing path reads the provenance digest: {offenders}")


def test_the_redaction_tool_is_the_only_writer():
    """And it writes it through the constant, so the two never get swapped."""
    tool = (ROOT / "tools" / "redact_logs.py").read_text()
    assert "audit_log.ORIGINAL_DIGEST_FIELD" in tool
    assert '"original_sha256"' not in tool, "write it via the constant, not a literal"


def test_a_clipped_record_without_a_sidecar_gets_no_digest_at_all():
    """THE TRAP THE REDACTION TOOL MUST NOT FALL INTO.

    Hashing the redacted CLIPPED text would make `stored_command_is_whole`'s
    first rung — a matching digest PROVES wholeness — return True for a command
    missing most of itself. Null is the honest answer.
    """
    if not FIXTURE.is_dir():
        pytest.skip("no vendored fixture")
    lying = []
    for log in FIXTURE.glob("*.jsonl"):
        for line in log.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if not record.get("command_clipped"):
                continue
            if audit_log.stored_command_is_whole(record) is not False:
                lying.append(record.get("seq"))
    assert not lying, f"clipped records claiming wholeness: {lying[:10]}"


def test_the_leak_check_covers_every_file_the_tool_writes(tmp_path):
    """THE GAP OPTION E OPENED. The check globbed `*.jsonl`, which was right
    until this tool started vendoring sidecar payloads — 73 files of real command
    text, holding exactly the long commands most likely to contain a path or an
    address, none of it checked. It happened to be clean; that is luck.

    A planted identifier in a sidecar must fail the run.
    """
    from tools import redact_logs

    # ⚠ PLANT AN IDENTIFIER THIS MACHINE ACTUALLY HAS. A hardcoded username is
    # planted-but-not-looked-for anywhere except its author's laptop, so this
    # asserted "the checker catches a leak" while proving only "the checker
    # catches THIS name" — and it failed on CI for that reason, not for a real
    # gap in the sidecar scan it exists to pin.
    identifiers = [v for v in redact_logs._derived_identities() if "@" not in v]
    if not identifiers:
        pytest.skip("nothing derived on this machine, so there is no identity "
                     "the checker is looking for and nothing to plant")

    out = tmp_path / "out"
    (out / "s1.log.jsonl.commands").mkdir(parents=True)
    (out / "s1.log.jsonl").write_text('{"event":"decision","seq":1}\n')
    (out / "s1.log.jsonl.commands" / "deadbeef").write_text(
        f"cd /Users/{identifiers[0]}/secret && ls\n")
    assert redact_logs.main(["--out", str(out), "--check"]) == 1
