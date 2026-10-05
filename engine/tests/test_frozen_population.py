"""A frozen population is pinned, private, never committed, and read only once
it is proven to be the pinned one. tests/frozen_population.py, docs/PARALLEL.md.

Every drift case runs against a small real population built here (chained
records, a real snapshot, a real pin), so the checks are exercised whether or
not this machine holds the frozen copy the suite's own test reads.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess

import pytest

from core.audit_log import append, build_body
from runner import blast_radius
from tests import frozen_population as fp

NAME = "p-v1"


def _population(tmp_path, commands=("git status", "ls -la", "git log -1")):
    """(frozen dir, pins dir) holding one real population, pinned."""
    live = tmp_path / "live"
    for seq, command in enumerate(commands, start=1):
        append("s1", build_body("s1", seq=seq, event="decision", decision="ALLOW",
                                kind="EXEC", command=command, cwd="/work",
                                ts=1000.0 + seq), root=live)
    frozen, pins = tmp_path / "frozen", tmp_path / "pins"
    pins.mkdir()
    blast_radius.snapshot([live], frozen / NAME)
    manifest = (frozen / NAME / blast_radius.MANIFEST).read_bytes()
    (pins / f"{NAME}.json").write_text(json.dumps({
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "records": len(commands), "taken": "2026-09-27"}), encoding="utf-8")
    return frozen, pins


def test_every_pin_holds_no_log_content():
    """A pin is committed; the population is not. So a pin carries the hash,
    the count and the date, and nothing a command could hide in."""
    pins = sorted(fp.PINS.glob("*.json"))
    assert pins, "no pinned population: this check would pass over nothing"
    for path in pins:
        pin = json.loads(path.read_text(encoding="utf-8"))
        assert set(pin) == fp.PIN_KEYS, (path.name, sorted(pin))
        assert re.fullmatch(r"[0-9a-f]{64}", pin["manifest_sha256"]), path.name
        assert isinstance(pin["records"], int) and pin["records"] > 0, path.name
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", pin["taken"]), path.name


def test_a_frozen_population_is_never_committed():
    if not (fp.ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    for path in sorted(fp.PINS.glob("*.json")):
        inside = f"logs/frozen/{path.stem}/{blast_radius.MANIFEST}"
        ignored = subprocess.run(["git", "check-ignore", "-q", inside], cwd=fp.ROOT)
        assert ignored.returncode == 0, f"{inside} is not ignored by git"
    tracked = subprocess.run(["git", "ls-files", "logs/frozen"], cwd=fp.ROOT,
                             capture_output=True, text=True, check=True).stdout
    assert tracked == "", f"tracked under logs/frozen/: {tracked.split()}"


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_a_frozen_population_on_disk_is_owner_only():
    """The copy holds real commands, 0600 in 0700 like the logs it came from."""
    if not fp.FROZEN.exists():
        pytest.skip("no frozen population on this machine")
    modes = {path: path.stat().st_mode & 0o777
             for path in [fp.FROZEN, *fp.FROZEN.rglob("*")]}
    opened = [f"{path} {oct(mode)}" for path, mode in modes.items() if mode & 0o077]
    assert not opened, opened


def test_an_absent_population_skips_and_says_how_to_get_it(tmp_path):
    with pytest.raises(pytest.skip.Exception) as skipped:
        fp.records("guard-selfmod-v1", frozen=tmp_path / "frozen")
    message = str(skipped.value)
    assert "never committed" in message and "cp -Rp" in message
    assert "runner/blast_radius.py snapshot" in message


def test_a_population_matching_its_pin_is_read(tmp_path):
    frozen, pins = _population(tmp_path)
    found = fp.records(NAME, frozen=frozen, pins=pins)
    assert [r["command"] for r in found] == ["git status", "ls -la", "git log -1"]


def test_a_file_changed_after_freezing_fails_loudly(tmp_path):
    frozen, pins = _population(tmp_path)
    log = next((frozen / NAME).rglob("*.log.jsonl"))
    log.write_text(log.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(pytest.fail.Exception,
                       match="the frozen population changed; make v2 on purpose"):
        fp.records(NAME, frozen=frozen, pins=pins)


def test_another_snapshot_under_the_pinned_name_fails_loudly(tmp_path):
    """Same logs, taken again: a different manifest (it records when), so it is
    not the pinned population, however alike its records are."""
    frozen, pins = _population(tmp_path)
    again = tmp_path / "again"
    blast_radius.snapshot([tmp_path / "live"], again / NAME)
    with pytest.raises(pytest.fail.Exception, match="MANIFEST sha256"):
        fp.records(NAME, frozen=again, pins=pins)


def test_a_record_count_that_disagrees_with_the_pin_fails_loudly(tmp_path):
    frozen, pins = _population(tmp_path)
    pin = json.loads((pins / f"{NAME}.json").read_text(encoding="utf-8"))
    pin["records"] += 1
    (pins / f"{NAME}.json").write_text(json.dumps(pin), encoding="utf-8")
    with pytest.raises(pytest.fail.Exception, match="4 pinned|pinned 4"):
        fp.records(NAME, frozen=frozen, pins=pins)
