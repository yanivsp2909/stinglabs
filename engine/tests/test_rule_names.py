"""Every rule id the engine can emit has a name, and the ids themselves never move.

⚠ THIS FILE IS THE ANTI-DRIFT MECHANISM, not the table. A translation table is
easy; a table that stays true is the whole problem. So the ids are extracted
from `core/engine.py`'s SOURCE and checked against the map — a rule added
without a name fails here, at the moment it is added, rather than showing a raw
id in a dashboard three weeks later.

⚠ AND THE RULE IDS DO NOT CHANGE. They are the standing live baseline's key and
~40 assertions depend on them. What this pass changed is only what a HUMAN
reads.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from core import rule_names
from tests import engine_source
from private_fixtures import needs_live_baseline  # noqa: E402


def emitted_rule_ids() -> set:
    """Every rule id literal the engine can put in a Verdict, from the source
    of every part of it (tests/engine_source.py).

    Reads the THIRD argument of every `Verdict(...)` call. f-strings are kept as
    their literal prefix — `f"secret_exact:{sink}"` yields the family
    `secret_exact`, which is what the map is keyed on.
    """
    found = set()
    for node in (n for tree in engine_source.trees().values() for n in ast.walk(tree)):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Verdict"):
            continue
        if len(node.args) < 3:
            continue
        arg = node.args[2]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            found.add(arg.value)
        elif isinstance(arg, ast.JoinedStr):
            head = arg.values[0]
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                found.add(head.value.rstrip(":"))
    return {f for f in found if f}


def test_every_rule_the_engine_emits_has_a_name():
    """⚠ THE MECHANISM. A new rule with no entry fails HERE, not in a dashboard."""
    missing = sorted(rid for rid in emitted_rule_ids()
                      if rid.partition(":")[0] not in rule_names.RULE_FAMILIES)
    assert not missing, (
        f"rule id(s) with no entry in core/rule_names.RULE_FAMILIES: {missing}")


def test_the_map_names_no_rule_the_engine_cannot_emit():
    """Drift in the other direction: a family kept after its rule was removed
    describes something that no longer exists, which is a different way of
    being confidently wrong."""
    emitted = {rid.partition(":")[0] for rid in emitted_rule_ids()}
    # `fallback` is emitted by `fallback_verdict`, which this scan does not
    # reach because it is not a literal third argument there.
    extra = sorted(set(rule_names.RULE_FAMILIES) - emitted
                    - {"fallback", "degraded_no_state"} - rule_names.RETIRED)
    assert not extra, (
        f"named but never emitted, and not marked RETIRED: {extra}. "
        f"Either the engine stopped emitting it — in which case add it to "
        f"RETIRED so readers of stored history keep the name — or the entry "
        f"describes something that never existed.")


def test_a_retired_rule_says_it_is_retired():
    """⚠ DELETING IT WOULD BE WORSE. `untrusted_local:git_commit` appears 28
    times in runner/live_baseline.json; a reader of that history needs the name.
    But a live-looking entry for a rule that cannot fire is its own lie."""
    for family in rule_names.RETIRED:
        assert "RETIRED" in rule_names.RULE_FAMILIES[family][0], family
        assert "Retired:" in rule_names.RULE_FAMILIES[family][1], family


def test_every_sink_the_engine_returns_has_a_meaning():
    """The suffix half. `check_sinks` returns these, and they are composed into
    a rule id, so an unnamed sink produces a half-translated sentence."""
    source = engine_source.text()
    sinks = set(re.findall(r'(?:return|yield) "([a-z_]+)", (?:span\(\)|argv_span|fact)', source))
    assert sinks, "no sink return found: the scan is reading the wrong source"
    missing = sorted(s for s in sinks if s not in rule_names.SINK_MEANINGS)
    assert not missing, (
        f"sink(s) with no entry in core/rule_names.SINK_MEANINGS: {missing}")


# ------------------------------------------------------- the ids do not move

@needs_live_baseline
def test_the_rule_ids_themselves_are_unchanged():
    """⚠ THE STANDING BASELINE'S KEY. Renaming a rule id would invalidate
    runner/live_baseline.json and ~40 assertions. This pass changed what a human
    reads and nothing else."""
    import json

    baseline = Path(__file__).parent.parent / "runner" / "live_baseline.json"
    accepted = json.loads(baseline.read_text(encoding="utf-8"))["accepted"]
    keyed = set()
    for entry in accepted.values():
        for side in ("recorded", "current"):
            value = (entry.get(side) or {}).get("rule_id")
            if value:
                keyed.add(value)
    emitted = emitted_rule_ids()
    for rule_id in sorted(k for k in keyed if k):
        family = rule_id.partition(":")[0]
        assert family in rule_names.RULE_FAMILIES, (
            f"the baseline references {rule_id} and nothing names it — a reader "
            f"of stored history would get a raw id with no way to look it up")


# ---------------------------------------------------------------- behaviour

def test_a_sink_is_never_described_as_a_destination():
    """⚠ THE BUG THIS MODULE EXISTS FOR. Two branches substituted a sink name
    into a "destination" slot and printed `what this sends to 'git push'`. Every
    meaning is a PREDICATE — a thing the action does — so it can only be dropped
    into a sentence about the action."""
    for sink, meaning in rule_names.SINK_MEANINGS.items():
        assert meaning.startswith(("this ", "a ", "the ")), (sink, meaning)
        assert not meaning.startswith(sink.replace("_", " ")), (sink, meaning)


def test_an_unknown_rule_returns_the_id_rather_than_a_guess():
    described = rule_names.describe("some_rule_invented_next_year:git_push")
    assert described["title"] == "some_rule_invented_next_year:git_push"
    assert "no description yet" in described["why"]


def test_describe_never_raises():
    for value in (None, "", "x", "a:b:c", 42, ":", "untrusted_local:"):
        assert rule_names.describe(value)["title"] is not None


def test_a_real_rule_reads_as_english():
    described = rule_names.describe("untrusted_local:git_commit")
    assert "Untrusted session" in described["title"]
    assert "into history" in described["title"]
    assert "git_commit" not in described["title"]
    assert described["rule_id"] == "untrusted_local:git_commit"


# ------------------------------------------------- the export, for other repos

def test_the_export_produces_what_a_consumer_needs(tmp_path):
    """⚠ A COPY THAT CANNOT DRIFT, BECAUSE NOBODY TYPES IT. The panel and the
    collector are separate repos and cannot import this one; a hand-kept list
    there is a list that disagrees with the ids it describes."""
    import subprocess
    import sys

    out = tmp_path / "rule_names.json"
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent.parent / "tools" /
                              "export_rule_names.py"), "--out", str(out)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    import json
    exported = json.loads(out.read_text())
    assert exported["families"]["untrusted_local"]["title"]
    assert exported["sinks"]["git_commit"]
    assert exported["generated_from"] == "core/rule_names.py"
    assert "do not hand-edit" in exported["note"].lower()
