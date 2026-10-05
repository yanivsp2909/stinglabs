"""Self-consistency: the same rule, re-presented blind, with different examples.

⚠ IT WAS CLAIMED THIS COULD NOT BE DONE, AND THAT CLAIM WAS WRONG. The reasoning
was that the rule unit "folds in no re-asks", so there is nothing to re-present.
But the unit being a RULE is exactly what makes it possible: the same rule can be
shown again with DIFFERENT worked examples, which is a new judgement about the
same question rather than a memory test.

⚠ WHAT IT MEASURES IS AGREEMENT, NOT CORRECTNESS. A rule judged the same way
twice from different examples is at least stable. A rule that flips means the
single-judgement precision figure has no error bar worth quoting — it does not
mean the second answer is the right one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools import label_prompts as lp


def store_with(labels):
    return {"version": 2, "seed": 7,
            "labels": {lp.rule_key(r): {"rule_id": r, "unit": "rule",
                                          "volume": v,
                                          "history": [{"at": "t", "label": l}]}
                        for r, v, l in labels}}


def records_for(rule, n, start=0):
    """⚠ EACH RECORD NEEDS A DISTINCT command_sha256. `rule_groups` dedupes by
    it — the first version of this fixture omitted it, all 40 records collapsed
    to one member, and the test failed on its own data rather than on the code."""
    return [{"rule_id": rule, "decision": "ASK", "event": "decision",
              "seq": start + i, "ts": 1000.0 + start + i,
              "command": f"cmd {rule} {start + i}",
              "command_sha256": f"{abs(hash((rule, start + i))):064x}"[:64],
              "session_id": "s", "_log_path": Path("/x/log.jsonl"), "_log": Path("/x/log.jsonl")}
            for i in range(n)]


def test_recheck_selects_a_quarter_of_judged_rules():
    rules = [(f"untrusted_expected:sink{i}", 10, "not_worth") for i in range(20)]
    store = store_with(rules)
    records = []
    for rule, n, _ in rules:
        records += records_for(rule, n)
    queue = lp.recheck_queue(records, store)
    assert len(queue) == 5, f"expected 25% of 20, got {len(queue)}"
    assert all(meta["recheck"] for _, meta, _, _ in queue)


def test_recheck_only_offers_rules_that_were_already_judged():
    store = store_with([("a:b", 10, "not_worth")])
    records = records_for("a:b", 10) + records_for("never:judged", 10)
    offered = {meta["rule_id"] for _, meta, _, _ in lp.recheck_queue(records, store)}
    assert offered == {"a:b"}


def test_recheck_shows_different_examples():
    """⚠ THE SAME EXAMPLES WOULD MAKE IT A MEMORY TEST — it would measure
    whether the judge remembers, not whether the judgement is stable."""
    records = records_for("a:b", 40)
    store = store_with([("a:b", 40, "not_worth")])
    first = {r["seq"] for r in lp._examples(records)}
    second = {r["seq"] for _, _, shown, _ in lp.recheck_queue(records, store)
               for r in shown}
    assert first and second
    assert not (first & second), f"the same examples were re-shown: {first & second}"


def test_a_group_too_small_for_a_disjoint_slice_reuses_and_does_not_pretend():
    """An honest weaker measurement rather than a fabricated stronger one."""
    records = records_for("a:b", 3)
    store = store_with([("a:b", 3, "not_worth")])
    shown = [r for _, _, s, _ in lp.recheck_queue(records, store) for r in s]
    assert len(shown) == 3


def test_recheck_uses_a_different_random_stream_than_the_first_pass():
    """Otherwise the "random 25%" would be the same 25% the first ordering
    already favoured."""
    import inspect
    source = inspect.getsource(lp.recheck_queue)
    assert 'seed", SEED) + 1' in source or "SEED) + 1" in source


def test_agreement_reports_that_it_cannot_be_computed_yet():
    """⚠ NEVER INVENTS A JUDGEMENT. With nothing re-judged it says so, and says
    the precision figure has no error bar until someone runs recheck."""
    result = lp.agreement(store_with([("a:b", 10, "not_worth")]))
    assert result["rules_rejudged"] == 0
    assert result["agreement"] is None
    assert "no error bar" in result["note"]


def test_agreement_counts_a_flip_and_a_match():
    store = store_with([("a:b", 10, "not_worth"), ("c:d", 5, "not_worth")])
    store["labels"]["rule:a:b"]["history"].append({"at": "t2", "label": "not_worth"})
    store["labels"]["rule:c:d"]["history"].append({"at": "t2", "label": "worth"})
    result = lp.agreement(store)
    assert result["rules_rejudged"] == 2
    assert result["agreed"] == 1
    assert result["disagreed"] == 1
    assert result["agreement"] == 0.5
    assert result["note"] == ""


def test_the_real_label_file_has_no_second_judgement_yet():
    """The state of the open gate, asserted so it cannot be quietly forgotten."""
    path = Path(__file__).parent.parent / "labels" / "prompt_labels.json"
    store = json.loads(path.read_text(encoding="utf-8"))
    assert lp.agreement(store)["rules_rejudged"] == 0, (
        "someone ran recheck — update the precision claim and this test")
