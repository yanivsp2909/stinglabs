"""The labelling tool — the parts of it that can be wrong without looking wrong.

This tool collects a judgement that only one person can supply and that nobody
will supply twice. So the failure that matters is not a crash; it is a run that
completes and produces a number meaning something other than what it says.

Four such failures, one test group each:

    the key      a label pointing at a different action than the one judged
    durability   a closed terminal costing the whole sitting
    order        a shuffle that is not reproducible, so resuming is a new run
    the report   a precision figure that counts what it says it excludes
"""
from __future__ import annotations

import hashlib
import json

import pytest

from tools import label_prompts as lp

FIXTURE = lp.FIXTURE_ROOT


def rec(**over):
    base = {"kind": "EXEC", "decision": "ASK", "rule_id": "untrusted_local:git_commit",
            "command": "git commit -m x", "session_id": "s", "seq": 1, "paths": []}
    return {**base, **over}


# ------------------------------------------------------------------- the key

def test_the_key_is_not_the_sequence_number():
    """`seq` is a position in a file that grows; the same action is a different
    seq in the live log and in the fixture prefix."""
    a = lp.key_for(rec(seq=1, command_sha256="abc"))
    b = lp.key_for(rec(seq=999, command_sha256="abc"))
    assert a == b


def test_the_key_prefers_the_provenance_digest_over_the_redacted_one():
    """THE WHOLE REASON THE KEY IS NOT `command_sha256`.

    `redact_logs.py` re-addresses every record onto its REDACTED bytes, so a
    fixture record's `command_sha256` is the digest of text that never ran.
    `original_sha256` is the digest of what did.
    """
    fixture_side = rec(command_sha256="digest-of-redacted",
                       original_sha256="digest-of-real")
    live_side = rec(command_sha256="digest-of-real")
    assert lp.key_for(fixture_side) == lp.key_for(live_side) == "cmd:digest-of-real"


def test_a_pathless_action_keys_on_a_home_normalised_path():
    """WRITE and EDIT have no command, so there is no digest to key on — and the
    fixture renamed the home directory, so the raw path disagrees between the two
    populations for the same action."""
    fixture_side = rec(kind="WRITE", command=None, command_sha256=None,
                       paths=["/Users/dev/sting/x/core.py"])
    live_side = rec(kind="WRITE", command=None, command_sha256=None,
                    paths=["/Users/someone-else/sting/x/core.py"])
    assert lp.key_for(fixture_side) == lp.key_for(live_side)
    assert lp.key_for(fixture_side).startswith("act:")


def test_different_actions_do_not_collide():
    a = lp.key_for(rec(kind="WRITE", command=None, command_sha256=None,
                       paths=["/Users/d/a.py"]))
    b = lp.key_for(rec(kind="WRITE", command=None, command_sha256=None,
                       paths=["/Users/d/b.py"]))
    assert a != b


def test_redacting_a_record_does_not_move_its_key():
    """⚠ THE PROPERTY THE LIVE-LOG COMPARISON WAS STANDING IN FOR, TESTED
    DIRECTLY — and the reason that comparison is gone is in the next test down.

    `redact_logs.py` re-addresses a fixture record onto its redacted bytes, so a
    fixture `command_sha256` digests text that never ran. If `key_for` used it,
    a label collected against the fixture would be filed under a key the live
    log does not have, and the whole labelling exercise would measure nothing.

    This is the mechanism, not a sample of it: the real substitution list, the
    real key function, and a control showing the naive key DOES move — so the
    test cannot pass by both sides being empty.
    """
    from tools import redact_logs

    # ⚠ THE IDENTIFIER COMES FROM THE MACHINE. Hardcoding one made this pass on
    # the author's laptop and fail on every runner, for a reason that has
    # nothing to do with keys moving under redaction — which is what it tests.
    identifiers = [v for v in redact_logs._derived_identities() if "@" not in v]
    if not identifiers:
        pytest.skip("nothing derived on this machine, so no command in this "
                     "test is redacted and the control below would be vacuous")
    ran = f"cd /Users/{identifiers[0]}/src/my-project && pytest -q"
    original = hashlib.sha256(ran.encode("utf-8")).hexdigest()
    published = redact_logs.redact(ran)
    assert published != ran, (
        "the substitution list no longer touches this command, so the control "
        "below proves nothing — pick a command it does redact")

    live = rec(command=ran, command_sha256=original)
    fixture = rec(command=published,
                   command_sha256=hashlib.sha256(published.encode()).hexdigest(),
                   original_sha256=original)

    assert lp.key_for(fixture) == lp.key_for(live)
    # The control: the key this replaced would have moved, for every record
    # redaction touched. Measured when that was found: 132 of 134.
    assert fixture["command_sha256"] != live["command_sha256"]


def test_the_key_survives_a_redaction_that_changes_nothing():
    """A record redaction did not touch has no `original_sha256` to fall back
    on, and must still key identically. That is the half of the population the
    naive key got right, and it must not break while fixing the other half."""
    untouched = "pytest -q"
    digest = hashlib.sha256(untouched.encode("utf-8")).hexdigest()
    assert lp.key_for(rec(command=untouched, command_sha256=digest)) == \
        lp.key_for(rec(command=untouched, command_sha256=digest,
                        original_sha256=digest))


@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_the_fixture_prompt_keys_are_all_provenance_digests():
    """⚠ THIS REPLACED A TEST THAT READ `~/.sting/dogfood`, AND THE REASON IS
    WORTH MORE THAN THE TEST WAS.

    The old assertion was `every fixture prompt key appears in the live log`. It
    was a real measurement once — 134 of 134 under this key, 2 of 134 under the
    naive one — but it depended on a directory OUTSIDE the repository that
    nothing here owns: `~/.sting/dogfood` grows with whatever the developer
    does, rotates, and gets tidied. It was emptied by hand, and the test began
    reporting `60 fixture prompts have no live counterpart` — a failure with
    nothing wrong with the code, in a suite where a failure is supposed to mean
    something.

    **A test that fails because someone tidied their home directory is a test
    that gets ignored**, and an ignored test in a suite of 2000 is worse than a
    missing one: it trains everybody to read red as noise. Worse, it could not
    have failed for the right reason either — the live log has moved on from the
    prefix the fixture was cut from, so the population it compared against was
    never the one the docstring described.

    What is asserted instead is a property of the FIXTURE ALONE, in the repo,
    deterministic: every prompt in it carries the provenance digest that makes
    its key match the log it came from. The mechanism itself is covered by
    `test_redacting_a_record_does_not_move_its_key` above, hermetically.
    """
    fx = lp.prompts(lp.load_records([FIXTURE]))
    assert fx, "no fixture prompts — this test would pass vacuously"
    without = [r for r in fx if not r.get("original_sha256")
                and r.get("command_sha256")]
    assert not without, (
        f"{len(without)} fixture prompts carry a redacted digest and no "
        f"original_sha256, so their keys cannot match the live log")


# ----------------------------------------------------------------- durability

def test_a_label_is_on_disk_before_the_next_question(tmp_path, monkeypatch):
    """190 judgements lost to a closed terminal means the measurement never gets
    made a second time."""
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    store = {"version": 1, "seed": 1, "labels": {}}
    store["labels"]["cmd:x"] = {"rule_id": "r", "decision": "ASK",
                                "history": [{"label": lp.WORTH, "at": None}]}
    lp.save_labels(store)
    assert json.loads((tmp_path / "l.json").read_text())["labels"]["cmd:x"]["history"] \
        == [{"label": lp.WORTH, "at": None}]


def test_the_labels_file_never_contains_a_command(tmp_path, monkeypatch):
    """It is committed. The key is a one-way digest precisely so the file does
    not need a redaction pass of its own."""
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    store = {"version": 1, "seed": 1, "labels": {
        lp.key_for(rec(command_sha256="d")): {
            "rule_id": "untrusted_local:git_commit", "decision": "ASK",
            "history": [{"label": lp.NOISE, "at": None}]}}}
    lp.save_labels(store)
    text = (tmp_path / "l.json").read_text()
    assert "git commit -m x" not in text
    assert "/Users/" not in text


# ---------------------------------------------------------------------- order

@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_the_queue_is_the_same_run_when_you_come_back_to_it():
    records = lp.load_records([FIXTURE])
    store = {"version": 1, "seed": 7, "labels": {}}
    first = [k for k, _m, _e, _r in lp.queue(records, store, "prompt")]
    again = [k for k, _m, _e, _r in lp.queue(records, store, "prompt")]
    assert first == again


@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_the_queue_is_shuffled_not_chronological():
    """Log order groups a session's near-identical commits together, and the
    answer to the fourteenth is contaminated by the thirteenth."""
    records = lp.load_records([FIXTURE])
    store = {"version": 1, "seed": 7, "labels": {}}
    queued = [k for k, _m, _e, _r in lp.queue(records, store, "prompt")]
    chronological = []
    for r in lp.prompts(records):
        if lp.judgeable(r) and lp.key_for(r) not in chronological:
            chronological.append(lp.key_for(r))
    assert queued != chronological
    assert sorted(queued) == sorted(chronological)


@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_already_judged_items_come_back_to_measure_the_judge():
    records = lp.load_records([FIXTURE])
    keys = [lp.key_for(r) for r in lp.prompts(records) if lp.judgeable(r)]
    store = {"version": 1, "seed": 7,
             "labels": {k: {"rule_id": "r", "decision": "ASK",
                            "history": [{"label": lp.WORTH, "at": None}]} for k in keys}}
    q = lp.queue(records, store, "prompt")
    assert q, "everything judged, so nothing came back — drift becomes unmeasurable"
    assert all(rep for _k, _m, _e, rep in q)


# --------------------------------------------------------------------- report

def test_cant_tell_is_excluded_from_precision_not_counted_as_noise(capsys):
    store = {"labels": {
        "a": {"rule_id": "r", "decision": "ASK", "history": [{"label": lp.WORTH, "at": None}]},
        "b": {"rule_id": "r", "decision": "ASK", "history": [{"label": lp.NOISE, "at": None}]},
        "c": {"rule_id": "r", "decision": "ASK", "history": [{"label": lp.UNSURE, "at": None}]},
        "d": {"rule_id": "r", "decision": "ASK", "history": [{"label": lp.UNSURE, "at": None}]}}}
    lp.report(store)
    out = capsys.readouterr().out
    assert "precision 1/2 = 50.0%" in out, out    # not 1/4, and not 1/3
    assert "can't tell 2" in out, out


def test_the_latest_answer_wins_so_a_re_ask_is_a_correction(capsys):
    store = {"labels": {"a": {"rule_id": "r", "decision": "ASK",
                              "history": [{"label": lp.WORTH, "at": None}, {"label": lp.NOISE, "at": None}]}}}
    lp.report(store)
    out = capsys.readouterr().out
    assert "worth 0" in out and "not worth 1" in out, out


def test_disagreement_is_reported_because_it_bounds_the_precision(capsys):
    store = {"labels": {
        "a": {"rule_id": "r", "decision": "ASK", "history": [{"label": lp.WORTH, "at": None}, {"label": lp.NOISE, "at": None}]},
        "b": {"rule_id": "r", "decision": "ASK", "history": [{"label": lp.WORTH, "at": None}, {"label": lp.WORTH, "at": None}]}}}
    lp.report(store)
    out = capsys.readouterr().out
    assert "answered more than once  2" in out, out
    assert "changed their mind     1" in out, out


def test_no_re_asks_says_so_rather_than_implying_a_perfect_judge(capsys):
    store = {"labels": {"a": {"rule_id": "r", "decision": "ASK",
                              "history": [{"label": lp.WORTH, "at": None}]}}}
    lp.report(store)
    assert "no error bar" in capsys.readouterr().out


def test_report_refuses_rather_than_printing_a_precision_of_nothing(capsys):
    assert lp.report({"labels": {}}) == 2
    assert "No labels yet" in capsys.readouterr().out


def test_gate_and_sink_split_a_rule_into_its_two_questions():
    assert lp.gate_and_sink("untrusted_local:git_commit") == \
        ("untrusted_local", "git_commit")
    assert lp.gate_and_sink("irreversible_action") == \
        ("irreversible_action", "(no sink)")
    assert lp.gate_and_sink(None) == ("(none)", "(no sink)")


# -------------------------------------------------------------------- context

@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_the_context_never_crosses_a_session_boundary():
    """Asserted on the RECORDS, not on the rendered text.

    A first version of this test compared 40-char command prefixes and failed on
    correct code: 92.8% of real commands begin `cd <root> &&`, so a prefix from
    another session legitimately appears in this one. String matching cannot tell
    "the same text" from "the same record" — the identity has to be checked
    against the objects.
    """
    records = lp.load_records([FIXTURE])
    ps = [r for r in lp.prompts(records) if lp.judgeable(r)]
    assert ps, "no prompts — vacuous"
    crossed = 0
    for r in ps:
        for b in lp.context_before(r, records):
            if b.get("session_id") != r.get("session_id"):
                crossed += 1
    assert crossed == 0, f"{crossed} context lines came from another session"


def test_the_flat_slice_really_would_cross_and_context_before_does_not():
    """CONSTRUCTED, because the fixture cannot show it.

    ⚠ On the vendored fixture the flat slice never crosses a session — no
    judgeable prompt lands within CONTEXT_LINES of a file boundary — so a test
    over the fixture alone would report a zero produced by the population rather
    than by the fix. Working rule 12: say which. This builds the boundary
    instead, so the property is checked rather than the corpus.
    """
    a = [{"session_id": "A", "seq": i, "kind": "EXEC", "command": f"a{i}",
          "decision": "ALLOW"} for i in range(6)]
    b = [{"session_id": "B", "seq": i, "kind": "EXEC", "command": f"b{i}",
          "decision": "ALLOW"} for i in range(3)]
    b[2]["decision"] = "ASK"
    records = a + b
    target = b[2]

    i = records.index(target)
    flat = records[max(0, i - lp.CONTEXT_LINES):i]
    assert any(r["session_id"] == "A" for r in flat), "the boundary was not built"

    ctx = lp.context_before(target, records)
    assert ctx == b[:2]
    assert all(r["session_id"] == "B" for r in ctx)


@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_the_context_is_the_actions_immediately_before_it():
    records = lp.load_records([FIXTURE])
    r = next(x for x in lp.prompts(records) if lp.judgeable(x)
             and len(lp.context_before(x, records)) == lp.CONTEXT_LINES)
    before = lp.context_before(r, records)
    same = [x for x in records if x.get("session_id") == r.get("session_id")]
    i = same.index(r)
    assert before == same[i - lp.CONTEXT_LINES:i]


# ============================================================ v2 · the mis-click

def test_enter_is_not_a_default_answer(tmp_path, monkeypatch, capsys):
    """MEASURED BEFORE ANYTHING WAS CHANGED, and it is the question that decides
    whether the existing labels are trustworthy.

    If a bare Enter recorded `worth`, every pause at the keyboard would have been
    manufacturing labels nobody chose, invisibly. It does not: an empty answer
    falls through to the reprompt.
    """
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    assert "" not in lp.CHOICES
    for stray in ("", " ", "yy", "y n", "\t"):
        assert stray.strip().lower() not in lp.CHOICES, stray


def test_y_is_not_a_label_key():
    """`y` is the universal "ok, continue" reflex, and this prompt is not asking
    for acknowledgement. Eight accidental `worth` labels in a row is exactly what
    that reflex looks like."""
    assert "y" not in lp.CHOICES
    assert lp.CHOICES["w"] == lp.WORTH and lp.CHOICES["n"] == lp.NOISE


def test_undo_removes_the_answer_and_puts_the_item_back(tmp_path, monkeypatch):
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    store = {"version": 2, "seed": 1, "labels": {}}
    lp.record_answer(store, "rule:x", lp.WORTH, unit="rule", rule_id="x", volume=3)
    assert lp.latest_label(store["labels"]["rule:x"]) == lp.WORTH

    removed = lp.undo_answer(store, "rule:x")
    assert removed == lp.WORTH
    # THE ENTRY GOES, not just its last answer. `queue` treats "has any history"
    # as "already judged", so a husk would drop the item out of the run instead
    # of putting it back — an undo that quietly loses the question.
    assert "rule:x" not in store["labels"]


def test_undo_of_a_corrected_answer_leaves_the_earlier_one(tmp_path, monkeypatch):
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    store = {"version": 2, "seed": 1, "labels": {}}
    lp.record_answer(store, "rule:x", lp.WORTH, unit="rule", rule_id="x")
    lp.record_answer(store, "rule:x", lp.NOISE, unit="rule", rule_id="x")
    assert lp.undo_answer(store, "rule:x") == lp.NOISE
    assert lp.latest_label(store["labels"]["rule:x"]) == lp.WORTH


def test_undo_on_nothing_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    assert lp.undo_answer({"labels": {}}, "rule:nope") is None


def test_fix_keeps_the_earlier_answer_so_the_change_is_visible(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    store = {"version": 2, "seed": 1, "labels": {}}
    lp.record_answer(store, "rule:untrusted_local:git_commit", lp.WORTH,
                     unit="rule", rule_id="untrusted_local:git_commit", volume=51)
    assert lp.do_fix(store, "untrusted_local:git_commit", "n") == 0
    hist = [h["label"] for h in lp.history_of(store["labels"]["rule:untrusted_local:git_commit"])]
    assert hist == [lp.WORTH, lp.NOISE]


def test_fix_refuses_an_ambiguous_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    store = {"version": 2, "seed": 1, "labels": {
        "rule:a:one": {"history": [{"label": lp.WORTH, "at": None}]},
        "rule:a:two": {"history": [{"label": lp.WORTH, "at": None}]}}}
    assert lp.do_fix(store, "rule:a", "n") == 2
    assert "matches 2" in capsys.readouterr().err


def test_reset_backs_up_before_clearing(tmp_path, monkeypatch):
    """The labels are the whole point of the tool; clearing them must be
    recoverable even when it was asked for."""
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    store = {"version": 2, "seed": 1, "labels": {}}
    lp.record_answer(store, "rule:x", lp.WORTH, unit="rule", rule_id="x")
    lp.do_reset(store, None, True)
    assert store["labels"] == {}
    backups = list(tmp_path.glob("l.backup-*.json"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text())["labels"], "backup is empty"


def test_recent_puts_a_correction_above_the_answer_it_replaced(tmp_path, monkeypatch, capsys):
    """Timestamps are second-resolution, so a `fix` applied seconds after the
    original ties with it — and the tie used to break on the key, showing the
    SUPERSEDED answer first. That is the one thing `recent` must not do."""
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    same = "2026-08-09T09:41:26+03:00"
    store = {"labels": {"rule:x": {"rule_id": "x", "history": [
        {"label": lp.WORTH, "at": same}, {"label": lp.NOISE, "at": same}]}}}
    lp.do_recent(store)
    out = capsys.readouterr().out
    assert out.index("NOT_WORTH") < out.index("WORTH  "), out


def test_recent_says_when_order_is_unrecoverable(tmp_path, monkeypatch, capsys):
    """v1 stored bare strings and sorted the file by key, so insertion order was
    destroyed. Reporting those in some arbitrary order as "most recent" would be
    a confident wrong answer."""
    monkeypatch.setattr(lp, "LABELS", tmp_path / "l.json")
    store = {"labels": {"cmd:a": {"rule_id": "r", "history": ["worth"]}}}
    lp.do_recent(store)
    assert "NO timestamp" in capsys.readouterr().out


# =============================================================== v2 · the unit

@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_rules_are_offered_biggest_first_so_stopping_early_buys_coverage():
    """The point of the rule unit is not that it is shorter — it is that the
    first few judgements are worth the most."""
    records = lp.load_records([FIXTURE])
    q = lp.queue(records, {"version": 2, "seed": 1, "labels": {}}, "rule")
    volumes = [m["volume"] for _k, m, _e, _r in q]
    assert volumes == sorted(volumes, reverse=True)
    assert sum(volumes[:4]) / sum(volumes) > 0.6


@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_every_prompt_belongs_to_exactly_one_rule_group():
    """Otherwise the volume weighting in `report` counts something twice."""
    records = lp.load_records([FIXTURE])
    groups = lp.rule_groups(records)
    keys = [lp.key_for(r) for members in groups.values() for r in members]
    assert len(keys) == len(set(keys))
    judgeable = {lp.key_for(r) for r in lp.prompts(records) if lp.judgeable(r)}
    assert set(keys) == judgeable


@pytest.mark.skipif(not FIXTURE.is_dir(), reason="fixture not present")
def test_examples_are_spread_across_time_not_taken_from_the_front():
    """Three consecutive minutes of one afternoon show the rule in one situation
    and invite a judgement about all of it."""
    records = lp.load_records([FIXTURE])
    groups = lp.rule_groups(records)
    big = max(groups.values(), key=len)
    assert len(big) > 6, "need a group large enough for this to mean anything"
    picked = lp._examples(big, 3)
    ordered = sorted(big, key=lambda r: r.get("ts") or 0)
    assert picked[0] is ordered[0] and picked[-1] is ordered[-1]
    assert len({id(p) for p in picked}) == 3


def test_mixed_is_excluded_from_precision_and_reported_separately(capsys):
    """A rule that is right sometimes is the most actionable finding available;
    averaging it into a percentage is precisely how it gets lost."""
    store = {"labels": {
        "rule:a": {"unit": "rule", "rule_id": "a", "volume": 10,
                   "history": [{"label": lp.WORTH, "at": None}]},
        "rule:b": {"unit": "rule", "rule_id": "b", "volume": 10,
                   "history": [{"label": lp.NOISE, "at": None}]},
        "rule:c": {"unit": "rule", "rule_id": "c", "volume": 80,
                   "history": [{"label": lp.MIXED, "at": None}]}}}
    lp.report(store)
    out = capsys.readouterr().out
    assert "10/20 prompts = 50.0%" in out, out
    assert "80 prompts sit under a rule you called MIXED" in out


def test_precision_is_weighted_by_how_often_a_rule_actually_fired(capsys):
    """A rule that prompted 74 times and a rule that prompted once are not one
    vote each."""
    store = {"labels": {
        "rule:big": {"unit": "rule", "rule_id": "big", "volume": 74,
                     "history": [{"label": lp.NOISE, "at": None}]},
        "rule:tiny": {"unit": "rule", "rule_id": "tiny", "volume": 1,
                      "history": [{"label": lp.WORTH, "at": None}]}}}
    lp.report(store)
    assert "1/75 prompts = 1.3%" in capsys.readouterr().out
