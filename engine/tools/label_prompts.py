#!/usr/bin/env python3
"""Ground truth for "was that prompt worth showing me?". $0, no network.

    python3 tools/label_prompts.py census      # what is there to judge
    python3 tools/label_prompts.py label       # judge it, by cause, biggest first
    python3 tools/label_prompts.py report      # precision, weighted, with coverage
    python3 tools/label_prompts.py recent      # what did I answer last
    python3 tools/label_prompts.py fix <key> <w|n|m|?>      # correct one after the fact
    python3 tools/label_prompts.py reset [--all | <key>]    # backs up first

WHY THIS EXISTS. A4 counts attacks blocked and A5 counts normal tasks blocked.
Neither says anything about the ASKs, and an ASK is a prompt rather than a block.
Every friction figure this project has produced counts prompts, which measures
VOLUME; whether they were WANTED has never been measured, and it is what decides
whether a person leaves the guard switched on.

────────────────────────────────────────────────────────────────────────────────
V2 — REBUILT AFTER THE OWNER TRIED IT AND COULD NOT JUDGE ANYTHING
────────────────────────────────────────────────────────────────────────────────

Two failures, both of the tool:

**1 · It showed the agent's side of the conversation only.** Five preceding
actions of `cd … && git add -A` say what the agent DID and nothing about what was
WANTED, and the judgement is entirely about the second. The instruction now comes
from the session transcript — see `tools/session_context.py`. Measured: an
instruction is recovered for **246 of 246** judgeable prompts, 141 by exact
command digest and 105 by timestamp. The time gap since the previous action is
shown too, because "3s later" is the agent mid-loop and "20 min later" is a person
coming back to the keyboard, and the same prompt is a different judgement across
those.

**2 · The unit was wrong.** 192 individual judgements about things that share a
handful of causes is not a task anyone finishes, and an unfinished set produces no
number at all. **The unit is now the RULE**, with examples shown underneath it,
and rules are presented **biggest first** — which is what makes the set
stoppable rather than merely shorter:

    4 judgements  cover  71.5% of all prompts
    8 judgements  cover  84.1%
    27 judgements cover  100%      (12 of those 27 rules have a single prompt)

So you can stop whenever you like and `report` states the coverage you bought.
`--unit prompt` keeps the old per-item behaviour for a rule worth taking apart.

**`m` — mixed — is a real answer, not a hedge.** A rule that is right sometimes
and wrong sometimes is the single most actionable finding this can produce: it
says the rule needs narrowing rather than removing. It is reported separately and
excluded from precision, because averaging it into a percentage would hide it.

────────────────────────────────────────────────────────────────────────────────
THE MIS-CLICK, AND WHAT WAS ACTUALLY WRONG
────────────────────────────────────────────────────────────────────────────────

Measured before changing anything: **Enter has no default.** Five bare Enters
produce zero labels and five reprompts, so nothing was being recorded by a stray
newline. `"yy"` and `"y n"` are rejected too.

The hazards were real but different, and all three are fixed:

    NO UNDO         one keystroke was final. `u` now steps back and re-asks.
    NO ECHO         nothing showed what had just been recorded, so a wrong
                    answer was invisible. Every answer now prints back.
    `y` MEANT YES   and `y` is the universal "ok, continue" reflex — which is
                    exactly what eight accidental `worth` labels in a row look
                    like. The keys are now `w`/`n`, neither of which is an
                    acknowledgement, and neither adjacent to the other.

Labels carry a timestamp so `recent` can show what was answered last. The first
version stored `history: ["worth"]` and wrote the file with `sort_keys=True`,
which destroyed insertion order — "show me my most recent label" was
unanswerable from the file. Old-format entries are still read.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import random
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import audit_log                                            # noqa: E402
from tools import session_context                                    # noqa: E402

ROOT = Path(__file__).parent.parent
LABELS = ROOT / "labels" / "prompt_labels.json"

LIVE_ROOTS = [Path("~/.sting/dogfood").expanduser(),
              Path("~/sting/sting-logs-archive").expanduser()]
FIXTURE_ROOT = ROOT / "logs" / "live-fixture"

WORTH, NOISE, MIXED, UNSURE = "worth", "not_worth", "mixed", "cant_tell"
# ⚠ NOT `y`. See the mis-click note in the module docstring: `y` is the reflex
# key for "ok, continue", and this prompt is not asking for acknowledgement.
CHOICES = {"w": WORTH, "n": NOISE, "m": MIXED, "?": UNSURE}
PROMPT_KEYS = "[w=worth  n=not worth  m=mixed  ?=can't tell  u=undo  s=skip  q=quit]"

EXAMPLES_PER_RULE = 3
CONTEXT_LINES = 5
REPEAT_RATE = 0.125
SEED = 20260809

_HOME = re.compile(r"/(?:Users|home)/[^/]+/")


# ------------------------------------------------------------------- loading

def load_records(roots: list[Path]) -> list[dict]:
    out: list[dict] = []
    for root in roots:
        if not root.is_dir():
            continue
        for f in sorted(root.rglob("*.log.jsonl")):
            for line in f.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rec["_log"] = f
                out.append(rec)
    return out


def full_command(rec: dict) -> tuple[str | None, bool]:
    """(command, is_whole), recovering from the sidecar when the record clipped.

    Judging the first 2048 bytes of a 10 KB command is judging a different
    command — the same reason the sidecar exists for verdicts.
    """
    cmd = rec.get("command")
    if cmd is None:
        return None, True
    whole = audit_log.stored_command_is_whole(rec)
    if whole is True:
        return cmd, True
    digest = rec.get("command_sha256")
    if digest:
        side = audit_log.sidecar_dir(rec["_log"]) / digest
        if side.is_file():
            return side.read_text(errors="replace"), True
    if whole is None and len(cmd) < audit_log._MAX_COMMAND:
        return cmd, True
    return cmd, False


def key_for(rec: dict) -> str:
    """Stable across the live log and the redacted fixture, and never a seq.

    `seq` is a position in a file that grows. And the digest must be the
    PROVENANCE one: `redact_logs.py` re-addresses fixture records onto their
    redacted bytes, so a fixture `command_sha256` digests text that never ran.
    Measured — under this key all 134 fixture prompt keys are found in the live
    log; under plain `command_sha256`, 2 of 134.
    """
    digest = rec.get("original_sha256") or rec.get("command_sha256")
    if digest:
        return f"cmd:{digest}"
    material = "\x00".join([
        str(rec.get("kind") or ""), str(rec.get("rule_id") or ""),
        *[_HOME.sub("/~/", str(p)) for p in (rec.get("paths") or [])]])
    return "act:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def rule_key(rule_id: str | None) -> str:
    return f"rule:{rule_id or '(none)'}"


def prompts(records: list[dict]) -> list[dict]:
    return [r for r in records if r.get("decision") in ("ASK", "DENY")]


def judgeable(rec: dict) -> bool:
    return full_command(rec)[1]


def gate_and_sink(rule_id: str | None) -> tuple[str, str]:
    """`untrusted_local:git_commit` -> ("untrusted_local", "git_commit").

    The gate is WHY the session was suspect; the sink is WHAT it was about to do.
    One number over both hides whichever is the problem.
    """
    rid = rule_id or "(none)"
    return tuple(rid.split(":", 1)) if ":" in rid else (rid, "(no sink)")


def context_before(rec: dict, records: list[dict],
                    n: int = CONTEXT_LINES) -> list[dict]:
    """The n actions before this one, IN THE SAME SESSION.

    ⚠ `records` is every log concatenated, so slicing the flat list hands you the
    tail of the PREVIOUS session for any prompt near a file boundary — answering
    "what was I doing" with someone else's afternoon.
    """
    sid = rec.get("session_id")
    same = [r for r in records if r.get("session_id") == sid]
    for i, r in enumerate(same):
        if r is rec:
            return same[max(0, i - n):i]
    return []


# -------------------------------------------------------------------- census

def rule_groups(records: list[dict]) -> dict[str, list[dict]]:
    """rule_id -> its judgeable prompts, one per distinct key, biggest first."""
    groups: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for r in prompts(records):
        if judgeable(r):
            groups[r.get("rule_id") or "(none)"].setdefault(key_for(r), r)
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    return {rule: list(members.values()) for rule, members in ordered}


def census(records: list[dict]) -> dict:
    ps = prompts(records)
    groups = rule_groups(records)
    ok = [r for r in ps if judgeable(r)]
    return {"records": len(records),
            "sessions": len({r.get("session_id") for r in records}),
            "prompts": len(ps),
            "ask": sum(1 for r in ps if r["decision"] == "ASK"),
            "deny": sum(1 for r in ps if r["decision"] == "DENY"),
            "judgeable": len(ok), "not_judgeable": len(ps) - len(ok),
            "distinct": len({key_for(r) for r in ok}),
            "rules": len(groups), "groups": groups}


def print_census(c: dict) -> None:
    print(f"  records                {c['records']}  over {c['sessions']} sessions")
    print(f"  PROMPTS (ASK + DENY)   {c['prompts']}   ({c['ask']} ASK, {c['deny']} DENY)")
    print(f"    judgeable            {c['judgeable']}")
    print(f"    NOT judgeable        {c['not_judgeable']}   (command clipped, sidecar gone)")
    print(f"\n  TO JUDGE, by unit:")
    print(f"    --unit rule    {c['rules']} judgements   <- the default")
    print(f"    --unit prompt  {c['distinct']} judgements")
    total = sum(len(v) for v in c["groups"].values())
    print(f"\n  {'rule':46} {'prompts':>8} {'cumulative':>11}")
    run = 0
    for rule, members in c["groups"].items():
        run += len(members)
        print(f"  {rule:46} {len(members):8} {100.0 * run / total:10.1f}%")


# -------------------------------------------------------------------- labels

def load_labels() -> dict:
    if LABELS.is_file():
        return json.loads(LABELS.read_text())
    return {"version": 2, "seed": SEED, "labels": {}}


def save_labels(store: dict) -> None:
    LABELS.parent.mkdir(parents=True, exist_ok=True)
    LABELS.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def history_of(entry: dict) -> list[dict]:
    """Tolerates v1 entries, whose history was a bare list of strings."""
    out = []
    for h in entry.get("history", []):
        out.append({"label": h, "at": None} if isinstance(h, str) else h)
    return out


def latest_label(entry: dict) -> str | None:
    hist = history_of(entry)
    return hist[-1]["label"] if hist else None


def record_answer(store: dict, key: str, label: str, **meta) -> None:
    entry = store["labels"].setdefault(key, {**meta, "history": []})
    entry.update({k: v for k, v in meta.items() if v is not None})
    entry.setdefault("history", [])
    entry["history"] = history_of(entry) + [
        {"label": label, "at": datetime.now().astimezone().isoformat(timespec="seconds")}]
    save_labels(store)


def undo_answer(store: dict, key: str) -> str | None:
    """Drop the most recent answer for one key. Returns what was removed.

    Removing the ENTRY when its history empties, rather than leaving a husk,
    because `queue` treats "has any history" as "already judged" — a husk would
    silently drop the item out of the run instead of putting it back.
    """
    entry = store["labels"].get(key)
    if not entry:
        return None
    hist = history_of(entry)
    if not hist:
        return None
    removed = hist.pop()["label"]
    if hist:
        entry["history"] = hist
    else:
        del store["labels"][key]
    save_labels(store)
    return removed


def backup_labels() -> Path | None:
    if not LABELS.is_file():
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = LABELS.with_name(f"{LABELS.stem}.backup-{stamp}.json")
    shutil.copy2(LABELS, dest)
    return dest


# --------------------------------------------------------------------- queue

def _examples(members: list[dict], n: int = EXAMPLES_PER_RULE) -> list[dict]:
    """Up to n examples, SPREAD ACROSS TIME rather than taken from the front.

    The first three members of a group are usually three consecutive minutes of
    one afternoon, which shows the rule's behaviour in one situation and invites
    a judgement about all of them.
    """
    ordered = sorted(members, key=lambda r: r.get("ts") or 0)
    if len(ordered) <= n:
        return ordered
    step = (len(ordered) - 1) / (n - 1)
    return [ordered[round(i * step)] for i in range(n)]


# ────────────────────────────────────────────── self-consistency (`recheck`)

RECHECK_FRACTION = 0.25


def recheck_queue(records: list[dict], store: dict,
                   fraction: float = RECHECK_FRACTION) -> list[tuple]:
    """A random `fraction` of ALREADY JUDGED rules, re-presented blind.

    ⚠ IT WAS CLAIMED THIS COULD NOT BE DONE, AND THAT CLAIM WAS WRONG. The
    reasoning was that the rule unit "folds in no re-asks", so there is nothing
    to re-present. But the unit being a RULE is exactly what makes this possible:
    the same rule can be shown again with DIFFERENT worked examples, which is a
    genuinely new judgement about the same question rather than a memory test.

    THREE THINGS MAKE IT BLIND, and all three are needed:

      the prior label is not displayed        `blind=True` reaches the renderer
      the examples are DIFFERENT ones         a disjoint slice of the same group
      the order is reshuffled                 so position carries no hint

    ⚠ WHAT IT MEASURES IS AGREEMENT, NOT CORRECTNESS. If a rule is judged
    "not worth showing" twice from different examples, the judgement is at least
    stable. If it flips, then the single-judgement precision figure has no error
    bar worth quoting, and that is the finding — it does not mean the second
    answer is right.
    """
    groups = rule_groups(records)
    judged = [(rule_key(rule), rule, members) for rule, members in groups.items()
               if latest_label(store["labels"].get(rule_key(rule), {}))]
    if not judged:
        return []
    rng = random.Random(store.get("seed", SEED) + 1)      # a DIFFERENT stream
    rng.shuffle(judged)
    take = max(1, round(len(judged) * fraction))
    out = []
    for key, rule, members in judged[:take]:
        out.append((key, {"unit": "rule", "rule_id": rule,
                          "volume": len(members), "recheck": True},
                    _other_examples(members, store, key), True))
    return out


def _other_examples(members: list[dict], store: dict, key: str,
                     n: int = EXAMPLES_PER_RULE) -> list[dict]:
    """Examples the first judgement did NOT see, where the group is big enough.

    ⚠ THE SAME EXAMPLES WOULD MAKE THIS A MEMORY TEST. Re-presenting the
    identical three commands measures whether the judge remembers, not whether
    the judgement is stable. Where a group has fewer than 2n members there is no
    disjoint slice, so the same ones are reused and the record says so — an
    honest weaker measurement rather than a fabricated stronger one.
    """
    ordered = sorted(members, key=lambda r: r.get("ts") or 0)
    if len(ordered) < 2 * n:
        return _examples(members, n)
    # ⚠ EXCLUDE EXACTLY WHAT THE FIRST PASS SHOWED, rather than taking a "second
    # half" and hoping. `_examples` spreads across the WHOLE range, so its picks
    # land in both halves — the first version of this took `ordered[len//2:]`
    # and still re-showed 2 of 3, which its own test caught.
    shown_before = {id(r) for r in _examples(ordered, n)}
    remaining = [r for r in ordered if id(r) not in shown_before]
    return _examples(remaining, n) if len(remaining) >= n else _examples(ordered, n)


def agreement(store: dict) -> dict:
    """Across rules judged more than once: how often the two agree.

    Returns the counts and the interval this licenses. **Never invents a
    judgement** — with nothing re-judged it reports that, and says the precision
    figure has no error bar until someone runs `recheck`.
    """
    repeated = {key: history_of(entry) for key, entry in store["labels"].items()
                 if len(history_of(entry)) >= 2}
    agreed = sum(1 for h in repeated.values() if h[-1]["label"] == h[-2]["label"])
    return {
        "rules_rejudged": len(repeated),
        "agreed": agreed,
        "disagreed": len(repeated) - agreed,
        "agreement": (agreed / len(repeated)) if repeated else None,
        "note": ("no rule has been judged twice, so the precision figure has no "
                  "self-consistency estimate and therefore no error bar. Run "
                  "`label_prompts.py recheck`.") if not repeated else "",
    }


def queue(records: list[dict], store: dict, unit: str) -> list[tuple]:
    """[(key, label_meta, [records to show], is_repeat)].

    BIGGEST FIRST for rules, so stopping early still buys coverage — 4 rules are
    71.5% of all prompts. Shuffled for individual prompts, where there is no
    size to order by and log order would group near-identical commits together.
    """
    if unit == "rule":
        groups = rule_groups(records)
        out = []
        for rule, members in groups.items():
            key = rule_key(rule)
            if latest_label(store["labels"].get(key, {})):
                continue
            out.append((key, {"unit": "rule", "rule_id": rule,
                              "volume": len(members)},
                        _examples(members), False))
        return out

    ok = [r for r in prompts(records) if judgeable(r)]
    first: dict[str, dict] = {}
    for r in ok:
        first.setdefault(key_for(r), r)
    rng = random.Random(store.get("seed", SEED))
    items = sorted(first.items())
    rng.shuffle(items)
    done = {k for k, v in store["labels"].items() if latest_label(v)}
    todo = [(k, {"unit": "prompt", "rule_id": r.get("rule_id"),
                 "decision": r.get("decision")}, [r], False)
            for k, r in items if k not in done]
    repeatable = [(k, r) for k, r in items
                  if k in done and len(history_of(store["labels"][k])) == 1]
    rng.shuffle(repeatable)
    repeats = [(k, {"unit": "prompt", "rule_id": r.get("rule_id"),
                    "decision": r.get("decision")}, [r], True)
               for k, r in repeatable[:int(len(items) * REPEAT_RATE)]]
    out = todo + repeats
    rng.shuffle(out)
    return out


# --------------------------------------------------------------------- shown

def show_example(rec: dict, records: list[dict], n: int, of: int) -> None:
    cmd, _ = full_command(rec)
    digest = rec.get("original_sha256") or rec.get("command_sha256")
    asked, how = session_context.asked_for(
        rec.get("session_id"), digest, rec.get("ts"))
    before = context_before(rec, records)
    gap = session_context.human_gap(session_context.gap_before(rec, before))
    when = (datetime.fromtimestamp(rec["ts"]).strftime("%a %d %b, %H:%M")
            if rec.get("ts") else "?")

    print(f"\n  ── example {n} of {of} ─ {when}   {gap}")
    if asked:
        print(f"\n     YOU ASKED:  ({how})")
        for line in asked.strip().splitlines()[:6]:
            print(f"       │ {line[:96]}")
    else:
        print(f"\n     YOU ASKED:  (not recoverable — {how})")
    if before:
        print(f"\n     just before:")
        for b in before[-3:]:
            c = (b.get("command") or " ".join(b.get("paths") or [])
                 or b.get("tool_name") or "")
            first = c.splitlines()[0] if c else ""
            print(f"       {str(b.get('kind') or ''):5} {first[:84]}")
    print(f"\n     THE AGENT THEN RAN:")
    for line in (cmd or " ".join(str(p) for p in (rec.get("paths") or []))
                 or "(no command)").splitlines()[:8]:
        print(f"       {line[:96]}")
    print(f"\n     STING SAID {rec['decision']}: {(rec.get('reason') or '')[:300]}")


def show_item(key: str, meta: dict, examples: list[dict], records: list[dict],
               seen: int, total: int) -> None:
    print("\n" + "=" * 78)
    if meta.get("unit") == "rule":
        gate, sink = gate_and_sink(meta["rule_id"])
        print(f"  {seen}/{total}   RULE  {meta['rule_id']}")
        print(f"           {meta['volume']} prompts came from this rule")
        print(f"           gate: {gate}   sink: {sink}")
    else:
        print(f"  {seen}/{total}   one prompt — {meta.get('rule_id')}")
    for i, rec in enumerate(examples, 1):
        show_example(rec, records, i, len(examples))
    print("\n" + "-" * 78)
    if meta.get("unit") == "rule":
        print(f"  Was it worth interrupting you, for prompts like these?")
    print("=" * 78)


# --------------------------------------------------------------------- label

def do_label(records: list[dict], store: dict, unit: str,
              recheck: bool = False) -> int:
    q = recheck_queue(records, store) if recheck else queue(records, store, unit)
    if recheck and q:
        print("=== RECHECK — self-consistency ===")
        print(f"  {len(q)} of the judged rules, re-presented BLIND:")
        print("    the prior label is not shown")
        print("    the worked examples are different ones")
        print("    the order is reshuffled")
        print("  This measures AGREEMENT, not correctness. A rule that flips")
        print("  means the single-judgement figure has no error bar worth")
        print("  quoting — it does not mean the second answer is right.\n")
    if not q:
        print("Nothing left to judge at this unit. Run `report`.")
        return 0
    total = len(q)
    if unit == "rule":
        vols = [m["volume"] for _, m, _, _ in q]
        cum = 0
        stop_at = []
        for i, v in enumerate(sorted(vols, reverse=True), 1):
            cum += v
            stop_at.append((i, 100.0 * cum / sum(vols)))
        marks = ", ".join(f"{i} covers {p:.0f}%" for i, p in stop_at[:4] if i in (1, 2, 4))
        print(f"\n{total} rules to judge, biggest first — {marks}.")
        print("Stop whenever you like; `report` states the coverage you bought.")
    else:
        print(f"\n{total} to judge.")
    print(f"  {PROMPT_KEYS}\n")

    trail: list[str] = []
    i = 0
    while i < len(q):
        key, meta, examples, _repeat = q[i]
        show_item(key, meta, examples, records, i + 1, total)
        answer = ""
        while True:
            try:
                answer = input(f"  {PROMPT_KEYS} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n  saved.")
                return 0
            if answer in ("q", "s", "u") or answer in CHOICES:
                break
            print("      w, n, m, ?, u, s or q")
        if answer == "q":
            print("  saved.")
            return 0
        if answer == "s":
            i += 1
            continue
        if answer == "u":
            # STEP BACK ONE AND RE-ASK. The trail holds only keys that were
            # actually answered, so undo skips over anything skipped rather
            # than silently re-asking something that was never judged.
            if not trail:
                print("      nothing to undo yet.")
                continue
            last = trail.pop()
            removed = undo_answer(store, last)
            back = next((j for j in range(i - 1, -1, -1) if q[j][0] == last), None)
            print(f"      undone: {removed} on {last}")
            if back is not None:
                i = back
            continue
        record_answer(store, key, CHOICES[answer], **meta)
        trail.append(key)
        # ECHO. A wrong answer was invisible before, which is what made one
        # mis-click unrecoverable.
        print(f"      recorded: {CHOICES[answer].upper()}  —  press u on the next "
              f"item to undo")
        i += 1
    print("\n  done. Run `report`.")
    return 0


# -------------------------------------------------------- recent / fix / reset

def do_recent(store: dict, n: int = 10) -> int:
    entries = []
    for key, entry in store["labels"].items():
        for i, h in enumerate(history_of(entry)):
            # ⚠ THE HISTORY INDEX IS PART OF THE SORT KEY. Timestamps are
            # second-resolution, and a `fix` applied seconds after the original
            # answer ties with it — at which point the tie broke on the key and
            # showed the SUPERSEDED answer above the correction. That is the one
            # thing this command exists not to do.
            entries.append(((h.get("at") or ""), i, key, h["label"], entry))
    if not entries:
        print("No labels yet.")
        return 2
    dated = [e for e in entries if e[0]]
    undated = [e for e in entries if not e[0]]
    dated.sort(reverse=True)
    print("=== MOST RECENT LABELS ===\n")
    for at, _i, key, label, entry in dated[:n]:
        print(f"  {at}   {label.upper():10} {key}")
        print(f"      {entry.get('rule_id')}   "
              f"{entry.get('volume', '')} {'prompts' if entry.get('volume') else ''}")
    if undated:
        print(f"\n  ⚠ {len(undated)} label(s) carry NO timestamp — written by v1, "
              f"which stored\n    history as bare strings and sorted the file by key, so "
              f"insertion order\n    was destroyed. Their order cannot be recovered from "
              f"the file.")
        for _, _i, key, label, entry in undated[:n]:
            print(f"      {label.upper():10} {key}  {entry.get('rule_id')}")
    return 0


def resolve_key(store: dict, prefix: str) -> str | None:
    if prefix in store["labels"]:
        return prefix
    hits = [k for k in store["labels"] if k.startswith(prefix)
            or k.split(":", 1)[-1].startswith(prefix)]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        print(f"  no label matches {prefix!r}", file=sys.stderr)
    else:
        print(f"  {prefix!r} matches {len(hits)}: {hits[:5]}", file=sys.stderr)
    return None


def do_fix(store: dict, prefix: str, answer: str) -> int:
    key = resolve_key(store, prefix)
    if key is None:
        return 2
    if answer not in CHOICES:
        print(f"  answer must be one of {sorted(CHOICES)}", file=sys.stderr)
        return 2
    was = latest_label(store["labels"][key])
    record_answer(store, key, CHOICES[answer])
    print(f"  {key}\n    {was} -> {CHOICES[answer]}")
    print("  the earlier answer is kept in `history`; `report` uses the last one "
          "and counts\n  the disagreement separately.")
    return 0


def do_reset(store: dict, target: str | None, everything: bool) -> int:
    if not everything and not target:
        print("  say which: `reset --all` or `reset <key>`", file=sys.stderr)
        return 2
    backup = backup_labels()
    if everything:
        n = len(store["labels"])
        store["labels"] = {}
        save_labels(store)
        print(f"  cleared {n} label(s).")
    else:
        key = resolve_key(store, target)
        if key is None:
            return 2
        store["labels"].pop(key)
        save_labels(store)
        print(f"  cleared {key}.")
    if backup:
        print(f"  backup: {backup}")
    return 0


# -------------------------------------------------------------------- report

def report(store: dict) -> int:
    judged = {k: v for k, v in store["labels"].items() if latest_label(v)}
    if not judged:
        print("No labels yet. Run `label` first.")
        return 2
    rules = {k: v for k, v in judged.items() if k.startswith("rule:")}
    items = {k: v for k, v in judged.items() if not k.startswith("rule:")}

    print("=== PROMPT PRECISION ===\n")
    if rules:
        vol = {k: v.get("volume", 0) for k, v in rules.items()}
        total_judged_vol = sum(vol.values())
        by = collections.Counter()
        volby = collections.Counter()
        for k, v in rules.items():
            by[latest_label(v)] += 1
            volby[latest_label(v)] += vol[k]
        decided_vol = volby[WORTH] + volby[NOISE]
        print(f"  BY RULE — {len(rules)} rules judged, covering "
              f"{total_judged_vol} prompts")
        for label in (WORTH, NOISE, MIXED, UNSURE):
            if by[label]:
                print(f"    {label:10} {by[label]:3} rules  "
                      f"{volby[label]:4} prompts")
        if decided_vol:
            print(f"\n  WEIGHTED PRECISION  {volby[WORTH]}/{decided_vol} prompts = "
                  f"{100.0 * volby[WORTH] / decided_vol:.1f}%")
            print("    weighted by how often each rule actually fired, so a rule "
                  "that\n    prompted 74 times counts 74 times.")
        if volby[MIXED]:
            print(f"\n  ⚠ {volby[MIXED]} prompts sit under a rule you called MIXED. "
                  f"Excluded from\n    the figure above on purpose — averaging it in "
                  f"would hide the one\n    finding that says WHICH rule to narrow.")
        print(f"\n  {'rule':44} {'prompts':>8}  verdict")
        for k, v in sorted(rules.items(), key=lambda kv: -kv[1].get("volume", 0)):
            print(f"  {str(v.get('rule_id'))[:44]:44} {v.get('volume', 0):8}  "
                  f"{latest_label(v)}")

    if items:
        c = collections.Counter(latest_label(v) for v in items.values())
        decided = c[WORTH] + c[NOISE]
        print(f"\n  BY INDIVIDUAL PROMPT — {len(items)} judged")
        print(f"    worth {c[WORTH]}   not worth {c[NOISE]}   mixed {c[MIXED]}   "
              f"can't tell {c[UNSURE]}")
        if decided:
            print(f"    precision {c[WORTH]}/{decided} = "
                  f"{100.0 * c[WORTH] / decided:.1f}%")

    changed = {k: v for k, v in judged.items() if len(history_of(v)) > 1}
    if changed:
        flipped = sum(1 for v in changed.values()
                      if len({h["label"] for h in history_of(v)}) > 1)
        print(f"\n  answered more than once  {len(changed)}")
        print(f"    changed their mind     {flipped}")
        if flipped:
            print("    ⚠ read the precision to no more precision than this.")
    else:
        print("\n  nothing was answered twice, so the precision has no error bar.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command",
                     choices=["census", "label", "report", "recent", "fix", "reset",
                               "recheck", "agreement"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--source", choices=["live", "fixture"], default="live")
    ap.add_argument("--unit", choices=["rule", "prompt"], default="rule",
                     help="rule: judge a cause with examples under it (default, "
                          "27 judgements, 4 of them cover 71.5%% of prompts). "
                          "prompt: one judgement per prompt.")
    ap.add_argument("--all", action="store_true", help="reset: clear every label")
    ap.add_argument("--labels", type=Path, default=None)
    args = ap.parse_args(argv)

    global LABELS
    if args.labels:
        LABELS = args.labels
    store = load_labels()

    if args.command == "report":
        return report(store)
    if args.command == "agreement":
        import json as _json
        print(_json.dumps(agreement(store), indent=2))
        return 0
    if args.command == "recent":
        return do_recent(store)
    if args.command == "fix":
        if len(args.args) != 2:
            print("  usage: fix <key> <w|n|m|?>", file=sys.stderr)
            return 2
        return do_fix(store, args.args[0], args.args[1])
    if args.command == "reset":
        return do_reset(store, args.args[0] if args.args else None, args.all)

    roots = LIVE_ROOTS if args.source == "live" else [FIXTURE_ROOT]
    records = load_records(roots)
    if not records:
        print(f"No logs under {', '.join(str(r) for r in roots)}", file=sys.stderr)
        return 2
    if args.command == "census":
        print(f"=== {args.source.upper()} ===")
        print_census(census(records))
        return 0
    return do_label(records, store, args.unit,
                     recheck=(args.command == "recheck"))


if __name__ == "__main__":
    sys.exit(main())
