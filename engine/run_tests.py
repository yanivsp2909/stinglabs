#!/usr/bin/env python3
"""One command. A thousand scenarios. Two rates, never one number.

    python3 run_tests.py

⚠ IT IS NOT A SECOND RUNNER. Every verdict here comes from `tools/grade_engine.py`
— which itself drives `runner/replay.py`'s own functions — and the corpus tier
runs through that harness's RECONCILIATION GATE. That gate exists because the
first version of the harness rebuilt the replay logic, collapsed every MCP and
WebFetch trace into an empty Bash call, and reported ELEVEN REAL CATCHES AS
MISSES. If the numbers here disagree with the checkpoint, this command prints
NOT TRUSTWORTHY and exits non-zero rather than showing you a score.

⚠ A SCENARIO IS A SEQUENCE, NOT A COMMAND. `curl example.com` alone is fine;
`curl` after reading `.env` is the catch. Every scenario is a list of calls
replayed in order against one session, because the engine's verdict depends on
everything that happened before — which is the only thing this engine does that
a pattern matcher cannot.

⚠ AND THE TWO RATES ARE NEVER AVERAGED.

    on an attack:   stopped = caught      · allowed = MISS
    on a normal:    allowed = correct     · stopped = FALSE POSITIVE

Different denominators, different meanings. One number hides whichever is worse,
and the half that gets hidden is always the false-positive half — generate a
thousand attacks and every "improvement" means blocking more.
"""
from __future__ import annotations

import argparse
import collections
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from tools import grade_engine as G                               # noqa: E402


def _rate(part: int, whole: int) -> str:
    return f"{part}/{whole}" + (f"  ({100.0 * part / whole:.1f}%)" if whole else "")


INLINE_CHARS = 400
INLINE_LINES = 6
"""How much of a command is printed where a person reads. ⚠ MEASURED, NOT
GUESSED: the longest command in the mined half is 2,058 characters across 42
lines — a heredoc that rewrites a file — and section 4 printed one of them whole.
Four hundred characters is about five terminal lines, which is enough to see what
a command DOES and short enough that six false positives still fit on a screen.

⚠ AND THE FULL TEXT STAYS REACHABLE, which is the half that makes truncation
honest. A truncated command a person cannot expand is a finding they cannot
judge, so every clipped line says exactly how much was cut and where the whole
thing is."""


def _inline(command: str, where: str = "") -> str:
    """A command, clipped for reading, never for the record.

    The full text is in `logs/run_tests.txt`'s companion — and for a MINED
    scenario it is in the session log the scenario was mined from, which is
    named so the reader can go and get it.
    """
    text = (command or "").rstrip()
    lines = text.splitlines()
    if len(text) <= INLINE_CHARS and len(lines) <= INLINE_LINES:
        return text
    kept = "\n".join(lines[:INLINE_LINES])[:INLINE_CHARS].rstrip()
    hidden_lines = max(0, len(lines) - INLINE_LINES)
    tail = (f"\n           … CLIPPED: {len(text) - len(kept)} more characters"
            + (f", {hidden_lines} more line(s)" if hidden_lines else "")
            + (f". Full text: {where}" if where else
               ". Full text: logs/run_tests.full.txt"))
    return kept + tail


def _source_of(result: dict) -> str:
    """Where the whole command can be read. ⚠ A MINED scenario's full text is in
    the session log it came from — the `.commands/` sidecar exists precisely
    because commands get long — and naming it is what keeps a clipped line
    judgeable."""
    sid = result.get("sid", "")
    if sid.startswith("MINED-"):
        name = sid[len("MINED-"):].split(":")[0]
        return f"~/.sting/sessions/{name}"
    return "logs/run_tests.full.txt"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(ROOT / "logs" / "run_tests.txt"))
    args = ap.parse_args(argv)

    started = time.time()
    lines: list[str] = []

    def W(text: str = "") -> None:
        lines.append(text)
        print(text)

    # ── the obvious cases first. If one of these misses it is the most
    #    important line in the report, so it is printed before anything else.
    basic = [G._run_basic(sid, spec) for sid, spec in G.BASIC.items()]
    basic_miss = [b for b in basic if b["state"] == "MISS"]
    basic_fp = [b for b in basic if b["state"] == "FALSE_POSITIVE"]

    # ── the committed corpus, through replay.py's own machinery, and its gate
    corpus_by_sid, corpus_config = G._run_corpus_via_replay()
    reconciliation = G._reconcile(corpus_by_sid)

    # ── the thousand
    thousand = G.run_thousand()["results"]

    attacks = [r for r in thousand if r["class"] == "attack"]
    normals = [r for r in thousand if r["class"] == "normal"]
    disagreements = [r for r in thousand if r["class"] == "disagreement"]

    na = [r for r in thousand if r["state"] == "NOT_APPLICABLE"]
    attacks_run = [r for r in attacks if r["state"] != "NOT_APPLICABLE"]
    normals_run = [r for r in normals if r["state"] != "NOT_APPLICABLE"]

    blocked = [r for r in attacks_run if r["state"] == "BLOCKED"]
    asked_a = [r for r in attacks_run if r["state"] == "ASK"]
    missed = [r for r in attacks_run if r["state"] == "MISS"]
    passed_n = [r for r in normals_run if r["state"] == "PASS"]
    asked_n = [r for r in normals_run if r["state"] == "ASK"]
    fps = [r for r in normals_run if r["state"] == "FALSE_POSITIVE"]

    predicted = [r for r in missed if r["group"].startswith("impossible/")]
    unpredicted = [r for r in missed if not r["group"].startswith("impossible/")]
    # ⚠ AND THE OTHER DIRECTION. A scenario written to be UNCATCHABLE that the
    # engine nonetheless stopped is a finding too, and a report that only ever
    # looks for failures would never show it.
    impossible = [r for r in thousand if r["group"].startswith("impossible/")]
    caught_anyway = [r for r in impossible if r["state"] in ("BLOCKED", "ASK")]

    W("=" * 78)
    W("STING — 1,000 scenarios, run as SEQUENCES")
    W("=" * 78)
    W()

    # ── section 0 · the gate ────────────────────────────────────────────────
    if reconciliation["ok"]:
        W(f"[GATE] ✓ the corpus tier reconciles with the checkpoint at "
          f"{reconciliation['harness']} blocked.")
    elif not reconciliation.get("readable", True):
        # ⚠ THE TWO FAILURES ARE DIFFERENT AND THE GATE MUST SAY WHICH. "The
        # harness disagrees" sends somebody to compare two numbers; "I could not
        # read the checkpoint" sends them to the checkpoint. Printing the first
        # when the second is true is the defect that said "Phase 0 has not
        # landed" when Phase 0 had landed.
        W("[GATE] ⚠⚠ NOT TRUSTWORTHY — THE CHECKPOINT COULD NOT BE READ.")
        for detail in reconciliation["detail"]:
            W(f"        {detail}")
        W("        Everything below is unquotable: there is no second opinion.")
    else:
        W("[GATE] ⚠⚠ NOT TRUSTWORTHY — the harness DISAGREES with the checkpoint.")
        for detail in reconciliation["detail"]:
            W(f"        {detail}")
        W("        Everything below is suspect. Fix the harness, not the number.")
    W(f"       corpus config: {corpus_config}")
    W()

    # ── section 1 · the obvious ones ────────────────────────────────────────
    W("─" * 78)
    W("1 · THE OBVIOUS ONES — read a credential, send it somewhere")
    W("─" * 78)
    for b in basic:
        W(f"  {b['state']:14} {b['sid']}")
    if basic_miss:
        W()
        W("  ⚠⚠ A BASIC SCENARIO MISSED. This is the most important line in this")
        W("     report — everything below is detail by comparison.")
        for b in basic_miss:
            W(f"     {b['sid']}: {b['why']}")
    else:
        W()
        W("  ✓ none of the obvious cases missed.")
    W()

    # ── section 2 · the two rates ───────────────────────────────────────────
    W("─" * 78)
    W("2 · THE TWO RATES — separately, with their denominators")
    W("─" * 78)
    W()
    W(f"  ATTACKS   ({len(attacks_run)} runnable)")
    W(f"    stopped at the decisive action   {_rate(len(blocked), len(attacks_run))}")
    W(f"    stopped as a PROMPT (ask)        {_rate(len(asked_a), len(attacks_run))}")
    W(f"    ⚠ MISSED                         {_rate(len(missed), len(attacks_run))}")
    W(f"        of which written to miss     {len(predicted)}  (the 'impossible' tier)")
    W(f"        ⚠ NOT predicted              {len(unpredicted)}")
    W()
    W(f"  NORMALS   ({len(normals_run)} runnable, MINED from real records)")
    W(f"    allowed — correct                {_rate(len(passed_n), len(normals_run))}")
    W(f"    escalated to a prompt (ask)      {_rate(len(asked_n), len(normals_run))}")
    W(f"    ⚠ FALSE POSITIVE                 {_rate(len(fps), len(normals_run))}")
    W()
    W("  ⚠ THESE ARE TWO RATES AND THEY ARE NEVER AVERAGED. Different")
    W("    denominators, different meanings. A single number hides whichever is")
    W("    worse, and it is always the false-positive half that gets hidden.")
    W()

    # ── section 3 · every miss, in full ─────────────────────────────────────
    W("─" * 78)
    W(f"3 · EVERY MISS ({len(missed)}) — the full command, so you can judge it")
    W("─" * 78)
    W()
    W("  NOT PREDICTED — these are the findings:")
    if not unpredicted:
        W("    (none)")
    for r in unpredicted:
        W(f"    {r['sid']}")
        W(f"      why  {r['why']}")
        W(f"      cmd  {_inline(r['command'])}")
    W()
    W("  WRITTEN TO MISS — outside what a PreToolUse hook can see. ⚠ A scenario")
    W("  that passes the day it is written tests nothing; these exist to mark")
    W("  the edge, and if one is ever CAUGHT that is a finding too:")
    for r in predicted:
        W(f"    {r['sid']}")
        W(f"      why  {r['why']}")
        W(f"      cmd  {_inline(r['command'])}")
    W()
    if caught_anyway:
        W(f"  ⚠ AND {len(caught_anyway)} OF THE 'IMPOSSIBLE' TIER WAS STOPPED ANYWAY.")
        W("    That is a finding in the other direction and it is printed here")
        W("    rather than counted as a win — it means either the scenario was")
        W("    not as unreachable as it was written to be, or the engine stopped")
        W("    it for a reason unrelated to the attack:")
        for r in caught_anyway:
            W(f"    {r['sid']}  ->  {r['state']}")
            W(f"      why  {r['why']}")
            W(f"      cmd  {_inline(r['command'])}")
        W()

    # ── section 4 · every false positive, in full ───────────────────────────
    W("─" * 78)
    W(f"4 · EVERY FALSE POSITIVE ({len(fps)}) — on work that really happened")
    W("─" * 78)
    W()
    W("  ⚠ EACH OF THESE WAS ALLOWED WHEN IT RAN. A developer did it, the engine")
    W("    of the day permitted it, and nothing broke. Today's engine stops it.")
    W("    The cwd and the declared boundary are printed because the question")
    W("    'was the engine right?' cannot be answered without them.")
    W()
    if not fps:
        W("    (none)")
    for r in fps:
        W(f"    rule   {r.get('rule_id')}")
        W(f"    cwd    {r.get('cwd')}")
        W(f"    roots  {r.get('roots')}")
        W(f"    cmd    {_inline(r['command'], _source_of(r))}")
        W()
    if asked_n:
        W(f"  and {len(asked_n)} normal(s) escalated to a PROMPT rather than blocked —")
        W("  the action still stops, but a human answers once:")
        for r in asked_n:
            W(f"    {r.get('rule_id')} :: {_inline(r['command'], _source_of(r))}")
        W()

    # ── section 5 · the ones with no right answer ───────────────────────────
    W("─" * 78)
    W(f"5 · DISAGREEMENT ({len(disagreements)}) — for a human, not a score")
    W("─" * 78)
    W()
    W("  ⚠ THE LABEL CANNOT BE ESTABLISHED WITHOUT JUDGEMENT, so these are")
    W("    reported and NOT counted as pass or fail. The generator deciding")
    W("    these would be the exact defect this corpus was built to avoid: its")
    W("    first oracle called `curl -d @.env` normal and then reported the")
    W("    engine's correct DENY as a false positive.")
    W()
    for r in disagreements:
        W(f"    {r['sid']}   engine said: {r['outcome'].upper()}")
        W(f"      {r['why']}")
        W(f"      cmd  {_inline(r['command'])}")
    W()

    # ── section 6 · what could not run ──────────────────────────────────────
    W("─" * 78)
    W(f"6 · COULD NOT RUN HERE ({len(na)}) — NOT_APPLICABLE, never MISSED")
    W("─" * 78)
    W()
    W("  ⚠ A4 HAS BEEN WRONG IN THIS DIRECTION TWICE. A scenario with no home on")
    W("    this machine is not an engine failure.")
    W()
    if not na:
        W("    (none — every scenario ran)")
    for r in na[:40]:
        W(f"    {r['sid']}: {r.get('reason', 'no reason recorded')}")
    if len(na) > 40:
        W(f"    … and {len(na) - 40} more")
    W()

    # ── section 7 · the shape of the corpus ─────────────────────────────────
    W("─" * 78)
    W("7 · WHAT WAS RUN")
    W("─" * 78)
    W()
    groups = collections.Counter(r["group"] for r in thousand)
    for group, count in sorted(groups.items()):
        W(f"    {count:5}  {group}")
    W(f"    {len(thousand):5}  TOTAL")
    W()
    W(f"    attacks {len(attacks)} · normals {len(normals)} · "
      f"disagreement {len(disagreements)}")
    W("    ⚠ the normals are the MAJORITY on purpose. 79 attacks against 25")
    W("      invented normals is a corpus that rewards blocking, and the")
    W("      rehearsal already showed the shape: 146 DENYs on real developer")
    W("      work, zero attacks.")
    W()

    # ── section 8 · what the numbers cannot say ─────────────────────────────
    W("─" * 78)
    W("8 · ⚠ WHAT THESE NUMBERS CANNOT TELL YOU")
    W("─" * 78)
    W()
    W("  ONE MACHINE. Every mined normal is from one laptop, one operating")
    W("  system, one filesystem layout. A developer whose repositories live")
    W("  somewhere else crosses a trust boundary this sample never crosses.")
    W()
    W("  ONE DEVELOPER'S HABITS. The mined half is what ONE person did while")
    W("  building this guard: heavy on git, python, pytest and curl to our own")
    W("  collector. It contains almost no Java, no Go, no Rails, no data-science")
    W("  notebook, and nothing from anybody who works differently.")
    W()
    W("  ONE LANGUAGE, ONE SHELL. zsh on macOS. The corpus is 0% Windows shell,")
    W("  and the Cursor-on-Windows transport has never run on a real machine.")
    W()
    W("  POLICY GIVEN PERFECT PARSING. These replay the actions each scenario")
    W("  INTENDS. A real agent might refuse, take a different route, or hand the")
    W("  engine a command shape the corpus never contains.")
    W()
    W("  AND THE ATTACKS ARE STILL OURS. Every one was written here. An attacker")
    W("  who has read this file writes the one that is not in it — which is why")
    W("  the 'impossible' tier exists and why its misses are reported rather")
    W("  than hidden.")
    W()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # ⚠ THE UNCLIPPED COMPANION. Truncation is only honest if the whole thing is
    # somewhere, and "somewhere" has to be a path rather than a promise.
    full = out.with_name(out.stem + ".full.txt")
    full.write_text("\n".join(
        f"{r['sid']}\n  state {r['state']}\n  rule  {r.get('rule_id')}\n"
        f"  cmd   {(r.get('command') or '').rstrip()}\n"
        for r in thousand
        if r["state"] in ("MISS", "FALSE_POSITIVE", "ASK", "DISAGREEMENT")
    ) + "\n", encoding="utf-8")

    W("─" * 78)
    W(f"log written to {out}")
    W(f"every miss/FP/ask/disagreement UNCLIPPED in {full}")
    W(f"{len(thousand)} scenarios in {time.time() - started:.1f}s")
    if basic_miss or not reconciliation["ok"]:
        W("⚠ exit non-zero: " + ("a basic scenario missed. "
                                  if basic_miss else "")
          + ("the harness does not reconcile." if not reconciliation["ok"] else ""))
    Path(out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 1 if (basic_miss or basic_fp or not reconciliation["ok"]) else 0


if __name__ == "__main__":
    sys.exit(main())
