"""What a session IS — declared where it is WRITTEN, not guessed where it is read.

⚠ THE HALF-DONE JOB THIS FINISHES. `purpose` on the BATCH could be declared by
`install.py` and by preflight, because both hand-build a batch and know what
they are. It could not be declared for a developer's session, because the
sending loop ships whatever is in the session root and a real session, a
preflight log and `bench-sub` are the same shape — same writer, same directory,
same suffix, real chains, records carrying `agent: claude-code` because that is
the adapter that parsed them. So `work` was the value nothing declared, and a
measurement could exclude declared probes while still being unable to say "over
declared work".

The fix is upstream of the reader: **the process that WRITES the session knows
what it is, and it is the only thing that does.** `build_body` already carries
`agent` and `guard_version` for exactly this class of question.

────────────────────────────────────────────────────────────────────────────────
WHERE THE VALUE COMES FROM, AND WHY THAT IS A DECLARATION RATHER THAN A DEFAULT
────────────────────────────────────────────────────────────────────────────────

`STING_PURPOSE`, read by the hook the same way it reads `STING_OBSERVE`,
`STING_ROOTS` and `STING_SCRATCH`. `install.py` bakes it into the hook command
it writes into each agent's config, so records produced by a wired-up agent hook
declare `work`; every harness that drives the hook for another reason sets its
own value in its own invocation, which is the one place that knows.

⚠ **THIS IS NOT THE TRAP THE FIELD WAS BUILT TO AVOID, AND THE DIFFERENCE IS
STRUCTURAL RATHER THAN RHETORICAL.** The trap is *absence defaulting to the
common case* — `purpose = record.get("purpose") or WORK`, a read-time coercion
of "nobody said" into "the usual thing". Nothing here does that. Absence stays
absent all the way to the reader and keeps meaning "nobody said".

What this is instead is the same act as `STING_ROOTS`: a human runs an installer
that writes a value into a config they can see and that the installer prints. The
project already treats that as legitimate and says so — *a trust boundary is a
declaration, so it is confirmed and never inferred.* Declaring "records produced
by this agent hook are my work" is the same kind of statement, made in the same
place, by the same person, revocable in the same file.

⚠ **THE OBJECTION WITH TEETH IS SCOPE, and it is answered by the definition.**
The baked value declares work for everything that agent ever does, which sounds
too broad until you ask what `purpose` means: it is what PRODUCED the session,
not what the session was ABOUT. A developer directing an agent is work even when
the task at hand is benchmarking. What must never claim work is a HARNESS driving
the hook with no developer behind it — and the price of this design is that every
such harness must declare itself. Three of the four in this repo did not, which
is the strongest evidence that the objection is real; they now do.

⚠ **WHAT ABSENCE MEANS AFTERWARDS, INCLUDING THE AMBIGUITY.** "Not written by a
wired-up agent hook" — a harness that declares nothing, a hand-run hook, or an
install predating this field. Those last two are not distinguishable from each
other, and that is a genuine limit rather than a detail: a machine installed last
month produces absent records forever until it is reinstalled.
"""
from __future__ import annotations

import os

WORK = "work"
"""A developer's session, produced by a wired-up agent hook."""

INSTALL_PROBE = "install_probe"
"""install.py's empty authenticated batch. Zero records, one session."""

PREFLIGHT = "preflight"
"""tools/preflight.py — a real record with a real chain, on every install."""

BENCHMARK = "benchmark"
"""tools/bench_latency.py, which drives the REAL hook with a synthetic payload.

⚠ THIS MEMBER WAS REFUSED ONE PASS AGO AND NOW EXISTS, WHICH IS THE RULE
WORKING RATHER THAN BENDING. It was refused because nothing SENT it: `bench-sub`
reaches a collector by being swept out of the ordinary session root like any
other log, so no batch-level sender could ever declare it. At RECORD level it
has a producer — the harness spawns the hook itself and owns that environment —
so the member now has a sender and may exist. A member with no sender still does
not."""

PURPOSES = (WORK, INSTALL_PROBE, PREFLIGHT, BENCHMARK)

ENV_VAR = "STING_PURPOSE"


def declared() -> str | None:
    """What this process's environment declares, or None for "nobody said".

    ⚠ NEVER RAISES AND NEVER GUESSES. An unrecognised value returns None rather
    than being passed through: an unknown claim reaching a reader is worse than
    no claim, because a reader cannot tell a typo from a member they have not
    learned yet. And quietly widening a closed set at the writing end is how a
    closed set stops being one.

    ⚠ AND IT NEVER FALLS BACK TO `WORK`. That single line is the whole
    difference between this and the trap.
    """
    value = (os.environ.get(ENV_VAR) or "").strip()
    return value if value in PURPOSES else None
