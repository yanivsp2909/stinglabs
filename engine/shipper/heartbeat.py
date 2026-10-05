"""Proof that the guard is still alive, as opposed to merely quiet.

⚠ THE PROBLEM IT EXISTS FOR. The canary proves a session STARTED. Nothing proves
a session is still being watched. So a laptop that is switched off and a laptop
running with a dead hook look identical from the collector: silence. The second
is the dangerous one — an agent acting with no guard at all — and it is
indistinguishable from a weekend.

⚠ IT IS NOT A LOG RECORD AND MUST NOT ENTER THE HASH CHAIN. Argued, not assumed:

  A CHAIN RECORD IS A CLAIM ABOUT AN ACTION. `H(n) = SHA-256(H(n-1) +
  canonical(body))` exists so that a decision cannot be edited or removed after
  the fact without the chain breaking. A heartbeat describes no action and no
  decision; it says "this process was running at 14:32". Putting it in the chain
  would make the chain's own contents partly a function of how often a timer
  fired, and the number of records in a session would stop being the number of
  things that happened.

  IT WOULD ALSO BREAK THE THING IT SITS BESIDE. The shipper sends batches whose
  `continues_from` is the hash of the last record shipped. If heartbeats joined
  the chain, they would have to be written by the HOOK (only the hook holds the
  chain's tail and the lock) — which means a timer inside the latency-critical
  process, waking on a schedule, taking the session lock, on the 12 ms path. The
  hook writes when an action happens and at no other time; that is the property
  that keeps it cheap and predictable.

  AND THE OPPOSITE CASE, HONESTLY. A chained heartbeat would be tamper-evident:
  an attacker who silences the guard could not remove the heartbeats that
  preceded it without breaking the chain. But an UNCHAINED heartbeat that stops
  arriving is already visible — absence is the signal, and absence cannot be
  forged by deleting a record. The chain protects records that EXIST from being
  altered; liveness is about records that DO NOT exist. Different problem,
  different mechanism.

⚠ THE COLLECTOR RECEIVES IT NOW — `POST /v1/heartbeat`, and it records
`via="heartbeat"` so silence stops meaning two things at once. The 404 path below
is KEPT anyway: a developer may point this at an older collector, and a shipper
that crashed or spammed in that case would be worse than one that says so once
and carries on shipping batches. `docs/21-heartbeat-gap.md` remains the record of
what was missing and what closed it.
"""
from __future__ import annotations

import platform
import time

from core import wire
from shipper import client, config


# The window the collector accepts, mirrored rather than imported: it is a
# separate repo and is not installed on this machine. If the two ever disagree
# the cost is a heartbeat whose interval is ignored, never a rejected heartbeat —
# the collector treats an out-of-range value as "not declared" and falls back.
COLLECTOR_MIN_INTERVAL = 30
COLLECTOR_MAX_INTERVAL = 86_400


def _clamped_interval(seconds) -> float:
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return float(config.HEARTBEAT_SECONDS)
    return float(min(COLLECTOR_MAX_INTERVAL, max(COLLECTOR_MIN_INTERVAL, value)))


def _clamp_note(seconds) -> str | None:
    """One line naming what `_clamped_interval` changed and to what — None when
    it changed nothing. It used to fall back or clamp in silence (item 9)."""
    sent = _clamped_interval(seconds)
    try:
        if float(seconds) == sent:
            return None
        why = (f"outside the collector's {COLLECTOR_MIN_INTERVAL}.."
               f"{COLLECTOR_MAX_INTERVAL} s window")
    except (TypeError, ValueError):
        why = "not a number, so the default is used"
    return (f"  ⚠ heartbeat interval {str(seconds)[:40]!r} is {why}: "
            f"declared as {sent:g} s")


class Heartbeat:
    def __init__(self, settings: config.Settings, cursor, *, now=time.time):
        self.settings = settings
        self.cursor = cursor
        self.now = now
        self.started_at = now()
        self._last_sent = 0.0
        self.supported = True          # until a 404 says otherwise
        self._announced = False
        self._clamp_said = False       # `_clamp_note`, once

    def payload(self) -> dict:
        """device, current cursor, guard ref, agent, uptime.

        `agent` is absent when no session has shipped yet — stated as null
        rather than guessed, because "which agent" is a fact about traffic and
        this process has seen none.
        """
        sessions = self.cursor.summary()
        return {
            "kind": "heartbeat",
            "wire_version": wire.WIRE_VERSION,
            "device_id": self.settings.device_id,
            "sent_at": self.now(),
            "uptime_seconds": round(self.now() - self.started_at, 1),
            # ⚠ DECLARED, SO THE COLLECTOR DOES NOT HAVE TO GUESS. Until this
            # field existed the collector could only OBSERVE the interval from
            # the gaps between heartbeats, which needs two of them — so a device
            # that sent one and died had no computable staleness threshold and
            # was reported as "unknown" forever. One number closes that.
            #
            # CLAMPED TO THE RANGE THE COLLECTOR ACCEPTS (30 s .. 24 h, read
            # from the collector's heartbeat handler). Sending a value
            # outside it is not an error there — it is ignored, and the device
            # silently falls back to "observed". Clamping here means a local
            # STING_HEARTBEAT_INTERVAL of 5 arrives as 30 and is USED, instead
            # of arriving as 5 and being discarded.
            "interval_seconds": _clamped_interval(self.settings.heartbeat_seconds),
            "guard_ref": wire.guard_ref(),
            # ⚠ WHAT THIS MACHINE SHIPS, NOT A SETTING: `masked`, or `held`
            # until install.py records the agreement (`config.HELD`). A claim,
            # like the rest; the collector carries it verbatim.
            "tier": self.settings.what_ships()["ships"],
            "os": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
            # ⚠ THE CURSOR, NOT THE LOG. What has been SHIPPED is the only thing
            # this process knows for certain; how much the hook has written is a
            # measurement, and a heartbeat that reported it would be reporting a
            # number it had to go and compute on a timer.
            # ⚠ NO `ends_at`: it is the LOCAL hash, sha256 over a raw record,
            # and every batch keys it (core/wire.py). The collector neither
            # stores nor reads this map (its heartbeat.py: "deliberately NOT
            # stored"), so it goes rather than being keyed.
            "cursor": {session: {"shipped": p["shipped"],
                                  "last_seq": p["last_seq"]}
                        for session, p in sessions.items()},
            "sessions_tracked": len(sessions),
            # ⚠ SAID IN THE PAYLOAD, so a collector that stores this cannot
            # mistake it for evidence of anything but a running process.
            "attests": ("a shipper process was running at sent_at. NOT that the "
                         "hook is installed, NOT that it is deciding correctly, "
                         "and NOT that anything was recorded."),
        }

    def due(self) -> bool:
        return (self.supported
                and self.settings.configured
                and (self.now() - self._last_sent) >= self.settings.heartbeat_seconds)

    def maybe_send(self, log=print) -> str | None:
        if not self.due():
            return None
        import json

        note = None if self._clamp_said else _clamp_note(self.settings.heartbeat_seconds)
        if note:
            self._clamp_said = True
            log(note)

        outcome = client.post(
            f"{self.settings.collector_url}/v1/heartbeat",
            self.settings.device_token,
            json.dumps(self.payload(), sort_keys=True).encode("utf-8"),
            timeout=self.settings.timeout_seconds)
        self._last_sent = self.now()

        if outcome.kind == client.UNSUPPORTED:
            # ⚠ ONCE, THEN STOP. A 404 every 15 minutes forever is noise that
            # trains the operator to ignore this process's output.
            self.supported = False
            if not self._announced:
                self._announced = True
                log("  ⚠ this collector has no /v1/heartbeat endpoint, so "
                     "liveness cannot be reported. Batches are unaffected. "
                     "See docs/21-heartbeat-gap.md for exactly what the "
                     "collector would need to add.")
            return outcome.kind
        return outcome.kind
