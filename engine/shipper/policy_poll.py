"""The out-of-band policy poll: fetch this org's policy, cache it, fail safe.

⚠ RUNS ON THE SHIPPER LOOP, NEVER THE DECISION PATH. Same place and cadence as
the heartbeat — a `due()` gate and a `maybe_fetch()` the loop calls each cycle —
so no network ever touches the 12 ms decision budget. It GETs the collector's
`GET /v1/policy` with the device token the shipper already holds, and writes the
result to `core.org_policy`'s local cache, which the engine (step 3) reads with
no network. This module changes NO verdict; step 2 only makes the policy present,
current and safe on the machine.

⚠ FAIL SAFE, EVERY BRANCH — the whole point of this step. Getting the policy from
the collector must never fail-open, crash, weaken, or rewind:

  unreachable / 401 / 5xx / malformed  KEEP the last-good cache, never drop to
                                       "no policy". Logged once when it starts
                                       failing, so a stale cache is VISIBLE.
  `unchanged`                          KEEP the cache, no download.
  a NEWER version                      validate and replace; a malformed body is
                                       REFUSED (last-good kept), never partly
                                       stored.
  an OLDER or EQUAL version            IGNORE — never rewind to a staler policy.
                                       ⚠ A collector whose policy doc was DELETED
                                       answers version 0, which is older than any
                                       real cache, so it is ignored and the
                                       last-good is kept — protection never
                                       silently drops. An admin CLEARS an org's
                                       sources by writing an EMPTY-sources policy
                                       with a BUMPED version (newer, and applied),
                                       NOT by deleting the document; a literal
                                       deletion is intentionally ignored.
  404 (no endpoint)                    announce once, stop polling, behave as
                                       empty — an older collector; batches and
                                       heartbeats are unaffected.

A policy can only ever ADD stricter sources (severity `log|ask|deny`); there is
no field that turns the guard off, so absence, empty, failure and a poisoned
cache all collapse to today's protection, never less.
"""
from __future__ import annotations

import time

from core import org_policy
from shipper import client, config


class PolicyPoll:
    """Mirrors `shipper.heartbeat.Heartbeat`: a due-gated, never-raising call the
    shipper loop makes each cycle. Holds no policy in memory — the cache file is
    the state, so a crash or restart resumes from the last-good on disk."""

    def __init__(self, settings: config.Settings, *, now=time.time):
        self.settings = settings
        self.now = now
        self._last_polled = 0.0            # 0 -> the first loop cycle is due
        self.supported = True             # flips off on a 404, like the heartbeat
        self._announced_unsupported = False
        self._failing = False             # last poll failed — for log-once
        self._stale_logged = False        # collector returned a not-newer version

    def due(self) -> bool:
        return (self.supported and self.settings.configured
                and (self.now() - self._last_polled)
                >= max(1, self.settings.policy_seconds))

    def _url(self) -> str:
        # ⚠ `?since=<cached version>` so the collector answers `unchanged` cheaply.
        return (f"{self.settings.collector_url}/v1/policy"
                f"?since={org_policy.cached_version()}")

    def maybe_fetch(self, log=print) -> str | None:
        """One poll if due, else None. Never raises."""
        if not self.due():
            return None
        outcome = client.get(self._url(), self.settings.device_token,
                             timeout=self.settings.timeout_seconds)
        self._last_polled = self.now()
        return self._apply(outcome, log)

    # ── the fail-safe ladder ─────────────────────────────────────────────────
    def _apply(self, outcome, log) -> str:
        if outcome.kind == client.UNSUPPORTED:
            self.supported = False
            if not self._announced_unsupported:
                self._announced_unsupported = True
                log("  ⚠ this collector has no /v1/policy endpoint, so org policy "
                    "cannot be synced. The guard runs on its local defaults and "
                    "detection is unchanged; batches and heartbeats are "
                    "unaffected. See core/org_policy.py for the endpoint's shape.")
            return outcome.kind

        if not outcome.advances:          # UNAVAILABLE / UNAUTHORISED / REFUSED
            # ⚠ KEEP THE LAST-GOOD CACHE. A fetch problem never weakens anything.
            if not self._failing:
                self._failing = True
                log(f"  ⚠ org policy sync is failing ({outcome.kind}: "
                    f"{outcome.detail or outcome.status}). The guard keeps the "
                    f"last policy it fetched (version "
                    f"{org_policy.cached_version()}); retrying every "
                    f"{self.settings.policy_seconds}s.")
            return outcome.kind

        # 200 — either `unchanged`, or a full policy to weigh.
        self._note_recovery(log)
        body = outcome.body if isinstance(outcome.body, dict) else {}
        if body.get("unchanged"):
            return "unchanged"

        policy = body.get("policy")
        if not isinstance(policy, dict):
            log("  ⚠ org policy response was 200 but carried no usable policy; "
                "keeping the last-good cache.")
            return "malformed"
        remote_version = policy.get("version")
        if (not isinstance(remote_version, int) or isinstance(remote_version, bool)
                or remote_version < 0 or remote_version > org_policy.MAX_VERSION):
            # ⚠ NO USABLE VERSION — a missing/negative/implausibly-huge version is
            # a bogus response, not a real one. Refuse it so a giant version can
            # never be stored and freeze out real updates; keep the last-good.
            log("  ⚠ fetched policy has no usable version; keeping the last-good "
                "cache.")
            return "malformed"

        # ⚠ NEVER REWIND. Older or equal — a deleted doc's version 0 included — is
        # ignored; a real clear arrives as a BUMPED empty-sources policy. Logged
        # once so a device whose cache is ahead of the collector (a stale freeze)
        # is VISIBLE rather than silent.
        if remote_version <= org_policy.cached_version():
            if not self._stale_logged:
                self._stale_logged = True
                log(f"  ⚠ collector returned org policy version {remote_version}, "
                    f"not newer than the cached version "
                    f"{org_policy.cached_version()}; keeping the cache. If this "
                    f"persists, the cache is ahead of the collector.")
            return "not_newer"
        self._stale_logged = False

        try:
            org_policy.store(policy)
        except org_policy.PolicyRejected as rejected:
            # ⚠ A MALFORMED FETCHED POLICY, OR A CACHE WRITE THAT FAILED, IS
            # REFUSED WHOLE — last-good kept. `store()` raises PolicyRejected on
            # any write error (a poisoned inode, a full disk), so this branch
            # covers both.
            log(f"  ⚠ org policy version {remote_version} was not cached "
                f"({rejected}); keeping the last-good cache.")
            return "rejected"
        except Exception as exc:                                # noqa: BLE001
            # ⚠ THE LOOP MUST NEVER CRASH HERE. `store()` is meant to raise only
            # PolicyRejected, but an unforeseen error must still degrade to
            # keep-last-good rather than take down the shipper (and with it the
            # heartbeat and batch shipping), the same discipline `client.get` and
            # the heartbeat already follow.
            log(f"  ⚠ org policy could not be cached "
                f"({type(exc).__name__}: {exc}); keeping the last-good cache.")
            return "store_failed"
        return "stored"

    def _note_recovery(self, log):
        if self._failing:
            self._failing = False
            log("  ✓ org policy sync recovered.")
