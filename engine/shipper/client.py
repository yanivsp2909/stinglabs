"""The only code here that opens a socket. Outbound, stdlib, no listener.

⚠ EVERY RESPONSE IS CLASSIFIED, AND NONE OF THEM RAISES INTO THE LOOP. The
shipper runs unattended beside a developer's agent; a traceback that kills it
means a laptop that silently stops reporting, which is exactly the state the
heartbeat exists to make visible. So the client answers with an Outcome and the
loop decides.

⚠ AND 202 IS NOT A FAILURE. The collector answers 202 when a batch was STORED
and did not continue what it already held — a gap. The batch is safe; the
information is that something earlier never arrived. Treating it as an error
would stall the cursor behind a hole that will never fill, and the shipper would
re-send the same batch forever while the log grew.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from shipper import config

# What the loop does about it. The name is the instruction.
STORED = "stored"                 # 200 — advance
STORED_WITH_GAP = "stored_gap"    # 202 — advance, and remember the gap
TOO_LARGE = "too_large"           # 413 — split and retry
UNAUTHORISED = "unauthorised"     # 401/403 — long backoff, do not advance
UNAVAILABLE = "unavailable"       # unreachable / 5xx — backoff, do not advance
REFUSED = "refused"               # 400 — the batch is wrong; do not loop on it
UNSUPPORTED = "unsupported"       # 404 — the endpoint does not exist here


@dataclass
class Outcome:
    kind: str
    status: int = 0
    body: dict = field(default_factory=dict)
    detail: str = ""

    @property
    def advances(self) -> bool:
        return self.kind in (STORED, STORED_WITH_GAP)


def _classify(status: int, body: dict) -> Outcome:
    if status == 200:
        return Outcome(STORED, status, body)
    if status == 202:
        return Outcome(STORED_WITH_GAP, status, body,
                        detail=(body.get("gap") or {}).get("meaning", "a gap"))
    if status == 413:
        return Outcome(TOO_LARGE, status, body,
                        detail=body.get("reason", "too large"))
    if status in (401, 403):
        return Outcome(UNAUTHORISED, status, body,
                        detail=body.get("error") or body.get("reason", ""))
    if status == 404:
        return Outcome(UNSUPPORTED, status, body)
    if status == 400:
        return Outcome(REFUSED, status, body, detail=body.get("reason", ""))
    return Outcome(UNAVAILABLE, status, body,
                    detail=body.get("reason", f"HTTP {status}"))


def _refused(url: str) -> Outcome | None:
    """A URL the token must never travel to (item E): UNAVAILABLE, not REFUSED.

    ⚠ UNAVAILABLE ON PURPOSE. REFUSED means "this batch is wrong" and the loop
    may give up on it; a wrong URL is the operator's to fix, so the loop backs
    off, keeps every record and retries once the setting is right. No socket is
    opened, so nothing leaves in cleartext."""
    reason = config.collector_url_refusal(url)
    return Outcome(UNAVAILABLE, 0, {}, detail=reason) if reason else None


def post(url: str, token: str, payload: bytes, *, timeout: float = 30.0) -> Outcome:
    """POST and classify. Never raises."""
    refused = _refused(url)
    if refused:
        return refused
    try:
        # ⚠ INSIDE THE TRY. `Request()` itself raises ValueError on a URL with
        # no scheme — `STING_COLLECTOR_URL=collector.example.com` without the
        # `http://` is the obvious typo — and constructing it outside meant a
        # misconfigured setting killed the loop instead of being classified.
        # Found by the test that posts to five bad URLs and requires that none
        # of them raise.
        request = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return _classify(response.status, _json(response.read()))
    except urllib.error.HTTPError as exc:
        return _classify(exc.code, _json(_safe_read(exc)))
    except urllib.error.URLError as exc:
        # ⚠ URLError SUBCLASSES OSError AND IS CAUGHT FIRST, so the broken-pipe
        # classification below is unreachable for anything urllib wraps — which
        # is everything. The first version of this file put that logic only in
        # the OSError arm and the path never fired: the collector logged 413,
        # the shipper logged "unavailable", and it backed off forever on a batch
        # it could have split. Found by testing against the real collector, and
        # a stub returning a clean 413 would have hidden it completely.
        if _closed_mid_upload(exc.reason):
            return Outcome(TOO_LARGE, 0, {}, detail="connection closed mid-upload")
        # DNS failure, connection refused, timeout, no route, captive portal.
        # All one thing to the loop: try again later, lose nothing.
        return Outcome(UNAVAILABLE, 0, {}, detail=str(exc.reason))
    except ValueError as exc:
        # A malformed collector URL. Not transient, but not fatal either: say so
        # and let the loop back off, so the records keep accumulating.
        return Outcome(UNAVAILABLE, 0, {}, detail=f"bad collector url: {exc}")
    except OSError as exc:
        # ⚠ A BROKEN PIPE IS EXPECTED HERE. The collector refuses an oversized
        # body WITHOUT reading it, which is the size cap working — so a large
        # POST can die mid-upload before any response is read. Classified as
        # TOO_LARGE rather than UNAVAILABLE so the loop splits instead of
        # backing off and retrying the same oversized batch forever.
        if _closed_mid_upload(exc):
            return Outcome(TOO_LARGE, 0, {}, detail="connection closed mid-upload")
        return Outcome(UNAVAILABLE, 0, {}, detail=str(exc))
    except Exception as exc:                                     # noqa: BLE001
        # The loop must survive anything. An unattended shipper that dies is a
        # laptop that stops reporting without saying so.
        return Outcome(UNAVAILABLE, 0, {},
                        detail=f"unexpected {type(exc).__name__}: {exc}")


def get(url: str, token: str, *, timeout: float = 30.0) -> Outcome:
    """GET and classify. Never raises — the read half of `post`.

    Same Bearer credential, the same `Outcome` vocabulary, and the same
    discipline that an unreachable collector or a misconfigured URL is
    CLASSIFIED rather than raised: the policy poll that calls this runs on the
    shipper loop, and a traceback there is a laptop that silently stops polling.
    There is no upload body, so the `TOO_LARGE`/mid-upload arm `post` needs does
    not apply — every transport failure is one thing to the caller: UNAVAILABLE,
    keep the last-good cache, try again later.
    """
    refused = _refused(url)
    if refused:
        return refused
    try:
        request = urllib.request.Request(
            url, method="GET",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return _classify(response.status, _json(response.read()))
    except urllib.error.HTTPError as exc:
        return _classify(exc.code, _json(_safe_read(exc)))
    except urllib.error.URLError as exc:
        # DNS failure, connection refused, timeout, no route, captive portal.
        return Outcome(UNAVAILABLE, 0, {}, detail=str(exc.reason))
    except ValueError as exc:
        # A malformed collector URL (`Request()` raises on a scheme-less URL).
        return Outcome(UNAVAILABLE, 0, {}, detail=f"bad collector url: {exc}")
    except Exception as exc:                                     # noqa: BLE001
        return Outcome(UNAVAILABLE, 0, {},
                        detail=f"unexpected {type(exc).__name__}: {exc}")


def _closed_mid_upload(reason) -> bool:
    """Did the peer hang up while we were still sending?

    ⚠ THE SIGNATURE OF A SIZE REFUSAL. The collector refuses an oversized body
    WITHOUT reading it — which is its size cap working — so the socket dies
    mid-upload and no response is ever read. EPIPE (32) and ECONNRESET (54 on
    macOS, 104 on Linux) are how that arrives.

    ⚠ AND IT IS AMBIGUOUS, WHICH IS FINE. A collector that crashes mid-upload
    resets too. Reading it as TOO_LARGE means the shipper halves the batch and
    retries; if the collector is genuinely down, the halves fail as well and it
    backs off exactly as before. The mis-read costs at most a couple of extra
    attempts and is self-correcting — while the opposite mis-read, treating a
    size refusal as "unavailable", backs off forever on a batch that would
    succeed if split.
    """
    errno = getattr(reason, "errno", None)
    return errno in (32, 54, 104) or "Broken pipe" in str(reason) \
        or "reset by peer" in str(reason)


def _safe_read(exc) -> bytes:
    try:
        return exc.read()
    except Exception:                                            # noqa: BLE001
        return b""


def _json(raw: bytes) -> dict:
    try:
        parsed = json.loads(raw.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:                                            # noqa: BLE001
        return {}
