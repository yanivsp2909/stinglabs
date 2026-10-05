"""A machine enrolling itself, so nobody mints a token by hand.

⚠ WHAT THIS REPLACES, AND WHY IT IS THE THING BLOCKING A CUSTOMER. Today an
operator runs `device_token.py issue`, reads a token off their terminal, and
sends it to a developer who pastes it into an install command. Fine for two
machines. For a customer it is impossible — and the failure is not effort, it is
that **the token travels through a chat window**, which is the one place a bearer
credential must never be.

⚠ THE TRADE IS THE COLLECTOR'S AND IT IS NOT HIDDEN HERE. A leaked device token
is one machine's records; a leaked ENROLMENT SECRET MINTS DEVICES.
the collector's `docs/enrolment.md` argues why that is acceptable and bounds it
four ways — an expiry, a use cap, every enrolment visible, and revocation that
does not touch devices already enrolled. Two of its own limits matter to this
file and are repeated rather than assumed:

  * **a shared secret cannot prove WHICH machine presents it.** Anyone holding it
    can enrol claiming any device id. That is inherent, and the collector
    refuses a COLLISION rather than merging so the failure is loud.
  * **the trade only survives because a device credential has no read.** The
    worst case for a leaked enrolment secret is an attacker who can write
    records into one org, not one who can read anybody's commands.

────────────────────────────────────────────────────────────────────────────────
⚠ ONE STRING, AND THAT IS THE WHOLE REQUIREMENT
────────────────────────────────────────────────────────────────────────────────

    sting-enrol-v1.<base64url({"url": "...", "secret": "..."})>

The URL travels WITH the secret because two fields is two things to get wrong,
and because a person who pastes the right secret at the wrong collector gets a
401 that tells them nothing useful. Everything else — the org, the device id —
comes from the enrolment or from the machine. **If a person still types four
things, this has not solved the problem it exists for.**

────────────────────────────────────────────────────────────────────────────────
⚠ AND EVERY FAILURE MUST LEAVE THE MACHINE UNINSTALLED
────────────────────────────────────────────────────────────────────────────────

This project has shipped a guard that reported success and guarded nothing,
twice. So enrolment happens BEFORE anything is placed, and every failure path
returns a `Failure` that `install.py` turns into an exit — never into a warning
over a half-installed machine. There is no state in which enrolment failed and
a hook config was still written.
"""
from __future__ import annotations

import base64
import json
import platform
import re
import socket

PREFIX = "sting-enrol-v1."
"""⚠ VERSIONED IN THE STRING ITSELF. A person pastes this into a terminal; the
day the shape changes, an old string must be refused with a sentence rather than
decoded into something almost right."""

MAX_STRING = 4096
"""A pasted credential, not a payload. Bounded before any decode."""

_SAFE_DEVICE = re.compile(r"[^A-Za-z0-9._-]+")

# ⚠ A STANDALONE MIRROR OF `shipper.config.collector_url_refusal` (item E). This
# file must stay importable on its own — the collector's contract test loads it
# by path — so it cannot import the shipper's rule. The two are pinned equal by
# tests/test_collector_url_must_be_https.py; change both or neither.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def collector_url_refusal(url: str | None) -> str | None:
    """None when `url` may receive the enrolment secret; otherwise why not.
    https://, or http:// to a loopback name. Never repeats the URL."""
    import urllib.parse

    try:
        parts = urllib.parse.urlsplit(url or "")
        host = (parts.hostname or "").lower()
    except ValueError:
        return "the collector URL cannot be parsed; it must be an https:// URL"
    scheme = parts.scheme.lower()
    if scheme == "https" and host:
        return None
    if scheme == "http" and host in _LOOPBACK_HOSTS:
        return None
    return ("the collector URL must be https:// — anything else would send the "
            "enrolment secret, the device token and every batch in cleartext")


class Failure(Exception):
    """A refusal with a sentence a person can act on.

    ⚠ EACH FAILURE GETS ITS OWN SENTENCE, WHICH IS TASK 1.4 AND THE HALF THAT
    MATTERS. "Enrolment failed" tells somebody nothing: an expired secret, a
    used-up cap, a revoked secret, no network and a wrong URL have five
    different next actions, and four of them are not "ask for a new secret".
    """

    def __init__(self, headline: str, *lines: str):
        super().__init__(headline)
        self.headline = headline
        self.lines = list(lines)

    def render(self) -> str:
        out = [f"  ⚠ ENROLMENT FAILED — {self.headline}"]
        out += [f"    {line}" for line in self.lines]
        out.append("    ⚠ NOTHING WAS INSTALLED. This machine is unchanged, and "
                    "it is not guarded.")
        return "\n".join(out)


def decode(value: str) -> tuple:
    """(url, secret) from an enrolment string, or raise `Failure`.

    ⚠ REFUSED BEFORE ANY NETWORK CALL. A typo in the string must not become a
    connection attempt to whatever the typo happens to spell.
    """
    if not isinstance(value, str) or not value.strip():
        raise Failure("the enrolment string is empty")
    value = value.strip()
    if len(value) > MAX_STRING:
        raise Failure(f"the enrolment string is longer than {MAX_STRING} "
                       f"characters, which is not one of ours")
    if not value.startswith(PREFIX):
        raise Failure(
            f"that does not look like an enrolment string",
            f"it must begin with `{PREFIX}`",
            "you may have been sent a device TOKEN instead — that goes in "
            "`--device-token`, not `--enrol`")
    body = value[len(PREFIX):]
    try:
        # ⚠ PADDING RESTORED RATHER THAN REQUIRED. base64url without `=` is what
        # survives being pasted through chat, a spreadsheet and a ticket.
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        fields = json.loads(raw)
    except Exception:                                            # noqa: BLE001
        raise Failure("the enrolment string is damaged and cannot be decoded",
                       "copy it again — a line break or a trailing space is "
                       "the usual cause") from None
    if not isinstance(fields, dict):
        raise Failure("the enrolment string does not contain an enrolment")
    url = fields.get("url")
    secret = fields.get("secret")
    if not isinstance(url, str) or not url:
        raise Failure("the enrolment string names no usable collector URL")
    refusal = collector_url_refusal(url)
    if refusal:
        raise Failure("the enrolment string names a collector this installer "
                       "will not send a secret to", refusal,
                       "ask for a new enrolment string that names an https:// "
                       "collector")
    if not isinstance(secret, str) or not secret:
        raise Failure("the enrolment string carries no secret")
    return url.rstrip("/"), secret


def propose_device_id(hostname: str | None = None) -> str:
    """This machine's name, from the machine.

    ⚠ TASK 1.3 — WHERE IT COMES FROM AND WHY NOT SOMETHING UNIQUE. The hostname
    is what a human recognises in a fleet list, and a device id nobody can
    recognise makes the whole device view useless. A uuid would never collide
    and would also never mean anything.

    The collector NAMESPACES it by the enrolment digest, so two people who both
    call their laptop `laptop` do not collide by accident. What remains is a
    genuine conflict — two machines enrolled from the SAME secret claiming one
    name — and the endpoint refuses that with 409 rather than merging, because
    a second credential for an existing device id would let one developer write
    records that read as another's machine.
    """
    name = hostname if hostname is not None else socket.gethostname()
    name = (name or "").split(".")[0]
    name = _SAFE_DEVICE.sub("-", name).strip("-")
    return name[:48] or "device"


def request_body(device_id: str, label: str = "") -> bytes:
    body = {"device_id": device_id, "os": platform.system() or "unknown"}
    if label:
        body["label"] = label[:120]
    return json.dumps(body).encode("utf-8")


# ⚠ ONE SENTENCE PER STATUS, AND THE STATUSES ARE THE COLLECTOR'S. Anything not
# listed falls through to a generic refusal that still says nothing was
# installed — an unknown status must not be optimistically treated as success.
def _explain(status: int, reason: str, device_id: str, url: str) -> Failure:
    if status == 401:
        return Failure(
            "the collector refused this enrolment secret",
            f"it said: {reason}",
            "an enrolment secret EXPIRES and can be REVOKED — both land here.",
            "ask whoever sent it for a new one; they run "
            "`tools/enrolment.py issue`.")
    if status == 429:
        return Failure(
            "this enrolment secret has been used up",
            f"it said: {reason}",
            "it has a USE CAP — that is deliberate, and it is what stops a "
            "leaked secret minting machines forever.",
            "ask for a new secret, or for the cap to be raised.")
    if status == 409:
        return Failure(
            f"a device called {device_id!r} is already enrolled in that org",
            "the collector refuses this rather than merging, because a second "
            "credential for one device id would let this machine's records read "
            "as another's.",
            f"choose a different name:  python3 install.py --enrol <string> "
            f"--device-id {device_id}-2")
    if status == 404:
        return Failure(
            "that collector does not offer enrolment",
            # ⚠ NOT AN f-STRING AROUND THE ROUTE. The collector's route
            # contract AST-scans this repo for `f"{base}/v1/…"` to enumerate
            # every endpoint the engine calls — and a prose sentence built that
            # way registered as a route named "/v1/enrol` returned 404.", which
            # failed the collector's suite while this one stayed green.
            f"`POST /v1/enrol` at {url} returned 404.",
            "the collector is reachable but is running a build without the "
            "enrolment endpoint — it needs deploying before this can work.",
            "meanwhile a token issued by hand still works: "
            "`--collector-url … --device-token … --device-id …`")
    if status == 413:
        return Failure("the collector refused the request as too large",
                        f"it said: {reason}")
    return Failure(f"the collector answered {status}",
                    f"it said: {reason}" if reason else
                    "and gave no reason this installer understands.")


def enrol(url: str, secret: str, device_id: str, label: str = "",
          opener=None, timeout: float = 20.0) -> dict:
    """POST /v1/enrol. Returns the collector's body, or raises `Failure`.

    ⚠ THE SECRET GOES IN A HEADER WITH ITS OWN SCHEME — `Authorization:
    Enrolment` — never `Bearer`. The collector refuses a Bearer here and refuses
    an Enrolment on `/v1/batches`, so a leaked enrolment secret can never also
    be a writer. That separation is the collector's, and sending it any other
    way would silently defeat it.
    """
    import urllib.error
    import urllib.request

    # ⚠ REFUSED BEFORE THE REQUEST EXISTS: the secret is in its header.
    refusal = collector_url_refusal(url)
    if refusal:
        raise Failure("this installer will not send the enrolment secret there",
                       refusal)
    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(
        f"{url}/v1/enrol", data=request_body(device_id, label), method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Enrolment {secret}"})
    try:
        with opener(request, timeout=timeout) as response:
            payload = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read() or b"{}")
        except Exception:                                        # noqa: BLE001
            body = {}
        raise _explain(exc.code, str(body.get("reason") or ""),
                        device_id, url) from None
    except urllib.error.URLError as exc:
        raise Failure(
            "the collector could not be reached",
            f"{url} — {exc.reason}",
            "check the URL and the network. Nothing was sent, and the secret "
            "is still good.") from None
    except Exception as exc:                                     # noqa: BLE001
        raise Failure("the enrolment call failed",
                       f"{type(exc).__name__}: {exc}") from None

    # ⚠ A 200 THAT DOES NOT CARRY A TOKEN IS A FAILURE, NOT A SUCCESS. Reading
    # a missing key as an empty string is how a machine ends up installed with
    # no credential and a green install log.
    token = payload.get("device_token")
    if not payload.get("enrolled") or not isinstance(token, str) or not token:
        raise Failure(
            "the collector accepted the request but returned no device token",
            f"it said: {json.dumps(payload)[:200]}",
            "this is a collector-side problem; nothing here can fix it.")
    return {
        "device_token": token,
        "device_id": payload.get("device_id") or device_id,
        "org": payload.get("org") or "",
        "url": url,
    }
