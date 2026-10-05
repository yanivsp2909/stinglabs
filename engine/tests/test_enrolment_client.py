"""A machine enrolling itself — the client half.

⚠ THE THING THAT BLOCKS A CUSTOMER IS NOT EFFORT, IT IS THE CHAT WINDOW. Today
an operator mints a token by hand and sends it to a developer, which puts a live
bearer credential in a message. One pasted enrolment string replaces that.

⚠ AND EVERY FAILURE MUST LEAVE THE MACHINE UNINSTALLED. This project has shipped
a guard that reported success and guarded nothing twice, and both times the
cause was a step that failed AFTER the point of no return. Enrolment therefore
runs in section 4, before the tree is placed in 6 and before hook configs are
written in 7 — so there is no state in which enrolment failed and a hook config
exists.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from installer import enrol

ROOT = Path(__file__).resolve().parent.parent


def a_string(url="https://c.example/ingest", secret="s3cret-value"):
    blob = base64.urlsafe_b64encode(
        json.dumps({"url": url, "secret": secret}).encode()).decode().rstrip("=")
    return enrol.PREFIX + blob


class _Response:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(status, reason):
    import urllib.error
    import io

    return urllib.error.HTTPError(
        "https://c.example/v1/enrol", status, "err", {},
        io.BytesIO(json.dumps({"enrolled": False, "reason": reason}).encode()))


# ══════════════════════════════ 1.2 · one string, and only one ══

def test_the_url_travels_inside_the_string():
    """⚠ IF A PERSON STILL TYPES FOUR THINGS, THIS HAS NOT SOLVED THE PROBLEM IT
    EXISTS FOR. The URL is in the string because two fields is two things to get
    wrong — and a right secret at the wrong collector is a 401 that explains
    nothing."""
    url, secret = enrol.decode(a_string())
    assert url == "https://c.example/ingest"
    assert secret == "s3cret-value"


def test_padding_is_restored_rather_than_required():
    """base64url without `=` is what survives being pasted through chat, a
    spreadsheet and a ticket."""
    for secret in ("a", "ab", "abc", "abcd"):
        url, got = enrol.decode(a_string(secret=secret))
        assert got == secret


@pytest.mark.parametrize("value,expect", [
    ("", "empty"),
    ("   ", "empty"),
    ("not-an-enrolment-string", "does not look like"),
    ("sting-enrol-v1.@@@not-base64@@@", "damaged"),
    (enrol.PREFIX + base64.urlsafe_b64encode(b'"a string"').decode().rstrip("="),
     "does not contain an enrolment"),
    (enrol.PREFIX + base64.urlsafe_b64encode(
        json.dumps({"secret": "x"}).encode()).decode().rstrip("="),
     "no usable collector URL"),
    (enrol.PREFIX + base64.urlsafe_b64encode(
        json.dumps({"url": "https://c.example"}).encode()).decode().rstrip("="),
     "no secret"),
])
def test_a_damaged_string_is_refused_before_any_network_call(value, expect):
    """⚠ A TYPO MUST NOT BECOME A CONNECTION TO WHATEVER THE TYPO SPELLS."""
    with pytest.raises(enrol.Failure) as caught:
        enrol.decode(value)
    assert expect in caught.value.headline


def test_a_device_token_pasted_by_mistake_says_so():
    """The likeliest wrong paste, and it deserves its own sentence."""
    with pytest.raises(enrol.Failure) as caught:
        enrol.decode("Mll-BgCikQ0zX3sTOKENLOOKINGTHING")
    assert "device TOKEN" in "\n".join(caught.value.lines)


# ══════════════════════════════════════ 1.3 · the device id ══

def test_the_device_id_comes_from_the_machine_and_is_recognisable():
    """⚠ A UUID WOULD NEVER COLLIDE AND WOULD ALSO NEVER MEAN ANYTHING. The
    hostname is what a human picks out of a fleet list."""
    assert enrol.propose_device_id("Alices-Laptop.local") == "Alices-Laptop"
    assert enrol.propose_device_id("a b/c") == "a-b-c"
    assert enrol.propose_device_id("") == "device"
    assert len(enrol.propose_device_id("x" * 300)) <= 48


def test_a_collision_is_explained_with_the_way_out():
    """⚠ THE ENDPOINT REFUSES 409 RATHER THAN MERGING, because a second
    credential for one device id would let this machine's records read as
    another's. So the installer has to say something useful."""
    failure = enrol._explain(409, "already enrolled", "laptop", "https://c.example")
    text = failure.render()
    assert "already enrolled" in text
    assert "--device-id laptop-2" in text, "no way forward is offered"
    assert "NOTHING WAS INSTALLED" in text


# ⚠ 1.4 · every failure is a different sentence, and none installs anything ══

@pytest.mark.parametrize("status,reason,expect", [
    (401, "this enrolment secret expired", "refused this enrolment secret"),
    (401, "this enrolment secret has been revoked", "refused this enrolment secret"),
    (429, "reached its use cap", "used up"),
    (409, "already enrolled", "already enrolled"),
    (404, "no such route", "does not offer enrolment"),
    (500, "", "answered 500"),
])
def test_each_failure_has_its_own_sentence(status, reason, expect):
    """⚠ "ENROLMENT FAILED" TELLS SOMEBODY NOTHING. Expired, used-up, revoked,
    no network and wrong URL have five different next actions, and four of them
    are not "ask for a new secret"."""
    failure = enrol._explain(status, reason, "laptop", "https://c.example")
    assert expect in failure.headline


def test_every_failure_says_nothing_was_installed():
    for status in (401, 404, 409, 429, 500):
        text = enrol._explain(status, "r", "d", "u").render()
        assert "NOTHING WAS INSTALLED" in text
        assert "not guarded" in text


def test_no_network_is_its_own_case_and_says_the_secret_is_still_good(monkeypatch):
    import urllib.error

    def refuse(*a, **k):
        raise urllib.error.URLError("Connection refused")

    with pytest.raises(enrol.Failure) as caught:
        enrol.enrol("https://c.example", "s", "laptop", opener=refuse)
    assert "could not be reached" in caught.value.headline
    assert "still good" in "\n".join(caught.value.lines)


def test_a_404_names_the_real_cause_rather_than_blaming_the_secret():
    """⚠ MEASURED IN PRODUCTION: `POST /v1/enrol` returns 404 on the deployed
    collector today, because the deploy predates the endpoint. Telling somebody
    their secret is bad when the endpoint is missing sends them to the wrong
    person."""
    lines = "\n".join(enrol._explain(404, "", "d", "https://c.example").lines)
    assert "without the enrolment endpoint" in lines
    assert "--device-token" in lines, "the old path is not offered as the way on"


def test_a_200_with_no_token_is_a_failure_not_a_success():
    """⚠ READING A MISSING KEY AS AN EMPTY STRING IS HOW A MACHINE ENDS UP
    INSTALLED WITH NO CREDENTIAL AND A GREEN INSTALL LOG."""
    for payload in ({"enrolled": True}, {"enrolled": False, "device_token": "t"},
                    {}, {"enrolled": True, "device_token": ""}):
        with pytest.raises(enrol.Failure):
            enrol.enrol("https://c.example", "s", "laptop",
                        opener=lambda *a, **k: _Response(payload))


def test_a_success_returns_what_the_collector_assigned():
    got = enrol.enrol("https://c.example", "s", "laptop",
                      opener=lambda *a, **k: _Response(
                          {"enrolled": True, "device_token": "tok",
                           "device_id": "ab12-laptop", "org": "acme"}))
    assert got == {"device_token": "tok", "device_id": "ab12-laptop",
                   "org": "acme", "url": "https://c.example"}


# ═══════════════════════════════ the wire shape the collector expects ══

def test_the_secret_goes_in_its_own_scheme_never_bearer(monkeypatch):
    """⚠ THE COLLECTOR REFUSES A BEARER ON /v1/enrol AND AN ENROLMENT ON
    /v1/batches, so a leaked enrolment secret can never also be a writer.
    Sending it as Bearer would silently defeat that separation."""
    seen = {}

    def capture(request, timeout=None):
        seen["auth"] = request.headers.get("Authorization")
        seen["url"] = request.full_url
        seen["body"] = json.loads(request.data)
        return _Response({"enrolled": True, "device_token": "t",
                          "device_id": "d", "org": "o"})

    enrol.enrol("https://c.example", "sec", "laptop", label="mine", opener=capture)

    assert seen["auth"] == "Enrolment sec"
    assert not seen["auth"].startswith("Bearer")
    assert seen["url"] == "https://c.example/v1/enrol"
    assert seen["body"]["device_id"] == "laptop"
    assert "os" in seen["body"] and seen["body"]["label"] == "mine"


# ═══════════════ 1.5 and the ordering that makes failure safe ══

def test_the_old_path_still_exists():
    """Two machines already have a hand-issued token; nothing here takes it
    away."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    assert '"--device-token"' in source and '"--enrol"' in source


def test_enrolment_runs_before_anything_is_placed():
    """⚠ THE ORDERING *IS* THE SAFETY PROPERTY, and it is checked in the source
    because a test cannot easily observe a negative. Section 4 enrols; section 6
    places the tree; section 7 writes the hook configs."""
    # ⚠ `.find()` AND AN EXPLICIT `!= -1`, NOT `.index()`. The repo's own
    # meta-test flags a comparison between positions derived from a file with
    # nothing establishing they were found — and it is right for the second
    # time: two offsets read out of a source file stop meaning anything the day
    # one marker moves, and a ValueError traceback is a worse message than a
    # sentence naming which marker went.
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    enrolling = source.find("if args.enrol:")
    placing = source.find('head("6 · Install")')
    configuring = source.find('head("7 · Hook configuration")')

    assert enrolling != -1, "install.py no longer enrols — re-point this test"
    assert placing != -1, "section 6 (place the tree) is gone or renamed"
    assert configuring != -1, "section 7 (hook configuration) is gone or renamed"
    assert enrolling < placing < configuring, (
        "enrolment moved after the point of no return — a failure would now "
        "leave a machine installed and unable to ship")


def test_a_failed_enrolment_returns_rather_than_continuing():
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    block = source[source.index("if args.enrol:"):
                   source.index('head("5 · What leaves this machine")')]
    assert "return 2" in block, (
        "a failed enrolment no longer stops the install")


# ══════════════════════════════ 2.2 · unattended, and no hang ══

def test_every_prompt_is_guarded_by_a_terminal_check():
    """⚠ IF IT PUSHES TO FIFTY LAPTOPS, NOBODY ANSWERS A PROMPT. An `input()`
    with no tty raises EOFError on a closed stdin and BLOCKS FOREVER on an
    inherited pipe that never closes — the second is the one that hangs a fleet
    rollout with no error anywhere."""
    import ast

    source = (ROOT / "install.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    prompts = [n for n in ast.walk(tree)
               if isinstance(n, ast.Call)
               and getattr(n.func, "id", None) == "input"]
    assert prompts, "no prompt found — this test has lost its subject"

    for node in prompts:
        # the guard must be in the same function, above the call
        enclosing = next(
            f for f in ast.walk(tree)
            if isinstance(f, ast.FunctionDef)
            and f.lineno <= node.lineno <= (f.end_lineno or node.lineno))
        body = ast.get_source_segment(source, enclosing) or ""
        assert "isatty" in body, (
            f"input() at line {node.lineno} in {enclosing.name}() is not "
            f"guarded by a terminal check — an unattended install would hang")
