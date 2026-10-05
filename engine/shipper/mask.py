"""What leaves this machine: every record, whole, with every value Sting
recognises replaced by its TYPE.

    curl -H "Authorization: Bearer [token]" https://api.example.com/v1 -d owner=[email]

DECIDED 27 Sep 2026: there are no tiers any more. Every record ships as this one
thing. The local log is not touched: it stays raw, the developer's evidence.

⚠ OFF THE HOOK, AFTER THE VERDICT. This runs in the shipper process, while a
batch is built. It changes no verdict and no byte of a local record, and the
hook never imports it (tests/test_every_record_ships_masked.py measures that in
a fresh interpreter).

⚠ MASK ON DOUBT. An over-masked value is cheap; a miss is a leak. Where a rule
has to guess where a value ends, it takes more.

⚠ BY FORMAT AND BY CONTEXT, NEVER BY ENTROPY. Randomness is what git hashes,
UUIDs and build ids are made of, and the entropy guard this project once had was
removed for firing on them (docs/83). A test asserts that no entropy measure
appears in this file's code.

────────────────────────────────────────────────────────────────────────────────
THE SOCKET: `sensitive_spans(text)`
────────────────────────────────────────────────────────────────────────────────

One question, asked of every string in a record: where is a value that must not
leave, and what is it? Every provider answers in one shape, `Span(type, start,
end, source)`, and the answers are merged leftmost-then-longest, overlaps masked
whole (#75's rule for the evidence window):

    source        type                          reads
    known-format  [aws-key] [github-token] …    a vendor's documented shape and
                                                checksum (core/known_formats)
    fingerprint   [secret-from-<file>]          a value THIS session read from a
                                                credential file (Layer A)
    org-policy    [org-sensitive]               a value read from a source the
                                                org's policy declares
    context       [token] [password]            a value NAMED as a secret:
                  [url-password]                Authorization:, user:pass@,
                                                --password, api_key=, "token":
    email         [email]                       an email address, always
    shape         [phone] [card] [ip]           a phone number, a card number
                  [id-number] [bank-account]    that passes Luhn, an IP address,
                  [mac]                         a US SSN, an IBAN (mod-97), a
                                                MAC address
                                                (shipper/identifying.py)
    label         [passport] [birth-date]       a value its KEY names as
                  [bank-account] [id-number]    personal, in key position only:
                  [address]                     passport=, "dob":, --zip, ת.ז:
    guess         [id-number]                   an Israeli ID with no label
                                                (9 digits, check digit), when
                                                the snapshot allowed it
    home          [user]                        the account name in a home
                                                folder, unless the org's policy
                                                sends it (shipper/disclosure.py)
    ner           [person]                      a person's name: Layer B, opt-in
                                                (STING_REDACT_PII)
    model         [secret] [email] [person]     what Sparta suspects: opt-in
                  [address] [phone]             (STING_SPARTA), the `model`
                  [id-number]                   parameter (shipper/sparta_enrich.py)

WHAT IT DOES NOT RECOGNISE LEAVES AS WRITTEN, and the installer says so where it
shows what ships: a password in an unusual spot (`mysql -phunter2`, `curl -u
user:pass`, a positional argument), a person's name without Layer B, a hostname,
and anything else in a heredoc.
"""
from __future__ import annotations

import functools
import re
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import NamedTuple

from core import known_formats, rule_names, wire
from core.credentials import _EMAIL, _SSN, _VALUE_TOKEN
from core.display import visible
from shipper import identifying
from shipper.redact import _fingerprint
from shipper.value_reading import value_span


class Span(NamedTuple):
    """Where a value sits in a text, what it is, and which provider said so."""
    type: str
    start: int
    end: int
    source: str


# ⚠ THE MODEL SLOT IS A PARAMETER, `model`, None unless a caller passes one. A
# model provider is one more callable `(text) -> Iterable[Span]`, source
# "model", merged like every other: it can add a mask and never remove one, so
# a code provider's mask always holds. It runs where this runs, in the shipper,
# off the hook, before a batch exists. The shipper passes Sparta's only when
# STING_SPARTA=1 (shipper/sparta_enrich.py); nothing here imports a model.
# A parameter and not a module global: a global would be set for every batch
# of the process at once, and the flag-off path would have to trust that
# nobody had set it.

# Which provider's type names a value when two find the same span: the most
# specific first. An echo is a value already masked elsewhere in the record.
_RANK = {"known-format": 0, "fingerprint": 1, "org-policy": 2, "context": 3,
         "email": 4, "shape": 5, "label": 6, "guess": 7, "home": 8, "echo": 9,
         "ner": 10, "model": 11}


# ═══════════════════════════════════════════════════════ known formats

# ⚠ A TYPE PER FORMAT, AS DATA. The format id says which vendor document the
# shape came from; the type says what a reader of the panel needs: what kind of
# value stood there. A test pins that every format has one.
FORMAT_TYPES = {
    "aws-access-key-id": "aws-key",
    "github-token": "github-token",
    "github-refresh-token": "github-token",
    "github-fine-grained-pat": "github-token",
    "gitlab-personal-access-token": "gitlab-token",
    "gitlab-service-token": "gitlab-token",
    "openai-api-key": "openai-key",
    "anthropic-api-key": "anthropic-key",
    "stripe-live-key": "stripe-key",
    "slack-token": "slack-token",
    "slack-webhook-url": "slack-webhook",
    "npm-access-token": "npm-token",
    "pypi-upload-token": "pypi-token",
    "huggingface-token": "huggingface-token",
    "sendgrid-api-key": "sendgrid-key",
    "twilio-api-key": "twilio-key",
    "digitalocean-token": "digitalocean-token",
    "shopify-token": "shopify-token",
    "databricks-token": "databricks-token",
    "hashicorp-vault-token": "vault-token",
    "terraform-cloud-token": "terraform-token",
    "postman-api-key": "postman-key",
    "private-key-pem": "private-key",
    "age-secret-key": "age-key",
    "alibaba-access-key-id": "alibaba-key",
    "tencent-secret-id": "tencent-key",
    "adobe-client-secret": "adobe-secret",
    "docker-pat": "docker-token",
    "clojars-api-token": "clojars-token",
    "rubygems-api-key": "rubygems-key",
    "groq-api-key": "groq-key",
    "perplexity-api-key": "perplexity-key",
    "openrouter-api-key": "openrouter-key",
    "linear-api-key": "linear-key",
    "figma-token": "figma-token",
    "typeform-token": "typeform-token",
    "notion-token": "notion-token",
    "sourcegraph-token": "sourcegraph-token",
    "atlassian-token": "atlassian-token",
    "supabase-token": "supabase-token",
    "planetscale-token": "planetscale-token",
    "datastax-astra-token": "astra-token",
    "newrelic-key": "newrelic-key",
    "sentry-token": "sentry-token",
    "grafana-token": "grafana-token",
    "dynatrace-token": "dynatrace-token",
    "square-token": "square-token",
    "paypal-braintree-token": "braintree-token",
    "razorpay-key-id": "razorpay-key",
    "easypost-key": "easypost-key",
    "shippo-token": "shippo-token",
    "sendinblue-key": "brevo-key",
    "amazon-mws-token": "mws-token",
    "doppler-token": "doppler-token",
    "sonarqube-token": "sonarqube-token",
    "tailscale-key": "tailscale-key",
    "discord-webhook-url": "discord-webhook",
    "stripe-webhook-secret": "stripe-webhook-secret",
    "sting-device-token": "sting-device-token",
    "sting-enrolment": "sting-enrolment",
}


def _known_format_spans(text: str) -> list[Span]:
    """Every documented credential shape in `text`, overlaps included.

    ⚠ THE CANDIDATES THE EVIDENCE MASK READS (`known_formats.masked_spans`),
    NOT `find_known_secrets`. That one answers "which values" and keeps one per
    overlap; a mask needs every match, or a GitLab-shaped token that ends in a
    PEM header hides the private key behind it (#75's CRITICAL). A placeholder
    never hides a real value behind it: that rule keeps a verdict, and a mask
    moves none. And the whole text: `MAX_SCAN` bounds the hook, not this."""
    return [Span(FORMAT_TYPES.get(hit.format_id, "secret"), hit.start, hit.end,
                 "known-format")
            for hit in known_formats._candidates(text, placeholder_hides=False)]


# ═══════════════════════════════════════════ what the session's state knows

MAX_FILE_NAME = 40
"""The longest file name a `[secret-from-…]` marker carries."""
_MAX_FILES = 3
_UNSAFE_IN_A_NAME = re.compile(r"[^A-Za-z0-9._-]")


@dataclass(frozen=True, eq=False)
class SessionValues:
    """What one session's engine state lets the shipper recognise, by HASH.

    `secret_prints` are the needles the engine stored when this session read a
    credential file (`SessionState.secret_fingerprints`), `sha256(value)[:8]`:
    Layer A matches a token by the same needle, so no value is ever held here.
    `secret_files` are the files those reads were of. ⚠ WHICH FILE A VALUE CAME
    FROM IS NOT IN THE STATE: its fingerprints are one list for the session. So
    the marker names every file the value could have come from, and names the
    one file exactly when the session read one. `policy_prints` are the needles
    from sources the org's policy declares (`policy_fingerprints`).

    `seen` is not the engine's: it is every value of `MIN_SESSION_ECHO`+
    characters that masking recognised in ANY record of the session, by type,
    kept by the shipper (`recognised_values`) — so a value a clue named in one
    record is masked in a record where nothing names it.

    `send_folder_names` is the org's, not the session's: True only when its
    policy sends home-folder account names as written (shipper/disclosure.py).
    False — masked — everywhere nothing set it.

    Frozen, so nothing changes it once a batch holds it; compared and hashed
    by identity, since `seen` is a dict (python review, round two)."""
    secret_prints: frozenset = frozenset()
    secret_files: tuple = ()
    policy_prints: frozenset = frozenset()
    seen: Mapping[str, str] = field(default_factory=dict)
    send_folder_names: bool = False

    @functools.cached_property
    def seen_index(self) -> dict:
        """`seen` indexed by its values' first characters, built once: a record
        is then scanned once, whatever the session remembers (python review)."""
        return _index(self.seen)

    @property
    def secret_type(self) -> str:
        names = list(dict.fromkeys(filter(None, map(_file_label, self.secret_files))))
        if not names:
            return "secret"
        shown = names[:_MAX_FILES] + (["…"] if len(names) > _MAX_FILES else [])
        return "secret-from-" + "|".join(shown)


NO_SESSION = SessionValues()


def _file_label(path: object) -> str:
    """A file's base name, safe inside a marker: no bracket, no newline, bounded."""
    name = str(path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return _UNSAFE_IN_A_NAME.sub("_", name)[:MAX_FILE_NAME]


def session_values(state) -> SessionValues:
    """The values a loaded `SessionState` lets the shipper recognise."""
    files = [source.get("path") for source in (state.secret_sources or ())
             if isinstance(source, dict) and source.get("how") == "content"]
    return SessionValues(frozenset(state.secret_fingerprints or ()), tuple(files),
                         frozenset(state.policy_fingerprints or ()))


def _fingerprint_spans(text: str, known: SessionValues) -> list[Span]:
    """Layer A: a token whose needle the engine stored when this session read
    a credential file. The token shape and the needle are the engine's own
    (`_VALUE_TOKEN`, `sha256[:8]`), never a second definition."""
    if not known.secret_prints:
        return []
    kind = known.secret_type
    return [Span(kind, m.start(), m.end(), "fingerprint")
            for m in _VALUE_TOKEN.finditer(text)
            if _fingerprint(m.group(0)) in known.secret_prints]


def _policy_spans(text: str, known: SessionValues) -> list[Span]:
    """A value read from a source the org's policy declares: a token, an email
    or an SSN whose needle the engine stored (`policy_fingerprints`). Every
    token is hashed and compared; nothing is filtered first."""
    if not known.policy_prints:
        return []
    return [Span("org-sensitive", m.start(), m.end(), "org-policy")
            for pattern in (_VALUE_TOKEN, _EMAIL, _SSN)
            for m in pattern.finditer(text)
            if _fingerprint(m.group(0)) in known.policy_prints]


def _email_spans(text: str, userinfo: frozenset = frozenset()) -> list[Span]:
    """Every email address, always. The engine's own bounded pattern, linear on
    a long near-email string. ⚠ NOT `user:pass@host`: to the pattern the
    password and the host read as an email, and as the longer span it would
    swallow the host that stays. `userinfo` holds the `@` of every URL
    password, and a match on one of those is the URL's."""
    if "@" not in text:
        return []
    return [Span("email", m.start(), m.end(), "email") for m in _EMAIL.finditer(text)
            if text.find("@", m.start(), m.end()) not in userinfo]


def _shape_spans(text: str) -> list[Span]:
    """A phone number, a card number, an IP address, an ID number, an IBAN or
    a MAC address, by its shape and check (shipper/identifying.py): masked
    wherever it stands, named or not."""
    found = (*identifying.phone_spans(text), *identifying.card_spans(text),
             *identifying.ip_spans(text), *identifying.id_number_spans(text),
             *identifying.iban_spans(text), *identifying.mac_spans(text))
    return [Span(kind, start, end, "shape") for kind, start, end in found]


def _guess_spans(text: str) -> list[Span]:
    """An unlabelled Israeli ID: masked, but named by a key when one names it
    (`identifying.israeli_id_spans`)."""
    return [Span(kind, start, end, "guess")
            for kind, start, end in identifying.israeli_id_spans(text)]


def _home_spans(text: str, known: SessionValues) -> list[Span]:
    """The account name in a home folder, `[user]`, unless the org's policy
    sends it (shipper/identifying.py, shipper/disclosure.py)."""
    if known.send_folder_names:
        return []
    return [Span(kind, start, end, "home")
            for kind, start, end in identifying.home_folder_spans(text)]


# ═══════════════════════════════════════ context: a value NAMED as a secret

_CLUES = ("password", "passwd", "secret", "token", "apikey", "accesskey",
          "privatekey", "clientsecret", "authorization")
"""A name holding one of these names a secret. Compared with case, `_`, `-` and
`.` folded away: API_KEY, api-key, apiKey and x.api.key all hold `apikey`."""
_PASSWORD_CLUES = ("password", "passwd")
_SEGMENT_CLUES = {"tok": "token", "pass": "password", "pw": "password",
                  "auth": "token", "cred": "token", "creds": "token",
                  "credential": "token", "credentials": "token", "cookie": "token"}
"""A WHOLE SEGMENT of a name that names a secret too — `TOK`, `DB_PASS`,
`--auth`, `Cookie:`. Measured: `TOK=<a real token>` shipped unmasked under the
clues above alone. Whole segments, so `bypass`, `author` and `compass` hold none."""
_SEGMENT = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_TRIGGERS = ("pass", "secret", "tok", "api", "access", "private", "auth", "cred",
             "cookie", "pw", "://")
"""What a text must hold, lower-cased, for any context rule to fire. Most
commands hold none of these and cost one scan each."""


def _names_a_secret(name: str) -> str | None:
    """"password" or "token" when `name` holds a clue or is made of a segment
    that is one, else None."""
    folded = re.sub(r"[_.\-]", "", name.lower())
    if any(clue in folded for clue in _CLUES):
        return "password" if any(c in folded for c in _PASSWORD_CLUES) else "token"
    kinds = {_SEGMENT_CLUES.get(part.lower()) for part in _SEGMENT.findall(name)}
    kinds.discard(None)
    if not kinds:
        return None
    return "password" if "password" in kinds else "token"


_AUTHORIZATION = re.compile(
    r"(?i)(?<![A-Za-z0-9_\-])(?P<name>(?:[a-z0-9]+[-_])*authorization)\\{0,3}[\"']?\]?[ \t]*(?::|=>?)[ \t]*"
    r"(?:[rbfu]{0,2}\\{0,3}[\"'])?[ \t]*"
    r"(?:(?P<scheme>bearer|basic|token|digest|negotiate|ntlm|apikey|api-key|sso-key)[ \t]+)?")
"""`Authorization: Bearer X` — or `Proxy-`, `X-`, `HTTP_`, any prefix joined by
`-` or `_` (python review; security review, round three: a fourth part was
missed) — in a header, a dict, a query or a keyword. A
scheme on this list stays and the credential after it is the value; after any
other word the whole header value is (`Authorization: Enrol X` masked `Enrol`
and shipped `X` until a measure found it)."""

_URL_PASSWORD = re.compile(
    r"(?i)(?<![A-Za-z0-9+.\-])[a-z][a-z0-9+.\-]{0,31}://"
    r"[^\s/?#@:\"'`<>]{0,256}:"                  # the user, which stays
    r"([^\s/?#\"'`<>]{1,1024}?)"                 # the password, which may hold an @
    r"@(?=[A-Za-z0-9\[][^\s@/?#\"'`<>]{0,255}(?:[/?#:\s\"'`<>),;\]\\]|$))")
"""`scheme://user:pass@host`. The password is the shortest run that ends at an
`@` followed by a host, so `p@ss@host` masks `p@ss`."""

_FLAG = re.compile(r"(?<![A-Za-z0-9_\-])--([A-Za-z0-9][A-Za-z0-9_.\-]{0,63})"
                   r"(=|(?:[ \t]|\\(?:\r\n|\n|\r))+)")
"""`--password X` and `--password=X`. ⚠ NEVER A SHORT FLAG: `-p` is `mkdir -p`
and `ssh -p 2222` far more often than it is a password."""

_USER_FLAG = re.compile(r"(?<![A-Za-z0-9_\-])--(?:user|proxy-user)"
                        r"(=|(?:[ \t]|\\(?:\r\n|\n|\r))+)")
"""`curl --user name:password`: the name stays, what follows its first colon
is a password (security review). With no password part the value is the
credential (`--user TOKEN`, `--user TOKEN:`). The short `-u` stays out, as `-p`
does: `docker run -u 1000:1000` is a uid and a gid."""

_KEY = re.compile(
    r"(?<![A-Za-z0-9_\-.$])(\\{0,3}[\"']?)([A-Za-z_][A-Za-z0-9_.\-]{0,127})\1\]?"
    r"((?:[ \t]|\\(?:\r\n|\n|\r))*)(:=|=>|=(?!=)|:(?![:/=\\]))")
"""`NAME=X`, `export NAME=X`, `NAME: X`, `"NAME": X`, `NAME := X`, `ENV["NAME"] = X`."""

_RULE_ID = re.compile(
    r"(?:%s):(?:%s)(?![A-Za-z0-9_])" % (
        "|".join(sorted(set(rule_names.RULE_FAMILIES) | rule_names.RETIRED, key=len, reverse=True)),
        "|".join(sorted(rule_names.SINK_MEANINGS, key=len, reverse=True))))
"""`secret_exact:git_push` is this engine's own rule id, `family:sink`, never a
name and a value; measured, it was the largest over-mask in real commands.
⚠ THE WHOLE RULE ID, NOT THE FAMILY (security review): `secret_exact: <a
token>` is a name and a value, and a family name alone exempted it."""


def _url_passwords(text: str) -> list[re.Match]:
    return list(_URL_PASSWORD.finditer(text)) if "://" in text else []


def _context_spans(text: str, urls: list[re.Match]) -> list[Span]:
    """Values named as secrets: an Authorization header, a URL's password, a
    `--password`-style flag, and an assignment or key whose name holds a clue."""
    lowered = text.lower()
    if not any(trigger in lowered for trigger in _TRIGGERS):
        return []
    spans: list[Span] = []

    def add(kind: str, where: tuple[int, int] | None) -> None:
        if where is not None:
            spans.append(Span(kind, where[0], where[1], "context"))

    headers = set()                  # names the header rule read, scheme kept
    for m in _AUTHORIZATION.finditer(text):
        headers.add(m.span("name"))
        add("token", value_span(text, m.end(), loose=m.group("scheme") is None))
    for m in urls:
        add("url-password", m.span(1))
    for m in _FLAG.finditer(text):
        kind = _names_a_secret(m.group(1))
        if kind:
            add(kind, value_span(text, m.end(), loose=False,
                                  flag_value=m.group(2) != "="))
    for m in _USER_FLAG.finditer(text):
        where = value_span(text, m.end(), loose=False, flag_value=m.group(1) != "=")
        if where is None:
            continue
        colon = text.find(":", *where)
        if colon != -1 and colon + 1 < where[1]:
            add("password", (colon + 1, where[1]))
        else:
            # ⚠ NO PASSWORD PART: the value IS the credential, as in
            # `curl --user sk_…:` (security review, round two). Masked whole.
            add("token", (where[0], colon if colon != -1 else where[1]))
    for m in _KEY.finditer(text):
        kind = _names_a_secret(m.group(2))
        if not m.group(1) and _RULE_ID.match(text, m.start(2)):
            continue
        if m.span(2) in headers:
            # ⚠ ONLY A NAME THE HEADER RULE MATCHED (security review, round
            # four): deferring on the name's shape alone shipped the value
            # where a line continuation stood before its colon.
            continue
        if kind:
            # `:`, `:=`, `=>` and a spaced ` = ` read the rest of the line (YAML,
            # a header, INI, TOML); a bare `NAME=` reads one shell word, and so
            # does one that only a line continuation separates from its name.
            loose = m.group(4) != "=" or any(c in " \t" for c in m.group(3))
            add(kind, value_span(text, m.end(), loose=loose))
    return spans


# ══════════════════════════════════ label: a value its KEY names as personal

_DECLARES = frozenset({"export", "set", "let", "const", "var", "declare", "local",
                       "readonly", "typeset", "env"})
"""Words a key may follow after a space and still be a key: `export ZIP=…`."""
_HEBREW = re.compile(r"[\u0590-\u05FF]")
_ANNOTATION = re.compile(
    r"(?:Optional\[\s*)?(?:str|int|float|bool|bytes|None|string|number|boolean|any"
    r"|object|date|datetime|Decimal|dict|list|tuple)(?:\s*\])?(?:\s*\|\s*None)?"
    r"(?:\s*=\s*(?P<default>.*))?")
"""A field DECLARED with its type (`address: str`, `zip: int | None = None`):
a declaration, not a value (measured on the snapshot, docs/107 §9). ⚠ ITS
DEFAULT IS A VALUE (security review, MEDIUM): `passport: str = "A1234567"`
shipped the default raw. Only an empty one names nothing (`_NO_DEFAULT`)."""
_NO_DEFAULT = re.compile(r"None|null|''|\"\"")


def _past_the_declaration(text: str, where: tuple[int, int]) -> tuple[int, int] | None:
    """`where` when it declares nothing; the default's value when it declares
    a type with one; None when it declares a type and no value."""
    value = text[where[0]:where[1]]
    note = _ANNOTATION.fullmatch(value.strip())
    if note is None:
        return where
    default = note.group("default")
    if default is None or _NO_DEFAULT.fullmatch(default.strip()):
        return None
    lead = len(value) - len(value.lstrip())
    return value_span(text, where[0] + lead + note.start("default"), loose=True)


_WORDS_BEFORE = re.compile(r"(?:([A-Za-z][A-Za-z'.]*) )?(?:([A-Za-z][A-Za-z'.]*) )?\Z")


_WORDS_WINDOW = 64
"""How far back `_words_before` reads: two words and their spaces."""


def _words_before(text: str, start: int) -> list[str]:
    """Up to two words right before `start` on its line, one space apart.
    ⚠ THE NEWLINE IS SEARCHED FOR ONLY IN THE WINDOW READ (the review): from
    the text's start, every key read as prose re-read the whole line, and a
    256 KB line took 1.50 s."""
    window = max(0, start - _WORDS_WINDOW)
    line = text.rfind("\n", window, start) + 1
    found = _WORDS_BEFORE.search(text, max(line, window), start)
    return [w for w in found.groups() if w] if found else []


def _tight(text: str, key: re.Match) -> bool:
    """A `_KEY` match written key=value, no space on either side of the `=`
    (`echo passport=X`): a key wherever it stands, not a word in a sentence
    (the review). "Key: value" keeps `_in_prose`'s rule."""
    return (key.group(4) == "=" and not key.group(3) and key.end() < len(text)
            and not text[key.end()].isspace())


def _in_prose(text: str, start: int) -> bool:
    """Is the unquoted key at `start` a word in a sentence: "IP address: …"?
    A key starts a line, a field or an assignment; one after a word and a
    space is prose, unless that word declares (`export ZIP=`). A shell
    assignment or an option before it is not a word in a sentence either
    (`VAR=1 passport=…`, `curl -d zip=…`, item 4)."""
    j = start - 1
    while j >= 0 and text[j] in " \t":
        j -= 1
    if j == start - 1 or j < 0 or not text[j].isalnum():
        return False
    begin = j
    while begin > 0 and text[begin - 1].isalnum():
        begin -= 1
    if text[begin:j + 1].lower() in _DECLARES:
        return False
    shell_word = begin
    while shell_word > 0 and not text[shell_word - 1].isspace():
        shell_word -= 1
    before = text[shell_word:j + 1]
    return not ("=" in before or before.startswith("-"))


def _personal_spans(text: str) -> list[Span]:
    """Values a key names as personal (`identifying.PERSONAL_KEYS`), read like a
    named secret's (`_context_spans`): `NAME=X`, `NAME: X`, `"NAME": X`,
    `--name X`, and the Hebrew keys. Only in key position: the word "address"
    in a sentence names nothing. A key inside a value already read is not read
    again, so a run of keys costs its length once."""
    lowered = text.lower()
    hebrew = _HEBREW.search(text) is not None
    if not hebrew and not any(t in lowered for t in identifying.PERSONAL_TRIGGERS):
        return []
    spans: list[Span] = []
    read_until = -1

    def add(kind: str, where: tuple[int, int] | None) -> None:
        nonlocal read_until
        if where is not None:
            spans.append(Span(kind, where[0], where[1], "label"))
            read_until = max(read_until, where[1])

    for m in _KEY.finditer(text):
        if m.start() < read_until:
            continue
        kind = identifying.personal_key(m.group(2))
        if not m.group(1) and not _tight(text, m) and _in_prose(text, m.start(2)):
            # A key after a word is prose, unless the words make a label:
            # `Passport number:`, `Home address:` (python review, MEDIUM).
            kind = identifying.labelled(_words_before(text, m.start(2)), m.group(2))
        if not kind:
            continue
        loose = m.group(4) != "=" or any(c in " \t" for c in m.group(3))
        where = value_span(text, m.end(), loose=loose)
        if where and m.group(4) == ":":
            where = _past_the_declaration(text, where)
        add(kind, where)
    read_until = -1
    for m in _FLAG.finditer(text):
        if m.start() < read_until:
            continue
        kind = identifying.personal_key(m.group(1))
        if kind:
            add(kind, value_span(text, m.end(), loose=False,
                                  flag_value=m.group(2) != "="))
    if hebrew:
        read_until = -1
        for m in identifying.HEBREW_KEY.finditer(text):
            if m.start() < read_until:
                continue
            add(identifying.HEBREW_TYPES[m.group("name")],
                value_span(text, m.end(), loose=True))
    return spans


# ═══════════════════════════════════════════════════ one question, merged

def _merged(spans: Iterable[Span]) -> list[Span]:
    """Leftmost first, then the longest, then the most specific provider; an
    overlap joins the span before it, whose type it keeps (#75's rule)."""
    ordered = sorted((s for s in spans if 0 <= s.start < s.end),
                     key=lambda s: (s.start, s.start - s.end,
                                    _RANK.get(s.source, len(_RANK))))
    out: list[Span] = []
    for span in ordered:
        if out and span.start < out[-1].end:
            if span.end > out[-1].end:
                out[-1] = out[-1]._replace(end=span.end)
            continue
        out.append(span)
    return out


def sensitive_spans(text: str, known: SessionValues = NO_SESSION, *,
                    analyzer=None, model=None) -> list[Span]:
    """Where in `text` a value sits that must not leave, and what it is.

    THE SOCKET. Every provider's answer, merged: non-overlapping, in position
    order. `known` is what this session's engine state recognises (Layer A and
    the org policy); `analyzer` is Layer B's NER, passed only when
    STING_REDACT_PII is on; `model` is Sparta's, passed only when
    STING_SPARTA=1."""
    return _merged(_candidates(text, known, analyzer, model))


def _candidates(text: str, known: SessionValues, analyzer,
                model: Callable[[str], Iterable[Span]] | None = None) -> list[Span]:
    """Every provider's answer, before merging: a record's echo reads these, so
    a value inside a longer one is masked wherever else the record carries it."""
    if not text:
        return []
    urls = _url_passwords(text)
    found = [*_known_format_spans(text), *_fingerprint_spans(text, known),
             *_policy_spans(text, known), *_context_spans(text, urls),
             *_email_spans(text, frozenset(m.end(1) for m in urls)),
             *_shape_spans(text), *_personal_spans(text), *_guess_spans(text),
             *_home_spans(text, known)]
    if analyzer is not None:
        found += [Span("person", start, end, "ner")
                  for start, end in analyzer.person_spans(text)
                  if 0 <= start < end <= len(text)]
    if model is not None:
        found += [span for span in model(text)
                  if 0 <= span.start < span.end <= len(text)]
    return found


def _apply(text: str, spans: list[Span]) -> tuple[str, Counter]:
    """`text` with every span replaced by `[type]`; how many of each. A span
    that already reads as its own marker is left, and not counted."""
    counts: Counter = Counter()
    pieces, cursor = [], 0
    for span in spans:
        marker = f"[{span.type}]"
        if text[span.start:span.end] == marker:
            continue
        pieces += [text[cursor:span.start], marker]
        cursor = span.end
        counts[span.type] += 1
    return "".join(pieces) + text[cursor:], counts


def mask_text(text: str, known: SessionValues = NO_SESSION, *,
              analyzer=None, model=None) -> tuple[str, Counter]:
    """`text` as it may leave, and how many values of each type it hid."""
    return _apply(text, sensitive_spans(text, known, analyzer=analyzer, model=model))


# ═══════════════════════════════════════════════════════════ the record

_MIN_ECHO = 4
"""The shortest masked value that is masked wherever else it appears in the
record. Shorter ones (`abc`) would hide every word that contains them."""
MIN_SESSION_ECHO = 8
"""The shortest value masked wherever else it appears in the SESSION: the
shortest password most policies accept. ⚠ MEASURED: at the engine's floor for
a value (12), a password of 8 to 11 characters one record named
(`postgres://app:X@db`) shipped as written where nothing names it
(`mysql -pX`). At 8 the snapshot gained 158 masks in 78 of 25,577 records; a
session holds far more text than a record, so a shorter value would hide
words. A value holding a space is not remembered either: after a clue, those
are mostly the prose and punctuation a quote happened to span."""
_MIN_PIECE = 3
"""The shortest piece of a masked value hidden at a window's `…` edge."""
_EDGE = "…"
_RUN = re.compile(r"[^\s\"'`…]+")


_MAX_DEPTH = 32
"""How deep a field's lists and mappings are read. The hook writes a string or
a list of strings; past this depth a container is masked whole, `[too-deep]`.
⚠ PYTHON REVIEW, ROUND TWO, HIGH: the walk recursed once per level and json
reads a line nested 5,000 deep, so one malformed line raised RecursionError out
of the shipper, and its supervisor restarted it onto the same record."""
TOO_DEEP = "too-deep"


def _texts(value, depth: int = 0) -> Iterator[str]:
    """Every string in a field: a mapping's keys too (security review, round
    three), and nothing below `_MAX_DEPTH`."""
    if isinstance(value, str):
        yield value
    elif depth >= _MAX_DEPTH:
        return
    elif isinstance(value, list):
        for item in value:
            yield from _texts(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _texts(key, depth + 1)
            yield from _texts(item, depth + 1)


def _walk(value, rewrite: Callable[[str], str], too_deep: Callable[[], str],
          depth: int = 0):
    """`value` with every string rewritten, and a container below `_MAX_DEPTH`
    replaced by `too_deep()`. Two keys masked alike are merged, the last kept:
    the local record keeps both."""
    if isinstance(value, str):
        return rewrite(value)
    if isinstance(value, (list, dict)) and depth >= _MAX_DEPTH:
        return too_deep()
    if isinstance(value, list):
        return [_walk(item, rewrite, too_deep, depth + 1) for item in value]
    if isinstance(value, dict):
        return {_walk(key, rewrite, too_deep, depth + 1):
                _walk(item, rewrite, too_deep, depth + 1) for key, item in value.items()}
    return value


_PREFIX = _MIN_ECHO
"""The characters a remembered value is indexed by: its shortest possible length."""


def _index(values: Mapping[str, str]) -> dict[str, list[tuple[str, str]]]:
    """{first `_PREFIX` characters: [(value, type)]}: every value, found by
    where it starts, so a text is read once rather than once per value."""
    index: dict[str, list[tuple[str, str]]] = {}
    for value, kind in values.items():
        index.setdefault(value[:_PREFIX], []).append((value, kind))
    return index


def _occurrences(text: str, index: dict[str, list[tuple[str, str]]]) -> list[Span]:
    """Every whole occurrence in `text` of an indexed value."""
    if not index:
        return []
    spans = []
    for at in range(len(text) - _PREFIX + 1):
        for value, kind in index.get(text[at:at + _PREFIX], ()):
            if text.startswith(value, at):
                spans.append(Span(kind, at, at + len(value), "echo"))
    return spans


def _piece_index(values: Mapping[str, str]) -> tuple[dict, dict]:
    """Every masked value's head, and every place a tail of it can start, by
    their first `_MIN_PIECE` characters: a piece at a `…` edge is sought only
    among the values that hold its first characters. ⚠ PYTHON REVIEW, ROUND
    TWO: sought size by size in every value, a command of 500 values each cut
    at an edge cost 15 times the same command without the edges."""
    heads: dict[str, list[tuple[str, str]]] = {}
    tails: dict[str, list[tuple[str, str, int]]] = {}
    for value, kind in values.items():
        heads.setdefault(value[:_MIN_PIECE], []).append((value, kind))
        for k in range(1, len(value) - _MIN_PIECE + 1):
            tails.setdefault(value[k:k + _MIN_PIECE], []).append((value, kind, k))
    return heads, tails


def _edge_pieces(text: str, pieces: tuple[dict, dict]) -> list[Span]:
    """A piece of a masked value cut at a `…` edge of `text`.

    ⚠ A WINDOW CAN CUT A VALUE AWAY FROM ITS NAME. `evidence` and a reason's
    quote are slices of a command: `--password=` can fall outside the slice
    while the value, or its first or last characters at the `…`, fall inside.
    No rule reads a value there without its name, so the record's own masks
    are carried to every field of it: whole by `_occurrences`, and in pieces
    here. `pieces` index the values this record holds (`_piece_index`), so
    the cost is its own."""
    heads, tails = pieces
    spans = []
    edge = text.find(_EDGE)
    while edge != -1:
        after = _RUN.match(text, edge + 1)
        if after:
            spans += _tail_piece(after.group(0), after.start(), tails)
        start = edge                 # back to a space, a quote or the last `…`: the
        while start > 0 and _RUN.match(text[start - 1]):     # walks never overlap
            start -= 1
        if start < edge:
            spans += _head_piece(text[start:edge], start, heads)
        edge = text.find(_EDGE, edge + 1)
    return spans


def _tail_piece(run: str, at: int, tails: dict) -> list[Span]:
    """The longest start of `run`, right after a `…`, that is a TAIL of a
    masked value, shorter than the value."""
    best: Span | None = None
    for value, kind, k in tails.get(run[:_MIN_PIECE], ()):
        size = len(value) - k
        if ((best is None or size > best.end - best.start) and size <= len(run)
                and run.startswith(value[k:])):
            best = Span(kind, at, at + size, "echo")
    return [best] if best else []


def _head_piece(run: str, at: int, heads: dict) -> list[Span]:
    """The longest end of `run`, right before a `…`, that is a HEAD of a masked
    value, shorter than the value."""
    for j in range(len(run) - _MIN_PIECE + 1):
        for value, kind in heads.get(run[j:j + _MIN_PIECE], ()):
            if len(run) - j < len(value) and value.startswith(run[j:]):
                return [Span(kind, at + j, at + len(run), "echo")]
    return []


def recognised_values(record: dict, known: SessionValues = NO_SESSION, *,
                      analyzer=None) -> dict[str, str]:
    """{value: type} for every value of `MIN_SESSION_ECHO`+ characters, and no
    whitespace, that masking recognises in this record — what the shipper
    keeps per session as `SessionValues.seen`. Held in the shipper's memory
    only, and only as long as the process runs: it already reads the raw log."""
    found: dict[str, str] = {}
    for key, value in record.items():
        if key in wire.UNMASKED or key == wire.MASKED_FIELD:
            continue
        for text in _texts(value):
            for span in _candidates(text, known, analyzer):
                piece = text[span.start:span.end]
                if (len(piece) >= MIN_SESSION_ECHO and not any(c.isspace() for c in piece)
                        and piece != f"[{span.type}]"):
                    found.setdefault(piece, span.type)
    return found


def mask_record(record: dict, known: SessionValues = NO_SESSION, *,
                analyzer=None, model=None) -> dict:
    """A NEW record: every string outside `wire.UNMASKED` masked, and
    `masked` = how many values of each type, when any. `model` is the model
    slot (`sensitive_spans`), asked once per distinct string.

    ⚠ EVERY STRING, NOT A LIST OF FIELDS. A field added to `build_body` later,
    or one this list never knew, is masked by default; the spine — ids, our own
    vocabulary, numbers, digests — is what `wire.UNMASKED` names, and it is
    copied untouched so the chain and the collector's keys still work.
    ⚠ `masked` IS THIS FUNCTION'S TO WRITE. A record that arrives carrying one
    (an edited log) loses it, so the mark says what this masking did."""
    fields = {key: value for key, value in record.items()
              if key not in wire.UNMASKED and key != wire.MASKED_FIELD}
    found: dict[str, list[Span]] = {}          # every candidate, merged when applied
    for text in (t for value in fields.values() for t in _texts(value)):
        if text not in found:
            found[text] = _candidates(text, known, analyzer, model)
            if known.seen:
                found[text] += _occurrences(text, known.seen_index)
    values: dict[str, str] = {}
    for text, spans in found.items():
        for span in spans:
            value = text[span.start:span.end]
            if len(value) >= _MIN_ECHO and value != f"[{span.type}]":
                values.setdefault(value, span.type)
    record_index = _index(values)
    pieces = _piece_index(values) if values and any(_EDGE in t for t in found) else None
    counts: Counter = Counter()

    def rewrite(text: str) -> str:
        spans = found[text]
        if values:
            spans = [*spans, *_occurrences(text, record_index),
                     *(_edge_pieces(text, pieces) if pieces else ())]
        masked, hidden = _apply(text, _merged(spans))
        counts.update(hidden)
        # ⚠ SHOWN BY THE PANEL, SO VISIBLE (item C, docs/110 §C): after the
        # masks, before the chain — `build_batch` chains what this returns, so
        # `tier_hash` still covers exactly the bytes sent. The local record
        # keeps its raw bytes.
        return visible(masked, multiline=True)

    def too_deep() -> str:
        counts[TOO_DEEP] += 1
        return f"[{TOO_DEEP}]"

    out = {key: (value if key in wire.UNMASKED else _walk(value, rewrite, too_deep))
           for key, value in record.items() if key != wire.MASKED_FIELD}
    if counts:
        out[wire.MASKED_FIELD] = dict(sorted(counts.items()))
    return out
