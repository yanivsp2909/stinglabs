"""Values that identify a person or a machine, found by their SHAPE: phone
numbers, card numbers, IP addresses, and the account name in a home folder.

Providers for `shipper/mask.py`'s socket, as `(type, start, end)`. Shipper
only: off the hook, after the verdict; nothing here moves a verdict or a byte
of a local record, and the hook never imports it.

⚠ MASK ON DOUBT, NEVER BY ENTROPY. Each rule reads a documented shape and a
check the shape carries (Luhn for a card, the octet ranges for an IPv4
address, `ipaddress` for an IPv6 one); none measures randomness. Where a rule
must guess, it takes the value: an over-masked version number is cheap, a
phone number shipped is not.

    type     what                               never
    phone    +<country> <digits>, or digits      a bare run of digits, a
             grouped by separators in a phone's  version, a date, a time
             shapes (docs/107)
    card     13-19 digits, alone or in groups    a run that fails Luhn, or
             of 4 then 3-6, that pass Luhn       starts with 0
    ip       IPv4 and IPv6 addresses             loopback (127.0.0.0/8, ::1),
                                                 0.0.0.0 and ::
    user     the account name in /Users/<name>,  a system folder (Shared,
             /home/<name>, C:\\Users\\<name>        Public, …), a variable
             (and its JSON-escaped form), and    ($USER, %USERNAME%), and every
             ~<name>/                            other folder of the path
    id-number  an Israeli ID (9 digits, check        a run failing the check,
             digit), unlabelled only if measured  nine zeros; an SSN in area
             so (MASK_UNLABELLED_ISRAELI_ID); a   000, 666 or 9xx, group 00
             US SSN, AAA-GG-SSSS                  or serial 0000
    bank-account  an IBAN: country code, check    one failing mod-97
             digits, 11-30 more, mod-97
    mac      six hex pairs, `:` or `-`            00:00:00:00:00:00

A value a KEY names as personal (`passport=`, `"dob":`, `--zip`, `ת.ז:`) is
masked by `shipper/mask.py`'s named-values provider, from `PERSONAL_KEYS`
below: only in key position, never the word in prose ("IP address").

⚠ THE ACCOUNT NAME SHIPS ONLY WHEN THE ORG SAYS SO (`shipper/disclosure.py`):
`home_folder_spans` is asked unless the cached org policy holds exactly
`"disclosure": {"folder_names": "send"}`.
"""
from __future__ import annotations

import ipaddress
import re

Found = tuple[str, int, int]

# ═══════════════════════════════════════════════════════════════ phones

_PHONE_SHAPES = (
    # +<country code> then 7-14 more digits, each after at most one
    # separator, a group maybe in parentheses: +972 54-123-4567, +1 (415)
    # 555-1234, +442079460958.
    re.compile(r"(?<![\w+])\+\d(?:[ .\-]?\(?\d\)?){7,14}(?![\d])"),
    # (area code) then two groups: (415) 555-1234, (02) 1234 5678.
    re.compile(r"(?<![\w)])\(\d{2,4}\)[ .\-]?\d{3,4}[ .\-]\d{3,4}(?![\w\-]|\.\d)"),
    # dashes, three or four groups, every group after the first 3-4 digits:
    # 415-555-1234, 054-123-4567, 1-800-555-1234. Never a date: 2026-09-28's
    # later groups are two digits.
    re.compile(r"(?<![\w.\-/+:])\d{1,4}(?:-\d{3,4}){2,3}(?![\w\-/]|\.\d)"),
    # a trunk 0 and one dash: 054-1234567, 02-1234567.
    re.compile(r"(?<![\w.\-/+:])0\d{1,3}-\d{6,8}(?![\w\-/]|\.\d)"),
    # dots, the North American shape only: 415.555.1234. A version's groups
    # are rarely three, three and four digits.
    re.compile(r"(?<![\w.\-/+:])\d{3}\.\d{3}\.\d{4}(?![\w\-/]|\.\d)"),
    # spaces, after a trunk 0 only: 020 7946 0958, 054 123 4567,
    # 01 23 45 67 89. Without the 0, `kill 4521 4522 4523` would be a phone.
    re.compile(r"(?<![\w.\-/+:])0\d{1,4}(?: \d{2,4}){2,4}(?![\w\-/]|\.\d)"),
)
_PHONE_DIGITS = (8, 15)
"""E.164 allows 15 digits; the shortest number a shape above can hold with its
country code or trunk prefix is 8."""


def phone_spans(text: str) -> list[Found]:
    if not any(c.isdigit() for c in text):
        return []
    found = []
    for shape in _PHONE_SHAPES:
        for m in shape.finditer(text):
            digits = sum(c.isdigit() for c in m.group(0))
            if _PHONE_DIGITS[0] <= digits <= _PHONE_DIGITS[1]:
                found.append(("phone", m.start(), m.end()))
    return found


# ═══════════════════════════════════════════════════════════════ cards

_CARD = re.compile(
    r"(?<![\w.\-])[1-9](?:\d{12,18}"                      # 13-19 digits, one run
    r"|\d{3}(?P<sep>[ \-])\d{3,6}(?:(?P=sep)\d{1,6}){1,3})"  # or 4, then groups
    r"(?![\w\-]|\.\d)")
_CARD_DIGITS = (13, 19)


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        value = int(ch)
        if i % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def card_spans(text: str) -> list[Found]:
    """Every card number. A grouped run that fails is tried again without its
    last groups, so `4111 1111 1111 1111 2026` still masks the card."""
    found = []
    for m in _CARD.finditer(text):
        run = m.group(0)
        ends = [len(run)] + [i for i in range(len(run) - 1, 0, -1) if run[i] in " -"]
        for end in ends:
            digits = "".join(c for c in run[:end] if c.isdigit())
            if len(digits) < _CARD_DIGITS[0]:
                break
            if len(digits) <= _CARD_DIGITS[1] and _luhn(digits):
                found.append(("card", m.start(), m.start() + end))
                break
    return found


# ═══════════════════════════════════════════════════════════════ IPs

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_IPV6 = re.compile(
    r"(?<![\w:.%])(?P<address>(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}))"   # an IPv4 tail tried first
    r"(?:%[\w.\-]{1,32})?(?![\w:])")
_MIN_V6_HEX = 4
"""The fewest hex digits an IPv6 address shipped here holds. Every address in
use does (2001:…, fe80::…, fd00::…); a slice like `x[1::2]` does not."""


_HEX = frozenset("0123456789abcdefABCDEF")


def _kept_ipv4(address: str) -> bool:
    """Loopback and the unspecified address stay: they name no machine."""
    return address.startswith("127.") or address == "0.0.0.0"


def ip_spans(text: str) -> list[Found]:
    found = []
    if "." in text:
        for m in _IPV4.finditer(text):
            octets = m.group(0).split(".")
            if all(int(o) <= 255 for o in octets) and not _kept_ipv4(m.group(0)):
                found.append(("ip", m.start(), m.end()))
    if text.count(":") >= 2:
        for m in _IPV6.finditer(text):
            candidate = m.group("address")
            hex_digits = sum(c in _HEX for c in candidate.split(".")[0])
            if hex_digits < _MIN_V6_HEX or not any(c.isdigit() for c in candidate):
                continue                  # `abc::def`, `x[1::2]`: code, not hosts
            try:
                address = ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            mapped = address.ipv4_mapped
            if address.is_loopback or address.is_unspecified or (
                    mapped is not None and (mapped.is_loopback or mapped.is_unspecified)):
                continue
            found.append(("ip", m.start(), m.end()))
    return found


# ═══════════════════════════════════════════════════════════ home folders

_SYSTEM_FOLDERS = frozenset({"shared", "guest", ".localized", "public", "default",
                             "default user", "all users", "linuxbrew",
                             "desktop.ini"})
"""Folders under /Users, /home or C:\\Users that belong to the system, not a
person: they stay."""

_SEPARATORS = r"[/\\]+(?:\.[/\\]+)*"
"""Between `Users` or `home` and the name: ANY run of separators, and `./`.
⚠ SECURITY REVIEW, HIGH: `/Users//<name>/` and `/Users/./<name>/` name the
same folder as `/Users/<name>/`, and one separator exactly matched neither."""

_POSIX_HOME = re.compile(
    r"(?<![\w.\-])(?:/mnt/[A-Za-z]|/System/Volumes/Data|/Volumes/[^/\r\n\"'`]{1,64}"
    r"|/var|/export|/usr)?"
    r"\\?/(?i:users|home)" + _SEPARATORS +
    r"(?P<name>(?:[^/\\\s\"'`:;,*?<>|()\[\]{}$%]|\\ ){1,64})")    # `\ ` is a space
_WINDOWS_HOME = re.compile(
    r"(?i)(?<![\w])[A-Z]:(?:\\{1,2}|/)users" + _SEPARATORS +
    r"(?:(?P<name>[^\\/:*?\"<>|\r\n\t%$]{1,64}?)(?=\\|/)"   # up to the next folder
    r"|(?P<short>[^\\/:*?\"<>|\s%$]{1,64}))")                 # or one word
_TILDE_HOME = re.compile(r"(?<![\w$~])~(?P<name>[A-Za-z_][\w.\-]{0,63})(?=/)")
_HOME_TRIGGERS = ("users", "home", "~")
"""Asked of the text lower-cased: `/Home/` and `/HOME/` too (python review,
HIGH: only `users` ignored case)."""

_SPACED_REST = re.compile(r"(?: [^\s\\/\"'`:*?<>|%$;&]{1,64}){1,4}(?=[\\/\"'`]|$)")
"""The rest of a name that holds a space: its words, to the next folder, the
closing quote or the value's end.

⚠ ONLY WHERE THE SHELL KEEPS THE SPACE IN THE PATH: inside quotes, or when
the path is the whole value (a record's `cwd`). Outside quotes a space ends a
path, for the shell as for this: `ls /Users/<name> -la` is three words, and
reading on took `-la` for the name, and `ls /Users/Shared docs` masked a
system folder (python review, round three). A name with a space written
unquoted mid-command is two arguments to the shell, and its second word
ships."""


def _kept(name: str) -> bool:
    """A system folder, exactly: `Guest Info` is a name that starts with one
    (security review, round four). `ls /Users/Shared docs` keeps `Shared` because
    outside quotes the name is one word."""
    return name.lower() in _SYSTEM_FOLDERS or not name.strip(".")


def _name_span(text: str, match: re.Match, group: str) -> tuple[int, int]:
    """Where the name in `match` stands, its spaced rest included when the
    path is quoted or is the whole value."""
    start, end = match.span(group)
    if match.start() == 0 or text[match.start() - 1] in "\"'`":
        rest = _SPACED_REST.match(text, end)
        if rest is not None:
            end = rest.end()
    return start, end


def home_folder_spans(text: str) -> list[Found]:
    """The account-name segment of every home folder in `text`; the path's
    other folders are left as they are."""
    lowered = text.lower()
    if not any(t in lowered for t in _HOME_TRIGGERS):
        return []
    found = []
    for m in _TILDE_HOME.finditer(text):
        if not _kept(m.group("name")):
            found.append(("user", *m.span("name")))
    for pattern in (_POSIX_HOME, _WINDOWS_HOME):
        for m in pattern.finditer(text):
            group = "name" if m.group("name") is not None else "short"
            start, end = _name_span(text, m, group)
            if not _kept(text[start:end].strip()):
                found.append(("user", start, end))
    return found


# ═══════════════════════════════════════════════════════════ ID numbers

_NINE_DIGITS = re.compile(r"(?<![\w.\-/+:#@$%])\d{9}(?![\w\-/]|\.\d)")
_SSN = re.compile(r"(?<![\w.\-/+:])(\d{3})-(\d{2})-(\d{4})(?![\w\-/]|\.\d)")

MASK_UNLABELLED_ISRAELI_ID = True
"""⚠ MEASURED, NOT CHOSEN (docs/107, "Measured, the third pass"). One in ten
random 9-digit numbers passes the check digit, so an Israeli ID with no label
is masked only while that hits at most one record in a thousand of the
snapshot. A labelled one (`ת.ז:`, `id_number=`) is masked by its key either
way."""


def israeli_id_holds(digits: str) -> bool:
    """The Israeli ID check digit: weights 1,2,1,2,… each product's digits
    summed, the total a multiple of ten. Nine zeros pass it and name nobody."""
    if len(digits) != 9 or not digits.isdigit() or not digits.strip("0"):
        return False
    total = 0
    for i, ch in enumerate(digits):
        value = int(ch) * (2 if i % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def _ssn_issued(area: str, group: str, serial: str) -> bool:
    """Never issued: area 000, 666 or 900-999; group 00; serial 0000."""
    return (area not in ("000", "666") and area[0] != "9"
            and group != "00" and serial != "0000")


def id_number_spans(text: str) -> list[Found]:
    """A US SSN in an issued range."""
    if "-" not in text:
        return []
    return [("id-number", m.start(), m.end()) for m in _SSN.finditer(text)
            if _ssn_issued(*m.groups())]


def israeli_id_spans(text: str) -> list[Found]:
    """A 9-digit run passing the Israeli ID check, when MASK_UNLABELLED_ISRAELI_ID.
    ⚠ THE WEAKEST SHAPE HERE: one run in ten passes by chance, so a key that
    names the value (`routing_number=021000021`) names its type."""
    if not MASK_UNLABELLED_ISRAELI_ID:
        return []
    return [("id-number", m.start(), m.end()) for m in _NINE_DIGITS.finditer(text)
            if israeli_id_holds(m.group(0))]


# ═══════════════════════════════════════════════════════════════ IBANs

_IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?"
                   r"(?![A-Za-z0-9])")
_IBAN_LENGTH = (15, 34)


def _mod97(compact: str) -> bool:
    """ISO 13616: the first four characters moved to the end, letters as
    10-35, the number mod 97 is 1."""
    moved = compact[4:] + compact[:4]
    remainder = 0
    for ch in moved:
        for digit in (str(int(ch, 36)) if ch.isalpha() else ch):
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def iban_spans(text: str) -> list[Found]:
    """Every IBAN. A grouped one that fails is tried again without its last
    groups, as a card is: `GB82 WEST 1234 5698 7654 32 2026` still masks."""
    found = []
    for m in _IBAN.finditer(text):
        run = m.group(0)
        ends = [len(run)] + [i for i in range(len(run) - 1, 0, -1) if run[i] == " "]
        for end in ends:
            compact = run[:end].replace(" ", "")
            if len(compact) < _IBAN_LENGTH[0]:
                break
            if len(compact) <= _IBAN_LENGTH[1] and _mod97(compact):
                found.append(("bank-account", m.start(), m.start() + end))
                break
    return found


# ═══════════════════════════════════════════════════════════ MAC addresses

_MAC = re.compile(r"(?<![0-9A-Fa-f:\-.])[0-9A-Fa-f]{2}([:\-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
                  r"(?![0-9A-Fa-f]|[:\-][0-9A-Fa-f])")


def mac_spans(text: str) -> list[Found]:
    """Six hex pairs. All-zero stays: it names no interface."""
    if ":" not in text and "-" not in text:
        return []
    return [("mac", m.start(), m.end()) for m in _MAC.finditer(text)
            if m.group(0).replace(m.group(1), "").strip("0")]


# ═══════════════════════════════════════════ the KEYS that name personal data

PERSONAL_KEYS = {
    ("passport",): "passport",
    ("dob",): "birth-date", ("date", "of", "birth"): "birth-date",
    ("birthdate",): "birth-date", ("birth", "date"): "birth-date",
    ("account", "number"): "bank-account", ("acct",): "bank-account",
    ("routing", "number"): "bank-account", ("iban",): "bank-account",
    ("swift",): "bank-account", ("bic",): "bank-account",
    ("ssn",): "id-number", ("national", "id"): "id-number",
    ("id", "number"): "id-number", ("tax", "id"): "id-number", ("vat",): "id-number",
    ("driver", "license"): "id-number",
    ("address",): "address", ("street",): "address",
    ("postal", "code"): "address", ("zip",): "address",
    ("zip", "code"): "address", ("zipcode",): "address",
}
"""A key named by these words, as its LAST words (`home_address`,
`customerDateOfBirth`), names a value of that type. Split on `_`, `-`, `.`
and case, like the secret clues in `shipper/mask.py`."""

LABEL_PHRASES = {
    ("passport", "number"): "passport", ("passport", "no"): "passport",
    ("account", "number"): "bank-account", ("account", "no"): "bank-account",
    ("routing", "number"): "bank-account", ("bank", "account"): "bank-account",
    ("swift", "code"): "bank-account", ("bic", "code"): "bank-account",
    ("id", "number"): "id-number", ("tax", "id"): "id-number",
    ("national", "id"): "id-number", ("driver", "license"): "id-number",
    ("driver's", "license"): "id-number", ("drivers", "license"): "id-number",
    ("social", "security", "number"): "id-number",
    ("postal", "code"): "address", ("zip", "code"): "address",
    ("date", "of", "birth"): "birth-date", ("birth", "date"): "birth-date",
}
"""A label written as words (`Passport number:`, `Date of birth:`): the words
before the key, and the key, as a phrase (python review, MEDIUM)."""

QUALIFIERS = frozenset({"home", "billing", "shipping", "mailing", "postal", "street",
                        "residential", "permanent", "current", "my", "your", "his",
                        "her", "their", "our", "customer", "user", "patient", "client",
                        "employee", "contact"})
"""A word that makes the key after it a label (`Home address:`, `my passport:`).
`IP address:` is prose: `ip` is not one."""

PERSONAL_TRIGGERS = ("passport", "dob", "birth", "account", "acct", "routing", "iban",
                     "swift", "bic", "ssn", "national", "number", "tax", "vat",
                     "driver", "address", "street", "postal", "zip", "code", "license",
                     " no:")
"""What a text must hold, lower-cased, for the key rule to read it."""

HEBREW_KEY = re.compile(
    r"(?<![\u0590-\u05FF\w])(?P<name>ת\.ז\.?|ת\"ז|תעודת זהות|מספר חשבון)"
    r"(?![\u0590-\u05FF])[\"']?[ \t]*(?::|=)")
HEBREW_TYPES = {"ת.ז": "id-number", "ת.ז.": "id-number", 'ת"ז': "id-number",
                "תעודת זהות": "id-number", "מספר חשבון": "bank-account"}

_KEY_SEGMENT = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")


def labelled(words: list[str], key: str) -> str | None:
    """The type a label written as words names: `words` are the ones before
    `key` on its line, nearest last. A phrase from LABEL_PHRASES, or a key
    PERSONAL_KEYS names after a QUALIFIER; else None (prose)."""
    lowered = [w.lower() for w in words] + [key.lower()]
    for size in (3, 2):
        if len(lowered) >= size and tuple(lowered[-size:]) in LABEL_PHRASES:
            return LABEL_PHRASES[tuple(lowered[-size:])]
    if words and words[-1].lower() in QUALIFIERS:
        return personal_key(key)
    return None


GENERIC_SUFFIXES = frozenset({"number", "no", "num", "nr"})
"""A last word that only says "the number of": `passport_number` names what
`passport` names (item 4), and `account_no` what `account_number` names (the
review). `id` and `code` are not here: `address_id` is a row, and the keys
that end in them (`tax_id`, `zip_code`) are named in full."""


def personal_key(name: str) -> str | None:
    """The type a key names, from its last words, or None. A generic last word
    (`GENERIC_SUFFIXES`) is read as `number` (`account_no`), then read past,
    when the whole key names nothing."""
    words = tuple(word.lower() for word in _KEY_SEGMENT.findall(name))
    while words:
        named = _named_by_last_words(words)
        if named:
            return named
        if len(words) < 2 or words[-1] not in GENERIC_SUFFIXES:
            return None
        named = _named_by_last_words((*words[:-1], "number"))
        if named:
            return named
        words = words[:-1]
    return None


def _named_by_last_words(words: tuple[str, ...]) -> str | None:
    for size in (3, 2, 1):
        if len(words) >= size and words[-size:] in PERSONAL_KEYS:
            return PERSONAL_KEYS[words[-size:]]
    return None
