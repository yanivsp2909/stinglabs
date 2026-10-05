"""Phone numbers, card numbers and IP addresses are masked in what ships.

Item A of fix/more-masking-and-agent-status. The shipper's masking
(`shipper/mask.py`) recognised credentials, emails and values named as secrets;
a phone number, a card number or a machine's address in a command shipped as
written. They are now masked by their SHAPE (`shipper/identifying.py`):

    [phone]  a +country code, or digits grouped by separators in a phone's
             shapes; never a bare run of digits, a version, a date or a time
    [card]   13-19 digits, alone or grouped, that pass the Luhn check
    [ip]     IPv4 and IPv6, except loopback (127.0.0.0/8, ::1) and 0.0.0.0

Mask on doubt: an over-masked version number is cheap, a phone number shipped
is not. The over-masking is measured on the snapshot (docs/107).

Every value here is a fake: fictional phone numbers (NANP 555-01xx, Ofcom's
drama range), card networks' published test numbers, and the documentation
address ranges (RFC 5737, RFC 3849).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shipper import mask                                           # noqa: E402


def _masked(text: str) -> str:
    return mask.mask_text(text)[0]


# ═══════════════════════════════════════════════════════════════ phones

@pytest.mark.parametrize("phone", [
    "+1 (415) 555-0123",
    "+1-415-555-0123",
    "+14155550123",
    "+44 20 7946 0958",
    "+972 54-555-0123",
    "(415) 555-0123",
    "415-555-0123",
    "1-800-555-0123",
    "054-555-0123",
    "054-5550123",
    "415.555.0123",
    "020 7946 0958",
    "01 23 45 67 89",
])
def test_a_formatted_phone_number_is_masked(phone):
    assert _masked(f"call {phone} now") == "call [phone] now"
    assert _masked(f'{{"phone": "{phone}"}}') == '{"phone": "[phone]"}'


@pytest.mark.parametrize("not_a_phone", [
    "4155550123",                   # a bare run of digits
    "1727500000",                   # a timestamp
    "2026-09-28",                   # a date
    "28-09-2026",
    "12:30:45",                     # a time
    "2026-09-28T12:30:45+03:00",
    "v1.0.3-33-g3c0ae67",           # git describe
    "python3.12.4",
    "sed -n 100,200p",
    "kill 4521 4522 4523",          # pids, spaced
    "seq 10 20 30 40",
    "--port 8000-8080",
    "+0300",                        # a timezone
    "550e8400-e29b-41d4-a716-446655440000",
])
def test_what_is_not_a_phone_number_is_left(not_a_phone):
    assert "[phone]" not in _masked(not_a_phone)


# ═══════════════════════════════════════════════════════════════ cards

@pytest.mark.parametrize("card", [
    "4111 1111 1111 1111",          # Visa's test number
    "4111-1111-1111-1111",
    "4242424242424242",             # Stripe's
    "5555555555554444",             # Mastercard's
    "3782 822463 10005",            # American Express's
    "378282246310005",
])
def test_a_card_number_that_passes_luhn_is_masked(card):
    assert _masked(f"pay with {card}.") == "pay with [card]."


@pytest.mark.parametrize("not_a_card", [
    "4111 1111 1111 1112",          # fails Luhn
    "4242424242424241",
    "0000000000000000",             # starts with 0
    "411111111111",                 # 12 digits
    "41111111111111111111",         # 20 digits
    "deadbeef4242424242424242cafe", # inside a hex string
])
def test_what_is_not_a_card_number_is_left(not_a_card):
    assert "[card]" not in _masked(not_a_card)


# ═══════════════════════════════════════════════════════════════ IPs

@pytest.mark.parametrize("text, expected", [
    ("ssh admin@203.0.113.7", "ssh admin@[ip]"),
    ("curl http://192.0.2.10:8080/x", "curl http://[ip]:8080/x"),
    ("mysql -h198.51.100.4 -u app", "mysql -h[ip] -u app"),
    ("route 10.0.0.0/8", "route [ip]/8"),
    ("ping 2001:db8::1", "ping [ip]"),
    ("curl http://[2001:db8::42]:443/", "curl http://[[ip]]:443/"),
    ("ip -6 addr fe80::1ff:fe23:4567:890a%en0", "ip -6 addr [ip]"),
    ("::ffff:203.0.113.9 is mapped", "[ip] is mapped"),
    ("host 010.001.002.003", "host [ip]"),       # leading zeros: still one
])
def test_an_ip_address_is_masked(text, expected):
    assert _masked(text) == expected


@pytest.mark.parametrize("kept", [
    "curl http://127.0.0.1:8000/", "ping 127.1.2.3", "bind 0.0.0.0:80",
    "curl http://[::1]:3000/", "listen [::]:80", "::ffff:127.0.0.1",
])
def test_loopback_and_the_unspecified_address_stay(kept):
    assert _masked(kept) == kept


@pytest.mark.parametrize("not_an_ip", [
    "1.2.3", "10.0.19041.1", "999.1.1.1", "1.2.3.4.5",
    "std::vector<int> v;", "x[1::2]", "a[::2]", "12:30:45",
    "00:1a:2b:3c:4d:5e",            # a MAC address
    "Foo::Bar::baz", "abc::def",
])
def test_what_is_not_an_ip_address_is_left(not_an_ip):
    assert "[ip]" not in _masked(not_an_ip)


# ═══════════════════════════════════════════════════════════ in a record

def test_a_record_carries_each_as_its_type_and_counts_it():
    record = {"seq": 3, "event": "decision", "decision": "ALLOW",
              "command": "curl -d 'card=4111 1111 1111 1111&tel=+1 (415) 555-0123' "
                         "http://203.0.113.7/pay",
              "cwd": "/work/repo"}
    shipped = mask.mask_record(record)
    assert shipped["command"] == ("curl -d 'card=[card]&tel=[phone]' "
                                  "http://[ip]/pay")
    assert shipped["masked"] == {"card": 1, "ip": 1, "phone": 1}
    assert shipped["seq"] == 3 and shipped["decision"] == "ALLOW"


def test_a_value_masked_once_is_masked_wherever_the_record_carries_it():
    record = {"command": "ping 203.0.113.7", "reason": "left for 203.0.113.7"}
    shipped = mask.mask_record(record)
    assert "203.0.113.7" not in str(shipped)


def test_no_entropy_measure_in_the_shape_rules():
    source = (Path(__file__).resolve().parents[1] / "shipper" / "identifying.py").read_text()
    assert "entropy" not in source.split('"""', 2)[2].lower()
