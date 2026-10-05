"""More personal data is masked before it ships: ID numbers, bank accounts,
MAC addresses, and a value its KEY names as personal.

Shipper only, like #78 item A (`shipper/identifying.py`, `shipper/mask.py`):
nothing here moves a verdict or a byte of a local record.

    by shape and check      Israeli ID (9 digits, check digit)   [id-number]
                            US SSN (AAA-GG-SSSS, issued ranges)   [id-number]
                            IBAN (country code, mod-97)           [bank-account]
                            MAC (six hex pairs, `:` or `-`)       [mac]
    by the key that names   passport, dob, account_number, ssn,
    it, in key position     address, zip, ת.ז, מספר חשבון, …      its type

⚠ NEVER BY ENTROPY. Every rule reads a shape and the check it carries, or the
name a value was given. The fixtures are synthetic: each passes (or, in the
negatives, fails) its type's own check, and none is a known-format credential.
"""
from __future__ import annotations

import time

import pytest

from shipper import identifying
from shipper.mask import mask_text


def masked(text: str) -> str:
    return mask_text(text)[0]


# ────────────────────────────────────────────────────── by shape and check
SHAPES = [
    ("israeli id, labelled", "ת.ז: 123456782", "ת.ז: [id-number]"),
    ("israeli id, key", "id_number=039337423", "id_number=[id-number]"),
    ("ssn", "SSN on file 123-45-6789 thanks", "SSN on file [id-number] thanks"),
    ("ssn, json", '{"n": "234-56-7890"}', '{"n": "[id-number]"}'),
    ("iban, grouped", "pay GB82 WEST 1234 5698 7654 32 today",
     "pay [bank-account] today"),
    ("iban, compact", "to DE89370400440532013000.", "to [bank-account]."),
    ("iban, israel", "IL620108000000099999999", "[bank-account]"),
    ("mac, colons", "ether 00:1A:2B:3C:4D:5E up", "ether [mac] up"),
    ("mac, dashes", "hw aa-bb-cc-dd-ee-ff", "hw [mac]"),
]


@pytest.mark.parametrize("label,text,want", SHAPES, ids=[s[0] for s in SHAPES])
def test_a_value_is_masked_by_its_shape_and_check(label, text, want):
    assert masked(text) == want


UNLABELLED = "customer 123456782 called"


def test_an_unlabelled_israeli_id_follows_the_measured_choice():
    """⚠ ONE IN TEN random 9-digit numbers passes the check digit, so an
    unlabelled one is masked only if the snapshot said it hits at most one
    record in a thousand (docs/107 "Measured, the third pass")."""
    if identifying.MASK_UNLABELLED_ISRAELI_ID:
        assert masked(UNLABELLED) == "customer [id-number] called"
    else:
        assert masked(UNLABELLED) == UNLABELLED


# ─────────────────────────────────────── by the key that names it, in key position
KEYS = [
    ("passport", "passport=X1234567", "passport=[passport]"),
    ("dob", '"dob": "1990-01-01"', '"dob": "[birth-date]"'),
    ("date_of_birth", "date_of_birth: 01/02/1990", "date_of_birth: [birth-date]"),
    ("birthdate flag", "--birthdate 1990-01-01", "--birthdate [birth-date]"),
    ("account_number", "account_number=12345678", "account_number=[bank-account]"),
    ("acct", "acct: 987654", "acct: [bank-account]"),
    ("routing_number", "routing_number=021000021", "routing_number=[bank-account]"),
    ("swift", "swift: DEUTDEFF", "swift: [bank-account]"),
    ("bic", "bic=DEUTDEFFXXX", "bic=[bank-account]"),
    ("iban key", 'IBAN="NOT-CHECKED-1"', 'IBAN="[bank-account]"'),
    ("national_id", "national_id=AB123456", "national_id=[id-number]"),
    ("tax_id", "tax_id: 12-3456789", "tax_id: [id-number]"),
    ("vat", "vat=GB123456789", "vat=[id-number]"),
    ("driver_license", "driver_license: D1234567", "driver_license: [id-number]"),
    ("ssn key", "ssn=not-a-shape", "ssn=[id-number]"),
    ("address", 'address: "12 Main St, Springfield"', 'address: "[address]"'),
    ("street", "street=Herzl-5", "street=[address]"),
    ("postal_code", "postal_code: 6100000", "postal_code: [address]"),
    ("zip", "zip=90210", "zip=[address]"),
    ("zip json", '{"zip": "90210"}', '{"zip": "[address]"}'),
    ("a prefixed key", '"home_address": "1 Rd"', '"home_address": "[address]"'),
    ("camel case", "customerDateOfBirth=1990-01-01", "customerDateOfBirth=[birth-date]"),
    ("export", "export ZIP=90210", "export ZIP=[address]"),
    ("hebrew account", "מספר חשבון: 12-345-678901", "מספר חשבון: [bank-account]"),
    ("hebrew id", "תעודת זהות: 000000018", "תעודת זהות: [id-number]"),
    # ⚠ PYTHON REVIEW, MEDIUM: a label of two or three words is a label.
    ("home address", "Home address: 12 Main St", "Home address: [address]"),
    ("my passport", "my passport: AB12345", "my passport: [passport]"),
    ("passport number", "Passport number: 12345678", "Passport number: [passport]"),
    ("account number", "Account number: 12345678", "Account number: [bank-account]"),
    ("date of birth", "Date of birth: 1990-01-01", "Date of birth: [birth-date]"),
    ("zip code", "Zip code: 90210", "Zip code: [address]"),
]


@pytest.mark.parametrize("label,text,want", KEYS, ids=[k[0] for k in KEYS])
def test_a_value_its_key_names_is_masked(label, text, want):
    assert masked(text) == want


# ───────────────────────────────────────────────────────── what stays as it is
STAYS = [
    ("9 digits failing the check", "order 123456789 shipped"),
    ("nine zeros", "000000000"),
    ("a git sha", "8336bceae4a81dc310586dcde47be38b87a9dd42"),
    ("a uuid", "550e8400-e29b-41d4-a716-446655440000"),
    ("a version", "python 3.12.1 and v2.34.5"),
    ("a date", "2026-09-29"),
    ("ssn area 000", "000-12-3456"),
    ("ssn area 666", "666-12-3456"),
    ("ssn area 9xx", "912-12-3456"),
    ("ssn group 00", "123-00-4567"),
    ("ssn serial 0000", "123-45-0000"),
    ("iban failing mod-97", "GB82WEST12345698765433"),
    ("mac all zero", "00:00:00:00:00:00"),
    ("a time", "12:34:56"),
    ("'address' in prose", "Your IP address: see the router"),
    ("'address' in prose, no colon", "check the mailing address first"),
    ("the zip command", "zip -r out.zip dir && unzip -l out.zip"),
    ("an unrelated key", "export PATH=/usr/bin:$PATH"),
    # ⚠ FROM THE SNAPSHOT (docs/107 §9): a field DECLARED with its type is not
    # a value. `address: str` masked `str`.
    ("a type annotation", "    address: str"),
    ("an optional annotation", "zip: int | None = None"),
]


@pytest.mark.parametrize("label,text", STAYS, ids=[s[0] for s in STAYS])
def test_what_is_not_personal_data_is_left_alone(label, text):
    assert masked(text) == text


# ⚠ ITEM 4: a key after a shell assignment or an option is in key position,
# not a word in a sentence, and a key that ends in a generic "number" word
# (`passport_number`) names what the words before it name.
KEY_POSITION = [
    ("after an assignment", "VAR=1 passport=X1234567", "VAR=1 passport=[passport]"),
    ("after two assignments", "A=1 B=two passport=X1234567",
     "A=1 B=two passport=[passport]"),
    ("after env and an assignment", "env A=1 zip=90210 ./run", "env A=1 zip=[address] ./run"),
    ("after an option", "curl -d passport=X1234567 https://x.invalid",
     "curl -d passport=[passport] https://x.invalid"),
    ("after a long option", "curl --data zip=90210 https://x.invalid",
     "curl --data zip=[address] https://x.invalid"),
]
COMPOUND = [
    ("passport_number", "passport_number=X1234567", "passport_number=[passport]"),
    ("PASSPORT_NO", "PASSPORT_NO=X1234567", "PASSPORT_NO=[passport]"),
    ("passportNumber", '{"passportNumber": "X1234567"}', '{"passportNumber": "[passport]"}'),
    ("passport-num flag", "--passport-num X1234567", "--passport-num [passport]"),
    ("ssn_number", "ssn_number=not-a-shape", "ssn_number=[id-number]"),
    ("iban_nr", "iban_nr=NOT-CHECKED", "iban_nr=[bank-account]"),
    ("vat_no", "vat_no=GB123456789", "vat_no=[id-number]"),
    ("both", "VAR=1 passport_number=X1234567", "VAR=1 passport_number=[passport]"),
]
STAYS_IN_ITEM_4 = [
    ("a version number", "version_number=3"),
    ("a line number", "line_number=42"),
    ("a build no", "build_no=7"),
    ("an account id", "account_id=5"),
    ("an address id", "address_id=42"),
    ("a key after a word is still prose", "check the address: 12 Main St"),
    ("a hyphenated word before is still prose", "the e-mail address: see the form"),
]


@pytest.mark.parametrize("label,text,want", KEY_POSITION + COMPOUND,
                         ids=[k[0] for k in KEY_POSITION + COMPOUND])
def test_a_key_after_shell_words_or_with_a_number_suffix_is_masked(label, text, want):
    assert masked(text) == want


@pytest.mark.parametrize("label,text", STAYS_IN_ITEM_4, ids=[s[0] for s in STAYS_IN_ITEM_4])
def test_item_4_leaves_what_is_not_personal_data_alone(label, text):
    assert masked(text) == text


# ⚠ REVIEW: `zip_code` and `account_no` named nothing: `code` is no generic
# word, and `account` alone is no key. A generic last word now stands for
# `number` before it is read past, and `zip_code` is a key. A key written
# key=value, with no space, is a key wherever it stands: `echo passport=…` is
# an argument, not a sentence. "Key: value" after a word keeps its rule.
REVIEW_KEYS = [
    ("zip_code", "zip_code=90210", "zip_code=[address]"),
    ("zipCode json", '{"zipCode": "90210"}', '{"zipCode": "[address]"}'),
    ("ZIP_CODE colon", "ZIP_CODE: 90210", "ZIP_CODE: [address]"),
    ("zipcode", "zipcode=90210", "zipcode=[address]"),
    ("account_no", "account_no=12345678", "account_no=[bank-account]"),
    ("ACCOUNT_NUM", "ACCOUNT_NUM: 12345678", "ACCOUNT_NUM: [bank-account]"),
    ("routing_nr", "routing_nr=021000021", "routing_nr=[bank-account]"),
    ("echo", "echo passport=X1234567", "echo passport=[passport]"),
    ("an argument", "python app.py passport=X1234567", "python app.py passport=[passport]"),
    ("in a sentence", "ship to zip_code=90210 today", "ship to zip_code=[address] today"),
    # the same before and after: they pin what stays
    ("acct_no", "acct_no=987654", "acct_no=[bank-account]"),
    ("export", "export ZIP=90210", "export ZIP=[address]"),
]
REVIEW_STAYS = [
    ("a label after a word", "check the address: 12 Main St"),
    ("a spaced = after a word", "the address = see below"),
    ("a space after =", "the address= see below"),
    ("a comparison", "if zip == 90210"),
    ("a code that is no zip", "error_code=42"),
    ("an account id", "account_id=5"),
]


# ⚠ SECURITY REVIEW, MEDIUM: a field declared with its type AND a default
# (`passport: str = "A1234567"`) was read as a declaration and shipped its
# default raw. The default is a value; `None` or an empty one is not.
DEFAULTS = [
    ("a quoted default", 'passport: str = "A1234567"', 'passport: str = "[passport]"'),
    ("a bare default", "zip: int = 90210", "zip: int = [address]"),
]
DEFAULTS_STAY = [
    ("a None default", "zip: int | None = None"),
    ("an empty default", 'address: str = ""'),
    ("no default", "    address: str"),
]


@pytest.mark.parametrize("label,text,want", DEFAULTS, ids=[d[0] for d in DEFAULTS])
def test_a_declared_fields_default_is_masked(label, text, want):
    assert masked(text) == want


@pytest.mark.parametrize("label,text", DEFAULTS_STAY, ids=[d[0] for d in DEFAULTS_STAY])
def test_a_declaration_without_a_value_stays(label, text):
    assert masked(text) == text


@pytest.mark.parametrize("label,text,want", REVIEW_KEYS, ids=[k[0] for k in REVIEW_KEYS])
def test_zip_code_account_no_and_a_tight_key_mask(label, text, want):
    assert masked(text) == want


@pytest.mark.parametrize("label,text", REVIEW_STAYS, ids=[s[0] for s in REVIEW_STAYS])
def test_the_review_leaves_a_label_in_a_sentence_alone(label, text):
    assert masked(text) == text


def test_an_ip_under_an_address_key_keeps_its_own_type():
    """A value two rules find is named by the more specific: the shape."""
    assert masked("ip_address: 10.20.30.40") == "ip_address: [ip]"
    assert masked("mac_address=00:1A:2B:3C:4D:5E") == "mac_address=[mac]"


# ────────────────────────────────────────── worst case: linear, not quadratic
ADVERSARIAL = [
    ("digit runs", "123456782 " * 5000),
    ("dashed triples", "123-45-6789-" * 4500),
    ("iban groups", "GB82 WEST " * 5000),
    ("hex pairs", "aa:" * 17000),
    ("keys", "zip=address=dob=" * 3200),
    ("hebrew keys", "ת.ז: " * 10000),
    # ⚠ ITEM 4 reads the shell word before a key: each is read by one key only.
    ("keys after long assignments", ("A=" + "x" * 500 + " passport=1 ") * 95),
    ("keys after long words", ("x" * 500 + " zip=1 ") * 98),
    ("numbered keys", "passport_number_no_nr=1 " * 2000),
]


def _cost(text: str) -> float:
    best = float("inf")
    for _ in range(5):
        started = time.perf_counter()
        mask_text(text)
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("label,text", ADVERSARIAL, ids=[a[0] for a in ADVERSARIAL])
def test_fifty_kilobytes_of_adversarial_text_is_linear(label, text):
    """Four times the text: linear is four times the time, quadratic sixteen.
    The bound is eight, best of five, so a loaded machine cannot fail it."""
    full, quarter = _cost(text[:50_000]), _cost(text[:12_500])
    assert full < 1.0, f"{label}: {full:.3f} s for 50 KB"
    assert full < 8 * max(quarter, 1e-3), (
        f"{label}: 50 KB {full:.4f} s, 12.5 KB {quarter:.4f} s")


# ⚠ REVIEW: `_words_before` searched back for the line's start from every key
# read as prose, so one long line was quadratic: 256 KB of "a zip: 1 " took
# 1.50 s against 0.15 s for 64 KB. It reads 64 characters, and now searches
# only those. Eight times the text: linear is eight times the time, quadratic
# sixty-four; the bound is sixteen.
ONE_LINE = [
    ("prose keys", "see the address: x "),
    ("short prose keys", "a zip: 1 "),
    ("prose labels", "word passport: q "),
]


@pytest.mark.parametrize("label,unit", ONE_LINE, ids=[o[0] for o in ONE_LINE])
def test_a_256_kb_line_is_masked_in_linear_time(label, unit):
    size = 256 * 1024
    text = (unit * (size // len(unit) + 1))[:size]
    full, eighth = _cost(text), _cost(text[:size // 8])
    assert full < 16 * max(eighth, 1e-3), (
        f"{label}: 256 KB {full:.4f} s, 32 KB {eighth:.4f} s")
