"""`install.py --status` says what is wrong with a setting, and carries on.

From #76's open list. `--status` reads the settings through
`shipper.config.from_env()`, which `int()`s the four intervals — and a
malformed one (`STING_SHIP_INTERVAL='5m'`) raised `ValueError` out of the one
command a person runs to find out what is wrong. It now names the setting,
where it was read from, and what the shipper does about it (it will not start
until it is fixed: `from_env()` still refuses it, pinned in
tests/test_there_are_no_tiers.py), and prints the rest of the status.

Nothing here touches the real machine: `tests/install_harness.py`.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from install_harness import home, no_real_supervisor              # noqa: E402,F401

import install                                                     # noqa: E402
from shipper import config                                         # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX fake supervisor")


@pytest.fixture(autouse=True)
def the_environment_is_put_back():
    """`--status` loads `~/.sting/env` into the process environment (`envfile`,
    for STING_ROOTS), so one test's malformed value would be the next one's."""
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


def _env(home: Path, text: str) -> None:
    (home / ".sting").mkdir(parents=True, exist_ok=True)
    (home / ".sting" / "env").write_text(text, encoding="utf-8")


@pytest.mark.parametrize("name", ["STING_SHIP_INTERVAL", "STING_SHIP_RECORDS",
                                  "STING_HEARTBEAT_INTERVAL", "STING_POLICY_SECONDS"])
def test_status_names_a_malformed_number_and_prints_the_rest(home, capsys, name):
    _env(home, f"STING_SHIPS='masked'\n{name}='5m'\n")
    rc = install.main(["--status"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert f"{name}='5m'" in out and "not a whole number" in out, out
    assert "the shipper will not start until it is" in out, out
    assert "  ships      masked records" in out, "the rest of the status still prints"


def test_a_malformed_number_in_the_environment_is_named_too(home, capsys, monkeypatch):
    _env(home, "STING_SHIPS='masked'\n")
    monkeypatch.setenv("STING_SHIP_INTERVAL", "soon")
    assert install.main(["--status"]) == 0
    out = capsys.readouterr().out
    assert "STING_SHIP_INTERVAL='soon'" in out and "the environment" in out, out


def test_a_long_malformed_value_is_shown_as_a_masked_view(home, capsys):
    """⚠ SECURITY REVIEW, MEDIUM: the value was printed whole, and a secret
    pasted into the wrong variable would be printed with it — in the one
    output people paste into tickets. At most its first 4 characters and its
    length."""
    secret = "sk-fake-" + "x7Q" * 12                     # made up
    _env(home, f"STING_SHIPS='masked'\nSTING_SHIP_INTERVAL='{secret}'\n")
    assert install.main(["--status"]) == 0
    out = capsys.readouterr().out
    assert secret not in out and secret[4:] not in out
    assert f"'{secret[:4]}…' ({len(secret)} characters)" in out


def test_well_formed_settings_print_no_warning(home, capsys):
    _env(home, "STING_SHIPS='masked'\nSTING_SHIP_INTERVAL='30'\n")
    assert install.main(["--status"]) == 0
    assert "not a whole number" not in capsys.readouterr().out


def test_the_shipper_still_refuses_to_start_on_one(tmp_path):
    """`--status` carries on; the shipper does not guess what was meant."""
    with pytest.raises(ValueError):
        config.from_env(env={"HOME": str(tmp_path), "STING_SHIP_INTERVAL": "5m"},
                        env_file=tmp_path / "absent")
    problems = config.setting_problems(
        env={"HOME": str(tmp_path), "STING_SHIP_INTERVAL": "5m"},
        env_file=tmp_path / "absent")
    assert [p["setting"] for p in problems] == ["STING_SHIP_INTERVAL"]
    assert problems[0]["where"] == "the environment"
