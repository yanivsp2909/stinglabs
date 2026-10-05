"""The device token was in a file with no special permissions, on the machine
running the agent being watched.

`hooks.json` was the reported location and it was fixed one commit before this
one — `install.write_hook_config` writes `<python> sting_hook.py --agent <name>`
and nothing else. **Nobody swept the other files the installer writes**, and the
supervisor artifact still carried it. Measured on the development machine, in a
file `-rw-r--r--`:

    ~/Library/LaunchAgents/dev.sting.shipper.plist
        <key>STING_DEVICE_TOKEN</key><string>IGYJCN…</string>

All three supervisor flavours had it — launchd's `EnvironmentVariables`,
systemd's `Environment=`, and Task Scheduler's wrapper `.cmd`, which exists
precisely BECAUSE schtasks has no environment block.

⚠ AND IT WAS PURE REDUNDANCY. `shipper/config.from_env` already reads every
setting from `~/.sting/env` (0600), environment-wins-over-file — that stopped
being tier-only when the first native Windows install found the shipper reading
one key out of its own file. So the token reached the shipper by the private
route whether or not the public file repeated it. Removing it costs nothing and
is the same act as taking the env prefix out of `hooks.json`: a setting the
guard needs does not belong in a file the thing being guarded can read.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import install
from installer import supervisor
from shipper import service

ROOT = Path(__file__).resolve().parent.parent

TOKEN = "tok_SUPERSECRET_do_not_ship_me"
ENV = {
    "STING_COLLECTOR_URL": "https://collector.invalid/ingest",
    "STING_DEVICE_ID": "test-box",
    "STING_DEVICE_TOKEN": TOKEN,
    "STING_OBSERVE": "1",
    "STING_ROOTS": "/x/y",
    "STING_SESSION_ROOT": "/tmp/sessions",
    "STING_TIER": "verdict_reason_location",
}


# ═══════════════════════════════════════ every generator, not just one ══

@pytest.mark.parametrize("generator", ["_plist", "_unit", "_cmd_wrapper"])
def test_no_supervisor_body_carries_the_token(generator):
    """⚠ ALL THREE. The Windows wrapper is the one most easily forgotten,
    because it is not a "config file" — it is a batch script, and it exists
    only because Task Scheduler has no environment block at all."""
    body = getattr(supervisor, generator)(
        sys.executable, Path("/opt/sting/shipper/run.py"),
        supervisor.public_env(ENV))

    assert TOKEN not in body, f"{generator} still writes the device token"
    # the non-secret settings must survive — this is a filter, not a purge
    assert "verdict_reason_location" in body
    assert "collector.invalid" in body


def test_the_filter_is_applied_at_the_one_place_all_flavours_pass_through():
    """Filtering inside each generator would be three copies, and the fourth
    flavour somebody adds is the one that forgets."""
    source = (ROOT / "installer" / "supervisor.py").read_text(encoding="utf-8")
    body = source.split("def write(", 1)[1].split("\ndef ", 1)[0]
    assert "public_env(env)" in body


def test_public_env_drops_only_what_is_named(tmp_path):
    out = supervisor.public_env(ENV)
    assert "STING_DEVICE_TOKEN" not in out
    assert set(ENV) - set(out) == {"STING_DEVICE_TOKEN"}
    assert supervisor.SECRETS == ("STING_DEVICE_TOKEN",)


def test_a_written_supervisor_file_does_not_contain_the_token(tmp_path,
                                                                monkeypatch):
    """The file on disk, not the string a generator returned."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(service, "target_path",
                        lambda: tmp_path / "sup" / "dev.sting.shipper.plist")

    result = supervisor.write(sys.executable, Path("/opt/x/run.py"), dict(ENV))
    if result["path"] is None:
        pytest.skip(f"no supervisor flavour here: {result['note']}")

    assert TOKEN not in Path(result["path"]).read_text(encoding="utf-8")


def test_the_shipper_still_gets_the_token_from_the_private_file(tmp_path,
                                                                 monkeypatch):
    """⚠ THE HALF THAT MAKES THE REMOVAL SAFE. If the shipper could only learn
    the token from the supervisor block, taking it out would break shipping —
    which is why this is asserted rather than assumed."""
    from shipper import config

    sting = tmp_path / ".sting"
    sting.mkdir()
    (sting / "env").write_text(
        "\n".join(f"export {k}='{v}'" for k, v in ENV.items()) + "\n",
        encoding="utf-8")

    settings = config.from_env(env={"HOME": str(tmp_path)})

    assert settings.device_token == TOKEN
    assert settings.collector_url == "https://collector.invalid/ingest"
    assert settings.configured, settings.why_not_configured()


# ═══════════════════════════════════ removal is not rotation — the report ══

def test_an_existing_leaking_file_is_detected_before_it_is_overwritten(tmp_path):
    """⚠ EVERY INSTALL REWRITES THIS FILE, so an upgrade silently deletes the
    credential and the operator never learns it was there — on a machine where
    it may have been world-readable for weeks, through backups and screen
    shares. Only they can rotate it."""
    stale = tmp_path / "dev.sting.shipper.plist"
    stale.write_text(f"<key>STING_DEVICE_TOKEN</key><string>{TOKEN}</string>",
                     encoding="utf-8")

    assert supervisor.leaked_secret_in(stale, ENV) == ["STING_DEVICE_TOKEN"]


def test_a_clean_or_absent_file_reports_nothing(tmp_path):
    assert supervisor.leaked_secret_in(tmp_path / "nope", ENV) == []
    clean = tmp_path / "clean.plist"
    clean.write_text("<key>STING_TIER</key><string>located</string>",
                     encoding="utf-8")
    assert supervisor.leaked_secret_in(clean, ENV) == []
    # and an EMPTY token must never match — every file contains "".
    assert supervisor.leaked_secret_in(clean, {"STING_DEVICE_TOKEN": ""}) == []


def test_the_report_names_the_key_and_never_the_value(tmp_path):
    """A report about a leaked secret must not be another copy of it."""
    stale = tmp_path / "s.plist"
    stale.write_text(TOKEN, encoding="utf-8")
    found = supervisor.leaked_secret_in(stale, ENV)
    assert found == ["STING_DEVICE_TOKEN"]
    assert TOKEN not in "".join(found)


def test_the_installer_tells_the_operator_to_rotate():
    """Said twice on purpose: at the write, and in the `Done` block a developer
    actually reads. Section 8 is ~100 lines and a whole preflight run away."""
    source = (ROOT / "install.py").read_text(encoding="utf-8")
    assert "was_leaking" in source
    done = source.split('head("Done")', 1)[1].split("def do_status", 1)[0]
    assert "ROTATE" in done
    assert "Removal is not rotation" in done


# ═════════════════════════════════════════ the reported file, still clean ══

def test_hooks_json_still_carries_no_settings_and_no_secret():
    """The originally-reported location. Fixed one commit earlier; pinned here
    so the sweep and the original cannot drift apart."""
    for agent in ("claude-code", "cursor", "codex", "copilot", "antigravity"):
        written = install.write_hook_config(
            agent, Path("/tmp/never-written/c.json"),
            Path("/opt/sting/current/sting_hook.py"), dict(ENV), dry_run=True)
        command = written["command"]
        assert TOKEN not in command, agent
        assert "STING_" not in command, (agent, command)
