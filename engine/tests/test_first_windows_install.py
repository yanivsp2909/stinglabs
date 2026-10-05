"""Four defects from the first native Windows install. None was CI-visible.

Windows 11, Python 3.14, no WSL. All five agents detected, the collector
reachable, the token accepted — and four failures, every one on the path a
customer takes, with the Windows suite green throughout.

⚠ TWO OF THEM LOOKED LIKE ONE BUG AND WERE NOT. Failure 1 (`STING_ROOTS` split
on `:`) and failure 3 (the shipper reading only one value from its env file)
share a symptom shape: what arrived had no colon and no backslash, what did not
was `https://…`, `C:\\Users\\…` and a token. That is a separator bug's
fingerprint exactly. **It was a coincidence.** The file was written correctly and
parsed correctly; only one key was ever asked for. Reading the file before
touching the parser is what separated them.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import probes                                              # noqa: E402
from installer import detect, place, supervisor                      # noqa: E402
from shipper import service                                          # noqa: E402
from shipper import config as shipper_config                         # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ══════════ 1 · the separator — the ENGINE was right, the CHECKS were stale

def test_split_and_join_are_inverses_on_both_platforms():
    """⚠ A SPLITTER WITHOUT A JOINER GETS A HAND-WRITTEN JOINER, AND IT WAS
    WRONG IN THREE PLACES. `split_roots` was fixed to `os.pathsep` in the
    Windows port; the three that BUILT such a value were not."""
    # ⚠ EACH SEPARATOR WITH THE PATHS THAT PLATFORM ACTUALLY WRITES. A colon
    # genuinely cannot represent Windows paths — that is the defect, not a
    # property to assert away — so pairing them is what the round trip means.
    for sep, paths in ((";", [r"C:\Users\dev\one", r"C:\Users\dev\two"]),
                       (":", ["/home/dev/one", "/home/dev/two"])):
        assert probes.split_roots(probes.join_roots(paths, sep), sep) == paths


def test_a_windows_path_survives_the_windows_separator():
    """THE DEFECT: `C:\\Users\\alice\\Projects` reported as unresolvable, on a
    platform where `;` is the separator. Every Windows path contains a colon in
    `C:`, so the user could not work around it."""
    value = r"C:\Users\alice\Projects;C:\Users\alice\sparta-security"

    assert probes.split_roots(value, ";") == [
        r"C:\Users\alice\Projects", r"C:\Users\alice\sparta-security"]


def test_no_module_still_splits_a_roots_value_on_a_literal_colon():
    """⚠ THE SCAN, because the fix is an absence. `preflight.py` and
    `replay_session.py` both hardcoded `value.split(":")` after the engine had
    moved on, and nothing pointed at them."""
    import re

    offenders = []
    for name in ("tools/preflight.py", "tools/replay_session.py",
                 "installer/detect.py", "hook_entry.py", "core/probes.py"):
        source = open(os.path.join(ROOT, name), encoding="utf-8").read()
        for i, line in enumerate(source.splitlines(), 1):
            code = line.split("#", 1)[0]
            if re.search(r'(ROOTS|SCRATCH|roots|scratch)\w*\s*\)?\.split\("\:"\)', code) \
                    or re.search(r'\.split\(":"\)', code) and "root" in code.lower():
                offenders.append(f"{name}:{i} {line.strip()}")
    assert not offenders, offenders


def test_the_remediation_message_does_not_contain_the_defect(monkeypatch):
    """⚠ THE FIFTH TIME A MESSAGE DESCRIBING A DEFECT HAS CONTAINED IT.

    Preflight printed `export STING_ROOTS='C:\\a:C:\\b'` — a colon separator, on
    Windows, from the tool whose neighbouring check exists to catch colon
    separators on Windows.
    """
    source = open(os.path.join(ROOT, "tools", "preflight.py"),
                  encoding="utf-8").read()
    assert '":".join' not in source, \
        "preflight builds a roots value with a literal colon"
    assert "join_roots" in source


def test_the_installer_proposes_a_value_its_own_splitter_can_read():
    """⚠ THE WORST OF THE FOUR SITES: this is the value `install.py` WRITES as
    the trust boundary. A colon here on Windows produces a STING_ROOTS that
    `split_roots` reads as one path that does not exist — the 74-of-89 denial
    condition, written by the installer itself."""
    proposal = detect.propose_roots()
    if not proposal["proposed"]:
        pytest.skip("no sibling repositories beside this checkout")

    assert probes.split_roots(proposal["value"]) == proposal["proposed"]


# ══════════ 2 · `current` is a POINTER FILE on Windows, not a directory

def test_place_returns_the_resolved_directory_not_the_pointer(tmp_path,
                                                               monkeypatch):
    """⚠ `install.py` BUILDS THE HOOK COMMAND FROM THIS VALUE. Returning the
    pointer path put `…\\current\\sting_hook.py` into every Windows agent's
    settings file — a path that cannot exist, which is what preflight reported
    as `[FAIL] entry point exists` while `[PASS] entry point runnable` passed
    beside it, because the two were asking about different files.
    """
    prefix = tmp_path / "prefix"
    placed = place.place(prefix=prefix, source=ROOT,
                         session_root=tmp_path / "sessions")

    current = placed["current"]
    assert (current / "sting_hook.py").is_file(), (
        f"the hook entry must exist under {current}")
    for name in place.PAYLOAD:
        assert (current / name).exists()


def test_installed_version_reads_through_the_pointer(tmp_path):
    """The same bug one level down: `current/INSTALL.json` is not a path that
    can exist on Windows, so every install read as "nothing installed"."""
    prefix = tmp_path / "prefix"
    place.place(prefix=prefix, source=ROOT, session_root=tmp_path / "sessions")

    assert place.installed_version(prefix), "the manifest was not found"


def test_nothing_builds_a_path_under_the_raw_current_name():
    """⚠ THE SCAN. `place.current_dir()` exists to resolve the layout; three
    places went round it and built `prefix / "current" / …` by hand."""
    import re

    offenders = []
    for name in ("install.py", "installer/place.py", "tools/preflight.py"):
        source = open(os.path.join(ROOT, name), encoding="utf-8").read()
        for i, line in enumerate(source.splitlines(), 1):
            code = line.split("#", 1)[0]
            if re.search(r'"current"\s*/', code):
                offenders.append(f"{name}:{i} {line.strip()}")
    assert not offenders, offenders


# ══════════ 3 · the shipper read ONE key from its own env file

def test_the_env_file_yields_every_key_not_just_the_tier(tmp_path):
    """⚠ THE ACTUAL FAILURE: `tier` arrived and the collector URL, device id and
    token did not — because the tier was the ONE key the reader looked for."""
    env_file = tmp_path / "env"
    env_file.write_text(
        "# written by install.py\n"
        "export STING_COLLECTOR_URL='https://example.invalid/ingest'\n"
        "export STING_DEVICE_ID='dev-win11'\n"
        "export STING_DEVICE_TOKEN='a-token-with-no-colon'\n"
        "export STING_TIER='verdict_reason_location'\n"
        r"export STING_ROOTS='C:\Users\alice\one;C:\Users\alice\two'" + "\n",
        encoding="utf-8")

    values = shipper_config.read_env_file(env_file)

    assert values["STING_TIER"] == "verdict_reason_location"
    assert values["STING_COLLECTOR_URL"] == "https://example.invalid/ingest"
    assert values["STING_DEVICE_ID"] == "dev-win11"
    assert values["STING_DEVICE_TOKEN"] == "a-token-with-no-colon"
    assert values["STING_ROOTS"] == r"C:\Users\alice\one;C:\Users\alice\two"


def test_a_url_and_a_windows_path_survive_the_parser(tmp_path):
    """⚠ THE HYPOTHESIS THAT HAD TO BE DISCONFIRMED. The values that failed all
    contained a colon or a backslash, which looks exactly like a separator bug.
    The parser handles both fine; the reader simply never asked for them."""
    env_file = tmp_path / "env"
    env_file.write_text(
        "export STING_COLLECTOR_URL='https://host:8787/v1'\n"
        r"export STING_SESSION_ROOT='C:\Users\alice\.sting\sessions'" + "\n",
        encoding="utf-8")

    values = shipper_config.read_env_file(env_file)

    assert values["STING_COLLECTOR_URL"] == "https://host:8787/v1"
    assert values["STING_SESSION_ROOT"] == r"C:\Users\alice\.sting\sessions"


def test_the_shipper_is_configured_from_the_file_alone(tmp_path):
    """A shipper started with an EMPTY environment — which is what a hand-run
    `python -m shipper.run` on Windows has — must still be configured."""
    env_file = tmp_path / "env"
    env_file.write_text(
        "export STING_COLLECTOR_URL='https://example.invalid'\n"
        "export STING_DEVICE_ID='d'\n"
        "export STING_DEVICE_TOKEN='t'\n", encoding="utf-8")

    settings = shipper_config.from_env({"HOME": str(tmp_path)},
                                        env_file=env_file)

    assert settings.configured, settings.why_not_configured()
    assert settings.collector_url == "https://example.invalid"


def test_the_environment_still_outranks_the_file(tmp_path):
    """⚠ THE OTHER HALF. An operator who exports a variable is overriding
    deliberately and must not be outranked by a file written weeks ago."""
    env_file = tmp_path / "env"
    env_file.write_text("export STING_DEVICE_ID='from-the-file'\n",
                        encoding="utf-8")

    settings = shipper_config.from_env(
        {"HOME": str(tmp_path), "STING_DEVICE_ID": "from-the-shell"},
        env_file=env_file)

    assert settings.device_id == "from-the-shell"


def test_the_home_fallback_is_not_a_posix_default(monkeypatch, tmp_path):
    """⚠ `\\tmp\\.sting\\sessions` — a POSIX default with its separators
    flipped, on a drive nobody named. `HOME` does not exist on Windows."""
    settings = shipper_config.from_env(
        {"USERPROFILE": str(tmp_path)}, env_file=tmp_path / "nonexistent")

    # ⚠ THE DEFECT IS "THE ROOT DID NOT COME FROM USERPROFILE", AND THIS LINE
    # IS THE WHOLE ASSERTION. Once the root starts with the supplied
    # `USERPROFILE`, it cannot be the hardcoded `\tmp\.sting\sessions` this
    # test was written for — that path starts with `\tmp`, not with tmp_path.
    assert str(settings.log_root).startswith(str(tmp_path)), settings.log_root
    assert str(settings.log_root).endswith(os.path.join(".sting", "sessions"))

    # ⚠ THE SECOND ASSERTION USED TO BE `"/tmp" not in str(log_root)` AND IT
    # ADDED NOTHING ONCE THE LINE ABOVE HOLDS — it only ever restated it, and
    # it restated it as a SUBSTRING OF A PATH THIS TEST DOES NOT CONTROL.
    # pytest's own `tmp_path` on Linux IS `/tmp/pytest-of-runner/…`, so the
    # assertion failed on Ubuntu for a reason that has nothing to do with the
    # defect; on macOS `tmp_path` is `/private/var/folders/…`, which is why it
    # passed where it was written. A test that passes or fails on the shape of
    # the temp directory is measuring the runner, not the product.


def test_an_isolated_call_does_not_read_the_real_env_file(tmp_path):
    """⚠ AND THE MODULE-LEVEL `ENV_FILE` WAS EVALUATED AT IMPORT, so a caller
    supplying its own `env` reached into the developer's real home and read
    their real collector URL. Caught by the existing isolation test."""
    settings = shipper_config.from_env({"HOME": str(tmp_path)})

    assert settings.collector_url == ""
    assert not settings.configured


# ══════════ 4 · schtasks — the folder, and telling the truth about it

def test_the_root_task_name_needs_no_folder():
    assert "\\" not in service.root_task_name()
    assert service.root_task_name() == service.label()
    assert service.task_name().endswith(service.label())
    assert service.task_name().startswith("\\Sting\\")


def test_activate_tries_the_folder_then_the_root(monkeypatch, tmp_path):
    """⚠ THE FALLBACK IS A DIAGNOSTIC AS MUCH AS A FIX. Which one succeeds is
    the answer to a question this machine cannot ask: root-only means it was the
    task FOLDER (our choice, our fix); both failing means elevation or policy
    (the machine's)."""
    import platform

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(supervisor.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    monkeypatch.setattr(service, "loaded",
                        lambda: {"loaded": True, "detail": "ok", "pid": 1,
                                 "file": None})
    seen = []

    def fake_run(command, timeout=20):
        seen.append(" ".join(str(c) for c in command))
        # the FOLDER is refused, the root is accepted — the real Windows shape
        return (1, "ERROR: Access is denied.") if "\\Sting\\" in seen[-1] else (0, "")

    monkeypatch.setattr(service, "_run", fake_run)

    outcome = supervisor.activate()

    assert any("\\Sting\\" in c for c in seen), "it must try the folder first"
    assert any(c.endswith(service.label()) or service.root_task_name() in c
               for c in seen), "it must fall back to the root"
    detail = outcome["detail"]
    finding = detail if isinstance(detail, str) else " ".join(detail)
    assert "NOT A FAILURE, A FINDING" in finding, finding


def test_both_refused_names_it_as_elevation_or_policy(monkeypatch, tmp_path):
    """The other branch: if the root is refused too, it is NOT the folder."""
    import platform

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(supervisor.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    monkeypatch.setattr(service, "loaded",
                        lambda: {"loaded": False, "detail": "no task", "pid": None,
                                 "file": None})
    monkeypatch.setattr(service, "_run",
                        lambda *a, **k: (1, "ERROR: Access is denied."))

    outcome = supervisor.activate()

    assert outcome["ok"] is False
    detail = outcome["detail"] if isinstance(outcome["detail"], str) else str(outcome)
    assert "unelevated shell or a domain policy" in detail


def test_status_never_reads_a_written_file_as_a_running_service():
    """⚠ TASK 4.3, AND THE EXACT MISTAKE MADE ONCE ALREADY with
    `installed = bool(path.exists())`. A supervisor that is written and not
    running must never read as installed."""
    state = service.status()

    assert "installed" not in state, \
        "the key that meant 'a file exists' and was read as 'it is running'"
    assert "file_present" in state and "loaded" in state
