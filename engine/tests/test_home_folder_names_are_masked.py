"""The account name in a home folder is masked in what ships, unless the org
says send.

Item B of fix/more-masking-and-agent-status. Every record carries paths — its
`cwd`, the files a command names — and a path under a home folder carries the
account name, which is usually a person's: `/Users/<name>/`, `/home/<name>/`,
`C:\\Users\\<name>\\` (and `C:\\\\Users\\\\<name>\\\\` inside JSON). That segment
becomes `[user]`; a system folder (`/Users/Shared`, `C:\\Users\\Public`) stays,
and every other folder of the path is untouched.

⚠ SENT ONLY WHEN THE ORG SAYS EXACTLY SO. The cached org policy
(`core/org_policy`, fetched by the shipper's poll) must hold exactly
`"disclosure": {"folder_names": "send"}`. Absent, damaged, any other value or
shape: masked. The collector passes a damaged section through unchanged
(the collector), so this side decides.

Every name here is made up.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shipper import mask                                           # noqa: E402

NAME = "fakeperson"


@pytest.fixture
def disclosure():
    """Imported per test, so a missing module fails each test on its own line."""
    from shipper import disclosure as module
    return module


def _masked(text: str, known=mask.NO_SESSION) -> str:
    return mask.mask_text(text, known)[0]


@pytest.mark.parametrize("text, expected", [
    (f"/Users/{NAME}/proj/app", "/Users/[user]/proj/app"),
    (f"cd /Users/{NAME}", "cd /Users/[user]"),
    (f"/home/{NAME}/.bashrc", "/home/[user]/.bashrc"),
    (f'"cwd": "/Users/{NAME}/sting/sting-engine"',
     '"cwd": "/Users/[user]/sting/sting-engine"'),
    (f"file:///Users/{NAME}/notes.md", "file:///Users/[user]/notes.md"),
    (f"/mnt/c/Users/{NAME}/Downloads", "/mnt/c/Users/[user]/Downloads"),
    (f"/System/Volumes/Data/Users/{NAME}/x", "/System/Volumes/Data/Users/[user]/x"),
    (f"/var/home/{NAME}/x", "/var/home/[user]/x"),
    (f"/Volumes/Macintosh HD/Users/{NAME}/x", "/Volumes/Macintosh HD/Users/[user]/x"),
    (f"/Volumes/Backup/Users/{NAME}/x", "/Volumes/Backup/Users/[user]/x"),
    (f"ls ~{NAME}/src", "ls ~[user]/src"),
    ("C:\\Users\\Fake Person\\Documents\\a.txt", "C:\\Users\\[user]\\Documents\\a.txt"),
    (f"type C:\\Users\\{NAME}\\.env", "type C:\\Users\\[user]\\.env"),
    (f'{{"path": "C:\\\\Users\\\\{NAME}\\\\x"}}', '{"path": "C:\\\\Users\\\\[user]\\\\x"}'),
    (f"c:/users/{NAME}/x", "c:/users/[user]/x"),
    (f"cd C:\\Users\\{NAME} && dir", "cd C:\\Users\\[user] && dir"),
    (f"/Users/{NAME}/a /Users/{NAME}2/b", "/Users/[user]/a /Users/[user]/b"),
])
def test_the_account_name_in_a_home_folder_is_masked(text, expected):
    assert _masked(text) == expected


@pytest.mark.parametrize("text, expected", [
    (f"/Users//{NAME}/p", "/Users//[user]/p"),
    (f"/Users///{NAME}/p", "/Users///[user]/p"),
    (f"/Users/./{NAME}/p", "/Users/./[user]/p"),
    (f"/home//{NAME}/p", "/home//[user]/p"),
    (f"cat /Users//{NAME}/.ssh/id_rsa", "cat /Users//[user]/.ssh/id_rsa"),
    (f"C:\\Users\\\\{NAME}\\Desktop", "C:\\Users\\\\[user]\\Desktop"),
    (f"C:\\Users\\.\\{NAME}\\Desktop", "C:\\Users\\.\\[user]\\Desktop"),
    (f"C:\\Users\\\\\\\\{NAME}\\Desktop", "C:\\Users\\\\\\\\[user]\\Desktop"),
    (f"C:\\Users\\\\\\{NAME}\\x", "C:\\Users\\\\\\[user]\\x"),
    (f"/Home/{NAME}/proj", "/Home/[user]/proj"),
    (f"/HOME/{NAME}/proj", "/HOME/[user]/proj"),
    (f"/USERS/{NAME}/proj", "/USERS/[user]/proj"),
    ("/Users/Fake Person/x", "/Users/[user]/x"),
    ("cd /Users/Fake\\ Person", "cd /Users/[user]"),
    ("cd /Users/Fake\\ Person/x", "cd /Users/[user]/x"),
    ('cd "/Users/Fake Person"', 'cd "/Users/[user]"'),
    ('{"cwd": "/Users/Fake Person"}', '{"cwd": "/Users/[user]"}'),
    ('cd "/Users/Fake Person" && ls', 'cd "/Users/[user]" && ls'),
    ("bash -c 'ls \"/Users/Fake Person\"'", "bash -c 'ls \"/Users/[user]\"'"),
    ("C:\\Users\\Fake Person", "C:\\Users\\[user]"),
    ('{"cwd": "C:\\\\Users\\\\Fake Person"}', '{"cwd": "C:\\\\Users\\\\[user]"}'),
    ('cd "C:\\Users\\Fake Person" & dir', 'cd "C:\\Users\\[user]" & dir'),
    ("/home/fake person/x y", "/home/[user]/x y"),
])
def test_a_repeated_separator_or_a_spaced_name_still_masks_it(text, expected):
    """⚠ SECURITY REVIEW, HIGH: `/Users//<name>/` is the same file as
    `/Users/<name>/`, and a doubled separator matched no pattern, so the name
    shipped raw. MEDIUM: a name holding a space was masked up to it. Python
    review, HIGH: `/Home/<name>` and `/HOME/<name>` (a case-preserving file
    system, a path from Windows) shipped the name: only `users` ignored case.
    Python review, round two, HIGH: a spaced name that ENDS the path (`cd
    /Users/<first> <last>`, a quoted cwd) shipped every word after the first."""
    assert _masked(text) == expected


@pytest.mark.parametrize("kept", [
    "/Users/Shared/Adobe/x", "/Users/Guest/x", "C:\\Users\\Public\\Documents",
    "C:\\Users\\Default\\AppData", "/home/linuxbrew/.linuxbrew/bin/brew",
    "src/Users/Profile.tsx",                # a project folder named Users
    "app/models/home/index.ts",
    "/Users/$USER/x", "/home/${USER}/x", "C:\\Users\\%USERNAME%\\x",
    "~/projects/x", "git log HEAD~2/",
])
def test_system_folders_project_folders_and_variables_stay(kept):
    assert _masked(kept) == kept


@pytest.mark.parametrize("text, expected", [
    ("ls /Users/john -la", "ls /Users/[user] -la"),
    ("find /Users/bob -name x.txt", "find /Users/[user] -name x.txt"),
    ("open /Users/bob -a Finder", "open /Users/[user] -a Finder"),
    ("tar -cf out.tar /Users/bob docs", "tar -cf out.tar /Users/[user] docs"),
    ("chmod 755 /Users/bob script.sh", "chmod 755 /Users/[user] script.sh"),
    ("echo /Users/john and mary", "echo /Users/[user] and mary"),
    ("cd /Users/bob && ls", "cd /Users/[user] && ls"),
    ("dir C:\\Users\\bob -la", "dir C:\\Users\\[user] -la"),
    ("ls /Users/Shared docs", "ls /Users/Shared docs"),
    ("ls /Users/Shared -la", "ls /Users/Shared -la"),
    ("cat /Users/Guest notes.txt", "cat /Users/Guest notes.txt"),
    ("dir C:\\Users\\Public docs", "dir C:\\Users\\Public docs"),
])
def test_an_argument_after_the_name_is_not_the_name(text, expected):
    """Python review, round three, HIGH: a spaced name that ran to the next
    shell operator or the text's end took the arguments after it (`ls
    /Users/<name> -la` lost `-la`), and a system folder with one after it
    was masked. Outside quotes a space ends a path, as it does for the shell;
    a name keeps its spaces in quotes, escaped, or as the whole value."""
    assert _masked(text) == expected


@pytest.mark.parametrize("text, expected", [
    ('{"cwd": "/Users/Guest Info"}', '{"cwd": "/Users/[user]"}'),
    ('cd "/Users/Public Relations"', 'cd "/Users/[user]"'),
    ('{"cwd": "/Users/Default Something/x"}', '{"cwd": "/Users/[user]/x"}'),
    ('{"cwd": "C:\\\\Users\\\\Guest Info"}', '{"cwd": "C:\\\\Users\\\\[user]"}'),
    ('cd "C:\\Users\\Public Relations"', 'cd "C:\\Users\\[user]"'),
])
def test_a_name_that_starts_with_a_system_folders_word_is_a_name(text, expected):
    """Security review, round four, HIGH: a name whose FIRST word is a system
    folder's (`Guest Info`, `Public Relations`) was kept, whole, on the quoted
    and whole-value paths: a system folder is kept only when it is the name."""
    assert _masked(text) == expected


def test_a_record_masks_the_name_in_every_field():
    record = {"seq": 1, "cwd": f"/Users/{NAME}/sting/sting-engine",
              "command": f"cat /Users/{NAME}/sting/notes.md",
              "paths": [f"/Users/{NAME}/sting/notes.md"]}
    shipped = mask.mask_record(record)
    assert NAME not in json.dumps(shipped)
    assert shipped["cwd"] == "/Users/[user]/sting/sting-engine"
    assert shipped["masked"]["user"] == 3


# ═══════════════════════════════════════════════ what the org's policy says

@pytest.mark.parametrize("policy, sends", [
    ({"disclosure": {"folder_names": "send"}}, True),
    ({}, False),
    ({"disclosure": {"folder_names": "mask"}}, False),
    ({"disclosure": {"folder_names": "SEND"}}, False),
    ({"disclosure": {"folder_names": " send"}}, False),
    ({"disclosure": {"folder_names": "send", "extra": 1}}, False),
    ({"disclosure": {"folder_names": True}}, False),
    ({"disclosure": "send"}, False),
    ({"disclosure": {}}, False),
    ({"disclosure": None}, False),
    ({"disclosure": ["folder_names", "send"]}, False),
])
def test_names_are_sent_only_when_the_org_says_exactly_send(disclosure, policy, sends):
    assert disclosure.sends_folder_names(policy) is sends


def test_the_cached_policy_decides_and_a_damaged_cache_masks(disclosure, tmp_path, monkeypatch):
    cache = tmp_path / "org_policy.json"
    monkeypatch.setenv("STING_POLICY_CACHE", str(cache))
    assert disclosure.sends_folder_names() is False            # no cache
    cache.write_text(json.dumps({"version": 3, "sensitive_sources": [],
                                 "disclosure": {"folder_names": "send"}}))
    assert disclosure.sends_folder_names() is True
    cache.write_text("{not json")
    assert disclosure.sends_folder_names() is False


def test_when_the_org_sends_names_the_path_ships_as_written():
    known = mask.SessionValues(send_folder_names=True)
    text = f"cd /Users/{NAME}/proj && curl http://203.0.113.7/"
    assert _masked(text, known) == f"cd /Users/{NAME}/proj && curl http://[ip]/"


def test_the_shipper_reads_the_orgs_setting_for_every_session(tmp_path, monkeypatch):
    """Through the shipper's own path: the cached policy decides, per session,
    whenever it is read."""
    from shipper.config import Settings
    from shipper.run import Shipper

    cache = tmp_path / "org_policy.json"
    monkeypatch.setenv("STING_POLICY_CACHE", str(cache))
    (tmp_path / "logs").mkdir()
    settings = Settings(collector_url="https://collector.invalid", device_id="d",
                        device_token="t", log_root=tmp_path / "logs",
                        state_root=tmp_path / "state")
    shipper = Shipper(settings, now=lambda: 1000.0, log=lambda line: None)
    assert shipper._session_values("s1").send_folder_names is False
    cache.write_text(json.dumps({"version": 2, "sensitive_sources": [],
                                 "disclosure": {"folder_names": "send"}}))
    assert shipper._session_values("s1").send_folder_names is True
    cache.write_text(json.dumps({"version": 3, "sensitive_sources": [],
                                 "disclosure": {"folder_names": "Send"}}))
    assert shipper._session_values("s1").send_folder_names is False
