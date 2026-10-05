"""Settings. Outbound only — there is no listen address here to configure.

⚠ WHAT THIS FILE DOES NOT CONTAIN IS THE POINT. No bind host, no port, no
socket options. The shipper opens connections and never accepts them, so there
is nothing on the developer's machine for anyone to reach.
`tests/test_shipper_is_outbound_only.py` asserts that on the source.
"""
from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from shipper import fingerprint_key as _key_file
from shipper import sparta_iface as _sparta

# ⚠ HTTPS, OR PLAIN HTTP THAT NEVER LEAVES THE MACHINE (item E, docs/98). The
# collector URL carries the enrolment secret once and the device token and every
# batch after it, so a cleartext scheme to anywhere else is refused. Loopback is
# kept because this repo's own shipper tests drive a real collector on
# `http://127.0.0.1:<port>`, and a loopback socket cannot be sniffed off a
# network. The NAMES are exact: `127.0.0.2` or `localhost.example.com` is refused.
# `installer/enrol.py` carries a standalone mirror of this rule (the collector's
# contract test loads that file by path), pinned equal by
# tests/test_collector_url_must_be_https.py.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def collector_url_refusal(url: str | None) -> str | None:
    """None when `url` may carry a device token; otherwise why not.

    ⚠ The reason never repeats the URL: a URL can carry userinfo."""
    try:
        parts = urllib.parse.urlsplit(url or "")
        host = (parts.hostname or "").lower()
    except ValueError:
        return "the collector URL cannot be parsed; it must be an https:// URL"
    scheme = parts.scheme.lower()
    if scheme == "https" and host:
        return None
    if scheme == "http" and host in LOOPBACK_HOSTS:
        return None
    return (f"the collector URL must be https:// (this one is "
            f"{scheme + '://' if scheme else 'missing a scheme'}{'' if host else ' with no host'}) — "
            f"anything else would send the enrolment secret, the device token "
            f"and every batch in cleartext")

# ⚠ THE BATCHING CHOICE, AND THE NUMBER IT IS DERIVED FROM.
#
# Measured on real sessions: ~145 actions per ACTIVE hour. One POST per action
# would be ~145 requests/hour of TLS handshake and HTTP overhead to move a few
# hundred bytes each — wasteful for the sender and noisy for the collector.
#
# WHICHEVER COMES FIRST:
#   300 s since the last flush   the trigger that actually fires in practice
#   200 pending records          a backstop for a burst, ~83 minutes at 145/hr
#
# At 145 actions/hour that is ~12 records per batch and 12 requests/hour while
# working — roughly 96 requests over an 8-hour day, against ~1160 actions.
#
# ⚠ WORST-CASE DELAY BETWEEN AN ACTION HAPPENING AND IT REACHING A COLLECTOR:
# 180 s (the interval) + 5 s (poll granularity) + the POST itself, so ~3 minutes
# and change. An action recorded one second after a flush waits the full
# interval. That is the cost of not POSTing per action, and it is acceptable
# because this is evidence collection and not real-time alerting — nothing
# downstream blocks on a batch arriving.
# ⚠ 180, NOT 300, AND WHAT THAT NUMBER IS *NOT* WIRED INTO WAS ESTABLISHED
# BEFORE IT MOVED. Three things read an interval in this system and only one of
# them is this constant:
#
#   FLUSH_SECONDS       this. When a BATCH goes. Local only — nothing on the
#                       wire carries it, and no receiver knows it.
#   HEARTBEAT_SECONDS   900, below. DECLARED on the wire as `interval_seconds`,
#                       and the collector's `collector/heartbeat.py` computes
#                       staleness as 3x whatever the device declares.
#   the collector's     3x the DECLARED interval, so 2700 s. Untouched by this.
#   threshold
#
# ⚠ SO A DEVICE THAT DECLARES ONE THING AND DOES ANOTHER WOULD LOOK BROKEN, and
# this change cannot cause that: the heartbeat still declares 900 and still
# sends every 900. The collector is told the truth before and after. (Its own
# README still says "the sender does not declare an interval today" — that
# stopped being true when `interval_seconds` was added, and it is the
# collector's line to correct.)
#
# ⚠ THE COST, AND IT IS NOT 1.67x ANYTHING, because an empty flush never POSTs:
# `should_flush` returns False on `pending <= 0`. The request count is set by
# ACTIVITY, not by the interval — at 145 actions/hour the same ~1160 daily
# actions go out in ~20 batches of ~7 instead of ~12 batches of ~12. More
# requests, the same records, and the ceiling is the busy case: 8 hours of
# continuous work is 160 flushes/day against 96.
#
# Against the collector's limiter — 60 requests and 20,000 records per MINUTE
# per device — 180 s is 0.33 requests/min. That is ~180x under the cap, and the
# cap's own comment sizes its headroom against a week-long backlog burst rather
# than the steady rate. Nothing objects.
#
# ⚠ AND ON BATTERY IT IS A WAKE EVERY 180 s, WHICH IS A REAL COST AND IS WHY
# THE POLL IS NOT THE FLUSH. The loop already wakes every POLL_SECONDS to read
# the log; the flush is a decision made on a wake that was happening anyway, so
# 300 -> 180 adds no wake-ups on macOS or Linux. On WINDOWS the supervisor
# deliberately turns off `DisallowStartIfOnBatteries` and
# `StopIfGoingOnBatteries` — a guard that stops guarding when unplugged is not
# one — so the process stays resident there too and this is again a decision,
# not a wake.
#
# What DOES change on battery is the radio: ~20 short POSTs a day instead of
# ~12, on a machine already talking to a dozen services. That is the honest
# statement, and it is why this is 180 and not 60 — at 60 the request count
# starts to be visible in a battery report, and the delay it buys (2 minutes
# saved) is not worth it for evidence collection that nothing blocks on.
FLUSH_SECONDS = 180
FLUSH_RECORDS = 200

# A single POST is capped so a large backlog — a laptop that was offline for a
# day — is split rather than sent as one enormous body the collector will refuse.
MAX_BATCH_RECORDS = 1000

# ⚠ HOW MANY CAPPED BATCHES ONE URGENT FLUSH MAY SEND BEFORE IT STOPS.
#
# A deny is flushed "up to and including it", and with a 1000-record cap that
# can take more than one POST — a laptop back from a day offline is exactly when
# a backlog is deep AND a deny matters most. Without a bound, one tick could try
# to empty a 200,000-record backlog in a single burst against a collector that
# has only just come back up.
#
# 20 rounds is 20,000 records, ~7x the largest real backlog observed here (2,928
# records across ten sessions). Past it the periodic flush drains the rest on
# its own schedule: the deny is late in that case, and a bounded burst is the
# price of not turning a recovery into a stampede.
MAX_URGENT_ROUNDS = 20

POLL_SECONDS = 5

# Exponential, capped. A collector that is down for an hour must not be probed
# 720 times, and a collector that comes back must be noticed within minutes.
BACKOFF_START = 5
BACKOFF_CAP = 300

# ⚠ A LONGER BACKOFF FOR 401 THAN FOR "UNREACHABLE", DELIBERATELY. An
# unreachable collector is usually transient — a closed lid, a train tunnel. A
# 401 is a configuration error that will not fix itself, and hammering it turns
# one wrong token into a stream of failed auth attempts in someone's logs.
BACKOFF_UNAUTHORISED = 600

HEARTBEAT_SECONDS = 900

# How often the shipper polls the collector for its org's policy. Matched to the
# heartbeat cadence — one out-of-band collector round-trip on the same clock — and
# cheap on the wire because the poll sends `?since=<cached version>` and the
# collector answers `unchanged` when nothing moved. A change takes at most this
# long to reach the machine; step 2 is plumbing, so 15 min is the sensible floor
# and `STING_POLICY_SECONDS` tunes it.
POLICY_SECONDS = 900


# ⚠ WHAT THIS MACHINE AGREED TO SEND LIVES IN A FILE, AND ONLY THERE.
#
# `install.py` writes `~/.sting/env`, and it writes `STING_SHIPS='masked'` into it
# only after printing what ships: every record, whole, with every value Sting
# recognises replaced by its type. That line is the agreement; nothing else is.
# A shell `export` is not one — it is how a process once shipped every command
# verbatim while the file said otherwise (the first real end-to-end run) — so
# the agreement is read from the file and never from the environment.
#
# ⚠ AND A MACHINE THAT AGREED TO LESS SENDS NOTHING NEW UNTIL IT AGREES AGAIN.
# Every install before 28 Sep 2026 recorded a TIER, and three of the four sent
# no command text at all. Such a file has no `STING_SHIPS`, so the shipper holds
# every record on disk — nothing lost, nothing pruned — and says once that
# re-running install.py resumes shipping. A `full` machine is held the same way:
# masked sends it less, and the reinstall is still where a person sees it.
HELD = "held"
"""What a machine without the agreement ships: nothing, until install.py."""

ENV_FILE = Path.home() / ".sting" / "env"


def read_env_file(path: Path | None = None) -> dict:
    r"""Every `export KEY='value'` in the file install.py wrote.

    ⚠ THIS USED TO RETURN THE TIER AND NOTHING ELSE, AND THAT IS THE WHOLE OF
    FAILURE 3 ON THE FIRST NATIVE WINDOWS INSTALL:

        sting shipper -> (unset)
          device   (unset)
          tier     verdict_reason_location   <- C:\Users\...\.sting\env

    The tier arrived because the tier was the ONE key this function looked for.
    The collector URL, the device id and the token did not arrive because
    nothing ever read them from the file — they came from `os.environ` alone.

    ⚠ WHICH IS FINE ON POSIX AND FATAL ON WINDOWS. The launchd plist and the
    systemd unit both carry the variables, and a developer running the shipper
    by hand does `source ~/.sting/env` first. On Windows the variables live in
    the scheduled task's wrapper `.cmd`, and **the task did not register**
    (failure 4) — so nothing had ever injected them, and `export KEY=value` is
    not something PowerShell can source.

    ⚠ THE TEMPTING WRONG DIAGNOSIS, RULED OUT BY READING THE FILE FIRST: the
    value that arrived has no colon and no backslash, and the three that did not
    are `https://…`, `C:\Users\…` and a token. That looks exactly like a
    separator bug and it is not one. The file was written correctly and parsed
    correctly; only one key was ever asked for. Two failures that looked like
    one root cause were two.

    Parsed rather than sourced: this must not execute a shell.
    """
    path = ENV_FILE if path is None else path
    values: dict = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, sep, value = line.partition("=")
        if not sep:
            continue
        # ⚠ STRIPPED ONCE, FROM THE OUTSIDE ONLY. `_quote` in install.py wraps
        # the whole value in single quotes and escapes any interior ones, so a
        # Windows path keeps its backslashes and a URL keeps its colons.
        values[key.strip()] = value.strip().strip("'\"")
    return values


@dataclass(frozen=True)
class Settings:
    collector_url: str = ""
    device_token: str = ""
    device_id: str = ""
    # ⚠ THE AGREEMENT, FROM THE FILE: `STING_SHIPS` as install.py wrote it.
    # `wire.MASKED` ships; anything else, or nothing, holds. See `HELD`.
    ships: str = ""
    settings_path: str = ""
    # ⚠ `STING_TIER` IS READ ONLY TO BE NAMED. Nothing sends by it any more;
    # a machine that still carries one is told so, once, where it looks.
    ignored_tier: str = ""
    ignored_tier_env: str = ""
    log_root: Path = Path()
    state_root: Path = Path()
    flush_seconds: int = FLUSH_SECONDS
    flush_records: int = FLUSH_RECORDS
    heartbeat_seconds: int = HEARTBEAT_SECONDS
    policy_seconds: int = POLICY_SECONDS
    timeout_seconds: float = 30.0
    # ⚠ OPT-IN, DEFAULT OFF. Layer B (person names, through an NER model) pulls a
    # heavier dependency that the default 'pure stdlib, no pip' install must
    # never require, so it is off unless a customer explicitly enables it. Every
    # other mask, emails included, is unconditional and needs no flag.
    redact_pii: bool = False
    # ⚠ THE KEY THE SHIPPED FINGERPRINTS ARE KEYED WITH (`fingerprint_key`):
    # `~/.sting/.env.fingerprint` of the home this runs as. Never its value.
    fingerprint_key_path: Path = field(
        default_factory=lambda: _key_file.path_under(Path.home()))
    # ⚠ OPT-IN, DEFAULT OFF: Sparta's enrichment (shipper/sparta_iface.py),
    # `STING_SPARTA` and `STING_SPARTA_TAINT` as written. Kept raw; only
    # `sparta_iface` decides what turns them on ("1", and nothing else).
    sparta: str = ""
    sparta_taint: str = ""

    @property
    def sparta_flags(self) -> dict:
        """The two Sparta flags as `sparta_iface` reads them."""
        return {_sparta.FLAG: self.sparta, _sparta.TAINT_FLAG: self.sparta_taint}

    @property
    def configured(self) -> bool:
        return bool(self.collector_url and self.device_token and self.device_id)

    def why_not_configured(self) -> str:
        missing = [name for name, value in (
            ("STING_COLLECTOR_URL", self.collector_url),
            ("STING_DEVICE_TOKEN", self.device_token),
            ("STING_DEVICE_ID", self.device_id)) if not value]
        return ", ".join(missing)

    def what_ships(self) -> dict:
        """What this machine sends, where that was agreed, and what is ignored.

        ⚠ THE ONE RULE: NEVER SEND MORE THAN THE MACHINE AGREED TO WITHOUT A
        PERSON RE-RUNNING install.py AND SEEING WHAT SHIPS. The agreement is
        `STING_SHIPS='masked'` in the file install.py wrote, which it writes
        only after printing the disclosure. A machine installed before that —
        whatever its `STING_TIER` said, `full` included — ships nothing new:
        every record stays on disk, and the reinstall resumes shipping."""
        from core import wire                              # local: see module

        agreed = self.ships == wire.MASKED
        where = self.settings_path or "~/.sting/env"
        key = _key_file.state(self.fingerprint_key_path)
        held = _key_file.why_held(self.fingerprint_key_path)
        if agreed and held:
            # ⚠ NEVER RAW, NEVER A NEW KEY OVER AN OLD ONE (`fingerprint_key`):
            # the shipper holds every record instead, and this says so.
            detail = (f"the fingerprint key {self.fingerprint_key_path} {held}. "
                      f"Records stay on disk until then")
        elif agreed:
            detail = (f"masked records: every record whole, every value Sting "
                      f"recognises replaced by its type (agreed in {where})")
        elif self.ships:
            detail = (f"{where} records STING_SHIPS={self.ships!r}, which this "
                      f"version does not send; re-run install.py to see what "
                      f"ships and resume")
        else:
            detail = (f"{where} records no agreement to what this version sends "
                      f"(every record whole, every value Sting recognises "
                      f"replaced by its type); re-run install.py to see it and "
                      f"resume shipping")
        ignored = [{"setting": "STING_TIER", "value": value, "where": place}
                   for value, place in ((self.ignored_tier, where),
                                        (self.ignored_tier_env,
                                         "this process's environment"))
                   if value]
        ships = wire.MASKED if agreed and not held else HELD
        return {"ships": ships, "agreed": agreed,
                "agreed_path": self.settings_path or None, "detail": detail,
                "ignored": ignored, "fingerprint_key": key}


def _home(env) -> Path:
    r"""The user's home, on every platform.

    ⚠ `HOME` DOES NOT EXIST ON WINDOWS, and the fallback was `/tmp`. Measured on
    the first native Windows install, the shipper reported:

        logs     \tmp\.sting\sessions

    which is a POSIX default with its separators flipped by `Path` — a directory
    that does not exist, on a drive nobody named. `Path.home()` consults
    `USERPROFILE` there and `HOME` on POSIX, which is the whole fix; `HOME` is
    still honoured first so a test or a sandbox can still redirect it.
    """
    named = env.get("HOME") or env.get("USERPROFILE")
    return Path(named) if named else Path.home()


def settings_file(env=None) -> Path:
    """The file `from_env` reads: `~/.sting/env` under this user's home, found
    through the environment passed (see `from_env`)."""
    return _home(os.environ if env is None else env) / ".sting" / "env"


_NUMBERS = (("STING_SHIP_INTERVAL", FLUSH_SECONDS), ("STING_SHIP_RECORDS", FLUSH_RECORDS),
            ("STING_HEARTBEAT_INTERVAL", HEARTBEAT_SECONDS),
            ("STING_POLICY_SECONDS", POLICY_SECONDS))
"""The settings `from_env` reads as whole numbers, and their defaults."""


def _whole_number(raw: str) -> bool:
    """Would `from_env` read `raw` as a number (as `int()` does)?"""
    try:
        int(raw)
    except ValueError:
        return False
    return True


def setting_problems(env=None, env_file: Path | None = None) -> list[dict]:
    """Every numeric setting `from_env` would refuse, as
    `{"setting", "value", "where"}` — `where` the environment or the file.

    ⚠ `from_env` RAISES ON THE FIRST, AND THE SHIPPER STOPS THERE: it does not
    guess what `5m` meant. This names every one, so `install.py --status` can
    say what is wrong and carry on (#76's open list). Read before anything
    loads the file into the environment, or a file's value reads as the
    environment's."""
    env = os.environ if env is None else env
    path = env_file if env_file is not None else settings_file(env)
    from_file = read_env_file(path)
    problems = []
    for name, _default in _NUMBERS:
        in_env = (env.get(name) or "").strip()
        raw = in_env or (from_file.get(name) or "").strip()
        if raw and not _whole_number(raw):
            problems.append({"setting": name, "value": raw,
                             "where": "the environment" if in_env else str(path)})
    return problems


def from_env(env=None, env_file: Path | None = None, *, strict: bool = True) -> Settings:
    """The shipper's settings. ⚠ `strict` (the shipper's own read) refuses a
    malformed number with `ValueError`; a status read passes `strict=False`
    and gets the default in its place, having named it (`setting_problems`)."""
    env = os.environ if env is None else env
    home = _home(env)
    # ⚠ THE FILE IS FOUND VIA THE PASSED ENVIRONMENT, NOT VIA MODULE-LEVEL
    # `ENV_FILE`. That constant is `Path.home()/".sting"/"env"` evaluated at
    # IMPORT, so a caller supplying its own `env` — a test, a sandbox, the
    # daemon — would have reached into the developer's real home and read their
    # real collector URL. Caught by
    # `test_the_collector_url_and_token_are_settings_not_constants`, which
    # passes `{"HOME": "/tmp"}` and requires an empty result.
    #
    # ⚠ AND THE FILE IS A FALLBACK; THE ENVIRONMENT WINS — for every setting but
    # one. An operator who exports a variable is making a deliberate override
    # and must not be silently outranked by a file written weeks ago. The one
    # exception is what may leave the machine: `STING_SHIPS` is read from the
    # file alone, because an export is not an agreement (see `HELD`).
    path = env_file if env_file is not None else settings_file(env)
    from_file = read_env_file(path)

    def setting(name: str) -> str:
        return ((env.get(name) or from_file.get(name) or "")).strip()

    def number(name: str, default: int) -> int:
        raw = setting(name)
        if not raw:
            return default
        if strict or _whole_number(raw):
            return int(raw)
        return default
    session_root = setting("STING_SESSION_ROOT")
    return Settings(
        # ⚠ FROM THE FILE ONLY — never `setting()`, which lets the environment
        # win. An export is not an agreement; see `HELD`.
        ships=(from_file.get("STING_SHIPS") or "").strip(),
        settings_path=str(path),
        ignored_tier=(from_file.get("STING_TIER") or "").strip(),
        ignored_tier_env=(env.get("STING_TIER") or "").strip(),
        collector_url=setting("STING_COLLECTOR_URL").rstrip("/"),
        device_token=setting("STING_DEVICE_TOKEN"),
        device_id=setting("STING_DEVICE_ID"),
        log_root=Path(session_root).expanduser() if session_root
                  else home / ".sting" / "sessions",
        state_root=Path(setting("STING_SHIPPER_STATE")
                         or home / ".sting" / "shipper").expanduser(),
        flush_seconds=number("STING_SHIP_INTERVAL", FLUSH_SECONDS),
        flush_records=number("STING_SHIP_RECORDS", FLUSH_RECORDS),
        heartbeat_seconds=number("STING_HEARTBEAT_INTERVAL", HEARTBEAT_SECONDS),
        policy_seconds=number("STING_POLICY_SECONDS", POLICY_SECONDS),
        redact_pii=setting("STING_REDACT_PII").lower() in ("1", "true", "yes", "on"),
        fingerprint_key_path=_key_file.path_under(home),
        sparta=setting(_sparta.FLAG),
        sparta_taint=setting(_sparta.TAINT_FLAG),
    )
