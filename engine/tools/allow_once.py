#!/usr/bin/env python3
"""
Approve one refused action, once — the way out that every refusal names.

    python3 tools/allow_once.py                  # the most recent refusal
    python3 tools/allow_once.py --list           # what could be approved
    python3 tools/allow_once.py --seq 7          # an earlier one, by step
    python3 tools/allow_once.py --revoke         # disarm without spending it

Exit codes:
    0   a grant was armed, or a list was printed, or a grant was revoked
    1   there is a refusal and it could not be approved
    2   there is no refusal to approve, or nothing is armed to revoke

⚠ WHY THIS FILE EXISTS AT ALL. `adapters/_common.with_location` has ended every
DENY, in all five adapters, with "or allow this one action once: python3
tools/allow_once.py" — naming a file that did not exist, in the checkout or in
the installed tree. Enforce mode plus a false positive plus a way out that
errors is how a guard gets uninstalled. `core/allow_once.py` had the whole
mechanism; only the hand-hold was missing, and the VS Code extension was the
sole way to reach it.

⚠ IT COMPUTES NOTHING. `action_hash` is copied verbatim out of the log record
the engine wrote, for the same reason `extension/src/allowOnce.ts` copies it:
re-deriving "the same action" here would be a second implementation of a
decision the engine already made, and it would be WRONG — the record's
`command` is clipped, so an action rebuilt from a record is not the action that
was judged. A test bans hashing in this file outright.

⚠ WHAT IT IS NOT. This is not an authorisation boundary, and nothing local can
be one. `core/allow_once.py` says it plainly: this process runs with the
developer's privileges, which are also the agent's, so a compromised agent can
arm its own grant. Refusing to arm unattended stops an approval being written
when NOBODY WAS ASKED; it does not stop a caller that passes `--yes`. Closing
that needs a signature over a key the agent cannot reach.

⚠ THE REFUSAL AND THE OVERRIDE BOTH STAY IN THE LOG. The engine's DENY is
already chained; spending this grant appends an `allow_once_used` record at the
same step, naming the rule that was overruled and `granted_by: cli`. The log
shows what the policy decided AND that a human overruled it — never just the
outcome.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.allow_once import (DEFAULT_TTL, grant_path,  # noqa: E402
                             write_grant)
from core.audit_log import LOG_SUFFIX, read_records                     # noqa: E402
from core.display import visible                                         # noqa: E402
from core.session import default_root                                   # noqa: E402

GRANTED_BY = "cli"
"""⚠ A CONSTANT, NOT THE OPERATING SYSTEM USER.

`granted_by` is inside the record and ships to the collector with it
(docs/70). A username there would be an identity leak on the wire — the exact
class the 9 Aug publication audit found twice. `extension/src/allowOnce.ts`
writes the constant `vscode-extension` for the same reason; this writes `cli`.
WHICH human is not knowable here anyway: the shell's user is the machine's
owner, not necessarily the person who read the refusal.
"""

NOTHING_TO_GRANT = "no refusal to approve"

_DISPLAY_WIDTH = 240
"""How much of a command is shown before the confirmation.

The record already clips at 16 KB; this is a second, much tighter clip for a
terminal. It is display only — the grant is bound to the hash the engine
recorded, never to the text printed here.
"""


def logs_under(root: Path) -> list[Path]:
    """Every session log, newest activity first.

    ⚠ DISCOVERED, NOT CONSTRUCTED, for the reason the extension lists the
    directory instead of hashing an id: reproducing `safe_session_id()` here
    would be one more place that has to agree with the engine about what a
    session is called.

    ⚠ STING_LOG OVERRIDES OUTRIGHT, which is `default_log_path`'s own
    precedence. A harness that names the log file itself (the corpus runner
    writes `logs/observe/<scenario>.log`) puts it somewhere this glob would
    never look, and silently listing nothing for exactly the runs a developer
    is debugging is the failure `tools/verify_log.py` already had once.
    """
    override = os.environ.get("STING_LOG")
    if override:
        path = Path(override).expanduser()
        return [path] if path.is_file() else []
    if not root.is_dir():
        return []
    return sorted((p for p in root.glob(f"*{LOG_SUFFIX}") if p.is_file()),
                   key=lambda p: p.stat().st_mtime, reverse=True)


def refusals(log: Path) -> list[dict]:
    """The DENY records, oldest first.

    `allow_once_used` is excluded on purpose — it is an ALLOW, and it is the
    record of an override that already happened. Offering to approve one would
    invite a developer to re-approve something that already went through.
    """
    return [r for r in read_records(log)
            if r.get("event") == "decision" and r.get("decision") == "DENY"]


def _clip(text, limit: int = _DISPLAY_WIDTH) -> str:
    """One line of a record's text, as the person approving it reads it: every
    bidi, zero-width or control character visible (item C, docs/110 §C), so the
    action shown is the action approved."""
    if not isinstance(text, str):
        return ""
    text = visible(text)
    return text if len(text) <= limit else text[:limit] + " …"


def _when(record: dict) -> str:
    ts = record.get("ts")
    if not isinstance(ts, (int, float)):
        return "unknown time"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def describe(record: dict, log: Path) -> str:
    """One line, for `--list`.

    ⚠ `evidence` IS DELIBERATELY NOT SHOWN. It is a ±60-character window of the
    raw command and is credential-shaped about 8% of the time — which is why the
    refusal the developer already read renders only its OFFSET. A convenience
    listing is not a reason to print a raw window of the command.
    """
    return (f"  step {str(record.get('seq')):>4}  {_when(record)}  "
            f"{record.get('rule_id') or 'no rule'}\n"
            f"            {record.get('kind') or '?'}  "
            f"{_clip(record.get('command') or ' '.join(record.get('paths') or []) or record.get('url') or '(no command)', 120)}")


def _confirm(prompt: str, assume_yes: bool, isatty: bool, readline) -> bool:
    """Did a human say yes?

    ⚠ ENTER HAS NO DEFAULT, and that is measured rather than stylistic.
    `tools/label_prompts.py` recorded eight accidental labels in a row because
    the reflex key was bound to a non-obvious answer. The reflex here is Enter,
    and the thing on the other side of it is a security override.

    ⚠ NOT A TERMINAL MEANS NOBODY WAS ASKED. Piped input is not consent: it is
    whatever the calling process happened to write. `--yes` is how a script says
    yes, and it says so on the record.
    """
    if assume_yes:
        return True
    if not isatty:
        return False
    sys.stderr.write(f"{prompt} [y/N] ")
    sys.stderr.flush()
    return readline().strip().lower() in ("y", "yes")


def _pick(records: list[dict], seq) -> tuple[dict | None, str]:
    """The refusal to approve, or why there is none."""
    if seq is None:
        return records[-1], ""
    for record in records:
        if record.get("seq") == seq:
            return record, ""
    return None, (f"step {seq} is not a refusal in this session. "
                  f"Run --list to see what is.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true",
                    help="show the refusals that could be approved, and arm nothing")
    ap.add_argument("--seq", type=int, default=None,
                    help="approve the refusal at this step instead of the last one")
    ap.add_argument("--session", default=None,
                    help="a session id, when more than one is active")
    ap.add_argument("--root", type=Path, default=None,
                    help="the session directory (default: $STING_SESSION_ROOT)")
    ap.add_argument("--ttl", type=float, default=DEFAULT_TTL,
                    help=f"seconds before the grant expires (default {DEFAULT_TTL:g})")
    ap.add_argument("--yes", action="store_true",
                    help="arm it without asking — for scripts, and recorded as cli")
    ap.add_argument("--revoke", action="store_true",
                    help="disarm an outstanding grant without spending it")
    args = ap.parse_args(argv)

    root = args.root or default_root()
    logs = logs_under(root)
    if args.session:
        logs = [p for p in logs if p.name.startswith(args.session)]
    if not logs:
        print(f"{NOTHING_TO_GRANT}: no session log under {root}.\n"
              f"If the guard is installed elsewhere, point --root at its "
              f"session directory.", file=sys.stderr)
        return 2

    log = logs[0]
    records = refusals(log)
    session_id = _session_id_of(log, records)

    if args.revoke:
        return _revoke(session_id, args.root)

    if not records:
        print(f"{NOTHING_TO_GRANT}: {log.name} holds no refusal.",
              file=sys.stderr)
        return 2

    if args.list:
        print(f"refusals in {log.name}:")
        for record in records:
            print(describe(record, log))
        print(f"\napprove the last one with:  python3 {_self()} --yes\n"
              f"or an earlier one with:     python3 {_self()} --seq <step> --yes")
        return 0

    record, why_not = _pick(records, args.seq)
    if record is None:
        print(why_not, file=sys.stderr)
        return 1

    action_hash = record.get("action_hash")
    if not isinstance(action_hash, str) or not action_hash:
        # ⚠ NEVER GUESSED, for the reason the extension refuses the same case:
        # a grant armed against a hash we invented matches nothing the engine
        # will ever compute, so it would sit on disk looking like permission
        # and quietly do nothing. Older engines did not write the field.
        print("this refusal carries no action_hash, so it cannot be approved — "
              "it was recorded by an engine older than the field.",
              file=sys.stderr)
        return 1

    print(f"Sting refused this action:\n\n"
          f"  session  {session_id}\n"
          f"  step     {record.get('seq')}   ({_when(record)})\n"
          f"  rule     {record.get('rule_id') or 'no rule'}\n"
          f"  why      {_clip(record.get('reason'))}\n"
          f"  action   {record.get('kind') or '?'}  "
          f"{_clip(record.get('command') or ' '.join(record.get('paths') or []) or record.get('url') or '(no command)')}\n")
    print(f"Approving arms a grant for THIS action only. It expires in "
          f"{args.ttl:g}s, is spent by the first matching attempt, and both the "
          f"refusal and the override stay in the log.\n")

    if not _confirm("Allow this one action once?", args.yes,
                     sys.stdin.isatty(), sys.stdin.readline):
        print("not approved; nothing was armed. Pass --yes to approve without "
              "being asked.", file=sys.stderr)
        return 1

    grant = write_grant(session_id, action_hash,
                         denied_at_seq=record.get("seq"),
                         rule_id=record.get("rule_id"),
                         reason=record.get("reason"),
                         ttl=args.ttl, granted_by=GRANTED_BY,
                         root=args.root)
    print(f"armed until {time.strftime('%H:%M:%S', time.localtime(grant['expires_at']))}. "
          f"Retry the action in your agent — the next matching attempt is "
          f"allowed once, and only that one.")
    return 0


def _session_id_of(log: Path, records: list[dict]) -> str:
    """The id the engine itself wrote, falling back to the file's own name.

    ⚠ THE RECORD IS PREFERRED BECAUSE STING_LOG BREAKS THE FILENAME. When a
    harness names the log, the stem is a scenario name and not a session id, so
    a grant written from the stem would land in a file `consume()` never opens.
    Every record carries the id `safe_session_id()` produced, which is exactly
    what `grant_path` will ask for.
    """
    for record in records or []:
        sid = record.get("session_id")
        if isinstance(sid, str) and sid:
            return sid
    return log.name[:-len(LOG_SUFFIX)] if log.name.endswith(LOG_SUFFIX) else log.stem


def _revoke(session_id: str, root: Path | None) -> int:
    """Take back an approval that has not been spent.

    Unlinked rather than emptied: `consume()` truncates under its own lock
    because a Windows unlink can fail while an fd is open, but nothing here
    holds the file open, so removing it is both sufficient and tidier.
    """
    path = grant_path(session_id, root)
    try:
        path.unlink()
    except OSError:
        print(f"nothing is armed for {session_id}.", file=sys.stderr)
        return 2
    print(f"revoked. The refusal for {session_id} stands.")
    return 0


def _self() -> str:
    """How to name this script back to the developer.

    The absolute path, because the developer is standing in their own project
    and not in the sting tree — which is the whole defect this file closes.
    """
    return str(Path(__file__).resolve())


if __name__ == "__main__":
    sys.exit(main())
