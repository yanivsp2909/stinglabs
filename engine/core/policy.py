"""Turning ONE rule down without turning the guard off.

⚠ WHY THIS SHIPS IN THE SAME PASS AS ENFORCE, AND IS NOT OPTIONAL. The rehearsal
measured ~28 stops a day catching zero attacks. Enforce mode without a way to
relax a single rule is a product a customer uninstalls on day two, and the only
thing standing between those two outcomes is being able to turn one rule down
without turning the guard off. Shipping enforce alone would be shipping the
first half of a decision.

────────────────────────────────────────────────────────────────────────────────
⚠ IT RELAXES AND IT CANNOT TIGHTEN, AND THAT ASYMMETRY IS DELIBERATE
────────────────────────────────────────────────────────────────────────────────

    DENY -> ASK      allowed
    DENY -> ALLOW    allowed
    ASK  -> ALLOW    allowed
    anything -> DENY REFUSED, silently ignored, and reported

A file that could make a machine refuse MORE than the policy says is a file
nobody would think to look in when a developer is blocked by a rule that is not
in the corpus. Every direction here makes the guard weaker, which means the
overlay can never be the reason something was stopped — only ever the reason
something was not. That is the property that makes it safe to read on the hot
path without a second look.

────────────────────────────────────────────────────────────────────────────────
⚠ WHERE IT LIVES, AND WHY THAT PLACE AND NOT THE REPO
────────────────────────────────────────────────────────────────────────────────

    ~/.sting/policy.json          0600, beside ~/.sting/env

**NOT in the repository, and this is the whole of TASK 2.2.** A settings file
inside the project is a file the agent edits all day — so "turn this rule off"
becomes something an attacker's session can do by writing a config, and the
guard's own relaxation becomes the exfiltration path. `core/engine.py` already
treats `.claude/settings.json` and friends as security-critical for exactly this
reason: an agent writing its own guard's configuration is the shape the product
exists to catch.

`~/.sting/` is where the credential and the decision logs already live. It is
outside every project root, so a write to it from an agent session is a
`write_outside` the engine can see and refuse — the relaxation file is protected
by the guard it relaxes. That is not a coincidence to be pleased about; it is
the reason this directory was chosen.

⚠ **IT IS STILL NOT A BOUNDARY AGAINST A DETERMINED LOCAL ATTACKER**, and saying
otherwise would be the kind of claim this project refuses. Anything running as
the developer can write `~/.sting/policy.json`. What the location buys is that
doing so is VISIBLE — a decision record exists for the attempt, and the guard
would have to be relaxed BEFORE the session that wants it, not during.

────────────────────────────────────────────────────────────────────────────────
THE FILE
────────────────────────────────────────────────────────────────────────────────

    {
      "version": 1,
      "rules": {
        "untrusted_local:git_commit": "ask",
        "irreversible_action:rm_rf":  "allow"
      }
    }

Keys are `rule_id` as it appears on the record and in the deny message, so the
thing a developer copies out of a refusal is the thing they paste in. Values are
`ask` or `allow`, lower-case. Anything else is ignored and reported.
"""
from __future__ import annotations

import dataclasses
import json
import os

from core.types import Decision, Verdict

PATH_ENV = "STING_POLICY"
"""An override for the file's location, for tests and for an operator who keeps
their home directory somewhere unusual. Same shape as STING_SESSION_ROOT."""

MAX_RULES = 200
"""A bound, because this is read on the hot path and parsed from a file a person
edits. Two hundred is far above any plausible number of relaxations and far
below anything that would cost measurable time."""

RELAX = {"ask": Decision.ASK, "allow": Decision.ALLOW}
"""The only two values. ⚠ `deny` IS NOT HERE — see the module docstring. Adding
it would make this file able to strengthen the policy, and a relaxation file
that can tighten is a file nobody looks in when something is unexpectedly
refused."""

SHIPPED_DEFAULT = {
    # ⚠ THE DEFAULT A MACHINE WE HAVE NEVER SEEN ARRIVES WITH — TASK 3.2, and
    # it is argued from the real recorded actions on this machine rather than
    # chosen. 185 stops, 146 of them DENY, and reading the actual commands:
    #
    #   59  untrusted_unexpected:git_push        every one a developer pushing
    #                                            their own branch
    #   38  untrusted_unexpected:guard_selfmod   `rm -rf $SCRATCH`, `pkill
    #                                            emulator` — scratch cleanup
    #                                            (relaxed until item C; below)
    #   32  untrusted_unexpected:network_egress  curl to our OWN collector's
    #                                            /healthz, firestore emulator
    #    6  untrusted_unexpected:write_outside   ordinary edits to a sibling
    #
    # ⚠ ZERO OF THE 146 WAS AN ATTACK. That is the "~28 stops a day catching
    # zero attacks" figure, confirmed against the commands rather than a rate.
    #
    # ⚠ AND THE RULES ARE NOT WRONG — THE SESSIONS REALLY WERE UNTRUSTED. The
    # `untrusted_*` family fires when the session has read attacker-authorable
    # text, and a developer's session does that constantly: a README, a fetched
    # doc, an issue body. In the CORPUS those same rules are the whole of the
    # I02 chain and they catch real attacks. So this is not "turn off a broken
    # rule". It is: on the untrusted family, the ratio of real work to real
    # attacks is such that DENY costs more than it buys, and ASK costs almost
    # nothing.
    #
    # ⚠ ASK IS NOT ALLOW. The action still stops; the developer answers once and
    # proceeds. What it removes is the case where a guard refuses a `git push`
    # and the person's only route forward is to uninstall it.
    "untrusted_unexpected:git_push": Decision.ASK,
    # ┌──────────────────────────────────────────────────────────────────────┐
    # │ ⚠ `untrusted_unexpected:guard_selfmod` IS NO LONGER HERE, ON PURPOSE. │
    # └──────────────────────────────────────────────────────────────────────┘
    # It was relaxed to ASK while the only two people running Sting were
    # building it with it, and this comment named the day it would go back to
    # DENY: the first install on a machine whose user is not a Sting developer.
    # That day came with a stronger rule (maintainer, 25 Sep): an agent tool call
    # that writes, deletes, moves, stops, unloads or uninstalls any part of the
    # INSTALLED guard is DENY in EVERY session, clean or tainted —
    # `installed_guard:guard_selfmod`, the floor in core/engine.py.
    #
    # ⚠ SO THE SHIPPED DEFAULT RELAXES NEITHER, FOR ANYONE. A machine that
    # develops Sting with agents opts IN on its own box, in its own
    # `~/.sting/policy.json`, and only there:
    #
    #     {"rules": {"installed_guard:guard_selfmod": "allow",
    #                "untrusted_unexpected:guard_selfmod": "ask"}}
    #
    # The first gives back what the engine decides without the floor (ALLOW in
    # a clean session, the irreversible ASK on a recursive delete), never a
    # blanket ALLOW; the second is the old relaxation, for a session that has
    # read attacker-authorable text. `secret_*:guard_selfmod` and the
    # catastrophic rules are relaxed by neither.
    #
    # ⚠ A PERSON IS NEVER STOPPED BY THIS. The hook sees agent tool calls only:
    # `launchctl bootout`, `install.py --uninstall` or an edit to this file,
    # typed in their own terminal, never reaches it.
    "untrusted_unexpected:network_egress": Decision.ASK,
    "untrusted_unexpected:write_outside": Decision.ASK,
    "untrusted_unexpected:pipe_to_shell": Decision.ASK,
    "untrusted_unexpected:dns_lookup": Decision.ASK,
    # ⚠ WHAT IS DELIBERATELY *NOT* HERE, AND THIS LIST IS THE PRODUCT.
    #
    #   secret_*              a credential that has actually been read is
    #                         leaving the machine. A false positive costs one
    #                         prompt; a miss costs the credential. Stays DENY.
    #   catastrophic_delete   `rm -rf /`. Stays DENY.
    #   untrusted_destructive an untrusted session deleting things. Stays DENY —
    #                         it fired ONCE in 185 stops, so it is not the noise.
    #   irreversible_action   already ASK. Nothing to relax.
    #
    # The shape of the rule: DENY survives where a false positive is cheap and a
    # miss is not recoverable. Everything relaxed here is recoverable — the
    # action is still stopped, and a human still says yes.
}
"""The relaxations every machine starts with, before `~/.sting/policy.json`.

⚠ IT IS A CONSTANT AND NOT A FILE THE INSTALLER WRITES, so the scorer and the
installed machine cannot disagree about what shipped. `runner/replay.py` drives
the real hook, so A4 and A5 are measured under exactly this default — which is
the point of putting it here rather than in a template.
"""

# How much weaker each decision is, so "does this relax?" is a comparison rather
# than a table of special cases. DENY is strongest.
_STRENGTH = {Decision.DENY: 2, Decision.ASK: 1, Decision.ALLOW: 0}


def home_path() -> str:
    """`~/.sting/policy.json`: where the file lives when STING_POLICY does not
    move it, and what uninstall removes.

    ⚠ A PERSON'S FILE, AND ONLY THEIRS. No code writes it. The org policy the
    shipper fetches is cached in `~/.sting/org_policy.json` (core/org_policy.py),
    which refuses to write here: the two used to be one path, and an org
    document then replaced a person's relaxations."""
    return os.path.join(os.path.expanduser("~"), ".sting", "policy.json")


def default_path() -> str:
    return os.environ.get(PATH_ENV) or home_path()


class Overlay:
    """The relaxations in force. Immutable, and cheap to build.

    ⚠ NEVER RAISES, AND AN UNREADABLE FILE IS AN EMPTY OVERLAY RATHER THAN A
    CRASH. This is read on the path that decides whether to block a developer's
    tool call; a JSON syntax error in a config file must not become a hook that
    cannot run. The failure is REPORTED — `problems` is non-empty and the caller
    puts it on stderr — because a relaxation somebody wrote and which is not in
    force is exactly as bad as one they did not write.
    """

    __slots__ = ("rules", "problems", "path")

    def __init__(self, rules: dict, problems: list, path: str):
        self.rules = rules
        self.problems = problems
        self.path = path

    def __bool__(self) -> bool:
        return bool(self.rules)

    @property
    def relaxed(self) -> list:
        """The rule ids this overlay touches, sorted. Goes on every record."""
        return sorted(self.rules)

    def apply(self, decision, rule_id):
        """(decision, relaxed_to) — the decision to ENFORCE, and whether it moved.

        ⚠ THE ENGINE'S VERDICT IS NOT MODIFIED, AND THIS IS NOT CALLED FROM THE
        ENGINE. `core/engine.decide()` performs no IO and reads nothing about
        the machine — a test enforces both — so the overlay is applied by the
        CALLER, after the engine has decided and after the engine's own verdict
        has been recorded. What changes is what is done with a decision, never
        the decision.
        """
        if not rule_id:
            return decision, None
        wanted = self.rules.get(rule_id)
        if wanted is None:
            return decision, None
        # ⚠ RELAXATION ONLY. A `rules` entry that would strengthen is dropped at
        # load time, but this is checked again here: two guards, because the one
        # that fails silently is the one that matters.
        if _STRENGTH.get(wanted, 99) >= _STRENGTH.get(decision, 0):
            return decision, None
        return wanted, wanted

    def enforce(self, verdict: Verdict) -> tuple[Verdict, str | None]:
        """(the verdict to ENFORCE, a note for stderr or None).

        `apply`, over a whole verdict. ⚠ A FLOOR GIVES BACK WHAT IT REPLACED.
        `installed_guard:guard_selfmod` carries the engine's own verdict as
        `beneath`, so relaxing it enforces the stricter of the relaxed value
        and that verdict, itself relaxed only by this overlay's own entries:
        the irreversible ASK on a recursive delete stays an ASK, and an
        untrusted session keeps `untrusted_unexpected:guard_selfmod` unless the
        person relaxed that too. Never a blanket ALLOW."""
        enforced, relaxed_to = self.apply(verdict.decision, verdict.rule_id)
        if relaxed_to is None:
            return verdict, None
        note = (f"sting: relaxed by policy — {verdict.rule_id} would have been "
                f"{verdict.decision}, enforced as {enforced}. "
                f"The engine's verdict is on the record unchanged.")
        beneath = getattr(verdict, "beneath", None)
        if beneath is not None:
            under, _ = self.enforce(beneath)
            if _STRENGTH.get(under.decision, 0) >= _STRENGTH.get(enforced, 0):
                return under, (
                    f"sting: relaxed by policy — {verdict.rule_id} would have "
                    f"been {verdict.decision}; what the engine decides beneath "
                    f"it is enforced: {under.decision}"
                    f"{f' ({under.rule_id})' if under.rule_id else ''}. "
                    f"The engine's verdict is on the record unchanged.")
        return dataclasses.replace(verdict, decision=enforced), note


EMPTY = Overlay({}, [], "")


def load(path: str | None = None) -> Overlay:
    """Read the overlay. Never raises."""
    path = default_path() if path is None else path
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        # ⚠ THE ORDINARY CASE, AND IT IS NOT A PROBLEM. Most machines never
        # write this file; they run the shipped default. Reporting it would put
        # a line on every tool call.
        return Overlay(dict(SHIPPED_DEFAULT), [], path)
    except (OSError, ValueError) as exc:
        return Overlay(dict(SHIPPED_DEFAULT), [f"{path}: {type(exc).__name__}: {exc}"], path)

    problems: list = []
    if not isinstance(raw, dict):
        return Overlay(dict(SHIPPED_DEFAULT), [f"{path}: not a JSON object"], path)

    # ⚠ DECLINING THE SHIPPED DEFAULT IS NOT THE SAME AS TIGHTENING, and
    # without this there was no way to get back to "enforce everything the
    # engine decides" — a gap introduced by shipping a default at all.
    #
    # `{"shipped_default": false}` drops the relaxations this build ships with,
    # leaving only what the file itself names. It cannot make anything STRICTER
    # than the engine: the strongest state reachable is exactly the engine's own
    # verdicts, which is the ceiling by construction. An operator who wants
    # everything enforced, and a test that needs a real DENY through the real
    # path, both need this and neither can get there any other way.
    base = (dict(SHIPPED_DEFAULT) if raw.get("shipped_default") is not False
            else {})

    entries = raw.get("rules")
    if entries is None:
        return Overlay(base, [], path)
    if not isinstance(entries, dict):
        return Overlay(base, [f"{path}: `rules` is not an object"], path)
    if len(entries) > MAX_RULES:
        return Overlay({}, [f"{path}: more than {MAX_RULES} rules; ignored "
                             f"entirely rather than truncated — a partial "
                             f"relaxation is one nobody can reason about"], path)

    # ⚠ THE FILE OVERRIDES THE SHIPPED DEFAULT AND NEVER MERELY ADDS TO IT.
    # An operator who wants `git_push` back at DENY cannot get there — this file
    # only relaxes — but they can leave it out of their own file and it stays
    # ASK. Starting from the default means "my file has three rules in it" does
    # not silently mean "and the other six are now enforced".
    rules: dict = dict(base)
    for rule_id, value in entries.items():
        if not isinstance(rule_id, str) or not rule_id:
            problems.append(f"{path}: a rule id that is not a string, ignored")
            continue
        wanted = RELAX.get(value.strip().lower()) if isinstance(value, str) else None
        if wanted is None:
            # ⚠ NAMED, INCLUDING `deny`. Somebody writing `"deny"` here is
            # trying to tighten and this file cannot; telling them it was
            # ignored is the difference between a setting that does nothing and
            # a setting they believe is doing something.
            problems.append(
                f"{path}: {rule_id} -> {value!r} is not `ask` or `allow`"
                + (" — this file can only RELAX a rule, never tighten one"
                   if isinstance(value, str) and value.strip().lower() == "deny"
                   else "") + "; ignored")
            continue
        rules[rule_id] = wanted
    return Overlay(rules, problems, path)


def describe(overlay: Overlay) -> str:
    """One line for stderr when anything is relaxed, or "".

    ⚠ ON EVERY CALL WHERE IT APPLIES, exactly as observe mode announces itself.
    A machine running with a rule turned down is a machine whose verdicts mean
    something different, and nobody should be in that state by accident.
    """
    if not overlay.rules and not overlay.problems:
        return ""
    parts = []
    if overlay.rules:
        parts.append("sting: POLICY RELAXED — "
                      + ", ".join(f"{r}->{v}" for r, v in
                                  sorted((k, str(x)) for k, x in overlay.rules.items()))
                      + f"  ({overlay.path})")
    parts += [f"sting: policy problem — {p}" for p in overlay.problems]
    return "\n".join(parts)
