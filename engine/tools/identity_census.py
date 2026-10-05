#!/usr/bin/env python3
"""Every identity a RELEASE ARCHIVE could carry — not the one the builder has.

    python3 tools/identity_census.py            # print the census and its gaps

⚠ WHY THIS IS A SECOND FILE AND NOT A SECOND CALLER OF `redact_logs`.
They are two jobs that want two different answers, and one function cannot give
both honestly:

    redacting a LIVE LOG      the running user's identity, and ONLY theirs.
                              Substituting a name that belongs to somebody else
                              corrupts the log — a real command containing that
                              word is silently rewritten — and on a receiver's
                              machine this repo's git history is a list of OUR
                              developers, which is precisely the wrong list for
                              THEIR log.

    checking a RELEASE ARCHIVE  every identity the TREE could be carrying,
                              whoever built it. The build host's own identity is
                              ONE ENTRY in that set, not the set.

⚠ AND THE REGRESSION THAT MADE THIS NECESSARY. When the identity sweep replaced
four hardcoded strings with `propose_identity()`, the archive check became
MACHINE-DEPENDENT: on a runner it scans for `runner` and the runner's ephemeral
hostname, so an archive built anywhere but one specific Mac passes while
carrying that developer's username — the exact leak the check exists to
prevent, now conditional on where the build ran. A "0 hits" result was true on
one machine and said nothing about any other.

────────────────────────────────────────────────────────────────────────────────
⚠ WHAT THIS CAN AND CANNOT DERIVE, STATED RATHER THAN IMPLIED
────────────────────────────────────────────────────────────────────────────────

DERIVABLE, and therefore here:

  * everyone in the git history — author and committer, name and email, over
    every commit. This is the set that can put a name in a comment, a docstring
    or a defect note, because it is exactly the set of people who have written
    one. It travels with the clone, so it is the same on every machine.
  * the build host's own identity, via `installer.detect.propose_identity()` —
    which catches an identity that reached the tree without a commit, i.e. an
    uncommitted working tree at build time.

NOT DERIVABLE, and honestly so:

  * ⚠ A UNIX USERNAME — INCLUDING OUR OWN. Measured rather than reasoned:
    planting `/Users/<the author's username>/notes.txt` in a staged archive and
    scanning it from another machine did NOT catch it, because a username never
    appears in a commit. Git knows a person's full name and an email address; it
    does not know their login. On the author's own machine the host half
    supplies it and the gap is invisible — which is the machine dependence all
    over again, one level down.
  * a third party who never authored a commit — a CUSTOMER's username in a
    defect note, a private hostname, a fragment of somebody's token. Four of
    those were the original sweep's findings and NONE of them is in any git
    identity.

So the honest position, which is what the brief asked for out loud: **the
NAME-and-EMAIL half is derivable and needs no hand-maintained list; the
USERNAME half cannot be derived on any machine but the owner's, and is caught
by SHAPE instead** — `/Users/<not-a-placeholder>`, a Windows home, a
token-shaped run of base64url. That list is closed, it is maintained by hand,
and it says so. A check that scans for the wrong thing silently is worse than
one that admits it needs a list, so both halves run and both are named.

⚠ AND A DEGRADED CENSUS IS LOUD. `actions/checkout` clones SHALLOW by default,
so on CI `git log` sees ONE commit and this census would quietly cover one
author. `completeness()` reports that, and the release gate refuses on it. A
check that silently scans for less than it claims is the defect being fixed,
and re-introducing it in a new file would be the joke telling itself.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.redact_logs import _TOO_GENERIC                          # noqa: E402

ROOT = Path(__file__).parent.parent

MIN_LENGTH = 4
"""Below this an identifier is a substring of ordinary words. `_TOO_GENERIC` is
imported rather than copied: two answers to "is this word an identity" is how
the substituter and the checker drifted apart the first time."""


def _run(args: list[str], root: Path) -> str:
    try:
        out = subprocess.run(args, cwd=str(root), capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout if out.returncode == 0 else ""


def _usable(value: str) -> bool:
    return (len(value) >= MIN_LENGTH
            and value.lower() not in _TOO_GENERIC
            and not value.lower().startswith("noreply@"))


def _expand(values) -> set:
    """Each identifier, plus the local part of anything address-shaped.

    ⚠ THE SAME REDUCTION `redact_logs` MAKES, AND FOR THE SAME REASON: an
    address appears JSON-escaped inside commands that themselves contain a
    regex, so a pattern written for a literal dot misses every one. The
    identifying TOKEN is escaping-proof.
    """
    out = set()
    for value in values:
        value = (value or "").strip()
        if not value:
            continue
        if _usable(value):
            out.add(value)
        if "@" in value:
            local = value.split("@", 1)[0]
            if _usable(local):
                out.add(local)
    return out


def git_identities(root: Path = ROOT) -> set:
    """Every author and committer in the history — name and email.

    ⚠ COMMITTER AS WELL AS AUTHOR. A commit made through the GitHub web UI
    carries a different committer, and a rebase or a squash rewrites one and not
    the other. Reading only `%an` misses a person who has been in this tree.
    """
    raw = _run(["git", "log", "--all", "--format=%an%n%ae%n%cn%n%ce"], root)
    return _expand(raw.splitlines())


def host_identities() -> set:
    """The build host's own identity — ONE ENTRY, not the list.

    It is here to catch what a commit cannot: an identity sitting in an
    uncommitted working tree at the moment the archive is built.
    """
    try:
        from installer.detect import propose_identity
        return _expand(propose_identity().get("identifiers") or [])
    except Exception:                                            # noqa: BLE001
        return set()


def completeness(root: Path = ROOT) -> dict:
    """What this census could and could not see. ⚠ READ THIS BEFORE THE SET.

    A census over a shallow clone is not a smaller census, it is a DIFFERENT
    claim — "no identity from the one commit I can see" — and reporting it as
    the first would be the machine-dependence bug wearing a new coat.
    """
    have_git = bool(_run(["git", "rev-parse", "--git-dir"], root))
    shallow = _run(["git", "rev-parse", "--is-shallow-repository"],
                    root).strip() == "true"
    commits = _run(["git", "rev-list", "--all", "--count"], root).strip()
    return {
        "git_available": have_git,
        "shallow": shallow,
        "commits_scanned": int(commits) if commits.isdigit() else 0,
        "host_identities": sorted(host_identities()),
        # ⚠ NAMED, NOT LISTED. Printing the census into a CI log would publish
        # the very names it exists to keep out of published bytes.
        "complete": have_git and not shallow,
        "why_not": ("" if have_git and not shallow else
                     "no git history here" if not have_git else
                     "the clone is SHALLOW — `actions/checkout` fetches depth 1 "
                     "by default, so only the tip commit's author is visible"),
    }


def tree_identities(root: Path = ROOT) -> set:
    """The set a release archive must be checked against."""
    return git_identities(root) | host_identities()


# ══════════════════════════════ the half that cannot be derived ══
#
# ⚠ A CLOSED LIST, MAINTAINED BY HAND, AND IT SAYS SO. Every entry is a shape
# that has actually leaked out of this tree. It cannot catch a shape nobody
# added — but it is the ONLY half that can see a username, and a username is
# what the original sweep found four times.
#
# ⚠ PLACEHOLDER NAMES ARE THE POINT OF THE FIX, so they must not fail it.
# `/Users/dev`, `C:\Users\<name>` and the corpus's `alice`/`bob` are what a real
# name is REPLACED WITH; a check that rejects them would forbid the cure.
_PLACEHOLDER = r"(?:dev|you|user|alice|bob|carol|shared|name|example|<[^>]+>)"

LEAK_SHAPES = [
    # A Windows customer's home directory, from defect notes about their
    # machine. Both `C:\Users\<name>` and the URI form `/C:/Users/<name>`.
    ("a real Windows home directory",
     re.compile(r"[Cc]:[\\/]+Users[\\/]+(?!" + _PLACEHOLDER + r"\b)"
                 r"[A-Za-z][A-Za-z0-9._-]{2,}")),
    # A POSIX home. `/Users/dev` and `/home/user` are placeholders and allowed.
    # ⚠ THIS IS THE ONE THAT CATCHES A UNIX USERNAME — ours included. The census
    # above cannot: a username never appears in a commit.
    ("a real POSIX home directory",
     re.compile(r"/(?:Users|home)/(?!" + _PLACEHOLDER + r"\b)"
                 r"[a-z][a-z0-9._-]{3,}")),
    # A bearer-token-shaped run of base64url. A supervisor comment carried six
    # characters of a real device token; `secrets.token_urlsafe(32)` gives 43.
    ("a token-shaped literal", re.compile(r"\b[A-Za-z0-9_-]{24,}\b")),
]

# Shapes the patterns above match that are NOT identity. Each is here because it
# fired, and each names why it is safe.
ALLOWED = re.compile(
    r"AKIAIOSFODNN7EXAMPLE"                    # AWS's own documentation key
    r"|[A-Fa-f0-9]{40,64}"                     # a sha256/sha1 digest
    r"|[A-Za-z0-9_-]*(?:_[A-Za-z]+){2,}"       # snake_case identifiers
    r"|(?:[a-z]+[A-Z][a-z]+){2,}"              # camelCase identifiers
    r"|[A-Za-z]+(?:-[A-Za-z]+){2,}"            # kebab-case words and rule ids
)

# Only text a person writes. A `.json` fixture or a `.jsonl` log is data, and
# the archive ships none of either.
SOURCE_SUFFIXES = (".py", ".md", ".ps1", ".txt", ".sh", "")


def shape_hits(text: str) -> list:
    """(what, matched) for every leak SHAPE in `text`."""
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        for what, pattern in LEAK_SHAPES:
            for hit in pattern.findall(line):
                value = hit if isinstance(hit, str) else hit[0]
                if ALLOWED.fullmatch(value) or ALLOWED.search(value):
                    continue
                out.append((number, what, value))
    return out


def scan(target: Path, identities=None) -> list:
    """Every (file, identity) hit under `target`. The RELEASE GATE.

    ⚠ IT SCANS THE STAGED BYTES, NOT THE WORKING TREE. A test that scans the
    repo answers "would an archive built from this checkout be clean"; this
    answers "is the archive that was just built clean", which is the question
    somebody is about to send to a stranger.
    """
    identities = sorted(identities if identities is not None
                        else tree_identities())
    hits = []
    for path in sorted(p for p in target.rglob("*") if p.is_file()):
        if "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name = str(path.relative_to(target))
        for value in identities:
            if value in text:
                line = next((i + 1 for i, l in enumerate(text.splitlines())
                             if value in l), 0)
                hits.append((name, line, f"from the census: {value!r}"))
        # ⚠ AND THE SHAPES, IN THE SAME PASS. Running only the census here was
        # measured missing a planted `/Users/<username>` from another machine —
        # the two halves cover different things and a gate needs both.
        if path.suffix in SOURCE_SUFFIXES:
            hits += [(name, line, f"{what}: {value!r}")
                     for line, what, value in shape_hits(text)]
    return hits


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scan", metavar="DIR", default=None,
                     help="a staged archive to check against the census")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    state = completeness()
    found = tree_identities()
    print(f"git history      {'yes' if state['git_available'] else 'NO'}"
          f"   {state['commits_scanned']} commit(s)"
          f"{'   ⚠ SHALLOW' if state['shallow'] else ''}")
    print(f"identities       {len(found)} derived "
          f"({len(git_identities())} from history, "
          f"{len(state['host_identities'])} from this host)")
    if not state["complete"]:
        print(f"⚠ INCOMPLETE — {state['why_not']}", file=sys.stderr)
        print("  an archive checked against this census is NOT checked against "
              "every identity it could carry.", file=sys.stderr)
        return 1
    print("complete — every identity in the history is covered. ⚠ A third party "
          "who never authored a commit is NOT, and cannot be; that half is "
          "checked by SHAPE.")

    if args.scan:
        target = Path(args.scan)
        if not target.is_dir():
            print(f"⚠ nothing to scan at {target}", file=sys.stderr)
            return 1
        hits = scan(target, found)
        if hits:
            # ⚠ THE VALUE IS PRINTED HERE AND NOWHERE ELSE. A release is being
            # REFUSED and the person has to find the line; the identity is
            # already in the bytes on their disk, so naming it publishes
            # nothing that the archive was not about to publish anyway.
            print(f"⚠ REFUSING TO SHIP — {len(hits)} identity hit(s):",
                  file=sys.stderr)
            for name, line, what in hits[:40]:
                print(f"    {name}:{line} — {what}", file=sys.stderr)
            return 1
        print(f"scanned {target.name} — no identity from the census survives")
    return 0


if __name__ == "__main__":
    sys.exit(main())
