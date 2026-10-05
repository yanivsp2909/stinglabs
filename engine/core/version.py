"""Which copy of this code is DECIDING. Not which copy is shipping.

⚠ THE DEFECT THIS EXISTS FOR. Every batch carried `manifest.guard_ref`, taken
from `git describe` run inside the sending tree, under a docstring
that said it was there "so a verdict can be tied to a policy". On the first real
end-to-end run those were two different trees: the hook was executing an
installed copy at `…-17-g1263dd3` while the sending process ran from a checkout
at `…-19-g75e36c6`, so every verdict was attributed to two commits that had not
made it. **Provenance that is wrong is worse than provenance that is absent**,
because a reader acts on it — they open the named commit and read a rule that
was not the rule.

The deciding version was, at that point, NOWHERE: not in the record body, not in
the session state, not derivable from anything either carried. So this is the
upstream half of the fix — the version travels from the process that decided,
inside the hashed body, and no later hop can guess it.

WHAT IT READS, AND WHY NOT git
────────────────────────────────────────────────────────────────────────────────
`INSTALL.json`, written by `installer/place.py` NEXT TO the code being run and
found relative to this file — deliberately not `~/.local/share/sting/current`,
which is what is installed NOW. During a reinstall those differ, and the honest
answer to "what decided this record" is the version of the bytes that were
executing, not the version that replaced them a second later.

`git describe` is not an option here and the reason is a budget, not taste: this
runs on the hook path, and a subprocess spawn is ~10 ms against a 12 ms p99
budget that `A6b-ii` already caps at two git spawns per verdict for probes that
have to exist. Reading a 361-byte JSON is **21.8 µs measured**, and it is cached
for the life of the process on top of that.

⚠ WHAT THIS STRING DOES AND DOES NOT PIN. It names an install, and an install
can be made from a dirty tree — this very machine's `INSTALL.json` carries
`"source_dirty": true`. So it identifies WHICH INSTALL decided, which is enough
to tell two policies apart and not enough to reconstruct the bytes. A checkout
running with no install answers `uninstalled`, which is a fact rather than a
guess: there is no cheap identifier for a working copy, and inventing one that
looks like a version would be the same class of error this module fixes.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

UNINSTALLED = "uninstalled"
"""No INSTALL.json beside the running code — a checkout, run directly."""

UNKNOWN = "unknown"
"""An INSTALL.json that is there and unreadable, or names no version. Kept
distinct from `uninstalled`: one means "not installed", the other means
"installed and something is wrong with it", and they lead somewhere different."""


def manifest_path() -> Path:
    """`INSTALL.json` beside the package this module is part of."""
    return Path(__file__).resolve().parent.parent / "INSTALL.json"


@lru_cache(maxsize=1)
def running_version() -> str:
    """The version of the code executing this call. Never raises.

    Cached for the process: the hook is a fresh process per tool call, so this
    is one read per call at worst, and one read per process for anything longer
    lived.
    """
    path = manifest_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return UNINSTALLED
    try:
        return str(json.loads(raw).get("guard_version") or UNKNOWN)
    except (ValueError, AttributeError):
        return UNKNOWN
