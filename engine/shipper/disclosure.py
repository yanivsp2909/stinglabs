"""What the org's policy says this laptop may send as written.

One setting today, read from the cached org policy (`core/org_policy`, which
the shipper's poll fetches and `sanitise` keeps untouched as a future
section):

    "disclosure": {"folder_names": "send"}

names the account in a home folder (`/Users/<name>/`) as written; anything
else masks it as `[user]` (shipper/identifying.py).

⚠ EXACTLY THAT, OR MASK. Absent, damaged, a value in another case, a second
key, the section as a string: masked. The collector stores the
section only for "send" and refuses anything else at save, but the collector
passes a damaged stored section through unchanged, and a cache is a local
file: this side decides for itself (`core/org_policy.sanitise` asks every
reader of a new section to validate it).
"""
from __future__ import annotations

from core import org_policy

FOLDER_NAMES_SENT = {"folder_names": "send"}


def sends_folder_names(policy: dict | None = None) -> bool:
    """Does the org's policy send home-folder account names as written?
    `policy` is the cached one when None. Never raises: `load_cached` answers
    the empty policy on every error, and the empty policy masks."""
    if policy is None:
        policy = org_policy.load_cached()
    section = policy.get("disclosure") if isinstance(policy, dict) else None
    return (isinstance(section, dict) and section.keys() == FOLDER_NAMES_SENT.keys()
            and type(section["folder_names"]) is str
            and section["folder_names"] == FOLDER_NAMES_SENT["folder_names"])
