"""Load `~/.sting/env` into the process environment. Stdlib only, cheap.

⚠ WHY THE HOOK READS THE FILE INSTEAD OF THE COMMAND LINE, ON EVERY PLATFORM.

`install.py` used to write the hook command with a POSIX env prefix:

    STING_OBSERVE='1' STING_ROOTS='…' python sting_hook.py --agent cursor

That has two faults, and the second is the one that made Windows guard nothing:

  1. ⚠ IT IS SECRETS AND SETTINGS IN A WORLD-READABLE FILE. hooks.json has no
     special permissions and an agent can read it. `~/.sting/env` is 0600. A
     setting the hook needs does not belong in a file the thing being guarded
     can read.
  2. ⚠ POWERSHELL READS THE PREFIX AS A COMMAND. Cursor runs a hook roughly as
     `Get-Content <temp>.json -Raw | & { $input | <command> }`, and
     `STING_OBSERVE='1'` at the front of that command is parsed as a command
     NAME, not an assignment. `failClosed:false` then made the resulting error
     a silent allow — so every Windows install guarded nothing and said so
     nowhere.

Reading the file here removes both. The hook command becomes just
`<python> sting_hook.py --agent <name>` — nothing to misparse, nothing to leak.

⚠ THE ENVIRONMENT WINS OVER THE FILE. A value already in `os.environ` is a
deliberate override — the shipper sets its own, a test exports one — and must
not be silently outranked by a file written weeks ago. This is the same
precedence `shipper/config.read_env_file` already follows; the two are pinned
equal by `tests/test_env_file_is_the_source.py`.
"""
from __future__ import annotations

import os


def default_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".sting", "env")


def load(path: str | None = None, environ=None) -> list:
    """Apply `export KEY='value'` lines to the environment. Returns the keys it
    set (those NOT already present). Never raises: a missing or unreadable file
    is a machine with no env file, which is a supported state.
    """
    environ = os.environ if environ is None else environ
    path = default_path() if path is None else path
    applied = []
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return applied
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        # ⚠ THE ENVIRONMENT WINS. Only fill a key nobody set.
        if key in environ:
            continue
        # Strip one layer of surrounding quotes, from the outside only, so a
        # Windows path keeps its backslashes and a URL keeps its colons —
        # `install.py::_quote` wraps the whole value in single quotes.
        environ[key] = value.strip().strip("'\"")
        applied.append(key)
    return applied
