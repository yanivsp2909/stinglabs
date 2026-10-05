"""Does an action VISIBLY carry a secret reference? fix/false-positives, items 1
and 3 of the maintainer's decisions of 30 Sep (docs/112).

Reading outside content no longer gates a push, a network send, a DNS lookup,
a write or a delete outside the project, or an MCP call — EXCEPT when the
action itself shows one of these, and then the verdict it had stays:

    a secret-named variable      $DEPLOY_KEY, ${AWS_SECRET_ACCESS_KEY}, %GH_TOKEN%,
                                 $env:API_KEY, printenv NAME — whatever
                                 `env_reads.looks_secret` names
    an environment dump          env, printenv, set, export -p, /proc/*/environ, …
                                 (`env_reads.env_read`)
    a password in a URL          scheme://user:pass@host
    a credential file sent       curl -d @.env, --data-binary @f, -F x=@f, -T f,
                                 wget --post-file f, scp / rsync of one
                                 (`credentials.CREDENTIAL_PATHS`)
    a deferred-execution write   launchd, systemd, cron, login items, shell rc
                                 files — written to, or installed by a command

WHY THESE. The secret rules trace values the session READ. These attacks send
a secret the session never read — C01 posts `$DEPLOY_KEY`, C03 the environment,
F03 a password in a URL, G05 `-d @.env`, P05 a LaunchAgent — so only the
untrusted gate caught them, and it keeps doing so for exactly these.

The same detector judges an MCP call's arguments (item 3): an MCP call after a
secret read asks only when its arguments carry a secret reference or a traced
value.

Linear in the text: every pattern is found once, and each command segment is
read once (tests/test_secret_reference.py has the shapes).
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from core.command_text import _SEGMENT_END, _bash_unquote
from core.credentials import CREDENTIAL_PATHS
from core import env_reads
from core.types import Action, ActionKind

VARIABLE = "a secret-named variable"
ENV_DUMP = "an environment dump"
URL_PASSWORD = "a password in a URL"
CREDENTIAL_SENT = "a credential file sent"
DEFERRED = "a deferred-execution write"

_VARIABLE = re.compile(r"\$\{?(?:env:)?([A-Za-z_]\w*)|%([A-Za-z_]\w*)%")
# The scheme starts where a run of scheme characters starts: `\b` would restart
# at every `.`, `-` or `+` inside one, and a long `a.a.a…` would be quadratic.
_URL_PASSWORD = re.compile(
    r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s/?#@:'\"]+:[^\s/?#@'\"]+@")
# A command that sends or uploads what it names.
_SENDER = re.compile(
    r"(?<![\w./-])(?:curl|wget|scp|sftp|rsync|http|https|xh|nc|ncat|socat)(?![\w-])")
# What such a command sends from a file: `@file` (curl -d/-F/--data-*),
# `-T file` / `--upload-file`, wget's `--post-file` / `--body-file`.
_PAYLOAD = re.compile(
    r"@\s*([^\s'\";|&<>]+)|(?:\s-T|--upload-file)[=\s]\s*([^\s'\";|&<>]+)"
    r"|--(?:post|body)-file[=\s]\s*([^\s'\";|&<>]+)")
_COPIER = re.compile(r"(?<![\w./-])(?:scp|sftp|rsync)(?![\w-])")
# What runs later, unasked: launchd, systemd, cron, login items, shell start and
# exit files — and (the reviews) a login key or an ssh `ProxyCommand`/`rc`,
# git's and npm's own configuration (an alias, a pager, a hook path, a script
# shell), a shadow binary on the PATH, a git hook.
_DEFERRED_PATH = re.compile(
    r"(?i)/Library/Launch(?:Agents|Daemons)/|/\.config/systemd/|/etc/systemd/"
    r"|/(?:usr/)?lib/systemd/|/etc/cron|/var/spool/cron|/var/at/tabs|/etc/anacrontab"
    r"|/Library/StartupItems/|/\.config/autostart/|background[-_ ]?task[-_ ]?management"
    r"|/\.(?:bashrc|zshrc|bash_profile|bash_login|zprofile|zlogin|profile|zshenv"
    r"|bash_logout|zlogout)(?![\w.-])"
    r"|/\.config/fish/(?:config\.fish|conf\.d/)|/etc/(?:profile|zshrc|bashrc|bash\.bashrc)(?![\w.-])"
    r"|/\.ssh/(?:authorized_keys2?|config|rc|environment)(?![\w.-])"
    r"|/\.gitconfig(?![\w.-])|/\.config/git/config(?![\w.-])|/\.npmrc(?![\w.-])"
    r"|/\.local/bin/|/\.git/hooks/")
# Installing one by command — where a command starts, so the word `at` in a
# commit message is not a scheduled job. ⚠ `[^\S\n]*` after the lookbehind, never
# `\s*`: a newline is itself a separator, and a run of blank lines made `\s*`
# re-swallow the rest of the run at every position — quadratic (the reviews).
_DEFERRED_VERB = re.compile(
    r"(?i)(?:^|(?<=[;&|\n({`]))[^\S\n]*(?:sudo[ \t]+)?(?:crontab(?![\w-])"
    r"|launchctl\s+(?:load|bootstrap|submit|enable)"
    r"|systemctl\s+(?:--user\s+)?(?:enable|link)|schtasks\s+/create|at\s+(?:now|\d))")


def _variables(text: str) -> bool:
    for match in _VARIABLE.finditer(text):
        name = match.group(1) or match.group(2)
        if name and env_reads.looks_secret(name):
            return True
    return False


def _credential_sent(command: str) -> bool:
    """A credential-shaped file a sending command carries as its payload, or a
    copier (scp, sftp, rsync) names. Each segment is read once."""
    start = 0
    ends = [m.start() for m in _SEGMENT_END.finditer(command)] + [len(command)]
    for end in ends:
        segment = command[start:end]
        start = end + 1
        if not _SENDER.search(segment):
            continue
        for match in _PAYLOAD.finditer(segment):
            path = _bash_unquote(match.group(1) or match.group(2) or match.group(3) or "")
            if path and CREDENTIAL_PATHS.search("/" + path.lstrip("/")):
                return True
        if _COPIER.search(segment):
            for word in segment.split():
                if not word.startswith("-") and CREDENTIAL_PATHS.search(
                        "/" + _bash_unquote(word).split(":", 1)[-1].lstrip("/")):
                    return True
    return False


def _with_aliases(command: str, aliases: Mapping[str, str] | None) -> str:
    """The command, followed by the body of every alias this session defined
    that it names: G05's `ls -la` is `curl … -d @.env` once expanded, the same
    reading `sinks.check_sinks` gives an alias. Each name is looked up once."""
    if not aliases:
        return command
    words = set(re.split(r"[\s;&|()`]+", command))
    bodies = [aliases[w] for w in sorted(words) if w in aliases]
    return " ; ".join([command, *bodies]) if bodies else command


def secret_references(action: Action,
                      aliases: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Every kind of secret reference this action visibly carries, each once,
    in the order above; () when it carries none. `aliases`: the session's
    (`SessionState.aliases`), whose bodies a command naming them runs."""
    found: list[str] = []
    command = (_with_aliases(action.command, aliases)
               if action.kind is ActionKind.EXEC and action.command else None)
    texts = [t for t in (command, action.url, action.content) if t]
    if any(_variables(t) for t in texts):
        found.append(VARIABLE)
    if command:
        read = env_reads.env_read(command)
        if read is not None and read.names and VARIABLE not in found:
            found.append(VARIABLE)
        if read is not None and read.dump:
            found.append(ENV_DUMP)
    if any(_URL_PASSWORD.search(t) for t in texts):
        found.append(URL_PASSWORD)
    if command and _credential_sent(command):
        found.append(CREDENTIAL_SENT)
    if _deferred(action, command):
        found.append(DEFERRED)
    return tuple(found)


def _deferred(action: Action, command: str | None) -> bool:
    """A deferred-execution write: a Write or Edit's path, a command, or — the
    reviews — an MCP call's arguments (a file server told to write one)."""
    if action.kind in (ActionKind.WRITE, ActionKind.EDIT):
        return any(_DEFERRED_PATH.search(p) for p in action.paths)
    if command:
        return bool(_DEFERRED_PATH.search(command) or _DEFERRED_VERB.search(command))
    if action.kind is ActionKind.TOOL:
        return any(_DEFERRED_PATH.search(t)
                   for t in (action.content, action.tool_arguments) if t)
    return False
