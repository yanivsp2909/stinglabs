"""Labelling: which actions mark the session untrusted or holding a secret
(`mark_sources`), which credential paths a command mentions, and how a secret
travels through copies, redirects and variables (`propagate`).

Moved out of core/engine.py; docs/ENGINE_LAYOUT.md.
"""
from __future__ import annotations

import re

from core import env_reads, org_policy
from core.downloads import (carried_downloads, copied_outside_files,
                            downloaded_files, pulled_downloads)
from core.shell_scan import (UNPARSED, bail_reason, code_mask_checked,
                             first_code_match)
from core.types import Action, ActionKind, SessionState, World
from core.command_text import (WINDOWS_READERS, _COPY_VERB, _GIT_COMMIT,
                               _NOT_SEGMENT_END,
                               _REDIRECT, _REDIRECT_VERB, _SEGMENT_END,
                               _SEGMENT_SEPARATORS, _TRUNCATING_REDIRECT,
                               _TRUNCATING_VERB, _abs, _basename, _bash_unquote,
                               _copy_pairs, _norm_path, _redirect_matches,
                               is_inside_project, span_evidence, without_commit_message)
from core.credentials import (CONFIDENTIAL_PATHS, CREDENTIAL_PATHS,
                              DEPENDENCY_PATHS, PLANTED_CONTENT,
                              carries_secret, fingerprint_values, policy_prints_in)
from core.globbing import _credential_scan_texts, _expanded_form
from core.irreversible import _cd_resolved_credential_paths, _deleted_by
from core.egress import _PRIVATE_HOST

# `mkdir` at a code position: its operands are folders this session makes.
_MKDIR = re.compile(r"(?<![\w./-])mkdir(?=[ \t])")


GIT_HISTORY = re.compile(r"\bgit\s+(log|show|branch|tag\s+-l|describe|blame)\b")

# Verbs that actually pull a file's contents into the session.
_READ_VERB = re.compile(
    r"\b(?:cat|head|tail|less|more|grep|egrep|awk|sed|base64|xxd|od|strings|"
    r"diff|cp|mv|source|export|read|tee|python\d?|node|jq)\b")

# ⚠ WINDOWS' READERS, EXACTLY LIKE `cat` (item D): cmd's `type`, PowerShell's
# `Get-Content` and its alias `gc`. On Windows `type .env` and `Get-Content
# .env` read a credential file and the session never knew. ⚠ ONLY WHERE A
# COMMAND STARTS — the line's start, after `;` `&` `|` a newline `(` `{` or
# `=`, or inside `cmd /c`, `-c` or `-Command` — because `find . -type f`,
# `git gc`, `--type`, `Content-Type:` and `echo type .env` read nothing, and a
# verdict moving on them would move outside this item's rule.
# ⚠ ONE BLANK RUN, AND NOT ACROSS A NEWLINE (fix/false-positives, the reviews):
# `\s*["']?\s*` split every run of blank lines two ways from every newline in
# it — cubic: 2,000 newlines took 27 s, on every command. A newline is itself
# a command position, so the same commands match, from it.
_WINDOWS_READ_VERB = re.compile(
    r"(?:^|(?<=[;&|\n({=])|(?<=\s/[cCkK] )|(?<=\s-[cC] )|(?i:(?<=-command )))"
    r"[^\S\n]*(?:[\"'][^\S\n]*)?" + WINDOWS_READERS + r"\s+\S")
_WINDOWS_GLUE = re.compile(r"[\"'`^]")
"""What cmd and PowerShell take out of a word before running it: quotes
(`"type" .env`, `& 'gc' .env`), cmd's `^` (`t^y^p^e`) and PowerShell's
backtick (`G`et-Content`)."""


def _reads_on_windows(command: str) -> bool:
    """Does `command` read a file with `type`, `Get-Content` or `gc`?

    ⚠ SECURITY REVIEW, HIGH: a quoted or escaped verb runs in cmd and
    PowerShell and put the verb out of the pattern's reach, so it is asked
    again of the command with that glue taken out. Only a yes or no: the paths
    are read from the command as written."""
    return bool(_WINDOWS_READ_VERB.search(command)
                or _WINDOWS_READ_VERB.search(_WINDOWS_GLUE.sub("", command)))

# A history read scoped to the commit that was JUST made. `-1` bounded so it
# cannot match `-12` or `-1x`; HEAD names the new commit by definition.
_SELF_SCOPED_READ = re.compile(r"(?<![\w-])-1(?![\w-])|\bHEAD\b")


def reads_back_own_commit(command: str | None) -> bool:
    """Does this command commit, and read back ONLY what it just committed?

    You cannot ingest a stranger's text by reading back something you wrote a
    microsecond earlier — the content was already in the session. That closes a
    loop where every commit command ending in `git log --oneline -1` created the
    untrusted source that justified asking about the NEXT commit: 39 of 66
    sources in one real session.

    THREE CONDITIONS, and the second is the one that is easy to get wrong:

      1. the command genuinely commits, at a code position;
      2. EVERY history read in it is scoped to the new commit. "Also commits"
         alone is not enough — `git commit … && git log --oneline -5` reads four
         commits it did not write, and 9 of 39 real cases were that shape;
      3. the command PARSED. An exemption granted on a command the scanner could
         not read would be an exemption granted on a guess.

    Failing any of them keeps the taint, which is the behaviour that predates
    this function. A missed match therefore costs a false positive and never a
    miss — which is what makes reading a flag defensible here, where elsewhere
    in this engine it has not been.
    """
    if not command:
        return False
    mask, parsed = code_mask_checked(command)
    if not parsed:
        return False                       # condition 3
    if not first_code_match(_GIT_COMMIT, command):
        return False                       # condition 1
    found = False
    for match in GIT_HISTORY.finditer(command):
        if match.start() >= len(mask) or not mask[match.start()]:
            continue                       # quoted text, not a read
        found = True
        end = _SEGMENT_END.search(command, match.end())
        segment = command[match.start():end.start() if end else len(command)]
        if not _SELF_SCOPED_READ.search(segment):
            return False                   # condition 2
    return found


def structure_mask(command: str, text_complete: bool = True) -> bytearray:
    """The mask STATE DERIVATION must use. Not the same choice a verdict makes.

    `code_mask` fails SAFE to all-code on anything it cannot parse, and that is
    right for a VERDICT: an unreadable command treated as entirely executable
    costs a false positive and can never cause a miss.

    ⚠ THE SAME BIAS IS WRONG FOR STATE RECONSTRUCTION, and it is not a smaller
    version of the same trade — it points the other way. A replay handed text it
    KNOWS is a 2048-byte prefix has lost the heredoc terminator, so the scan
    bails, so every byte reads as code, so `propagate` reads a COMMIT MESSAGE as
    shell. That is how `83aea8bb:117` — whose message describes `_copy_pairs`
    test cases such as `install -m 755 .env debug/.env` — tainted three fixture
    paths and made six later verdicts deny `secret_exact`. Failing safe invented
    structure rather than over-restricting it.

    So when the text is known incomplete AND the scan bailed, derive NOTHING:
    every byte is data. Both conditions are required —

      incomplete, parsed cleanly   the prefix's structure is real. Keep it. This
                                   is why the record is not dropped wholesale:
                                   the 2048 bytes that ARE present are genuine.
      complete, scan bailed        a real command we cannot read. Keep failing
                                   safe to code; that is the live behaviour and
                                   it is correct.

    `text_complete` comes from `audit_log.stored_command_is_whole`, whose rungs
    are ordered by authority — a matching digest and the `command_clipped` fact
    cannot lie inside an intact chain, while the marker and a bare length can,
    and are only consulted when the first two are absent.
    """
    mask, parsed = code_mask_checked(command)
    if parsed or text_complete:
        return mask
    return bytearray(len(command))


_NON_INGESTING_TOOLS = frozenset({
    # Tools whose RESULT is an identifier or an acknowledgement, and which
    # therefore cannot carry a stranger's prose into the model's context.
    # Deliberately short: everything absent from it marks the session untrusted.
    "tabs_close_mcp", "tabs_create_mcp", "resize_window",
})


def _tool_can_ingest(action: Action) -> bool:
    """Could this tool call put someone else's text into the session?

    ⚠ WHAT IS ACTUALLY KNOWABLE HERE. The hook fires on **PreToolUse — the tool
    has not run**, so the RESULT does not exist yet. The engine cannot key on
    what came back, only on the name and the arguments. Marking on the result is
    the structurally correct fix and it is PostToolUse work; PROGRESS.md's "four
    unknowns" is exactly the question of whether each agent even delivers one.

    So this is a capability judgement about a NAME, and it fails towards
    marking: an unrecognised tool is a tool we cannot vouch for. That is what
    keeps the C01-C05 family working, since `mcp__weather__get_alerts` is
    unknown here and a weather API result is precisely a stranger's text.

    THE ONE ARGUMENT THAT IS AVAILABLE is `navigate`'s URL — measured, 44 of 44
    navigate calls carry one — and a navigation to a loopback address fetches a
    page this machine is serving to itself.

    ⚠ ITS LIMIT, STATED: a page served from 127.0.0.1 can still embed remote
    content, and then the ingestion is real. This panel cannot — it is verified
    self-contained — but nothing here checks that, and a localhost dev server
    proxying a remote API is an ordinary thing. This is a friction judgement
    about the developer's own machine, not a security proof.
    """
    name = (action.tool_name or "").rsplit("__", 1)[-1]
    if name in _NON_INGESTING_TOOLS:
        return False
    if name == "navigate":
        host = (action.url or "").split("//")[-1].split("/")[0]
        host = host.split("@")[-1].split(":")[0]
        return not (host and _PRIVATE_HOST.match(host))
    return True


def mark_sources(state: SessionState, action: Action, world: World,
                  text_complete: bool = True) -> None:
    """Does this action CREATE a label?

    Called AFTER the verdict, so a source never judges itself.
    """
    seq = state.seq

    # ---- UNTRUSTED: "a stranger wrote this" ----
    if action.kind is ActionKind.FETCH:
        state.mark_untrusted(seq, "web", action.url or "")
    elif (action.kind is ActionKind.TOOL and action.tool_origin != "builtin"
           and _tool_can_ingest(action)):
        # Declared by the adapter, not sniffed from the name. `mcp__` is Claude
        # Code's convention and had no business being tested in the engine.
        #
        # The test is "not a RECOGNISED builtin" rather than "is mcp", so the
        # unset default falls on the STRICTER side here exactly as it does at
        # the sink: an adapter that forgets to declare an origin still marks its
        # tool calls untrusted rather than silently trusting them.
        state.mark_untrusted(seq, "mcp", action.tool_name or "")
    elif action.kind is ActionKind.READ:
        for path in action.paths:
            if PLANTED_CONTENT.search(path):
                state.mark_untrusted(seq, "issue", path)
            elif DEPENDENCY_PATHS.search(path):
                state.mark_untrusted(seq, "dependency", path)
            # A real repository file is the project's own text (docs/113 §3a):
            # only an issue body or an installed dependency marks it above, and
            # anything else counts only when it lies outside the roots.
            elif not is_inside_project(path, action.workspace_roots, world):
                state.mark_untrusted(seq, "outside", path)
    elif action.kind is ActionKind.EXEC and action.command:
        # SOURCE detection reads the command WITHOUT its commit message.
        # ⚠ THE MASK IS UNRELIABLE HERE WHEN THE PARSE FAILED, AND MARKING
        # ANYWAY IS THE CORRECT DIRECTION — the opposite of the DENY-capable
        # consumers, which is why this one is NOT gated on UNPARSED.
        #
        #   a DENY rule reading an all-code fallback  -> false BLOCKS
        #   a MARKING rule reading it                 -> false RESTRICTION,
        #                                                which is fail-safe
        #
        # Skipping the mark on an unparseable command was measured and REJECTED:
        # it removes the false mark from `echo 'git log' ; echo "` and, by the
        # same signature, removes the REAL mark from `git log ; echo "`. An
        # attacker reading git history appends one unbalanced quote and the
        # session stays clean — defeating K01, K02, K03, K04 and K06, whose
        # whole mechanism is commit-message text entering a session. Working
        # rule #5: they choose whether the command parses.
        #
        # Measured cost of the rejected gate: 0 corpus scenarios, 0 of 2390 live
        # verdicts. Both zeros are blindness — neither population contains an
        # unparseable complete command, because 266 of 266 live parse failures
        # are clipped records rather than unparseable text.
        # `code_mask_checked` is the one door — see
        # tests/test_unparseable_commands.py. `bail_reason` reads the mask it
        # returns, so this consumer still receives the parse state and decides.
        _mask, _ = code_mask_checked(action.command)
        unparsed = bail_reason(_mask) == UNPARSED
        history = first_code_match(GIT_HISTORY, action.command,
                                    structure_mask(action.command, text_complete))
        if history and not reads_back_own_commit(action.command):
            # The SPAN, not a prefix. See span_evidence: `command[:80]` showed a
            # heredoc opener for a match 4000 bytes later, and produced a wrong
            # diagnosis twice.
            #
            # ⚠ LOW CONFIDENCE IS RECORDED, BECAUSE THE MARK IS STICKY. A session
            # marked on an unreadable command carries that premise for every
            # later action, and the developer sees a denial citing a `git log`
            # they may never have run. The verdict does not change — this is the
            # fail-safe direction — but the reason says which kind of evidence
            # it rests on, so a false mark is diagnosable instead of mysterious.
            state.mark_untrusted(
                seq, "git-history-unreadable" if unparsed else "git-history",
                span_evidence(action.command, history.start(), history.end()))

    # ---- SECRET: "this must not leave" ----
    # Only READS create a secret SOURCE. Writing a credential-shaped file is
    # propagation, not ingestion — propagate() labels the destination. Marking
    # it here too would make a deny reason cite the copy rather than the
    # original, so I02's push would blame debug/.env instead of the .env read
    # that it traces back to, which is the fact the developer needs.
    candidates: list[str] = []
    if action.kind is ActionKind.READ:
        candidates += list(action.paths)
    elif action.kind is ActionKind.EXEC and action.command:
        # `cat .env` is a read the adapter classifies as EXEC — but only when a
        # verb actually pulls the contents in. `git add debug/.env` mentions a
        # credential path and reads nothing into context; treating it as a
        # source would make I02's denial blame the copy instead of the original.
        stripped = without_commit_message(action.command)
        # `install` COPIES FILE CONTENTS and was in neither gate, so
        # `install -m 755 .env debug/.env` marked no source at all and the
        # session never learned it held a secret — a total miss even after the
        # operand parsing was fixed. It is added via _COPY_VERB, which anchors
        # to a command position, and that anchoring is the whole point:
        # `install` UNANCHORED appears 6 times in the corpus and every one is
        # `pip install` or `npm install`, which read no file. At a command
        # position: zero. So the anchored form adds the verb without giving
        # package managers the power to unlock path extraction.
        if (_READ_VERB.search(stripped) or _COPY_VERB.search(stripped)
                or _reads_on_windows(stripped)):
            # A DESTINATION is not an ingestion point. `cp .env debug/.env`
            # reads .env and writes debug/.env; propagate() labels the
            # destination, and marking it here as well is what let the copy
            # become "the" origin in a deny reason. The engine already knows
            # which operand is which — _copy_pairs and _REDIRECT yield (src, dst)
            # pairs — so the role is available, it was simply not consulted.
            written = _copy_destinations(stripped, action.cwd)
            candidates += [p for p in _paths_mentioned_in(stripped, action.cwd,
                                                           reads=True)
                            if p not in written]

    # WAS THIS PATH AN OPERAND, OR A GUESS?
    #
    # A READ names its file in the tool input: the agent asked for it. An EXEC
    # candidate was parsed out of command TEXT by _paths_mentioned_in, which is
    # inference, not fact. The two deserve opposite treatment when the file
    # cannot be read, and conflating them is what produced the phantom:
    # `/repo/.env`, scraped from a path mentioned inside a test fixture, became
    # a SECRET source for a file that has never existed on this machine — and
    # `or ""` made `fingerprint_values("")` return nothing, so the source was
    # recorded with an empty fingerprint list and no way to tell it apart from
    # a real read of a file with no recognisable credentials in it. That one
    # phantom set holds_secret and poisoned the 166 actions after it.
    parsed_from_text = action.kind is not ActionKind.READ

    for path in candidates:
        if CREDENTIAL_PATHS.search(path):
            content = world.read_text(path)
            if content is None:
                # read_text returns None for missing-or-unreadable and "" for a
                # genuinely empty file, so the two ARE distinguishable; line 826
                # already leans on that same distinction as an existence check.
                if parsed_from_text:
                    # A path we merely INFERRED, for a file that isn't there.
                    # That is not evidence of anything. The guard runs as the
                    # same user as the agent, so "cannot read" here is in
                    # practice "does not exist" — if the agent could read it,
                    # so could we.
                    continue
                # A real operand we could not read. FAIL CLOSED: the agent
                # asked for this file by name and rule set B covers what
                # fingerprinting cannot. Recorded as `unread` rather than
                # `content`, so the state says which of the two it was.
                state.mark_secret(seq, path, "unread", [])
                continue
            prints = sorted(fingerprint_values(content))
            # A secret-looking value nothing fingerprinted (docs/112 item 3):
            # recorded apart, so the secret rules' sources are unchanged.
            if env_reads.unprinted_secret_in_text(content):
                state.unprinted_secret = True
            if prints:
                state.mark_secret(seq, path, "content", prints)
            else:
                # Read fine, nothing fingerprintable inside. Calling that
                # "content" is what made `how="content"` with zero fingerprints
                # possible — a combination that must not exist, because it reads
                # identically to a read that never happened. The path is still
                # the signal, so record the honest reason.
                state.mark_secret(seq, path, "path_policy", [])
        elif CONFIDENTIAL_PATHS.search(path):
            # No credential inside to fingerprint — the path IS the signal.
            state.mark_secret(seq, path, "path_policy", [])

    # ⚠ THE ENVIRONMENT, READ LIKE A SECRET FILE (item B, docs/110 §B). A
    # command that can print a secret-looking variable — a full dump, or a read
    # by a name that looks secret — marks the session, and the values come from
    # the HOOK's view of the environment (`World.environment`), never this
    # process's: provenance then follows the exact values. `core/env_reads.py`.
    env_read = None
    if action.kind is ActionKind.EXEC and action.command:
        environ = _hook_environment(world)
        env_read = env_reads.env_read(action.command, environ)
    elif action.kind is ActionKind.READ and any(
            env_reads.reads_proc_environ(p) for p in action.paths):
        environ = _hook_environment(world)
        env_read = env_reads.EnvRead(True, ())
    if env_read is not None:
        for label, how, prints in env_reads.marks(env_read, environ):
            state.mark_secret(seq, label, how, prints)
        if env_read.dump and env_reads.unprinted_secret(environ):
            state.unprinted_secret = True           # docs/112 item 3, as above

    # ⚠ ORG-POLICY SOURCES — THE COARSE TAINT (STEP 3a). A read whose resolved
    # path/URL matches a source the org DECLARED, or a command mentioning a
    # declared db/bucket, marks the session with that source's SEVERITY (log/ask/
    # deny), carried on `policy_sources`. ADDITIVE: an empty policy (or a load
    # failure — `org_policy.load_cached()` returns the empty policy, never raises)
    # matches nothing, so this is a no-op and the session is byte-identical to a
    # machine with no policy. It NEVER fingerprints a value (step 3b) and NEVER
    # weakens — the mark only ever ESCALATES an egress, in `_policy_escalate`.
    # ⚠ A FETCH READS A URL, NOT A FILE — pass it as a candidate so a bucket/path
    # source matches a `FETCH https://…/s3://…` too, not only a shell command or a
    # native file READ. (A TOOL call's arguments are a step-3a gap, see
    # `org_policy.match`.)
    # ⚠ SCAN THE EXECUTED COMMAND, NOT ITS PROSE. A commit MESSAGE that merely
    # names a declared table/bucket/path in English is not a read of it — strip it
    # first, exactly as the SECRET path above (`without_commit_message`) does, so a
    # benign `git commit -m "fix customers_pii view"` never taints the session and
    # denies a later, unrelated egress. Scan the bash-UNQUOTED form too, joined on a
    # newline (a token boundary), so `customers''_pii` — one token to the shell —
    # can't split a declared identifier or path past the match. This is the same
    # (raw, unquoted) union `_paths_mentioned_in` already scans.
    policy_command = without_commit_message(action.command or "")
    policy_text = policy_command + "\n" + _bash_unquote(policy_command)
    policy_candidates = candidates + ([action.url] if action.url else [])
    for source in org_policy.match(policy_candidates, policy_text):
        state.mark_policy_source(seq, source["value"], source["type"],
                                 source["severity"])

    # ⚠ ORG-POLICY VALUES — THE PRECISE FINGERPRINT (STEP 3b). For each declared
    # PATH source this read actually touched, fingerprint the distinctive VALUES the
    # file returned (whole records / long tokens at the SAME floor the secret
    # fingerprinter uses, plus structural email/SSN fields) — never plaintext, never
    # bare names or short numbers. On egress an EXACT value match is a confirmed
    # exfiltration and denies (`_policy_value_escalate`), the certain tier above 3a's
    # coarse severity. `readable_paths` returns [] with no policy (byte-identical) and
    # for bucket/db/FETCH sources whose CONTENT the engine cannot read here — those
    # stay coarse-taint only. The read is the same local `world.read_text` the
    # credential fingerprinting above already performs; no network.
    #
    # ⚠ ONLY A GENUINE READ FEEDS THE FINGERPRINT. A command's PATH TOKENS are passed
    # to `readable_paths` ONLY when a READ/COPY verb pulled the file's contents in —
    # the same gate the CREDENTIAL branch above uses. Without it, `rm /declared/x`,
    # `chmod … /declared/x`, or a command that merely MENTIONS the path would make the
    # guard open and fingerprint a file the session never read (and then falsely deny a
    # later, unrelated egress of that value). A native READ names its file in the tool
    # input, so its operands always count; only command-text tokens need the gate.
    # `policy_candidates` are already genuine reads — a native READ's operands, or the
    # EXEC credential paths the SECRET branch parsed ONLY inside its own read/copy-verb
    # gate above. The raw command TEXT is the one ungated source, so its path tokens
    # feed `readable_paths` ONLY when a read/copy verb pulled contents in.
    read_command = ""
    if action.kind is ActionKind.EXEC and action.command:
        _executed = without_commit_message(action.command)
        if _READ_VERB.search(_executed) or _COPY_VERB.search(_executed):
            read_command = policy_text
    for path in org_policy.readable_paths(policy_candidates, read_command):
        content = world.read_text(path)
        if content:
            prints = policy_prints_in(content)
            if prints:
                state.mark_policy_value(seq, path, sorted(prints))


def _hook_environment(world) -> dict[str, str]:
    """`world.environment()`: the environment the hook was started with
    (item B, docs/110 §B). A World without one — replay, and every World
    written before it — or one that fails, is `{}`: the session is still
    marked, and no value is known. Never raises."""
    if not callable(getattr(world, "environment", None)):
        return {}
    try:
        return env_reads.as_environment(world.environment())
    except Exception:                              # noqa: BLE001 — a mark never fails a verdict
        return {}


_PATH_TOKEN = re.compile(r"[\w./~-]*(?:\.env[\w.]*|\.pem|\.p12|\.pfx|"
                          r"id_rsa|id_ed25519|\.npmrc|\.netrc|\.pgpass|"
                          r"\.git-credentials)[\w./-]*|"
                          r"[\w./~-]*/\.(?:ssh|aws|kube|docker)/[\w./-]*|"
                          # ⚠ THE BARE-RELATIVE DOT-DIRECTORY, at a token boundary.
                          # The alternative above demands a `/` BEFORE the dir,
                          # so `.aws/credentials` spelled relative to the cwd was
                          # never EXTRACTED — a `^` on the matcher cannot help a
                          # token that is never found. This runs over the WHOLE
                          # command (finditer), so the guard is a lookbehind, not
                          # `^`: the dir must not be glued to a path character,
                          # which keeps `foo.aws/x` and `.aws-backup/x` out.
                          # Absolutised by the caller, it then matches
                          # CREDENTIAL_PATHS exactly as `~/.aws/credentials` does.
                          r"(?<![\w./~-])\.(?:ssh|aws|kube|docker)/[\w./-]*")


# Where a `_PATH_TOKEN` match can be: inside one run of path characters, with a
# credential keyword starting at or after its first character (item 4, security
# review). The keywords are exactly the literals each alternative needs: the
# credential names anywhere, a `/.ssh/`-style directory anywhere, and a bare
# `.ssh/`-style directory only at the start of a run, where the lookbehind of the
# third alternative allows it.
_PATH_CHAR_RUN = re.compile(r"[\w./~-]+")
_PATH_TOKEN_KEY = re.compile(
    r"(?=\.env|\.pem|\.p12|\.pfx|id_rsa|id_ed25519|\.npmrc|\.netrc|\.pgpass"
    r"|\.git-credentials|/\.(?:ssh|aws|kube|docker)/)")
_BARE_DOT_DIR = re.compile(r"\.(?:ssh|aws|kube|docker)/")


def _path_token_matches(text: str) -> list[re.Match]:
    """`list(_PATH_TOKEN.finditer(text))` — the identical matches, in linear time.

    ⚠ `finditer` TRIED EVERY POSITION OF A LONG RUN WITH NO KEYWORD AHEAD, and
    each try scanned the run and backtracked: `rm -rf /` + 16,000 `a` + `?` took
    3.2 s, quadratic. A match must start in a run of path characters with a
    keyword starting at or after it, so each run is searched only while a keyword
    lies ahead — and a search that succeeds reaches past the rightmost keyword its
    greedy prefix can, so a run takes a few searches, not one per character.
    Checked against `finditer` in `tests/test_the_guard_cannot_be_stalled.py`."""
    out: list[re.Match] = []
    for run in _PATH_CHAR_RUN.finditer(text):
        keys = [m.start() for m in _PATH_TOKEN_KEY.finditer(text, run.start(), run.end())]
        if _BARE_DOT_DIR.match(text, run.start(), run.end()):
            keys.insert(0, run.start())
        if not keys:
            continue
        pos, last = run.start(), max(keys)
        while pos <= last:
            match = _PATH_TOKEN.search(text, pos, run.end())
            if match is None:
                break
            out.append(match)
            pos = max(match.end(), pos + 1)
    return out


def _names_a_labelled_path(state: SessionState, command: str) -> bool:
    """Does the command mention a path this session labelled, or a
    credential-shaped one? Used where the SOURCE is a path rather than a value."""
    for path in list(state.tainted_paths) + [e.get("path", "") for e in
                                               (state.secret_sources or [])]:
        base = _basename(path or "")
        if base and base in command:
            return True
    # ⚠ TOKEN BY TOKEN, RATHER THAN WIDENING `CREDENTIAL_PATHS`. Its
    # alternatives are anchored on `^` or a separator, so `.env` after a SPACE
    # — `pbcopy < .env` — matches nothing. Splitting first gives each operand
    # its own `^` without touching the matcher every other rule depends on.
    #
    # ⚠ THE RAW COMMAND AND ITS SHELL-RESOLVED FORM, unioned: `pbcopy < .e''nv`
    # is `.env` to the shell but a split token here. `_bash_unquote` collapses
    # the glue; scanning both can only ADD a hit the literal pass missed. The
    # EXPANDED form adds `pbcopy < .en?` and `.{env,x}` the same way (docs/89).
    for source in _credential_scan_texts(command):
        if any(CREDENTIAL_PATHS.search(token)
               for token in re.split(r"[\s<>|;&]+", source) if token):
            return True
    return False


def _copies_a_secret_into_sync(state: SessionState, action: Action,
                                world: World, command: str) -> bool:
    """Does this command copy something LABELLED into a cloud-sync root?

    ⚠ ASKED OF THE SOURCE, NOT THE DESTINATION. `_copy_pairs` already gives
    (source, destination) for cp/mv/install and the redirect forms, and
    `_level_of_path` already answers "is this file tainted" — the taint
    machinery needs nothing new. What it does NOT answer is whether the SESSION
    holding a secret is enough on its own; it is not, and it must not be, or
    every write in a synced folder during a secret-holding session would fire.
    """
    roots = _sync_roots(world)
    if not roots:
        return False
    for _pos, src, dst in _copy_pairs(command, action.cwd):
        if not any(dst == r or dst.startswith(r.rstrip("/") + "/") for r in roots):
            continue
        # The source is labelled, or its CONTENT traces to something labelled.
        if _level_of_path(state, src) or CREDENTIAL_PATHS.search(src):
            return True
    return False


def _sync_roots(world) -> tuple:
    """`world.sync_roots()`, defensively — a world that cannot answer is a world
    that says None, and None is the QUIET branch here (see World.sync_roots)."""
    ask = getattr(world, "sync_roots", None)
    if ask is None:
        return ()
    try:
        return tuple(ask() or ())
    except Exception:                                            # noqa: BLE001
        return ()


def _copy_destinations(command: str, cwd: str) -> set[str]:
    """Absolute paths this command WRITES to via a copy or a redirect.

    Same parsing propagate() uses to label destinations, read here for the
    opposite purpose: to keep a destination out of the SOURCE list.
    """
    out: set[str] = {dst for _pos, _src, dst in _copy_pairs(command, cwd)}
    for _src, dst in (m.groups() for m in
                      _redirect_matches(_REDIRECT, _REDIRECT_VERB, command)):
        out.add(_abs(dst, cwd))
    return out


def _paths_mentioned_in(command: str, cwd: str, reads: bool = False) -> list[str]:
    """Credential-shaped paths named inside a shell command.

    Deliberately narrow: it looks for the credential shapes we already care
    about rather than trying to parse shell. A real tokenizer is the right
    answer eventually; guessing at one here would be worse than this.

    `reads` is for `mark_sources` alone: a glob then also yields names it does
    not SPELL (`i???s?` -> `id_rsa`), which only mark if the World finds the file
    — never at an exit, where text is all there is (`_read_names`, docs/89).
    """
    found: list[str] = []
    seen: set[str] = set()
    # ⚠ THE RAW COMMAND FIRST, THEN ITS SHELL-RESOLVED FORM. The raw pass is
    # unchanged, so every path found today is still found (never less); the
    # second pass adds the ones the shell glued — `@.e''nv` -> `@.env`. Dedup
    # keeps a glue-free command's two identical passes to one set of tokens.
    # ⚠ THEN AS BASH EXPANDS IT — braces and globs, `cat .en?` -> `.env` — a third
    # pass that only appends (docs/89). The first two are byte-identical.
    expansion = _expanded_form(command, reads)
    for source in _credential_scan_texts(command, expansion):
        for match in _path_token_matches(source):
            token = match.group(0).strip()
            if not token:
                continue
            if token.startswith("~"):
                token = token.replace("~", "/HOME", 1)   # normalised, not resolved
            elif not token.startswith("/"):
                token = f"{cwd.rstrip('/')}/{token}"
            if token not in seen:
                seen.add(token)
                found.append(token)
    # Each expanded word as ONE token, too: `_PATH_TOKEN` has no `id_dsa`,
    # `id_ecdsa` or `.docker/config.json`, which the plain spelling reaches
    # through the cd-resolving pass below — this reaches them without re-running
    # that quadratic pass for every expansion.
    for form in expansion.forms:
        token = (form.replace("~", "/HOME", 1) if form.startswith("~")
                 else form if form.startswith("/")
                 else f"{cwd.rstrip('/')}/{form}")
        if CREDENTIAL_PATHS.search(token) and token not in seen:
            seen.add(token)
            found.append(token)
    # ⚠ AND A BARE READ INSIDE A DIRECTORY AN EARLIER `cd` MOVED INTO. The passes
    # above resolve every relative token against the ONE static `cwd`, so
    # `cd .aws && cat credentials` named `/repo/credentials` and matched nothing —
    # the generic filename is only a credential because of the effective cwd. This
    # ADDS those (dedup'd), never removes; see `_cd_resolved_credential_paths`.
    # The expanded form, when there is one, is read the same way after the raw
    # command — `id_{dsa,x}` and `cd .a?s && cat credentials` land here.
    for text in (command, expansion.text) if expansion.positional else (command,):
        for path in _cd_resolved_credential_paths(text, cwd):
            if path not in seen:
                seen.add(path)
                found.append(path)
    return found


# ------------------------------------------------------------------- propagate

# ⚠ THE PATHS RUN TO THE END OF THE SEGMENT, NEWLINE INCLUDED (item D, docs/97). This
# used to be `(.+?)(?:&&|;|\||$)`: `.` never crosses a newline and `$` matches
# only at the very end, so `git add <tainted><newline>echo ok` matched nothing,
# the file never reached `staged_secret_files`, and the next commit — when git
# could not be inspected — went ALLOW where the `&&` form DENIES. Built from the
# shared `_NOT_SEGMENT_END` atom, so a `\<newline>` continuation stays inside
# and a bare newline ends it, exactly as `_SEGMENT_END` splits. A single `&`
# now ends the capture too (it did not before), which only drops the `&` and
# what follows it from the path list — never a staged path.
_GIT_ADD = re.compile(
    rf"\bgit\s+add\s+(?:-\w+\s+)*((?:{_NOT_SEGMENT_END})+?)(?=[{_SEGMENT_SEPARATORS}]|$)")
# G03: X=$(cat .env) / X=`cat .env` / read -r x < .env
_VAR_FROM_FILE = re.compile(
    r"\b(\w+)=[\"']?(?:\$\(|`)\s*(?:cat|head|tail|base64|xxd|grep|awk|sed|"
    + WINDOWS_READERS + r")\s+([^)`]+)[)`]")
_VAR_FROM_REDIRECT = re.compile(r"\bread\s+(?:-\w+\s+)*(\w+)\s*<\s*(\S+)")
# G05: alias name='...'
_ALIAS = re.compile(r"\balias\s+(\w+)=(['\"])(.*?)\2")


def _level_of_path(state: SessionState, path: str) -> str | None:
    entry = state.tainted_paths.get(path)
    return entry.get("level") if entry else None


_MAX_CREATED_PROBES = 64
"""More written paths than this in one action are not asked about one by one:
the rest are simply not recorded as created (a later delete of them asks)."""


def _mark_created(state: SessionState, world: World, written: list[str]) -> None:
    """⚠ WHAT THIS SESSION CREATES IS ITS OWN (docs/112, item C): deleting it,
    or anything under a folder it made, loses nothing that was there before the
    session. A Write, a copy or move destination, a `>` target, a `mkdir`
    operand — ONLY when the World says it is not there yet. `propagate` runs
    before the command does, so an existing file (an overwrite the user may
    have declined, `mkdir -p` of a folder that is there) is never marked. A
    World that cannot say, a variable, a glob or `~` (`/HOME`, not a path on
    disk) marks nothing."""
    exists = getattr(world, "exists", None)
    if exists is None:
        return
    for path in written[:_MAX_CREATED_PROBES]:
        if not path:
            continue
        if (any(c in path for c in "$`*?[") or path == "/HOME"
                or path.startswith(("/HOME/", "/dev/"))):
            continue
        path = _norm_path(path)
        if exists(path) is False:
            state.mark_created(path)


def _created_destinations(state: SessionState, command: str,
                          pairs: list[tuple[int, str, str]]) -> list[str]:
    """A copy's destination is new content the session made. A MOVE's is the
    same content under a new name (the second review round): it is the
    session's only when what it moves was — `mv notes moved` must not make the
    user's notes deletable unasked."""
    made: list[str] = []
    for at, src, dst in pairs[:_MAX_CREATED_PROBES]:     # the rest are not created
        # The verb from the copy's own match, however many blanks lead it — a
        # fixed window after `at` read `mv` after 64 blanks as a copy (the
        # third review round).
        verb = _COPY_VERB.match(command, at)
        if verb is None or verb.group(1) != "mv":
            made.append(dst)
            continue
        bare = _norm_path(src).rstrip("/")
        if any(bare == c or bare.startswith(c.rstrip("/") + "/") for c in state.created_paths):
            made.append(dst)
    return made


def propagate(state: SessionState, action: Action, world: World,
               text_complete: bool = True) -> None:
    """Does this action MOVE labelled data somewhere new?"""
    seq = state.seq

    # ⚠ AUTHORSHIP IS RECORDED HERE, ALONGSIDE PROPAGATION AND SEPARATE FROM IT.
    #
    # WHAT COUNTS: a WRITE, a copy/move DESTINATION, and a `>` redirect target —
    # every shape that brings a path into existence with contents this session
    # chose.
    #
    # ⚠ WHAT DOES NOT, AND EACH EXCLUSION IS A DECISION:
    #   an EDIT      — the file already existed; editing it is not creating it,
    #                  and treating it as authorship would make every file the
    #                  session merely touched "ours", which is the opposite of
    #                  what the deferred rule needs.
    #   an APPEND    — `>>` is the same argument as EDIT. The `>>` form is how a
    #                  payload is added to a file somebody else made, which is
    #                  precisely the case that must NOT read as authored.
    #   a READ       — obviously.
    # Writes made BEFORE the session was untrusted are still recorded: the fact
    # is "who created this", which does not change when trust does. The RULES
    # gate on trust; the fact does not.
    if action.kind is ActionKind.WRITE:
        for path in action.paths:
            state.mark_authored(path)
        _mark_created(state, world, list(action.paths))
    if action.kind is ActionKind.EXEC and action.command:
        pairs = _copy_pairs(action.command, action.cwd)
        redirected = [_abs(dst, action.cwd) for _src, dst in (m.groups() for m in _redirect_matches(
            _TRUNCATING_REDIRECT, _TRUNCATING_VERB, action.command))]
        for dst in [dst for _pos, _src, dst in pairs] + redirected:
            state.mark_authored(dst)
        written = _created_destinations(state, action.command, pairs) + redirected
        # ⚠ A DOWNLOAD IS OUTSIDE CONTENT, WHOEVER WROTE THE FILE (docs/112).
        # Running one keeps the verdict it had before that pass
        # (`outside_content`), so the file is recorded apart from authorship.
        #
        # One seed, one follow (the round-6 reviews). Three kinds of outside
        # content enter here, and `carried_downloads` follows every copy of
        # them — a chain, a folder's `dst/basename`, a `>`/`tee`/`of=`/`-o`
        # write, a pipeline stage — in one linear pass:
        #   · what a fetch WROTE (`downloaded_files`: curl -o, wget, gh … > f);
        #   · what a clone / host pull / release download wrote (`pulled`,
        #     item 1): a folder cannot be enumerated, so it loses track;
        #   · a file OUTSIDE the roots this command READS (`outside` SOURCES,
        #     item 3): seeded so the copy's destination is followed, defeating
        #     the authorship that used to launder it; an unreadable or folder
        #     source loses track (fail closed).
        downloaded = downloaded_files(action.command, action.cwd)
        pulled = pulled_downloads(action.command, action.cwd)
        outside = copied_outside_files(action.command, action.cwd,
                                       action.workspace_roots, world, state)
        seed = (set(state.downloaded_paths) | set(downloaded)
                | set(pulled.paths) | set(outside.paths))
        carried = carried_downloads(action.command, action.cwd, seed)
        for path in list(downloaded) + list(pulled.paths) + list(carried.paths):
            state.mark_downloaded(path)
        if pulled.lost or carried.lost or outside.lost:
            state.lose_track_of_downloads()
        if _MKDIR.search(action.command):
            mask, _parsed = code_mask_checked(action.command)
            written += [path for _verb, path in _deleted_by(
                action.command, action.cwd, _MKDIR,
                lambda at: at >= len(mask) or bool(mask[at]))]
        _mark_created(state, world, written)

    # ---- Rule set A: exact, the bytes are recognised ----
    if action.kind in (ActionKind.WRITE, ActionKind.EDIT):
        carries = carries_secret(action.content, state)
        for dest in action.paths:
            # Writing to a credential-shaped path WHILE holding secrets is a
            # copy, not a coincidence. This is an addition to docs/02's rule
            # set A, and it is what separates I02 from acceptance criterion A9:
            #   I02  writes debug/.env      -> a credential path -> exact -> DENY
            #   A9   writes a Dockerfile    -> ordinary path    -> derived -> ASK
            # Without it, a verbatim copy that happens to rename the file would
            # be judged more leniently than the same bytes in the same file.
            if carries or (state.holds_secret and CREDENTIAL_PATHS.search(dest)):
                state.taint(dest, "exact", seq)

    if action.kind is ActionKind.EXEC and action.command:
        # STRUCTURE, every line below: which operand is copied, redirected,
        # staged or assigned. All of it is "what does this command do", none of
        # it is "what does it carry" — so all of it reads executed_text().
        #
        # Measured against the corpus, stripping here removes only extractions
        # that were already wrong:
        #   A01/N04  _GIT_ADD captured `&& git commit -m "AKIA_TEST_A01 …"`
        #            and treated a commit MESSAGE as a list of staged paths.
        #   I02      _REDIRECT read the `<` of `<noreply@anthropic.com>` in a
        #            Co-Authored-By trailer as a redirect operator.
        # Nothing real is lost; the mangled taint key `/repo/debug/.env"),`
        # came from exactly this pattern reading Python source as shell.
        # Raw, for the reason given in check_sinks: stripping unbalances quotes
        # and the scanner then fails safe to all-code, buying nothing.
        cmd = action.command
        prop_mask = structure_mask(cmd, text_complete)

        def _code_pairs(matches):
            """(src, dst) only where the shell will actually run the verb."""
            return [m.groups() for m in matches
                    if m.start() < len(prop_mask) and prop_mask[m.start()]]

        # A copy's operands come from _copy_pairs, which already resolves both
        # sides against cwd; a redirect's still come from its own pattern. Both
        # are gated on code position for the same reason — a `cp` written inside
        # a heredoc copies nothing.
        copies = [(src, dst) for pos, src, dst in _copy_pairs(cmd, action.cwd)
                   if pos < len(prop_mask) and prop_mask[pos]]
        redirects = [(_abs(src, action.cwd), _abs(dst, action.cwd))
                      for src, dst in _code_pairs(_redirect_matches(
                          _REDIRECT, _REDIRECT_VERB, cmd))]
        for src, dst in copies + redirects:
            level = _level_of_path(state, src)
            if level is None and CREDENTIAL_PATHS.search(src):
                level = "exact"
            if level:
                state.taint(dst, level, seq)

        for match in (m for m in _GIT_ADD.finditer(cmd)
                       if m.start() < len(prop_mask) and prop_mask[m.start()]):
            for token in match.group(1).split():
                path = _abs(token, action.cwd)
                if _level_of_path(state, path):
                    if path not in state.staged_secret_files:
                        state.staged_secret_files.append(path)

        # G03 — a shell variable filled from a tainted file, used a call later.
        for pattern in (_VAR_FROM_FILE, _VAR_FROM_REDIRECT):
            for name, src in _code_pairs(pattern.finditer(cmd)):
                src_path = _abs(src.split()[0] if src.split() else src, action.cwd)
                if (_level_of_path(state, src_path)
                        or CREDENTIAL_PATHS.search(src_path)):
                    state.tainted_vars[name] = seq

        # G05 — record the definition; the danger surfaces at invocation.
        for name, _quote, body in _ALIAS.findall(cmd):
            state.aliases[name] = body

    # ---- Rule set B: session inheritance. The important one. ----
    # Five lines that catch what content matching structurally cannot: base64,
    # hex-in-CSS, a paraphrased design doc. You cannot obfuscate WHEN a file was
    # written. state.taint() already refuses to downgrade an exact label.
    if state.holds_secret and action.kind in (ActionKind.WRITE, ActionKind.EDIT):
        for dest in action.paths:
            state.taint(dest, "derived", seq)
