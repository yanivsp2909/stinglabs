# Labels — the only ground truth this project has about its own friction

`prompt_labels.json` lives here, written by `tools/label_prompts.py`.

## Why it is in git

A4 counts attacks blocked and A5 counts normal tasks blocked. Neither says
anything about whether an **ASK** was wanted. An ASK is a prompt, not a block,
and a prompt its owner did not want is the cost side of this product — the thing
that decides whether the guard stays switched on. Every friction number so far
has counted prompts, which measures volume, not whether they were worth showing.

Only one person can supply that judgement, it is about their own sessions, and
nobody will supply it twice. Same rule as `results/`: **a number that cannot name
the artifact that produced it is not evidence.**

## What is in the file, and what deliberately is not

```json
{ "version": 2, "seed": 20260809,
  "labels": {
    "rule:untrusted_local:git_commit": {
        "unit": "rule", "rule_id": "untrusted_local:git_commit", "volume": 51,
        "history": [ {"label": "worth",     "at": "2026-08-09T09:41:26+03:00"},
                     {"label": "not_worth", "at": "2026-08-09T09:44:02+03:00"} ] } } }
```

⚠ **v1 entries had no `at` and history was a bare list of strings.** The file was
also written with `sort_keys=True`, so insertion order was destroyed — "show me
my most recent label" was simply unanswerable from a v1 file, and `recent` says
so rather than presenting an arbitrary order as an answer. v1 entries are still
read.

**No command text, no paths, no reasons.** The key is a one-way digest, so this
file needs no redaction pass of its own — which is the point, because it is
committed and the logs it was derived from are not. A test enforces it.

`history` is a list, not a value: a re-asked item appends, so a change of mind is
visible rather than overwritten. `report` uses the **last** entry and counts the
disagreements separately.

## The unit: a rule, not a prompt

The default unit is the **rule**, with three examples shown under it, and rules
come **biggest first**. That is not just shorter — it is stoppable: 4 judgements
cover 71.5% of all prompts, 8 cover 84.1%, and 12 of the 27 rules have a single
prompt each. `report` states the coverage you actually bought, so stopping early
still produces a number that means something. `--unit prompt` gives the old
per-item behaviour when one rule is worth taking apart.

`m` (mixed) is a real answer. A rule that is right sometimes and wrong sometimes
is the most actionable thing this can find — it says NARROW this rule rather than
remove it — so it is reported separately and kept out of the precision figure,
where it would otherwise be averaged into invisibility.

## The key, and why it is not a seq number

    key = "cmd:" + (original_sha256 or command_sha256)      when there is a command
          "act:" + sha256(kind, rule_id, home-normalised paths)   when there is not

`seq` is a position in a file that grows, so a label keyed to one silently
re-points at a different action. The digest is already inside the hashed body, so
the record itself attests it.

⚠ **`original_sha256` comes first for a measured reason.** The vendored fixture is
redacted, and `redact_logs.py` re-addresses every record onto its REDACTED bytes
— so a fixture record's `command_sha256` is the digest of text that never ran.
Under this key all 134 fixture prompt keys are found in the live log; under plain
`command_sha256`, **2 of 134**. Labels made against either population are valid
for the other.

## Judging fairly — where the context comes from

`tools/session_context.py` reads the agent's own transcript at
`~/.claude/projects/<project>/<session-id>.jsonl` and shows **what you asked
for**, next to what the agent then ran. Without it the tool showed the agent's
half of the conversation only, and the judgement is entirely about the other
half.

⚠ **The transcript is not evidence and is never treated as such.** It has no hash
chain and can be edited freely. It is there to help a person remember a moment;
the log remains the record of what happened. Two routes, and the display says
which was used: an exact command-digest match, or the last human turn at or
before the record's timestamp for the third of prompts that have no command.

## Reading the number

`report` prints self-consistency before precision, on purpose. If the re-asks
disagree 15% of the time, the precision figure has no third digit — read it to no
more precision than the judge has.
