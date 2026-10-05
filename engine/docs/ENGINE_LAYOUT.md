# Where the engine's rules live

`core/engine.py` was one 7,281-line file, so nearly every rule change or bug
fix edited it and two agents working at once collided on it. It is now ten
modules, split by responsibility. The split moved code and changed none of it:
every function, class and constant is `ast.dump`-equal to what it was.

`core/engine.py` still answers for all of it: `decide()` lives there, and every
name that ever lived in it is importable from it, private ones included. A name
is **looked up in the module that uses it**, so a test that monkeypatches one
must patch it there (`tests/engine_source.readers(name)` says where).

## The modules, bottom to top

Each module imports only from the ones above it in this list, never from
`engine.py`, so a change to a lower module can be read without the higher ones.

| module | lines | what it holds |
|---|---|---|
| `command_text.py` | 1,106 | How a command is read: segments and `_SEGMENT_END`, words and quoting (`_bash_unquote`, ANSI-C), paths (`_abs`, `_norm_path`, `is_inside_project`), redirects, copy operands, `$VAR` assignment and expansion, the text that executes (`executed_text`, the commit-message strip, `_structure_text`), the git command shapes (`_GIT_COMMIT`, `_GIT_PUSH`, global options), `_verb`, `span_evidence`, `mentions_path`. No rule decides anything here. |
| `credentials.py` | 421 | What is sensitive: `CREDENTIAL_PATHS`, `CONFIDENTIAL_PATHS`, `DEPENDENCY_PATHS`, `REFERENCE_DATA`, `PLANTED_CONTENT`; value fingerprints, org-policy prints, `carries_secret`, the environment and the canary. |
| `globbing.py` | 824 | Brace and glob expansion for recognition: which credential names a word such as `.e*` or `.{e,x}nv` could expand to (`_expanded_form`, `_credential_scan_texts`). |
| `irreversible.py` | 1,046 | Mechanism 1: deletion targets and **cd folding** (`_deleted_by`, `_cd_bases`, `_cd_resolved_credential_paths`), regenerable artifacts, declared scratch, a truncated credential file, `is_irreversible`; and row f, the catastrophic roots: `deletes_a_catastrophic_root`, the **find sweep** (`find_destroys_a_catastrophic_root`), `writes_a_raw_block_device`. |
| `egress.py` | 645 | **Network egress**, where data goes: `_URL`, `/dev/tcp` hosts, inbound reads that send nothing (`_inbound_read`, curl/wget read flags), `_destinations`, `DEFAULT_EXPECTED_HOSTS` and `_is_expected`, a push's pre-existing remote, the exit phrase. |
| `guard_runs.py` | 365 | **What RUNS a guard part no agent may run** (docs/108 §6): the one-shot override (`tools/allow_once.py`), read in linear time (`Runs`, `override_run`). The committed regexes are in tests/test_the_override_check_is_linear.py as the reference every segment start is compared with. |
| `guard_floor.py` | 737 | **guard_selfmod and the installed-guard floor** (item C, docs/104): the guard_selfmod patterns (`_GUARD_SELFMOD`, `_KILL`, `_GUARD_PROCESS`, `_STING_PERSISTED`, `CONFIG_SELFMOD_PATHS`), the write readers (tee, sed -i, curl, wget, rsync, patch, dd, truncate), `touched_guard_part`, `_guard_floor`, and `_DECISION_RANK`, which the org-policy ladder shares. |
| `sources.py` | 708 | Labelling: `mark_sources`, which credential paths a command mentions (`_paths_mentioned_in`), a commit that reads itself back, and `propagate` (copies, redirects, variables, aliases, `git add`). |
| `sinks.py` | 822 | The exits: `check_sinks` and `_sink_hit` (every sink, the **git sinks** included), the network, DNS, pipe-to-shell, clipboard, git-hook, shell-profile and deferred-execution patterns, `_pipes_into_interpreter`, a secret in argv (`_secret_in_argv_span`), and Mechanism 3 (`weakens_security`). |
| `secret_ladder.py` | 417 | **The secret ladder** (`_secret_level`, `_staged_secret_level`, `_exact_source`) and **the reasons** it gives (`_exact_reason`, `_secret_origin`, `_held_secret_clause`, `_untrusted_origin`). |
| `engine.py` | 828 | `decide()`, **the verdict body** (`_verdict_body`), `_verdict_for`, `fallback_verdict`, the org-policy severity ladder, and the re-export of every name above. |

## Which files a task touches

| task | files |
|---|---|
| a deletion or `cd` folding rule | `irreversible.py` (reads words and paths through `command_text.py`) |
| the find sweep, a catastrophic root | `irreversible.py` |
| network egress, an expected host, an inbound read | `egress.py`; the sink that fires is `sinks.py` |
| the secret ladder or its reason text | `secret_ladder.py` |
| a git sink (`git commit`, `git push`) | the shapes in `command_text.py`, the sink in `sinks.py`, the remote check in `egress.py` |
| guard_selfmod, the installed-guard floor | `guard_floor.py`; the guard_selfmod sink itself is a branch of `sinks._sink_hit` |
| what counts as running a guard part (allow-once) | `guard_runs.py`; the floor wraps what it finds |
| what counts as a credential path | `credentials.py`; its glob and brace spellings are `globbing.py` |
| how the verdict is assembled, a new rule's order | `engine.py` |

Shared by everything: `core/shell_scan.py` (840 lines, unsplit: the masking
and quoted views every module reads through), `core/types.py`,
`core/rule_names.py`.

## Rules for the next change

- A new name goes in the module whose responsibility it is. If it needs a name
  from a module below, import it; if it needs one from above, it is in the
  wrong module.
- A module-level cache or pattern has exactly one home. Nothing rebinds another
  module's global.
- `tests/test_hook_entry.py` pins what the engine may import: a new module is
  added to that allowlist and to `tests/engine_source.MODULES`, and nowhere
  else.
