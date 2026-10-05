#!/bin/bash
# Confirms nothing outside this engine checkout was created or changed.
# Run before AND after every numbered step. Exits non-zero if anything drifted.
#
#   STING_SAFETY_NEIGHBOURS="$HOME/src/repo-a:$HOME/src/repo-b" ./safety_check.sh
#
# Each neighbour is a git repository that a session in this checkout must not
# touch: its working tree and its HEAD are pinned on the first run (which fails
# on purpose, recording the baseline) and compared on every run after.
#
# ─────────────────────────────────────────────────────────────────────────────
# ⚠ EVERY ARM STATES ITS OWN PRECONDITION AND FAILS ON IT.
#
# A check that reports the WRONG failure is worse than one that reports none,
# because it spends the reader's trust. This file has now done that once: the
# $HOME arm ran `git status --porcelain` on $HOME, which worked only because
# $HOME happened to contain a stray `.git` in which everything was untracked.
# When that repo was removed by an ordinary `rm -rf ~/.git`, the arm printed
# "68 deletions" — a diff computed against nothing, describing a catastrophe
# that had not happened. The baseline was intact; the measurement was empty.
#
# So no arm here diffs before proving it CAN measure. A missing baseline, a path
# that is not a repository, a listing that came back empty — each says which,
# by name, and fails.
# ─────────────────────────────────────────────────────────────────────────────
set -u
fail=0

ENGINE="$(cd "$(dirname "$0")" && pwd)"
BASELINES="${STING_SAFETY_BASELINES:-/tmp/sting-safety}"
mkdir -p "$BASELINES"

# ─────────────────────────────────────────────────────────────── preconditions

need_baseline() {
  # ⚠ A MISSING BASELINE RECORDS ITSELF AND STILL FAILS. Recording it silently
  # would mean the first run after adding a repo passes while comparing against
  # a file it just wrote — a green tick for a measurement that never happened.
  # Failing once forces the operator to acknowledge the new baseline.
  local name="$1" baseline="$2"
  if [ ! -f "$baseline" ]; then
    echo "  ?? $name — NO BASELINE at $baseline. Recording it now; this run"
    echo "     fails on purpose so a first baseline is never mistaken for a"
    echo "     comparison. Re-run to verify against it."
    return 1
  fi
  return 0
}

need_repo() {
  local name="$1" repo="$2"
  if ! git -C "$repo" rev-parse --git-dir >/dev/null 2>&1; then
    echo "  FAIL $name — $repo is NOT A GIT REPOSITORY."
    echo "       This arm cannot measure anything. It is not reporting drift;"
    echo "       it is reporting that it is blind."
    fail=1
    return 1
  fi
  return 0
}

# ────────────────────────────────────────────────────── working-tree drift

check() {
  local name="$1" repo="$2" baseline="$3"
  need_repo "$name" "$repo" || return
  local now; now=$(mktemp)
  git -C "$repo" status --porcelain > "$now" 2>/dev/null
  if ! need_baseline "$name" "$baseline"; then
    cp "$now" "$baseline"; fail=1; rm -f "$now"; return
  fi
  if diff -q "$baseline" "$now" >/dev/null 2>&1; then
    echo "  OK  $name — unchanged ($(wc -l < "$now" | tr -d ' ') entries)"
  else
    echo "  FAIL $name — DRIFTED:"
    diff "$baseline" "$now" | sed 's/^/       /'
    fail=1
  fi
  rm -f "$now"
}

# ───────────────────────────────────────────────────────────── committed drift

# A COMMIT IS A CHANGE, AND `git status` CANNOT SEE ONE.
#
# `check` compares `git status --porcelain`, which returns to empty the moment a
# change is committed. A session that edited a neighbour and then committed it
# left this printing "unchanged (0 entries)" while the neighbour had moved by two
# commits. The check was honest about what it measured; the header was not.
#
# ⚠ SO EVERY NEIGHBOUR GETS BOTH ARMS: a working-tree arm and a HEAD arm.
check_head() {
  local name="$1" repo="$2" baseline="$3"
  need_repo "$name HEAD" "$repo" || return
  local now; now=$(git -C "$repo" rev-parse HEAD 2>/dev/null)
  if [ -z "$now" ]; then
    echo "  FAIL $name HEAD — repository has no commits yet; nothing to pin."
    fail=1; return
  fi
  if ! need_baseline "$name HEAD" "$baseline"; then
    echo "$now" > "$baseline"; fail=1; return
  fi
  if [ "$now" == "$(cat "$baseline")" ]; then
    echo "  OK  $name HEAD — unchanged (${now:0:8})"
  else
    echo "  FAIL $name HEAD — MOVED: $(cut -c1-8 < "$baseline") -> ${now:0:8}"
    echo "       if authorised, re-baseline:  git -C $repo rev-parse HEAD > $baseline"
    fail=1
  fi
}

# ──────────────────────────────────────────────────── files appearing at $HOME

# ⚠ A LISTING, NOT A REPOSITORY, AND THE REASON MATTERS.
#
# The purpose of this arm was always "notice files appearing outside the
# project". It achieved that through `git status --porcelain` on a repo at $HOME
# in which everything was untracked — so every entry showed as `??` and the
# output was, in effect, a directory listing produced by an accident. Nobody
# chose that mechanism; it was inherited from a stray `git init`.
#
# Deleting `~/.git` was ordinary cleanup and it took the check with it. So the
# mechanism is now the thing it was always pretending to be: a snapshot of the
# top-level entries of $HOME, which depends on nothing that can be removed by
# tidying up.
#
# WHAT IT COVERS
#   a new file or directory appearing at the top level of $HOME
#   an existing top-level entry disappearing
#
# ⚠ WHAT IT DOES NOT COVER, AND THIS IS A REAL LIMIT RATHER THAN A FOOTNOTE
#   an EDIT to a file that already exists — a listing sees names, not contents
#   anything created DEEPER than the top level, e.g. ~/Documents/notes/new.txt
#
# The old arm did not cover those either: `git status --porcelain` collapses an
# untracked directory to a single `?? .config/` line and never descends. So this
# is the same coverage, obtained deliberately instead of by luck. If edit
# detection is ever needed, it needs hashes, and it should be added knowing that
# hashing $HOME is a different and much larger job.
check_listing() {
  local name="$1" dir="$2" baseline="$3"
  if [ ! -d "$dir" ]; then
    echo "  FAIL $name — $dir is not a directory. This arm is blind."
    fail=1; return
  fi
  local now; now=$(mktemp)
  ls -A "$dir" 2>/dev/null | LC_ALL=C sort > "$now"
  if [ ! -s "$now" ]; then
    # ⚠ THE FAILURE THAT STARTED ALL THIS. An empty measurement must never be
    # diffed against a full baseline — that reports every entry as deleted.
    echo "  FAIL $name — the listing came back EMPTY for $dir."
    echo "       Refusing to diff an empty measurement against a baseline;"
    echo "       that would report every entry as deleted. Fix the read first."
    fail=1; rm -f "$now"; return
  fi
  if ! need_baseline "$name" "$baseline"; then
    cp "$now" "$baseline"; fail=1; rm -f "$now"; return
  fi
  if diff -q "$baseline" "$now" >/dev/null 2>&1; then
    echo "  OK  $name — unchanged ($(wc -l < "$now" | tr -d ' ') top-level entries)"
  else
    echo "  FAIL $name — top-level entries CHANGED:"
    diff "$baseline" "$now" | sed 's/^/       /'
    echo "       (a listing sees names appearing and disappearing, never edits)"
    fail=1
  fi
  rm -f "$now"
}

# ──────────────────────────────────────────────────────────────────── the arms

echo "Safety check — nothing outside $ENGINE may change"

IFS=':' read -r -a NEIGHBOURS <<< "${STING_SAFETY_NEIGHBOURS:-}"
for repo in ${NEIGHBOURS[@]+"${NEIGHBOURS[@]}"}; do
  [ -n "$repo" ] || continue
  name=$(basename "$repo")
  check      "$name" "$repo" "$BASELINES/before-$name.txt"
  check_head "$name" "$repo" "$BASELINES/before-$name-head.txt"
done
check_listing "\$HOME" "$HOME" "$BASELINES/before-home-listing.txt"

# Everything this repo tracks must be inside the checkout by construction
# (it is this directory), so just report what is here.
echo "  --  this checkout: $(git -C "$ENGINE" status --porcelain . | wc -l | tr -d ' ') uncommitted entries"

[ $fail -eq 0 ] && echo "PASS" || { echo "STOP — something outside this checkout changed."; exit 1; }
