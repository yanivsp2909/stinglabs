#!/usr/bin/env bash
# Build the archive you send somebody who has no GitHub account.
#
#     bash tools/make_release.sh v0.9-some-tag
#
# ⚠ WHAT SHIPS, AND WHY IT IS NOT THE REPO. The checkout is 32 MB; the guard
# needs 1.6 MB of it. Tests, the corpus, the vendored fixture and PROGRESS.md
# are most of the bytes and none of them run the guard — and the fixture in
# particular is redacted session data that has no business on a stranger's disk.
# `place.PAYLOAD` already names exactly what an install copies; this ships that,
# plus the three files a person needs to run it.
#
# ⚠ AND IT WRITES A VERSION FILE, WHICH IS THE WHOLE REASON AN ARCHIVE IS
# ACCEPTABLE. `git describe` needs a `.git`; a tarball has none, so an unpacked
# release reported `nogit-<hash>` and a receiver could not tell 0.7 from 0.8.
# With VERSION it reports `v0.8-retention-measured-a96e98e1` — the same shape a
# clone reports, and the content hash still decides if the label lies.
set -euo pipefail

TAG="${1:?usage: make_release.sh <tag>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${2:-$ROOT/dist}"
NAME="sting-$TAG"

git -C "$ROOT" rev-parse "$TAG" >/dev/null 2>&1 || {
  echo "no such tag: $TAG" >&2; exit 2; }

mkdir -p "$OUT"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# ─────────────────────────────────────────────────────────────────────────────
# ⚠ THE PAYLOAD IS READ FROM `place.PAYLOAD` AT THE TAG, NEVER RESTATED HERE.
#
# It used to be a hardcoded list on the next line, and the two drifted the day
# the daemon landed. Measured, on an archive built from HEAD:
#
#     place.PAYLOAD   core adapters daemon shipper tools hook_entry.py sting_hook.py
#     this script     core adapters       shipper tools hook_entry.py
#
# So the archive was missing `daemon/` and `sting_hook.py` — and `sting_hook.py`
# is the file `install.py` points EVERY AGENT'S HOOK AT. The install completed,
# exited 0, wrote the hook config, and left a hook command naming a file that
# was not on disk. Only preflight noticed.
#
# ⚠ AT THE TAG, not at HEAD: an archive of v0.9 must ship what v0.9's installer
# copies. Reading today's list would build yesterday's release against
# tomorrow's manifest, which is the same drift with a longer fuse.
PAYLOAD="$(git -C "$ROOT" show "$TAG:installer/place.py" | python3 -c '
import ast, sys
tree = ast.parse(sys.stdin.read())
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
            getattr(t, "id", None) == "PAYLOAD" for t in node.targets):
        print(" ".join(ast.literal_eval(node.value)))
        break
else:
    sys.exit("could not find PAYLOAD in installer/place.py at this tag")
')"
[ -n "$PAYLOAD" ] || { echo "empty payload — refusing to build" >&2; exit 2; }

# The runtime payload, plus what a human needs to start it.
# ⚠ ONE LIST FEEDS BOTH THE ARCHIVE AND THE CHECK, AND IT DID NOT USED TO.
# The extras below — install.py, installer/, requirements.txt, README.md — were
# passed to `git archive` but were NOT in the loop that verifies what landed,
# which only walked $PAYLOAD. That is the `daemon/` defect exactly, for a worse
# file set: `install.py` IS THE ENTRY POINT, and `installer/` is the package it
# imports (place, prepare, enrol, detect, console, messages, recorded,
# supervisor) while `place.PAYLOAD` names only `installer/cursor_bridge.ps1`.
# A tag where any of them was renamed or gained `export-ignore` would have built
# two archives, passed the census, written both checksums, printed the success
# banner and exited 0 — and the receiver would get ModuleNotFoundError from the
# first command the runbook tells them to type.
SHIPPED="$PAYLOAD install.py installer requirements.txt README.md"
# ⚠ NOTICE ONLY WHERE THE TAG HAS ONE. It arrived with docs/85 (the borrowed
# pattern table's MIT/Apache attribution). A rehearsal from an earlier tag must
# still build, and `git archive` refuses a pathspec the tag does not carry —
# so it is asked of the TAG, not of the working tree, like everything else here.
if git -C "$ROOT" cat-file -e "$TAG:NOTICE" 2>/dev/null; then
  SHIPPED="$SHIPPED NOTICE"
fi

git -C "$ROOT" archive --format=tar "$TAG" $SHIPPED \
  | (cd "$STAGE" && mkdir -p "$NAME" && tar xf - -C "$NAME")

printf '%s\n' "$TAG" > "$STAGE/$NAME/VERSION"

# ⚠ THE POSITIVE ARCHIVE MARKER, written AFTER `git archive` for the same reason
# VERSION is — a `git archive` output, and therefore a git checkout, can never
# carry it. `install.py --cleanup-after-install` REFUSES to delete a source that
# does not hold this manifest with its sentinel (installer/cleanup.py). It is the
# opt-in self-delete's positive signal; the absence of `.git` is only its second,
# independent check. Identity-safe: sentinel is kebab-case, tag is a version.
printf '{"sentinel":"sting-release-archive","tag":"%s","built_by":"tools/make_release.sh"}\n' \
  "$TAG" > "$STAGE/$NAME/.sting-release"

# ⚠ AND IT IS CHECKED, BECAUSE DERIVING THE LIST IS NOT THE SAME AS SHIPPING IT.
# `git archive` skips a path that does not exist at the tag without complaining,
# so a name that was added later would still build a quietly incomplete archive.
# This is the assertion that would have caught the drift.
for item in $SHIPPED; do
  [ -e "$STAGE/$NAME/$item" ] || {
    echo "REFUSING TO SHIP: '$item' is shipped by this script and is not in" >&2
    echo "  the archive. An install from this would either write a hook config" >&2
    echo "  pointing at a file that is not there, or fail to import at all." >&2
    exit 2; }
done

# ⚠ AND THE STAGED BYTES ARE CHECKED FOR SOMEBODY'S NAME BEFORE THEY BECOME A
# TARBALL. This used to be a test that scanned the working tree against the
# identity of whoever's machine ran it — so on a runner it looked for `runner`,
# and an archive built anywhere but one specific laptop passed while carrying a
# developer's username. Two halves now run: a CENSUS derived from the git
# history (same on every machine, and it REFUSES on a shallow clone) and the
# SHAPE list, which is the only half that can see a username.
python3 "$ROOT/tools/identity_census.py" --scan "$STAGE/$NAME" || {
  echo "REFUSING TO SHIP: the staged archive carries an identity (above)." >&2
  echo "  Replace it with a placeholder — '<name>', '/Users/dev'." >&2
  exit 2; }

# ─────────────────────────────────────────────────────────────────────────────
# ⚠ TWO ARCHIVES, ONE STAGING. EVERY CHECK ABOVE HAS ALREADY RUN, ONCE, OVER
# THE BYTES BOTH OF THESE ARE PACKED FROM.
#
# `.tar.gz` needs nothing installed anywhere — Windows has shipped bsdtar since
# 2018. But DOUBLE-CLICKING a `.tar.gz` in Explorer does nothing useful and a
# `.zip` extracts, and that is a wall for a stranger on Windows at the moment we
# least want one: before they have run anything.
#
# ⚠ NOT TWO `git archive` INVOCATIONS. Two builds are two chances to diverge,
# and the divergence would be invisible until somebody on Windows got a
# different product from somebody on macOS. `tests/test_both_archives_are_one_product.py`
# unpacks both and compares them file by file on every run.
#
# ⚠ AND NONE OF THE BUILD HOST'S OWN METADATA GOES IN. On a Mac that gives
# staged files an extended attribute (provenance, quarantine, Finder), bsdtar
# writes an AppleDouble `._*` entry beside each one AND the attribute as a pax
# header. The .zip has neither, and on Linux a `._*` file unpacks as junk.
# COPYFILE_DISABLE=1 stops the first and --no-xattrs the second; each alone
# leaves the other (measured, docs/66). GNU tar ignores the first and knows the
# second. `--no-mac-metadata` would also stop the first on a Mac, and GNU tar
# refuses it, which would fail every build on Linux.
COPYFILE_DISABLE=1 tar -czf "$OUT/$NAME.tar.gz" --no-xattrs -C "$STAGE" "$NAME"
python3 "$ROOT/tools/pack_zip.py" "$STAGE" "$NAME" "$OUT/$NAME.zip"

# ⚠ ONE CHECKSUM FILE COVERING BOTH, in `shasum -c` format — one line per
# archive, so a receiver checks whichever they took and the file is the same
# file either way. It is generated from the finished archives, never typed.
( cd "$OUT" && shasum -a 256 "$NAME.tar.gz" "$NAME.zip" > "$NAME.sha256" )

echo "built   $OUT/$NAME.tar.gz  ($(du -h "$OUT/$NAME.tar.gz" | cut -f1))"
echo "        $OUT/$NAME.zip     ($(du -h "$OUT/$NAME.zip" | cut -f1))"
echo "digest  $OUT/$NAME.sha256  (both, one line each)"
cat "$OUT/$NAME.sha256" | sed "s/^/          /"
echo
echo "Send the checksum file and ONE archive. What the receiver runs, in full:"
echo
echo "  macOS / Linux"
echo "    shasum -a 256 -c --ignore-missing $NAME.sha256"
echo "    tar xzf $NAME.tar.gz && cd $NAME"
echo "    python3 install.py"
echo
echo "  Windows  — the .zip, because Explorer opens it"
echo "    Get-FileHash $NAME.zip -Algorithm SHA256   # compare to $NAME.sha256"
echo "    tar -xf $NAME.zip && cd $NAME              # or double-click it"
echo "    python install.py"
echo
echo "⚠ WITHOUT --ignore-missing, 'shasum -c' prints FAILED for the archive you"
echo "  did NOT take and EXITS 1 — measured, and alarming at exactly the wrong"
echo "  moment. If your shasum lacks that flag:"
echo "      grep $NAME.zip $NAME.sha256 | shasum -a 256 -c -"
echo ""
echo "⚠ TWO ARCHIVES, ONE PRODUCT: they are packed from the same staged bytes,"
echo "  and install.py is the only thing inside either that anyone runs."
echo
echo "⚠ A checksum proves the bytes are the bytes you sent. It proves NOTHING"
echo "  about whether YOU are who they think — anyone who can replace the"
echo "  archive can replace the digest beside it. Send the digest over a"
echo "  different channel than the archive, and read the section in"
echo "  docs/distribution-decision.md before treating this as supply-chain safe."
