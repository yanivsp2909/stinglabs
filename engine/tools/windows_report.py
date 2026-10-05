#!/usr/bin/env python3
"""Group a Windows test run by CAUSE, and map each cause to one of the seven
known porting sites — or to none.

⚠ THE "NONE" BUCKET IS THE POINT. Seven sites were named by reading the code.
Anything that fails for a reason outside those seven is something nobody
predicted, and a list of predicted breakages is worth much less than a list of
unpredicted ones. That bucket is Phase 3's real risk.

    python3 tools/windows_report.py windows-results.xml

Reads pytest's JUnit XML so the grouping is over structured results rather than
scraped console text.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

# ⚠ AND THIS LINE IS ITSELF A WINDOWS FINDING. The first run of this script on
# the runner died with UnicodeEncodeError: cp1252 cannot encode U+26A0 — the
# `⚠` this codebase uses in every comment, every deny reason, and every
# installer message. Windows' default console codec is not UTF-8, so any of
# those reaching stderr on Windows raises. That is an EIGHTH site, and nobody
# named it. See docs/26-windows-phase-0.md.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# The seven sites from docs/windows-redecision.md, each with the SIGNATURE a
# failure caused by it leaves behind. A signature is a claim: if a failure
# matches it, that failure is evidence for that site.
SITES = [
    ("1 · fcntl at module scope",
     r"No module named 'fcntl'|ModuleNotFoundError.*fcntl|LockUnavailable"),
    ("2 · CREDENTIAL_PATHS anchored on /",
     r"holds_secret|CREDENTIAL_PATHS|mark_secret|secret_origin"),
    # ⚠ `workspace_roots` REMOVED for the same reason: it matched 11 adapter
    # tests whose fixtures use POSIX `/tmp`, which Windows resolves to `D:\tmp`
    # — a harness path shape, not the boundary check.
    ("3 · is_inside_project",
     r"is_inside_project\(|write_outside|outside the project"),
    # ⚠ `absolute` REMOVED. It matched 18 `test_extension_contract` failures
    # whose real cause is a Node ESM URL scheme error, and attributed them to a
    # site that was already fixed. THE THIRD prose-matching false positive in
    # this tool. A signature must name something only that site produces.
    ("4 · _abs",
     r"\b_abs\(|resolve_path\("),
    ("5 · basename via rsplit\"/\"",
     r"rsplit\('/'\)|basename|PurePosixPath"),
    ("6 · STING_ROOTS split on \":\"",
     r"STING_ROOTS|split\(':'\)|roots_env"),
    ("7 · no case normalisation",
     r"casefold|lower\(\)|case-insensit|\.ENV"),
]

# Failures that are about the TEST HARNESS rather than the engine. Called out
# separately because "the test shells out to /bin/sh" is not a porting site and
# must not inflate the count of real defects.
HARNESS = [
    ("harness · POSIX shell or tool",
     r"/bin/sh|/bin/bash|\bsh: |No such file or directory: '(sh|bash|git|chmod)'"
     r"|WinError 2"),
    ("harness · POSIX-only permissions",
     r"chmod|0o600|st_mode|PermissionError"),
    ("harness · path separator in a fixture",
     r"'/tmp|\\\\tmp|assert '/"),
]


def classify(text: str) -> str:
    for name, pattern in SITES:
        if re.search(pattern, text, re.IGNORECASE):
            return name
    for name, pattern in HARNESS:
        if re.search(pattern, text, re.IGNORECASE):
            return name
    return "⚠ UNPREDICTED — maps to NONE of the seven"


def main(path: str) -> int:
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError) as exc:
        print(f"## Windows measurement\n\n**No results to read** ({exc}).\n\n"
              f"If the suite did not collect, Phase 0 has not landed.")
        return 0

    total = passed = 0
    groups: dict[str, list[str]] = defaultdict(list)
    for case in tree.iter("testcase"):
        total += 1
        problem = case.find("failure") if case.find("failure") is not None \
            else case.find("error")
        if problem is None:
            passed += 1
            continue
        # ⚠ THE ASSERTION, NOT THE CAPTURED OUTPUT. Classifying the whole blob
        # matched `test_check_only…` as site 2, because the failure text
        # contains install.py's Windows refusal banner — which now literally
        # names CREDENTIAL_PATHS. A classifier whose false positive is the
        # sentence describing the defect: the third time this shape has appeared
        # in this repo, and the reason signatures are matched against the
        # message plus the TAIL of the traceback rather than everything pytest
        # captured on the way there.
        text = problem.text or ""
        blob = (problem.get("message") or "") + "\n" + text[-400:]
        name = f"{case.get('classname', '')}::{case.get('name', '')}"
        groups[classify(blob)].append(name)

    failed = total - passed
    print("## Windows measurement — Phase 0\n")
    print(f"**{passed} passed, {failed} failed, {total} collected.**\n")
    if not total:
        print("⚠ Nothing was collected. That is the finding: the suite does "
              "not start on Windows.\n")
        return 0

    print("| cause | failures |")
    print("|---|---:|")
    for name in sorted(groups, key=lambda k: -len(groups[k])):
        print(f"| {name} | {len(groups[name])} |")

    unpredicted = groups.get("⚠ UNPREDICTED — maps to NONE of the seven", [])
    print(f"\n### ⚠ Mapping to NONE of the seven: {len(unpredicted)}\n")
    if unpredicted:
        print("These are the ones nobody predicted, and they are Phase 3's "
              "real risk:\n")
        for name in sorted(unpredicted)[:40]:
            print(f"- `{name}`")
        if len(unpredicted) > 40:
            print(f"- …and {len(unpredicted) - 40} more")
    else:
        print("None — every failure matched a known site or the harness. "
              "⚠ Treat that with suspicion rather than relief: it more likely "
              "means the signatures are too broad than that the reading was "
              "perfect.")

    print("\n<details><summary>every failure, by cause</summary>\n")
    for name in sorted(groups, key=lambda k: -len(groups[k])):
        print(f"\n**{name}** ({len(groups[name])})\n")
        for case in sorted(groups[name])[:60]:
            print(f"- `{case}`")
    print("\n</details>")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1
                               else "windows-results.xml"))
    except BrokenPipeError:                                      # `| head`
        sys.stderr.close()
