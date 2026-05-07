#!/usr/bin/env python3
"""
Scan the DuetOS source tree for `// STUB:` and `// GAP:` markers
and emit a JSON manifest of (file, line, kind, comment, has_macro).

Each marker is one row. `has_macro` is true when the line
immediately following the marker (or the next non-blank line
within 3 lines) contains a `FIX_NOTE_STUB(...)` or
`FIX_NOTE_GAP(...)` macro call — i.e. the marker is **observable**
at runtime and feeds the fix journal.

Use cases:
    1. Compare the manifest against a fix-journal report to find
       markers that exist in source but were never observed at
       runtime — candidates for cold-path coverage or unreachable
       dead code (per CLAUDE.md "is built but not wired in").
    2. Audit how many markers are observable vs. comment-only.
    3. Dashboard metric: % of markers with macro coverage.

Usage:
    tools/build/gen-fix-markers.py [--root .] [--output markers.json]

Output (JSON array on stdout by default):
    [
      {
        "file": "kernel/power/reboot.cpp",
        "line": 91,
        "kind": "GAP",
        "comment": "no ACPI S5 path — see header. ...",
        "has_macro": true
      },
      ...
    ]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

MARKER_RE = re.compile(r"^\s*//\s*(STUB|GAP):\s*(.*)$")
MACRO_RE = re.compile(r"\bFIX_NOTE_(STUB|GAP)\s*\(")
COMMENT_CONT_RE = re.compile(r"^\s*//")  # any `//`-starting continuation line
SOURCE_DIRS = ["kernel", "drivers", "subsystems", "userland", "boot"]
SOURCE_EXTS = {".h", ".hpp", ".c", ".cpp", ".cc", ".rs"}
# Hard cap on how many lines past the marker we scan. Multi-line
# marker comments (e.g. a 5-line // STUB: explanation) are skipped
# transparently — the cap kicks in once we hit a non-comment line.
LOOKAHEAD_HARD_CAP = 12


def find_sources(root: Path) -> list[Path]:
    found: list[Path] = []
    for top in SOURCE_DIRS:
        base = root / top
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in SOURCE_EXTS:
                continue
            found.append(path)
    return sorted(found)


def scan_file(path: Path, root: Path) -> list[dict]:
    results: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return results
    rel = path.relative_to(root).as_posix()
    for idx, line in enumerate(lines):
        m = MARKER_RE.match(line)
        if m is None:
            continue
        kind = m.group(1)
        comment = m.group(2).strip()
        # Scan up to LOOKAHEAD_HARD_CAP lines past the marker for
        # a FIX_NOTE_* macro. The macro might be:
        #   (a) immediately after the marker (single-line marker)
        #   (b) after a multi-line comment block
        #   (c) inside the function whose body the marker describes
        #       (marker on the comment above a function decl, macro
        #       on the first line of the body)
        # We stop early if we hit ANOTHER // STUB: / // GAP: marker
        # so the search doesn't bleed into the next marker's scope.
        has_macro = False
        for off in range(1, LOOKAHEAD_HARD_CAP + 1):
            j = idx + off
            if j >= len(lines):
                break
            line_j = lines[j]
            if MARKER_RE.match(line_j):
                # Hit the next marker — stop without finding a macro.
                break
            if MACRO_RE.search(line_j):
                has_macro = True
                break
        results.append(
            {
                "file": rel,
                "line": idx + 1,  # 1-indexed
                "kind": kind,
                "comment": comment,
                "has_macro": has_macro,
            }
        )
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: cwd)",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write JSON to file instead of stdout",
    )
    args = ap.parse_args()

    rows: list[dict] = []
    for path in find_sources(args.root):
        rows.extend(scan_file(path, args.root))

    payload = json.dumps(rows, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)

    # Brief summary on stderr so callers piping JSON to a file
    # still see something.
    total = len(rows)
    with_macro = sum(1 for r in rows if r["has_macro"])
    by_kind: dict[str, int] = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    print(
        f"# {total} markers ({by_kind.get('STUB', 0)} STUB, {by_kind.get('GAP', 0)} GAP);"
        f" {with_macro} observable, {total - with_macro} comment-only",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
