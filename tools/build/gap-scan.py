#!/usr/bin/env python3
"""gap-scan.py — static discovery of un-annotated "gap-shaped" source sites.

Phase C of the dynamic fix-discovery system
(docs/superpowers/specs/2026-06-11-dynamic-fix-discovery-design.md).

Scans kernel/driver/subsystem source for sites that *look* incomplete — a
handler returning the not-implemented sentinel, a `default:` arm returning it,
a `// TODO`/`// FIXME`, an `-ENOSYS` — and emits the ones that DON'T already
carry a `// GAP:` / `// STUB:` / `FIX_NOTE_*` annotation. The output
(`gap-candidates.json`) is joined with runtime InferredGap hits by
gen-fix-patches.py: a candidate that was also hit at runtime is "confirmed
live"; one never hit is a "cold candidate".

This is what frees discovery from depending on a human having typed `// GAP:`.

Usage:
    tools/build/gap-scan.py [--root DIR ...] [--out gap-candidates.json]

Defaults: roots = kernel drivers subsystems (relative to repo root); out =
gap-candidates.json in CWD.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Patterns that mark a line as a candidate gap site. (kind, compiled-regex).
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("not_implemented_status", re.compile(r"\bkStatusNotImplemented\b")),
    ("errorcode_not_implemented", re.compile(r"ErrorCode::Not(Implemented|Supported)\b")),
    ("enosys", re.compile(r"-\s*ENOSYS\b")),
    ("todo_fixme", re.compile(r"//.*\b(TODO|FIXME)\b")),
]

# A line is considered already-annotated (and therefore the human's job) if it
# OR a nearby line carries one of these. We check a small window around the hit.
ANNOTATION = re.compile(r"//\s*(GAP|STUB):|FIX_NOTE_(GAP|STUB)\b")

# Best-effort enclosing-function detector: a line that looks like a function
# definition header `... name(...)`. Good enough for candidate labelling; the
# authoritative key downstream is file:line, not the name.
FUNC_DEF = re.compile(r"^[A-Za-z_].*\b([A-Za-z_]\w*)\s*\([^;]*$")

SOURCE_SUFFIXES = (".c", ".cpp", ".cc", ".h", ".hpp")

# A line that is itself the macro/comment that DEFINES the annotation convention
# (in fix_journal.h) must never be reported as a candidate.
SKIP_FILE_SUFFIXES = ("diag/fix_journal.h", "diag/fix_journal.cpp", "build/gap-scan.py")

# How many lines above/below a hit to scan for an existing annotation.
ANNOTATION_WINDOW = 2


def enclosing_function(lines: list[str], idx: int) -> str:
    """Best-effort: nearest preceding function-definition header's name."""
    for j in range(idx, max(idx - 60, -1), -1):
        m = FUNC_DEF.match(lines[j].rstrip())
        if m and "return" not in lines[j] and "=" not in lines[j].split("(")[0]:
            return m.group(1)
    return ""


def guest_reachable_guess(path: str) -> bool:
    """Heuristic: syscall / subsystem ABI files are guest-reachable."""
    p = path.replace("\\", "/")
    return any(seg in p for seg in ("syscall/", "subsystems/win32", "subsystems/linux", "loader/"))


def scan_file(path: Path, repo_root: Path) -> list[dict]:
    rel = str(path.relative_to(repo_root)).replace("\\", "/")
    if any(rel.endswith(suf) for suf in SKIP_FILE_SUFFIXES):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    out: list[dict] = []
    for i, line in enumerate(lines):
        for kind, rx in PATTERNS:
            if not rx.search(line):
                continue
            lo = max(0, i - ANNOTATION_WINDOW)
            hi = min(len(lines), i + ANNOTATION_WINDOW + 1)
            if any(ANNOTATION.search(lines[k]) for k in range(lo, hi)):
                continue  # already annotated — the human's job, done
            out.append(
                {
                    "file": rel,
                    "line": i + 1,
                    "function": enclosing_function(lines, i),
                    "pattern_kind": kind,
                    "guest_reachable_guess": guest_reachable_guess(rel),
                }
            )
            break  # one candidate per line
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Static discovery of un-annotated gap-shaped sites.")
    ap.add_argument("--root", action="append", default=None, help="root dir(s) to scan (repeatable)")
    ap.add_argument("--out", type=Path, default=Path("gap-candidates.json"))
    args = ap.parse_args()

    # When --root points at a fixture tree, treat it as both repo_root and the
    # only scan root. Otherwise default to the repo's source trees.
    if args.root:
        roots = [Path(r) for r in args.root]
        repo_root = roots[0]
    else:
        repo_root = Path(__file__).resolve().parents[2]
        roots = [repo_root / d for d in ("kernel", "drivers", "subsystems")]

    candidates: list[dict] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in SOURCE_SUFFIXES:
                candidates.extend(scan_file(path, repo_root))

    args.out.write_text(json.dumps(candidates, indent=1), encoding="utf-8")
    print(f"# gap-scan: {len(candidates)} un-annotated candidate(s) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
