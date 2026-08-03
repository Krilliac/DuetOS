#!/usr/bin/env python3
"""Find spinlock scopes that log or probe while holding the lock.

WHY
    klog and raw SerialWrite both take the serial lock. Any subsystem lock
    held across a log call therefore establishes `subsystem-lock ->
    serial-lock`. If any path can reach that subsystem's recorder while
    already holding the serial lock — which klog writers do — the two
    orderings are inverted and the pair can deadlock.

    This is not hypothetical. `FixJournalInit` held `g_lock` across a
    `KLOG_INFO_V`, and once SMP started working (2026-08-03) it deadlocked
    `FixJournalEmitBootSummary`: smoke profiles finished their sleep, emitted
    none of the boot summaries, and hung until the harness timeout while the
    rest of the kernel kept ticking. It presented as a flaky `qemu_timeout`
    on a rotating set of profiles, because which CPU lost the race varied.

    One instance was found by hand from a boot log. This finds the rest.

USAGE
    python3 tools/test/check-spinlock-log-order.py            # report
    python3 tools/test/check-spinlock-log-order.py --json     # machine form

EXIT
    0 no findings, 1 at least one lock held across a log/probe call

CAVEATS
    Textual and intentionally conservative: it follows brace depth from the
    guard declaration to the end of its enclosing scope. It cannot see
    logging that happens inside a callee, so a clean result is necessary but
    not sufficient. Panic paths are excluded — a crash dump deliberately
    logs while holding whatever it holds.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

GUARD = re.compile(r"\bSpinLockGuard\s+(\w+)\s*\(\s*([\w:.\->]+)\s*\)")
LOGGING = re.compile(r"\b(KLOG_\w+|SerialWrite|SerialWriteHex|KBP_PROBE\w*|ProbeFire)\s*\(")
# Paths that legitimately log under a lock: crash/panic dumps have already
# given up on forward progress, and the lock-order audit itself reports.
EXEMPT_FILES = {"kernel/core/panic.cpp", "kernel/diag/bsod.cpp", "kernel/diag/minidump.cpp",
                "kernel/sync/lockdep.cpp", "kernel/diag/crash_dump.cpp"}
EXEMPT_FN = re.compile(r"\b(Panic|Bsod|CrashDump|Minidump|Oops|DumpBacktrace|LockdepReport)\w*\b")


def scan(path: Path) -> list[dict]:
    rel = path.relative_to(ROOT).as_posix()
    if rel in EXEMPT_FILES:
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    findings = []
    for i, line in enumerate(lines):
        m = GUARD.search(line)
        if not m:
            continue
        depth = 0
        started = False
        hits = []
        for j in range(i, min(i + 200, len(lines))):
            cur = lines[j]
            if j > i:
                if LOGGING.search(cur) and not cur.lstrip().startswith(("//", "*", "/*")):
                    if not EXEMPT_FN.search(cur):
                        hits.append({"line": j + 1, "text": cur.strip()[:110]})
            depth += cur.count("{") - cur.count("}")
            if j > i:
                started = started or depth > 0
            if started and depth <= 0:
                break
        if hits:
            findings.append({"file": rel, "guard_line": i + 1,
                             "lock": m.group(2), "hits": hits})
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--root", default="kernel")
    args = ap.parse_args()

    files = sorted((ROOT / args.root).rglob("*.cpp"))
    findings = [f for p in files for f in scan(p)]

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"{f['file']}:{f['guard_line']}  holds {f['lock']} across:")
            for h in f["hits"]:
                print(f"    line {h['line']}: {h['text']}")
        print(f"\nscanned {len(files)} files under {args.root}/ — "
              f"{len(findings)} lock scope(s) log while held")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
