#!/usr/bin/env python3
"""Find smoke-app verdict lines that are emitted as more than one write.

WHY
    The kernel's write syscall is line-atomic PER CALL — DoWrite drives COM1
    with a single SerialWriteN holding the port lock. It guarantees nothing
    ACROSS calls. So a verdict emitted as

        Out("[foo_smoke] SomeCheck = ");
        Out(ok ? "PASS\\r\\n" : "FAIL\\r\\n");

    leaves a window in which another CPU's klog lands between the two writes
    and splits the logical line in the serial log.

    CI greps for exact signature lines, so a split line reads as a MISSING
    signature and fails the smoke even though the check passed. On 2026-08-03
    that took down `qemu smoke (pe-threads, 4 vCPU)`:

        [thread2_smoke] GetExitCodeThread     = [t=...] [D] loader/dll : ...

    with `PASS (0x42)` displaced to the next line, while
    `[ring3-thread2-smoke] PASS` and `[thread2_smoke] done` both showed the
    run had succeeded. The window widened once SMP started working, because
    there are now peer CPUs generating klog traffic.

    Fix in the app: build the whole line and emit it with ONE write (see
    OutVerdict in userland/apps/thread2_smoke/thread2_smoke.c).

USAGE
    python3 tools/test/check-smoke-line-atomicity.py            # report
    python3 tools/test/check-smoke-line-atomicity.py --app foo  # one app

EXIT
    0 always — this is a triage report, not a gate.

SCOPE NOTE
    A multi-write line only matters if CI greps for it. Many apps build
    output in pieces harmlessly. This reports the risk surface; it does not
    claim every hit is a live flake. Lines carrying a PASS/FAIL verdict are
    flagged separately because those are the ones signature-grep depends on.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APPS = ROOT / "userland/apps"

# A write call whose string literal does not end the line.
WRITE = re.compile(r'\b(Out\w*|Print\w*|Emit\w*)\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)\s*;')
VERDICT_NEXT = re.compile(r'\b(?:Out\w*|Print\w*|Emit\w*)\s*\([^;]*\b(PASS|FAIL)\b', re.S)


def scan(path: Path) -> list[tuple[int, str, bool]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    for i, line in enumerate(lines):
        m = WRITE.search(line)
        if not m:
            continue
        literal = m.group(2)
        if literal.endswith("\\n"):
            continue  # terminated — atomic on its own
        # Does the NEXT non-blank line finish it with a verdict?
        nxt = ""
        for j in range(i + 1, min(i + 3, len(lines))):
            if lines[j].strip():
                nxt = lines[j]
                break
        carries_verdict = bool(VERDICT_NEXT.search(nxt))
        out.append((i + 1, literal[:60], carries_verdict))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--app", help="limit to one app directory name")
    args = ap.parse_args()

    files = sorted(APPS.rglob("*.c"))
    if args.app:
        files = [f for f in files if args.app in f.parts]

    total = 0
    verdict_risk = 0
    rows = []
    for f in files:
        hits = scan(f)
        if not hits:
            continue
        v = sum(1 for _, _, carries in hits if carries)
        total += len(hits)
        verdict_risk += v
        rows.append((v, len(hits), f.relative_to(ROOT).as_posix()))

    rows.sort(key=lambda r: (-r[0], -r[1]))
    print(f"{'verdict':>7} {'total':>6}  file")
    for v, n, name in rows[:25]:
        print(f"{v:>7} {n:>6}  {name}")

    print(f"\n{len(rows)} app(s) emit multi-write lines: {total} split writes, "
          f"{verdict_risk} of them immediately followed by a PASS/FAIL verdict.")
    print("The verdict column is the real flake surface — those are the lines "
          "CI signature-greps.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
