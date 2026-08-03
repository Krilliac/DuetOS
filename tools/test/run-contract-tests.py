#!/usr/bin/env python3
"""Run every Python contract test under tools/test/ and report a compact verdict.

WHY
    The tree carries 100+ `tools/test/test-*.py` contract tests — static
    checks that pin source-level invariants (copy-out overloads, syscall
    bijection, claim-script safety, FFI signatures). They are cheap enough
    to run when a full kernel build is not possible (low RAM, no WSL
    toolchain), which makes them the first signal to re-scan after any
    change. Before this script there was no aggregate runner, so each
    session re-derived a `for` loop and picked a timeout by guesswork.

USAGE
    python tools/test/run-contract-tests.py                 # run all
    python tools/test/run-contract-tests.py --timeout 600   # slower box
    python tools/test/run-contract-tests.py --pattern arp    # subset
    python tools/test/run-contract-tests.py --jsonl out.jsonl

EXIT CODES
    0  every selected test passed
    1  at least one test failed or timed out

NOTES
    The default per-test timeout is deliberately generous:
    test-parallel-claim-safety.py drives real git repos through subprocess
    and legitimately takes ~240s on a loaded 16 GB host. A short timeout
    reports it as a hang and buries a passing suite.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST_DIR = ROOT / "tools" / "test"
DEFAULT_TIMEOUT_SECONDS = 420


def discover(pattern: str | None) -> list[Path]:
    tests = sorted(TEST_DIR.glob("test-*.py"))
    if pattern:
        tests = [t for t in tests if pattern in t.name]
    return tests


def run_one(test: Path, timeout: int) -> dict:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [sys.executable, str(test)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        return {
            "test": test.name,
            "status": "TIMEOUT",
            "returncode": None,
            "seconds": round(time.monotonic() - started, 1),
            "tail": f"exceeded {timeout}s",
        }

    output = (completed.stdout + completed.stderr).strip()
    return {
        "test": test.name,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "returncode": completed.returncode,
        "seconds": round(time.monotonic() - started, 1),
        "tail": "\n".join(output.splitlines()[-8:]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS,
                        help=f"per-test timeout in seconds (default {DEFAULT_TIMEOUT_SECONDS})")
    parser.add_argument("--pattern", help="only run tests whose filename contains this substring")
    parser.add_argument("--jsonl", type=Path, help="write one JSON result object per line to this file")
    args = parser.parse_args()

    tests = discover(args.pattern)
    if not tests:
        print("no contract tests matched", file=sys.stderr)
        return 1

    results = [run_one(test, args.timeout) for test in tests]

    if args.jsonl:
        with args.jsonl.open("w", encoding="utf-8") as handle:
            for result in results:
                handle.write(json.dumps(result) + "\n")

    bad = [r for r in results if r["status"] != "PASS"]
    total_seconds = round(sum(r["seconds"] for r in results), 1)
    print(f"TOTAL={len(results)} PASS={len(results) - len(bad)} "
          f"FAIL={sum(1 for r in bad if r['status'] == 'FAIL')} "
          f"TIMEOUT={sum(1 for r in bad if r['status'] == 'TIMEOUT')} "
          f"WALL={total_seconds}s")

    for result in bad:
        print(f"\n### {result['status']} rc={result['returncode']} "
              f"{result['test']} ({result['seconds']}s)\n{result['tail']}")

    slowest = sorted(results, key=lambda r: r["seconds"], reverse=True)[:3]
    print("\nslowest: " + ", ".join(f"{r['test']} {r['seconds']}s" for r in slowest))

    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
