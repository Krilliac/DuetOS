#!/usr/bin/env python3
"""Hostile source contract for stopped-task AddressSpace reads."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "kernel/debug/breakpoints.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "kernel/debug/breakpoints.h").read_text(encoding="utf-8")


def function_body(name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*\)\s*\{{", SOURCE)
    if match is None:
        raise AssertionError(f"missing {name} definition")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start : index + 1]
    raise AssertionError(f"unterminated {name} definition")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    body = function_body("BpReadMem")
    checks = [
        (
            "AddressSpaceLookupUserFrame" not in body and "PhysToVirt" not in body,
            "BpReadMem must not turn an unpinned frame snapshot into a direct-map pointer",
        ),
        (
            re.search(r"stopped_as\s*=\s*e->stopped_as\s*;\s*mm::AddressSpaceRetain\(stopped_as\)", body, re.S)
            is not None,
            "captured AddressSpace must be retained while the debugger entry is locked",
        ),
        (
            "mm::AddressSpaceReadUserMemory(stopped_as" in body,
            "stopped-task bytes must be copied by the mutation-serialized VM API",
        ),
        (
            body.index("mm::AddressSpaceRetain(stopped_as)")
            < body.index("mm::AddressSpaceReadUserMemory(stopped_as")
            < body.index("mm::AddressSpaceRelease(stopped_as)"),
            "AddressSpace pin must enclose every stopped-task read transaction",
        ),
        (
            re.search(
                r"\{\s*sync::SpinLockGuard g\(g_lock\);.*?mm::AddressSpaceRetain\(stopped_as\);\s*\}\s*"
                r"u64 copied.*?AddressSpaceReadUserMemory",
                body,
                re.S,
            )
            is not None,
            "debugger spinlock must be released before the blocking VM read",
        ),
        (
            "user_va > ~u64{0} - copied" in body,
            "multi-page debugger read must reject user-VA addition overflow",
        ),
        (
            "no physical-frame or" in HEADER and "task context outside traps/IRQs" in HEADER,
            "public contract must state the pinning and blocking-context requirements",
        ),
        (
            "ResolveStoppedUserByte" not in SOURCE,
            "raw stopped-user direct-pointer helper must stay retired",
        ),
    ]

    for index, (condition, message) in enumerate(checks, 1):
        check(condition, message)
        print(f"PASS {index}: {message}")
    print(f"PASS: {len(checks)}/{len(checks)} breakpoint AddressSpace read contracts")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
