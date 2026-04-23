#!/usr/bin/env python3
"""Fail when LinuxSyscallDispatch and LinuxGapFill handle the same syscall number.

Usage:
  python3 tools/linux-compat/check-gapfill-overlap.py
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Dict, Set


def parse_enum_numbers(text: str) -> Dict[str, int]:
    mapping: Dict[str, int] = {}
    for name, value in re.findall(r"\b(kSys[A-Za-z0-9_]+)\s*=\s*([0-9]+)\s*,", text):
        mapping[name] = int(value)
    return mapping


def extract_switch_cases(text: str, func_name: str) -> Set[str]:
    func_match = re.search(rf"\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{", text)
    if not func_match:
        raise ValueError(f"Function {func_name} not found")

    i = func_match.end() - 1
    depth = 0
    body_start = i + 1
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                body = text[body_start:j]
                return set(re.findall(r"\bcase\s+(kSys[A-Za-z0-9_]+)\s*:", body))
    raise ValueError(f"Could not parse body for {func_name}")


def load_allowlist(path: pathlib.Path, symbol_to_nr: Dict[str, int]) -> Set[int]:
    allowed: Set[int] = set()
    if not path.exists():
        return allowed
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("kSys"):
            if line not in symbol_to_nr:
                raise ValueError(f"Unknown allowlist symbol: {line}")
            allowed.add(symbol_to_nr[line])
            continue
        try:
            allowed.add(int(line, 0))
        except ValueError as exc:
            raise ValueError(f"Invalid allowlist entry: {line}") from exc
    return allowed


def resolve_cases(case_names: Set[str], symbol_to_nr: Dict[str, int], label: str) -> Set[int]:
    missing = sorted(name for name in case_names if name not in symbol_to_nr)
    if missing:
        raise ValueError(f"{label} has unresolved syscall symbols: {', '.join(missing)}")
    return {symbol_to_nr[name] for name in case_names}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=pathlib.Path(__file__).resolve().parents[2],
        type=pathlib.Path,
        help="Repository root (default: auto-detected)",
    )
    parser.add_argument(
        "--allowlist",
        default="tools/linux-compat/gapfill-overlap-allowlist.txt",
        help="Path (relative to repo root) for overlap allowlist entries",
    )
    args = parser.parse_args()

    root = args.repo_root.resolve()
    linux_path = root / "kernel/subsystems/linux/syscall.cpp"
    translate_path = root / "kernel/subsystems/translation/translate.cpp"
    allowlist_path = root / args.allowlist

    linux_text = linux_path.read_text(encoding="utf-8")
    translate_text = translate_path.read_text(encoding="utf-8")

    symbols = parse_enum_numbers(linux_text)
    symbols.update(parse_enum_numbers(translate_text))

    dispatch_cases = extract_switch_cases(linux_text, "LinuxSyscallDispatch")
    gapfill_cases = extract_switch_cases(translate_text, "LinuxGapFill")

    dispatch_numbers = resolve_cases(dispatch_cases, symbols, "LinuxSyscallDispatch")
    gapfill_numbers = resolve_cases(gapfill_cases, symbols, "LinuxGapFill")
    allowlist_numbers = load_allowlist(allowlist_path, symbols)

    overlap = dispatch_numbers & gapfill_numbers
    forbidden = sorted(n for n in overlap if n not in allowlist_numbers)

    print(
        "[linux-compat] dispatch="
        f"{len(dispatch_numbers)} gapfill={len(gapfill_numbers)} "
        f"overlap={len(overlap)} allowlisted={len(overlap) - len(forbidden)}"
    )

    if forbidden:
        print("[linux-compat] FAIL: overlapping syscall numbers are handled in both dispatch and gap-fill:")
        for nr in forbidden:
            print(f"  - {nr}")
        print(
            "[linux-compat] Fix by removing translation handling or explicitly allowlisting in "
            f"{allowlist_path.relative_to(root)}"
        )
        return 1

    print("[linux-compat] PASS: no unallowlisted dispatch/gap-fill overlap")
    return 0


if __name__ == "__main__":
    sys.exit(main())
