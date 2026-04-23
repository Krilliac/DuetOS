#!/usr/bin/env python3
"""Check Linux syscall ownership between primary dispatcher and translator.

Policy:
  * Primary dispatcher owns every syscall flagged Implemented in
    linux_syscall_table_generated.h.
  * Translation unit owns miss-path syscalls only.
  * Overlap is rejected unless the syscall number is explicitly
    allowlisted below.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Temporary/intentional overlaps only. Keep this empty unless a migration
# needs a bounded handoff window, then document that in tools/linux-compat/README.md.
ALLOWLIST: set[int] = set()


def parse_implemented_numbers(generated_header: Path) -> set[int]:
    text = generated_header.read_text()
    pattern = re.compile(r'\{(\d+),\s*\d+,\s*HandlerState::Implemented,\s*"[^"]+"\}')
    return {int(m.group(1)) for m in pattern.finditer(text)}


def parse_translation_owned_numbers(translation_cpp: Path) -> set[int]:
    text = translation_cpp.read_text()
    enum_match = re.search(r"enum\s*:\s*u64\s*\{(?P<body>.*?)\};", text, re.S)
    if enum_match is None:
        raise RuntimeError(f"failed to locate translation enum in {translation_cpp}")

    values: dict[str, int] = {}
    next_value = 0
    for raw in enum_match.group("body").splitlines():
        line = raw.split("//", 1)[0].strip().rstrip(",")
        if not line:
            continue
        if "=" in line:
            name, rhs = [part.strip() for part in line.split("=", 1)]
            value = int(rhs, 0)
        else:
            name = line
            value = next_value
        values[name] = value
        next_value = value + 1

    # Only linux translator ownership constants.
    return {value for name, value in values.items() if name.startswith("kSys")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--generated-header",
        type=Path,
        default=Path("kernel/subsystems/linux/linux_syscall_table_generated.h"),
    )
    ap.add_argument(
        "--translation-cpp",
        type=Path,
        default=Path("kernel/subsystems/translation/translate.cpp"),
    )
    args = ap.parse_args()

    primary = parse_implemented_numbers(args.generated_header)
    translation = parse_translation_owned_numbers(args.translation_cpp)

    overlap = sorted((primary & translation) - ALLOWLIST)

    print(f"primary-implemented: {len(primary)}")
    print(f"translation-owned: {len(translation)}")
    print(f"allowlisted-overlap: {len((primary & translation) & ALLOWLIST)}")

    if overlap:
        print("overlap-error:", ", ".join(str(n) for n in overlap))
        return 1

    print("ownership-check: ok (no non-allowlisted overlap)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
