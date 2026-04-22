#!/usr/bin/env python3
"""
Generate a CustomOS NT-syscall mapping table from the j00ru CSV.

Reads `nt-syscalls-x64.csv` (one row per NT call, one column per Windows
version), filters to the calls present in EVERY listed version (the
~292 "bedrock" calls), and emits a C++ header listing each with:

  * its NT syscall number on the chosen Windows version (Win11 by default)
  * the corresponding CustomOS internal SYS_* number, or kSysNtNotImpl
    when we don't yet have a mapping

The mapping rules are hand-curated below in `KNOWN_MAPPINGS`. Every time
we add a new SYS_* that has a clean NT counterpart, add an entry there
and re-run the generator.

Usage:
    python3 gen-nt-shim.py --csv nt-syscalls-x64.csv \\
        --version 'Windows 11 and Server (11 25H2)' \\
        --out ../../kernel/subsystems/win32/nt_syscall_table_generated.h
"""

import argparse
import csv
import sys
from pathlib import Path

# ----------------------------------------------------------------------
# Mapping rules. Each entry says: "this NT function is the closest
# equivalent of this CustomOS SYS_* number". Add entries as we
# implement matching SYS_* numbers in kernel/core/syscall.h.
#
# Naming: keep the SYS_* identifier exactly as it appears in syscall.h
# so the generator can emit the C++ enum reference verbatim.
# ----------------------------------------------------------------------
KNOWN_MAPPINGS = {
    # CustomOS today (slice 80-era) — clean Nt analogues
    "NtTerminateProcess":          "SYS_EXIT",            # ExitProcess maps here too via kernel32
    "NtWriteFile":                 "SYS_WRITE",           # path-based today; close enough for handle-on-stdout
    "NtYieldExecution":            "SYS_YIELD",
    "NtAllocateVirtualMemory":     "SYS_HEAP_ALLOC",      # HeapAlloc-shape; not 1:1 but a route exists
    "NtFreeVirtualMemory":         "SYS_HEAP_FREE",
    "NtQueryPerformanceCounter":   "SYS_PERF_COUNTER",
    "NtQuerySystemTime":           "SYS_GETTIME_FT",
    "NtDelayExecution":            "SYS_SLEEP_MS",         # batch 22
    # Slice 81+ candidates (filled in as the SYS_* lands)
    # "NtCreateFile":              "SYS_OPEN",
    # "NtReadFile":                "SYS_FREAD",
    # "NtClose":                   "SYS_FCLOSE",
}

HEADER_TEMPLATE = """// AUTO-GENERATED — do not edit by hand.
// Regenerate via: python3 tools/win32-compat/gen-nt-shim.py
//                 --csv tools/win32-compat/nt-syscalls-x64.csv
//                 --version '{version}'
//                 --out kernel/subsystems/win32/nt_syscall_table_generated.h
//
// Source data: tools/win32-compat/nt-syscalls-x64.csv (j00ru/windows-syscalls)
// Target Windows version: {version}
// Bedrock NT calls (present in every Windows XP→Win11 25H2): {bedrock_count}
// CustomOS coverage: {covered_count}/{bedrock_count} = {pct}%
//
// See tools/win32-compat/README.md for the legal + design rationale.

#pragma once

#include "../../core/syscall.h"
#include "../../core/types.h"

namespace customos::subsystems::win32
{{

/// Sentinel value for `NtSyscallMapping::customos_sys` indicating that
/// CustomOS has no internal SYS_* number that maps to this NT call. The
/// ntdll shim's catch-all stub returns STATUS_NOT_IMPLEMENTED for these.
inline constexpr u32 kSysNtNotImpl = 0xFFFFFFFFu;

/// One row of the NT-syscall mapping table. Used by the (future) ntdll
/// shim to route an `eax = nt_number` syscall into the matching CustomOS
/// SYS_*. Sorted by `nt_number` so the shim can binary-search.
struct NtSyscallMapping
{{
    const char* nt_name;     // e.g. "NtCreateFile"
    u16 nt_number;           // syscall number on the target Windows version
    u32 customos_sys;        // matching SYS_* enumerator value, or kSysNtNotImpl
}};

/// Bedrock NT syscalls — present in every Windows version from XP SP1
/// through Windows 11 25H2 / Server 2025. These are the API surface a
/// real-world Windows binary is most likely to depend on.
inline constexpr NtSyscallMapping kBedrockNtSyscalls[] = {{
{rows}}};

inline constexpr u32 kBedrockNtSyscallCount =
    sizeof(kBedrockNtSyscalls) / sizeof(kBedrockNtSyscalls[0]);

inline constexpr u32 kBedrockNtSyscallsCovered = {covered_count};

}} // namespace customos::subsystems::win32
"""


def parse_hex_or_dec(value):
    """j00ru's CSV uses '0x00ab' for hex; some old columns use plain decimal."""
    s = value.strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return None
    try:
        return int(s)
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, type=Path)
    ap.add_argument("--version", required=True,
                    help='Column header in the CSV, e.g. "Windows 11 and Server (11 25H2)"')
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    with args.csv.open() as f:
        reader = csv.reader(f)
        header = next(reader)
        if args.version not in header:
            print(f"error: '{args.version}' not in CSV header. Available:", file=sys.stderr)
            for h in header[1:]:
                print(f"  {h}", file=sys.stderr)
            sys.exit(2)
        version_col = header.index(args.version)

        bedrock = []  # list of (name, nt_number_on_target)
        for row in reader:
            if not row or not row[0]:
                continue
            name = row[0]
            # Universal-bedrock filter: every per-version column non-empty.
            if any(not c.strip() for c in row[1:]):
                continue
            nt_num = parse_hex_or_dec(row[version_col])
            if nt_num is None:
                continue
            bedrock.append((name, nt_num))

    # Sort by NT number so the C++ table is binary-searchable.
    bedrock.sort(key=lambda x: x[1])

    rows_out = []
    covered = 0
    for name, num in bedrock:
        sys_enum = KNOWN_MAPPINGS.get(name)
        if sys_enum is None:
            mapping_expr = "kSysNtNotImpl"
        else:
            mapping_expr = f"static_cast<u32>(::customos::core::{sys_enum})"
            covered += 1
        rows_out.append(
            f'    {{"{name}", 0x{num:04x}, {mapping_expr}}},'
        )

    pct = (100 * covered // len(bedrock)) if bedrock else 0
    text = HEADER_TEMPLATE.format(
        version=args.version,
        bedrock_count=len(bedrock),
        covered_count=covered,
        pct=pct,
        rows="\n".join(rows_out) + ("\n" if rows_out else ""),
    )
    args.out.write_text(text)

    print(f"wrote {args.out}")
    print(f"  bedrock NT calls   : {len(bedrock)}")
    print(f"  CustomOS-mapped    : {covered} ({pct}%)")
    print(f"  unmapped           : {len(bedrock) - covered} (route to kSysNtNotImpl)")


if __name__ == "__main__":
    main()
