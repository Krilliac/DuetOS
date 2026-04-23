#!/usr/bin/env python3
"""
Emit a comprehensive Linux x86_64 syscall-number -> name table.

Consumes `linux-syscalls-x86_64.csv` (columns: number, name, args)
and produces a C++ header with a sorted `kLinuxSyscalls` array that
the translator + dispatcher include for name lookup.

The optional `--mapped-from-dispatcher` argument points at
`kernel/subsystems/linux/syscall.cpp`; any syscall whose matching
`Do<Name>` handler appears there is flagged with
`linux::HandlerState::Implemented` in the generated header. The
remaining syscalls (which the dispatcher returns -ENOSYS for)
flag as `HandlerState::Unimplemented`. That gives the translator
a cheap "implemented vs not" snapshot without duplicating the
logic inside the dispatcher.

The optional `--gap-fill-from-translator` argument points at
`kernel/subsystems/translation/translate.cpp`; syscall numbers
handled by `LinuxGapFill(...)` there are counted toward an
"effective" coverage metric (primary dispatcher + translator
gap-fill).

Usage:
    python3 gen-linux-syscall-table.py \\
        --csv tools/linux-compat/linux-syscalls-x86_64.csv \\
        --mapped-from-dispatcher kernel/subsystems/linux/syscall.cpp \\
        --out kernel/subsystems/linux/linux_syscall_table_generated.h
"""

import argparse
import csv
import re
import sys
from pathlib import Path


HEADER_TEMPLATE = """// AUTO-GENERATED — do not edit by hand.
// Regenerate via: python3 tools/linux-compat/gen-linux-syscall-table.py
//                 --csv tools/linux-compat/linux-syscalls-x86_64.csv
//                 --mapped-from-dispatcher kernel/subsystems/linux/syscall.cpp
//                 --out kernel/subsystems/linux/linux_syscall_table_generated.h
//
// Source data: tools/linux-compat/linux-syscalls-x86_64.csv
// Total syscalls listed: {total}
// Primary handlers implemented in kernel/subsystems/linux/syscall.cpp: {primary}
// Effective coverage (primary + LinuxGapFill in translation/translate.cpp): {effective}
// Coverage (primary): {primary_pct}%
// Coverage (effective): {effective_pct}%
//
// See tools/linux-compat/README.md for provenance.

#pragma once

#include "../../core/types.h"

namespace customos::subsystems::linux
{{

enum class HandlerState : u8
{{
    Unknown = 0,     // number outside the known ABI range
    Unimplemented,   // known name, no Do* in syscall.cpp
    Implemented,     // known name, matching Do* handler exists
}};

struct LinuxSyscallEntry
{{
    u16 number;
    u8 args;            // 0..6
    HandlerState state;
    const char* name;
}};

/// Dense-by-number, sorted table of every known x86_64 Linux syscall.
inline constexpr LinuxSyscallEntry kLinuxSyscalls[] = {{
{rows}}};

inline constexpr u32 kLinuxSyscallCount =
    sizeof(kLinuxSyscalls) / sizeof(kLinuxSyscalls[0]);

inline constexpr u32 kLinuxSyscallMaxNumber = {max_nr};

/// Dense index by syscall number. Unknown numbers map to nullptr.
/// This keeps lookup O(1) while preserving the historical API.
inline constexpr const LinuxSyscallEntry* kLinuxSyscallByNumber[] = {{
{index_rows}}};

inline constexpr u32 kLinuxSyscallHandlersImplemented = {implemented};

/// Look up `nr` in the dense by-number index. Returns nullptr if unknown.
inline const LinuxSyscallEntry* LinuxSyscallLookup(u64 nr)
{{
    if (nr > kLinuxSyscallMaxNumber)
        return nullptr;
    return kLinuxSyscallByNumber[static_cast<u32>(nr)];
}}

}} // namespace customos::subsystems::linux
"""


# Manual name translation for cases where the dispatcher function is
# named differently from the canonical syscall (e.g. the dispatcher
# prefixes with "Do" and camel-cases). The heuristic below converts
# snake_case -> DoCamelCase and looks for it in the source; when a
# name needs an explicit override (different spelling entirely) add
# it here.
NAME_ALIASES = {
    # syscall name          : dispatcher symbol in syscall.cpp
    "rt_sigaction":         "DoRtSigaction",
    "rt_sigprocmask":       "DoRtSigprocmask",
    "rt_sigreturn":         "DoRtSigreturn",
    "set_tid_address":      "DoSetTidAddress",
    "set_robust_list":      "DoSetRobustList",
    "set_mempolicy_home_node": "DoSetMempolicyHomeNode",
    "clock_gettime":        "DoClockGetTime",
    "exit_group":           "DoExitGroup",
    "getpid":               "DoGetPid",
    "getuid":               "DoGetUid",
    "getgid":               "DoGetGid",
    "geteuid":              "DoGetEuid",
    "getegid":              "DoGetEgid",
    "setpgid":              "DoSetPgid",
    "getppid":              "DoGetPpid",
    "getpgid":              "DoGetPgid",
    "getsid":               "DoGetSid",
    "gettid":               "DoGetTid",
    "getrandom":            "DoGetRandom",
    "newfstatat":           "DoNewFstatat",
    "getdents64":           "DoGetdents64",
    "arch_prctl":           "DoArchPrctl",
    "prlimit64":            "DoPrlimit64",
    "pipe2":                "DoPipe2",
    "dup3":                 "DoDup3",
    "epoll_pwait":          "DoEpollPwait",
    "epoll_create1":        "DoEpollCreate1",
    "epoll_wait":           "DoEpollWait",
    "epoll_ctl":            "DoEpollCtl",
}


def snake_to_camel(name):
    return "".join(p.capitalize() for p in name.split("_"))


def build_dispatcher_symbols(source_text):
    # Every handler body in syscall.cpp is declared as
    # `i64 DoFoo(...)`. Grep them out.
    return set(re.findall(r"\bi64\s+(Do[A-Za-z0-9_]+)\s*\(", source_text))


def classify(name, dispatcher_symbols):
    sym = NAME_ALIASES.get(name)
    if sym and sym in dispatcher_symbols:
        return "Implemented"
    sym = f"Do{snake_to_camel(name)}"
    if sym in dispatcher_symbols:
        return "Implemented"
    return "Unimplemented"


def parse_translator_constants(source_text):
    constants = {}
    for name, value in re.findall(r"\b(kSys[A-Za-z0-9_]+)\s*=\s*([0-9]+)\s*,", source_text):
        constants[name] = int(value)
    return constants


def parse_linux_gap_fill_numbers(source_text):
    fn_match = re.search(r"Result\s+LinuxGapFill\s*\([^)]*\)\s*\{", source_text)
    if not fn_match:
        return set()
    body_start = fn_match.end() - 1
    depth = 0
    body_end = None
    for i in range(body_start, len(source_text)):
        ch = source_text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                body_end = i
                break
    if body_end is None:
        return set()
    body = source_text[body_start + 1:body_end]
    switch_match = re.search(r"switch\s*\(\s*nr\s*\)\s*\{(?P<switch>.*?)\n\s*default\s*:", body, re.S)
    if not switch_match:
        return set()
    switch_body = switch_match.group("switch")
    constants = parse_translator_constants(source_text)
    out = set()
    for case_name in re.findall(r"\bcase\s+(kSys[A-Za-z0-9_]+)\s*:", switch_body):
        value = constants.get(case_name)
        if value is not None:
            out.add(value)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, type=Path)
    ap.add_argument("--mapped-from-dispatcher", type=Path, default=None)
    ap.add_argument("--gap-fill-from-translator", type=Path, default=None)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    dispatcher_symbols = set()
    if args.mapped_from_dispatcher is not None:
        dispatcher_symbols = build_dispatcher_symbols(
            args.mapped_from_dispatcher.read_text()
        )

    gap_fill_numbers = set()
    if args.gap_fill_from_translator is not None:
        gap_fill_numbers = parse_linux_gap_fill_numbers(
            args.gap_fill_from_translator.read_text()
        )

    rows = []
    with args.csv.open() as f:
        reader = csv.DictReader(f)
        for r in reader:
            nr = int(r["number"])
            name = r["name"].strip()
            try:
                args_n = int(r.get("args", "0"))
            except ValueError:
                args_n = 0
            state = classify(name, dispatcher_symbols)
            rows.append((nr, name, args_n, state))

    rows.sort(key=lambda r: r[0])

    primary = sum(1 for _, _, _, s in rows if s == "Implemented")
    effective = sum(1 for nr, _, _, s in rows if (s == "Implemented") or (nr in gap_fill_numbers))
    total = len(rows)
    max_nr = max((nr for nr, _, _, _ in rows), default=0)
    pct = (100 * implemented // total) if total else 0

    row_lines = []
    number_to_row_index = {}
    for idx, (nr, name, args_n, state) in enumerate(rows):
        row_lines.append(
            f'    {{{nr}, {args_n}, HandlerState::{state}, "{name}"}},'
        )
        number_to_row_index[nr] = idx

    index_row_lines = []
    for nr in range(max_nr + 1):
        row_index = number_to_row_index.get(nr)
        if row_index is None:
            index_row_lines.append("    nullptr,")
        else:
            index_row_lines.append(f"    &kLinuxSyscalls[{row_index}],")

    args.out.write_text(
        HEADER_TEMPLATE.format(
            total=total,
            implemented=implemented,
            pct=pct,
            max_nr=max_nr,
            rows="\n".join(row_lines) + ("\n" if row_lines else ""),
            index_rows="\n".join(index_row_lines) + ("\n" if index_row_lines else ""),
        )
    )
    print(f"wrote {args.out}")
    print(f"  total syscalls : {total}")
    print(f"  primary        : {primary} ({primary_pct}%)")
    print(f"  effective      : {effective} ({effective_pct}%)")
    print(f"  unimplemented  : {total - primary}")


if __name__ == "__main__":
    main()
