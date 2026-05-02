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
// Implemented (Do<Name> body in some syscall_*.cpp): {primary}
// Dispatched (kSys<Name> case but no Do<Name>; inline impl): {dispatched}
// Effective coverage (Implemented + Dispatched + LinuxGapFill): {effective}
// Coverage (implemented): {primary_pct}%
// Coverage (effective): {effective_pct}%
//
// See tools/linux-compat/README.md for provenance.

#pragma once

#include "util/types.h"

namespace duetos::subsystems::linux
{{

enum class HandlerState : u8
{{
    Unknown = 0,     // number outside the known ABI range
    Unimplemented,   // deliberate -ENOSYS (kSysEnosys_-block) or no kSys constant at all
    Dispatched,      // kSys<Name> case exists in dispatch but no Do<Name> body
                     // (inline impl, alias to non-Do<Name> fn, etc.). Returns a
                     // coherent value to userspace, just not via the Do<Name>
                     // convention the script's heuristic looks for.
    Implemented,     // known name, matching Do<Name> handler exists in some
                     // syscall_*.cpp peer.
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
inline constexpr u32 kLinuxSyscallHandlersImplementedPrimary = {primary};
inline constexpr u32 kLinuxSyscallHandlersImplementedEffective = {effective};

/// Look up `nr` in the dense by-number index. Returns nullptr if unknown.
inline const LinuxSyscallEntry* LinuxSyscallLookup(u64 nr)
{{
    if (nr > kLinuxSyscallMaxNumber)
        return nullptr;
    return kLinuxSyscallByNumber[static_cast<u32>(nr)];
}}

}} // namespace duetos::subsystems::linux
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
    # Every handler body in syscall_*.cpp is declared as
    # `i64 DoFoo(...)`. Grep them out.
    return set(re.findall(r"\bi64\s+(Do[A-Za-z0-9_]+)\s*\(", source_text))


def build_dispatched_numbers(source_text):
    """Return the set of syscall numbers reachable through the
    primary dispatcher's switch — anything with a `case kSysX:`
    that ISN'T inside the kSysEnosys_-only block at the bottom.

    The kSysEnosys_<Name> = N constants live in the enum next to
    the canonical kSys<Name>; their cases all collapse onto a
    single `rv = kENOSYS; break;` arm. Numbers in that arm are
    deliberately unimplemented (deprecated / never-released
    surfaces); numbers OUTSIDE it have either a real Do<Name>
    handler or an inline impl that returns something other than
    -ENOSYS.
    """
    name_to_num = {}
    for m in re.finditer(r"\b(kSys[A-Za-z0-9_]+)\s*=\s*(\d+)\s*,", source_text):
        name_to_num[m.group(1)] = int(m.group(2))
    enosys_numbers = {n for name, n in name_to_num.items() if name.startswith("kSysEnosys_")}
    case_names = set(re.findall(r"\bcase\s+(kSys[A-Za-z0-9_]+)\s*:", source_text))
    dispatched = set()
    for name in case_names:
        nr = name_to_num.get(name)
        if nr is not None and nr not in enosys_numbers:
            dispatched.add(nr)
    return dispatched


def classify(name, number, dispatcher_symbols, dispatched_numbers):
    """Three states:
       Implemented   — a Do<Name> body exists in some syscall_*.cpp.
       Dispatched    — kSys<Name> has a switch case in the dispatcher
                       (inline impl, alias to a non-Do<Name> function,
                       or routes through a sub-namespace fn) but no
                       Do<Name> body exists. Reaches the user with a
                       coherent return value, just not via the
                       Do<Name> convention.
       Unimplemented — neither of the above. Includes the
                       kSysEnosys_* deliberate-ENOSYS block plus any
                       syscall that has no kSys constant at all.
    """
    sym = NAME_ALIASES.get(name)
    if sym and sym in dispatcher_symbols:
        return "Implemented"
    sym = f"Do{snake_to_camel(name)}"
    if sym in dispatcher_symbols:
        return "Implemented"
    if number in dispatched_numbers:
        return "Dispatched"
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
    dispatched_numbers = set()
    if args.mapped_from_dispatcher is not None:
        # The syscall dispatch lives in syscall.cpp but the
        # individual `Do*` handlers are split across the
        # syscall_<family>.cpp peers. Scan the whole
        # subsystems/linux/ directory for `i64 DoFoo(...)`
        # bodies, not just the single dispatcher TU.
        dispatcher_dir = args.mapped_from_dispatcher.parent
        for cpp in sorted(dispatcher_dir.glob("syscall*.cpp")):
            dispatcher_symbols |= build_dispatcher_symbols(cpp.read_text())
        # The dispatcher TU is the canonical source for
        # "which kSys numbers have a switch case that isn't
        # the kSysEnosys_-only collapsed arm".
        dispatched_numbers = build_dispatched_numbers(
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
            state = classify(name, nr, dispatcher_symbols, dispatched_numbers)
            rows.append((nr, name, args_n, state))

    rows.sort(key=lambda r: r[0])

    primary = sum(1 for _, _, _, s in rows if s == "Implemented")
    dispatched = sum(1 for _, _, _, s in rows if s == "Dispatched")
    effective = sum(1 for nr, _, _, s in rows if s in ("Implemented", "Dispatched")
                                              or (nr in gap_fill_numbers))
    total = len(rows)
    max_nr = max((nr for nr, _, _, _ in rows), default=0)
    primary_pct = (100 * primary // total) if total else 0
    effective_pct = (100 * effective // total) if total else 0

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
            primary=primary,
            dispatched=dispatched,
            effective=effective,
            primary_pct=primary_pct,
            effective_pct=effective_pct,
            implemented=primary,
            max_nr=max_nr,
            rows="\n".join(row_lines) + ("\n" if row_lines else ""),
            index_rows="\n".join(index_row_lines) + ("\n" if index_row_lines else ""),
        )
    )
    print(f"wrote {args.out}")
    print(f"  total syscalls : {total}")
    print(f"  implemented    : {primary} ({primary_pct}%)")
    print(f"  dispatched     : {dispatched}")
    print(f"  effective      : {effective} ({effective_pct}%)")
    print(f"  unimplemented  : {total - effective}")


if __name__ == "__main__":
    main()
