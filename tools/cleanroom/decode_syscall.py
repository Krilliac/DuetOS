#!/usr/bin/env python3
"""Annotate CRTRACE syscall::* entries with human-readable names.

The kernel records `syscall::native-dispatch` and
`syscall::linux-dispatch` entries with a=syscall_num, b=pid,
c=rip. This helper prints the equivalent of `crtrace show` with
each numeric syscall replaced by its symbol so the trace is
readable without cross-referencing kernel/core/syscall.h and
kernel/subsystems/linux/syscall.cpp by hand.

Usage:
    tools/cleanroom/decode_syscall.py LOG     # decode all CRTRACE syscall entries
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Native syscall map — extracted from kernel/core/syscall.h
# (numbers under SYS_*). Keep this in sync when new SYS_* lands.
NATIVE_SYSCALLS: dict[int, str] = {
    0: "EXIT", 1: "GETPID", 2: "WRITE", 3: "YIELD", 4: "STAT",
    5: "READ", 6: "DROPCAPS", 7: "SPAWN", 8: "GETPROCID",
    9: "GETLASTERROR", 10: "SETLASTERROR", 11: "HEAP_ALLOC",
    12: "HEAP_FREE", 13: "PERF_COUNTER", 14: "HEAP_SIZE",
    15: "HEAP_REALLOC", 17: "GETTIME_FT", 18: "NOW_NS",
    19: "SLEEP_MS", 20: "FILE_OPEN", 21: "FILE_READ",
    22: "FILE_CLOSE", 23: "FILE_SEEK", 24: "FILE_FSTAT",
    25: "MUTEX_CREATE", 26: "MUTEX_WAIT", 27: "MUTEX_RELEASE",
    28: "VMAP", 29: "VUNMAP", 30: "EVENT_CREATE",
    31: "EVENT_SET", 32: "EVENT_RESET", 33: "EVENT_WAIT",
    34: "TLS_ALLOC", 35: "TLS_FREE", 36: "TLS_GET",
    37: "TLS_SET", 38: "BP_INSTALL", 39: "BP_REMOVE",
    40: "GETTIME_ST", 41: "ST_TO_FT", 42: "FT_TO_ST",
    43: "FILE_WRITE", 44: "FILE_CREATE", 45: "THREAD_CREATE",
    46: "DEBUG_PRINT", 47: "MEM_STATUS", 48: "WAIT_MULTI",
    49: "SYSTEM_INFO", 50: "DEBUG_PRINTW", 51: "SEM_CREATE",
    52: "SEM_RELEASE", 53: "SEM_WAIT", 54: "THREAD_WAIT",
    55: "THREAD_EXIT_CODE", 56: "NT_INVOKE",
    57: "DLL_PROC_ADDRESS", 58: "WIN_CREATE", 59: "WIN_DESTROY",
    60: "WIN_SHOW", 61: "WIN_MSGBOX", 62: "WIN_PEEK_MSG",
    63: "WIN_GET_MSG", 64: "WIN_POST_MSG", 65: "GDI_FILL_RECT",
    66: "GDI_TEXT_OUT", 67: "GDI_RECTANGLE", 68: "GDI_CLEAR",
    69: "WIN_MOVE", 70: "WIN_GET_RECT", 71: "WIN_SET_TEXT",
    72: "WIN_TIMER_SET", 73: "WIN_TIMER_KILL", 74: "GDI_LINE",
    75: "GDI_ELLIPSE", 76: "GDI_SET_PIXEL",
    77: "WIN_GET_KEYSTATE", 78: "WIN_GET_CURSOR",
    79: "WIN_SET_CURSOR", 80: "WIN_SET_CAPTURE",
}

# Linux ABI map — only the entries we've actually seen on a
# clean-room boot survey, plus the obvious neighbors. Add more
# as they show up in traces.
LINUX_SYSCALLS: dict[int, str] = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    5: "fstat", 8: "lseek", 9: "mmap", 10: "mprotect",
    11: "munmap", 12: "brk", 13: "rt_sigaction",
    14: "rt_sigprocmask", 16: "ioctl", 21: "access",
    28: "madvise", 39: "getpid", 56: "clone", 57: "fork",
    58: "vfork", 59: "execve", 60: "exit", 63: "uname",
    72: "fcntl", 79: "getcwd", 89: "readlink", 90: "chmod",
    96: "gettimeofday", 158: "arch_prctl", 186: "gettid",
    202: "futex", 218: "set_tid_address", 228: "clock_gettime",
    231: "exit_group", 257: "openat", 273: "set_robust_list",
    302: "prlimit64", 318: "getrandom", 322: "execveat",
    334: "rseq",
}

CRTRACE_SYSCALL_RE = re.compile(
    r"^CRTRACE\s+0x[0-9a-fA-F]+\s+syscall::(native-dispatch|linux-dispatch)"
    r"\s+a=0x([0-9a-fA-F]+)\s+b=0x([0-9a-fA-F]+)\s+c=0x([0-9a-fA-F]+)"
)


def annotate_line(line: str) -> str:
    m = CRTRACE_SYSCALL_RE.match(line)
    if not m:
        return line
    flavor, a_hex, b_hex, c_hex = m.groups()
    n = int(a_hex, 16)
    pid = int(b_hex, 16)
    rip = int(c_hex, 16)
    table = NATIVE_SYSCALLS if flavor == "native-dispatch" else LINUX_SYSCALLS
    name = table.get(n, "?")
    flavor_short = "native" if flavor == "native-dispatch" else "linux "
    return f"{flavor_short}  pid={pid:#06x}  rip={rip:#018x}  nr={n:>3d}  {name}"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("log", help="serial log captured from a survey boot")
    p.add_argument("--summary", action="store_true",
                   help="print a count-per-syscall histogram instead of per-line")
    args = p.parse_args()

    lines = Path(args.log).read_bytes().decode("utf-8", errors="replace").splitlines()
    if args.summary:
        from collections import Counter
        hist: Counter[tuple[str, int, str]] = Counter()
        for raw in lines:
            m = CRTRACE_SYSCALL_RE.match(raw)
            if not m:
                continue
            flavor, a_hex, _b, _c = m.groups()
            n = int(a_hex, 16)
            table = NATIVE_SYSCALLS if flavor == "native-dispatch" else LINUX_SYSCALLS
            hist[(flavor, n, table.get(n, "?"))] += 1
        for (flavor, n, name), count in sorted(hist.items(), key=lambda x: -x[1]):
            short = "native" if flavor == "native-dispatch" else "linux "
            print(f"{count:>5d}  {short}  nr={n:>3d}  {name}")
        return 0

    for raw in lines:
        out = annotate_line(raw.rstrip())
        if out != raw.rstrip():
            print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
