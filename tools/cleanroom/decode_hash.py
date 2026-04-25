#!/usr/bin/env python3
"""Reverse-look-up for shell::command hashes in CRTRACE entries.

The kernel records `CleanroomTraceHashToken(cmd)` (a hash of the
command name) in the `a` slot of each `shell::command` entry, and
the same hash of `argv[1]` in the `c` slot. This helper hashes a
list of candidate command names with the kernel's hash function
and prints a hash -> name table you can grep CRTRACE output
against.

The kernel's hash function is in
kernel/core/cleanroom_trace.cpp:CleanroomTraceHashToken. It uses
FNV-1a-style mixing with a NON-STANDARD offset basis
(1469598103934665603 — one digit short of the real FNV-1a-64
offset 14695981039346656037). This script intentionally uses the
SAME constant the kernel uses so the hashes match what's in
the trace, and DOES NOT pretend to be a portable FNV-1a
implementation. If the kernel constant is ever fixed to the
real FNV-1a offset, update KERNEL_FNV_OFFSET here in lockstep.

Usage:
    tools/cleanroom/decode_hash.py [name ...]
    tools/cleanroom/decode_hash.py --all          # hash every shell command name
    tools/cleanroom/decode_hash.py --grep TRACE   # find hashes in TRACE that match a known name
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Mirror of the kernel's offset/prime — see kernel/core/cleanroom_trace.cpp:82.
KERNEL_FNV_OFFSET = 1469598103934665603
KERNEL_FNV_PRIME  = 1099511628211
U64_MASK          = (1 << 64) - 1


def kernel_hash(s: str) -> int:
    h = KERNEL_FNV_OFFSET
    for b in s.encode():
        h ^= b
        h = (h * KERNEL_FNV_PRIME) & U64_MASK
    return h


# Curated baseline of shell command names. Extracted from
# kernel/core/shell.cpp's command-name table on 2026-04-25.
# Keep alphabetically sorted; new commands can be appended.
KNOWN_SHELL_COMMANDS: tuple[str, ...] = (
    "about", "alias", "attacksim", "bp", "breakpoint", "cat", "cd",
    "checkup", "clear", "cls", "cp", "crtrace", "date", "dhcp",
    "echo", "env", "expr", "exit", "find", "fwpolicy", "fwtrace",
    "grep", "guard", "health", "help", "history", "ifconfig",
    "inspect", "instr", "kill", "l", "linuxexec", "ll", "logout",
    "ls", "man", "memdump", "mount", "msr", "mv", "net", "netinfo",
    "netscan", "passwd", "pid", "ping", "probe", "ps", "redteam",
    "reboot", "redirect", "route", "set", "shutdown", "sleep",
    "source", "spawn", "sysinfo", "time", "unalias", "unset",
    "useradd", "usbnet", "uuid", "uuidgen", "wifi", "whoami",
)


def cmd_hash_table(names: list[str]) -> dict[int, str]:
    return {kernel_hash(n): n for n in names}


def parse_grep(log_path: Path) -> int:
    table = cmd_hash_table(list(KNOWN_SHELL_COMMANDS))
    pat = re.compile(r"CRTRACE\s+[\w:.-]+::command\s*0x([0-9a-fA-F]{16})")
    found = 0
    raw_bytes = log_path.read_bytes()
    for raw in raw_bytes.decode("utf-8", errors="replace").splitlines():
        m = pat.search(raw)
        if not m:
            continue
        h = int(m.group(1), 16)
        name = table.get(h)
        if name is not None:
            found += 1
            print(f"0x{h:016x}  {name:<12s}  {raw.rstrip()}")
        else:
            print(f"0x{h:016x}  <unknown>     {raw.rstrip()}")
    return 0 if found else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true",
                   help="print hash for every name in the curated list")
    g.add_argument("--grep", metavar="LOG",
                   help="annotate CRTRACE shell::command hashes from LOG with names")
    p.add_argument("names", nargs="*", help="command names to hash")
    args = p.parse_args()

    if args.grep:
        return parse_grep(Path(args.grep))

    names = list(KNOWN_SHELL_COMMANDS) if args.all else args.names
    if not names:
        p.print_help(sys.stderr)
        return 2
    for n in names:
        print(f"0x{kernel_hash(n):016x}  {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
