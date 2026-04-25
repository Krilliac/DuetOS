#!/usr/bin/env python3
"""Reverse-look-up for shell::command hashes in CRTRACE entries.

The kernel records `CleanroomTraceHashToken(cmd)` (a hash of the
command name) in the `a` slot of each `shell::command` entry, and
the same hash of `argv[1]` in the `c` slot. This helper hashes a
list of candidate command names with the kernel's hash function
and prints a hash -> name table you can grep CRTRACE output
against.

The kernel's hash function is in
kernel/core/cleanroom_trace.cpp:CleanroomTraceHashToken — RFC-
style FNV-1a-64 (offset 14695981039346656037, prime
1099511628211). Any standard FNV-1a-64 implementation will
produce matching hashes. An earlier revision used a truncated
offset basis (1469598103934665603, missing the trailing digit);
that constant is preserved below as KERNEL_FNV_OFFSET_LEGACY so
old captured logs can still be decoded with --legacy-hash.

Usage:
    tools/cleanroom/decode_hash.py [name ...]
    tools/cleanroom/decode_hash.py --all          # hash every shell command name
    tools/cleanroom/decode_hash.py --grep TRACE   # find hashes in TRACE that match a known name
    tools/cleanroom/decode_hash.py --legacy-hash --grep OLD_TRACE   # for pre-fix captures
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Mirror of the kernel's current offset/prime — see kernel/core/cleanroom_trace.cpp.
KERNEL_FNV_OFFSET = 14695981039346656037
KERNEL_FNV_OFFSET_LEGACY = 1469598103934665603  # Pre-2026-04-25; missing trailing digit.
KERNEL_FNV_PRIME = 1099511628211
U64_MASK = (1 << 64) - 1


def kernel_hash(s: str, *, legacy: bool = False) -> int:
    h = KERNEL_FNV_OFFSET_LEGACY if legacy else KERNEL_FNV_OFFSET
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


def cmd_hash_table(names: list[str], *, legacy: bool = False) -> dict[int, str]:
    return {kernel_hash(n, legacy=legacy): n for n in names}


def parse_grep(log_path: Path, *, legacy: bool = False) -> int:
    table = cmd_hash_table(list(KNOWN_SHELL_COMMANDS), legacy=legacy)
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
    p.add_argument("--legacy-hash", action="store_true",
                   help="use the pre-2026-04-25 truncated FNV-1a offset basis (for old logs)")
    p.add_argument("names", nargs="*", help="command names to hash")
    args = p.parse_args()

    if args.grep:
        return parse_grep(Path(args.grep), legacy=args.legacy_hash)

    names = list(KNOWN_SHELL_COMMANDS) if args.all else args.names
    if not names:
        p.print_help(sys.stderr)
        return 2
    for n in names:
        print(f"0x{kernel_hash(n, legacy=args.legacy_hash):016x}  {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
