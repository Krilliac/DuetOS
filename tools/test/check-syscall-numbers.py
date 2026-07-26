#!/usr/bin/env python3
"""
check-syscall-numbers.py — verify every annotated syscall literal in the
userland Win32 DLLs against the kernel's authoritative syscall enum.

WHAT
    Parses `{number -> SYS_NAME}` from kernel/syscall/syscall.h, then
    scans userland/libs/**/*.{c,h} for syscall invocation sites that
    STATE which syscall they mean:

        __asm__ ... "a"((long long)20), /* SYS_FILE_OPEN */
        duet_syscall1(19 /* SYS_SLEEP_MS */, ms);

    and checks the stated name against the number actually used.

    MISMATCH  the named syscall exists, but at a different number.
    PHANTOM   the named syscall does not exist in the enum at all.

WHY
    Hand-written syscall numbers in the DLL thunks are literals no
    compiler can check, and a wrong one is invisible until a guest PE
    exercises it — at which point it silently performs an unrelated
    kernel operation rather than failing. This has now bitten SIX times:

        GetModuleHandleA   79 -> SYS_WIN_SET_CURSOR   (fixed 2026-06-17)
        CloseHandle         4 -> SYS_STAT             (fixed 2026-07-26)
        Sleep              11 -> SYS_HEAP_ALLOC       (fixed 2026-07-26)
        GetTickCount       70 -> SYS_WIN_GET_RECT     (fixed 2026-07-26)
        HeapAlloc          71 -> SYS_WIN_SET_TEXT     (fixed 2026-07-26)
        HeapFree           72 -> SYS_WIN_TIMER_SET    (fixed 2026-07-26)
        GetProcAddress     80 -> SYS_WIN_SET_CAPTURE  (fixed 2026-07-26)
        CreateWaitableTimerW 33 -> SYS_EVENT_WAIT     (fixed 2026-07-26)

    Every one of them named its intended syscall in a comment while
    calling a different number, so every one is mechanically detectable.
    This turns a recurring per-call-site mistake into a check.

DELIBERATE LIMIT
    Only sites that NAME a syscall are checked. A bare literal states no
    intent, so there is nothing to verify it against — those are counted
    and reported under --list-unannotated, never failed. Annotating a
    call site is therefore what buys it coverage.

    This checks the NUMBER, not the argument registers. A call with the
    right number but the wrong argument slot (the i386 remap puts
    ebx/ecx/edx -> rdi/rsi/rdx) is out of scope and still needs review
    against the enum's per-syscall doc comment.

USAGE
    python3 tools/test/check-syscall-numbers.py [--root <repo>]
              [--list-unannotated] [--strict]

    Exit 0 clean / 1 on any MISMATCH or PHANTOM.

QUICK ANALYSIS
    # what the checker can see in one DLL
    python3 tools/test/check-syscall-numbers.py --list-unannotated \\
        | grep kernel32_32
"""

import argparse
import os
import re
import sys

# `    SYS_FOO = 42,` inside the syscall enum.
_ENUM_ENTRY = re.compile(r"^\s*(SYS_[A-Z0-9_]+)\s*=\s*(\d+)\s*,", re.MULTILINE)

# 64-bit inline-asm form: "a"((long long)20)  /  "a"((long)19)
_ASM_SITE = re.compile(r'"a"\(\s*\(\s*long(?:\s+long)?\s*\)\s*(\d+)\s*\)')
# 32-bit trampoline form: duet_syscall3(172, ...)
_TRAMPOLINE_SITE = re.compile(r"\bduet_syscall\d\s*\(\s*(\d+)")

# A SYS_* name mentioned in a comment.
_NAME_IN_COMMENT = re.compile(r"/\*[^*]*?(SYS_[A-Z0-9_]+)[^*]*?\*/|//[^\n]*?(SYS_[A-Z0-9_]+)")

# A prose assertion of the form `SYS_FOO = 42`, wherever it appears —
# in a doc block, a file header, anywhere. Position-independent, and
# precise because `= <number>` is an explicit factual claim rather than
# a passing mention. This is what catches a wrong name stated in a
# function's doc block instead of on the call line, which is where
# GetProcAddress hid ("SYS_DLL_PROC_ADDR = 80", three lines up).
#
# A bare `SYS_FOO` mention is deliberately NOT checked. Prose
# legitimately names wildcards (`SYS_WIN_*`), syscalls that do not
# exist yet by design (`// GAP: needs SYS_FILE_TRUNCATE`), and — in
# this very file's sibling comments — the wrong names of already-fixed
# bugs. Flagging those produced 20+ false positives on a clean tree,
# and a check that cries wolf gets ignored.
_NAME_EQ_NUM = re.compile(r"\b(SYS_[A-Z0-9_]+)\s*=\s*(\d+)\b")


def parse_enum(syscall_h):
    """Return {number: name} and {name: number} from the kernel enum."""
    with open(syscall_h, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    by_num = {}
    by_name = {}
    for m in _ENUM_ENTRY.finditer(text):
        name, num = m.group(1), int(m.group(2))
        # First definition wins; the enum has no intentional duplicates,
        # and a later alias must not mask the canonical name.
        by_num.setdefault(num, name)
        by_name.setdefault(name, num)
    return by_num, by_name


def claimed_name(line):
    """The SYS_* name a call site states on its own line, if any."""
    m = _NAME_IN_COMMENT.search(line)
    if not m:
        return None
    return m.group(1) or m.group(2)


def scan_file(path):
    """Yield (lineno, number, claimed_name_or_None, line) per call site."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    for idx, line in enumerate(lines, start=1):
        for pattern in (_ASM_SITE, _TRAMPOLINE_SITE):
            for m in pattern.finditer(line):
                number = int(m.group(1))
                name = claimed_name(line)
                # An asm operand line often carries its comment on the
                # SAME line; a trampoline call may put it just after the
                # literal. Both are covered by same-line search. If the
                # line has no comment, look one line ahead for the
                # continuation operand's comment only when this line
                # ends mid-expression (trailing comma).
                if name is None and line.rstrip().endswith(",") and idx < len(lines):
                    name = claimed_name(lines[idx])
                yield idx, number, name, line.strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    ap.add_argument("--root", default=default_root, help="repo root (default: inferred from this script)")
    ap.add_argument("--list-unannotated", action="store_true", help="also list call sites that name no syscall")
    ap.add_argument("--strict", action="store_true", help="fail if any call site is unannotated")
    args = ap.parse_args()

    syscall_h = os.path.join(args.root, "kernel", "syscall", "syscall.h")
    libs_root = os.path.join(args.root, "userland", "libs")
    if not os.path.isfile(syscall_h):
        print("check-syscall-numbers: missing %s" % syscall_h, file=sys.stderr)
        return 2
    if not os.path.isdir(libs_root):
        print("check-syscall-numbers: missing %s" % libs_root, file=sys.stderr)
        return 2

    by_num, by_name = parse_enum(syscall_h)
    if not by_num:
        print("check-syscall-numbers: parsed 0 enum entries — refusing to report a vacuous pass", file=sys.stderr)
        return 2

    errors = 0
    checked = 0
    name_checked = 0
    unannotated = []

    for dirpath, _dirnames, filenames in os.walk(libs_root):
        for fn in sorted(filenames):
            if not (fn.endswith(".c") or fn.endswith(".h")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, args.root).replace("\\", "/")

            # Position-independent assertion check — see _NAME_EQ_NUM.
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                blines = fh.readlines()
            for lineno, line in enumerate(blines, start=1):
                for m in _NAME_EQ_NUM.finditer(line):
                    nm, asserted = m.group(1), int(m.group(2))
                    name_checked += 1
                    if nm not in by_name:
                        print("BAD-ASSERTION %s:%d: asserts '%s = %d', but '%s' is not in the syscall enum "
                              "(%d is %s)" % (rel, lineno, nm, asserted, nm, asserted,
                                              by_num.get(asserted, "undefined")))
                        print("         %s" % line.strip())
                        errors += 1
                    elif by_name[nm] != asserted:
                        print("BAD-ASSERTION %s:%d: asserts '%s = %d', enum says %d (%d is %s)"
                              % (rel, lineno, nm, asserted, by_name[nm], asserted,
                                 by_num.get(asserted, "undefined")))
                        print("         %s" % line.strip())
                        errors += 1

            for lineno, number, name, line in scan_file(path):
                if name is None:
                    unannotated.append((rel, lineno, number, line))
                    continue
                checked += 1
                actual = by_num.get(number)
                if name not in by_name:
                    print("PHANTOM  %s:%d: names '%s', which is not in the syscall enum "
                          "(number %d is %s)" % (rel, lineno, name, number, actual or "undefined"))
                    print("         %s" % line)
                    errors += 1
                elif by_name[name] != number:
                    print("MISMATCH %s:%d: names '%s' (= %d) but calls %d (= %s)"
                          % (rel, lineno, name, by_name[name], number, actual or "undefined"))
                    print("         %s" % line)
                    errors += 1

    if args.list_unannotated:
        for rel, lineno, number, line in unannotated:
            print("UNANNOTATED %s:%d: calls %d (%s) with no SYS_* named" % (rel, lineno, number,
                                                                           by_num.get(number, "undefined")))

    print("check-syscall-numbers: %d enum entries, %d annotated site(s) verified, "
          "%d asserted number(s) checked, %d unannotated, %d error(s)"
          % (len(by_num), checked, name_checked, len(unannotated), errors))
    if errors or (args.strict and unannotated):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
