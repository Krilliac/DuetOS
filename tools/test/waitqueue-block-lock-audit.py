#!/usr/bin/env python3
#
# DuetOS untimed-WaitQueueBlock lock auditor.
#
# `sched::WaitQueueBlock(wq)` is the untimed park: it returns only
# when a waker calls WaitQueueWake{One,All} on the same queue. Its
# contract (sched.h) is "check condition, then block, both with
# interrupts disabled" — and on a uniprocessor `arch::Cli()` is
# enough to make that pair atomic.
#
# It is NOT enough on SMP. `Cli` masks interrupts on the CALLING CPU
# only; per-CPU runqueues plus work-stealing (sched.cpp
# RunqueuePushOn / StealNormalFromPeer) mean the waker genuinely runs
# at the same instant on another CPU. A waker that fires between the
# condition test and the enqueue is lost, and the sleeper stays
# parked until the NEXT event — forever if there isn't one. The same
# window lets a releaser free the very buffer the sleeper is about to
# read, which is how the socket layer's UDP RX ring turned into a
# use-after-free (kernel/net/socket.cpp, 2026-07-27 slice).
#
# There is no exported release-and-block primitive today
# (`WaitQueueBlockCurrentLocked` is file-local to sched.cpp), so the
# two acceptable shapes are:
#   1. hold a `sync::SpinLock` across the condition test, drop it,
#      and park with the BOUNDED `WaitQueueBlockTimeout` — the
#      timeout caps the residual lost-wake at N ticks; or
#   2. the eventual real fix: a `WaitQueueBlockLocked(wq, lock)` that
#      atomically releases the caller's lock and enqueues.
#
# This script pins the live inventory of call sites that are still on
# neither shape. It classifies every untimed `WaitQueueBlock(` site by
# what its enclosing function holds:
#
#   CLI-ONLY   — the function uses arch::Cli() and no spinlock. This
#                is the UP-only pattern; a real SMP lost-wake.
#   UNGUARDED  — neither. Either the caller establishes the guard
#                (check it by hand) or the site is plainly racy.
#   SPINLOCK   — the function does take a sync::SpinLock. Reported
#                for completeness; not counted against the gate.
#
# Heuristics, stated plainly: this is a per-function lexical scan, not
# a data-flow analysis. It cannot see a guard established by a caller,
# and it does not try to prove the spinlock it found is the one that
# guards the condition. That is why the gate is a per-file RATCHET
# against BASELINE below rather than a "must be zero" assert — the
# existing backlog is real work, not noise, and the useful signal is
# "did this slice ADD one".
#
# Usage:
#   tools/test/waitqueue-block-lock-audit.py [--list] [paths...]
#   tools/test/waitqueue-block-lock-audit.py --baseline   # emit a new
#                                                         # BASELINE dict
# With no paths it scans the standard kernel source roots.
#
# Exit status: 0 if no file exceeds its baseline count of
# CLI-ONLY + UNGUARDED sites, 1 otherwise. So it works as a human
# report AND a scripted/CI gate.
#
# Reusable rig (CLAUDE.md "Reusable Tooling"). Sibling of
# alloc-null-check-audit.py — same shape, same contract, different
# bug class.

import os
import re
import sys

DEFAULT_ROOTS = ("kernel", "drivers", "subsystems", "userland")
SRC_EXT = (".c", ".cpp", ".cc")

# The untimed park. `WaitQueueBlockTimeout` / `WaitQueueBlockCurrentLocked`
# do not match: the `(` has to follow the name directly.
BLOCK_RE = re.compile(r"\bWaitQueueBlock\s*\(")
CLI_RE = re.compile(r"\barch::Cli\s*\(")
SPIN_RE = re.compile(r"\b(?:SpinLockAcquire|SpinLockTryAcquire(?:For)?|SpinLock(?:Try|Reentrant)?Guard)\b")

# Per-file ceiling of CLI-ONLY + UNGUARDED sites. Regenerate with
# `--baseline` when a slice legitimately retires (or knowingly adds)
# sites, and say which in the commit message.
# Recorded 2026-07-27, immediately after kernel/net/socket.cpp was
# converted off the Cli-only shape (it held the 27th site). Every
# entry below is a real SMP lost-wake waiting to be retired the same
# way; the gate exists so the count only ever goes down.
BASELINE = {
    "kernel/diag/hung_task.cpp": 1,
    "kernel/drivers/input/ps2kbd.cpp": 1,
    "kernel/drivers/input/ps2mouse.cpp": 1,
    "kernel/drivers/storage/nvme.cpp": 1,
    "kernel/drivers/usb/xhci_init.cpp": 1,
    "kernel/proc/process.cpp": 1,
    "kernel/security/broker.cpp": 1,
    "kernel/subsystems/linux/fanotify.cpp": 1,
    "kernel/subsystems/linux/inotify.cpp": 1,
    "kernel/subsystems/linux/msg_queues.cpp": 3,
    "kernel/subsystems/linux/syscall_async_io.cpp": 1,
    "kernel/subsystems/linux/syscall_pipe.cpp": 7,
    "kernel/subsystems/linux/syscall_stub.cpp": 2,
    "kernel/subsystems/linux/sysv_ipc.cpp": 1,
    "kernel/subsystems/win32/dir_syscall.cpp": 1,
    "kernel/subsystems/win32/waitaddr_syscall.cpp": 1,
    "kernel/sync/adaptive_mutex.cpp": 1,
}


def strip_noise(text):
    """Blank out comments and string/char literals so doc prose that
    mentions WaitQueueBlock never counts as a call site."""
    out = []
    i = 0
    n = len(text)
    state = "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block_comment"
                out.append("  ")
                i += 2
                continue
            if c == '"' or c == "'":
                state = "str"
                quote = c
                out.append(" ")
                i += 1
                continue
            out.append(c)
            i += 1
        elif state == "line_comment":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
        elif state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
        else:  # str
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == quote:
                state = "code"
            out.append("\n" if c == "\n" else " ")
            i += 1
    return "".join(out)


def brace_spans(lines):
    """Every brace body in the file as (start_index, end_index).

    Nested bodies come out too — the caller picks the innermost span
    that looks like a function definition, so an `if` block inside a
    function doesn't shadow the function's own guards.
    """
    stack = []
    spans = []
    for idx, line in enumerate(lines):
        for ch in line:
            if ch == "{":
                stack.append(idx)
            elif ch == "}" and stack:
                spans.append((stack.pop(), idx))
    while stack:
        spans.append((stack.pop(), len(lines) - 1))
    return spans


NON_FUNC_KW = (
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "else",
    "do",
    "try",
    "namespace",
    "struct",
    "class",
    "union",
    "enum",
    "extern",
    "return",
    "case",
    "default",
)
# A definition header ends at the parameter list's `)`, optionally
# followed by cv / noexcept / trailing-return decoration.
FUNC_HDR_RE = re.compile(r"\)\s*(?:const\b\s*)?(?:noexcept\b[^;{]*)?(?:->[^;{]*)?$")


def header_text(lines, start):
    """Declarator text for the body opening on line `start` — the
    opening line up to its `{`, plus up to three continuation lines
    above it for signatures wrapped by clang-format."""
    parts = [lines[start].split("{")[0].strip()]
    i = start - 1
    while i >= 0 and (start - i) <= 3:
        text = lines[i].strip()
        if text == "" or text.endswith((";", "{", "}", ":")):
            break
        parts.insert(0, text)
        i -= 1
    return " ".join(p for p in parts if p).strip()


def is_function_header(header):
    if not header or not FUNC_HDR_RE.search(header):
        return False
    first = re.match(r"[A-Za-z_]\w*", header)
    return first is None or first.group(0) not in NON_FUNC_KW


def scan_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    if "WaitQueueBlock" not in raw:
        return []
    lines = strip_noise(raw).splitlines()
    spans = brace_spans(lines)
    funcs = [(s, e, header_text(lines, s)) for (s, e) in spans]
    funcs = [f for f in funcs if is_function_header(f[2])]

    findings = []
    for idx, line in enumerate(lines):
        m = BLOCK_RE.search(line)
        if m is None:
            continue
        # A call is a statement — it ends in `;`. Anything else on
        # that line is the primitive's own definition header in
        # kernel/sched/sched.cpp, which is not a call site.
        if ";" not in line[m.end() :]:
            continue
        # Innermost enclosing function definition.
        best = None
        for start, end, header in funcs:
            if start <= idx <= end and (best is None or start > best[0]):
                best = (start, end, header)
        if best is None:
            findings.append((idx + 1, "UNGUARDED", "<no enclosing function>"))
            continue
        body = "\n".join(lines[best[0] : best[1] + 1])
        if SPIN_RE.search(body):
            verdict = "SPINLOCK"
        elif CLI_RE.search(body):
            verdict = "CLI-ONLY"
        else:
            verdict = "UNGUARDED"
        findings.append((idx + 1, verdict, best[2]))
    return findings


def gather(roots):
    files = []
    for p in roots:
        if os.path.isfile(p):
            files.append(p)
            continue
        for root, _, names in os.walk(p):
            for n in names:
                if n.endswith(SRC_EXT):
                    files.append(os.path.join(root, n))
    return sorted(set(files))


def main(argv):
    show_all = False
    emit_baseline = False
    roots = []
    for a in argv[1:]:
        if a == "--list":
            show_all = True
        elif a == "--baseline":
            emit_baseline = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            roots.append(a)
    if not roots:
        roots = [r for r in DEFAULT_ROOTS if os.path.isdir(r)]

    counts = {}
    totals = {"CLI-ONLY": 0, "UNGUARDED": 0, "SPINLOCK": 0}
    for f in gather(roots):
        key = f.replace(os.sep, "/")
        for lineno, verdict, where in scan_file(f):
            totals[verdict] += 1
            if verdict == "SPINLOCK":
                if show_all:
                    print("%s:%d: [%s] %s" % (key, lineno, verdict, where))
                continue
            counts[key] = counts.get(key, 0) + 1
            print("%s:%d: [%s] untimed WaitQueueBlock in %s" % (key, lineno, verdict, where))

    if emit_baseline:
        print("\nBASELINE = {")
        for k in sorted(counts):
            print('    "%s": %d,' % (k, counts[k]))
        print("}")
        return 0

    print(
        "\n[waitqueue-block-lock] %d CLI-ONLY, %d UNGUARDED, %d SPINLOCK untimed-block site(s)"
        % (totals["CLI-ONLY"], totals["UNGUARDED"], totals["SPINLOCK"]),
        file=sys.stderr,
    )

    regressions = []
    for key, n in sorted(counts.items()):
        allowed = BASELINE.get(key, 0)
        if n > allowed:
            regressions.append("%s: %d site(s), baseline %d" % (key, n, allowed))
    if regressions:
        print("[waitqueue-block-lock] over baseline:", file=sys.stderr)
        for r in regressions:
            print("  " + r, file=sys.stderr)
        return 1
    print("[waitqueue-block-lock] PASS (no file over its baseline)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
