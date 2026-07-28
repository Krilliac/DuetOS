#!/usr/bin/env python3
#
# DuetOS untimed-WaitQueueBlock auditor.
#
# `sched::WaitQueueBlock(wq)` parks the caller with NO timer arm: the
# only way back is an explicit WaitQueueWake{One,All}. That is correct
# when the waker is another task holding the same lock, and WRONG when
# the waker is a device ISR, because the "check the condition under
# arch::Cli, then block" guard that closes the race on a uniprocessor
# closes nothing on SMP — the ISR runs on whichever CPU the MSI-X
# vector is routed to, so it can fire (and wake an empty queue) in the
# window between the re-check and the enqueue inside WaitQueueBlock.
# The task then sleeps forever on a live, healthy device.
#
# Scope: only translation units that bind an interrupt are considered.
# A wait queue woken by a peer TASK is not in this class — the waker
# takes g_sched_lock, and an untimed block there is the ordinary
# condition-variable contract (e.g. a Linux mq_* call asked to block
# with a NULL timeout). Requiring an ISR waker is what keeps this a
# zero-false-positive gate rather than a style complaint.
#
# Within those TUs, two mechanical shapes make the failure both real
# and unrecoverable; each is a rule here:
#
#   A. Deadline contradiction. The enclosing function computes an
#      HPET deadline / tick budget — i.e. it has already decided the
#      wait is bounded — and then blocks untimed. The untimed block
#      makes the deadline check unreachable, so the timeout and the
#      surprise-removal escape it guards can never run.
#
#   B. UP-only lost-wakeup guard. The block is immediately preceded by
#      an `arch::Cli()` + a re-check that `continue`s. That idiom is
#      an explicit claim to have closed the lost-wakeup race, and it
#      is only true on a uniprocessor.
#
# The fix in both cases is `WaitQueueBlockTimeout(wq, /*ticks=*/1)`:
# the enclosing retry loop re-reads its condition anyway, so a timeout
# wake is a free retry and a real wake is still immediate.
#
# Usage:
#   tools/test/untimed-waitqueue-audit.py [paths...]
# With no paths it scans the standard source roots.
#
# Exit status: 0 if no offending call site is found, 1 otherwise — so
# it works as a human report AND a scripted/CI gate. It is tuned for
# ZERO false positives on a clean tree; a plain condition-variable
# wait woken by another task matches neither rule and is not flagged.
#
# Reusable rig (CLAUDE.md "Reusable Tooling"). Sibling of
# tools/test/alloc-null-check-audit.py.

import os
import re
import sys

DEFAULT_ROOTS = ("kernel", "drivers", "subsystems", "userland")
SRC_EXT = (".c", ".cpp", ".cc")

# The header above is a comment block, not a docstring, so __doc__ is
# None — spell the help text out rather than print "None".
USAGE = (
    "usage: tools/test/untimed-waitqueue-audit.py [paths...]\n"
    "\n"
    "Flags sched::WaitQueueBlock call sites whose waker is a device ISR:\n"
    "  [A] the enclosing function already bounded the wait with an HPET\n"
    "      deadline / tick budget, which the untimed block makes\n"
    "      unreachable;\n"
    "  [B] the block sits behind an arch::Cli() + `continue` re-check,\n"
    "      a lost-wakeup guard that only holds on a uniprocessor.\n"
    "Fix either with WaitQueueBlockTimeout(wq, /*ticks=*/1).\n"
    "\n"
    "With no paths, scans: " + " ".join(DEFAULT_ROOTS) + "\n"
    "Exit status: 0 clean, 1 if any site is flagged (usable as a gate)."
)

# The untimed primitive only. `WaitQueueBlockTimeout(` does not match
# because of the mandatory `(` — it is the fix, not the defect.
BLOCK_RE = re.compile(r"\bWaitQueueBlock\s*\(")

# A TU that binds an IRQ/MSI-X vector has an ISR waker, which is the
# precondition for the whole class (see the header).
ISR_TU_RE = re.compile(r"\b(?:IrqInstall|IdtSetGate|MsiX\w*|irq_vector|\w*IsrHandler)\b")

# Rule A: names that mean "this function already bounded its wait".
DEADLINE_RE = re.compile(r"\b(?:Hpet\w*Deadline\w*|\w*deadline\w*|\w*budget\w*|\w*timeout_ticks\w*)\b", re.IGNORECASE)

# Rule B: the UP-only guard. Both must appear in the lines just above
# the block, inside the same function.
CLI_RE = re.compile(r"\bCli\s*\(\s*\)")
CONTINUE_RE = re.compile(r"\bcontinue\s*;")
GUARD_WINDOW = 15

# Blocks whose opener is one of these are not the enclosing function.
NOT_A_FUNCTION_RE = re.compile(r"\b(?:namespace|struct|class|union|enum|if|else|for|while|switch|do|try|catch)\b")


def strip_code(text):
    """Blank out comments and string/char literals, preserving line count.

    Brace matching below is textual, so a `{` inside a comment or a
    string would corrupt the function-extent walk."""
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
            if c == '"':
                state = "string"
                out.append(" ")
                i += 1
                continue
            if c == "'":
                state = "char"
                out.append(" ")
                i += 1
                continue
            out.append(c)
        elif state == "line_comment":
            if c == "\n":
                state = "code"
                out.append(c)
            else:
                out.append(" ")
        elif state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
                continue
            out.append(c if c == "\n" else " ")
        else:  # string / char literal
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if (state == "string" and c == '"') or (state == "char" and c == "'"):
                state = "code"
            out.append(c if c == "\n" else " ")
        i += 1
    return "".join(out)


def header_for(lines, opener):
    """The signature line belonging to a brace opener (Allman style)."""
    if lines[opener].strip() not in ("{", ""):
        return lines[opener]
    j = opener - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    return lines[j] if j >= 0 else ""


def enclosing_function(lines, idx):
    """(start, end) line indexes of the function body containing `idx`.

    Walks outward through enclosing brace openers and stops at the
    first one whose header reads like a function rather than a
    namespace / type / control-flow block. Returns None if the call
    site is not inside a function body we can bound."""
    depth = 0
    for i in range(idx, -1, -1):
        scan = lines[i][: lines[i].find("WaitQueueBlock")] if i == idx else lines[i]
        for ch in reversed(scan):
            if ch == "}":
                depth += 1
            elif ch == "{":
                if depth > 0:
                    depth -= 1
                    continue
                if NOT_A_FUNCTION_RE.search(header_for(lines, i)):
                    continue  # keep walking outward
                # Found the function opener — find its matching close.
                bal = 0
                for j in range(i, len(lines)):
                    bal += lines[j].count("{") - lines[j].count("}")
                    if bal == 0 and j > i:
                        return (i, j)
                return (i, len(lines) - 1)
    return None


def scan_file(path):
    findings = []
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return findings
    if "WaitQueueBlock" not in raw or not ISR_TU_RE.search(raw):
        return findings
    src = raw.splitlines()
    code = strip_code(raw).splitlines()
    for i, line in enumerate(code):
        if not BLOCK_RE.search(line):
            continue
        extent = enclosing_function(code, i)
        if extent is None:
            continue
        start, end = extent
        body = "\n".join(code[start : end + 1])
        window = "\n".join(code[max(start, i - GUARD_WINDOW) : i])
        if DEADLINE_RE.search(body):
            findings.append((i + 1, "A", "untimed block inside a deadline-bounded function", src[i].strip()[:90]))
        elif CLI_RE.search(window) and CONTINUE_RE.search(window):
            findings.append((i + 1, "B", "untimed block behind a UP-only Cli re-check guard", src[i].strip()[:90]))
    return findings


def gather(paths):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        for root, _, names in os.walk(p):
            for n in names:
                if n.endswith(SRC_EXT):
                    files.append(os.path.join(root, n))
    return sorted(set(files))


def main(argv):
    roots = []
    for a in argv[1:]:
        if a in ("-h", "--help"):
            print(USAGE)
            return 0
        roots.append(a)
    if not roots:
        roots = [r for r in DEFAULT_ROOTS if os.path.isdir(r)]

    total = 0
    for f in gather(roots):
        for lineno, rule, why, text in scan_file(f):
            print("%s:%d: [%s] %s: %s" % (f.replace(os.sep, "/"), lineno, rule, why, text))
            total += 1

    if total:
        print(
            "\n[untimed-waitqueue] %d offending WaitQueueBlock site(s); use "
            "WaitQueueBlockTimeout(wq, /*ticks=*/1)" % total,
            file=sys.stderr,
        )
        return 1
    print("[untimed-waitqueue] PASS (no deadline-defeating / UP-only-guarded blocks)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
