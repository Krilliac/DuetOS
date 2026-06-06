#!/usr/bin/env python3
#
# DuetOS allocation null-check auditor.
#
# Every memory allocator in DuetOS signals failure by returning a
# null pointer — the kernel slab/heap/stack allocators (KMalloc,
# SlabAlloc, SlabAllocZeroed, PoisonAlloc, AllocateKernelStack) and
# the userland CRT shims (malloc/calloc/realloc/strdup, HeapAlloc,
# VirtualAlloc). A caller that dereferences the result without first
# checking it for null faults the moment the allocator is exhausted.
#
# This is the static form of the "fix anything you surface" null
# sweep: instead of fanning out read-only agents over the tree every
# session, run this and get the live inventory of allocation sites
# whose result is NOT guarded within a short window. It is tuned for
# ZERO false positives on a clean tree so it doubles as a CI gate —
# any non-zero exit is a real regression to investigate, not noise.
#
# What "guarded" means (any of these within `--window` lines after
# the assignment, on the assigned variable `v`):
#   if (!v) / if (v == nullptr|NULL|0|(void*)0) / if (v != ...) /
#   if (v) / v == ... / v != ... / !v / ternary `v ?` / `v &&` /
#   KASSERT(v ...) / a bare `return v;` (handed to a caller to check).
#
# It deliberately covers ONLY the allocation-result class, which has
# clean signal. Div-by-zero / over-underflow / length checks were
# evaluated and rejected for a gate: they need data-flow the regex
# can't do and produce false positives that would make the gate cry
# wolf. Use the audit agents for those.
#
# Usage:
#   tools/test/alloc-null-check-audit.py [--window N] [paths...]
# With no paths it scans the standard source roots. Default window 10.
#
# Exit status: 0 if no unguarded allocation site found, 1 otherwise.
# So it works as a human report AND a scripted/CI gate.
#
# Reusable rig (CLAUDE.md "Reusable Tooling"). Pairs with the
# read-only audit agents — those reason about semantics; this pins
# the cheap, mechanical class so the next session doesn't re-derive
# the grep battery from scratch.

import os
import re
import sys

KERNEL_ALLOCS = ("KMalloc", "SlabAllocZeroed", "SlabAlloc", "PoisonAlloc", "AllocateKernelStack")
USER_ALLOCS = ("malloc", "calloc", "realloc", "strdup", "HeapAlloc", "VirtualAlloc")

DEFAULT_ROOTS = ("kernel", "drivers", "subsystems", "userland")
SRC_EXT = (".c", ".cpp", ".cc")


def build_alloc_re(names):
    # `<var> = [ (cast) ] Alloc(`  — allows a leading C-style cast.
    alt = "|".join(re.escape(n) for n in names)
    return re.compile(r"(\b\w+)\s*=\s*(?:\([^)=;]*\)\s*)?(?:" + alt + r")\s*\(")


def is_guarded(var, window_lines):
    v = re.escape(var)
    blob = "\n".join(window_lines)
    patterns = (
        r"!\s*%s\b" % v,
        r"%s\s*==\s*(nullptr|NULL|0|\(\s*void\s*\*\s*\)\s*0)" % v,
        r"%s\s*!=\s*(nullptr|NULL|0|\(\s*void\s*\*\s*\)\s*0)" % v,
        r"if\s*\(\s*%s\s*\)" % v,
        r"%s\s*&&" % v,
        r"%s\s*\?" % v,
        r"KASSERT\w*\(\s*%s\b" % v,
        r"return\s+%s\s*;" % v,  # forwarded to the caller to check
        # Comparison against another value (e.g. allocator self-tests
        # that assert `p != expected`): a null result still trips the
        # branch / assertion, so the deref below is reached only on the
        # non-null path.
        r"%s\s*(==|!=)\s*[A-Za-z0-9_(]" % v,
    )
    return any(re.search(p, blob) for p in patterns)


def scan_file(path, kern_re, user_re, window):
    findings = []
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return findings
    is_kernel = not path.replace(os.sep, "/").startswith("userland/")
    rx = kern_re if is_kernel else user_re
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        m = rx.search(line)
        if not m:
            continue
        var = m.group(1)
        if var in ("void", "auto", "const", "return"):
            continue
        # Window starts at the assignment line itself (same-line
        # ternary guards count) through `window` following lines.
        if is_guarded(var, lines[i : i + 1 + window]):
            continue
        findings.append((i + 1, line.strip()[:100]))
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
    window = 10
    roots = []
    it = iter(argv[1:])
    for a in it:
        if a == "--window":
            window = int(next(it))
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            roots.append(a)
    if not roots:
        roots = [r for r in DEFAULT_ROOTS if os.path.isdir(r)]

    kern_re = build_alloc_re(KERNEL_ALLOCS)
    user_re = build_alloc_re(USER_ALLOCS)

    total = 0
    for f in gather(roots):
        for lineno, text in scan_file(f, kern_re, user_re, window):
            print("%s:%d: unguarded allocation result: %s" % (f, lineno, text))
            total += 1

    if total:
        print("\n[alloc-null-check] %d unguarded allocation site(s) found" % total, file=sys.stderr)
        return 1
    print("[alloc-null-check] PASS (no unguarded allocation sites)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
