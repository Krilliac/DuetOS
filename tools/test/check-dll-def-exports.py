#!/usr/bin/env python3
"""
check-dll-def-exports.py — static consistency check between each
userland DLL's .def export list and the definitions in its sources.

WHAT
    For every `userland/libs/<lib>/*.def`, cross-check the names in the
    EXPORTS section against the definitions sitting next to it:
    `__declspec(dllexport)` functions and data in the `.c` files, plus
    `.globl` symbols in any `.S` files.

    ERROR   name in EXPORTS with no definition in the directory.
            lld-link fails the DLL build on this ("unresolved external
            symbol ... referenced by export"), but only on a host that
            has the cross-toolchain installed — this script catches it
            on any host, in a second.
    WARN    (opt-in, --warn-unexported) definition present but absent
            from EXPORTS: compiled into the DLL and unreachable by any
            importer.

    A library whose sources generate exports from a macro (a `#define`
    whose body contains `__declspec(dllexport)`, as user32_32 and
    friends do) cannot be checked by textual scanning — the names only
    exist after preprocessing. Those libraries are reported as SKIP and
    never produce an error, so the check stays trustworthy rather than
    noisy.

WHY
    The `_32` (PE32/i386) companion DLLs are .def-driven — the .def
    sets the PE export-table Name field so the i386 IAT walker matches
    the importer's descriptor. Adding an implementation without the
    .def line (or the reverse) is an easy and entirely silent mistake
    on a dev host without clang + lld-link, and the failure only
    surfaces in CI or, worse, as a missing import at guest runtime.

USAGE
    python3 tools/test/check-dll-def-exports.py [--root <repo>]
              [--lib <name> ...] [--warn-unexported] [--strict]

    --lib             restrict to one or more library directory names
                      (e.g. --lib kernel32_32); repeatable.
    --warn-unexported also report definitions missing from EXPORTS.
    --strict          treat warnings as failures too.

    Exit 0 clean / 1 errors (or warnings under --strict).

QUICK ANALYSIS
    # just the 32-bit companion set, including unreachable definitions
    python3 tools/test/check-dll-def-exports.py --lib kernel32_32 --warn-unexported
"""

import argparse
import os
import re
import sys

# `Name`, `Name @3`, `Name @3 NONAME`, `Name = other.Name` (forwarder),
# `Name DATA`. Everything after the first token is decoration we only
# need to classify, not resolve.
_EXPORT_LINE = re.compile(r"^\s*([A-Za-z_@?][A-Za-z0-9_@?$]*)\s*(=\s*\S+)?\s*(@\s*\d+)?\s*(NONAME|DATA|PRIVATE)*\s*$")

# Directives that may only appear before EXPORTS. Deliberately checked
# only while outside the EXPORTS section: `HeapSize` and `StackSize`
# are also perfectly ordinary kernel32 export names, and treating an
# export line as a directive silently truncates the parse (which is
# exactly what this script did on its first run).
_PRE_EXPORT_DIRECTIVES = ("LIBRARY", "NAME", "DESCRIPTION", "VERSION", "HEAPSIZE", "STACKSIZE", "STUB")
# Sections that end the export list.
_SECTION_DIRECTIVES = ("SECTIONS", "SEGMENTS", "IMPORTS")

# The identifier immediately before the parameter list (a function) or
# before the `;`/`=`/`[` that ends a data definition. The middle is
# barred from crossing `;`, `{` or `}` so one declspec's match can
# never swallow the next definition.
_DLLEXPORT_DEF = re.compile(r"__declspec\s*\(\s*dllexport\s*\)([^;{}]*?)[\(=;\[]", re.DOTALL)
_TRAILING_IDENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")

# Assembly globals — `.globl name` / `.global name`.
_ASM_GLOBL = re.compile(r"^\s*\.glob(?:a)?l\s+([A-Za-z_@?][A-Za-z0-9_@?$]*)", re.MULTILINE)

# A macro whose body emits a dllexport: the directory's real export
# names only exist after preprocessing, so textual scanning can't see
# them.
_EXPORT_MACRO = re.compile(r"^\s*#\s*define\s+\w+\s*\([^\n]*\)[^\n]*\\?\n?(?:[^\n]*\\\n)*[^\n]*__declspec\s*\(\s*dllexport",
                           re.MULTILINE)


def strip_comments(text):
    """Remove /* */ and // comments so commented-out code never counts."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def parse_def(path):
    """Return (exports, forwarded) name sets from a .def file."""
    exports = set()
    forwarded = set()
    in_exports = False
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split(";", 1)[0].rstrip()
            if not line.strip():
                continue
            first = line.strip().split()[0].upper()
            if first == "EXPORTS":
                in_exports = True
                continue
            if not in_exports:
                if first in _PRE_EXPORT_DIRECTIVES:
                    continue
                continue
            if first in _SECTION_DIRECTIVES:
                in_exports = False
                continue
            m = _EXPORT_LINE.match(line)
            if not m:
                continue
            name = m.group(1)
            # `Name = otherdll.Other` forwards to another DLL — nothing
            # in this directory is expected to define it.
            if m.group(2):
                forwarded.add(name)
            else:
                exports.add(name)
    return exports, forwarded


def parse_definitions(directory):
    """Return (defined_names, uses_export_macro) for one library dir."""
    defined = set()
    uses_macro = False
    for entry in sorted(os.listdir(directory)):
        path = os.path.join(directory, entry)
        if entry.endswith(".c") or entry.endswith(".h"):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            if _EXPORT_MACRO.search(text):
                uses_macro = True
            body = strip_comments(text)
            for m in _DLLEXPORT_DEF.finditer(body):
                ident = _TRAILING_IDENT.search(m.group(1))
                if ident:
                    defined.add(ident.group(1))
        elif entry.endswith(".S") or entry.endswith(".asm"):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                asm = strip_comments(fh.read())
            for m in _ASM_GLOBL.finditer(asm):
                sym = m.group(1)
                defined.add(sym)
                # i386 MSVC decorates cdecl with one leading underscore;
                # the .def carries the undecorated C name.
                if sym.startswith("_"):
                    defined.add(sym[1:])
    return defined, uses_macro


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    ap.add_argument("--root", default=default_root, help="repo root (default: inferred from this script)")
    ap.add_argument("--lib", action="append", default=[], help="restrict to this library dir name (repeatable)")
    ap.add_argument("--warn-unexported", action="store_true", help="also report definitions missing from EXPORTS")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures")
    args = ap.parse_args()

    libs_root = os.path.join(args.root, "userland", "libs")
    if not os.path.isdir(libs_root):
        print("check-dll-def-exports: no userland/libs under %s" % args.root, file=sys.stderr)
        return 2

    errors = 0
    warnings = 0
    checked = 0
    skipped = 0

    for lib in sorted(os.listdir(libs_root)):
        directory = os.path.join(libs_root, lib)
        if not os.path.isdir(directory):
            continue
        if args.lib and lib not in args.lib:
            continue
        defs = [f for f in sorted(os.listdir(directory)) if f.endswith(".def")]
        if not defs:
            continue
        defined, uses_macro = parse_definitions(directory)
        if uses_macro:
            print("SKIP  %s: exports are macro-generated; not checkable by text scan" % lib)
            skipped += 1
            continue
        for def_name in defs:
            exports, forwarded = parse_def(os.path.join(directory, def_name))
            if not exports and not forwarded:
                continue
            checked += 1
            for name in sorted(exports - defined):
                print("ERROR %s/%s: '%s' is exported but never defined in %s/" % (lib, def_name, name, lib))
                errors += 1
            if args.warn_unexported:
                for name in sorted(defined - exports - forwarded):
                    print("WARN  %s/%s: '%s' is defined but missing from EXPORTS (unreachable)" %
                          (lib, def_name, name))
                    warnings += 1

    print("check-dll-def-exports: %d .def file(s) checked, %d skipped lib(s), %d error(s), %d warning(s)" %
          (checked, skipped, errors, warnings))
    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
