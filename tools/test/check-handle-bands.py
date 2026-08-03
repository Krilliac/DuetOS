#!/usr/bin/env python3
"""
check-handle-bands.py — verify every declared handle-band constant
appears in DoFileClose, and that ProcessRelease has explicit cleanup
for each band that needs per-process teardown.

WHAT
    Parses handle-band constants from kernel/proc/process.h
    (kWin32*Base) and kernel/subsystems/win32/job_syscall.h
    (kJobHandleBase), then checks that each constant name appears in:

        kernel/subsystems/win32/file_syscall.cpp  (DoFileClose)

    For ProcessRelease, the check is different: not every band is
    closed via its constant name — kobject-shaped handles go through
    HandleTableDrain, thread handles are cleaned at task exit, etc.
    Instead, we check that each band has an identified cleanup path
    (either the constant appears in ProcessRelease, or the band's
    associated array name appears, or the band is in the known-exempt
    list of bands cleaned through other mechanisms).

    A band missing from DoFileClose means CloseHandle silently leaks
    that handle type. A band missing from both ProcessRelease AND the
    exempt list means process exit silently leaks it.

    Excludes VA-space bases that are NOT handle bands:
        kWin32VmapBase, kWin32ExtraHeapArenaBase

WHY
    The handle band chain in DoFileClose is a hand-maintained
    whitelist. Every time a new handle band is added, it must be
    updated — but the compiler has no way to enforce this, so the
    drift is invisible until a guest PE leaks 100% of that handle
    type. This script is the "convert the whitelist into a property
    test" move: it fails when a new band is declared but not wired
    into the dispatch site.

USAGE
    python3 tools/test/check-handle-bands.py [--root <repo>]

    Exit 0 = all bands covered.  Exit 1 = at least one gap.
"""

import argparse
import os
import re
import sys


# VA-space bases that are NOT handle bands — exclude from all checks.
EXCLUDED = {
    "kWin32VmapBase",
    "kWin32ExtraHeapArenaBase",
}


# Bands whose ProcessRelease cleanup goes through a mechanism OTHER
# than an explicit constant-name reference in process.cpp. Each entry
# documents why the band is exempt:
#
#   kobject: Handle is KObject-shaped; cleaned up by HandleTableDrain
#            which iterates the kobj_handles[] table.
#   task_exit: Cleaned up when the owning task exits / is reaped by
#              the scheduler.
#   global_pool: Not per-process; cleaned by explicit close only.
#   tid_only: Row stores an immutable TID with no ownership; no
#             refcount to drop at exit.
#   inline_array: ProcessRelease already iterates the per-process
#                 array by index (not by constant name). The cleanup
#                 token below is searched for instead.
#
PROCESS_RELEASE_EXEMPT = {
    "kWin32MutexBase":         "kobject (HandleTableDrain)",
    "kWin32EventBase":         "kobject (HandleTableDrain)",
    "kWin32SemaphoreBase":     "kobject (HandleTableDrain)",
    "kWin32IocpBase":          "kobject (HandleTableDrain)",
    "kWin32ThreadBase":        "task_exit (sched reaper)",
    "kWin32ForeignThreadBase": "tid_only (no ownership)",
    "kWin32RegistryBase":      "borrowed RegKey* (no ownership)",
    "kJobHandleBase":          "global_pool (not per-process)",
}

# For bands whose ProcessRelease cleanup uses array names rather than
# the constant, map constant -> token to search for in process.cpp.
PROCESS_RELEASE_TOKENS = {
    "kWin32HandleBase":   "win32_files",
    "kWin32ProcessBase":  "ProcessDropOwnedProcessHandles",
    "kWin32SectionBase":  "win32_section_handles",
    "kWin32DirBase":      "win32_dirs",
}

# Opaque generation-tagged handle families dispatch through a decoder rather
# than comparing the public value to the legacy low-tag band directly.
CLOSE_DISPATCH_TOKENS = {
    "kWin32ProcessBase": "IsWin32ProcessHandle",
}


def find_band_constants(root):
    """Find all handle-band constants across the relevant headers."""
    bands = {}  # name -> source file

    # 1. kWin32*Base constants in process.h
    process_h = os.path.join(root, "kernel", "proc", "process.h")
    if os.path.isfile(process_h):
        with open(process_h, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r"\b(kWin32\w*Base)\b", line)
                if m and m.group(1) not in EXCLUDED:
                    bands[m.group(1)] = "process.h"

    # 2. kJobHandleBase in job_syscall.h
    job_h = os.path.join(
        root, "kernel", "subsystems", "win32", "job_syscall.h"
    )
    if os.path.isfile(job_h):
        with open(job_h, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r"\b(kJobHandleBase)\b", line)
                if m:
                    bands[m.group(1)] = "job_syscall.h"

    return bands


def check_file_for_bands(filepath, bands):
    """Return the set of band names that appear in filepath."""
    found = set()
    if not os.path.isfile(filepath):
        return found
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    for name in bands:
        if name in content:
            found.add(name)
    return found


def check_file_for_tokens(filepath, tokens):
    """Return the set of token keys whose values appear in filepath."""
    found = set()
    if not os.path.isfile(filepath):
        return found
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    for key, token in tokens.items():
        if token in content:
            found.add(key)
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Check handle-band coverage in DoFileClose and ProcessRelease"
    )
    parser.add_argument(
        "--root",
        default=os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ),
        help="Repository root (default: inferred from script location)",
    )
    args = parser.parse_args()
    root = args.root

    bands = find_band_constants(root)
    if not bands:
        print("ERROR: no handle-band constants found — check paths")
        return 1

    file_syscall = os.path.join(
        root, "kernel", "subsystems", "win32", "file_syscall.cpp"
    )
    process_cpp = os.path.join(root, "kernel", "proc", "process.cpp")

    # --- DoFileClose coverage ---
    close_found = check_file_for_bands(file_syscall, bands)
    close_by_token = check_file_for_tokens(file_syscall, CLOSE_DISPATCH_TOKENS)

    # --- ProcessRelease coverage ---
    # A band is covered if: (a) its constant name appears in
    # process.cpp, OR (b) its cleanup token appears, OR (c) it is
    # in the exempt list.
    release_by_name = check_file_for_bands(process_cpp, bands)
    release_by_token = check_file_for_tokens(process_cpp, PROCESS_RELEASE_TOKENS)

    errors = 0
    print("=== DoFileClose (file_syscall.cpp) ===")
    for name in sorted(bands):
        src = bands[name]
        if name in close_found or name in close_by_token:
            print(f"  OK    {name} ({src})")
        else:
            print(f"  MISSING  {name} ({src})")
            errors += 1

    print()
    print("=== ProcessRelease (process.cpp) ===")
    for name in sorted(bands):
        src = bands[name]
        if name in release_by_name or name in release_by_token:
            print(f"  OK    {name} ({src})")
        elif name in PROCESS_RELEASE_EXEMPT:
            reason = PROCESS_RELEASE_EXEMPT[name]
            print(f"  OK    {name} ({src}) — exempt: {reason}")
        else:
            print(f"  MISSING  {name} ({src})")
            errors += 1

    print()
    print(f"{len(bands)} bands checked, {errors} gaps found.")
    return 1 if errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
