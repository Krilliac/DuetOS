#pragma once

// Boot cmdline helpers hoisted out of kernel_main (core/main.cpp)
// so the boot-bringup TUs can resolve cmdline knobs without a
// dependency back into main.cpp's anonymous namespace. Pure code
// motion — the cache + parse logic is byte-identical to the
// previous in-main.cpp statics.

#include "util/types.h"

namespace duetos::core
{

// Walk the Multiboot2 tag list for type-1 (boot cmdline) and
// return its NUL-terminated string, or nullptr if absent. Caches
// the result on first success so callers running after the early
// identity map is torn down read the cache instead of faulting on
// the now-unmapped low info_phys VA.
const char* FindBootCmdline(duetos::uptr info_phys);

// Return true iff `cmdline` contains the whitespace-delimited
// token "key=value" where `value` matches `want`. Case-sensitive.
// A nullptr cmdline returns false.
bool CmdlineMatches(const char* cmdline, const char* key, const char* want);

// Parse the "debugstub=1" cmdline token (set by an external debugger
// host such as duetos-vmm --gdb) and cache it. Call once early in boot
// while the Multiboot2 info page is still mapped. When set, the kernel
// stands down its boot-time int3 / hardware-breakpoint / watchpoint
// self-tests (TrapsSelfTest's int3, BpSelfTest, WatchSelfTest), which
// would otherwise be intercepted by the host debugger's #BP/#DB and
// wedge or corrupt the boot.
void DebugStubInit(const char* cmdline);

// True iff DebugStubInit saw "debugstub=1". False before DebugStubInit.
bool DebugStubAttached();

} // namespace duetos::core
