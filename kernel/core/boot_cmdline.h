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

} // namespace duetos::core
