#pragma once

#include "syscall.h"
#include "types.h"

/*
 * DuetOS — diagnostic name lookup for native SyscallNumber values.
 *
 * The runtime needs to map a u64 syscall number back to its
 * "SYS_FOO" identifier in two places:
 *
 *   1. translation/translate.cpp's NativeName() — the per-syscall
 *      hit / miss / overhead reporting reads it on every translated
 *      Linux↔native fallthrough.
 *   2. debug/syscall_scan.cpp's site classifier — the inspect-syscalls
 *      command labels every recovered `int 0x80` site with this.
 *
 * Both places had hand-maintained parallel tables that drifted from
 * the SyscallNumber enum (one had 17 entries, the other 47, against
 * an enum that grew to 129). They now share this single source —
 * see syscall_names.def — and a static_assert per row keeps the
 * def aligned to the enum at compile time.
 */

namespace duetos::core
{

struct SyscallNameEntry
{
    u64 nr;
    const char* name;
};

inline constexpr SyscallNameEntry kSyscallNames[] = {
#define X(name, num) {(num), #name},
#include "syscall_names.def"
#undef X
};

inline constexpr u64 kSyscallNamesCount = sizeof(kSyscallNames) / sizeof(kSyscallNames[0]);

// Verify each row matches the enum value in syscall.h. If the enum
// is reshuffled or a new SYS_FOO is added without updating the def,
// this fires at compile time with a row-specific message.
#define X(name, num)                                                                                                   \
    static_assert(static_cast<u64>(::duetos::core::name) == (num),                                                     \
                  "syscall_names.def row for " #name " disagrees with SyscallNumber enum");
#include "syscall_names.def"
#undef X

/// Look up the "SYS_FOO" name for a native syscall number.
/// Returns nullptr if `nr` is not in the def.
const char* SyscallNumberName(u64 nr);

} // namespace duetos::core
