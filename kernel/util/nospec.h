#pragma once

#include "util/types.h"

/*
 * DuetOS — Spectre v1 nospec helpers + saturating refcount.
 *
 * Two unrelated-but-small primitives that the kernel CVE audit
 * (wiki/security/Linux-CVE-Audit.md classes N and O) called for:
 *
 *   MaskedIndex(idx, bound) — Spectre v1 (bounds-check bypass)
 *     mitigation. Returns a value that is `idx` when `idx < bound`
 *     and 0 otherwise, computed without a data-dependent branch
 *     the speculator can mispredict. Use at every callsite where a
 *     user-supplied (or other untrusted) integer is about to be
 *     used as an array index after a runtime bounds check.
 *
 *   RefcountIncSaturating(&n) — bumps a refcount but stops at
 *     UINT32_MAX. Used to prevent the CVE-2016-0728-class
 *     overflow-to-UAF pattern on any refcount an unprivileged
 *     path can drive. Returns true if the increment landed, false
 *     if the refcount was saturated.
 *
 * Both are header-only, no out-of-line definitions. The mask
 * sequence is the canonical "subtract, sign-bit, replicate" trick
 * the Linux kernel's array_index_nospec uses on most ISAs.
 *
 * STAC/CLAC, lfence, retpoline, and SMAP/SMEP enforcement are
 * separate concerns and live in kernel/arch/x86_64/.
 */

namespace duetos::util
{

/// Spectre-v1-safe array index. Returns `idx` when `idx < bound`,
/// 0 otherwise. Speculative loads through the returned value are
/// bounded to `[0, bound)` regardless of how the CPU mispredicts
/// the original `if (idx < bound)` check.
///
/// Discipline: do the runtime `if (idx < bound) return -EINVAL`
/// check first (for the architectural path), THEN pass `idx`
/// through MaskedIndex when reading from the array. The check
/// protects correctness; the mask protects the speculative
/// window. Both are required.
[[nodiscard]] constexpr u64 MaskedIndex(u64 idx, u64 bound)
{
    // If idx < bound, (idx - bound) sets the sign bit; sign-
    // extending arithmetic right-shift by 63 replicates it into
    // a 64-bit mask of all-ones. The compiler-visible logic is
    // branchless and the speculator cannot redirect through a
    // smaller (or zero) bound to a larger idx.
    const u64 diff = idx - bound;
    const u64 mask = static_cast<u64>(static_cast<i64>(diff) >> 63);
    return idx & mask;
}

[[nodiscard]] constexpr u32 MaskedIndex32(u32 idx, u32 bound)
{
    const u32 diff = idx - bound;
    const u32 mask = static_cast<u32>(static_cast<i32>(diff) >> 31);
    return idx & mask;
}

/// Saturating refcount increment. Caller passes a pointer to a
/// `u32` (or wider) counter. Returns true if the count was
/// incremented; false if it was already at the saturation
/// ceiling, in which case the count is left at the ceiling and
/// the caller MUST treat the operation as a refcount-overflow
/// (refuse the share, drop the new reference, etc.).
///
/// This is a single-thread primitive — callers that need
/// atomicity wrap it in their own lock (the kernel's existing
/// refcount path under `kernel/ipc/kobject.cpp` already serialises
/// via `g_kobject_lock`).
[[nodiscard]] inline bool RefcountIncSaturating(u32* count)
{
    if (*count == 0xFFFFFFFFu)
        return false;
    ++(*count);
    return true;
}

[[nodiscard]] inline bool RefcountIncSaturating(u64* count)
{
    if (*count == 0xFFFFFFFFFFFFFFFFull)
        return false;
    ++(*count);
    return true;
}

} // namespace duetos::util
