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
///
/// Implementation: the mask is built from the `(idx < bound)`
/// comparison promoted to 0 / 1 and negated to all-0s / all-1s.
/// On x86_64 the compiler lowers this to `cmp + sbb` (or
/// equivalently `cmp + setb + neg`) — three flag-driven
/// instructions, no branch the speculator can mispredict. Works
/// for the full u64 idx range; an earlier "sign bit of
/// (idx - bound)" formula failed for idx > 2^63 + bound because
/// the wrapped difference stayed in the top half and the mask
/// resolved to all-1s, letting the speculator carry the bad idx
/// through.
[[nodiscard]] constexpr u64 MaskedIndex(u64 idx, u64 bound)
{
    const u64 mask = 0ULL - static_cast<u64>(idx < bound);
    return idx & mask;
}

[[nodiscard]] constexpr u32 MaskedIndex32(u32 idx, u32 bound)
{
    const u32 mask = 0U - static_cast<u32>(idx < bound);
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
