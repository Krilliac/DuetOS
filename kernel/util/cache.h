#pragma once

#include "util/types.h"

/*
 * CPU cache geometry + compiler prefetch wrappers.
 *
 * x86_64 commodity hardware has used 64-byte coherent cache lines for the
 * targets DuetOS supports. Keep this as the conservative compile-time layout
 * constant: it is safe for alignas/static layout and matches CPUID-reported
 * CLFLUSH size on Intel/AMD CPUs we care about. Runtime probes can still log
 * richer cache details later, but hot data structures need a constant at
 * compile time.
 */

namespace duetos::util
{

inline constexpr u64 kCpuCacheLineBytes = 64;
static_assert((kCpuCacheLineBytes & (kCpuCacheLineBytes - 1)) == 0, "cache-line size must be a power of two");

/// Prefetch a read-mostly address we expect to touch soon. Locality 1 keeps
/// the line around briefly without treating a freelist walk as long-lived data.
inline void PrefetchReadOnce(const void* ptr)
{
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(ptr, 0, 1);
#else
    (void)ptr;
#endif
}

/// Prefetch a read address that should stay hot after the immediate access.
inline void PrefetchReadKeep(const void* ptr)
{
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(ptr, 0, 3);
#else
    (void)ptr;
#endif
}

/// Prefetch a write target that will be populated shortly.
inline void PrefetchWriteKeep(const void* ptr)
{
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(ptr, 1, 3);
#else
    (void)ptr;
#endif
}

} // namespace duetos::util
