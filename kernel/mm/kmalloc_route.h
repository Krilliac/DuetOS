#pragma once

#include "util/types.h"

/*
 * DuetOS — KMalloc small-allocation slab routing: pure decision logic.
 *
 * WHAT
 *   The constants and constexpr helpers that decide (a) whether a
 *   KMalloc request is small enough to route to a per-size SlabCache
 *   instead of the first-fit kheap, (b) which size class it lands in,
 *   and (c) how a KFree'd pointer is discriminated back to its origin
 *   (routed slab object vs classic kheap chunk) from the single u64
 *   word at `ptr - 16`.
 *
 * WHY THIS IS A SEPARATE HEADER
 *   The logic is pure — no locks, no allocator state — so keeping it
 *   freestanding (only util/types.h) lets the hosted unit test
 *   (tests/host/test_kmalloc_route.cpp) pin every boundary and the
 *   encode/decode roundtrip natively, under sanitizers, on every PR.
 *   kheap.cpp consumes it for the live routing hooks.
 *
 * DISCRIMINATION CONTRACT (the load-bearing part)
 *   Every routed object carries a 16-byte route header immediately
 *   before the payload pointer handed to the caller:
 *       obj[0..8)  = EncodeRouteHeader(class)   — magic | class index
 *       obj[8..16) = caller RIP                  — leak attribution
 *   Every LIVE classic kheap chunk stores `nullptr` in its
 *   ChunkHeader::next field, which sits exactly 16 bytes before the
 *   payload (static_assert'd in kheap.cpp). So the u64 at `ptr - 16`
 *   is 0 for every live kheap pointer and kSlabRouteMagic|class for
 *   every live routed pointer — an unambiguous single-word probe.
 */

namespace duetos::mm
{

/// Routed size classes, in bytes of caller-visible payload. All
/// multiples of 16 so the payload keeps kHeapAlignment without any
/// per-allocation rounding logic. The progression doubles with two
/// intermediate steps (96, 192, 384) to cap worst-case internal
/// fragmentation at ~33% instead of ~50%.
inline constexpr u32 kSlabRouteClassCount = 8;
inline constexpr u64 kSlabRouteClassBytes[kSlabRouteClassCount] = {32, 64, 96, 128, 192, 256, 384, 512};

/// Requests above this go to the classic kheap path untouched.
inline constexpr u64 kSlabRouteMaxBytes = 512;

/// Route header size: one u64 magic+class word + one u64 caller-RIP
/// word. Equals kHeapAlignment, so the payload after the header is
/// 16-byte aligned whenever the slab object itself is.
inline constexpr u64 kSlabRouteHeaderBytes = 16;

/// Sentinel "not a routed size / not a routed class" value.
inline constexpr u32 kRouteNoClass = 0xFFFFFFFFu;

/// Magic for the route header's first word. Asymmetric and grep-able;
/// the low byte is RESERVED (must be 0 here) — EncodeRouteHeader ORs
/// the class index into it, and DecodeRouteClass masks it back off.
/// Must never collide with: 0 (live kheap chunk discriminator),
/// kHeapMagicLive / kHeapMagicFree (kheap chunk states), the 0xCC
/// slab freed-object poison word, or kSlabRouteMagicFreed below.
inline constexpr u64 kSlabRouteMagic = 0xB10CA11C0DE5AB00ULL;

/// Stamped over the magic word when a routed object is KFree'd, so a
/// second KFree of the same pointer (before the slab recycles the
/// slot) is caught as a dedicated double-free panic instead of a
/// confusing downstream corruption. Distinct tag — its high 56 bits
/// deliberately do NOT match kSlabRouteMagic.
inline constexpr u64 kSlabRouteMagicFreed = 0xDEADB10CF2EED5ABULL;

/// Map a KMalloc byte count to its route class index, or kRouteNoClass
/// for 0 and for anything above kSlabRouteMaxBytes. Smallest class
/// whose payload fits the request: 1..32 -> 0, 33..64 -> 1, ...,
/// 385..512 -> 7.
constexpr u32 SizeToRouteClass(u64 bytes)
{
    if (bytes == 0 || bytes > kSlabRouteMaxBytes)
    {
        return kRouteNoClass;
    }
    for (u32 i = 0; i < kSlabRouteClassCount; ++i)
    {
        if (bytes <= kSlabRouteClassBytes[i])
        {
            return i;
        }
    }
    return kRouteNoClass; // unreachable: bytes <= kSlabRouteMaxBytes == last class
}

/// Build the route header's magic word for a class index.
constexpr u64 EncodeRouteHeader(u32 route_class)
{
    return kSlabRouteMagic | static_cast<u64>(route_class & 0xFFu);
}

/// Recover the class index from a route header word, or kRouteNoClass
/// if the word is not a live route header (wrong magic, or a class
/// index beyond the table).
constexpr u32 DecodeRouteClass(u64 m)
{
    if ((m & ~0xFFull) != kSlabRouteMagic)
    {
        return kRouteNoClass;
    }
    const u32 route_class = static_cast<u32>(m & 0xFFull);
    if (route_class >= kSlabRouteClassCount)
    {
        return kRouteNoClass;
    }
    return route_class;
}

/// What the discriminator word at `ptr - 16` says about a pointer
/// handed to KFree.
enum class RouteWord : u8
{
    Kheap,       ///< 0 — live classic kheap chunk (ChunkHeader::next == nullptr).
    RoutedLive,  ///< Valid route header — free through the class's SlabCache.
    RoutedFreed, ///< Freed tag — second KFree of a routed pointer: double free.
    Garbage,     ///< Anything else — let the classic path's magic checks decide.
};

/// The discrimination decision function. Pure; the caller owns
/// reading the word and acting on the verdict.
constexpr RouteWord RouteWordClassify(u64 m)
{
    if (m == 0)
    {
        return RouteWord::Kheap;
    }
    if (DecodeRouteClass(m) != kRouteNoClass)
    {
        return RouteWord::RoutedLive;
    }
    if (m == kSlabRouteMagicFreed)
    {
        return RouteWord::RoutedFreed;
    }
    return RouteWord::Garbage;
}

} // namespace duetos::mm
