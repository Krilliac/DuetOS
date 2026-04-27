#pragma once

#include "util/types.h"

/*
 * DuetOS — memory-corruption diagnostic primitives, v0 (plan C2).
 *
 * WHAT
 *   A single header that owns the canary / poison constants and
 *   tiny inline helpers shared by the kernel heap (red zones,
 *   freed-payload poison) and the physical frame allocator
 *   (freed-page poison). One source of truth for the values means
 *   a `git grep` for any of them turns up every use site, and the
 *   runtime checker / shell `mem` command can print a single legend
 *   instead of three duplicates.
 *
 * SCOPE
 *   v0 covers two of the three layers from plan C2:
 *
 *     1. Heap red zones — `kheap` writes `kHeapTrailerCanary` after
 *        every payload and verifies it on `KFree`. The chunk
 *        header's `magic` already serves as the leading canary
 *        (kHeapHeaderMagicLive / Free).
 *
 *     2. Freed-page poison — `frame_allocator` writes
 *        `kFreedPagePoison` over every page returned to the pool.
 *
 *   Layer 3 (slab freed-object poison) is parked: there is no slab
 *   allocator yet. `kSlabFreedObjectPoison` is reserved here so a
 *   future slab implementation lands a uniform value and the
 *   runtime-checker plumbing can be written once.
 *
 * COST
 *   Heap red zone: 16 extra bytes per allocation, two cmpq on
 *   alloc/free. Freed-page poison: one 4 KiB store per
 *   `FreeFrame`. Both are unconditional — the costs are small
 *   enough not to need a build flag, and gating "is the kernel
 *   memory-safe" behind a debug-only knob is the wrong default.
 *
 * CONTEXT
 *   Header-only, freestanding, no external deps. Safe to include
 *   from anywhere in the kernel.
 */

namespace duetos::mm
{

/// Trailing red-zone value on every kheap allocation. 16 bytes
/// wide so a same-aligned overrun by even one machine word is
/// caught. Chosen for grep-ability (asymmetric, unambiguous when
/// it shows up in a hex dump).
inline constexpr u64 kHeapTrailerCanaryLo = 0xCA11AB1ECA11AB1EULL;
inline constexpr u64 kHeapTrailerCanaryHi = 0xDEADC0DEDEADC0DEULL;
inline constexpr u64 kHeapTrailerCanaryBytes = 16; // 2 × u64.

/// Byte pattern written over freed pages by `FreeFrame` /
/// `FreeContiguousFrames`. Same value the kheap uses for freed
/// payloads, so a use-after-free trace shows the same byte either
/// way and a future runtime check can compare both layers against
/// one constant.
inline constexpr u8 kFreedPagePoison = 0xDE;

/// Reserved for a future slab allocator. `0xCC` is the de-facto
/// "scratch / freed object" pattern across many kernels and
/// debuggers; pre-declaring it here keeps a future
/// `slab.cpp` from minting yet another value.
inline constexpr u8 kSlabFreedObjectPoison = 0xCC;

/// Write the trailer canary at `[ptr, ptr + kHeapTrailerCanaryBytes)`.
/// Caller is responsible for the storage and for the alignment
/// (kHeapAlignment in kheap.cpp guarantees 16-byte alignment of
/// the trailer).
inline void WriteHeapTrailerCanary(void* ptr)
{
    auto* lo = static_cast<u64*>(ptr);
    lo[0] = kHeapTrailerCanaryLo;
    lo[1] = kHeapTrailerCanaryHi;
}

/// Returns true iff the 16 bytes starting at `ptr` exactly match
/// the trailer canary written by `WriteHeapTrailerCanary`.
inline bool CheckHeapTrailerCanary(const void* ptr)
{
    const auto* lo = static_cast<const u64*>(ptr);
    return lo[0] == kHeapTrailerCanaryLo && lo[1] == kHeapTrailerCanaryHi;
}

/// Fill `bytes` at `ptr` with `kFreedPagePoison`. Caller must be
/// holding the frame already (i.e. just before returning it to the
/// allocator) — this is not allocator-aware.
inline void PoisonFreedPage(void* ptr, u64 bytes)
{
    auto* p = static_cast<u8*>(ptr);
    for (u64 i = 0; i < bytes; ++i)
    {
        p[i] = kFreedPagePoison;
    }
}

} // namespace duetos::mm
