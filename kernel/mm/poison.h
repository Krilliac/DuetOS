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

/// Pattern stamped over the unused-payload bytes of every free
/// slab object. `0xCC` is the de-facto "scratch / freed object"
/// pattern across many kernels and debuggers. The slab freelist
/// is intrusive: the first `sizeof(void*)` bytes of a free object
/// hold the freelist `next` pointer, so the poison covers only the
/// trailing `[sizeof(void*), obj_size)` region. Every free object
/// — both freshly-carved and SlabFree-returned — carries this
/// pattern; SlabAlloc verifies it before handing the object out,
/// catching one class of slab-object use-after-write.
inline constexpr u8 kSlabFreedObjectPoison = 0xCC;

/// Write `kSlabFreedObjectPoison` across the trailing payload of a
/// slab object (everything past the `next` link). Caller owns the
/// pointer and the size; the slab allocator stamps this on Free
/// and on fresh-slab carve.
inline void PoisonSlabFreedObject(void* obj, u64 obj_size, u64 link_bytes)
{
    if (obj_size <= link_bytes)
    {
        return;
    }
    auto* p = static_cast<u8*>(obj) + link_bytes;
    u64 n = obj_size - link_bytes;
    // 8-byte chunked stamp via a u64 pattern. Slab objects are
    // aligned to >= 8 bytes (slab.cpp guarantees this) so the
    // u64* store is safe without an alignment prologue.
    constexpr u64 kPatternWord = 0xCCCCCCCCCCCCCCCCULL;
    while (n >= 8)
    {
        *reinterpret_cast<u64*>(p) = kPatternWord;
        p += 8;
        n -= 8;
    }
    while (n != 0)
    {
        *p++ = kSlabFreedObjectPoison;
        --n;
    }
}

/// Verify the trailing-payload poison set by `PoisonSlabFreedObject`.
/// Returns the byte offset of the first mismatch, or `obj_size` if
/// every byte matched. Caller must check the result against
/// `obj_size` to decide whether the object was clean.
inline u64 CheckSlabFreedObjectPoison(const void* obj, u64 obj_size, u64 link_bytes)
{
    if (obj_size <= link_bytes)
    {
        return obj_size;
    }
    const auto* p = static_cast<const u8*>(obj) + link_bytes;
    const u64 n = obj_size - link_bytes;
    // 8-byte chunked compare: a clean object is the dominant case,
    // so the bulk loop short-circuits on the FIRST mismatched word
    // and the byte-precise offset is recovered from the trailing
    // bytes of that word. Slab alignment >= 8 lets us load u64
    // without a head fixup.
    constexpr u64 kPatternWord = 0xCCCCCCCCCCCCCCCCULL;
    u64 i = 0;
    while (i + 8 <= n)
    {
        if (*reinterpret_cast<const u64*>(p + i) != kPatternWord)
        {
            // Word-level mismatch — pinpoint the byte.
            for (u64 j = 0; j < 8; ++j)
            {
                if (p[i + j] != kSlabFreedObjectPoison)
                {
                    return link_bytes + i + j;
                }
            }
            // Unreachable: the u64 compare said mismatch, the
            // byte walk must find it.
            return link_bytes + i;
        }
        i += 8;
    }
    for (; i < n; ++i)
    {
        if (p[i] != kSlabFreedObjectPoison)
        {
            return link_bytes + i;
        }
    }
    return obj_size;
}

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

// ---------------------------------------------------------------------------
// Hardware-poison frame blacklist (v1 minimal — record-only).
//
// Background: an x86_64 SRAR (Software Recoverable Action Required)
// machine-check fires when the CPU consumes an uncorrectable memory
// error on a load. Per Intel SDM Vol 3 Ch 16, `MCG_STATUS.RIPV=1`
// promises the iret frame is restartable IF software repairs the
// underlying condition first. Linux's `hwpoison` (mm/memory-failure.c)
// does that repair by walking every PTE that references the failing
// frame, unmapping it, and signalling consumers. v1 here does the
// minimal infrastructure half: it records the failing PFN so the
// allocator never recycles it back into the free pool. Full SRAR
// recovery (PTE walk + signal) lands on top of this once the rmap +
// signal-delivery stories are ready.
//
// The list is small (32 frames) — a real machine emitting more than
// 32 SRARs without a reboot is in a hardware-failure state where
// the OS is no longer the load-bearing layer.
// ---------------------------------------------------------------------------

inline constexpr u32 kFramePoisonCapacity = 32;

/// Mark the page-aligned physical frame `frame_phys` as bad. After
/// this call, the next `FreeFrame(f)` for that PFN will drop the
/// frame instead of returning it to the free pool, and any future
/// caller can query `IsFramePoisoned` before consuming a frame.
///
/// Idempotent: poisoning a frame already on the list is a no-op.
/// Returns true on insert (new or already-present), false only when
/// the list is saturated and `frame_phys` was not already on it.
///
/// `frame_phys` is rounded down to page granularity by the implementation;
/// callers may pass either a frame-aligned PFN-style value or a
/// byte-precise fault address.
bool PoisonFrame(u64 frame_phys);

/// Returns true iff the page-aligned frame `frame_phys` has been
/// recorded via `PoisonFrame`. Cheap linear scan (≤ 32 entries).
bool IsFramePoisoned(u64 frame_phys);

/// Number of distinct frames recorded via `PoisonFrame` since boot.
/// 0 on a healthy box. Diagnostic for `mem` / `crprobe` shell paths.
u32 PoisonedFrameCount();

/// Boot self-test — exercises the round-trip (poison fake PFN,
/// query, count, idempotent re-poison). Restores list to empty
/// before returning so the live SRAR record path stays unaffected.
/// Emits `[mm/poison-selftest] PASS` on success; panics on failure.
void PoisonFrameSelfTest();

} // namespace duetos::mm
