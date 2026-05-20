#pragma once

#include "util/types.h"

/*
 * DuetOS kernel heap — v0.
 *
 * A first-fit + coalescing freelist allocator over a single contiguous pool
 * carved out of the physical frame allocator at boot. Backed by the static
 * higher-half direct map, so the heap's virtual range is always
 * [KERNEL_VIRTUAL_BASE + base_phys .. + base_phys + pool_bytes).
 *
 * Scope limits that will be fixed in later commits:
 *   - Single fixed-size pool. No growth. KernelHeapInit() panics if the pool
 *     can't be obtained; KMalloc returns nullptr when the pool is exhausted.
 *   - Not thread-safe. No lock today; SMP bring-up will add a spinlock.
 *   - First fit, not best fit. Fine for boot-time data structures and the
 *     handful of allocations the early kernel makes.
 *   - 16-byte header per allocation. Payload alignment is 16 bytes (enough
 *     for any scalar or pointer; SSE/AVX state lives in per-thread save areas
 *     allocated separately).
 *
 * Context: kernel. Init runs once after FrameAllocatorInit. KMalloc/KFree
 * are then safe to call from any kernel code that is NOT in IRQ context
 * (sleeping in IRQ would need spinlock_irqsave; see [thread safety rules]
 * in CLAUDE.md).
 */

namespace duetos::mm
{

/// Minimum payload alignment guaranteed by KMalloc. Doubles as the unit of
/// rounding on requested sizes — KMalloc(7) and KMalloc(16) both consume the
/// same 16-byte payload slot.
inline constexpr u64 kHeapAlignment = 16;

/// Kernel heap pool size. 64 MiB (= 16384 contiguous 4 KiB frames). The
/// original 2 MiB sizing was a "boot-era data structures only" budget that
/// the boot-time self-test battery (ring3-smoke, pe-compat, linux-smoke)
/// outgrew once the kernel actually runs the full battery on a healthy
/// boot — `AddressSpaceCreate` alone is 128 KiB per ring-3 task and the
/// linux-smoke batch queues ~13 tasks (panic site: kernel/mm/kheap.cpp:445
/// "KMalloc OOM - pool exhausted, request size 0x20080"). 64 MiB leaves
/// plenty of headroom and is still trivial against any modern minimum.
inline constexpr u64 kKernelHeapBytes = 64ULL * 1024 * 1024;

struct KernelHeapStats
{
    u64 pool_bytes;         // total pool size including all headers
    u64 used_bytes;         // sum of allocated chunk sizes (incl. headers)
    u64 free_bytes;         // sum of free chunk sizes (incl. headers, including binned)
    u64 alloc_count;        // lifetime KMalloc calls that returned non-null
    u64 free_count;         // lifetime KFree calls that did anything
    u64 largest_free_run;   // largest contiguous free chunk on the main freelist
    u64 free_chunk_count;   // number of nodes on the freelist (fragmentation, excludes bins)
    u64 binned_chunk_count; ///< Chunks currently parked in size-class bins (also "free").
    u64 bin_alloc_hits;     ///< Allocations satisfied by a size-class bin (no freelist walk).
    u64 bin_free_hits;      ///< Frees absorbed by a size-class bin (no coalesce).
};

/// Carve a contiguous pool out of the physical frame allocator and seed the
/// freelist. Panics on failure — boot can't continue without a heap.
void KernelHeapInit();

/// Allocate `bytes` of memory aligned to kHeapAlignment. Returns nullptr if
/// the pool is exhausted. `bytes == 0` returns nullptr.
void* KMalloc(u64 bytes);

/// Release a pointer previously returned by KMalloc. nullptr is a no-op.
/// Coalesces with adjacent free chunks. Calling KFree on a pointer not from
/// KMalloc, or double-freeing, is a kernel bug and triggers a panic.
void KFree(void* ptr);

/// Snapshot of allocator state. Cheap (O(freelist length + bin chunks)).
KernelHeapStats KernelHeapStatsRead();

/// Push every chunk currently parked in a size-class bin back onto the
/// main coalescing freelist. After this returns, the bin fast path is
/// empty for every size class — the next round of size-class alloc/free
/// activity warms it up again. Used by the self-test (so the
/// "everything coalesced back" invariant is checkable after small-size
/// allocations) and available to memory-pressure paths that prefer
/// fewer free chunks at the cost of a slower next allocation.
void KernelHeapDrainBins();

/// One row of the heap-leak ranking — a (caller RIP, bytes outstanding,
/// allocation count) tuple. The reporter sorts descending by `bytes`.
struct HeapLeakEntry
{
    u64 caller_rip; ///< `__builtin_return_address(0)` captured at KMalloc time.
    u64 bytes;      ///< Sum of live allocation payload+header sizes from this RIP.
    u64 count;      ///< Number of live allocations from this RIP.
};

/// Walk the heap in chunk-size steps and aggregate live chunks by their
/// recorded `caller_rip`. Writes up to `out_capacity` entries into `out`,
/// sorted descending by `bytes`. Returns the number of distinct RIPs
/// observed (clipped to `out_capacity`); if more distinct RIPs exist
/// than capacity, the ones below the cutoff are silently dropped.
///
/// Takes the kheap's freelist invariants as gospel — does NOT acquire a
/// lock today (kheap is single-CPU at v0). Cheap O(N_chunks); the
/// aggregation table is fixed-size (`out_capacity`) so worst-case is
/// O(N_chunks * out_capacity) compares. Safe to call from any kernel
/// task context.
u32 KernelHeapTopAllocators(HeapLeakEntry* out, u32 out_capacity);

/// Exercise allocate / free / coalesce end-to-end. Prints to COM1 and panics
/// on any inconsistency. Intended for use during boot only.
void KernelHeapSelfTest();

} // namespace duetos::mm
