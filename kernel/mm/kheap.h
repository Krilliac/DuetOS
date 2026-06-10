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
 * Small allocations (1..512 B) are routed to per-size SlabCaches once
 * KMallocSlabRoutingInit() runs — O(1) alloc/free with the classic
 * first-fit walk as fallback. See kernel/mm/kmalloc_route.h for the
 * pure routing/discrimination logic and its hosted unit test.
 *
 * Scope limits that will be fixed in later commits:
 *   - Single fixed-size pool. No growth. KernelHeapInit() panics if the pool
 *     can't be obtained; KMalloc returns nullptr when the pool is exhausted.
 *   - First fit, not best fit (above the routed 512 B ceiling). Fine for the
 *     allocation mix the kernel makes today.
 *   - 32-byte header per classic allocation (16 B route header on routed
 *     ones). Payload alignment is 16 bytes (enough for any scalar or
 *     pointer; SSE/AVX state lives in per-thread save areas allocated
 *     separately).
 *
 * Context: kernel. Init runs once after FrameAllocatorInit. KMalloc/KFree
 * are IRQ-safe and SMP-safe: a recursive irqsave spinlock guards the
 * freelist + size-class bins (see g_kheap_lock in kheap.cpp), and the
 * route caches use irq-safe slab mode.
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
/// linux-smoke batch queues ~13 tasks (panic site: kernel/mm/kheap.cpp:446
/// "KMalloc OOM - pool exhausted, request size 0x20080").
///
/// NOTE: 64 MiB is NOT comfortable headroom — the full non-emulator boot
/// battery (the ~12 security probes + ring3 trio + PE smokes + Linux
/// batch, all spawning 128 KiB address spaces concurrently before the
/// reaper catches up) has been observed to reach this ceiling and OOM
/// `AddressSpaceCreate`. The durable fix is to shrink the per-AS cost
/// (lazy/grown region table — see mm/address_space.h), NOT to keep
/// growing this number; raising the heap just moves the wall.
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

    // KMalloc small-allocation slab routing (kmalloc_route.h). The
    // routed byte gauges count whole slab objects (16 B route header
    // + class payload + 16 B trailer canary), i.e. the honest cost,
    // and live INSIDE used_bytes (slabs are KMalloc-backed) — they
    // are a breakdown, not an addition.
    u64 routed_alloc_count;       ///< Lifetime KMalloc calls satisfied by a route cache.
    u64 routed_free_count;        ///< Lifetime KFree calls returned to a route cache.
    u64 routed_live_bytes;        ///< Bytes in routed objects currently handed out.
    u64 routed_cached_free_bytes; ///< Bytes parked free in route caches (freelists + magazines).
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

/// Build the eight per-size SlabCaches (irq-safe mode) behind KMalloc
/// small-allocation routing, then enable routing. After this returns,
/// KMalloc(1..512) is satisfied O(1) from a route cache (classic
/// first-fit path remains the fallback when a cache can't grow) and
/// KFree discriminates routed pointers via the u64 word at ptr-16.
/// Call once; panics if any cache fails to create — routing half-
/// initialised would be worse than not at all.
void KMallocSlabRoutingInit();

/// Memory-pressure helper: push every routed object cached in the
/// CALLING CPU's per-cache magazines back onto the route caches'
/// global freelists (see SlabCacheDrainLocalMagazine). Invoked by
/// KernelHeapDrainBins so existing reclaim call sites cover both
/// layers. No-op before KMallocSlabRoutingInit.
void KMallocRouteDrain();

/// Boot self-test for the routing layer: per-class route + header
/// verification, LIFO reuse + poison visibility, the 512/513 routing
/// boundary, counter round-trips, and trailer-canary tamper
/// detection. Panics on failure; emits a PASS sentinel on success.
void KMallocRouteSelfTest();

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
/// Coverage note: slab-routed allocations (<= 512 B) don't appear as
/// chunks — their slab BLOCKS attribute to the slab grower's RIP, so
/// this ranking covers >512 B allocations plus aggregate slab growth.
/// Routed objects do record a caller RIP in their route header; a
/// routed-object walker is a follow-up if small-object leaks ever
/// dominate (KernelHeapStats.routed_live_bytes is the cheap tell).
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
