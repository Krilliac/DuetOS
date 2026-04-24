#pragma once

#include "../core/types.h"

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

/// Initial heap pool size. 2 MiB (= 512 contiguous 4 KiB frames). Generous
/// for boot-era data structures; far smaller than typical OOM headroom on
/// any machine that meets our minimums.
inline constexpr u64 kKernelHeapBytes = 2ULL * 1024 * 1024;

struct KernelHeapStats
{
    u64 pool_bytes;       // total pool size including all headers
    u64 used_bytes;       // sum of allocated chunk sizes (incl. headers)
    u64 free_bytes;       // sum of free chunk sizes (incl. headers)
    u64 alloc_count;      // lifetime KMalloc calls that returned non-null
    u64 free_count;       // lifetime KFree calls that did anything
    u64 largest_free_run; // largest contiguous free chunk right now
    u64 free_chunk_count; // number of nodes on the freelist (fragmentation)
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

/// Snapshot of allocator state. Cheap (O(freelist length)).
KernelHeapStats KernelHeapStatsRead();

/// Exercise allocate / free / coalesce end-to-end. Prints to COM1 and panics
/// on any inconsistency. Intended for use during boot only.
void KernelHeapSelfTest();

} // namespace duetos::mm
