#pragma once

#include "util/types.h"

/*
 * DuetOS — slab allocator, v0.
 *
 * WHAT
 *   A fixed-size object allocator sitting on top of `kheap`.
 *   Each `SlabCache` hands out objects of one size from a chain
 *   of "slabs" (large blocks carved into a freelist of equal-
 *   sized objects). Alloc / Free are O(1) pointer manipulations
 *   on a per-cache freelist.
 *
 * WHY
 *   The kheap is a first-fit + coalescing freelist with a 16-
 *   byte header per allocation. Hot-path callers that allocate
 *   many objects of one size (Task structs, slot ring entries,
 *   work-pool items, packet buffers) pay:
 *     - 16 B of header per object,
 *     - O(N) freelist scan worst case,
 *     - external fragmentation as the size mix shifts.
 *   A slab cache gives the same workload:
 *     - 0 B header per object (size is implicit from the cache),
 *     - O(1) alloc / free (pop / push the cache's freelist),
 *     - zero internal fragmentation within the size class.
 *
 *   Slabs come from the kheap via `KMalloc`, so the kheap is
 *   still the single source of bytes. Slab is a layer that
 *   trades amortised kheap calls (one per N objects) for
 *   per-object speed.
 *
 * SHAPE
 *   - One `SlabCache` per object size. Multiple callers of the
 *     same size share a cache by construction — the cache pointer
 *     IS the size identity.
 *   - Each underlying slab is a `kSlabBytes`-byte block from
 *     `KMalloc`, sliced into `kSlabBytes / obj_size` objects.
 *     The block boundary is bookkeeping only — alloc / free walk
 *     a single global freelist that spans every slab in the
 *     cache.
 *   - Caches NEVER shrink — once a slab is allocated, it stays
 *     allocated until `SlabCacheDestroy`. Empty-slab reaping is
 *     a follow-on; the v0 cost ceiling is one slab's worth of
 *     unused storage per workload spike, which is acceptable for
 *     the size classes we target (≤ 2 KiB).
 *
 * THREADING
 *   Each cache has its own `sched::Mutex`. Cache operations are
 *   safe from any kernel context that can take a sleeping mutex.
 *   IRQ-context allocation is OUT OF SCOPE for v0; the kheap
 *   itself isn't IRQ-safe today either, so the slab inherits the
 *   same restriction.
 *
 * SCOPE LIMITS (v0)
 *   - No per-CPU magazine (free-pool cached on the calling CPU).
 *     Future B2-followup: once the sched lock splits per-CPU,
 *     the same pattern lets slab caches add a magazine layer for
 *     truly lock-free fast-path alloc / free on the running CPU.
 *   - No object constructor / destructor. Objects are returned
 *     uninitialised; callers placement-new if they need it.
 *   - No KMalloc-replacement integration. Existing KMalloc /
 *     KFree call sites are unchanged. A future slice can add a
 *     "size-classed kheap" that routes small allocations through
 *     pre-built slab caches automatically.
 */

namespace duetos::mm
{

struct SlabCache;

/// Default per-slab block size. Sized so the kheap header is
/// negligible (< 0.1%) and so a 64 B object yields 256 free
/// slots per slab — a comfortable batch size for the typical
/// driver / IPC workload spike.
inline constexpr u64 kSlabBytes = 16 * 1024;

/// Allocate a `SlabCache` that hands out objects of size
/// `obj_size`, padded out to `alignment`. `alignment` must be a
/// power of two in `[8, 256]`; `obj_size` must be `> 0` and
/// `≤ kSlabBytes / 2` (so each slab fits at least two objects —
/// otherwise the kheap allocation pattern beats the slab).
/// `name` is borrowed for diagnostics; storage must outlive the
/// cache.
///
/// Returns nullptr on invalid arguments or allocation failure.
SlabCache* SlabCacheCreate(const char* name, u32 obj_size, u32 alignment);

/// Free every slab the cache holds, then the cache struct
/// itself. The caller is responsible for ensuring no live
/// allocations remain — `SlabCacheDestroy` panics if the
/// `obj_in_use` counter is non-zero, since freeing the backing
/// slabs would invalidate every outstanding pointer.
void SlabCacheDestroy(SlabCache* c);

/// Allocate one object from the cache. O(1) when the cache's
/// freelist is non-empty; O(K) (K = objects per slab) when a
/// fresh slab has to be carved. Returns nullptr if the
/// underlying `KMalloc(kSlabBytes)` fails.
void* SlabAlloc(SlabCache* c);

/// Return `obj` to the cache. Must have been returned by
/// `SlabAlloc` on the SAME cache; the slab allocator does not
/// validate cross-cache frees (the cost would dwarf the
/// allocation). nullptr is a no-op.
void SlabFree(SlabCache* c, void* obj);

struct SlabStats
{
    u64 obj_size;
    u64 objects_per_slab;
    u64 slabs;       ///< Total slabs ever allocated for this cache.
    u64 obj_in_use;  ///< Currently allocated, awaiting SlabFree.
    u64 obj_free;    ///< In a slab but not currently allocated.
    u64 alloc_count; ///< Lifetime SlabAlloc calls that returned non-null.
    u64 free_count;  ///< Lifetime SlabFree calls that did anything.
};

/// Cheap diagnostic snapshot. Racy under concurrent activity —
/// for human-readable shell commands, not for caller decisions.
SlabStats SlabCacheStatsRead(const SlabCache* c);

/// Boot-time self-test. Creates a cache, runs alloc / free /
/// re-alloc round-trips that span multiple slabs, asserts the
/// LIFO ordering invariant (last-freed object is the next
/// allocation), then destroys the cache. Panics on any
/// mismatch.
void SlabSelfTest();

} // namespace duetos::mm
