/*
 * DuetOS — slab allocator: implementation.
 *
 * See `slab.h` for the public contract. This TU owns:
 *   - kheap-backed allocation of cache structs + per-slab blocks,
 *   - the per-cache global freelist (intrusive singly-linked
 *     through the first sizeof(void*) bytes of each free object),
 *   - the slab chain (head pointer per cache),
 *   - the boot self-test.
 *
 * State invariants (held under `c->lock`):
 *   - obj_in_use + obj_free == slabs * objects_per_slab
 *   - alloc_count >= free_count (lifetime monotonic)
 *   - free_head reachable in N hops where N == obj_free
 *
 * The freelist is intrusive: a free object's first 8 bytes hold
 * the `next` pointer (cast through SlabFreeNode). This is safe
 * because the caller has already returned the object — the bytes
 * are owned by the cache between SlabFree and the next SlabAlloc
 * that hands them back.
 */

#include "mm/slab.h"

#include "core/panic.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "util/types.h"

namespace duetos::mm
{

namespace
{

struct SlabFreeNode
{
    SlabFreeNode* next;
};

struct Slab
{
    Slab* next;    ///< Next slab in cache->slab_head chain.
    void* base;    ///< Pointer to the kheap-backed block (== Slab struct itself,
                   ///< since the bookkeeping struct lives at the start of the
                   ///< block — saves a separate allocation).
    u32 obj_count; ///< Number of objects carved from this slab.
    u32 _pad;
};

bool IsPowerOfTwo(u32 x)
{
    return x != 0 && (x & (x - 1)) == 0;
}

u64 RoundUp(u64 v, u64 align)
{
    return (v + align - 1) & ~(align - 1);
}

} // namespace

struct SlabCache
{
    sched::Mutex lock;
    const char* name;     ///< Borrowed; outlives the cache.
    u32 obj_size;         ///< Padded to `alignment`.
    u32 objects_per_slab; ///< Computed at Create.

    Slab* slab_head;         ///< Chain of every slab owned by this cache.
    SlabFreeNode* free_head; ///< Cache-wide freelist of unused objects.

    u64 slabs;
    u64 obj_in_use;
    u64 obj_free;
    u64 alloc_count;
    u64 free_count;
};

namespace
{

// Carve one fresh slab. Allocates a kSlabBytes block, places the
// Slab struct at offset 0, then slices the remainder into
// `objects_per_slab` objects threaded onto a brand-new freelist.
// Returns the head of that freelist (caller-of-this-helper splices
// it onto `c->free_head` under the cache lock).
SlabFreeNode* GrowOneSlab(SlabCache* c)
{
    void* block = KMalloc(kSlabBytes);
    if (block == nullptr)
    {
        return nullptr;
    }

    auto* slab = static_cast<Slab*>(block);
    slab->base = block;
    slab->obj_count = c->objects_per_slab;

    // The first `kFirstObjOffset` bytes of the block hold the
    // Slab struct; objects start after that, aligned up.
    constexpr u64 kFirstObjOffsetUnaligned = sizeof(Slab);
    const u64 first_obj = RoundUp(kFirstObjOffsetUnaligned, c->obj_size);

    // Re-derive how many objects actually fit after the slab
    // header. Build the freelist top-down so the FIRST object in
    // the slab ends up at the HEAD of the per-slab freelist;
    // alloc-then-free of N consecutive objects produces
    // sequential addresses, which is friendlier to the
    // hardware prefetcher than randomised addresses. The slab
    // freelist is then spliced onto the cache's global freelist.
    auto* base_u8 = static_cast<u8*>(block);
    SlabFreeNode* head = nullptr;
    for (u64 i = c->objects_per_slab; i-- > 0;)
    {
        auto* obj_u8 = base_u8 + first_obj + i * c->obj_size;
        auto* node = reinterpret_cast<SlabFreeNode*>(obj_u8);
        node->next = head;
        head = node;
    }

    // Link the slab into the cache.
    slab->next = c->slab_head;
    c->slab_head = slab;
    ++c->slabs;
    c->obj_free += c->objects_per_slab;
    return head;
}

} // namespace

SlabCache* SlabCacheCreate(const char* name, u32 obj_size, u32 alignment)
{
    if (name == nullptr || obj_size == 0)
    {
        return nullptr;
    }
    if (!IsPowerOfTwo(alignment) || alignment < 8 || alignment > 256)
    {
        return nullptr;
    }
    const u32 padded = static_cast<u32>(RoundUp(obj_size, alignment));
    if (padded > kSlabBytes / 2)
    {
        return nullptr;
    }

    auto* c = static_cast<SlabCache*>(KMalloc(sizeof(SlabCache)));
    if (c == nullptr)
    {
        return nullptr;
    }
    *c = SlabCache{};
    c->name = name;
    c->obj_size = padded;

    // Compute objects_per_slab. Each slab spends `sizeof(Slab)`
    // bytes on bookkeeping; the rest, after rounding the object
    // start up to obj_size, is the usable object area.
    const u64 first_obj_offset = RoundUp(sizeof(Slab), padded);
    c->objects_per_slab = static_cast<u32>((kSlabBytes - first_obj_offset) / padded);
    if (c->objects_per_slab < 2)
    {
        // Degenerate — caller chose too-large an obj_size for
        // kSlabBytes. The Create-side guard above is meant to
        // catch this; defensive double-check.
        KFree(c);
        return nullptr;
    }

    KLOG_INFO_S("slab", "cache created", "name", name);
    return c;
}

void SlabCacheDestroy(SlabCache* c)
{
    if (c == nullptr)
    {
        return;
    }
    sched::MutexLock(&c->lock);
    KASSERT(c->obj_in_use == 0, "slab", "Destroy with live allocations");
    Slab* s = c->slab_head;
    while (s != nullptr)
    {
        Slab* next = s->next;
        KFree(s->base);
        s = next;
    }
    sched::MutexUnlock(&c->lock);
    KFree(c);
}

void* SlabAlloc(SlabCache* c)
{
    KASSERT(c != nullptr, "slab", "SlabAlloc null cache");
    sched::MutexLock(&c->lock);
    if (c->free_head == nullptr)
    {
        SlabFreeNode* fresh = GrowOneSlab(c);
        if (fresh == nullptr)
        {
            sched::MutexUnlock(&c->lock);
            return nullptr;
        }
        c->free_head = fresh;
    }
    SlabFreeNode* node = c->free_head;
    c->free_head = node->next;
    --c->obj_free;
    ++c->obj_in_use;
    ++c->alloc_count;
    sched::MutexUnlock(&c->lock);
    return node;
}

void SlabFree(SlabCache* c, void* obj)
{
    if (obj == nullptr)
    {
        return;
    }
    KASSERT(c != nullptr, "slab", "SlabFree null cache");
    sched::MutexLock(&c->lock);
    auto* node = static_cast<SlabFreeNode*>(obj);
    node->next = c->free_head;
    c->free_head = node;
    ++c->obj_free;
    --c->obj_in_use;
    ++c->free_count;
    sched::MutexUnlock(&c->lock);
}

SlabStats SlabCacheStatsRead(const SlabCache* c)
{
    SlabStats s{};
    if (c == nullptr)
    {
        return s;
    }
    s.obj_size = c->obj_size;
    s.objects_per_slab = c->objects_per_slab;
    s.slabs = c->slabs;
    s.obj_in_use = c->obj_in_use;
    s.obj_free = c->obj_free;
    s.alloc_count = c->alloc_count;
    s.free_count = c->free_count;
    return s;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

void SlabSelfTest()
{
    constexpr u32 kObjSize = 64;
    constexpr u32 kAlign = 16;
    // For obj_size = 64 padded to align 16, kSlabBytes / 64 ≈ 256
    // objects per slab. Cap the test at a fixed count + a few
    // overflow slots so we span exactly two slabs without using a
    // VLA. The +4 produces one slab grow (per_slab+1) and three
    // more allocations on the second slab.
    constexpr u32 kAllocCount = (kSlabBytes / kObjSize) + 4;
    constexpr u32 kPtrsCap = kAllocCount; // compile-time bound

    SlabCache* c = SlabCacheCreate("slab-st", kObjSize, kAlign);
    KASSERT(c != nullptr, "slab", "self-test: Create failed");

    const u32 per_slab = static_cast<u32>(SlabCacheStatsRead(c).objects_per_slab);
    KASSERT(per_slab >= 2, "slab", "self-test: per_slab < 2");
    KASSERT(kAllocCount > per_slab, "slab", "self-test: alloc count must exceed per_slab to grow");

    void* ptrs[kPtrsCap];
    for (u32 i = 0; i < kAllocCount; ++i)
    {
        ptrs[i] = SlabAlloc(c);
        KASSERT(ptrs[i] != nullptr, "slab", "self-test: alloc returned null");
    }
    {
        const auto s = SlabCacheStatsRead(c);
        KASSERT(s.obj_in_use == kAllocCount, "slab", "self-test: in_use mismatch");
        KASSERT(s.slabs >= 2, "slab", "self-test: slab grow did not happen");
        KASSERT(s.alloc_count == kAllocCount, "slab", "self-test: alloc_count mismatch");
    }

    // LIFO ordering: free one, the next allocation should be the
    // exact pointer just freed.
    SlabFree(c, ptrs[kAllocCount - 1]);
    void* reuse = SlabAlloc(c);
    KASSERT(reuse == ptrs[kAllocCount - 1], "slab", "self-test: LIFO ordering broken");
    ptrs[kAllocCount - 1] = reuse;

    // Drain everything.
    for (u32 i = 0; i < kAllocCount; ++i)
    {
        SlabFree(c, ptrs[i]);
    }
    {
        const auto s = SlabCacheStatsRead(c);
        KASSERT(s.obj_in_use == 0, "slab", "self-test: in_use != 0 after drain");
        KASSERT(s.free_count == kAllocCount + 1, "slab", "self-test: free_count mismatch");
    }

    SlabCacheDestroy(c);
    KLOG_INFO("slab", "self-test: passed");
}

} // namespace duetos::mm
