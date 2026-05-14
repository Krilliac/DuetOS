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

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "mm/poison.h"
#include "sched/sched.h"
#include "util/saturating.h"
#include "util/string.h"
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

// Per-CPU magazine size. A small power-of-two so the magazine
// itself fits in a few cache lines and the alloc/free fast path
// is a bounded handful of instructions. Bulk refill / drain on a
// magazine miss takes kMagazineSize / 2 objects so the next ~half
// magazine of operations on this CPU can stay on the fast path.
inline constexpr u32 kMagazineSize = 16;

struct Magazine
{
    u32 count; ///< 0..kMagazineSize objects currently cached.
    u32 _pad;
    void* objs[kMagazineSize]; ///< LIFO; pop from objs[--count], push at objs[count++].
};

bool IsPowerOfTwo(u32 x)
{
    return x != 0 && (x & (x - 1)) == 0;
}

u64 RoundUp(u64 v, u64 align)
{
    return (v + align - 1) & ~(align - 1);
}

constexpr u64 kRflagsIfBit = 1ULL << 9;

inline u64 ReadRflagsLocal()
{
    u64 f;
    asm volatile("pushfq; pop %0" : "=r"(f)::"memory");
    return f;
}

// IRQ-off scope guard for the magazine fast path. Disabling
// interrupts on the running CPU pins us there for the duration —
// no preemption to a different CPU mid-magazine, no IRQ handler
// stomping the magazine while we hold a half-updated count.
struct IrqOff
{
    u64 saved_rflags;
    IrqOff() : saved_rflags(ReadRflagsLocal()) { arch::Cli(); }
    ~IrqOff()
    {
        if ((saved_rflags & kRflagsIfBit) != 0)
        {
            arch::Sti();
        }
    }
    IrqOff(const IrqOff&) = delete;
    IrqOff& operator=(const IrqOff&) = delete;
};

} // namespace

struct SlabCache
{
    sched::Mutex lock;
    const char* name;     ///< Borrowed; outlives the cache.
    u32 obj_size;         ///< Padded to `alignment`.
    u32 objects_per_slab; ///< Computed at Create.

    Slab* slab_head;         ///< Chain of every slab owned by this cache.
    SlabFreeNode* free_head; ///< Cache-wide freelist of unused objects (mutex-protected).

    // Counters touched on both the magazine fast path (lock-free) and
    // the global slow path (under c->lock). All access goes through
    // __atomic_* with relaxed ordering — these are bookkeeping, not
    // synchronization, and a torn read of one counter can't break
    // any caller's allocation.
    u64 slabs;
    u64 obj_in_use;
    u64 obj_free;
    u64 alloc_count;
    u64 free_count;
    u64 magazine_alloc; ///< Allocs satisfied from a per-CPU magazine.
    u64 magazine_free;  ///< Frees absorbed by a per-CPU magazine.

    Magazine magazines[acpi::kMaxCpus];
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
        // KMalloc OOM during slab growth — the calling cache can't
        // service its next Alloc() and the caller upstack receives
        // nullptr without any signal of why. Pin the cache name in
        // the log so a regression points at the responsible cache.
        KLOG_ONCE_WARN_V("mm/slab", "GrowOneSlab: KMalloc failed — cache cannot grow (slab bytes)", kSlabBytes);
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
        // Stamp the trailing payload with the slab poison BEFORE the
        // freelist link is written, so freshly-carved objects look
        // identical to SlabFree-returned ones to the alloc-side
        // verifier. The first sizeof(SlabFreeNode) bytes are about
        // to be overwritten by the link, so don't bother poisoning
        // them.
        PoisonSlabFreedObject(obj_u8, c->obj_size, sizeof(SlabFreeNode));
        auto* node = reinterpret_cast<SlabFreeNode*>(obj_u8);
        node->next = head;
        head = node;
    }

    // Link the slab into the cache.
    slab->next = c->slab_head;
    c->slab_head = slab;
    __atomic_add_fetch(&c->slabs, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&c->obj_free, c->objects_per_slab, __ATOMIC_RELAXED);
    return head;
}

// Pop one object off the global freelist. Caller holds c->lock.
// Returns nullptr iff the freelist is empty AND a fresh slab grow
// would be required (callers that want to grow do so explicitly).
SlabFreeNode* PopGlobalFreelist(SlabCache* c)
{
    SlabFreeNode* node = c->free_head;
    if (node == nullptr)
    {
        return nullptr;
    }
    c->free_head = node->next;
    return node;
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

    // Drain every CPU's magazine back onto the global freelist
    // BEFORE checking obj_in_use. Magazined objects aren't "in
    // use" by a caller, so they don't fail the live-allocations
    // check; but draining is the cleanest way to ensure the
    // poison invariants hold across destruction and to make the
    // bookkeeping snapshot below internally consistent.
    for (u32 cpu = 0; cpu < acpi::kMaxCpus; ++cpu)
    {
        Magazine& m = c->magazines[cpu];
        while (m.count > 0)
        {
            auto* node = static_cast<SlabFreeNode*>(m.objs[--m.count]);
            node->next = c->free_head;
            c->free_head = node;
        }
    }

    const u64 in_use = __atomic_load_n(&c->obj_in_use, __ATOMIC_RELAXED);
    KASSERT(in_use == 0, "slab", "Destroy with live allocations");
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

    void* obj = nullptr;

    // ---- Fast path: pop from this CPU's magazine. -----------------
    {
        IrqOff guard;
        const u32 cpu = cpu::CurrentCpuIdOrBsp();
        if (cpu < acpi::kMaxCpus)
        {
            Magazine& m = c->magazines[cpu];
            if (m.count > 0)
            {
                obj = m.objs[--m.count];
                __atomic_sub_fetch(&c->obj_free, 1, __ATOMIC_RELAXED);
                __atomic_add_fetch(&c->obj_in_use, 1, __ATOMIC_RELAXED);
                util::SatAtomicAdd<u64>(&c->alloc_count, 1);
                util::SatAtomicAdd<u64>(&c->magazine_alloc, 1);
            }
        }
    }

    if (obj == nullptr)
    {
        // ---- Slow path: take cache mutex, pull a batch from the
        // global freelist into the magazine, and return the head to
        // the caller. Bulk refill (kMagazineSize / 2 objects) so the
        // next ~half-magazine of allocs on this CPU stay fast-path.
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

        SlabFreeNode* head = PopGlobalFreelist(c);
        // Pull up to kMagazineSize / 2 ADDITIONAL objects into a
        // refill list. May come up short if the freelist drains; the
        // splice below copes with any count, including zero.
        SlabFreeNode* refill = nullptr;
        u32 refill_count = 0;
        while (refill_count < kMagazineSize / 2)
        {
            SlabFreeNode* n = PopGlobalFreelist(c);
            if (n == nullptr)
            {
                break;
            }
            n->next = refill;
            refill = n;
            ++refill_count;
        }
        sched::MutexUnlock(&c->lock);

        // Counter updates: caller's object becomes in-use (alloc),
        // refill objects stay free (their location changed, not
        // their state). Single batched atomic per counter.
        __atomic_sub_fetch(&c->obj_free, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&c->obj_in_use, 1, __ATOMIC_RELAXED);
        util::SatAtomicAdd<u64>(&c->alloc_count, 1);

        obj = head;

        // Splice the refill list into THIS CPU's magazine. Must be
        // done with IRQs disabled so a preemption mid-splice can't
        // migrate us and corrupt the wrong magazine.
        if (refill != nullptr)
        {
            IrqOff guard;
            const u32 cpu = cpu::CurrentCpuIdOrBsp();
            if (cpu < acpi::kMaxCpus)
            {
                Magazine& m = c->magazines[cpu];
                while (refill != nullptr && m.count < kMagazineSize)
                {
                    SlabFreeNode* next = refill->next;
                    m.objs[m.count++] = refill;
                    refill = next;
                }
            }
        }

        // Magazine couldn't take everything (only happens if it was
        // already partially full from a parallel free path) — return
        // the leftovers to the global freelist. Cold path within a
        // cold path; clarity over micro-optimisation.
        if (refill != nullptr)
        {
            sched::MutexLock(&c->lock);
            while (refill != nullptr)
            {
                SlabFreeNode* next = refill->next;
                refill->next = c->free_head;
                c->free_head = refill;
                refill = next;
            }
            sched::MutexUnlock(&c->lock);
        }
    }

    // Verify the trailing-payload poison before handing the object
    // out. A mismatch means something wrote into the object between
    // its last SlabFree and this SlabAlloc — i.e. a use-after-free
    // on the slab side.
    const u64 mismatch = CheckSlabFreedObjectPoison(obj, c->obj_size, sizeof(SlabFreeNode));
    if (mismatch != c->obj_size)
    {
        KLOG_WARN_S("slab", "freed-object poison mismatch", "cache", c->name);
        KASSERT(false, "slab", "use-after-free in slab object");
    }
    return obj;
}

void* SlabAllocZeroed(SlabCache* c)
{
    void* obj = SlabAlloc(c);
    if (obj == nullptr)
        return nullptr;
    // Wipe the freed-object poison pattern. SlabAlloc has already
    // verified it, so callers can trust that what gets memset to 0
    // here was unambiguously a freed (or fresh-carved) slot — no
    // live-object data leaks through.
    memset(obj, 0, c->obj_size);
    return obj;
}

void SlabFree(SlabCache* c, void* obj)
{
    if (obj == nullptr)
    {
        return;
    }
    KASSERT(c != nullptr, "slab", "SlabFree null cache");

    // Stamp the trailing payload with the slab poison BEFORE the
    // freelist link gets written into the first sizeof(SlabFreeNode)
    // bytes. Done outside any lock — the caller has already returned
    // the object to us, so the bytes are ours to scribble on.
    PoisonSlabFreedObject(obj, c->obj_size, sizeof(SlabFreeNode));

    // ---- Fast path: push into this CPU's magazine. ---------------
    {
        IrqOff guard;
        const u32 cpu = cpu::CurrentCpuIdOrBsp();
        if (cpu < acpi::kMaxCpus)
        {
            Magazine& m = c->magazines[cpu];
            if (m.count < kMagazineSize)
            {
                m.objs[m.count++] = obj;
                __atomic_sub_fetch(&c->obj_in_use, 1, __ATOMIC_RELAXED);
                __atomic_add_fetch(&c->obj_free, 1, __ATOMIC_RELAXED);
                util::SatAtomicAdd<u64>(&c->free_count, 1);
                util::SatAtomicAdd<u64>(&c->magazine_free, 1);
                return;
            }
        }
    }

    // ---- Slow path: magazine full (or no per-CPU slot). Drop into
    // the global freelist. While we hold the lock, opportunistically
    // bulk-drain half this CPU's magazine back to global so the next
    // ~half-magazine of frees on this CPU stay fast-path.
    SlabFreeNode* drain_head = nullptr;
    u32 drain_count = 0;
    {
        IrqOff guard;
        const u32 cpu = cpu::CurrentCpuIdOrBsp();
        if (cpu < acpi::kMaxCpus)
        {
            Magazine& m = c->magazines[cpu];
            while (drain_count < kMagazineSize / 2 && m.count > 0)
            {
                auto* node = static_cast<SlabFreeNode*>(m.objs[--m.count]);
                node->next = drain_head;
                drain_head = node;
                ++drain_count;
            }
        }
    }

    sched::MutexLock(&c->lock);
    auto* node = static_cast<SlabFreeNode*>(obj);
    node->next = c->free_head;
    c->free_head = node;
    while (drain_head != nullptr)
    {
        SlabFreeNode* next = drain_head->next;
        drain_head->next = c->free_head;
        c->free_head = drain_head;
        drain_head = next;
    }
    sched::MutexUnlock(&c->lock);

    __atomic_sub_fetch(&c->obj_in_use, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&c->obj_free, 1, __ATOMIC_RELAXED);
    util::SatAtomicAdd<u64>(&c->free_count, 1);
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
    s.slabs = __atomic_load_n(&c->slabs, __ATOMIC_RELAXED);
    s.obj_in_use = __atomic_load_n(&c->obj_in_use, __ATOMIC_RELAXED);
    s.obj_free = __atomic_load_n(&c->obj_free, __ATOMIC_RELAXED);
    s.alloc_count = __atomic_load_n(&c->alloc_count, __ATOMIC_RELAXED);
    s.free_count = __atomic_load_n(&c->free_count, __ATOMIC_RELAXED);
    s.magazine_alloc = __atomic_load_n(&c->magazine_alloc, __ATOMIC_RELAXED);
    s.magazine_free = __atomic_load_n(&c->magazine_free, __ATOMIC_RELAXED);
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

    // Poison verification: the trailing payload of a re-allocated
    // object must come back stamped with kSlabFreedObjectPoison
    // (the freelist link occupies the first sizeof(SlabFreeNode)
    // bytes; the rest is the poison band).
    {
        const auto* probe = static_cast<const u8*>(reuse) + sizeof(void*);
        for (u32 i = 0; i < kObjSize - sizeof(void*); ++i)
        {
            KASSERT(probe[i] == kSlabFreedObjectPoison, "slab", "self-test: poison missing on reuse");
        }
    }

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
