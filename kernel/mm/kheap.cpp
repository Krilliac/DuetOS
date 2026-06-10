#include "mm/kheap.h"

#include "mm/frame_allocator.h"
#include "mm/kmalloc_route.h"
#include "mm/page.h"
#include "mm/poison.h"
#include "mm/slab.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "core/panic.h"
#include "sync/spinlock.h"
#include "util/cache.h"
#include "util/debug_assert.h"
#include "util/saturating.h"

namespace duetos::mm
{

namespace
{

using arch::Halt;
using arch::SerialWrite;
using arch::SerialWriteHex;

// Magic values for the header's `magic` field. Large / unlikely / asymmetric
// so they won't collide with arbitrary payload bytes. If KFree ever sees
// neither value, the header has been overwritten — heap corruption — which
// is a Class-A integrity violation (runtime-recovery-strategy.md): halt.
constexpr u64 kHeapMagicLive = 0xDEADBEEFCAFEBABEULL; // chunk is handed out
constexpr u64 kHeapMagicFree = 0xFEEDFACE5A5A5A5AULL; // chunk is on freelist

// Byte pattern written over every freed payload so use-after-free + read-
// uninitialized bugs surface as obvious 0xDE..DE instead of stale data.
// Picked deliberately: 0xDE is a valid x86 prefix byte AND commonly used as
// a poison in other kernels, so grep-ability is good.
constexpr u8 kHeapFreePoison = 0xDE;

// Header sits at the start of every chunk, allocated or free. 32 bytes wide:
// payload is still returned 16-byte aligned because the header is a multiple
// of the alignment.
//
// The `next` field is meaningful only while the chunk is on the freelist;
// for an allocated chunk it overlaps the payload but the user owns those
// bytes once we hand them out, so it doesn't matter.
struct alignas(kHeapAlignment) ChunkHeader
{
    u64 size;          // total chunk size in bytes (header + payload)
    u64 magic;         // kHeapMagicLive or kHeapMagicFree
    ChunkHeader* next; // address-ordered freelist link (free chunks only)
    u64 caller_rip;    // return address of the KMalloc call site for live chunks; 0 when free
};

static_assert(sizeof(ChunkHeader) == 32, "Header must be 32 bytes");
static_assert(sizeof(ChunkHeader) % kHeapAlignment == 0, "Header must preserve payload alignment");

// LOAD-BEARING: the small-allocation route discriminator. `next` must
// sit exactly kSlabRouteHeaderBytes (16) before the payload, because
// KFree reads the u64 at `ptr - 16` to tell routed slab objects (route
// magic there) from classic kheap chunks — and KMalloc unconditionally
// writes `next = nullptr` on every live chunk (both the bin fast path
// and the freelist path), guaranteeing that word reads 0 for every
// live classic pointer. Reordering ChunkHeader's fields or letting a
// live chunk keep a non-null `next` breaks KFree's discrimination.
static_assert(__builtin_offsetof(ChunkHeader, next) == 16, "KFree discriminator expects next at payload-16");

// IRQ-off scope guard. KMalloc / KFree mutate the global address-
// ordered freelist + size-class bin pointers; without bracketing,
// an IRQ handler that itself allocates (frame allocator, slab, log
// ring growth) could re-enter the kheap and observe a half-updated
// freelist. Mirrors `mm/frame_allocator.cpp::FramePoolIrqOff` and
// `mm/slab.cpp::IrqOff` — same shape, same restore-iff-was-on
// rules, so the kheap follows the rest of the allocator family
// (T5-04: IRQ-safe kmalloc/kfree).
constexpr u64 kKheapRflagsIfBit = 1ULL << 9;

inline u64 ReadKheapRflags()
{
    u64 f;
    asm volatile("pushfq; pop %0" : "=r"(f)::"memory");
    return f;
}

struct KheapIrqOff
{
    u64 saved_rflags;
    KheapIrqOff() : saved_rflags(ReadKheapRflags()) { arch::Cli(); }
    ~KheapIrqOff()
    {
        if ((saved_rflags & kKheapRflagsIfBit) != 0)
        {
            arch::Sti();
        }
    }
    KheapIrqOff(const KheapIrqOff&) = delete;
    KheapIrqOff& operator=(const KheapIrqOff&) = delete;
};

[[noreturn]] void PanicHeapCorrupt(const char* what, const ChunkHeader* chunk)
{
    core::PanicWithValue("mm/kheap", what, reinterpret_cast<u64>(chunk));
}

inline void PoisonPayload(ChunkHeader* chunk)
{
    u8* payload = reinterpret_cast<u8*>(chunk) + sizeof(ChunkHeader);
    const u64 payload_size = chunk->size - sizeof(ChunkHeader);
    for (u64 i = 0; i < payload_size; ++i)
    {
        payload[i] = kHeapFreePoison;
    }
}

inline void AssertMagic(const ChunkHeader* chunk, u64 expected, const char* context)
{
    if (chunk->magic != expected)
    {
        PanicHeapCorrupt(context, chunk);
    }
}

constinit u8* g_pool_base = nullptr;
constinit u64 g_pool_bytes = 0;
constinit ChunkHeader* g_freelist = nullptr;
// Cross-CPU lock for the freelist + size-class bins. KheapIrqOff
// only did cli/sti (same-CPU IRQ re-entrancy) — no exclusion
// across CPUs, so concurrent KMalloc/KFree from APs could corrupt
// the freelist. Reentrant so KernelHeapSelfTest's nested
// KMalloc/KFree don't self-deadlock; irqsave, so it subsumes the
// old KheapIrqOff. Runtime path never calls the frame allocator
// (the 2 MiB pool is carved once in KernelHeapInit, pre-SMP), so
// the only cross-allocator order is slab-cache -> kheap, acyclic.
constinit sync::SpinLock g_kheap_lock{};
constinit util::SatU64 g_alloc_count = 0;
constinit util::SatU64 g_free_count = 0;

// Size-class bins. Each bin holds a LIFO stack of free chunks of one
// exact size, parked OUTSIDE the coalescing freelist. KMalloc checks
// the matching bin before walking the freelist; KFree pushes onto the
// matching bin before the freelist insert + coalesce. The trade is:
// pay a fixed-size per-class memory cap (kBinDepth * chunk_size per
// class) and modest external fragmentation in exchange for O(1)
// alloc/free on the size classes the workload actually hammers.
//
// Index = (chunk_size - kMinBinChunkSize) / kHeapAlignment. A chunk
// is the smallest thing the heap can hand out (header + one alignment
// unit of payload + trailer canary); kBinCount classes above that
// cover [kMinBinChunkSize, kMinBinChunkSize + kBinCount * 16) bytes
// of chunk size, i.e. payloads of [kHeapAlignment, kHeapAlignment +
// (kBinCount - 1) * 16] bytes. With kBinCount=12 + kHeapAlignment=16
// + canary=16 + header=32, that covers payloads of 16..192 B — the
// hot range for slab-cache plumbing, ring entries, and small driver
// objects that don't earn a dedicated SlabCache.
constexpr u32 kMinBinChunkSize = static_cast<u32>(sizeof(ChunkHeader) + kHeapAlignment + kHeapTrailerCanaryBytes);
constexpr u32 kBinCount = 12;
constexpr u32 kBinDepth = 8;

constinit ChunkHeader* g_bins[kBinCount] = {};
constinit u32 g_bin_count[kBinCount] = {};
// Bin hit counters — saturating per class BB. Reported via inspect /
// shell health, never used for modular arithmetic.
constinit util::SatU64 g_bin_alloc_hits = 0;
constinit util::SatU64 g_bin_free_hits = 0;

constexpr u32 kInvalidBin = 0xFFFFFFFFu;

// ---- KMalloc small-allocation slab routing state -------------------
// (decision logic lives in mm/kmalloc_route.h; the caches are built by
// KMallocSlabRoutingInit and never torn down). `g_route_enabled` flips
// LAST in init, so a true value implies every cache pointer is valid.
constinit bool g_route_enabled = false;
constinit SlabCache* g_route_caches[kSlabRouteClassCount] = {};
constinit util::SatU64 g_routed_alloc_count = 0;
constinit util::SatU64 g_routed_free_count = 0;

// Route-cache object layout: [16 B route header | class payload | 16 B
// trailer canary]. All class payloads are multiples of 16, so the
// payload pointer (obj + 16) keeps kHeapAlignment.
constexpr u64 RouteCacheObjBytes(u32 route_class)
{
    return kSlabRouteHeaderBytes + kSlabRouteClassBytes[route_class] + kHeapTrailerCanaryBytes;
}

inline u32 BinIndexForChunkSize(u64 chunk_size)
{
    if (chunk_size < kMinBinChunkSize)
    {
        return kInvalidBin;
    }
    const u64 over = chunk_size - kMinBinChunkSize;
    if ((over % kHeapAlignment) != 0)
    {
        // Bin chunk sizes are always multiples of kHeapAlignment beyond
        // kMinBinChunkSize; a non-multiple means caller asked for a
        // size that doesn't map cleanly. Defensive — KMalloc rounds
        // payload to alignment so this shouldn't fire in practice.
        return kInvalidBin;
    }
    const u64 idx = over / kHeapAlignment;
    if (idx >= kBinCount)
    {
        return kInvalidBin;
    }
    return static_cast<u32>(idx);
}

[[noreturn]] void PanicHeap(const char* message)
{
    core::Panic("mm/kheap", message);
}

inline u64 RoundUp(u64 value, u64 align)
{
    return (value + (align - 1)) & ~(align - 1);
}

inline bool InsidePool(const void* ptr)
{
    const u8* p = static_cast<const u8*>(ptr);
    return p >= g_pool_base && p < g_pool_base + g_pool_bytes;
}

inline bool ChunkAdjacent(const ChunkHeader* lhs, const ChunkHeader* rhs)
{
    const u8* end_of_lhs = reinterpret_cast<const u8*>(lhs) + lhs->size;
    return end_of_lhs == reinterpret_cast<const u8*>(rhs);
}

// Insert `chunk` into the address-ordered freelist and coalesce with the
// neighbours that turn out to be physically adjacent. Returns nothing —
// the freelist invariant is restored before this returns.
//
// The freelist is singly-linked but address-sorted, so the insertion
// walk already produces the predecessor (or nullptr for "insert at
// head") for free. Reuse that predecessor for the backward coalesce
// instead of re-walking the list — KFree was previously paying the
// O(n) cost twice per free.
void FreelistInsertAndCoalesce(ChunkHeader* chunk)
{
    chunk->next = nullptr;

    if (g_freelist == nullptr)
    {
        g_freelist = chunk;
        return;
    }

    ChunkHeader* prev = nullptr;
    if (chunk < g_freelist)
    {
        chunk->next = g_freelist;
        g_freelist = chunk;
    }
    else
    {
        // Walk until we find the first node whose successor is past `chunk`.
        ChunkHeader* cursor = g_freelist;
        while (cursor->next != nullptr && cursor->next < chunk)
        {
            if (cursor->next->next != nullptr)
            {
                util::PrefetchReadOnce(cursor->next->next);
            }
            cursor = cursor->next;
        }
        chunk->next = cursor->next;
        cursor->next = chunk;
        prev = cursor;
    }

    // Address-ordered-freelist invariant, in O(1) local form:
    // prev < chunk < chunk->next. The entire coalescing scheme
    // (and the insertion walk itself) assumes strict address
    // ordering; a mis-ordered insert silently corrupts the heap.
    // Debug-only — the always-on magic checks below catch the
    // corruption that ordering breakage usually rides in on.
    DEBUG_ASSERT(prev == nullptr || prev < chunk, "mm/kheap", "freelist not address-ordered (prev >= chunk)");
    DEBUG_ASSERT(chunk->next == nullptr || chunk < chunk->next, "mm/kheap",
                 "freelist not address-ordered (chunk >= next)");

    // Coalesce forward (chunk + next). Verify magic before folding —
    // if the "free" successor got its magic clobbered we'd silently
    // absorb corrupt bytes into `chunk`'s size.
    if (chunk->next != nullptr && ChunkAdjacent(chunk, chunk->next))
    {
        AssertMagic(chunk->next, kHeapMagicFree, "Coalesce: forward neighbour not Free");
        chunk->size += chunk->next->size;
        chunk->next = chunk->next->next;
    }

    // Coalesce backward (prev + chunk). `prev` was captured during the
    // insertion walk above; nullptr means `chunk` is the new head and
    // has no predecessor to coalesce with.
    if (prev != nullptr && ChunkAdjacent(prev, chunk))
    {
        AssertMagic(prev, kHeapMagicFree, "Coalesce: backward neighbour not Free");
        prev->size += chunk->size;
        prev->next = chunk->next;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
void KernelHeapInit()
{
    KLOG_TRACE_SCOPE("mm/kheap", "KernelHeapInit");
    constexpr u64 kFrames = kKernelHeapBytes / kPageSize;
    static_assert(kFrames * kPageSize == kKernelHeapBytes, "Heap size must be a multiple of the page size");

    auto base_phys_r = AllocateContiguousFrames(kFrames);
    if (!base_phys_r)
    {
        PanicHeap("could not allocate contiguous frames for the heap pool");
    }
    const PhysAddr base_phys = base_phys_r.value();

    g_pool_base = static_cast<u8*>(PhysToVirt(base_phys));
    g_pool_bytes = kKernelHeapBytes;
    g_freelist = reinterpret_cast<ChunkHeader*>(g_pool_base);
    g_freelist->size = kKernelHeapBytes;
    g_freelist->magic = kHeapMagicFree;
    g_freelist->next = nullptr;
    g_freelist->caller_rip = 0;
    g_alloc_count = 0;
    g_free_count = 0;

    SerialWrite("[mm] kernel heap online: pool=");
    SerialWriteHex(kKernelHeapBytes);
    SerialWrite(" base_virt=");
    SerialWriteHex(reinterpret_cast<u64>(g_pool_base));
    SerialWrite(" base_phys=");
    SerialWriteHex(base_phys);
    SerialWrite("\n");
}

void* KMalloc(u64 bytes)
{
    // ---- Small-allocation slab route -------------------------------
    // BEFORE g_kheap_lock: the route path takes a route-cache spinlock
    // and, on slab growth, re-enters KMalloc for the 16 KiB backing
    // block — lock order is route-cache -> kheap. Keeping the route
    // check outside the kheap lock keeps that order acyclic (the kheap
    // itself never calls into the slab). No recursion either: both the
    // grow (16 KiB) and SlabCacheCreate's own allocations are > 512 B,
    // so re-entrant KMalloc calls always take the classic path below.
    if (g_route_enabled && bytes != 0 && bytes <= kSlabRouteMaxBytes)
    {
        const u32 route_class = SizeToRouteClass(bytes);
        void* obj = SlabAlloc(g_route_caches[route_class]);
        if (obj != nullptr)
        {
            auto* base = static_cast<u8*>(obj);
            // 16 B route header: [0..8) the magic+class discriminator
            // KFree reads at ptr-16; [8..16) caller RIP, mirroring
            // ChunkHeader::caller_rip for a future routed-leak walker.
            *reinterpret_cast<u64*>(base) = EncodeRouteHeader(route_class);
            *reinterpret_cast<u64*>(base + 8) = reinterpret_cast<u64>(__builtin_return_address(0));
            // Same trailing red zone as the classic path, immediately
            // after the class payload; KFree's routed leg verifies it.
            WriteHeapTrailerCanary(base + kSlabRouteHeaderBytes + kSlabRouteClassBytes[route_class]);
            ++g_routed_alloc_count;
            return base + kSlabRouteHeaderBytes;
        }
        // Route cache couldn't grow (backing KMalloc OOM) — fall
        // through to the classic first-fit path rather than failing
        // a request the freelist might still satisfy.
    }

    sync::SpinLockRecursiveGuard g_lock(g_kheap_lock);
    if (bytes == 0 || g_freelist == nullptr)
    {
        return nullptr;
    }
    // Reject obviously-insane sizes BEFORE the RoundUp + add below.
    // Without this gate, `bytes` near u64-max would wrap `needed` to
    // a tiny value and the chunk-fit loop would happily satisfy the
    // request from a small free chunk — the caller then writes off
    // the end. `g_pool_bytes` is the actual ceiling (nothing larger
    // than the pool itself can ever fit), so use that.
    if (bytes >= g_pool_bytes)
    {
        return nullptr;
    }
    // IRQ-disable for the duration of the alloc — bracketing the
    // freelist + bins mutation matches the rest of the allocator
    // family (frame allocator, slab). See KheapIrqOff above.
    KheapIrqOff irq_guard;

    // Round payload up to alignment so a future split also produces an
    // aligned chunk. Header is already aligned by construction. Add a
    // trailing red zone so KFree can detect linear overruns past the
    // user payload — see mm/poison.h.
    const u64 payload = RoundUp(bytes, kHeapAlignment);
    const u64 needed = sizeof(ChunkHeader) + payload + kHeapTrailerCanaryBytes;

    // ---- Size-class bin fast path ---------------------------------
    // If the requested chunk size lands in a size class AND the bin
    // for that class has a parked chunk, pop it without walking the
    // address-ordered freelist. The parked chunk's size is exactly
    // `needed` (bins are size-exact), so no split or trailing-fit
    // logic runs here — just retag, restamp the canary, and return.
    {
        const u32 bin = BinIndexForChunkSize(needed);
        if (bin != kInvalidBin && g_bins[bin] != nullptr)
        {
            ChunkHeader* hot = g_bins[bin];
            AssertMagic(hot, kHeapMagicFree, "KMalloc: bin head not Free");
            DEBUG_ASSERT(hot->size == needed, "mm/kheap", "bin entry size mismatch");
            g_bins[bin] = hot->next;
            --g_bin_count[bin];
            hot->magic = kHeapMagicLive;
            hot->next = nullptr;
            hot->caller_rip = reinterpret_cast<u64>(__builtin_return_address(0));
            ++g_alloc_count;
            ++g_bin_alloc_hits;
            u8* canary_at = reinterpret_cast<u8*>(hot) + hot->size - kHeapTrailerCanaryBytes;
            WriteHeapTrailerCanary(canary_at);
            return reinterpret_cast<void*>(reinterpret_cast<u8*>(hot) + sizeof(ChunkHeader));
        }
    }

    ChunkHeader* prev = nullptr;
    ChunkHeader* cursor = g_freelist;
    while (cursor != nullptr)
    {
        // Every chunk on the freelist MUST have the Free magic. A Live
        // magic here means a double-free somewhere stitched an allocated
        // chunk into the freelist; random bytes mean heap header got
        // overwritten by an OOB write. Either way: heap integrity is
        // gone — halt loud, don't silently heal.
        AssertMagic(cursor, kHeapMagicFree, "KMalloc: corrupt magic on freelist chunk");
        if (cursor->next != nullptr)
        {
            util::PrefetchReadOnce(cursor->next);
        }

        if (cursor->size >= needed)
        {
            // Split if the remainder can hold another minimum-sized chunk
            // (header + one alignment unit of payload). Otherwise hand out
            // the whole chunk and tolerate the small internal fragmentation.
            constexpr u64 kMinSplit = sizeof(ChunkHeader) + kHeapAlignment;
            const u64 remainder = cursor->size - needed;
            if (remainder >= kMinSplit)
            {
                auto* split = reinterpret_cast<ChunkHeader*>(reinterpret_cast<u8*>(cursor) + needed);
                util::PrefetchWriteKeep(split);
                split->size = remainder;
                split->magic = kHeapMagicFree;
                split->next = cursor->next;
                split->caller_rip = 0;
                cursor->size = needed;
                if (prev == nullptr)
                {
                    g_freelist = split;
                }
                else
                {
                    prev->next = split;
                }
            }
            else
            {
                if (prev == nullptr)
                {
                    g_freelist = cursor->next;
                }
                else
                {
                    prev->next = cursor->next;
                }
            }

            cursor->magic = kHeapMagicLive;
            cursor->next = nullptr; // not on freelist anymore
            // Caller-RIP tagging (plan D6). `__builtin_return_address(0)`
            // captures the address inside KMalloc's caller right after
            // its `call kheap+offset`. KMalloc is not inlined (external
            // linkage in a .cpp), so this attribution is stable. The
            // shell `heap leaks` command aggregates by this RIP.
            cursor->caller_rip = reinterpret_cast<u64>(__builtin_return_address(0));
            ++g_alloc_count;
            // Stamp the trailing red zone. Sits at chunk_end -
            // kHeapTrailerCanaryBytes — i.e. immediately after the
            // user-visible payload. Any linear overrun by even one
            // word lands here and is detected on KFree.
            u8* canary_at = reinterpret_cast<u8*>(cursor) + cursor->size - kHeapTrailerCanaryBytes;
            WriteHeapTrailerCanary(canary_at);
            return reinterpret_cast<void*>(reinterpret_cast<u8*>(cursor) + sizeof(ChunkHeader));
        }
        prev = cursor;
        cursor = cursor->next;
    }

    // Pool exhausted. Once-per-boot to avoid log floods under sustained
    // memory pressure; the caller's nullptr return is the actionable
    // signal. Subsequent OOMs are silent at this layer.
    KLOG_ONCE_WARN("mm/kheap", "pool exhausted (KMalloc returned null)");
    KLOG_CRITICAL_AV(::duetos::core::LogArea::Memory, "mm/kheap", "KMalloc OOM — pool exhausted, request size", bytes);
    KBP_PROBE_V(::duetos::debug::ProbeId::kHeapAllocFail, bytes);
    // Journal the OOM: KMalloc returning null is a "the workaround
    // (caller's nullptr-handling) is now load-bearing" event from
    // the fix-journal's perspective. Pin = "mm/kheap" so dedup
    // groups every OOM under one record (the journal shouldn't blow
    // up under sustained pressure); ctx_a = request size; ctx_b =
    // total free bytes at fail time so the off-line tooling can see
    // whether the request was just outsized vs. pool was actually
    // exhausted.
    // Capture the UPSTREAM caller (the `auto* p = KMalloc(...)` site)
    // rather than the address inside this function — that's the line
    // the offline patch generator wants to insert a nullcheck after.
    // __builtin_return_address(0) from inside this OOM path yields
    // the return address into the immediate caller of KMalloc.
    const auto upstream = reinterpret_cast<u64>(__builtin_return_address(0));
    (void)::duetos::diag::FixJournalRecordAtCaller(
        ::duetos::diag::FixDetector::SoftFaultRecov, "mm/kheap",
        "kheap OOM: KMalloc returned null; investigate caller's null-handling and pool sizing", bytes,
        KernelHeapStatsRead().free_bytes, /*severity=*/2, upstream);
    return nullptr;
}

void KFree(void* ptr)
{
    if (ptr == nullptr)
    {
        return;
    }

    // ---- Small-allocation slab route discriminator ------------------
    // Read the u64 at ptr-16: 0 = live classic chunk (ChunkHeader::next,
    // unconditionally nulled by KMalloc — see the static_assert at
    // ChunkHeader), route magic = routed object, freed tag = routed
    // double free, anything else = let the classic magic checks panic.
    // Runs BEFORE g_kheap_lock for the same route-cache -> kheap lock-
    // order reason as KMalloc's hook (SlabFree may take the route
    // spinlock). Gated on InsidePool so a wild pointer is still never
    // dereferenced — every routed object is inside the pool because
    // slabs are KMalloc-backed. Detection of a RACING double free
    // (two CPUs freeing the same pointer simultaneously) is best-
    // effort; the sequential free-free case — the common bug shape —
    // is what the freed tag catches.
    if (g_route_enabled && InsidePool(ptr))
    {
        u8* route_base = static_cast<u8*>(ptr) - kSlabRouteHeaderBytes;
        const u64 route_word = *reinterpret_cast<const u64*>(route_base);
        switch (RouteWordClassify(route_word))
        {
        case RouteWord::RoutedLive:
        {
            const u32 route_class = DecodeRouteClass(route_word);
            SlabCache* cache = (route_class < kSlabRouteClassCount) ? g_route_caches[route_class] : nullptr;
            if (cache == nullptr)
            {
                PanicHeap("kmalloc-route: routed pointer but no cache for its class");
            }
            // Trailing red zone, mirroring the classic path's check.
            const u8* canary_at = static_cast<const u8*>(ptr) + kSlabRouteClassBytes[route_class];
            if (!CheckHeapTrailerCanary(canary_at))
            {
                core::PanicWithValue("mm/kheap", "kmalloc-route: trailing red-zone canary corrupt (heap overflow?)",
                                     reinterpret_cast<u64>(ptr));
            }
            // Freed-tag placement (read slab.cpp before touching this):
            // SlabFree poisons obj[8, obj_size) with 0xCC and — on the
            // global-freelist leg — writes the freelist link over
            // obj[0..8). So the ONLY slot that can carry the freed tag
            // is obj[0..8), and it survives exactly while the object
            // sits in a per-CPU magazine (the magazine stores the
            // pointer elsewhere and leaves obj[0..8) alone) — which is
            // where a just-freed object lands, i.e. precisely the
            // free();free() window. Once the object migrates to the
            // global freelist the tag is overwritten by the link and a
            // second KFree classifies as Garbage -> falls through to
            // the classic path -> panics on the Live-magic check. Both
            // halves of the double-free window therefore panic; only
            // the message differs.
            *reinterpret_cast<u64*>(route_base) = kSlabRouteMagicFreed;
            SlabFree(cache, route_base);
            ++g_routed_free_count;
            return;
        }
        case RouteWord::RoutedFreed:
            core::PanicWithValue("mm/kheap", "kmalloc-route double free", reinterpret_cast<u64>(ptr));
        case RouteWord::Kheap:
        case RouteWord::Garbage:
            break; // classic path below owns the verdict
        }
    }

    sync::SpinLockRecursiveGuard g_lock(g_kheap_lock);
    // IRQ-disable for the duration of the free — same rationale
    // as KMalloc's bracket. The pool-bounds check below doesn't
    // need locking but the freelist/bin-push paths do.
    KheapIrqOff irq_guard;
    if (!InsidePool(ptr))
    {
        // Caller-side bug — `ptr` was not handed out by KMalloc.
        // Debug: panic. Release: log and refuse the free. The
        // pointer might be from an unrelated arena (frame
        // allocator, MMIO mapping); freeing it would reach into
        // memory the heap doesn't own.
        core::DebugPanicOrWarn("mm/kheap", "KFree pointer outside heap pool");
        return;
    }

    auto* chunk = reinterpret_cast<ChunkHeader*>(static_cast<u8*>(ptr) - sizeof(ChunkHeader));
    // Documentation-of-invariant: KMalloc lays out every chunk so
    // that the user pointer sits exactly sizeof(ChunkHeader) past
    // the header. The arithmetic above is the inverse; if `ptr`
    // came from KMalloc, `chunk` is now well-formed and the magic
    // check below should succeed.
    DEBUG_ASSERT(reinterpret_cast<u64>(chunk) % alignof(ChunkHeader) == 0, "mm/kheap",
                 "KFree: derived chunk header pointer is misaligned");

    // Magic check first: catches double-free (previous KFree flipped
    // magic to Free; second KFree sees wrong magic and panics instead
    // of re-inserting a free chunk into the freelist, which would
    // eventually hand the same memory out twice) and catches
    // foreign-KFree on a pointer that isn't from KMalloc.
    AssertMagic(chunk, kHeapMagicLive, "KFree on chunk without Live magic (double-free / corruption?)");

    // Sanity-check the header. A size below one chunk's worth or above the
    // pool means the magic check passed by coincidence but the rest of
    // the header is corrupt — safer to halt than proceed with a bogus
    // size and walk past the end of the pool on coalesce.
    if (chunk->size < sizeof(ChunkHeader) + kHeapAlignment + kHeapTrailerCanaryBytes || chunk->size > g_pool_bytes)
    {
        PanicHeap("KFree on chunk with corrupt size (magic OK, size wild?)");
    }

    // Trailing red zone — catches linear overruns past the user
    // payload. Verify before flipping magic so the panic banner
    // points at a Live chunk (the corruption is the caller's, not
    // a freelist surprise).
    const u8* canary_at = reinterpret_cast<const u8*>(chunk) + chunk->size - kHeapTrailerCanaryBytes;
    if (!CheckHeapTrailerCanary(canary_at))
    {
        PanicHeapCorrupt("KFree: trailing red-zone canary corrupt (heap overflow?)", chunk);
    }

    // Flip to Free BEFORE poisoning so that if poison races with another
    // thread reading the magic (future SMP concern), the transition is
    // observable in sensible order.
    chunk->magic = kHeapMagicFree;
    PoisonPayload(chunk);

    // ---- Size-class bin fast path ---------------------------------
    // If this chunk fits a size class AND that class's bin has room,
    // park it there instead of running the freelist insert + double
    // coalesce walk. The next KMalloc of the same size pops it
    // straight back out without any freelist work.
    {
        const u32 bin = BinIndexForChunkSize(chunk->size);
        if (bin != kInvalidBin && g_bin_count[bin] < kBinDepth)
        {
            chunk->next = g_bins[bin];
            chunk->caller_rip = 0;
            g_bins[bin] = chunk;
            ++g_bin_count[bin];
            ++g_free_count;
            ++g_bin_free_hits;
            return;
        }
    }

    FreelistInsertAndCoalesce(chunk);
    ++g_free_count;
}

KernelHeapStats KernelHeapStatsRead()
{
    sync::SpinLockRecursiveGuard g_lock(g_kheap_lock);
    KernelHeapStats stats{};
    stats.pool_bytes = g_pool_bytes;
    stats.alloc_count = g_alloc_count;
    stats.free_count = g_free_count;
    stats.bin_alloc_hits = g_bin_alloc_hits;
    stats.bin_free_hits = g_bin_free_hits;

    for (const ChunkHeader* c = g_freelist; c != nullptr; c = c->next)
    {
        if (c->next != nullptr)
        {
            util::PrefetchReadOnce(c->next);
        }
        stats.free_bytes += c->size;
        ++stats.free_chunk_count;
        if (c->size > stats.largest_free_run)
        {
            stats.largest_free_run = c->size;
        }
    }
    // Bins also hold free chunks. Account their bytes against the
    // pool so used_bytes correctly identifies live allocations and
    // doesn't drift as the bin populations shift.
    for (u32 b = 0; b < kBinCount; ++b)
    {
        for (const ChunkHeader* c = g_bins[b]; c != nullptr; c = c->next)
        {
            stats.free_bytes += c->size;
            ++stats.binned_chunk_count;
        }
    }
    stats.used_bytes = stats.pool_bytes - stats.free_bytes;

    // Routed-layer breakdown. The slab BLOCKS are KMalloc-backed, so
    // these bytes already sit inside used_bytes — used_bytes semantics
    // are unchanged; the routed gauges let an operator tell "heap used
    // by big allocations" from "heap parked in route caches".
    stats.routed_alloc_count = g_routed_alloc_count;
    stats.routed_free_count = g_routed_free_count;
    if (g_route_enabled)
    {
        for (u32 i = 0; i < kSlabRouteClassCount; ++i)
        {
            const SlabStats s = SlabCacheStatsRead(g_route_caches[i]);
            stats.routed_live_bytes += s.obj_in_use * s.obj_size;
            stats.routed_cached_free_bytes += s.obj_free * s.obj_size;
        }
    }
    return stats;
}

void KMallocSlabRoutingInit()
{
    KASSERT(!g_route_enabled, "mm/kheap", "double KMallocSlabRoutingInit");

    // Names are borrowed by the caches for diagnostics; static
    // literals outlive everything. Indices mirror kSlabRouteClassBytes.
    static const char* const kRouteCacheNames[kSlabRouteClassCount] = {"kmalloc-32",  "kmalloc-64",  "kmalloc-96",
                                                                       "kmalloc-128", "kmalloc-192", "kmalloc-256",
                                                                       "kmalloc-384", "kmalloc-512"};

    for (u32 i = 0; i < kSlabRouteClassCount; ++i)
    {
        // IRQ-safe mode: KMalloc/KFree are IRQ-safe today and routing
        // must not downgrade that — the route caches' slow path spins
        // irqsave instead of sleeping on the scheduler mutex.
        g_route_caches[i] = SlabCacheCreateIrqSafe(kRouteCacheNames[i], static_cast<u32>(RouteCacheObjBytes(i)),
                                                   static_cast<u32>(kHeapAlignment));
        if (g_route_caches[i] == nullptr)
        {
            PanicHeap("KMallocSlabRoutingInit: route cache create failed");
        }
    }

    // Flip LAST: a true g_route_enabled promises every cache pointer
    // above is valid (KMalloc/KFree index the array unconditionally).
    g_route_enabled = true;
    KLOG_INFO("mm/kheap", "kmalloc slab routing online (8 classes, <=512B)");
}

void KMallocRouteDrain()
{
    if (!g_route_enabled)
    {
        return;
    }
    for (u32 i = 0; i < kSlabRouteClassCount; ++i)
    {
        SlabCacheDrainLocalMagazine(g_route_caches[i]);
    }
}

void KernelHeapDrainBins()
{
    // Drain the route caches' local magazines first, and BEFORE the
    // kheap lock (route-cache -> kheap order, same as the alloc path).
    // Existing memory-pressure call sites (env/autonomic MemReclaim)
    // thereby reclaim both layers with their one existing call.
    KMallocRouteDrain();

    sync::SpinLockRecursiveGuard g_lock(g_kheap_lock);
    for (u32 b = 0; b < kBinCount; ++b)
    {
        ChunkHeader* head = g_bins[b];
        g_bins[b] = nullptr;
        g_bin_count[b] = 0;
        while (head != nullptr)
        {
            ChunkHeader* next = head->next;
            // Magic is already Free; size is exact for the bin. Push
            // back into the address-ordered freelist so coalescing
            // restores the pool to one big chunk if the rest is empty.
            FreelistInsertAndCoalesce(head);
            head = next;
        }
    }
}

u32 KernelHeapTopAllocators(HeapLeakEntry* out, u32 out_capacity)
{
    sync::SpinLockRecursiveGuard g_lock(g_kheap_lock);
    if (out == nullptr || out_capacity == 0 || g_pool_base == nullptr)
    {
        return 0;
    }
    for (u32 i = 0; i < out_capacity; ++i)
    {
        out[i] = HeapLeakEntry{};
    }
    u32 distinct = 0;

    // Walk every chunk in the pool (live + free), aggregating live
    // chunks by their `caller_rip`. The aggregation table is the
    // caller's `out` buffer, used as a fixed-size hash bucket: linear
    // search per chunk, capped at `out_capacity`. Worst case is
    // O(N_chunks * out_capacity), which is fine for the boot-era
    // chunk counts we see today.
    const u8* pool_end = g_pool_base + g_pool_bytes;
    const ChunkHeader* c = reinterpret_cast<const ChunkHeader*>(g_pool_base);
    while (reinterpret_cast<const u8*>(c) < pool_end)
    {
        if (c->magic != kHeapMagicLive && c->magic != kHeapMagicFree)
        {
            // Corrupt magic — bail rather than walking off the end.
            // The runtime checker is the canonical detector for this;
            // the leak tracker shouldn't double-panic.
            break;
        }
        if (c->size == 0 || c->size > g_pool_bytes)
        {
            break;
        }
        const auto* next = reinterpret_cast<const ChunkHeader*>(reinterpret_cast<const u8*>(c) + c->size);
        if (reinterpret_cast<const u8*>(next) < pool_end)
        {
            util::PrefetchReadOnce(next);
        }
        if (c->magic == kHeapMagicLive)
        {
            const u64 rip = c->caller_rip;
            // Find existing entry for this RIP, or take the first
            // empty slot.
            i32 hit = -1;
            i32 first_empty = -1;
            for (u32 i = 0; i < out_capacity; ++i)
            {
                if (out[i].count != 0 && out[i].caller_rip == rip)
                {
                    hit = static_cast<i32>(i);
                    break;
                }
                if (out[i].count == 0 && first_empty < 0)
                {
                    first_empty = static_cast<i32>(i);
                }
            }
            if (hit >= 0)
            {
                out[hit].bytes += c->size;
                ++out[hit].count;
            }
            else if (first_empty >= 0)
            {
                out[first_empty].caller_rip = rip;
                out[first_empty].bytes = c->size;
                out[first_empty].count = 1;
                ++distinct;
            }
            // No room for a new RIP and not a match — silently drop.
            // Leak ranking is best-effort; missing the long tail is
            // fine, missing the head is what we'd worry about, and
            // a head-of-distribution RIP would land in the table on
            // its first allocation.
        }
        c = reinterpret_cast<const ChunkHeader*>(reinterpret_cast<const u8*>(c) + c->size);
    }

    // Selection-sort: small N (out_capacity == 32 in the shell) means
    // O(N²) is irrelevant compared to the O(N_chunks * N) walk above.
    for (u32 i = 0; i < distinct; ++i)
    {
        u32 best = i;
        for (u32 j = i + 1; j < distinct; ++j)
        {
            if (out[j].bytes > out[best].bytes)
            {
                best = j;
            }
        }
        if (best != i)
        {
            HeapLeakEntry tmp = out[i];
            out[i] = out[best];
            out[best] = tmp;
        }
    }
    return distinct;
}

void KernelHeapSelfTest()
{
    sync::SpinLockRecursiveGuard g_lock(g_kheap_lock);
    KLOG_TRACE_SCOPE("mm/kheap", "KernelHeapSelfTest");
    SerialWrite("[mm] kernel heap self-test\n");

    const KernelHeapStats baseline = KernelHeapStatsRead();
    if (baseline.free_bytes != baseline.pool_bytes || baseline.free_chunk_count != 1)
    {
        PanicHeap("self-test: heap not pristine at start");
    }

    // Three small allocations should come out distinct, in increasing
    // address order, each 16-byte aligned.
    void* a = KMalloc(32);
    void* b = KMalloc(64);
    void* c = KMalloc(128);
    if (a == nullptr || b == nullptr || c == nullptr)
    {
        PanicHeap("self-test: small allocation returned null");
    }
    if (a == b || b == c || a == c)
    {
        PanicHeap("self-test: KMalloc handed out duplicate pointers");
    }
    if ((reinterpret_cast<uptr>(a) & (kHeapAlignment - 1)) != 0)
    {
        PanicHeap("self-test: returned pointer not aligned");
    }
    if (a >= b || b >= c)
    {
        PanicHeap("self-test: allocations not address-ordered");
    }

    SerialWrite("  alloc 32   : ");
    SerialWriteHex(reinterpret_cast<u64>(a));
    SerialWrite("\n");
    SerialWrite("  alloc 64   : ");
    SerialWriteHex(reinterpret_cast<u64>(b));
    SerialWrite("\n");
    SerialWrite("  alloc 128  : ");
    SerialWriteHex(reinterpret_cast<u64>(c));
    SerialWrite("\n");

    // Touch every byte of each payload end-to-end. If the header overlapped
    // the payload, this would scribble the freelist link and the next
    // KMalloc would walk off into garbage.
    auto fill = [](void* ptr, u64 bytes, u8 pattern)
    {
        u8* p = static_cast<u8*>(ptr);
        for (u64 i = 0; i < bytes; ++i)
        {
            p[i] = pattern;
        }
    };
    fill(a, 32, 0xAA);
    fill(b, 64, 0xBB);
    fill(c, 128, 0xCC);

    // Free the middle chunk. Coalescing isn't expected here — `b`'s
    // neighbours are still allocated.
    KFree(b);
    const KernelHeapStats mid = KernelHeapStatsRead();
    if (mid.alloc_count != baseline.alloc_count + 3 || mid.free_count != baseline.free_count + 1)
    {
        PanicHeap("self-test: alloc/free counters drifted");
    }

    // Free the others; the freelist should coalesce back into a single
    // chunk equal to the original pool.
    KFree(a);
    KFree(c);

    const KernelHeapStats merged = KernelHeapStatsRead();
    if (merged.free_bytes != baseline.pool_bytes || merged.free_chunk_count != 1)
    {
        SerialWrite("  free_bytes      : ");
        SerialWriteHex(merged.free_bytes);
        SerialWrite("\n");
        SerialWrite("  free_chunk_count: ");
        SerialWriteHex(merged.free_chunk_count);
        SerialWrite("\n");
        PanicHeap("self-test: freelist did not coalesce back to one chunk");
    }
    SerialWrite("  coalesced  : free=");
    SerialWriteHex(merged.free_bytes);
    SerialWrite(" chunks=");
    SerialWriteHex(merged.free_chunk_count);
    SerialWrite("\n");

    // A large allocation should land in the now-merged region.
    void* big = KMalloc(8192);
    if (big == nullptr)
    {
        PanicHeap("self-test: large allocation failed after coalesce");
    }
    SerialWrite("  alloc 8192 : ");
    SerialWriteHex(reinterpret_cast<u64>(big));
    SerialWrite("\n");
    KFree(big);

    // Poison verification: allocate, write a pattern, free. The payload
    // is now back on the freelist as poisoned bytes. Re-allocate the
    // SAME size; since the freelist just coalesced into one chunk, the
    // new allocation lands at the same address. Its bytes must be
    // kHeapFreePoison — any stale pattern means poison-on-free
    // regressed and use-after-free would no longer be obvious.
    void* poison_probe = KMalloc(128);
    if (poison_probe == nullptr)
    {
        PanicHeap("self-test: poison-probe alloc failed");
    }
    auto* poison_bytes = static_cast<u8*>(poison_probe);
    for (u64 i = 0; i < 128; ++i)
    {
        poison_bytes[i] = 0xAA;
    }
    KFree(poison_probe);
    void* poison_probe2 = KMalloc(128);
    if (poison_probe2 != poison_probe)
    {
        PanicHeap("self-test: expected to re-use same chunk for poison probe");
    }
    const auto* reread = static_cast<const u8*>(poison_probe2);
    for (u64 i = 0; i < 128; ++i)
    {
        if (reread[i] != kHeapFreePoison)
        {
            PanicHeap("self-test: poison-on-free did not mark freed payload");
        }
    }
    KFree(poison_probe2);

    const KernelHeapStats final_stats = KernelHeapStatsRead();
    if (final_stats.free_bytes != baseline.pool_bytes || final_stats.free_chunk_count != 1)
    {
        PanicHeap("self-test: heap not pristine at end");
    }

    SerialWrite("  poison     : verified 0xDE across freed payload\n");

    // Trailing red zone (plan C2). Allocate a known size, find the
    // canary at chunk_end - kHeapTrailerCanaryBytes, verify it
    // reads as the expected pattern, transiently corrupt it,
    // verify CheckHeapTrailerCanary returns false, restore, free.
    // The destructive step uses the helper directly — we don't
    // call KFree on the corrupted state because that would Panic
    // (which is the production path we WANT, but Panic halts the
    // kernel and we still have boot to finish).
    void* canary_probe = KMalloc(64);
    if (canary_probe == nullptr)
    {
        PanicHeap("self-test: canary-probe alloc failed");
    }
    auto* canary_chunk = reinterpret_cast<u8*>(canary_probe) - sizeof(ChunkHeader);
    auto* canary_chunk_hdr = reinterpret_cast<ChunkHeader*>(canary_chunk);
    u8* canary_at = canary_chunk + canary_chunk_hdr->size - kHeapTrailerCanaryBytes;
    if (!CheckHeapTrailerCanary(canary_at))
    {
        PanicHeap("self-test: fresh allocation has wrong trailer canary");
    }
    const u8 saved_byte = canary_at[0];
    canary_at[0] = 0xFF; // Simulate one-byte overrun.
    if (CheckHeapTrailerCanary(canary_at))
    {
        PanicHeap("self-test: corrupted canary not detected");
    }
    canary_at[0] = saved_byte;
    if (!CheckHeapTrailerCanary(canary_at))
    {
        PanicHeap("self-test: restored canary mis-detected");
    }
    KFree(canary_probe);
    SerialWrite("  red-zone   : trailer canary verified + tamper detection OK\n");

    SerialWrite("[mm] kernel heap self-test OK\n");
}

void KMallocRouteSelfTest()
{
    KLOG_TRACE_SCOPE("mm/kheap", "KMallocRouteSelfTest");
    if (!g_route_enabled)
    {
        PanicHeap("route-selftest: routing not enabled (init ordering broken?)");
    }

    // Counter / in-use baselines. Delta-based: routing has been live
    // since the previous initcall, so other early allocations may
    // already sit in the caches — assert OUR round-trips, not absolute
    // zeros. This initcall runs on the boot task with nothing else
    // doing small KMallocs concurrently at this phase; if that ever
    // changes, these equality checks are the canary.
    const u64 routed_allocs_before = g_routed_alloc_count;
    const u64 routed_frees_before = g_routed_free_count;
    u64 in_use_before = 0;
    for (u32 i = 0; i < kSlabRouteClassCount; ++i)
    {
        in_use_before += SlabCacheStatsRead(g_route_caches[i]).obj_in_use;
    }

    for (u32 i = 0; i < kSlabRouteClassCount; ++i)
    {
        const u64 payload = kSlabRouteClassBytes[i];

        // (1) Route + header shape: non-null, 16-aligned, route magic
        // carrying this exact class at ptr-16.
        void* p = KMalloc(payload);
        if (p == nullptr)
        {
            PanicHeap("route-selftest: routed alloc returned null");
        }
        if ((reinterpret_cast<uptr>(p) & (kHeapAlignment - 1)) != 0)
        {
            PanicHeap("route-selftest: routed pointer not aligned");
        }
        const u64 live_word = *reinterpret_cast<const u64*>(static_cast<u8*>(p) - kSlabRouteHeaderBytes);
        if (DecodeRouteClass(live_word) != i)
        {
            core::PanicWithValue("mm/kheap", "route-selftest: wrong route header class", live_word);
        }

        // (2) Free + realloc of the same size: LIFO reuse through the
        // per-CPU magazine must return the exact pointer, and the slab
        // freed-object poison (0xCC) must be visible across the whole
        // payload band before we write anything — proving the object
        // really took the SlabFree poison trip in between.
        KFree(p);
        void* p2 = KMalloc(payload);
        if (p2 != p)
        {
            PanicHeap("route-selftest: LIFO reuse broken (different pointer)");
        }
        const auto* poison_band = static_cast<const u8*>(p2);
        for (u64 b = 0; b < payload; ++b)
        {
            if (poison_band[b] != kSlabFreedObjectPoison)
            {
                PanicHeap("route-selftest: freed-object poison missing on reuse");
            }
        }
        KFree(p2);
    }

    // (3) Routing boundary: 512 routes (class 7), 513 takes the
    // classic path (discriminator word at ptr-16 is ChunkHeader::next
    // == nullptr on a live classic chunk).
    void* at_max = KMalloc(kSlabRouteMaxBytes);
    void* over_max = KMalloc(kSlabRouteMaxBytes + 1);
    if (at_max == nullptr || over_max == nullptr)
    {
        PanicHeap("route-selftest: boundary alloc returned null");
    }
    const u64 at_max_word = *reinterpret_cast<const u64*>(static_cast<u8*>(at_max) - kSlabRouteHeaderBytes);
    if (DecodeRouteClass(at_max_word) != kSlabRouteClassCount - 1)
    {
        PanicHeap("route-selftest: 512B alloc did not route to the last class");
    }
    const u64 over_max_word = *reinterpret_cast<const u64*>(static_cast<u8*>(over_max) - kSlabRouteHeaderBytes);
    if (over_max_word != 0)
    {
        core::PanicWithValue("mm/kheap", "route-selftest: 513B alloc has non-zero discriminator", over_max_word);
    }
    KFree(at_max);
    KFree(over_max);

    // (4) Counter round-trips: 8 classes x 2 allocs + the 512B probe
    // = 17 routed allocs, all freed; per-cache in_use back at the
    // baseline (the freed objects are parked free in magazines).
    constexpr u64 kExpectedRoutedOps = 2 * kSlabRouteClassCount + 1;
    if (g_routed_alloc_count != routed_allocs_before + kExpectedRoutedOps)
    {
        PanicHeap("route-selftest: routed alloc counter did not move as expected");
    }
    if (g_routed_free_count != routed_frees_before + kExpectedRoutedOps)
    {
        PanicHeap("route-selftest: routed free counter did not move as expected");
    }
    u64 in_use_after = 0;
    for (u32 i = 0; i < kSlabRouteClassCount; ++i)
    {
        in_use_after += SlabCacheStatsRead(g_route_caches[i]).obj_in_use;
    }
    if (in_use_after != in_use_before)
    {
        core::PanicWithValue("mm/kheap", "route-selftest: routed obj_in_use did not round-trip", in_use_after);
    }

    // (5) Trailer-canary tamper detection, mirroring the kheap
    // self-test's red-zone leg: corrupt one byte, detect via the
    // check helper (NOT via KFree, which would panic the boot),
    // restore, then free cleanly.
    void* tamper_probe = KMalloc(64);
    if (tamper_probe == nullptr)
    {
        PanicHeap("route-selftest: tamper-probe alloc failed");
    }
    u8* tamper_canary = static_cast<u8*>(tamper_probe) + 64;
    if (!CheckHeapTrailerCanary(tamper_canary))
    {
        PanicHeap("route-selftest: fresh routed allocation has wrong trailer canary");
    }
    const u8 saved = tamper_canary[0];
    tamper_canary[0] = 0xFF; // Simulate one-byte overrun.
    if (CheckHeapTrailerCanary(tamper_canary))
    {
        PanicHeap("route-selftest: corrupted routed canary not detected");
    }
    tamper_canary[0] = saved;
    if (!CheckHeapTrailerCanary(tamper_canary))
    {
        PanicHeap("route-selftest: restored routed canary mis-detected");
    }
    KFree(tamper_probe);

    SerialWrite("[kmalloc-route-selftest] PASS (8 classes, route+fallback)\n");
}

} // namespace duetos::mm
