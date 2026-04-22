#include "kheap.h"

#include "frame_allocator.h"
#include "page.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"

namespace customos::mm
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
    u64 reserved;      // padding to 32 bytes; zero when allocated
};

static_assert(sizeof(ChunkHeader) == 32, "Header must be 32 bytes");
static_assert(sizeof(ChunkHeader) % kHeapAlignment == 0, "Header must preserve payload alignment");

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
constinit u64 g_alloc_count = 0;
constinit u64 g_free_count = 0;

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
void FreelistInsertAndCoalesce(ChunkHeader* chunk)
{
    chunk->next = nullptr;

    if (g_freelist == nullptr)
    {
        g_freelist = chunk;
        return;
    }

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
            cursor = cursor->next;
        }
        chunk->next = cursor->next;
        cursor->next = chunk;
    }

    // Coalesce forward (chunk + next). Verify magic before folding —
    // if the "free" successor got its magic clobbered we'd silently
    // absorb corrupt bytes into `chunk`'s size.
    if (chunk->next != nullptr && ChunkAdjacent(chunk, chunk->next))
    {
        AssertMagic(chunk->next, kHeapMagicFree, "Coalesce: forward neighbour not Free");
        chunk->size += chunk->next->size;
        chunk->next = chunk->next->next;
    }

    // Coalesce backward (prev + chunk). Need a second walk to find prev,
    // since the freelist is singly-linked. v0: pay the O(n) cost.
    if (chunk != g_freelist)
    {
        ChunkHeader* prev = g_freelist;
        while (prev->next != chunk)
        {
            prev = prev->next;
        }
        if (ChunkAdjacent(prev, chunk))
        {
            AssertMagic(prev, kHeapMagicFree, "Coalesce: backward neighbour not Free");
            prev->size += chunk->size;
            prev->next = chunk->next;
        }
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

    const PhysAddr base_phys = AllocateContiguousFrames(kFrames);
    if (base_phys == kNullFrame)
    {
        PanicHeap("could not allocate contiguous frames for the heap pool");
    }

    g_pool_base = static_cast<u8*>(PhysToVirt(base_phys));
    g_pool_bytes = kKernelHeapBytes;
    g_freelist = reinterpret_cast<ChunkHeader*>(g_pool_base);
    g_freelist->size = kKernelHeapBytes;
    g_freelist->magic = kHeapMagicFree;
    g_freelist->next = nullptr;
    g_freelist->reserved = 0;
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
    if (bytes == 0 || g_freelist == nullptr)
    {
        return nullptr;
    }

    // Round payload up to alignment so a future split also produces an
    // aligned chunk. Header is already aligned by construction.
    const u64 payload = RoundUp(bytes, kHeapAlignment);
    const u64 needed = sizeof(ChunkHeader) + payload;

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
                split->size = remainder;
                split->magic = kHeapMagicFree;
                split->next = cursor->next;
                split->reserved = 0;
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
            cursor->reserved = 0;
            ++g_alloc_count;
            return reinterpret_cast<void*>(reinterpret_cast<u8*>(cursor) + sizeof(ChunkHeader));
        }
        prev = cursor;
        cursor = cursor->next;
    }

    // Pool exhausted. Once-per-boot to avoid log floods under sustained
    // memory pressure; the caller's nullptr return is the actionable
    // signal. Subsequent OOMs are silent at this layer.
    KLOG_ONCE_WARN("mm/kheap", "pool exhausted (KMalloc returned null)");
    return nullptr;
}

void KFree(void* ptr)
{
    if (ptr == nullptr)
    {
        return;
    }
    if (!InsidePool(ptr))
    {
        PanicHeap("KFree pointer outside heap pool");
    }

    auto* chunk = reinterpret_cast<ChunkHeader*>(static_cast<u8*>(ptr) - sizeof(ChunkHeader));

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
    if (chunk->size < sizeof(ChunkHeader) + kHeapAlignment || chunk->size > g_pool_bytes)
    {
        PanicHeap("KFree on chunk with corrupt size (magic OK, size wild?)");
    }

    // Flip to Free BEFORE poisoning so that if poison races with another
    // thread reading the magic (future SMP concern), the transition is
    // observable in sensible order.
    chunk->magic = kHeapMagicFree;
    PoisonPayload(chunk);

    FreelistInsertAndCoalesce(chunk);
    ++g_free_count;
}

KernelHeapStats KernelHeapStatsRead()
{
    KernelHeapStats stats{};
    stats.pool_bytes = g_pool_bytes;
    stats.alloc_count = g_alloc_count;
    stats.free_count = g_free_count;

    for (const ChunkHeader* c = g_freelist; c != nullptr; c = c->next)
    {
        stats.free_bytes += c->size;
        ++stats.free_chunk_count;
        if (c->size > stats.largest_free_run)
        {
            stats.largest_free_run = c->size;
        }
    }
    stats.used_bytes = stats.pool_bytes - stats.free_bytes;
    return stats;
}

void KernelHeapSelfTest()
{
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
    SerialWrite("[mm] kernel heap self-test OK\n");
}

} // namespace customos::mm
