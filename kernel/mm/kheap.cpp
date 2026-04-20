#include "kheap.h"

#include "frame_allocator.h"
#include "page.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/panic.h"

namespace customos::mm
{

namespace
{

using arch::Halt;
using arch::SerialWrite;
using arch::SerialWriteHex;

// Header sits at the start of every chunk, allocated or free. 16 bytes wide
// to keep returned payload pointers 16-byte aligned without any padding.
//
// The `next` field is meaningful only while the chunk is on the freelist;
// for an allocated chunk it overlaps the first 8 bytes of the user payload,
// which is fine — the user owns those bytes once we hand them out.
struct alignas(kHeapAlignment) ChunkHeader
{
    u64 size;          // total chunk size in bytes (header + payload)
    ChunkHeader* next; // address-ordered freelist link (free chunks only)
};

static_assert(sizeof(ChunkHeader) == kHeapAlignment, "Header size must equal payload alignment to avoid padding");

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

    // Coalesce forward (chunk + next).
    if (chunk->next != nullptr && ChunkAdjacent(chunk, chunk->next))
    {
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
    g_freelist->next = nullptr;
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
                split->next = cursor->next;
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

            cursor->next = nullptr; // not on freelist anymore
            ++g_alloc_count;
            return reinterpret_cast<void*>(reinterpret_cast<u8*>(cursor) + sizeof(ChunkHeader));
        }
        prev = cursor;
        cursor = cursor->next;
    }

    return nullptr; // pool exhausted
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

    // Sanity-check the header. A size below one chunk's worth or above the
    // pool is a double-free or corruption. Cheap to detect; expensive to
    // debug if we don't.
    if (chunk->size < sizeof(ChunkHeader) + kHeapAlignment || chunk->size > g_pool_bytes)
    {
        PanicHeap("KFree on chunk with corrupt size (double-free?)");
    }

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

    const KernelHeapStats final_stats = KernelHeapStatsRead();
    if (final_stats.free_bytes != baseline.pool_bytes || final_stats.free_chunk_count != 1)
    {
        PanicHeap("self-test: heap not pristine at end");
    }

    SerialWrite("[mm] kernel heap self-test OK\n");
}

} // namespace customos::mm
