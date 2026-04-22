#include "heap.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/process.h"
#include "../../mm/address_space.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"

namespace customos::win32
{

namespace
{

// Header layout for every block, free or allocated. 16 bytes.
// Living inside user memory — the kernel reads/writes through
// PhysToVirt(frame) + page_offset when manipulating the list.
//
//   size: block size in bytes INCLUDING the header. Min size
//         is sizeof(BlockHeader) so a zero-byte allocation
//         still has a valid free-block shape on reclaim.
//   next: user VA of the next free block's header, or 0 for
//         end-of-list. Only meaningful when the block is free.
//         When allocated, this field holds garbage the user
//         can overwrite — the kernel ignores it.
struct BlockHeader
{
    u64 size;
    u64 next;
};
constexpr u64 kHeaderSize = sizeof(BlockHeader);
// Below this payload size, splitting a free block is not
// worth it — the leftover would be too small to hold a
// header. The block is handed out whole.
constexpr u64 kMinSplitPayload = 16;

// Read a u64 from `proc`'s user memory at `user_va` via the
// kernel direct map. Walks the AS's region table to find the
// backing frame. `user_va` MUST live inside one mapped page;
// the heap-management code only touches the first 16 bytes of
// each block, and headers are 16-byte-aligned, so we never
// cross a page boundary.
u64 PeekU64(const customos::core::Process* proc, u64 user_va)
{
    const u64 page_va = user_va & ~0xFFFULL;
    const customos::mm::PhysAddr frame = customos::mm::AddressSpaceLookupUserFrame(proc->as, page_va);
    if (frame == customos::mm::kNullFrame)
        return 0;
    const auto* direct = static_cast<const u8*>(customos::mm::PhysToVirt(frame));
    const u64 off = user_va - page_va;
    u64 v = 0;
    for (u64 b = 0; b < 8; ++b)
        v |= static_cast<u64>(direct[off + b]) << (b * 8);
    return v;
}

void PokeU64(customos::core::Process* proc, u64 user_va, u64 value)
{
    const u64 page_va = user_va & ~0xFFFULL;
    const customos::mm::PhysAddr frame = customos::mm::AddressSpaceLookupUserFrame(proc->as, page_va);
    if (frame == customos::mm::kNullFrame)
        return;
    auto* direct = static_cast<u8*>(customos::mm::PhysToVirt(frame));
    const u64 off = user_va - page_va;
    for (u64 b = 0; b < 8; ++b)
        direct[off + b] = static_cast<u8>((value >> (b * 8)) & 0xFF);
}

// Round request up: we always return 8-byte-aligned pointers,
// and each allocated block has a header preceding the payload.
// Minimum allocation is one header of payload so a later free
// still has room to link into the list.
u64 RoundRequestToBlockSize(u64 requested)
{
    u64 payload = requested < kHeaderSize ? kHeaderSize : requested;
    payload = (payload + 7) & ~u64(7);
    return payload + kHeaderSize;
}

} // namespace

bool Win32HeapInit(customos::core::Process* proc)
{
    KLOG_TRACE_SCOPE("win32/heap", "Win32HeapInit");
    using namespace customos::mm;
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    if (proc == nullptr || proc->as == nullptr)
        return false;

    // Map N RW+NX user pages starting at kWin32HeapVa. One
    // AddressSpaceMapUserPage call per page — there's no bulk
    // API. On any failure we leak the frames we've mapped so
    // far (they're owned by the AS now; AddressSpaceRelease
    // will clean them up when the load itself is aborted).
    for (u64 i = 0; i < kWin32HeapPages; ++i)
    {
        const PhysAddr frame = AllocateFrame();
        if (frame == kNullFrame)
            return false;
        AddressSpaceMapUserPage(proc->as, kWin32HeapVa + i * kPageSize, frame,
                                kPagePresent | kPageUser | kPageWritable | kPageNoExecute);
    }

    proc->heap_base = kWin32HeapVa;
    proc->heap_pages = kWin32HeapPages;

    // Seed: one free block covering the entire heap region.
    // Header lives at kWin32HeapVa; size = heap_bytes; next = 0.
    const u64 heap_bytes = kWin32HeapPages * kPageSize;
    PokeU64(proc, kWin32HeapVa + 0, heap_bytes); // size
    PokeU64(proc, kWin32HeapVa + 8, 0);          // next
    proc->heap_free_head = kWin32HeapVa;

    SerialWrite("[w32-heap] init pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" base=");
    SerialWriteHex(kWin32HeapVa);
    SerialWrite(" size=");
    SerialWriteHex(heap_bytes);
    SerialWrite("\n");
    return true;
}

u64 Win32HeapAlloc(customos::core::Process* proc, u64 size)
{
    if (proc == nullptr || proc->heap_free_head == 0)
        return 0;
    if (size == 0)
        size = 1; // Win32: HeapAlloc(size=0) returns a unique non-null ptr.

    const u64 needed = RoundRequestToBlockSize(size);

    // First-fit: walk the free list, find the first block
    // whose size >= needed. `prev` tracks the predecessor so
    // we can splice the chosen block out.
    u64 prev = 0;
    u64 cur = proc->heap_free_head;
    while (cur != 0)
    {
        const u64 block_size = PeekU64(proc, cur + 0);
        const u64 block_next = PeekU64(proc, cur + 8);
        if (block_size >= needed)
        {
            const u64 leftover = block_size - needed;
            if (leftover >= kHeaderSize + kMinSplitPayload)
            {
                // Split. Keep the low part as the allocated
                // block; the high part becomes a fresh free
                // block inheriting `cur`'s next pointer.
                const u64 split_va = cur + needed;
                PokeU64(proc, split_va + 0, leftover);
                PokeU64(proc, split_va + 8, block_next);
                PokeU64(proc, cur + 0, needed); // shrink the allocated block's header
                if (prev == 0)
                    proc->heap_free_head = split_va;
                else
                    PokeU64(proc, prev + 8, split_va);
            }
            else
            {
                // Take the whole block. Splice out of list.
                if (prev == 0)
                    proc->heap_free_head = block_next;
                else
                    PokeU64(proc, prev + 8, block_next);
                // Header size already equals block_size — no change.
            }
            // Payload lives immediately after the 8-byte
            // in-use header. We keep the `next` field of the
            // header as garbage (caller will overwrite it as
            // part of their data).
            return cur + kHeaderSize;
        }
        prev = cur;
        cur = block_next;
    }

    // No free block large enough. Win32 returns NULL when
    // HEAP_GENERATE_EXCEPTIONS isn't set — we never honor
    // that flag, so always NULL on OOM.
    KLOG_ONCE_WARN("win32/heap", "process heap exhausted (HeapAlloc returned NULL)");
    return 0;
}

void Win32HeapFree(customos::core::Process* proc, u64 user_ptr)
{
    if (proc == nullptr || user_ptr == 0)
        return; // Win32: free(NULL) is a no-op.
    const u64 block_hdr = user_ptr - kHeaderSize;
    // Bounds-check: block must be inside the heap region.
    if (block_hdr < proc->heap_base)
        return;
    if (block_hdr >= proc->heap_base + proc->heap_pages * customos::mm::kPageSize)
        return;
    // Prepend to the free list. O(1) insertion, no coalescing.
    // The header's `size` field is preserved from allocation;
    // we just update `next`.
    PokeU64(proc, block_hdr + 8, proc->heap_free_head);
    proc->heap_free_head = block_hdr;
}

u64 Win32HeapSize(customos::core::Process* proc, u64 user_ptr)
{
    if (proc == nullptr || user_ptr == 0)
        return 0;
    const u64 block_hdr = user_ptr - kHeaderSize;
    if (block_hdr < proc->heap_base)
        return 0;
    if (block_hdr >= proc->heap_base + proc->heap_pages * customos::mm::kPageSize)
        return 0;
    const u64 block_size = PeekU64(proc, block_hdr + 0);
    if (block_size < kHeaderSize)
        return 0;
    return block_size - kHeaderSize;
}

u64 Win32HeapRealloc(customos::core::Process* proc, u64 user_ptr, u64 new_size)
{
    if (proc == nullptr)
        return 0;
    // realloc(NULL, size) ≡ malloc(size). Matches both the
    // ucrt realloc contract and Windows HeapReAlloc's behaviour
    // when lpMem is NULL (though real Windows returns an error
    // for HeapReAlloc(NULL) — our version collapses the two
    // paths since callers can't tell the difference without a
    // working GetLastError and we don't set one here).
    if (user_ptr == 0)
        return Win32HeapAlloc(proc, new_size);
    // realloc(ptr, 0) — ucrt convention: free and return NULL.
    // Win32 HeapReAlloc with size 0 is undefined; ucrt / msvcrt
    // realloc with size 0 frees.
    if (new_size == 0)
    {
        Win32HeapFree(proc, user_ptr);
        return 0;
    }

    const u64 block_hdr = user_ptr - kHeaderSize;
    if (block_hdr < proc->heap_base)
        return 0;
    if (block_hdr >= proc->heap_base + proc->heap_pages * customos::mm::kPageSize)
        return 0;
    const u64 old_block_size = PeekU64(proc, block_hdr + 0);
    if (old_block_size < kHeaderSize)
        return 0;
    const u64 old_payload = old_block_size - kHeaderSize;

    // Fits in place — the existing block already reserved at
    // least new_size bytes during its original allocation (size
    // got rounded up to 8 by RoundRequestToBlockSize). No
    // shrink-in-place: v0 doesn't have coalescing, so splitting
    // off the tail would fragment without an offsetting benefit.
    if (new_size <= old_payload)
        return user_ptr;

    const u64 new_ptr = Win32HeapAlloc(proc, new_size);
    if (new_ptr == 0)
        return 0; // alloc failed; caller keeps old pointer.

    // Copy old payload -> new block. Walk one page-chunk at a
    // time through AddressSpaceLookupUserFrame so blocks that
    // straddle page boundaries still copy correctly (block
    // alignment is 8 bytes, not 4 KiB, so any allocation above
    // a few KiB or straddling a boundary is common).
    u64 src_va = user_ptr;
    u64 dst_va = new_ptr;
    u64 remaining = old_payload;
    while (remaining > 0)
    {
        const u64 src_page = src_va & ~0xFFFULL;
        const u64 dst_page = dst_va & ~0xFFFULL;
        const customos::mm::PhysAddr src_frame = customos::mm::AddressSpaceLookupUserFrame(proc->as, src_page);
        const customos::mm::PhysAddr dst_frame = customos::mm::AddressSpaceLookupUserFrame(proc->as, dst_page);
        if (src_frame == customos::mm::kNullFrame || dst_frame == customos::mm::kNullFrame)
        {
            // Shouldn't happen — both VAs come from our own
            // heap region, which PeLoad mapped every page of.
            // Defensive: free the new block so we don't leak
            // on this unexpected path.
            Win32HeapFree(proc, new_ptr);
            return 0;
        }
        const u64 src_off = src_va - src_page;
        const u64 dst_off = dst_va - dst_page;
        const u64 src_room = customos::mm::kPageSize - src_off;
        const u64 dst_room = customos::mm::kPageSize - dst_off;
        u64 chunk = remaining;
        if (chunk > src_room)
            chunk = src_room;
        if (chunk > dst_room)
            chunk = dst_room;
        const auto* src = static_cast<const u8*>(customos::mm::PhysToVirt(src_frame)) + src_off;
        auto* dst = static_cast<u8*>(customos::mm::PhysToVirt(dst_frame)) + dst_off;
        for (u64 i = 0; i < chunk; ++i)
            dst[i] = src[i];
        src_va += chunk;
        dst_va += chunk;
        remaining -= chunk;
    }
    Win32HeapFree(proc, user_ptr);
    return new_ptr;
}

} // namespace customos::win32
