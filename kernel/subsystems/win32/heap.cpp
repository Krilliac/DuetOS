#include "heap.h"

#include "../../arch/x86_64/serial.h"
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

} // namespace customos::win32
