#include "subsystems/win32/heap.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "proc/process.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "subsystems/win32/custom.h"

namespace duetos::win32
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
u64 PeekU64(const duetos::core::Process* proc, u64 user_va)
{
    const u64 page_va = user_va & ~0xFFFULL;
    const duetos::mm::PhysAddr frame = duetos::mm::AddressSpaceLookupUserFrame(proc->as, page_va);
    if (frame == duetos::mm::kNullFrame)
        return 0;
    const auto* direct = static_cast<const u8*>(duetos::mm::PhysToVirt(frame));
    const u64 off = user_va - page_va;
    u64 v = 0;
    for (u64 b = 0; b < 8; ++b)
        v |= static_cast<u64>(direct[off + b]) << (b * 8);
    return v;
}

void PokeU64(duetos::core::Process* proc, u64 user_va, u64 value)
{
    const u64 page_va = user_va & ~0xFFFULL;
    const duetos::mm::PhysAddr frame = duetos::mm::AddressSpaceLookupUserFrame(proc->as, page_va);
    if (frame == duetos::mm::kNullFrame)
        return;
    auto* direct = static_cast<u8*>(duetos::mm::PhysToVirt(frame));
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

bool Win32HeapInit(duetos::core::Process* proc)
{
    KLOG_TRACE_SCOPE("win32/heap", "Win32HeapInit");
    using namespace duetos::mm;
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
        auto frame_r = AllocateFrame();
        if (!frame_r)
            return false;
        const PhysAddr frame = frame_r.value();
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

    // Auto-enable the observability tier of the Win32 custom
    // diagnostics suite for every Win32 PE. Apps that don't want
    // them can still clear bits explicitly via SYS_WIN32_CUSTOM
    // op=SetPolicy. Kept here (rather than ProcessCreate) because
    // Win32HeapInit is the canonical "this process is a Win32 PE
    // with imports" gate — non-Win32 native tasks don't pay the
    // ~7 KB state allocation.
    duetos::subsystems::win32::custom::ApplySystemDefaultPolicy(proc);
    return true;
}

u64 Win32HeapAllocOnBinding(duetos::core::Process* proc, const Win32HeapBinding& b, u64 size)
{
    if (proc == nullptr || b.free_head_ptr == nullptr || *b.free_head_ptr == 0)
        return 0;
    if (size == 0)
        size = 1; // Win32: HeapAlloc(size=0) returns a unique non-null ptr.

    const u64 needed = RoundRequestToBlockSize(size);

    // First-fit walk on the binding's free list. Same shape as
    // the legacy default-heap path, but reads/writes the head
    // through the binding pointer so secondary heaps don't
    // perturb the default-heap state.
    u64 prev = 0;
    u64 cur = *b.free_head_ptr;
    while (cur != 0)
    {
        const u64 block_size = PeekU64(proc, cur + 0);
        const u64 block_next = PeekU64(proc, cur + 8);
        if (block_size >= needed && !duetos::subsystems::win32::custom::IsQuarantined(proc, cur + kHeaderSize))
        {
            const u64 leftover = block_size - needed;
            if (leftover >= kHeaderSize + kMinSplitPayload)
            {
                const u64 split_va = cur + needed;
                PokeU64(proc, split_va + 0, leftover);
                PokeU64(proc, split_va + 8, block_next);
                PokeU64(proc, cur + 0, needed);
                if (prev == 0)
                    *b.free_head_ptr = split_va;
                else
                    PokeU64(proc, prev + 8, split_va);
            }
            else
            {
                if (prev == 0)
                    *b.free_head_ptr = block_next;
                else
                    PokeU64(proc, prev + 8, block_next);
            }
            return cur + kHeaderSize;
        }
        prev = cur;
        cur = block_next;
    }

    KLOG_ONCE_WARN("win32/heap", "heap exhausted (HeapAlloc returned NULL)");
    return 0;
}

u64 Win32HeapAlloc(duetos::core::Process* proc, u64 size)
{
    if (proc == nullptr)
        return 0;
    Win32HeapBinding b{proc->heap_base, proc->heap_pages, &proc->heap_free_head};
    return Win32HeapAllocOnBinding(proc, b, size);
}

void Win32HeapFreeOnBinding(duetos::core::Process* proc, const Win32HeapBinding& b, u64 user_ptr)
{
    if (proc == nullptr || user_ptr == 0 || b.free_head_ptr == nullptr)
        return;
    // user_ptr must be far enough above zero that `user_ptr -
    // kHeaderSize` doesn't wrap u64. The downstream upper-bound
    // check at line 203 already rejects the wrapped value, but
    // gate up-front so the intermediate `block_hdr` doesn't get
    // exposed to any code path that adds it to anything.
    if (user_ptr < kHeaderSize)
        return;
    const u64 block_hdr = user_ptr - kHeaderSize;
    if (block_hdr < b.base_va)
        return;
    if (block_hdr >= b.base_va + b.pages * duetos::mm::kPageSize)
        return;
    const u64 block_size = PeekU64(proc, block_hdr + 0);
    PokeU64(proc, block_hdr + 8, *b.free_head_ptr);
    *b.free_head_ptr = block_hdr;
    if (block_size > kHeaderSize)
        duetos::subsystems::win32::custom::OnHeapFree(proc, user_ptr, block_size - kHeaderSize);
}

void Win32HeapFree(duetos::core::Process* proc, u64 user_ptr)
{
    if (proc == nullptr)
        return;
    Win32HeapBinding b{proc->heap_base, proc->heap_pages, &proc->heap_free_head};
    Win32HeapFreeOnBinding(proc, b, user_ptr);
}

u64 Win32HeapSizeOnBinding(duetos::core::Process* proc, const Win32HeapBinding& b, u64 user_ptr)
{
    if (proc == nullptr || user_ptr == 0)
        return 0;
    const u64 block_hdr = user_ptr - kHeaderSize;
    if (block_hdr < b.base_va)
        return 0;
    if (block_hdr >= b.base_va + b.pages * duetos::mm::kPageSize)
        return 0;
    const u64 block_size = PeekU64(proc, block_hdr + 0);
    if (block_size < kHeaderSize)
        return 0;
    return block_size - kHeaderSize;
}

u64 Win32HeapSize(duetos::core::Process* proc, u64 user_ptr)
{
    if (proc == nullptr)
        return 0;
    Win32HeapBinding b{proc->heap_base, proc->heap_pages, &proc->heap_free_head};
    return Win32HeapSizeOnBinding(proc, b, user_ptr);
}

u64 Win32HeapReallocOnBinding(duetos::core::Process* proc, const Win32HeapBinding& b, u64 user_ptr, u64 new_size)
{
    if (proc == nullptr)
        return 0;
    if (user_ptr == 0)
        return Win32HeapAllocOnBinding(proc, b, new_size);
    if (new_size == 0)
    {
        Win32HeapFreeOnBinding(proc, b, user_ptr);
        return 0;
    }

    const u64 block_hdr = user_ptr - kHeaderSize;
    if (block_hdr < b.base_va)
        return 0;
    if (block_hdr >= b.base_va + b.pages * duetos::mm::kPageSize)
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

    const u64 new_ptr = Win32HeapAllocOnBinding(proc, b, new_size);
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
        const duetos::mm::PhysAddr src_frame = duetos::mm::AddressSpaceLookupUserFrame(proc->as, src_page);
        const duetos::mm::PhysAddr dst_frame = duetos::mm::AddressSpaceLookupUserFrame(proc->as, dst_page);
        if (src_frame == duetos::mm::kNullFrame || dst_frame == duetos::mm::kNullFrame)
        {
            // Shouldn't happen — both VAs come from our own
            // heap region, which PeLoad mapped every page of.
            // Defensive: free the new block so we don't leak
            // on this unexpected path.
            Win32HeapFreeOnBinding(proc, b, new_ptr);
            return 0;
        }
        const u64 src_off = src_va - src_page;
        const u64 dst_off = dst_va - dst_page;
        const u64 src_room = duetos::mm::kPageSize - src_off;
        const u64 dst_room = duetos::mm::kPageSize - dst_off;
        u64 chunk = remaining;
        if (chunk > src_room)
            chunk = src_room;
        if (chunk > dst_room)
            chunk = dst_room;
        const auto* src = static_cast<const u8*>(duetos::mm::PhysToVirt(src_frame)) + src_off;
        auto* dst = static_cast<u8*>(duetos::mm::PhysToVirt(dst_frame)) + dst_off;
        for (u64 i = 0; i < chunk; ++i)
            dst[i] = src[i];
        src_va += chunk;
        dst_va += chunk;
        remaining -= chunk;
    }
    Win32HeapFreeOnBinding(proc, b, user_ptr);
    return new_ptr;
}

u64 Win32HeapRealloc(duetos::core::Process* proc, u64 user_ptr, u64 new_size)
{
    if (proc == nullptr)
        return 0;
    Win32HeapBinding b{proc->heap_base, proc->heap_pages, &proc->heap_free_head};
    return Win32HeapReallocOnBinding(proc, b, user_ptr, new_size);
}

bool Win32HeapResolveHandle(duetos::core::Process* proc, u64 heap_handle, Win32HeapBinding* out)
{
    if (proc == nullptr || out == nullptr)
        return false;
    // Default heap: handle == proc->heap_base (also the value
    // GetProcessHeap returned in the v0 single-heap path).
    if (heap_handle == proc->heap_base || heap_handle == 0 || heap_handle == kWin32HeapVa)
    {
        out->base_va = proc->heap_base;
        out->pages = proc->heap_pages;
        out->free_head_ptr = &proc->heap_free_head;
        return true;
    }
    using duetos::core::Process;
    for (u64 i = 0; i < Process::kWin32ExtraHeapCap; ++i)
    {
        if (proc->extra_heaps[i].in_use && proc->extra_heaps[i].base_va == heap_handle)
        {
            out->base_va = proc->extra_heaps[i].base_va;
            out->pages = proc->extra_heaps[i].pages;
            out->free_head_ptr = &proc->extra_heaps[i].free_head;
            return true;
        }
    }
    return false;
}

u64 Win32HeapExCreate(duetos::core::Process* proc, u64 pages)
{
    using namespace duetos::mm;
    using duetos::core::Process;
    if (proc == nullptr || proc->as == nullptr)
        return 0;
    if (pages == 0)
        pages = 1;
    if (pages > Process::kWin32ExtraHeapPagesMax)
        pages = Process::kWin32ExtraHeapPagesMax;

    // Find a free slot.
    u64 slot = Process::kWin32ExtraHeapCap;
    for (u64 i = 0; i < Process::kWin32ExtraHeapCap; ++i)
    {
        if (!proc->extra_heaps[i].in_use)
        {
            slot = i;
            break;
        }
    }
    if (slot == Process::kWin32ExtraHeapCap)
    {
        KLOG_ONCE_WARN("win32/heap", "HeapCreate: no free extra-heap slot");
        return 0;
    }

    const u64 base_va = Process::kWin32ExtraHeapArenaBase + slot * Process::kWin32ExtraHeapStride;
    // Map fresh frames RW+NX. On any frame failure, unmap the
    // pages we already mapped to keep the AS clean — this slot
    // stays available for a future, smaller HeapCreate.
    u64 mapped = 0;
    for (; mapped < pages; ++mapped)
    {
        auto frame_r = AllocateFrame();
        if (!frame_r)
            break;
        const PhysAddr frame = frame_r.value();
        AddressSpaceMapUserPage(proc->as, base_va + mapped * kPageSize, frame,
                                kPagePresent | kPageUser | kPageWritable | kPageNoExecute);
    }
    if (mapped < pages)
    {
        for (u64 i = 0; i < mapped; ++i)
            AddressSpaceUnmapUserPage(proc->as, base_va + i * kPageSize);
        return 0;
    }

    proc->extra_heaps[slot].in_use = true;
    proc->extra_heaps[slot].base_va = base_va;
    proc->extra_heaps[slot].pages = pages;

    const u64 heap_bytes = pages * kPageSize;
    PokeU64(proc, base_va + 0, heap_bytes);
    PokeU64(proc, base_va + 8, 0);
    proc->extra_heaps[slot].free_head = base_va;

    arch::SerialWrite("[w32-heap] ex-create pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" slot=");
    arch::SerialWriteHex(slot);
    arch::SerialWrite(" base=");
    arch::SerialWriteHex(base_va);
    arch::SerialWrite(" pages=");
    arch::SerialWriteHex(pages);
    arch::SerialWrite("\n");
    return base_va;
}

bool Win32HeapExDestroy(duetos::core::Process* proc, u64 heap_handle)
{
    using namespace duetos::mm;
    using duetos::core::Process;
    if (proc == nullptr)
        return false;
    // Refuse to destroy the default heap — Win32 lets HeapDestroy
    // succeed on GetProcessHeap() but the runtime undermines the
    // CRT if it actually goes through. Return true (success) so
    // a caller's ABI-conformant cleanup path doesn't trip on the
    // sentinel; the unmap is a no-op.
    if (heap_handle == proc->heap_base)
        return true;
    for (u64 i = 0; i < Process::kWin32ExtraHeapCap; ++i)
    {
        if (proc->extra_heaps[i].in_use && proc->extra_heaps[i].base_va == heap_handle)
        {
            const u64 base = proc->extra_heaps[i].base_va;
            const u64 pages = proc->extra_heaps[i].pages;
            for (u64 p = 0; p < pages; ++p)
                AddressSpaceUnmapUserPage(proc->as, base + p * kPageSize);
            proc->extra_heaps[i].in_use = false;
            proc->extra_heaps[i].base_va = 0;
            proc->extra_heaps[i].pages = 0;
            proc->extra_heaps[i].free_head = 0;
            arch::SerialWrite("[w32-heap] ex-destroy slot=");
            arch::SerialWriteHex(i);
            arch::SerialWrite("\n");
            return true;
        }
    }
    return false;
}

} // namespace duetos::win32
