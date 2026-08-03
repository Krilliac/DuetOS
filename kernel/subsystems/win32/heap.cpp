#include "subsystems/win32/heap.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "subsystems/win32/custom.h"

namespace duetos::win32
{

namespace
{

// Header layout for every block, free or allocated. The header is stored in
// user-writable memory, so every field is hostile input when read back.
struct BlockHeader
{
    u64 size;
    u64 next;
};

constexpr u64 kHeaderSize = sizeof(BlockHeader);
constexpr u64 kMinSplitPayload = 16;
constexpr u64 kReallocCopyChunk = 256;

// Process::win32_heap_lock is a sleeping mutex because all heap operations
// enter the address-space transaction API, which may itself sleep. Lock order:
//
//   Process::win32_heap_lock
//     -> AddressSpace::mutation_lock
//       -> AddressSpace::regions_lock
//
// No heap path may hold a spinlock while acquiring either mutex or while
// allocating/freeing frames. The heap mutex is process-owned and covers the
// default metadata, every extra_heaps[] row, and every in-band free-list
// traversal or mutation.
class HeapLockGuard
{
  public:
    explicit HeapLockGuard(duetos::core::Process& process) : m_process(process)
    {
        duetos::sched::MutexLock(&m_process.win32_heap_lock);
    }

    ~HeapLockGuard() { duetos::sched::MutexUnlock(&m_process.win32_heap_lock); }

    HeapLockGuard(const HeapLockGuard&) = delete;
    HeapLockGuard& operator=(const HeapLockGuard&) = delete;

  private:
    duetos::core::Process& m_process;
};

// A pointer to the kernel-owned head is useful only inside a heap-lock critical
// section. Unlike the public Win32HeapBinding receipt, HeapView never escapes
// this translation unit or the lock that protects the pointed-to metadata.
struct HeapView
{
    u64 base_va;
    u64 pages;
    u64* free_head;
};

struct HeapFreeNotice
{
    u64 user_ptr;
    u64 payload_size;
    bool valid;
};

struct HeapReallocOutcome
{
    u64 result;
    HeapFreeNotice notice;
};

bool TryHeapEnd(const HeapView& view, u64* end_out)
{
    if (end_out == nullptr || view.base_va == 0 || view.pages == 0 || view.free_head == nullptr ||
        view.pages > (~u64{0} - view.base_va) / duetos::mm::kPageSize)
    {
        return false;
    }
    *end_out = view.base_va + view.pages * duetos::mm::kPageSize;
    return *end_out > view.base_va;
}

bool IsHeaderVaInHeap(const HeapView& view, u64 heap_end, u64 header_va)
{
    return header_va >= view.base_va && header_va <= heap_end - kHeaderSize && (header_va & 7) == 0;
}

bool IsFreeLinkInHeap(const HeapView& view, u64 heap_end, u64 link)
{
    return link == 0 || IsHeaderVaInHeap(view, heap_end, link);
}

bool ReadHeapU64(duetos::core::Process* proc, u64 user_va, u64* value_out)
{
    if (proc == nullptr || proc->as == nullptr || value_out == nullptr)
        return false;
    *value_out = 0;
    return duetos::mm::AddressSpaceReadUserMemory(proc->as, user_va, value_out, sizeof(*value_out));
}

bool WriteHeapU64(duetos::core::Process* proc, u64 user_va, u64 value)
{
    return proc != nullptr && proc->as != nullptr &&
           duetos::mm::AddressSpaceWriteUserMemory(proc->as, user_va, &value, sizeof(value));
}

bool RoundRequestToBlockSize(u64 requested, u64* block_size_out)
{
    if (block_size_out == nullptr)
        return false;
    u64 payload = requested < kHeaderSize ? kHeaderSize : requested;
    if (payload > ~u64{0} - 7)
        return false;
    payload = (payload + 7) & ~u64{7};
    if (payload > ~u64{0} - kHeaderSize)
        return false;
    *block_size_out = payload + kHeaderSize;
    return true;
}

// Requires proc->win32_heap_lock.
bool ResolveDefaultViewLocked(duetos::core::Process* proc, HeapView* view_out)
{
    if (proc == nullptr || view_out == nullptr || proc->heap_base == 0 || proc->heap_pages == 0)
        return false;
    HeapView view{proc->heap_base, proc->heap_pages, &proc->heap_free_head};
    u64 heap_end = 0;
    if (!TryHeapEnd(view, &heap_end))
        return false;
    *view_out = view;
    return true;
}

// Requires proc->win32_heap_lock. Revalidates all receipt fields before
// exposing the internal head pointer to a locked helper.
bool ResolveBindingLocked(duetos::core::Process* proc, const Win32HeapBinding& binding, HeapView* view_out)
{
    if (proc == nullptr || view_out == nullptr)
        return false;

    if (binding.slot == kWin32DefaultHeapBindingSlot)
    {
        if (binding.base_va != proc->heap_base || binding.pages != proc->heap_pages || binding.generation != 1)
            return false;
        return ResolveDefaultViewLocked(proc, view_out);
    }

    using duetos::core::Process;
    if (binding.slot >= Process::kWin32ExtraHeapCap)
        return false;
    Process::Win32ExtraHeap& row = proc->extra_heaps[binding.slot];
    if (!row.in_use || row.base_va != binding.base_va || row.pages != binding.pages ||
        row.generation != binding.generation)
        return false;

    HeapView view{row.base_va, row.pages, &row.free_head};
    u64 heap_end = 0;
    if (!TryHeapEnd(view, &heap_end))
        return false;
    *view_out = view;
    return true;
}

// Requires proc->win32_heap_lock.
bool ResolveHandleLocked(duetos::core::Process* proc, u64 heap_handle, Win32HeapBinding* out)
{
    if (proc == nullptr || out == nullptr)
        return false;

    if (proc->heap_base != 0 && proc->heap_pages != 0 &&
        (heap_handle == proc->heap_base || heap_handle == 0 || heap_handle == kWin32HeapVa))
    {
        *out = Win32HeapBinding{proc->heap_base, proc->heap_pages, 1, kWin32DefaultHeapBindingSlot, 0};
        return true;
    }

    using duetos::core::Process;
    for (u32 slot = 0; slot < Process::kWin32ExtraHeapCap; ++slot)
    {
        const Process::Win32ExtraHeap& row = proc->extra_heaps[slot];
        if (row.in_use && row.base_va == heap_handle && row.pages != 0 && row.generation != 0)
        {
            *out = Win32HeapBinding{row.base_va, row.pages, row.generation, slot, 0};
            return true;
        }
    }
    return false;
}

// Requires proc->win32_heap_lock.
u64 HeapAllocLocked(duetos::core::Process* proc, const HeapView& view, u64 size)
{
    if (*view.free_head == 0)
        return 0;
    if (size == 0)
        size = 1; // HeapAlloc(size=0) returns a unique non-null pointer.

    u64 needed = 0;
    u64 heap_end = 0;
    if (!RoundRequestToBlockSize(size, &needed) || !TryHeapEnd(view, &heap_end))
        return 0;
    const u64 heap_bytes = heap_end - view.base_va;
    if (needed > heap_bytes)
        return 0;

    u64 prev = 0;
    u64 cur = *view.free_head;
    // Hostile next pointers can form a cycle. A valid arena cannot contain
    // more distinct headers than heap_bytes / kHeaderSize, so this bound turns
    // a guest-created cycle into ordinary allocation failure.
    const u64 max_hops = heap_bytes / kHeaderSize + 1;
    for (u64 hop = 0; cur != 0 && hop < max_hops; ++hop)
    {
        if (!IsHeaderVaInHeap(view, heap_end, cur))
            break;

        u64 block_size = 0;
        u64 block_next = 0;
        if (!ReadHeapU64(proc, cur, &block_size) || !ReadHeapU64(proc, cur + sizeof(u64), &block_next))
            break;
        if (block_size < kHeaderSize || block_size > heap_end - cur || (block_size & 7) != 0 ||
            !IsFreeLinkInHeap(view, heap_end, block_next))
        {
            break;
        }

        if (block_size >= needed && !duetos::subsystems::win32::custom::IsQuarantined(proc, cur + kHeaderSize))
        {
            const u64 leftover = block_size - needed;
            if (leftover >= kHeaderSize + kMinSplitPayload)
            {
                const u64 split_va = cur + needed;
                // Publish the replacement link last. If a VM mutation makes
                // an intermediate write fail, the old list remains reachable
                // and at worst loses reusable tail capacity; no out-of-arena
                // pointer or raw frame survives the failed transaction.
                if (!WriteHeapU64(proc, split_va, leftover) ||
                    !WriteHeapU64(proc, split_va + sizeof(u64), block_next) || !WriteHeapU64(proc, cur, needed))
                {
                    return 0;
                }
                if (prev == 0)
                    *view.free_head = split_va;
                else if (!WriteHeapU64(proc, prev + sizeof(u64), split_va))
                    return 0;
            }
            else
            {
                if (prev == 0)
                    *view.free_head = block_next;
                else if (!WriteHeapU64(proc, prev + sizeof(u64), block_next))
                    return 0;
            }
            return cur + kHeaderSize;
        }

        prev = cur;
        cur = block_next;
    }
    return 0;
}

// Requires proc->win32_heap_lock.
bool HeapFreeLocked(duetos::core::Process* proc, const HeapView& view, u64 user_ptr, HeapFreeNotice* notice_out)
{
    if (notice_out != nullptr)
        *notice_out = HeapFreeNotice{};
    if (user_ptr == 0 || user_ptr < kHeaderSize || (user_ptr & 7) != 0)
        return false;

    u64 heap_end = 0;
    if (!TryHeapEnd(view, &heap_end))
        return false;
    const u64 block_header = user_ptr - kHeaderSize;
    if (!IsHeaderVaInHeap(view, heap_end, block_header) || !IsFreeLinkInHeap(view, heap_end, *view.free_head))
    {
        return false;
    }

    u64 block_size = 0;
    if (!ReadHeapU64(proc, block_header, &block_size) || block_size < kHeaderSize ||
        block_size > heap_end - block_header || (block_size & 7) != 0)
    {
        return false;
    }
    if (!WriteHeapU64(proc, block_header + sizeof(u64), *view.free_head))
        return false;

    *view.free_head = block_header;
    if (notice_out != nullptr)
        *notice_out = HeapFreeNotice{user_ptr, block_size - kHeaderSize, true};
    return true;
}

// Requires proc->win32_heap_lock.
u64 HeapSizeLocked(duetos::core::Process* proc, const HeapView& view, u64 user_ptr)
{
    if (user_ptr == 0 || user_ptr < kHeaderSize || (user_ptr & 7) != 0)
        return 0;
    u64 heap_end = 0;
    if (!TryHeapEnd(view, &heap_end))
        return 0;
    const u64 block_header = user_ptr - kHeaderSize;
    if (!IsHeaderVaInHeap(view, heap_end, block_header))
        return 0;

    u64 block_size = 0;
    if (!ReadHeapU64(proc, block_header, &block_size) || block_size < kHeaderSize ||
        block_size > heap_end - block_header || (block_size & 7) != 0)
    {
        return 0;
    }
    return block_size - kHeaderSize;
}

// Requires proc->win32_heap_lock. Every transaction stays within one source
// page and one destination page; the fixed stack buffer bounds kernel stack
// use and no allocation occurs while the heap mutex is held.
bool CopyHeapPayloadLocked(duetos::core::Process* proc, u64 source_va, u64 destination_va, u64 length)
{
    u8 buffer[kReallocCopyChunk];
    while (length != 0)
    {
        const u64 source_room = duetos::mm::kPageSize - (source_va & (duetos::mm::kPageSize - 1));
        const u64 destination_room = duetos::mm::kPageSize - (destination_va & (duetos::mm::kPageSize - 1));
        u64 chunk = length;
        if (chunk > source_room)
            chunk = source_room;
        if (chunk > destination_room)
            chunk = destination_room;
        if (chunk > sizeof(buffer))
            chunk = sizeof(buffer);

        if (!duetos::mm::AddressSpaceReadUserMemory(proc->as, source_va, buffer, chunk) ||
            !duetos::mm::AddressSpaceWriteUserMemory(proc->as, destination_va, buffer, chunk))
        {
            return false;
        }
        source_va += chunk;
        destination_va += chunk;
        length -= chunk;
    }
    return true;
}

// Requires proc->win32_heap_lock.
HeapReallocOutcome HeapReallocLocked(duetos::core::Process* proc, const HeapView& view, u64 user_ptr, u64 new_size)
{
    HeapReallocOutcome outcome{};
    if (user_ptr == 0)
    {
        outcome.result = HeapAllocLocked(proc, view, new_size);
        return outcome;
    }
    if (new_size == 0)
    {
        (void)HeapFreeLocked(proc, view, user_ptr, &outcome.notice);
        return outcome;
    }

    const u64 old_payload = HeapSizeLocked(proc, view, user_ptr);
    if (old_payload == 0)
        return outcome;
    if (new_size <= old_payload)
    {
        outcome.result = user_ptr;
        return outcome;
    }

    const u64 new_ptr = HeapAllocLocked(proc, view, new_size);
    if (new_ptr == 0)
        return outcome;
    if (!CopyHeapPayloadLocked(proc, user_ptr, new_ptr, old_payload))
    {
        (void)HeapFreeLocked(proc, view, new_ptr, &outcome.notice);
        return outcome;
    }

    (void)HeapFreeLocked(proc, view, user_ptr, &outcome.notice);
    outcome.result = new_ptr;
    return outcome;
}

void PublishHeapFreeNotice(duetos::core::Process* proc, const HeapFreeNotice& notice)
{
    if (notice.valid)
        duetos::subsystems::win32::custom::OnHeapFree(proc, notice.user_ptr, notice.payload_size);
}

void UnmapHeapPrefix(duetos::core::Process* proc, u64 base_va, u64 pages)
{
    for (u64 page = 0; page < pages; ++page)
        (void)duetos::mm::AddressSpaceUnmapUserPage(proc->as, base_va + page * duetos::mm::kPageSize);
}

} // namespace

bool Win32HeapInit(duetos::core::Process* proc)
{
    KLOG_TRACE_SCOPE("win32/heap", "Win32HeapInit");
    using namespace duetos::mm;
    if (proc == nullptr || proc->as == nullptr)
        return false;

    const u64 heap_bytes = kWin32HeapPages * kPageSize;
    {
        HeapLockGuard guard(*proc);
        if (proc->heap_base != 0 || proc->heap_pages != 0 || proc->heap_free_head != 0)
            return false;

        u64 mapped = 0;
        for (; mapped < kWin32HeapPages; ++mapped)
        {
            auto frame_result = AllocateFrame();
            if (!frame_result)
                break;
            const PhysAddr frame = frame_result.value();
            if (!AddressSpaceMapUserPage(proc->as, kWin32HeapVa + mapped * kPageSize, frame,
                                         kPagePresent | kPageUser | kPageWritable | kPageNoExecute))
            {
                FreeFrame(frame);
                break;
            }
        }
        if (mapped != kWin32HeapPages)
        {
            UnmapHeapPrefix(proc, kWin32HeapVa, mapped);
            return false;
        }

        // Publish kernel metadata only after both hostile-user-memory writes
        // succeed. A failed seed is fully unmapped and remains invisible.
        if (!WriteHeapU64(proc, kWin32HeapVa, heap_bytes) || !WriteHeapU64(proc, kWin32HeapVa + sizeof(u64), 0))
        {
            UnmapHeapPrefix(proc, kWin32HeapVa, kWin32HeapPages);
            return false;
        }
        proc->heap_base = kWin32HeapVa;
        proc->heap_pages = kWin32HeapPages;
        proc->heap_free_head = kWin32HeapVa;
    }

    {
        arch::SerialLineGuard line;
        arch::SerialWrite("[w32-heap] init pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" base=");
        arch::SerialWriteHex(kWin32HeapVa);
        arch::SerialWrite(" size=");
        arch::SerialWriteHex(heap_bytes);
        arch::SerialWrite("\n");
    }

    // This allocation-capable policy hook intentionally runs after releasing
    // win32_heap_lock.
    duetos::subsystems::win32::custom::ApplySystemDefaultPolicy(proc);
    return true;
}

u64 Win32HeapAllocOnBinding(duetos::core::Process* proc, const Win32HeapBinding& binding, u64 size)
{
    u64 result = 0;
    if (proc != nullptr)
    {
        HeapLockGuard guard(*proc);
        HeapView view{};
        if (ResolveBindingLocked(proc, binding, &view))
            result = HeapAllocLocked(proc, view, size);
    }
    if (result == 0)
        KLOG_ONCE_WARN("win32/heap", "heap exhausted or corrupt (HeapAlloc returned NULL)");
    return result;
}

u64 Win32HeapAlloc(duetos::core::Process* proc, u64 size)
{
    u64 result = 0;
    if (proc != nullptr)
    {
        HeapLockGuard guard(*proc);
        HeapView view{};
        if (ResolveDefaultViewLocked(proc, &view))
            result = HeapAllocLocked(proc, view, size);
    }
    if (result == 0)
        KLOG_ONCE_WARN("win32/heap", "heap exhausted or corrupt (HeapAlloc returned NULL)");
    return result;
}

void Win32HeapFreeOnBinding(duetos::core::Process* proc, const Win32HeapBinding& binding, u64 user_ptr)
{
    if (proc == nullptr)
        return;
    HeapLockGuard guard(*proc);
    HeapView view{};
    HeapFreeNotice notice{};
    if (ResolveBindingLocked(proc, binding, &view))
        (void)HeapFreeLocked(proc, view, user_ptr, &notice);
    // Keep quarantine publication ordered before another thread can reuse the
    // just-freed block. This hook is bounded and non-allocating.
    PublishHeapFreeNotice(proc, notice);
}

void Win32HeapFree(duetos::core::Process* proc, u64 user_ptr)
{
    if (proc == nullptr)
        return;
    HeapLockGuard guard(*proc);
    HeapView view{};
    HeapFreeNotice notice{};
    if (ResolveDefaultViewLocked(proc, &view))
        (void)HeapFreeLocked(proc, view, user_ptr, &notice);
    PublishHeapFreeNotice(proc, notice);
}

u64 Win32HeapSizeOnBinding(duetos::core::Process* proc, const Win32HeapBinding& binding, u64 user_ptr)
{
    if (proc == nullptr)
        return 0;
    HeapLockGuard guard(*proc);
    HeapView view{};
    return ResolveBindingLocked(proc, binding, &view) ? HeapSizeLocked(proc, view, user_ptr) : 0;
}

u64 Win32HeapSize(duetos::core::Process* proc, u64 user_ptr)
{
    if (proc == nullptr)
        return 0;
    HeapLockGuard guard(*proc);
    HeapView view{};
    return ResolveDefaultViewLocked(proc, &view) ? HeapSizeLocked(proc, view, user_ptr) : 0;
}

u64 Win32HeapReallocOnBinding(duetos::core::Process* proc, const Win32HeapBinding& binding, u64 user_ptr, u64 new_size)
{
    if (proc == nullptr)
        return 0;
    HeapLockGuard guard(*proc);
    HeapView view{};
    HeapReallocOutcome outcome{};
    if (ResolveBindingLocked(proc, binding, &view))
        outcome = HeapReallocLocked(proc, view, user_ptr, new_size);
    PublishHeapFreeNotice(proc, outcome.notice);
    return outcome.result;
}

u64 Win32HeapRealloc(duetos::core::Process* proc, u64 user_ptr, u64 new_size)
{
    if (proc == nullptr)
        return 0;
    HeapLockGuard guard(*proc);
    HeapView view{};
    HeapReallocOutcome outcome{};
    if (ResolveDefaultViewLocked(proc, &view))
        outcome = HeapReallocLocked(proc, view, user_ptr, new_size);
    PublishHeapFreeNotice(proc, outcome.notice);
    return outcome.result;
}

bool Win32HeapResolveHandle(duetos::core::Process* proc, u64 heap_handle, Win32HeapBinding* out)
{
    if (out != nullptr)
        *out = Win32HeapBinding{};
    if (proc == nullptr || out == nullptr)
        return false;
    HeapLockGuard guard(*proc);
    return ResolveHandleLocked(proc, heap_handle, out);
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

    u64 created_base = 0;
    u64 created_slot = Process::kWin32ExtraHeapCap;
    bool table_full = false;
    {
        HeapLockGuard guard(*proc);
        for (u64 slot = 0; slot < Process::kWin32ExtraHeapCap; ++slot)
        {
            if (!proc->extra_heaps[slot].in_use && proc->extra_heaps[slot].generation != ~u64{0})
            {
                created_slot = slot;
                break;
            }
        }
        if (created_slot == Process::kWin32ExtraHeapCap)
        {
            table_full = true;
        }
        else
        {
            const u64 base_va = Process::kWin32ExtraHeapArenaBase + created_slot * Process::kWin32ExtraHeapStride;
            u64 mapped = 0;
            for (; mapped < pages; ++mapped)
            {
                auto frame_result = AllocateFrame();
                if (!frame_result)
                    break;
                const PhysAddr frame = frame_result.value();
                if (!AddressSpaceMapUserPage(proc->as, base_va + mapped * kPageSize, frame,
                                             kPagePresent | kPageUser | kPageWritable | kPageNoExecute))
                {
                    FreeFrame(frame);
                    break;
                }
            }
            if (mapped != pages)
            {
                UnmapHeapPrefix(proc, base_va, mapped);
            }
            else
            {
                const u64 heap_bytes = pages * kPageSize;
                if (!WriteHeapU64(proc, base_va, heap_bytes) || !WriteHeapU64(proc, base_va + sizeof(u64), 0))
                {
                    UnmapHeapPrefix(proc, base_va, pages);
                }
                else
                {
                    Process::Win32ExtraHeap& row = proc->extra_heaps[created_slot];
                    ++row.generation;
                    row.in_use = true;
                    row.base_va = base_va;
                    row.pages = pages;
                    row.free_head = base_va;
                    created_base = base_va;
                }
            }
        }
    }

    if (table_full)
        KLOG_ONCE_WARN("win32/heap", "HeapCreate: no free extra-heap slot");
    if (created_base != 0)
    {
        arch::SerialLineGuard line;
        arch::SerialWrite("[w32-heap] ex-create pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" slot=");
        arch::SerialWriteHex(created_slot);
        arch::SerialWrite(" base=");
        arch::SerialWriteHex(created_base);
        arch::SerialWrite(" pages=");
        arch::SerialWriteHex(pages);
        arch::SerialWrite("\n");
    }
    return created_base;
}

bool Win32HeapExDestroy(duetos::core::Process* proc, u64 heap_handle)
{
    using duetos::core::Process;
    if (proc == nullptr || proc->as == nullptr)
        return false;

    bool destroyed = false;
    u64 destroyed_slot = Process::kWin32ExtraHeapCap;
    {
        HeapLockGuard guard(*proc);
        // Preserve the existing ABI: destroying the process heap succeeds but
        // is a no-op, so CRT cleanup cannot dismantle its own allocator.
        if (proc->heap_base != 0 && heap_handle == proc->heap_base)
        {
            destroyed = true;
        }
        else
        {
            for (u64 slot = 0; slot < Process::kWin32ExtraHeapCap; ++slot)
            {
                Process::Win32ExtraHeap& row = proc->extra_heaps[slot];
                if (!row.in_use || row.base_va != heap_handle)
                    continue;
                UnmapHeapPrefix(proc, row.base_va, row.pages);
                row.in_use = false;
                row.base_va = 0;
                row.pages = 0;
                row.free_head = 0;
                destroyed = true;
                destroyed_slot = slot;
                break;
            }
        }
    }

    if (destroyed_slot != Process::kWin32ExtraHeapCap)
    {
        arch::SerialLineGuard line;
        arch::SerialWrite("[w32-heap] ex-destroy slot=");
        arch::SerialWriteHex(destroyed_slot);
        arch::SerialWrite("\n");
    }
    return destroyed;
}

} // namespace duetos::win32
