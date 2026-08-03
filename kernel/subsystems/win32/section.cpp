/*
 * Win32 anonymous section pool.
 *
 * The global spinlock protects only slot state, generation, refs, and brief
 * metadata snapshots. Per-slot map_mutex serializes W^X history and borrowed
 * range transactions. Allocation, address-space work, TLB waits, and teardown
 * happen with the spinlock released.
 */

#include "subsystems/win32/section.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/saturating.h"

namespace duetos::subsystems::win32::section
{

namespace
{

enum class SectionState : u8
{
    Free,
    Constructing,
    Live,
    Retiring,
};

struct Section
{
    SectionState state;
    u8 _pad0[3];
    u32 generation;
    u32 num_pages;
    util::SatU32 refcount;
    u32 page_protect;
    mm::PhysAddr* frames;
    bool has_writable_view;
    bool has_executable_view;
    u8 _pad1[6];
    // Persistent across slot generations. Never clear/reinitialize this field.
    sched::Mutex map_mutex;
};

constinit Section g_pool[kSectionPoolCap]{};
constinit sync::SpinLock g_section_lock{};

class SectionMapGuard
{
  public:
    explicit SectionMapGuard(sched::Mutex& mutex) : m_mutex(mutex) { sched::MutexLock(&m_mutex); }
    ~SectionMapGuard() { sched::MutexUnlock(&m_mutex); }
    SectionMapGuard(const SectionMapGuard&) = delete;
    SectionMapGuard& operator=(const SectionMapGuard&) = delete;

  private:
    sched::Mutex& m_mutex;
};

inline u64 PageUp(u64 value)
{
    return (value + (mm::kPageSize - 1)) & ~(mm::kPageSize - 1);
}

u64 ProtectToPteFlags(u32 win32_protect)
{
    constexpr u32 kPageReadonly = 0x02;
    constexpr u32 kPageReadwrite = 0x04;
    constexpr u32 kPageWritecopy = 0x08;
    constexpr u32 kPageExecute = 0x10;
    constexpr u32 kPageExecuteRead = 0x20;
    constexpr u32 kPageExecuteReadwrite = 0x40;

    u64 flags = mm::kPagePresent | mm::kPageUser;
    switch (win32_protect)
    {
    case kPageReadonly:
        flags |= mm::kPageNoExecute;
        break;
    case kPageReadwrite:
    case kPageWritecopy:
        flags |= mm::kPageWritable | mm::kPageNoExecute;
        break;
    case kPageExecute:
    case kPageExecuteRead:
        break;
    case kPageExecuteReadwrite:
        KLOG_ONCE_WARN("subsystems/win32/section", "PAGE_EXECUTE_READWRITE refused (W^X); downgraded to RW+NX");
        flags |= mm::kPageWritable | mm::kPageNoExecute;
        break;
    default:
        KLOG_WARN_V("subsystems/win32/section", "unknown PAGE_* protect, treating as RW",
                    static_cast<u64>(win32_protect));
        flags |= mm::kPageWritable | mm::kPageNoExecute;
        break;
    }
    return flags;
}

SectionKey LiveKeyForSlot(u32 slot)
{
    if (slot >= kSectionPoolCap)
    {
        return kInvalidSectionKey;
    }
    sync::SpinLockGuard guard(g_section_lock);
    const Section& section = g_pool[slot];
    if (section.state != SectionState::Live || section.refcount == 0)
    {
        return kInvalidSectionKey;
    }
    return SectionKey{slot, section.generation};
}

bool ReserveSlot(SectionKey* key_out)
{
    sync::SpinLockGuard guard(g_section_lock);
    for (u32 slot = 0; slot < kSectionPoolCap; ++slot)
    {
        Section& section = g_pool[slot];
        if (section.state != SectionState::Free || section.generation >= kSectionMaxGeneration)
        {
            continue;
        }
        ++section.generation;
        section.state = SectionState::Constructing;
        section.num_pages = 0;
        section.refcount = 0;
        section.page_protect = 0;
        section.frames = nullptr;
        section.has_writable_view = false;
        section.has_executable_view = false;
        *key_out = SectionKey{slot, section.generation};
        return true;
    }
    return false;
}

void AbortConstruction(SectionKey key)
{
    sync::SpinLockGuard guard(g_section_lock);
    Section& section = g_pool[key.slot];
    if (section.state == SectionState::Constructing && section.generation == key.generation)
    {
        section.state = SectionState::Free;
    }
}

bool PublishConstruction(SectionKey key, mm::PhysAddr* frames, u32 num_pages, u32 page_protect)
{
    sync::SpinLockGuard guard(g_section_lock);
    Section& section = g_pool[key.slot];
    if (section.state != SectionState::Constructing || section.generation != key.generation)
    {
        return false;
    }
    section.frames = frames;
    section.num_pages = num_pages;
    section.page_protect = page_protect;
    section.refcount = 1;
    section.has_writable_view = false;
    section.has_executable_view = false;
    section.state = SectionState::Live;
    return true;
}

void FreeFrameVector(mm::PhysAddr* frames, u32 num_pages)
{
    if (frames == nullptr)
    {
        return;
    }
    for (u32 page = 0; page < num_pages; ++page)
    {
        if (frames[page] != mm::kNullFrame)
        {
            mm::FreeFrame(frames[page]);
        }
    }
    mm::KFree(frames);
}

bool SnapshotLiveSection(SectionKey key, mm::PhysAddr** frames_out, u32* num_pages_out, bool* writable_out,
                         bool* executable_out)
{
    sync::SpinLockGuard guard(g_section_lock);
    const Section& section = g_pool[key.slot];
    if (section.state != SectionState::Live || section.generation != key.generation || section.refcount == 0 ||
        section.frames == nullptr || section.num_pages == 0)
    {
        return false;
    }
    *frames_out = section.frames;
    *num_pages_out = section.num_pages;
    if (writable_out != nullptr)
    {
        *writable_out = section.has_writable_view;
    }
    if (executable_out != nullptr)
    {
        *executable_out = section.has_executable_view;
    }
    return true;
}

bool MapSection(SectionKey key, mm::AddressSpace* target_as, u64 base_va, u32 view_protect, bool adopt_view_reference)
{
    if (!SectionKeyIsValid(key) || target_as == nullptr || (base_va & (mm::kPageSize - 1)) != 0)
    {
        return false;
    }
    // This operation pin keeps the frame vector alive. On the new API's
    // success path it becomes the active view reference without a gap.
    if (!SectionRetain(key))
    {
        return false;
    }

    bool mapped = false;
    {
        Section& section = g_pool[key.slot];
        SectionMapGuard map_guard(section.map_mutex);
        mm::PhysAddr* frames = nullptr;
        u32 num_pages = 0;
        bool has_writable_view = false;
        bool has_executable_view = false;
        if (SnapshotLiveSection(key, &frames, &num_pages, &has_writable_view, &has_executable_view))
        {
            constexpr u64 kUserLastPage = 0x00007FFFFFFFF000ULL;
            const u64 last_page_offset = static_cast<u64>(num_pages - 1) * mm::kPageSize;
            const u64 flags = ProtectToPteFlags(view_protect);
            const bool grants_write = (flags & mm::kPageWritable) != 0;
            const bool grants_exec = (flags & mm::kPageNoExecute) == 0;
            if (base_va <= kUserLastPage && last_page_offset <= kUserLastPage - base_va &&
                !(grants_exec && has_writable_view) && !(grants_write && has_executable_view))
            {
                mapped = mm::AddressSpaceMapBorrowedRange(target_as, base_va, frames, num_pages, flags);
                if (mapped)
                {
                    sync::SpinLockGuard guard(g_section_lock);
                    Section& live = g_pool[key.slot];
                    if (live.state == SectionState::Live && live.generation == key.generation)
                    {
                        live.has_writable_view = live.has_writable_view || grants_write;
                        live.has_executable_view = live.has_executable_view || grants_exec;
                    }
                }
            }
            else if ((grants_exec && has_writable_view) || (grants_write && has_executable_view))
            {
                KLOG_WARN("subsystems/win32/section", "SectionMap: sticky W^X history rejected aliased view");
            }
        }
    }

    if (!mapped || !adopt_view_reference)
    {
        SectionRelease(key);
    }
    return mapped;
}

bool UnmapSection(SectionKey key, mm::AddressSpace* target_as, u64 base_va, bool release_view_reference)
{
    if (!SectionKeyIsValid(key) || target_as == nullptr || (base_va & (mm::kPageSize - 1)) != 0)
    {
        return false;
    }
    // Take a temporary operation pin in addition to the caller-claimed view
    // reference. This makes stale/double-unmap a clean refusal rather than a
    // frame-vector lifetime assumption inside the address-space transaction.
    if (!SectionRetain(key))
    {
        return false;
    }

    bool unmapped = false;
    {
        Section& section = g_pool[key.slot];
        SectionMapGuard map_guard(section.map_mutex);
        mm::PhysAddr* frames = nullptr;
        u32 num_pages = 0;
        if (SnapshotLiveSection(key, &frames, &num_pages, nullptr, nullptr))
        {
            unmapped = mm::AddressSpaceUnmapBorrowedRangeExpected(target_as, base_va, frames, num_pages);
        }
    }

    SectionRelease(key); // temporary operation pin
    if (unmapped && release_view_reference)
    {
        SectionRelease(key);
    }
    return unmapped;
}

} // namespace

bool SectionCreate(u64 size_bytes, u32 page_protect, SectionKey* key_out)
{
    if (key_out == nullptr || size_bytes == 0 || size_bytes > kSectionMaxBytes)
    {
        return false;
    }
    *key_out = kInvalidSectionKey;
    SectionKey key{};
    if (!ReserveSlot(&key))
    {
        KLOG_ERROR("subsystems/win32/section", "SectionCreate: pool exhausted or every generation retired");
        return false;
    }

    const u32 num_pages = static_cast<u32>(PageUp(size_bytes) / mm::kPageSize);
    auto* frames = static_cast<mm::PhysAddr*>(mm::KMalloc(sizeof(mm::PhysAddr) * num_pages));
    if (frames == nullptr)
    {
        AbortConstruction(key);
        return false;
    }
    for (u32 page = 0; page < num_pages; ++page)
    {
        frames[page] = mm::kNullFrame;
    }
    for (u32 page = 0; page < num_pages; ++page)
    {
        auto frame_result = mm::AllocateFrame();
        if (!frame_result)
        {
            FreeFrameVector(frames, num_pages);
            AbortConstruction(key);
            return false;
        }
        frames[page] = frame_result.value();
        auto* bytes = static_cast<u8*>(mm::PhysToVirt(frames[page]));
        for (u64 offset = 0; offset < mm::kPageSize; ++offset)
        {
            bytes[offset] = 0;
        }
    }
    if (!PublishConstruction(key, frames, num_pages, page_protect))
    {
        FreeFrameVector(frames, num_pages);
        AbortConstruction(key);
        return false;
    }
    *key_out = key;
    return true;
}

bool SectionRetain(SectionKey key)
{
    if (!SectionKeyIsValid(key))
    {
        return false;
    }
    sync::SpinLockGuard guard(g_section_lock);
    Section& section = g_pool[key.slot];
    const u32 refs = static_cast<u32>(section.refcount);
    if (section.state != SectionState::Live || section.generation != key.generation || refs == 0 ||
        refs == static_cast<u32>(~0U))
    {
        return false;
    }
    ++section.refcount;
    return true;
}

void SectionRelease(SectionKey key)
{
    if (!SectionKeyIsValid(key))
    {
        return;
    }
    mm::PhysAddr* doomed_frames = nullptr;
    u32 doomed_pages = 0;
    {
        sync::SpinLockGuard guard(g_section_lock);
        Section& section = g_pool[key.slot];
        if (section.state != SectionState::Live || section.generation != key.generation || section.refcount == 0)
        {
            return;
        }
        --section.refcount;
        if (section.refcount != 0)
        {
            return;
        }
        section.state = SectionState::Retiring;
        doomed_frames = section.frames;
        doomed_pages = section.num_pages;
        section.frames = nullptr;
        section.num_pages = 0;
        section.page_protect = 0;
        section.has_writable_view = false;
        section.has_executable_view = false;
    }

    FreeFrameVector(doomed_frames, doomed_pages);

    sync::SpinLockGuard guard(g_section_lock);
    Section& section = g_pool[key.slot];
    if (section.state == SectionState::Retiring && section.generation == key.generation)
    {
        section.state = SectionState::Free;
    }
}

bool SectionMapAndRetainView(SectionKey key, mm::AddressSpace* target_as, u64 base_va, u32 view_protect)
{
    return MapSection(key, target_as, base_va, view_protect, true);
}

bool SectionUnmapAndReleaseView(SectionKey key, mm::AddressSpace* target_as, u64 base_va)
{
    return UnmapSection(key, target_as, base_va, true);
}

u64 SectionViewSize(SectionKey key)
{
    if (!SectionKeyIsValid(key))
    {
        return 0;
    }
    sync::SpinLockGuard guard(g_section_lock);
    const Section& section = g_pool[key.slot];
    if (section.state != SectionState::Live || section.generation != key.generation || section.refcount == 0)
    {
        return 0;
    }
    return static_cast<u64>(section.num_pages) * mm::kPageSize;
}

void SectionLifetimeSelfTest()
{
    auto expect = [](bool condition, const char* message)
    {
        if (!condition)
        {
            core::Panic("win32/section-selftest", message);
        }
    };

    SectionKey first{};
    expect(SectionCreate(2 * mm::kPageSize, 0x04, &first), "initial section create failed");
    expect(SectionViewSize(first) == 2 * mm::kPageSize, "initial section size mismatch");
    auto as_result = mm::AddressSpaceCreate(mm::kFrameBudgetTrusted);
    expect(static_cast<bool>(as_result), "address-space create failed");
    mm::AddressSpace* as = as_result.value();
    constexpr u64 kViewBase = 0x000000009FFFF000ULL;
    expect(SectionMapAndRetainView(first, as, kViewBase, 0x04), "transactional view map failed");

    // Drop the handle reference first. The active view must keep the object
    // alive until its exact expected-frame unmap completes.
    SectionRelease(first);
    expect(SectionViewSize(first) == 2 * mm::kPageSize, "view did not retain section lifetime");
    expect(SectionUnmapAndReleaseView(first, as, kViewBase), "transactional view unmap failed");
    expect(!SectionRetain(first), "retired section generation remained retainable");
    mm::AddressSpaceRelease(as);

    SectionKey second{};
    expect(SectionCreate(mm::kPageSize, 0x02, &second), "recycled section create failed");
    expect(second.slot == first.slot && second.generation == first.generation + 1,
           "recycled slot did not advance generation");
    SectionRelease(first); // stale release must not affect the new generation.
    expect(SectionViewSize(second) == mm::kPageSize, "stale release damaged recycled section");
    SectionRelease(second);
    expect(!SectionRetain(second), "released recycled generation remained retainable");
    arch::SerialWrite("[section-lifetime-selftest] PASS\n");
}

// Temporary compatibility wrappers; see section.h.
i32 SectionCreate(u64 size_bytes, u32 page_protect)
{
    SectionKey key{};
    return SectionCreate(size_bytes, page_protect, &key) ? static_cast<i32>(key.slot) : -1;
}

void SectionRetain(u32 idx)
{
    (void)SectionRetain(LiveKeyForSlot(idx));
}

void SectionRelease(u32 idx)
{
    SectionRelease(LiveKeyForSlot(idx));
}

bool SectionMap(u32 idx, mm::AddressSpace* target_as, u64 base_va, u32 view_protect)
{
    return MapSection(LiveKeyForSlot(idx), target_as, base_va, view_protect, false);
}

bool SectionUnmap(u32 idx, mm::AddressSpace* target_as, u64 base_va)
{
    return UnmapSection(LiveKeyForSlot(idx), target_as, base_va, false);
}

u64 SectionViewSize(u32 idx)
{
    return SectionViewSize(LiveKeyForSlot(idx));
}

i32 SectionUnmapAtVa(mm::AddressSpace* target_as, u64 base_va)
{
    if (target_as == nullptr || (base_va & (mm::kPageSize - 1)) != 0)
    {
        return -1;
    }
    for (u32 slot = 0; slot < kSectionPoolCap; ++slot)
    {
        const SectionKey key = LiveKeyForSlot(slot);
        if (SectionKeyIsValid(key) && UnmapSection(key, target_as, base_va, false))
        {
            return static_cast<i32>(slot);
        }
    }
    return -1;
}

i32 LookupSectionHandle(core::Process* caller, u64 handle)
{
    if (caller == nullptr || handle < core::Process::kWin32SectionBase)
    {
        return -1;
    }
    const u64 slot = handle - core::Process::kWin32SectionBase;
    if (slot >= core::Process::kWin32SectionCap || !caller->win32_section_handles[slot].in_use)
    {
        return -1;
    }
    return static_cast<i32>(caller->win32_section_handles[slot].pool_index);
}

} // namespace duetos::subsystems::win32::section
