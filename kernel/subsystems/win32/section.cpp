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
    u32 max_page_protect;
    mm::PhysAddr* frames;
    core::ResourceSectionChargeKey resource_charge;
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

enum SectionAccess : u8
{
    kSectionAccessRead = 1U << 0,
    kSectionAccessWrite = 1U << 1,
    kSectionAccessExecute = 1U << 2,
};

struct DecodedProtection
{
    u64 pte_flags;
    u8 access;
};

bool DecodeProtection(u32 win32_protect, DecodedProtection* decoded_out)
{
    constexpr u32 kPageReadonly = 0x02;
    constexpr u32 kPageReadwrite = 0x04;
    constexpr u32 kPageWritecopy = 0x08;
    constexpr u32 kPageExecute = 0x10;
    constexpr u32 kPageExecuteRead = 0x20;
    constexpr u32 kPageExecuteReadwrite = 0x40;
    constexpr u32 kPageExecuteWritecopy = 0x80;

    if (decoded_out == nullptr)
    {
        return false;
    }
    DecodedProtection decoded{mm::kPagePresent | mm::kPageUser, 0};
    switch (win32_protect)
    {
    case kPageReadonly:
        decoded.pte_flags |= mm::kPageNoExecute;
        decoded.access = kSectionAccessRead;
        break;
    case kPageReadwrite:
        decoded.pte_flags |= mm::kPageWritable | mm::kPageNoExecute;
        decoded.access = kSectionAccessRead | kSectionAccessWrite;
        break;
    case kPageExecute:
        // x86_64 has no execute-only user PTE. Keep the logical access as X
        // for maximum-subset checks; the architectural mapping is RX, as on
        // Windows/x86.
        decoded.access = kSectionAccessExecute;
        break;
    case kPageExecuteRead:
        decoded.access = kSectionAccessRead | kSectionAccessExecute;
        break;
    case kPageWritecopy:
    case kPageExecuteReadwrite:
    case kPageExecuteWritecopy:
        // No COW machinery exists, and W+X is forbidden. Never silently
        // broaden/downgrade these requests into a different protection.
        return false;
    default:
        return false;
    }
    *decoded_out = decoded;
    return true;
}

bool ProtectionIsSubset(const DecodedProtection& view, const DecodedProtection& maximum)
{
    return (view.access & static_cast<u8>(~maximum.access)) == 0;
}

bool ReserveSlot(core::ResourceSectionPoolClass pool_class, SectionKey* key_out)
{
    sync::SpinLockGuard guard(g_section_lock);
    auto reserve_range = [key_out](u32 begin, u32 end)
    {
        for (u32 slot = begin; slot < end; ++slot)
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
            section.max_page_protect = 0;
            section.frames = nullptr;
            section.resource_charge = core::kInvalidResourceSectionChargeKey;
            section.has_writable_view = false;
            section.has_executable_view = false;
            *key_out = SectionKey{slot, section.generation};
            return true;
        }
        return false;
    };

    if (pool_class == core::ResourceSectionPoolClass::AuthenticatedService &&
        reserve_range(core::kResourceSectionOrdinaryPoolCapacity, kSectionPoolCap))
    {
        return true;
    }
    return reserve_range(0, core::kResourceSectionOrdinaryPoolCapacity);
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

bool PublishConstruction(SectionKey key, mm::PhysAddr* frames, u32 num_pages, u32 max_page_protect,
                         core::ResourceSectionChargeKey resource_charge)
{
    sync::SpinLockGuard guard(g_section_lock);
    Section& section = g_pool[key.slot];
    if (section.state != SectionState::Constructing || section.generation != key.generation)
    {
        return false;
    }
    section.frames = frames;
    section.num_pages = num_pages;
    section.max_page_protect = max_page_protect;
    section.resource_charge = resource_charge;
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

void RollbackResourceCharge(core::ResourceSectionChargeKey& charge, const char* failure)
{
    if (!core::ResourceSectionChargeKeyIsValid(charge))
        return;
    if (!core::ResourceDomainReleaseSection(&charge))
        core::Panic("subsystems/win32/section", failure);
}

bool SnapshotLiveSection(SectionKey key, mm::PhysAddr** frames_out, u32* num_pages_out, u32* max_page_protect_out,
                         bool* writable_out, bool* executable_out)
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
    if (max_page_protect_out != nullptr)
    {
        *max_page_protect_out = section.max_page_protect;
    }
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

bool MapSection(SectionKey key, mm::AddressSpace* target_as, u64 base_va, u32 view_protect)
{
    DecodedProtection view{};
    if (!SectionKeyIsValid(key) || target_as == nullptr || (base_va & (mm::kPageSize - 1)) != 0 ||
        !DecodeProtection(view_protect, &view))
    {
        return false;
    }
    // This operation pin keeps the frame vector alive and becomes the active
    // view reference on success without a lifetime gap.
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
        u32 max_page_protect = 0;
        bool has_writable_view = false;
        bool has_executable_view = false;
        DecodedProtection maximum{};
        if (SnapshotLiveSection(key, &frames, &num_pages, &max_page_protect, &has_writable_view,
                                &has_executable_view) &&
            DecodeProtection(max_page_protect, &maximum) && ProtectionIsSubset(view, maximum))
        {
            constexpr u64 kUserLastPage = 0x00007FFFFFFFF000ULL;
            const u64 last_page_offset = static_cast<u64>(num_pages - 1) * mm::kPageSize;
            const u64 flags = view.pte_flags;
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

    if (!mapped)
    {
        SectionRelease(key);
    }
    return mapped;
}

bool UnmapSection(SectionKey key, mm::AddressSpace* target_as, u64 base_va)
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
        if (SnapshotLiveSection(key, &frames, &num_pages, nullptr, nullptr, nullptr))
        {
            unmapped = mm::AddressSpaceUnmapBorrowedRangeExpected(target_as, base_va, frames, num_pages);
        }
    }

    SectionRelease(key); // temporary operation pin
    if (unmapped)
    {
        SectionRelease(key);
    }
    return unmapped;
}

} // namespace

bool SectionCreate(core::ResourceDomainKey domain, u64 size_bytes, u32 page_protect, SectionKey* key_out)
{
    if (key_out == nullptr)
    {
        return false;
    }
    *key_out = kInvalidSectionKey;
    DecodedProtection maximum{};
    if (size_bytes == 0 || size_bytes > kSectionMaxBytes || !DecodeProtection(page_protect, &maximum))
    {
        return false;
    }
    const u32 num_pages = static_cast<u32>(PageUp(size_bytes) / mm::kPageSize);
    core::ResourceSectionChargeKey resource_charge = core::kInvalidResourceSectionChargeKey;
    core::ResourceSectionPoolClass pool_class = core::ResourceSectionPoolClass::Ordinary;
    if (!core::ResourceDomainTryChargeSection(domain, num_pages, &resource_charge, &pool_class))
    {
        KLOG_WARN("subsystems/win32/section", "SectionCreate: resource-domain quota refused allocation");
        return false;
    }

    SectionKey key{};
    if (!ReserveSlot(pool_class, &key))
    {
        RollbackResourceCharge(resource_charge, "SectionCreate slot-refusal charge rollback failed");
        KLOG_ERROR("subsystems/win32/section", "SectionCreate: pool exhausted or every generation retired");
        return false;
    }

    auto* frames = static_cast<mm::PhysAddr*>(mm::KMalloc(sizeof(mm::PhysAddr) * num_pages));
    if (frames == nullptr)
    {
        RollbackResourceCharge(resource_charge, "SectionCreate metadata-OOM charge rollback failed");
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
            RollbackResourceCharge(resource_charge, "SectionCreate frame-OOM charge rollback failed");
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
    if (!PublishConstruction(key, frames, num_pages, page_protect, resource_charge))
    {
        FreeFrameVector(frames, num_pages);
        RollbackResourceCharge(resource_charge, "SectionCreate publication charge rollback failed");
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
    core::ResourceSectionChargeKey doomed_charge = core::kInvalidResourceSectionChargeKey;
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
        doomed_charge = section.resource_charge;
        section.frames = nullptr;
        section.num_pages = 0;
        section.max_page_protect = 0;
        section.resource_charge = core::kInvalidResourceSectionChargeKey;
        section.has_writable_view = false;
        section.has_executable_view = false;
    }

    FreeFrameVector(doomed_frames, doomed_pages);

    // The exact charge remains live through the object's final reference and
    // frame teardown. Never publish this physical slot as Free unless the
    // matching non-wrapping charge was consumed successfully; a mismatch is
    // internal corruption and must fail closed with the slot Retiring.
    if (!core::ResourceDomainReleaseSection(&doomed_charge))
    {
        core::Panic("subsystems/win32/section", "final resource-domain charge release failed");
    }

    sync::SpinLockGuard guard(g_section_lock);
    Section& section = g_pool[key.slot];
    if (section.state == SectionState::Retiring && section.generation == key.generation)
    {
        section.state = SectionState::Free;
    }
}

bool SectionViewProtectionIsCompatible(SectionKey key, u32 view_protect)
{
    DecodedProtection view{};
    if (!SectionKeyIsValid(key) || !DecodeProtection(view_protect, &view))
    {
        return false;
    }
    sync::SpinLockGuard guard(g_section_lock);
    const Section& section = g_pool[key.slot];
    DecodedProtection maximum{};
    return section.state == SectionState::Live && section.generation == key.generation && section.refcount != 0 &&
           DecodeProtection(section.max_page_protect, &maximum) && ProtectionIsSubset(view, maximum);
}

bool SectionMapAndRetainView(SectionKey key, mm::AddressSpace* target_as, u64 base_va, u32 view_protect)
{
    return MapSection(key, target_as, base_va, view_protect);
}

bool SectionUnmapAndReleaseView(SectionKey key, mm::AddressSpace* target_as, u64 base_va)
{
    return UnmapSection(key, target_as, base_va);
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

    core::ResourceDomainKey lifetime_domain = core::kInvalidResourceDomainKey;
    expect(core::ResourceDomainCreateTrusted(&lifetime_domain), "lifetime resource-domain create failed");

    constexpr u32 kRejectedCreateProtections[] = {
        0x00,  // no protection selected
        0x01,  // PAGE_NOACCESS is not representable as a present view
        0x08,  // PAGE_WRITECOPY needs COW
        0x40,  // PAGE_EXECUTE_READWRITE violates W^X
        0x80,  // PAGE_EXECUTE_WRITECOPY needs COW and violates W^X
        0x104, // PAGE_READWRITE | unsupported modifier
    };
    for (const u32 rejected_protect : kRejectedCreateProtections)
    {
        SectionKey rejected{0, 1};
        expect(!SectionCreate(lifetime_domain, mm::kPageSize, rejected_protect, &rejected) &&
                   rejected == kInvalidSectionKey,
               "unsupported Section maximum protection was accepted");
    }

    DecodedProtection read_only{};
    DecodedProtection read_write{};
    DecodedProtection execute_only{};
    DecodedProtection execute_read{};
    expect(DecodeProtection(0x02, &read_only) && (read_only.pte_flags & mm::kPageWritable) == 0 &&
               (read_only.pte_flags & mm::kPageNoExecute) != 0,
           "PAGE_READONLY decoder flags drifted");
    expect(DecodeProtection(0x04, &read_write) && (read_write.pte_flags & mm::kPageWritable) != 0 &&
               (read_write.pte_flags & mm::kPageNoExecute) != 0,
           "PAGE_READWRITE decoder flags drifted");
    expect(DecodeProtection(0x10, &execute_only) && (execute_only.pte_flags & mm::kPageWritable) == 0 &&
               (execute_only.pte_flags & mm::kPageNoExecute) == 0,
           "PAGE_EXECUTE decoder flags drifted");
    expect(DecodeProtection(0x20, &execute_read) && (execute_read.pte_flags & mm::kPageWritable) == 0 &&
               (execute_read.pte_flags & mm::kPageNoExecute) == 0,
           "PAGE_EXECUTE_READ decoder flags drifted");
    expect(ProtectionIsSubset(execute_only, execute_read) && !ProtectionIsSubset(execute_read, execute_only) &&
               ProtectionIsSubset(read_only, execute_read) && !ProtectionIsSubset(read_write, execute_read),
           "Section protection subset lattice drifted");

    SectionKey first{};
    expect(SectionCreate(lifetime_domain, 2 * mm::kPageSize, 0x04, &first), "initial section create failed");
    core::ResourceDomainSnapshot lifetime_snapshot{};
    expect(core::ResourceDomainInspectExact(lifetime_domain, &lifetime_snapshot) &&
               lifetime_snapshot.section_objects == 1 && lifetime_snapshot.section_pages == 2,
           "initial Section charge was not published to its domain");
    expect(SectionViewSize(first) == 2 * mm::kPageSize, "initial section size mismatch");
    expect(SectionViewProtectionIsCompatible(first, 0x02), "RW maximum rejected read-only subset");
    expect(SectionViewProtectionIsCompatible(first, 0x04), "RW maximum rejected exact RW view");
    expect(!SectionViewProtectionIsCompatible(first, 0x08), "RW maximum accepted COW view");
    expect(!SectionViewProtectionIsCompatible(first, 0x10), "RW maximum accepted executable view");
    expect(!SectionViewProtectionIsCompatible(first, 0x40), "RW maximum accepted writable+executable view");
    auto as_result = mm::AddressSpaceCreate(mm::kFrameBudgetTrusted);
    expect(static_cast<bool>(as_result), "address-space create failed");
    mm::AddressSpace* as = as_result.value();
    constexpr u64 kViewBase = 0x000000009FFFF000ULL;
    expect(!SectionMapAndRetainView(first, as, kViewBase + 1, 0x04), "unaligned Section view was accepted");
    expect(!SectionMapAndRetainView(first, as, kViewBase, 0x20), "view exceeded Section maximum access");
    expect(SectionMapAndRetainView(first, as, kViewBase, 0x04), "transactional view map failed");

    // A different live Section key must not be able to clear this view merely
    // because it names the same VA. Exact expected-frame comparison keeps the
    // original PTE and both objects' references intact on mismatch.
    SectionKey wrong_key{};
    expect(SectionCreate(lifetime_domain, mm::kPageSize, 0x04, &wrong_key), "mismatch Section create failed");
    expect(!SectionUnmapAndReleaseView(wrong_key, as, kViewBase),
           "foreign Section key cleared an existing borrowed view");
    expect(mm::AddressSpaceProbePte(as, kViewBase) != mm::kNullFrame,
           "failed exact unmap disturbed the original Section PTE");
    SectionRelease(wrong_key);

    // Drop the handle reference first. The active view must keep the object
    // alive until its exact expected-frame unmap completes.
    SectionRelease(first);
    expect(core::ResourceDomainInspectExact(lifetime_domain, &lifetime_snapshot) &&
               lifetime_snapshot.section_objects == 1 && lifetime_snapshot.section_pages == 2,
           "handle close released a Section charge still pinned by a live view");
    expect(SectionViewSize(first) == 2 * mm::kPageSize, "view did not retain section lifetime");
    expect(SectionUnmapAndReleaseView(first, as, kViewBase), "transactional view unmap failed");
    expect(core::ResourceDomainInspectExact(lifetime_domain, &lifetime_snapshot) &&
               lifetime_snapshot.section_objects == 0 && lifetime_snapshot.section_pages == 0,
           "final Section view release did not consume its exact charge");
    expect(!SectionRetain(first), "retired section generation remained retainable");
    mm::AddressSpaceRelease(as);

    SectionKey second{};
    expect(SectionCreate(lifetime_domain, mm::kPageSize, 0x02, &second), "recycled section create failed");
    expect(second.slot == first.slot && second.generation == first.generation + 1,
           "recycled slot did not advance generation");
    SectionRelease(first); // stale release must not affect the new generation.
    expect(SectionViewSize(second) == mm::kPageSize, "stale release damaged recycled section");
    expect(SectionViewProtectionIsCompatible(second, 0x02), "read-only maximum rejected exact view");
    expect(!SectionViewProtectionIsCompatible(second, 0x04), "read-only maximum accepted writable view");
    SectionRelease(second);
    expect(!SectionRetain(second), "released recycled generation remained retainable");

    SectionKey executable{};
    expect(SectionCreate(lifetime_domain, mm::kPageSize, 0x20, &executable), "executable-read section create failed");
    expect(SectionViewProtectionIsCompatible(executable, 0x02), "RX maximum rejected read-only subset");
    expect(SectionViewProtectionIsCompatible(executable, 0x10), "RX maximum rejected execute-only subset");
    expect(SectionViewProtectionIsCompatible(executable, 0x20), "RX maximum rejected exact RX view");
    expect(!SectionViewProtectionIsCompatible(executable, 0x04), "RX maximum accepted writable view");
    auto exec_as_result = mm::AddressSpaceCreate(mm::kFrameBudgetTrusted);
    expect(static_cast<bool>(exec_as_result), "executable-view address-space create failed");
    mm::AddressSpace* exec_as = exec_as_result.value();
    expect(SectionMapAndRetainView(executable, exec_as, kViewBase, 0x10),
           "execute-only subset failed to map transactionally");
    expect(SectionUnmapAndReleaseView(executable, exec_as, kViewBase),
           "execute-only subset failed to unmap transactionally");
    mm::AddressSpaceRelease(exec_as);
    SectionRelease(executable);
    expect(!SectionRetain(executable), "released executable section remained retainable");

    expect(core::ResourceDomainRelease(lifetime_domain), "lifetime resource-domain release failed");

    // Physical partition regression: while every row is free, authenticated
    // services must prefer [6,8), preserving [0,6) for ordinary domains.
    // Six one-page Sections across three ordinary spawn roots must then fill
    // exactly that ordinary partition; a seventh root must fail and roll its
    // prospective charge back instead of crossing into reserved capacity.
    core::ResourceDomainKey service_domain = core::kInvalidResourceDomainKey;
    SectionKey service_sections[core::kResourceSectionReservedServiceSlots]{};
    expect(core::ResourceDomainCreateAuthenticatedService(&service_domain), "partition service-domain create failed");
    for (u32 index = 0; index < core::kResourceSectionReservedServiceSlots; ++index)
    {
        expect(SectionCreate(service_domain, mm::kPageSize, 0x04, &service_sections[index]),
               "authenticated service could not use reserved Section capacity");
        expect(service_sections[index].slot >= core::kResourceSectionOrdinaryPoolCapacity,
               "authenticated service did not prefer its reserved Section partition");
    }

    core::ResourceDomainKey ordinary_domains[4]{};
    SectionKey ordinary_sections[6]{};
    for (u32 domain_index = 0; domain_index < 4; ++domain_index)
    {
        expect(core::ResourceDomainCreateTrusted(&ordinary_domains[domain_index]),
               "partition ordinary-domain create failed");
    }
    for (u32 section_index = 0; section_index < 6; ++section_index)
    {
        const u32 domain_index = section_index / 2;
        expect(SectionCreate(ordinary_domains[domain_index], mm::kPageSize, 0x04, &ordinary_sections[section_index]),
               "ordinary Section could not fill its six-slot partition");
        expect(ordinary_sections[section_index].slot < core::kResourceSectionOrdinaryPoolCapacity,
               "ordinary Section escaped into a service-reserved slot");
    }
    SectionKey refused_ordinary = kInvalidSectionKey;
    expect(!SectionCreate(ordinary_domains[3], mm::kPageSize, 0x04, &refused_ordinary) &&
               refused_ordinary == kInvalidSectionKey,
           "ordinary Section consumed service-reserved capacity");
    core::ResourceDomainSnapshot refused_snapshot{};
    expect(core::ResourceDomainInspectExact(ordinary_domains[3], &refused_snapshot) &&
               refused_snapshot.section_objects == 0 && refused_snapshot.section_pages == 0,
           "ordinary partition refusal leaked its resource charge");

    for (SectionKey& section : service_sections)
        SectionRelease(section);
    expect(core::ResourceDomainRelease(service_domain), "partition service-domain release failed");
    for (SectionKey& section : ordinary_sections)
        SectionRelease(section);
    for (core::ResourceDomainKey& domain : ordinary_domains)
        expect(core::ResourceDomainRelease(domain), "partition ordinary-domain release failed");

    arch::SerialWrite("[section-lifetime-selftest] PASS\n");
}

} // namespace duetos::subsystems::win32::section
