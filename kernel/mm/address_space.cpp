/*
 * DuetOS — per-process address space: implementation.
 *
 * Companion to address_space.h — see there for the AddressSpace
 * struct and the kernel-half vs user-half split rules.
 *
 * WHAT
 *   An `AddressSpace` is one PML4 root + the bookkeeping needed
 *   to map/unmap pages into it. The kernel half (top 256 PML4
 *   entries) is shared across every AddressSpace via shared
 *   high-half tables installed at boot; the user half is
 *   per-process and zeroed at create time.
 *
 * HOW
 *   `Create` allocates a fresh PML4 frame, copies the kernel-
 *   half pointers from the boot PML4, and zeroes the user
 *   half. `Activate` writes CR3. User mappings are mutated through a
 *   task-context transaction lock; their page-table and owned-frame
 *   ledger commits remain bounded under an IRQ-safe structural lock.
 *
 *   Teardown (`Release`) drains owned leaf frames from the ledger,
 *   then frees the remaining user-half page-table tree and PML4.
 *   Empty intermediate tables are pruned earlier on unmap. The kernel
 *   half is left alone because it is shared.
 */

#include "mm/address_space.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "log/klog.h"
#include "core/panic.h"
#include "cpu/critical.h"
#include "cpu/ipi_call.h"
#include "cpu/percpu.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "util/string.h"

namespace duetos::mm
{

namespace
{

// Same magic numbers paging.cpp uses; duplicated rather than exported
// so paging.cpp's internal constants stay internal. If they ever
// drift, the static_asserts below catch it.
constexpr u64 kEntriesPerTable = 512;
constexpr u64 kAddrMask = 0x000FFFFFFFFFF000ULL;
constexpr u64 kKernelHalfFirstIndex = 256;
// A consecutive 1024-page range spans at most three PTs, two PDs, and two
// PDPTs, so seven prepared/retired intermediate frames are sufficient.
constexpr u8 kMaxBorrowedRangePageTables = 7;

// Lifetime counters — maintained inside the public release/create
// paths. Plain globals because v0 has no AS allocator concurrency.
// Saturating: class BB (wrap-to-zero defense gap). Reported by
// inspect / health; never used for modular arithmetic.
constinit util::SatU64 g_created = 0;
constinit util::SatU64 g_destroyed = 0;
constinit util::SatU64 g_cr3_switches = 0;

// One boot-global reservation identity source. This deliberately does not
// live in AddressSpace: a per-AS sequence combined with an owner pointer can
// suffer allocator-address ABA after the old AS is destroyed and a new AS is
// allocated at the same address. UINT64_MAX is a permanent exhaustion
// sentinel and is never issued, so the source cannot wrap or reuse a value.
constinit u64 g_next_reservation_token = 1;

// Separate globally unique identities for short-lived write leases.  Keeping
// this source outside AddressSpace prevents allocator-address ABA: a stale
// copied lease can never match a row in a later AS allocated at the same VA.
// UINT64_MAX is a permanent exhaustion sentinel and is never issued.
constinit u64 g_next_write_lease_token = 1;

[[noreturn]] void PanicAs(const char* message, u64 value)
{
    core::PanicWithValue("mm/as", message, value);
}

u64 AllocateReservationTokenValue()
{
    u64 current = __atomic_load_n(&g_next_reservation_token, __ATOMIC_ACQUIRE);
    for (;;)
    {
        if (current == 0)
        {
            PanicAs("global reservation token source wrapped", current);
        }
        if (current == ~u64{0})
        {
            return 0;
        }
        const u64 next = current + 1;
        if (__atomic_compare_exchange_n(&g_next_reservation_token, &current, next, /*weak=*/false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            return current;
        }
    }
}

u64 AllocateWriteLeaseTokenValue()
{
    u64 current = __atomic_load_n(&g_next_write_lease_token, __ATOMIC_ACQUIRE);
    for (;;)
    {
        if (current == 0)
        {
            PanicAs("global write-lease token source wrapped", current);
        }
        if (current == ~u64{0})
        {
            return 0;
        }
        const u64 next = current + 1;
        if (__atomic_compare_exchange_n(&g_next_write_lease_token, &current, next, /*weak=*/false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            return current;
        }
    }
}

// Walker that mirrors WalkToPte in paging.cpp but operates on an
// arbitrary PML4 root — needed both for installing user mappings
// into a non-active AS and for tearing down user-half tables at
// destroy time. Can't share the paging.cpp implementation because
// it's anonymous-namespace local; the duplication is small (~30
// lines) and the alternative (exporting WalkToPte) would expand
// paging.h's surface for one consumer.
inline u64 IndexPml4(u64 v)
{
    return (v >> 39) & 0x1FF;
}
inline u64 IndexPdpt(u64 v)
{
    return (v >> 30) & 0x1FF;
}
inline u64 IndexPd(u64 v)
{
    return (v >> 21) & 0x1FF;
}
inline u64 IndexPt(u64 v)
{
    return (v >> 12) & 0x1FF;
}

inline void Invlpg(u64 v)
{
    asm volatile("invlpg (%0)" : : "r"(v) : "memory");
}

struct UserTlbRange
{
    u64 start;
    u64 end;
};

// IPI-call callback. It deliberately does not inspect current_as: a target
// may switch away after the active-mask snapshot, but that CR3 reload already
// flushed the old non-PCID translations and invalidating the new AS is benign.
void InvalidateUserTlbRange(void* opaque)
{
    const auto* range = static_cast<const UserTlbRange*>(opaque);
    for (u64 virt = range->start; virt < range->end; virt += kPageSize)
    {
        Invlpg(virt);
    }
}

void ConfirmedUserTlbShootdown(AddressSpace* as, u64 start, u64 end)
{
    KASSERT(start < end && ((start | end) & (kPageSize - 1)) == 0, "mm/as", "invalid confirmed user TLB range");

    // Pin the requestor while retaining IF=1. Two CPUs may enter this barrier
    // together; each must remain able to drain the other's IPI-call mailbox.
    cpu::CriticalGuard critical_guard;
    cpu::PerCpu* self = cpu::CurrentCpu();
    const u32 self_id = (self != nullptr) ? self->cpu_id : 0u;

    UserTlbRange range{.start = start, .end = end};
    if ((as == nullptr && AddressSpaceCurrent() == nullptr) || AddressSpaceCurrent() == as)
    {
        InvalidateUserTlbRange(&range);
    }

    const u32 limit = arch::SmpCpuIdLimit();
    if (limit > acpi::kMaxCpus)
    {
        PanicAs("confirmed user TLB CPU limit exceeds target array", limit);
    }
    const u32 active_mask = (as != nullptr) ? __atomic_load_n(&as->active_cpu_mask, __ATOMIC_ACQUIRE) : ~u32{0};
    u32 target_ids[acpi::kMaxCpus] = {};
    u32 target_count = 0;
    for (u32 id = 0; id < limit; ++id)
    {
        const u32 bit = u32{1} << id;
        if (id == self_id || (active_mask & bit) == 0)
        {
            continue;
        }
        cpu::PerCpu* peer = arch::SmpGetPercpu(id);
        if (peer != nullptr && __atomic_load_n(&peer->tlb_ipi_ready, __ATOMIC_ACQUIRE))
        {
            target_ids[target_count++] = id;
        }
    }
    if (target_count == 0)
    {
        return;
    }

    constexpr u64 kRflagsIf = 1ULL << 9;
    if ((arch::ReadRflags() & kRflagsIf) == 0)
    {
        PanicAs("confirmed user TLB shootdown with interrupts disabled", self_id);
    }

    for (u32 target_index = 0; target_index < target_count; ++target_index)
    {
        const u32 id = target_ids[target_index];
        while (!cpu::IpiCallOne(id, &InvalidateUserTlbRange, &range, /*wait=*/true))
        {
            // Mailbox pressure is transient and never grants permission to
            // recycle a frame behind a peer's stale user translation.
            asm volatile("pause" ::: "memory");
        }
    }
}

// Allocate a fresh page-table frame, zero it, return its kernel
// virtual alias, or nullptr when the physical frame pool is dry.
// Returning null (instead of panicking) lets reserve preparation fail
// the single user mapping gracefully before structural commit — a
// userland exec hitting the frame ceiling must kill that process, never
// halt the kernel.
u64* AllocateTable()
{
    auto frame_r = AllocateFrame();
    if (!frame_r)
    {
        return nullptr;
    }
    const PhysAddr frame = frame_r.value();
    auto* table = static_cast<u64*>(PhysToVirt(frame));
    for (u64 i = 0; i < kEntriesPerTable; ++i)
    {
        table[i] = 0;
    }
    return table;
}

class AddressSpaceMutationGuard
{
  public:
    explicit AddressSpaceMutationGuard(const AddressSpace& as) : m_lock(as.mutation_lock)
    {
        KASSERT(sched::CurrentTask() != nullptr, "mm/as", "address-space mutation before scheduler initialization");
        sched::MutexLock(&m_lock);
    }

    ~AddressSpaceMutationGuard() { sched::MutexUnlock(&m_lock); }

    AddressSpaceMutationGuard(const AddressSpaceMutationGuard&) = delete;
    AddressSpaceMutationGuard& operator=(const AddressSpaceMutationGuard&) = delete;

  private:
    sched::Mutex& m_lock;
};

// A map transaction prepares every page-table frame before taking the
// IRQ-saving regions_lock. Commit consumes the zeroed tables without
// calling the frame allocator; failure cleanup likewise runs after the
// structural lock has been released.
struct PageTableReserve
{
    u64* tables[kMaxBorrowedRangePageTables]{};
    u8 count{};
    u8 next{};
};

void ReleasePageTableReserve(PageTableReserve& reserve)
{
    for (u8 i = 0; i < reserve.count; ++i)
    {
        if (reserve.tables[i] != nullptr)
        {
            FreeFrame(VirtToPhys(reserve.tables[i]));
            reserve.tables[i] = nullptr;
        }
    }
    reserve.count = 0;
    reserve.next = 0;
}

bool PreparePageTableReserve(PageTableReserve& reserve, u8 count)
{
    KASSERT(count <= kMaxBorrowedRangePageTables, "mm/as", "page-table reserve exceeds bounded transaction cap");
    for (u8 i = 0; i < count; ++i)
    {
        u64* table = AllocateTable();
        if (table == nullptr)
        {
            ReleasePageTableReserve(reserve);
            return false;
        }
        reserve.tables[reserve.count++] = table;
    }
    return true;
}

u64* TakeReservedTable(PageTableReserve& reserve)
{
    KASSERT(reserve.next < reserve.count, "mm/as", "page-table transaction exhausted its reserve");
    u64* table = reserve.tables[reserve.next];
    reserve.tables[reserve.next] = nullptr;
    ++reserve.next;
    return table;
}

u64* WalkToPteIn(u64* pml4, u64 virt, PageTableReserve* reserve);

// Count how many intermediate tables are absent on the path to `virt`.
// Caller holds regions_lock, so the count remains valid until commit while
// the outer mutation_lock excludes every page-table writer.
u8 MissingTableCount(u64* pml4, u64 virt)
{
    const u64 i4 = IndexPml4(virt);
    const u64 i3 = IndexPdpt(virt);
    const u64 i2 = IndexPd(virt);

    const u64 pml4_entry = pml4[i4];
    if ((pml4_entry & kPagePresent) == 0)
    {
        return 3;
    }
    auto* pdpt = static_cast<u64*>(PhysToVirt(pml4_entry & kAddrMask));
    const u64 pdpt_entry = pdpt[i3];
    if ((pdpt_entry & kPagePresent) == 0)
    {
        return 2;
    }
    if ((pdpt_entry & kPageHugeOrPat) != 0)
    {
        PanicAs("AS walker hit a 1 GiB PS page", virt);
    }
    auto* pd = static_cast<u64*>(PhysToVirt(pdpt_entry & kAddrMask));
    const u64 pd_entry = pd[i2];
    if ((pd_entry & kPagePresent) == 0)
    {
        return 1;
    }
    if ((pd_entry & kPageHugeOrPat) != 0)
    {
        PanicAs("AS walker hit a 2 MiB PS page", virt);
    }
    return 0;
}

// Validate that a consecutive borrowed range has no present leaves and count
// the unique missing intermediate tables needed to commit it. The range is
// consecutive, so every (PML4), (PML4,PDPT), and (PML4,PDPT,PD) key appears in
// one contiguous run; remembering the preceding indices avoids counting a
// missing parent once per page. Caller holds regions_lock and mutation_lock.
bool PrepareBorrowedRangePlanLocked(u64* pml4, u64 virt, u64 count, u8& missing_tables)
{
    u64 previous_i4 = kEntriesPerTable;
    u64 previous_i3 = kEntriesPerTable;
    u64 previous_i2 = kEntriesPerTable;
    bool pml4_present = false;
    bool pdpt_entry_present = false;
    u64* pdpt = nullptr;
    u64* pd = nullptr;
    missing_tables = 0;

    for (u64 page = 0; page < count; ++page)
    {
        const u64 page_virt = virt + page * kPageSize;
        const u64 i4 = IndexPml4(page_virt);
        const u64 i3 = IndexPdpt(page_virt);
        const u64 i2 = IndexPd(page_virt);

        if (i4 != previous_i4)
        {
            previous_i4 = i4;
            previous_i3 = kEntriesPerTable;
            previous_i2 = kEntriesPerTable;
            const u64 pml4_entry = pml4[i4];
            pml4_present = (pml4_entry & kPagePresent) != 0;
            if (!pml4_present)
            {
                ++missing_tables;
                pdpt = nullptr;
            }
            else
            {
                pdpt = static_cast<u64*>(PhysToVirt(pml4_entry & kAddrMask));
            }
        }

        if (i3 != previous_i3)
        {
            previous_i3 = i3;
            previous_i2 = kEntriesPerTable;
            if (!pml4_present)
            {
                ++missing_tables;
                pdpt_entry_present = false;
                pd = nullptr;
            }
            else
            {
                const u64 pdpt_entry = pdpt[i3];
                if ((pdpt_entry & kPagePresent) != 0 && (pdpt_entry & kPageHugeOrPat) != 0)
                {
                    PanicAs("borrowed-range plan hit a 1 GiB PS page", page_virt);
                }
                pdpt_entry_present = (pdpt_entry & kPagePresent) != 0;
                if (!pdpt_entry_present)
                {
                    ++missing_tables;
                    pd = nullptr;
                }
                else
                {
                    pd = static_cast<u64*>(PhysToVirt(pdpt_entry & kAddrMask));
                }
            }
        }

        if (i2 != previous_i2)
        {
            previous_i2 = i2;
            if (!pml4_present || !pdpt_entry_present)
            {
                ++missing_tables;
            }
            else
            {
                const u64 pd_entry = pd[i2];
                if ((pd_entry & kPagePresent) != 0 && (pd_entry & kPageHugeOrPat) != 0)
                {
                    PanicAs("borrowed-range plan hit a 2 MiB PS page", page_virt);
                }
                if ((pd_entry & kPagePresent) == 0)
                {
                    ++missing_tables;
                }
            }
        }

        u64* existing = WalkToPteIn(pml4, page_virt, nullptr);
        if (existing != nullptr && (*existing & kPagePresent) != 0)
        {
            return false;
        }
    }

    KASSERT(missing_tables <= kMaxBorrowedRangePageTables, "mm/as", "borrowed-range plan exceeded page-table bound");
    return true;
}

// Walk to a leaf PTE without doing slow work. When `reserve` is null this
// is lookup-only and returns null for a missing level. Otherwise each
// missing level consumes one table prepared before regions_lock was taken.
u64* WalkToPteIn(u64* pml4, u64 virt, PageTableReserve* reserve)
{
    const u64 i4 = IndexPml4(virt);
    const u64 i3 = IndexPdpt(virt);
    const u64 i2 = IndexPd(virt);
    const u64 i1 = IndexPt(virt);

    u64& pml4_entry = pml4[i4];
    if ((pml4_entry & kPagePresent) == 0)
    {
        if (reserve == nullptr)
        {
            return nullptr;
        }
        u64* new_pdpt = TakeReservedTable(*reserve);
        const PhysAddr phys = VirtToPhys(new_pdpt);
        // PML4 entry must carry kPageUser when it covers a user-
        // accessible PT — without it the CPU page walker rejects
        // the user access at the PML4 level even if the leaf PTE
        // has User set. SMAP/SMEP gating still holds because
        // those check the leaf PTE's bits.
        pml4_entry = phys | kPagePresent | kPageWritable | kPageUser;
    }
    auto* pdpt = static_cast<u64*>(PhysToVirt(pml4_entry & kAddrMask));

    u64& pdpt_entry = pdpt[i3];
    if ((pdpt_entry & kPagePresent) == 0)
    {
        if (reserve == nullptr)
        {
            return nullptr;
        }
        u64* new_pd = TakeReservedTable(*reserve);
        const PhysAddr phys = VirtToPhys(new_pd);
        pdpt_entry = phys | kPagePresent | kPageWritable | kPageUser;
    }
    if (pdpt_entry & kPageHugeOrPat)
    {
        PanicAs("AS walker hit a 1 GiB PS page", virt);
    }
    auto* pd = static_cast<u64*>(PhysToVirt(pdpt_entry & kAddrMask));

    u64& pd_entry = pd[i2];
    if ((pd_entry & kPagePresent) == 0)
    {
        if (reserve == nullptr)
        {
            return nullptr;
        }
        u64* new_pt = TakeReservedTable(*reserve);
        const PhysAddr phys = VirtToPhys(new_pt);
        pd_entry = phys | kPagePresent | kPageWritable | kPageUser;
    }
    if (pd_entry & kPageHugeOrPat)
    {
        PanicAs("AS walker hit a 2 MiB PS page", virt);
    }
    auto* pt = static_cast<u64*>(PhysToVirt(pd_entry & kAddrMask));
    return &pt[i1];
}

struct RetiredPageTables
{
    PhysAddr frames[3]{};
    u8 count{};
};

bool PageTableIsEmpty(const u64* table)
{
    for (u64 i = 0; i < kEntriesPerTable; ++i)
    {
        if (table[i] != 0)
        {
            return false;
        }
    }
    return true;
}

void AppendRetiredTable(RetiredPageTables& retired, PhysAddr frame)
{
    KASSERT(retired.count < 3, "mm/as", "too many page-table levels retired for one VA");
    retired.frames[retired.count++] = frame;
}

void ReleaseRetiredPageTables(RetiredPageTables& retired)
{
    for (u8 i = 0; i < retired.count; ++i)
    {
        FreeFrame(retired.frames[i]);
        retired.frames[i] = kNullFrame;
    }
    retired.count = 0;
}

struct RetiredPageTableRange
{
    PhysAddr frames[kMaxBorrowedRangePageTables]{};
    u8 count{};
};

void AppendRetiredRangeTables(RetiredPageTableRange& range, const RetiredPageTables& path)
{
    for (u8 i = 0; i < path.count; ++i)
    {
        bool duplicate = false;
        for (u8 j = 0; j < range.count; ++j)
        {
            if (range.frames[j] == path.frames[i])
            {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
        {
            continue;
        }
        KASSERT(range.count < kMaxBorrowedRangePageTables, "mm/as", "borrowed-range prune exceeded page-table bound");
        range.frames[range.count++] = path.frames[i];
    }
}

void ReleaseRetiredRangeTables(RetiredPageTableRange& range)
{
    for (u8 i = 0; i < range.count; ++i)
    {
        FreeFrame(range.frames[i]);
        range.frames[i] = kNullFrame;
    }
    range.count = 0;
}

// Leaf PTE at `virt` has already been cleared. Detach each now-empty
// intermediate table from the top-level tree while regions_lock is held,
// but merely record its frame here. The caller performs the TLB shootdown
// first and returns these frames to the allocator afterward.
RetiredPageTables PruneEmptyTablePathLocked(AddressSpace* as, u64 virt)
{
    KASSERT_WITH_VALUE(virt <= 0x00007FFFFFFFFFFFULL, "mm/as", "attempted to prune outside the canonical user half",
                       virt);
    RetiredPageTables retired{};
    const u64 i4 = IndexPml4(virt);
    const u64 i3 = IndexPdpt(virt);
    const u64 i2 = IndexPd(virt);

    u64& pml4_entry = as->pml4_virt[i4];
    if ((pml4_entry & kPagePresent) == 0)
    {
        return retired;
    }
    auto* pdpt = static_cast<u64*>(PhysToVirt(pml4_entry & kAddrMask));
    u64& pdpt_entry = pdpt[i3];
    if ((pdpt_entry & kPagePresent) == 0 || (pdpt_entry & kPageHugeOrPat) != 0)
    {
        return retired;
    }
    auto* pd = static_cast<u64*>(PhysToVirt(pdpt_entry & kAddrMask));
    u64& pd_entry = pd[i2];
    if ((pd_entry & kPagePresent) == 0 || (pd_entry & kPageHugeOrPat) != 0)
    {
        return retired;
    }
    auto* pt = static_cast<u64*>(PhysToVirt(pd_entry & kAddrMask));
    if (!PageTableIsEmpty(pt))
    {
        return retired;
    }

    AppendRetiredTable(retired, pd_entry & kAddrMask);
    pd_entry = 0;
    if (!PageTableIsEmpty(pd))
    {
        return retired;
    }

    AppendRetiredTable(retired, pdpt_entry & kAddrMask);
    pdpt_entry = 0;
    if (!PageTableIsEmpty(pdpt))
    {
        return retired;
    }

    AppendRetiredTable(retired, pml4_entry & kAddrMask);
    pml4_entry = 0;
    return retired;
}

// Release every PT/PD/PDPT frame reachable from PML4[0..255] of `pml4`.
// Walks to the leaf level only inside present entries; never touches
// the kernel half (PML4[256..511]) since those entries are SHARED with
// every other AS via the boot PML4's PDPTs — freeing them would yank
// the kernel address space out from under every running process.
void FreeUserHalfTables(u64* pml4)
{
    for (u64 i4 = 0; i4 < kKernelHalfFirstIndex; ++i4)
    {
        const u64 e4 = pml4[i4];
        if ((e4 & kPagePresent) == 0)
        {
            continue;
        }
        const PhysAddr pdpt_phys = e4 & kAddrMask;
        auto* pdpt = static_cast<u64*>(PhysToVirt(pdpt_phys));
        for (u64 i3 = 0; i3 < kEntriesPerTable; ++i3)
        {
            const u64 e3 = pdpt[i3];
            if ((e3 & kPagePresent) == 0 || (e3 & kPageHugeOrPat) != 0)
            {
                continue;
            }
            const PhysAddr pd_phys = e3 & kAddrMask;
            auto* pd = static_cast<u64*>(PhysToVirt(pd_phys));
            for (u64 i2 = 0; i2 < kEntriesPerTable; ++i2)
            {
                const u64 e2 = pd[i2];
                if ((e2 & kPagePresent) == 0 || (e2 & kPageHugeOrPat) != 0)
                {
                    continue;
                }
                FreeFrame(e2 & kAddrMask); // free the PT page
            }
            FreeFrame(pd_phys);
        }
        FreeFrame(pdpt_phys);
        pml4[i4] = 0;
    }
}

constexpr u16 kNoReservation = u16(-1);

bool UserReservationRangeValid(u64 lo, u64 hi)
{
    constexpr u64 kUserTopExclusive = 0x0000800000000000ULL;
    if (lo >= hi || hi > kUserTopExclusive || ((lo | hi) & (kPageSize - 1)) != 0)
    {
        return false;
    }
    return (hi - lo) / kPageSize <= kMaxUserVmReservationPages;
}

u16 FindReservationIndex(const AddressSpace* as, u64 token_value)
{
    if (as == nullptr || token_value == 0)
    {
        return kNoReservation;
    }
    for (u16 i = 0; i < as->reservation_count; ++i)
    {
        if (as->reservations[i].token_value == token_value)
        {
            return i;
        }
    }
    return kNoReservation;
}

bool RangeOverlapsReservation(const AddressSpace* as, u64 lo, u64 hi)
{
    KASSERT(as != nullptr && lo < hi, "mm/as", "invalid reservation-overlap query");
    for (u16 i = 0; i < as->reservation_count; ++i)
    {
        const AddressSpaceUserReservation& reservation = as->reservations[i];
        if (lo < reservation.hi && hi > reservation.lo)
        {
            return true;
        }
    }
    return false;
}

bool WriteLeaseRangeValid(u64 lo, u64 len, u64* hi_out)
{
    constexpr u64 kUserTopExclusive = 0x0000800000000000ULL;
    if (hi_out != nullptr)
    {
        *hi_out = 0;
    }
    if (len == 0 || lo >= kUserTopExclusive || len > kUserTopExclusive - lo)
    {
        return false;
    }
    const u64 hi = lo + len;
    const u64 first_page = lo & ~(kPageSize - 1);
    const u64 last_page = (hi - 1) & ~(kPageSize - 1);
    const u64 page_count = ((last_page - first_page) / kPageSize) + 1;
    if (page_count > kAddressSpaceWriteLeaseMaxPages)
    {
        return false;
    }
    if (hi_out != nullptr)
    {
        *hi_out = hi;
    }
    return true;
}

u16 FindWriteLeaseRowLocked(const AddressSpace& as, u64 token_value)
{
    if (token_value == 0)
    {
        return kAddressSpaceWriteLeaseCapacity;
    }
    for (u16 index = 0; index < kAddressSpaceWriteLeaseCapacity; ++index)
    {
        if (as.write_leases[index].token_value == token_value)
        {
            return index;
        }
    }
    return kAddressSpaceWriteLeaseCapacity;
}

bool RangeOverlapsWriteLease(AddressSpace* as, u64 lo, u64 hi)
{
    KASSERT(as != nullptr && lo < hi, "mm/as", "invalid write-lease overlap query");
    sync::SpinLockGuard guard(as->write_leases_lock);
    u16 live = 0;
    bool overlap = false;
    for (const AddressSpaceWriteLeaseRow& row : as->write_leases)
    {
        if (row.token_value == 0)
        {
            if (row.lo != 0 || row.hi != 0)
            {
                return true; // corrupt rows fail closed against mutation
            }
            continue;
        }
        ++live;
        if (row.lo >= row.hi)
        {
            return true;
        }
        overlap = overlap || (lo < row.hi && hi > row.lo);
    }
    return live != as->write_lease_count ? true : overlap;
}

bool AddressSpaceHasWriteLeases(AddressSpace* as)
{
    sync::SpinLockGuard guard(as->write_leases_lock);
    u16 live = 0;
    for (const AddressSpaceWriteLeaseRow& row : as->write_leases)
    {
        if (row.token_value != 0)
        {
            ++live;
        }
        else if (row.lo != 0 || row.hi != 0)
        {
            return true;
        }
    }
    return live != 0 || live != as->write_lease_count;
}

} // namespace

core::Result<AddressSpace*> AddressSpaceCreate(u64 frame_budget)
{
    KLOG_TRACE_SCOPE("mm/as", "AddressSpaceCreate");
    if (frame_budget == 0 || frame_budget > kMaxUserVmRegionsPerAs)
    {
        PanicAs("AddressSpaceCreate: frame_budget out of range [1..kMaxUserVmRegionsPerAs]", frame_budget);
    }

    auto* as = static_cast<AddressSpace*>(KMalloc(sizeof(AddressSpace)));
    if (as == nullptr)
    {
        // OOM during AddressSpace bookkeeping struct alloc — the
        // caller (typically ProcessCreate) returns nullptr upward
        // without a separate signal. Surface so a post-mortem can
        // tie the process-create failure to memory pressure.
        KLOG_ERROR("mm/as", "AddressSpaceCreate: KMalloc for AddressSpace struct failed");
        return core::Err{core::ErrorCode::OutOfMemory};
    }
    // Zero the chunk before populating. KMalloc returns memory still
    // carrying whatever was last in it — including the freed-payload
    // poison `kFreedPagePoison` (0xDE) from the C2 patch — and the
    // embedded locks are plain zero-valid structs (SpinLock ticket
    // counters plus Mutex owner/wait-queue links). KMalloc does not run
    // field initializers, so explicit zeroing is their initialization
    // contract. Without it, `mutation_lock.waiters.tail` reads back as
    // `0xdededededededede` and the first contended MutexLock dereferences
    // a non-canonical pointer and #GPs.
    memset(as, 0, sizeof(AddressSpace));

    // Heap-allocate the user-VM region table (grown on demand later in
    // AddressSpaceMapUserPage). Clamp the initial capacity down for
    // tiny-budget sandbox ASes. This replaces the old 128 KiB inline
    // array — a fresh AS now costs the struct + 480 bytes of ledgers
    // (384-byte region table + 96-byte reservation table), not 128 KiB.
    const u16 init_cap =
        (frame_budget < kInitialRegionCapacity) ? static_cast<u16>(frame_budget) : kInitialRegionCapacity;
    auto* regions = static_cast<AddressSpaceUserRegion*>(KMalloc(sizeof(AddressSpaceUserRegion) * init_cap));
    if (regions == nullptr)
    {
        KLOG_ERROR("mm/as", "AddressSpaceCreate: KMalloc for region table failed");
        KFree(as);
        return core::Err{core::ErrorCode::OutOfMemory};
    }

    auto* reservations = static_cast<AddressSpaceUserReservation*>(
        KMalloc(sizeof(AddressSpaceUserReservation) * kInitialUserVmReservationCapacity));
    if (reservations == nullptr)
    {
        KLOG_ERROR("mm/as", "AddressSpaceCreate: KMalloc for reservation table failed");
        KFree(regions);
        KFree(as);
        return core::Err{core::ErrorCode::OutOfMemory};
    }

    auto pml4_frame_r = AllocateFrame();
    if (!pml4_frame_r)
    {
        // Frame allocator exhausted while reserving the PML4 root —
        // every user process needs one, so a fresh-process spawn
        // under high memory pressure dies here silently. Cleanup
        // releases the region table + struct alloc; we still return the
        // error but now the OOM is in the log.
        KLOG_ERROR("mm/as", "AddressSpaceCreate: AllocateFrame for PML4 root failed");
        KFree(reservations);
        KFree(regions);
        KFree(as);
        return core::Err{pml4_frame_r.error()};
    }
    const PhysAddr pml4_frame = pml4_frame_r.value();

    auto* pml4 = static_cast<u64*>(PhysToVirt(pml4_frame));

    // PML4 layout for a per-process AS:
    //
    //   [0..255]    — zero. User-half, fully private. MapUserPage
    //                 installs fresh PDPTs/PDs/PTs on demand.
    //                 BUT: ring3_smoke's ASLR picker MUST keep user
    //                 bases >= 1 GiB — the boot PML4's PML4[0]
    //                 PDPT[0] covers [0, 1 GiB) with 2 MiB PS pages
    //                 (the boot stack + IST stacks + kernel image
    //                 live there), and the per-AS walker would
    //                 descend into a PS entry and panic. User VAs
    //                 above 1 GiB land in fresh private tables.
    //   [256..511]  — copied from boot PML4 (kernel-half direct map +
    //                 MMIO arena). Shared via copied PDPTs so future
    //                 kernel-half mapping changes propagate everywhere
    //                 without shootdown.
    u64* boot_pml4 = BootPml4Virt();
    for (u64 i = 0; i < kKernelHalfFirstIndex; ++i)
    {
        pml4[i] = 0;
    }
    for (u64 i = kKernelHalfFirstIndex; i < kEntriesPerTable; ++i)
    {
        pml4[i] = boot_pml4[i];
    }

    as->pml4_phys = pml4_frame;
    as->pml4_virt = pml4;
    as->refcount = 1;
    as->frame_budget = frame_budget;
    as->region_count = 0;
    as->region_capacity = init_cap;
    as->regions = regions;
    as->reservation_count = 0;
    as->reservation_capacity = kInitialUserVmReservationCapacity;
    as->reservations = reservations;
    as->write_lease_count = 0;
    as->next_write_lease_hint = 0;

    ++g_created;

    arch::SerialWrite("[as] created pml4_phys=");
    arch::SerialWriteHex(pml4_frame);
    arch::SerialWrite(" as=");
    arch::SerialWriteHex(reinterpret_cast<u64>(as));
    arch::SerialWrite("\n");

    return as;
}

bool AddressSpaceReserveUserRange(AddressSpace* as, u64 lo, u64 hi, AddressSpaceReservationToken* out_token)
{
    if (out_token != nullptr)
    {
        *out_token = AddressSpaceReservationToken{};
    }
    if (as == nullptr || out_token == nullptr || !UserReservationRangeValid(lo, hi))
    {
        return false;
    }

    AddressSpaceMutationGuard mutation(*as);
    if (as->reservation_count >= kMaxUserVmReservationsPerAs || RangeOverlapsReservation(as, lo, hi))
    {
        return false;
    }

    // The reservation begins empty. Scan both owned and borrowed PTEs:
    // borrowed views intentionally have no region-ledger row, so checking
    // only `regions` would recreate the exact Section-vs-stack hole this
    // token closes. mutation_lock already excludes every page-table writer
    // and final teardown, so this bounded read-only walk intentionally keeps
    // interrupts enabled instead of holding regions_lock for up to 2048 PTE
    // probes.
    for (u64 va = lo; va < hi; va += kPageSize)
    {
        u64* pte = WalkToPteIn(as->pml4_virt, va, nullptr);
        if (pte != nullptr && (*pte & kPagePresent) != 0)
        {
            return false;
        }
    }

    if (as->reservation_count == as->reservation_capacity)
    {
        u16 new_capacity = static_cast<u16>(as->reservation_capacity * 2u);
        if (new_capacity > kMaxUserVmReservationsPerAs)
        {
            new_capacity = kMaxUserVmReservationsPerAs;
        }
        auto* grown =
            static_cast<AddressSpaceUserReservation*>(KMalloc(sizeof(AddressSpaceUserReservation) * new_capacity));
        if (grown == nullptr)
        {
            return false;
        }
        memcpy(grown, as->reservations, sizeof(AddressSpaceUserReservation) * as->reservation_count);
        AddressSpaceUserReservation* old = as->reservations;
        as->reservations = grown;
        as->reservation_capacity = new_capacity;
        KFree(old);
    }

    const u64 token_value = AllocateReservationTokenValue();
    if (token_value == 0)
    {
        return false;
    }
    as->reservations[as->reservation_count++] = AddressSpaceUserReservation{lo, hi, token_value};
    *out_token = AddressSpaceReservationToken(as, token_value);
    return true;
}

bool AddressSpaceReservationMatches(AddressSpace* as, const AddressSpaceReservationToken& token, u64 lo, u64 hi)
{
    if (as == nullptr || !token.IsValid() || token.owner_ != as || !UserReservationRangeValid(lo, hi))
    {
        return false;
    }
    AddressSpaceMutationGuard mutation(*as);
    const u16 index = FindReservationIndex(as, token.value_);
    return index != kNoReservation && as->reservations[index].lo == lo && as->reservations[index].hi == hi;
}

bool AddressSpaceCommitUserReservation(AddressSpace* as, const AddressSpaceReservationToken& token, u64 expected_lo,
                                       u64 expected_hi)
{
    if (as == nullptr || !token.IsValid() || token.owner_ != as || !UserReservationRangeValid(expected_lo, expected_hi))
    {
        return false;
    }

    AddressSpaceMutationGuard mutation(*as);
    const u16 reservation_index = FindReservationIndex(as, token.value_);
    if (reservation_index == kNoReservation || as->reservations[reservation_index].lo != expected_lo ||
        as->reservations[reservation_index].hi != expected_hi)
    {
        return false;
    }

    const u64 expected_pages = (expected_hi - expected_lo) / kPageSize;
    u64 tagged_pages = 0;
    {
        sync::SpinLockGuard guard(as->regions_lock);
        for (u16 i = 0; i < as->region_count; ++i)
        {
            const AddressSpaceUserRegion& region = as->regions[i];
            if (region.reservation_token != token.value_)
            {
                continue;
            }
            if (region.vaddr < expected_lo || region.vaddr >= expected_hi)
            {
                return false;
            }
            u64* pte = WalkToPteIn(as->pml4_virt, region.vaddr, nullptr);
            if (pte == nullptr || (*pte & kPagePresent) == 0 || (*pte & kAddrMask) != region.frame)
            {
                return false;
            }
            ++tagged_pages;
        }
        if (tagged_pages != expected_pages)
        {
            return false;
        }
        for (u16 i = 0; i < as->region_count; ++i)
        {
            if (as->regions[i].reservation_token == token.value_)
            {
                as->regions[i].reservation_token = 0;
            }
        }
    }

    const u16 last = static_cast<u16>(as->reservation_count - 1);
    if (reservation_index != last)
    {
        as->reservations[reservation_index] = as->reservations[last];
    }
    --as->reservation_count;
    return true;
}

namespace
{

bool MapOwnedUserPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags, u64 reservation_token)
{
    if (as == nullptr)
    {
        PanicAs("AddressSpaceMapUserPage with null AS", virt);
    }
    if ((virt & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceMapUserPage: unaligned virt", virt);
    }
    if ((frame & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceMapUserPage: unaligned phys", frame);
    }
    // Reject anything outside the canonical low half. A user mapping
    // installed in the kernel half would either silently land inside
    // shared kernel tables (corrupting every other AS's view of the
    // kernel) or hit the panic in the boot direct map. Refusing here
    // turns "obvious bug" into a named one.
    constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
    if (virt > kUserMax)
    {
        PanicAs("AddressSpaceMapUserPage: virt outside canonical low half", virt);
    }
    if ((flags & kPageUser) == 0)
    {
        PanicAs("AddressSpaceMapUserPage: flags missing kPageUser", flags);
    }
    // W^X enforcement — no user mapping may be BOTH writable AND
    // executable. That combination is the canonical shellcode-
    // injection substrate (write bytes to a page, then jump there).
    // A mapping that's writable must carry kPageNoExecute; a mapping
    // that's executable (NX clear) must NOT carry kPageWritable.
    // This applies to every caller of MapUserPage — loader, spawn,
    // future mprotect-equivalent, etc. Panicking here turns "I
    // accidentally introduced W+X in a new code path" into a boot-
    // time failure rather than a silent regression.
    //
    // The kernel's own mapping API (mm::MapPage) mirrors this
    // check; see paging.cpp.
    if ((flags & kPageWritable) != 0 && (flags & kPageNoExecute) == 0)
    {
        PanicAs("AddressSpaceMapUserPage: W^X violation (writable+exec user page)", flags);
    }
    // Reject kPageGlobal on user pages. A global mapping survives a
    // CR3 flush, so a user page marked global would remain in the
    // TLB across a process switch — cross-process leak. Kernel-half
    // mappings legitimately use global; user-half never should.
    if ((flags & kPageGlobal) != 0)
    {
        PanicAs("AddressSpaceMapUserPage: kPageGlobal on user page", flags);
    }
    AddressSpaceMutationGuard mutation(*as);
    if (reservation_token == 0)
    {
        if (RangeOverlapsReservation(as, virt, virt + kPageSize))
        {
            KLOG_WARN_V("mm/as", "MapUserPage: VA reserved by another owner", virt);
            return false;
        }
    }
    else
    {
        const u16 reservation_index = FindReservationIndex(as, reservation_token);
        if (reservation_index == kNoReservation || virt < as->reservations[reservation_index].lo ||
            virt >= as->reservations[reservation_index].hi)
        {
            KLOG_WARN_V("mm/as", "MapReservedUserPage: stale token or VA outside reservation", virt);
            return false;
        }
    }

    bool budget_exhausted = false;
    bool already_mapped = false;
    bool grow_regions = false;
    u16 region_count = 0;
    u16 new_capacity = 0;
    u8 missing_tables = 0;
    AddressSpaceUserRegion* current_regions = nullptr;
    {
        sync::SpinLockGuard guard(as->regions_lock);
        region_count = as->region_count;
        budget_exhausted = region_count >= as->frame_budget;
        if (!budget_exhausted)
        {
            u64* existing = WalkToPteIn(as->pml4_virt, virt, nullptr);
            if (existing != nullptr && (*existing & kPagePresent) != 0)
            {
                already_mapped = true;
            }
            else
            {
                missing_tables = MissingTableCount(as->pml4_virt, virt);
                grow_regions = region_count == as->region_capacity;
                current_regions = as->regions;
                if (grow_regions)
                {
                    u32 cap = static_cast<u32>(as->region_capacity) * 2u;
                    if (cap > as->frame_budget)
                    {
                        cap = static_cast<u32>(as->frame_budget);
                    }
                    new_capacity = static_cast<u16>(cap);
                }
            }
        }
    }

    if (budget_exhausted)
    {
        KLOG_WARN_V("mm/as", "MapUserPage: frame budget exhausted — refusing mapping", region_count);
        return false;
    }
    if (already_mapped)
    {
        KLOG_WARN_V("mm/as", "MapUserPage: virtual address already mapped — refusing overwrite", virt);
        return false;
    }

    // Prepare both fallible resources before the bounded structural
    // commit. mutation_lock keeps the inspected table path and regions
    // pointer stable while regions_lock is intentionally dropped.
    AddressSpaceUserRegion* grown_regions = nullptr;
    if (grow_regions)
    {
        grown_regions = static_cast<AddressSpaceUserRegion*>(KMalloc(sizeof(AddressSpaceUserRegion) * new_capacity));
        if (grown_regions == nullptr)
        {
            KLOG_WARN_V("mm/as", "MapUserPage: region-table grow OOM — refusing mapping", region_count);
            return false;
        }
        memcpy(grown_regions, current_regions, sizeof(AddressSpaceUserRegion) * region_count);
    }

    PageTableReserve reserve{};
    if (!PreparePageTableReserve(reserve, missing_tables))
    {
        if (grown_regions != nullptr)
        {
            KFree(grown_regions);
        }
        KLOG_WARN_V("mm/as", "MapUserPage: frame pool dry building page tables — refusing mapping", virt);
        return false;
    }

    {
        sync::SpinLockGuard guard(as->regions_lock);
        if (grown_regions != nullptr)
        {
            as->regions = grown_regions;
            as->region_capacity = new_capacity;
        }
        u64* pte = WalkToPteIn(as->pml4_virt, virt, &reserve);
        KASSERT(pte != nullptr, "mm/as", "prepared map transaction produced no leaf PTE");
        KASSERT((*pte & kPagePresent) == 0, "mm/as", "map transaction raced an existing PTE");
        *pte = (frame & kAddrMask) | (flags | kPagePresent);
        as->regions[as->region_count] = AddressSpaceUserRegion{virt, frame, reservation_token};
        ++as->region_count;
    }

    KASSERT(reserve.next == reserve.count, "mm/as", "map transaction left prepared tables unused");
    ReleasePageTableReserve(reserve);
    if (grown_regions != nullptr)
    {
        KFree(current_regions);
    }

    // Invalidation is outside the IRQ-saving structural lock. The outer
    // mutation transaction prevents a same-VA unmap/remap from overtaking
    // this commit while the local translation state is synchronized.
    if (AddressSpaceCurrent() == as)
    {
        Invlpg(virt);
    }
    return true;
}

} // namespace

bool AddressSpaceMapUserPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags)
{
    return MapOwnedUserPage(as, virt, frame, flags, 0);
}

bool AddressSpaceMapReservedUserPage(AddressSpace* as, const AddressSpaceReservationToken& token, u64 virt,
                                     PhysAddr frame, u64 flags)
{
    if (!token.IsValid() || token.owner_ != as)
    {
        return false;
    }
    return MapOwnedUserPage(as, virt, frame, flags, token.value_);
}

namespace
{
struct RetiredUserPage
{
    u64 virt{};
    PhysAddr frame{kNullFrame};
    RetiredPageTables page_tables{};
};

// Commit the structural half of an unmap. Caller holds regions_lock and
// the outer mutation_lock. TLB retirement and frame release happen only
// after the IRQ-saving structural lock has been dropped.
RetiredUserPage DetachUserPageByIndexLocked(AddressSpace* as, u16 idx)
{
    // Precondition the header comment describes but nothing
    // enforced: idx must address a live row. With region_count==0
    // the `u16(region_count - 1)` below wraps to 0xFFFF and the
    // compaction line writes 64 KiB past the table — silent heap
    // corruption. Always-on (not DEBUG_ASSERT): an OOB write into
    // the region table is a stability/security hole.
    KASSERT(as->region_count > 0, "mm/as", "UnmapUserPageByIndex on empty region table");
    KASSERT(idx < as->region_count, "mm/as", "UnmapUserPageByIndex idx out of range");

    const u64 virt = as->regions[idx].vaddr;
    const PhysAddr frame = as->regions[idx].frame;

    // Clear the leaf PTE. If the walk can't find one the tables
    // are corrupt relative to the region table — panic so the gap
    // is visible, rather than silently leaving the region list out
    // of sync with the page tables.
    u64* pte = WalkToPteIn(as->pml4_virt, virt, nullptr);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
    {
        PanicAs("AddressSpaceUnmapUserPage: region table claims mapping but PTE absent", virt);
    }
    if ((*pte & kAddrMask) != frame)
    {
        PanicAs("AddressSpaceUnmapUserPage: region table/PTE frame mismatch", virt);
    }
    *pte = 0;
    RetiredPageTables page_tables = PruneEmptyTablePathLocked(as, virt);

    // Compact the region table — swap the dying slot with the last
    // in-use slot. Order doesn't matter; destroy walks `region_count`
    // entries.
    const u16 last = u16(as->region_count - 1);
    if (idx != last)
    {
        as->regions[idx] = as->regions[last];
    }
    --as->region_count;
    return RetiredUserPage{virt, frame, page_tables};
}
} // namespace

bool AddressSpaceCommitUserReservationReplacingOwnedRange(AddressSpace* as,
                                                          const AddressSpaceReservationToken& destination_token,
                                                          u64 destination_lo, u64 destination_hi, u64 source_lo,
                                                          u64 source_hi)
{
    if (as == nullptr || !destination_token.IsValid() || destination_token.owner_ != as ||
        !UserReservationRangeValid(destination_lo, destination_hi) || !UserReservationRangeValid(source_lo, source_hi))
    {
        return false;
    }
    if (destination_lo < source_hi && destination_hi > source_lo)
    {
        return false;
    }

    AddressSpaceMutationGuard mutation(*as);
    const u16 reservation_index = FindReservationIndex(as, destination_token.value_);
    if (reservation_index == kNoReservation || as->reservations[reservation_index].lo != destination_lo ||
        as->reservations[reservation_index].hi != destination_hi ||
        RangeOverlapsReservation(as, source_lo, source_hi) || RangeOverlapsWriteLease(as, source_lo, source_hi) ||
        RangeOverlapsWriteLease(as, destination_lo, destination_hi))
    {
        return false;
    }

    constexpr u64 kSeenWordBits = 64;
    constexpr u64 kSeenWordCount = (kMaxUserVmRegionsPerAs + kSeenWordBits - 1) / kSeenWordBits;
    u64 destination_seen[kSeenWordCount]{};
    u64 source_seen[kSeenWordCount]{};
    const u64 destination_pages = (destination_hi - destination_lo) / kPageSize;
    const u64 source_pages = (source_hi - source_lo) / kPageSize;
    u64 destination_count = 0;
    u64 source_count = 0;

    // Validate both ledgers and every corresponding leaf before publishing or
    // retiring anything. The bitsets make duplicate VA rows a refusal rather
    // than allowing a matching row count to hide a hole.
    {
        sync::SpinLockGuard guard(as->regions_lock);
        for (u16 i = 0; i < as->region_count; ++i)
        {
            const AddressSpaceUserRegion& region = as->regions[i];
            const bool in_destination = region.vaddr >= destination_lo && region.vaddr < destination_hi;
            const bool in_source = region.vaddr >= source_lo && region.vaddr < source_hi;

            if (!in_destination && !in_source)
            {
                if (region.reservation_token == destination_token.value_)
                {
                    return false;
                }
                continue;
            }

            const u64 page_index =
                in_destination ? (region.vaddr - destination_lo) / kPageSize : (region.vaddr - source_lo) / kPageSize;
            u64* const seen = in_destination ? destination_seen : source_seen;
            const u64 word = page_index / kSeenWordBits;
            const u64 bit = u64{1} << (page_index % kSeenWordBits);
            if ((seen[word] & bit) != 0)
            {
                return false;
            }
            seen[word] |= bit;

            if ((in_destination && region.reservation_token != destination_token.value_) ||
                (in_source && region.reservation_token != 0))
            {
                return false;
            }
            u64* pte = WalkToPteIn(as->pml4_virt, region.vaddr, nullptr);
            if (pte == nullptr || (*pte & kPagePresent) == 0 || (*pte & kAddrMask) != region.frame)
            {
                return false;
            }
            if (in_destination)
            {
                ++destination_count;
            }
            else
            {
                ++source_count;
            }
        }
    }
    if (destination_count != destination_pages || source_count != source_pages)
    {
        return false;
    }

    // Validation succeeded under the same outer mutation transaction. Retire
    // source rows with a persistent scan so swap-removal stays O(region_count)
    // and no page-sized receipt array is needed on the kernel stack.
    u16 scan = 0;
    u64 retired_count = 0;
    while (retired_count < source_pages)
    {
        RetiredUserPage retired{};
        bool found = false;
        {
            sync::SpinLockGuard guard(as->regions_lock);
            while (scan < as->region_count)
            {
                const AddressSpaceUserRegion& region = as->regions[scan];
                if (region.vaddr >= source_lo && region.vaddr < source_hi)
                {
                    KASSERT(region.reservation_token == 0, "mm/as", "validated replacement source changed ownership");
                    retired = DetachUserPageByIndexLocked(as, scan);
                    found = true;
                    break;
                }
                ++scan;
            }
        }
        KASSERT(found, "mm/as", "validated replacement source page disappeared");
        TlbShootdownAddr(as, retired.virt);
        FreeFrame(retired.frame);
        ReleaseRetiredPageTables(retired.page_tables);
        ++retired_count;
    }

    // Publish the destination only after every source translation and frame
    // is retired. No recoverable failure remains after the validation pass.
    {
        sync::SpinLockGuard guard(as->regions_lock);
        u64 committed_count = 0;
        for (u16 i = 0; i < as->region_count; ++i)
        {
            if (as->regions[i].reservation_token == destination_token.value_)
            {
                KASSERT(as->regions[i].vaddr >= destination_lo && as->regions[i].vaddr < destination_hi, "mm/as",
                        "replacement destination escaped reservation");
                as->regions[i].reservation_token = 0;
                ++committed_count;
            }
        }
        KASSERT(committed_count == destination_pages, "mm/as", "validated replacement destination disappeared");
    }

    const u16 current_reservation_index = FindReservationIndex(as, destination_token.value_);
    KASSERT(current_reservation_index != kNoReservation, "mm/as",
            "replacement destination reservation disappeared during exclusive commit");
    const u16 last = static_cast<u16>(as->reservation_count - 1);
    if (current_reservation_index != last)
    {
        as->reservations[current_reservation_index] = as->reservations[last];
    }
    --as->reservation_count;
    return true;
}

bool AddressSpaceUnmapUserPage(AddressSpace* as, u64 virt)
{
    if (as == nullptr)
    {
        return false;
    }
    if ((virt & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceUnmapUserPage: unaligned virt", virt);
    }
    constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
    if (virt > kUserMax)
    {
        PanicAs("AddressSpaceUnmapUserPage: virt outside canonical low half", virt);
    }
    AddressSpaceMutationGuard mutation(*as);
    if (RangeOverlapsReservation(as, virt, virt + kPageSize) || RangeOverlapsWriteLease(as, virt, virt + kPageSize))
    {
        return false;
    }
    RetiredUserPage retired{};
    {
        sync::SpinLockGuard guard(as->regions_lock);
        // Find the region. Linear scan over region_count — typical
        // region_count is small (≤128), and munmap is infrequent; this
        // stays cheaper than building an index.
        u16 found = u16(-1);
        for (u16 i = 0; i < as->region_count; ++i)
        {
            if (as->regions[i].vaddr == virt)
            {
                found = i;
                break;
            }
        }
        if (found == u16(-1))
        {
            return false;
        }
        retired = DetachUserPageByIndexLocked(as, found);
    }

    // The transaction stays exclusive until every CPU has discarded the
    // old translation and only then returns the backing frame for reuse.
    TlbShootdownAddr(as, retired.virt);
    FreeFrame(retired.frame);
    ReleaseRetiredPageTables(retired.page_tables);
    return true;
}

bool AddressSpaceReleaseUserReservation(AddressSpace* as, const AddressSpaceReservationToken& token, u64 expected_lo,
                                        u64 expected_hi)
{
    if (as == nullptr || !token.IsValid() || token.owner_ != as || !UserReservationRangeValid(expected_lo, expected_hi))
    {
        return false;
    }

    AddressSpaceMutationGuard mutation(*as);
    u16 reservation_index = FindReservationIndex(as, token.value_);
    if (reservation_index == kNoReservation || as->reservations[reservation_index].lo != expected_lo ||
        as->reservations[reservation_index].hi != expected_hi || RangeOverlapsWriteLease(as, expected_lo, expected_hi))
    {
        return false;
    }

    // Token-tagged rows are the exact owned-page set. Keep the reservation
    // live while each page is structurally detached and its TLB/frame/table
    // retirement completes; ordinary mappers remain excluded for the entire
    // transaction. Swap-removal means `scan` stays on the same index after a
    // match so the row moved into that slot is checked next.
    u16 scan = 0;
    for (;;)
    {
        RetiredUserPage retired{};
        bool found = false;
        {
            sync::SpinLockGuard guard(as->regions_lock);
            while (scan < as->region_count && as->regions[scan].reservation_token != token.value_)
            {
                ++scan;
            }
            if (scan < as->region_count)
            {
                KASSERT(as->regions[scan].vaddr >= expected_lo && as->regions[scan].vaddr < expected_hi, "mm/as",
                        "reservation-tagged page escaped its VA window");
                retired = DetachUserPageByIndexLocked(as, scan);
                found = true;
            }
        }
        if (!found)
        {
            break;
        }
        TlbShootdownAddr(as, retired.virt);
        FreeFrame(retired.frame);
        ReleaseRetiredPageTables(retired.page_tables);
    }

    // No untagged owned or borrowed leaf may exist inside the capability's
    // window. Reservation creation started empty and every generic map/unmap
    // path rejects overlap, so a survivor is ledger corruption, not a
    // recoverable conflict. The outer mutation transaction excludes every
    // PTE writer and teardown; keep interrupts enabled during this bounded
    // verification walk just as reservation creation does.
    for (u64 va = expected_lo; va < expected_hi; va += kPageSize)
    {
        u64* pte = WalkToPteIn(as->pml4_virt, va, nullptr);
        KASSERT(pte == nullptr || (*pte & kPagePresent) == 0, "mm/as", "foreign PTE survived reservation release");
    }

    reservation_index = FindReservationIndex(as, token.value_);
    KASSERT(reservation_index != kNoReservation, "mm/as", "reservation disappeared during exclusive release");
    const u16 last = static_cast<u16>(as->reservation_count - 1);
    if (reservation_index != last)
    {
        as->reservations[reservation_index] = as->reservations[last];
    }
    --as->reservation_count;
    return true;
}

bool AddressSpaceMapBorrowedRange(AddressSpace* as, u64 virt, const PhysAddr* frames, u64 count, u64 flags)
{
    if (as == nullptr)
    {
        PanicAs("AddressSpaceMapBorrowedRange with null AS", virt);
    }
    if ((virt & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceMapBorrowedRange: unaligned virt", virt);
    }
    if (frames == nullptr || count == 0 || count > kMaxBorrowedRangePages)
    {
        return false;
    }
    constexpr u64 kUserLastPage = 0x00007FFFFFFFF000ULL;
    const u64 last_page_offset = (count - 1) * kPageSize;
    if (virt > kUserLastPage || last_page_offset > kUserLastPage - virt)
    {
        PanicAs("AddressSpaceMapBorrowedRange: range outside canonical low half", virt);
    }
    if ((flags & kPageUser) == 0)
    {
        PanicAs("AddressSpaceMapBorrowedRange: flags missing kPageUser", flags);
    }
    if ((flags & kPageWritable) != 0 && (flags & kPageNoExecute) == 0)
    {
        PanicAs("AddressSpaceMapBorrowedRange: W^X violation", flags);
    }
    if ((flags & kPageGlobal) != 0)
    {
        PanicAs("AddressSpaceMapBorrowedRange: kPageGlobal on user page", flags);
    }
    for (u64 page = 0; page < count; ++page)
    {
        if ((frames[page] & 0xFFF) != 0)
        {
            PanicAs("AddressSpaceMapBorrowedRange: unaligned phys", frames[page]);
        }
    }

    AddressSpaceMutationGuard mutation(*as);
    const u64 range_hi = virt + count * kPageSize;
    if (RangeOverlapsReservation(as, virt, range_hi))
    {
        return false;
    }
    u8 missing_tables = 0;
    {
        sync::SpinLockGuard guard(as->regions_lock);
        if (!PrepareBorrowedRangePlanLocked(as->pml4_virt, virt, count, missing_tables))
        {
            return false;
        }
    }

    PageTableReserve reserve{};
    if (!PreparePageTableReserve(reserve, missing_tables))
    {
        KLOG_WARN_V("mm/as", "MapBorrowedRange: frame pool dry building page tables", virt);
        return false;
    }
    {
        sync::SpinLockGuard guard(as->regions_lock);
        for (u64 page = 0; page < count; ++page)
        {
            const u64 page_virt = virt + page * kPageSize;
            u64* pte = WalkToPteIn(as->pml4_virt, page_virt, &reserve);
            KASSERT(pte != nullptr, "mm/as", "prepared borrowed-range transaction produced no leaf PTE");
            KASSERT((*pte & kPagePresent) == 0, "mm/as", "borrowed-range transaction raced an existing PTE");
            *pte = (frames[page] & kAddrMask) | (flags | kPagePresent);
        }
    }
    KASSERT(reserve.next == reserve.count, "mm/as", "borrowed-range transaction left prepared tables unused");
    ReleasePageTableReserve(reserve);
    TlbShootdownRange(as, virt, count * kPageSize);
    return true;
}

bool AddressSpaceMapBorrowedPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags)
{
    return AddressSpaceMapBorrowedRange(as, virt, &frame, 1, flags);
}

PhysAddr AddressSpaceProbePte(const AddressSpace* as, u64 virt)
{
    if (as == nullptr)
        return kNullFrame;
    if ((virt & 0xFFF) != 0)
        PanicAs("AddressSpaceProbePte: unaligned virt", virt);
    sync::SpinLockGuard guard(as->regions_lock);
    u64* pte = WalkToPteIn(as->pml4_virt, virt, nullptr);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
        return kNullFrame;
    return *pte & kAddrMask;
}

u64 AddressSpaceProbePteRaw(const AddressSpace* as, u64 virt)
{
    if (as == nullptr)
        return 0;
    if ((virt & 0xFFF) != 0)
        PanicAs("AddressSpaceProbePteRaw: unaligned virt", virt);
    sync::SpinLockGuard guard(as->regions_lock);
    u64* pte = WalkToPteIn(as->pml4_virt, virt, nullptr);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
        return 0;
    return *pte;
}

core::Result<AddressSpace*> AddressSpaceFork(const AddressSpace* parent)
{
    if (parent == nullptr)
        return core::Err{core::ErrorCode::InvalidArgument};
    // Not RESULT_TRY_ASSIGN: clang-format misparses a pointer-typed
    // macro arg as multiplication (`AddressSpace * child`). The
    // explicit unwrap keeps the file's `Type* var` pointer style.
    auto child_r = AddressSpaceCreate(parent->frame_budget);
    if (!child_r)
        return core::Err{child_r.error()};
    AddressSpace* child = child_r.value();

    // Stabilize the parent's owned-frame ledger for the whole copy, but
    // take the IRQ-saving structural lock only long enough to snapshot
    // one row and its PTE. Frame allocation and memcpy remain sleepable.
    AddressSpaceMutationGuard parent_mutation(*parent);
    u16 parent_region_count = 0;
    {
        sync::SpinLockGuard parent_guard(parent->regions_lock);
        parent_region_count = parent->region_count;
    }
    for (u16 i = 0; i < parent_region_count; ++i)
    {
        AddressSpaceUserRegion parent_region{};
        u64 parent_pte = 0;
        {
            sync::SpinLockGuard parent_guard(parent->regions_lock);
            parent_region = parent->regions[i];
            u64* parent_pte_ptr = WalkToPteIn(parent->pml4_virt, parent_region.vaddr, nullptr);
            parent_pte = (parent_pte_ptr != nullptr && (*parent_pte_ptr & kPagePresent) != 0) ? *parent_pte_ptr : 0;
        }
        const u64 va = parent_region.vaddr;
        const PhysAddr parent_frame = parent_region.frame;
        if (parent_pte == 0 || (parent_pte & kAddrMask) != parent_frame)
        {
            // Region table thinks `va` is mapped but the PTE
            // walk found nothing present. That means an unmap
            // path mutated the page tables without removing
            // the matching region entry — a kernel-internal
            // invariant break. Surface it loudly so the next
            // such bug is found at fork time, not days later
            // when the child segfaults on a missing page.
            KLOG_WARN_2V("mm/address_space", "AddressSpaceFork: region table out of sync with PTEs", "va", va,
                         "pte_frame", parent_pte & kAddrMask);
            AddressSpaceRelease(child);
            return core::Err{core::ErrorCode::InvalidArgument};
        }
        // Extract flags: mask out the address bits, keep the
        // protection / present / user / NX flags.
        const u64 flags = parent_pte & ~kAddrMask;
        auto child_frame_r = AllocateFrame();
        if (!child_frame_r)
        {
            AddressSpaceRelease(child);
            return core::Err{child_frame_r.error()};
        }
        const PhysAddr child_frame = child_frame_r.value();
        // Copy page contents through the direct-map alias.
        const void* src = PhysToVirt(parent_frame);
        void* dst = PhysToVirt(child_frame);
        memcpy(dst, src, kPageSize);
        // Deliberately drop parent_region.reservation_token here. Tokens are
        // capabilities scoped to one AS and are never inherited by fork;
        // committed caller-stack pages become ordinary child-owned mappings.
        // Linux child Tasks receive no owned-stack descriptor, so they cannot
        // demand-grow through the parent's uncommitted reservation window.
        if (!AddressSpaceMapUserPage(child, va, child_frame, flags))
        {
            // A fork is all-or-nothing. The child owns none of this
            // frame on refusal, and releasing the partial AS reclaims
            // every page committed by earlier iterations.
            FreeFrame(child_frame);
            AddressSpaceRelease(child);
            return core::Err{core::ErrorCode::OutOfMemory};
        }
    }
    return child;
}

void AddressSpaceClearUserMappings(AddressSpace* as)
{
    if (as == nullptr)
        return;
    for (;;)
    {
        bool pinned = false;
        {
            AddressSpaceMutationGuard mutation(*as);
            pinned = AddressSpaceHasWriteLeases(as);
            if (!pinned)
            {
                KASSERT(as->reservation_count == 0, "mm/as",
                        "AddressSpaceClearUserMappings with live user-VA reservation token");
                for (;;)
                {
                    RetiredUserPage retired{};
                    {
                        sync::SpinLockGuard guard(as->regions_lock);
                        if (as->region_count == 0)
                        {
                            return;
                        }
                        retired = DetachUserPageByIndexLocked(as, u16(as->region_count - 1));
                    }
                    TlbShootdownAddr(as, retired.virt);
                    FreeFrame(retired.frame);
                    ReleaseRetiredPageTables(retired.page_tables);
                }
            }
        }
        KASSERT(pinned, "mm/as", "write-lease wait lost its predicate");
        sched::SchedYield();
    }
}

bool AddressSpaceProtectUserPage(AddressSpace* as, u64 virt, u64 new_flags)
{
    if (as == nullptr)
        return false;
    if ((virt & 0xFFF) != 0)
        PanicAs("AddressSpaceProtectUserPage: unaligned virt", virt);
    constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
    if (virt > kUserMax)
        PanicAs("AddressSpaceProtectUserPage: virt outside canonical low half", virt);
    if ((new_flags & kPageUser) == 0)
        PanicAs("AddressSpaceProtectUserPage: flags missing kPageUser", new_flags);
    if ((new_flags & kPageWritable) != 0 && (new_flags & kPageNoExecute) == 0)
        PanicAs("AddressSpaceProtectUserPage: W^X violation", new_flags);
    if ((new_flags & kPageGlobal) != 0)
        PanicAs("AddressSpaceProtectUserPage: kPageGlobal on user page", new_flags);

    AddressSpaceMutationGuard mutation(*as);
    if (RangeOverlapsReservation(as, virt, virt + kPageSize) || RangeOverlapsWriteLease(as, virt, virt + kPageSize))
    {
        return false;
    }
    bool refused_write_to_exec = false;
    {
        sync::SpinLockGuard guard(as->regions_lock);
        bool owned_mapping = false;
        for (u16 i = 0; i < as->region_count; ++i)
        {
            if (as->regions[i].vaddr == virt)
            {
                owned_mapping = true;
                break;
            }
        }
        if (!owned_mapping)
        {
            // A present leaf that is absent from the owned-frame ledger is a
            // borrowed mapping. Its owner must serialize protection with its
            // own frame/view lifetime transaction.
            return false;
        }
        u64* pte = WalkToPteIn(as->pml4_virt, virt, nullptr);
        if (pte == nullptr || (*pte & kPagePresent) == 0)
            return false;
        // SEC-004: a currently writable page may not become executable.
        const bool granting_exec = (new_flags & kPageNoExecute) == 0;
        const bool currently_writable = (*pte & kPageWritable) != 0;
        if (granting_exec && currently_writable)
        {
            new_flags |= kPageNoExecute;
            refused_write_to_exec = true;
        }
        const u64 frame = *pte & kAddrMask;
        *pte = frame | (new_flags | kPagePresent);
    }
    if (refused_write_to_exec)
    {
        KLOG_ONCE_WARN("mm/address_space",
                       "AddressSpaceProtectUserPage: W^X — refusing W->X transition, kept page non-executable");
    }
    // Protect downgrades (e.g. RW→RO) leave stale RW entries in
    // peer-CPU TLBs that allow writes through after the PTE was
    // already narrowed. Broadcast the shootdown. See class FF.
    TlbShootdownAddr(as, virt);
    return true;
}

namespace
{
bool UnmapBorrowedRange(AddressSpace* as, u64 virt, const PhysAddr* expected_frames, u64 count, bool require_expected)
{
    if (as == nullptr)
    {
        return false;
    }
    if ((virt & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceUnmapBorrowedRange: unaligned virt", virt);
    }
    if (count == 0 || count > kMaxBorrowedRangePages || (require_expected && expected_frames == nullptr))
    {
        return false;
    }
    constexpr u64 kUserLastPage = 0x00007FFFFFFFF000ULL;
    const u64 last_page_offset = (count - 1) * kPageSize;
    if (virt > kUserLastPage || last_page_offset > kUserLastPage - virt)
    {
        PanicAs("AddressSpaceUnmapBorrowedRange: range outside canonical low half", virt);
    }
    if (require_expected)
    {
        for (u64 page = 0; page < count; ++page)
        {
            if ((expected_frames[page] & 0xFFF) != 0)
            {
                PanicAs("AddressSpaceUnmapBorrowedRange: unaligned expected phys", expected_frames[page]);
            }
        }
    }

    AddressSpaceMutationGuard mutation(*as);
    if (RangeOverlapsReservation(as, virt, virt + count * kPageSize) ||
        RangeOverlapsWriteLease(as, virt, virt + count * kPageSize))
    {
        return false;
    }
    RetiredPageTableRange retired_tables{};
    {
        sync::SpinLockGuard guard(as->regions_lock);
        // Validation pass first: failure cannot leave a partially-unmapped
        // view. The outer mutation lock keeps the checked leaves stable.
        for (u64 page = 0; page < count; ++page)
        {
            const u64 page_virt = virt + page * kPageSize;
            u64* pte = WalkToPteIn(as->pml4_virt, page_virt, nullptr);
            if (pte == nullptr || (*pte & kPagePresent) == 0 ||
                (require_expected && (*pte & kAddrMask) != expected_frames[page]))
            {
                return false;
            }
        }
        for (u64 page = 0; page < count; ++page)
        {
            u64* pte = WalkToPteIn(as->pml4_virt, virt + page * kPageSize, nullptr);
            KASSERT(pte != nullptr, "mm/as", "validated borrowed-range PTE disappeared during commit");
            *pte = 0;
        }
        // Prune after every leaf is clear. This lets a PT/PD shared by pages
        // in the same range retire exactly once, after its last leaf vanished.
        for (u64 page = 0; page < count; ++page)
        {
            const RetiredPageTables path = PruneEmptyTablePathLocked(as, virt + page * kPageSize);
            AppendRetiredRangeTables(retired_tables, path);
        }
    }
    TlbShootdownRange(as, virt, count * kPageSize);
    ReleaseRetiredRangeTables(retired_tables);
    return true;
}
} // namespace

bool AddressSpaceUnmapBorrowedRangeExpected(AddressSpace* as, u64 virt, const PhysAddr* expected_frames, u64 count)
{
    return UnmapBorrowedRange(as, virt, expected_frames, count, true);
}

bool AddressSpaceUnmapBorrowedPage(AddressSpace* as, u64 virt)
{
    return UnmapBorrowedRange(as, virt, nullptr, 1, false);
}

void AddressSpaceActivate(AddressSpace* as)
{
    cpu::PerCpu* p = cpu::CurrentCpu();
    if (p->current_as == as)
    {
        return; // fast path: no-op same-AS switch
    }

    // Publish entry before CR3 and retire the old bit only after CR3 has
    // flushed its non-PCID translations. The brief overlap is intentional:
    // an unnecessary IPI is safe, while clearing the old bit first lets a
    // concurrent reclaimer miss this CPU and recycle a frame before the CR3
    // reload has removed its stale translation.
    const u32 bit = 1u << (p->cpu_id & 31u);
    AddressSpace* old_as = p->current_as;
    if (as != nullptr)
    {
        __atomic_fetch_or(&as->active_cpu_mask, bit, __ATOMIC_RELEASE);
    }

    const PhysAddr cr3 = (as != nullptr) ? as->pml4_phys : BootPml4Phys();
    arch::WriteCr3(cr3);
    p->current_as = as;
    if (old_as != nullptr)
    {
        __atomic_fetch_and(&old_as->active_cpu_mask, ~bit, __ATOMIC_RELEASE);
    }
    ++g_cr3_switches;
}

AddressSpace* AddressSpaceCurrent()
{
    return cpu::CurrentCpu()->current_as;
}

PhysAddr AddressSpaceLookupUserFrame(const AddressSpace* as, u64 virt)
{
    if (as == nullptr)
        return kNullFrame;
    sync::SpinLockGuard guard(as->regions_lock);
    const u64 page_va = virt & ~(kPageSize - 1);
    for (u16 i = 0; i < as->region_count; ++i)
    {
        if (as->regions[i].vaddr == page_va)
            return as->regions[i].frame;
    }
    return kNullFrame;
}

bool AddressSpaceTrySnapshotUserRegionSummary(const AddressSpace* as, AddressSpaceUserRegionSummary* out)
{
    if (out == nullptr)
    {
        return false;
    }
    *out = AddressSpaceUserRegionSummary{};
    if (as == nullptr)
    {
        return false;
    }

    // Panic/stop diagnostics must never wait here: this CPU or an
    // unacknowledged peer may already own the structural lock.
    sync::SpinLockTryGuard guard(as->regions_lock);
    if (!guard)
    {
        return false;
    }

    const u16 count = as->region_count;
    if (count > as->region_capacity || count > as->frame_budget || (count != 0 && as->regions == nullptr))
    {
        return false;
    }

    AddressSpaceUserRegionSummary summary{};
    summary.page_count = count;
    if (count == 0)
    {
        *out = summary;
        return true;
    }

    constexpr u64 kUserLastPage = 0x00007FFFFFFFF000ULL;
    summary.min_vaddr = ~u64{0};
    for (u16 index = 0; index < count; ++index)
    {
        const u64 vaddr = as->regions[index].vaddr;
        if ((vaddr & (kPageSize - 1)) != 0 || vaddr > kUserLastPage)
        {
            return false;
        }
        if (vaddr < summary.min_vaddr)
        {
            summary.min_vaddr = vaddr;
        }
        const u64 end = vaddr + kPageSize;
        if (end > summary.max_vaddr_exclusive)
        {
            summary.max_vaddr_exclusive = end;
        }
    }
    *out = summary;
    return true;
}

namespace
{
bool CopyUserMemoryTransaction(AddressSpace* as, u64 user_va, void* kernel_buffer, u64 len, bool write)
{
    if (len == 0)
    {
        return true;
    }
    constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
    const u64 page_offset = user_va & (kPageSize - 1);
    if (as == nullptr || kernel_buffer == nullptr || user_va > kUserMax || len > (kPageSize - page_offset))
    {
        return false;
    }

    AddressSpaceMutationGuard mutation(*as);
    u64 pte_value = 0;
    {
        sync::SpinLockGuard guard(as->regions_lock);
        u64* pte = WalkToPteIn(as->pml4_virt, user_va, nullptr);
        if (pte == nullptr)
        {
            return false;
        }
        pte_value = *pte;
        constexpr u64 kReadableUser = kPagePresent | kPageUser;
        if ((pte_value & kReadableUser) != kReadableUser || (write && (pte_value & kPageWritable) == 0))
        {
            return false;
        }
    }

    auto* direct = static_cast<u8*>(PhysToVirt(pte_value & kAddrMask)) + page_offset;
    if (write)
    {
        memcpy(direct, kernel_buffer, len);
    }
    else
    {
        memcpy(kernel_buffer, direct, len);
    }
    return true;
}
} // namespace

bool AddressSpaceReadUserMemory(AddressSpace* as, u64 user_va, void* kernel_dst, u64 len)
{
    return CopyUserMemoryTransaction(as, user_va, kernel_dst, len, false);
}

bool AddressSpaceWriteUserMemory(AddressSpace* as, u64 user_va, const void* kernel_src, u64 len)
{
    return CopyUserMemoryTransaction(as, user_va, const_cast<void*>(kernel_src), len, true);
}

AddressSpaceWriteLeaseStatus AddressSpaceAcquireWriteLease(AddressSpace* as, u64 user_va, u64 len,
                                                           AddressSpaceWriteLease* out_lease)
{
    u64 hi = 0;
    if (as == nullptr || out_lease == nullptr || !WriteLeaseRangeValid(user_va, len, &hi))
    {
        return AddressSpaceWriteLeaseStatus::InvalidArgument;
    }
    if (out_lease->owner_ != nullptr || out_lease->token_value_ != 0 || out_lease->lo_ != 0 || out_lease->hi_ != 0)
    {
        // Never overwrite a live or non-canonical output object: doing so could
        // orphan both the exact ledger row and its AddressSpace reference.
        return AddressSpaceWriteLeaseStatus::InvalidArgument;
    }

    AddressSpaceMutationGuard mutation(*as);
    sync::SpinLockGuard lease_guard(as->write_leases_lock);
    if (as->write_lease_count > kAddressSpaceWriteLeaseCapacity ||
        as->next_write_lease_hint >= kAddressSpaceWriteLeaseCapacity)
    {
        return AddressSpaceWriteLeaseStatus::CorruptState;
    }

    u16 live = 0;
    u16 free_slot = kAddressSpaceWriteLeaseCapacity;
    for (u16 offset = 0; offset < kAddressSpaceWriteLeaseCapacity; ++offset)
    {
        const u16 index = static_cast<u16>((as->next_write_lease_hint + offset) % kAddressSpaceWriteLeaseCapacity);
        const AddressSpaceWriteLeaseRow& row = as->write_leases[index];
        if (row.token_value != 0)
        {
            if (row.lo >= row.hi)
            {
                return AddressSpaceWriteLeaseStatus::CorruptState;
            }
            ++live;
            continue;
        }
        if (row.lo != 0 || row.hi != 0)
        {
            return AddressSpaceWriteLeaseStatus::CorruptState;
        }
        if (free_slot == kAddressSpaceWriteLeaseCapacity)
        {
            free_slot = index;
        }
    }
    if (live != as->write_lease_count)
    {
        return AddressSpaceWriteLeaseStatus::CorruptState;
    }
    if (free_slot == kAddressSpaceWriteLeaseCapacity)
    {
        return AddressSpaceWriteLeaseStatus::CapacityExhausted;
    }

    {
        sync::SpinLockGuard regions_guard(as->regions_lock);
        const u64 first_page = user_va & ~(kPageSize - 1);
        const u64 last_page = (hi - 1) & ~(kPageSize - 1);
        for (u64 page = first_page;; page += kPageSize)
        {
            u64* pte = WalkToPteIn(as->pml4_virt, page, nullptr);
            constexpr u64 kReadableUser = kPagePresent | kPageUser;
            if (pte == nullptr || (*pte & kReadableUser) != kReadableUser)
            {
                return AddressSpaceWriteLeaseStatus::Unmapped;
            }
            if ((*pte & kPageWritable) == 0)
            {
                return AddressSpaceWriteLeaseStatus::NotWritable;
            }
            if (page == last_page)
            {
                break;
            }
        }
    }

    const u64 token_value = AllocateWriteLeaseTokenValue();
    if (token_value == 0)
    {
        return AddressSpaceWriteLeaseStatus::TokenExhausted;
    }
    as->write_leases[free_slot] = AddressSpaceWriteLeaseRow{user_va, hi, token_value};
    ++as->write_lease_count;
    as->next_write_lease_hint = static_cast<u16>((free_slot + 1U) % kAddressSpaceWriteLeaseCapacity);
    AddressSpaceRetain(as);
    out_lease->owner_ = as;
    out_lease->token_value_ = token_value;
    out_lease->lo_ = user_va;
    out_lease->hi_ = hi;
    return AddressSpaceWriteLeaseStatus::Ok;
}

bool AddressSpaceCopyToWriteLease(const AddressSpaceWriteLease& lease, u64 offset, const void* kernel_src, u64 len)
{
    if (!lease.IsValid() || (len != 0 && kernel_src == nullptr))
    {
        return false;
    }
    const u64 lease_bytes = lease.hi_ - lease.lo_;
    if (offset > lease_bytes || len > lease_bytes - offset)
    {
        return false;
    }

    AddressSpace* const as = lease.owner_;
    sync::SpinLockGuard lease_guard(as->write_leases_lock);
    const u16 slot = FindWriteLeaseRowLocked(*as, lease.token_value_);
    if (slot == kAddressSpaceWriteLeaseCapacity)
    {
        return false;
    }
    const AddressSpaceWriteLeaseRow& row = as->write_leases[slot];
    if (row.lo != lease.lo_ || row.hi != lease.hi_ || row.token_value != lease.token_value_)
    {
        return false;
    }
    if (len == 0)
    {
        return true;
    }

    sync::SpinLockGuard regions_guard(as->regions_lock);
    const u64 first_lease_page = row.lo & ~(kPageSize - 1);
    const u64 last_lease_page = (row.hi - 1) & ~(kPageSize - 1);
    for (u64 page = first_lease_page;; page += kPageSize)
    {
        u64* pte = WalkToPteIn(as->pml4_virt, page, nullptr);
        constexpr u64 kWritableUser = kPagePresent | kPageUser | kPageWritable;
        if (pte == nullptr || (*pte & kWritableUser) != kWritableUser)
        {
            return false;
        }
        if (page == last_lease_page)
        {
            break;
        }
    }

    const auto* source = static_cast<const u8*>(kernel_src);
    u64 destination = row.lo + offset;
    u64 remaining = len;
    while (remaining != 0)
    {
        u64* pte = WalkToPteIn(as->pml4_virt, destination, nullptr);
        KASSERT(pte != nullptr, "mm/as", "validated write-lease PTE disappeared");
        const u64 page_offset = destination & (kPageSize - 1);
        const u64 chunk = remaining < kPageSize - page_offset ? remaining : kPageSize - page_offset;
        auto* direct = static_cast<u8*>(PhysToVirt(*pte & kAddrMask)) + page_offset;
        memcpy(direct, source, chunk);
        source += chunk;
        destination += chunk;
        remaining -= chunk;
    }
    return true;
}

bool AddressSpaceReleaseWriteLease(AddressSpaceWriteLease* lease)
{
    if (lease == nullptr || !lease->IsValid())
    {
        return false;
    }
    AddressSpace* const as = lease->owner_;
    const u64 token_value = lease->token_value_;
    {
        sync::SpinLockGuard guard(as->write_leases_lock);
        const u16 slot = FindWriteLeaseRowLocked(*as, token_value);
        if (slot == kAddressSpaceWriteLeaseCapacity)
        {
            return false;
        }
        const AddressSpaceWriteLeaseRow& row = as->write_leases[slot];
        if (row.lo != lease->lo_ || row.hi != lease->hi_ || row.token_value != token_value ||
            as->write_lease_count == 0)
        {
            return false;
        }
        as->write_leases[slot] = AddressSpaceWriteLeaseRow{};
        --as->write_lease_count;
    }
    lease->owner_ = nullptr;
    lease->token_value_ = 0;
    lease->lo_ = 0;
    lease->hi_ = 0;
    AddressSpaceRelease(as);
    return true;
}

void AddressSpaceRetain(AddressSpace* as)
{
    if (as == nullptr)
    {
        return;
    }
    // Atomic CAS-loop retain — see ProcessRetain for the rationale.
    // Plain `++as->refcount` was a cross-CPU race that contributed
    // to the SMP=8 saturation UAF: a peer dropping the AS to 0
    // while this CPU was racing a retain could leave the AS
    // double-freed.
    while (true)
    {
        u64 cur = __atomic_load_n(&as->refcount.value, __ATOMIC_ACQUIRE);
        if (cur == 0)
        {
            PanicAs("AddressSpaceRetain on AS with refcount==0", reinterpret_cast<u64>(as));
        }
        if (cur == ~u64{0})
        {
            PanicAs("AddressSpaceRetain would wrap saturated refcount", reinterpret_cast<u64>(as));
        }
        const u64 next = cur + 1;
        if (__atomic_compare_exchange_n(&as->refcount.value, &cur, next, /*weak=*/false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            return;
        }
    }
}

void AddressSpaceRelease(AddressSpace* as)
{
    if (as == nullptr)
    {
        return;
    }
    // Checked CAS decrement. A load-then-sub sequence lets two buggy
    // releasers both witness 1: one reaches zero while the other underflows
    // freed storage to UINT64_MAX. Only an exact witnessed value may be
    // decremented, and only the sole zero-transition owner may destroy.
    u64 current = __atomic_load_n(&as->refcount.value, __ATOMIC_ACQUIRE);
    u64 new_count = 0;
    for (;;)
    {
        if (current == 0)
        {
            PanicAs("AddressSpaceRelease on AS with refcount==0", reinterpret_cast<u64>(as));
        }
        new_count = current - 1;
        if (__atomic_compare_exchange_n(&as->refcount.value, &current, new_count, /*weak=*/false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            break;
        }
    }
    if (new_count != 0)
    {
        return;
    }

    // Last reference dropped. CRITICAL: if this AS is the currently-
    // active one on this CPU, switch back to the kernel AS BEFORE
    // freeing its tables — otherwise the next memory access would
    // walk freed page tables and the next interrupt would land on
    // a corrupt RSP0 stack. Reaper context is the canonical caller;
    // the reaper runs on its own task / AS, so this is normally a
    // no-op, but defensive switching is cheaper than diagnosing a
    // freed-page-table fault.
    if (AddressSpaceCurrent() == as)
    {
        AddressSpaceActivate(nullptr);
    }

    const u32 active_cpu_mask = __atomic_load_n(&as->active_cpu_mask, __ATOMIC_ACQUIRE);
    KASSERT_WITH_VALUE(active_cpu_mask == 0, "mm/as", "AddressSpaceRelease while AS active on a peer CPU",
                       active_cpu_mask);

    {
        AddressSpaceMutationGuard mutation(*as);
        KASSERT(!AddressSpaceHasWriteLeases(as), "mm/as", "AddressSpaceRelease with live write lease");
        u16 regions_at_destroy = 0;
        {
            sync::SpinLockGuard guard(as->regions_lock);
            regions_at_destroy = as->region_count;
        }

        arch::SerialWrite("[as] destroying pml4_phys=");
        arch::SerialWriteHex(as->pml4_phys);
        arch::SerialWrite(" regions=");
        arch::SerialWriteHex(regions_at_destroy);
        arch::SerialWrite("\n");

        // Detach one owned frame at a time under the structural lock,
        // then return it after interrupts are restored. The whole drain
        // remains one mutation transaction, so no mapper can repopulate
        // the AS between iterations.
        for (;;)
        {
            PhysAddr frame = kNullFrame;
            {
                sync::SpinLockGuard guard(as->regions_lock);
                if (as->region_count == 0)
                {
                    break;
                }
                --as->region_count;
                frame = as->regions[as->region_count].frame;
            }
            FreeFrame(frame);
        }
        arch::SerialWrite("[as] regions freed\n");

        // Free intermediate user-half tables, then the PML4 itself.
        FreeUserHalfTables(as->pml4_virt);
        arch::SerialWrite("[as] tables freed\n");
        FreeFrame(as->pml4_phys);
        arch::SerialWrite("[as] pml4 frame freed\n");

        // Free the heap-allocated ledgers before the struct itself. Live
        // reservation rows are legal here (e.g. a PE load/spawn failure):
        // final AS destruction invalidates their untransferred tokens after
        // every owned frame has already been returned above.
        KFree(as->reservations);
        as->reservations = nullptr;
        KFree(as->regions);
        as->regions = nullptr;
    }

    // mutation's destructor must release the embedded lock before the
    // AddressSpace allocation itself becomes invalid.
    KFree(as);
    arch::SerialWrite("[as] AddressSpace struct freed\n");
    ++g_destroyed;
    arch::SerialWrite("[as] release done\n");
}

AddressSpaceStats AddressSpaceStatsRead()
{
    return AddressSpaceStats{
        .created = g_created,
        .destroyed = g_destroyed,
        .cr3_switches = g_cr3_switches,
        .live = g_created - g_destroyed,
    };
}

void AddressSpaceSelfTest()
{
    KLOG_TRACE_SCOPE("mm/as", "AddressSpaceSelfTest");
    // Use a VA inside PDPT[1] of the low half — outside anything
    // ring3_smoke or any existing mapping touches. If ring3 ever
    // moves to the same VA range, bump this to stay disjoint.
    constexpr u64 kTestVa = 0x0000000050000000ULL;

    arch::SerialWrite("[mm/as] isolation self-test\n");

    auto a_r = AddressSpaceCreate(kFrameBudgetTrusted);
    if (!a_r)
    {
        PanicAs("self-test: AddressSpaceCreate failed for A", 0);
    }
    AddressSpace* a = a_r.value();
    auto b_r = AddressSpaceCreate(kFrameBudgetTrusted);
    if (!b_r)
    {
        PanicAs("self-test: AddressSpaceCreate failed for B", 0);
    }
    AddressSpace* b = b_r.value();

    auto frame_r = AllocateFrame();
    if (!frame_r)
    {
        PanicAs("self-test: AllocateFrame failed", 0);
    }
    const PhysAddr frame = frame_r.value();
    if (!AddressSpaceMapUserPage(a, kTestVa, frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
    {
        FreeFrame(frame);
        PanicAs("self-test: AddressSpaceMapUserPage refused test mapping", kTestVa);
    }

    // Walk a's tables directly — must find the PTE we just
    // installed, with Present + User bits set.
    const u64 a_pte = AddressSpaceProbePteRaw(a, kTestVa);
    if ((a_pte & kPagePresent) == 0 || (a_pte & kPageUser) == 0)
    {
        PanicAs("self-test: AS-A does not have the page we mapped", kTestVa);
    }

    // Walk b's tables at the same VA — must return nullptr (no
    // user-half tables exist for this VA in b's PML4 tree yet).
    // This is the CORE isolation assertion: two sibling ASes DO
    // NOT share a mapping installed in one of them.
    const u64 b_pte = AddressSpaceProbePteRaw(b, kTestVa);
    if ((b_pte & kPagePresent) != 0)
    {
        PanicAs("self-test: AS-B SAW AS-A's private page — ISOLATION BROKEN", kTestVa);
    }

    // Transaction-copy access must keep frame lookup, permission check,
    // and direct-map dereference inside one mutation lifetime. Exercise
    // both directions, isolation, and write refusal after an RO downgrade.
    const u8 write_probe[4] = {0xD0, 0xE7, 0xA5, 0x5A};
    u8 read_probe[4]{};
    if (!AddressSpaceWriteUserMemory(a, kTestVa + 37, write_probe, sizeof(write_probe)) ||
        !AddressSpaceReadUserMemory(a, kTestVa + 37, read_probe, sizeof(read_probe)))
    {
        PanicAs("self-test: transaction-copy read/write refused mapped page", kTestVa);
    }
    for (u32 i = 0; i < sizeof(write_probe); ++i)
    {
        if (read_probe[i] != write_probe[i])
        {
            PanicAs("self-test: transaction-copy data mismatch", i);
        }
    }
    if (AddressSpaceReadUserMemory(b, kTestVa + 37, read_probe, sizeof(read_probe)))
    {
        PanicAs("self-test: transaction-copy crossed address-space isolation", kTestVa);
    }
    if (AddressSpaceReadUserMemory(a, kTestVa + kPageSize - 2, read_probe, sizeof(read_probe)))
    {
        PanicAs("self-test: transaction-copy accepted a cross-page range", kTestVa);
    }

    // A write lease holds only a logical PTE/lifetime pin: it must exclude
    // unmap and protection changes without retaining mutation_lock, copy via
    // the direct map, and reject replay after consumption. Compile-time copy
    // deletion prevents an otherwise-dangling owner pointer after AS release.
    AddressSpaceWriteLease write_lease{};
    if (AddressSpaceAcquireWriteLease(a, kTestVa + 37, sizeof(write_probe), &write_lease) !=
            AddressSpaceWriteLeaseStatus::Ok ||
        !write_lease.IsValid() ||
        AddressSpaceAcquireWriteLease(a, kTestVa + 41, sizeof(write_probe), &write_lease) !=
            AddressSpaceWriteLeaseStatus::InvalidArgument)
    {
        PanicAs("self-test: writable mapping lease acquisition/reuse guard failed", kTestVa);
    }
    const u8 leased_probe[4] = {0x51, 0xA5, 0x7E, 0xD0};
    if (AddressSpaceProtectUserPage(a, kTestVa, kPagePresent | kPageUser | kPageNoExecute) ||
        AddressSpaceUnmapUserPage(a, kTestVa) ||
        !AddressSpaceCopyToWriteLease(write_lease, 0, leased_probe, sizeof(leased_probe)) ||
        !AddressSpaceReleaseWriteLease(&write_lease) || AddressSpaceReleaseWriteLease(&write_lease) ||
        !AddressSpaceReadUserMemory(a, kTestVa + 37, read_probe, sizeof(read_probe)))
    {
        PanicAs("self-test: exact write-lease exclusion/copy/replay failed", kTestVa);
    }
    for (u32 i = 0; i < sizeof(leased_probe); ++i)
    {
        if (read_probe[i] != leased_probe[i])
        {
            PanicAs("self-test: write-lease data mismatch", i);
        }
    }
    AddressSpaceWriteLease unmapped_lease{};
    if (AddressSpaceAcquireWriteLease(b, kTestVa + 37, sizeof(write_probe), &unmapped_lease) !=
            AddressSpaceWriteLeaseStatus::Unmapped ||
        unmapped_lease.IsValid())
    {
        PanicAs("self-test: write lease accepted unmapped sibling range", kTestVa);
    }
    if (!AddressSpaceProtectUserPage(a, kTestVa, kPagePresent | kPageUser | kPageNoExecute) ||
        AddressSpaceWriteUserMemory(a, kTestVa + 37, write_probe, sizeof(write_probe)))
    {
        PanicAs("self-test: transaction-copy bypassed read-only PTE", kTestVa);
    }

    // A sparse reservation must exclude every generic mapper, accept only
    // its exact AS-scoped capability, tag the owned page for exact release,
    // and make the VA reusable only after that token is retired.
    constexpr u64 kReservedVa = 0x0000000051000000ULL;
    constexpr u64 kReservedHi = kReservedVa + 3 * kPageSize;
    AddressSpaceReservationToken token_a{};
    AddressSpaceReservationToken token_b{};
    if (!AddressSpaceReserveUserRange(a, kReservedVa, kReservedHi, &token_a) || !token_a.IsValid() ||
        !AddressSpaceReservationMatches(a, token_a, kReservedVa, kReservedHi) ||
        !AddressSpaceReserveUserRange(b, kReservedVa, kReservedHi, &token_b) || token_a.value_ == token_b.value_)
    {
        PanicAs("self-test: user-VA reservation setup failed", kReservedVa);
    }

    PhysAddr rejected_owned = AllocateFrame().value_or(kNullFrame);
    if (rejected_owned == kNullFrame ||
        AddressSpaceMapUserPage(a, kReservedVa, rejected_owned,
                                kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
    {
        PanicAs("self-test: ordinary owned map entered reserved range", kReservedVa);
    }
    FreeFrame(rejected_owned);

    PhysAddr rejected_borrowed = AllocateFrame().value_or(kNullFrame);
    if (rejected_borrowed == kNullFrame ||
        AddressSpaceMapBorrowedPage(a, kReservedVa, rejected_borrowed,
                                    kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
    {
        PanicAs("self-test: borrowed map entered reserved range", kReservedVa);
    }
    FreeFrame(rejected_borrowed);

    PhysAddr wrong_token_frame = AllocateFrame().value_or(kNullFrame);
    if (wrong_token_frame == kNullFrame ||
        AddressSpaceMapReservedUserPage(a, token_b, kReservedVa, wrong_token_frame,
                                        kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
    {
        PanicAs("self-test: foreign-AS reservation token was accepted", kReservedVa);
    }
    FreeFrame(wrong_token_frame);

    PhysAddr reserved_frame = AllocateFrame().value_or(kNullFrame);
    if (reserved_frame == kNullFrame ||
        !AddressSpaceMapReservedUserPage(a, token_a, kReservedVa, reserved_frame,
                                         kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
    {
        PanicAs("self-test: exact reservation token map failed", kReservedVa);
    }
    if (!AddressSpaceReleaseUserReservation(a, token_a, kReservedVa, kReservedHi) ||
        AddressSpaceProbePte(a, kReservedVa) != kNullFrame ||
        AddressSpaceReservationMatches(a, token_a, kReservedVa, kReservedHi))
    {
        PanicAs("self-test: exact reservation release failed", kReservedVa);
    }
    if (!AddressSpaceReleaseUserReservation(b, token_b, kReservedVa, kReservedHi))
    {
        PanicAs("self-test: empty reservation release failed", kReservedVa);
    }

    // Fully populated reservations may commit into ordinary AS ownership;
    // incomplete ones must remain exact-token capabilities and unwind safely.
    constexpr u64 kCommittedVa = 0x0000000052000000ULL;
    constexpr u64 kCommittedHi = kCommittedVa + 2 * kPageSize;
    AddressSpaceReservationToken committed_token{};
    if (!AddressSpaceReserveUserRange(a, kCommittedVa, kCommittedHi, &committed_token))
    {
        PanicAs("self-test: committed reservation setup failed", kCommittedVa);
    }
    for (u64 va = kCommittedVa; va < kCommittedHi; va += kPageSize)
    {
        PhysAddr committed_frame = AllocateFrame().value_or(kNullFrame);
        if (committed_frame == kNullFrame ||
            !AddressSpaceMapReservedUserPage(a, committed_token, va, committed_frame,
                                             kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
        {
            PanicAs("self-test: committed reservation map failed", va);
        }
    }
    if (!AddressSpaceCommitUserReservation(a, committed_token, kCommittedVa, kCommittedHi) ||
        AddressSpaceReservationMatches(a, committed_token, kCommittedVa, kCommittedHi) ||
        !AddressSpaceUnmapUserPage(a, kCommittedVa) || !AddressSpaceUnmapUserPage(a, kCommittedVa + kPageSize))
    {
        PanicAs("self-test: reservation commit did not publish ordinary ownership", kCommittedVa);
    }

    constexpr u64 kPartialVa = 0x0000000053000000ULL;
    constexpr u64 kPartialHi = kPartialVa + 2 * kPageSize;
    AddressSpaceReservationToken partial_token{};
    PhysAddr partial_frame = AllocateFrame().value_or(kNullFrame);
    if (partial_frame == kNullFrame || !AddressSpaceReserveUserRange(a, kPartialVa, kPartialHi, &partial_token) ||
        !AddressSpaceMapReservedUserPage(a, partial_token, kPartialVa, partial_frame,
                                         kPagePresent | kPageWritable | kPageUser | kPageNoExecute) ||
        AddressSpaceCommitUserReservation(a, partial_token, kPartialVa, kPartialHi) ||
        !AddressSpaceReleaseUserReservation(a, partial_token, kPartialVa, kPartialHi) ||
        AddressSpaceProbePte(a, kPartialVa) != kNullFrame)
    {
        PanicAs("self-test: partial reservation commit was not fail-closed", kPartialVa);
    }

    // A move-style replacement validates both complete ranges before it
    // retires the source or publishes the destination. Protection changes are
    // excluded while the destination capability remains live.
    constexpr u64 kReplaceSourceVa = 0x0000000054000000ULL;
    constexpr u64 kReplaceSourceHi = kReplaceSourceVa + 2 * kPageSize;
    constexpr u64 kReplaceDestinationVa = 0x0000000055000000ULL;
    constexpr u64 kReplaceDestinationHi = kReplaceDestinationVa + 3 * kPageSize;
    for (u64 va = kReplaceSourceVa; va < kReplaceSourceHi; va += kPageSize)
    {
        PhysAddr source_frame = AllocateFrame().value_or(kNullFrame);
        if (source_frame == kNullFrame ||
            !AddressSpaceMapUserPage(a, va, source_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
        {
            PanicAs("self-test: replacement source setup failed", va);
        }
    }
    AddressSpaceReservationToken replace_token{};
    if (!AddressSpaceReserveUserRange(a, kReplaceDestinationVa, kReplaceDestinationHi, &replace_token))
    {
        PanicAs("self-test: replacement destination reservation failed", kReplaceDestinationVa);
    }
    for (u64 va = kReplaceDestinationVa; va < kReplaceDestinationHi; va += kPageSize)
    {
        PhysAddr destination_frame = AllocateFrame().value_or(kNullFrame);
        if (destination_frame == kNullFrame ||
            !AddressSpaceMapReservedUserPage(a, replace_token, va, destination_frame,
                                             kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
        {
            PanicAs("self-test: replacement destination setup failed", va);
        }
    }
    if (AddressSpaceProtectUserPage(a, kReplaceDestinationVa, kPagePresent | kPageUser | kPageNoExecute) ||
        !AddressSpaceCommitUserReservationReplacingOwnedRange(
            a, replace_token, kReplaceDestinationVa, kReplaceDestinationHi, kReplaceSourceVa, kReplaceSourceHi) ||
        AddressSpaceReservationMatches(a, replace_token, kReplaceDestinationVa, kReplaceDestinationHi))
    {
        PanicAs("self-test: combined replacement transaction failed", kReplaceDestinationVa);
    }
    for (u64 va = kReplaceSourceVa; va < kReplaceSourceHi; va += kPageSize)
    {
        if (AddressSpaceProbePte(a, va) != kNullFrame)
        {
            PanicAs("self-test: combined replacement retained source page", va);
        }
    }
    if (!AddressSpaceProtectUserPage(a, kReplaceDestinationVa, kPagePresent | kPageUser | kPageNoExecute))
    {
        PanicAs("self-test: combined replacement did not publish destination", kReplaceDestinationVa);
    }
    for (u64 va = kReplaceDestinationVa; va < kReplaceDestinationHi; va += kPageSize)
    {
        if (!AddressSpaceUnmapUserPage(a, va))
        {
            PanicAs("self-test: replacement destination cleanup failed", va);
        }
    }

    // An incomplete source must leave both the ordinary source and exact
    // destination reservation intact so the caller can roll back safely.
    constexpr u64 kFailedSourceVa = 0x0000000056000000ULL;
    constexpr u64 kFailedSourceHi = kFailedSourceVa + 2 * kPageSize;
    constexpr u64 kFailedDestinationVa = 0x0000000057000000ULL;
    constexpr u64 kFailedDestinationHi = kFailedDestinationVa + 2 * kPageSize;
    PhysAddr failed_source_frame = AllocateFrame().value_or(kNullFrame);
    if (failed_source_frame == kNullFrame ||
        !AddressSpaceMapUserPage(a, kFailedSourceVa, failed_source_frame,
                                 kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
    {
        PanicAs("self-test: failed-replacement source setup failed", kFailedSourceVa);
    }
    AddressSpaceReservationToken failed_replace_token{};
    if (!AddressSpaceReserveUserRange(a, kFailedDestinationVa, kFailedDestinationHi, &failed_replace_token))
    {
        PanicAs("self-test: failed-replacement destination reservation failed", kFailedDestinationVa);
    }
    for (u64 va = kFailedDestinationVa; va < kFailedDestinationHi; va += kPageSize)
    {
        PhysAddr destination_frame = AllocateFrame().value_or(kNullFrame);
        if (destination_frame == kNullFrame ||
            !AddressSpaceMapReservedUserPage(a, failed_replace_token, va, destination_frame,
                                             kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
        {
            PanicAs("self-test: failed-replacement destination setup failed", va);
        }
    }
    if (AddressSpaceCommitUserReservationReplacingOwnedRange(a, failed_replace_token, kFailedDestinationVa,
                                                             kFailedDestinationHi, kFailedSourceVa, kFailedSourceHi) ||
        !AddressSpaceReservationMatches(a, failed_replace_token, kFailedDestinationVa, kFailedDestinationHi) ||
        AddressSpaceProbePte(a, kFailedSourceVa) == kNullFrame ||
        AddressSpaceProbePte(a, kFailedDestinationVa) == kNullFrame ||
        !AddressSpaceReleaseUserReservation(a, failed_replace_token, kFailedDestinationVa, kFailedDestinationHi) ||
        !AddressSpaceUnmapUserPage(a, kFailedSourceVa))
    {
        PanicAs("self-test: failed replacement was not failure-atomic", kFailedSourceVa);
    }

    // Exercise a borrowed transaction across a PDPT boundary. A mismatched
    // expected-frame vector must leave all three leaves intact, and the
    // generic owned-page protect API must refuse to mutate the borrowed view.
    constexpr u64 kBorrowedVa = 0x000000007FFFF000ULL;
    PhysAddr borrowed_frames[3]{};
    for (u64 page = 0; page < 3; ++page)
    {
        auto borrowed_r = AllocateFrame();
        if (!borrowed_r)
        {
            PanicAs("self-test: borrowed-range AllocateFrame failed", page);
        }
        borrowed_frames[page] = borrowed_r.value();
    }
    if (!AddressSpaceMapBorrowedRange(a, kBorrowedVa, borrowed_frames, 3,
                                      kPagePresent | kPageWritable | kPageUser | kPageNoExecute))
    {
        PanicAs("self-test: borrowed-range map refused test transaction", kBorrowedVa);
    }
    if (AddressSpaceProtectUserPage(a, kBorrowedVa, kPagePresent | kPageUser | kPageNoExecute))
    {
        PanicAs("self-test: owned-page protect accepted borrowed mapping", kBorrowedVa);
    }
    const PhysAddr wrong_frames[3] = {borrowed_frames[1], borrowed_frames[0], borrowed_frames[2]};
    if (AddressSpaceUnmapBorrowedRangeExpected(a, kBorrowedVa, wrong_frames, 3))
    {
        PanicAs("self-test: borrowed-range unmap accepted mismatched frame vector", kBorrowedVa);
    }
    for (u64 page = 0; page < 3; ++page)
    {
        if (AddressSpaceProbePte(a, kBorrowedVa + page * kPageSize) != borrowed_frames[page])
        {
            PanicAs("self-test: failed borrowed unmap partially cleared transaction", page);
        }
    }
    if (!AddressSpaceUnmapBorrowedRangeExpected(a, kBorrowedVa, borrowed_frames, 3))
    {
        PanicAs("self-test: borrowed-range expected unmap failed", kBorrowedVa);
    }
    for (u64 page = 0; page < 3; ++page)
    {
        if (AddressSpaceProbePte(a, kBorrowedVa + page * kPageSize) != kNullFrame)
        {
            PanicAs("self-test: borrowed-range PTE survived unmap", page);
        }
        FreeFrame(borrowed_frames[page]);
    }

    // Deliberately NOT flipping CR3 here. kernel_main runs on the
    // boot stack (.bss.boot — low-half VA, reachable only via
    // PML4[0] of the boot PML4). New ASes copy ONLY the kernel
    // half (PML4[256..511]), so switching CR3 to a freshly-made
    // AS while on the boot stack would triple-fault on the next
    // stack access. The switch mechanics are instead proven by
    // ring3_smoke (two tasks in two ASes run to completion on
    // KMalloc'd kernel stacks, which ARE in the higher-half
    // direct map and thus reachable after CR3 flip).
    //
    // If a worker-thread-hosted flavour of this self-test is ever
    // wanted, spawn it via sched::SchedCreate after scheduler
    // bring-up — the worker's kernel stack is in kernel-half, so
    // the CR3 flip is safe from that context.

    AddressSpaceRelease(a);
    AddressSpaceRelease(b);

    arch::SerialWrite("[mm/as] isolation self-test OK\n");
}

// ---------------------------------------------------------------------------
// TLB shootdown. See address_space.h for the contract.
//
// The caller is migration-pinned while the exact sparse active/ready peer
// set is snapshotted. Every target executes the invalidation through the
// confirmed IPI-call mailbox path; a slow peer is waited out, never treated
// as permission to reclaim. Not-yet-ready APs are excluded because their
// monotonic shootdown-domain join performs a full TLB flush before publish.
// ---------------------------------------------------------------------------

void TlbShootdownAddr(AddressSpace* as, u64 virt)
{
    const u64 start = virt & ~(kPageSize - 1);
    if (start > ~u64{0} - kPageSize)
    {
        PanicAs("TlbShootdownAddr range overflow", virt);
    }
    ConfirmedUserTlbShootdown(as, start, start + kPageSize);
}

void TlbShootdownRange(AddressSpace* as, u64 virt, u64 len)
{
    if (len == 0)
    {
        return;
    }
    if (virt > ~u64{0} - len)
    {
        PanicAs("TlbShootdownRange input overflow", virt);
    }
    const u64 raw_end = virt + len;
    if (raw_end > ~u64{0} - (kPageSize - 1))
    {
        PanicAs("TlbShootdownRange alignment overflow", raw_end);
    }
    const u64 start = virt & ~(kPageSize - 1);
    const u64 end = (raw_end + kPageSize - 1) & ~(kPageSize - 1);
    ConfirmedUserTlbShootdown(as, start, end);
}

} // namespace duetos::mm
