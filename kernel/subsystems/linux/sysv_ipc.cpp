/*
 * SysV IPC (shared memory + semaphores) — v0.
 *
 * Two engines in one TU because both share the same name+key
 * pool-allocator pattern and POSIX permission stubbing:
 *
 *   shmget / shmat / shmdt / shmctl — named shared memory.
 *     8-segment global pool. Each segment owns N physical frames
 *     (max 256 pages = 1 MiB / segment). Attach maps every frame
 *     into the caller's AS via AddressSpaceMapBorrowedRange at a
 *     bump-allocated VA in the per-process SHM arena. Detach
 *     reverses. Refcount = one allocation reference + active
 *     attaches; IPC_RMID drops the allocation reference and frees frames
 *     only when refcount hits zero.
 *
 *   semget / semop / semctl / semtimedop — named semaphore sets.
 *     8-set global pool, 16 semaphores per set. Each semaphore
 *     has a value + WaitQueue. semop runs a vector of operations
 *     atomically (acquire all under arch::Cli or block); supports
 *     the increment / decrement-with-wait / wait-on-zero shapes
 *     that real userland exercises.
 *
 * Sub-GAPs documented inline.
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u32 kShmPoolCap = 8;
constexpr u32 kShmMaxPages = 256; // 1 MiB / segment cap
constexpr i32 kShmAllocBusy = -2;

constexpr u32 kSemPoolCap = 8;
constexpr u32 kSemPerSet = 16;

// IPC flag bits
constexpr u64 kIpcCreat = 0x200;
constexpr u64 kIpcExcl = 0x400;
constexpr u64 kIpcNowait = 0x800; // semop SEM_NOWAIT

// shmat flag bits
constexpr u64 kShmRdonly = 0x1000; // SHM_RDONLY — attach read-only

// IPC commands
constexpr u64 kIpcRmid = 0;
constexpr u64 kIpcSet = 1;
constexpr u64 kIpcStat = 2;
constexpr u64 kIpcInfo = 3;
constexpr u64 kSemGetval = 12;
constexpr u64 kSemSetval = 16;

// Linux page size
constexpr u64 kPage = 4096ull;

struct ShmSegment
{
    bool in_use;
    bool marked_destroy;
    bool initializing;
    u8 _pad;
    u32 refcount; // initial allocation reference + active attaches
    i32 key;      // SysV key passed by the caller (IPC_PRIVATE = 0)
    u32 page_count;
    // Creating process. For IPC_PRIVATE (key == 0) segments — which carry no
    // sharing token — DoShmat refuses attach from any other pid so a
    // co-resident ELF cannot brute-force shmid 1..8 and map a private
    // segment. Keyed segments (key != 0) stay shareable by design.
    u64 owner_pid;
    u64 size_bytes;
    mm::PhysAddr* frames; // KMalloc'd page_count entries
};

struct Semaphore
{
    i32 value;
    sched::WaitQueue wq;
};

struct SemSet
{
    bool in_use;
    bool marked_destroy;
    u8 _pad[2];
    i32 key;
    u32 nsems;
    u32 _pad2;
    // Creating process. Only the owner (or a kCapDebug holder) may
    // RMID / SETVAL the set, so a co-resident ELF can't brute-force
    // semid 1..8 and destroy or poison another process's semaphores.
    u64 owner_pid;
    Semaphore sems[kSemPerSet];
};

ShmSegment g_shm_pool[kShmPoolCap];
sync::SpinLock g_shm_lock{};
SemSet g_sem_pool[kSemPoolCap];

// =========================================================
// SHM helpers
// =========================================================

// The Process VM transaction is the sole lock for this per-Process ledger.
// Keep the transient states fail-closed (`in_use == true`) so exec and final
// teardown never mistake an in-flight attach/detach for an empty row:
//
//   Free -> Reserved -> Published -> Claimed -> Free
//                       ^              |
//                       +--- Restore --+
//
// A reserved row has only `in_use` set. A claimed row has shmid == 0 while
// retaining the exact published base/page tuple. The Process VM mutex excludes
// peer syscalls, so an exact tuple is sufficient here; there is no callback or
// deferred worker that can outlive the transaction and require a generation.
struct ShmAttachReservation
{
    u32 slot{static_cast<u32>(core::Process::kLinuxShmAttachCap)};
};

struct ShmAttachClaim
{
    u32 slot{static_cast<u32>(core::Process::kLinuxShmAttachCap)};
    core::Process::LinuxShmAttach published{};
};

bool ShmAttachRowReserved(const core::Process::LinuxShmAttach& row)
{
    return row.in_use && row.shmid == 0 && row.base_va == 0 && row.page_count == 0;
}

bool ShmAttachRowClaimed(const core::Process::LinuxShmAttach& row, const ShmAttachClaim& claim)
{
    return row.in_use && row.shmid == 0 && row.base_va == claim.published.base_va &&
           row.page_count == claim.published.page_count;
}

bool ShmAttachReserve(core::Process* process, ShmAttachReservation* reservation)
{
    if (process == nullptr || reservation == nullptr)
        return false;
    for (u32 slot = 0; slot < core::Process::kLinuxShmAttachCap; ++slot)
    {
        auto& row = process->linux_shm_attaches[slot];
        if (row.in_use)
            continue;
        row = {};
        row.in_use = true;
        reservation->slot = slot;
        return true;
    }
    return false;
}

bool ShmAttachAbort(core::Process* process, const ShmAttachReservation& reservation)
{
    if (process == nullptr || reservation.slot >= core::Process::kLinuxShmAttachCap)
        return false;
    auto& row = process->linux_shm_attaches[reservation.slot];
    if (!ShmAttachRowReserved(row))
        return false;
    row = {};
    return true;
}

bool ShmAttachPublish(core::Process* process, const ShmAttachReservation& reservation, u32 shmid, u64 base_va,
                      u32 page_count)
{
    if (process == nullptr || reservation.slot >= core::Process::kLinuxShmAttachCap || shmid == 0 || base_va == 0 ||
        page_count == 0)
    {
        return false;
    }
    auto& row = process->linux_shm_attaches[reservation.slot];
    if (!ShmAttachRowReserved(row))
        return false;
    row.shmid = shmid;
    row.base_va = base_va;
    row.page_count = page_count;
    return true;
}

bool ShmAttachClaimByBase(core::Process* process, u64 base_va, ShmAttachClaim* claim)
{
    if (process == nullptr || claim == nullptr || base_va == 0)
        return false;
    for (u32 slot = 0; slot < core::Process::kLinuxShmAttachCap; ++slot)
    {
        auto& row = process->linux_shm_attaches[slot];
        if (!row.in_use || row.shmid == 0 || row.base_va != base_va || row.page_count == 0)
            continue;
        claim->slot = slot;
        claim->published = row;
        row = {};
        row.in_use = true;
        row.base_va = claim->published.base_va;
        row.page_count = claim->published.page_count;
        return true;
    }
    return false;
}

bool ShmAttachRestore(core::Process* process, const ShmAttachClaim& claim)
{
    if (process == nullptr || claim.slot >= core::Process::kLinuxShmAttachCap)
        return false;
    auto& row = process->linux_shm_attaches[claim.slot];
    if (!ShmAttachRowClaimed(row, claim))
        return false;
    row = claim.published;
    return true;
}

bool ShmAttachFinish(core::Process* process, const ShmAttachClaim& claim)
{
    if (process == nullptr || claim.slot >= core::Process::kLinuxShmAttachCap)
        return false;
    auto& row = process->linux_shm_attaches[claim.slot];
    if (!ShmAttachRowClaimed(row, claim))
        return false;
    row = {};
    return true;
}

// Caller holds g_shm_lock for the complete lookup.
i32 ShmFindByKeyLocked(i32 key)
{
    if (key == 0) // IPC_PRIVATE
        return -1;
    for (u32 i = 0; i < kShmPoolCap; ++i)
        if (g_shm_pool[i].in_use && !g_shm_pool[i].initializing && !g_shm_pool[i].marked_destroy &&
            g_shm_pool[i].key == key)
            return static_cast<i32>(i);
    return -1;
}

struct ShmRetiredFrames
{
    mm::PhysAddr* frames{};
    u32 count{};
};

// Caller holds g_shm_lock. Detach ownership only; physical release is a
// separate post-lock phase because FreeFrame/KFree are never spin-safe.
ShmRetiredFrames ShmRetireIfReadyLocked(ShmSegment& segment)
{
    if (!segment.in_use || segment.initializing || segment.refcount != 0 || !segment.marked_destroy)
        return {};
    ShmRetiredFrames retired{segment.frames, segment.page_count};
    segment = {};
    return retired;
}

void ShmReleaseRetiredFrames(const ShmRetiredFrames& retired)
{
    if (retired.frames == nullptr)
    {
        KASSERT(retired.count == 0, "linux/shm", "retired frame count without vector");
        return;
    }
    for (u32 page = 0; page < retired.count; ++page)
        mm::FreeFrame(retired.frames[page]);
    mm::KFree(retired.frames);
}

bool ShmDropReference(u32 slot)
{
    if (slot >= kShmPoolCap)
        return false;
    ShmRetiredFrames retired{};
    bool dropped = false;
    const sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_shm_lock);
    ShmSegment& segment = g_shm_pool[slot];
    if (segment.in_use && !segment.initializing && segment.refcount > 0)
    {
        --segment.refcount;
        retired = ShmRetireIfReadyLocked(segment);
        dropped = true;
    }
    sync::SpinLockRelease(g_shm_lock, lock_flags);
    ShmReleaseRetiredFrames(retired);
    return dropped;
}

i32 ShmAlloc(i32 key, u64 size, u64 owner_pid)
{
    if (size == 0 || size > static_cast<u64>(kShmMaxPages) * kPage)
        return -1;
    const u64 page_count = (size + kPage - 1) / kPage;
    if (page_count == 0 || page_count > kShmMaxPages)
        return -1;

    u32 slot = kShmPoolCap;
    sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_shm_lock);
    if (key != 0)
    {
        for (u32 i = 0; i < kShmPoolCap; ++i)
        {
            const ShmSegment& segment = g_shm_pool[i];
            if (segment.in_use && !segment.marked_destroy && segment.key == key)
            {
                sync::SpinLockRelease(g_shm_lock, lock_flags);
                return kShmAllocBusy;
            }
        }
    }
    for (u32 i = 0; i < kShmPoolCap; ++i)
    {
        if (g_shm_pool[i].in_use)
            continue;
        ShmSegment& segment = g_shm_pool[i];
        segment = {};
        segment.in_use = true;
        segment.initializing = true;
        segment.refcount = 1; // shmget owns the initial reference
        segment.key = key;
        segment.owner_pid = owner_pid;
        segment.page_count = static_cast<u32>(page_count);
        segment.size_bytes = page_count * kPage;
        slot = i;
        break;
    }
    sync::SpinLockRelease(g_shm_lock, lock_flags);
    if (slot == kShmPoolCap)
        return -1;

    // All fallible allocation and zero-fill work happens after the slot is
    // marked Initializing and after the global metadata lock is released.
    auto* frames = static_cast<mm::PhysAddr*>(mm::KMalloc(sizeof(mm::PhysAddr) * page_count));
    u32 allocated = 0;
    if (frames != nullptr)
    {
        for (; allocated < page_count; ++allocated)
        {
            const mm::PhysAddr frame = mm::AllocateFrame().value_or(mm::kNullFrame);
            if (frame == mm::kNullFrame)
                break;
            volatile u8* page = reinterpret_cast<u8*>(mm::PhysToVirt(frame));
            for (u32 byte = 0; byte < kPage; ++byte)
                page[byte] = 0;
            frames[allocated] = frame;
        }
    }

    const bool allocation_ok = frames != nullptr && allocated == page_count;
    bool published = false;
    lock_flags = sync::SpinLockAcquire(g_shm_lock);
    ShmSegment& segment = g_shm_pool[slot];
    if (segment.in_use && segment.initializing && segment.frames == nullptr && segment.key == key &&
        segment.owner_pid == owner_pid && segment.page_count == page_count)
    {
        if (allocation_ok)
        {
            segment.frames = frames;
            segment.initializing = false;
            published = true;
        }
        else
        {
            segment = {};
        }
    }
    sync::SpinLockRelease(g_shm_lock, lock_flags);

    if (!published)
    {
        for (u32 page = 0; page < allocated; ++page)
            mm::FreeFrame(frames[page]);
        if (frames != nullptr)
            mm::KFree(frames);
        return -1;
    }
    return static_cast<i32>(slot);
}


} // namespace

// =========================================================
// shmget / shmat / shmdt / shmctl
// =========================================================

i64 DoShmget(u64 key, u64 size, u64 shmflg)
{
    core::Process* process = core::CurrentProcess();
    if (process == nullptr)
        return -22;
    const i32 ikey = static_cast<i32>(key);
    const bool create = (shmflg & kIpcCreat) != 0;
    const bool excl = (shmflg & kIpcExcl) != 0;

    // A concurrent creator leaves a short-lived Initializing row. Retry
    // outside the spin lock so keyed shmget cannot create duplicate segments.
    constexpr u32 kCreateRetryLimit = 64;
    for (u32 attempt = 0; attempt < kCreateRetryLimit; ++attempt)
    {
        if (ikey != 0)
        {
            bool initializing = false;
            sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_shm_lock);
            const i32 existing = ShmFindByKeyLocked(ikey);
            if (existing >= 0)
            {
                if (create && excl)
                {
                    sync::SpinLockRelease(g_shm_lock, lock_flags);
                    return -17; // -EEXIST
                }
                sync::SpinLockRelease(g_shm_lock, lock_flags);
                return existing + 1;
            }
            for (u32 slot = 0; slot < kShmPoolCap; ++slot)
            {
                const ShmSegment& segment = g_shm_pool[slot];
                if (segment.in_use && segment.initializing && !segment.marked_destroy && segment.key == ikey)
                {
                    initializing = true;
                    break;
                }
            }
            sync::SpinLockRelease(g_shm_lock, lock_flags);
            if (initializing)
            {
                sched::SchedYield();
                continue;
            }
            if (!create)
                return -2; // -ENOENT
        }

        const i32 idx = ShmAlloc(ikey, size, process->pid);
        if (idx == kShmAllocBusy)
        {
            sched::SchedYield();
            continue;
        }
        if (idx < 0)
            return -28; // -ENOSPC
        arch::SerialWrite("[linux/shm] alloc idx=");
        arch::SerialWriteHex(static_cast<u64>(idx));
        arch::SerialWrite(" key=");
        arch::SerialWriteHex(static_cast<u64>(ikey));
        arch::SerialWrite(" size=");
        arch::SerialWriteHex(size);
        arch::SerialWrite("\n");
        return idx + 1;
    }
    return -11; // -EAGAIN: a keyed creator did not publish in bounded retries
}

i64 DoShmat(u64 shmid, u64 shmaddr, u64 shmflg)
{
    if (shmid == 0 || shmid > kShmPoolCap)
        return -22; // -EINVAL
    const u32 idx = static_cast<u32>(shmid - 1);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return -22;

    // Outermost transaction: attach-row selection, VA selection, borrowed
    // PTE commit, and row/cursor publication are one Process operation.
    core::ScopedProcessVmTransaction vm_transaction(p);

    // Pick a base VA. shmaddr == 0 → bump-allocate from arena.
    u64 base = (shmaddr == 0) ? p->linux_shm_cursor : shmaddr;
    if ((base & (kPage - 1)) != 0)
        return -22; // misaligned

    // Reject attach targets in the kernel half — without this an
    // attacker holding a SysV shm key can pass shmaddr =
    // 0xFFFFFFFF80000000 and drive AddressSpaceMapBorrowedRange past
    // its kUserMax PanicAs gate (kernel DoS via mm/address_space.cpp).
    constexpr u64 kShmUserMaxExclusive = 0x0000800000000000ULL;
    if (base >= kShmUserMaxExclusive)
        return -22; // -EINVAL

    // Reserve a fail-closed ledger row before pinning frames or touching PTEs.
    // Every failure below aborts this exact row before the VM lock is dropped.
    ShmAttachReservation reservation{};
    if (!ShmAttachReserve(p, &reservation))
        return -24; // -EMFILE

    // Pin the segment under the IRQ-safe global metadata lock, then release
    // that lock before page-table allocation or TLB work. The retained
    // reference keeps `frames` stable through map or rollback.
    sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_shm_lock);
    auto& seg = g_shm_pool[idx];
    const bool ref_saturated = seg.refcount == ~u32{0};
    if (!seg.in_use || seg.initializing || seg.marked_destroy || seg.frames == nullptr || seg.page_count == 0 ||
        (seg.key == 0 && seg.owner_pid != p->pid) || ref_saturated)
    {
        const bool denied_private =
            seg.in_use && !seg.initializing && !seg.marked_destroy && seg.key == 0 && seg.owner_pid != p->pid;
        sync::SpinLockRelease(g_shm_lock, lock_flags);
        const bool aborted = ShmAttachAbort(p, reservation);
        KASSERT(aborted, "linux/shm", "segment revalidation lost reserved attach row");
        return denied_private ? -13 : (ref_saturated ? -24 : -22);
    }
    // Snapshot and retain the exact frame vector in one locked step.
    mm::PhysAddr* const frames = seg.frames;
    const u32 pages = seg.page_count;
    ++seg.refcount;
    sync::SpinLockRelease(g_shm_lock, lock_flags);

    // Check the VA range against the pinned page count. A page past
    // the user half would trip AddressSpaceMapBorrowedRange's
    // PanicAs gate (kernel halt) rather than fail gracefully.
    if (base >= kShmUserMaxExclusive || static_cast<u64>(pages) * kPage > (kShmUserMaxExclusive - base))
    {
        const bool dropped = ShmDropReference(idx);
        KASSERT(dropped, "linux/shm", "range rejection lost segment reference");
        const bool aborted = ShmAttachAbort(p, reservation);
        KASSERT(aborted, "linux/shm", "range rejection lost reserved attach row");
        return -22; // -EINVAL
    }

    // SHM_RDONLY drops the writable bit so a read-only attach can't be used to
    // mutate the segment. Default (no flag) keeps the writable mapping.
    const u64 kFlags = (shmflg & kShmRdonly) != 0
                           ? (mm::kPagePresent | mm::kPageUser | mm::kPageNoExecute)
                           : (mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute);
    // Atomic range mapping either publishes every PTE or none of them. The
    // segment reference above keeps the frame vector alive while this sleeps.
    if (!mm::AddressSpaceMapBorrowedRange(p->as, base, frames, pages, kFlags))
    {
        const bool dropped = ShmDropReference(idx);
        KASSERT(dropped, "linux/shm", "map refusal lost segment reference");
        const bool aborted = ShmAttachAbort(p, reservation);
        KASSERT(aborted, "linux/shm", "map refusal lost reserved attach row");
        return -12; // -ENOMEM
    }
    // refcount already bumped above (segment pinned); attach recorded below.

    if (!ShmAttachPublish(p, reservation, static_cast<u32>(shmid), base, pages))
    {
        // Restore ownership before releasing the segment reference. Exact
        // expected-frame unmap cannot clear a newer borrowed view at this VA.
        const bool unmapped = mm::AddressSpaceUnmapBorrowedRangeExpected(p->as, base, frames, pages);
        KASSERT(unmapped, "linux/shm", "attach publish rollback mismatched borrowed frames");
        const bool aborted = ShmAttachAbort(p, reservation);
        KASSERT(aborted, "linux/shm", "attach publish rollback lost reserved row");
        const bool dropped = ShmDropReference(idx);
        KASSERT(dropped, "linux/shm", "publish rollback lost segment reference");
        return -12;
    }
    if (shmaddr == 0)
        p->linux_shm_cursor = base + pages * kPage;

    arch::SerialWrite("[linux/shm] attach pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" shmid=");
    arch::SerialWriteHex(shmid);
    arch::SerialWrite(" va=");
    arch::SerialWriteHex(base);
    arch::SerialWrite(" pages=");
    arch::SerialWriteHex(pages);
    arch::SerialWrite("\n");
    return static_cast<i64>(base);
}

i64 DoShmdt(u64 shmaddr)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return -22;

    core::ScopedProcessVmTransaction vm_transaction(p);
    ShmAttachClaim claim{};
    if (!ShmAttachClaimByBase(p, shmaddr, &claim))
        return -22;

    const u32 idx = claim.published.shmid - 1;
    if (idx >= kShmPoolCap)
    {
        const bool restored = ShmAttachRestore(p, claim);
        KASSERT(restored, "linux/shm", "invalid detach row could not be restored");
        return -22;
    }

    // Snapshot the pinned segment vector under the metadata critical section,
    // then drop it before the sleepable AddressSpace transaction.
    mm::PhysAddr* frames = nullptr;
    const sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_shm_lock);
    ShmSegment& seg = g_shm_pool[idx];
    if (seg.in_use && !seg.initializing && seg.frames != nullptr && seg.page_count == claim.published.page_count &&
        seg.refcount > 0)
    {
        frames = seg.frames;
    }
    sync::SpinLockRelease(g_shm_lock, lock_flags);
    if (frames == nullptr)
    {
        const bool restored = ShmAttachRestore(p, claim);
        KASSERT(restored, "linux/shm", "segment mismatch could not restore claimed attach row");
        return -22;
    }

    if (!mm::AddressSpaceUnmapBorrowedRangeExpected(p->as, claim.published.base_va, frames, claim.published.page_count))
    {
        const bool restored = ShmAttachRestore(p, claim);
        KASSERT(restored, "linux/shm", "failed exact unmap could not restore claimed attach row");
        return -22;
    }

    const bool finished = ShmAttachFinish(p, claim);
    KASSERT(finished, "linux/shm", "successful exact unmap lost claimed attach row");

    // Only after the PTEs and ledger row are gone may the attach reference
    // release the frame vector.
    const bool dropped = ShmDropReference(idx);
    KASSERT(dropped, "linux/shm", "successful detach lost segment reference");
    return 0;
}

void LinuxShmDrainProcess(core::Process* p)
{
    // Release every SHM attachment this process still holds at exit.
    //
    // DoShmat pins the segment with ++refcount and records the attach in
    // p->linux_shm_attaches[]. Before this drain existed, the only path that
    // dropped that reference was an explicit shmdt(2) — so a process that
    // exited while still attached, normally or by fault, leaked the reference
    // permanently. ShmRetireIfReadyLocked retires only at refcount == 0,
    // so the segment could never be collected and its pool slot never
    // returned. With kShmPoolCap == 8, eight such exits exhaust SysV SHM for
    // the rest of the boot, along with the backing frames.
    //
    // ProcessRelease calls this with no competing syscall and before releasing
    // the sole AddressSpace reference. Exact unmap precedes every attach-ref
    // drop, so no borrowed PTE can name a frame returned to the allocator.
    if (p == nullptr)
        return;
    for (u32 i = 0; i < core::Process::kLinuxShmAttachCap; ++i)
    {
        auto& att = p->linux_shm_attaches[i];
        if (!att.in_use)
            continue;
        const bool indexable = att.shmid != 0 && (att.shmid - 1) < kShmPoolCap;
        const u32 idx = indexable ? (att.shmid - 1) : 0;
        if (!indexable)
        {
            att = {};
            continue;
        }

        // Keep the attach reference live while taking an exact frame snapshot
        // and unmapping. If an invariant mismatch occurs, leak the reference
        // rather than free frames beneath a surviving borrowed PTE; AS teardown
        // immediately after this drain will still remove that PTE.
        mm::PhysAddr* frames = nullptr;
        const sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_shm_lock);
        ShmSegment& segment = g_shm_pool[idx];
        if (segment.in_use && !segment.initializing && segment.frames != nullptr && segment.refcount > 0 &&
            segment.page_count == att.page_count)
        {
            frames = segment.frames;
        }
        sync::SpinLockRelease(g_shm_lock, lock_flags);
        if (frames == nullptr || p->as == nullptr ||
            !mm::AddressSpaceUnmapBorrowedRangeExpected(p->as, att.base_va, frames, att.page_count))
        {
            arch::SerialWrite("[linux/shm] drain kept ref after exact-unmap mismatch pid=");
            arch::SerialWriteHex(p->pid);
            arch::SerialWrite(" va=");
            arch::SerialWriteHex(att.base_va);
            arch::SerialWrite("\n");
            continue;
        }

        att = {};
        const bool dropped = ShmDropReference(idx);
        KASSERT(dropped, "linux/shm", "drain exact unmap lost segment reference");
    }
}

i64 DoShmctl(u64 shmid, u64 cmd, u64 user_buf)
{
    (void)user_buf; // shmid_ds copy-out / copy-in deferred; sub-GAP
    if (shmid == 0 || shmid > kShmPoolCap)
        return -22;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return -22;
    const u32 idx = static_cast<u32>(shmid - 1);
    const bool has_debug = core::ProcessHasCap(p, core::kCapDebug);
    sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_shm_lock);
    ShmSegment& seg = g_shm_pool[idx];
    if (!seg.in_use || seg.initializing)
    {
        sync::SpinLockRelease(g_shm_lock, lock_flags);
        return -22;
    }
    // IPC_RMID / IPC_SET mutate shared state — only the creating
    // process (or a kCapDebug holder) may. Without this a co-resident
    // ELF could RMID a segment it never created, dropping the owner's
    // initial reference (a second RMID then frees the frames while a
    // peer still has them mapped — a cross-process UAF).
    const bool is_owner = (seg.owner_pid == p->pid) || has_debug;
    if ((cmd == kIpcRmid || cmd == kIpcSet) && !is_owner)
    {
        sync::SpinLockRelease(g_shm_lock, lock_flags);
        return -1; // -EPERM
    }
    if (cmd == kIpcRmid && seg.marked_destroy)
    {
        sync::SpinLockRelease(g_shm_lock, lock_flags);
        return -22; // the initial shmget reference was already consumed
    }
    if (cmd == kIpcRmid)
    {
        seg.marked_destroy = true;
        if (seg.refcount > 0)
            --seg.refcount; // drop the shmget initial reference
        const ShmRetiredFrames retired = ShmRetireIfReadyLocked(seg);
        sync::SpinLockRelease(g_shm_lock, lock_flags);
        ShmReleaseRetiredFrames(retired);
        return 0;
    }
    if (cmd == kIpcStat || cmd == kIpcSet || cmd == kIpcInfo)
    {
        sync::SpinLockRelease(g_shm_lock, lock_flags);
        return 0; // accept-as-noop; struct copy is sub-GAP
    }
    sync::SpinLockRelease(g_shm_lock, lock_flags);
    return -22;
}

// =========================================================
// semget / semop / semctl / semtimedop
// =========================================================

namespace
{

i32 SemFindByKey(i32 key)
{
    if (key == 0)
        return -1;
    for (u32 i = 0; i < kSemPoolCap; ++i)
        if (g_sem_pool[i].in_use && !g_sem_pool[i].marked_destroy && g_sem_pool[i].key == key)
            return static_cast<i32>(i);
    return -1;
}

i32 SemAlloc(i32 key, u32 nsems, u64 owner_pid)
{
    if (nsems == 0 || nsems > kSemPerSet)
        return -1;
    arch::Cli();
    for (u32 i = 0; i < kSemPoolCap; ++i)
    {
        if (g_sem_pool[i].in_use)
            continue;
        SemSet& s = g_sem_pool[i];
        s.in_use = true;
        s.marked_destroy = false;
        s.key = key;
        s.nsems = nsems;
        s.owner_pid = owner_pid;
        for (u32 j = 0; j < kSemPerSet; ++j)
        {
            s.sems[j].value = 0;
            s.sems[j].wq.head = nullptr;
            s.sems[j].wq.tail = nullptr;
        }
        arch::Sti();
        return static_cast<i32>(i);
    }
    arch::Sti();
    return -1;
}

} // namespace

i64 DoSemget(u64 key, u64 nsems, u64 semflg)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return -22;
    const i32 ikey = static_cast<i32>(key);
    const bool create = (semflg & kIpcCreat) != 0;
    const bool excl = (semflg & kIpcExcl) != 0;
    if (ikey != 0)
    {
        const i32 existing = SemFindByKey(ikey);
        if (existing >= 0)
        {
            if (create && excl)
                return -17;
            return existing + 1;
        }
        if (!create)
            return -2;
    }
    const i32 idx = SemAlloc(ikey, static_cast<u32>(nsems), p->pid);
    if (idx < 0)
        return -28;
    arch::SerialWrite("[linux/sem] alloc idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite(" key=");
    arch::SerialWriteHex(static_cast<u64>(ikey));
    arch::SerialWrite(" nsems=");
    arch::SerialWriteHex(nsems);
    arch::SerialWrite("\n");
    return idx + 1;
}

namespace
{

struct SemBuf
{
    u16 sem_num;
    i16 sem_op;
    i16 sem_flg;
};

// Try to apply every op atomically. Returns true on success (all
// applied). Returns false when any op would block; callers can
// then go to sleep on the first blocking semaphore. Caller holds
// arch::Cli.
bool SemTryApplyLocked(SemSet& s, const SemBuf* ops, u32 nops, u32* block_idx_out)
{
    // First pass: validate that every op can complete without
    // blocking. If not, identify which sem is the blocker.
    for (u32 i = 0; i < nops; ++i)
    {
        const u32 sn = ops[i].sem_num;
        if (sn >= s.nsems)
            return false;
        const i32 op = ops[i].sem_op;
        const i32 cur = s.sems[sn].value;
        if (op == 0 && cur != 0)
        {
            *block_idx_out = sn;
            return false;
        }
        if (op < 0 && cur + op < 0)
        {
            *block_idx_out = sn;
            return false;
        }
    }
    // Apply.
    for (u32 i = 0; i < nops; ++i)
    {
        const u32 sn = ops[i].sem_num;
        s.sems[sn].value += ops[i].sem_op;
    }
    // Wake every sem queue we touched (incremented). A real Linux
    // does selective wake based on the op; v0 wakes every sem
    // we incremented, callers re-check.
    for (u32 i = 0; i < nops; ++i)
    {
        if (ops[i].sem_op > 0)
            sched::WaitQueueWakeAll(&s.sems[ops[i].sem_num].wq);
    }
    return true;
}

} // namespace

i64 DoSemop(u64 semid, u64 user_ops, u64 nops)
{
    if (semid == 0 || semid > kSemPoolCap)
        return -22;
    if (nops == 0 || nops > kSemPerSet)
        return -22;
    const u32 idx = static_cast<u32>(semid - 1);

    SemBuf ops[kSemPerSet];
    if (!mm::CopyFromUser(ops, reinterpret_cast<const void*>(user_ops), sizeof(SemBuf) * nops))
        return -14; // -EFAULT

    // Detect SEM_NOWAIT: if ANY op carries IPC_NOWAIT we honour it
    // for the whole batch (matches Linux).
    bool nowait = false;
    for (u32 i = 0; i < nops; ++i)
        if ((static_cast<u32>(ops[i].sem_flg) & kIpcNowait) != 0)
            nowait = true;

    arch::Cli();
    SemSet& s = g_sem_pool[idx];
    if (!s.in_use || s.marked_destroy)
    {
        arch::Sti();
        return -22;
    }
    while (true)
    {
        u32 block_idx = 0;
        if (SemTryApplyLocked(s, ops, static_cast<u32>(nops), &block_idx))
        {
            arch::Sti();
            return 0;
        }
        if (nowait)
        {
            arch::Sti();
            return -11; // -EAGAIN
        }
        sched::WaitQueueBlock(&s.sems[block_idx].wq);
        arch::Cli();
        if (!s.in_use || s.marked_destroy)
        {
            arch::Sti();
            return -22; // semset removed under us
        }
    }
}

i64 DoSemtimedop(u64 semid, u64 user_ops, u64 nops, u64 user_timeout)
{
    (void)user_timeout; // timeout deferred — accept-as-untimed (sub-GAP)
    return DoSemop(semid, user_ops, nops);
}

i64 DoSemctl(u64 semid, u64 semnum, u64 cmd, u64 arg)
{
    if (semid == 0 || semid > kSemPoolCap)
        return -22;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return -22;
    const u32 idx = static_cast<u32>(semid - 1);
    arch::Cli();
    SemSet& s = g_sem_pool[idx];
    if (!s.in_use)
    {
        arch::Sti();
        return -22;
    }
    // Mutating ops (RMID / SETVAL / IPC_SET) require ownership — a
    // co-resident ELF must not destroy or poison another process's
    // semaphore set by guessing semid 1..8. Reads stay open.
    const bool is_owner = (s.owner_pid == p->pid) || core::ProcessHasCap(p, core::kCapDebug);
    const bool is_mutating = (cmd == kIpcRmid || cmd == kSemSetval || cmd == kIpcSet);
    if (is_mutating && !is_owner)
    {
        arch::Sti();
        return -1; // -EPERM
    }
    if (cmd == kIpcRmid)
    {
        s.marked_destroy = true;
        s.in_use = false;
        // Wake all waiters on every sem in the set so blocked
        // semop callers see -EIDRM (we report -EINVAL here to
        // keep the v0 errno-set small).
        for (u32 i = 0; i < s.nsems; ++i)
            sched::WaitQueueWakeAll(&s.sems[i].wq);
        arch::Sti();
        return 0;
    }
    if (cmd == kSemGetval)
    {
        if (semnum >= s.nsems)
        {
            arch::Sti();
            return -22;
        }
        const i32 val = s.sems[semnum].value;
        arch::Sti();
        return val;
    }
    if (cmd == kSemSetval)
    {
        if (semnum >= s.nsems)
        {
            arch::Sti();
            return -22;
        }
        // Clamp to Linux SEMVMX (32767). `arg` is a raw guest u64; an
        // unchecked static_cast<i32> lets a guest set the kernel
        // semaphore value to e.g. INT32_MIN, after which a peer's
        // semop `cur + op` arithmetic in SemTryApplyLocked signed-
        // overflows (UB) and the set is permanently wedged.
        constexpr u64 kSemVmx = 32767;
        if (arg > kSemVmx)
        {
            arch::Sti();
            return -34; // -ERANGE
        }
        s.sems[semnum].value = static_cast<i32>(arg);
        sched::WaitQueueWakeAll(&s.sems[semnum].wq);
        arch::Sti();
        return 0;
    }
    if (cmd == kIpcStat || cmd == kIpcSet)
    {
        arch::Sti();
        return 0; // semid_ds copy-out deferred (sub-GAP)
    }
    arch::Sti();
    return -22;
}

} // namespace duetos::subsystems::linux::internal
