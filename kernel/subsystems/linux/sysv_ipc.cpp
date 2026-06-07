/*
 * SysV IPC (shared memory + semaphores) — v0.
 *
 * Two engines in one TU because both share the same name+key
 * pool-allocator pattern and POSIX permission stubbing:
 *
 *   shmget / shmat / shmdt / shmctl — named shared memory.
 *     8-segment global pool. Each segment owns N physical frames
 *     (max 256 pages = 1 MiB / segment). Attach maps every frame
 *     into the caller's AS via AddressSpaceMapBorrowedPage at a
 *     bump-allocated VA in the per-process SHM arena. Detach
 *     reverses. Refcount = (handles outstanding) + (active
 *     attaches); IPC_RMID marks for destroy and frees frames
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
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u32 kShmPoolCap = 8;
constexpr u32 kShmMaxPages = 256; // 1 MiB / segment cap

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
    u8 _pad[2];
    u32 refcount; // attachments + open handles
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
    Semaphore sems[kSemPerSet];
};

ShmSegment g_shm_pool[kShmPoolCap];
SemSet g_sem_pool[kSemPoolCap];

// =========================================================
// SHM helpers
// =========================================================

i32 ShmFindByKey(i32 key)
{
    if (key == 0) // IPC_PRIVATE
        return -1;
    for (u32 i = 0; i < kShmPoolCap; ++i)
        if (g_shm_pool[i].in_use && !g_shm_pool[i].marked_destroy && g_shm_pool[i].key == key)
            return static_cast<i32>(i);
    return -1;
}

i32 ShmAlloc(i32 key, u64 size)
{
    if (size == 0)
        return -1;
    // Bound `size` BEFORE the page round-up: `size + kPage - 1`
    // wraps for size in [U64_MAX-4094, U64_MAX], yielding a tiny
    // page_count that would pass the kShmMaxPages check below and
    // turn a near-U64_MAX request into a silent 1-page segment.
    if (size > static_cast<u64>(kShmMaxPages) * kPage)
        return -1;
    const u64 page_count = (size + kPage - 1) / kPage;
    if (page_count > kShmMaxPages)
        return -1;
    arch::Cli();
    for (u32 i = 0; i < kShmPoolCap; ++i)
    {
        if (g_shm_pool[i].in_use)
            continue;
        ShmSegment& s = g_shm_pool[i];
        s.in_use = true;
        s.marked_destroy = false;
        s.refcount = 1; // shmget itself holds the initial reference
        s.key = key;
        s.owner_pid = (core::CurrentProcess() != nullptr) ? core::CurrentProcess()->pid : 0;
        s.page_count = static_cast<u32>(page_count);
        s.size_bytes = page_count * kPage;
        arch::Sti();
        // Allocate the frame array + physical frames OUTSIDE Cli/Sti.
        s.frames = static_cast<mm::PhysAddr*>(mm::KMalloc(sizeof(mm::PhysAddr) * page_count));
        if (s.frames == nullptr)
        {
            arch::Cli();
            s.in_use = false;
            arch::Sti();
            return -1;
        }
        bool ok = true;
        for (u32 p = 0; p < page_count; ++p)
        {
            const mm::PhysAddr f = mm::AllocateFrame().value_or(mm::kNullFrame);
            if (f == mm::kNullFrame)
            {
                // Roll back already-allocated frames.
                for (u32 q = 0; q < p; ++q)
                    mm::FreeFrame(s.frames[q]);
                mm::KFree(s.frames);
                arch::Cli();
                s.frames = nullptr;
                s.in_use = false;
                arch::Sti();
                ok = false;
                break;
            }
            // Zero-fill the frame (Linux SHM guarantees zero on
            // first access). PhysToVirt gives a kernel-direct
            // map pointer so we can write to the frame here.
            volatile u8* page = reinterpret_cast<u8*>(mm::PhysToVirt(f));
            for (u32 b = 0; b < kPage; ++b)
                page[b] = 0;
            s.frames[p] = f;
        }
        if (!ok)
            return -1;
        return static_cast<i32>(i);
    }
    arch::Sti();
    return -1;
}

void ShmMaybeFreeLocked(ShmSegment& s)
{
    // Caller holds arch::Cli.
    if (!s.in_use || s.refcount > 0 || !s.marked_destroy)
        return;
    mm::PhysAddr* frames = s.frames;
    const u32 count = s.page_count;
    s.frames = nullptr;
    s.page_count = 0;
    s.size_bytes = 0;
    s.in_use = false;
    s.marked_destroy = false;
    s.key = 0;
    arch::Sti();
    for (u32 i = 0; i < count; ++i)
        mm::FreeFrame(frames[i]);
    mm::KFree(frames);
    arch::Cli();
}

} // namespace

// =========================================================
// shmget / shmat / shmdt / shmctl
// =========================================================

i64 DoShmget(u64 key, u64 size, u64 shmflg)
{
    const i32 ikey = static_cast<i32>(key);
    const bool create = (shmflg & kIpcCreat) != 0;
    const bool excl = (shmflg & kIpcExcl) != 0;
    if (ikey != 0)
    {
        const i32 existing = ShmFindByKey(ikey);
        if (existing >= 0)
        {
            if (create && excl)
                return -17; // -EEXIST
            arch::Cli();
            ++g_shm_pool[existing].refcount;
            arch::Sti();
            return existing + 1; // shmid = pool_idx + 1
        }
        if (!create)
            return -2; // -ENOENT
    }
    const i32 idx = ShmAlloc(ikey, size);
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

i64 DoShmat(u64 shmid, u64 shmaddr, u64 shmflg)
{
    if (shmid == 0 || shmid > kShmPoolCap)
        return -22; // -EINVAL
    const u32 idx = static_cast<u32>(shmid - 1);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return -22;

    arch::Cli();
    if (!g_shm_pool[idx].in_use || g_shm_pool[idx].marked_destroy)
    {
        arch::Sti();
        return -22;
    }
    // IPC_PRIVATE isolation: a key == 0 segment has no sharing token, so only
    // its creator may attach. Keyed segments stay shareable (POSIX). This
    // closes the brute-force-shmid cross-process leak without breaking keyed
    // cross-process sharing.
    if (g_shm_pool[idx].key == 0 && g_shm_pool[idx].owner_pid != p->pid)
    {
        arch::Sti();
        return -13; // -EACCES
    }
    const u32 page_count = g_shm_pool[idx].page_count;
    arch::Sti();

    // Find a free attach slot.
    i32 slot = -1;
    for (u32 i = 0; i < core::Process::kLinuxShmAttachCap; ++i)
        if (!p->linux_shm_attaches[i].in_use)
        {
            slot = static_cast<i32>(i);
            break;
        }
    if (slot < 0)
        return -24; // -EMFILE

    // Pick a base VA. shmaddr == 0 → bump-allocate from arena.
    u64 base = (shmaddr == 0) ? p->linux_shm_cursor : shmaddr;
    if ((base & (kPage - 1)) != 0)
        return -22; // misaligned

    // Reject attach targets in the kernel half — without this an
    // attacker holding a SysV shm key can pass shmaddr =
    // 0xFFFFFFFF80000000 and drive AddressSpaceMapBorrowedPage past
    // its kUserMax PanicAs gate (kernel DoS via mm/address_space.cpp).
    constexpr u64 kShmUserMaxExclusive = 0x0000800000000000ULL;
    const u64 want_bytes = static_cast<u64>(page_count) * kPage;
    if (base >= kShmUserMaxExclusive || want_bytes > (kShmUserMaxExclusive - base))
        return -22; // -EINVAL

    // Pin the segment, THEN map with interrupts enabled. The map
    // loop calls AddressSpaceMapBorrowedPage → WalkToPteIn(create) →
    // AllocateFrame; running up to kShmMaxPages (256) of that under
    // arch::Cli() is a long IRQ-off critical section (≈3 page-table
    // frame allocs/page) that starves the timer/scheduler — an
    // unprivileged ELF with a shm key could trigger it on demand.
    // Bumping seg.refcount here (under Cli, after re-validating)
    // pins the segment so a concurrent IPC_RMID cannot free
    // seg.frames while we map outside the lock — the same staged
    // discipline ShmAlloc/DoMsgsnd already use in this file.
    arch::Cli();
    auto& seg = g_shm_pool[idx];
    if (!seg.in_use || seg.marked_destroy)
    {
        arch::Sti();
        return -22;
    }
    // Snapshot frames + page count together under this lock so the
    // map loop can't mix a fresh frames[] with a stale count if the
    // pool slot was recycled (IPC_RMID + full detach + new shmget)
    // since the earlier validate.
    mm::PhysAddr* const frames = seg.frames;
    const u32 pages = seg.page_count;
    ++seg.refcount;
    arch::Sti();

    // Authoritative VA-range check against the pinned page count
    // (the pre-pin check above used a possibly-stale count). A page
    // past the user half would trip AddressSpaceMapBorrowedPage's
    // PanicAs gate (kernel halt) rather than fail gracefully.
    if (base >= kShmUserMaxExclusive || static_cast<u64>(pages) * kPage > (kShmUserMaxExclusive - base))
    {
        arch::Cli();
        if (seg.refcount > 0)
            --seg.refcount;
        ShmMaybeFreeLocked(seg);
        arch::Sti();
        return -22; // -EINVAL
    }

    // SHM_RDONLY drops the writable bit so a read-only attach can't be used to
    // mutate the segment. Default (no flag) keeps the writable mapping.
    const u64 kFlags = (shmflg & kShmRdonly) != 0
                           ? (mm::kPagePresent | mm::kPageUser | mm::kPageNoExecute)
                           : (mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute);
    bool ok = true;
    u32 mapped = 0;
    for (u32 i = 0; i < pages; ++i)
    {
        if (!mm::AddressSpaceMapBorrowedPage(p->as, base + i * kPage, frames[i], kFlags))
        {
            ok = false;
            break;
        }
        ++mapped;
    }
    if (!ok)
    {
        for (u32 i = 0; i < mapped; ++i)
            mm::AddressSpaceUnmapBorrowedPage(p->as, base + i * kPage);
        arch::Cli();
        if (seg.refcount > 0)
            --seg.refcount;
        ShmMaybeFreeLocked(seg);
        arch::Sti();
        return -12; // -ENOMEM
    }
    // refcount already bumped above (segment pinned); attach recorded below.

    p->linux_shm_attaches[slot].in_use = true;
    p->linux_shm_attaches[slot].shmid = static_cast<u32>(shmid);
    p->linux_shm_attaches[slot].base_va = base;
    p->linux_shm_attaches[slot].page_count = pages;
    if (shmaddr == 0)
        p->linux_shm_cursor = base + pages * kPage;

    arch::SerialWrite("[linux/shm] attach pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" shmid=");
    arch::SerialWriteHex(shmid);
    arch::SerialWrite(" va=");
    arch::SerialWriteHex(base);
    arch::SerialWrite(" pages=");
    arch::SerialWriteHex(page_count);
    arch::SerialWrite("\n");
    return static_cast<i64>(base);
}

i64 DoShmdt(u64 shmaddr)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return -22;
    for (u32 i = 0; i < core::Process::kLinuxShmAttachCap; ++i)
    {
        auto& att = p->linux_shm_attaches[i];
        if (!att.in_use || att.base_va != shmaddr)
            continue;
        const u32 idx = att.shmid - 1;
        if (idx >= kShmPoolCap)
            return -22;
        for (u32 pg = 0; pg < att.page_count; ++pg)
            mm::AddressSpaceUnmapBorrowedPage(p->as, att.base_va + pg * kPage);
        att.in_use = false;
        arch::Cli();
        ShmSegment& seg = g_shm_pool[idx];
        if (seg.refcount > 0)
            --seg.refcount;
        ShmMaybeFreeLocked(seg);
        arch::Sti();
        return 0;
    }
    return -22; // -EINVAL: shmaddr not an active attach
}

i64 DoShmctl(u64 shmid, u64 cmd, u64 user_buf)
{
    (void)user_buf; // shmid_ds copy-out / copy-in deferred; sub-GAP
    if (shmid == 0 || shmid > kShmPoolCap)
        return -22;
    const u32 idx = static_cast<u32>(shmid - 1);
    arch::Cli();
    ShmSegment& seg = g_shm_pool[idx];
    if (!seg.in_use)
    {
        arch::Sti();
        return -22;
    }
    if (cmd == kIpcRmid)
    {
        seg.marked_destroy = true;
        if (seg.refcount > 0)
            --seg.refcount; // drop the shmget initial reference
        ShmMaybeFreeLocked(seg);
        arch::Sti();
        return 0;
    }
    if (cmd == kIpcStat || cmd == kIpcSet || cmd == kIpcInfo)
    {
        arch::Sti();
        return 0; // accept-as-noop; struct copy is sub-GAP
    }
    arch::Sti();
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

i32 SemAlloc(i32 key, u32 nsems)
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
    const i32 idx = SemAlloc(ikey, static_cast<u32>(nsems));
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
    const u32 idx = static_cast<u32>(semid - 1);
    arch::Cli();
    SemSet& s = g_sem_pool[idx];
    if (!s.in_use)
    {
        arch::Sti();
        return -22;
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
