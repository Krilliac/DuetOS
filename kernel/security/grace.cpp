/*
 * DuetOS elevation grace cache.
 *
 * Cache rows are prompt-suppression metadata. A Process owns the
 * authoritative lease deadline and lazily expires it before any
 * capability snapshot can authorize an operation.
 */

#include "security/grace.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sync/spinlock.h"
#include "time/timekeeper.h"
#include "util/types.h"

namespace duetos::security
{

using duetos::core::Cap;
using duetos::core::kCapCount;
using duetos::core::kCapNone;
using duetos::core::Panic;

namespace
{

GraceEntry g_rows[kGraceCacheCapacity];
sync::SpinLock g_grace_lock{};
u64 g_next_generation = 1;

bool IsValidCap(Cap cap)
{
    return cap != kCapNone && cap < kCapCount;
}

bool IsLive(const GraceEntry& entry, u64 now_ns)
{
    return entry.in_use && now_ns < entry.deadline_ns;
}

void ClearLocked(u32 index)
{
    sync::SpinLockAssertHeld(g_grace_lock);
    g_rows[index] = GraceEntry{};
}

u32 ReapLocked(u64 now_ns)
{
    sync::SpinLockAssertHeld(g_grace_lock);
    u32 reaped = 0;
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (g_rows[i].in_use && (now_ns == 0 || g_rows[i].deadline_ns <= now_ns))
        {
            ClearLocked(i);
            ++reaped;
        }
    }
    return reaped;
}

u32 FindLiveRowLocked(u64 pid, Cap cap, u64 now_ns)
{
    sync::SpinLockAssertHeld(g_grace_lock);
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (IsLive(g_rows[i], now_ns) && g_rows[i].pid == pid && g_rows[i].cap == cap)
            return i;
    }
    return kGraceCacheCapacity;
}

u32 AllocSlotLocked()
{
    sync::SpinLockAssertHeld(g_grace_lock);
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (!g_rows[i].in_use)
            return i;
    }

    u32 victim = 0;
    u64 earliest = g_rows[0].deadline_ns;
    for (u32 i = 1; i < kGraceCacheCapacity; ++i)
    {
        if (g_rows[i].deadline_ns < earliest)
        {
            earliest = g_rows[i].deadline_ns;
            victim = i;
        }
    }
    return victim;
}

u64 NextGenerationLocked()
{
    sync::SpinLockAssertHeld(g_grace_lock);
    u64 generation = g_next_generation++;
    if (generation == 0)
        generation = g_next_generation++;
    return generation;
}

bool InsertMetadataForSelfTest(u64 pid, Cap cap, u32 lifetime_seconds)
{
    if (!IsValidCap(cap) || lifetime_seconds == 0)
        return false;

    const u64 now = duetos::time::MonotonicNs();
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    ReapLocked(now);
    u32 slot = FindLiveRowLocked(pid, cap, now);
    if (slot == kGraceCacheCapacity)
        slot = AllocSlotLocked();
    g_rows[slot] = GraceEntry{
        pid, cap, now + static_cast<u64>(lifetime_seconds) * 1000000000ull, NextGenerationLocked(), true,
    };
    sync::SpinLockRelease(g_grace_lock, flags);
    return true;
}

} // namespace

void GraceCacheInit()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
        ClearLocked(i);
    sync::SpinLockRelease(g_grace_lock, flags);
}

bool GraceCacheLookup(u64 pid, Cap cap)
{
    if (!IsValidCap(cap))
        return false;

    const u64 now = duetos::time::MonotonicNs();
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    ReapLocked(now);
    const bool found = FindLiveRowLocked(pid, cap, now) != kGraceCacheCapacity;
    sync::SpinLockRelease(g_grace_lock, flags);
    return found;
}

bool GraceCacheTryGrant(core::Process* process, Cap cap)
{
    if (process == nullptr || !IsValidCap(cap))
        return false;

    const u64 now = duetos::time::MonotonicNs();
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    ReapLocked(now);
    const u32 slot = FindLiveRowLocked(process->pid, cap, now);
    bool granted = false;
    if (slot != kGraceCacheCapacity)
    {
        const GraceEntry row = g_rows[slot];
        granted = core::ProcessCapsGrantLease(process, cap, row.deadline_ns, row.generation);
        if (!granted)
            ClearLocked(slot);
    }
    sync::SpinLockRelease(g_grace_lock, flags);
    return granted;
}

bool GraceCacheGrantLease(core::Process* process, Cap cap, u32 lifetime_seconds)
{
    if (process == nullptr || !IsValidCap(cap) || lifetime_seconds == 0)
        return false;

    const u64 now = duetos::time::MonotonicNs();
    if (now == 0)
        return false;
    const u64 duration_ns = static_cast<u64>(lifetime_seconds) * 1000000000ull;
    const u64 deadline_ns = now + duration_ns;
    if (deadline_ns <= now)
        return false;

    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    ReapLocked(now);
    u32 slot = FindLiveRowLocked(process->pid, cap, now);
    if (slot == kGraceCacheCapacity)
        slot = AllocSlotLocked();
    const u64 generation = NextGenerationLocked();

    // Install authority first. A cache row must never claim a grant
    // that the Process ceiling rejected.
    const bool granted = core::ProcessCapsGrantLease(process, cap, deadline_ns, generation);
    if (granted)
    {
        g_rows[slot] = GraceEntry{
            process->pid, cap, deadline_ns, generation, true,
        };
    }
    sync::SpinLockRelease(g_grace_lock, flags);
    return granted;
}

void GraceCacheExpire(u64 pid, Cap cap)
{
    if (!IsValidCap(cap))
        return;

    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (g_rows[i].in_use && g_rows[i].pid == pid && g_rows[i].cap == cap)
            ClearLocked(i);
    }
    sync::SpinLockRelease(g_grace_lock, flags);
}

void GraceCacheExpirePid(u64 pid)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (g_rows[i].in_use && g_rows[i].pid == pid)
            ClearLocked(i);
    }
    sync::SpinLockRelease(g_grace_lock, flags);
}

u32 GraceCacheReap()
{
    const u64 now = duetos::time::MonotonicNs();
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    const u32 reaped = ReapLocked(now);
    sync::SpinLockRelease(g_grace_lock, flags);
    return reaped;
}

u32 GraceCacheLiveCount()
{
    const u64 now = duetos::time::MonotonicNs();
    u32 count = 0;
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    ReapLocked(now);
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (IsLive(g_rows[i], now))
            ++count;
    }
    sync::SpinLockRelease(g_grace_lock, flags);
    return count;
}

bool GraceCacheEntryAt(u32 idx, GraceEntry* out)
{
    const u64 now = duetos::time::MonotonicNs();
    u32 seen = 0;
    bool found = false;
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_grace_lock);
    ReapLocked(now);
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (!IsLive(g_rows[i], now))
            continue;
        if (seen++ != idx)
            continue;
        if (out != nullptr)
            *out = g_rows[i];
        found = true;
        break;
    }
    sync::SpinLockRelease(g_grace_lock, flags);
    return found;
}

void GraceCacheSelfTest()
{
    arch::SerialWrite("[grace] self-test: lock/lazy-lease/eviction\n");
    GraceCacheInit();

    constexpr u64 kFakePid = 0x4DC0DE;
    const Cap kTestCap = core::kCapFsWrite;
    static core::Process process{};
    process.pid = kFakePid;
    if (core::AuthorizationContextKeyIsValid(process.authorization) &&
        !core::AuthorizationRelease(&process.authorization))
        Panic("grace", "synthetic authorization reset failed");
    if (!core::AuthorizationCreateTrusted(core::CapSetEmpty(), core::CapSetTrusted(), core::kTickBudgetTrusted,
                                          &process.authorization))
        Panic("grace", "synthetic authorization create failed");

    if (GraceCacheLookup(kFakePid, kTestCap))
        Panic("grace", "empty cache returned a hit");
    if (GraceCacheGrantLease(&process, kTestCap, 0) || GraceCacheLookup(kFakePid, kTestCap))
        Panic("grace", "zero-lifetime lease was not fail-closed");

    if (duetos::time::MonotonicNs() == 0)
    {
        if (GraceCacheGrantLease(&process, kTestCap, 60))
            Panic("grace", "clockless lease grant did not fail closed");
    }
    else
    {
        if (GraceCacheGrantLease(&process, kTestCap, 60) == false || !GraceCacheLookup(kFakePid, kTestCap) ||
            !core::ProcessHasCap(&process, kTestCap))
            Panic("grace", "positive lease was not published");

        // Cache removal is metadata-only. The Process lease remains
        // usable only until its original authoritative deadline.
        GraceCacheExpirePid(kFakePid);
        if (GraceCacheLookup(kFakePid, kTestCap) || !core::ProcessHasCap(&process, kTestCap))
            Panic("grace", "metadata expiry changed Process lease authority");
        core::ProcessCapsDisableMask(&process, 1ULL << static_cast<u32>(kTestCap));

        GraceCacheInit();
        for (u32 i = 0; i < kGraceCacheCapacity; ++i)
        {
            if (!InsertMetadataForSelfTest(0x10000 + i, kTestCap, 600 + i))
                Panic("grace", "capacity setup insert failed");
        }
        if (!InsertMetadataForSelfTest(0x20000, kTestCap, 1200) || GraceCacheLiveCount() != kGraceCacheCapacity ||
            GraceCacheLookup(0x10000, kTestCap) || !GraceCacheLookup(0x20000, kTestCap))
            Panic("grace", "earliest metadata eviction failed");
    }

    GraceCacheInit();
    if (!core::AuthorizationRelease(&process.authorization))
        Panic("grace", "synthetic authorization release failed");
    arch::SerialWrite("[grace] self-test: PASS\n");
}

} // namespace duetos::security
