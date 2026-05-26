/*
 * DuetOS — elevation grace cache, v0.
 *
 * See grace.h for the public contract and design rationale.
 */

#include "security/grace.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
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
bool g_initialized = false;

bool IsLive(const GraceEntry& e, u64 now_ns)
{
    return e.in_use && now_ns < e.deadline_ns;
}

// Find an existing row for (pid, cap). Returns kGraceCacheCapacity on
// miss. Treats expired rows as miss — caller must clear in_use when
// returning early because of expiry.
u32 FindRow(u64 pid, Cap cap, u64 now_ns)
{
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (g_rows[i].in_use && g_rows[i].pid == pid && g_rows[i].cap == cap)
        {
            if (g_rows[i].deadline_ns > now_ns)
                return i;
            // Expired — clear in place so an insert reuses the slot.
            g_rows[i].in_use = false;
        }
    }
    return kGraceCacheCapacity;
}

u32 AllocSlot()
{
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (!g_rows[i].in_use)
            return i;
    }
    // Full — evict the row with the earliest deadline.
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
    g_rows[victim].in_use = false;
    return victim;
}

} // namespace

void GraceCacheInit()
{
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
        g_rows[i].in_use = false;
    g_initialized = true;
}

bool GraceCacheLookup(u64 pid, Cap cap)
{
    if (cap == kCapNone || cap >= kCapCount)
        return false;
    const u64 now = duetos::time::MonotonicNs();
    return FindRow(pid, cap, now) != kGraceCacheCapacity;
}

bool GraceCacheInsert(u64 pid, Cap cap, u32 lifetime_seconds)
{
    if (cap == kCapNone || cap >= kCapCount)
        return false;
    if (lifetime_seconds == 0)
        return false; // no_cache semantics
    const u64 now = duetos::time::MonotonicNs();
    GraceCacheReap();
    u32 slot = FindRow(pid, cap, now);
    if (slot == kGraceCacheCapacity)
        slot = AllocSlot();
    // Slot postcondition. AllocSlot always returns a row in
    // [0, kGraceCacheCapacity) by construction — either an empty
    // slot or the eviction victim. A regression that broke that
    // invariant would let the write below silently scribble outside
    // g_rows[], poisoning the SECURITY-CRITICAL grace cache (a stale
    // PID/cap row past the array bound could falsely match a future
    // Lookup and grant a cached privilege the user never validated).
    KASSERT_WITH_VALUE(slot < kGraceCacheCapacity, "security/grace", "slot exceeds cache capacity",
                       static_cast<u64>(slot));
    GraceEntry& e = g_rows[slot];
    e.pid = pid;
    e.cap = cap;
    e.deadline_ns = now + static_cast<u64>(lifetime_seconds) * 1000000000ull;
    e.in_use = true;
    return true;
}

void GraceCacheExpirePid(u64 pid)
{
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (g_rows[i].in_use && g_rows[i].pid == pid)
            g_rows[i].in_use = false;
    }
}

u32 GraceCacheReap()
{
    const u64 now = duetos::time::MonotonicNs();
    u32 reaped = 0;
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (g_rows[i].in_use && g_rows[i].deadline_ns <= now)
        {
            g_rows[i].in_use = false;
            ++reaped;
        }
    }
    return reaped;
}

u32 GraceCacheLiveCount()
{
    const u64 now = duetos::time::MonotonicNs();
    u32 n = 0;
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (IsLive(g_rows[i], now))
            ++n;
    }
    return n;
}

bool GraceCacheEntryAt(u32 idx, GraceEntry* out)
{
    const u64 now = duetos::time::MonotonicNs();
    u32 seen = 0;
    for (u32 i = 0; i < kGraceCacheCapacity; ++i)
    {
        if (!IsLive(g_rows[i], now))
            continue;
        if (seen == idx)
        {
            if (out != nullptr)
                *out = g_rows[i];
            return true;
        }
        ++seen;
    }
    return false;
}

void GraceCacheSelfTest()
{
    arch::SerialWrite("[grace] self-test: insert/lookup/expire/reap\n");
    GraceCacheInit();

    constexpr u64 kFakePid = 0x4DC0DE;
    const Cap kTestCap = duetos::core::kCapFsWrite;

    if (GraceCacheLookup(kFakePid, kTestCap))
        Panic("grace", "empty cache returned a hit");

    if (!GraceCacheInsert(kFakePid, kTestCap, 60))
        Panic("grace", "insert with positive lifetime failed");
    if (!GraceCacheLookup(kFakePid, kTestCap))
        Panic("grace", "lookup missed a fresh insert");

    // no_cache lifetime → no row written.
    if (GraceCacheInsert(kFakePid + 1, kTestCap, 0))
        Panic("grace", "zero-lifetime insert wrote a row");
    if (GraceCacheLookup(kFakePid + 1, kTestCap))
        Panic("grace", "zero-lifetime lookup returned a hit");

    // ExpirePid drops every row for the pid.
    GraceCacheExpirePid(kFakePid);
    if (GraceCacheLookup(kFakePid, kTestCap))
        Panic("grace", "ExpirePid left a row behind");

    // Capacity sanity: fill then re-fill; we should never overflow.
    for (u32 i = 0; i < kGraceCacheCapacity + 4; ++i)
        GraceCacheInsert(0x10000 + i, kTestCap, 600);
    if (GraceCacheLiveCount() > kGraceCacheCapacity)
        Panic("grace", "live count exceeded capacity");

    GraceCacheInit();
    arch::SerialWrite("[grace] self-test: PASS\n");
}

} // namespace duetos::security
