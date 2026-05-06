#include "debug/tripwire.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sync/spinlock.h"
#include "util/crc32.h"

namespace duetos::debug
{

namespace
{

struct Entry
{
    const char* name;    // caller-supplied static string; nullptr = free row
    u64 addr;            // VA of watched region
    u64 len_bytes;       // > 0 when armed
    u32 expected_crc;    // baseline taken at install / Refresh
    u32 last_actual_crc; // most recent Verify result (0 before first scan)
    TripwireAction action;
    bool armed;         // false after a Panic-action row has fired
    u64 verify_count;   // # scans that have walked past this row
    u64 mismatch_count; // # of those that found a mismatch
};

// .bss-resident — sized for "more than the 4 hardware DR slots, but
// still bounded so a buggy install loop can't grow forever". 16 rows
// is comfortably above any realistic kernel-debugging session and
// fits in one cache line per row × 16 = 1 KiB total.
constexpr u8 kMaxTripwires = 16;

constinit Entry g_table[kMaxTripwires] = {};
constinit ::duetos::sync::SpinLock g_table_lock = {};

const char* ActionName(TripwireAction a)
{
    switch (a)
    {
    case TripwireAction::Log:
        return "log";
    case TripwireAction::LogEach:
        return "log-each";
    case TripwireAction::Panic:
        return "panic";
    }
    return "?";
}

bool NameEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    for (u32 k = 0;; ++k)
    {
        if (a[k] != b[k])
            return false;
        if (a[k] == 0)
            return true;
    }
}

// Caller holds g_table_lock.
Entry* FindByName(const char* name)
{
    if (name == nullptr)
        return nullptr;
    for (u8 i = 0; i < kMaxTripwires; ++i)
    {
        if (g_table[i].name != nullptr && NameEq(g_table[i].name, name))
            return &g_table[i];
    }
    return nullptr;
}

// Caller holds g_table_lock.
Entry* FindFreeSlot()
{
    for (u8 i = 0; i < kMaxTripwires; ++i)
    {
        if (g_table[i].name == nullptr)
            return &g_table[i];
    }
    return nullptr;
}

u32 ComputeCrc(u64 va, u64 len)
{
    return ::duetos::util::Crc32(reinterpret_cast<const u8*>(va), len);
}

} // namespace

bool Tripwire(const char* name, const void* addr, u64 len_bytes, TripwireAction action)
{
    if (name == nullptr || addr == nullptr || len_bytes == 0)
    {
        arch::SerialWrite("[tripwire] install REJECTED — bad name/addr/len\n");
        return false;
    }
    const u64 va = reinterpret_cast<u64>(addr);
    const u32 baseline = ComputeCrc(va, len_bytes);
    {
        ::duetos::sync::SpinLockGuard guard(g_table_lock);
        if (FindByName(name) != nullptr)
        {
            arch::SerialWrite("[tripwire] install REJECTED — name already in use: \"");
            arch::SerialWrite(name);
            arch::SerialWrite("\"\n");
            return false;
        }
        Entry* slot = FindFreeSlot();
        if (slot == nullptr)
        {
            arch::SerialWrite("[tripwire] install REJECTED — table full (max=");
            arch::SerialWriteHex(static_cast<u64>(kMaxTripwires));
            arch::SerialWrite(")\n");
            return false;
        }
        slot->name = name;
        slot->addr = va;
        slot->len_bytes = len_bytes;
        slot->expected_crc = baseline;
        slot->last_actual_crc = baseline;
        slot->action = action;
        slot->armed = true;
        slot->verify_count = 0;
        slot->mismatch_count = 0;
    }
    arch::SerialWrite("[tripwire] armed name=\"");
    arch::SerialWrite(name);
    arch::SerialWrite("\" va=");
    arch::SerialWriteHex(va);
    arch::SerialWrite(" len=");
    arch::SerialWriteHex(len_bytes);
    arch::SerialWrite(" crc=");
    arch::SerialWriteHex(static_cast<u64>(baseline));
    arch::SerialWrite(" action=");
    arch::SerialWrite(ActionName(action));
    arch::SerialWrite("\n");
    return true;
}

bool TripwireRemove(const char* name)
{
    ::duetos::sync::SpinLockGuard guard(g_table_lock);
    Entry* e = FindByName(name);
    if (e == nullptr)
        return false;
    e->name = nullptr;
    e->addr = 0;
    e->len_bytes = 0;
    e->expected_crc = 0;
    e->last_actual_crc = 0;
    e->armed = false;
    e->verify_count = 0;
    e->mismatch_count = 0;
    return true;
}

bool TripwireRefresh(const char* name)
{
    // Compute the new CRC outside the lock — the region read can be
    // arbitrarily large, and holding the table lock across it would
    // serialise unrelated installs. The window between read and store
    // is benign: any concurrent writer that would invalidate the new
    // baseline will be caught by the NEXT Verify scan.
    u64 va = 0;
    u64 len = 0;
    {
        ::duetos::sync::SpinLockGuard guard(g_table_lock);
        Entry* e = FindByName(name);
        if (e == nullptr)
            return false;
        va = e->addr;
        len = e->len_bytes;
    }
    const u32 baseline = ComputeCrc(va, len);
    {
        ::duetos::sync::SpinLockGuard guard(g_table_lock);
        Entry* e = FindByName(name);
        if (e == nullptr)
            return false; // raced with Remove — caller can retry
        e->expected_crc = baseline;
        e->last_actual_crc = baseline;
        e->armed = true;
    }
    return true;
}

usize TripwireVerify()
{
    // Snapshot row metadata under the lock, then run CRC walks
    // outside it. Each scan can be O(MB) of memory; holding the
    // table lock across it would block install/remove unnecessarily.
    struct Snap
    {
        const char* name;
        u64 addr;
        u64 len;
        u32 expected;
        TripwireAction action;
        bool armed;
        u8 idx;
    } rows[kMaxTripwires];
    u8 row_count = 0;
    {
        ::duetos::sync::SpinLockGuard guard(g_table_lock);
        for (u8 i = 0; i < kMaxTripwires; ++i)
        {
            if (g_table[i].name == nullptr || !g_table[i].armed)
                continue;
            rows[row_count] = {g_table[i].name,
                               g_table[i].addr,
                               g_table[i].len_bytes,
                               g_table[i].expected_crc,
                               g_table[i].action,
                               true,
                               i};
            ++row_count;
        }
    }
    usize mismatches = 0;
    for (u8 r = 0; r < row_count; ++r)
    {
        const u32 actual = ComputeCrc(rows[r].addr, rows[r].len);
        const bool ok = (actual == rows[r].expected);
        u64 hits_after = 0;
        bool first_mismatch = false;
        {
            ::duetos::sync::SpinLockGuard guard(g_table_lock);
            Entry* e = &g_table[rows[r].idx];
            // Row may have been removed mid-scan — rebind by name to
            // be safe. If it's gone, just skip the bookkeeping.
            if (e->name == nullptr || !NameEq(e->name, rows[r].name))
                continue;
            ++e->verify_count;
            e->last_actual_crc = actual;
            if (!ok)
            {
                first_mismatch = (e->mismatch_count == 0);
                ++e->mismatch_count;
                hits_after = e->mismatch_count;
                if (rows[r].action == TripwireAction::Panic)
                    e->armed = false; // disarm so a re-Verify doesn't double-fire
            }
        }
        if (!ok)
        {
            ++mismatches;
            const bool emit =
                (rows[r].action == TripwireAction::LogEach) ||
                ((rows[r].action == TripwireAction::Log || rows[r].action == TripwireAction::Panic) && first_mismatch);
            if (emit)
            {
                arch::SerialWrite("[tripwire] HIT name=\"");
                arch::SerialWrite(rows[r].name);
                arch::SerialWrite("\" va=");
                arch::SerialWriteHex(rows[r].addr);
                arch::SerialWrite(" len=");
                arch::SerialWriteHex(rows[r].len);
                arch::SerialWrite(" expected_crc=");
                arch::SerialWriteHex(static_cast<u64>(rows[r].expected));
                arch::SerialWrite(" actual_crc=");
                arch::SerialWriteHex(static_cast<u64>(actual));
                arch::SerialWrite(" hits=");
                arch::SerialWriteHex(hits_after);
                arch::SerialWrite("\n");
            }
            if (rows[r].action == TripwireAction::Panic && first_mismatch)
            {
                ::duetos::core::PanicWithValue("debug/tripwire", rows[r].name, rows[r].addr);
            }
        }
    }
    return mismatches;
}

usize TripwireList(TripwireInfo* out, usize cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    usize n = 0;
    ::duetos::sync::SpinLockGuard guard(g_table_lock);
    for (u8 i = 0; i < kMaxTripwires && n < cap; ++i)
    {
        if (g_table[i].name == nullptr)
            continue;
        out[n].name = g_table[i].name;
        out[n].addr = g_table[i].addr;
        out[n].len_bytes = g_table[i].len_bytes;
        out[n].expected_crc = g_table[i].expected_crc;
        out[n].last_actual_crc = g_table[i].last_actual_crc;
        out[n].action = g_table[i].action;
        out[n].verify_count = g_table[i].verify_count;
        out[n].mismatch_count = g_table[i].mismatch_count;
        out[n].armed = g_table[i].armed;
        ++n;
    }
    return n;
}

bool TripwireSelfTest()
{
    constexpr const char kName[] = "tripwire-selftest";
    // 32-byte buffer — enough for a non-trivial CRC, small enough to
    // keep the self-test fast. Volatile so the compiler can't elide
    // the post-arm scribble.
    volatile u8 buf[32] = {};
    for (u8 i = 0; i < 32; ++i)
        buf[i] = static_cast<u8>(0xA5 ^ i);
    arch::SerialWrite("[tripwire] selftest: arming on stack-local va=");
    arch::SerialWriteHex(reinterpret_cast<u64>(const_cast<u8*>(buf)));
    arch::SerialWrite("\n");
    if (!Tripwire(kName, const_cast<u8*>(buf), 32, TripwireAction::Log))
    {
        arch::SerialWrite("[tripwire] selftest FAILED — install rejected\n");
        return false;
    }
    if (TripwireVerify() != 0)
    {
        arch::SerialWrite("[tripwire] selftest FAILED — clean buffer mismatched immediately\n");
        TripwireRemove(kName);
        return false;
    }
    // Scribble — a CRC over 32 bytes WILL change with one byte flip.
    buf[7] ^= 0xFF;
    if (TripwireVerify() != 1)
    {
        arch::SerialWrite("[tripwire] selftest FAILED — scribble didn't trip\n");
        TripwireRemove(kName);
        return false;
    }
    // Refresh adopts the new state as baseline; next verify must be green.
    if (!TripwireRefresh(kName))
    {
        arch::SerialWrite("[tripwire] selftest FAILED — refresh returned false\n");
        TripwireRemove(kName);
        return false;
    }
    if (TripwireVerify() != 0)
    {
        arch::SerialWrite("[tripwire] selftest FAILED — post-refresh verify still mismatches\n");
        TripwireRemove(kName);
        return false;
    }
    if (!TripwireRemove(kName))
    {
        arch::SerialWrite("[tripwire] selftest FAILED — remove returned false\n");
        return false;
    }
    arch::SerialWrite("[tripwire] selftest OK\n");
    return true;
}

} // namespace duetos::debug
