#include "debug/watch.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "core/panic.h"
#include "debug/breakpoints.h"
#include "sync/spinlock.h"
#include "util/symbols.h"

namespace duetos::debug
{

namespace
{

// One row per concurrently-installed watchpoint. The hardware ceiling
// is 4 (DR0..DR3); the table size matches that. Slot is "free" iff
// `id.value == kBpIdNone.value`.
struct Entry
{
    BreakpointId id;    // returned by BpInstallHardware (matches BP-subsystem id)
    const char* name;   // caller-supplied static string
    u64 addr;           // watched VA
    u64 hit_count;      // bumped on every #DB hit
    u8 len_bytes;       // 1 / 2 / 4 / 8
    WatchAction action; // what to do on hit
};

constexpr u8 kMaxWatches = 4; // DR0..DR3 ceiling; matches hw

// .bss-resident — zero on construction.
constinit Entry g_table[kMaxWatches] = {};
constinit ::duetos::sync::SpinLock g_table_lock = {};

bool LenIsValid(u8 n)
{
    return n == 1 || n == 2 || n == 4 || n == 8;
}

BpLen LenToEnum(u8 n)
{
    switch (n)
    {
    case 1:
        return BpLen::One;
    case 2:
        return BpLen::Two;
    case 4:
        return BpLen::Four;
    default:
        return BpLen::Eight;
    }
}

const char* ActionName(WatchAction a)
{
    switch (a)
    {
    case WatchAction::LogOnce:
        return "log-once";
    case WatchAction::LogEachHit:
        return "log-each";
    case WatchAction::Panic:
        return "panic";
    }
    return "?";
}

// Look up an entry by BreakpointId. Returns nullptr if not found.
// Caller holds g_table_lock OR is in trap context (which is single-CPU
// w.r.t. itself; concurrent #DB on another CPU is handled by the per-
// row id comparison being a single u32 read).
Entry* FindById(BreakpointId id)
{
    for (u8 i = 0; i < kMaxWatches; ++i)
    {
        if (g_table[i].id.value == id.value && id.value != kBpIdNone.value)
        {
            return &g_table[i];
        }
    }
    return nullptr;
}

Entry* FindByName(const char* name)
{
    if (name == nullptr)
        return nullptr;
    for (u8 i = 0; i < kMaxWatches; ++i)
    {
        if (g_table[i].id.value == kBpIdNone.value)
            continue;
        const char* n = g_table[i].name;
        if (n == nullptr)
            continue;
        bool eq = true;
        for (u32 k = 0;; ++k)
        {
            if (n[k] != name[k])
            {
                eq = false;
                break;
            }
            if (n[k] == 0)
                break;
        }
        if (eq)
            return &g_table[i];
    }
    return nullptr;
}

Entry* FindFreeSlot()
{
    for (u8 i = 0; i < kMaxWatches; ++i)
    {
        if (g_table[i].id.value == kBpIdNone.value)
            return &g_table[i];
    }
    return nullptr;
}

// Trap-context callback. Runs with interrupts disabled. Looks up the
// row, prints a structured hit line, executes the configured action.
void OnHit(BreakpointId id, ::duetos::arch::TrapFrame* frame)
{
    Entry* e = FindById(id);
    if (e == nullptr)
    {
        // Stale BP id reached our dispatcher — the underlying BP table
        // forwarded a hit for an entry our wrapper doesn't track. Log
        // once and continue; the BP subsystem's accounting still runs.
        arch::SerialWrite("[watch] HIT (unknown id=");
        arch::SerialWriteHex(static_cast<u64>(id.value));
        arch::SerialWrite(") rip=");
        ::duetos::core::WriteAddressWithSymbol(frame != nullptr ? frame->rip : 0);
        arch::SerialWrite("\n");
        return;
    }
    const u64 hits_after = ++e->hit_count;
    const bool emit_log = (e->action == WatchAction::LogEachHit) ||
                          ((e->action == WatchAction::LogOnce || e->action == WatchAction::Panic) && hits_after == 1);
    if (emit_log)
    {
        arch::SerialWrite("[watch] HIT name=\"");
        arch::SerialWrite(e->name != nullptr ? e->name : "?");
        arch::SerialWrite("\" va=");
        arch::SerialWriteHex(e->addr);
        arch::SerialWrite(" rip=");
        const u64 rip = frame != nullptr ? frame->rip : 0;
        ::duetos::core::WriteAddressWithSymbol(rip);
        arch::SerialWrite(" rsp=");
        arch::SerialWriteHex(frame != nullptr ? frame->rsp : 0);
        arch::SerialWrite(" hits=");
        arch::SerialWriteHex(hits_after);
        arch::SerialWrite("\n");
    }
    if (e->action == WatchAction::Panic)
    {
        // Build a panic message that names the watch + its address.
        // PanicWithValue takes a single u64 — feed it the writer's RIP
        // so the panic banner pins the offending instruction directly.
        // Note: PanicWithValue is [[noreturn]] and dumps full state;
        // serial output above gives the symbolised RIP first in case
        // the panic path itself trips on something downstream.
        ::duetos::core::PanicWithValue("debug/watch", e->name != nullptr ? e->name : "watch",
                                       frame != nullptr ? frame->rip : 0);
    }
}

} // namespace

bool Watch(const char* name, const void* addr, u8 len_bytes, WatchAction action)
{
    if (name == nullptr || addr == nullptr || !LenIsValid(len_bytes))
    {
        arch::SerialWrite("[watch] install REJECTED — bad name/addr/len\n");
        return false;
    }
    const u64 va = reinterpret_cast<u64>(addr);
    {
        ::duetos::sync::SpinLockGuard guard(g_table_lock);
        if (FindByName(name) != nullptr)
        {
            arch::SerialWrite("[watch] install REJECTED — name already in use: \"");
            arch::SerialWrite(name);
            arch::SerialWrite("\"\n");
            return false;
        }
        Entry* slot = FindFreeSlot();
        if (slot == nullptr)
        {
            arch::SerialWrite("[watch] install REJECTED — table full (max=");
            arch::SerialWriteHex(static_cast<u64>(kMaxWatches));
            arch::SerialWrite(")\n");
            return false;
        }
        BpError err = BpError::None;
        const BreakpointId id = BpInstallHardware(va, BpKind::HwWrite, LenToEnum(len_bytes),
                                                  /*owner_pid=*/0, /*suspend_on_hit=*/false, &err, OnHit);
        if (id.value == kBpIdNone.value)
        {
            arch::SerialWrite("[watch] install FAILED — BpInstallHardware err=");
            arch::SerialWriteHex(static_cast<u64>(err));
            arch::SerialWrite(" name=\"");
            arch::SerialWrite(name);
            arch::SerialWrite("\"\n");
            return false;
        }
        slot->id = id;
        slot->name = name;
        slot->addr = va;
        slot->hit_count = 0;
        slot->len_bytes = len_bytes;
        slot->action = action;
    }
    arch::SerialWrite("[watch] armed name=\"");
    arch::SerialWrite(name);
    arch::SerialWrite("\" va=");
    arch::SerialWriteHex(va);
    arch::SerialWrite(" len=");
    arch::SerialWriteHex(static_cast<u64>(len_bytes));
    arch::SerialWrite(" action=");
    arch::SerialWrite(ActionName(action));
    arch::SerialWrite("\n");
    return true;
}

bool WatchRemove(const char* name)
{
    BreakpointId id_to_remove = kBpIdNone;
    {
        ::duetos::sync::SpinLockGuard guard(g_table_lock);
        Entry* e = FindByName(name);
        if (e == nullptr)
            return false;
        id_to_remove = e->id;
        e->id = kBpIdNone;
        e->name = nullptr;
        e->addr = 0;
        e->hit_count = 0;
        e->len_bytes = 0;
    }
    // Drop the underlying BP outside the lock — BpRemove serialises
    // through the BP subsystem's own lock; nesting them invites a
    // future lockdep flag.
    const BpError err = BpRemove(id_to_remove, /*requester_pid=*/0);
    if (err != BpError::None)
    {
        arch::SerialWrite("[watch] remove WARNING — BpRemove err=");
        arch::SerialWriteHex(static_cast<u64>(err));
        arch::SerialWrite(" (table row already cleared)\n");
    }
    return true;
}

usize WatchList(WatchInfo* out, usize cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    usize n = 0;
    ::duetos::sync::SpinLockGuard guard(g_table_lock);
    for (u8 i = 0; i < kMaxWatches && n < cap; ++i)
    {
        if (g_table[i].id.value == kBpIdNone.value)
            continue;
        out[n].name = g_table[i].name;
        out[n].addr = g_table[i].addr;
        out[n].len_bytes = g_table[i].len_bytes;
        out[n].action = g_table[i].action;
        out[n].hit_count = g_table[i].hit_count;
        ++n;
    }
    return n;
}

bool WatchSelfTest()
{
    // Watch a stack-local u64. Action = LogEachHit so the test stays
    // panic-free regardless of outcome.
    constexpr const char kName[] = "watch-selftest";
    volatile u64 target = 0;
    arch::SerialWrite("[watch] selftest: arming on stack-local va=");
    arch::SerialWriteHex(reinterpret_cast<u64>(const_cast<u64*>(&target)));
    arch::SerialWrite("\n");
    if (!Watch(kName, const_cast<u64*>(&target), 8, WatchAction::LogEachHit))
    {
        arch::SerialWrite("[watch] selftest FAILED — install rejected\n");
        return false;
    }
    // Trigger one hit. The compiler can't elide a write through volatile.
    target = 0xDEADBEEFCAFEBABEULL;
    // Read back to confirm the write went through.
    const u64 readback = target;
    if (readback != 0xDEADBEEFCAFEBABEULL)
    {
        WatchRemove(kName);
        arch::SerialWrite("[watch] selftest FAILED — write didn't land\n");
        return false;
    }
    // Snapshot to confirm the hit counter advanced.
    WatchInfo info{};
    const usize n = WatchList(&info, 1);
    bool ok = (n == 1) && (info.hit_count >= 1);
    if (!ok)
    {
        arch::SerialWrite("[watch] selftest FAILED — hit_count=");
        arch::SerialWriteHex(n == 1 ? info.hit_count : 0);
        arch::SerialWrite(" (expected >= 1)\n");
    }
    if (!WatchRemove(kName))
    {
        arch::SerialWrite("[watch] selftest WARNING — remove returned false\n");
        ok = false;
    }
    arch::SerialWrite(ok ? "[watch] selftest OK\n" : "[watch] selftest FAILED\n");
    return ok;
}

} // namespace duetos::debug
