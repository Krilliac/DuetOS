#include "diag/kstat.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sync/spinlock.h"

namespace duetos::diag
{

namespace
{

// Static entry table. Sized at compile time — there is no growth
// path for v0. Registration is boot-only; once the heartbeat starts
// emitting, every consumer just reads.
struct KstatEntry
{
    const char* module;
    const char* name;
    KstatKind kind;
    KstatReader reader;
    void* ctx;
};

KstatEntry g_entries[kMaxKstatEntries] = {};

// Live entry count. Bumped under `g_lock` during Register, observed
// lock-free by the walker / lookup. The store-release pattern
// (write fields, then publish the count last) makes a reader that
// sees count==N safe to read entries [0, N). Without a barrier here
// we'd be relying on x86's program-order writes; using the lock
// gives us that for free.
volatile u32 g_entries_count = 0;

// Aggregate stats for the registry itself. Updated under `g_lock`
// for the counters; `reads_total` is bumped lock-free under the
// hot read path.
u32 g_registrations_total = 0;
u32 g_register_failures = 0;
volatile u64 g_reads_total = 0;

// Registration spinlock. Walker and lookup do NOT take this — entries
// are write-once + count-bumped-after-fields-set, so a concurrent
// register racing with a read can at worst miss the new entry, never
// observe a torn one.
sync::SpinLock g_lock{};

// Cheap NUL-terminated string equality. The kernel has no <string.h>
// in scope here, and string compares are confined to the slow path
// (registration dup-check + the lookup-by-name in `KstatRead`), so a
// hand-rolled inner loop is fine.
bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return a == b;
    }
    while (*a != '\0' && *b != '\0')
    {
        if (*a != *b)
        {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

bool EntryMatches(const KstatEntry& e, const char* module, const char* name)
{
    return StrEq(e.module, module) && StrEq(e.name, name);
}

// ----- Formatting helpers for KstatFormatProcText. --------------
//
// All bounded — caller passes a buffer + cap and we never write past
// the cap. No allocations; no kernel-side printf dependency.

u64 AppendStr(char* buf, u64 cap, u64 cursor, const char* s)
{
    if (s == nullptr)
    {
        return cursor;
    }
    while (*s != '\0' && cursor < cap)
    {
        buf[cursor++] = *s++;
    }
    return cursor;
}

u64 AppendU64(char* buf, u64 cap, u64 cursor, u64 value)
{
    if (cursor >= cap)
    {
        return cursor;
    }
    if (value == 0)
    {
        buf[cursor++] = '0';
        return cursor;
    }
    char tmp[24];
    int n = 0;
    while (value != 0 && n < 24)
    {
        tmp[n++] = static_cast<char>('0' + (value % 10));
        value /= 10;
    }
    for (int i = n - 1; i >= 0 && cursor < cap; --i)
    {
        buf[cursor++] = tmp[i];
    }
    return cursor;
}

const char* KindName(KstatKind k)
{
    switch (k)
    {
    case KstatKind::Counter:
        return "counter";
    case KstatKind::Gauge:
        return "gauge";
    }
    return "?";
}

} // namespace

bool KstatRegister(const char* module, const char* name, KstatKind kind, KstatReader reader, void* ctx)
{
    if (module == nullptr || name == nullptr || reader == nullptr)
    {
        // Bad input is bad input — don't quietly succeed. Bump the
        // failure count so a misconfigured caller surfaces in
        // `KstatRegistryStatsRead`.
        sync::SpinLockGuard guard(g_lock);
        ++g_register_failures;
        return false;
    }

    sync::SpinLockGuard guard(g_lock);

    const u32 live = g_entries_count;

    // Duplicate-key refusal. Two callers registering the same
    // module:name almost certainly means a copy/paste bug — the
    // second registration would silently shadow the first. Reject
    // both with a failure tick + a klog-free return; the caller
    // owns the diagnostic.
    for (u32 i = 0; i < live; ++i)
    {
        if (EntryMatches(g_entries[i], module, name))
        {
            ++g_register_failures;
            return false;
        }
    }

    if (live >= kMaxKstatEntries)
    {
        ++g_register_failures;
        return false;
    }

    g_entries[live] = KstatEntry{module, name, kind, reader, ctx};
    // Publish the new entry by bumping the count LAST. A reader
    // walking without the lock either sees the old count (and skips
    // this entry) or the new one (and sees a fully-constructed
    // entry). x86's program-order store ordering is what makes this
    // safe; the spinlock release also fences.
    g_entries_count = live + 1;
    ++g_registrations_total;
    return true;
}

bool KstatRead(const char* module, const char* name, u64* out_value)
{
    if (module == nullptr || name == nullptr || out_value == nullptr)
    {
        return false;
    }
    // Snapshot the live count under the program-order rule the
    // registration path leans on. The walker doesn't need the lock.
    const u32 live = g_entries_count;
    for (u32 i = 0; i < live; ++i)
    {
        if (EntryMatches(g_entries[i], module, name))
        {
            __atomic_add_fetch(&g_reads_total, 1, __ATOMIC_RELAXED);
            *out_value = g_entries[i].reader(g_entries[i].ctx);
            return true;
        }
    }
    return false;
}

void KstatWalk(KstatWalkCb cb, void* cookie)
{
    if (cb == nullptr)
    {
        return;
    }
    const u32 live = g_entries_count;
    for (u32 i = 0; i < live; ++i)
    {
        const auto& e = g_entries[i];
        __atomic_add_fetch(&g_reads_total, 1, __ATOMIC_RELAXED);
        const u64 v = e.reader(e.ctx);
        cb(e.module, e.name, e.kind, v, cookie);
    }
}

u64 KstatFormatProcText(char* buf, u64 cap)
{
    if (buf == nullptr || cap == 0)
    {
        return 0;
    }

    u64 cursor = 0;
    cursor = AppendStr(buf, cap, cursor, "# /proc/kstat - unified kernel statistics.\n");
    cursor = AppendStr(buf, cap, cursor, "# Format: <module>:<name> <kind> <value>\n");

    const u32 live = g_entries_count;
    for (u32 i = 0; i < live; ++i)
    {
        const auto& e = g_entries[i];
        __atomic_add_fetch(&g_reads_total, 1, __ATOMIC_RELAXED);
        const u64 v = e.reader(e.ctx);

        cursor = AppendStr(buf, cap, cursor, e.module);
        cursor = AppendStr(buf, cap, cursor, ":");
        cursor = AppendStr(buf, cap, cursor, e.name);
        cursor = AppendStr(buf, cap, cursor, " ");
        cursor = AppendStr(buf, cap, cursor, KindName(e.kind));
        cursor = AppendStr(buf, cap, cursor, " ");
        cursor = AppendU64(buf, cap, cursor, v);
        cursor = AppendStr(buf, cap, cursor, "\n");
    }
    return cursor;
}

KstatRegistryStats KstatRegistryStatsRead()
{
    sync::SpinLockGuard guard(g_lock);
    return KstatRegistryStats{
        .entries_live = g_entries_count,
        .registrations_total = g_registrations_total,
        .register_failures = g_register_failures,
        .reads_total = g_reads_total,
    };
}

namespace
{

// Self-test fixtures. The reader takes its value from a static u64
// so we can drive specific values into the registry and read them
// back without involving any real subsystem.
u64 g_st_counter_a = 0;
u64 g_st_counter_b = 0;
u64 g_st_gauge_c = 0;

u64 ReadCounterA(void* /*ctx*/)
{
    return g_st_counter_a;
}
u64 ReadCounterB(void* /*ctx*/)
{
    return g_st_counter_b;
}
u64 ReadGaugeC(void* ctx)
{
    return *static_cast<u64*>(ctx);
}

struct WalkCounters
{
    u32 saw_counter_a;
    u32 saw_counter_b;
    u32 saw_gauge_c;
    u64 a_value;
    u64 b_value;
    u64 c_value;
};

void WalkAccumulate(const char* module, const char* name, KstatKind kind, u64 value, void* cookie)
{
    auto* w = static_cast<WalkCounters*>(cookie);
    if (StrEq(module, "kstat-selftest"))
    {
        if (StrEq(name, "counter_a") && kind == KstatKind::Counter)
        {
            ++w->saw_counter_a;
            w->a_value = value;
        }
        else if (StrEq(name, "counter_b") && kind == KstatKind::Counter)
        {
            ++w->saw_counter_b;
            w->b_value = value;
        }
        else if (StrEq(name, "gauge_c") && kind == KstatKind::Gauge)
        {
            ++w->saw_gauge_c;
            w->c_value = value;
        }
    }
}

} // namespace

void KstatSelfTest()
{
    arch::SerialWrite("[kstat] self-test: register + read + walk + dup-reject\n");

    // Seed the fixtures with distinct values.
    g_st_counter_a = 0x1111;
    g_st_counter_b = 0x2222;
    g_st_gauge_c = 0x3333;

    if (!KstatRegister("kstat-selftest", "counter_a", KstatKind::Counter, &ReadCounterA, nullptr))
    {
        core::Panic("diag/kstat", "self-test: counter_a register failed");
    }
    if (!KstatRegister("kstat-selftest", "counter_b", KstatKind::Counter, &ReadCounterB, nullptr))
    {
        core::Panic("diag/kstat", "self-test: counter_b register failed");
    }
    if (!KstatRegister("kstat-selftest", "gauge_c", KstatKind::Gauge, &ReadGaugeC, &g_st_gauge_c))
    {
        core::Panic("diag/kstat", "self-test: gauge_c register failed");
    }

    // Duplicate register MUST fail.
    if (KstatRegister("kstat-selftest", "counter_a", KstatKind::Counter, &ReadCounterA, nullptr))
    {
        core::Panic("diag/kstat", "self-test: duplicate register did not refuse");
    }

    // Direct reads.
    u64 v = 0;
    if (!KstatRead("kstat-selftest", "counter_a", &v) || v != 0x1111)
    {
        core::Panic("diag/kstat", "self-test: counter_a read mismatch");
    }
    if (!KstatRead("kstat-selftest", "counter_b", &v) || v != 0x2222)
    {
        core::Panic("diag/kstat", "self-test: counter_b read mismatch");
    }
    if (!KstatRead("kstat-selftest", "gauge_c", &v) || v != 0x3333)
    {
        core::Panic("diag/kstat", "self-test: gauge_c read mismatch");
    }
    // Lookup miss returns false.
    if (KstatRead("kstat-selftest", "does-not-exist", &v))
    {
        core::Panic("diag/kstat", "self-test: miss-lookup returned true");
    }

    // Mutate the gauge and re-read — confirms the reader is invoked
    // every time (not cached at registration).
    g_st_gauge_c = 0x4444;
    if (!KstatRead("kstat-selftest", "gauge_c", &v) || v != 0x4444)
    {
        core::Panic("diag/kstat", "self-test: gauge_c live re-read mismatch");
    }

    // Walker MUST observe all three of our entries.
    WalkCounters w = {};
    KstatWalk(&WalkAccumulate, &w);
    if (w.saw_counter_a != 1 || w.saw_counter_b != 1 || w.saw_gauge_c != 1)
    {
        core::Panic("diag/kstat", "self-test: walker did not observe all entries");
    }
    if (w.a_value != 0x1111 || w.b_value != 0x2222 || w.c_value != 0x4444)
    {
        core::Panic("diag/kstat", "self-test: walker observed wrong values");
    }

    // /proc/kstat format check. Just verify we wrote some bytes and
    // the buffer starts with our '#' header; the content correctness
    // is implicitly proven by the walker above.
    char fmt_buf[1024] = {};
    const u64 wrote = KstatFormatProcText(fmt_buf, sizeof(fmt_buf));
    if (wrote == 0 || fmt_buf[0] != '#')
    {
        core::Panic("diag/kstat", "self-test: format produced no/invalid output");
    }

    // Registry stats sanity. We've registered three entries above
    // (the production heartbeat registrations happen later, after
    // this self-test runs, so we can count exactly).
    const auto stats = KstatRegistryStatsRead();
    if (stats.entries_live < 3 || stats.registrations_total < 3)
    {
        core::Panic("diag/kstat", "self-test: registry stats not advanced");
    }
    if (stats.register_failures < 1)
    {
        core::Panic("diag/kstat", "self-test: register_failures did not record dup");
    }

    arch::SerialWrite("[kstat] self-test OK (register + read + walk + dup-reject + format).\n");
}

} // namespace duetos::diag
