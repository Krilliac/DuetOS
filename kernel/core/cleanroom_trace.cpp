#include "cleanroom_trace.h"

#include "../sync/spinlock.h"

namespace duetos::core
{

namespace
{

constinit sync::SpinLock g_cleanroom_lock = {};
constinit CleanroomTraceEntry g_trace[kCleanroomTraceCapacity] = {};
constinit u32 g_head = 0;
constinit u32 g_count = 0;

void CopyBounded(char* dst, u32 cap, const char* src)
{
    if (dst == nullptr || cap == 0)
        return;
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < cap && src[i] != '\0'; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

} // namespace

void CleanroomTraceRecord(const char* subsystem, const char* event, u64 a, u64 b, u64 c)
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    CleanroomTraceEntry& e = g_trace[g_head];
    CopyBounded(e.subsystem, sizeof(e.subsystem), subsystem);
    CopyBounded(e.event, sizeof(e.event), event);
    e.a = a;
    e.b = b;
    e.c = c;
    g_head = (g_head + 1) % kCleanroomTraceCapacity;
    if (g_count < kCleanroomTraceCapacity)
        ++g_count;
}

u32 CleanroomTraceCount()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    return g_count;
}

bool CleanroomTraceRead(u32 index, CleanroomTraceEntry* out)
{
    if (out == nullptr)
        return false;
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    if (index >= g_count)
        return false;
    const u32 oldest = (g_head + kCleanroomTraceCapacity - g_count) % kCleanroomTraceCapacity;
    const u32 slot = (oldest + index) % kCleanroomTraceCapacity;
    *out = g_trace[slot];
    return true;
}

void CleanroomTraceClear()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    g_head = 0;
    g_count = 0;
    for (u32 i = 0; i < kCleanroomTraceCapacity; ++i)
        g_trace[i] = {};
}

u64 CleanroomTraceHashToken(const char* text)
{
    // Stable 64-bit FNV-1a for low-cardinality identifiers
    // (shell command names, event labels) so call sites can
    // record meaningful breadcrumbs without storing long text.
    constexpr u64 kOffset = 1469598103934665603ull;
    constexpr u64 kPrime = 1099511628211ull;
    u64 h = kOffset;
    if (text == nullptr)
        return h;
    for (u32 i = 0; text[i] != '\0'; ++i)
    {
        h ^= static_cast<u8>(text[i]);
        h *= kPrime;
    }
    return h;
}

} // namespace duetos::core
