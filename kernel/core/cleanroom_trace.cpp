#include "cleanroom_trace.h"

#include "../sync/spinlock.h"

namespace duetos::core
{

namespace
{

constinit sync::SpinLock g_cleanroom_lock = {};

// Sticky boot region — fills once, then locks. Captures the
// driver init / PE-loader / firmware-loader events that fire
// during the early-boot blast and would otherwise vanish under
// syscall load before any dump runs.
constinit CleanroomTraceEntry g_boot[kCleanroomTraceBootCapacity] = {};
constinit u32 g_boot_count = 0;

// Rolling tail — wraps over the most recent
// kCleanroomTraceRollingCapacity events for steady-state
// observation.
constinit CleanroomTraceEntry g_rolling[kCleanroomTraceRollingCapacity] = {};
constinit u32 g_rolling_head = 0;
constinit u32 g_rolling_count = 0;

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

void WriteEntry(CleanroomTraceEntry& e, const char* subsystem, const char* event, u64 a, u64 b, u64 c)
{
    CopyBounded(e.subsystem, sizeof(e.subsystem), subsystem);
    CopyBounded(e.event, sizeof(e.event), event);
    e.a = a;
    e.b = b;
    e.c = c;
}

} // namespace

void CleanroomTraceRecord(const char* subsystem, const char* event, u64 a, u64 b, u64 c)
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    if (g_boot_count < kCleanroomTraceBootCapacity)
    {
        WriteEntry(g_boot[g_boot_count], subsystem, event, a, b, c);
        ++g_boot_count;
        return;
    }
    WriteEntry(g_rolling[g_rolling_head], subsystem, event, a, b, c);
    g_rolling_head = (g_rolling_head + 1) % kCleanroomTraceRollingCapacity;
    if (g_rolling_count < kCleanroomTraceRollingCapacity)
        ++g_rolling_count;
}

u32 CleanroomTraceCount()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    return g_boot_count + g_rolling_count;
}

u32 CleanroomTraceBootCount()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    return g_boot_count;
}

u32 CleanroomTraceRollingCount()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    return g_rolling_count;
}

bool CleanroomTraceRead(u32 index, CleanroomTraceEntry* out)
{
    if (out == nullptr)
        return false;
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    if (index < g_boot_count)
    {
        *out = g_boot[index];
        return true;
    }
    const u32 rolling_index = index - g_boot_count;
    if (rolling_index >= g_rolling_count)
        return false;
    const u32 oldest =
        (g_rolling_head + kCleanroomTraceRollingCapacity - g_rolling_count) % kCleanroomTraceRollingCapacity;
    const u32 slot = (oldest + rolling_index) % kCleanroomTraceRollingCapacity;
    *out = g_rolling[slot];
    return true;
}

void CleanroomTraceClear()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    g_boot_count = 0;
    g_rolling_head = 0;
    g_rolling_count = 0;
    for (u32 i = 0; i < kCleanroomTraceBootCapacity; ++i)
        g_boot[i] = {};
    for (u32 i = 0; i < kCleanroomTraceRollingCapacity; ++i)
        g_rolling[i] = {};
}

u64 CleanroomTraceHashToken(const char* text)
{
    // FNV-1a 64-bit. The earlier revision of this function used a
    // truncated offset basis (1469598103934665603, missing the
    // trailing digit of the spec-correct value); the values below
    // are the real RFC-style FNV-1a-64 constants so external
    // decoders can use any standard FNV-1a-64 implementation
    // unchanged. Keep tools/cleanroom/decode_hash.py in lockstep.
    constexpr u64 kOffset = 14695981039346656037ull;
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
