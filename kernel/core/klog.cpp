#include "klog.h"

#include "../arch/x86_64/serial.h"

namespace customos::core
{

namespace
{

// In-kernel log ring — stores the last kLogRingCapacity entries so
// the panic path can dump recent history to serial even after a
// catastrophic halt. Fixed-size static storage (no allocation).
// Subsystem + message are static-string pointers; value is copied.
// Not SMP-safe — two CPUs racing can produce torn entries. Flagged
// for the SMP-safe-serial work.
struct LogEntry
{
    LogLevel level;
    bool has_value;
    const char* subsystem;
    const char* message;
    u64 value;
};

constinit LogEntry g_log_ring[kLogRingCapacity] = {};
constinit u64 g_log_ring_next = 0;  // monotonically increasing write cursor
constinit u64 g_log_ring_count = 0; // saturates at kLogRingCapacity

// Runtime severity threshold — set via SetLogThreshold. Lines with
// level < max(threshold, kKlogMinLevel) are silently dropped. Default
// matches the compile-time floor so behaviour is unchanged unless
// somebody explicitly raises it.
constinit LogLevel g_log_threshold = kKlogMinLevel;

inline void PushEntry(LogLevel level, const char* subsystem, const char* message, u64 value, bool has_value)
{
    const u64 slot = g_log_ring_next % kLogRingCapacity;
    g_log_ring[slot] = LogEntry{
        .level = level,
        .has_value = has_value,
        .subsystem = subsystem,
        .message = message,
        .value = value,
    };
    ++g_log_ring_next;
    if (g_log_ring_count < kLogRingCapacity)
    {
        ++g_log_ring_count;
    }
}

inline const char* LevelTag(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Debug:
        return "[D] ";
    case LogLevel::Info:
        return "[I] ";
    case LogLevel::Warn:
        return "[W] ";
    case LogLevel::Error:
        return "[E] ";
    }
    return "[?] ";
}

inline bool LevelEnabled(LogLevel level)
{
    const u8 floor = static_cast<u8>(kKlogMinLevel);
    const u8 runtime = static_cast<u8>(g_log_threshold);
    const u8 effective = floor > runtime ? floor : runtime;
    return static_cast<u8>(level) >= effective;
}

} // namespace

void SetLogThreshold(LogLevel level)
{
    g_log_threshold = level;
}

LogLevel GetLogThreshold()
{
    return g_log_threshold;
}

void Log(LogLevel level, const char* subsystem, const char* message)
{
    if (!LevelEnabled(level))
    {
        return;
    }
    arch::SerialWrite(LevelTag(level));
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n");

    PushEntry(level, subsystem, message, 0, false);
}

void LogWithValue(LogLevel level, const char* subsystem, const char* message, u64 value)
{
    if (!LevelEnabled(level))
    {
        return;
    }
    arch::SerialWrite(LevelTag(level));
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("   val=");
    arch::SerialWriteHex(value);
    arch::SerialWrite("\n");

    PushEntry(level, subsystem, message, value, true);
}

void DumpLogRing()
{
    arch::SerialWrite("[panic] --- log ring (last ");
    arch::SerialWriteHex(g_log_ring_count);
    arch::SerialWrite(" entries, oldest first) ---\n");

    // Oldest entry lives at (next - count) mod capacity. Walk forward
    // `count` slots.
    const u64 start = g_log_ring_next - g_log_ring_count;
    for (u64 i = 0; i < g_log_ring_count; ++i)
    {
        const u64 slot = (start + i) % kLogRingCapacity;
        const LogEntry& e = g_log_ring[slot];
        // Defensive: a torn entry (SMP race, future concern) would
        // show as null pointers. Skip silently rather than deref.
        if (e.subsystem == nullptr || e.message == nullptr)
        {
            continue;
        }
        arch::SerialWrite(LevelTag(e.level));
        arch::SerialWrite(e.subsystem);
        arch::SerialWrite(" : ");
        arch::SerialWrite(e.message);
        if (e.has_value)
        {
            arch::SerialWrite("   val=");
            arch::SerialWriteHex(e.value);
        }
        arch::SerialWrite("\n");
    }
}

void KLogSelfTest()
{
    KLOG_DEBUG("core/klog", "debug-level sanity line");
    KLOG_INFO("core/klog", "info-level sanity line");
    KLOG_WARN("core/klog", "warn-level sanity line");
    KLOG_ERROR("core/klog", "error-level sanity line");
    KLOG_INFO_V("core/klog", "value-form sanity line", 0xCAFEBABE);
}

} // namespace customos::core
