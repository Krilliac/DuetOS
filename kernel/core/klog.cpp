#include "klog.h"

#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"

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

// Secondary sink. Set via SetLogTee once a framebuffer console (or
// any string consumer) is up. Timestamps are NOT forwarded — they
// would clutter on-screen output, and the serial log keeps them.
constinit LogTee g_tee = nullptr;

inline void Tee(const char* s)
{
    if (g_tee != nullptr && s != nullptr)
    {
        g_tee(s);
    }
}

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

// Write a u64 as decimal, no padding. Handles 0 explicitly.
// Max 20 digits fits any u64.
inline void WriteDecimal(u64 v)
{
    if (v == 0)
    {
        arch::SerialWriteByte('0');
        return;
    }
    char buf[20];
    int n = 0;
    while (v > 0)
    {
        buf[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n > 0)
    {
        arch::SerialWriteByte(static_cast<u8>(buf[--n]));
    }
}

// Hex without leading zeros. Always prints "0x"; 0 comes out as "0x0".
inline void WriteCompactHex(u64 v)
{
    arch::SerialWrite("0x");
    if (v == 0)
    {
        arch::SerialWriteByte('0');
        return;
    }
    // Find the highest non-zero nibble, then emit from there down.
    u32 start = 16;
    for (u32 i = 16; i > 0; --i)
    {
        if (((v >> ((i - 1) * 4)) & 0xF) != 0)
        {
            start = i;
            break;
        }
    }
    for (u32 i = start; i > 0; --i)
    {
        const u8 nib = static_cast<u8>((v >> ((i - 1) * 4)) & 0xF);
        const char c = (nib < 10) ? static_cast<char>('0' + nib) : static_cast<char>('a' + nib - 10);
        arch::SerialWriteByte(static_cast<u8>(c));
    }
}

// Append a decimal rendering after the hex when the value is small
// enough that decimal is actually easier to read than hex.
// Threshold = 1e12 covers every sector count, byte size up to 1 TB,
// tick counter, PID, etc. Pointers / bitmasks above that stay hex-only
// since decimal would just be a longer string of digits.
inline void MaybeAppendDecimal(u64 v)
{
    if (v < 1'000'000'000'000ULL)
    {
        arch::SerialWrite(" (");
        WriteDecimal(v);
        arch::SerialWrite(")");
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

// Timestamp rendering. We format wall time since boot — in
// microseconds when HPET is up, or scheduler ticks (10 ms units)
// when it isn't. The goal is something a human can glance at and
// immediately understand how long a boot phase took, without
// decoding HPET counts.
//
// Output formats (stable, grep-friendly):
//   HPET-backed : "[t=123.456ms] "  — millisecond + 3-digit fraction
//                 "[t=89us] "       — sub-millisecond, raw microseconds
//   Fallback    : "[t=50ms] "       — scheduler-tick * 10
//
// HPET period is in femtoseconds per tick. Microseconds = counter *
// period_fs / 1e9; we reorganise to avoid overflow by computing
// ticks-per-microsecond up front.
inline u64 ElapsedMicros()
{
    const u64 counter = arch::HpetReadCounter();
    if (counter == 0)
    {
        return 0;
    }
    const u32 period_fs = arch::HpetPeriodFemtoseconds();
    if (period_fs == 0)
    {
        return 0;
    }
    // ticks_per_us = 1e9 fs / period_fs. Integer division is fine
    // for the period values we actually see (100000000, 69841279).
    const u64 ticks_per_us = 1'000'000'000ULL / period_fs;
    if (ticks_per_us == 0)
    {
        return 0;
    }
    return counter / ticks_per_us;
}

inline void WriteTimestampPrefix()
{
    const u64 us = ElapsedMicros();
    if (us != 0)
    {
        if (us < 1000)
        {
            arch::SerialWrite("[t=");
            WriteDecimal(us);
            arch::SerialWrite("us] ");
        }
        else
        {
            const u64 ms_whole = us / 1000;
            const u64 us_frac = us % 1000;
            arch::SerialWrite("[t=");
            WriteDecimal(ms_whole);
            arch::SerialWrite(".");
            // Zero-pad to 3 digits.
            if (us_frac < 100)
                arch::SerialWriteByte('0');
            if (us_frac < 10)
                arch::SerialWriteByte('0');
            WriteDecimal(us_frac);
            arch::SerialWrite("ms] ");
        }
        return;
    }
    // HPET wasn't ready — fall back to the scheduler tick counter
    // (10 ms per tick). Prefix "~" as a reminder the precision is
    // coarse.
    const u64 ticks = arch::TimerTicks();
    arch::SerialWrite("[t~");
    WriteDecimal(ticks * 10);
    arch::SerialWrite("ms] ");
}

} // namespace

void SetLogThreshold(LogLevel level)
{
    g_log_threshold = level;
}

void SetLogTee(LogTee writer)
{
    g_tee = writer;
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
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    arch::SerialWrite(tag);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n");

    // Tee to the secondary sink (framebuffer console etc.). No
    // timestamp on this path — on-screen renderers want the text,
    // not the hex tick stamp. Chunk-by-chunk mirrors the serial
    // ordering so an interleaved IRQ tee doesn't scramble one
    // logical line.
    Tee(tag);
    Tee(subsystem);
    Tee(" : ");
    Tee(message);
    Tee("\n");

    PushEntry(level, subsystem, message, 0, false);
}

void LogWithValue(LogLevel level, const char* subsystem, const char* message, u64 value)
{
    if (!LevelEnabled(level))
    {
        return;
    }
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    arch::SerialWrite(tag);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("   val=");
    WriteCompactHex(value);
    MaybeAppendDecimal(value);
    arch::SerialWrite("\n");

    Tee(tag);
    Tee(subsystem);
    Tee(" : ");
    Tee(message);
    Tee("\n");

    PushEntry(level, subsystem, message, value, true);
}

void DumpLogRing()
{
    arch::SerialWrite("[panic] --- log ring (last ");
    WriteDecimal(g_log_ring_count);
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
            WriteCompactHex(e.value);
            MaybeAppendDecimal(e.value);
        }
        arch::SerialWrite("\n");
    }
}

void DumpLogRingTo(LogTee writer)
{
    if (writer == nullptr)
    {
        return;
    }
    // Oldest-first walk. No timestamp / header prefix — the
    // caller (shell `dmesg`) may want to frame its own banner.
    const u64 start = g_log_ring_next - g_log_ring_count;
    for (u64 i = 0; i < g_log_ring_count; ++i)
    {
        const u64 slot = (start + i) % kLogRingCapacity;
        const LogEntry& e = g_log_ring[slot];
        if (e.subsystem == nullptr || e.message == nullptr)
        {
            continue;
        }
        writer(LevelTag(e.level));
        writer(e.subsystem);
        writer(" : ");
        writer(e.message);
        writer("\n");
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
