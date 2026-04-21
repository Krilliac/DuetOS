#include "klog.h"

#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../sched/sched.h"

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
    u64 timestamp_us; // wall-time snapshot at write, 0 if HPET wasn't up
    const char* subsystem;
    const char* message;
    u64 value;
};

constinit LogEntry g_log_ring[kLogRingCapacity] = {};
constinit u64 g_log_ring_next = 0;  // monotonically increasing write cursor
constinit u64 g_log_ring_count = 0; // saturates at kLogRingCapacity

constinit bool g_color_enabled = true;

// Runtime severity threshold — set via SetLogThreshold. Lines with
// level < max(threshold, kKlogMinLevel) are silently dropped.
// Default is Info: the compile-time floor is Trace (so Trace calls
// exist in the binary), but the runtime default drops them. Users
// dial down to Trace via `loglevel t` when they want function
// entry / exit timing. This keeps boot logs readable by default
// while leaving deep instrumentation a shell command away.
constinit LogLevel g_log_threshold = LogLevel::Info;

// Secondary sink. Set via SetLogTee once a framebuffer console (or
// any string consumer) is up. Timestamps are NOT forwarded — they
// would clutter on-screen output, and the serial log keeps them.
constinit LogTee g_tee = nullptr;
constinit LogTee g_file_sink = nullptr;
constinit LogLevel g_file_sink_min_level = LogLevel::Info;
// Per-line current level: set at the top of Log/LogWithValue/etc;
// read by Tee when deciding whether to forward to the file sink.
// Racy under SMP; accept that for v0 — the pattern is single-CPU.
constinit LogLevel g_current_log_level = LogLevel::Debug;

inline void Tee(const char* s)
{
    if (s == nullptr)
    {
        return;
    }
    if (g_tee != nullptr)
    {
        g_tee(s);
    }
    // File sink respects its own minimum level so low-noise captures
    // (e.g. /tmp/boot.log on a 512-byte tmpfs file) don't fill up
    // with Debug ticks.
    if (g_file_sink != nullptr && static_cast<u8>(g_current_log_level) >= static_cast<u8>(g_file_sink_min_level))
    {
        g_file_sink(s);
    }
}

// Forward decl — defined below; PushEntry captures timestamp.
inline u64 ElapsedMicros();

inline void PushEntry(LogLevel level, const char* subsystem, const char* message, u64 value, bool has_value)
{
    const u64 slot = g_log_ring_next % kLogRingCapacity;
    g_log_ring[slot] = LogEntry{
        .level = level,
        .has_value = has_value,
        .timestamp_us = ElapsedMicros(),
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
    case LogLevel::Trace:
        return "[T] ";
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

// ANSI SGR escape sequences for severity colouring. `None` is the
// universal reset; everything else is a per-level foreground tint.
// Emitted only around the `[X]` tag so the subsystem + message
// bodies stay uncoloured (they'd clash with any in-text highlighting
// readers add manually, and the tag-only colour is enough to spot
// warns/errors on a busy boot log).
inline const char* LevelColorPrefix(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Trace:
        return "\x1b[36m"; // cyan — distinct from Debug's dim grey
    case LogLevel::Debug:
        return "\x1b[2m"; // dim
    case LogLevel::Info:
        return ""; // no tint — default terminal colour
    case LogLevel::Warn:
        return "\x1b[33m"; // yellow
    case LogLevel::Error:
        return "\x1b[1;31m"; // bold red
    }
    return "";
}

inline const char* kAnsiReset = "\x1b[0m";

// Emit the colour prefix for `level` iff colour is enabled. Safe to
// call when the terminal doesn't understand SGR — the escape shows
// up as literal bytes, which is already how a plain log-capture tool
// would render it. For that case, use `SetLogColor(false)`.
inline void OpenColor(LogLevel level)
{
    if (!g_color_enabled)
    {
        return;
    }
    const char* p = LevelColorPrefix(level);
    if (p[0] != 0)
    {
        arch::SerialWrite(p);
    }
}

inline void CloseColor(LogLevel level)
{
    if (!g_color_enabled)
    {
        return;
    }
    const char* p = LevelColorPrefix(level);
    if (p[0] != 0)
    {
        arch::SerialWrite(kAnsiReset);
    }
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

void SetLogFileSink(LogTee writer)
{
    g_file_sink = writer;
    // Back-fill: every log line that has fired up to now went through
    // Tee but not through this sink (it wasn't installed yet). Replay
    // the ring — with the current min-level filter applied — so the
    // file sink sees the relevant boot history.
    if (writer == nullptr)
    {
        return;
    }
    const u64 start = g_log_ring_next - g_log_ring_count;
    for (u64 i = 0; i < g_log_ring_count; ++i)
    {
        const u64 slot = (start + i) % kLogRingCapacity;
        const LogEntry& e = g_log_ring[slot];
        if (e.subsystem == nullptr || e.message == nullptr)
        {
            continue;
        }
        if (static_cast<u8>(e.level) < static_cast<u8>(g_file_sink_min_level))
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

void SetLogFileSinkMinLevel(LogLevel min_level)
{
    g_file_sink_min_level = min_level;
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
    g_current_log_level = level;
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    OpenColor(level);
    arch::SerialWrite(tag);
    CloseColor(level);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n");

    // Tee to the secondary sink (framebuffer console etc.). No
    // timestamp or ANSI codes on this path — on-screen renderers
    // want clean text and drive their own colour from LogLevel.
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
    g_current_log_level = level;
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    OpenColor(level);
    arch::SerialWrite(tag);
    CloseColor(level);
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

void LogWithString(LogLevel level, const char* subsystem, const char* message, const char* label, const char* value_str)
{
    if (!LevelEnabled(level))
    {
        return;
    }
    g_current_log_level = level;
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    OpenColor(level);
    arch::SerialWrite(tag);
    CloseColor(level);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("   ");
    arch::SerialWrite(label ? label : "str");
    arch::SerialWrite("=\"");
    arch::SerialWrite(value_str ? value_str : "(null)");
    arch::SerialWrite("\"\n");

    Tee(tag);
    Tee(subsystem);
    Tee(" : ");
    Tee(message);
    Tee(" ");
    Tee(label ? label : "str");
    Tee("=");
    Tee(value_str ? value_str : "(null)");
    Tee("\n");

    // Ring-buffer entry records the message only; the string pointer
    // would need per-entry deep-copy storage we don't have yet.
    PushEntry(level, subsystem, message, 0, false);
}

void LogWith2Values(LogLevel level, const char* subsystem, const char* message, const char* a_label, u64 a_value,
                    const char* b_label, u64 b_value)
{
    if (!LevelEnabled(level))
    {
        return;
    }
    g_current_log_level = level;
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    OpenColor(level);
    arch::SerialWrite(tag);
    CloseColor(level);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("   ");
    arch::SerialWrite(a_label ? a_label : "a");
    arch::SerialWrite("=");
    WriteCompactHex(a_value);
    MaybeAppendDecimal(a_value);
    arch::SerialWrite("   ");
    arch::SerialWrite(b_label ? b_label : "b");
    arch::SerialWrite("=");
    WriteCompactHex(b_value);
    MaybeAppendDecimal(b_value);
    arch::SerialWrite("\n");

    Tee(tag);
    Tee(subsystem);
    Tee(" : ");
    Tee(message);
    Tee("\n");

    // Record only the first value — a second u64 would bloat every
    // entry just to service the rarer 2-value path.
    PushEntry(level, subsystem, message, a_value, true);
}

void SetLogColor(bool enabled)
{
    g_color_enabled = enabled;
}

bool GetLogColor()
{
    return g_color_enabled;
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
        // Render the timestamp the entry was written with — same
        // format as live logging. Zero (HPET-wasn't-up) prints as
        // "[t=?]" so the gap is explicit.
        if (e.timestamp_us == 0)
        {
            arch::SerialWrite("[t=?] ");
        }
        else if (e.timestamp_us < 1000)
        {
            arch::SerialWrite("[t=");
            WriteDecimal(e.timestamp_us);
            arch::SerialWrite("us] ");
        }
        else
        {
            const u64 ms_whole = e.timestamp_us / 1000;
            const u64 us_frac = e.timestamp_us % 1000;
            arch::SerialWrite("[t=");
            WriteDecimal(ms_whole);
            arch::SerialWrite(".");
            if (us_frac < 100)
                arch::SerialWriteByte('0');
            if (us_frac < 10)
                arch::SerialWriteByte('0');
            WriteDecimal(us_frac);
            arch::SerialWrite("ms] ");
        }
        OpenColor(e.level);
        arch::SerialWrite(LevelTag(e.level));
        CloseColor(e.level);
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
    DumpLogRingToFiltered(writer, LogLevel::Debug);
}

void DumpLogRingToFiltered(LogTee writer, LogLevel min_level)
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
        if (static_cast<u8>(e.level) < static_cast<u8>(min_level))
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

// ---------------------------------------------------------------
// Trace scope tracking
// ---------------------------------------------------------------
//
// A fixed-size table of currently-entered scopes. On panic, each
// still-active slot emits "X entered at tN ms, still running for
// NN ms" so a hang tells you which function stopped making
// progress. Racy under SMP (multi-CPU scope enter/exit would want
// per-CPU tables); single-CPU today, so a global works.

namespace
{

struct InflightEntry
{
    const char* subsystem;
    const char* name;
    u64 enter_us;
    bool active;
};

constinit InflightEntry g_inflight[kScopeInflightCapacity] = {};

// Find the first free slot. Returns the index or -1.
i32 InflightClaim()
{
    for (u32 i = 0; i < kScopeInflightCapacity; ++i)
    {
        if (!g_inflight[i].active)
        {
            return static_cast<i32>(i);
        }
    }
    return -1;
}

void InflightRelease(i32 slot)
{
    if (slot >= 0 && static_cast<u32>(slot) < kScopeInflightCapacity)
    {
        g_inflight[slot].active = false;
    }
}

} // namespace

TraceScope::TraceScope(const char* subsystem, const char* name)
    : m_subsystem(subsystem), m_name(name), m_enter_us(ElapsedMicros()), m_slot(InflightClaim())
{
    if (m_slot >= 0)
    {
        g_inflight[m_slot].subsystem = subsystem;
        g_inflight[m_slot].name = name;
        g_inflight[m_slot].enter_us = m_enter_us;
        g_inflight[m_slot].active = true;
    }
    else
    {
        // Table full — one-shot warn so the user knows the hang
        // dump may be missing entries if we die from here on.
        KLOG_ONCE_WARN("core/klog", "trace inflight table full; hang diagnosis degraded");
    }

    // Runtime-gated Trace log. The call site couldn't know at
    // compile time whether the scope would fire, so the macro
    // already passed the compile-time gate; this call does the
    // runtime check inside Log().
    LogWithString(LogLevel::Trace, subsystem, "> enter", "fn", name);
}

TraceScope::~TraceScope()
{
    const u64 exit_us = ElapsedMicros();
    const u64 elapsed = (exit_us >= m_enter_us) ? (exit_us - m_enter_us) : 0;
    InflightRelease(m_slot);

    if (!LevelEnabled(LogLevel::Trace))
    {
        return;
    }
    // Hand-rolled line: we want "< exit   fn=\"name\"   elapsed_us=N"
    // which no existing helper produces (LogWithString lacks a second
    // labelled value; LogWith2Values can't carry a string).
    g_current_log_level = LogLevel::Trace;
    const char* tag = LevelTag(LogLevel::Trace);
    WriteTimestampPrefix();
    OpenColor(LogLevel::Trace);
    arch::SerialWrite(tag);
    CloseColor(LogLevel::Trace);
    arch::SerialWrite(m_subsystem);
    arch::SerialWrite(" : < exit   fn=\"");
    arch::SerialWrite(m_name);
    arch::SerialWrite("\"   elapsed_us=");
    WriteDecimal(elapsed);
    arch::SerialWrite("\n");

    Tee(tag);
    Tee(m_subsystem);
    Tee(" : < exit ");
    Tee(m_name);
    Tee("\n");

    PushEntry(LogLevel::Trace, m_subsystem, m_name, elapsed, true);
}

void DumpInflightScopes()
{
    // Walk the table; count active entries first so the banner
    // can report "N scopes still in flight" before the detail.
    u32 active = 0;
    for (u32 i = 0; i < kScopeInflightCapacity; ++i)
    {
        if (g_inflight[i].active)
            ++active;
    }
    if (active == 0)
    {
        arch::SerialWrite("[panic] no scopes in flight at panic\n");
        return;
    }
    arch::SerialWrite("[panic] --- ");
    WriteDecimal(active);
    arch::SerialWrite(" scope(s) still running at panic ---\n");
    const u64 now_us = ElapsedMicros();
    for (u32 i = 0; i < kScopeInflightCapacity; ++i)
    {
        const InflightEntry& e = g_inflight[i];
        if (!e.active)
            continue;
        const u64 running = (now_us >= e.enter_us) ? (now_us - e.enter_us) : 0;
        arch::SerialWrite("[panic]   ");
        arch::SerialWrite(e.subsystem ? e.subsystem : "(null)");
        arch::SerialWrite(" :: ");
        arch::SerialWrite(e.name ? e.name : "(null)");
        arch::SerialWrite("   running_us=");
        WriteDecimal(running);
        arch::SerialWrite("\n");
    }
}

// ---------------------------------------------------------------
// Resource-metrics snapshot
// ---------------------------------------------------------------

void LogMetrics(LogLevel level, const char* subsystem, const char* label)
{
    if (!LevelEnabled(level))
    {
        return;
    }
    const auto heap = mm::KernelHeapStatsRead();
    const u64 free_frames = mm::FreeFramesCount();
    const auto sched_stats = sched::SchedStatsRead();

    g_current_log_level = level;
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    OpenColor(level);
    arch::SerialWrite(tag);
    CloseColor(level);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : metrics ");
    arch::SerialWrite(label ? label : "");
    arch::SerialWrite("   heap_used=");
    WriteDecimal(heap.used_bytes);
    arch::SerialWrite("   heap_free=");
    WriteDecimal(heap.free_bytes);
    arch::SerialWrite("   frames_free=");
    WriteDecimal(free_frames);
    arch::SerialWrite("   ctx_switches=");
    WriteDecimal(sched_stats.context_switches);
    arch::SerialWrite("   tasks_live=");
    WriteDecimal(sched_stats.tasks_live);
    arch::SerialWrite("\n");

    Tee(tag);
    Tee(subsystem);
    Tee(" : metrics ");
    Tee(label ? label : "");
    Tee("\n");

    // Ring entry: record heap used as the one preserved value so
    // post-mortem shows "at metrics checkpoint X, heap was at Y".
    PushEntry(level, subsystem, label ? label : "metrics", heap.used_bytes, true);
}

void KLogSelfTest()
{
    KLOG_TRACE("core/klog", "trace-level sanity line (filtered by default)");
    KLOG_DEBUG("core/klog", "debug-level sanity line");
    KLOG_INFO("core/klog", "info-level sanity line");
    KLOG_WARN("core/klog", "warn-level sanity line");
    KLOG_ERROR("core/klog", "error-level sanity line");
    KLOG_INFO_V("core/klog", "value-form sanity line", 0xCAFEBABE);
    KLOG_INFO_S("core/klog", "string-form sanity line", "who", "CustomOS");
    KLOG_INFO_2V("core/klog", "two-value sanity line", "a", 0x8000, "b", 512);
    // Fire the same once-macro call site from a loop — the static
    // guard is per-site, so only the first iteration should emit.
    for (int i = 0; i < 3; ++i)
    {
        KLOG_ONCE_INFO("core/klog", "once-info sanity (fires once even in a loop)");
    }
    // Exercise TraceScope — RAII guard emits enter + exit if the
    // runtime threshold is dialed down to Trace. With the default
    // Info threshold this is invisible.
    {
        KLOG_TRACE_SCOPE("core/klog", "self-test-scope");
    }
}

} // namespace customos::core
