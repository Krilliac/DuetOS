/*
 * DuetOS — kernel structured logging: implementation.
 *
 * Companion to klog.h — see there for the line format, severity
 * levels, and design rationale.
 *
 * WHAT
 *   Backs the `klog::Log* / Trace / Debug / Warn / Error` calls.
 *   Lines are emitted to the serial port immediately and copied
 *   into a fixed-size in-kernel ring (`g_log_ring`) so the panic
 *   path can dump the last N entries to serial after a halt.
 *
 * HOW
 *   Single-shot serial writer + fixed-shape formatters (no
 *   variadic printf — too much surface for kernel code). Severity
 *   threshold is mutable at runtime (`SetLogThreshold`). An
 *   optional secondary sink (`g_tee`) forwards level >= a min to
 *   a registered consumer (e.g. the framebuffer console once
 *   it's up).
 *
 * WHY THIS FILE IS LARGE
 *   One formatter per argument shape (no value, +u64, +string,
 *   +pair). Each is short but they accumulate. Plus the
 *   timestamp helpers, the colour-SGR wrapping, the ring + sink
 *   plumbing.
 */

#include "log/klog.h"

#include "arch/x86_64/hpet.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "time/tick.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "util/build_config.h"
#include "util/datetime.h"
#include "util/saturating.h"

namespace duetos::core
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
// Saturating: a log-flood attack cannot wrap the write cursor.
// Reads do `g_log_ring_next - g_log_ring_count` (line ~580 / ~879
// / ~946 / ~977) so an underflow would compute a giant start
// offset and the reader would walk garbage; saturation keeps the
// arithmetic monotonic. wiki/security/Linux-CVE-Audit.md class BB.
constinit util::SatU64 g_log_ring_next = 0; // monotonically increasing write cursor
constinit u64 g_log_ring_count = 0;         // saturates at kLogRingCapacity

constinit bool g_color_enabled = true;

// Wall-clock anchor: Unix-epoch seconds at the moment WallClockInit
// sampled the RTC, captured alongside the elapsed-microseconds reading
// at the same instant. Live timestamps are derived as:
//   wall_secs = boot_unix_secs + (now_us - boot_us) / 1_000_000
// This avoids the per-line CMOS UIP wait (~1 ms) RtcRead would impose.
constinit u64 g_wall_clock_boot_unix_secs = 0;
constinit u64 g_wall_clock_boot_us = 0;
constinit bool g_wall_clock_anchored = false;
constinit bool g_wall_clock_enabled = false;

// Runtime area mask. Default `LogArea::All` (every bit set) means
// every legacy / new call site emits as-before. Operators dial it
// down via `logarea off <name>` to suppress chatter from a single
// subsystem while keeping the rest visible.
constinit u32 g_log_area_mask = static_cast<u32>(LogArea::All);

// Per-area minimum level. `Trace` (or absence) means "use the
// global threshold." Indexed by bit position. ~32 areas × 1 byte =
// 32 bytes; a no-op when no override is set.
constinit u8 g_log_area_levels[32] = {};

// Runtime severity threshold — set via SetLogThreshold. Lines with
// level < max(threshold, kKlogMinLevel) are silently dropped.
// Default is read from `core::kKlogDefaultLevel` (build_config.h),
// which keys off `CMAKE_BUILD_TYPE`: debug builds default to Debug
// (full driver + IRQ + sched chatter), release builds default to
// Info (warnings and above). Both can be flipped at runtime via
// `loglevel <t|d|i|w|e>` so a release operator can dial down to
// Trace when they want function entry / exit timing.
constinit LogLevel g_log_threshold = static_cast<LogLevel>(kKlogDefaultLevel);

// Secondary sink. Set via SetLogTee once a framebuffer console (or
// any string consumer) is up. Timestamps are NOT forwarded — they
// would clutter on-screen output, and the serial log keeps them.
constinit LogTee g_tee = nullptr;

// Line-oriented sink (set via SetLogLineSink). Receives one
// fully-assembled log line per call, tagged with level + area so
// the receiver can route each line to a per-subsystem file rather
// than flooding one aggregate log. The chunk Tee path accumulates
// bytes into `g_line_accum` and fires the sink on '\n' or when the
// buffer fills.
constinit LogLineSink g_line_sink = nullptr;
constinit LogLevel g_line_sink_min_level = LogLevel::Info;
// Per-line current level / area: set at the top of each Log/LogA*
// function and read by the Tee accumulator when emitting a complete
// line through the line sink. Racy under SMP; accept that for v0 —
// the pattern is single-CPU and the existing g_current_log_level
// state already runs the same risk.
constinit LogLevel g_current_log_level = LogLevel::Debug;
constinit LogArea g_current_log_area = LogArea::General;

// Per-line accumulator for the line sink. Each chunk fed to Tee()
// is appended here until '\n' arrives (or the buffer is full),
// then handed to the line sink as one record. 384 bytes covers a
// long subsystem path + message + two value fields; longer lines
// truncate at the buffer boundary (the serial sink still receives
// the full unbuffered version, so nothing is lost from the
// authoritative log).
constinit char g_line_accum[384] = {};
constinit u32 g_line_accum_used = 0;

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
    // Line sink: buffer chunks until a newline arrives (or the
    // accumulator is one byte from full), then emit the whole line
    // with the current level + area so per-area file routing can
    // pick the right output. Respects its own minimum level so
    // low-noise captures aren't overwhelmed by Debug ticks.
    if (g_line_sink != nullptr && static_cast<u8>(g_current_log_level) >= static_cast<u8>(g_line_sink_min_level))
    {
        for (const char* p = s; *p != 0; ++p)
        {
            const char c = *p;
            if (g_line_accum_used + 1 < sizeof(g_line_accum))
            {
                g_line_accum[g_line_accum_used++] = c;
            }
            const bool flush_now = (c == '\n') || (g_line_accum_used + 1 >= sizeof(g_line_accum));
            if (flush_now)
            {
                g_line_accum[g_line_accum_used] = '\0';
                g_line_sink(g_current_log_level, g_current_log_area, g_line_accum, g_line_accum_used);
                g_line_accum_used = 0;
            }
        }
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
    case LogLevel::Critical:
        return "[C] ";
    default:
        return "[?] ";
    }
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
    case LogLevel::Critical:
        return "\x1b[1;37;41m"; // bold white on red — louder than Error
    default:
        return "";
    }
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

// Position of the lowest set bit in `area`. Returns 32 for None
// (used as a sentinel "no slot" marker).
inline u32 AreaBitIndex(LogArea area)
{
    const u32 v = static_cast<u32>(area);
    if (v == 0)
        return 32;
    // Single-bit count-trailing-zeros. Bit-twiddle (no __builtin
    // outside of debug — keep this freestanding-friendly).
    u32 idx = 0;
    u32 t = v;
    while ((t & 1u) == 0u && idx < 31)
    {
        t >>= 1;
        ++idx;
    }
    return idx;
}

inline bool AreaPasses(LogArea area, LogLevel level)
{
    // Combined-mask values (e.g. LogArea::All) have multiple bits.
    // The mask AND is still meaningful: any overlap with the active
    // mask means at least one of the named areas is enabled. Per-
    // area level overrides only apply to single-bit values.
    const u32 area_bits = static_cast<u32>(area);
    if ((area_bits & g_log_area_mask) == 0u)
        return false;
    // Single-bit area: check per-area level override on top of the
    // global threshold. The HIGHER of the two wins so overrides
    // can only RAISE the bar for a given area, not lower it below
    // the global. (If you need to LOWER below global, set the
    // global to that level too.)
    if ((area_bits & (area_bits - 1u)) == 0u)
    {
        const u32 idx = AreaBitIndex(area);
        if (idx < 32)
        {
            const u8 area_min = g_log_area_levels[idx];
            if (area_min > 0 && static_cast<u8>(level) < area_min)
                return false;
        }
    }
    return true;
}

inline bool LevelAndAreaEnabled(LogLevel level, LogArea area)
{
    return LevelEnabled(level) && AreaPasses(area, level);
}

// Subsystem-string → LogArea mapping. Used by the legacy non-A
// macros so existing call sites pick up an area without source
// changes. Prefix-match against the subsystem path (the convention
// is "kernel-tree path sans `kernel/`" — see klog.h's design
// note). Order matters: first hit wins, so put the most specific
// prefixes first (e.g. "drivers/net/" before "drivers/").
struct AreaPrefix
{
    const char* prefix;
    LogArea area;
};

constinit const AreaPrefix kAreaPrefixes[] = {
    // Most specific first.
    {"drivers/net/wireless", LogArea::Wireless},
    {"net/wireless", LogArea::Wireless},
    {"drivers/storage/", LogArea::Storage},
    {"drivers/usb/", LogArea::USB},
    {"drivers/gpu/", LogArea::GPU},
    {"drivers/video/", LogArea::Graphics},
    {"drivers/input/", LogArea::Input},
    {"drivers/audio/", LogArea::Audio},
    {"drivers/net/", LogArea::Net},
    {"drivers/pci", LogArea::PCI},
    {"drivers/power", LogArea::Power},
    {"drivers/", LogArea::Driver},
    {"subsystems/win32/", LogArea::Win32},
    {"subsystems/linux/", LogArea::Linux},
    {"subsystems/translation", LogArea::Linux},
    {"subsystems/graphics", LogArea::Graphics},
    {"subsystems/audio", LogArea::Audio},
    {"subsystems/", LogArea::Linux}, // catch-all for less-tagged TUs
    {"loader/", LogArea::Loader},
    {"pe-load", LogArea::Loader},
    {"pe-resolve", LogArea::Loader},
    {"pe-report", LogArea::Loader},
    {"dll-load", LogArea::Loader},
    {"elf-load", LogArea::Loader},
    {"sched/", LogArea::Sched},
    {"sched", LogArea::Sched},
    {"proc/", LogArea::Process},
    {"proc", LogArea::Process},
    {"win32/", LogArea::Win32},
    {"win32-", LogArea::Win32},
    {"win32", LogArea::Win32},
    {"linux/", LogArea::Linux},
    {"net/", LogArea::Net},
    {"net-", LogArea::Net},
    {"net", LogArea::Net},
    {"fs/", LogArea::FS},
    {"fs-", LogArea::FS},
    {"klog", LogArea::Diag},
    {"mm/", LogArea::Memory},
    {"mm", LogArea::Memory},
    {"heap", LogArea::Memory},
    {"frame-allocator", LogArea::Memory},
    {"paging", LogArea::Memory},
    {"slab", LogArea::Memory},
    {"syscall/", LogArea::Syscall},
    {"syscall", LogArea::Syscall},
    {"syscall-gate", LogArea::Syscall},
    {"sys", LogArea::Syscall},
    {"cap-", LogArea::Security},
    {"security/", LogArea::Security},
    {"security", LogArea::Security},
    {"acpi/", LogArea::ACPI},
    {"acpi", LogArea::ACPI},
    {"pci", LogArea::PCI},
    {"time/", LogArea::Time},
    {"timer", LogArea::Time},
    {"hpet", LogArea::Time},
    {"tick", LogArea::Time},
    {"power/", LogArea::Power},
    {"debug/", LogArea::Diag},
    {"diag/", LogArea::Diag},
    {"ipc/", LogArea::IPC},
    {"ipc", LogArea::IPC},
    {"ring3", LogArea::Ring3},
    {"thread", LogArea::Process},
    {"task", LogArea::Sched},
    {"apps/", LogArea::App},
    {"app/", LogArea::App},
    {"selftest", LogArea::Test},
    {"smoke", LogArea::Test},
    {"boot", LogArea::Boot},
    {"init", LogArea::Boot},
    {"core/", LogArea::Boot},
    {"arch/", LogArea::Boot},
};

inline LogArea AreaFromSubsystemImpl(const char* subsystem)
{
    if (subsystem == nullptr)
        return LogArea::General;
    for (const auto& entry : kAreaPrefixes)
    {
        const char* a = subsystem;
        const char* b = entry.prefix;
        while (*a != '\0' && *b != '\0' && *a == *b)
        {
            ++a;
            ++b;
        }
        if (*b == '\0')
            return entry.area;
    }
    return LogArea::General;
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

inline void MaybeWriteWallClockPrefix()
{
    if (!g_wall_clock_enabled || !g_wall_clock_anchored)
        return;
    const u64 elapsed_us = ElapsedMicros();
    const u64 wall_secs = g_wall_clock_boot_unix_secs +
                          (elapsed_us > g_wall_clock_boot_us ? (elapsed_us - g_wall_clock_boot_us) / 1000000ull : 0);
    const ::duetos::util::DateTime dt = ::duetos::util::DateTimeFromUnixSecs(wall_secs);
    char buf[24];
    if (::duetos::util::FormatIso8601(dt, buf, sizeof(buf)) > 0)
    {
        arch::SerialWrite("[");
        arch::SerialWrite(buf);
        arch::SerialWrite("] ");
    }
}

inline void WriteTimestampPrefix()
{
    MaybeWriteWallClockPrefix();
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
    // HPET wasn't ready — fall back to the portable scheduler-
    // tick counter via the time:: wrapper (forwards to
    // arch::TimerTicks today, but lets future arch backends
    // swap in without touching klog). 10 ms per tick at the v0
    // 100 Hz rate. Prefix "~" as a reminder the precision is
    // coarse.
    const u64 ticks = ::duetos::time::TickCount();
    arch::SerialWrite("[t~");
    WriteDecimal(ticks * ::duetos::time::TickPeriodNs() / 1'000'000ULL);
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

void SetLogLineSink(LogLineSink sink)
{
    g_line_sink = sink;
    // Reset the per-line accumulator so a partial line carried over
    // from the prior sink doesn't bleed into the first record this
    // sink sees.
    g_line_accum_used = 0;
    if (sink == nullptr)
    {
        return;
    }
    // Back-fill: every log line that fired up to now went through
    // Tee but not through this sink (it wasn't installed yet).
    // Replay the ring — with the current min-level filter applied
    // — so the sink captures the relevant boot history before the
    // first new live line lands. Each replayed line is reassembled
    // into one contiguous record and shipped with its area derived
    // from the subsystem prefix (the ring entry doesn't store the
    // area separately — keeping the entry narrow on purpose).
    const u64 start = g_log_ring_next - g_log_ring_count;
    for (u64 i = 0; i < g_log_ring_count; ++i)
    {
        const u64 slot = (start + i) % kLogRingCapacity;
        const LogEntry& e = g_log_ring[slot];
        if (e.subsystem == nullptr || e.message == nullptr)
        {
            continue;
        }
        if (static_cast<u8>(e.level) < static_cast<u8>(g_line_sink_min_level))
        {
            continue;
        }
        char line[384];
        u32 len = 0;
        auto append = [&](const char* s)
        {
            while (*s != 0 && len + 1 < sizeof(line))
            {
                line[len++] = *s++;
            }
        };
        append(LevelTag(e.level));
        append(e.subsystem);
        append(" : ");
        append(e.message);
        append("\n");
        line[len] = '\0';
        const LogArea area = AreaFromSubsystemImpl(e.subsystem);
        sink(e.level, area, line, len);
    }
}

void SetLogLineSinkMinLevel(LogLevel min_level)
{
    g_line_sink_min_level = min_level;
}

LogLevel GetLogThreshold()
{
    return g_log_threshold;
}

namespace
{
// Atomic-enough single-pointer post-emit hook. Set/cleared rarely
// (boot-time + shutdown), called many times per second. A plain
// load is fine on x86_64 for an aligned pointer; the 1-cycle
// branch on null when no hook is registered keeps the hot path
// effectively free.
PostEmitHook g_post_emit_hook = nullptr;
bool g_post_emit_in_flight = false; // recursion guard

inline void PostEmit()
{
    if (g_post_emit_hook == nullptr)
        return;
    if (g_post_emit_in_flight)
        return; // hook itself called Log* — refuse to recurse
    g_post_emit_in_flight = true;
    g_post_emit_hook();
    g_post_emit_in_flight = false;
}
} // namespace

void SetPostEmitHook(PostEmitHook hook)
{
    g_post_emit_hook = hook;
}

void Log(LogLevel level, const char* subsystem, const char* message)
{
    const LogArea inferred_area = AreaFromSubsystemImpl(subsystem);
    if (!LevelAndAreaEnabled(level, inferred_area))
    {
        return;
    }
    // Defensive: a caller passing nullptr for subsystem or message
    // must not page-fault inside the log path. Substitute a marker
    // so the bug surfaces in the log instead of as a #PF in serial.
    if (subsystem == nullptr)
    {
        subsystem = "<null-subsys>";
    }
    if (message == nullptr)
    {
        message = "<null-msg>";
    }
    g_current_log_level = level;
    g_current_log_area = inferred_area;
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
    PostEmit();
}

void LogWithValue(LogLevel level, const char* subsystem, const char* message, u64 value)
{
    const LogArea inferred_area = AreaFromSubsystemImpl(subsystem);
    if (!LevelAndAreaEnabled(level, inferred_area))
    {
        return;
    }
    if (subsystem == nullptr)
    {
        subsystem = "<null-subsys>";
    }
    if (message == nullptr)
    {
        message = "<null-msg>";
    }
    g_current_log_level = level;
    g_current_log_area = inferred_area;
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
    PostEmit();
}

void LogWithString(LogLevel level, const char* subsystem, const char* message, const char* label, const char* value_str)
{
    const LogArea inferred_area = AreaFromSubsystemImpl(subsystem);
    if (!LevelAndAreaEnabled(level, inferred_area))
    {
        return;
    }
    if (subsystem == nullptr)
    {
        subsystem = "<null-subsys>";
    }
    if (message == nullptr)
    {
        message = "<null-msg>";
    }
    if (label == nullptr)
    {
        label = "<null-label>";
    }
    if (value_str == nullptr)
    {
        value_str = "<null-value>";
    }
    g_current_log_level = level;
    g_current_log_area = inferred_area;
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
    PostEmit();
}

void LogWith2Values(LogLevel level, const char* subsystem, const char* message, const char* a_label, u64 a_value,
                    const char* b_label, u64 b_value)
{
    const LogArea inferred_area = AreaFromSubsystemImpl(subsystem);
    if (!LevelAndAreaEnabled(level, inferred_area))
    {
        return;
    }
    if (subsystem == nullptr)
    {
        subsystem = "<null-subsys>";
    }
    if (message == nullptr)
    {
        message = "<null-msg>";
    }
    if (a_label == nullptr)
    {
        a_label = "a";
    }
    if (b_label == nullptr)
    {
        b_label = "b";
    }
    g_current_log_level = level;
    g_current_log_area = inferred_area;
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
    PostEmit();
}

void SetLogColor(bool enabled)
{
    g_color_enabled = enabled;
}

bool GetLogColor()
{
    return g_color_enabled;
}

void WallClockInit()
{
    arch::RtcTime rtc;
    arch::RtcRead(&rtc);
    if (rtc.year < 1970 || rtc.year > 2099)
        return; // CMOS junk — refuse to anchor against it
    const ::duetos::util::DateTime dt = {i32(rtc.year), rtc.month, rtc.day, rtc.hour, rtc.minute, rtc.second};
    const u64 unix_secs = ::duetos::util::UnixSecsFromDateTime(dt);
    if (unix_secs == ::duetos::util::kJulianDayInvalid)
        return;
    g_wall_clock_boot_unix_secs = unix_secs;
    g_wall_clock_boot_us = ElapsedMicros();
    g_wall_clock_anchored = true;
}

void SetLogWallClock(bool enabled)
{
    g_wall_clock_enabled = enabled;
}

bool GetLogWallClock()
{
    return g_wall_clock_enabled;
}

void ClearLogRing()
{
    g_log_ring_next = 0;
    g_log_ring_count = 0;
    for (u64 i = 0; i < kLogRingCapacity; ++i)
    {
        g_log_ring[i] = LogEntry{};
    }
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

void DumpLogRingFilteredAreaTo(LogTee writer, u32 area_mask, u32 max_entries)
{
    if (writer == nullptr || area_mask == 0)
    {
        return;
    }
    // Oldest-first walk; same pattern as DumpLogRingToFiltered.
    // The subsystem-prefix → area mapping is recomputed per entry
    // because the LogEntry struct doesn't store the area (kept
    // narrow on purpose so the ring stays cache-friendly).
    const u64 start = g_log_ring_next - g_log_ring_count;
    u32 emitted = 0;
    for (u64 i = 0; i < g_log_ring_count; ++i)
    {
        const u64 slot = (start + i) % kLogRingCapacity;
        const LogEntry& e = g_log_ring[slot];
        if (e.subsystem == nullptr || e.message == nullptr)
        {
            continue;
        }
        const u32 entry_area = static_cast<u32>(AreaFromSubsystemImpl(e.subsystem));
        if ((entry_area & area_mask) == 0)
        {
            continue;
        }
        writer(LevelTag(e.level));
        writer(e.subsystem);
        writer(" : ");
        writer(e.message);
        writer("\n");
        ++emitted;
        if (max_entries != 0 && emitted >= max_entries)
        {
            break;
        }
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
    g_current_log_area = AreaFromSubsystemImpl(m_subsystem);
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
    PostEmit();
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
    // Metrics are landmark snapshots — boot-phase checkpoints and
    // user-requested shell dumps. They emit unconditionally, even
    // when the runtime threshold would normally suppress `level`
    // (release builds default to Warn, which would otherwise drop
    // the Info-tagged boot/bringup-complete checkpoint that CI and
    // forensic boot logs both grep for).
    const auto heap = mm::KernelHeapStatsRead();
    const u64 free_frames = mm::FreeFramesCount();
    const auto sched_stats = sched::SchedStatsRead();

    g_current_log_level = level;
    g_current_log_area = AreaFromSubsystemImpl(subsystem);
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
    PostEmit();
}

void KLogSelfTest()
{
    KLOG_TRACE("core/klog", "trace-level sanity line (filtered by default)");
    KLOG_DEBUG("core/klog", "debug-level sanity line");
    KLOG_INFO("core/klog", "info-level sanity line");
    KLOG_WARN("core/klog", "warn-level sanity line");
    KLOG_ERROR("core/klog", "error-level sanity line");
    KLOG_CRITICAL("core/klog", "critical-level sanity line");
    KLOG_INFO_V("core/klog", "value-form sanity line", 0xCAFEBABE);
    KLOG_INFO_S("core/klog", "string-form sanity line", "who", "DuetOS");
    KLOG_INFO_2V("core/klog", "two-value sanity line", "a", 0x8000, "b", 512);
    KLOG_INFO_A(LogArea::Diag, "core/klog", "area-tagged sanity line (Diag)");
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

// -----------------------------------------------------------------
// Area-aware Log* implementations.
//
// Same body as the non-A variants above, but the gate consults the
// caller-provided area instead of the AreaFromSubsystemImpl
// inference. Saves one strncmp-style walk per call when the caller
// already knows their area, and lets a single TU emit lines from
// multiple areas (e.g. a syscall handler logging Memory + Sched
// inside its body).
// -----------------------------------------------------------------
void LogA(LogLevel level, LogArea area, const char* subsystem, const char* message)
{
    if (!LevelAndAreaEnabled(level, area))
        return;
    if (subsystem == nullptr)
        subsystem = "<null-subsys>";
    if (message == nullptr)
        message = "<null-msg>";
    g_current_log_level = level;
    g_current_log_area = area;
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    OpenColor(level);
    arch::SerialWrite(tag);
    CloseColor(level);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n");
    Tee(tag);
    Tee(subsystem);
    Tee(" : ");
    Tee(message);
    Tee("\n");
    PushEntry(level, subsystem, message, 0, false);
    PostEmit();
}

void LogAWithValue(LogLevel level, LogArea area, const char* subsystem, const char* message, u64 value)
{
    if (!LevelAndAreaEnabled(level, area))
        return;
    if (subsystem == nullptr)
        subsystem = "<null-subsys>";
    if (message == nullptr)
        message = "<null-msg>";
    g_current_log_level = level;
    g_current_log_area = area;
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
    PostEmit();
}

void LogAWithString(LogLevel level, LogArea area, const char* subsystem, const char* message, const char* label,
                    const char* value_str)
{
    if (!LevelAndAreaEnabled(level, area))
        return;
    if (subsystem == nullptr)
        subsystem = "<null-subsys>";
    if (message == nullptr)
        message = "<null-msg>";
    if (label == nullptr)
        label = "<null-label>";
    if (value_str == nullptr)
        value_str = "<null>";
    g_current_log_level = level;
    g_current_log_area = area;
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    OpenColor(level);
    arch::SerialWrite(tag);
    CloseColor(level);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("   ");
    arch::SerialWrite(label);
    arch::SerialWrite("=\"");
    arch::SerialWrite(value_str);
    arch::SerialWrite("\"\n");
    Tee(tag);
    Tee(subsystem);
    Tee(" : ");
    Tee(message);
    Tee("\n");
    PushEntry(level, subsystem, message, 0, false);
    PostEmit();
}

void LogAWith2Values(LogLevel level, LogArea area, const char* subsystem, const char* message, const char* a_label,
                     u64 a_value, const char* b_label, u64 b_value)
{
    if (!LevelAndAreaEnabled(level, area))
        return;
    if (subsystem == nullptr)
        subsystem = "<null-subsys>";
    if (message == nullptr)
        message = "<null-msg>";
    if (a_label == nullptr)
        a_label = "a";
    if (b_label == nullptr)
        b_label = "b";
    g_current_log_level = level;
    g_current_log_area = area;
    const char* tag = LevelTag(level);
    WriteTimestampPrefix();
    OpenColor(level);
    arch::SerialWrite(tag);
    CloseColor(level);
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("   ");
    arch::SerialWrite(a_label);
    arch::SerialWrite("=");
    WriteCompactHex(a_value);
    MaybeAppendDecimal(a_value);
    arch::SerialWrite("   ");
    arch::SerialWrite(b_label);
    arch::SerialWrite("=");
    WriteCompactHex(b_value);
    MaybeAppendDecimal(b_value);
    arch::SerialWrite("\n");
    Tee(tag);
    Tee(subsystem);
    Tee(" : ");
    Tee(message);
    Tee("\n");
    PushEntry(level, subsystem, message, a_value, true);
    PostEmit();
}

// -----------------------------------------------------------------
// Area control APIs.
// -----------------------------------------------------------------
void SetLogAreaMask(u32 mask)
{
    g_log_area_mask = mask;
}

u32 GetLogAreaMask()
{
    return g_log_area_mask;
}

void EnableLogArea(LogArea area)
{
    g_log_area_mask |= static_cast<u32>(area);
}

void DisableLogArea(LogArea area)
{
    g_log_area_mask &= ~static_cast<u32>(area);
}

bool IsLogAreaEnabled(LogArea area)
{
    return (g_log_area_mask & static_cast<u32>(area)) != 0;
}

void SetLogAreaLevel(LogArea area, LogLevel level)
{
    const u32 idx = AreaBitIndex(area);
    if (idx >= 32)
        return;
    g_log_area_levels[idx] = static_cast<u8>(level);
}

LogLevel GetLogAreaLevel(LogArea area)
{
    const u32 idx = AreaBitIndex(area);
    if (idx >= 32)
        return LogLevel::Trace;
    return static_cast<LogLevel>(g_log_area_levels[idx]);
}

LogArea AreaFromSubsystem(const char* subsystem)
{
    return AreaFromSubsystemImpl(subsystem);
}

const char* LogAreaName(LogArea area)
{
    switch (area)
    {
    case LogArea::None:
        return "none";
    case LogArea::General:
        return "general";
    case LogArea::Boot:
        return "boot";
    case LogArea::Memory:
        return "memory";
    case LogArea::Sched:
        return "sched";
    case LogArea::Process:
        return "process";
    case LogArea::Syscall:
        return "syscall";
    case LogArea::Loader:
        return "loader";
    case LogArea::FS:
        return "fs";
    case LogArea::Net:
        return "net";
    case LogArea::Storage:
        return "storage";
    case LogArea::USB:
        return "usb";
    case LogArea::GPU:
        return "gpu";
    case LogArea::Input:
        return "input";
    case LogArea::Audio:
        return "audio";
    case LogArea::IPC:
        return "ipc";
    case LogArea::Win32:
        return "win32";
    case LogArea::Linux:
        return "linux";
    case LogArea::Time:
        return "time";
    case LogArea::Power:
        return "power";
    case LogArea::Security:
        return "security";
    case LogArea::Diag:
        return "diag";
    case LogArea::Ring3:
        return "ring3";
    case LogArea::App:
        return "app";
    case LogArea::Driver:
        return "driver";
    case LogArea::ACPI:
        return "acpi";
    case LogArea::PCI:
        return "pci";
    case LogArea::Wireless:
        return "wireless";
    case LogArea::Graphics:
        return "graphics";
    case LogArea::Test:
        return "test";
    case LogArea::Arith:
        return "arith";
    case LogArea::All:
        return "all";
    default:
        return "?";
    }
}

LogArea LogAreaFromName(const char* name)
{
    if (name == nullptr)
        return LogArea::None;
    auto eq = [](const char* a, const char* b)
    {
        while (*a != '\0' && *b != '\0')
        {
            char ca = *a;
            char cb = *b;
            if (ca >= 'A' && ca <= 'Z')
                ca = static_cast<char>(ca + ('a' - 'A'));
            if (cb >= 'A' && cb <= 'Z')
                cb = static_cast<char>(cb + ('a' - 'A'));
            if (ca != cb)
                return false;
            ++a;
            ++b;
        }
        return *a == '\0' && *b == '\0';
    };
    constexpr LogArea kAll[] = {
        LogArea::General, LogArea::Boot,     LogArea::Memory,   LogArea::Sched,    LogArea::Process, LogArea::Syscall,
        LogArea::Loader,  LogArea::FS,       LogArea::Net,      LogArea::Storage,  LogArea::USB,     LogArea::GPU,
        LogArea::Input,   LogArea::Audio,    LogArea::IPC,      LogArea::Win32,    LogArea::Linux,   LogArea::Time,
        LogArea::Power,   LogArea::Security, LogArea::Diag,     LogArea::Ring3,    LogArea::App,     LogArea::Driver,
        LogArea::ACPI,    LogArea::PCI,      LogArea::Wireless, LogArea::Graphics, LogArea::Test,    LogArea::Arith,
        LogArea::All,
    };
    for (LogArea a : kAll)
    {
        if (eq(name, LogAreaName(a)))
            return a;
    }
    return LogArea::None;
}

} // namespace duetos::core
