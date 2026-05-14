#pragma once

#include "util/types.h"

/*
 * DuetOS — kernel structured logging.
 *
 * Replaces the ad-hoc `arch::SerialWrite("[subsys] msg\n")` pattern
 * with a uniform, severity-tagged API. Output lines look like:
 *
 *     [t=12.345ms] [I] <subsystem> : <message>
 *     [t=12.345ms] [I] <subsystem> : <message>   val=0x<hex> (<dec>)
 *     [t=12.345ms] [W] <subsystem> : <message>
 *     [t=12.345ms] [E] <subsystem> : <message>
 *     [t=12.345ms] [D] <subsystem> : <message>
 *     [t=12.345ms] [I] <subsystem> : <message>   <label>="<str>"
 *     [t=12.345ms] [I] <subsystem> : <message>   <a>=0x.. (N)   <b>=0x.. (N)
 *
 * The severity letter is the single-character bracket prefix; tools
 * grep on it to filter. Subsystem tag convention matches core::Panic
 * (use the kernel-tree path sans `kernel/`). ANSI SGR colour is wrapped
 * around the tag so terminals highlight warn/error at a glance; it
 * can be toggled with `SetLogColor(false)` when capturing to a file.
 *
 * Timestamp is wall-time since boot — microseconds when HPET is up,
 * scheduler-tick * 10ms ("[t~50ms] ") before that.
 *
 * Design choices:
 *   - No variadic printf. `snprintf` in a kernel is a large surface;
 *     the fixed-shape helpers (u64 / string / pair) cover every
 *     current need without the format-string footgun.
 *   - Compile-time min level (`kKlogMinLevel`) filters cheaply —
 *     Debug calls compile to a single inline check.
 *   - No allocation, no lock. Concurrent writers may interleave;
 *     that's the cost of no-lock — in return we can log from IRQ
 *     context with no deadlock risk. An SMP-safe ring buffer that
 *     serialises writes is a future improvement (see revisit
 *     markers in the decision log).
 *   - Ring buffer remembers the last kLogRingCapacity entries with
 *     their timestamps, replayed by core::Panic so the post-mortem
 *     shows "what happened in the 63 lines before we died" with
 *     wall-clock times attached.
 *   - Source-location for Warn / Error / Critical: every KLOG_WARN*
 *     / KLOG_ERROR* / KLOG_CRITICAL* macro captures `__FILE__` /
 *     `__LINE__` at the call site and the renderer appends
 *     `   at <kernel-relative-path>:<line>` after the message body.
 *     The motivation: a `[W] mm/paging : something tripped` line in
 *     a 30,000-line boot log is one grep away from the call site,
 *     not a debugger session. Trace / Debug / Info macros DO NOT
 *     capture file:line — they are high-volume and the location is
 *     usually obvious from the subsystem prefix; adding 30 bytes
 *     per line would dwarf the message.
 *
 *     Escape hatch — call `core::Log()` / `core::LogWithValue()` /
 *     etc. DIRECTLY (without the KLOG_* macro) and the file/line
 *     defaults to nullptr/0; the renderer omits the at-clause. Use
 *     for ring-buffer replay, post-mortem reconstruction, or any
 *     site that intentionally wants to emit a synthetic log line
 *     whose source location should NOT be the call site (because
 *     the call site is the synthesis point, not the origin).
 *
 * Context: kernel. Safe at any interrupt level.
 */

namespace duetos::core
{

enum class LogLevel : u8
{
    Trace = 0, // finest-grained — function enter/exit + timing
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5, // unrecoverable / catastrophic — almost-panic. Fires
                  // exactly once before the system either halts or
                  // enters a degraded recovery path. Distinct from
                  // Error so a log filter can surface "we lost a
                  // subsystem" without drowning in the warn/error
                  // noise that normal driver bring-up emits.
};

// -----------------------------------------------------------------
// Log areas — bitmask grouping for runtime filter control.
//
// Each Log* call carries a `LogArea`. The runtime mask
// `g_log_area_mask` (set via SetLogAreaMask / EnableLogArea /
// DisableLogArea) gates which areas reach the serial port and
// the secondary sinks. Areas can be combined freely:
//
//     SetLogAreaMask(LogArea::Memory | LogArea::Sched);
//
// turns the boot log into a focused trace of just the allocator
// + scheduler chatter, even when the global level is at Trace.
//
// The legacy KLOG_* macros default to LogArea::General — they
// always pass through. The newer KLOG_*_A(area, ...) macros
// take an explicit area; use those for subsystem-tagged spam
// like driver bring-up or syscall dispatch tracing so an
// operator can toggle them off without losing the General
// signal.
//
// The numeric width is 32 bits, leaving room for ~30 areas
// before we have to widen to u64.
// -----------------------------------------------------------------
enum class LogArea : u32
{
    None = 0,
    General = 1u << 0,   // default for legacy KLOG_* without an area
    Boot = 1u << 1,      // kernel_main, init phases, bringup
    Memory = 1u << 2,    // mm/ — frame allocator, paging, heap, slabs
    Sched = 1u << 3,     // sched/ — task lifecycle, runqueues, locks
    Process = 1u << 4,   // proc/ — Process create/release, caps
    Syscall = 1u << 5,   // syscall/ — dispatcher, cap-gate, individual handlers
    Loader = 1u << 6,    // loader/ — PE/ELF/DLL loading, relocations
    FS = 1u << 7,        // fs/ — VFS, ramfs, FAT32, ext4, NTFS, exFAT
    Net = 1u << 8,       // net/, drivers/net/ — packet, TCP/IP, ARP, DHCP
    Storage = 1u << 9,   // drivers/storage/ — NVMe, AHCI, GPT
    USB = 1u << 10,      // drivers/usb/ — xHCI, HID, mass-storage
    GPU = 1u << 11,      // drivers/gpu/, drivers/video/ — render path
    Input = 1u << 12,    // drivers/input/ — PS/2, USB HID
    Audio = 1u << 13,    // drivers/audio/ — HDA, AC97
    IPC = 1u << 14,      // ipc/, kernel/subsystems/linux/sysv_ipc, pipes, sections
    Win32 = 1u << 15,    // subsystems/win32/ — NT syscalls, Win32 thunks, registry
    Linux = 1u << 16,    // subsystems/linux/ — Linux ABI translation
    Time = 1u << 17,     // time/, arch/x86_64/timer.cpp, hpet.cpp
    Power = 1u << 18,    // power/, drivers/power
    Security = 1u << 19, // security/ — auth, canaries, fault domains, pentest
    Diag = 1u << 20,     // debug/, diag/ — breakpoints, runtime checker, hexdump
    Ring3 = 1u << 21,    // ring-3 entry/exit, user-mode trampolines
    App = 1u << 22,      // kernel/apps/ — in-kernel applications
    Driver = 1u << 23,   // generic driver bring-up before subsystem-specific buckets
    ACPI = 1u << 24,     // acpi/
    PCI = 1u << 25,      // drivers/pci/
    Wireless = 1u << 26, // kernel/net/wireless/, drivers/net/wireless/
    Graphics = 1u << 27, // drivers/video/ compositor / framebuffer / theme
    Test = 1u << 28,     // self-tests, smoke harnesses
    Arith = 1u << 29,    // arithmetic / math helpers (fewer, separate so they're easy to silence)
    All = 0xFFFFFFFFu,
};

inline constexpr u32 LogAreaBits(LogArea a)
{
    return static_cast<u32>(a);
}
inline constexpr LogArea operator|(LogArea a, LogArea b)
{
    return static_cast<LogArea>(LogAreaBits(a) | LogAreaBits(b));
}
inline constexpr LogArea operator&(LogArea a, LogArea b)
{
    return static_cast<LogArea>(LogAreaBits(a) & LogAreaBits(b));
}
inline constexpr LogArea operator~(LogArea a)
{
    return static_cast<LogArea>(~LogAreaBits(a));
}

/// Compile-time minimum severity. KLOG_TRACE / KLOG_TRACE_V /
/// KLOG_TRACE_SCOPE call sites fold to nothing when `level <
/// kKlogMinLevel`, so raising this floor genuinely eliminates the
/// trace-emit code from the binary.
///
/// Wired off the build-flavor knob `DUETOS_KLOG_COMPILE_FLOOR`:
///   - Debug builds default to Trace — the deepest instrumentation
///     compiles in. The runtime threshold (`g_log_threshold`) starts
///     at Debug so Trace lines are dropped unless `loglevel t`
///     explicitly enables them, but the call sites themselves
///     remain so they're available on demand.
///   - Release builds default to Debug — Trace call sites are dead
///     code at compile time. Operators trying to enable Trace via
///     `loglevel t` on a release image will get a no-op (the lines
///     don't exist in the binary). Document this in the shell help
///     once we have a test that reaches it.
///
/// The runtime threshold (set by `SetLogThreshold`) can only RAISE
/// the effective floor — it cannot dip below this compile-time
/// minimum.
#ifndef DUETOS_KLOG_COMPILE_FLOOR
#ifdef DUETOS_BUILD_FLAVOR
#if DUETOS_BUILD_FLAVOR == 1        // Debug
#define DUETOS_KLOG_COMPILE_FLOOR 0 // Trace
#else                               // Release / RelWithDebInfo / MinSizeRel
#define DUETOS_KLOG_COMPILE_FLOOR 1 // Debug
#endif
#else
#define DUETOS_KLOG_COMPILE_FLOOR 1 // Debug — safe default for header-only TUs
#endif
#endif
inline constexpr LogLevel kKlogMinLevel = static_cast<LogLevel>(DUETOS_KLOG_COMPILE_FLOOR);

/// Set the RUNTIME minimum severity. Lines below this level are
/// dropped at the head of Log / LogWithValue (they still don't
/// enter the log ring). Compile-time filtering via `kKlogMinLevel`
/// still applies — runtime threshold can only be raised above the
/// compile-time floor, never below. Useful during driver
/// bring-up (dial Debug noise down mid-boot) or in CI runs (drop
/// Warn+ only).
void SetLogThreshold(LogLevel level);

/// Current runtime threshold. Defaults to the compile-time floor.
LogLevel GetLogThreshold();

/// Post-emit hook — called once after every klog line is fully
/// written to serial + tee. Used by the kernel shell to redraw
/// its prompt + current input buffer on a fresh line so an
/// operator typing through a flood of klog lines sees what they
/// have typed instead of having it scrolled away. Pass nullptr
/// to clear. The hook MUST NOT itself call Log* (it would
/// recurse — the hook fires while the trailing newline is the
/// last write, not while a line is in flight, but a klog line
/// FROM the hook would invoke the hook again on its own emit).
using PostEmitHook = void (*)();
void SetPostEmitHook(PostEmitHook hook);

// -----------------------------------------------------------------
// Area filtering — runtime bitmask + per-area level overrides.
//
// `g_log_area_mask` carries one bit per LogArea. A log line passes
// the area gate iff `(area & mask) != 0`. Default mask is
// `LogArea::All` so every legacy / new call site emits.
//
// In addition, each area can carry its own MINIMUM level override
// (`SetLogAreaLevel`). Useful for "I want everything from Memory
// at Debug, but Net only at Warn." When no override is set the
// global threshold applies.
//
// Both gates AND together: a line passes only if it's above both
// the (per-area-or-global) level AND in the active mask.
// -----------------------------------------------------------------
void SetLogAreaMask(u32 mask);
u32 GetLogAreaMask();
void EnableLogArea(LogArea area);
void DisableLogArea(LogArea area);
bool IsLogAreaEnabled(LogArea area);

/// Per-area minimum level override. `LogLevel::Trace` (or absence)
/// means "use the global threshold." Lines below the per-area level
/// are dropped, AS ARE lines below the global threshold — the gate
/// is the higher of the two. Pass `LogLevel::Trace` to clear the
/// override.
void SetLogAreaLevel(LogArea area, LogLevel level);
LogLevel GetLogAreaLevel(LogArea area);

/// Map a subsystem-tag prefix (e.g. "mm/", "drivers/net/", "fs/")
/// to a LogArea bit. Used by the legacy macro path to auto-tag
/// callers that don't pass an explicit area. Unknown prefix maps
/// to `LogArea::General` so legacy lines always pass the area
/// gate when the General bit is set.
LogArea AreaFromSubsystem(const char* subsystem);

/// Human-readable name for a single area. Used by the `logarea`
/// shell command's listing. Returns `"?"` for combined masks or
/// the `None` sentinel.
const char* LogAreaName(LogArea area);

/// Parse an area name back to a single-bit `LogArea`. Returns
/// `LogArea::None` on miss. Case-insensitive, matches the names
/// `LogAreaName` returns.
LogArea LogAreaFromName(const char* name);

/// Emit a tagged log line. Single-letter severity + subsystem + msg.
/// Safe from IRQ context. No-op if level / area filters drop it.
///
/// `file` / `line` carry the source-location of the call site —
/// populated automatically by the KLOG_WARN / KLOG_ERROR /
/// KLOG_CRITICAL macros, defaulted to nullptr / 0 for the direct-
/// call escape hatch (ring-buffer replay, synthesised log lines).
/// When non-null, the renderer appends `   at <path>:<line>` after
/// the message body and stores the pair in the ring entry so the
/// panic-time replay can reproduce it. Trace / Debug / Info macros
/// do NOT capture file:line — they would dwarf the message.
void Log(LogLevel level, const char* subsystem, const char* message, const char* file = nullptr, u32 line = 0);

/// As above, with a u64 rendered as hex after the message.
void LogWithValue(LogLevel level, const char* subsystem, const char* message, u64 value, const char* file = nullptr,
                  u32 line = 0);

/// Variant that takes a labelled NUL-terminated string. Renders as
///     [I] subsys : message   <label>="<value>"
/// Handy for device names, PCI vendors, file paths — anything the
/// reader wants to see literally, not as hex. `value_str` must
/// outlive the log call; it's stored by pointer in the ring buffer.
void LogWithString(LogLevel level, const char* subsystem, const char* message, const char* label, const char* value_str,
                   const char* file = nullptr, u32 line = 0);

/// Variant that carries two labelled u64 values on one line. Renders as
///     [I] subsys : message   <a_label>=0x... (dec)   <b_label>=0x... (dec)
/// Useful for (base, size) / (count, stride) / (got, want) pairs that
/// currently take two separate log lines. Ring-buffer persistence
/// captures only the first value to keep the entry size bounded; if
/// both values matter for post-mortem analysis, use two LogWithValue
/// calls instead.
void LogWith2Values(LogLevel level, const char* subsystem, const char* message, const char* a_label, u64 a_value,
                    const char* b_label, u64 b_value, const char* file = nullptr, u32 line = 0);

// Area-aware variants. Same shape as the top set, but the caller
// names an explicit LogArea so the runtime mask can silence whole
// classes of chatter (e.g. "drop everything from drivers/net while
// I focus on a memory bug"). The legacy non-A variants above
// auto-tag via `AreaFromSubsystem(subsystem)` so old call sites
// stay zero-touch.
void LogA(LogLevel level, LogArea area, const char* subsystem, const char* message, const char* file = nullptr,
          u32 line = 0);
void LogAWithValue(LogLevel level, LogArea area, const char* subsystem, const char* message, u64 value,
                   const char* file = nullptr, u32 line = 0);
void LogAWithString(LogLevel level, LogArea area, const char* subsystem, const char* message, const char* label,
                    const char* value_str, const char* file = nullptr, u32 line = 0);
void LogAWith2Values(LogLevel level, LogArea area, const char* subsystem, const char* message, const char* a_label,
                     u64 a_value, const char* b_label, u64 b_value, const char* file = nullptr, u32 line = 0);

/// Toggle ANSI colour codes on the serial sink. Defaults to on.
/// Off is useful for log-capture tools that don't understand escape
/// sequences, or for CI runs that diff boot logs byte-wise.
/// Does NOT affect the tee (framebuffer) — colours there are driven
/// by the console itself.
void SetLogColor(bool enabled);
bool GetLogColor();

/// Sample the RTC once and remember the wall-clock time at boot.
/// After this call, subsequent log lines may carry an ISO 8601
/// `[2026-05-03T14:07:30Z]` prefix in addition to the uptime
/// `[t=…ms]` prefix — controlled by `SetLogWallClock`.
///
/// Intended to run exactly once during early boot, after the RTC
/// driver is up but before the first interesting log line.
/// Subsequent calls overwrite the boot anchor (cheap, no harm).
/// Reading the RTC per-line would be wasteful (the CMOS UIP wait
/// can busy-spin up to ~1 ms); this anchor + ElapsedMicros offset
/// is the same trick Linux uses for `dmesg --time-format iso`.
void WallClockInit();

/// Toggle the ISO 8601 wall-clock prefix. Defaults to OFF so
/// existing log scanners are not surprised. When ON and
/// `WallClockInit` has run, every emitted log line carries
/// `[YYYY-MM-DDTHH:MM:SSZ]` immediately after the uptime prefix.
void SetLogWallClock(bool enabled);
bool GetLogWallClock();

// -----------------------------------------------------------------
// Trace / scope instrumentation.
//
// `TraceScope` is an RAII guard: construction logs "enter" at Trace
// level with the current timestamp; destruction logs "exit" with the
// elapsed wall time in microseconds. Use via KLOG_TRACE_SCOPE() at
// the top of a function to get automatic enter/exit pairing.
//
// While a scope is alive it also registers in a small global
// in-flight table; on panic the panic path dumps every scope that
// entered but never exited — so a hang gives you a grep-able
// "function X was still running after NNms" record.
//
// The in-flight table is fixed-size (kScopeInflightCapacity). A
// scope that opens when the table is full still logs enter/exit but
// doesn't occupy a slot — the hang-dump list becomes incomplete,
// logged as a one-shot warn so you notice.
//
// Cost when Trace is filtered at runtime: one load + compare +
// branch at enter, same at exit, plus the RAII guard storage
// (three pointers, 8 bytes of timestamp). Near-zero.
//
// Cost when Trace is raised above the compile-time floor: the
// KLOG_TRACE_SCOPE macro folds to a no-op via `if constexpr` —
// zero instructions, zero storage, the RAII object isn't even
// declared. That's the mode release builds can opt into once we
// have a real release preset.
// -----------------------------------------------------------------

inline constexpr u32 kScopeInflightCapacity = 16;

class TraceScope
{
  public:
    /// `subsystem` + `name` must outlive the scope (static strings).
    /// Entering logs "> name" at Trace level; leaving logs "< name
    /// elapsed_us=N".
    TraceScope(const char* subsystem, const char* name);
    ~TraceScope();

    TraceScope(const TraceScope&) = delete;
    TraceScope(TraceScope&&) = delete;
    TraceScope& operator=(const TraceScope&) = delete;
    TraceScope& operator=(TraceScope&&) = delete;

  private:
    const char* m_subsystem;
    const char* m_name;
    u64 m_enter_us;
    i32 m_slot; // -1 if the in-flight table was full at construction
};

/// Snapshot of in-flight scopes, emitted by `core::Panic` so a
/// hang dump shows "X was still running when we died". Safe to
/// call from any context. No-op if nothing is in flight.
void DumpInflightScopes();

/// Emit a single structured "metrics snapshot" line covering
/// heap, frames, context switches, and task counts. Callers use
/// this at key checkpoints (end of boot, per-phase markers) so
/// the timeline of resource consumption is visible without
/// ad-hoc prints. Level-gated like any klog call.
void LogMetrics(LogLevel level, const char* subsystem, const char* label);

/// Runtime sanity check of the log path. Prints one line at each
/// level; visual inspection confirms the format. Called from
/// kernel_main after Serial is up.
void KLogSelfTest();

/// Dump the last kLogRingCapacity entries from the in-kernel ring
/// buffer to COM1 in oldest-first order. Called by `core::Panic`
/// (via `DumpDiagnostics`) so the final serial log always shows
/// the last ~64 klog lines leading up to the halt, even when the
/// panic banner buries the scroll-back.
///
/// Safe to call from panic / IRQ context. Does NOT clear the ring —
/// multiple calls emit the same content.
void DumpLogRing();

/// Drop every entry currently in the ring. Used by `dmesg c` to
/// "zero the clock" so the next `dmesg` starts fresh. Does not
/// affect in-flight scope tracking (that has its own table).
void ClearLogRing();

/// Size of the log-ring buffer. Exposed so tests / diagnostics can
/// reason about how many historical lines are retained.
inline constexpr u64 kLogRingCapacity = 64;

/// Optional second sink for every log line. When set, each line
/// is forwarded to `writer` AFTER the serial write completes so
/// a slow sink never blocks the primary path. The writer is
/// called with short chunks (tag, subsystem, separator, message,
/// newline) in sequence — no timestamp prefix — so a framebuffer
/// console receives clean "[I] subsys : msg" lines. Pass
/// `nullptr` to disable. Safe to set from task context; avoid
/// setting from IRQ.
using LogTee = void (*)(const char*);
void SetLogTee(LogTee writer);

/// Line-oriented sink for area-routed persistence. Called once per
/// fully-formatted log line (no timestamp prefix, trailing newline
/// included) with the LogLevel and LogArea so the receiver can route
/// each line to a per-subsystem file rather than dumping everything
/// into a single aggregate log.
///
/// When set, the current log ring is replayed through the sink
/// immediately so it captures the full boot history — not just
/// post-install lines. Pass `nullptr` to disable. Safe to install
/// from task context.
///
/// The sink's minimum severity is controlled separately via
/// `SetLogLineSinkMinLevel` (default Info — Debug entries are
/// filtered out so the per-area files aren't overwhelmed by
/// timer-tick spam).
///
/// The `line` pointer is into a small static accumulator owned by
/// klog; treat it as valid only for the duration of the call. The
/// `line_len` argument is the byte length excluding the trailing
/// NUL (the buffer IS NUL-terminated for convenience but `line_len`
/// is what callers should use when appending to a file).
///
/// Replaces the older chunk-based `SetLogFileSink` API; the line +
/// area shape lets each subsystem own its own log file (NET.LOG,
/// USB.LOG, FS.LOG, …) instead of every line flooding into one
/// aggregate.
using LogLineSink = void (*)(LogLevel level, LogArea area, const char* line, u32 line_len);
void SetLogLineSink(LogLineSink sink);
void SetLogLineSinkMinLevel(LogLevel min_level);

/// Variant of DumpLogRing that writes to an arbitrary string
/// sink instead of COM1 directly. Useful for surfacing the ring
/// to a shell `dmesg` command without also echoing to serial.
/// Same oldest-first order; caller-supplied writer sees one
/// chunk per formatted token.
void DumpLogRingTo(LogTee writer);

/// As DumpLogRingTo, but drops entries below `min_level` before
/// writing. `min_level == Debug` is equivalent to the unfiltered
/// form. Shell `dmesg w` uses this to emit only Warn+ entries.
void DumpLogRingToFiltered(LogTee writer, LogLevel min_level);

/// As DumpLogRingTo, but drops entries whose subsystem-derived
/// `LogArea` is not set in `area_mask`, and writes at most
/// `max_entries` of those that pass the filter (oldest-first).
/// Used by the per-domain crash-dump emitter to splice the tail
/// of klog history relevant to a single subsystem into the dump
/// record without touching unrelated areas.
///
/// `area_mask` is a bitwise OR of `LogArea` values. The match
/// reuses `AreaFromSubsystem(entry.subsystem)` so callers don't
/// need to track the area separately — passing the prefix the
/// subsystem already logs under is enough.
///
/// `max_entries == 0` means no cap (write every match in the
/// ring). Safe from any context that can take the same locks
/// as `DumpLogRingTo` (i.e. not from inside the trap handler).
void DumpLogRingFilteredAreaTo(LogTee writer, u32 area_mask, u32 max_entries);

} // namespace duetos::core

// Convenience macros. The `do { } while (0)` lets call sites still
// write `KLOG_INFO(...);` with a trailing semicolon.

// Trace-level call sites fold to nothing when the compile-time
// floor is above Trace. The `if constexpr` guard checks the enum
// value of kKlogMinLevel at compile time; if Trace < floor, the
// body is discarded and no call is emitted.
#define KLOG_TRACE(subsys, msg)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        if constexpr (static_cast<::duetos::u8>(::duetos::core::LogLevel::Trace) >=                                    \
                      static_cast<::duetos::u8>(::duetos::core::kKlogMinLevel))                                        \
        {                                                                                                              \
            ::duetos::core::Log(::duetos::core::LogLevel::Trace, (subsys), (msg));                                     \
        }                                                                                                              \
    } while (0)

#define KLOG_TRACE_V(subsys, msg, val)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        if constexpr (static_cast<::duetos::u8>(::duetos::core::LogLevel::Trace) >=                                    \
                      static_cast<::duetos::u8>(::duetos::core::kKlogMinLevel))                                        \
        {                                                                                                              \
            ::duetos::core::LogWithValue(::duetos::core::LogLevel::Trace, (subsys), (msg), (val));                     \
        }                                                                                                              \
    } while (0)

// Function-scope instrumentation. Drop this at the top of a
// function and get automatic enter / exit / elapsed logging at
// Trace level, plus in-flight tracking for hang diagnosis.
//
// Usage:
//     void AhciInit() {
//         KLOG_TRACE_SCOPE("drivers/ahci", "AhciInit");
//         // ... body ...
//     }
//
// The helper creates a unique local name per call site by
// concatenating __LINE__, so two scopes in the same function
// don't collide.
#if (DUETOS_KLOG_COMPILE_FLOOR <= 0) // Trace compiled in
#define KLOG_TRACE_SCOPE_IMPL2(subsys, name, line_)                                                                    \
    ::duetos::core::TraceScope _klog_trace_scope_##line_((subsys), (name))
#define KLOG_TRACE_SCOPE_IMPL(subsys, name, line_) KLOG_TRACE_SCOPE_IMPL2(subsys, name, line_)
#define KLOG_TRACE_SCOPE(subsys, name) KLOG_TRACE_SCOPE_IMPL(subsys, name, __LINE__)
#else
// Trace compiled out — KLOG_TRACE_SCOPE folds to a typed-zero so
// the call site stays a single statement (works in `if`/`else`
// chains without braces) but no TraceScope object is constructed,
// the in-flight table isn't touched, and storage for two pointers
// + a u64 disappears from every function that uses it.
#define KLOG_TRACE_SCOPE(subsys, name) ((void)0)
#endif

// Metrics snapshot. Prints one line with current heap-used,
// frames-free, context-switches, tasks-live, each as a labelled
// decimal value. Use at phase boundaries to see the timeline.
#define KLOG_METRICS(subsys, label)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogMetrics(::duetos::core::LogLevel::Info, (subsys), (label));                                 \
    } while (0)

#define KLOG_DEBUG(subsys, msg)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::Log(::duetos::core::LogLevel::Debug, (subsys), (msg));                                         \
    } while (0)

#define KLOG_DEBUG_V(subsys, msg, val)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Debug, (subsys), (msg), (val));                         \
    } while (0)

#define KLOG_DEBUG_S(subsys, msg, label, s)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithString(::duetos::core::LogLevel::Debug, (subsys), (msg), (label), (s));                 \
    } while (0)

#define KLOG_INFO(subsys, msg)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::Log(::duetos::core::LogLevel::Info, (subsys), (msg));                                          \
    } while (0)

#define KLOG_WARN(subsys, msg)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::Log(::duetos::core::LogLevel::Warn, (subsys), (msg), __FILE__, __LINE__);                      \
    } while (0)

#define KLOG_ERROR(subsys, msg)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::Log(::duetos::core::LogLevel::Error, (subsys), (msg), __FILE__, __LINE__);                     \
    } while (0)

// Critical: degraded-but-still-running events that warrant the same
// attention as a panic but don't (or can't) halt the system. Filter-
// always-on by default (above every other level) so a `loglevel e`
// demotion still surfaces them; the runtime threshold is clamped to
// at most Critical-1 to enforce that.
#define KLOG_CRITICAL(subsys, msg)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::Log(::duetos::core::LogLevel::Critical, (subsys), (msg), __FILE__, __LINE__);                  \
    } while (0)

#define KLOG_CRITICAL_V(subsys, msg, val)                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Critical, (subsys), (msg), (val), __FILE__, __LINE__);  \
    } while (0)

#define KLOG_CRITICAL_S(subsys, msg, label, s)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithString(::duetos::core::LogLevel::Critical, (subsys), (msg), (label), (s), __FILE__,     \
                                      __LINE__);                                                                       \
    } while (0)

// "With value" forms — one u64 appended as hex.
#define KLOG_INFO_V(subsys, msg, val)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Info, (subsys), (msg), (val));                          \
    } while (0)

#define KLOG_WARN_V(subsys, msg, val)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Warn, (subsys), (msg), (val), __FILE__, __LINE__);      \
    } while (0)

#define KLOG_ERROR_V(subsys, msg, val)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Error, (subsys), (msg), (val), __FILE__, __LINE__);     \
    } while (0)

#define KLOG_ERROR_S(subsys, msg, label, s)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithString(::duetos::core::LogLevel::Error, (subsys), (msg), (label), (s), __FILE__,        \
                                      __LINE__);                                                                       \
    } while (0)

#define KLOG_ERROR_2V(subsys, msg, la, a, lb, b)                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWith2Values(::duetos::core::LogLevel::Error, (subsys), (msg), (la), (a), (lb), (b),         \
                                       __FILE__, __LINE__);                                                            \
    } while (0)

// "With string" forms — one labelled C-string appended.
#define KLOG_INFO_S(subsys, msg, label, s)                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithString(::duetos::core::LogLevel::Info, (subsys), (msg), (label), (s));                  \
    } while (0)

#define KLOG_WARN_S(subsys, msg, label, s)                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWithString(::duetos::core::LogLevel::Warn, (subsys), (msg), (label), (s), __FILE__,         \
                                      __LINE__);                                                                       \
    } while (0)

// "With two values" forms — two labelled u64 values on one line.
#define KLOG_INFO_2V(subsys, msg, la, a, lb, b)                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWith2Values(::duetos::core::LogLevel::Info, (subsys), (msg), (la), (a), (lb), (b));         \
    } while (0)

#define KLOG_WARN_2V(subsys, msg, la, a, lb, b)                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogWith2Values(::duetos::core::LogLevel::Warn, (subsys), (msg), (la), (a), (lb), (b),          \
                                       __FILE__, __LINE__);                                                            \
    } while (0)

// Once-firing variants — each call site emits at most once per boot.
// The static bool sits in .bss, so KLOG_ONCE_INFO from inside a hot
// loop costs one load + one branch after the first firing.
// Useful for unimplemented-stub warnings, rare-but-expected conditions,
// or any "I only want to know once" observation.
#define KLOG_ONCE_INFO(subsys, msg)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        static bool _klog_once = false;                                                                                \
        if (!_klog_once)                                                                                               \
        {                                                                                                              \
            _klog_once = true;                                                                                         \
            ::duetos::core::Log(::duetos::core::LogLevel::Info, (subsys), (msg));                                      \
        }                                                                                                              \
    } while (0)

#define KLOG_ONCE_WARN(subsys, msg)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        static bool _klog_once = false;                                                                                \
        if (!_klog_once)                                                                                               \
        {                                                                                                              \
            _klog_once = true;                                                                                         \
            ::duetos::core::Log(::duetos::core::LogLevel::Warn, (subsys), (msg), __FILE__, __LINE__);                  \
        }                                                                                                              \
    } while (0)

// Warn-once that also renders a single u64 value alongside the message.
// Same dedup semantics as KLOG_ONCE_WARN (one fire per call site, ever),
// but the value gives the caller a way to pin which specific instance
// of the bug tripped — e.g. "OOB TLS slot index" with the offending idx,
// or "unhandled IRQ vector" with the vector number. The value is
// captured by the function call, not by the static once flag, so a
// callsite that fires once per BAD vector still needs explicit
// per-vector dedup; this macro is the right shape for "I want the
// first occurrence's value, ignore the rest forever."
#define KLOG_ONCE_WARN_V(subsys, msg, val)                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        static bool _klog_once = false;                                                                                \
        if (!_klog_once)                                                                                               \
        {                                                                                                              \
            _klog_once = true;                                                                                         \
            ::duetos::core::LogWithValue(::duetos::core::LogLevel::Warn, (subsys), (msg), (val), __FILE__, __LINE__);  \
        }                                                                                                              \
    } while (0)

// -----------------------------------------------------------------
// Area-aware variants — caller passes an explicit LogArea so a
// runtime `logarea off net` (etc.) can silence the chatter without
// disturbing other subsystems. Use these for high-volume traces
// (driver bring-up, syscall dispatch, allocator paths). The
// non-A variants stay valid for general status lines.
// -----------------------------------------------------------------
#define KLOG_TRACE_A(area_, subsys, msg)                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        if constexpr (static_cast<::duetos::u8>(::duetos::core::LogLevel::Trace) >=                                    \
                      static_cast<::duetos::u8>(::duetos::core::kKlogMinLevel))                                        \
        {                                                                                                              \
            ::duetos::core::LogA(::duetos::core::LogLevel::Trace, (area_), (subsys), (msg));                           \
        }                                                                                                              \
    } while (0)

#define KLOG_TRACE_AV(area_, subsys, msg, val)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        if constexpr (static_cast<::duetos::u8>(::duetos::core::LogLevel::Trace) >=                                    \
                      static_cast<::duetos::u8>(::duetos::core::kKlogMinLevel))                                        \
        {                                                                                                              \
            ::duetos::core::LogAWithValue(::duetos::core::LogLevel::Trace, (area_), (subsys), (msg), (val));           \
        }                                                                                                              \
    } while (0)

#define KLOG_DEBUG_A(area_, subsys, msg)                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogA(::duetos::core::LogLevel::Debug, (area_), (subsys), (msg));                               \
    } while (0)

#define KLOG_DEBUG_AV(area_, subsys, msg, val)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithValue(::duetos::core::LogLevel::Debug, (area_), (subsys), (msg), (val));               \
    } while (0)

#define KLOG_DEBUG_AS(area_, subsys, msg, label, s)                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithString(::duetos::core::LogLevel::Debug, (area_), (subsys), (msg), (label), (s));       \
    } while (0)

#define KLOG_INFO_A(area_, subsys, msg)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogA(::duetos::core::LogLevel::Info, (area_), (subsys), (msg));                                \
    } while (0)

#define KLOG_INFO_AV(area_, subsys, msg, val)                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithValue(::duetos::core::LogLevel::Info, (area_), (subsys), (msg), (val));                \
    } while (0)

#define KLOG_INFO_AS(area_, subsys, msg, label, s)                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithString(::duetos::core::LogLevel::Info, (area_), (subsys), (msg), (label), (s));        \
    } while (0)

#define KLOG_INFO_A2V(area_, subsys, msg, la, a, lb, b)                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWith2Values(::duetos::core::LogLevel::Info, (area_), (subsys), (msg), (la), (a), (lb),     \
                                        (b));                                                                          \
    } while (0)

#define KLOG_WARN_A(area_, subsys, msg)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogA(::duetos::core::LogLevel::Warn, (area_), (subsys), (msg), __FILE__, __LINE__);            \
    } while (0)

#define KLOG_WARN_AV(area_, subsys, msg, val)                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithValue(::duetos::core::LogLevel::Warn, (area_), (subsys), (msg), (val), __FILE__,       \
                                      __LINE__);                                                                       \
    } while (0)

#define KLOG_ERROR_A(area_, subsys, msg)                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogA(::duetos::core::LogLevel::Error, (area_), (subsys), (msg), __FILE__, __LINE__);           \
    } while (0)

#define KLOG_ERROR_AV(area_, subsys, msg, val)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithValue(::duetos::core::LogLevel::Error, (area_), (subsys), (msg), (val), __FILE__,      \
                                      __LINE__);                                                                       \
    } while (0)

#define KLOG_CRITICAL_A(area_, subsys, msg)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogA(::duetos::core::LogLevel::Critical, (area_), (subsys), (msg), __FILE__, __LINE__);        \
    } while (0)

#define KLOG_CRITICAL_AV(area_, subsys, msg, val)                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithValue(::duetos::core::LogLevel::Critical, (area_), (subsys), (msg), (val), __FILE__,   \
                                      __LINE__);                                                                       \
    } while (0)

#define KLOG_CRITICAL_AS(area_, subsys, msg, label, s)                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithString(::duetos::core::LogLevel::Critical, (area_), (subsys), (msg), (label), (s),     \
                                       __FILE__, __LINE__);                                                            \
    } while (0)

#define KLOG_WARN_AS(area_, subsys, msg, label, s)                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithString(::duetos::core::LogLevel::Warn, (area_), (subsys), (msg), (label), (s),         \
                                       __FILE__, __LINE__);                                                            \
    } while (0)

#define KLOG_ERROR_AS(area_, subsys, msg, label, s)                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::core::LogAWithString(::duetos::core::LogLevel::Error, (area_), (subsys), (msg), (label), (s),        \
                                       __FILE__, __LINE__);                                                            \
    } while (0)
