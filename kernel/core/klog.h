#pragma once

#include "types.h"

/*
 * CustomOS — kernel structured logging.
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
 *
 * Context: kernel. Safe at any interrupt level.
 */

namespace customos::core
{

enum class LogLevel : u8
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
};

/// Compile-time minimum severity. Adjust per build preset — Debug for
/// `x86_64-debug`, Info for `x86_64-release` (once release preset
/// exists). Calls below this level compile to a no-op in release.
inline constexpr LogLevel kKlogMinLevel = LogLevel::Debug;

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

/// Emit a tagged log line. Single-letter severity + subsystem + msg.
/// Safe from IRQ context. No-op if `level < max(kKlogMinLevel,
/// GetLogThreshold())`.
void Log(LogLevel level, const char* subsystem, const char* message);

/// As above, with a u64 rendered as hex after the message.
void LogWithValue(LogLevel level, const char* subsystem, const char* message, u64 value);

/// Variant that takes a labelled NUL-terminated string. Renders as
///     [I] subsys : message   <label>="<value>"
/// Handy for device names, PCI vendors, file paths — anything the
/// reader wants to see literally, not as hex. `value_str` must
/// outlive the log call; it's stored by pointer in the ring buffer.
void LogWithString(LogLevel level, const char* subsystem, const char* message, const char* label,
                   const char* value_str);

/// Variant that carries two labelled u64 values on one line. Renders as
///     [I] subsys : message   <a_label>=0x... (dec)   <b_label>=0x... (dec)
/// Useful for (base, size) / (count, stride) / (got, want) pairs that
/// currently take two separate log lines. Ring-buffer persistence
/// captures only the first value to keep the entry size bounded; if
/// both values matter for post-mortem analysis, use two LogWithValue
/// calls instead.
void LogWith2Values(LogLevel level, const char* subsystem, const char* message, const char* a_label, u64 a_value,
                    const char* b_label, u64 b_value);

/// Toggle ANSI colour codes on the serial sink. Defaults to on.
/// Off is useful for log-capture tools that don't understand escape
/// sequences, or for CI runs that diff boot logs byte-wise.
/// Does NOT affect the tee (framebuffer) — colours there are driven
/// by the console itself.
void SetLogColor(bool enabled);
bool GetLogColor();

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

/// Variant of DumpLogRing that writes to an arbitrary string
/// sink instead of COM1 directly. Useful for surfacing the ring
/// to a shell `dmesg` command without also echoing to serial.
/// Same oldest-first order; caller-supplied writer sees one
/// chunk per formatted token.
void DumpLogRingTo(LogTee writer);

} // namespace customos::core

// Convenience macros. The `do { } while (0)` lets call sites still
// write `KLOG_INFO(...);` with a trailing semicolon.
#define KLOG_DEBUG(subsys, msg)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::Log(::customos::core::LogLevel::Debug, (subsys), (msg));                                     \
    } while (0)

#define KLOG_INFO(subsys, msg)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::Log(::customos::core::LogLevel::Info, (subsys), (msg));                                      \
    } while (0)

#define KLOG_WARN(subsys, msg)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::Log(::customos::core::LogLevel::Warn, (subsys), (msg));                                      \
    } while (0)

#define KLOG_ERROR(subsys, msg)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::Log(::customos::core::LogLevel::Error, (subsys), (msg));                                     \
    } while (0)

// "With value" forms — one u64 appended as hex.
#define KLOG_INFO_V(subsys, msg, val)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::LogWithValue(::customos::core::LogLevel::Info, (subsys), (msg), (val));                      \
    } while (0)

#define KLOG_WARN_V(subsys, msg, val)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::LogWithValue(::customos::core::LogLevel::Warn, (subsys), (msg), (val));                      \
    } while (0)

#define KLOG_ERROR_V(subsys, msg, val)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::LogWithValue(::customos::core::LogLevel::Error, (subsys), (msg), (val));                     \
    } while (0)

// "With string" forms — one labelled C-string appended.
#define KLOG_INFO_S(subsys, msg, label, s)                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::LogWithString(::customos::core::LogLevel::Info, (subsys), (msg), (label), (s));              \
    } while (0)

#define KLOG_WARN_S(subsys, msg, label, s)                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::LogWithString(::customos::core::LogLevel::Warn, (subsys), (msg), (label), (s));              \
    } while (0)

// "With two values" forms — two labelled u64 values on one line.
#define KLOG_INFO_2V(subsys, msg, la, a, lb, b)                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::LogWith2Values(::customos::core::LogLevel::Info, (subsys), (msg), (la), (a), (lb), (b));     \
    } while (0)

#define KLOG_WARN_2V(subsys, msg, la, a, lb, b)                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ::customos::core::LogWith2Values(::customos::core::LogLevel::Warn, (subsys), (msg), (la), (a), (lb), (b));     \
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
            ::customos::core::Log(::customos::core::LogLevel::Info, (subsys), (msg));                                  \
        }                                                                                                              \
    } while (0)

#define KLOG_ONCE_WARN(subsys, msg)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        static bool _klog_once = false;                                                                                \
        if (!_klog_once)                                                                                               \
        {                                                                                                              \
            _klog_once = true;                                                                                         \
            ::customos::core::Log(::customos::core::LogLevel::Warn, (subsys), (msg));                                  \
        }                                                                                                              \
    } while (0)
