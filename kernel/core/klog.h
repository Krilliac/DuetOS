#pragma once

#include "types.h"

/*
 * CustomOS — kernel structured logging.
 *
 * Replaces the ad-hoc `arch::SerialWrite("[subsys] msg\n")` pattern
 * with a uniform, severity-tagged API. Output lines look like:
 *
 *     [I] <subsystem> : <message>
 *     [I] <subsystem> : <message>   val=0x<hex>
 *     [W] <subsystem> : <message>
 *     [E] <subsystem> : <message>
 *     [D] <subsystem> : <message>
 *
 * Severity letter is the single-character bracket prefix; consuming
 * tools (future CI log diff, log grep in `qemu.log`) can filter on
 * it trivially. Subsystem tag convention matches core::Panic (use
 * the kernel-tree path sans `kernel/`).
 *
 * Design choices:
 *   - No variadic printf. `snprintf` in a kernel is a large surface;
 *     the "message + optional u64" API covers every existing need
 *     and we reach for `PanicWithValue`-style for anything richer.
 *   - Compile-time min level (`kKlogMinLevel`) filters cheaply —
 *     Debug calls compile to a single inline check.
 *   - No allocation, no lock. Concurrent writers may interleave;
 *     that's the cost of no-lock — in return we can log from IRQ
 *     context with no deadlock risk. An SMP-safe ring buffer that
 *     serialises writes is a future improvement (see revisit
 *     markers in the decision log).
 *   - Timestamp omitted for now; when added it'll be TimerTicks()
 *     at 10 ms resolution. Cheap single-instruction read.
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

/// Emit a tagged log line. Single-letter severity + subsystem + msg.
/// Safe from IRQ context. No-op if `level < kKlogMinLevel`.
void Log(LogLevel level, const char* subsystem, const char* message);

/// As above, with a u64 rendered as hex after the message.
void LogWithValue(LogLevel level, const char* subsystem, const char* message, u64 value);

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
