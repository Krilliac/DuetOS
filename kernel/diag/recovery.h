#pragma once

#include "util/types.h"

/*
 * DuetOS — runtime recovery infrastructure.
 *
 * Implements the API surface defined in
 * `docs/knowledge/runtime-recovery-strategy.md`. See that doc for
 * the full taxonomy (Class A halt / B driver restart / C process
 * kill / D retry / E reject / F object reset).
 *
 * This header exposes:
 *
 *   Class B — DriverFault(...) : one-line call sites from driver
 *             code when the driver decides it can't keep going on
 *             the current device. Today: logs + increments a global
 *             fault counter. Future: triggers Teardown + Probe
 *             retry + strike-out-after-N policy.
 *
 *   Class D — RetryWithBackoff<Fn>(...) : template helper that
 *             re-invokes a callable with exponential backoff and a
 *             bounded attempt cap. Per the strategy doc, every
 *             retry logs at Warn and the final give-up at Error.
 *
 * Class A (halt) is already provided by `core::Panic` in panic.h.
 * Class C (process kill) is partially implemented by the scheduler
 * dead-task reaper (next commit); full ring-3 process-kill arrives
 * with the userland commit.
 * Class E (reject) is the trust-boundary pattern that arrives with
 * the syscall surface.
 * Class F (object reset) is case-by-case and has no shared API —
 * subsystems that opt in write their own path and document the
 * bounded-ness argument in their knowledge file.
 *
 * Context: kernel. All entry points safe at any interrupt level
 * except where noted (RetryWithBackoff with a SchedSleepTicks
 * policy must not run in IRQ context).
 */

namespace duetos::core
{

// ---------------------------------------------------------------------------
// Class B — driver fault reporting.
// ---------------------------------------------------------------------------

/// Reason a driver is reporting itself broken. Extend as real drivers
/// hit real faults — the current list covers the cases we've seen in
/// other kernels' driver-restart machinery.
enum class DriverFaultReason : u8
{
    DeviceTimeout = 0, // Device didn't respond in the expected window.
    UnexpectedStatus,  // Device returned a status the driver can't decode.
    DmaError,          // DMA abort / bus fault reported by the controller.
    FirmwareLied,      // Device descriptor / capabilities inconsistent.
    InternalInvariant, // Driver's own state machine entered invalid state.
    Hung,              // Watchdog on a driver thread fired.
    Unknown,           // Catch-all for drivers that don't fit above.
};

/// Report a driver fault. v0 behaviour:
///
///   - Emit a `klog::Error` line with driver name + reason.
///   - Increment `DriverFaultCount()` for diagnostics.
///   - Return to the caller (driver decides what to do next — today
///     this typically means "log and proceed in degraded mode").
///
/// When the driver model lands this will call a registered
/// `fault_handler(driver_name, reason)` that owns the Teardown →
/// Probe retry loop. Call sites don't change — the transition is
/// behind this API.
void DriverFault(const char* driver_name, DriverFaultReason reason);

/// Number of driver faults seen since boot. Diagnostic only.
u64 DriverFaultCount();

// ---------------------------------------------------------------------------
// Class D — retry with bounded backoff.
// ---------------------------------------------------------------------------

/// Retry policy. `base_delay_ticks` is the first backoff; subsequent
/// retries wait `base * 2^attempt`. `max_attempts` caps the total;
/// `max_total_ticks` caps total wall-clock wait.
struct RetryPolicy
{
    u32 max_attempts;
    u64 base_delay_ticks; // 1 tick = 10 ms at current TimerInit rate
    u64 max_total_ticks;  // give up once cumulative wait exceeds this
};

/// Conservative defaults for "fast I/O paths" — 3 attempts, 10 ms
/// base, 100 ms cap. Sensible for AHCI / NVMe command retries.
inline constexpr RetryPolicy kRetryFastIo = {
    .max_attempts = 3,
    .base_delay_ticks = 1,
    .max_total_ticks = 10,
};

/// Defaults for background work that can tolerate longer waits —
/// 10 attempts, 10 ms base, 1 s cap.
inline constexpr RetryPolicy kRetryBackground = {
    .max_attempts = 10,
    .base_delay_ticks = 1,
    .max_total_ticks = 100,
};

/// Result of a retried operation.
enum class RetryOutcome : u8
{
    Success = 0, // operation reported success
    GaveUp = 1,  // exhausted attempts / total-time budget
};

/// Retry `fn()` until it returns true or the policy exhausts. Emits
/// a `klog::Warn` on each retry and `klog::Error` on final give-up.
/// `label` identifies the operation in log output.
///
/// Must NOT be called from IRQ context — sleeps between attempts.
///
/// Intentionally template so the callable can be a lambda with
/// captures without forcing a heap allocation for type erasure.
template <typename Fn> RetryOutcome RetryWithBackoff(const char* label, Fn fn, const RetryPolicy& policy);

// ---------------------------------------------------------------------------
// Class C — partial: task reap request hook.
// ---------------------------------------------------------------------------

/// Called by the scheduler when a task flips to Dead. Today this
/// is a thin signal to the reaper thread; future ring-3 process
/// termination extends this to also tear down the address space,
/// file descriptors, capability table, and IPC ports.
///
/// Declared here (rather than inside sched/sched.h) so future
/// Class C consumers know to look in diag/recovery.h for the
/// extension point.
void OnTaskExited();

} // namespace duetos::core

// ---------------------------------------------------------------------------
// Template implementation — must live in the header.
// ---------------------------------------------------------------------------

#include "log/klog.h"

namespace duetos::sched
{
void SchedSleepTicks(u64 ticks); // forward decl to avoid pulling sched.h
}

namespace duetos::core
{

template <typename Fn> RetryOutcome RetryWithBackoff(const char* label, Fn fn, const RetryPolicy& policy)
{
    u64 elapsed = 0;
    u64 delay = policy.base_delay_ticks;

    for (u32 attempt = 0; attempt < policy.max_attempts; ++attempt)
    {
        if (fn())
        {
            return RetryOutcome::Success;
        }

        if (elapsed + delay > policy.max_total_ticks)
        {
            break;
        }

        LogWithValue(LogLevel::Warn, label, "retry: operation failed, backing off (attempt)",
                     static_cast<u64>(attempt));
        sched::SchedSleepTicks(delay);
        elapsed += delay;
        delay *= 2; // exponential
    }

    LogWithValue(LogLevel::Error, label, "retry: gave up after attempts", static_cast<u64>(policy.max_attempts));
    return RetryOutcome::GaveUp;
}

} // namespace duetos::core
