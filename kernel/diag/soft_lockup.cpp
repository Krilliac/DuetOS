/*
 * DuetOS — soft-lockup detector, v0 (plan D4).
 *
 * See `soft_lockup.h` for the public contract. This TU owns the
 * state machine + warning rate-limiting + self-test.
 *
 * Why it's a separate TU from the NMI watchdog (`arch::NmiWatchdog*`):
 *   - Watchdog runs in NMI context, fires only when timer IRQ has
 *     stopped, panics on detection.
 *   - This detector runs in IRQ context (timer IRQ tail), fires
 *     when a task hogs the CPU, logs and continues.
 *   The two failure modes are disjoint and the response policies
 *   differ; combining them would tangle the rate-limiting + the
 *   panic semantics.
 */

#include "diag/soft_lockup.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "util/types.h"

namespace duetos::diag
{

namespace
{

// State machine. All single-CPU for v0; per-CPU upgrade lands
// with B2 SMP. The detector runs from the timer IRQ — accesses
// don't need locking because IRQs serialise on a single CPU.
constinit u64 g_last_tid = 0;       ///< Most recently observed running TID.
constinit u64 g_same_tid_count = 0; ///< Consecutive ticks with that TID.
constinit u64 g_warned_for_tid = 0; ///< TID we've already warned about; rate-limit gate.
constinit u64 g_warnings_total = 0; ///< Total warnings emitted since boot.
constinit bool g_enabled = true;    ///< Disabled from panic path.

} // namespace

void SoftLockupTick(u64 now_ticks, u64 current_tid)
{
    (void)now_ticks; // future use: include in the warning line

    if (!g_enabled)
    {
        return;
    }

    // Idle / boot task (TID 0) never counts as a lockup — those
    // are legitimately always-running.
    if (current_tid == 0)
    {
        g_last_tid = 0;
        g_same_tid_count = 0;
        return;
    }

    if (current_tid != g_last_tid)
    {
        // Scheduler swapped to a different task — reset the
        // counter and clear the rate-limit gate so a future
        // lockup of THIS new TID can warn even if we already
        // warned about a different one.
        g_last_tid = current_tid;
        g_same_tid_count = 1;
        g_warned_for_tid = 0;
        return;
    }

    ++g_same_tid_count;
    if (g_same_tid_count > kSoftLockupThresholdTicks && g_warned_for_tid != current_tid)
    {
        // First crossing of the threshold for this run. Log once,
        // mark this TID as "already warned" so we don't spam the
        // klog — the next reset (TID change) clears the gate.
        ++g_warnings_total;
        g_warned_for_tid = current_tid;
        KLOG_WARN_V("soft-lockup", "task running > 1s without yield, tid", current_tid);
    }
}

void SoftLockupDisable()
{
    g_enabled = false;
}

u64 SoftLockupWarningsEmitted()
{
    return g_warnings_total;
}

void SoftLockupSelfTest()
{
    arch::SerialWrite("[soft-lockup] self-test: state machine + threshold + reset\n");

    // Save + reset state so the test starts from a clean slate
    // even if a prior caller already advanced counters. (At boot
    // this is fresh; the save/restore makes the test re-runnable
    // from a shell command later.)
    const u64 saved_warnings = g_warnings_total;
    g_last_tid = 0;
    g_same_tid_count = 0;
    g_warned_for_tid = 0;

    // (1) Idle TID (0) never counts. Drive 200 ticks with TID=0
    // and assert no warning.
    for (u64 i = 0; i < 200; ++i)
    {
        SoftLockupTick(i, 0);
    }
    if (g_warnings_total != saved_warnings)
    {
        core::Panic("diag/soft-lockup", "self-test: idle TID triggered a warning");
    }

    // (2) Same TID for threshold+1 consecutive ticks → exactly
    // one warning.
    for (u64 i = 0; i <= kSoftLockupThresholdTicks; ++i)
    {
        SoftLockupTick(1000 + i, 42);
    }
    if (g_warnings_total != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: threshold did not trigger exactly one warning");
    }

    // (3) Continuing on the same TID does NOT re-warn (rate limit).
    for (u64 i = 0; i < kSoftLockupThresholdTicks * 2; ++i)
    {
        SoftLockupTick(2000 + i, 42);
    }
    if (g_warnings_total != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: rate limit failed (re-warned)");
    }

    // (4) TID change resets the state — short subsequent run
    // does not warn.
    SoftLockupTick(3000, 99); // single tick on TID 99; counter = 1
    if (g_warnings_total != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: TID change spuriously warned");
    }

    // (5) Holding TID 99 long enough now warns (separate gate).
    for (u64 i = 0; i < kSoftLockupThresholdTicks; ++i)
    {
        SoftLockupTick(3001 + i, 99);
    }
    if (g_warnings_total != saved_warnings + 2)
    {
        core::Panic("diag/soft-lockup", "self-test: post-reset threshold did not warn");
    }

    // Reset state for steady-state operation.
    g_last_tid = 0;
    g_same_tid_count = 0;
    g_warned_for_tid = 0;

    arch::SerialWrite("[soft-lockup] self-test OK (idle skip + threshold + rate limit + per-TID reset).\n");
}

} // namespace duetos::diag
