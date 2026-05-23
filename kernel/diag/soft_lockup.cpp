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
#include "arch/x86_64/smp.h"
#include "core/panic.h"
#include "diag/fault_react.h"
#include "log/klog.h"
#include "security/fault_domain.h"
#include "util/types.h"

namespace duetos::diag
{

namespace
{

// Per-CPU detector state. v0 uses a single slot (slot 0) since
// only the BSP runs at this point in the boot path; once SMP
// brings APs up (plan B2), each CPU's tick handler will index
// this array by its own CPU ID. The struct shape is the
// future-portable form — adding more slots requires bumping
// `kSoftLockupCpuMax` and routing `current_cpu` into
// `SoftLockupTick`. (D4-followup, 2026-04-28.)
struct PerCpuState
{
    u64 last_tid;       ///< Most recently observed running TID.
    u64 same_tid_count; ///< Consecutive ticks with that TID.
    u64 warned_for_tid; ///< TID we've already warned about; rate-limit gate.
};

constexpr u32 kSoftLockupCpuMax = 1;
constinit PerCpuState g_per_cpu[kSoftLockupCpuMax] = {};
// Aliases keep the existing single-CPU code path readable; the
// per-CPU restructuring is purely structural for now.
#define g_state g_per_cpu[0]

constinit u64 g_warnings_total = 0; ///< Total warnings (across all CPUs).
constinit bool g_enabled = true;    ///< Disabled from panic path.
// True while SoftLockupSelfTest is driving synthetic ticks. The
// LAPIC-timer-driven SoftLockupTick path early-returns when this
// is set so it can't interleave its real tid into the self-test's
// synthetic state machine and trip the rate-limit assertion. The
// self-test calls a sibling helper that bypasses this gate.
constinit bool g_self_test_in_progress = false;

// Internal tick implementation. The public `SoftLockupTick` adds
// the timer-driven gates; the self-test calls the internal one
// directly so its synthetic tids reach the state machine
// regardless of whether the timer-driven path is gated.
void TickInternal(u64 now_ticks, u64 current_tid, const char* current_name);

} // namespace

void SoftLockupTick(u64 now_ticks, u64 current_tid, const char* current_name)
{
    if (!g_enabled || g_self_test_in_progress)
    {
        return;
    }
    TickInternal(now_ticks, current_tid, current_name);
}

namespace
{

void TickInternal(u64 now_ticks, u64 current_tid, const char* current_name)
{
    (void)now_ticks; // future use: include in the warning line

    // Idle / boot task (TID 0) never counts as a lockup — those
    // are legitimately always-running.
    if (current_tid == 0)
    {
        g_state.last_tid = 0;
        g_state.same_tid_count = 0;
        return;
    }

    if (current_tid != g_state.last_tid)
    {
        // Scheduler swapped to a different task — reset the
        // counter and clear the rate-limit gate so a future
        // lockup of THIS new TID can warn even if we already
        // warned about a different one.
        g_state.last_tid = current_tid;
        g_state.same_tid_count = 1;
        g_state.warned_for_tid = 0;
        return;
    }

    ++g_state.same_tid_count;
    if (g_state.same_tid_count > kSoftLockupThresholdTicks && g_state.warned_for_tid != current_tid)
    {
        // First crossing of the threshold for this run. Route
        // through diag::FaultReactDispatch so the dispatch
        // counter reflects soft-lockup events. Default policy
        // for SoftLockup is RestartDomain, but we don't bind a
        // domain (there's nothing TO restart for "task X is
        // hogging the CPU") — the dispatcher decays
        // RestartDomain → Continue when domain is unbound, so
        // the observable outcome is "log + return", same as
        // the previous KLOG_WARN_V path. The "already warned"
        // gate stays at this layer to keep rate-limiting cheap.
        ++g_warnings_total;
        g_state.warned_for_tid = current_tid;

        // Identity line — emitted BEFORE FaultReactDispatch's
        // bare `val=<tid>` warning so a log reader sees task
        // name and stuck-ticks count next to each other. Raw
        // SerialWrite (not klog) because we are inside the timer
        // IRQ tail: klog's spinlock would deadlock if the hot
        // task happens to be holding it, and raw UART bytes get
        // out even when the rest of the world is wedged. One
        // line per first-crossing of the threshold (rate-limited
        // by `warned_for_tid` above) — costs ~120 UART bytes per
        // distinct lockup, zero cost when no lockup happens.
        arch::SerialWrite("[soft-lockup] task stuck tid=");
        arch::SerialWriteHex(current_tid);
        arch::SerialWrite(" name=\"");
        arch::SerialWrite(current_name != nullptr ? current_name : "<unknown>");
        arch::SerialWrite("\" ticks_in_run=");
        arch::SerialWriteHex(g_state.same_tid_count);
        arch::SerialWrite("\n");

        // Broadcast NMI to peer CPUs so they each capture their
        // own panic_snapshot_* state. The peer NMI handler
        // populates the snapshot and halts; the snapshots
        // survive into a subsequent panic dump if this lockup
        // escalates. If the lockup eventually clears on its
        // own, the snapshots are just dead BSS — no cost. This
        // is the "lightweight cross-CPU visibility" half of the
        // NMI-watchdog HPET-fallback proposal — the full
        // hardware-NMI-on-no-progress lands when the HPET driver
        // gains per-timer comparator + IOAPIC routing.
        //
        // Skipped during self-test (the test exercises the state
        // machine with synthetic TIDs and shouldn't broadcast).
        if (!g_self_test_in_progress)
            ::duetos::arch::PanicBroadcastNmi();

        ::duetos::diag::FaultEvidence ev = {};
        ev.source = "diag/soft-lockup";
        ev.kind = ::duetos::diag::FaultKind::SoftLockup;
        ev.severity = ::duetos::diag::FaultSeverity::Degraded;
        ev.attempt_count = 0;
        ev.faulting_rip = 0;
        ev.aux = current_tid;
        (void)::duetos::diag::FaultReactDispatch(::duetos::core::kFaultDomainInvalid, ev);
    }
}

} // namespace

void SoftLockupDisable()
{
    g_enabled = false;
}

void SoftLockupEnable()
{
    // Reset the per-CPU streak state so a re-enable doesn't
    // immediately fire on a stale TID match.
    for (u32 i = 0; i < kSoftLockupCpuMax; ++i)
    {
        g_per_cpu[i].last_tid = 0;
        g_per_cpu[i].same_tid_count = 0;
        g_per_cpu[i].warned_for_tid = 0;
    }
    g_enabled = true;
}

u64 SoftLockupWarningsEmitted()
{
    return g_warnings_total;
}

void SoftLockupSelfTest()
{
    arch::SerialWrite("[soft-lockup] self-test: state machine + threshold + reset\n");

    // Gate the timer-driven SoftLockupTick path for the duration
    // of the test. Without this, the LAPIC tick handler interleaves
    // its real (current_tid) into the per-CPU state machine between
    // our synthetic ticks and the rate-limit assertion fires
    // spuriously on a real-world preemption boundary. The test
    // calls TickInternal directly to bypass the same gate.
    g_self_test_in_progress = true;

    // Save + reset state so the test starts from a clean slate
    // even if a prior caller already advanced counters. (At boot
    // this is fresh; the save/restore makes the test re-runnable
    // from a shell command later.)
    const u64 saved_warnings = g_warnings_total;
    g_state.last_tid = 0;
    g_state.same_tid_count = 0;
    g_state.warned_for_tid = 0;

    // (1) Idle TID (0) never counts. Drive 200 ticks with TID=0
    // and assert no warning.
    for (u64 i = 0; i < 200; ++i)
    {
        TickInternal(i, 0, "selftest-idle");
    }
    if (g_warnings_total != saved_warnings)
    {
        core::Panic("diag/soft-lockup", "self-test: idle TID triggered a warning");
    }

    // (2) Same TID for threshold+1 consecutive ticks → exactly
    // one warning.
    for (u64 i = 0; i <= kSoftLockupThresholdTicks; ++i)
    {
        TickInternal(1000 + i, 42, "selftest-42");
    }
    if (g_warnings_total != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: threshold did not trigger exactly one warning");
    }

    // (3) Continuing on the same TID does NOT re-warn (rate limit).
    for (u64 i = 0; i < kSoftLockupThresholdTicks * 2; ++i)
    {
        TickInternal(2000 + i, 42, "selftest-42");
    }
    if (g_warnings_total != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: rate limit failed (re-warned)");
    }

    // (4) TID change resets the state — short subsequent run
    // does not warn.
    TickInternal(3000, 99, "selftest-99"); // single tick on TID 99; counter = 1
    if (g_warnings_total != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: TID change spuriously warned");
    }

    // (5) Holding TID 99 long enough now warns (separate gate).
    for (u64 i = 0; i < kSoftLockupThresholdTicks; ++i)
    {
        TickInternal(3001 + i, 99, "selftest-99");
    }
    if (g_warnings_total != saved_warnings + 2)
    {
        core::Panic("diag/soft-lockup", "self-test: post-reset threshold did not warn");
    }

    // Reset state for steady-state operation.
    g_state.last_tid = 0;
    g_state.same_tid_count = 0;
    g_state.warned_for_tid = 0;

    // Re-open the timer-driven path now that the synthetic
    // sequence is done.
    g_self_test_in_progress = false;

    arch::SerialWrite("[soft-lockup] self-test OK (idle skip + threshold + rate limit + per-TID reset).\n");
}

} // namespace duetos::diag
