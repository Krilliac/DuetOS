#pragma once

#include "util/types.h"

/*
 * DuetOS — soft-lockup detector, v0 (plan D4).
 *
 * WHAT
 *   Watches for a single task that has been running on the CPU
 *   for "too long" without yielding. Distinct from the NMI
 *   watchdog (`arch::NmiWatchdog*`), which detects a fully wedged
 *   CPU where even the timer IRQ has stopped firing. The soft-
 *   lockup detector covers the case where the CPU is making
 *   progress at the IRQ level — the timer tick is firing — but
 *   the same kernel-mode task is hogging it.
 *
 * MECHANISM
 *   `SoftLockupTick(now_ticks, current_tid)` is called from the
 *   timer-IRQ tail (after `OnTimerTick`'s scheduler bookkeeping).
 *   It tracks the most recently observed running TID and a
 *   counter of consecutive ticks with that TID. If the counter
 *   exceeds `kSoftLockupThresholdTicks` (~100 ticks ≈ 1 second
 *   on the 100 Hz scheduler), a one-time klog warning fires.
 *   The warning is rate-limited per TID so a single misbehaving
 *   loop logs once, not every tick.
 *
 * GATING
 *   Active by default. Disable via `SoftLockupDisable()` from
 *   the panic / shutdown paths — once we're crashing, the noisy
 *   warning channel only obscures the real signal.
 *
 * SCOPE FOR v0
 *   - Single global state (the kernel runs on one CPU during
 *     bring-up; per-CPU state lands with B2 SMP).
 *   - Warning, not panic — soft-lockups are bugs to investigate,
 *     not always reasons to halt.
 *   - No "stuck task killer" — a future slice can pair the
 *     detector with `sched::SchedKillByTid` once a workload
 *     justifies the risk of false-positive task termination.
 *
 * NOT IN SCOPE
 *   - Cross-task wait-for graph analysis (lockdep handles that
 *     for tagged locks; soft-lockup catches "task in tight loop").
 *   - Per-task hung-task detection (the runaway-CPU detector +
 *     the kernel scan thread cover that with longer thresholds).
 */

namespace duetos::diag
{

/// 1 second on the 100 Hz scheduler tick. Tunable knob — too low
/// fires false positives during a legitimate long memcpy /
/// KASLR shuffle; too high lets a real loop run longer than the
/// runaway-CPU detector takes to react. 100 is the v0
/// compromise.
inline constexpr u64 kSoftLockupThresholdTicks = 100;

/// Per-tick check. Cheap (single load + compare in the common
/// case where the running TID changed since last tick — the
/// scheduler swapped tasks). Called from the timer IRQ after
/// `sched::OnTimerTick`. `current_tid == 0` means "kernel boot
/// task / idle" and is excluded from the lockup count — those
/// are legitimate "always-running" tasks.
void SoftLockupTick(u64 now_ticks, u64 current_tid);

/// Hard-disable the detector. Idempotent. Called from the panic
/// path so a final warning log doesn't drown out the crash dump.
void SoftLockupDisable();

/// Re-enable the detector. Idempotent. Pairs with
/// `SoftLockupDisable` so the soft-lockup detector can be a
/// driver fault domain (E3-followup) — Restart calls disable
/// then enable.
void SoftLockupEnable();

/// Total soft-lockup warnings emitted since boot. Cheap u64
/// load; the runtime checker / `inspect` (future) reports this.
/// Non-zero is a kernel bug to triage.
u64 SoftLockupWarningsEmitted();

/// Boot-time self-test. Drives the state machine directly with
/// synthesised tick + TID inputs:
///   - Same TID for `kSoftLockupThresholdTicks + 1` consecutive
///     ticks → exactly one warning.
///   - TID change resets the counter; subsequent ticks with the
///     new TID are not "in lockup" until the threshold is met.
///   - `current_tid == 0` (idle) never counts.
/// Asserts the warnings counter advances by exactly 1. Panics
/// on mismatch.
void SoftLockupSelfTest();

} // namespace duetos::diag
