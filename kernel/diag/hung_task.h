#pragma once

#include "util/types.h"

/*
 * DuetOS — hung-task detector, v0.
 *
 * WHAT
 *   Complement to the per-CPU soft-lockup detector. Soft-lockup
 *   catches "CPU pegged running the same task forever" — a tight
 *   non-progressing loop in kernel mode. Hung-task catches the
 *   reverse failure shape: a task stuck in `TaskState::Blocked`
 *   that nobody ever wakes. The usual causes are
 *     - circular lock acquisition (deadlock),
 *     - a lost wakeup (signaller fired before the waiter
 *       enqueued, OR signaller never fired at all),
 *     - a dropped signal (event consumer crashed mid-handler
 *       and never called the matching `WakeOne`).
 *
 * MECHANISM
 *   `HungTaskTick()` is called from the heartbeat task every
 *   beat (~5 s). It walks the global all-tasks list under the
 *   sched lock, snapshots every (id, name, block_start_tick)
 *   triple where the task is currently Blocked with a non-zero
 *   block-start anchor, then releases the lock and computes
 *   `now_ticks - block_start_tick` for each snapshot. Tasks
 *   blocked for at least `kHungTaskThresholdTicks` fire a
 *   first-crossing warning (klog + probe + FaultReactDispatch).
 *
 *   Per-TID rate limiting: a fired warning records the TID + the
 *   tick it fired at. Subsequent ticks for the same TID within
 *   `kHungTaskRewarmSuppressionTicks` are silently suppressed —
 *   one warning per genuinely-stuck task per minute is enough
 *   for triage and avoids the soft-lockup-spam class of failure
 *   on long-running hangs.
 *
 * GATING
 *   Active by default once SchedInit has run (the all-tasks list
 *   is built incrementally as tasks are created). Disable via
 *   `HungTaskDisable()` from the panic / shutdown paths — once
 *   the box is crashing, the noisy warning channel only obscures
 *   the real signal.
 *
 * SCOPE
 *   - Stateless walker: no per-task state on Task itself; the
 *     per-TID rate-limit slot table lives in this TU.
 *   - Bounded snapshot: at most `kMaxBlockedSnapshotEntries`
 *     entries per pass. A workload with more blocked tasks than
 *     that gets one pass's worth visited; the next beat picks up
 *     whichever entries fell off this time. Cheap when the
 *     count is low (empty list, one walk).
 *   - Warning, not panic — a hung task is a bug to investigate,
 *     not always a reason to halt. Future fault-domain owners
 *     can override the per-domain policy to escalate.
 *
 * NOT IN SCOPE
 *   - Killing the hung task. We don't have a safe "detach
 *     Blocked task from arbitrary wait queue" primitive in v0
 *     (the producer that owns the WaitQueue might be mid-
 *     enqueue), so a future slice that adds a safe detach can
 *     wire kill-on-hung-task in then.
 *   - Cross-task wait-for graph analysis. Lockdep already
 *     handles cycles in tagged-lock acquisition order; hung-
 *     task catches the runtime symptom regardless of whether
 *     the cycle was statically detectable.
 */

namespace duetos::diag
{

/// 30 s on the 100 Hz scheduler tick. Tunable knob. Large enough
/// that a typical sleeping mutex on a real I/O path never trips
/// (a slow nvme command, a 10s wait-for-input, an ARP retry burst,
/// a TCP RTO window — all sit comfortably under this), small
/// enough that a missed wakeup or deadlock is visible to the
/// operator within a heartbeat-cadence-aligned window.
inline constexpr u64 kHungTaskThresholdTicks = 3000;

/// Per-TID re-warn suppression window. After warning once for a
/// hung TID, suppress further warnings for the same TID for this
/// many ticks (~1 minute at 100 Hz). One warn per minute per
/// stuck task is enough for triage and avoids the per-beat spam
/// that would otherwise drown a real concurrent hang.
inline constexpr u64 kHungTaskRewarmSuppressionTicks = 6000;

/// Per-tick walker. Called from the heartbeat task every beat
/// AFTER `RuntimeCheckerTick()` and BEFORE `FaultReactDrainPending()`.
/// Cheap when no tasks are hung — one bounded walk of the all-
/// tasks list under the sched lock, then a stack-buffer scan with
/// no allocations and no locks.
void HungTaskTick();

/// Hard-disable the detector. Idempotent. Called from the panic
/// path so a final warning log doesn't drown out the crash dump.
void HungTaskDisable();

/// Re-enable the detector. Idempotent.
void HungTaskEnable();

/// Total hung-task warnings emitted since boot. Cheap u64 load;
/// non-zero is a kernel bug to triage.
u64 HungTaskWarningsEmitted();

/// Boot-time self-test. Synthesises one Blocked task with its
/// `block_start_tick` rewound far enough into the past that the
/// detector MUST cross the threshold, drives `HungTaskTick()`,
/// asserts the warning counter advanced by exactly 1, then
/// re-runs to confirm the rate-limit suppresses a second warn.
/// Panics on mismatch. The synthesised task is created cleanly
/// (via `sched::SchedCreate`) and is signalled to exit at the
/// end of the test — no leak.
void HungTaskSelfTest();

} // namespace duetos::diag
