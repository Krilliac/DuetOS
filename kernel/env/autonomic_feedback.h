#pragma once

#include "env/autonomic.h"
#include "util/types.h"

/*
 * DuetOS — autonomic engine closed-loop feedback.
 *
 * Slice A of the autonomic arc lands "sense → decide → act". This
 * file closes the loop by adding "→ measure → record". When
 * `AutonomicApply` fires an action, it enqueues a feedback entry
 * carrying the pre-action snapshot of the metrics that action
 * targets and a deadline `check_at_tick` (default fire_tick + 10
 * = 100 ms at 100 Hz). The `kselfthink` kernel thread calls
 * `AutoFeedbackTick()` on every wake; pending entries whose
 * deadline has passed get evaluated, classified into one of three
 * outcomes, and appended to the selfthink causal chain.
 *
 * Outcomes:
 *
 *   * `Improved`  — targeted metric moved the expected direction
 *                   by more than the noise threshold (default 2 %).
 *                   E.g. MemReclaim freed > 2 % of heap.
 *   * `NoChange`  — within ±noise of the pre value. The action
 *                   ran but its observable effect was below the
 *                   threshold. Recorded; no probe fire.
 *   * `Worsened`  — metric moved AGAINST the expected direction.
 *                   Fires `kAutonomicOutcomeMissed` so a future
 *                   investigator has a sentinel line right at the
 *                   regression point.
 *
 * Actions whose effect isn't quantifiable as a single-metric
 * delta (SecurityEscalate, the SchedPower* triplet) are classified
 * `Diagnostic` and only logged; they have no expected metric move.
 *
 * Subsystem isolation: pure observation of metrics already
 * exposed through `mm::*` / `core::RuntimeCheckerStatusRead`.
 * No new actuators; the kernel still owns every effect.
 *
 * Context: kernel. Enqueue is task-context (called from
 * `AutonomicApply`, which is task-context per its own contract).
 * Tick is task-context (called from `kselfthink`).
 */

namespace duetos::env::feedback
{

/// Ring capacity. The autonomic engine fires at most a few
/// actions per minute under normal load; 64 entries lets a
/// burst-fire spike retain its pre-snapshots for the full
/// outcome window without dropping any.
inline constexpr u64 kFeedbackRingCap = 64;

/// Default check window — 10 ticks at 100 Hz = 100 ms. Long
/// enough for kernel-side mutators (heap drain, pool drain,
/// power-bias change) to observably move the targeted metric;
/// short enough that the operator sees the outcome in the
/// next causal-chain dump.
inline constexpr u64 kFeedbackDelayTicks = 10;

/// Outcome classification.
enum class Outcome : u8
{
    Pending = 0,    // deadline not yet reached
    Improved = 1,   // metric moved expected direction
    NoChange = 2,   // within ±kFeedbackNoisePct of pre
    Worsened = 3,   // metric moved against expected direction
    Diagnostic = 4, // action has no quantifiable single-metric move
};

const char* OutcomeName(Outcome o);

/// Pre-action snapshot of every metric any current action class
/// targets. Captured once per `AutonomicApply` set and copied
/// into every per-action feedback entry the set emits.
struct PreMetrics
{
    u64 phys_used_pct;
    u64 heap_used_pct;
    u64 health_issues_total;
};

/// One pending feedback record. Sized to 48 B for cache line
/// friendliness.
struct FeedbackEntry
{
    u8 live;    // 1 while waiting for deadline; 0 once evaluated
    u8 outcome; // Outcome enum value (Pending until evaluated)
    u8 rule;    // AutoRule
    u8 action;  // AutoAction
    u32 reserved;
    u64 tick_fired;
    u64 check_at_tick;
    PreMetrics pre;
};
static_assert(sizeof(FeedbackEntry) == 48, "FeedbackEntry packing changed");

/// Capture every metric the current action set could care about.
/// Called by `AutonomicApply` before any actuator runs so the
/// pre/post comparison is meaningful.
PreMetrics CapturePreMetrics();

/// Enqueue a feedback entry. Called once per (rule, action) pair
/// from `AutonomicApply`. `fire_tick` is the poll's tick stamp — the
/// same value the learner recorded its decision context under, so a
/// Live-mode reward credit-assigns the right synapses. Safe from task
/// context. Wrap-safe — a full ring overwrites the oldest still-pending
/// entry.
void Enqueue(AutoRule rule, AutoAction action, const PreMetrics& pre, u64 fire_tick);

/// Walk the ring, evaluate any entry whose deadline has passed,
/// and record the outcome through the selfthink causal chain.
/// Idempotent: an already-evaluated entry is skipped.
void Tick();

/// Read-only stats — total enqueued + per-outcome counts. Used
/// by the `selfthink feedback` shell command.
struct FeedbackStats
{
    u64 enqueued_total;
    u64 evaluated_total;
    u64 per_outcome[5]; // indexed by Outcome
    u64 ring_overflows;
};
FeedbackStats StatsRead();

/// Walk every still-live entry newest-first, invoking `cb`. Used
/// by `selfthink feedback` to print pending + evaluated history.
/// Stops early when `cb` returns false. Returns entries visited.
u32 RingWalk(bool (*cb)(const FeedbackEntry& e, void* ctx), void* ctx);

/// Boot self-test. Drives a synthetic Enqueue → fast-forward
/// deadline → Tick → assert classification round-trip works.
/// Emits `[autonomic-feedback] selftest pass`.
void SelfTest();

} // namespace duetos::env::feedback
