#pragma once

#include "security/attack_sim.h"
#include "security/event_ring.h"
#include "util/types.h"

/*
 * DuetOS — purple-team coverage scorecard v0.
 *
 * Wraps `AttackSimRun()` with measurement: pre/post snapshots of
 * the event ring + per-attack timing brackets + a coverage score.
 *
 * Today, AttackSimRun runs every attack and records "Caught by
 * <detector>" — a binary signal. The scorecard adds:
 *
 *   - Did at least one event fire in the run window?
 *     (count, not specific kinds — the v0 attacks share underlying
 *     mechanisms so attributing one specific EventKind to one
 *     attack is brittle while runtime_checker's per-issue path
 *     is being refactored.)
 *   - How long was the run window?
 *   - What's the per-attack PASS/FAIL ratio? (carries over from
 *     AttackSimRun.)
 *   - Were any events DROPPED during the run? (would indicate the
 *     ring is too small for the attack workload.)
 *
 * v1 will add per-attack expectation tables ("attack X SHOULD
 * raise EventKind Y, attack Z SHOULD raise EventKind W") once
 * runtime_checker.cpp publishes EventKind-labelled events.
 *
 * See `.claude/knowledge/purple-team-coverage-scorecard-v0.md`
 * for the full design.
 *
 * Context: kernel. Same constraints as AttackSimRun — task
 * context only.
 */

namespace duetos::security
{

struct ScorecardSummary
{
    // Counts mirrored from AttackSimRun's AttackSummary.
    u64 attacks_run;
    u64 attacks_passed;
    u64 attacks_failed;
    u64 attacks_skipped;

    // Event-ring observations across the run window.
    u64 events_observed;     // ring deltas (publishes during the run)
    u64 events_dropped;      // dropped_oldest delta (ring overflowed)
    u64 runbooks_emitted;    // IrRunbookEmitted event count in window
    u64 policy_changes_seen; // PolicyChanged event count in window

    // Wall-clock timing.
    u64 run_start_ns;
    u64 run_end_ns;

    // Coverage scoring.
    //   coverage_pct = passed / max(1, run - skipped)
    // Stored as integer percent (0..100).
    u32 coverage_pct;
    bool ran_to_completion;
};

/// Run the full attacker simulation suite under measurement and
/// return the scorecard. Calls `AttackSimRun()` internally; the
/// caller does not need to call it separately.
ScorecardSummary PurpleTeamRunAll();

/// Read-only accessor for the last summary. Zero-initialised
/// until PurpleTeamRunAll has completed.
const ScorecardSummary& PurpleTeamLastSummary();

/// Pretty-print the summary to the serial console.
void PurpleTeamReport(const ScorecardSummary& s);

/// Boot-time self-test: sanity-checks that the scorecard's
/// pre/post event-ring observations are correct. Publishes 5
/// synthetic events around a no-op "run", confirms
/// events_observed == 5. PASS / FAIL printed to COM1.
void PurpleTeamSelfTest();

} // namespace duetos::security
