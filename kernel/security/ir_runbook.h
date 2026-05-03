#pragma once

#include "security/event_ring.h"
#include "util/types.h"

/*
 * DuetOS — incident-response runbook v0 (blue team).
 *
 * For every wall trip / detector fire, this TU emits a short
 * "what just happened + what to check next + escalation lever"
 * stanza to the serial console, and publishes an
 * `IrRunbookEmitted` event so the purple-team scorecard can
 * confirm the runbook actually ran.
 *
 * The data is a constexpr table indexed by EventKind. Adding a
 * new EventKind without a matching runbook entry trips the boot-
 * time self-test — preventing detectors from sliding in without
 * follow-up guidance.
 *
 * See `.claude/knowledge/blue-team-ir-runbook-v0.md` for the
 * design rationale and the per-EventKind step inventory.
 *
 * Context: kernel. Same constraints as event_ring publishes —
 * safe from any context, no allocation, no spinlock contention
 * (table is constexpr, output goes through SerialWrite).
 */

namespace duetos::security
{

inline constexpr u32 kIrMaxSteps = 6;

struct IrRunbookEntry
{
    EventKind kind;
    const char* one_line_summary;   // "FsWriteRateBurst — caller wrote >16 MiB in 1 s"
    const char* what_happened;      // 1-2 sentences explaining the trip
    const char* steps[kIrMaxSteps]; // up to 6 numbered steps; nullptr terminates
    const char* escalate_to;        // "policy set forensic" or similar; may be nullptr
};

/// Look up the entry for `kind`. Returns nullptr if no entry is
/// registered (every EventKind that needs follow-up MUST have
/// one — IrRunbookSelfTest enforces this at boot).
const IrRunbookEntry* IrRunbookLookup(EventKind kind);

/// Emit the runbook lines for `kind` to the serial console + bump
/// the emit counter + publish an `IrRunbookEmitted` event with
/// the underlying kind in aux1. Idempotent at the call-site
/// level; callers can fire this safely after every wall trip.
void IrRunbookEmit(EventKind kind, u32 actor_pid);

struct IrRunbookStats
{
    u64 emits_total;
    EventKind last_kind;
    u64 last_uptime_ns;
    u64 missing_entries; // emits called for a kind with no entry
};
IrRunbookStats IrRunbookStatsRead();

/// Boot-time self-test: walks every actionable EventKind and
/// confirms an entry exists. Mode-change events (PolicyChanged,
/// GuardModeChanged, ...) and bookkeeping events (AttackSimRun,
/// IrRunbookEmitted) are explicitly opted-out — they do not need
/// runbook follow-up. PASS / FAIL printed to COM1.
void IrRunbookSelfTest();

} // namespace duetos::security
