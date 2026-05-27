#pragma once

#include "diag/fma/ereport.h"
#include "util/types.h"

/*
 * DuetOS — FMA diagnosis engine, v0 (skeleton).
 *
 * Reads the ereport ring (see ereport.h), applies a small set of
 * correlation rules, and appends `Suspect` records to a fixed
 * suspect ring. The engine itself does NOT remediate — it builds
 * an audit trail. A later slice consumes the suspect list and
 * fires page retire / driver mark-failed / system flag.
 *
 * The three v0 rules:
 *
 *   1. ECC correlation. If `>=kEccCorrelationThreshold` events of
 *      class `EccCorrected` and matching `target_id` (DIMM cluster)
 *      land in a `kCorrelationWindowTicks` window, append a Suspect
 *      with severity Degraded suggesting page retire.
 *
 *   2. Driver-fault correlation. If `>=kDriverFaultThreshold`
 *      events of class `DriverFault` OR `DriverTimeout` and matching
 *      `target_id` (driver / domain id) land in the window, append
 *      a Suspect suggesting driver restart.
 *
 *   3. KernelIntegrity is always Critical. ONE event is enough; no
 *      correlation needed. Append a Suspect immediately.
 *
 * Total per-tick work is O(ring_size + targets_tracked); bounded
 * <1 ms even at full ring. Runs from the heartbeat task.
 *
 * Context: kernel, heartbeat thread. Not safe from IRQ context —
 * uses a small stack-local target table for correlation that costs
 * ~512 bytes.
 */

namespace duetos::diag::fma
{

/// A suspect — what the diagnosis engine thinks is broken. Kept
/// after diagnosis as an audit trail for the remediation slice.
struct Suspect
{
    u64 timestamp_ticks;        ///< Tick at which this suspect was identified.
    EreportClass primary_class; ///< Which class of events triggered the rule.
    u64 target_id;              ///< Suspect target (DIMM cluster, driver id, etc.).
    u32 contributing_events;    ///< How many ereports rolled up into this suspect.
    EreportSeverity severity;   ///< Engine-assigned severity (may exceed any detector's).
    char description[32];       ///< Null-terminated short label for log output.
};

/// Run the diagnosis engine over the recent ereport window. Called
/// from the heartbeat task every beat. Walks the ereport ring, runs
/// each registered rule, appends Suspect entries to the suspect ring
/// for rules that fire. Returns the number of NEW suspects identified
/// this pass.
///
/// Idempotent within a tick: a rule that fires for target T does NOT
/// re-fire for T again until the contributing ereports have aged out
/// of the correlation window. Implementation: each rule records the
/// `last_suspect_tick_for(target)` and refuses to re-suspect within
/// `kCorrelationWindowTicks` of that mark.
u32 DiagnoseTick();

/// Number of suspects currently in the ring (saturates at
/// kSuspectRingSize when the ring has wrapped). Diagnostic only.
u32 SuspectCount();

/// Walk the suspect ring, newest-first, up to `max` entries.
using SuspectWalkCb = void (*)(const Suspect& s, void* cookie);
void SuspectWalk(u32 max, SuspectWalkCb cb, void* cookie);

/// Boot-time install. Currently a no-op — the engine is data-only
/// and runs from the heartbeat. Kept for the explicit "this
/// subsystem was wired in" call site in boot_bringup.cpp.
void FmaInstall();

/// Self-test. Posts a synthesized sequence of ereports that should
/// trigger each of the three rules, calls `DiagnoseTick`, asserts
/// the right Suspects appear. Prints `[fma] self-test OK (...)`.
/// Panics on mismatch — the engine being silently broken would mean
/// every future fault correlation goes unnoticed.
void FmaSelfTest();

inline constexpr u32 kSuspectRingSize = 64;

/// Rule thresholds. Hand-picked for the v0 skeleton:
///   - ECC: 5+ correctable errors on the same DIMM in a 60 s
///     window crosses from "transient cosmic ray noise" into
///     "this DIMM is degrading."
///   - Driver: 3+ faults from the same driver in 60 s indicates
///     the driver is stuck retrying a permanent failure.
inline constexpr u64 kEccCorrelationThreshold = 5;
inline constexpr u64 kDriverFaultThreshold = 3;

/// 60 s at the 100 Hz scheduler tick rate. Matches the heartbeat's
/// kTimerHz constant; if the tick rate ever changes this needs to
/// move with it.
inline constexpr u64 kCorrelationWindowTicks = 6000;

} // namespace duetos::diag::fma
