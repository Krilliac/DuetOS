#pragma once

#include "util/types.h"

/*
 * DuetOS — Fault Management Architecture (FMA) ereport schema, v0.
 *
 * WHAT
 *   A typed event ring for structured fault reports. Detectors
 *   (driver-fault, soft-lockup, hung-task, runtime-checker integrity
 *   findings, future ECC/MCA hardware paths) post an `Ereport` per
 *   observed failure. The diagnosis engine (see diagnose.h) walks
 *   the ring every heartbeat and rolls correlated events into
 *   `Suspect` records.
 *
 * WHY NEXT TO fault_react?
 *   `diag::FaultReactDispatch` is REACTIVE — one fault arrives, one
 *   reaction is chosen + executed. It does no correlation across
 *   events or across time. FMA is PREDICTIVE — it consumes the same
 *   evidence (plus a few new categories like ECC and MCA) AND looks
 *   for patterns: "the same DIMM threw 5 SBE errors in 60 seconds,
 *   retire those pages." The two surfaces are complementary; both
 *   read from the detector layer, but they answer different
 *   questions.
 *
 * SCOPE FOR v0 (SKELETON)
 *   - Single global ring of `kEreportRingSize` (256) entries, fixed
 *     `.bss`. Wrap-around: head bumps monotonically; head %
 *     ring_size is the slot. When head overruns tail, the oldest
 *     entry is silently dropped (events_dropped ticks).
 *   - No per-CPU rings (per-CPU is a follow-up — the v0 hot post
 *     path takes one atomic add).
 *   - Three diagnosis rules (see diagnose.h). No full eft language.
 *   - No actual remediation — suspects are recorded as an audit
 *     trail. Future slices wire page-retire / driver-restart on
 *     top.
 *
 * Context: kernel. `EreportPost` is safe from any context EXCEPT
 * NMI (one __atomic_add_fetch on the head + a store of fixed-size
 * fields into the slot — no locks, no allocation). NMI-safe needs
 * a different ring shape; deferred.
 */

namespace duetos::diag::fma
{

/// FMA event class. Mirrors illumos's ereport.* class hierarchy
/// but flatter — we're not trying to be schema-compatible. Numeric
/// values are stable so a later slice can persist event logs.
enum class EreportClass : u16
{
    EccCorrected = 1,     // ECC single-bit error, corrected by hardware.
    EccUncorrectable = 2, // ECC multi-bit error, not corrected.
    DimmFailure = 3,      // Memory controller reports module dead.
    CpuMca = 10,          // CPU MCA bank event (Machine Check).
    CpuThermal = 11,      // Thermal threshold crossed.
    DriverFault = 20,     // Mirrors core::DriverFault — driver self-report.
    DriverTimeout = 21,   // Driver gave up after retry-with-backoff.
    StorageRetry = 30,    // I/O retried but eventually succeeded.
    StorageError = 31,    // I/O permanently failed.
    NetworkDrop = 40,     // Network packet dropped (NIC / stack).
    KernelIntegrity = 50, // text / IDT / GDT / MSR / PTE drift.
    SoftLockup = 60,      // CPU pinned in a non-progressing loop.
    HungTask = 61,        // Task stuck Blocked past the hung-task threshold.
    Unknown = 0xFFFF,
};

/// Severity from the detector. Advisory only — the diagnosis
/// engine applies its own weight based on class + correlation.
enum class EreportSeverity : u8
{
    Informational = 0,
    Recoverable,
    Degraded,
    Critical,
};

/// One ereport. Fixed-size for ring storage. The (class, target_id)
/// pair is the correlation key:
///   - ECC events       : target_id = DIMM cluster id (physical address >> N).
///   - Driver faults    : target_id = driver_id / fault-domain id.
///   - MCA banks        : target_id = bank number.
///   - SoftLockup/Hung  : target_id = task id.
///   - KernelIntegrity  : target_id = HealthIssue enum value.
struct Ereport
{
    u64 timestamp_ticks;      ///< sched::SchedNowTicks() at post time.
    EreportClass cls;         ///< Event class (correlation key half 1).
    EreportSeverity severity; ///< Detector's advisory severity.
    u16 _pad0;                ///< Layout padding; keeps target_id 8-aligned.
    u32 source_cpu;           ///< Which CPU detected the event.
    u64 target_id;            ///< Class-specific id (correlation key half 2).
    u64 aux0;                 ///< Class-specific payload (CR2, MCA status, count).
    u64 aux1;                 ///< Class-specific payload (RIP, addr, flags).
    char detector[16];        ///< Null-terminated short label ("drv.nvme.0").
};

/// Submit an ereport. Cheap — one atomic head bump + a slot store.
/// Safe from any context except NMI.
///
/// `detector` is copied into the slot (capped at 15 chars + NUL);
/// callers can pass stack-local strings safely.
void EreportPost(EreportClass cls, EreportSeverity sev, u64 target_id, u64 aux0, u64 aux1, const char* detector);

/// Lifetime totals since boot.
struct EreportStats
{
    u64 events_total;        ///< Total `EreportPost` calls.
    u64 events_dropped;      ///< Ring overruns (newest-overwrites-oldest semantics).
    u64 diagnoses_total;     ///< `DiagnoseTick` invocations.
    u64 suspects_identified; ///< Suspects appended across all diagnoses.
};
EreportStats EreportStatsRead();

/// Walker. Calls `cb` once per ring entry, NEWEST-first. Limited
/// to the last `max` entries. Safe for the diagnosis engine and
/// for shell readers; `cb` MUST NOT call `EreportPost` (would
/// race the head bump).
using EreportWalkCb = void (*)(const Ereport& ev, void* cookie);
void EreportWalk(u32 max, EreportWalkCb cb, void* cookie);

/// Ring size — fixed at boot. 256 entries × ~56 B = ~14 KiB BSS.
/// At a realistic event rate (a few per heartbeat under healthy
/// load, dozens per heartbeat during a fault storm) the 60 s
/// correlation window covers ~6000 heartbeats; even a fault storm
/// shouldn't overrun 256 entries in 60 s. If it does, the diagnosis
/// engine still sees the most recent 256, which is the most
/// actionable subset.
inline constexpr u32 kEreportRingSize = 256;

} // namespace duetos::diag::fma
