#pragma once

#include "util/types.h"
#include "diag/fix_journal.h"

/// kernel/diag/introspect — fix-journal cross-boot introspection.
///
/// The fix journal records this boot's gaps in the in-RAM ring; the
/// persistence layer flushes them to FAT32 KERNEL.FIX and rotates
/// older snapshots to KERNEL.F0..F3. Until now nothing in the kernel
/// COMPARED the current boot to the prior one — every analysis was
/// offline (tools/build/gen-fix-trend.py).
///
/// This module loads the most recent prior journal (KERNEL.F0) into a
/// fixed-size in-RAM digest right after the persistence install runs,
/// then compares the digest to the current in-RAM ring on demand
/// (`IntrospectComputeAndLog`, the `dintro` shell command). The
/// classification mirrors gen-fix-trend.py:
///
///   NEW         — in current ring, NOT in prior digest
///   PERSISTENT  — in BOTH current ring and prior digest
///   RESOLVED    — in prior digest, NOT in current ring
///
/// Storage budget: kPriorDigestCap × (u8 detector + char[40] pin +
/// u32 repeat) ≈ 64 × 45 = ~3 KiB of .bss. Plenty for a typical boot
/// (~25 records); overflow is recorded as a counter so a future bump
/// is easy to size.
///
/// Design discipline: this is OBSERVATIONAL only. Per
/// Design-Decision #016 the kernel never auto-applies. The
/// introspector emits a structured line + populates a snapshot
/// readable by `dintro`; humans (or a Claude session) read it and
/// decide what to do.

namespace duetos::diag::introspect
{

/// Max prior-boot records the digest can hold. A typical boot
/// produces 20-30 unique records; 64 leaves headroom for the
/// rotation siblings to grow before a manual bump is needed.
inline constexpr u64 kPriorDigestCap = 64;

/// One row in the prior-boot digest. Mirrors the on-disk
/// `FixRecord` field shape but only the bits needed for diff
/// classification.
struct PriorEntry
{
    char source_pin[40]; // verbatim copy from the on-disk record
    u32 repeat;          // prior boot's final repeat count
    u8 detector;         // FixDetector enum value
    u8 reserved[3];
};

/// Classification kind used by IntrospectStats and the dintro shell.
enum class DeltaKind : u8
{
    Unknown = 0,
    New = 1,        // in current ring, not in prior digest
    Persistent = 2, // in both
    Resolved = 3,   // in prior digest, not in current ring
};

/// Snapshot row produced by IntrospectSnapshot — pairs a prior entry
/// (when present) with the current ring's repeat (when present).
struct DeltaEntry
{
    DeltaKind kind;
    u8 detector;
    u8 reserved[2];
    u32 cur_repeat;  // current ring's repeat; 0 for Resolved rows
    u32 prev_repeat; // prior digest's repeat; 0 for New rows
    u32 reserved2;
    char source_pin[40];
};

/// Aggregate counts emitted by IntrospectComputeAndLog and exposed
/// to dintro stats.
struct IntrospectStats
{
    u32 prior_loaded;  // records read into the digest from KERNEL.F0
    u32 prior_dropped; // prior records that didn't fit in the digest
    u32 current_total; // records in the current ring at compute time
    u32 new_count;     // DeltaKind::New
    u32 persistent;    // DeltaKind::Persistent
    u32 resolved;      // DeltaKind::Resolved
    u32 prior_present; // true after LoadPriorDigest succeeded
    u32 last_computed; // monotonic count of ComputeAndLog calls
};

/// Read KERNEL.F0 from the active FAT32 volume into the in-RAM
/// digest. Call once, right after `FixJournalPersistInstall` (the
/// rotation it performs is what makes KERNEL.F0 point at the prior
/// boot rather than the half-written current snapshot). Subsequent
/// calls are no-ops; the digest is owned by the first successful
/// load. Safe to call before any FAT32 volume is mounted — surfaces
/// as `prior_present=0`.
void LoadPriorDigest();

/// Re-scan the current in-RAM ring, diff against the prior digest,
/// log a `[introspect] new=N persistent=P resolved=R` structured
/// line via klog, and update the stats. Idempotent and cheap (linear
/// scan of two small arrays).
void IntrospectComputeAndLog();

/// Read-only stats accessor; populated by ComputeAndLog. Safe in any
/// context.
IntrospectStats GetStats();

/// Materialise the per-row delta into `out` (capacity `cap`). Returns
/// the number of rows written (<= cap). Rows appear in classification
/// order: New, Persistent, Resolved.
u64 Snapshot(DeltaEntry* out, u64 cap);

/// Boot self-test. Validates the load → compute → snapshot pipeline
/// against a controlled in-memory FixJournal state. Emits one
/// `[smoke] introspect=ok new=N persistent=P resolved=R` line on
/// pass; fires `kBootSelftestFail` with a sub-check on fail.
void IntrospectSelfTest();

} // namespace duetos::diag::introspect
