#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — fix journal (observe-and-record self-healing).
 *
 * Records structured "this gap was hit at this site" entries that a
 * future reviewer (typically a Claude session attached to a live
 * boot) can list, inspect, and convert into a real source fix.
 *
 * What this module is:
 *   - A bounded in-RAM ring of `FixRecord` (1024 entries, fixed
 *     128-byte stride). Source of truth.
 *   - Dedup by (detector, source_pin) — a gap hit 1000 times is one
 *     record with `repeat_count=1000`, not 1000 records.
 *   - Sinks: tmpfs mirror (Tier 1, this slice), FAT32 file (Tier 2,
 *     follow-up slice), NVMe panic-reserved LBAs (Tier 3, follow-up).
 *
 * What this module is NOT:
 *   - It does NOT mutate kernel `.text`, dispatch tables, or
 *     function-pointer state at runtime. Design-Decision #016
 *     (`wiki/reference/Design-Decisions.md`) explicitly forbids
 *     silent self-healing — "sophisticated rootkits actively
 *     exploit self-healing code." Every record IS the audit event
 *     #016 demands.
 *   - It does NOT decide whether to retry / restart / kill — that's
 *     the job of `diag::FaultReactDispatch`. The journal is a
 *     passive observer.
 *
 * Workflow:
 *   1. Detector site (e.g. Win32 unmapped thunk, unknown syscall,
 *      a `// STUB:` marker, an extable fixup) calls
 *      `FixJournalRecord(detector, source_pin, hint, ctx_a, ctx_b)`.
 *   2. The journal interns the record (dedup) and fires the
 *      `kFixJournaled` probe so an armed run breaks in GDB.
 *   3. Heartbeat-side flush mirrors new records to tmpfs and (when
 *      installed) FAT32.
 *   4. The reviewer uses `dfix list / show / mark-done` (kernel
 *      shell) or reads `/proc/fixjournal` to triage and convert
 *      records into real source fixes in the tree.
 *
 * Context: kernel. Recorders run in process or IRQ context as long
 * as the spinlock can be acquired (no allocation, no logging from
 * inside the critical section). Trap-context recorders should use
 * `FixJournalRecordFromTrap` (deferred slot, drained later).
 */

namespace duetos::diag
{

/// What kind of gap was observed. Stable IDs — appended-to, never
/// renumbered, since on-disk records use these as integers.
enum class FixDetector : u8
{
    None = 0,           // sentinel; never appears in a real record
    StubMarker = 1,     // `// STUB:` site reached; behaviour known incomplete
    GapMarker = 2,      // `// GAP:` site reached; happy path ok, edge missing
    UnknownSyscall = 3, // syscall.cpp default arm fired with no GapFill match
    UnmappedThunk = 4,  // Win32ThunksLookupCatchAll hit (kOffMissLogger)
    SoftFaultRecov = 5, // RetryWithBackoff success after >=1 retry, page-fault
                        // fixup recovered, OOM-after-evict succeeded, etc.
    LoaderReject = 6,   // PE/ELF loader rejected an image
    CapDenial = 7,      // SyscallGate cap-set check denied a syscall.
                        // ctx_a = syscall_number, ctx_b = proc_id,
                        // source_pin = `cap.<MissingCap>`. Persists the
                        // cap-audit ring's signal across boots so a
                        // recurring deny pattern survives FAT32/NVMe
                        // rotation. Dedups per (cap, syscall) pair —
                        // a deny storm is one record with repeat=N.
};

/// Stable human label. Always returns a non-null pointer into .rodata.
const char* FixDetectorName(FixDetector d);

/// On-disk and in-RAM record. Fixed 128-byte stride so tmpfs
/// accounting (16 records ~= 2 KiB) and the FAT32 / NVMe sinks
/// can append without per-record framing. Field layout is part of
/// the on-disk format: do NOT reorder, only append.
struct FixRecord
{
    u32 magic;           // 'FIXR' = 0x52584946
    u32 seq;             // monotonic; ring assigns at intern time
    u64 ts_ns;           // duetos::time::MonotonicNs() at first hit
    u64 caller_rip;      // __builtin_return_address(0) of recorder
    u64 ctx_a;           // detector-specific (syscall #, name hash)
    u64 ctx_b;           // detector-specific (DLL hash, address)
    u32 repeat_count;    // >=1; same (detector, source_pin) dedups here
    u16 severity;        // FaultSeverity for soft-faults; 0 otherwise
    u8 detector;         // FixDetector (cast)
    u8 flags;            // bit0 = audited (mark-done set), bit1..7 = reserved
    char source_pin[40]; // "kernel/mm/dma.cpp:122" or "ntdll!NtCreateFile"
    char hint[40];       // one-line "what to implement" prompt
};
static_assert(sizeof(FixRecord) == 128, "FixRecord stride is part of the on-disk format");

constexpr u32 kFixRecordMagic = 0x52584946; // 'FIXR' little-endian
constexpr u8 kFixFlagAudited = 1u << 0;

/// Capacity of the in-RAM ring. Wrap is recorded in a sentinel
/// record so the reviewer knows entries were dropped.
constexpr u64 kFixJournalCapacity = 1024;

/// Lifetime counters since boot. Diagnostics only.
struct FixJournalStats
{
    u64 records_recorded; // total successful intern calls (including dedup re-hits)
    u64 records_unique;   // distinct (detector, source_pin) pairs interned
    u64 records_dropped;  // ring overflow drops since boot (>=1 means wrap)
    u64 dedup_hits;       // intern calls that bumped repeat_count instead of allocating
    u64 trap_deferred;    // FixJournalRecordFromTrap calls awaiting drain
};

/// One-time init. Zeroes the ring, resets stats, sets the boot
/// epoch. Idempotent. Must run once before any recorder fires.
void FixJournalInit();

/// Record a gap. Safe from process and IRQ context. Not safe from
/// trap / NMI / soft-IRQ context — use `FixJournalRecordFromTrap`
/// there. `source_pin` and `hint` are copied into the record (up
/// to 39 chars + NUL); pass nullptr for `hint` if none.
///
/// `source_pin` may be nullptr or empty — in that case the record
/// auto-derives a pin of the form `func+0xOFF` from the caller's
/// rip via the embedded symbol table. Function-relative offsets
/// are KASLR-stable so dedup remains stable across boots. Auto-
/// derivation fails (returns `Err{InvalidArgument}`) only if the
/// caller's rip lies outside any known symbol — typically a sign
/// the recorder is in a generated stub or a JIT region.
///
/// Returns `Ok` on success, `Err{OutOfMemory}` if the ring is full
/// and the record is a brand-new (detector, source_pin) — in that
/// case the drop is recorded in stats. Existing records always
/// succeed (dedup just bumps the counter).
::duetos::core::Result<void> FixJournalRecord(FixDetector detector, const char* source_pin, const char* hint, u64 ctx_a,
                                              u64 ctx_b);

/// Same as above but with a severity hint (used by SoftFaultRecov
/// records to carry the FaultSeverity). `severity` is opaque to
/// the journal — stored verbatim, displayed by `dfix show`.
::duetos::core::Result<void> FixJournalRecordSev(FixDetector detector, const char* source_pin, const char* hint,
                                                 u64 ctx_a, u64 ctx_b, u16 severity);

/// Trap-handler-safe deferred record. Stores the (detector, ctx_a,
/// rip) triple into a small per-CPU pending slot. Drained on the
/// next `FixJournalDrainTrapPending()` call from the heartbeat
/// thread. Safe from any context that can do plain stores.
void FixJournalRecordFromTrap(FixDetector detector, u64 ctx_a, u64 caller_rip);

/// Heartbeat-side drain. Walks the deferred slot(s) and converts
/// them to full records via the normal `FixJournalRecord` path.
/// Cheap when no slots are valid.
void FixJournalDrainTrapPending();

/// Snapshot up to `cap` records starting at the most recent and
/// going back. Returns the number copied. The shell and the
/// `/proc/fixjournal` view use this; nobody else should.
u64 FixJournalSnapshot(FixRecord* out, u64 cap);

/// Lock-free snapshot for panic / trap context. Skips the
/// `g_lock` acquire so a hard crash that interrupted a recorder
/// mid-update doesn't deadlock. Tradeoff: a record being written
/// concurrently (vanishingly rare in panic — IRQs disabled, other
/// CPUs NMI-halted) may be read in a torn state. Readers of the
/// resulting on-disk file MUST validate `magic == kFixRecordMagic`
/// before trusting record contents; torn records get filtered.
u64 FixJournalSnapshotPanicSafe(FixRecord* out, u64 cap);

/// Set the audited bit on a record by sequence number. Returns
/// `Err{NotFound}` if the seq isn't in the ring (either never
/// existed or was overwritten by wrap). Used by `dfix mark-done`.
::duetos::core::Result<void> FixJournalMarkAudited(u32 seq);

/// Live counter view. Cheap; does not lock.
FixJournalStats FixJournalGetStats();

/// Emit a single structured `[smoke] fix_journal_summary` log line
/// summarising the current ring contents: total records, unique
/// pins, audited count, and a per-detector breakdown. Designed to
/// be called at smoke-profile completion so a CI grep can detect
/// regressions ("yesterday's run had 3 unmapped_thunk records,
/// today's has 5 → investigate") without parsing the FAT32
/// KERNEL.FIX file. Cheap (single ring walk under g_lock) so the
/// non-smoke boot path can call it too if useful.
void FixJournalEmitBootSummary();

/// Boot self-test. Synthesizes one record per detector kind,
/// asserts the unique count rose by exactly the number injected,
/// asserts a known dedup-hit increments repeat_count instead of
/// adding a new record, asserts mark-done sets the flag bit.
/// Prints `[smoke] fix_journal=ok records=<n>` on pass. Panics
/// on mismatch.
void FixJournalSelfTest();

} // namespace duetos::diag

// ---------------------------------------------------------------------------
// Marker macros — drop these on the line below a `// STUB:` or `// GAP:`
// comment to make the marker observable. No-op when DUETOS_FIX_JOURNAL_OFF
// is defined. The strings are baked into .rodata, so the per-call cost is
// one immediate-arg function call.
// ---------------------------------------------------------------------------
#if defined(DUETOS_FIX_JOURNAL_OFF)
#define FIX_NOTE_STUB(source_pin, hint) ((void)0)
#define FIX_NOTE_GAP(source_pin, hint) ((void)0)
#else
#define FIX_NOTE_STUB(source_pin, hint)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::StubMarker, (source_pin), (hint), 0, 0);         \
    } while (0)
#define FIX_NOTE_GAP(source_pin, hint)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::GapMarker, (source_pin), (hint), 0, 0);          \
    } while (0)
#endif
