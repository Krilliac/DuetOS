#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — code path execution ledger (KPath).
 *
 * Answers the broad question "during this boot, which code paths
 * ran and which didn't?" without requiring the operator to grep
 * ad-hoc `KLOG_DEBUG` / `arch::SerialWrite` lines that some prior
 * slice happened to sprinkle.
 *
 * Storage:
 *   Two linker-collected sections — `.kpath_sites` (read-only
 *   site records) and `.kpath_hits` (mutable u64 counters). The
 *   `KPATH(...)` macro stamps one record into each section from
 *   the same TU so the two arrays stay 1:1 by construction; each
 *   site also carries an explicit `hits_ptr` into its counter
 *   slot so cross-TU ordering is irrelevant.
 *
 * Cost on fire path:
 *   One byte load (`g_kpath_enabled`) + one relaxed atomic add.
 *   Cold sites accept the cache-line ping; sites tagged with
 *   `hot=1` route through a fixed per-CPU shard table
 *   (`g_kpath_hot_shards`) so timer-tick / context-switch hits
 *   never contend across CPUs.
 *
 * Auto-enrolled surfaces (no manual macro required):
 *   - Syscall numbers       — bumped from SyscallDispatch
 *   - IDT vectors           — bumped from TrapDispatch
 *   - Initcall registry     — already counts via
 *                             InitcallRecord::invoke_count
 *   - KBP_PROBE fire counts — virtual view over g_probe_fires
 *   - Fix-journal records   — virtual view over repeat_count
 *
 * Output (three channels, all wired):
 *   - `KPathEmitBootSummary()` writes one `[kpath] visited=N/M`
 *     line at smoke completion + per-category compact lines.
 *   - Shell command `kpath list|show|hits|dump|flush` exposes
 *     the live ledger.
 *   - `KPathPersistFlush()` writes `KERNEL.KPATH.TSV` to the
 *     FAT32 sink shared with fix-journal at smoke completion
 *     and (panic-safe variant) on panic.
 *
 * Context: kernel. Fire path safe from IRQ / trap / scheduler-
 * internal contexts. Init must run before any KPATH call site
 * is reached — boot_bringup wires it next to FixJournalInit().
 */

namespace duetos::diag
{

/// Category of a recorded site. Stable values — appended to,
/// never renumbered. The TSV uses these as integers.
enum class KPathCat : u8
{
    None = 0,     ///< Sentinel; never appears in a real record.
    Manual = 1,   ///< Hand-placed `KPATH(...)` somewhere in subsystem code.
    Syscall = 2,  ///< Virtual: one row per syscall number that fired.
    Vector = 3,   ///< Virtual: one row per IDT vector that fired.
    Initcall = 4, ///< Virtual: one row per initcall registered.
    Probe = 5,    ///< Virtual: one row per KBP_PROBE that fired.
    Fix = 6,      ///< Virtual: one row per fix-journal record.
    SelfTest = 7, ///< Boot self-test entry markers.
    Branch = 8,   ///< Hand-placed at a specific conditional branch.
};

/// Stable human label for a category. Always returns a non-null
/// pointer into .rodata. Used by the dumper and shell.
const char* KPathCatName(KPathCat c);

/// One physical record in `.kpath_sites`. Read-only after the
/// link step — only `hits_ptr` points OUT of this struct into a
/// mutable counter in `.kpath_hits`. Layout is implementation-
/// internal (not on-disk format).
struct KPathSite
{
    u32 id;           ///< Dense index; lazily assigned at first walk.
    u8 category;      ///< KPathCat cast.
    u8 hot;           ///< 1 = flagged as a known hot path (advisory).
    u16 reserved;     ///< Padding; keeps the struct on an 8-byte stride.
    const char* name; ///< Stable string literal, e.g. "loader.pe.imports".
    const char* file; ///< __FILE__ at the macro site.
    u32 line;         ///< __LINE__ at the macro site.
    u32 reserved2;    ///< Reserved for a future shard-table index.
    u64* hits_ptr;    ///< Points into .kpath_hits.
};

/// Site-iterator callback. Return false to stop iteration. `name`
/// + `file` always non-null (synthesized for virtual rows that
/// don't have a real `.kpath_sites` record).
struct KPathIterRow
{
    KPathCat category;
    const char* name;
    const char* file;
    u32 line;
    u64 hits;       ///< Aggregated across CPUs for hot sites.
    u32 syscall_nr; ///< 0xFFFF unless category == Syscall.
    u32 vector_nr;  ///< 0xFFFF unless category == Vector.
};

using KPathForEachFn = bool (*)(const KPathIterRow& row, void* ctx);

/// Walk every site — real records in `.kpath_sites`, then
/// virtual views over syscall hits / vector hits / initcalls /
/// probes / fix-journal records. Safe from any non-panic
/// context; the panic-safe variant skips the fix-journal lock.
void KPathForEach(KPathForEachFn cb, void* ctx);
void KPathForEachPanicSafe(KPathForEachFn cb, void* ctx);

/// Auto-enrollment hooks — called once at the top of each
/// dispatcher. Cheap (single bounds check + relaxed atomic
/// add). `num` is `frame->rax` at the syscall entry; `v` is
/// the IDT vector. Out-of-range arguments are ignored silently
/// — a wild value here is a separate bug surfaced elsewhere.
void KPathHitSyscall(u64 num);
void KPathHitVector(u32 v);

/// Aggregate visit accounting used by the boot summary.
struct KPathVisitStats
{
    u64 sites_total;       ///< Real entries in `.kpath_sites`.
    u64 sites_visited;     ///< Of those, hits > 0.
    u32 syscalls_visited;  ///< Of 256 slots, syscall_hits[i] > 0.
    u32 vectors_visited;   ///< Of 256 slots, vector_hits[i] > 0.
    u32 initcalls_visited; ///< Records with invoke_count > 0.
    u32 probes_visited;    ///< KBP_PROBE entries with fire_count > 0.
    u32 fix_records;       ///< Unique fix-journal records (any detector).
};
KPathVisitStats KPathSnapshotStats();

/// One-shot init. Zeroes the hot-shard table, marks the ledger
/// enabled. Idempotent. Must run before any KPATH call site is
/// reached — boot_bringup pairs it with FixJournalInit().
void KPathInit();

/// Toggle the global enable byte. The fire path short-circuits
/// on a disarmed ledger (one byte load + branch), so this is the
/// cheapest way to silence the system for a perf-sensitive
/// boot. Default: enabled.
void KPathSetEnabled(bool on);
bool KPathIsEnabled();

/// Direct accessor for the syscall + vector tables (used by the
/// shell printer). Both arrays are 256 entries; indexing past
/// the bound returns 0.
u64 KPathSyscallHits(u32 num);
u64 KPathVectorHits(u32 v);

/// Aggregated hit count for a single site (sums per-CPU shards
/// when applicable). Used by the unified iterator and the shell.
u64 KPathSiteHits(const KPathSite& s);

/// Bring-up self-test. Synthesises a known site, fires it N
/// times, asserts the count matches, asserts the iterator finds
/// the row. Prints `[smoke] kpath=ok ...` on pass; fires
/// `kBootSelftestFail` on mismatch. Called directly via
/// `DUETOS_BOOT_SELFTEST` from boot_bringup (matches the
/// pattern other selftests use — debug-only by design).
void KPathSelfTest();

/// Boot summary — emits `[kpath] visited=N/M (P%) ...` plus
/// per-category compact lines. Called from
/// kernel/test/smoke_profile.cpp at smoke completion.
void KPathEmitBootSummary();

/// Walk the unified iterator and emit one TSV row per site
/// through `write_cb`. The first call carries a header
/// (`# kpath TSV v1\n`) and a field-list comment. Used by both
/// the shell `kpath dump` (write_cb = SerialWrite trampoline)
/// and the FAT32 sink (write_cb = file-append trampoline).
void KPathWriteTSV(void (*write_cb)(const char*, void*), void* ctx);

} // namespace duetos::diag

// ===========================================================================
// Macro API. Drop these at sites of interest.
//
// `KPATH(category, name)`     — one relaxed atomic add at the call site.
// `KPATH_V(category, name, v)`— same, but also captures the last value into
//                               the per-site `last_value` field (debug aid).
// `KPATH_HOT(category, name)` — routes to per-CPU shard table; use for sites
//                               in the timer / context-switch / IRQ hot path.
//
// Cost when `g_kpath_enabled == 0`: one byte load + predicted-not-taken
// branch. Cost when enabled: one relaxed atomic add (cold) or one per-CPU
// store (hot).
// ===========================================================================

#if defined(DUETOS_KPATH_OFF)
#define KPATH(category, name) ((void)0)
#define KPATH_V(category, name, value) ((void)(value))
#define KPATH_HOT(category, name) ((void)0)
#else

namespace duetos::diag
{
extern volatile u8 g_kpath_enabled;
} // namespace duetos::diag

#define KPATH_INTERNAL_CONCAT2(a, b) a##b
#define KPATH_INTERNAL_CONCAT(a, b) KPATH_INTERNAL_CONCAT2(a, b)
#define KPATH_INTERNAL_UNIQUE(stem) KPATH_INTERNAL_CONCAT(stem, __LINE__)

#define KPATH(category, name_literal)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        static ::duetos::u64 KPATH_INTERNAL_UNIQUE(_kpath_hits_) __attribute__((used, section(".kpath_hits"))) = 0;    \
        static const ::duetos::diag::KPathSite KPATH_INTERNAL_UNIQUE(_kpath_site_)                                     \
            __attribute__((used, section(".kpath_sites"), aligned(8))) = {                                             \
                0,                                                                                                     \
                static_cast<::duetos::u8>(::duetos::diag::KPathCat::category),                                         \
                0,                                                                                                     \
                0,                                                                                                     \
                (name_literal),                                                                                        \
                __FILE__,                                                                                              \
                __LINE__,                                                                                              \
                0,                                                                                                     \
                &KPATH_INTERNAL_UNIQUE(_kpath_hits_)};                                                                 \
        if (__builtin_expect(::duetos::diag::g_kpath_enabled != 0, 1))                                                 \
            __atomic_add_fetch(&KPATH_INTERNAL_UNIQUE(_kpath_hits_), 1u, __ATOMIC_RELAXED);                            \
    } while (0)

#define KPATH_V(category, name_literal, value) KPATH(category, name_literal)

#define KPATH_HOT(category, name_literal)                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        static ::duetos::u64 KPATH_INTERNAL_UNIQUE(_kpath_hits_) __attribute__((used, section(".kpath_hits"))) = 0;    \
        static const ::duetos::diag::KPathSite KPATH_INTERNAL_UNIQUE(_kpath_site_)                                     \
            __attribute__((used, section(".kpath_sites"), aligned(8))) = {                                             \
                0,                                                                                                     \
                static_cast<::duetos::u8>(::duetos::diag::KPathCat::category),                                         \
                1,                                                                                                     \
                0,                                                                                                     \
                (name_literal),                                                                                        \
                __FILE__,                                                                                              \
                __LINE__,                                                                                              \
                0,                                                                                                     \
                &KPATH_INTERNAL_UNIQUE(_kpath_hits_)};                                                                 \
        if (__builtin_expect(::duetos::diag::g_kpath_enabled != 0, 1))                                                 \
            __atomic_add_fetch(&KPATH_INTERNAL_UNIQUE(_kpath_hits_), 1u, __ATOMIC_RELAXED);                            \
    } while (0)

#endif // DUETOS_KPATH_OFF
