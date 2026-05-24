#pragma once

#include "util/types.h"

#include "diag/resmon.h"

/*
 * DuetOS — kernel self-thinking + cross-subsystem introspection.
 *
 * DuetOS already exposes a wealth of per-subsystem counters and
 * dedicated diagnostic primitives (resmon, runtime_checker, the
 * probe ring, the autonomic engine, the fix-journal, the
 * cross-boot diff in `diag::introspect`). Each one answers a
 * single question well. None of them assembles "what is the
 * whole kernel doing right now, and what recent events led to
 * that state" in one place.
 *
 * `selfthink` is that assembly. It owns two artefacts:
 *
 *   1. `SelfPortrait` — a value-type snapshot of every subsystem
 *      surface the kernel can read cheaply. CPU + memory + box
 *      (via `ResmonSnapshot`), scheduler counters, kernel-heap
 *      shape, frame allocator headroom, fault-domain population,
 *      autonomic engine status, fix-journal volume, cross-boot
 *      introspect digest, runtime-checker health totals, and the
 *      probe-ring fire count. Built lock-free, in microseconds,
 *      from any context.
 *
 *   2. `CausalChain` — a 1024-entry lock-free ring of `CausalEntry`
 *      rows describing recent kernel events of interest: probe
 *      fires, autonomic actions, metric anomalies (Layer 2 of
 *      the slice plan), fault-react dispatches, runtime-checker
 *      Heal outcomes. Each row is a single record an operator
 *      can correlate against ps / heap / probe ring output.
 *
 * A `kselfthink` kernel thread wakes on a steady tick cadence,
 * snapshots the portrait, and is the future driver of the Layer
 * 2 / 3 work (autonomic feedback evaluation, baseline tracking,
 * narrative writer, persistence). For Slice A the thread's job
 * is just to keep the most-recent snapshot fresh so shell
 * queries don't pay the cost.
 *
 * Naming note: the verb `introspect` is already taken by
 * `duetos::diag::introspect` (cross-boot fix-journal diff,
 * commit 4b44805). `selfthink` is the live cross-subsystem
 * self-portrait + causal chain — distinct module, distinct
 * shell command, surfaces the existing introspect's stats
 * inside its Health section so the two cooperate rather than
 * compete.
 *
 * Subsystem isolation: every field is sourced through an
 * existing public kernel API. No subsystem state is mutated;
 * no syscall surface is added. Win32 / Linux subsystems never
 * see this code.
 *
 * Context: kernel. Snapshot + chain read are safe from any
 * context. The kthread runs only in task context.
 */

namespace duetos::diag::selfthink
{

/// Causal-chain ring capacity. 1024 × 48 B = 48 KiB of .bss.
/// Roomy enough to survive a heartbeat-window of bursts without
/// wrap; small enough not to balloon the kernel image.
inline constexpr u64 kCausalRingCap = 1024;

enum class CausalKind : u16
{
    None = 0,
    ProbeFire = 1,  // a debug::ProbeId fired (armed-log path)
    AutoAction = 2, // env::AutonomicApply ran a real effect
    Anomaly = 3,    // Layer 2 — metric outside baseline window
    FaultReact = 4, // diag::FaultReactDispatch handled a fault
    Heal = 5,       // runtime_checker Heal-class issue resolved
    Annotation = 6, // operator-injected note from the shell
};

/// One row in the causal chain. Mirrors the shape of the probe
/// ring but adds a subsystem tag for cross-source grep.
struct CausalEntry
{
    u64 tick;       // TickCount() at append time
    u32 cpu_id;     // arch::SmpCpuId at append time
    u16 kind;       // CausalKind
    u16 source_id;  // probe_id / action id / metric id
    u64 value;      // probe value / packed delta / anomaly score
    u64 caller_rip; // origin RIP (ProbeFire path) or 0
    char tag[16];   // null-terminated subsystem tag
};
static_assert(sizeof(CausalEntry) == 48, "CausalEntry packing changed");

/// Cross-subsystem self-portrait. Embeds `ResmonSnapshot` for
/// the CPU / memory / box surface so the arithmetic stays
/// identical to what `resmon`, `top`, and `free` already print.
struct SelfPortrait
{
    u64 tick_taken; // TickCount() at snapshot time

    ResmonSnapshot resmon;

    // Scheduler — extra surface beyond what resmon copies.
    u64 sched_total_ticks;
    u64 sched_idle_ticks;
    u64 sched_tasks_reaped;

    // Memory — extra surface beyond what resmon copies.
    u64 mm_frames_total;
    u64 mm_frames_free;
    u64 mm_frames_peak_used;
    u64 mm_heap_alloc_count;
    u64 mm_heap_free_count;
    u64 mm_heap_free_chunks;

    // Diagnostics: runtime-checker health.
    u64 health_scans_run;
    u64 health_issues_total;
    u64 health_last_scan_issues;
    u32 health_last_issue;  // HealthIssue enum value
    u32 health_baseline_ok; // 1 once baseline captured

    // Diagnostics: fix journal volume + cross-boot introspect.
    u64 fix_records_total;
    u64 fix_records_unique;
    u64 fix_records_dropped;
    u32 introspect_new; // duetos::diag::introspect digest
    u32 introspect_persistent;
    u32 introspect_resolved;

    // Probe ring — total armed fires since boot.
    u64 probe_total_fires;

    // Autonomic engine — current report.
    u64 auto_ticks;
    u64 auto_actions_fired;
    u32 auto_last_action; // env::AutoAction enum value
    u32 auto_last_rule;   // env::AutoRule enum value

    // Fault domains.
    u32 fault_domains_count;

    u32 reserved;
};

/// Build a snapshot from the current kernel state. Lock-free,
/// no allocation, returns by value. Cost target: under 100 µs.
/// Safe from any context.
SelfPortrait SelfPortraitSnapshot();

/// Append a row to the causal chain. Wrap-safe. Lock-free
/// (single u64 fetch_add on the head index). `tag` is copied
/// up to 15 chars + NUL; pass a short string literal. Safe
/// from any context.
void CausalRecord(CausalKind kind, u16 source_id, u64 value, u64 caller_rip, const char* tag);

/// Walk the chain from newest to oldest, invoking `cb` for each
/// populated entry. Stops early when `cb` returns false. Returns
/// the number of entries visited (<= kCausalRingCap). Safe from
/// any context (no locks, no allocations).
u32 CausalRingWalk(bool (*cb)(const CausalEntry& e, void* ctx), void* ctx);

/// Total causal events ever recorded (may exceed ring capacity).
u64 CausalRingTotal();

/// Most-recent snapshot kept by the kselfthink thread, for
/// cheap shell access without rebuilding the portrait on every
/// query. Zero-initialised until the first kthread tick lands.
const SelfPortrait& SelfthinkLatestPortrait();

/// Spawn the `kselfthink` kernel thread. Exactly once. Panics
/// on a second call. Wakes every `DUETOS_SELFTHINK_TICKS` ticks
/// (default 100 = 1 s at the 100 Hz scheduler tick) and refreshes
/// the latest portrait.
void StartSelfthinkThread();

/// Boot self-test. Builds a snapshot, asserts every field is in
/// a sensible range, exercises a CausalRecord round-trip. Emits
/// `[selfthink] selftest pass` on success; fires
/// `kSelfthinkSelftestFail` on a failed sub-check.
void SelfthinkSelfTest();

} // namespace duetos::diag::selfthink
