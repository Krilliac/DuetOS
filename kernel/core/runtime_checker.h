#pragma once

#include "types.h"

/*
 * CustomOS — Runtime invariant checker, v0.
 *
 * Proactive detection of silent corruption / drift in kernel
 * state. The checker runs a fixed battery of invariant tests
 * that don't require the code-under-test to have any explicit
 * logging or self-check. Each test is O(1) or O(small N); the
 * whole scan completes in microseconds so it can run on every
 * heartbeat tick without meaningful overhead.
 *
 * What this catches that normal panic / trap handling DOESN'T:
 *
 *   * Heap metadata corruption before a later KMalloc/KFree
 *     trips a panic (usually on the WRONG thread, far from the
 *     buggy writer).
 *   * Frame allocator bitmap drift — a double-free, underflowed
 *     refcount, or invariant-breaking race.
 *   * Scheduler runqueue inconsistency — more exited than created,
 *     impossible task counts, etc.
 *   * Silent flip of a security control register bit (SMEP,
 *     SMAP, NXE, WP) — the CPU will NOT panic when these clear,
 *     it will just stop enforcing protection. Catching them via
 *     periodic scan is the only way.
 *   * `__stack_chk_guard` drifting to zero (unlikely but the
 *     cost of checking is one load).
 *   * Kernel-stack overflow in any task — a sentinel at the
 *     bottom of each task's stack is compared each scan.
 *
 * Policy: a finding is logged as Warn by default. The guard
 * subsystem can be configured to escalate — e.g. flip into a
 * safe mode on a control-register drift, or panic on a second
 * consecutive heap-integrity failure. Today the checker only
 * logs + counts; the escalation hooks are a follow-up.
 *
 * Scope limits (v0):
 *   - No cross-task checks — each scan is single-threaded, sees
 *     a consistent snapshot of global state via the existing
 *     StatsRead accessors. Per-task stack checks iterate the
 *     runqueue under its normal spinlock.
 *   - No performance counter check — would need baseline +
 *     rate; skipped for v0.
 *   - No IOMMU / page-table walk — future slice.
 *
 * Context: kernel. Thread-safe (uses StatsRead accessors). Do
 * NOT call from IRQ context; the runqueue walk takes a
 * spinlock.
 */

namespace customos::core
{

enum class HealthIssue : u32
{
    None = 0,

    // Heap
    HeapPoolMismatch,      // used + free + overhead != pool
    HeapUnderflow,         // free_count > alloc_count
    HeapFreelistEmpty,     // free_chunk_count == 0 but used < pool
    HeapFragmentationHigh, // free_chunk_count > cap (fragmentation creep)

    // Frames
    FramesOverflow,     // free > total
    FramesAllAllocated, // free == 0 (may be a leak)

    // Scheduler
    SchedExitedMoreThanCreated,
    SchedReapedMoreThanExited,
    SchedLiveUnreasonable,  // tasks_live > cap
    SchedNoContextSwitches, // timer not firing after N uptime

    // Control registers
    Cr0WpCleared,
    Cr4SmepCleared,
    Cr4SmapCleared,
    EferNxeCleared,

    // Canary
    StackCanaryZero,

    // Per-task kernel stack overflow (at least one task's bottom
    // sentinel differs from kStackCanary). Each affected task is
    // logged separately by the sched walker; this counter just
    // surfaces the condition in the health report.
    TaskStackOverflow,

    // IDT descriptor table has been modified since baseline —
    // no legitimate subsystem should touch it after boot. A
    // non-matching hash is a strong "something scribbled on the
    // IDT" signal (rootkit handler swap, stray write, etc.).
    IdtModified,

    // GDT / TSS IST slot hash changed since baseline. RSP0 is
    // deliberately excluded from the hash — the scheduler
    // legitimately rewrites it on every user-mode task switch.
    GdtModified,

    // Kernel .text section spot-check hash changed since
    // baseline — should be impossible under W^X (text pages are
    // RX, not writable). Firing this means W^X has silently
    // been bypassed OR a direct-map alias was used to write.
    KernelTextModified,

    // Saved rsp of a task's frame is outside [stack_base,
    // stack_base + stack_size). Either an earlier push walked
    // past the bottom, or a wild-pointer store overwrote the
    // task's saved rsp — either way the next resume would
    // triple-fault.
    TaskRspOutOfRange,

    // IRQ nesting depth exceeded the allowed ceiling. Normal
    // nesting is 1 (handler) with an occasional 2 (NMI inside
    // IRQ). Anything > 4 indicates a runaway re-entry — a
    // handler that didn't mask properly before calling something
    // that can interrupt again, or an IRQ storm flooding the
    // CPU faster than handlers can drain.
    IrqNestingExcessive,

    // A monotonically-increasing counter went BACKWARDS between
    // consecutive scans. The only way a u64 "goes backwards" in
    // practice is arithmetic underflow in a decrement that the
    // writer didn't bounds-check, or memory corruption.
    // Reporting the counter ID with the finding lets the
    // operator identify which subsystem regressed.
    CounterWentBackwards,

    // HPET or scheduler-tick clock stopped advancing across two
    // consecutive scans despite the heartbeat firing. Means the
    // timer IRQ path is broken or the HPET MMIO window is
    // silently failing.
    ClockStalled,

    // Count sentinel
    Count,
};

const char* HealthIssueName(HealthIssue i);

struct HealthReport
{
    u64 scans_run;
    u64 issues_found_total; // cumulative since boot
    u64 last_scan_issues;   // how many tests failed in the LAST scan
    u64 per_issue_count[u32(HealthIssue::Count)];
    HealthIssue last_issue; // most recent failing check
    u64 baseline_captured;  // 1 once RuntimeCheckerInit has run
};

/// Capture the boot-time baseline for checks that need one
/// (control-register expected bits, stack-canary seed visibility).
/// Safe single-init.
void RuntimeCheckerInit();

/// Run the full battery of checks. Logs each failure via klog at
/// Warn level (subsystem = "health"). Returns the number of
/// failures observed in THIS scan.
u64 RuntimeCheckerScan();

/// Hook for the heartbeat thread — runs a scan and bumps counters.
/// Exactly equivalent to calling `RuntimeCheckerScan()` and
/// ignoring the return value.
void RuntimeCheckerTick();

/// Current stats snapshot. Returned by const-reference to avoid
/// copying the 128-byte per-issue array on every call (kernel
/// has no memcpy; compiler-inserted struct copies would need
/// one for arrays this size).
const HealthReport& RuntimeCheckerStatusRead();

} // namespace customos::core
