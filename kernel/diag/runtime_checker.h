#pragma once

#include "util/types.h"

/*
 * DuetOS — Runtime invariant checker, v0.
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

namespace duetos::core
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

    // A syscall-related MSR has changed since baseline. The
    // three most rootkit-abused are IA32_LSTAR (SYSCALL entry
    // RIP, Linux syscall target), IA32_STAR (SYSCALL CS/SS),
    // and IA32_SYSENTER_EIP (SYSENTER entry). A modern rootkit
    // hooks syscalls by overwriting these. Each is set once at
    // boot and never legitimately rewritten — any scan-time
    // drift is a confirmed attack or very serious bug.
    SyscallMsrHijacked,

    // IA32_FEATURE_CONTROL lock bit unexpectedly cleared.
    // Firmware sets this bit at boot to prevent late changes
    // to the VMX / SMRR controls it configured. A cleared lock
    // bit indicates either firmware that didn't lock (rare) or
    // a rogue write that's setting up for a VMX-based attack.
    FeatureControlUnlocked,

    // MBR (LBA 0) or GPT header/backup has been modified since
    // baseline. Disk-persistence malware (bootkits, ransomware
    // payload) typically scribbles LBA 0 to install a shim that
    // runs before the OS kernel; catching the drift at runtime
    // means the shim doesn't survive to the next boot.
    BootSectorModified,

    // A single non-idle task consumed >90% of the scan interval's
    // scheduler ticks. Catches kernel-thread busy loops and any
    // user task whose tick budget is large enough to evade the
    // per-task kill path. Logs the offending id + name so the
    // operator can correlate against ps output.
    TaskRunawayCpu,

    // A Machine Check Architecture bank reported a hardware error
    // event (IA32_MCi_STATUS.VAL set). Correctable ECC, uncorrected
    // cache line, memory controller timeout — every one of these
    // lives in MCi_STATUS and never raises #MC on its own. The
    // checker surfaces them, logs the error code + addr, then
    // clears the bank so the next scan sees only new events.
    McaBankFault,

    // An IRQ vector has fired at a rate far above the per-scan
    // threshold for any known legitimate source (timer = 100/s,
    // keyboard/mouse intermittent, NIC RX typically <1000/s).
    // Surfaces runaway handlers, chattering devices, or
    // misconfigured edge/level trigger — all of which burn CPU
    // silently until something catches them.
    IrqStorm,

    // A user process pushed past the burst-window FS write cap
    // (1 s / `kFsWriteWindowByteCapByLevel[0]`). Defends against
    // ransomware-style mass file rewrites by a trusted-but-
    // compromised process. Counted globally; the kill itself is
    // enacted at the syscall site (see `RecordFsWrite` in
    // kernel/proc/process.cpp), so this finding's purpose is
    // operator visibility — every increment represents one
    // ransomware-style burst the kernel actively shut down.
    MassFsWriteRate,

    // A process exceeded the SUSTAINED-window FS write cap
    // (5 min / `kFsWriteWindowByteCapByLevel[1]`). Catches the
    // low-and-slow attacker who reads our open-source threshold
    // constants and paces writes to stay under the burst cap;
    // even at 14 MiB/s sustained the 5-minute budget runs out.
    MassFsWriteRateSustained,

    // A process exceeded the LONG-window FS write cap
    // (1 h / `kFsWriteWindowByteCapByLevel[2]`). Final wall
    // against an attacker pacing under both prior windows —
    // even 700 KiB/s averaged over an hour blows past 2 GiB.
    MassFsWriteRateLong,

    // A process touched (created / wrote-to / unlinked /
    // renamed) a registered canary or suspicious-extension
    // path. No threshold — first touch trips. The kill is
    // enacted at the syscall site (see `CanaryTrip` in
    // kernel/security/canary.cpp); this finding is the
    // operator-visible counter.
    CanaryFileTouched,

    // A process wrote to (or otherwise mutated) an autostart-
    // equivalent path: init scripts, registry "Run" keys,
    // boot config files. Default Advisory mode logs but lets
    // the write through (legitimate installers do this); Deny
    // mode kills the writer via `KillReason::PersistenceDrop`.
    // Either way the counter increments — operators correlate
    // these events against image-load logs to find malware
    // that survived a reboot.
    PersistenceDropDetected,

    // A monitored kernel function-pointer table drifted from its
    // boot-time hash. Real-world parallel: a rootkit overwrites a
    // single slot in `driver_ops` / `bus_ops` / a syscall dispatch
    // shim so calls through that pointer land at the rootkit's
    // hook. The detector hashes registered tables on every scan;
    // a single-byte slot rewrite changes the hash.
    KernelFnTableModified,

    // A saved return address on the current kernel stack pointed
    // outside the kernel `.text` range. Either a stack-smash that
    // overwrote a frame's saved RIP with attacker-controlled data,
    // or a wild-pointer store that scribbled a saved RIP slot. The
    // next return through that frame would either crash or — if
    // the attacker chose a controllable target — divert kernel
    // control flow. Detected by walking the active RBP chain at
    // scan time.
    TaskStackRipCorrupt,

    // A monitored kernel page's page-table-entry attribute bits
    // diverged from baseline (e.g. a `.rodata` page that was
    // baselined NX+RO is now NX-clear or W-set). Real-world
    // parallel: a rootkit flips a page from RX to RWX so it can
    // hot-patch executable bytes without paying the CR0.WP /
    // direct-map costs the simpler `.text` patch attack does.
    // The CR0.WP detector cannot see this — that bit is global,
    // PTE attributes are per-page.
    KernelPteWxFlipped,

    // Count sentinel
    Count,
};

const char* HealthIssueName(HealthIssue i);

// Response policy — what the kernel does when a finding fires.
//
// Heal    : Restore the affected state from a golden baseline
//           the checker captured at init. Log the finding
//           *and* the heal outcome. Safe only for bytes whose
//           legitimate value is known, immutable, and
//           restorable without racing against the hardware
//           (descriptor tables, syscall MSRs, security CR
//           bits). An attacker who trips a Heal-tier finding
//           observes full logging + their corruption rolled
//           back — they don't get a crash oracle + they don't
//           get lingering influence on the kernel either.
//
// Isolate : Kill the offending task / quarantine the offending
//           region; kernel keeps running. Used when the
//           corruption is scoped to one resource (a task's
//           own kernel stack) and the rest of the kernel is
//           unaffected.
//
// LogOnly : Not safely recoverable in either direction; not
//           catastrophic enough to warrant a panic. Scan logs,
//           bumps counters, continues. Operator-facing signal
//           only. Examples: clock drift, counter regression,
//           boot-sector hash drift on a disk we can't roll
//           back from in-kernel.
//
// Panic   : Continued execution would accumulate damage or
//           execute against a structure we fundamentally
//           can't trust (heap bookkeeping, kernel .text).
//           Last resort — reached only when Heal fails or the
//           finding class has no known restoration path.
enum class HealthResponse : u8
{
    Heal = 0,
    Isolate,
    LogOnly,
    Panic,
};

const char* HealthResponseName(HealthResponse r);

/// The response policy for each finding. Consulted inside
/// `Report` after counters + logging are updated.
HealthResponse ResponseFor(HealthIssue issue);

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

/// Note that a process has just crossed an FS write-rate cap.
/// Called from `RecordFsWrite` (kernel/proc/process.cpp) when
/// the per-process window byte count exceeds the cap for the
/// indicated level. `level_index` selects which HealthIssue is
/// bumped:
///   0 -> MassFsWriteRate            (1 s burst window)
///   1 -> MassFsWriteRateSustained   (5 min sustained window)
///   2 -> MassFsWriteRateLong        (1 h long-tail window)
/// Out-of-range indices route to the burst counter as a safe
/// default (no out-of-bounds risk).
///
/// Safe from any context: bumps a counter and writes a log line.
/// Does NOT itself flag the calling task — kill enforcement is
/// the caller's responsibility (see `RecordFsWrite`).
void RuntimeCheckerNoteFsWriteRateExceeded(u32 level_index);

/// Note that a canary path has been touched. Called from
/// `security::CanaryTrip` (kernel/security/canary.cpp) when a
/// matched syscall site detected a forbidden-path access.
/// Bumps the `CanaryFileTouched` HealthIssue counter through
/// the standard `Report` path. Safe from any context.
void RuntimeCheckerNoteCanaryFileTouched();

/// Note that a persistence-equivalent path has been written.
/// Called from `security::PersistenceNote` when a create /
/// unlink / rename hits the autostart registry. Bumps the
/// `PersistenceDropDetected` HealthIssue counter regardless of
/// the persistence detector's mode (Advisory vs. Deny) — the
/// counter is the operator-visible signal; the kill (if any)
/// happens at the syscall site.
void RuntimeCheckerNotePersistenceDrop();

/// Test-only counter bump. Increments the per-issue count +
/// total + last_issue WITHOUT invoking `ResponseFor` — so a
/// Panic-class HealthIssue can be exercised by attack_sim
/// without halting the kernel mid-test. The standard production
/// `Report` path is the right one for everywhere else.
///
/// Marked _ForTest in the name so a code reviewer notices any
/// non-attack-sim caller. Logging stays at Warn level so the
/// boot log still surfaces the event.
void RuntimeCheckerBumpIssueCounter_ForTest(HealthIssue issue);

/// Current stats snapshot. Returned by const-reference to avoid
/// copying the 128-byte per-issue array on every call (kernel
/// has no memcpy; compiler-inserted struct copies would need
/// one for arrays this size).
const HealthReport& RuntimeCheckerStatusRead();

} // namespace duetos::core
