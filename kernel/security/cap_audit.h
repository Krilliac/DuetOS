#pragma once

#include "proc/process.h"
#include "util/build_config.h"
#include "util/types.h"

/*
 * DuetOS — capability-gate audit hook.
 *
 * Sits one layer below `SyscallGate` (kernel/syscall/cap_gate.cpp).
 * Every cap-gated syscall passes through `CapAuditTrace(...)` after
 * the cap-set check completes; the audit decides — based on the
 * compile-time `kCapAuditMode` knob — whether to emit a trace line.
 *
 * The audit is INDEPENDENT of the cap-gate decision itself. The gate
 * always runs (a release image cannot bypass cap checks). What the
 * audit controls is the OBSERVABILITY of those checks: does the
 * release operator see a trace per call (Full), per Nth call
 * (Sample), or never (Off)?
 *
 * Audit modes — see build_config.h:
 *   Off    — `CapAuditTrace` returns immediately. The TU still
 *            compiles the call site (one near-jump) so a flip from
 *            Off → Sample at runtime would be possible if a future
 *            slice exposes it; today the mode is constexpr-folded
 *            and the call is dead-code-eliminated.
 *   Sample — every kCapAuditSampleStride'th call emits one klog
 *            line. The counter is a single u64; bus-width atomic
 *            increment is fine without a lock.
 *   Full   — every call emits a klog line. Verbose; expect ~kHz
 *            traffic during normal Win32 PE runs.
 *
 * Output line shape:
 *
 *     [cap-audit] syscall=NN proc=NN allowed=Y missing=kCapXxx
 *
 * `missing == kCapNone` means the call passed; otherwise the field
 * names the FIRST missing cap (matching the gate's diagnostic).
 *
 * Why a separate hook, not a klog inside SyscallGate:
 *   - Sampling needs a counter. Burying the counter in cap_gate.cpp
 *     would entangle audit policy with the gate's correctness path.
 *     Separated, the gate stays one-job and the audit is its own
 *     replaceable / configurable surface.
 *   - The counter is centralised so the shell can read "audit
 *     calls observed since boot" without scraping serial.
 *   - A "release-audit" preset wants Full mode without rebuilding
 *     the gate. With the audit out-of-band, that's a one-knob flip.
 *
 * Context: kernel-only. Safe at any IRQ level (no allocation, no
 * lock, single u64 increment).
 */

namespace duetos::security
{

/// Result of a cap-gate decision, fed into the audit hook by
/// SyscallGate. We pass the resolved enum (Cap missing, kCapNone if
/// allowed) rather than re-deriving it inside the audit so the
/// audit doesn't duplicate the FirstMissingCap walk.
struct CapAuditEvent
{
    u64 syscall_number;
    u64 proc_id; // 0 if proc was nullptr (kernel-thread origin)
    u64 required_mask;
    duetos::core::Cap missing; // kCapNone when allowed
};

/// Process one cap-gate decision. Behavior is governed by
/// `core::kCapAuditMode`:
///   - Off    — returns immediately; no klog line.
///   - Sample — increments a counter; emits a line every
///              kCapAuditSampleStride'th call.
///   - Full   — emits a line every call.
///
/// When the audit is Off at compile time, the entire body folds
/// away because of the `if constexpr` gate inside the
/// implementation. The call-site overhead reduces to whatever the
/// optimizer leaves (typically zero — a near-tail-call into an
/// empty function the linker drops).
void CapAuditTrace(const CapAuditEvent& event);

/// Total cap-gate decisions observed by the audit since boot.
/// Includes both allow and deny outcomes. Cheap to read (one u64
/// load). The shell `inspect cap-audit` (future) prints this.
u64 CapAuditCallCount();

/// Total cap-gate denials observed by the audit since boot. A
/// non-zero value with a benign-looking workload is the operator's
/// signal that some PE/ELF is hitting the gate's deny path —
/// cross-reference with the SandboxDenials counter on the
/// originating Process for the per-process attribution.
u64 CapAuditDenyCount();

/// Reset both counters. Used by self-tests; not exposed via the
/// shell to avoid masking deny activity in long-running sessions.
void CapAuditResetCounters();

/// Force the next call to emit a sample (regardless of stride).
/// Used by the self-test to confirm the sample path works without
/// having to fire kCapAuditSampleStride synthetic events.
void CapAuditForceNextSample();

/// Read the current runtime audit mode. Initialised from
/// `core::kCapAuditMode` at boot; flipped by `CapAuditSetMode`.
/// Cheap (one byte load).
duetos::core::CapAuditMode CapAuditGetMode();

/// Suppress / re-enable the persistent fix-journal mirror of cap denials.
/// The cap-gate self-test wraps its table sweep in
/// `CapAuditSuppressJournal(true) ... CapAuditSuppressJournal(false)` so its
/// EXPECTED empty/nullptr-caps denials don't land in KERNEL.FIX (where the
/// patch generator would mis-flag them as "proc 0" cap-denial bugs). The
/// in-RAM denial ring is unaffected. Process-context only.
void CapAuditSuppressJournal(bool suppress);

/// A single captured cap-gate denial. Lives in the kernel-owned
/// ring buffer accessible through `CapAuditCopyRecentDenials`.
/// All fields are by-value snapshots — no pointers escape the
/// kernel — so the ring is safe to expose to the shell and to a
/// future `/proc/caplog` file.
struct CapAuditDenialRecord
{
    u64 sequence;              // monotonic; rolls over after 2^64 denies (never).
    u64 boot_tick;             // sched tick when the denial fired.
    u64 syscall_number;        // matches CapAuditEvent.syscall_number.
    u64 proc_id;               // 0 for kernel-thread origin.
    u64 required_mask;         // bitmask of required caps.
    duetos::core::Cap missing; // first missing cap.
    u8 _pad[7];
};

/// Copy the most recent denials (newest-first) into `out`. Returns
/// the count written, capped at `out_cap` and at the ring's live
/// occupancy. The ring is 256 entries deep; a tight deny storm
/// older than ~256 events is dropped silently — the operator is
/// expected to `dmesg` for the full klog history and use this
/// surface for "what just happened?" triage.
u64 CapAuditCopyRecentDenials(CapAuditDenialRecord* out, u64 out_cap);

/// Total entries dropped because the ring was full when a denial
/// arrived. Wraps the simple "256 most recent" model: callers see
/// a clean cap on the per-call cost, and the operator sees a
/// non-zero `dropped` count as a signal to widen the buffer (or
/// to filter the workload that's generating the storm).
u64 CapAuditDenialDropCount();

/// Set the runtime audit mode. Takes effect on the next
/// `CapAuditTrace` call. Has NO EFFECT on a build whose compile-time
/// mode is `Off` — the EmitLine path is dead code in such a build,
/// so flipping the runtime to Full would silently do nothing. The
/// shell command surfaces a warning when a flip is attempted on an
/// Off-at-compile-time build (see kernel/shell).
///
/// Returns true if the mode was changed; false if the build's
/// compile-time mode is Off (in which case nothing was changed).
bool CapAuditSetMode(duetos::core::CapAuditMode mode);

/// Compile-time minimum mode this build can reach. Equal to
/// `core::kCapAuditMode`; exposed via this API so the shell can
/// surface the floor without including build_config.h directly.
duetos::core::CapAuditMode CapAuditCompileTimeMode();

/// Boot-time self-test. Runs three synthetic events through
/// `CapAuditTrace` and asserts the counters land where they should.
/// Panics on mismatch — the audit is observability infrastructure,
/// and a regression here means the release operator can't see what
/// the kernel is doing on their behalf.
void CapAuditSelfTest();

} // namespace duetos::security
