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

/// Boot-time self-test. Runs three synthetic events through
/// `CapAuditTrace` and asserts the counters land where they should.
/// Panics on mismatch — the audit is observability infrastructure,
/// and a regression here means the release operator can't see what
/// the kernel is doing on their behalf.
void CapAuditSelfTest();

} // namespace duetos::security
