#pragma once

#include "util/types.h"

/*
 * DuetOS — self-defensive fault-reaction dispatcher (v0).
 *
 * Glue layer between fault-reporting sites (drivers, runtime
 * checker, watchdogs, retry-exhausted paths) and the existing
 * recovery taxonomy (halt / driver-restart / process-kill /
 * retry / reject / object-reset — see
 * `docs/knowledge/runtime-recovery-strategy.md`).
 *
 * Today every reporter picks its own reaction ad-hoc:
 *   - DriverFault logs and counts.
 *   - The trap handler hard-codes extable -> MarkRestart.
 *   - runtime_checker / soft_lockup / ubsan each log + DebugPanicOrWarn.
 * That works in isolation but means there is NO single chokepoint
 * where a kernel-owned policy can clamp a misjudged reaction
 * (e.g. a buggy driver demoting a corruption-class fault to
 * "Continue"). This module is that chokepoint.
 *
 * Shape:
 *
 *   1. The reporter builds a `FaultEvidence` (kind + severity +
 *      source + optional faulting RIP / aux word) and calls
 *      `FaultReactDispatch(domain_id, ev)`.
 *
 *   2. The dispatcher looks up the domain's per-subsystem policy
 *      (`FaultReactionFn`, registered via `FaultReactSetPolicy`)
 *      and consults it for a desired `FaultReaction`.
 *
 *   3. The dispatcher applies a kernel-owned floor — the strictest
 *      reaction that the (source, kind) pair must NOT fall below
 *      regardless of what the policy returned. The actual reaction
 *      is `max(policy_choice, floor)`.
 *
 *   4. The dispatcher executes the reaction:
 *        Continue       -> Warn-log + return.
 *        RetryNow       -> Info-log + return; caller retries.
 *        RestartDomain  -> FaultDomainMarkRestart + Error-log + return.
 *        KillProcess    -> Error-log + return (STUB; ring-3 path
 *                          arrives with the userland process model).
 *        Halt           -> Panic. Does not return.
 *
 * "Self-reflection + polymorphism" in this file means: the
 * subsystem inspects its OWN restart_count / attempt_count /
 * evidence and picks a reaction for itself; different subsystems
 * pick differently. The kernel keeps the floor, so a buggy
 * subsystem can never be more reckless than the kernel allows.
 *
 * Context: kernel. The dispatcher itself is safe from process /
 * IRQ / soft-IRQ context (it does NOT take locks, allocate, or
 * sleep). Policy callbacks inherit that constraint. NMI / #MC
 * context is NOT supported in v0 — the trap handler should mark
 * the domain via `FaultDomainMarkRestart` directly and let the
 * heartbeat-side `FaultReactDispatch` run later if a richer
 * decision is needed.
 */

namespace duetos::core
{
// Forward decl — header-cycle avoidance. Defined in security/fault_domain.h.
using FaultDomainId = u32;
} // namespace duetos::core

namespace duetos::diag
{

/// What went wrong, broadly. Used by both the per-subsystem
/// policy and the kernel-owned floor.
enum class FaultKind : u8
{
    DeviceTimeout = 0, // Device didn't respond in the expected window.
    DmaError,          // DMA abort / bus fault.
    UnexpectedStatus,  // Device returned an undecodable status word.
    FirmwareLied,      // Descriptor / capability inconsistent.
    InternalInvariant, // Subsystem state machine entered invalid state.
    Hung,              // Watchdog on a subsystem thread fired.
    RetryExhausted,    // RetryWithBackoff gave up.
    KernelPageFault,   // Uncovered kernel-mode #PF (no extable hit).
    UserPageFault,     // Ring-3 wild pointer / NX-stack jump.
    MemoryCorruption,  // Heap / page-table / freelist sanity check failed.
    StackCanaryFailed, // Stack-protector tripped.
    SoftLockup,        // CPU pinned in a non-progressing loop.
    Unknown,           // Catch-all when the reporter has no better label.
};

/// Severity hint from the reporter. Advisory — the dispatcher
/// applies the floor regardless.
enum class FaultSeverity : u8
{
    Recoverable = 0, // No state lost; retry / continue is safe.
    Degraded,        // Subsystem can keep running with reduced
                     // capability; fresh init recommended.
    Critical,        // Kernel-owned data may be inconsistent.
};

/// Per-fault evidence. All pointers must outlive the dispatch
/// call (the evidence is read synchronously and not stored).
struct FaultEvidence
{
    const char* source; // Short stable label: "drivers/usb/xhci",
                        // "kernel/mm/kheap", … Used by the floor
                        // to recognise kernel-critical sources.
    FaultKind kind;
    FaultSeverity severity;
    u32 attempt_count; // For retry-flavored kinds; 0 otherwise.
    u64 faulting_rip;  // 0 if not applicable.
    u64 aux;           // Kind-specific (cr2, status reg, addr…).
};

/// What to do about it. STRICTLY ORDERED from least to most
/// disruptive — the dispatcher uses `max(policy, floor)` against
/// this ordering, so adding new values in the middle is an ABI
/// break for existing policies. Append new values at the end.
enum class FaultReaction : u8
{
    Continue = 0,  // Log + return. No recovery action.
    RetryNow,      // Caller retries the operation.
    RestartDomain, // Mark the fault domain for deferred restart.
    KillProcess,   // (STUB until ring-3 process model lands.)
    Halt,          // Panic. Does not return.
};

/// Per-domain reaction policy. Pure function — must not allocate,
/// block, or take locks. Receives the evidence (which already
/// carries the kind) and returns the desired reaction. The
/// dispatcher MAY override toward stricter (it never weakens).
using FaultReactionFn = FaultReaction (*)(const FaultEvidence& ev);

/// Default policy used when no per-domain override is registered.
/// Conservative table keyed off `kind` only; ignores attempt_count
/// / severity. Exported so tests + audits can compare against it.
FaultReaction DefaultReactionPolicy(const FaultEvidence& ev);

/// Register a per-domain reaction policy. nullptr `fn` clears
/// the override (the dispatcher reverts to the default). The
/// `domain_id` must already be a registered fault domain;
/// otherwise the call is a no-op + a Warn log. Idempotent.
void FaultReactSetPolicy(::duetos::core::FaultDomainId domain_id, FaultReactionFn fn);

/// Look up the policy currently in effect for a domain. Returns
/// `&DefaultReactionPolicy` if no override is registered. Never
/// returns nullptr.
FaultReactionFn FaultReactGetPolicy(::duetos::core::FaultDomainId domain_id);

/// Kernel-owned floor. Independent of any subsystem policy.
/// Returns the strictest reaction the dispatcher MUST apply
/// for the (source, kind) pair regardless of policy choice.
///
/// Floor rules in v0:
///   - source starts with "kernel/mm" -> at least Halt.
///   - kind == MemoryCorruption       -> at least Halt.
///   - kind == StackCanaryFailed      -> at least Halt.
///   - kind == KernelPageFault        -> at least Halt.
///   - severity == Critical           -> at least RestartDomain.
///   - everything else                -> Continue (no floor).
///
/// Exposed for tests + audit code; not normally called directly
/// — `FaultReactDispatch` consults it.
FaultReaction FaultReactPolicyFloor(const FaultEvidence& ev);

/// One-shot dispatcher. Calls the domain's policy, applies the
/// floor, executes the reaction, and returns what was actually
/// taken (which may be stricter than what the policy returned).
///
/// `domain_id` may be `kFaultDomainInvalid` for fault-reporting
/// sites that don't have a registered domain yet — in that case
/// the default policy is used and `RestartDomain` decays to
/// `Continue` (there's nothing to mark).
FaultReaction FaultReactDispatch(::duetos::core::FaultDomainId domain_id, const FaultEvidence& ev);

/// Trap-handler-safe deferred report. Records the (domain_id,
/// kind, faulting_rip) triple into a per-domain pending slot
/// AND calls `FaultDomainMarkRestart` so the lossless restart
/// backbone still fires. Safe to call from any context that
/// can do plain stores: trap handlers, IRQ, soft-IRQ, NMI.
///
/// The trap handler must NOT call `FaultReactDispatch` directly
/// — the dispatcher takes klog locks and may panic, both of
/// which are unsafe in trap context. Instead the trap handler
/// records the fault via this function; `FaultReactDrainPending`
/// is called from the heartbeat thread to apply the policy +
/// floor + execution.
///
/// Per-domain slot model: only one pending entry per domain
/// survives at a time. If two faults hit the same domain
/// before the heartbeat drains, the second overwrites the
/// first (the bool MarkRestart is set either way, so the
/// restart still fires; the overwritten kind/rip is lost).
/// On the typical case where a single subsystem trips a
/// fixup once per beat that's not a real loss; if it becomes
/// one we extend to a small ring.
void FaultReactReportFromTrap(::duetos::core::FaultDomainId domain_id, FaultKind kind, u64 faulting_rip);

/// Heartbeat-side drain. Walks every domain's pending slot,
/// builds a `FaultEvidence`, calls `FaultReactDispatch`, and
/// clears the slot. Called from `kheartbeat` BEFORE
/// `FaultDomainTick` so a `RestartDomain` reaction's
/// `FaultDomainMarkRestart` re-arms the bool that the tick
/// then drains. Cheap when no slots are valid — one linear
/// scan over the bounded registry.
void FaultReactDrainPending();

/// How many faults have been overwritten in pending slots
/// since boot (i.e. a domain hit twice before the heartbeat
/// drained it). Diagnostic only; non-zero is an indication
/// the slot model isn't enough for the fault rate and a ring
/// upgrade is warranted.
u64 FaultReactPendingOverwriteCount();

/// Diagnostic counters. Lifetime totals since boot.
u64 FaultReactDispatchCount();
u64 FaultReactReactionCount(FaultReaction r);

/// Human-readable label for log lines + shell commands.
const char* FaultKindName(FaultKind k);
const char* FaultReactionName(FaultReaction r);

/// Boot-time self-test. Registers a toy fault domain, exercises
/// the dispatcher with both a permissive policy (clamped up by
/// the floor for kernel-critical kinds) and a strict policy
/// (passed through), and verifies the counters + side effects.
/// Panics on mismatch.
void FaultReactSelfTest();

} // namespace duetos::diag
