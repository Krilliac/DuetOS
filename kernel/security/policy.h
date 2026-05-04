#pragma once

#include "drivers/storage/block.h"
#include "security/canary.h"
#include "security/guard.h"
#include "util/types.h"

/*
 * DuetOS — security policy engine v0 (white team).
 *
 * Composes every per-subsystem security mode into one operator-
 * facing profile. Today the operator has to flip ~3 independent
 * switches (image guard mode, persistence-drop mode, blockguard
 * write mode) to get a consistent posture. The policy engine
 * makes that one command:
 *
 *     policy set production
 *
 * which flips all three at once + publishes a `PolicyChanged`
 * event so the audit trail records WHO chose the profile and WHEN.
 *
 * Profiles:
 *   Default     — bytewise no-op snapshot of whatever each
 *                 subsystem chose for itself. Existence prevents
 *                 a "no profile chosen" inconsistent state.
 *   Lab         — permissive: Advisory everywhere. Prevents
 *                 detection-tool development from being
 *                 interrupted by killable trips.
 *   Production  — strict default: Enforce/Deny everywhere.
 *   Forensic    — maximum: every wall enforces; intended for
 *                 use after a confirmed incident.
 *
 * Threshold knobs (sandbox denial, fs-write-rate caps, fault-
 * react floor) are hard-coded constants today, not runtime-
 * settable. Future v1 may surface them through the policy table
 * once each subsystem provides a setter; v0 only flips what's
 * already adjustable.
 *
 * See wiki/security/Attack-Simulation.md (white-team policy
 * engine) for the full rationale and the per-subsystem
 * composition matrix.
 *
 * Context: kernel. Mode setters are task-context only — block
 * write-guard's setter logs at klog scope. Do NOT call PolicySet
 * from IRQ context.
 */

namespace duetos::security
{

enum class PolicyProfile : u16
{
    Default = 0,
    Lab,
    Production,
    Forensic,
    Count, // sentinel
};

const char* PolicyProfileName(PolicyProfile p);

struct PolicySnapshot
{
    PolicyProfile profile;
    Mode guard_mode;
    PersistenceMode persistence_mode;
    drivers::storage::WriteGuardMode write_guard_mode;
    u64 applied_at_uptime_ns;
    u32 applied_by_pid; // 0 = boot init / kernel
};

/// Read-only snapshot of the current policy state. Cheap; held
/// under a spinlock.
PolicySnapshot PolicyCurrent();

/// Apply `profile` atomically. Sets every per-subsystem mode in
/// a single critical section, publishes a `PolicyChanged` event
/// (and one `*ModeChanged` per subsystem that actually changed),
/// and updates the snapshot. `actor_pid == 0` means kernel-init.
void PolicySet(PolicyProfile profile, u32 actor_pid);

/// Profile-only hint for boot-time subsystems. NOT a security
/// gate — the per-subsystem modes are the gates; this is for
/// ergonomics ("if profile is Lab, dump verbose detector logs").
PolicyProfile PolicyCurrentProfileHint();

/// Boot-time init. Sets profile to Default by reading whatever
/// each subsystem chose for itself + storing the snapshot.
/// Idempotent.
void PolicyInit();

/// Resolve the per-subsystem modes a profile WOULD apply,
/// without applying them. Useful for the `policy diff` shell
/// command.
PolicySnapshot PolicyResolve(PolicyProfile profile);

/// Boot-time self-test. Applies each profile in sequence,
/// reads back via PolicyCurrent, asserts every per-subsystem
/// mode matches expectation, then restores the original
/// profile. Runs at boot iff DUETOS_DEBUG. PASS / FAIL printed
/// to COM1.
void PolicySelfTest();

} // namespace duetos::security
