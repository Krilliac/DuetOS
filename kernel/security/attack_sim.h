#pragma once

#include "../core/types.h"

/*
 * CustomOS attacker-simulation suite — red-team harness.
 *
 * Runs a battery of in-kernel attack scenarios that a rootkit /
 * kernel-level malware would attempt, verifies each is detected
 * by the runtime invariant checker, and reports PASS/FAIL per
 * attack.
 *
 * Every simulation follows the same pattern:
 *   1. Snapshot the pre-attack state (MSR value, memory bytes,
 *      etc.) so we can restore.
 *   2. Perform the attack (write the MSR, scribble memory, ...).
 *   3. Invoke `RuntimeCheckerScan()` directly — forces detection
 *      without waiting for the next 5-second heartbeat.
 *   4. Query the health report to confirm the expected
 *      `HealthIssue` bumped its counter.
 *   5. Restore the pre-attack state so the kernel stays
 *      well-formed + subsequent attacks run cleanly.
 *
 * Intended for:
 *   - Operator-driven demos (`attacksim` shell command).
 *   - CI smoke variant that runs it after the normal signatures
 *     + asserts every expected detection actually fired.
 *   - Manual testing when adding new HealthIssue detectors —
 *     extend the suite with a matching attack to prove the
 *     detector is live.
 *
 * NOT run at boot. These attacks deliberately trigger
 * security-critical findings that escalate the guard to
 * Enforce + the block write-guard to Deny; running during
 * boot would pre-poison every image load + storage write for
 * the rest of the session.
 *
 * Context: kernel. Must run from task context (not IRQ) — one
 * of the simulations does `wrmsr`, which is privileged but
 * otherwise happens synchronously from the calling thread.
 */

namespace customos::security
{

enum class AttackOutcome : u8
{
    Pass,         // attack performed, detector caught it as expected
    FailNoDetect, // attack performed, detector did NOT catch it — REGRESSION
    Skipped,      // attack could not run on this platform (e.g. no VMX)
};

const char* AttackOutcomeName(AttackOutcome o);

struct AttackResult
{
    const char* name;     // e.g. "IDT hijack"
    const char* detector; // expected HealthIssue name
    AttackOutcome outcome;
};

inline constexpr u64 kMaxAttackResults = 16;

struct AttackSummary
{
    u64 count;
    u64 passed;
    u64 failed;
    u64 skipped;
    AttackResult results[kMaxAttackResults];
};

/// Run the full attacker simulation suite. Runs all simulations
/// even if an early one fails; failure of one detector does not
/// prevent the others from running. The summary lives as a
/// file-scope singleton (no return-by-value — avoids the
/// freestanding-kernel memcpy).
///
/// Safe to call exactly once per boot — each attack is
/// idempotent in its restore step, but the guard/blockguard
/// escalation paths are one-way within a boot.
void AttackSimRun();

/// Read-only accessor for the last-completed suite's summary.
/// Zero-initialised until AttackSimRun has completed.
const AttackSummary& AttackSimSummary();

} // namespace customos::security
