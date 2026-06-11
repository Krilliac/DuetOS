#pragma once

#include "util/types.h"

/*
 * DuetOS — env autonomic rule engine, v0.
 *
 * The "sense → decide → act" leg of the autonomic-OS arc (see
 * wiki/drivers/Neural-Engine.md). The env-monitor task already
 * SENSES (SystemEnvironment) and DECIDES a power policy
 * (EnvironmentDerivePolicy). This engine adds ACT: on every
 * monitor poll it evaluates a small, bounded rule table and
 * invokes real, kernel-owned effects.
 *
 * Every rule reads a real telemetry source and every action calls
 * a real, task-context-safe kernel mechanism — no stubs, no
 * facades. The decision (`AutonomicEvaluate`) is a pure function
 * of sensed inputs + retained edge state; that is the exact seam a
 * future NPU-backed learned policy replaces (it never touches the
 * actuators). The engine has no NPU dependency and runs entirely
 * CPU-side.
 *
 * Rule table (id : if <real sensed> then <real action>):
 *   1 MemPressure       free frames < 10%        → heap-drain + pool-drain
 *   2 ThermalPower      thermal_throttle rising  → pool-drain + health scan
 *   3 SecurityIntegrity health issues_total rose → guard Enforce + Production
 *   4 CpuSaturation     loadavg > nCPU rising    → health scan + rebalance
 *   5 PowerTransition   EnvPowerPolicy changed   → scheduler power bias
 *
 * Edge-triggered: an action fires on the rising edge of its
 * condition (and rule 5 on any policy change, restoring the
 * scheduler bias on the way back up to Performance). Re-firing is
 * suppressed while a latched condition stays true, so a contended
 * box does not flood. Apply is idempotent.
 *
 * Threading: kernel task context only (the env-monitor poll, ~2 s
 * cadence). Never call from IRQ.
 *
 * Subsystem isolation: freestanding kernel engine. No subsystem
 * (Win32 / Linux ABI) reaches it; it issues no syscalls and grants
 * no privilege — it drives kernel-owned levers the kernel already
 * owns.
 */

namespace duetos::env
{

enum class AutoRule : u8
{
    None = 0,
    MemPressure,
    ThermalPower,
    SecurityIntegrity,
    CpuSaturation,
    PowerTransition,
};

enum class AutoAction : u8
{
    None = 0,
    MemReclaim,        // KernelHeapDrainBins + FrameAllocatorDrainPools
    FootprintTrim,     // FrameAllocatorDrainPools (shrink resident set)
    SecurityEscalate,  // SetGuardMode(Enforce) + PolicySet(Production)
    ForceHealthScan,   // RuntimeCheckerScan()
    SchedPerformance,  // SchedSetPowerBias(Performance)
    SchedBalanced,     // SchedSetPowerBias(Balanced)
    SchedPowerSave,    // SchedSetPowerBias(PowerSave)
    SchedRebalanceNow, // SchedRequestActiveBalance() — one-shot cross-CPU rebalance
    Count,
};

// 10% free-frame floor; below it rule 1 reclaims.
inline constexpr u64 kMemPressurePctFree = 10;

/// Sensed inputs for one evaluation. Passed by value so the pure
/// evaluator is testable without hardware. Q11 loadavg: 2048 == 1.0.
struct AutoInputs
{
    u64 free_frames;
    u64 total_frames;
    bool thermal_throttle;
    u64 health_issues_total;
    u32 loadavg_1min_q11;
    u32 cpu_online;
    u8 power_policy; // EnvPowerPolicy as u8
};

/// Engine's retained edge-tracking state (one instance, owned by
/// the engine; exposed so the self-test can drive the pure path).
struct AutonomicState
{
    bool valid;
    bool mem_pressure;
    bool thermal_active;
    bool cpu_saturated;
    u64 health_total;
    u8 last_power_policy;
};

/// Distinct-action capacity of one decision. The rule floor alone fires
/// at most 4 (independent rules), but Live mode reconciles the learner's
/// proposal WITH the floor (net ∪ floor), so the set must hold the union
/// of every discretionary + safety + bias + rebalance action that can
/// co-occur in one tick without silently dropping an actuator.
inline constexpr u32 kAutoActionSetCap = 8;

struct AutoActionSet
{
    AutoAction actions[kAutoActionSetCap];
    AutoRule rules[kAutoActionSetCap];
    u32 count;
};

struct AutonomicReport
{
    u64 ticks;
    u64 actions_fired;
    u64 per_action[static_cast<u32>(AutoAction::Count)];
    AutoAction last;
    AutoRule last_rule;
};

/// Pure decision: rising-edge rule evaluation. No side effects, no
/// logging, no kernel calls. Updates `st` in place to the new
/// latched state and returns the actions whose edge fired. This is the
/// rule floor — both the safety baseline and (Slice 2+) the learned
/// policy's imitation teacher.
AutoActionSet AutonomicEvaluate(AutonomicState& st, const AutoInputs& in);

/// The full decide step: rule floor (AutonomicEvaluate) + learned policy,
/// reconciled by the shield (ShieldReconcile) and traced. Routed by
/// AutonomicTick. `now` is the poll's tick stamp — in Live mode the
/// learner records the decision under it so the delayed feedback reward
/// credit-assigns the right synapses. Off/Shadow actuate the rule floor;
/// Live lets the net drive behind the shield. Pure of actuation — returns
/// the set AutonomicApply then executes.
AutoActionSet PolicyDecide(AutonomicState& st, const AutoInputs& in, u64 now);

/// Perform the real effects of an action set (kernel calls + log +
/// probe). `now` is the fire tick stamped into each feedback entry so a
/// later reward matches the decision. Task context only. Not exercised by
/// the self-test.
void AutonomicApply(const AutoActionSet& set, u64 now);

/// One poll iteration: sense → PolicyDecide → AutonomicApply → fold into
/// the report. Called from the env-monitor loop.
void AutonomicTick();

/// Capture the baseline so the first tick does not false-fire on
/// boot-time conditions. Call once after EnvironmentInit().
void AutonomicInit();

const AutonomicReport& AutonomicStatus();

const char* AutoActionName(AutoAction a);
const char* AutoRuleName(AutoRule r);

/// Boot self-test: drives the pure evaluator through each rule's
/// rising edge, asserts the action + idempotence (a held condition
/// does not re-fire). Emits `[autonomic] selftest pass`. Never
/// performs a real Apply.
void AutonomicSelfTest();

} // namespace duetos::env
