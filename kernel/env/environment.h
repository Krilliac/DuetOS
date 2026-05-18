#pragma once

#include "util/types.h"

/*
 * DuetOS — unified system-environment view, v0 (slice 2 of 3).
 *
 * The kernel already *detects* its environment, but the facts are
 * scattered across half a dozen subsystems and read ad-hoc:
 *
 *   arch::HypervisorInfoGet()        — hypervisor kind / bare-metal
 *   arch::CpuInfoGet()               — vendor / features
 *   acpi::CpuCount() + smp::*Online  — logical-CPU census
 *   mm::TotalFrames()                — physical RAM size
 *   acpi::srat::*                    — NUMA presence / node count
 *   drivers::power::PowerSnapshot*   — AC / battery / lid / thermal
 *   cpu::TopologyForCpu()            — hybrid (P/E) core presence
 *
 * This module is a *read-only aggregator*: it never re-detects
 * anything. It composes one `SystemEnvironment` snapshot at boot,
 * derives a coarse power policy from it, prints one canonical
 * `[env] ...` banner (a structural sentinel that survives log-level
 * demotion so `tools/test/boot-log-analyze.sh` can grep it), and
 * exposes cached query accessors. The owning subsystems remain the
 * single source of truth for every field.
 *
 * Slice 2 (this revision) adds the `env-monitor` kernel thread:
 * it re-composes the snapshot on a timed poll, publishes the new
 * value under a spinlock, and on a power-policy transition leaves a
 * gated KLOG sentinel + a `kEnvPolicyChange` probe. The cached
 * state is therefore live, not frozen at boot — that is the
 * "reactive" half. The idle-path C-state reaction is deferred to
 * slice 3, where deep C-states (a real lever) and a consumer land
 * together; wiring a no-op policy read into the hot idle loop now
 * would be a facade.
 *
 * Slice 3 adds the ACPI SCI/GPE power-event path so the monitor
 * wakes on a real interrupt instead of only on its poll.
 *
 * Context: kernel. `EnvironmentInit()` runs once at boot, after
 * `drivers::power::PowerInit()` (so AC/battery/thermal are live) and
 * after SMP AP bring-up (so the online census is final).
 * `EnvironmentMonitorStart()` then spawns the poller. Reads are
 * snapshot-by-value under a spinlock, safe from any context and
 * concurrent with the monitor's writes.
 */

namespace duetos::arch
{
enum class HypervisorKind : u8;
}

namespace duetos::drivers::power
{
enum AcState : u8;
enum BatteryState : u8;
} // namespace duetos::drivers::power

namespace duetos::env
{

enum class EnvPlatform : u8
{
    BareMetal,   // CPUID hypervisor bit clear
    Virtualized, // a real VMM (KVM / VMware / VBox / Hyper-V / Xen / ...)
    Emulated,    // a pure emulator (QEMU TCG, Bochs) — no host power mgmt
};

enum class EnvFormFactor : u8
{
    Unknown,
    Server,
    Desktop,
    Laptop,
};

enum class EnvPowerPolicy : u8
{
    Performance, // bare-metal server/desktop on wall power
    Balanced,    // laptop on AC, or virtualized (host owns real PM)
    PowerSave,   // on battery, or thermally throttled
};

/// One authoritative snapshot of the runtime environment. Every
/// field is copied from its owning subsystem at `EnvironmentInit`
/// time (slice 2's monitor re-composes it on change).
struct SystemEnvironment
{
    // Virtualization
    arch::HypervisorKind hv_kind;
    EnvPlatform platform;
    // CPU census
    u32 cpu_online;  // currently-online logical CPUs
    u32 cpu_total;   // MADT-reported logical CPUs
    bool cpu_hybrid; // any P/E hybrid core present
    // Memory
    u64 ram_bytes;
    bool numa;
    u32 numa_nodes;
    // Chassis / power
    EnvFormFactor form_factor;
    drivers::power::AcState ac;
    drivers::power::BatteryState battery_state;
    u8 battery_percent; // 0..100; 255 = unknown / no battery
    bool lid_present;
    bool lid_open; // valid iff lid_present
    // Thermal
    u8 cpu_temp_c; // 0 = not available
    u8 pkg_temp_c;
    bool thermal_throttle;
    // Derived
    EnvPowerPolicy power_policy;
    bool valid; // false until EnvironmentInit() has run
};

/// Compose the snapshot from the already-detected subsystem state,
/// derive the power policy, cache it, and emit the canonical
/// `[env] ...` banner. Safe exactly once at boot.
void EnvironmentInit();

/// Snapshot-by-value of the composed view, taken under the publish
/// lock so it never tears against a concurrent monitor write.
/// `valid == false` until `EnvironmentInit()` has run.
SystemEnvironment EnvironmentGet();

/// Cheap accessor for the derived policy (read under the publish
/// lock). Live once the monitor is running — slice 3's idle path
/// and the shell read this.
EnvPowerPolicy EnvironmentPowerPolicy();

/// Re-read every source, recompute the policy, and atomically
/// publish the new snapshot. Returns true iff any observable field
/// changed. Called by the `env-monitor` task; exposed for the
/// self-test. Safe from task context (takes the publish lock; the
/// underlying reads — PowerSnapshotRead etc. — are process-context
/// safe).
bool EnvironmentRecompose();

/// Spawn the `env-monitor` kernel thread (timed poll → recompose →
/// publish, with a gated KLOG + probe on policy transitions). Call
/// once, after `EnvironmentInit()` and with the scheduler online.
void EnvironmentMonitorStart();

/// Pure derivation: policy implied by a given snapshot. Exposed so
/// slice 2's monitor recomputes it identically on every poll. No
/// side effects, no caching.
EnvPowerPolicy EnvironmentDerivePolicy(const SystemEnvironment& e);

const char* EnvPlatformName(EnvPlatform p);
const char* EnvFormFactorName(EnvFormFactor f);
const char* EnvPowerPolicyName(EnvPowerPolicy p);

/// Boot self-test: asserts the cached snapshot is valid and that
/// `EnvironmentPowerPolicy()` equals `EnvironmentDerivePolicy()` of
/// the live snapshot, exercises the `EnvironmentDerivePolicy()`
/// decision matrix the monitor relies on against synthetic
/// snapshots, and verifies `EnvironmentRecompose()` preserves the
/// cached==derived invariant (recompose, then re-check). Emits one
/// `[env-selftest] PASS` line. Panics on regression.
void EnvironmentSelfTest();

} // namespace duetos::env
