#pragma once

#include "util/types.h"

/*
 * DuetOS — unified system-environment view, v0 (slice 1 of 3).
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
 * Slice 2 adds a monitor task that re-composes the snapshot and
 * reacts to runtime changes; slice 3 adds the ACPI SCI/GPE
 * power-event path. The query API here is the stable seam both
 * later slices build on.
 *
 * Context: kernel. `EnvironmentInit()` runs once at boot, after
 * `drivers::power::PowerInit()` (so AC/battery/thermal are live) and
 * after SMP AP bring-up (so the online census is final). Every query
 * thereafter is a cached read, safe from any context.
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

/// Cached read of the composed snapshot. `valid == false` until
/// `EnvironmentInit()` has run.
const SystemEnvironment& EnvironmentGet();

/// Cheap accessor for the derived policy. Slice 2's monitor and the
/// scheduler idle path read this; today it is constant after boot.
EnvPowerPolicy EnvironmentPowerPolicy();

/// Pure derivation: policy implied by a given snapshot. Exposed so
/// slice 2's monitor recomputes it identically on every poll. No
/// side effects, no caching.
EnvPowerPolicy EnvironmentDerivePolicy(const SystemEnvironment& e);

const char* EnvPlatformName(EnvPlatform p);
const char* EnvFormFactorName(EnvFormFactor f);
const char* EnvPowerPolicyName(EnvPowerPolicy p);

/// Boot self-test: asserts the cached snapshot is valid and that
/// `EnvironmentPowerPolicy()` equals `EnvironmentDerivePolicy()` of
/// the live snapshot (the invariant slice 2 depends on). Emits one
/// `[env-selftest] PASS` line. Panics on regression.
void EnvironmentSelfTest();

} // namespace duetos::env
