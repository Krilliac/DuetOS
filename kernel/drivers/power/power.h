#pragma once

#include "util/types.h"

/*
 * DuetOS — Power / battery / thermal shell, v0.
 *
 * Umbrella for anything that isn't "CPU instruction" or "PCI
 * device" but still reports energy / thermal / presence state:
 *
 *   - AC adapter presence (plugged vs on-battery).
 *   - Battery state (present / charging / discharging / percent
 *     / rate / voltage).
 *   - Thermal zones (passive/active trip points, current temp).
 *   - Power buttons (power / sleep / lid).
 *   - PSU reachable (some server boards expose PSU over SMBus).
 *
 * Scope (v0):
 *   - Live ACPI power data via the AML interpreter: battery
 *     `_STA`/`_BIF`/`_BST`, AC `_PSR`, lid `_LID` — decoded by
 *     `kernel/acpi/acpi_power.cpp`, with the ACPI EC driver
 *     (`kernel/acpi/ec.cpp`) backing any EmbeddedControl
 *     FieldUnits those methods read. `backend_is_stub` is cleared
 *     whenever live data is present and re-polled each
 *     `PowerSnapshotRead`.
 *   - On firmware with no power AML (QEMU) we fall back to the
 *     SMBIOS chassis heuristic for battery *presence* only.
 *   - MSR thermal reading (from arch::ThermalRead) folded in
 *     as the CPU thermal source.
 *
 * Not in scope (still):
 *   - SMBus master driver — some PSUs expose smart-battery data
 *     over SMBus.
 *   - Power *events* (button / lid-close interrupts) — needs ACPI
 *     GPE / `_Qxx` SCI dispatch (lid *state* is already read via
 *     `_LID`).
 *   - S3/S0ix suspend-to-RAM wake plumbing.
 *   - Per-vendor register backlight (the ACPI `_BCM` path is
 *     handled by `kernel/acpi/acpi_power.cpp`).
 *
 * Context: kernel. `PowerInit` runs once at boot after SMBIOS
 * + thermal probes.
 */

namespace duetos::drivers::power
{

enum AcState : u8
{
    kAcUnknown = 0,
    kAcOnline,  // wall power present
    kAcOffline, // on battery
};

enum BatteryState : u8
{
    kBatNotPresent = 0,
    kBatUnknown,
    kBatCharging,
    kBatDischarging,
    kBatFull,
};

struct BatteryInfo
{
    BatteryState state;
    u8 percent;     // 0..100; 255 = unknown
    i32 rate_mw;    // charge/discharge rate in mW; negative = discharge
    u32 voltage_mv; // 0 = unknown
    u32 design_capacity_mwh;
    u32 full_capacity_mwh;
};

struct PowerSnapshot
{
    AcState ac;
    BatteryInfo battery;
    bool chassis_is_laptop; // from SMBIOS chassis type
    u8 cpu_temp_c;          // from MSR thermal; 0 = not available
    u8 package_temp_c;
    u8 tj_max_c;
    bool thermal_throttle_hit;
    bool backend_is_stub; // true only when no live ACPI power data
    bool lid_present;     // firmware declared a _LID method
    bool lid_open;        // valid iff lid_present
};

/// Probe SMBIOS + MSR thermal, build the initial snapshot, log
/// a summary. Safe single-init.
void PowerInit();

/// Refresh the snapshot (re-read thermal MSRs; AC/battery stay
/// stubbed until AML lands). Returns a copy.
PowerSnapshot PowerSnapshotRead();

const char* AcStateName(AcState s);
const char* BatteryStateName(BatteryState s);

} // namespace duetos::drivers::power
