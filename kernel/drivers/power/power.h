#pragma once

#include "../../core/types.h"

/*
 * CustomOS — Power / battery / thermal shell, v0.
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
 *   - SMBIOS says "this is a laptop chassis"? Then we EXPECT
 *     battery hardware. Otherwise treat as desktop.
 *   - MSR thermal reading (from arch::ThermalRead) folded in
 *     as the CPU thermal source.
 *   - Everything else is a stub with a log line explaining why
 *     real data needs an ACPI AML interpreter: battery state
 *     lives in _BIF / _BST methods in the DSDT/SSDT, AC state
 *     lives in _PSR. We don't have AML yet.
 *
 * Not in scope:
 *   - ACPI AML interpreter — the gate for real battery readings.
 *     docs/knowledge/ notes the future slice.
 *   - Embedded Controller (EC) access — laptop-specific SMBus or
 *     direct-IO interface that many devices use instead of AML
 *     methods. Requires vendor-specific quirks per laptop model.
 *   - SMBus master driver — some PSUs expose smart-battery data
 *     over SMBus.
 *   - Power events (button presses, lid close) — needs AML
 *     general-purpose event (GPE) routing.
 *
 * Context: kernel. `PowerInit` runs once at boot after SMBIOS
 * + thermal probes.
 */

namespace customos::drivers::power
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
    bool backend_is_stub; // true in v0 — AML not implemented yet
};

/// Probe SMBIOS + MSR thermal, build the initial snapshot, log
/// a summary. Safe single-init.
void PowerInit();

/// Refresh the snapshot (re-read thermal MSRs; AC/battery stay
/// stubbed until AML lands). Returns a copy.
PowerSnapshot PowerSnapshotRead();

const char* AcStateName(AcState s);
const char* BatteryStateName(BatteryState s);

} // namespace customos::drivers::power
