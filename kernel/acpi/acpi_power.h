#pragma once

#include "util/types.h"

/*
 * DuetOS — ACPI power-device evaluators, v0.
 *
 * Thin wrappers that locate the firmware's power devices in the AML
 * namespace and run their control methods through the AML
 * interpreter (aml_eval.cpp), surfacing decoded state to the power
 * shell (drivers/power):
 *
 *   - Battery   — `_STA` (presence) + `_BIF` (info) + `_BST` (state)
 *   - AC adapter — `_PSR` (1 = online)
 *   - Lid switch — `_LID` (1 = open)
 *   - Backlight  — `_BCL` (levels) / `_BQC` (current) / `_BCM` (set)
 *
 * Device discovery is firmware-driven: the namespace is scanned for
 * a Method whose leaf is the relevant control method, and the
 * owning device path is used. No hard-coded `\_SB.PCI0...` paths.
 *
 * On QEMU (no battery/AC/lid AML) every reader returns false and
 * the power shell keeps its existing "no battery" answer. Battery
 * methods that touch EC FieldUnits work once AcpiEcInit has
 * registered the EmbeddedControl handler.
 *
 * GAP: mA-based batteries (`_BIF` PowerUnit == 1) are converted to
 * mW using the present/design voltage (approximate). `_BIX` (the
 * extended ACPI 5.0 info packet) is not parsed — `_BIF` only.
 *
 * Context: kernel, process context (the interpreter busy-waits).
 */

namespace duetos::acpi
{

enum class AcpiBatStatus : u8
{
    Unknown = 0,
    NotPresent,
    Charging,
    Discharging,
    Full,
};

struct AcpiBatteryReading
{
    AcpiBatStatus status;
    u8 percent;     // 0..100; 255 = unknown
    i32 rate_mw;    // signed: negative = discharging
    u32 voltage_mv; // 0 = unknown
    u32 design_mwh; // design capacity (mWh)
    u32 full_mwh;   // last-full-charge capacity (mWh)
};

/// Evaluate the first battery device's `_STA`/`_BIF`/`_BST`.
/// Returns false if no battery method is declared or evaluation
/// failed (caller keeps its fallback).
bool AcpiReadBattery(AcpiBatteryReading* out);

/// Evaluate the AC adapter's `_PSR`. `*online` ← (result != 0).
bool AcpiReadAcOnline(bool* online);

/// Evaluate the lid switch's `_LID`. `*open` ← (result != 0).
bool AcpiReadLid(bool* open);

/// Backlight via the ACPI video methods. Levels: `_BCL` package
/// (the leading two AC/battery defaults are skipped — only the
/// real level list is returned). Get/Set: `_BQC`/`_BCM`.
bool AcpiBacklightLevels(u32* levels, u32 cap, u32* count);
bool AcpiBacklightGet(u32* level);
bool AcpiBacklightSet(u32 level);

/// Boot self-test: exercises the namespace scan + decode path and
/// asserts graceful "absent" behaviour on platforms (QEMU) with no
/// power AML. Emits one `[acpi/power] selftest PASS` line.
void AcpiPowerSelfTest();

} // namespace duetos::acpi
