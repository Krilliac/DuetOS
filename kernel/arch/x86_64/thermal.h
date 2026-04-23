#pragma once

#include "../../core/types.h"

/*
 * CustomOS — MSR-based CPU thermal readouts, v0.
 *
 * Reads Intel / AMD "digital thermal sensor" MSRs:
 *
 *   IA32_THERM_STATUS (0x19C)
 *     - bit 31   : reading valid
 *     - bits 22:16 : distance from TJMax in °C (unsigned, counts down)
 *     - bit  0   : thermal threshold hit
 *
 *   MSR_TEMPERATURE_TARGET (0x1A2, Intel; optional)
 *     - bits 23:16 : TJMax (°C)
 *     - We default to 100 °C if missing.
 *
 *   IA32_PACKAGE_THERM_STATUS (0x1B1)
 *     - same layout as IA32_THERM_STATUS, but for the whole
 *       package (all cores).
 *
 * Returns absolute Celsius by subtracting the distance from
 * TJMax. Coarse (1 °C resolution) but accurate enough for
 * "am I throttling?" and "what's my thermal envelope?".
 *
 * On QEMU TCG + AMD we get 0 for the reading — the MSRs aren't
 * implemented. The probe surfaces "no thermal data" cleanly
 * instead of faulting.
 *
 * Requires kCpuFeatMsr (CPUID leaf 1 EDX bit 5). Gated by
 * `CpuHas(kCpuFeatMsr)`; if unset, `ThermalRead` returns a
 * record with valid=false.
 *
 * Context: kernel. Non-privileged MSRs; rdmsr in ring 0 is fine.
 */

namespace customos::arch
{

struct ThermalReading
{
    bool valid;         // true iff we got a non-zero reading
    bool core_valid;    // IA32_THERM_STATUS bit 31
    bool package_valid; // IA32_PACKAGE_THERM_STATUS bit 31
    u8 tj_max_c;        // junction-max temp (°C) — often 100
    u8 core_temp_c;     // current core temperature
    u8 package_temp_c;  // package temperature
    bool thermal_throttle_hit;
};

/// Sample the thermal MSRs. Safe at any time once CPUID is up.
/// Returns a zeroed record if the CPU doesn't have MSRs or the
/// sensors aren't reporting.
ThermalReading ThermalRead();

/// Sample once + log a one-line summary. Runs at boot so the
/// boot log shows current thermals. Does nothing if MSR is
/// unavailable; logs a Warn line.
void ThermalProbe();

} // namespace customos::arch
