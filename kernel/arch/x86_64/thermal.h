#pragma once

#include "util/types.h"

/*
 * DuetOS — CPU thermal readouts, v1.
 *
 * TWO vendor paths, because the two vendors do not put the sensor in
 * the same place at all.
 *
 * Intel — MSRs, read through `arch::ReadMsrSafe` so an absent MSR is a
 * recovered #GP rather than a wedge:
 *
 *   IA32_THERM_STATUS (0x19C)
 *     - bit 31     : reading valid
 *     - bits 22:16 : distance from TJMax in C (unsigned, counts down)
 *     - bit  0     : thermal threshold hit
 *   MSR_TEMPERATURE_TARGET (0x1A2)
 *     - bits 23:16 : TJMax (C). Defaults to 100 when the MSR is
 *                    absent or reads zero.
 *   IA32_PACKAGE_THERM_STATUS (0x1B1)
 *     - same layout, whole package.
 *
 * AMD — NOT an MSR. Zen reports core temperature through the System
 * Management Network: THM_TCON_CUR_TMP at SMN address 0x00059800,
 * reached via the index/data register pair (PCI config 0x60 / 0x64) on
 * device 0:0.0. Decode lives in `cpu_sensor_math.h`. Family-gated to
 * 17h / 19h / 1Ah — an unrecognised family reports unsupported rather
 * than decoding a register that may not be there.
 *
 * HONESTY CONTRACT. `valid == false` means "this machine has no CPU
 * temperature we can read", which is a DIFFERENT fact from 0 C. A UI
 * must render it as unsupported. `source` says which path answered so
 * a caller can explain why: `tj_max_c` is Intel-only and is 0 (not
 * 100) on the AMD path, because we do not know AMD's junction limit
 * from this register and inventing one would be exactly the lie this
 * header exists to prevent.
 *
 * Context: kernel. The AMD path writes the SMN index register in PCI
 * config space, so it takes a spinlock and must not run from IRQ
 * context. The Intel path is rdmsr-only and is safe anywhere.
 */

namespace duetos::arch
{

enum class ThermalSource : u8
{
    None = 0,     // no readable sensor on this machine
    IntelMsr = 1, // IA32_THERM_STATUS family
    AmdSmn = 2,   // Zen THM_TCON_CUR_TMP via SMN
};

struct ThermalReading
{
    bool valid;            // true iff a real reading was obtained
    ThermalSource source;  // which path answered
    bool core_valid;       // per-core figure present
    bool package_valid;    // package figure present (Intel only)
    bool tj_max_valid;     // `tj_max_c` carries a real junction limit
    u8 tj_max_c;           // junction-max temp (C) — Intel only
    u8 core_temp_c;        // current core temperature (AMD: Tctl)
    u8 package_temp_c;     // package temperature
    bool thermal_throttle_hit;
};

/// Sample the thermal sensors. Returns a zeroed record with
/// `source == None` when this machine exposes none. The vendor probe
/// runs once and is cached, so a repeated call costs one register read
/// and never re-takes a recovered #GP.
ThermalReading ThermalRead();

/// Sample once + log a one-line summary. Runs at boot so the boot log
/// shows current thermals, and prints an explicit "unsupported" line
/// (never a zero) when there is no sensor.
void ThermalProbe();

/// Boot self-test for the decode math and the unsupported-vs-zero
/// invariant. Panics on mismatch; emits one PASS line. Touches the
/// sensor only through `ThermalRead`, so it runs identically on QEMU
/// (where the answer is "unsupported") and on bare metal.
void ThermalSelfTest();

} // namespace duetos::arch
