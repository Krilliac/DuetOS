#pragma once

#include "util/types.h"

/*
 * DuetOS — RAPL (Running Average Power Limit) energy/power telemetry, v0.
 *
 * READ-ONLY. This TU reads the RAPL energy + power-info MSRs and
 * decodes them into joules / watts / the TDP envelope. It NEVER writes
 * a RAPL MSR — raising a power limit (MSR_PKG_POWER_LIMIT) without
 * adequate cooling can overheat the package, so per the hardware-safety
 * contract (wiki/security/Hardware-Safety.md) RAPL is read-only
 * telemetry by default; any future limit-*setting* surface must sit
 * behind a kernel capability + an explicit cooling-aware tune mode.
 *
 * Intel (architectural since Sandy Bridge):
 *   MSR_RAPL_POWER_UNIT     (0x606) — power/energy/time unit exponents
 *   MSR_PKG_POWER_INFO      (0x614) — thermal-spec (TDP) / min / max power
 *   MSR_PKG_ENERGY_STATUS   (0x611) — cumulative package energy (32-bit, wraps)
 *   MSR_DRAM_ENERGY_STATUS  (0x619) — cumulative DRAM-domain energy (optional)
 *
 * AMD (Zen / family 17h+; different MSR numbers, same unit layout):
 *   MSR_AMD_RAPL_PWR_UNIT   (0xC0010299)
 *   MSR_AMD_PKG_ENERGY_STAT (0xC001029B)
 *   (AMD exposes no PKG_POWER_INFO, so TDP is reported "unknown".)
 *
 * Gating mirrors thermal.cpp exactly: a `rdmsr` against an MSR the
 * platform does not implement raises #GP that the trap dispatcher does
 * not recover from. Reads are issued only when CpuHas(kCpuFeatMsr) AND
 * the vendor is recognised AND we are NOT under a hypervisor
 * (IsEmulator()) — KVM/TCG do not reliably expose RAPL. On those paths
 * RaplRead() returns valid=false, and the boot probe logs "no data".
 *
 * Context: kernel. Non-privileged MSRs; rdmsr in ring 0 is fine.
 */

namespace duetos::arch
{

struct RaplReading
{
    bool valid;         // true iff a plausible reading was obtained
    bool is_intel;      // which vendor MSR set was used (false ⇒ AMD)
    u8 energy_unit_exp; // EU: energy unit = 1 / 2^EU joules
    u8 power_unit_exp;  // PU: power unit  = 1 / 2^PU watts
    u64 pkg_energy_uj;  // cumulative package energy, microjoules (wraps)
    bool dram_valid;    // DRAM-domain energy present
    u64 dram_energy_uj; // cumulative DRAM energy, microjoules
    bool tdp_valid;     // PKG_POWER_INFO present (Intel only)
    u32 tdp_mw;         // thermal-spec power (TDP), milliwatts
    u32 min_power_mw;   // minimum power envelope, milliwatts
    u32 max_power_mw;   // maximum power envelope, milliwatts
};

/// Sample the RAPL MSRs once. Returns a zeroed record (valid=false)
/// when the CPU lacks MSRs, the vendor is unrecognised, or we are under
/// a hypervisor. Safe at any time once CPUID + CpuInfo are up.
RaplReading RaplRead();

/// Read package energy, busy-wait `window_ms` on the monotonic clock,
/// read again, and return the average package power over the window in
/// milliwatts. Returns 0 when RAPL is unavailable or the window is 0.
/// Intended for interactive use (a shell command) — it spins for the
/// whole window, so keep `window_ms` small (≈200 ms).
u32 RaplSamplePackagePowerMw(u32 window_ms);

/// Sample once + log a one-line summary at boot. Records the energy +
/// timestamp baseline used by average-power callers. No-ops (logs a
/// Debug line) when RAPL is unavailable.
void RaplProbe();

/// Pure-math boot self-test of the unit-decode arithmetic (energy →
/// microjoules, power field → milliwatts). Panics on mismatch so it
/// gates CI; emits one "[rapl-selftest] PASS" line on success. Does not
/// touch hardware, so it runs identically on QEMU and bare metal.
void RaplSelfTest();

} // namespace duetos::arch
