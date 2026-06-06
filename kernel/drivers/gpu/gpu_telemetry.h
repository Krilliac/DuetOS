#pragma once

#include "util/types.h"

/*
 * DuetOS — GPU clock / temperature telemetry reader, v0.
 *
 * READ-ONLY. Reports GPU identity (vendor/device/family) and, on Intel
 * Gen9+ with a live MMIO aperture, the raw GT P-state register
 * (GEN6_RPSTAT1 at BAR0+0xA01C). It writes no GPU register — clock /
 * voltage / fan programming is a physical-damage surface
 * (wiki/security/Hardware-Safety.md), so this is telemetry only.
 *
 * GAPs (v0, deliberate):
 *   - The RPSTAT1 → MHz conversion is gen-specific (the CAGF field
 *     shift/mask and the GT-frequency multiplier differ across Gen6..
 *     Gen13). v0 reports the raw register + a best-effort Gen9+ CAGF
 *     estimate, flagged separately; trust the raw value, treat the MHz
 *     as approximate until per-gen decode lands.
 *   - GPU temperature is not read on any vendor (Intel thermal regs,
 *     AMD SMU, NVIDIA GSP all deferred) — temp_valid is always false.
 *   - AMD (registers at BAR5, SMU-mediated) and NVIDIA (GSP RPC) report
 *     no frequency.
 *
 * Under QEMU the default display is bochs-vga (1234:1111) with no P-state
 * register, so rpstat_valid is false there.
 *
 * Context: kernel.
 */

namespace duetos::drivers::gpu
{

struct GpuTelemetryReading
{
    bool valid;         // a GPU exists at the queried index
    u16 vendor_id;      // 0x8086 Intel, 0x1002 AMD, 0x10DE NVIDIA, 0x1234 QEMU
    u16 device_id;      //
    const char* vendor; // short vendor string
    const char* family; // vendor probe result or nullptr
    bool mmio_live;     // BAR0 MMIO returned a non-0xFFFFFFFF liveness read
    bool is_intel;      //
    bool rpstat_valid;  // Intel + live + RPSTAT1 != 0xFFFFFFFF
    u32 rpstat_raw;     // raw GEN6_RPSTAT1 dword (Intel)
    u32 freq_mhz_est;   // GAP: best-effort Gen9+ CAGF→MHz, 0 if !rpstat_valid
    bool temp_valid;    // GAP: always false in v0
    u32 temp_c;         // GAP: always 0
};

/// GAP: best-effort Gen9+ current-frequency decode. Extracts the CAGF
/// field (bits 31:23) of GEN6_RPSTAT1 and scales by the Gen9 GT step
/// (50/3 ≈ 16.67 MHz per CAGF unit). Exact on Gen9..Gen11; approximate
/// elsewhere. Exposed for the self-test.
u32 GpuIntelCagfToMhz(u32 rpstat1);

/// Read GPU telemetry at registry index `index`. Zeroed (valid=false)
/// when index is out of range.
GpuTelemetryReading GpuTelemetryRead(u64 index);

/// Log a one-line summary per discovered GPU at boot.
void GpuTelemetryProbe();

/// Pure-math self-test of the CAGF→MHz extraction. Panics on mismatch;
/// emits one "[gpu-telemetry-selftest] PASS" line.
void GpuTelemetrySelfTest();

} // namespace duetos::drivers::gpu
