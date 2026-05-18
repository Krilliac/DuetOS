#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Neural Processing Unit (NPU / AI accelerator), v0.
 *
 * Recent commodity x86_64 SoCs ship a fixed-function inference
 * accelerator on-die, alongside the iGPU:
 *
 *   - Intel "AI Boost" NPU (the ex-Movidius VPU lineage): NPU 3720
 *     on Meteor Lake / Arrow Lake, NPU 4000 on Lunar Lake. Exposed
 *     as its own PCI endpoint under vendor 0x8086.
 *   - AMD XDNA ("Ryzen AI"): the AIE-ML tile on Phoenix / Hawk
 *     Point (XDNA1) and Strix Point (XDNA2), vendor 0x1022.
 *
 * Both present a single PCI endpoint with a large MMIO BAR (the
 * boot/firmware register file plus the command-queue doorbell
 * aperture). A full driver loads signed NPU firmware, sets up a
 * command ring, and submits compiled inference blobs; that is the
 * peer of the GPU driver's command path, not of the Win32 ML
 * runtime — the kernel owns the device, subsystems reach it only
 * through a cap-gated submit syscall (none exists yet).
 *
 * v0 scope (mirrors the MEI PCI scaffold idiom):
 *   - PCI probe. Primary gate is the standards-defined class code
 *     0x12 "Processing Accelerators" (AMD XDNA and any spec-
 *     compliant NPU report this). Intel's NPU mis-reports as a
 *     Multimedia controller, so a documented secondary gate keys
 *     on the known Intel NPU device-ID family.
 *   - Map BAR0 as MMIO (capped) so a future driver can reach the
 *     boot register file without re-running the size probe.
 *   - Inventory behind a stable accessor (`NpuDeviceCount` /
 *     `NpuDevice`).
 *   - Boot-log line per device + the accelerator generation
 *     inferred from (vendor, device-ID).
 *
 * Out of scope (deferred — each its own slice):
 *   - Firmware load + boot handshake.
 *   - Command ring / doorbell / completion IRQ.
 *   - The cap-gated `SYS_*` submit surface and the Win32/Linux
 *     inference-API facades that would route through it.
 *
 * Threading: kernel context only. Probe runs once at boot.
 *
 * Subsystem isolation: freestanding kernel driver. No subsystem
 * (Win32 / Linux ABI) reaches it directly — and none will until
 * the kernel-owned submit gate exists.
 */

namespace duetos::drivers::npu
{

inline constexpr u16 kVendorIntel = 0x8086;
inline constexpr u16 kVendorAmd = 0x1022;

// The PCI-SIG base-class for dedicated inference/compute silicon.
// AMD XDNA reports (0x12, 0x00); Intel's NPU does not (see the
// device-ID secondary gate in npu.cpp).
inline constexpr u8 kPciClassProcessingAccel = 0x12;

inline constexpr u32 kMaxNpuDevices = 4;

enum class NpuKind : u8
{
    Unknown = 0,
    IntelNpu37, // NPU 3720 — Meteor Lake / Arrow Lake
    IntelNpu40, // NPU 4000 — Lunar Lake
    AmdXdna1,   // AIE-ML — Phoenix / Hawk Point
    AmdXdna2,   // AIE-ML v2 — Strix Point
};

struct NpuDeviceInfo
{
    bool live;
    u16 vendor_id;
    u16 device_id;
    u8 bus;
    u8 device;
    u8 function;
    NpuKind kind;
    const char* kind_tag; // "intel-npu37" / "amd-xdna2" / "?"
    u64 mmio_phys;
    u64 mmio_size;
    void* mmio_virt;
};

/// Walk the PCI cache, register every NPU/AI-accelerator device,
/// map each one's primary BAR. Idempotent — early-returns once the
/// inventory is populated.
void NpuInit();

/// Number of NPU devices found.
u32 NpuDeviceCount();

/// Accessor for an NPU record. Panics on out-of-range index.
const NpuDeviceInfo& NpuDevice(u32 index);

/// Map a (vendor, device-ID) pair to a coarse accelerator
/// generation. Returns NpuKind::Unknown for anything the family
/// table does not recognise.
NpuKind NpuClassifyDevice(u16 vendor_id, u16 device_id);

/// Short string for an NpuKind.
const char* NpuKindTag(NpuKind k);

/// True if `device_id` is a known Intel NPU endpoint. Used as the
/// secondary probe gate because Intel's NPU mis-reports its PCI
/// class. AMD XDNA matches the standards class gate instead.
bool NpuIsIntelNpuDeviceId(u16 device_id);

/// Boot self-test. Drives the classifier against known device-IDs
/// and asserts the tag table is wired up. Logs
/// `[npu] selftest pass/fail` and panics on failure.
void NpuSelfTest();

} // namespace duetos::drivers::npu
