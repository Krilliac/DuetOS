#pragma once

#include "../../core/result.h"
#include "../../core/types.h"

/*
 * DuetOS — GPU discovery layer, v0.
 *
 * Walks the PCI device cache after `PciEnumerate()` has run, picks
 * out display-class controllers (class_code == 0x03), classifies
 * them by vendor, reads + maps their primary MMIO BAR, and logs
 * each finding. This is the single-slice entry point for the three
 * tier-1 GPU families (Intel iGPU, AMD Radeon, NVIDIA GeForce) and
 * the dev-tier emulated devices (QEMU Bochs, virtio-gpu).
 *
 * Scope (v0):
 *   - Discovery + classification only. No command-ring setup, no
 *     modeset, no surface allocation, no IRQ routing.
 *   - BAR 0 is mapped as MMIO into the kernel MMIO arena so a
 *     future driver can reach vendor-specific registers without
 *     re-running the size probe.
 *   - Up to kMaxGpus devices are tracked (typical: 1; multi-GPU
 *     workstations: 2-4).
 *
 * Out of scope — deferred to vendor-specific follow-on slices:
 *   - GFX/display engine init, ring setup, power management.
 *   - Kernel-side command submission (DRM-style submit interface).
 *   - User-mode API (Vulkan ICD, D3D translation).
 *   - Interrupt handling (MSI/MSI-X table programming).
 *
 * The tier mapping matches
 * `docs/knowledge/hardware-target-matrix.md`. Any device that
 * doesn't match a known vendor lands in the "unknown" tier — it's
 * still logged so the boot log documents the gap.
 *
 * Context: kernel. `GpuInit` runs once at boot after `PciEnumerate`.
 * Accessors are read-only after.
 */

namespace duetos::drivers::gpu
{

// Vendor IDs. Covers the tier-1 real GPUs + tier-3 emulation.
// Reference: pci-ids.ucw.cz / PCI SIG.
inline constexpr u16 kVendorIntel = 0x8086;
inline constexpr u16 kVendorAmd = 0x1002;
inline constexpr u16 kVendorNvidia = 0x10DE;
inline constexpr u16 kVendorVmware = 0x15AD;     // svga ii
inline constexpr u16 kVendorQemuBochs = 0x1234;  // QEMU -vga std
inline constexpr u16 kVendorRedHatVirt = 0x1AF4; // virtio-gpu

// PCI class code for display controllers; every GPU uses this.
// Subclass values: 0x00=VGA, 0x01=XGA, 0x02=3D, 0x80=other.
inline constexpr u8 kPciClassDisplay = 0x03;

inline constexpr u64 kMaxGpus = 4;

struct GpuInfo
{
    u16 vendor_id;
    u16 device_id;
    u8 bus;
    u8 device;
    u8 function;
    u8 subclass;        // 0x00 VGA, 0x02 3D, ...
    const char* vendor; // short string ("Intel", "AMD", "QEMU-Bochs", ...)
    const char* tier;   // "tier1", "tier3-dev", "unknown"
    const char* family; // vendor probe result ("gen9-skylake", ...) or nullptr
    u64 mmio_phys;      // BAR 0 physical base
    u64 mmio_size;      // BAR 0 size in bytes
    void* mmio_virt;    // kernel-mapped aperture, nullptr if not mapped

    // Register-level probe result. Populated by `RunVendorProbe`
    // after the BAR is mapped. What goes in `probe_reg` depends on
    // vendor: NVIDIA = PMC_BOOT_0 (BAR0+0); Intel = BAR0 dword 0
    // (architecture-specific; currently just a liveness read); AMD
    // GFX9+ = 0 (registers live at BAR5, not mapped in v0). All
    // other vendors leave it 0.
    u32 probe_reg;
    bool mmio_live;   // true iff BAR0 MMIO read returned != 0xFFFFFFFF
    const char* arch; // decoded architecture name (NVIDIA only today), or nullptr
};

/// Discover every display-class PCI device, map each one's primary
/// MMIO BAR, and log the result. Idempotent — early-returns until
/// `GpuShutdown` clears the live flag.
void GpuInit();

/// Drop every GPU record + clear the live flag so the next
/// `GpuInit` re-walks PCI. Always succeeds. MMIO mappings are
/// retained (same v0 trade-off as drivers/net).
::duetos::core::Result<void> GpuShutdown();

/// Count of GPUs found by the most recent `GpuInit` call.
u64 GpuCount();

/// Accessor for a discovered GPU record. Panics if `index >= GpuCount()`.
const GpuInfo& Gpu(u64 index);

// -------------------------------------------------------------------
// Vendor-specific probe stubs. Each `*Probe(info)` is called by
// `GpuInit` for every discovered device whose vendor matches — the
// stub inspects the device_id, names the GPU family, and logs
// "probe OK" with the generation tag. No driver logic yet; a real
// vendor driver slice will replace the probe with actual init
// (ring setup, power management, modeset, interrupt wiring).
//
// Grouping by function rather than per-file keeps the v0 surface
// minimal — one file per driver namespace lives under
// `kernel/drivers/gpu/<vendor>/` when that vendor's driver grows
// past a page of code.
// -------------------------------------------------------------------

/// Classify an Intel iGPU by device_id. Returns the family tag
/// ("gen9-skylake", "gen11-icelake", ...) or "unknown-intel-gpu".
/// Pure string lookup; no register pokes.
const char* IntelGenTag(u16 device_id);

/// Classify an AMD Radeon by device_id. GFX9 / GFX10 / GFX11 tags.
const char* AmdGenTag(u16 device_id);

/// Classify an NVIDIA GPU by device_id. Turing / Ampere / Ada tags.
const char* NvidiaGenTag(u16 device_id);

} // namespace duetos::drivers::gpu
