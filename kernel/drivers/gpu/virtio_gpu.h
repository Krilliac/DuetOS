#pragma once

#include "../../core/types.h"

/*
 * DuetOS — virtio-gpu discovery, v0.
 *
 * Modern paravirtualized GPU exposed by QEMU's `-vga virtio` and
 * every virtio-GPU-compatible hypervisor (KVM, Xen HVM, Cloud
 * Hypervisor). Device ID 0x1050 under vendor 0x1AF4 on PCIe.
 *
 * This slice gets only as far as reading the controller's
 * capabilities + common-config region. Queue programming +
 * actual commands (GET_DISPLAY_INFO, RESOURCE_CREATE_2D,
 * SET_SCANOUT, RESOURCE_FLUSH) are the v1 story — a real
 * virtio-gpu driver is roughly the same size as the Bochs VBE
 * driver × 10.
 *
 * What lands here:
 *   - Walk PCI capabilities looking for `vendor-specific` entries
 *     whose `cfg_type` encodes one of the five virtio-pci
 *     structure kinds (common config, notify, ISR, device
 *     config, PCI-access).
 *   - MapMmio the BAR referenced by each found capability so a
 *     future queue-setup slice can reach the register
 *     file without re-walking.
 *   - Read + log num_queues, device_feature[low], device_status
 *     from the common config. Every modern virtio-gpu reports
 *     num_queues == 2 (controlq + cursorq).
 *
 * Context: kernel. `VirtioGpuProbe` runs from the GPU vendor-
 * probe pass in drivers/gpu/gpu.cpp.
 */

namespace duetos::drivers::gpu
{

struct VirtioGpuLayout
{
    bool present;            // detected + capabilities parsed
    volatile u8* common_cfg; // mapped common config region
    volatile u8* notify;     // mapped notify region
    volatile u8* isr;        // mapped ISR region
    volatile u8* device_cfg; // mapped device config region
    u32 notify_off_multiplier;
    u64 common_cfg_phys;
    u64 notify_phys;
    u64 isr_phys;
    u64 device_cfg_phys;
    // Snapshot taken during probe — not kept live.
    u16 num_queues;
    u32 device_features_lo;
    u8 device_status_after_reset;
};

/// Probe a virtio-gpu device given its PCI bus/device/function.
/// Walks capabilities, maps regions, logs. Safe to call multiple
/// times per PCI device — non-destructive.
VirtioGpuLayout VirtioGpuProbe(u8 bus, u8 device, u8 function);

/// Last probe result (for the shell `gpu` command to surface).
/// `present == false` before VirtioGpuProbe runs.
VirtioGpuLayout VirtioGpuLastLayout();

// virtio-gpu v1: controlq + GET_DISPLAY_INFO
//
// virtio-gpu §5.7 defines two virtqueues — controlq (0) for 2D/3D
// commands and cursorq (1) for low-latency cursor moves. To discover
// scanout geometry we only need controlq. v1 scope:
//   - Negotiate features (accept none), flip DRIVER_OK.
//   - Allocate desc/avail/used rings as physically-contiguous pages.
//   - Program queue 0 via common_cfg (queue_desc/driver/device,
//     queue_size, queue_enable).
//   - Build a descriptor chain for VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
//     push it, notify the device, poll the used ring.
//   - Parse the response into `VirtioDisplayInfo`.
//
// Scope (future):
//   - RESOURCE_CREATE_2D + ATTACH_BACKING + SET_SCANOUT +
//     TRANSFER_TO_HOST_2D + RESOURCE_FLUSH — the full blit cycle.
//   - MSI-X interrupt-driven completion (today we poll the used ring).
//   - cursorq for hardware cursor.
//   - virgl 3D path (requires VIRTIO_GPU_F_VIRGL feature + context init).

struct VirtioDisplayRect
{
    u32 x;
    u32 y;
    u32 width;
    u32 height;
};

inline constexpr u32 kVirtioGpuMaxScanouts = 16;

struct VirtioDisplayInfo
{
    bool valid;          // false iff the command did not return RESP_OK_DISPLAY_INFO
    u32 active_scanouts; // number of pmodes with enabled != 0
    VirtioDisplayRect rects[kVirtioGpuMaxScanouts];
    u32 enabled[kVirtioGpuMaxScanouts]; // enabled bit per scanout (0/1)
    u32 flags[kVirtioGpuMaxScanouts];   // vendor flag bits per scanout
};

/// Complete the ACK → DRIVER → FEATURES_OK → queue setup → DRIVER_OK
/// handshake for the last probed virtio-gpu. Returns false if any
/// step fails (device not present, features rejected, queue-size
/// unreasonable, allocator exhausted). Idempotent — skips work if
/// already done.
bool VirtioGpuBringUp();

/// Send VIRTIO_GPU_CMD_GET_DISPLAY_INFO and return a reference to the
/// cached result. Safe to call multiple times — reuses the same
/// request/response pages. `valid == false` if the device didn't
/// respond with RESP_OK_DISPLAY_INFO. Caller must have run
/// `VirtioGpuBringUp()`. Returned reference is valid for the
/// lifetime of the kernel.
const VirtioDisplayInfo& VirtioGpuGetDisplayInfo();

/// Most recent GET_DISPLAY_INFO result (for the shell `gpu` command
/// to surface). `valid == false` before GetDisplayInfo has run.
const VirtioDisplayInfo& VirtioGpuLastDisplayInfo();

} // namespace duetos::drivers::gpu
