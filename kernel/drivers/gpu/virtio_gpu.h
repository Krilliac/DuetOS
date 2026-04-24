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

} // namespace duetos::drivers::gpu
