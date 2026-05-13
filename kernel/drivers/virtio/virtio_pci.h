#pragma once

#include "drivers/pci/pci.h"
#include "util/types.h"

/*
 * DuetOS — shared VirtIO 1.0 PCI transport.
 *
 * The virtio-gpu driver currently carries its own inline copy of
 * this transport code (kernel/drivers/gpu/virtio_gpu.cpp). The
 * goal of this header is to host the canonical version that the
 * net / block / rng / console / balloon drivers (and, when the
 * refactor is cheap, virtio-gpu itself) share. The 1.0 modern
 * PCI device + capability layout is fixed by the spec and the
 * same for every device class.
 *
 * Public surface:
 *   - VirtioPciLayout  — pointers + phys addresses for the four
 *                        BAR-mapped config regions of a virtio
 *                        device (common / notify / isr / device).
 *   - VirtioPciProbe   — walk a PCI device's caps list, map each
 *                        cap region, reset + ack the device,
 *                        snapshot num_queues + device_features.
 *   - VirtioNegotiate  — drive the FEATURES_OK + DRIVER_OK status
 *                        bits with a caller-supplied feature mask.
 *   - VirtioDeviceIdFor*  — convenience: the modern (0x1040+id)
 *                        and transitional device IDs by class.
 *
 * Queue-setup helpers (descriptor / avail / used pages, queue
 * select, notify) are pending — see `kernel/drivers/virtio/`
 * follow-on slices. v0 hosts the probe + status path so the
 * per-device drivers can come online behind a single transport.
 *
 * Context: kernel. Probe runs from boot; no IRQ context. Status
 * MMIO writes use volatile + explicit ordering.
 */

namespace duetos::drivers::virtio
{

// Red Hat / QEMU VirtIO PCI vendor ID. Every modern virtio device
// (transitional or modern) sits behind this vendor.
inline constexpr u16 kVirtioVendorId = 0x1AF4;

// Modern device-id base (virtio 1.0 §4.1.2.1).
//   device-id = kVirtioDeviceIdBase + virtio_subsystem_id
inline constexpr u16 kVirtioDeviceIdBase = 0x1040;

// Per-class virtio subsystem IDs (virtio 1.0 §5).
enum class VirtioClass : u16
{
    kInvalid = 0,
    kNetwork = 1,
    kBlock = 2,
    kConsole = 3,
    kEntropy = 4,
    kBalloon = 5,
    kScsi = 8,
    kGpu = 16,
    kInput = 18,
    kSocket = 19,
};

// Common-config status bits (virtio 1.0 §2.1).
inline constexpr u8 kStatusAck = 0x01;
inline constexpr u8 kStatusDriver = 0x02;
inline constexpr u8 kStatusDriverOk = 0x04;
inline constexpr u8 kStatusFeaturesOk = 0x08;
inline constexpr u8 kStatusFailed = 0x80;

// Common-config feature bits shared by every device (virtio 1.0
// §6). Per-device feature bits sit below 32.
inline constexpr u64 kFeatureVersion1 = 1ULL << 32;

struct VirtioPciLayout
{
    pci::DeviceAddress addr;

    volatile u8* common_cfg;
    u64 common_cfg_phys;
    volatile u8* notify;
    u64 notify_phys;
    u32 notify_off_multiplier;
    volatile u8* isr;
    u64 isr_phys;
    volatile u8* device_cfg;
    u64 device_cfg_phys;

    // Snapshot taken after the reset + ack + driver bits land.
    u16 num_queues;
    u32 device_features_lo;
    u32 device_features_hi;
    u8 device_status_after_reset;

    // True iff the device responded to the probe + we successfully
    // mapped its common_cfg + read its features. False means the
    // probe found a virtio-marked PCI function but couldn't bring
    // it past the reset stage — caller skips it.
    bool present;

    // The detected virtio subsystem class. Filled from the
    // device's PCI device_id when it matches the modern range
    // (0x1040 + N). Older transitional devices use 0x1000..0x103F
    // and the class has to be inferred elsewhere — they aren't
    // supported by this v0 transport.
    VirtioClass cls;
};

/// Probe a PCI device address for VirtIO. Walks the capabilities
/// list, maps the four cfg regions through `mm::MapMmio`, resets
/// the device, sets ACK + DRIVER status bits, and snapshots
/// num_queues + device_features (low + high halves). Returns a
/// layout with `present=true` on success.
VirtioPciLayout VirtioPciProbe(pci::DeviceAddress addr);

/// Negotiate `driver_features` with the device. Writes the
/// requested mask + sets FEATURES_OK; on success sets DRIVER_OK
/// and returns true. Caller must include `kFeatureVersion1` to
/// stay on the modern path. Returns false if the device clears
/// FEATURES_OK (i.e. it doesn't accept the offered subset).
bool VirtioNegotiate(VirtioPciLayout* L, u64 driver_features);

/// Map a virtio class enum to the modern PCI device-id (virtio
/// 1.0). Transitional IDs are NOT covered.
inline u16 VirtioModernDeviceId(VirtioClass c)
{
    return static_cast<u16>(kVirtioDeviceIdBase + static_cast<u16>(c));
}

/// Map a PCI device-id back to a virtio class. Returns
/// `kInvalid` for non-modern IDs.
VirtioClass VirtioClassFromDeviceId(u16 device_id);

/// Short human-readable name for a virtio class, used in boot
/// log lines. Returns "unknown" for `kInvalid` / unsupported.
const char* VirtioClassName(VirtioClass c);

} // namespace duetos::drivers::virtio
