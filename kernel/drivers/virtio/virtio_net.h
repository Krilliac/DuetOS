#pragma once

#include "drivers/virtio/virtio_pci.h"
#include "util/types.h"

namespace duetos::drivers::virtio
{

namespace virtio_net_contract
{

inline constexpr u32 kRxSlots = 32;
inline constexpr u32 kRxBufferBytes = 2048;
inline constexpr u32 kMinimumFrameBytes = 14;
// Preserve the existing public virtio-net 1518-byte upper bound. The shared
// stack independently applies its standard non-FCS Ethernet RX clamp.
inline constexpr u32 kMaximumFrameBytes = 1518;
inline constexpr u32 kJoinBudgetTicks = 200;

struct NetHeader
{
    u8 flags;
    u8 gso_type;
    u16 header_length;
    u16 gso_size;
    u16 checksum_start;
    u16 checksum_offset;
};
// VIRTIO_NET_F_MRG_RXBUF is deliberately not negotiated. Its num_buffers
// field would extend this otherwise ten-byte header to twelve bytes and would
// require a multi-descriptor reassembly path.
static_assert(sizeof(NetHeader) == 10, "virtio-net header must match the non-MRG_RXBUF wire layout");

enum class RxDisposition : u8
{
    Deliver,
    Drop,
};

struct RxInspection
{
    RxDisposition disposition;
    u32 frame_bytes;
    bool close_admission;
};

constexpr RxInspection InspectRxCompletion(u32 active_slots, u32 descriptor_head, u32 used_bytes)
{
    if (active_slots == 0 || active_slots > kRxSlots || descriptor_head >= active_slots)
        return {RxDisposition::Drop, 0, true};
    if (used_bytes <= sizeof(NetHeader))
        return {RxDisposition::Drop, 0, false};
    const u32 frame_bytes = used_bytes - static_cast<u32>(sizeof(NetHeader));
    if (frame_bytes < kMinimumFrameBytes || frame_bytes > kMaximumFrameBytes || used_bytes > kRxBufferBytes)
        return {RxDisposition::Drop, 0, false};
    return {RxDisposition::Deliver, frame_bytes, false};
}

struct CapabilityFingerprint
{
    u64 bar_address;
    u64 bar_size;
    u64 physical;
    u32 offset;
    u32 length;
    u8 bir;
    u8 capability_offset;
    u8 capability_length;
    bool present;
    bool bar_is_64bit;
    bool bar_is_prefetchable;
};

struct TransportFingerprint
{
    pci::DeviceAddress address;
    u32 vendor_device;
    u32 class_revision;
    u32 subsystem;
    CapabilityFingerprint common;
    CapabilityFingerprint notify;
    CapabilityFingerprint isr;
    CapabilityFingerprint device;
    u32 notify_off_multiplier;
};

constexpr bool SameDeviceAddress(pci::DeviceAddress lhs, pci::DeviceAddress rhs)
{
    return lhs.bus == rhs.bus && lhs.device == rhs.device && lhs.function == rhs.function;
}

constexpr bool SameCapability(const CapabilityFingerprint& lhs, const CapabilityFingerprint& rhs)
{
    return lhs.present == rhs.present &&
           (!lhs.present ||
            (lhs.bar_address == rhs.bar_address && lhs.bar_size == rhs.bar_size && lhs.physical == rhs.physical &&
             lhs.offset == rhs.offset && lhs.length == rhs.length && lhs.bir == rhs.bir &&
             lhs.capability_offset == rhs.capability_offset && lhs.capability_length == rhs.capability_length &&
             lhs.bar_is_64bit == rhs.bar_is_64bit && lhs.bar_is_prefetchable == rhs.bar_is_prefetchable));
}

constexpr bool HeaderIsSupported(const NetHeader& header)
{
    return header.flags == 0 && header.gso_type == 0 && header.header_length == 0 && header.gso_size == 0 &&
           header.checksum_start == 0 && header.checksum_offset == 0;
}

constexpr bool SameTransport(const TransportFingerprint& lhs, const TransportFingerprint& rhs)
{
    return SameDeviceAddress(lhs.address, rhs.address) && lhs.vendor_device == rhs.vendor_device &&
           lhs.class_revision == rhs.class_revision && lhs.subsystem == rhs.subsystem &&
           SameCapability(lhs.common, rhs.common) && SameCapability(lhs.notify, rhs.notify) &&
           SameCapability(lhs.isr, rhs.isr) && SameCapability(lhs.device, rhs.device) &&
           lhs.notify_off_multiplier == rhs.notify_off_multiplier;
}

struct TeardownProof
{
    bool worker_joined;
    bool operations_drained;
    bool stack_unbound;
    bool device_reset;
    bool bus_master_disabled;
};

constexpr bool MayReleaseDma(const TeardownProof& proof)
{
    return proof.worker_joined && proof.operations_drained && proof.stack_unbound && proof.device_reset &&
           proof.bus_master_disabled;
}

} // namespace virtio_net_contract

struct VirtioNetActivation
{
    u8 mac[6];
    bool mac_valid;
    bool link_up;
};

/// Retain one validated modern virtio-net transport for the current immutable
/// PCI/MMIO epoch. Discovery does not bind a stack interface, enable BME,
/// publish queues, start DHCP, or create a worker. v0 intentionally supports
/// one staged function; an exact repeat is idempotent.
bool VirtioNetProbe(const VirtioPciLayout& layout);

/// Activate (or reactivate after quiesce) the staged function on the registry-
/// allocated interface. The expected BDF and full capability/BAR fingerprint
/// are revalidated before any retained MMIO pointer is dereferenced. Output is
/// zeroed on failure and published only after the binding, datapath, admission
/// gate, and worker are all live. Repeating the exact live BDF/interface is
/// idempotent; every other concurrent/live request fails.
bool VirtioNetRestart(pci::DeviceAddress expected_address, u32 iface_index, VirtioNetActivation* out_activation);

/// Send one standard Ethernet frame through the current exact publication.
bool VirtioNetTransmit(const void* frame, u32 len);

/// Explicit task-context teardown. It closes driver admission, joins the RX
/// worker, unbinds the exact stack receipt, resets the device, verifies PCI
/// bus mastering is off, and only then frees queue/DMA frames. A failed proof
/// leaves the stable context quarantined for a later retry.
///
/// GAP: the virtio PCI fabric has no detach callback yet, so surprise removal
/// does not invoke this function automatically. Callers must quiesce before
/// re-probing or removing a known-present device. Quiesce retains the staged
/// transport so a same-epoch VirtioNetRestart can reactivate it without
/// remapping PCI capabilities.
bool VirtioNetQuiesce();

} // namespace duetos::drivers::virtio
