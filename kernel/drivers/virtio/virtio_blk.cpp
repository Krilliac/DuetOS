#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"

/*
 * virtio-blk — block device.
 *
 * Real driver: a single requestq virtqueue. Each request is a
 * three-descriptor chain (header + data + status). The block
 * shim plugs into the existing `drivers/storage/block.h`
 * BlockDevice abstraction so VFS / lsblk / install / mkfs all
 * see virtio-blk uniformly with NVMe / AHCI / xHCI-MSC.
 *
 * v0 (this file): probe + feature negotiate + log; no requests
 * dispatched. STUB until shared queue-setup lands.
 */

namespace duetos::drivers::virtio
{

// VIRTIO_BLK_F_* — driver opts into a small set. SEG_MAX +
// BLK_SIZE + RO are the ones the read/write path uses.
inline constexpr u64 kBlkFeatureSegMax = 1ULL << 2;
inline constexpr u64 kBlkFeatureGeometry = 1ULL << 4;
inline constexpr u64 kBlkFeatureRo = 1ULL << 5;
inline constexpr u64 kBlkFeatureBlkSize = 1ULL << 6;

bool VirtioBlkProbe(const VirtioPciLayout& L)
{
    VirtioPciLayout layout = L;
    // Only ask for features the device offered, intersected with
    // what we know how to obey today. Geometry / blk_size are
    // informational — if the device advertises them, opt in so the
    // device-cfg page parses correctly; otherwise stay out.
    u64 want = kFeatureVersion1;
    const u64 dev_features =
        (static_cast<u64>(layout.device_features_hi) << 32) | static_cast<u64>(layout.device_features_lo);
    want |= dev_features & (kBlkFeatureSegMax | kBlkFeatureGeometry | kBlkFeatureRo | kBlkFeatureBlkSize);

    if (!VirtioNegotiate(&layout, want))
    {
        KLOG_WARN("drivers/virtio/blk", "feature negotiation failed");
        return false;
    }
    KLOG_INFO_V("drivers/virtio/blk", "attached (no requests dispatched yet)", static_cast<u64>(layout.num_queues));
    // STUB: read/write request dispatch. A real driver reads the
    // capacity (8-byte u64 at device_cfg + 0) into a BlockDevice
    // registration, then hands every BlockDeviceRead / Write
    // through a virtqueue request chain. Until queue setup lands
    // in the shared transport, virtio-blk is observe-only.
    return true;
}

} // namespace duetos::drivers::virtio
