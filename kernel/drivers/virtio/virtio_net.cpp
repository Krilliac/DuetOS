#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"

/*
 * virtio-net — network device.
 *
 * Real driver: per-direction virtqueue pair (RX + TX) per
 * configured queue pair. Multi-queue and offload features
 * (checksum / TSO / merged buffers) are advertised on top.
 * The net shim plugs into the existing `drivers/net/net.h`
 * NIC abstraction so `ifconfig` / `dhcp` / `ip` / `ping`
 * surface virtio-net uniformly with e1000.
 *
 * v0 (this file): probe + feature negotiate + log MAC address
 * if exposed; no packet transmit / receive. STUB until shared
 * queue-setup lands.
 */

namespace duetos::drivers::virtio
{

inline constexpr u64 kNetFeatureMac = 1ULL << 5;
inline constexpr u64 kNetFeatureStatus = 1ULL << 16;
inline constexpr u64 kNetFeatureMq = 1ULL << 22;

bool VirtioNetProbe(const VirtioPciLayout& L)
{
    VirtioPciLayout layout = L;
    const u64 dev_features =
        (static_cast<u64>(layout.device_features_hi) << 32) | static_cast<u64>(layout.device_features_lo);
    u64 want = kFeatureVersion1;
    want |= dev_features & (kNetFeatureMac | kNetFeatureStatus | kNetFeatureMq);

    if (!VirtioNegotiate(&layout, want))
    {
        KLOG_WARN("drivers/virtio/net", "feature negotiation failed");
        return false;
    }

    // If the device advertised VIRTIO_NET_F_MAC, the device_cfg
    // page starts with the 6-byte MAC. Read it for observability —
    // the boot log getting a real MAC even before TX/RX is a clear
    // signal that the transport works end-to-end.
    if ((want & kNetFeatureMac) != 0 && layout.device_cfg != nullptr)
    {
        u64 mac = 0;
        for (u32 i = 0; i < 6; ++i)
            mac = (mac << 8) | layout.device_cfg[i];
        KLOG_INFO_V("drivers/virtio/net", "attached (mac in lower 6 bytes)", mac);
    }
    else
    {
        KLOG_INFO_V("drivers/virtio/net", "attached (no MAC feature)", static_cast<u64>(layout.num_queues));
    }
    // STUB: TX / RX virtqueues + packet dispatch. Until shared
    // queue setup + an IRQ wire-up lands, virtio-net does not
    // move frames.
    return true;
}

} // namespace duetos::drivers::virtio
