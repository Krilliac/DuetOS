#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"

/*
 * virtio-net — paravirtualised NIC.
 *
 * Spec: virtio 1.0 §5.1. Single-queue v0: one transmitq
 * (queue 1). Receiveq + multi-queue + checksum/TSO/GSO offload
 * are all advertised on top and ignored in v0 — we negotiate
 * VERSION_1 + MAC + STATUS only.
 *
 * Each TX request is a 2-descriptor chain:
 *
 *   desc[0]  driver-write    virtio_net_hdr (12 B with VERSION_1)
 *   desc[1]  driver-write    Ethernet frame
 *
 * The header is all-zero for plain frames (no offloads
 * negotiated); a single static 12-byte header page is reused
 * for every transmit. The frame buffer is the caller's —
 * `mm::VirtToPhys` resolves its DMA address. Receiveq is GAP
 * (queue 0 unconfigured); the device tolerates that by
 * dropping inbound frames, which matches "TX-only sender" v0
 * semantics.
 *
 * `VirtioNetTransmit(buf, len)` is the public surface — a
 * future NIC-registration slice can plug it into
 * `kernel/drivers/net/net.h` so `NetTransmit` routes here.
 */

namespace duetos::drivers::virtio
{

inline constexpr u64 kNetFeatureMac = 1ULL << 5;
inline constexpr u64 kNetFeatureStatus = 1ULL << 16;
inline constexpr u64 kNetFeatureMq = 1ULL << 22;

namespace
{

// virtio_net_hdr layout with VERSION_1 negotiated (virtio 1.0
// §5.1.6). 12 bytes. All-zero for the no-offload TX path.
struct NetHdr
{
    u8 flags;
    u8 gso_type;
    u16 hdr_len;
    u16 gso_size;
    u16 csum_start;
    u16 csum_offset;
    u16 num_buffers;
};

struct NetState
{
    bool up;
    u8 mac[6];
    u8 _pad;
    VirtioPciLayout layout;
    VirtioQueue txq;
    mm::PhysAddr hdr_phys;
    u8* hdr_virt;
};

constinit NetState g_net = {};

void DrainTxUsed(VirtioQueue* q)
{
    u32 head = 0;
    u32 used_len = 0;
    while (VirtioQueueTryPop(q, &head, &used_len))
    {
        // Discard.
    }
}

} // namespace

bool VirtioNetProbe(const VirtioPciLayout& L)
{
    if (g_net.up)
    {
        KLOG_WARN("drivers/virtio/net", "second device detected; v0 supports only one");
        return false;
    }

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
    if (layout.num_queues < 2)
    {
        KLOG_WARN_V("drivers/virtio/net", "device exposes too few queues", static_cast<u64>(layout.num_queues));
        return false;
    }

    // queue_index 1 = transmitq. queue 0 = receiveq (unconfigured
    // in TX-only v0; the device drops inbound frames).
    if (!VirtioQueueSetup(&layout, &g_net.txq, /*queue_index=*/1, kVirtqDefaultSize))
    {
        KLOG_WARN("drivers/virtio/net", "transmitq setup failed");
        return false;
    }

    const mm::PhysAddr phys = mm::AllocateFrame();
    if (phys == mm::kNullFrame)
    {
        KLOG_WARN("drivers/virtio/net", "header page alloc failed");
        return false;
    }
    g_net.hdr_phys = phys;
    g_net.hdr_virt = static_cast<u8*>(mm::PhysToVirt(phys));
    auto* h = reinterpret_cast<NetHdr*>(g_net.hdr_virt);
    *h = NetHdr{};

    if ((want & kNetFeatureMac) != 0 && layout.device_cfg != nullptr)
    {
        for (u32 i = 0; i < 6; ++i)
            g_net.mac[i] = layout.device_cfg[i];
    }
    g_net.layout = layout;
    g_net.up = true;

    u64 mac_packed = 0;
    for (u32 i = 0; i < 6; ++i)
        mac_packed = (mac_packed << 8) | g_net.mac[i];
    KLOG_INFO_V("drivers/virtio/net", "attached (TX-only, mac in lower 6 bytes)", mac_packed);
    // GAP: receiveq + per-frame RX dispatch + NIC registration
    // against `drivers/net/net.h`. `VirtioNetTransmit` is
    // reachable today but inbound packets are dropped at the
    // device.
    return true;
}

bool VirtioNetTransmit(const void* frame, u32 len)
{
    if (!g_net.up || frame == nullptr || len == 0 || len > 1518)
        return false;

    DrainTxUsed(&g_net.txq);

    const mm::PhysAddr data_phys = mm::VirtToPhys(frame);
    if (data_phys == 0)
        return false;

    VirtqDesc* d = const_cast<VirtqDesc*>(g_net.txq.desc);
    d[0].addr = g_net.hdr_phys;
    d[0].len = sizeof(NetHdr);
    d[0].flags = kVirtqDescNext;
    d[0].next = 1;
    d[1].addr = data_phys;
    d[1].len = len;
    d[1].flags = 0; // driver-write only — device reads our frame.
    d[1].next = 0;

    VirtioQueuePublish(&g_net.layout, &g_net.txq, /*desc_head=*/0);
    for (u32 spin = 0; spin < 2000000; ++spin)
    {
        u32 head = 0;
        u32 used_len = 0;
        if (VirtioQueueTryPop(&g_net.txq, &head, &used_len))
            return true;
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/virtio/net", "TX completion poll timed out");
    return false;
}

} // namespace duetos::drivers::virtio
