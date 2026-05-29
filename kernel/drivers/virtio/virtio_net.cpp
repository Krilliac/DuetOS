#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "drivers/net/net.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "net/stack.h"
#include "sched/sched.h"

/*
 * virtio-net — paravirtualised NIC.
 *
 * Spec: virtio 1.0 §5.1. v0 wires receiveq (queue 0) + transmitq
 * (queue 1); multi-queue / checksum / TSO / GSO offload are
 * advertised on top and ignored — we negotiate VERSION_1 + MAC +
 * STATUS, plus MQ-advertised-only when offered (we still only
 * drive the queue 0/1 pair).
 *
 * Each TX request is a 2-descriptor chain:
 *
 *   desc[0]  driver-write    virtio_net_hdr (12 B with VERSION_1)
 *   desc[1]  driver-write    Ethernet frame
 *
 * The header is all-zero for plain frames (no offloads
 * negotiated); a single static 12-byte header page is reused
 * for every transmit. The caller's frame is copied into a
 * pre-allocated direct-map TX staging page (the net stack's
 * reply frames are not guaranteed to be direct-map-resolvable
 * via `mm::VirtToPhys`); the device DMAs from the staging
 * page, mirroring e1000's `E1000Send` contract.
 *
 * Each RX slot owns one 2 KiB device-write buffer big enough to
 * hold the 12-byte virtio_net_hdr + max-size Ethernet frame. We
 * carve 16 contiguous 4 KiB frames into 32 buffers and pre-post
 * all 32 to the receiveq at probe time. The drain helper pops
 * completed buffers, hands them to the kernel net stack via
 * `NetStackInjectRx`, and re-publishes the descriptor.
 *
 * `VirtioNetTransmit(buf, len)` is the public TX surface; the
 * `VirtioNetTxTrampoline` adapter routes it as a `NetTxFn` so
 * `NetStackBindInterface` wires the device into the same iface
 * table e1000 / cdc_ecm use. IRQ wire-up is the next slice —
 * v0 polls the receiveq from a dedicated kernel task at 10 ms
 * cadence.
 */

namespace duetos::drivers::virtio
{

inline constexpr u64 kNetFeatureMac = 1ULL << 5;
inline constexpr u64 kNetFeatureStatus = 1ULL << 16;
inline constexpr u64 kNetFeatureMq = 1ULL << 22;

namespace
{

// virtio_net_hdr layout with VERSION_1 negotiated (virtio 1.0
// §5.1.6). 12 bytes. All-zero for the no-offload TX path; on RX
// the device fills it in and the driver skips past it before
// handing the frame up the stack.
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

// RX-buffer geometry. 32 slots × 2048 bytes = 64 KiB across 16
// physical frames. Each buffer holds one virtio_net_hdr (12 B)
// + up to 2036 bytes of Ethernet frame — well past the 1518-byte
// Ethernet max so a future jumbo-frame slice can grow without
// reshuffling the layout.
inline constexpr u32 kRxSlots = 32;
inline constexpr u32 kRxBufBytes = 2048;
inline constexpr u32 kRxBuffersPerFrame = static_cast<u32>(mm::kPageSize / kRxBufBytes);
static_assert(kRxBuffersPerFrame > 0, "page size must hold at least one RX buffer");
static_assert(kRxSlots % kRxBuffersPerFrame == 0, "RX slot count must divide evenly into frames");
inline constexpr u32 kRxFrames = kRxSlots / kRxBuffersPerFrame;

// Polling cadence for the RX-drain task: one scheduler tick =
// 10 ms at 100 Hz. Matches the cdc_ecm RX rhythm; e1000 polls
// faster because it can also block on a wait queue when IRQs
// fire. v0 virtio-net has no IRQ wire-up.
inline constexpr u32 kRxPollSleepTicks = 1;
inline constexpr u32 kRxPollBudget = 16;

// Pick the iface_index after the two existing drivers:
//   0 = e1000 (kernel/drivers/net/net.cpp)
//   1 = cdc_ecm (kernel/drivers/usb/cdc_ecm.cpp)
//   2 = virtio-net (this driver)
// kMaxInterfaces in net/stack.cpp is 4, leaving slot 3 for the
// next NIC to land.
inline constexpr u32 kVirtioNetIfaceIndex = 2;

struct NetState
{
    bool up;
    u8 mac[6];
    u8 _pad;
    VirtioPciLayout layout;
    VirtioQueue txq;
    VirtioQueue rxq;
    mm::PhysAddr hdr_phys;
    u8* hdr_virt;
    // TX DMA staging buffer. The net stack hands `IfaceTx` reply
    // frames built in transient buffers that are NOT guaranteed
    // to be in the kernel direct map, so we cannot resolve the
    // caller's pointer through `mm::VirtToPhys` (it panics on a
    // non-direct-map address). Mirror the e1000 driver: copy the
    // caller's frame into this pre-allocated, direct-map staging
    // page and DMA from there. One frame at a time matches the
    // single-in-flight TX model.
    mm::PhysAddr tx_buf_phys;
    u8* tx_buf_virt;
    // RX-buffer phys / virt for every slot. Indexed by descriptor
    // id; the device returns `head == slot` on completion because
    // every RX descriptor is a single-buffer chain.
    mm::PhysAddr rx_buf_phys[kRxSlots];
    u8* rx_buf_virt[kRxSlots];
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

// Publish one RX descriptor as a single-buffer device-write chain.
// `idx` doubles as both the descriptor index and the buffer slot
// id — the device's used-ring `head` lookup goes straight back to
// rx_buf_virt[idx].
void NetRxPostDesc(u16 idx)
{
    VirtqDesc* d = const_cast<VirtqDesc*>(g_net.rxq.desc);
    d[idx].addr = g_net.rx_buf_phys[idx];
    d[idx].len = kRxBufBytes;
    d[idx].flags = kVirtqDescWrite;
    d[idx].next = 0;
    VirtioQueuePublish(&g_net.layout, &g_net.rxq, idx);
}

// TX entry point shaped as a `net::NetTxFn` so
// `NetStackBindInterface` can plug it into the iface table. The
// stack already enforces firewall + counters before reaching this
// trampoline, so the call is unconditional.
bool VirtioNetTxTrampoline(u32 iface_index, const void* frame, u64 len)
{
    (void)iface_index;
    if (len == 0 || len > 0xFFFFFFFFULL)
        return false;
    return VirtioNetTransmit(frame, static_cast<u32>(len));
}

// RX drain — pop every completion the device handed us up to
// `budget`, inject each frame into the kernel net stack, and
// re-publish the descriptor so the buffer is available for the
// next packet. Single-CPU v0; no locking required.
u32 NetDrainRx(u32 budget)
{
    if (!g_net.up)
        return 0;
    u32 drained = 0;
    while (drained < budget)
    {
        u32 head = 0;
        u32 used_len = 0;
        if (!VirtioQueueTryPop(&g_net.rxq, &head, &used_len))
            break;
        if (head < kRxSlots && used_len > sizeof(NetHdr))
        {
            const u8* buf = g_net.rx_buf_virt[head];
            const u32 frame_len = used_len - static_cast<u32>(sizeof(NetHdr));
            duetos::net::NetStackInjectRx(kVirtioNetIfaceIndex, buf + sizeof(NetHdr), frame_len);
        }
        if (head < kRxSlots)
            NetRxPostDesc(static_cast<u16>(head));
        ++drained;
    }
    return drained;
}

// Dedicated RX-poll task. Mirrors the e1000 pattern but without
// the MSI-X wait-queue branch — virtio-net IRQ wiring is the
// next slice. The 10 ms sleep matches the receiveq's typical
// drain cadence under QEMU SLIRP / vhost-net and keeps the CPU
// out of a busy-poll when no traffic is arriving.
void VirtioNetRxPollEntry(void*)
{
    for (;;)
    {
        const u32 drained = NetDrainRx(kRxPollBudget);
        if (drained == kRxPollBudget)
            continue;
        duetos::sched::SchedSleepTicks(kRxPollSleepTicks);
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

    // queue 0 = receiveq, queue 1 = transmitq. Set up both before
    // posting anything; the device sees a fully-configured driver
    // by the time we mark DRIVER_OK.
    if (!VirtioQueueSetup(&layout, &g_net.rxq, /*queue_index=*/0, kRxSlots))
    {
        KLOG_WARN("drivers/virtio/net", "receiveq setup failed");
        return false;
    }
    if (!VirtioQueueSetup(&layout, &g_net.txq, /*queue_index=*/1, kVirtqDefaultSize))
    {
        KLOG_WARN("drivers/virtio/net", "transmitq setup failed");
        return false;
    }

    // Spec §3.1.1 step 8 — both queues are up, finalise the device.
    VirtioMarkDriverOk(&layout);

    // TX header page (12 bytes, all-zero, reused across transmits).
    auto hdr_phys_r = mm::AllocateFrame();
    if (!hdr_phys_r)
    {
        KLOG_WARN("drivers/virtio/net", "header page alloc failed");
        return false;
    }
    const mm::PhysAddr hdr_phys = hdr_phys_r.value();
    g_net.hdr_phys = hdr_phys;
    g_net.hdr_virt = static_cast<u8*>(mm::PhysToVirt(hdr_phys));
    auto* h = reinterpret_cast<NetHdr*>(g_net.hdr_virt);
    *h = NetHdr{};

    // TX DMA staging page. One 4 KiB frame holds any single
    // Ethernet frame (max 1518 B) with room to spare. The TX
    // path copies the caller's frame here, then DMAs from this
    // direct-map address — never from the caller's pointer.
    auto tx_phys_r = mm::AllocateFrame();
    if (!tx_phys_r)
    {
        KLOG_WARN("drivers/virtio/net", "TX staging page alloc failed");
        return false;
    }
    const mm::PhysAddr tx_phys = tx_phys_r.value();
    g_net.tx_buf_phys = tx_phys;
    g_net.tx_buf_virt = static_cast<u8*>(mm::PhysToVirt(tx_phys));

    // RX buffers: kRxFrames physical frames, each carved into
    // kRxBuffersPerFrame buffers. Slot id `f * per + b` resolves to
    // a buffer inside frame `f` at offset `b * kRxBufBytes`.
    for (u32 f = 0; f < kRxFrames; ++f)
    {
        auto phys_r = mm::AllocateFrame();
        if (!phys_r)
        {
            KLOG_WARN_V("drivers/virtio/net", "RX buffer frame alloc failed at frame", static_cast<u64>(f));
            return false;
        }
        const mm::PhysAddr phys = phys_r.value();
        u8* virt = static_cast<u8*>(mm::PhysToVirt(phys));
        for (u32 b = 0; b < kRxBuffersPerFrame; ++b)
        {
            const u32 slot = f * kRxBuffersPerFrame + b;
            g_net.rx_buf_phys[slot] = phys + b * kRxBufBytes;
            g_net.rx_buf_virt[slot] = virt + b * kRxBufBytes;
        }
    }

    if ((want & kNetFeatureMac) != 0 && layout.device_cfg != nullptr)
    {
        for (u32 i = 0; i < 6; ++i)
            g_net.mac[i] = layout.device_cfg[i];
    }
    g_net.layout = layout;
    g_net.up = true;

    // Pre-fill every RX descriptor. From this moment the device
    // can write inbound frames into our buffers; the drain task
    // (spawned below) pops the used ring on a 10 ms cadence.
    for (u16 i = 0; i < kRxSlots; ++i)
        NetRxPostDesc(i);

    // Register with the kernel net stack. Iface 2 is the
    // virtio-net slot (see kVirtioNetIfaceIndex). Bind with
    // 0.0.0.0 so DHCP DISCOVER goes out with the correct src.
    duetos::net::MacAddress mac{};
    for (u64 i = 0; i < 6; ++i)
        mac.octets[i] = g_net.mac[i];
    duetos::net::Ipv4Address ip{{0, 0, 0, 0}};
    duetos::net::NetStackBindInterface(kVirtioNetIfaceIndex, mac, ip, &VirtioNetTxTrampoline);
    duetos::net::DhcpStart(kVirtioNetIfaceIndex);

    // Spawn the RX-drain task. The thread runs for the lifetime
    // of the kernel; no graceful shutdown today (virtio-net never
    // hot-unplugs in QEMU).
    duetos::sched::SchedCreate(VirtioNetRxPollEntry, nullptr, "virtio-net-rx-poll");

    u64 mac_packed = 0;
    for (u32 i = 0; i < 6; ++i)
        mac_packed = (mac_packed << 8) | g_net.mac[i];
    KLOG_INFO_V("drivers/virtio/net", "attached (RX+TX, iface=2, mac in lower 6 bytes)", mac_packed);
    return true;
}

bool VirtioNetTransmit(const void* frame, u32 len)
{
    if (!g_net.up || frame == nullptr || len == 0 || len > 1518)
        return false;

    DrainTxUsed(&g_net.txq);

    // Copy the caller's frame into the direct-map TX staging
    // page. The net stack's IfaceTx path builds reply frames
    // (ARP / ICMP / TCP) in transient buffers that are not
    // guaranteed to live in the kernel direct map; resolving
    // such a pointer through mm::VirtToPhys panics. Staging +
    // copy is the same contract e1000's E1000Send uses.
    const u8* src = static_cast<const u8*>(frame);
    for (u32 i = 0; i < len; ++i)
        g_net.tx_buf_virt[i] = src[i];

    VirtqDesc* d = const_cast<VirtqDesc*>(g_net.txq.desc);
    d[0].addr = g_net.hdr_phys;
    d[0].len = sizeof(NetHdr);
    d[0].flags = kVirtqDescNext;
    d[0].next = 1;
    d[1].addr = g_net.tx_buf_phys;
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
