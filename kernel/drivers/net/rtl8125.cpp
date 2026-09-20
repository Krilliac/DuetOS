#include "drivers/net/rtl8125.h"

#include "drivers/net/rtl8125_contract.h"
#include "drivers/net/wireless_watch.h"
#include "drivers/pci/pci.h"
#include "drivers/net/net.h"
#include "mm/dma.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "security/driver_domain.h"
#include "sync/spinlock.h"

namespace duetos::drivers::net
{
namespace
{
using namespace rtl8125::contract;

constexpr u32 kRegMac = 0x00;
constexpr u32 kRegTxDescLow = 0x20;
constexpr u32 kRegTxDescHigh = 0x24;
constexpr u32 kRegRxConfig = 0x44;
constexpr u32 kRegChipCmd = 0x37;
constexpr u32 kRegTxPoll = 0x90;
constexpr u32 kRegRxDescLow = 0xE4;
constexpr u32 kRegRxDescHigh = 0xE8;
constexpr u32 kRegRxMax = 0xDA;
constexpr u8 kCmdReset = 0x10;
constexpr u8 kCmdRxEnable = 0x08;
constexpr u8 kCmdTxEnable = 0x04;
constexpr u32 kRxAcceptBroadcast = 1u << 3;
constexpr u32 kRxAcceptMulticast = 1u << 2;
constexpr u32 kRxAcceptPhysical = 1u << 1;

struct Descriptor
{
    u32 options1;
    u32 options2;
    u64 address;
};
static_assert(sizeof(Descriptor) == 16);

struct Context
{
    DriverOperationGate operations{};
    DriverWorkerLease worker{};
    sync::SpinLock tx_lock{};
    pci::DeviceAddress address{};
    volatile u8* mmio = nullptr;
    mm::DmaBuffer rx_ring_dma{};
    mm::DmaBuffer tx_ring_dma{};
    mm::DmaBuffer rx_buf_dma{};
    mm::DmaBuffer tx_buf_dma{};
    Descriptor* rx_ring = nullptr;
    Descriptor* tx_ring = nullptr;
    u8* rx_buffers = nullptr;
    u8* tx_buffers = nullptr;
    ::duetos::net::NetInterfaceBinding binding{};
    u32 iface = 0;
    u32 rx_cursor = 0;
    u32 tx_cursor = 0;
    u32 tx_clean = 0;
    u32 tx_in_flight = 0;
    bool bound = false;
    bool dma_armed = false;
    bool online = false;
};

Context g_context{};

u8 Read8(const Context& c, u32 offset) { return *reinterpret_cast<volatile u8*>(c.mmio + offset); }
u32 Read32(const Context& c, u32 offset) { return *reinterpret_cast<volatile u32*>(c.mmio + offset); }
void Write8(const Context& c, u32 offset, u8 value) { *reinterpret_cast<volatile u8*>(c.mmio + offset) = value; }
void Write16(const Context& c, u32 offset, u16 value) { *reinterpret_cast<volatile u16*>(c.mmio + offset) = value; }
void Write32(const Context& c, u32 offset, u32 value) { *reinterpret_cast<volatile u32*>(c.mmio + offset) = value; }

bool Valid(const Context& c, u32 offset, u32 bytes)
{
    return c.mmio != nullptr && offset <= 0x10000u && bytes <= 0x10000u - offset;
}

void FreeDma(Context& c)
{
    mm::FreeDmaCoherent(c.rx_buf_dma);
    mm::FreeDmaCoherent(c.tx_buf_dma);
    mm::FreeDmaCoherent(c.rx_ring_dma);
    mm::FreeDmaCoherent(c.tx_ring_dma);
    c.mmio = nullptr;
    c.rx_ring_dma = {};
    c.tx_ring_dma = {};
    c.rx_buf_dma = {};
    c.tx_buf_dma = {};
    c.rx_ring = nullptr;
    c.tx_ring = nullptr;
    c.rx_buffers = nullptr;
    c.tx_buffers = nullptr;
    c.bound = false;
    c.dma_armed = false;
}

bool StackTx(void* opaque, u32 iface, const void* frame, u64 len)
{
    auto* c = static_cast<Context*>(opaque);
    if (c == nullptr || !c->online || iface != c->iface || frame == nullptr || len < kMinimumFrameBytes ||
        len > 1500 || !DriverOperationGateTryAcquire(&c->operations))
        return false;
    const sync::SpinLockGuard guard(c->tx_lock);
    if (c->tx_in_flight >= kRingSlots - 1)
    {
        (void)DriverOperationGateRelease(&c->operations);
        return false;
    }
    const u32 slot = c->tx_cursor;
    for (u32 i = 0; i < len; ++i)
        c->tx_buffers[slot * kBufferBytes + i] = static_cast<const u8*>(frame)[i];
    Descriptor& d = c->tx_ring[slot];
    d.address = c->tx_buf_dma.phys + u64(slot) * kBufferBytes;
    d.options2 = 0;
    d.options1 = EncodeTx(d.address, static_cast<u16>(len), true, true, slot == kRingSlots - 1) | kDescOwn;
    mm::DmaSyncForDevice(c->tx_buf_dma, u64(slot) * kBufferBytes, len);
    mm::DmaSyncForDevice(c->tx_ring_dma, u64(slot) * sizeof(Descriptor), sizeof(Descriptor));
    c->tx_cursor = (slot + 1) % kRingSlots;
    ++c->tx_in_flight;
    Write8(*c, kRegTxPoll, 0x40);
    (void)DriverOperationGateRelease(&c->operations);
    return true;
}

void Poll(void* opaque)
{
    auto* c = static_cast<Context*>(opaque);
    if (c == nullptr)
        return;
    const u64 generation = DriverWorkerLeaseActiveGeneration(&c->worker);
    if (generation == 0)
        return;
    while (DriverWorkerLeaseShouldRun(&c->worker, generation))
    {
        if (DriverOperationGateTryAcquire(&c->operations))
        {
            for (u32 count = 0; count < 32; ++count)
            {
                Descriptor& d = c->rx_ring[c->rx_cursor];
                mm::DmaSyncForCpu(c->rx_ring_dma, u64(c->rx_cursor) * sizeof(Descriptor), sizeof(Descriptor));
                const u32 options = d.options1;
                const u16 length = static_cast<u16>(options & 0x3FFFu);
                const RxDisposition disposition = ValidateRx(options, length, kBufferBytes);
                if (disposition == RxDisposition::NotReady)
                    break;
                if (disposition == RxDisposition::Deliver)
                {
                    const u64 offset = u64(c->rx_cursor) * kBufferBytes;
                    mm::DmaSyncForCpu(c->rx_buf_dma, offset, length);
                    ::duetos::net::NetStackInjectRx(c->binding, c->rx_buffers + offset, length);
                }
                d.options2 = 0;
                d.options1 = EncodeRx(d.address, c->rx_cursor == kRingSlots - 1);
                mm::DmaSyncForDevice(c->rx_ring_dma, u64(c->rx_cursor) * sizeof(Descriptor), sizeof(Descriptor));
                c->rx_cursor = (c->rx_cursor + 1) % kRingSlots;
            }
            while (c->tx_in_flight != 0 && (c->tx_ring[c->tx_clean].options1 & kDescOwn) == 0)
            {
                c->tx_clean = (c->tx_clean + 1) % kRingSlots;
                --c->tx_in_flight;
            }
            (void)DriverOperationGateRelease(&c->operations);
        }
        sched::SchedSleepTicks(1);
    }
    (void)DriverWorkerLeaseAcknowledge(&c->worker, generation);
}

} // namespace

bool Rtl8125BringUp(NicInfo& nic, u32 iface_index)
{
    if (!rtl8125::contract::IsExactHardware(nic.vendor_id, nic.device_id, nic.subsystem_vendor_id,
                                             nic.subsystem_device_id, nic.revision_id) ||
        nic.mmio_virt == nullptr || nic.mmio_size < 0x1A00)
        return false;
    if (!Valid(g_context, 0, 0))
        g_context.mmio = static_cast<volatile u8*>(nic.mmio_virt);
    if (g_context.online)
        return false;
    g_context.address.bus = nic.bus;
    g_context.address.device = nic.device;
    g_context.address.function = nic.function;
    g_context.iface = iface_index;
    auto rx_ring = mm::AllocDmaCoherent(kRingSlots * sizeof(Descriptor), mm::Zone::Dma32);
    auto tx_ring = mm::AllocDmaCoherent(kRingSlots * sizeof(Descriptor), mm::Zone::Dma32);
    auto rx_buf = mm::AllocDmaCoherent(u64(kRingSlots) * kBufferBytes, mm::Zone::Dma32);
    auto tx_buf = mm::AllocDmaCoherent(u64(kRingSlots) * kBufferBytes, mm::Zone::Dma32);
    if (!rx_ring || !tx_ring || !rx_buf || !tx_buf)
        return false;
    g_context.rx_ring_dma = rx_ring.value();
    g_context.tx_ring_dma = tx_ring.value();
    g_context.rx_buf_dma = rx_buf.value();
    g_context.tx_buf_dma = tx_buf.value();
    g_context.rx_ring = static_cast<Descriptor*>(g_context.rx_ring_dma.virt);
    g_context.tx_ring = static_cast<Descriptor*>(g_context.tx_ring_dma.virt);
    g_context.rx_buffers = static_cast<u8*>(g_context.rx_buf_dma.virt);
    g_context.tx_buffers = static_cast<u8*>(g_context.tx_buf_dma.virt);
    const auto abort_bringup = [&]() {
        const u16 safe = static_cast<u16>(pci::PciConfigRead16(g_context.address, 0x04) & ~0x4u);
        pci::PciConfigWrite32(g_context.address, 0x04, safe);
        FreeDma(g_context);
    };
    for (u32 i = 0; i < kRingSlots; ++i)
    {
        g_context.rx_ring[i].address = g_context.rx_buf_dma.phys + u64(i) * kBufferBytes;
        g_context.rx_ring[i].options2 = 0;
        g_context.rx_ring[i].options1 = EncodeRx(g_context.rx_ring[i].address, i == kRingSlots - 1);
        g_context.tx_ring[i] = {};
    }
    mm::DmaSyncForDevice(g_context.rx_ring_dma, 0, g_context.rx_ring_dma.bytes);
    mm::DmaSyncForDevice(g_context.tx_ring_dma, 0, g_context.tx_ring_dma.bytes);
    const u16 command = pci::PciConfigRead16(g_context.address, 0x04);
    pci::PciConfigWrite32(g_context.address, 0x04, static_cast<u16>(command | 0x6u));
    if ((pci::PciConfigRead16(g_context.address, 0x04) & 0x6u) != 0x6u)
    {
        abort_bringup();
        return false;
    }
    g_context.dma_armed = true;
    // The reset is the only chip-wide control write. No PHY, OCP, or firmware
    // writes are attempted; RTL8125 firmware upload remains a documented gap.
    Write8(g_context, kRegChipCmd, kCmdReset);
    for (u32 tries = 0; tries < 10000 && (Read8(g_context, kRegChipCmd) & kCmdReset) != 0; ++tries)
        sched::SchedSleepTicks(1);
    if ((Read8(g_context, kRegChipCmd) & kCmdReset) != 0)
    {
        abort_bringup();
        return false;
    }
    const u32 mac0 = Read32(g_context, kRegMac);
    const u32 mac4 = *reinterpret_cast<volatile u16*>(g_context.mmio + 4);
    for (u32 i = 0; i < 4; ++i)
        nic.mac[i] = static_cast<u8>(mac0 >> (8 * i));
    nic.mac[4] = static_cast<u8>(mac4);
    nic.mac[5] = static_cast<u8>(mac4 >> 8);
    nic.mac_valid = (nic.mac[0] | nic.mac[1] | nic.mac[2] | nic.mac[3] | nic.mac[4] | nic.mac[5]) != 0;
    if (!nic.mac_valid)
    {
        abort_bringup();
        return false;
    }
    Write32(g_context, kRegTxDescLow, static_cast<u32>(g_context.tx_ring_dma.phys));
    Write32(g_context, kRegTxDescHigh, static_cast<u32>(g_context.tx_ring_dma.phys >> 32));
    Write32(g_context, kRegRxDescLow, static_cast<u32>(g_context.rx_ring_dma.phys));
    Write32(g_context, kRegRxDescHigh, static_cast<u32>(g_context.rx_ring_dma.phys >> 32));
    Write16(g_context, kRegRxMax, static_cast<u16>(kBufferBytes));
    Write32(g_context, kRegRxConfig, kRxAcceptBroadcast | kRxAcceptMulticast | kRxAcceptPhysical);
    const u64 generation = DriverWorkerLeasePrepare(&g_context.worker);
    ::duetos::net::MacAddress mac{};
    for (u32 i = 0; i < 6; ++i)
        mac.octets[i] = nic.mac[i];
    if (generation == 0 || !::duetos::net::NetStackBindInterfaceOwned(iface_index, mac,
                                                                       ::duetos::net::Ipv4Address{{0, 0, 0, 0}}, StackTx,
                                                                       &g_context, &g_context.binding))
    {
        abort_bringup();
        return false;
    }
    g_context.bound = true;
    if (!DriverOperationGateOpen(&g_context.operations))
    {
        abort_bringup();
        return false;
    }
    Write8(g_context, kRegChipCmd, kCmdRxEnable | kCmdTxEnable);
    if (sched::SchedCreate(Poll, &g_context, "rtl8125-rx-poll") == nullptr)
    {
        abort_bringup();
        return false;
    }
    g_context.online = true;
    nic.driver_online = true;
    nic.link_up = true;
    nic.wireless_fw_state = NicInfo::WirelessFwState::NotApplicable;
    ::duetos::net::DhcpStart(iface_index);
    return true;
}

bool Rtl8125QuiesceAll()
{
    if (!g_context.online && !g_context.bound)
        return true;
    g_context.online = false;
    (void)DriverOperationGateClose(&g_context.operations);
    const u64 generation = DriverWorkerLeaseActiveGeneration(&g_context.worker);
    if (generation != 0)
        (void)DriverWorkerLeaseRequestRetire(&g_context.worker, generation);
    bool worker_joined = generation == 0;
    for (u32 waited = 0; !worker_joined && waited < 1000; ++waited)
    {
        worker_joined = DriverWorkerLeaseIsAcknowledged(&g_context.worker, generation);
        if (!worker_joined)
            sched::SchedSleepTicks(1);
    }
    if (!worker_joined)
        return false;
    if (g_context.bound)
        (void)::duetos::net::NetStackUnbindInterface(g_context.binding, 1000);
    if (g_context.mmio != nullptr)
        Write8(g_context, kRegChipCmd, 0);
    const u16 command = static_cast<u16>(pci::PciConfigRead16(g_context.address, 0x04) & ~0x4u);
    pci::PciConfigWrite32(g_context.address, 0x04, command);
    if (generation != 0)
        (void)DriverWorkerLeaseRelease(&g_context.worker, generation);
    FreeDma(g_context);
    return true;
}

} // namespace duetos::drivers::net
