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
    bool mmio_access_ready = false;
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
    bool pci_command_saved = false;
    u16 pci_command_original = 0;
    bool online = false;
    bool quarantined = false;
    bool worker_started = false;
    bool operation_gate_open = false;
};

Context g_context{};

u8 Read8(const Context& c, u32 offset)
{
    return *reinterpret_cast<volatile u8*>(c.mmio + offset);
}
u32 Read32(const Context& c, u32 offset)
{
    return *reinterpret_cast<volatile u32*>(c.mmio + offset);
}
void Write8(const Context& c, u32 offset, u8 value)
{
    *reinterpret_cast<volatile u8*>(c.mmio + offset) = value;
}
void Write16(const Context& c, u32 offset, u16 value)
{
    *reinterpret_cast<volatile u16*>(c.mmio + offset) = value;
}
void Write32(const Context& c, u32 offset, u32 value)
{
    *reinterpret_cast<volatile u32*>(c.mmio + offset) = value;
}

bool LiveIdentityMatches(const pci::DeviceAddress& address, const NicInfo& nic)
{
    const u32 id = pci::PciConfigRead32(address, 0x00);
    const u32 class_revision = pci::PciConfigRead32(address, 0x08);
    const u32 subsystem = pci::PciConfigRead32(address, 0x2C);
    return static_cast<u16>(id) == rtl8125::contract::kVendorRealtek &&
           static_cast<u16>(id >> 16) == rtl8125::contract::kDevice &&
           static_cast<u8>(class_revision) == nic.revision_id && static_cast<u16>(subsystem) == kSubsystemVendor &&
           static_cast<u16>(subsystem >> 16) == kSubsystemDevice;
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
    c.mmio_access_ready = false;
    c.rx_ring = nullptr;
    c.tx_ring = nullptr;
    c.rx_buffers = nullptr;
    c.tx_buffers = nullptr;
    c.bound = false;
    c.dma_armed = false;
    c.pci_command_saved = false;
    c.pci_command_original = 0;
    c.worker_started = false;
    c.operation_gate_open = false;
    c.online = false;
    c.address = {};
    c.binding = {};
    c.iface = 0;
    c.rx_cursor = 0;
    c.tx_cursor = 0;
    c.tx_clean = 0;
    c.tx_in_flight = 0;
    c.quarantined = false;
}

bool RestorePciCommandSafe(const pci::DeviceAddress& address, u16 original)
{
    return RunPciSafeRestore(
        original, [&](u16 command) { pci::PciConfigWrite32(address, 0x04, command); },
        [&]() { return pci::PciConfigRead16(address, 0x04); });
}

bool AbortPreactivation(Context& c)
{
    if (c.pci_command_saved && !RestorePciCommandSafe(c.address, c.pci_command_original))
    {
        c.quarantined = true;
        return false;
    }
    FreeDma(c);
    return true;
}

bool StackTx(void* opaque, u32 iface, const void* frame, u64 len)
{
    auto* c = static_cast<Context*>(opaque);
    const u16 wire_length = PrepareTxLength(len);
    if (c == nullptr || !c->online || iface != c->iface || frame == nullptr || wire_length == 0 ||
        !DriverOperationGateTryAcquire(&c->operations))
        return false;
    const sync::SpinLockGuard guard(c->tx_lock);
    if (c->tx_in_flight >= kRingSlots - 1)
    {
        (void)DriverOperationGateRelease(&c->operations);
        return false;
    }
    const u32 slot = c->tx_cursor;
    const u64 buffer_address = c->tx_buf_dma.phys + u64(slot) * kBufferBytes;
    if (!DescriptorAddressValid(buffer_address, wire_length))
    {
        (void)DriverOperationGateRelease(&c->operations);
        return false;
    }
    for (u32 i = 0; i < wire_length; ++i)
        c->tx_buffers[slot * kBufferBytes + i] = 0;
    for (u32 i = 0; i < len; ++i)
        c->tx_buffers[slot * kBufferBytes + i] = static_cast<const u8*>(frame)[i];
    Descriptor& d = c->tx_ring[slot];
    d.address = buffer_address;
    d.options2 = 0;
    d.options1 = EncodeTx(d.address, wire_length, true, true, slot == kRingSlots - 1) | kDescOwn;
    mm::DmaSyncForDevice(c->tx_buf_dma, u64(slot) * kBufferBytes, wire_length);
    // DmaSyncForDevice is the architecture-owned compiler/CPU ordering
    // barrier; the OWN write is the descriptor publication point.
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
                    const u16 payload_length = RxPayloadLength(length);
                    if (payload_length != 0)
                        ::duetos::net::NetStackInjectRx(c->binding, c->rx_buffers + offset, payload_length);
                }
                d.options2 = 0;
                d.options1 = EncodeRx(d.address, kBufferBytes, c->rx_cursor == kRingSlots - 1);
                mm::DmaSyncForDevice(c->rx_ring_dma, u64(c->rx_cursor) * sizeof(Descriptor), sizeof(Descriptor));
                c->rx_cursor = (c->rx_cursor + 1) % kRingSlots;
            }
            while (c->tx_in_flight != 0)
            {
                mm::DmaSyncForCpu(c->tx_ring_dma, u64(c->tx_clean) * sizeof(Descriptor), sizeof(Descriptor));
                if ((c->tx_ring[c->tx_clean].options1 & kDescOwn) != 0)
                    break;
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
    if (g_context.online || g_context.quarantined || g_context.pci_command_saved || g_context.mmio_access_ready ||
        g_context.mmio != nullptr)
        return false;

    pci::DeviceAddress candidate{};
    candidate.bus = nic.bus;
    candidate.device = nic.device;
    candidate.function = nic.function;
    if (!LiveIdentityMatches(candidate, nic))
        return false;

    const u16 original_command = pci::PciConfigRead16(candidate, 0x04);
    const auto preflight_result = RunPciPreflight(
        original_command, [&](u16 command) { pci::PciConfigWrite32(candidate, 0x04, command); },
        [&]() { return pci::PciConfigRead16(candidate, 0x04); });
    if (preflight_result != PciPreflightResult::ReadyForMmio)
    {
        if (preflight_result == PciPreflightResult::QuarantinePciOnly)
        {
            // Retain only the PCI identity needed to retry a safe BME-off
            // restore. MMIO was never published and must not be touched.
            g_context.address = candidate;
            g_context.pci_command_original = original_command;
            g_context.pci_command_saved = true;
            g_context.quarantined = true;
        }
        return false;
    }

    g_context.address = candidate;
    g_context.iface = iface_index;
    g_context.mmio = static_cast<volatile u8*>(nic.mmio_virt);
    g_context.mmio_access_ready = true;
    g_context.pci_command_original = original_command;
    g_context.pci_command_saved = true;

    auto rx_ring = mm::AllocDmaCoherent(kRingSlots * sizeof(Descriptor), mm::Zone::Dma32);
    auto tx_ring = mm::AllocDmaCoherent(kRingSlots * sizeof(Descriptor), mm::Zone::Dma32);
    auto rx_buf = mm::AllocDmaCoherent(u64(kRingSlots) * kBufferBytes, mm::Zone::Dma32);
    auto tx_buf = mm::AllocDmaCoherent(u64(kRingSlots) * kBufferBytes, mm::Zone::Dma32);
    if (!rx_ring || !tx_ring || !rx_buf || !tx_buf)
    {
        if (rx_ring)
            mm::FreeDmaCoherent(rx_ring.value());
        if (tx_ring)
            mm::FreeDmaCoherent(tx_ring.value());
        if (rx_buf)
            mm::FreeDmaCoherent(rx_buf.value());
        if (tx_buf)
            mm::FreeDmaCoherent(tx_buf.value());
        (void)AbortPreactivation(g_context);
        return false;
    }
    g_context.rx_ring_dma = rx_ring.value();
    g_context.tx_ring_dma = tx_ring.value();
    g_context.rx_buf_dma = rx_buf.value();
    g_context.tx_buf_dma = tx_buf.value();
    g_context.rx_ring = static_cast<Descriptor*>(g_context.rx_ring_dma.virt);
    g_context.tx_ring = static_cast<Descriptor*>(g_context.tx_ring_dma.virt);
    g_context.rx_buffers = static_cast<u8*>(g_context.rx_buf_dma.virt);
    g_context.tx_buffers = static_cast<u8*>(g_context.tx_buf_dma.virt);
    if (!RingBaseValid(g_context.rx_ring_dma.phys, kRingSlots * sizeof(Descriptor)) ||
        !RingBaseValid(g_context.tx_ring_dma.phys, kRingSlots * sizeof(Descriptor)) ||
        !DescriptorAddressValid(g_context.rx_buf_dma.phys, u64(kRingSlots) * kBufferBytes) ||
        !DescriptorAddressValid(g_context.tx_buf_dma.phys, u64(kRingSlots) * kBufferBytes))
    {
        (void)AbortPreactivation(g_context);
        return false;
    }
    for (u32 i = 0; i < kRingSlots; ++i)
    {
        g_context.rx_ring[i].address = g_context.rx_buf_dma.phys + u64(i) * kBufferBytes;
        g_context.rx_ring[i].options2 = 0;
        if (!DescriptorAddressValid(g_context.rx_ring[i].address, kBufferBytes))
        {
            (void)AbortPreactivation(g_context);
            return false;
        }
        g_context.rx_ring[i].options1 = EncodeRx(g_context.rx_ring[i].address, kBufferBytes, i == kRingSlots - 1);
        g_context.tx_ring[i] = {};
    }
    mm::DmaSyncForDevice(g_context.rx_ring_dma, 0, g_context.rx_ring_dma.bytes);
    mm::DmaSyncForDevice(g_context.tx_ring_dma, 0, g_context.tx_ring_dma.bytes);
    // The reset is the only chip-wide control write. No PHY, OCP, or firmware
    // writes are attempted; RTL8125 firmware upload remains a documented gap.
    Write8(g_context, kRegChipCmd, kCmdReset);
    for (u32 tries = 0; tries < 10000 && (Read8(g_context, kRegChipCmd) & kCmdReset) != 0; ++tries)
        sched::SchedSleepTicks(1);
    if ((Read8(g_context, kRegChipCmd) & kCmdReset) != 0)
    {
        (void)AbortPreactivation(g_context);
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
        (void)AbortPreactivation(g_context);
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
    if (generation == 0 ||
        !::duetos::net::NetStackBindInterfaceOwned(iface_index, mac, ::duetos::net::Ipv4Address{{0, 0, 0, 0}}, StackTx,
                                                   &g_context, &g_context.binding))
    {
        if (generation != 0)
            (void)DriverWorkerLeaseRelease(&g_context.worker, generation);
        (void)AbortPreactivation(g_context);
        return false;
    }
    g_context.bound = true;
    if (sched::SchedCreate(Poll, &g_context, "rtl8125-rx-poll") == nullptr)
    {
        g_context.quarantined = true;
        (void)Rtl8125QuiesceAll();
        return false;
    }
    g_context.worker_started = true;
    const u16 command = pci::PciConfigRead16(g_context.address, 0x04);
    pci::PciConfigWrite32(g_context.address, 0x04,
                          static_cast<u32>(command | kPciCommandMemorySpace | kPciCommandBusMaster));
    if ((pci::PciConfigRead16(g_context.address, 0x04) & (kPciCommandMemorySpace | kPciCommandBusMaster)) !=
        (kPciCommandMemorySpace | kPciCommandBusMaster))
    {
        g_context.quarantined = true;
        (void)Rtl8125QuiesceAll();
        return false;
    }
    g_context.dma_armed = true;
    if (!DriverOperationGateOpen(&g_context.operations))
    {
        g_context.quarantined = true;
        (void)Rtl8125QuiesceAll();
        return false;
    }
    g_context.operation_gate_open = true;
    Write8(g_context, kRegChipCmd, kCmdRxEnable | kCmdTxEnable);
    g_context.online = true;
    nic.driver_online = true;
    // Linux r8169 identifies PHYstatus (0x6c), bit 1 as LinkStatus. Do not
    // claim carrier or start DHCP when the status read does not report it.
    nic.link_up = (Read8(g_context, 0x6C) & 0x02u) != 0;
    nic.wireless_fw_state = NicInfo::WirelessFwState::NotApplicable;
    if (nic.link_up)
        ::duetos::net::DhcpStart(iface_index);
    return true;
}

bool Rtl8125QuiesceAll()
{
    if (!g_context.online && !g_context.bound && !g_context.quarantined && !g_context.pci_command_saved &&
        !g_context.dma_armed && !g_context.mmio_access_ready)
        return true;
    g_context.online = false;
    if (g_context.operation_gate_open && !DriverOperationGateClose(&g_context.operations))
    {
        g_context.quarantined = true;
        return false;
    }
    g_context.operation_gate_open = false;
    if (DriverOperationGatePinCount(&g_context.operations) != 0)
    {
        g_context.quarantined = true;
        return false;
    }
    const u64 generation = DriverWorkerLeaseActiveGeneration(&g_context.worker);
    if (generation != 0)
    {
        if (!DriverWorkerLeaseRequestRetire(&g_context.worker, generation))
        {
            g_context.quarantined = true;
            return false;
        }
        if (!g_context.worker_started && !DriverWorkerLeaseAcknowledge(&g_context.worker, generation))
        {
            g_context.quarantined = true;
            return false;
        }
    }
    bool worker_joined = generation == 0;
    for (u32 waited = 0; !worker_joined && waited < 1000; ++waited)
    {
        worker_joined = DriverWorkerLeaseIsAcknowledged(&g_context.worker, generation);
        if (!worker_joined)
            sched::SchedSleepTicks(1);
    }
    if (!worker_joined || DriverOperationGatePinCount(&g_context.operations) != 0)
    {
        g_context.quarantined = true;
        return false;
    }
    if (g_context.bound)
    {
        if (::duetos::net::NetStackUnbindInterface(g_context.binding, 1000) !=
            ::duetos::net::NetInterfaceUnbindResult::Unbound)
        {
            g_context.quarantined = true;
            return false;
        }
        g_context.bound = false;
    }
    bool stopped = !g_context.mmio_access_ready;
    if (g_context.mmio_access_ready)
    {
        Write8(g_context, kRegChipCmd, 0);
        for (u32 waited = 0; waited < 1000; ++waited)
        {
            if ((Read8(g_context, kRegChipCmd) & (kCmdRxEnable | kCmdTxEnable)) == 0)
            {
                stopped = true;
                break;
            }
            sched::SchedSleepTicks(1);
        }
        if (!stopped)
        {
            g_context.quarantined = true;
            return false;
        }
    }
    bool bus_master_off = true;
    if (g_context.pci_command_saved && !RestorePciCommandSafe(g_context.address, g_context.pci_command_original))
    {
        g_context.quarantined = true;
        return false;
    }
    if (g_context.pci_command_saved)
        bus_master_off = (pci::PciConfigRead16(g_context.address, 0x04) & kPciCommandBusMaster) == 0;
    if (!TeardownProof(!g_context.operation_gate_open, worker_joined, !g_context.bound, stopped, bus_master_off))
    {
        g_context.quarantined = true;
        return false;
    }
    if (generation != 0)
    {
        if (!DriverWorkerLeaseRelease(&g_context.worker, generation))
        {
            g_context.quarantined = true;
            return false;
        }
    }
    FreeDma(g_context);
    return true;
}

} // namespace duetos::drivers::net
