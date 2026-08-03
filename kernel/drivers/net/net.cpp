/*
 * DuetOS — network PCI inventory and admitted-backend dispatcher.
 *
 * WHAT
 *   Walks PCI inventory, classifies NIC identities, admits only exact
 *   safe-probe profiles, and owns their restart lifecycle plus the
 *   shell-facing inventory behind `ifconfig` / `netscan`.
 *
 * HOW
 *   The enabled 8086:100E and 8086:10D3 e1000 profiles, AMD 1022:2000
 *   PCnet profile, and modern 1AF4:1041 virtio-net profile publish an
 *   exact-generation `NetInterfaceBinding`. Their polling workers inject RX
 *   through that receipt, while stack TX enters through a closable
 *   driver-operation gate. Shutdown closes and drains both domains before
 *   hardware DMA or stable context storage can be reclaimed.
 *
 *   Other wired and wireless families remain visible as inventory but fail
 *   closed before speculative BAR access. USB network class drivers have
 *   separate source ownership and are not represented by a generic vtable
 *   in this file.
 */

#include "drivers/net/net.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "diag/cleanroom_trace.h"
#include "drivers/net/bcm43xx.h"
#include "drivers/net/iwlwifi.h"
#include "drivers/net/mt76.h"
#include "drivers/net/pcnet.h"
#include "drivers/net/rtl88xx.h"
#include "drivers/net/wireless_watch.h"
#include "drivers/pci/pci.h"
#include "drivers/virtio/virtio_net.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/paging.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "security/driver_domain.h"
#include "sync/spinlock.h"

namespace duetos::drivers::net
{

namespace
{

NicInfo g_nics[kMaxNics] = {};
u64 g_nic_count = 0;

enum class NicRegistryState : u8
{
    Stopped = 0,
    Starting,
    Running,
    Stopping,
    Quarantined,
};

sync::SpinLock g_nic_registry_lock{};
NicRegistryState g_nic_registry_state = NicRegistryState::Stopped;

// MapMmio uses a monotonic virtual arena; unmapping page tables does not
// reclaim its cursor. Keep stable BDF/BAR mappings across NetShutdown /
// NetInit cycles instead of consuming another aperture on every restart.
struct NicMmioCacheEntry
{
    bool valid;
    pci::DeviceAddress address;
    u8 bar_index;
    u64 physical_address;
    u64 mapped_bytes;
    void* virtual_address;
};

constexpr u32 kNicMmioCacheSlots = 8;
NicMmioCacheEntry g_nic_mmio_cache[kNicMmioCacheSlots] = {};

bool SamePciAddress(const pci::DeviceAddress& left, const pci::DeviceAddress& right)
{
    return left.bus == right.bus && left.device == right.device && left.function == right.function;
}

bool LivePciIdentityMatches(const NicInfo& nic)
{
    pci::DeviceAddress address{};
    address.bus = nic.bus;
    address.device = nic.device;
    address.function = nic.function;

    const u32 expected_vendor_device = static_cast<u32>(nic.vendor_id) | (static_cast<u32>(nic.device_id) << 16);
    const u32 expected_class_revision =
        static_cast<u32>(nic.revision_id) | (static_cast<u32>(nic.programming_interface) << 8) |
        (static_cast<u32>(nic.subclass) << 16) | (static_cast<u32>(nic.class_code) << 24);
    if (pci::PciConfigRead32(address, 0x00) != expected_vendor_device ||
        pci::PciConfigRead32(address, 0x08) != expected_class_revision ||
        ((pci::PciConfigRead32(address, 0x0C) >> 16) & 0x7Fu) != 0)
        return false;

    const u32 subsystem = pci::PciConfigRead32(address, 0x2C);
    const u16 subsystem_vendor = static_cast<u16>(subsystem & 0xFFFFu);
    const bool subsystem_known = subsystem_vendor != 0 && subsystem_vendor != 0xFFFFu;
    return subsystem_known == nic.subsystem_known &&
           (!subsystem_known || (subsystem_vendor == nic.subsystem_vendor_id &&
                                 static_cast<u16>(subsystem >> 16) == nic.subsystem_device_id));
}

void* AcquireNicMmioMapping(const pci::DeviceAddress& address, u8 bar_index, u64 physical_address, u64 mapped_bytes)
{
    if (physical_address == 0 || mapped_bytes == 0)
        return nullptr;

    for (const NicMmioCacheEntry& entry : g_nic_mmio_cache)
    {
        if (entry.valid && SamePciAddress(entry.address, address) && entry.bar_index == bar_index &&
            entry.physical_address == physical_address && entry.mapped_bytes >= mapped_bytes)
            return entry.virtual_address;
    }

    for (NicMmioCacheEntry& entry : g_nic_mmio_cache)
    {
        if (entry.valid)
            continue;
        void* mapping = mm::MapMmio(physical_address, mapped_bytes);
        if (mapping == nullptr)
            return nullptr;
        entry.valid = true;
        entry.address = address;
        entry.bar_index = bar_index;
        entry.physical_address = physical_address;
        entry.mapped_bytes = mapped_bytes;
        entry.virtual_address = mapping;
        return mapping;
    }

    KLOG_ERROR("drivers/net", "NIC MMIO mapping cache exhausted; leaving device probe-only");
    return nullptr;
}

struct VendorEntry
{
    u16 vendor_id;
    const char* short_name;
};

constexpr VendorEntry kVendors[] = {
    {kVendorIntel, "Intel"},           {kVendorRealtek, "Realtek"},
    {kVendorBroadcom, "Broadcom"},     {kVendorAmd, "AMD"},
    {kVendorMarvell, "Marvell"},       {kVendorMellanox, "Mellanox"},
    {kVendorRedHatVirt, "virtio-net"}, {kVendorMediaTek, "MediaTek"},
    {kVendorIttim, "ITTIM"},
};

const char* VendorShort(u16 vid)
{
    for (const VendorEntry& v : kVendors)
    {
        if (v.vendor_id == vid)
            return v.short_name;
    }
    return "unknown";
}

const char* SubclassName(u8 subclass)
{
    switch (subclass)
    {
    case kPciSubclassEthernet:
        return "ethernet";
    case kPciSubclassTokenRing:
        return "token-ring";
    case kPciSubclassOther:
        return "other/wifi";
    default:
        return "?";
    }
}

// Intel e1000 / e1000e register offsets (subset).
// See Intel 8254x / 8257x programmer's reference.
constexpr u64 kE1000RegStatus = 0x00008; // Device Status
constexpr u64 kE1000RegRal0 = 0x05400;   // Receive Address Low  (MAC [0..3])
constexpr u64 kE1000RegRah0 = 0x05404;   // Receive Address High (MAC [4..5] + valid)
constexpr u32 kE1000StatusLinkUp = 1u << 1;
constexpr u32 kE1000RahAddressValid = 1u << 31;
// RAH0 is the highest register the v0 driver accesses. Refuse a BAR mapping
// that cannot contain the complete final dword.
constexpr u64 kE1000MinimumMmioBytes = kE1000RegRah0 + sizeof(u32);

// Read a MMIO u32 from the NIC's mapped BAR 0. Offset is in bytes.
u32 Mmio32(const NicInfo& n, u64 offset)
{
    if (n.mmio_virt == nullptr || offset > n.mmio_size || n.mmio_size - offset < sizeof(u32))
        return 0;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + offset);
    return *p;
}

// Read the MAC + link state from an Intel e1000-family NIC. The
// RAL/RAH registers are populated by the card from its EEPROM
// during reset, so they're readable without any init work on
// our side. This is the smallest useful real-hardware probe we
// can do without ring setup.
void ProbeE1000State(NicInfo& n)
{
    n.mac_valid = false;
    n.link_up = false;
    for (u32 i = 0; i < 6; ++i)
        n.mac[i] = 0;
    if (n.mmio_virt == nullptr || n.mmio_size < kE1000MinimumMmioBytes)
        return;
    const u32 ral = Mmio32(n, kE1000RegRal0);
    const u32 rah = Mmio32(n, kE1000RegRah0);
    if ((rah & kE1000RahAddressValid) == 0)
        return; // no populated MAC
    n.mac[0] = static_cast<u8>(ral & 0xFF);
    n.mac[1] = static_cast<u8>((ral >> 8) & 0xFF);
    n.mac[2] = static_cast<u8>((ral >> 16) & 0xFF);
    n.mac[3] = static_cast<u8>((ral >> 24) & 0xFF);
    n.mac[4] = static_cast<u8>(rah & 0xFF);
    n.mac[5] = static_cast<u8>((rah >> 8) & 0xFF);
    n.mac_valid = true;
    const u32 status = Mmio32(n, kE1000RegStatus);
    n.link_up = (status & kE1000StatusLinkUp) != 0;
}

// ---------------------------------------------------------------
// Intel e1000 driver — reset, link, legacy RX/TX rings, packet send, and
// bounded polling worker. Functional admission is intentionally restricted
// to the two emulator-backed profiles in nic_ids.h: 82540EM (100E) and
// 82574L/e1000e (10D3). Other exact Intel IDs remain inventory-only until
// their generation-specific PHY, reset, and queue contracts are implemented.
// ---------------------------------------------------------------

// Additional e1000 register offsets (CTRL / STATUS already above).
constexpr u64 kE1000RegCtrl = 0x00000;
constexpr u64 kE1000RegIcr = 0x000C0;   // Interrupt Cause Read (RC)
constexpr u64 kE1000RegImc = 0x000D8;   // Interrupt Mask Clear
constexpr u64 kE1000RegRctl = 0x00100;  // Receive Control
constexpr u64 kE1000RegTctl = 0x00400;  // Transmit Control
constexpr u64 kE1000RegTipg = 0x00410;  // TX Inter-Packet Gap
constexpr u64 kE1000RegRdbal = 0x02800; // RX Desc Base Addr Low
constexpr u64 kE1000RegRdbah = 0x02804; // RX Desc Base Addr High
constexpr u64 kE1000RegRdlen = 0x02808;
constexpr u64 kE1000RegRdh = 0x02810;
constexpr u64 kE1000RegRdt = 0x02818;
constexpr u64 kE1000RegTdbal = 0x03800;
constexpr u64 kE1000RegTdbah = 0x03804;
constexpr u64 kE1000RegTdlen = 0x03808;
constexpr u64 kE1000RegTdh = 0x03810;
constexpr u64 kE1000RegTdt = 0x03818;
constexpr u64 kE1000RegMta0 = 0x05200; // multicast table array base (128 × u32)

// CTRL bits.
constexpr u32 kE1000CtrlRst = 1u << 26; // Software reset
constexpr u32 kE1000CtrlSlu = 1u << 6;  // Set Link Up
constexpr u32 kE1000CtrlAsde = 1u << 5; // Auto-Speed Detect Enable

// RCTL bits.
constexpr u32 kE1000RctlEn = 1u << 1;     // Receiver Enable
constexpr u32 kE1000RctlBam = 1u << 15;   // Broadcast Accept Mode
constexpr u32 kE1000RctlSecrc = 1u << 26; // Strip Ethernet CRC
// RCTL.BSIZE bits 16..17 = 0b00 for 2048-byte buffers (with BSEX=0).

// TCTL bits.
constexpr u32 kE1000TctlEn = 1u << 1;
constexpr u32 kE1000TctlPsp = 1u << 3; // Pad Short Packets
// CT (collision threshold) bits 4..11 = 0x10, COLD (collision dist) bits 12..21 = 0x40.

// RX descriptor (16 bytes). Layout per 82540EM §3.2.3.
struct alignas(16) E1000RxDesc
{
    u64 addr;
    u16 length;
    u16 checksum;
    u8 status;
    u8 errors;
    u16 special;
};
static_assert(sizeof(E1000RxDesc) == 16, "e1000 RX descriptor must be 16 bytes");

// TX descriptor (16 bytes). "Legacy" format — §3.3.3.1.
struct alignas(16) E1000TxDesc
{
    u64 addr;
    u16 length;
    u8 cso;
    u8 cmd;
    u8 sta;
    u8 css;
    u16 special;
};
static_assert(sizeof(E1000TxDesc) == 16, "e1000 TX descriptor must be 16 bytes");

// Ring sizes — one page each (4 KiB / 16 B = 256 descriptors).
constexpr u32 kE1000RxRingSlots = 256;
constexpr u32 kE1000TxRingSlots = 256;
constexpr u32 kE1000RxBufBytes = 2048;

// RX descriptor status bits.
constexpr u8 kE1000RxStatusDd = 1u << 0;  // Descriptor Done
constexpr u8 kE1000RxStatusEop = 1u << 1; // End Of Packet

// TX descriptor command bits.
constexpr u8 kE1000TxCmdEop = 1u << 0;   // End Of Packet
constexpr u8 kE1000TxCmdIfcs = 1u << 1;  // Insert FCS
constexpr u8 kE1000TxCmdRs = 1u << 3;    // Report Status
constexpr u8 kE1000TxStatusDd = 1u << 0; // Descriptor Done

constexpr u16 kPciCommandMemorySpace = 1u << 1;
constexpr u16 kPciCommandBusMaster = 1u << 2;

bool DisablePciBusMasterForProbe(const pci::DeviceAddress& address)
{
    const u16 command = pci::PciConfigRead16(address, 0x04);
    const u16 safe_command = static_cast<u16>(command & ~kPciCommandBusMaster);
    // Status shares the upper half and is W1C. Write a zero upper half rather
    // than echoing pending status while taking ownership away from firmware.
    pci::PciConfigWrite32(address, 0x04, static_cast<u32>(safe_command));
    return pci::PciConfigRead16(address, 0x04) == safe_command;
}

struct E1000Ctx
{
    // Admission and pin publication share one atomic word, so shutdown can
    // never observe zero pins between a caller's open check and publication.
    DriverOperationGate operations;
    // These synchronization objects are stable across restart. In particular,
    // issued_generation is never reset, so a delayed old receipt cannot alias
    // a future worker.
    DriverWorkerLease rx_worker;
    sync::SpinLock tx_lock;
    pci::DeviceAddress pci_address;
    nic_ids::IntelE1000BringUpProfile profile;
    u16 pci_command_original;
    bool pci_command_saved;
    bool dma_armed;
    bool stack_bound;
    bool quarantined;
    volatile u8* mmio; // BAR 0 kernel-virtual
    u64 mmio_bytes;
    mm::DmaBuffer rx_ring_dma;
    E1000RxDesc* rx_ring;
    mm::DmaBuffer rx_buf_dma; // 256 x 2 KiB receive buffers
    u8* rx_buf_base_virt;
    u32 rx_tail;
    bool rx_discard_until_eop;
    mm::DmaBuffer tx_ring_dma;
    E1000TxDesc* tx_ring;
    mm::DmaBuffer tx_buf_dma; // 256 x 2 KiB transmit staging buffers
    u8* tx_buf_base_virt;
    u32 tx_tail;
    u32 tx_clean;
    u32 tx_in_flight;
    u64 rx_packets;
    u64 rx_bytes;
    u64 rx_dropped;
    u64 tx_packets;
    u64 tx_bytes;
    // Exact network-stack binding receipt. The stack owns callback admission
    // independently from the device gate and drains it before DMA is freed.
    duetos::net::NetInterfaceBinding stack_binding;
    u32 iface_index;
};

// Per-controller state. One slot per discovered e1000 adapter;
// the count mirrors the order in which E1000BringUp() is called
// during NetInit. kMaxNics (4) is an upper bound — the stack
// also caps at kMaxInterfaces (4) so the indices line up cleanly.
constexpr u32 kMaxE1000 = 4;
E1000Ctx g_e1000s[kMaxE1000] = {};
u32 g_e1000_count = 0;

bool E1000AcquireOperation(E1000Ctx& ctx)
{
    return DriverOperationGateTryAcquire(&ctx.operations);
}

void E1000ReleaseOperation(E1000Ctx& ctx)
{
    KASSERT(DriverOperationGateRelease(&ctx.operations), "drivers/net/e1000", "operation pin underflow");
}

bool E1000UpdatePciCommand(E1000Ctx& ctx, u16 set_bits, u16 clear_bits)
{
    const u16 current = pci::PciConfigRead16(ctx.pci_address, 0x04);
    const u16 desired = static_cast<u16>((current | set_bits) & ~clear_bits);
    // PCI status occupies the upper half of config dword 0x04 and contains
    // write-one-to-clear bits. Never echo a status snapshot while changing
    // Command: an upper half of zero preserves every pending status bit.
    pci::PciConfigWrite32(ctx.pci_address, 0x04, static_cast<u32>(desired));
    const u16 observed = pci::PciConfigRead16(ctx.pci_address, 0x04);
    return (observed & set_bits) == set_bits && (observed & clear_bits) == 0;
}

bool E1000PreparePciCommand(E1000Ctx& ctx)
{
    ctx.pci_command_original = pci::PciConfigRead16(ctx.pci_address, 0x04);
    ctx.pci_command_saved = true;
    // Keep the device unable to DMA while reset and descriptor publication
    // are in progress, but turn on memory decode before the first MMIO read.
    return E1000UpdatePciCommand(ctx, kPciCommandMemorySpace, kPciCommandBusMaster);
}

bool E1000EnableBusMaster(E1000Ctx& ctx)
{
    if (!E1000UpdatePciCommand(ctx, kPciCommandMemorySpace | kPciCommandBusMaster, 0))
        return false;
    ctx.dma_armed = true;
    return true;
}

bool E1000DisableBusMaster(E1000Ctx& ctx)
{
    const bool disabled = E1000UpdatePciCommand(ctx, 0, kPciCommandBusMaster);
    if (disabled)
        ctx.dma_armed = false;
    return disabled;
}

bool E1000RestorePciCommand(E1000Ctx& ctx)
{
    if (!ctx.pci_command_saved)
        return true;
    const u16 desired = static_cast<u16>(ctx.pci_command_original & ~kPciCommandBusMaster);
    pci::PciConfigWrite32(ctx.pci_address, 0x04, static_cast<u32>(desired));
    const u16 observed = pci::PciConfigRead16(ctx.pci_address, 0x04);
    const u16 owned_mask = kPciCommandMemorySpace | kPciCommandBusMaster;
    return (observed & owned_mask) == (desired & owned_mask);
}

bool E1000MacIsUsable(const NicInfo& n)
{
    if (!n.mac_valid || (n.mac[0] & 1u) != 0)
        return false;
    bool all_zero = true;
    for (u32 i = 0; i < 6; ++i)
        all_zero = all_zero && n.mac[i] == 0;
    return !all_zero;
}

// Reset only ordinary runtime fields. The operation gate, worker lease, and
// TX lock remain at stable addresses and are never aggregate-overwritten.
void E1000ClearRuntimeFields(E1000Ctx& ctx)
{
    KASSERT(!DriverOperationGateIsOpen(&ctx.operations), "drivers/net/e1000", "clear with operation gate open");
    KASSERT(DriverOperationGatePinCount(&ctx.operations) == 0, "drivers/net/e1000", "clear with operation pins");
    KASSERT(DriverWorkerLeaseActiveGeneration(&ctx.rx_worker) == 0, "drivers/net/e1000", "clear with live worker");
    ctx.pci_address = {};
    ctx.profile = nic_ids::IntelE1000BringUpProfile::None;
    ctx.pci_command_original = 0;
    ctx.pci_command_saved = false;
    ctx.dma_armed = false;
    ctx.stack_bound = false;
    ctx.quarantined = false;
    ctx.mmio = nullptr;
    ctx.mmio_bytes = 0;
    ctx.rx_ring_dma = {};
    ctx.rx_ring = nullptr;
    ctx.rx_buf_dma = {};
    ctx.rx_buf_base_virt = nullptr;
    ctx.rx_tail = 0;
    ctx.rx_discard_until_eop = false;
    ctx.tx_ring_dma = {};
    ctx.tx_ring = nullptr;
    ctx.tx_buf_dma = {};
    ctx.tx_buf_base_virt = nullptr;
    ctx.tx_tail = 0;
    ctx.tx_clean = 0;
    ctx.tx_in_flight = 0;
    ctx.rx_packets = 0;
    ctx.rx_bytes = 0;
    ctx.rx_dropped = 0;
    ctx.tx_packets = 0;
    ctx.tx_bytes = 0;
    ctx.stack_binding = {};
    ctx.iface_index = 0;
}

// Per-controller MMIO helpers — each function takes an explicit
// ctx so all the driver functions work on whichever controller
// the caller is operating on instead of a file-scope singleton.
void E1000Write(E1000Ctx& ctx, u64 off, u32 value)
{
    KASSERT(ctx.mmio != nullptr && off <= ctx.mmio_bytes && ctx.mmio_bytes - off >= sizeof(u32), "drivers/net/e1000",
            "MMIO write outside mapped BAR extent");
    *reinterpret_cast<volatile u32*>(ctx.mmio + off) = value;
}
u32 E1000Read(E1000Ctx& ctx, u64 off)
{
    KASSERT(ctx.mmio != nullptr && off <= ctx.mmio_bytes && ctx.mmio_bytes - off >= sizeof(u32), "drivers/net/e1000",
            "MMIO read outside mapped BAR extent");
    return *reinterpret_cast<volatile u32*>(ctx.mmio + off);
}

// Spin a small number of cycles so the controller sees our MMIO
// writes complete before we poll related registers. 1 ms worth
// of pauses is plenty on any real NIC.
void E1000Delay()
{
    for (u32 i = 0; i < 1024; ++i)
        asm volatile("pause" ::: "memory");
}

bool E1000Reset(E1000Ctx& ctx)
{
    // Mask all interrupts, read ICR to clear any pending, then reset.
    E1000Write(ctx, kE1000RegImc, 0xFFFFFFFFu);
    (void)E1000Read(ctx, kE1000RegIcr);
    E1000Write(ctx, kE1000RegCtrl, E1000Read(ctx, kE1000RegCtrl) | kE1000CtrlRst);
    // Reset takes ~1 ms; poll CTRL.RST to clear.
    for (u32 i = 0; i < 100; ++i)
    {
        E1000Delay();
        if ((E1000Read(ctx, kE1000RegCtrl) & kE1000CtrlRst) == 0)
        {
            // Mask IRQs again — reset may have re-enabled some.
            E1000Write(ctx, kE1000RegImc, 0xFFFFFFFFu);
            (void)E1000Read(ctx, kE1000RegIcr);
            return true;
        }
    }
    arch::SerialWrite("[e1000] reset timed out\n");
    return false;
}

void E1000ClearMulticastTable(E1000Ctx& ctx)
{
    for (u32 i = 0; i < 128; ++i)
        E1000Write(ctx, kE1000RegMta0 + u64(i) * 4, 0);
}

bool E1000SetupRxRing(E1000Ctx& ctx)
{
    // One 4 KiB frame for the RX descriptor ring (256 × 16 B).
    auto ring_r = mm::AllocDmaCoherent(mm::kPageSize, mm::Zone::Dma32);
    if (!ring_r)
        return false;
    ctx.rx_ring_dma = ring_r.value();
    ctx.rx_ring = static_cast<E1000RxDesc*>(ctx.rx_ring_dma.virt);

    // 256 × 2 KiB = 128 pages contiguous for RX buffers. Each
    // descriptor points at buf_base + slot × 2048.
    constexpr u64 kRxBufferBytes = u64(kE1000RxRingSlots) * kE1000RxBufBytes;
    auto buffers_r = mm::AllocDmaCoherent(kRxBufferBytes, mm::Zone::Dma32);
    if (!buffers_r)
    {
        mm::FreeDmaCoherent(ctx.rx_ring_dma);
        ctx.rx_ring_dma = {};
        ctx.rx_ring = nullptr;
        return false;
    }
    ctx.rx_buf_dma = buffers_r.value();
    ctx.rx_buf_base_virt = static_cast<u8*>(ctx.rx_buf_dma.virt);
    for (u32 i = 0; i < kE1000RxRingSlots; ++i)
    {
        ctx.rx_ring[i].addr = ctx.rx_buf_dma.phys + u64(i) * kE1000RxBufBytes;
        ctx.rx_ring[i].status = 0;
    }
    mm::DmaSyncForDevice(ctx.rx_ring_dma, 0, kE1000RxRingSlots * sizeof(E1000RxDesc));

    E1000Write(ctx, kE1000RegRctl, 0);
    E1000Write(ctx, kE1000RegRdbal, u32(ctx.rx_ring_dma.phys));
    E1000Write(ctx, kE1000RegRdbah, u32(ctx.rx_ring_dma.phys >> 32));
    E1000Write(ctx, kE1000RegRdlen, kE1000RxRingSlots * sizeof(E1000RxDesc));
    E1000Write(ctx, kE1000RegRdh, 0);
    E1000Write(ctx, kE1000RegRdt, kE1000RxRingSlots - 1);
    ctx.rx_tail = kE1000RxRingSlots - 1;

    return true;
}

bool E1000SetupTxRing(E1000Ctx& ctx)
{
    auto ring_r = mm::AllocDmaCoherent(mm::kPageSize, mm::Zone::Dma32);
    if (!ring_r)
        return false;
    ctx.tx_ring_dma = ring_r.value();
    ctx.tx_ring = static_cast<E1000TxDesc*>(ctx.tx_ring_dma.virt);

    constexpr u64 kTxBufferBytes = u64(kE1000TxRingSlots) * kE1000RxBufBytes;
    auto buffers_r = mm::AllocDmaCoherent(kTxBufferBytes, mm::Zone::Dma32);
    if (!buffers_r)
    {
        mm::FreeDmaCoherent(ctx.tx_ring_dma);
        ctx.tx_ring_dma = {};
        ctx.tx_ring = nullptr;
        return false;
    }
    ctx.tx_buf_dma = buffers_r.value();
    ctx.tx_buf_base_virt = static_cast<u8*>(ctx.tx_buf_dma.virt);

    mm::DmaSyncForDevice(ctx.tx_ring_dma, 0, kE1000TxRingSlots * sizeof(E1000TxDesc));
    E1000Write(ctx, kE1000RegTctl, 0);
    E1000Write(ctx, kE1000RegTdbal, u32(ctx.tx_ring_dma.phys));
    E1000Write(ctx, kE1000RegTdbah, u32(ctx.tx_ring_dma.phys >> 32));
    E1000Write(ctx, kE1000RegTdlen, kE1000TxRingSlots * sizeof(E1000TxDesc));
    E1000Write(ctx, kE1000RegTdh, 0);
    E1000Write(ctx, kE1000RegTdt, 0);
    ctx.tx_tail = 0;
    ctx.tx_clean = 0;
    ctx.tx_in_flight = 0;

    // TIPG: IPGT=10, IPGR1=8 (0xA << 10), IPGR2=6 (0x6 << 20).
    // Canonical 0x0060200A for 82540EM.
    E1000Write(ctx, kE1000RegTipg, 0x0060200AU);

    return true;
}

bool E1000EnableDatapath(E1000Ctx& ctx)
{
    // Descriptor publication completes while BME and both engines are off.
    mm::DmaSyncForDevice(ctx.rx_ring_dma, 0, ctx.rx_ring_dma.bytes);
    mm::DmaSyncForDevice(ctx.rx_buf_dma, 0, ctx.rx_buf_dma.bytes);
    mm::DmaSyncForDevice(ctx.tx_ring_dma, 0, ctx.tx_ring_dma.bytes);
    mm::DmaSyncForDevice(ctx.tx_buf_dma, 0, ctx.tx_buf_dma.bytes);
    if (!E1000EnableBusMaster(ctx))
        return false;

    const u32 rctl = kE1000RctlEn | kE1000RctlBam | kE1000RctlSecrc;
    const u32 tctl = kE1000TctlEn | kE1000TctlPsp | (0x10u << 4) | (0x40u << 12);
    E1000Write(ctx, kE1000RegRctl, rctl);
    E1000Write(ctx, kE1000RegTctl, tctl);
    (void)E1000Read(ctx, kE1000RegStatus);
    return true;
}

bool E1000Send(E1000Ctx& ctx, const u8* data, u32 len)
{
    if (data == nullptr || len == 0)
        return false;
    if (len > kE1000RxBufBytes)
        return false;
    if (!E1000AcquireOperation(ctx))
        return false;

    const sync::IrqFlags flags = sync::SpinLockAcquire(ctx.tx_lock);
    while (ctx.tx_in_flight != 0)
    {
        const u64 clean_offset = u64(ctx.tx_clean) * sizeof(E1000TxDesc);
        mm::DmaSyncForCpu(ctx.tx_ring_dma, clean_offset, sizeof(E1000TxDesc));
        if ((ctx.tx_ring[ctx.tx_clean].sta & kE1000TxStatusDd) == 0)
            break;
        ctx.tx_clean = (ctx.tx_clean + 1) % kE1000TxRingSlots;
        --ctx.tx_in_flight;
    }

    // Reserve one descriptor so TDT never aliases TDH while work remains.
    if (ctx.tx_in_flight >= kE1000TxRingSlots - 1)
    {
        sync::SpinLockRelease(ctx.tx_lock, flags);
        E1000ReleaseOperation(ctx);
        return false;
    }

    const u32 slot = ctx.tx_tail;
    u8* buf = ctx.tx_buf_base_virt + u64(slot) * kE1000RxBufBytes;
    for (u32 i = 0; i < len; ++i)
        buf[i] = data[i];

    E1000TxDesc& d = ctx.tx_ring[slot];
    d.addr = ctx.tx_buf_dma.phys + u64(slot) * kE1000RxBufBytes;
    d.length = u16(len);
    d.cso = 0;
    d.cmd = kE1000TxCmdEop | kE1000TxCmdIfcs | kE1000TxCmdRs;
    d.sta = 0;
    d.css = 0;
    d.special = 0;

    const u64 buffer_offset = u64(slot) * kE1000RxBufBytes;
    const u64 descriptor_offset = u64(slot) * sizeof(E1000TxDesc);
    mm::DmaSyncForDevice(ctx.tx_buf_dma, buffer_offset, len);
    mm::DmaSyncForDevice(ctx.tx_ring_dma, descriptor_offset, sizeof(E1000TxDesc));
    const u32 next = (slot + 1) % kE1000TxRingSlots;
    ctx.tx_tail = next;
    ++ctx.tx_in_flight;
    E1000Write(ctx, kE1000RegTdt, next);
    ++ctx.tx_packets;
    ctx.tx_bytes += len;
    sync::SpinLockRelease(ctx.tx_lock, flags);
    E1000ReleaseOperation(ctx);
    return true;
}

// Drain every RX descriptor whose DD bit is set. Hands each
// valid frame up to the network stack via the iface_index bound
// in E1000BringUp — each controller delivers to its own stack
// slot rather than all feeding index 0.
u32 E1000DrainRx(E1000Ctx& ctx, u32 budget_packets)
{
    if (!DriverOperationGateIsOpen(&ctx.operations))
        return 0;
    u32 drained = 0;
    for (u32 checked = 0; checked < kE1000RxRingSlots; ++checked)
    {
        if (budget_packets != 0 && drained >= budget_packets)
            break;
        const u32 slot = (ctx.rx_tail + 1) % kE1000RxRingSlots;
        volatile E1000RxDesc& d = ctx.rx_ring[slot];
        const u64 descriptor_offset = u64(slot) * sizeof(E1000RxDesc);
        mm::DmaSyncForCpu(ctx.rx_ring_dma, descriptor_offset, sizeof(E1000RxDesc));
        const u8 status = d.status;
        if ((status & kE1000RxStatusDd) == 0)
            break;
        const u16 len = d.length;
        const u8 errors = d.errors;
        const bool end_of_packet = (status & kE1000RxStatusEop) != 0;
        const bool continued_fragment = ctx.rx_discard_until_eop;
        if (!end_of_packet)
            ctx.rx_discard_until_eop = true;
        else
            ctx.rx_discard_until_eop = false;
        // The NIC DMA-writes `length`; a non-conforming or hostile
        // device can report past the 2 KiB per-slot buffer. The 256
        // RX buffers are one contiguous allocation, so trusting an
        // over-length descriptor lets the L3 parsers read across
        // slots (cross-frame info leak) or off the end of the whole
        // RX region on the last slot. Drop + recycle out-of-range
        // descriptors instead of injecting them.
        if (continued_fragment || !end_of_packet || errors != 0 || len == 0 || len > kE1000RxBufBytes)
        {
            ++ctx.rx_dropped;
        }
        else
        {
            const u64 buffer_offset = u64(slot) * kE1000RxBufBytes;
            mm::DmaSyncForCpu(ctx.rx_buf_dma, buffer_offset, len);
            u8* buf = ctx.rx_buf_base_virt + buffer_offset;
            duetos::net::NetStackInjectRx(ctx.stack_binding, buf, len);
            ++ctx.rx_packets;
            ctx.rx_bytes += len;
            ++drained;
        }
        // Release the descriptor back to the controller.
        d.length = 0;
        d.checksum = 0;
        d.status = 0;
        d.errors = 0;
        d.special = 0;
        mm::DmaSyncForDevice(ctx.rx_ring_dma, descriptor_offset, sizeof(E1000RxDesc));
        ctx.rx_tail = slot;
        E1000Write(ctx, kE1000RegRdt, slot);
    }
    return drained;
}

// RX poll task entry. `arg` is &g_e1000s[n] — the slot outlives
// the task (module-scope array).
void E1000RxPollEntry(void* arg)
{
    E1000Ctx* ctx = static_cast<E1000Ctx*>(arg);
    if (ctx == nullptr)
        return;
    const u64 generation = DriverWorkerLeaseActiveGeneration(&ctx->rx_worker);
    if (generation == 0)
        return;
    constexpr u32 kRxPollBudget = 64;
    while (DriverWorkerLeaseShouldRun(&ctx->rx_worker, generation))
    {
        const u32 drained = E1000DrainRx(*ctx, kRxPollBudget);
        if (drained == kRxPollBudget)
            continue;
        if (!DriverWorkerLeaseShouldRun(&ctx->rx_worker, generation))
            break;
        // Polling is intentional for both admitted v0 profiles. It avoids
        // owning a monotonic IRQ vector/table mapping across restart until a
        // reusable MSI-X route and exact 82574 IVAR contract exist.
        duetos::sched::SchedSleepTicks(1);
    }
    (void)DriverWorkerLeaseAcknowledge(&ctx->rx_worker, generation);
}

// Spec-defined broadcast address for the self-test ARP-like blast.
constexpr u8 kBroadcastMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Minimum ethernet payload is 46 bytes; controller will pad (PSP)
// up to 60 + 4 CRC = 64-byte wire length. We ship 60 bytes of our
// own content so the padding is deterministic.
void E1000SelfTestTx(E1000Ctx& ctx, const NicInfo& n)
{
    u8 frame[60] = {};
    // Dst = broadcast.
    for (u32 i = 0; i < 6; ++i)
        frame[i] = kBroadcastMac[i];
    // Src = our MAC.
    for (u32 i = 0; i < 6; ++i)
        frame[6 + i] = n.mac[i];
    // EtherType = 0x88B5 (IEEE Std 802 - Local Experimental Ethertype 1),
    // a reserved value the stack will ignore when routed back.
    frame[12] = 0x88;
    frame[13] = 0xB5;
    // Payload: a short recognizable marker so a tcpdump on the host
    // netdev sees this frame clearly.
    const char kMarker[] = "DUETOS-E1000-SELFTEST";
    for (u32 i = 0; i < sizeof(kMarker) - 1 && 14 + i < sizeof(frame); ++i)
        frame[14 + i] = u8(kMarker[i]);

    if (E1000Send(ctx, frame, sizeof(frame)))
    {
        arch::SerialWrite("[e1000] self-test TX: 60-byte broadcast marker emitted\n");
    }
    else
    {
        // Self-test TX submission failed — typically means the
        // tx ring is wedged or the BAR mapping is broken. Klog
        // so the regression appears in dmesg + panic dump.
        KLOG_ERROR("drivers/net/e1000", "self-test TX submission failed");
    }
}

// Claim the next free E1000Ctx slot. Returns nullptr when the
// per-family cap (kMaxE1000) is reached. The cap matches
// kMaxNics and kMaxInterfaces so the three tables stay aligned.
// The caller is responsible for rolling back g_e1000_count if
// bring-up fails after this point (see E1000BringUp).
E1000Ctx* E1000AllocCtx()
{
    if (g_e1000_count >= kMaxE1000)
        return nullptr;
    return &g_e1000s[g_e1000_count++];
}

void E1000FreeDmaStorage(E1000Ctx& ctx)
{
    KASSERT(!ctx.dma_armed, "drivers/net/e1000", "freeing DMA while PCI bus mastering may be enabled");
    mm::FreeDmaCoherent(ctx.rx_ring_dma);
    mm::FreeDmaCoherent(ctx.rx_buf_dma);
    mm::FreeDmaCoherent(ctx.tx_ring_dma);
    mm::FreeDmaCoherent(ctx.tx_buf_dma);

    ctx.rx_ring_dma = {};
    ctx.rx_ring = nullptr;
    ctx.rx_buf_dma = {};
    ctx.rx_buf_base_virt = nullptr;
    ctx.tx_ring_dma = {};
    ctx.tx_ring = nullptr;
    ctx.tx_buf_dma = {};
    ctx.tx_buf_base_virt = nullptr;
}

bool E1000DisableHardware(E1000Ctx& ctx)
{
    if (!ctx.pci_command_saved)
        return true;
    if (ctx.mmio == nullptr)
        return E1000DisableBusMaster(ctx) && E1000RestorePciCommand(ctx);
    if (!ctx.dma_armed && !E1000UpdatePciCommand(ctx, kPciCommandMemorySpace, kPciCommandBusMaster))
        return false;
    E1000Write(ctx, kE1000RegImc, 0xFFFFFFFFu);
    (void)E1000Read(ctx, kE1000RegIcr);
    E1000Write(ctx, kE1000RegRctl, 0);
    E1000Write(ctx, kE1000RegTctl, 0);
    (void)E1000Read(ctx, kE1000RegStatus);
    E1000Delay();

    const bool bus_master_disabled = E1000DisableBusMaster(ctx);
    const bool reset_complete = bus_master_disabled && E1000Reset(ctx);
    const bool command_restored = bus_master_disabled && E1000RestorePciCommand(ctx);
    if (!bus_master_disabled || !reset_complete || !command_restored)
    {
        KLOG_ERROR_2V("drivers/net/e1000", "hardware quiesce unconfirmed; DMA retained", "bus-master-off",
                      bus_master_disabled ? 1 : 0, "reset-complete", reset_complete ? 1 : 0);
        return false;
    }
    return true;
}

bool E1000StackTx(void* context, u32 iface_index, const void* frame, u64 len)
{
    auto* ctx = static_cast<E1000Ctx*>(context);
    if (ctx == nullptr || frame == nullptr || iface_index != ctx->iface_index || len > kE1000RxBufBytes)
        return false;
    return E1000Send(*ctx, static_cast<const u8*>(frame), static_cast<u32>(len));
}

bool E1000UnbindStack(E1000Ctx& ctx)
{
    if (!ctx.stack_bound)
        return true;
    constexpr u32 kStackDrainBudgetTicks = 200;
    const duetos::net::NetInterfaceUnbindResult result =
        duetos::net::NetStackUnbindInterface(ctx.stack_binding, kStackDrainBudgetTicks);
    if (result != duetos::net::NetInterfaceUnbindResult::Unbound)
    {
        KLOG_ERROR_V("drivers/net/e1000", "network-stack binding ownership not released; context quarantined",
                     static_cast<u64>(result));
        return false;
    }
    ctx.stack_bound = false;
    ctx.stack_binding = {};
    return true;
}

bool E1000ReleaseUnstartedWorker(E1000Ctx& ctx, u64 generation)
{
    if (generation == 0)
        return true;
    return DriverWorkerLeaseRequestRetire(&ctx.rx_worker, generation) &&
           DriverWorkerLeaseAcknowledge(&ctx.rx_worker, generation) &&
           DriverWorkerLeaseRelease(&ctx.rx_worker, generation);
}

void E1000AbortUnstartedBringUp(E1000Ctx& ctx, u32 saved_count, u64 worker_generation)
{
    (void)DriverOperationGateClose(&ctx.operations);
    const bool stack_unbound = E1000UnbindStack(ctx);
    const bool worker_released = E1000ReleaseUnstartedWorker(ctx, worker_generation);
    const bool operations_drained = DriverOperationGatePinCount(&ctx.operations) == 0;
    // A failed stack drain may mean a TX callback is still inside the driver.
    // Retain live hardware and DMA for NetShutdown to retry; resetting or
    // disabling BME underneath that callback would trade a rollback failure
    // for an in-flight MMIO/DMA race.
    if (!stack_unbound || !worker_released || !operations_drained)
    {
        ctx.quarantined = true;
        KLOG_ERROR("drivers/net/e1000", "failed bring-up retained as quarantined context");
        return;
    }
    if (!E1000DisableHardware(ctx))
    {
        ctx.quarantined = true;
        KLOG_ERROR("drivers/net/e1000", "failed bring-up hardware teardown quarantined");
        return;
    }
    E1000FreeDmaStorage(ctx);
    E1000ClearRuntimeFields(ctx);
    g_e1000_count = saved_count;
}

bool E1000BringUp(NicInfo& n, u32 iface_index)
{
    const nic_ids::IntelE1000BringUpProfile profile = nic_ids::IntelE1000BringUpProfileFromDeviceId(n.device_id);
    if (profile == nic_ids::IntelE1000BringUpProfile::None || n.mmio_virt == nullptr ||
        n.mmio_size < kE1000MinimumMmioBytes || !LivePciIdentityMatches(n))
        return false;

    const u32 saved_count = g_e1000_count;
    E1000Ctx* ctx = E1000AllocCtx();
    if (ctx == nullptr)
    {
        // GAP: more than kMaxE1000 e1000 adapters present — additional
        // controllers are left at probe-only state — revisit when
        // kMaxE1000 / kMaxInterfaces are lifted.
        KLOG_WARN_V("drivers/net/e1000", "e1000 slot limit reached; controller skipped", iface_index);
        return false;
    }

    E1000ClearRuntimeFields(*ctx);
    ctx->pci_address.bus = n.bus;
    ctx->pci_address.device = n.device;
    ctx->pci_address.function = n.function;
    ctx->profile = profile;
    ctx->mmio = static_cast<volatile u8*>(n.mmio_virt);
    ctx->mmio_bytes = n.mmio_size;
    ctx->iface_index = iface_index;

    // Config dword 0x04 is changed before the first MMIO access. If memory
    // decode or BME-disable cannot be confirmed, do not touch the BAR.
    if (!E1000PreparePciCommand(*ctx))
    {
        // Preserve the stable context when bus-master-off cannot be proven.
        // Clearing it here would discard the only receipt NetShutdown can use
        // to retry the fail-closed PCI teardown.
        E1000AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    if (!E1000Reset(*ctx))
    {
        E1000AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    ProbeE1000State(n);
    if (!E1000MacIsUsable(n))
    {
        n.mac_valid = false;
        KLOG_ERROR("drivers/net/e1000", "reset did not publish a usable unicast MAC");
        E1000AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    const u32 ctrl = E1000Read(*ctx, kE1000RegCtrl) | kE1000CtrlSlu | kE1000CtrlAsde;
    E1000Write(*ctx, kE1000RegCtrl, ctrl);
    E1000ClearMulticastTable(*ctx);

    if (!E1000SetupRxRing(*ctx))
    {
        E1000AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }
    if (!E1000SetupTxRing(*ctx))
    {
        E1000AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    const u64 worker_generation = DriverWorkerLeasePrepare(&ctx->rx_worker);
    if (worker_generation == 0)
    {
        E1000AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    duetos::net::MacAddress mac{};
    for (u64 i = 0; i < 6; ++i)
        mac.octets[i] = n.mac[i];
    const duetos::net::Ipv4Address ip{{0, 0, 0, 0}};
    if (!duetos::net::NetStackBindInterfaceOwned(iface_index, mac, ip, E1000StackTx, ctx, &ctx->stack_binding))
    {
        E1000AbortUnstartedBringUp(*ctx, saved_count, worker_generation);
        return false;
    }
    ctx->stack_bound = true;

    if (!E1000EnableDatapath(*ctx) || !DriverOperationGateOpen(&ctx->operations))
    {
        E1000AbortUnstartedBringUp(*ctx, saved_count, worker_generation);
        return false;
    }

    const auto worker = duetos::sched::SchedCreate(E1000RxPollEntry, ctx, "e1000-rx-poll");
    if (worker == nullptr)
    {
        E1000AbortUnstartedBringUp(*ctx, saved_count, worker_generation);
        return false;
    }

    E1000Delay();
    n.link_up = (E1000Read(*ctx, kE1000RegStatus) & kE1000StatusLinkUp) != 0;
    n.driver_online = true;
    n.firmware_pending = false;
    n.wireless_fw_state = NicInfo::WirelessFwState::NotApplicable;
    duetos::net::DhcpStart(iface_index);

    arch::SerialWrite("[e1000] online iface=");
    arch::SerialWriteHex(iface_index);
    arch::SerialWrite(" pci=");
    arch::SerialWriteHex(n.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(n.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(n.function);
    arch::SerialWrite(" mac=");
    for (u64 i = 0; i < 6; ++i)
    {
        if (i != 0)
            arch::SerialWrite(":");
        arch::SerialWriteHex(n.mac[i]);
    }
    arch::SerialWrite(n.link_up ? " link=up" : " link=down");
    arch::SerialWrite(" rx_ring=");
    arch::SerialWriteHex(ctx->rx_ring_dma.phys);
    arch::SerialWrite(" tx_ring=");
    arch::SerialWriteHex(ctx->tx_ring_dma.phys);
    arch::SerialWrite(" mode=poll\n");
    core::CleanroomTraceRecord("e1000", "poll-worker-online", n.device_id, iface_index, worker_generation);

    E1000SelfTestTx(*ctx, n);
    return true;
}

// Returns true iff the vendor ID matched an inventory family. A match does
// not imply MMIO access or an online driver: only the explicit safe-backend
// branches below can perform hardware I/O. A matched-but-not-brought-up
// device stays in the registry as `(probe only)`.
//
// `iface_index` is the network-stack interface slot this NIC will
// occupy once added to g_nics[]. It equals g_nic_count at call time
// and is passed through to E1000BringUp so each controller is bound
// to a distinct stack slot.
bool RunVendorProbe(NicInfo& n, u32 iface_index)
{
    const char* family = nullptr;
    switch (n.vendor_id)
    {
    case kVendorIntel:
        family = IntelNicTag(n.device_id);
        break;
    case kVendorRealtek:
        family = RealtekNicTag(n.device_id);
        break;
    case kVendorBroadcom:
        family = BroadcomNicTag(n.device_id, n.subsystem_vendor_id, n.subsystem_device_id, n.subsystem_known);
        break;
    case kVendorRedHatVirt:
        family = VirtioNetTag(n.device_id);
        break;
    case kVendorMediaTek:
    case kVendorIttim:
        family = MediatekNicTag(n.vendor_id, n.device_id);
        if (family == nullptr)
            return false;
        break;
    case kVendorAmd:
        // AMD PCnet (Am79C970A/Am79C973) — VirtualBox's default adapter.
        if (n.device_id != 0x2000)
            return false;
        family = "pcnet-am79c970";
        break;
    default:
        return false;
    }
    n.family = family;
    bool brought_up = false;
    bool wireless_shell = false;
    if (n.vendor_id == kVendorIntel && nic_ids::IntelE1000BringUpEligible(n.device_id))
    {
        // Only the explicit 100E and 10D3 emulator-backed profiles reach
        // MMIO. E1000BringUp enables PCI memory decode before its sole
        // post-reset MAC/status read; every other Intel family is inventory.
        brought_up = E1000BringUp(n, iface_index);
    }
    // Wireless dispatch — order matters only insofar as each `Matches`
    // is keyed off vendor_id, so at most one will fire per NIC.
    else if (IwlwifiMatches(n.vendor_id, n.device_id))
    {
        wireless_shell = IwlwifiBringUp(n);
        brought_up = wireless_shell;
    }
    else if (Rtl88xxMatches(n.vendor_id, n.device_id))
    {
        wireless_shell = Rtl88xxBringUp(n);
        brought_up = wireless_shell;
    }
    else if (Bcm43xxMatches(n))
    {
        wireless_shell = Bcm43xxBringUp(n);
        brought_up = wireless_shell;
    }
    else if (Mt76Matches(n.vendor_id, n.device_id))
    {
        wireless_shell = Mt76BringUp(n);
        brought_up = wireless_shell;
    }
    else if (n.vendor_id == kVendorAmd && n.device_id == 0x2000)
    {
        brought_up = PcnetBringUp(n, iface_index);
    }
    else if (n.vendor_id == kVendorRedHatVirt && nic_ids::VirtioNetBringUpEligible(n.device_id))
    {
        pci::DeviceAddress address{};
        address.bus = n.bus;
        address.device = n.device;
        address.function = n.function;
        ::duetos::drivers::virtio::VirtioNetActivation activation{};
        brought_up = ::duetos::drivers::virtio::VirtioNetRestart(address, iface_index, &activation);
        if (brought_up)
        {
            for (u32 i = 0; i < 6; ++i)
                n.mac[i] = activation.mac[i];
            n.mac_valid = activation.mac_valid;
            n.link_up = activation.link_up;
            n.driver_online = true;
            n.firmware_pending = false;
            n.wireless_fw_state = NicInfo::WirelessFwState::NotApplicable;
        }
    }
    {
        // Hold the serial line lock across the full vid/did/family
        // print so a concurrent [dhcp] (or any other writer firing
        // off another task) can't interleave at a SerialWrite call
        // boundary. Smoke-test grep matches the line as a single
        // substring; without the guard the line was occasionally
        // split.
        arch::SerialLineGuard line;
        arch::SerialWrite("[net-probe] vid=");
        arch::SerialWriteHex(n.vendor_id);
        arch::SerialWrite(" did=");
        arch::SerialWriteHex(n.device_id);
        arch::SerialWrite(" family=");
        arch::SerialWrite(family);
        if (wireless_shell)
            arch::SerialWrite("  (driver shell online — firmware pending)\n");
        else if (brought_up)
            arch::SerialWrite("  (driver online)\n");
        else
            arch::SerialWrite("  (probe only — no packet I/O)\n");
    }
    if (n.mac_valid)
    {
        arch::SerialLineGuard line;
        arch::SerialWrite("[net-probe]   mac=");
        for (u64 i = 0; i < 6; ++i)
        {
            if (i != 0)
                arch::SerialWrite(":");
            arch::SerialWriteHex(n.mac[i]);
        }
        arch::SerialWrite(n.link_up ? "  link=up\n" : "  link=down\n");
    }
    return true;
}

void LogNic(const NicInfo& n)
{
    arch::SerialWrite("  nic ");
    arch::SerialWriteHex(n.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(n.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(n.function);
    arch::SerialWrite("  vid=");
    arch::SerialWriteHex(n.vendor_id);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(n.device_id);
    arch::SerialWrite(" vendor=\"");
    arch::SerialWrite(n.vendor);
    arch::SerialWrite("\" sub=");
    arch::SerialWrite(SubclassName(n.subclass));
    if (n.mmio_size != 0)
    {
        arch::SerialWrite(" bar");
        arch::SerialWriteHex(n.mmio_bar);
        arch::SerialWrite("=");
        arch::SerialWriteHex(n.mmio_phys);
        arch::SerialWrite("/");
        arch::SerialWriteHex(n.mmio_size);
        if (n.mmio_virt != nullptr)
        {
            arch::SerialWrite(" -> ");
            arch::SerialWriteHex(reinterpret_cast<u64>(n.mmio_virt));
        }
    }
    arch::SerialWrite("\n");
}

bool NicRecordIsWireless(const NicInfo& nic)
{
    return nic.subclass == kPciSubclassOther || nic_ids::NicFamilyLooksWireless(nic.family);
}

} // namespace

::duetos::core::Result<void> NetInit()
{
    KLOG_TRACE_SCOPE("drivers/net", "NetInit");
    {
        sync::SpinLockGuard guard(g_nic_registry_lock);
        if (g_nic_registry_state == NicRegistryState::Running)
            return {};
        if (g_nic_registry_state != NicRegistryState::Stopped)
            return ::duetos::core::Err{::duetos::core::ErrorCode::Busy};
        g_nic_registry_state = NicRegistryState::Starting;
    }

    const u64 n = pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_nic_count < kMaxNics; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code != kPciClassNetwork)
            continue;

        NicInfo nic = {};
        nic.vendor_id = d.vendor_id;
        nic.device_id = d.device_id;
        nic.subsystem_vendor_id = d.subsystem_vendor_id;
        nic.subsystem_device_id = d.subsystem_device_id;
        nic.bus = d.addr.bus;
        nic.device = d.addr.device;
        nic.function = d.addr.function;
        nic.class_code = d.class_code;
        nic.subclass = d.subclass;
        nic.programming_interface = d.programming_interface;
        nic.revision_id = d.revision_id;
        nic.subsystem_known = d.subsystem_known;
        nic.vendor = VendorShort(d.vendor_id);

        // The PCI cache is immutable for an enumeration epoch. Revalidate the
        // complete endpoint identity before BAR sizing or backend dispatch so
        // a removed/replaced function cannot inherit the cached driver's
        // register contract. Concrete backends may repeat this immediately
        // before their first hardware write.
        if (!LivePciIdentityMatches(nic))
        {
            KLOG_WARN_V("drivers/net", "cached NIC identity changed; device skipped", nic.device_id);
            continue;
        }

        // Classification does not authorize MMIO. Only a backend whose
        // register contract is explicitly safe gets a mapping. Realtek's
        // metadata records BAR2 for future split backends, but its safe-probe
        // gate is closed, so no speculative register read occurs.
        nic.mmio_bar = d.vendor_id == kVendorRealtek ? nic_ids::RealtekWirelessPreferredMmioBar(d.device_id) : 0;
        const bool requires_mapped_mmio =
            (d.vendor_id == kVendorIntel && nic_ids::IntelE1000BringUpEligible(d.device_id)) ||
            IwlwifiMatches(d.vendor_id, d.device_id) || Rtl88xxMatches(d.vendor_id, d.device_id) ||
            Bcm43xxMatches(nic) || Mt76Matches(d.vendor_id, d.device_id);
        if (requires_mapped_mmio)
        {
            if (!DisablePciBusMasterForProbe(d.addr))
            {
                KLOG_ERROR_V("drivers/net", "could not disarm NIC before BAR sizing", nic.device_id);
            }
            else
            {
                const pci::Bar bar = pci::PciReadBar(d.addr, nic.mmio_bar);
                const u64 minimum_bytes =
                    (d.vendor_id == kVendorIntel && nic_ids::IntelE1000BringUpEligible(d.device_id))
                        ? kE1000MinimumMmioBytes
                        : 1;
                if (bar.size >= minimum_bytes && !bar.is_io)
                {
                    nic.mmio_phys = bar.address;
                    constexpr u64 kMmioCap = 2ULL * 1024 * 1024;
                    const u64 map_bytes = (bar.size > kMmioCap) ? kMmioCap : bar.size;
                    nic.mmio_virt = AcquireNicMmioMapping(d.addr, nic.mmio_bar, bar.address, map_bytes);
                    if (nic.mmio_virt != nullptr)
                        nic.mmio_size = map_bytes;
                }
            }
        }

        // Probe contract: false means no vendor matched. Unknown devices
        // never reached an MMIO mapping because mapping eligibility was
        // decided independently above; skip the registry add.
        // iface_index is the g_nics[] slot this NIC will occupy on
        // success — equal to g_nic_count before the increment below.
        if (!RunVendorProbe(nic, u32(g_nic_count)))
        {
            KLOG_WARN_V("drivers/net", "no vendor match; device skipped did", nic.device_id);
            KBP_PROBE_V(::duetos::debug::ProbeId::kProbeFail, nic.device_id);
            continue;
        }
        const u64 nic_index = g_nic_count++;
        g_nics[nic_index] = nic;
        if (g_nics[nic_index].driver_online && NicRecordIsWireless(g_nics[nic_index]))
        {
            if (IwlwifiMatches(g_nics[nic_index].vendor_id, g_nics[nic_index].device_id))
                IwlwifiStartWatch(g_nics[nic_index]);
            else if (Rtl88xxMatches(g_nics[nic_index].vendor_id, g_nics[nic_index].device_id))
                Rtl88xxStartWatch(g_nics[nic_index]);
            else if (Bcm43xxMatches(g_nics[nic_index]))
                Bcm43xxStartWatch(g_nics[nic_index]);
            else if (Mt76Matches(g_nics[nic_index].vendor_id, g_nics[nic_index].device_id))
                Mt76StartWatch(g_nics[nic_index]);
        }
    }

    core::LogWithValue(core::LogLevel::Info, "drivers/net", "discovered NICs", g_nic_count);
    for (u64 i = 0; i < g_nic_count; ++i)
    {
        LogNic(g_nics[i]);
    }
    if (g_nic_count == 0)
    {
        core::Log(core::LogLevel::Warn, "drivers/net", "no PCI network controllers found");
    }
    {
        // Publish every completed record as one release point. Readers never
        // inspect g_nics or g_nic_count while the state is Starting.
        sync::SpinLockGuard guard(g_nic_registry_lock);
        g_nic_registry_state = NicRegistryState::Running;
    }
    return {};
}

namespace
{

// Quiesce one polling e1000 controller and release its DMA rings + buffers.
// Close driver admission, retire/join the exact worker generation, drain
// already-pinned TX, then unbind the exact stack receipt before disabling PCI
// bus mastering. Any failed proof retains the stable context and DMA storage.
bool E1000QuiesceOne(E1000Ctx& ctx)
{
    if (ctx.mmio == nullptr)
        return true;

    constexpr u64 kRflagsInterruptEnable = 1ULL << 9;
    if ((arch::ReadRflags() & kRflagsInterruptEnable) == 0)
    {
        KLOG_ERROR("drivers/net/e1000", "shutdown requires ordinary task context with interrupts enabled");
        return false;
    }

    const u32 iface_index = ctx.iface_index;
    const u64 generation = DriverWorkerLeaseActiveGeneration(&ctx.rx_worker);

    (void)DriverOperationGateClose(&ctx.operations);

    if (generation != 0)
        (void)DriverWorkerLeaseRequestRetire(&ctx.rx_worker, generation);

    constexpr u32 kRetireBudgetTicks = 200;
    bool worker_done = generation == 0;
    bool operations_done = false;
    for (u32 waited = 0; waited <= kRetireBudgetTicks; ++waited)
    {
        worker_done = generation == 0 || DriverWorkerLeaseIsAcknowledged(&ctx.rx_worker, generation);
        operations_done = DriverOperationGatePinCount(&ctx.operations) == 0;
        if (worker_done && operations_done)
            break;
        if (waited != kRetireBudgetTicks)
            duetos::sched::SchedSleepTicks(1);
    }

    if (!worker_done || !operations_done)
    {
        KLOG_ERROR_2V("drivers/net/e1000", "retire timed out; DMA storage quarantined", "worker_done",
                      worker_done ? 1 : 0, "operation_pins", DriverOperationGatePinCount(&ctx.operations));
        ctx.quarantined = true;
        return false;
    }

    // The worker is the sole reader of stack_binding outside stack callbacks.
    // Join it before clearing the receipt, then drain the stack's independent
    // callback pins while the driver gate remains closed.
    if (!E1000UnbindStack(ctx))
    {
        ctx.quarantined = true;
        return false;
    }

    if (generation != 0 && !DriverWorkerLeaseRelease(&ctx.rx_worker, generation))
    {
        KLOG_ERROR("drivers/net/e1000", "worker lease release failed; context quarantined");
        ctx.quarantined = true;
        return false;
    }
    if (!E1000DisableHardware(ctx))
    {
        ctx.quarantined = true;
        return false;
    }
    E1000FreeDmaStorage(ctx);

    if (iface_index < g_nic_count)
        g_nics[iface_index].driver_online = false;
    E1000ClearRuntimeFields(ctx);

    arch::SerialWrite("[e1000] quiesced — stack/worker drained, BME off, rings freed\n");
    return true;
}

// Quiesce all online e1000 controllers and reset the per-family
// count so E1000AllocCtx works correctly after a NetInit/NetShutdown
// cycle.
bool E1000QuiesceAll()
{
    bool all_quiesced = true;
    for (u32 i = 0; i < g_e1000_count; ++i)
    {
        if (!E1000QuiesceOne(g_e1000s[i]))
            all_quiesced = false;
    }
    if (all_quiesced)
        g_e1000_count = 0;
    return all_quiesced;
}

bool HasOnlineBackendWithoutRestartContract()
{
    for (u64 i = 0; i < g_nic_count; ++i)
    {
        const NicInfo& nic = g_nics[i];
        if (!nic.driver_online)
            continue;
        if (nic.vendor_id == kVendorIntel && nic_ids::IntelE1000BringUpEligible(nic.device_id))
            continue;
        if (nic.vendor_id == kVendorAmd && nic.device_id == 0x2000)
            continue;
        if (nic.vendor_id == kVendorRedHatVirt && nic_ids::VirtioNetBringUpEligible(nic.device_id))
            continue;
        KLOG_WARN_V("drivers/net", "shutdown refused for live backend without teardown contract", nic.device_id);
        return true;
    }
    return false;
}

} // namespace

::duetos::core::Result<void> NetShutdown()
{
    KLOG_TRACE_SCOPE("drivers/net", "NetShutdown");
    {
        sync::SpinLockGuard guard(g_nic_registry_lock);
        if (g_nic_registry_state == NicRegistryState::Stopped)
            return {};
        if (g_nic_registry_state != NicRegistryState::Running && g_nic_registry_state != NicRegistryState::Quarantined)
            return ::duetos::core::Err{::duetos::core::ErrorCode::Busy};
        g_nic_registry_state = NicRegistryState::Stopping;
    }

    // Every admitted family gets a teardown attempt. Do not short-circuit:
    // one quarantined device must not leave another family live indefinitely.
    const bool unsupported_online = HasOnlineBackendWithoutRestartContract();
    const bool pcnet_quiesced = PcnetQuiesceAll();
    const bool e1000_quiesced = E1000QuiesceAll();
    const bool virtio_net_quiesced = ::duetos::drivers::virtio::VirtioNetQuiesce();
    if (unsupported_online || !pcnet_quiesced || !e1000_quiesced || !virtio_net_quiesced)
    {
        sync::SpinLockGuard guard(g_nic_registry_lock);
        g_nic_registry_state = NicRegistryState::Quarantined;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Busy};
    }

    u64 dropped = 0;
    {
        sync::SpinLockGuard guard(g_nic_registry_lock);
        dropped = g_nic_count;
        for (u64 i = 0; i < g_nic_count; ++i)
            g_nics[i] = {};
        g_nic_count = 0;
        g_nic_registry_state = NicRegistryState::Stopped;
    }
    arch::SerialWrite("[drivers/net] shutdown: dropped ");
    arch::SerialWriteHex(dropped);
    arch::SerialWrite(" NIC records\n");
    return {};
}

u64 NicCount()
{
    sync::SpinLockGuard guard(g_nic_registry_lock);
    return g_nic_registry_state == NicRegistryState::Running ? g_nic_count : 0;
}

bool NicSnapshot(u64 index, NicInfo* out)
{
    if (out == nullptr)
        return false;
    sync::SpinLockGuard guard(g_nic_registry_lock);
    if (g_nic_registry_state != NicRegistryState::Running || index >= g_nic_count)
        return false;
    *out = g_nics[index];
    return true;
}

bool NicIsWireless(u64 index)
{
    NicInfo nic{};
    if (!NicSnapshot(index, &nic))
        return false;
    // PCI subclass 0x80 is "network controller / other" — vendors
    // ship their wireless cards there since there's no dedicated
    // PCI subclass for Wi-Fi. The family tag is the secondary
    // signal for vendors that put wireless on subclass 0x00 by
    // mistake (or pre-PCIe legacy).
    return NicRecordIsWireless(nic);
}

WirelessStatus WirelessStatusRead()
{
    WirelessStatus s = {};
    sync::SpinLockGuard guard(g_nic_registry_lock);
    if (g_nic_registry_state != NicRegistryState::Running)
        return s;
    for (u64 i = 0; i < g_nic_count; ++i)
    {
        if (!NicRecordIsWireless(g_nics[i]))
            continue;
        ++s.adapters_detected;
        if (g_nics[i].driver_online)
            ++s.drivers_online;
        switch (g_nics[i].wireless_fw_state)
        {
        case NicInfo::WirelessFwState::Ready:
            ++s.firmware_ready;
            break;
        case NicInfo::WirelessFwState::Missing:
            ++s.firmware_missing;
            break;
        case NicInfo::WirelessFwState::Incompatible:
            ++s.firmware_incompatible;
            break;
        case NicInfo::WirelessFwState::LoadError:
            ++s.firmware_load_error;
            break;
        case NicInfo::WirelessFwState::UploadFailed:
            ++s.firmware_upload_failed;
            break;
        case NicInfo::WirelessFwState::NotApplicable:
            break;
        default:
            // Unknown enumerator — treat as "no firmware accounted for".
            break;
        }
    }
    return s;
}

// -------------------------------------------------------------------
// Vendor classifiers — thin wrappers over the explicit device-ID
// tables in drivers/net/nic_ids.h (single source of truth, shared
// with the wireless drivers' *Matches predicates and host-tested by
// tests/host/test_nic_ids.cpp).
// -------------------------------------------------------------------

const char* IntelNicTag(u16 device_id)
{
    const char* wifi = nic_ids::IntelWirelessTag(device_id);
    if (wifi != nullptr)
        return wifi;
    if (device_id == 0x100E)
        return "e1000-82540em";
    if (device_id == 0x10D3)
        return "e1000e-82574";
    switch (nic_ids::IntelWiredFamilyFromDeviceId(device_id))
    {
    case nic_ids::IntelWiredFamily::E1000Classic:
        return "e1000-classic";
    case nic_ids::IntelWiredFamily::E1000e:
        return "e1000e";
    case nic_ids::IntelWiredFamily::Igb:
        return "igb-82575/i210/i350";
    case nic_ids::IntelWiredFamily::Igc:
        return "igc-i225/i226";
    case nic_ids::IntelWiredFamily::Ixgbe:
        return "ixgbe-82598/82599/x540/x550";
    case nic_ids::IntelWiredFamily::I40e:
        return "i40e-x710";
    case nic_ids::IntelWiredFamily::None:
    default:
        return "intel-nic-unknown";
    }
}

const char* RealtekNicTag(u16 device_id)
{
    const char* wifi = nic_ids::RealtekWirelessTag(device_id);
    if (wifi != nullptr)
        return wifi;
    const char* wired = nic_ids::RealtekWiredTag(device_id);
    return wired != nullptr ? wired : "realtek-unknown";
}

const char* BroadcomNicTag(u16 device_id, u16 subsystem_vendor_id, u16 subsystem_device_id, bool subsystem_known)
{
    // bcm57xx wired (tg3 family — gigabit ethernet).
    if (device_id >= 0x1600 && device_id <= 0x16FF)
        return "bcm57xx-tg3";
    const char* wifi =
        nic_ids::BroadcomWirelessTagFromIdentity(device_id, subsystem_vendor_id, subsystem_device_id, subsystem_known);
    return wifi != nullptr ? wifi : "broadcom-unknown";
}

const char* VirtioNetTag(u16 device_id)
{
    // virtio-net uses the "transitional" PCI ID 0x1000 or the
    // modern PCI ID 0x1041.
    if (device_id == 0x1000 || device_id == 0x1041)
        return "virtio-net";
    return "virtio-unknown-class";
}

const char* MediatekNicTag(u16 vendor_id, u16 device_id)
{
    return Mt76InventoryTag(Mt76FamilyFromIdentity(vendor_id, device_id));
}

namespace
{

::duetos::core::Result<void> RegisterNetModule()
{
    ::duetos::security::RegisterDriverDomain(
        "drivers/net", []() -> ::duetos::core::Result<void> { return ::duetos::drivers::net::NetInit(); },
        []() -> ::duetos::core::Result<void> { return ::duetos::drivers::net::NetShutdown(); });
    return {};
}

} // namespace

KERNEL_INITCALL(Drivers, "drivers/net.module", RegisterNetModule)

} // namespace duetos::drivers::net
