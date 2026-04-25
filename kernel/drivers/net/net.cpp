#include "net.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../../net/stack.h"
#include "../../sched/sched.h"
#include "../pci/pci.h"
#include "bcm43xx.h"
#include "iwlwifi.h"
#include "rtl88xx.h"

namespace duetos::drivers::net
{

namespace
{

NicInfo g_nics[kMaxNics] = {};
u64 g_nic_count = 0;

// Module-scope so `NetShutdown` can clear it and the next
// `NetInit` re-walks PCI. Was a function-local `static constinit`
// while this subsystem was init-once.
constinit bool g_init_done = false;

struct VendorEntry
{
    u16 vendor_id;
    const char* short_name;
};

constexpr VendorEntry kVendors[] = {
    {kVendorIntel, "Intel"},     {kVendorRealtek, "Realtek"},   {kVendorBroadcom, "Broadcom"},
    {kVendorMarvell, "Marvell"}, {kVendorMellanox, "Mellanox"}, {kVendorRedHatVirt, "virtio-net"},
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

// Read a MMIO u32 from the NIC's mapped BAR 0. Offset is in bytes.
u32 Mmio32(const NicInfo& n, u64 offset)
{
    if (n.mmio_virt == nullptr)
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
    if (n.mmio_virt == nullptr)
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

// True for chip families whose register layout matches the e1000
// RAL/RAH/STATUS set. Covers e1000 (82540em), e1000e (82574,
// 82579, i210, i217). ixgbe / i40e have different layouts.
bool IsE1000CompatFamily(const char* family)
{
    if (family == nullptr)
        return false;
    // Prefix match — tags are strings like "e1000-82540em",
    // "e1000e-82574", "e1000e-82579/i210/i217".
    const char* p = family;
    if (p[0] != 'e' || p[1] != '1' || p[2] != '0' || p[3] != '0' || p[4] != '0')
        return false;
    // Accept "e1000" or "e1000e" prefix; reject "e10000..." etc.
    return p[5] == '\0' || p[5] == '-' || p[5] == 'e';
}

// ---------------------------------------------------------------
// Intel e1000 driver — full bring-up: reset, link up, RX/TX rings,
// packet send + RX polling task. Covers 82540EM (QEMU's default),
// 82545EM and the other "classic" e1000 variants; e1000e (PCIe
// controllers 82571+) share most of the register file but diverge
// enough (different PHY access, different flow control) that we
// keep the real driver gated to kVendorIntel + classic e1000 IDs
// for now. Wider coverage is a linear extension.
// ---------------------------------------------------------------

// Additional e1000 register offsets (CTRL / STATUS already above).
constexpr u64 kE1000RegCtrl = 0x00000;
constexpr u64 kE1000RegIcr = 0x000C0;    // Interrupt Cause Read (RC)
constexpr u64 kE1000RegImc = 0x000D8;    // Interrupt Mask Clear
constexpr u64 kE1000RegImsSet = 0x000D0; // Interrupt Mask Set
constexpr u64 kE1000RegRctl = 0x00100;   // Receive Control
constexpr u64 kE1000RegTctl = 0x00400;   // Transmit Control
constexpr u64 kE1000RegTipg = 0x00410;   // TX Inter-Packet Gap
constexpr u64 kE1000RegRdbal = 0x02800;  // RX Desc Base Addr Low
constexpr u64 kE1000RegRdbah = 0x02804;  // RX Desc Base Addr High
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
constexpr u8 kE1000RxStatusDd = 1u << 0; // Descriptor Done
// End-Of-Packet flag — every complete frame on a 2 KiB buffer has
// it set; we don't fragment-check today (short frames always
// single-descriptor) but name the bit so the next slice's jumbo
// frames / large-buffer handling doesn't have to rediscover it.
[[maybe_unused]] constexpr u8 kE1000RxStatusEop = 1u << 1;

// TX descriptor command bits.
constexpr u8 kE1000TxCmdEop = 1u << 0;  // End Of Packet
constexpr u8 kE1000TxCmdIfcs = 1u << 1; // Insert FCS
constexpr u8 kE1000TxCmdRs = 1u << 3;   // Report Status

// IMS / ICR bits that matter for RX-driven wakeups.
constexpr u32 kE1000IntTxdw = 1u << 0;   // TX Desc Written Back
constexpr u32 kE1000IntLsc = 1u << 2;    // Link Status Change
constexpr u32 kE1000IntRxdmt0 = 1u << 4; // RX Desc Min Threshold
constexpr u32 kE1000IntRxo = 1u << 6;    // RX Overrun
constexpr u32 kE1000IntRxt0 = 1u << 7;   // RX Timer (desc done)

struct E1000Ctx
{
    bool online;
    volatile u8* mmio; // BAR 0 kernel-virtual
    E1000RxDesc* rx_ring;
    mm::PhysAddr rx_ring_phys;
    mm::PhysAddr rx_buf_base_phys; // contiguous 256 × 2 KiB = 512 KiB
    u8* rx_buf_base_virt;
    u32 rx_tail;
    E1000TxDesc* tx_ring;
    mm::PhysAddr tx_ring_phys;
    mm::PhysAddr tx_buf_base_phys; // contiguous 256 × 2 KiB = 512 KiB staging
    u8* tx_buf_base_virt;
    u32 tx_tail;
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
    NicInfo* nic;
    // MSI-X state. `irq_vector` is non-zero when binding
    // succeeded; in that case the RX polling task blocks on
    // `rx_wait` and the handler wakes it on RX/link events
    // instead of running at tick cadence.
    u8 irq_vector;
    duetos::sched::WaitQueue rx_wait;
};

constinit E1000Ctx g_e1000 = {};

void E1000Write(u64 off, u32 value)
{
    *reinterpret_cast<volatile u32*>(g_e1000.mmio + off) = value;
}
u32 E1000Read(u64 off)
{
    return *reinterpret_cast<volatile u32*>(g_e1000.mmio + off);
}

// Spin a small number of cycles so the controller sees our MMIO
// writes complete before we poll related registers. 1 ms worth
// of pauses is plenty on any real NIC.
void E1000Delay()
{
    for (u32 i = 0; i < 1024; ++i)
        asm volatile("pause" ::: "memory");
}

bool E1000Reset()
{
    // Mask all interrupts, read ICR to clear any pending, then reset.
    E1000Write(kE1000RegImc, 0xFFFFFFFFu);
    (void)E1000Read(kE1000RegIcr);
    E1000Write(kE1000RegCtrl, E1000Read(kE1000RegCtrl) | kE1000CtrlRst);
    // Reset takes ~1 ms; poll CTRL.RST to clear.
    for (u32 i = 0; i < 100; ++i)
    {
        E1000Delay();
        if ((E1000Read(kE1000RegCtrl) & kE1000CtrlRst) == 0)
        {
            // Mask IRQs again — reset may have re-enabled some.
            E1000Write(kE1000RegImc, 0xFFFFFFFFu);
            (void)E1000Read(kE1000RegIcr);
            return true;
        }
    }
    arch::SerialWrite("[e1000] reset timed out\n");
    return false;
}

void E1000ClearMulticastTable()
{
    for (u32 i = 0; i < 128; ++i)
        E1000Write(kE1000RegMta0 + u64(i) * 4, 0);
}

bool E1000SetupRxRing()
{
    // One 4 KiB frame for the RX descriptor ring (256 × 16 B).
    const mm::PhysAddr ring_phys = mm::AllocateFrame();
    if (ring_phys == mm::kNullFrame)
        return false;
    auto* ring_virt = static_cast<u8*>(mm::PhysToVirt(ring_phys));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        ring_virt[i] = 0;
    g_e1000.rx_ring_phys = ring_phys;
    g_e1000.rx_ring = reinterpret_cast<E1000RxDesc*>(ring_virt);

    // 256 × 2 KiB = 128 pages contiguous for RX buffers. Each
    // descriptor points at buf_base + slot × 2048.
    constexpr u32 kRxBufPages = (kE1000RxRingSlots * kE1000RxBufBytes) / mm::kPageSize;
    const mm::PhysAddr buf_phys = mm::AllocateContiguousFrames(kRxBufPages);
    if (buf_phys == mm::kNullFrame)
    {
        mm::FreeFrame(ring_phys);
        return false;
    }
    g_e1000.rx_buf_base_phys = buf_phys;
    g_e1000.rx_buf_base_virt = static_cast<u8*>(mm::PhysToVirt(buf_phys));
    for (u32 i = 0; i < kE1000RxRingSlots; ++i)
    {
        g_e1000.rx_ring[i].addr = buf_phys + u64(i) * kE1000RxBufBytes;
        g_e1000.rx_ring[i].status = 0;
    }

    E1000Write(kE1000RegRdbal, u32(ring_phys));
    E1000Write(kE1000RegRdbah, u32(ring_phys >> 32));
    E1000Write(kE1000RegRdlen, kE1000RxRingSlots * sizeof(E1000RxDesc));
    E1000Write(kE1000RegRdh, 0);
    E1000Write(kE1000RegRdt, kE1000RxRingSlots - 1);
    g_e1000.rx_tail = kE1000RxRingSlots - 1;

    // Enable receive: broadcast accept, strip CRC, 2 KiB buffers (BSIZE=00).
    u32 rctl = kE1000RctlEn | kE1000RctlBam | kE1000RctlSecrc;
    E1000Write(kE1000RegRctl, rctl);
    return true;
}

bool E1000SetupTxRing()
{
    const mm::PhysAddr ring_phys = mm::AllocateFrame();
    if (ring_phys == mm::kNullFrame)
        return false;
    auto* ring_virt = static_cast<u8*>(mm::PhysToVirt(ring_phys));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        ring_virt[i] = 0;
    g_e1000.tx_ring_phys = ring_phys;
    g_e1000.tx_ring = reinterpret_cast<E1000TxDesc*>(ring_virt);

    constexpr u32 kTxBufPages = (kE1000TxRingSlots * kE1000RxBufBytes) / mm::kPageSize;
    const mm::PhysAddr buf_phys = mm::AllocateContiguousFrames(kTxBufPages);
    if (buf_phys == mm::kNullFrame)
    {
        mm::FreeFrame(ring_phys);
        return false;
    }
    g_e1000.tx_buf_base_phys = buf_phys;
    g_e1000.tx_buf_base_virt = static_cast<u8*>(mm::PhysToVirt(buf_phys));

    E1000Write(kE1000RegTdbal, u32(ring_phys));
    E1000Write(kE1000RegTdbah, u32(ring_phys >> 32));
    E1000Write(kE1000RegTdlen, kE1000RxRingSlots * sizeof(E1000TxDesc));
    E1000Write(kE1000RegTdh, 0);
    E1000Write(kE1000RegTdt, 0);
    g_e1000.tx_tail = 0;

    // TIPG: IPGT=10, IPGR1=8 (0xA << 10), IPGR2=6 (0x6 << 20).
    // Canonical 0x0060200A for 82540EM.
    E1000Write(kE1000RegTipg, 0x0060200AU);

    // Enable transmit: PSP, CT=0x10 (bits 4..11), COLD=0x40 (bits 12..21).
    u32 tctl = kE1000TctlEn | kE1000TctlPsp | (0x10u << 4) | (0x40u << 12);
    E1000Write(kE1000RegTctl, tctl);
    return true;
}

bool E1000Send(const u8* data, u32 len)
{
    if (!g_e1000.online || data == nullptr || len == 0)
        return false;
    if (len > kE1000RxBufBytes)
        return false;

    const u32 slot = g_e1000.tx_tail;
    u8* buf = g_e1000.tx_buf_base_virt + u64(slot) * kE1000RxBufBytes;
    for (u32 i = 0; i < len; ++i)
        buf[i] = data[i];

    E1000TxDesc& d = g_e1000.tx_ring[slot];
    d.addr = g_e1000.tx_buf_base_phys + u64(slot) * kE1000RxBufBytes;
    d.length = u16(len);
    d.cso = 0;
    d.cmd = kE1000TxCmdEop | kE1000TxCmdIfcs | kE1000TxCmdRs;
    d.sta = 0;
    d.css = 0;
    d.special = 0;

    const u32 next = (slot + 1) % kE1000TxRingSlots;
    g_e1000.tx_tail = next;
    E1000Write(kE1000RegTdt, next);
    ++g_e1000.tx_packets;
    g_e1000.tx_bytes += len;
    return true;
}

// Drain every RX descriptor whose DD bit is set. For each valid
// EOP descriptor log the first 32 bytes (ethernet dst+src+type +
// a few payload bytes). A real TCP/IP stack would hand the frame
// up to the protocol layer here; v0 just counts + logs.
void E1000DrainRx()
{
    if (!g_e1000.online)
        return;
    for (u32 checked = 0; checked < kE1000RxRingSlots; ++checked)
    {
        const u32 slot = (g_e1000.rx_tail + 1) % kE1000RxRingSlots;
        volatile E1000RxDesc& d = g_e1000.rx_ring[slot];
        if ((d.status & kE1000RxStatusDd) == 0)
            return;
        const u16 len = d.length;
        u8* buf = g_e1000.rx_buf_base_virt + u64(slot) * kE1000RxBufBytes;
        ++g_e1000.rx_packets;
        g_e1000.rx_bytes += len;
        // Hand the frame up the stack — ARP / IPv4 dispatch
        // lives in net/stack.cpp. Interface index 0 matches
        // the NetStackBindInterface call in E1000BringUp.
        duetos::net::NetStackInjectRx(/*iface_index=*/0, buf, len);
        // Release the descriptor back to the controller.
        d.status = 0;
        g_e1000.rx_tail = slot;
        E1000Write(kE1000RegRdt, slot);
    }
}

// MSI-X / MSI handler. ICR (Interrupt Cause Read) clear-on-read:
// the single read below acknowledges every pending bit in one
// shot. We don't act on the specific cause (RXT0 / RXO / LSC /
// TXDW) — the RX task drains the ring unconditionally and any
// rare link-status change is picked up the next time we look at
// the status register. Waking is enough.
void E1000IrqHandler()
{
    if (g_e1000.mmio == nullptr)
        return;
    (void)E1000Read(kE1000RegIcr);
    duetos::sched::WaitQueueWakeOne(&g_e1000.rx_wait);
}

void E1000RxPollEntry(void*)
{
    const bool have_msix = (g_e1000.irq_vector != 0);
    for (;;)
    {
        E1000DrainRx();
        if (have_msix)
        {
            // Block until IRQ wakes us. Same lost-wakeup guard
            // pattern as NVMe/xHCI: under Cli, re-check whether
            // the next RX descriptor is marked DD; if so we
            // skip blocking and loop to drain.
            duetos::arch::Cli();
            const u32 slot = (g_e1000.rx_tail + 1) % kE1000RxRingSlots;
            if ((g_e1000.rx_ring[slot].status & kE1000RxStatusDd) != 0)
            {
                duetos::arch::Sti();
                continue;
            }
            duetos::sched::WaitQueueBlock(&g_e1000.rx_wait);
        }
        else
        {
            duetos::sched::SchedSleepTicks(1);
        }
    }
}

// Spec-defined broadcast address for the self-test ARP-like blast.
constexpr u8 kBroadcastMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Minimum ethernet payload is 46 bytes; controller will pad (PSP)
// up to 60 + 4 CRC = 64-byte wire length. We ship 60 bytes of our
// own content so the padding is deterministic.
void E1000SelfTestTx(const NicInfo& n)
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

    if (E1000Send(frame, sizeof(frame)))
    {
        arch::SerialWrite("[e1000] self-test TX: 60-byte broadcast marker emitted\n");
    }
    else
    {
        arch::SerialWrite("[e1000] self-test TX: submission failed\n");
    }
}

bool E1000BringUp(NicInfo& n)
{
    if (n.mmio_virt == nullptr)
        return false;
    if (g_e1000.online)
    {
        // v0 supports a single e1000 controller; subsequent NICs
        // stay at probe level.
        return false;
    }
    g_e1000.mmio = static_cast<volatile u8*>(n.mmio_virt);
    g_e1000.nic = &n;

    if (!E1000Reset())
        return false;

    // Re-read MAC after reset (EEPROM reload populates RAL/RAH).
    ProbeE1000State(n);

    // Bring the link up + auto-speed-detect.
    const u32 ctrl = (E1000Read(kE1000RegCtrl) | kE1000CtrlSlu | kE1000CtrlAsde) & ~u32(0);
    E1000Write(kE1000RegCtrl, ctrl);
    E1000ClearMulticastTable();

    if (!E1000SetupRxRing())
        return false;
    if (!E1000SetupTxRing())
        return false;

    g_e1000.online = true;
    n.driver_online = true;
    n.firmware_pending = false;

    // MSI-X bring-up. Classic 82540EM (QEMU's `-device e1000`)
    // only exposes legacy MSI (cap 0x05), not MSI-X (0x11), so
    // PciMsixBindSimple will return Unsupported and we fall
    // back to polling. Real hardware + e1000e variants do
    // advertise MSI-X; the wiring lights up automatically there.
    {
        pci::DeviceAddress addr{};
        addr.bus = n.bus;
        addr.device = n.device;
        addr.function = n.function;
        auto r = pci::PciMsixBindSimple(addr, /*entry_index=*/0, E1000IrqHandler, /*out_route=*/nullptr);
        if (r.has_value())
        {
            g_e1000.irq_vector = r.value();
            // Enable RX + link + TX-writeback IRQ sources. Writing
            // to IMS (Interrupt Mask SET) turns bits on; IMC
            // (clear) takes them off. Read ICR once to clear any
            // pending state before we unmask.
            (void)E1000Read(kE1000RegIcr);
            const u32 mask = kE1000IntRxt0 | kE1000IntRxdmt0 | kE1000IntRxo | kE1000IntLsc | kE1000IntTxdw;
            E1000Write(kE1000RegImsSet, mask);
            arch::SerialWrite("[e1000] MSI-X bound vector=");
            arch::SerialWriteHex(g_e1000.irq_vector);
            arch::SerialWrite("\n");
        }
        else
        {
            arch::SerialWrite("[e1000] MSI-X unavailable — RX task will tick-poll\n");
        }
    }

    // Re-read link state now that we've asserted SLU — can take a
    // moment on real silicon, but QEMU brings it up instantly.
    E1000Delay();
    const u32 status = E1000Read(kE1000RegStatus);
    n.link_up = (status & kE1000StatusLinkUp) != 0;

    arch::SerialWrite("[e1000] online pci=");
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
    arch::SerialWriteHex(g_e1000.rx_ring_phys);
    arch::SerialWrite(" tx_ring=");
    arch::SerialWriteHex(g_e1000.tx_ring_phys);
    arch::SerialWrite("\n");

    // Spawn RX polling task — the real interrupt path comes in the
    // MSI-X wiring follow-up. Polling at 10 ms is plenty for v0
    // (QEMU's user netdev generates no traffic unless the host
    // initiates; on real hardware the tick cadence is unrelated to
    // line rate since we're draining a batch per tick).
    duetos::sched::SchedCreate(E1000RxPollEntry, nullptr, "e1000-rx-poll");

    // Bind to the network stack. Static IP 10.0.2.15 matches
    // QEMU's default SLIRP DHCP lease so the host can ping us
    // without manual configuration. Real hardware will want a
    // DHCP client or a cmdline override — follow-up slice.
    auto tx_trampoline = [](u32 iface_index, const void* frame, u64 len) -> bool
    {
        (void)iface_index;
        return E1000Send(static_cast<const u8*>(frame), u32(len));
    };
    duetos::net::MacAddress mac{};
    for (u64 i = 0; i < 6; ++i)
        mac.octets[i] = n.mac[i];
    // Start with the all-zero IP so DHCP's DISCOVER uses the
    // correct src=0.0.0.0. The stack rebinds iface 0 to the
    // leased IP on ACK.
    duetos::net::Ipv4Address ip{{0, 0, 0, 0}};
    duetos::net::NetStackBindInterface(/*iface_index=*/0, mac, ip, tx_trampoline);
    duetos::net::DhcpStart(/*iface_index=*/0);

    // Self-test: emit one broadcast frame so a tcpdump on the host
    // side can confirm the TX path works end-to-end.
    E1000SelfTestTx(n);
    return true;
}

void RunVendorProbe(NicInfo& n)
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
        family = BroadcomNicTag(n.device_id);
        break;
    case kVendorRedHatVirt:
        family = VirtioNetTag(n.device_id);
        break;
    default:
        return;
    }
    n.family = family;
    bool brought_up = false;
    bool wireless_shell = false;
    if (n.vendor_id == kVendorIntel && IsE1000CompatFamily(family))
    {
        ProbeE1000State(n);
        // Accept classic e1000 (82540-family, 0x1000..0x107F), early
        // e1000e PCIe variants (82571..82583, 0x10A4..0x10FF) and
        // modern e1000e (i210/i217/i218/i219, 0x1500..0x15FF). The
        // register layout the driver touches (CTRL, STATUS, RCTL,
        // TCTL, RAL/RAH, RDBAL/TDBAL descriptor rings) is common
        // across the family; PHY access + EEPROM differ but the
        // v0 driver doesn't use either. MSI-X capability presence
        // is detected at runtime via PciMsixBindSimple — the
        // same code path succeeds on e1000e and falls back to
        // polling on classic e1000.
        const bool is_classic = (n.device_id >= 0x1000 && n.device_id <= 0x107F);
        const bool is_e1000e_early = (n.device_id >= 0x10A4 && n.device_id <= 0x10FF);
        const bool is_e1000e_modern = (n.device_id >= 0x1500 && n.device_id <= 0x15FF);
        if (is_classic || is_e1000e_early || is_e1000e_modern)
        {
            brought_up = E1000BringUp(n);
        }
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
    else if (Bcm43xxMatches(n.vendor_id, n.device_id))
    {
        wireless_shell = Bcm43xxBringUp(n);
        brought_up = wireless_shell;
    }
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
    if (n.mac_valid)
    {
        arch::SerialWrite("[net-probe]   mac=");
        for (u64 i = 0; i < 6; ++i)
        {
            if (i != 0)
                arch::SerialWrite(":");
            arch::SerialWriteHex(n.mac[i]);
        }
        arch::SerialWrite(n.link_up ? "  link=up\n" : "  link=down\n");
    }
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
        arch::SerialWrite(" bar0=");
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

} // namespace

void NetInit()
{
    KLOG_TRACE_SCOPE("drivers/net", "NetInit");
    if (g_init_done)
        return;
    g_init_done = true;

    const u64 n = pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_nic_count < kMaxNics; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code != kPciClassNetwork)
            continue;

        NicInfo nic = {};
        nic.vendor_id = d.vendor_id;
        nic.device_id = d.device_id;
        nic.bus = d.addr.bus;
        nic.device = d.addr.device;
        nic.function = d.addr.function;
        nic.subclass = d.subclass;
        nic.vendor = VendorShort(d.vendor_id);

        const pci::Bar bar0 = pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0 && !bar0.is_io)
        {
            nic.mmio_phys = bar0.address;
            nic.mmio_size = bar0.size;
            // Cap at 2 MiB — NIC register files are tiny (<256 KiB);
            // bigger BARs on HPC NICs are for RDMA doorbells which
            // no v0 driver touches.
            constexpr u64 kMmioCap = 2ULL * 1024 * 1024;
            const u64 map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
            nic.mmio_virt = mm::MapMmio(bar0.address, map_bytes);
        }

        RunVendorProbe(nic);
        g_nics[g_nic_count++] = nic;
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
}

::duetos::core::Result<void> NetShutdown()
{
    KLOG_TRACE_SCOPE("drivers/net", "NetShutdown");
    const u64 dropped = g_nic_count;
    g_nic_count = 0;
    g_init_done = false;
    arch::SerialWrite("[drivers/net] shutdown: dropped ");
    arch::SerialWriteHex(dropped);
    arch::SerialWrite(" NIC records (MMIO mappings retained)\n");
    return {};
}

u64 NicCount()
{
    return g_nic_count;
}

const NicInfo& Nic(u64 index)
{
    KASSERT_WITH_VALUE(index < g_nic_count, "drivers/net", "Nic index out of range", index);
    return g_nics[index];
}

namespace
{

bool StrPrefixMatches(const char* s, const char* prefix)
{
    if (s == nullptr || prefix == nullptr)
        return false;
    for (u32 i = 0; prefix[i] != '\0'; ++i)
    {
        if (s[i] == '\0' || s[i] != prefix[i])
            return false;
    }
    return true;
}

bool FamilyLooksWireless(const char* family)
{
    if (family == nullptr)
        return false;
    // Match the families our vendor-tag tables emit for wireless
    // adapters: iwlwifi (Intel), rtl8821ae-wifi (Realtek),
    // bcm4331-wifi (Broadcom). Substring-checked at the prefix
    // since the suffixes drift across silicon revisions.
    return StrPrefixMatches(family, "iwlwifi") || StrPrefixMatches(family, "rtl8821") ||
           StrPrefixMatches(family, "bcm43") || StrPrefixMatches(family, "bcm4331") ||
           StrPrefixMatches(family, "rtl88");
}

} // namespace

bool NicIsWireless(u64 index)
{
    if (index >= g_nic_count)
        return false;
    const NicInfo& n = g_nics[index];
    // PCI subclass 0x80 is "network controller / other" — vendors
    // ship their wireless cards there since there's no dedicated
    // PCI subclass for Wi-Fi. The family tag is the secondary
    // signal for vendors that put wireless on subclass 0x00 by
    // mistake (or pre-PCIe legacy).
    return n.subclass == kPciSubclassOther || FamilyLooksWireless(n.family);
}

WirelessStatus WirelessStatusRead()
{
    WirelessStatus s = {};
    for (u64 i = 0; i < g_nic_count; ++i)
    {
        if (!NicIsWireless(i))
            continue;
        ++s.adapters_detected;
        if (g_nics[i].driver_online)
            ++s.drivers_online;
    }
    return s;
}

// -------------------------------------------------------------------
// Vendor classifiers. Coarse ranges; unknown IDs land on "unknown".
// Source: Linux kernel driver pci_device_id tables.
// -------------------------------------------------------------------

const char* IntelNicTag(u16 device_id)
{
    // e1000 (82540..82547) → gigabit legacy. Every "82..." in the
    // 0x1000..0x107F range is e1000 family.
    if (device_id >= 0x1000 && device_id <= 0x107F)
        return "e1000-82540em";
    // e1000e (82571..82579) — PCIe variants. Many device IDs.
    if (device_id >= 0x10A0 && device_id <= 0x10FB)
        return "e1000e-82574";
    if (device_id >= 0x1501 && device_id <= 0x15FF)
        return "e1000e-82579/i210/i217";
    // ixgbe (82598..82599 + X540/X550/X710) — 10/25/40 Gbps.
    if (device_id >= 0x10B6 && device_id <= 0x10FB)
        return "ixgbe-82598";
    if (device_id >= 0x1528 && device_id <= 0x1560)
        return "ixgbe-x540/x550";
    // i40e (X710/XL710) — 40 Gbps.
    if (device_id >= 0x1572 && device_id <= 0x158B)
        return "i40e-x710";
    // Wi-Fi: iwlwifi covers 1000/4965/5000/6000/7000/8000/9000/AX/Be.
    // The PCI IDs are scattered — match the Linux iwlwifi pci_table
    // family-by-family rather than as one coarse range.
    //
    //   1000/100        : 0x0083, 0x0084, 0x0085, 0x0087, 0x0089, 0x008A, 0x008B
    //   6000            : 0x0082..0x0091, 0x008D..0x008E
    //   4965            : 0x4229, 0x4230
    //   5000/5150       : 0x4232..0x423D
    //   7260/3160       : 0x08B1..0x08B4
    //   7265/3165/3168  : 0x095A, 0x095B
    //   8260/3168       : 0x24F3, 0x24F4, 0x24F5, 0x24FD
    //   9000/AX         : 0x2526, 0x271B, 0x271C, 0x30DC, 0x31DC, 0x9DF0, 0xA370
    //   AX200/AX201/AX210: 0x2723, 0x2725, 0x7AF0, 0x7E40, 0xA0F0, 0x43F0
    //   Be200/Be201     : 0x272B, 0x51F0, 0x51F1, 0xD2F0, 0xE2F0
    if (device_id == 0x4229 || device_id == 0x4230)
        return "iwlwifi-4965";
    if (device_id >= 0x4232 && device_id <= 0x423D)
        return "iwlwifi-5000";
    if ((device_id >= 0x0082 && device_id <= 0x0091) || device_id == 0x008D || device_id == 0x008E)
        return "iwlwifi-6000";
    if (device_id == 0x0083 || device_id == 0x0084 || device_id == 0x0085 || device_id == 0x0087 ||
        device_id == 0x0089 || device_id == 0x008A || device_id == 0x008B)
        return "iwlwifi-1000";
    if (device_id >= 0x08B1 && device_id <= 0x08B4)
        return "iwlwifi-7260";
    if (device_id == 0x095A || device_id == 0x095B)
        return "iwlwifi-7265";
    if (device_id == 0x24F3 || device_id == 0x24F4 || device_id == 0x24F5 || device_id == 0x24FD)
        return "iwlwifi-8260";
    if (device_id == 0x2526 || device_id == 0x271B || device_id == 0x271C || device_id == 0x30DC ||
        device_id == 0x31DC || device_id == 0x9DF0 || device_id == 0xA370)
        return "iwlwifi-9000";
    if (device_id == 0x2723 || device_id == 0x2725 || device_id == 0x7AF0 || device_id == 0x7E40 ||
        device_id == 0xA0F0 || device_id == 0x43F0)
        return "iwlwifi-AX2xx";
    if (device_id == 0x272B || device_id == 0x51F0 || device_id == 0x51F1 || device_id == 0xD2F0 || device_id == 0xE2F0)
        return "iwlwifi-Be2xx";
    return "intel-nic-unknown";
}

const char* RealtekNicTag(u16 device_id)
{
    switch (device_id)
    {
    // Wired
    case 0x8139:
        return "rtl8139";
    case 0x8168:
    case 0x8169:
        return "rtl8169";
    case 0x8136:
        return "rtl8101e";
    case 0x8125:
        return "rtl8125-2.5g";
    // Wireless: rtl88xx family — covers Wi-Fi 4/5/6 PCIe parts. The
    // family tag drives the bring-up dispatch in RunVendorProbe.
    case 0x8723:
    case 0xB723:
        return "rtl8723be-wifi";
    case 0x8812:
    case 0xB812:
        return "rtl8812ae-wifi";
    case 0x8813:
    case 0xB813:
        return "rtl8813ae-wifi";
    case 0x8814:
    case 0xB814:
        return "rtl8814ae-wifi";
    case 0x8821:
    case 0xC821:
    case 0xC822:
    case 0xC820:
        return "rtl8821ae-wifi";
    case 0x8822:
    case 0xB822:
        return "rtl8822be-wifi";
    case 0x8852:
    case 0xB852:
        return "rtl8852ae-wifi";
    default:
        return "realtek-unknown";
    }
}

const char* BroadcomNicTag(u16 device_id)
{
    // bcm57xx wired (tg3 family — gigabit ethernet).
    if (device_id >= 0x1600 && device_id <= 0x16FF)
        return "bcm57xx-tg3";
    // bcm43xx wireless: Linux maps the entire 0x4300..0x43FF range
    // to b43/brcmsmac/brcmfmac silicon. Subdivide so the bring-up
    // logging tags the rough generation.
    if (device_id >= 0x4300 && device_id <= 0x4329)
        return "bcm4318-wifi";
    if (device_id == 0x4331 || device_id == 0x4350 || device_id == 0x4351 || device_id == 0x4357 ||
        device_id == 0x4358 || device_id == 0x4359)
        return "bcm4331-wifi";
    if (device_id >= 0x4350 && device_id <= 0x4360)
        return "bcm43602-wifi";
    if (device_id >= 0x43A0 && device_id <= 0x43FF)
        return "bcm43xx-wifi";
    if (device_id == 0x4727)
        return "bcm4313-wifi";
    return "broadcom-unknown";
}

const char* VirtioNetTag(u16 device_id)
{
    // virtio-net uses the "transitional" PCI ID 0x1000 or the
    // modern PCI ID 0x1041.
    if (device_id == 0x1000 || device_id == 0x1041)
        return "virtio-net";
    return "virtio-unknown-class";
}

} // namespace duetos::drivers::net
