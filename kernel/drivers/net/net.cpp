/*
 * DuetOS — network driver glue layer: implementation.
 *
 * Companion to net.h — see there for the per-interface record,
 * driver-vtable shape, and the TX/RX queue contract the upper
 * stack consumes.
 *
 * WHAT
 *   The thin layer between concrete NIC drivers (e1000, RTL,
 *   USB-CDC-ECM, RNDIS) and the in-kernel TCP/IP stack
 *   (kernel/net/stack.cpp). Owns the active-interface table,
 *   driver registration, packet enqueue, and the shell-facing
 *   diagnostic dumpers behind `ifconfig` / `netscan`.
 *
 * HOW
 *   Drivers call `NetRegisterInterface(vtable, hw_addr)` at
 *   probe time; the layer stashes the vtable and exposes a
 *   uniform `NetTxPacket` / `NetRxPoll` to the stack. RX
 *   pollers run from a dedicated kernel thread per NIC; TX
 *   submissions come synchronously from the stack and either
 *   immediately enqueue or block on the NIC's driver lock.
 *
 * WHY THIS FILE IS LARGE
 *   Diagnostic surface — every NIC type wants its own pretty-
 *   print of state, every command (ifconfig / dhcp / route /
 *   netscan) lives here, and the wireless-credentials helper
 *   for the wifi flyout panel adds another section.
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
#include "drivers/net/rtl88xx.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "security/driver_domain.h"

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
    {kVendorIntel, "Intel"},       {kVendorRealtek, "Realtek"},   {kVendorBroadcom, "Broadcom"},
    {kVendorMarvell, "Marvell"},   {kVendorMellanox, "Mellanox"}, {kVendorRedHatVirt, "virtio-net"},
    {kVendorMediaTek, "MediaTek"},
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
constexpr u64 kE1000RegIvar = 0x000E4;   // Interrupt Vector Allocation Register (82574/e1000e)
constexpr u64 kE1000RegIvargp = 0x000E8; // IVAR misc/other causes group
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
constexpr u32 kE1000IvarValid = 1u << 7; // per-byte IVAR "entry valid"

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
    u64 rx_dropped; // RX descriptors dropped for out-of-range length
    u64 tx_packets;
    u64 tx_bytes;
    NicInfo* nic;
    // Network-stack interface index this controller is bound to.
    // Set in E1000BringUp; used by E1000DrainRx to route frames
    // to the right stack slot. Each e1000 gets a distinct index
    // matching its g_nics[] position.
    u32 iface_index;
    // MSI-X state. `irq_vector` is non-zero when binding
    // succeeded; in that case the RX polling task blocks on
    // `rx_wait` and the handler wakes it on RX/link events
    // instead of running at tick cadence.
    u8 irq_vector;
    duetos::sched::WaitQueue rx_wait;
};

// Per-controller state. One slot per discovered e1000 adapter;
// the count mirrors the order in which E1000BringUp() is called
// during NetInit. kMaxNics (4) is an upper bound — the stack
// also caps at kMaxInterfaces (4) so the indices line up cleanly.
constexpr u32 kMaxE1000 = 4;
E1000Ctx g_e1000s[kMaxE1000] = {};
u32 g_e1000_count = 0;

// Per-controller MMIO helpers — each function takes an explicit
// ctx so all the driver functions work on whichever controller
// the caller is operating on instead of a file-scope singleton.
void E1000Write(E1000Ctx& ctx, u64 off, u32 value)
{
    *reinterpret_cast<volatile u32*>(ctx.mmio + off) = value;
}
u32 E1000Read(E1000Ctx& ctx, u64 off)
{
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
    auto ring_phys_r = mm::AllocateFrame();
    if (!ring_phys_r)
        return false;
    const mm::PhysAddr ring_phys = ring_phys_r.value();
    auto* ring_virt = static_cast<u8*>(mm::PhysToVirt(ring_phys));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        ring_virt[i] = 0;
    ctx.rx_ring_phys = ring_phys;
    ctx.rx_ring = reinterpret_cast<E1000RxDesc*>(ring_virt);

    // 256 × 2 KiB = 128 pages contiguous for RX buffers. Each
    // descriptor points at buf_base + slot × 2048.
    constexpr u32 kRxBufPages = (kE1000RxRingSlots * kE1000RxBufBytes) / mm::kPageSize;
    auto buf_phys_r = mm::AllocateContiguousFrames(kRxBufPages);
    if (!buf_phys_r)
    {
        mm::FreeFrame(ring_phys);
        return false;
    }
    const mm::PhysAddr buf_phys = buf_phys_r.value();
    ctx.rx_buf_base_phys = buf_phys;
    ctx.rx_buf_base_virt = static_cast<u8*>(mm::PhysToVirt(buf_phys));
    for (u32 i = 0; i < kE1000RxRingSlots; ++i)
    {
        ctx.rx_ring[i].addr = buf_phys + u64(i) * kE1000RxBufBytes;
        ctx.rx_ring[i].status = 0;
    }

    E1000Write(ctx, kE1000RegRdbal, u32(ring_phys));
    E1000Write(ctx, kE1000RegRdbah, u32(ring_phys >> 32));
    E1000Write(ctx, kE1000RegRdlen, kE1000RxRingSlots * sizeof(E1000RxDesc));
    E1000Write(ctx, kE1000RegRdh, 0);
    E1000Write(ctx, kE1000RegRdt, kE1000RxRingSlots - 1);
    ctx.rx_tail = kE1000RxRingSlots - 1;

    // Enable receive: broadcast accept, strip CRC, 2 KiB buffers (BSIZE=00).
    u32 rctl = kE1000RctlEn | kE1000RctlBam | kE1000RctlSecrc;
    E1000Write(ctx, kE1000RegRctl, rctl);
    return true;
}

bool E1000SetupTxRing(E1000Ctx& ctx)
{
    auto ring_phys_r = mm::AllocateFrame();
    if (!ring_phys_r)
        return false;
    const mm::PhysAddr ring_phys = ring_phys_r.value();
    auto* ring_virt = static_cast<u8*>(mm::PhysToVirt(ring_phys));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        ring_virt[i] = 0;
    ctx.tx_ring_phys = ring_phys;
    ctx.tx_ring = reinterpret_cast<E1000TxDesc*>(ring_virt);

    constexpr u32 kTxBufPages = (kE1000TxRingSlots * kE1000RxBufBytes) / mm::kPageSize;
    auto buf_phys_r = mm::AllocateContiguousFrames(kTxBufPages);
    if (!buf_phys_r)
    {
        mm::FreeFrame(ring_phys);
        return false;
    }
    const mm::PhysAddr buf_phys = buf_phys_r.value();
    ctx.tx_buf_base_phys = buf_phys;
    ctx.tx_buf_base_virt = static_cast<u8*>(mm::PhysToVirt(buf_phys));

    E1000Write(ctx, kE1000RegTdbal, u32(ring_phys));
    E1000Write(ctx, kE1000RegTdbah, u32(ring_phys >> 32));
    E1000Write(ctx, kE1000RegTdlen, kE1000RxRingSlots * sizeof(E1000TxDesc));
    E1000Write(ctx, kE1000RegTdh, 0);
    E1000Write(ctx, kE1000RegTdt, 0);
    ctx.tx_tail = 0;

    // TIPG: IPGT=10, IPGR1=8 (0xA << 10), IPGR2=6 (0x6 << 20).
    // Canonical 0x0060200A for 82540EM.
    E1000Write(ctx, kE1000RegTipg, 0x0060200AU);

    // Enable transmit: PSP, CT=0x10 (bits 4..11), COLD=0x40 (bits 12..21).
    u32 tctl = kE1000TctlEn | kE1000TctlPsp | (0x10u << 4) | (0x40u << 12);
    E1000Write(ctx, kE1000RegTctl, tctl);
    return true;
}

bool E1000Send(E1000Ctx& ctx, const u8* data, u32 len)
{
    if (!ctx.online || data == nullptr || len == 0)
        return false;
    if (len > kE1000RxBufBytes)
        return false;

    const u32 slot = ctx.tx_tail;
    u8* buf = ctx.tx_buf_base_virt + u64(slot) * kE1000RxBufBytes;
    for (u32 i = 0; i < len; ++i)
        buf[i] = data[i];

    E1000TxDesc& d = ctx.tx_ring[slot];
    d.addr = ctx.tx_buf_base_phys + u64(slot) * kE1000RxBufBytes;
    d.length = u16(len);
    d.cso = 0;
    d.cmd = kE1000TxCmdEop | kE1000TxCmdIfcs | kE1000TxCmdRs;
    d.sta = 0;
    d.css = 0;
    d.special = 0;

    const u32 next = (slot + 1) % kE1000TxRingSlots;
    ctx.tx_tail = next;
    E1000Write(ctx, kE1000RegTdt, next);
    ++ctx.tx_packets;
    ctx.tx_bytes += len;
    return true;
}

// Drain every RX descriptor whose DD bit is set. Hands each
// valid frame up to the network stack via the iface_index bound
// in E1000BringUp — each controller delivers to its own stack
// slot rather than all feeding index 0.
u32 E1000DrainRx(E1000Ctx& ctx, u32 budget_packets)
{
    if (!ctx.online)
        return 0;
    u32 drained = 0;
    for (u32 checked = 0; checked < kE1000RxRingSlots; ++checked)
    {
        if (budget_packets != 0 && drained >= budget_packets)
            break;
        const u32 slot = (ctx.rx_tail + 1) % kE1000RxRingSlots;
        volatile E1000RxDesc& d = ctx.rx_ring[slot];
        if ((d.status & kE1000RxStatusDd) == 0)
            break;
        const u16 len = d.length;
        // The NIC DMA-writes `length`; a non-conforming or hostile
        // device can report past the 2 KiB per-slot buffer. The 256
        // RX buffers are one contiguous allocation, so trusting an
        // over-length descriptor lets the L3 parsers read across
        // slots (cross-frame info leak) or off the end of the whole
        // RX region on the last slot. Drop + recycle out-of-range
        // descriptors instead of injecting them.
        if (len == 0 || len > kE1000RxBufBytes)
        {
            ++ctx.rx_dropped;
            d.status = 0;
            ctx.rx_tail = slot;
            E1000Write(ctx, kE1000RegRdt, slot);
            continue;
        }
        u8* buf = ctx.rx_buf_base_virt + u64(slot) * kE1000RxBufBytes;
        ++ctx.rx_packets;
        ctx.rx_bytes += len;
        // Deliver to the stack slot this controller is bound to.
        duetos::net::NetStackInjectRx(ctx.iface_index, buf, len);
        // Release the descriptor back to the controller.
        d.status = 0;
        ctx.rx_tail = slot;
        E1000Write(ctx, kE1000RegRdt, slot);
        ++drained;
    }
    return drained;
}

void E1000ConfigureMsixIvar(E1000Ctx& ctx, u8 vector)
{
    // 82574/e1000e layout: one byte per queue source in IVAR.
    // Program queue 0 RX + queue 0 TX + misc causes to the same
    // vector and set the VALID bit on each programmed byte.
    const u32 entry = (u32(vector & 0x1F) | kE1000IvarValid);
    const u32 ivar = entry | (entry << 8) | (entry << 16) | (entry << 24);
    E1000Write(ctx, kE1000RegIvar, ivar);
    E1000Write(ctx, kE1000RegIvargp, entry);
    core::CleanroomTraceRecord("e1000", "ivar-programmed", vector, ivar, entry);
}

// MSI-X / MSI handlers — one per controller slot. IrqHandler is
// void(*)() with no argument, so per-controller dispatch uses
// per-slot thunks rather than a closure. Each thunk indexes
// directly into g_e1000s[]. Slots beyond kMaxE1000 are never
// bound because E1000AllocCtx caps allocation.
//
// ICR (Interrupt Cause Read) is clear-on-read: the single read
// acknowledges every pending bit. Waking the RX poll task is
// sufficient — it drains unconditionally and re-reads link state.
void E1000IrqHandlerSlot0()
{
    if (g_e1000s[0].mmio == nullptr)
        return;
    (void)E1000Read(g_e1000s[0], kE1000RegIcr);
    duetos::sched::WaitQueueWakeOne(&g_e1000s[0].rx_wait);
}
void E1000IrqHandlerSlot1()
{
    if (g_e1000s[1].mmio == nullptr)
        return;
    (void)E1000Read(g_e1000s[1], kE1000RegIcr);
    duetos::sched::WaitQueueWakeOne(&g_e1000s[1].rx_wait);
}
void E1000IrqHandlerSlot2()
{
    if (g_e1000s[2].mmio == nullptr)
        return;
    (void)E1000Read(g_e1000s[2], kE1000RegIcr);
    duetos::sched::WaitQueueWakeOne(&g_e1000s[2].rx_wait);
}
void E1000IrqHandlerSlot3()
{
    if (g_e1000s[3].mmio == nullptr)
        return;
    (void)E1000Read(g_e1000s[3], kE1000RegIcr);
    duetos::sched::WaitQueueWakeOne(&g_e1000s[3].rx_wait);
}

// Table of per-slot handlers — indexed by the slot assigned in
// E1000AllocCtx. One entry per kMaxE1000.
constexpr duetos::arch::IrqHandler kE1000SlotHandlers[kMaxE1000] = {
    E1000IrqHandlerSlot0,
    E1000IrqHandlerSlot1,
    E1000IrqHandlerSlot2,
    E1000IrqHandlerSlot3,
};

// RX poll task entry. `arg` is &g_e1000s[n] — the slot outlives
// the task (module-scope array).
void E1000RxPollEntry(void* arg)
{
    E1000Ctx* ctx = static_cast<E1000Ctx*>(arg);
    if (ctx == nullptr)
        return;
    const bool have_msix = (ctx->irq_vector != 0);
    constexpr u32 kRxPollBudget = 64;
    for (;;)
    {
        const u32 drained = E1000DrainRx(*ctx, kRxPollBudget);
        if (drained == kRxPollBudget)
            continue;
        if (have_msix)
        {
            // Block until IRQ wakes us. Same lost-wakeup guard
            // pattern as NVMe/xHCI: under Cli, re-check whether
            // the next RX descriptor is marked DD; if so we
            // skip blocking and loop to drain.
            duetos::arch::Cli();
            const u32 slot = (ctx->rx_tail + 1) % kE1000RxRingSlots;
            if ((ctx->rx_ring[slot].status & kE1000RxStatusDd) != 0)
            {
                duetos::arch::Sti();
                continue;
            }
            // Bounded wait: under QEMU SLIRP the e1000e MSI-X
            // delivery is unreliable for some IRQ causes (RXT0 in
            // particular). The 10 ms timeout makes the RX poll
            // path tick-poll as a safety net while still benefiting
            // from real IRQ wakeups when they fire.
            duetos::sched::WaitQueueBlockTimeout(&ctx->rx_wait, /*ticks=*/1);
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

bool E1000BringUp(NicInfo& n, u32 iface_index)
{
    if (n.mmio_virt == nullptr)
        return false;

    // Claim the next per-controller slot. Remember the count before
    // allocation so we can roll it back on any bring-up failure.
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

    ctx->mmio = static_cast<volatile u8*>(n.mmio_virt);
    ctx->nic = &n;
    ctx->iface_index = iface_index;

    if (!E1000Reset(*ctx))
    {
        *ctx = {};
        g_e1000_count = saved_count;
        return false;
    }

    // Re-read MAC after reset (EEPROM reload populates RAL/RAH).
    ProbeE1000State(n);

    // Bring the link up + auto-speed-detect.
    const u32 ctrl = (E1000Read(*ctx, kE1000RegCtrl) | kE1000CtrlSlu | kE1000CtrlAsde) & ~u32(0);
    E1000Write(*ctx, kE1000RegCtrl, ctrl);
    E1000ClearMulticastTable(*ctx);

    if (!E1000SetupRxRing(*ctx))
    {
        *ctx = {};
        g_e1000_count = saved_count;
        return false;
    }
    if (!E1000SetupTxRing(*ctx))
    {
        // RX ring was allocated — free it before rolling back.
        if (ctx->rx_ring_phys != mm::kNullFrame)
            mm::FreeFrame(ctx->rx_ring_phys);
        constexpr u32 kRxBufPages = (kE1000RxRingSlots * kE1000RxBufBytes) / mm::kPageSize;
        if (ctx->rx_buf_base_phys != mm::kNullFrame)
            mm::FreeContiguousFrames(ctx->rx_buf_base_phys, kRxBufPages);
        *ctx = {};
        g_e1000_count = saved_count;
        return false;
    }

    ctx->online = true;
    n.driver_online = true;
    n.firmware_pending = false;
    n.wireless_fw_state = NicInfo::WirelessFwState::NotApplicable;

    // MSI-X bring-up. IrqHandler is void(*)() — use the per-slot
    // thunk table so each controller wakes its own RX wait queue.
    // The slot index is (ctx - g_e1000s), set just above.
    const u32 slot_idx = u32(ctx - g_e1000s);
    pci::DeviceAddress addr{};
    addr.bus = n.bus;
    addr.device = n.device;
    addr.function = n.function;
    auto r = pci::PciMsixBindSimple(addr, /*entry_index=*/0, kE1000SlotHandlers[slot_idx], /*out_route=*/nullptr);
    if (r.has_value())
    {
        ctx->irq_vector = r.value();
        E1000ConfigureMsixIvar(*ctx, ctx->irq_vector);
        // Enable RX + link + TX-writeback IRQ sources. Writing
        // to IMS (Interrupt Mask SET) turns bits on; IMC
        // (clear) takes them off. Read ICR once to clear any
        // pending state before we unmask.
        (void)E1000Read(*ctx, kE1000RegIcr);
        const u32 mask = kE1000IntRxt0 | kE1000IntRxdmt0 | kE1000IntRxo | kE1000IntLsc | kE1000IntTxdw;
        E1000Write(*ctx, kE1000RegImsSet, mask);
        arch::SerialWrite("[e1000] MSI-X bound vector=");
        arch::SerialWriteHex(ctx->irq_vector);
        arch::SerialWrite(" (IVAR programmed)\n");
        core::CleanroomTraceRecord("e1000", "msix-bound", ctx->irq_vector, 1, 0);
    }
    else
    {
        arch::SerialWrite("[e1000] MSI-X unavailable — RX task will tick-poll\n");
        core::CleanroomTraceRecord("e1000", "msix-fallback-poll", n.device_id, 0, 0);
    }

    // Re-read link state now that we've asserted SLU — can take a
    // moment on real silicon, but QEMU brings it up instantly.
    E1000Delay();
    const u32 status = E1000Read(*ctx, kE1000RegStatus);
    n.link_up = (status & kE1000StatusLinkUp) != 0;

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
    arch::SerialWriteHex(ctx->rx_ring_phys);
    arch::SerialWrite(" tx_ring=");
    arch::SerialWriteHex(ctx->tx_ring_phys);
    arch::SerialWrite("\n");

    // Spawn per-controller RX polling task. The task receives ctx
    // as its argument so it operates on the correct ring.
    duetos::sched::SchedCreate(E1000RxPollEntry, ctx, "e1000-rx-poll");

    // Bind to the network stack at iface_index. NetTxFn is
    // bool(*)(u32 iface_index, const void*, u64); the stateless
    // lambda below converts to a function pointer because it
    // captures nothing — the iface_index argument the stack
    // passes back routes to the matching e1000 ctx directly.
    // GAP: multi-NIC routing policy (source-based routing, bonding,
    // failover) is not implemented — each iface is independent and
    // the upper stack selects the outbound iface per-packet using
    // its own route table — revisit when the route table lands.
    auto tx_fn = [](u32 iface_idx, const void* frame, u64 len) -> bool
    {
        for (u32 i = 0; i < g_e1000_count; ++i)
        {
            if (g_e1000s[i].iface_index == iface_idx && g_e1000s[i].online)
                return E1000Send(g_e1000s[i], static_cast<const u8*>(frame), u32(len));
        }
        return false;
    };

    duetos::net::MacAddress mac{};
    for (u64 i = 0; i < 6; ++i)
        mac.octets[i] = n.mac[i];
    // Start with the all-zero IP so DHCP's DISCOVER uses the
    // correct src=0.0.0.0. The stack rebinds the iface to the
    // leased IP on ACK.
    duetos::net::Ipv4Address ip{{0, 0, 0, 0}};
    duetos::net::NetStackBindInterface(iface_index, mac, ip, tx_fn);
    duetos::net::DhcpStart(iface_index);

    // Self-test: emit one broadcast frame so a tcpdump on the host
    // side can confirm the TX path works end-to-end.
    E1000SelfTestTx(*ctx, n);
    return true;
}

// Returns true iff the vendor ID matched one of the families we know
// how to probe. False means no driver code touched the device — the
// caller is then responsible for unwinding any pre-probe MMIO mapping
// it set up rather than registering a half-initialised NIC entry. A
// matched-but-not-brought-up device still returns true; it stays in
// the registry so device manager can list it as `(probe only)`.
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
        family = BroadcomNicTag(n.device_id);
        break;
    case kVendorRedHatVirt:
        family = VirtioNetTag(n.device_id);
        break;
    case kVendorMediaTek:
        family = MediatekNicTag(n.device_id);
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
            brought_up = E1000BringUp(n, iface_index);
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
    else if (Mt76Matches(n.vendor_id, n.device_id))
    {
        wireless_shell = Mt76BringUp(n);
        brought_up = wireless_shell;
    }
    else if (n.vendor_id == kVendorAmd && n.device_id == 0x2000)
    {
        // AMD PCnet — full wired driver (polled RX/TX + DHCP). This is the
        // default NIC a stock VirtualBox VM exposes, so it brings real
        // networking up with no adapter reconfiguration.
        brought_up = PcnetBringUp(n);
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

        u64 map_bytes = 0;
        const pci::Bar bar0 = pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0 && !bar0.is_io)
        {
            nic.mmio_phys = bar0.address;
            nic.mmio_size = bar0.size;
            // Cap at 2 MiB — NIC register files are tiny (<256 KiB);
            // bigger BARs on HPC NICs are for RDMA doorbells which
            // no v0 driver touches.
            constexpr u64 kMmioCap = 2ULL * 1024 * 1024;
            map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
            nic.mmio_virt = mm::MapMmio(bar0.address, map_bytes);
        }

        // Probe contract: false means no vendor matched. Unmap the
        // MMIO and skip the registry add — keeping the entry would
        // leak a 2 MiB MMIO mapping per unrecognised PCI network
        // controller for the lifetime of the boot.
        // iface_index is the g_nics[] slot this NIC will occupy on
        // success — equal to g_nic_count before the increment below.
        if (!RunVendorProbe(nic, u32(g_nic_count)))
        {
            if (nic.mmio_virt != nullptr && map_bytes != 0)
            {
                mm::UnmapMmio(nic.mmio_virt, map_bytes);
            }
            KLOG_WARN_V("drivers/net", "no vendor match; device skipped did", nic.device_id);
            KBP_PROBE_V(::duetos::debug::ProbeId::kProbeFail, nic.device_id);
            continue;
        }
        const u64 nic_index = g_nic_count++;
        g_nics[nic_index] = nic;
        if (g_nics[nic_index].driver_online && NicIsWireless(nic_index))
        {
            if (IwlwifiMatches(g_nics[nic_index].vendor_id, g_nics[nic_index].device_id))
                IwlwifiStartWatch(g_nics[nic_index]);
            else if (Rtl88xxMatches(g_nics[nic_index].vendor_id, g_nics[nic_index].device_id))
                Rtl88xxStartWatch(g_nics[nic_index]);
            else if (Bcm43xxMatches(g_nics[nic_index].vendor_id, g_nics[nic_index].device_id))
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
}

namespace
{

// Quiesce one e1000 controller and release its DMA rings + buffer
// frames. Safe to call when ctx.online is false (register touches
// are skipped). The MSI-X handler stays installed — the device-side
// IMC mask + reset stops further events; a subsequent E1000BringUp
// rebinds via PciMsixBindSimple. The RX-poll task spawned by
// bring-up keeps running but observes `online == false`
// (E1000Send / E1000DrainRx both early-return) so it idles cheaply.
void E1000QuiesceOne(E1000Ctx& ctx)
{
    if (!ctx.online)
        return;

    // 1. Mask all interrupt sources, drain any pending cause bits,
    //    clear the IVAR routing so a stray IRQ during reset doesn't
    //    target a stale vector.
    E1000Write(ctx, kE1000RegImc, 0xFFFFFFFFu);
    (void)E1000Read(ctx, kE1000RegIcr);
    E1000Write(ctx, kE1000RegIvar, 0);
    E1000Write(ctx, kE1000RegIvargp, 0);

    // 2. Disable receive + transmit so the controller stops touching
    //    descriptor memory before we free the backing frames.
    E1000Write(ctx, kE1000RegRctl, 0);
    E1000Write(ctx, kE1000RegTctl, 0);

    // 3. Software reset returns ring-pointer registers (RDBAL/RDBAH/
    //    TDBAL/TDBAH/RDLEN/TDLEN/RDH/RDT/TDH/TDT) to their power-on
    //    defaults. Failure here just means the controller didn't
    //    acknowledge — the ring-pointer registers we care about are
    //    no longer being read because RCTL/TCTL are already cleared.
    (void)E1000Reset(ctx);

    // 4. Free the descriptor rings and buffer pools. AllocateFrame
    //    handed out one page each for the rings, AllocateContiguousFrames
    //    a multi-page run for the buffers.
    if (ctx.rx_ring_phys != mm::kNullFrame)
        mm::FreeFrame(ctx.rx_ring_phys);
    if (ctx.tx_ring_phys != mm::kNullFrame)
        mm::FreeFrame(ctx.tx_ring_phys);
    constexpr u32 kRxBufPages = (kE1000RxRingSlots * kE1000RxBufBytes) / mm::kPageSize;
    constexpr u32 kTxBufPages = (kE1000TxRingSlots * kE1000RxBufBytes) / mm::kPageSize;
    if (ctx.rx_buf_base_phys != mm::kNullFrame)
        mm::FreeContiguousFrames(ctx.rx_buf_base_phys, kRxBufPages);
    if (ctx.tx_buf_base_phys != mm::kNullFrame)
        mm::FreeContiguousFrames(ctx.tx_buf_base_phys, kTxBufPages);

    // 5. Wake any sleeper on the RX wait queue so the polling task
    //    re-checks `online` and stops dereferencing freed ring
    //    pointers. The wake happens BEFORE the context zero so the
    //    WaitQueue node list is still intact when WakeAll walks it.
    (void)duetos::sched::WaitQueueWakeAll(&ctx.rx_wait);

    // 6. Clear the context. `online = false` is the wake-up gate the
    //    RX-poll task and E1000Send check on every entry; clearing
    //    it before the rest of the state means a racing TX submission
    //    bails before reading a freed pointer.
    NicInfo* nic = ctx.nic;
    ctx = {};
    if (nic != nullptr)
        nic->driver_online = false;

    arch::SerialWrite("[e1000] quiesced — IRQs masked, RX/TX disabled, rings freed\n");
}

// Quiesce all online e1000 controllers and reset the per-family
// count so E1000AllocCtx works correctly after a NetInit/NetShutdown
// cycle.
void E1000QuiesceAll()
{
    for (u32 i = 0; i < g_e1000_count; ++i)
        E1000QuiesceOne(g_e1000s[i]);
    g_e1000_count = 0;
}

} // namespace

::duetos::core::Result<void> NetShutdown()
{
    KLOG_TRACE_SCOPE("drivers/net", "NetShutdown");
    E1000QuiesceAll();
    const u64 dropped = g_nic_count;
    g_nic_count = 0;
    g_init_done = false;
    arch::SerialWrite("[drivers/net] shutdown: dropped ");
    arch::SerialWriteHex(dropped);
    arch::SerialWrite(" NIC records\n");
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
           StrPrefixMatches(family, "rtl88") || StrPrefixMatches(family, "mt76") ||
           StrPrefixMatches(family, "mt7615") || StrPrefixMatches(family, "mt7663") ||
           StrPrefixMatches(family, "mt7915") || StrPrefixMatches(family, "mt7916") ||
           StrPrefixMatches(family, "mt7921") || StrPrefixMatches(family, "mt7922") ||
           StrPrefixMatches(family, "mt7925");
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

const char* MediatekNicTag(u16 device_id)
{
    // MediaTek mt76 PCIe wireless family. Tag returned drives the
    // family-string heuristic in `FamilyLooksWireless`, so the
    // names below must start with a recognised wireless prefix.
    switch (Mt76FamilyFromDeviceId(device_id))
    {
    case Mt76Family::Mt7615:
        return "mt7615-wifi";
    case Mt76Family::Mt7663:
        return "mt7663-wifi";
    case Mt76Family::Mt7915:
        return "mt7915-wifi";
    case Mt76Family::Mt7916:
        return "mt7916-wifi";
    case Mt76Family::Mt7921:
        return "mt7921-wifi";
    case Mt76Family::Mt7922:
        return "mt7922-wifi";
    case Mt76Family::Mt7925:
        return "mt7925-wifi";
    case Mt76Family::Unknown:
    default:
        return "mediatek-unknown";
    }
}

namespace
{

::duetos::core::Result<void> RegisterNetModule()
{
    ::duetos::security::RegisterDriverDomain(
        "drivers/net",
        []() -> ::duetos::core::Result<void>
        {
            ::duetos::drivers::net::NetInit();
            return {};
        },
        []() -> ::duetos::core::Result<void> { return ::duetos::drivers::net::NetShutdown(); });
    return {};
}

} // namespace

KERNEL_INITCALL(Drivers, "drivers/net.module", RegisterNetModule)

} // namespace duetos::drivers::net
