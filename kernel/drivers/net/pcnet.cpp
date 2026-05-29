#include "drivers/net/net.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "drivers/pci/pci.h"
#include "mm/dma.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "util/string.h"
#include "util/types.h"

/*
 * DuetOS — AMD PCnet-PCI II/III (Am79C970A/Am79C973, PCI 1022:2000)
 * NIC driver. This is VirtualBox's DEFAULT adapter ("PCnet-FAST III")
 * and QEMU's `-device pcnet`, so a default-config VM gets real wired
 * networking with no adapter reconfiguration.
 *
 * The chip is driven through I/O ports (BAR0 is an I/O BAR), not MMIO,
 * via the RAP/RDP register pair in 32-bit "DWIO" mode with SWSTYLE 2
 * (32-bit, 16-byte descriptors). Polled RX/TX (no MSI/INTx) — the
 * emulated card flips the descriptor OWN bits in guest memory
 * regardless of interrupt enables, so a poll task is reliable and
 * sidesteps the IRQ-routing surface entirely.
 *
 * Register/offset/struct values cross-verified against the OSDev
 * "AMD PCNET" page, QEMU hw/net/pcnet.c, and Linux pcnet32.c. Plugs
 * into the same net-stack contract e1000 uses: NetStackBindInterface
 * (iface 0) + DhcpStart, with a per-driver RX poll task feeding
 * NetStackInjectRx.
 *
 * Context: kernel. PcnetBringUp runs from RunVendorProbe during NetInit.
 */

namespace duetos::drivers::net
{

namespace
{

namespace arch = ::duetos::arch;
namespace mm = ::duetos::mm;
namespace netstack = ::duetos::net;

// I/O register offsets from the BAR0 I/O base, 32-bit DWIO mode.
constexpr u16 kRdp = 0x10;   // register data port (CSR via RAP)
constexpr u16 kRap = 0x14;   // register address port (index)
constexpr u16 kReset = 0x18; // reading resets the chip (32-bit)
constexpr u16 kReset16 = 0x14;
[[maybe_unused]] constexpr u16 kBdp = 0x1C; // bus-config data port (BCR via RAP) — completes the I/O map

// CSR0 control/status bits.
constexpr u32 kCsr0Init = 0x0001;
constexpr u32 kCsr0Strt = 0x0002;
constexpr u32 kCsr0Stop = 0x0004;
constexpr u32 kCsr0Tdmd = 0x0008; // transmit demand
constexpr u32 kCsr0Idon = 0x0100; // init done

// Descriptor status bits (high 16 of dword1).
constexpr u16 kDescOwn = 0x8000;
constexpr u16 kDescErr = 0x4000;
constexpr u16 kDescStp = 0x0200;
constexpr u16 kDescEnp = 0x0100;

constexpr u32 kRxCount = 8;
constexpr u32 kTxCount = 8;
constexpr u8 kRxLog2 = 3; // log2(kRxCount)
constexpr u8 kTxLog2 = 3;
constexpr u32 kBufSize = 2048; // per-descriptor buffer (Ethernet frame + slack)

struct PcnetState
{
    bool online;
    u16 io;
    mm::DmaBuffer init_blk;
    mm::DmaBuffer rx_ring;
    mm::DmaBuffer tx_ring;
    mm::DmaBuffer rx_bufs;
    mm::DmaBuffer tx_bufs;
    u32 rx_cur;
    u32 tx_cur;
};
constinit PcnetState g_pcnet{};

inline void WriteRap(u32 reg)
{
    arch::Outl(g_pcnet.io + kRap, reg);
}
inline u32 ReadCsr(u32 n)
{
    WriteRap(n);
    return arch::Inl(g_pcnet.io + kRdp);
}
inline void WriteCsr(u32 n, u32 v)
{
    WriteRap(n);
    arch::Outl(g_pcnet.io + kRdp, v);
}

inline u32* RxDesc(u32 i)
{
    return static_cast<u32*>(g_pcnet.rx_ring.virt) + i * 4;
}
inline u32* TxDesc(u32 i)
{
    return static_cast<u32*>(g_pcnet.tx_ring.virt) + i * 4;
}
inline u8* RxBuf(u32 i)
{
    return static_cast<u8*>(g_pcnet.rx_bufs.virt) + i * kBufSize;
}
inline u8* TxBuf(u32 i)
{
    return static_cast<u8*>(g_pcnet.tx_bufs.virt) + i * kBufSize;
}

// BCNT = two's-complement of the buffer length in the low 12 bits, with
// the top nibble set to ones (0xF000) — the chip's descriptor convention.
inline u16 EncodeBcnt(u32 len)
{
    return static_cast<u16>((-static_cast<i32>(len)) & 0x0FFF) | 0xF000u;
}

// TX trampoline registered with the stack. Copies the frame into the
// next host-owned TX descriptor's buffer, hands it to the card, and pokes
// TDMD. Returns false (drop) if the ring is full.
bool PcnetTx(u32 /*iface*/, const void* frame, u64 len)
{
    if (!g_pcnet.online || frame == nullptr || len == 0)
        return false;
    if (len > kBufSize)
        len = kBufSize;
    u32* d = TxDesc(g_pcnet.tx_cur);
    if ((static_cast<u16>(d[1] >> 16) & kDescOwn) != 0)
        return false; // card still owns this slot — ring full

    memcpy(TxBuf(g_pcnet.tx_cur), frame, len);
    d[2] = 0;
    // Single dword write sets BCNT (low16) + OWN|STP|ENP (high16) atomically
    // so the card never observes a half-built descriptor.
    const u16 status = kDescOwn | kDescStp | kDescEnp;
    d[1] = (static_cast<u32>(status) << 16) | EncodeBcnt(static_cast<u32>(len));
    WriteCsr(0, ReadCsr(0) | kCsr0Tdmd);
    g_pcnet.tx_cur = (g_pcnet.tx_cur + 1) % kTxCount;
    return true;
}

void PcnetRxPollEntry(void*)
{
    for (;;)
    {
        // Drain every host-owned (ready) RX descriptor this pass.
        for (u32 guard = 0; guard < kRxCount; ++guard)
        {
            u32* d = RxDesc(g_pcnet.rx_cur);
            const u16 status = static_cast<u16>(d[1] >> 16);
            if ((status & kDescOwn) != 0)
                break; // card owns it — nothing ready
            const u16 mcnt = static_cast<u16>(d[2] & 0x0FFF);
            // Deliver only complete, error-free frames; mcnt includes the
            // 4-byte Ethernet FCS, which the stack doesn't want.
            if ((status & kDescErr) == 0 && (status & kDescEnp) != 0 && mcnt > 4)
            {
                netstack::NetStackInjectRx(0, RxBuf(g_pcnet.rx_cur), mcnt - 4u);
            }
            // Hand the descriptor back to the card (OWN=1, fresh BCNT).
            d[2] = 0;
            d[1] = (static_cast<u32>(kDescOwn) << 16) | EncodeBcnt(kBufSize);
            g_pcnet.rx_cur = (g_pcnet.rx_cur + 1) % kRxCount;
        }
        ::duetos::sched::SchedSleepTicks(1);
    }
}

void FreeAll()
{
    if (g_pcnet.init_blk.virt)
        mm::FreeDmaCoherent(g_pcnet.init_blk);
    if (g_pcnet.rx_ring.virt)
        mm::FreeDmaCoherent(g_pcnet.rx_ring);
    if (g_pcnet.tx_ring.virt)
        mm::FreeDmaCoherent(g_pcnet.tx_ring);
    if (g_pcnet.rx_bufs.virt)
        mm::FreeDmaCoherent(g_pcnet.rx_bufs);
    if (g_pcnet.tx_bufs.virt)
        mm::FreeDmaCoherent(g_pcnet.tx_bufs);
    g_pcnet = PcnetState{};
}

} // namespace

bool PcnetBringUp(NicInfo& n)
{
    if (g_pcnet.online)
        return true; // single-controller v0

    pci::DeviceAddress addr{};
    addr.bus = n.bus;
    addr.device = n.device;
    addr.function = n.function;
    const pci::Bar bar = pci::PciReadBar(addr, 0);
    if (!bar.is_io || bar.address == 0)
    {
        arch::SerialWrite("[pcnet] BAR0 is not an I/O BAR — cannot drive\n");
        return false;
    }
    g_pcnet.io = static_cast<u16>(bar.address);

    // Enable PCI I/O space (bit 0) + bus master (bit 2) so descriptor DMA
    // works; without bus master the chip never touches the rings.
    const u32 cs = pci::PciConfigRead32(addr, 0x04);
    const u16 cmd = static_cast<u16>(cs & 0xFFFF) | 0x0001u | 0x0004u;
    pci::PciConfigWrite32(addr, 0x04, (cs & 0xFFFF0000u) | cmd);

    // Read the MAC from the address PROM (first 6 I/O bytes) BEFORE the
    // reset — the canonical order. Reading it after reset / DWIO / SWSTYLE
    // returned all-0xFF on the QEMU/VBox model; reading the live APROM
    // window first yields the real MAC.
    for (u32 i = 0; i < 6; ++i)
        n.mac[i] = arch::Inb(g_pcnet.io + static_cast<u16>(i));
    n.mac_valid = true;

    // Reset, then latch 32-bit DWIO mode (a 32-bit write to RDP).
    (void)arch::Inl(g_pcnet.io + kReset);
    (void)arch::Inw(g_pcnet.io + kReset16);
    // Non-compound `i = i + 1`: pre/post-inc on a volatile-qualified
    // counter is deprecated in C++20. The volatile keeps this post-reset
    // settle spin from being optimised away.
    for (volatile u32 i = 0; i < 20000; i = i + 1)
    {
    }
    arch::Outl(g_pcnet.io + kRdp, 0);
    WriteCsr(0, kCsr0Stop);
    WriteCsr(58, (ReadCsr(58) & 0xFF00u) | 2u); // SWSTYLE 2 (32-bit, 16-byte descs)

    auto ib_r = mm::AllocDmaCoherent(32, mm::Zone::Dma32);
    auto rxr_r = mm::AllocDmaCoherent(kRxCount * 16, mm::Zone::Dma32);
    auto txr_r = mm::AllocDmaCoherent(kTxCount * 16, mm::Zone::Dma32);
    auto rxb_r = mm::AllocDmaCoherent(kRxCount * kBufSize, mm::Zone::Dma32);
    auto txb_r = mm::AllocDmaCoherent(kTxCount * kBufSize, mm::Zone::Dma32);
    if (!ib_r || !rxr_r || !txr_r || !rxb_r || !txb_r)
    {
        arch::SerialWrite("[pcnet] DMA allocation failed — aborting bring-up\n");
        if (ib_r)
            mm::FreeDmaCoherent(ib_r.value());
        if (rxr_r)
            mm::FreeDmaCoherent(rxr_r.value());
        if (txr_r)
            mm::FreeDmaCoherent(txr_r.value());
        if (rxb_r)
            mm::FreeDmaCoherent(rxb_r.value());
        if (txb_r)
            mm::FreeDmaCoherent(txb_r.value());
        return false;
    }
    g_pcnet.init_blk = ib_r.value();
    g_pcnet.rx_ring = rxr_r.value();
    g_pcnet.tx_ring = txr_r.value();
    g_pcnet.rx_bufs = rxb_r.value();
    g_pcnet.tx_bufs = txb_r.value();

    for (u32 i = 0; i < kRxCount; ++i)
    {
        u32* d = RxDesc(i);
        d[0] = static_cast<u32>(g_pcnet.rx_bufs.phys + i * kBufSize);
        d[1] = (static_cast<u32>(kDescOwn) << 16) | EncodeBcnt(kBufSize); // OWN=1 (card)
        d[2] = 0;
        d[3] = 0;
    }
    for (u32 i = 0; i < kTxCount; ++i)
    {
        u32* d = TxDesc(i);
        d[0] = static_cast<u32>(g_pcnet.tx_bufs.phys + i * kBufSize);
        d[1] = 0; // OWN=0 (host)
        d[2] = 0;
        d[3] = 0;
    }

    u8* ib = static_cast<u8*>(g_pcnet.init_blk.virt);
    memset(ib, 0, 32);
    ib[0] = 0;
    ib[1] = 0;                             // MODE = 0 (normal)
    ib[2] = static_cast<u8>(kRxLog2 << 4); // RLEN (log2 in high nibble)
    ib[3] = static_cast<u8>(kTxLog2 << 4); // TLEN
    for (u32 i = 0; i < 6; ++i)
        ib[4 + i] = n.mac[i]; // PADR
    // ib[10..11] reserved, ib[12..19] LADRF already zeroed by memset.
    *reinterpret_cast<u32*>(ib + 20) = static_cast<u32>(g_pcnet.rx_ring.phys); // RDRA
    *reinterpret_cast<u32*>(ib + 24) = static_cast<u32>(g_pcnet.tx_ring.phys); // TDRA

    WriteCsr(1, static_cast<u32>(g_pcnet.init_blk.phys & 0xFFFF));
    WriteCsr(2, static_cast<u32>((g_pcnet.init_blk.phys >> 16) & 0xFFFF));
    WriteCsr(4, ReadCsr(4) | 0x0800u); // APAD_XMT: auto-pad short frames
    WriteCsr(0, kCsr0Init);

    bool init_done = false;
    for (u32 tries = 0; tries < 100000; ++tries)
    {
        if ((ReadCsr(0) & kCsr0Idon) != 0)
        {
            init_done = true;
            break;
        }
    }
    if (!init_done)
    {
        arch::SerialWrite("[pcnet] INIT timed out (IDON never set) — aborting\n");
        WriteCsr(0, kCsr0Stop);
        FreeAll();
        return false;
    }
    WriteCsr(0, kCsr0Strt); // start (polled — no IENA)

    g_pcnet.rx_cur = 0;
    g_pcnet.tx_cur = 0;
    g_pcnet.online = true;
    // PCnet under QEMU/VBox NAT is always "linked"; there's no simple
    // link-status bit to poll the way e1000 exposes STATUS.LU.
    n.link_up = true;
    n.driver_online = true;
    n.firmware_pending = false;
    n.wireless_fw_state = NicInfo::WirelessFwState::NotApplicable;

    arch::SerialWrite("[pcnet] online io=");
    arch::SerialWriteHex(g_pcnet.io);
    arch::SerialWrite(" mac=");
    for (u32 i = 0; i < 6; ++i)
    {
        if (i != 0)
            arch::SerialWrite(":");
        arch::SerialWriteHex(n.mac[i]);
    }
    arch::SerialWrite(" link=up (polled)\n");

    netstack::MacAddress mac{};
    for (u32 i = 0; i < 6; ++i)
        mac.octets[i] = n.mac[i];
    netstack::Ipv4Address ip{};
    (void)netstack::NetStackBindInterface(0, mac, ip, &PcnetTx);
    (void)netstack::DhcpStart(0);

    ::duetos::sched::SchedCreate(PcnetRxPollEntry, nullptr, "pcnet-rx-poll");
    return true;
}

} // namespace duetos::drivers::net
