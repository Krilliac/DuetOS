#include "usb.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"
#include "hid_descriptor.h"

namespace customos::drivers::usb
{

namespace
{

HostControllerInfo g_hcs[kMaxHostControllers] = {};
u64 g_hc_count = 0;

HciKind KindFromProgIf(u8 prog_if)
{
    switch (prog_if)
    {
    case kProgIfUhci:
        return HciKind::Uhci;
    case kProgIfOhci:
        return HciKind::Ohci;
    case kProgIfEhci:
        return HciKind::Ehci;
    case kProgIfXhci:
        return HciKind::Xhci;
    case kProgIfDevice:
        return HciKind::Device;
    case kProgIfOther:
        return HciKind::Other;
    default:
        return HciKind::Unknown;
    }
}

// Stub class-driver probes. Each logs its invocation and refuses
// the attach (returns false), so a future real driver can take
// over by changing the return value. They're registered in the
// table below.

// HID class driver. v0 does not claim the device yet (the host
// controller can't hand us a descriptor to parse), but when a
// future xHCI slice starts delivering descriptors we'll feed them
// straight into hid::HidParseDescriptor. The parser itself is
// reachable today via HidSelfTest at boot and is exercised by the
// boot-keyboard + boot-mouse golden descriptors. Logged prog_if
// values: 0x00 boot-interface, 0x01 keyboard-boot, 0x02 mouse-
// boot.
bool HidProbe(u8 subclass, u8 prog_if)
{
    arch::SerialWrite("[usb-hid] probe subclass=");
    arch::SerialWriteHex(subclass);
    arch::SerialWrite(" prog_if=");
    arch::SerialWriteHex(prog_if);
    arch::SerialWrite(" parser=ready  (not claimed — bus enumeration pending)\n");
    return false;
}

// MSC class driver. Byte-level CBW/CSW + SCSI CDB builders +
// response parsers are live (see msc_scsi.{h,cpp}); the BBB wire
// protocol can be driven as soon as a bulk-transfer path exists.
// v0 refuses the attach — a future xHCI slice flips this to true
// and adds the bulk-in / bulk-out transfer wiring.
bool MscProbe(u8 subclass, u8 prog_if)
{
    arch::SerialWrite("[usb-msc] probe subclass=");
    arch::SerialWriteHex(subclass);
    arch::SerialWrite(" prog_if=");
    arch::SerialWriteHex(prog_if);
    arch::SerialWrite(" cbw_csw=ready  (not claimed — bulk transfer pending)\n");
    return false;
}

bool HubProbe(u8 subclass, u8 prog_if)
{
    arch::SerialWrite("[usb-hub] probe subclass=");
    arch::SerialWriteHex(subclass);
    arch::SerialWrite(" prog_if=");
    arch::SerialWriteHex(prog_if);
    arch::SerialWrite("  (stub — not claimed)\n");
    return false;
}

bool VideoProbe(u8 subclass, u8 prog_if)
{
    arch::SerialWrite("[usb-video] probe subclass=");
    arch::SerialWriteHex(subclass);
    arch::SerialWrite(" prog_if=");
    arch::SerialWriteHex(prog_if);
    arch::SerialWrite("  (stub — not claimed)\n");
    return false;
}

constexpr UsbClassDriver kClassDrivers[] = {
    {kUsbClassHid, "hid", HidProbe},
    {kUsbClassMsc, "msc", MscProbe},
    {kUsbClassHub, "hub", HubProbe},
    {kUsbClassVideo, "video", VideoProbe},
};

// xHCI capability registers (offsets at the base of the
// operational MMIO window). See xHCI spec §5.3.
//
//   CAPLENGTH      u8   — length of the capability regs (so
//                         operational regs live at bar + CAPLENGTH)
//   HCIVERSION     u16  — BCD, typically 0x0100 / 0x0110
//   HCSPARAMS1     u32  — MaxPorts (bits 31:24), MaxIntrs (23:8), MaxSlots (7:0)
//   HCCPARAMS1     u32  — 64-bit addressing, context size, xEC offset
//
// Operational registers (xHCI spec §5.4) live at `opbase = bar +
// CAPLENGTH`:
//
//   USBCMD   u32 at opbase+0x00 — Run/Stop (bit 0), HCReset (bit 1)
//   USBSTS   u32 at opbase+0x04 — Halted (bit 0), CNR "not ready" (bit 11)
//   PAGESIZE u32 at opbase+0x08 — supported page sizes bitmap
//   CONFIG   u32 at opbase+0x38 — MaxSlotsEn (bits 7:0) — we don't write
//
// Per-port register bank (xHCI spec §5.4.8) starts at opbase+0x400
// with 0x10 bytes per port:
//
//   PORTSC   u32 at opbase+0x400 + 0x10*portnum
//     bit 0      CCS  — Current Connect Status
//     bit 1      PED  — Port Enabled/Disabled
//     bit 4      PR   — Port Reset (in progress)
//     bits 5..8  PLS  — Port Link State (U0/U1/U2/U3/...)
//     bit 9      PP   — Port Power
//     bits 10..13 PortSpeed — 1 Full, 2 Low, 3 High, 4 Super, 5 SuperPlus
//     bit 16     LWS  — Link State Write Strobe (read-only here)
//
// Everything below is READ-ONLY probing. Writing USBCMD or PORTSC
// is a future slice; touching them without ring / interrupt
// handling would leave the controller in a partially-running
// state.
u32 Mmio32(const HostControllerInfo& h, u64 offset)
{
    if (h.mmio_virt == nullptr)
        return 0;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(h.mmio_virt) + offset);
    return *p;
}

// xHCI operational-register offsets relative to `opbase`.
constexpr u64 kXhciOpUsbCmd = 0x00;
constexpr u64 kXhciOpUsbSts = 0x04;
constexpr u64 kXhciOpPageSize = 0x08;
constexpr u64 kXhciOpConfig = 0x38;
constexpr u64 kXhciPortRegBase = 0x400;
constexpr u64 kXhciPortRegStride = 0x10;

// USBSTS bits.
constexpr u32 kXhciStsHcHalted = 1u << 0;
constexpr u32 kXhciStsCnr = 1u << 11;

// PORTSC bits.
constexpr u32 kXhciPortScCcs = 1u << 0;
constexpr u32 kXhciPortScPed = 1u << 1;
constexpr u32 kXhciPortScPr = 1u << 4; // PR is bit 4, not 9

const char* XhciPortSpeedName(u32 speed_bits)
{
    switch (speed_bits & 0xF)
    {
    case 0:
        return "none";
    case 1:
        return "full";
    case 2:
        return "low";
    case 3:
        return "high";
    case 4:
        return "super";
    case 5:
        return "super+";
    default:
        return "?";
    }
}

void DecodeXhciCaps(const HostControllerInfo& h)
{
    if (h.mmio_virt == nullptr)
        return;
    const u32 caplen_and_version = Mmio32(h, 0x00);
    const u8 caplen = caplen_and_version & 0xFF;
    const u16 hciver = u16(caplen_and_version >> 16);
    const u32 hcsp1 = Mmio32(h, 0x04);
    const u32 hccp1 = Mmio32(h, 0x10);
    const u8 max_ports = u8((hcsp1 >> 24) & 0xFF);
    arch::SerialWrite("[xhci] caplen=");
    arch::SerialWriteHex(caplen);
    arch::SerialWrite(" hciver=");
    arch::SerialWriteHex(hciver);
    arch::SerialWrite(" max_slots=");
    arch::SerialWriteHex(hcsp1 & 0xFF);
    arch::SerialWrite(" max_intrs=");
    arch::SerialWriteHex((hcsp1 >> 8) & 0x7FF);
    arch::SerialWrite(" max_ports=");
    arch::SerialWriteHex(max_ports);
    arch::SerialWrite(" hcc1=");
    arch::SerialWriteHex(hccp1);
    arch::SerialWrite("\n");

    // Guard against absurd caplen values. Spec minimum is 0x20 bytes
    // (HCSPARAMS1..DBOFF). 0 or a tiny value here means the BAR
    // decode is wrong and the op register bank wouldn't be at a
    // sensible offset — reading onward would touch garbage.
    if (caplen < 0x20)
    {
        arch::SerialWrite("[xhci]   caplen below spec minimum; skipping op regs\n");
        return;
    }
    const u64 opbase = caplen;
    const u32 usbcmd = Mmio32(h, opbase + kXhciOpUsbCmd);
    const u32 usbsts = Mmio32(h, opbase + kXhciOpUsbSts);
    const u32 pagesize = Mmio32(h, opbase + kXhciOpPageSize);
    const u32 config = Mmio32(h, opbase + kXhciOpConfig);
    arch::SerialWrite("[xhci]   usbcmd=");
    arch::SerialWriteHex(usbcmd);
    arch::SerialWrite(" usbsts=");
    arch::SerialWriteHex(usbsts);
    arch::SerialWrite(" (");
    arch::SerialWrite((usbsts & kXhciStsHcHalted) ? "halted" : "running");
    if (usbsts & kXhciStsCnr)
        arch::SerialWrite(",not-ready");
    arch::SerialWrite(") pagesize=");
    arch::SerialWriteHex(pagesize);
    arch::SerialWrite(" slots_en=");
    arch::SerialWriteHex(config & 0xFF);
    arch::SerialWrite("\n");

    // Walk PORTSC. Only meaningful if the controller isn't CNR.
    // Cap the iteration at the spec maximum (255 ports) and the
    // reasonable MMIO window size.
    const u64 port_region_bytes = u64(max_ports) * kXhciPortRegStride;
    if (max_ports == 0 || kXhciPortRegBase + port_region_bytes > h.mmio_size)
    {
        arch::SerialWrite("[xhci]   port region outside mapped BAR, skipping\n");
        return;
    }
    for (u64 i = 0; i < max_ports; ++i)
    {
        const u32 portsc = Mmio32(h, opbase + kXhciPortRegBase + i * kXhciPortRegStride);
        const bool connected = (portsc & kXhciPortScCcs) != 0;
        const bool enabled = (portsc & kXhciPortScPed) != 0;
        const bool resetting = (portsc & kXhciPortScPr) != 0;
        const u32 speed = (portsc >> 10) & 0xF;
        // Suppress the empty-port flood; we care about connected
        // or mid-reset ports.
        if (!connected && !resetting && speed == 0)
            continue;
        arch::SerialWrite("[xhci]   port ");
        arch::SerialWriteHex(i + 1); // xHCI port numbering is 1-based
        arch::SerialWrite(" portsc=");
        arch::SerialWriteHex(portsc);
        arch::SerialWrite(connected ? " connected" : " empty");
        if (enabled)
            arch::SerialWrite(",enabled");
        if (resetting)
            arch::SerialWrite(",resetting");
        arch::SerialWrite(" speed=");
        arch::SerialWrite(XhciPortSpeedName(speed));
        arch::SerialWrite("\n");
    }
}

void LogHostController(const HostControllerInfo& h)
{
    arch::SerialWrite("  usb ");
    arch::SerialWriteHex(h.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(h.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(h.function);
    arch::SerialWrite("  vid=");
    arch::SerialWriteHex(h.vendor_id);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(h.device_id);
    arch::SerialWrite(" kind=");
    arch::SerialWrite(HciKindName(h.kind));
    if (h.mmio_size != 0)
    {
        arch::SerialWrite(" bar0=");
        arch::SerialWriteHex(h.mmio_phys);
        arch::SerialWrite("/");
        arch::SerialWriteHex(h.mmio_size);
        if (h.mmio_virt != nullptr)
        {
            arch::SerialWrite(" -> ");
            arch::SerialWriteHex(reinterpret_cast<u64>(h.mmio_virt));
        }
    }
    arch::SerialWrite("\n");
}

} // namespace

const char* HciKindName(HciKind k)
{
    switch (k)
    {
    case HciKind::Uhci:
        return "uhci";
    case HciKind::Ohci:
        return "ohci";
    case HciKind::Ehci:
        return "ehci";
    case HciKind::Xhci:
        return "xhci";
    case HciKind::Device:
        return "device-ctrl";
    case HciKind::Other:
        return "other";
    default:
        return "unknown";
    }
}

void UsbInit()
{
    KLOG_TRACE_SCOPE("drivers/usb", "UsbInit");
    static constinit bool s_done = false;
    KASSERT(!s_done, "drivers/usb", "UsbInit called twice");
    s_done = true;

    const u64 n = pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_hc_count < kMaxHostControllers; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code != kPciClassSerialBus || d.subclass != kPciSubclassUsb)
            continue;
        // Device-mode controllers don't host a bus — skip them in
        // v0 (target programs are host-mode only).
        if (d.prog_if == kProgIfDevice)
            continue;

        HostControllerInfo h = {};
        h.vendor_id = d.vendor_id;
        h.device_id = d.device_id;
        h.bus = d.addr.bus;
        h.device = d.addr.device;
        h.function = d.addr.function;
        h.prog_if = d.prog_if;
        h.kind = KindFromProgIf(d.prog_if);

        // UHCI uses port I/O, not MMIO — BAR 0's is_io is set and
        // MapMmio isn't the right abstraction. We still record the
        // I/O port base in mmio_phys (repurposed) but skip the map.
        const pci::Bar bar0 = pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0)
        {
            h.mmio_phys = bar0.address;
            h.mmio_size = bar0.size;
            if (!bar0.is_io)
            {
                constexpr u64 kMmioCap = 1ULL * 1024 * 1024;
                const u64 map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
                h.mmio_virt = mm::MapMmio(bar0.address, map_bytes);
            }
        }

        g_hcs[g_hc_count++] = h;
    }

    core::LogWithValue(core::LogLevel::Info, "drivers/usb", "discovered host controllers", g_hc_count);
    for (u64 i = 0; i < g_hc_count; ++i)
    {
        LogHostController(g_hcs[i]);
        // xHCI is the only host-controller variant whose capability
        // register layout we decode in v0. EHCI / OHCI / UHCI have
        // their own — decoders added when we actually target them.
        if (g_hcs[i].kind == HciKind::Xhci)
        {
            DecodeXhciCaps(g_hcs[i]);
        }
    }
    if (g_hc_count == 0)
    {
        core::Log(core::LogLevel::Warn, "drivers/usb", "no USB host controllers found");
    }

    // Announce which class drivers are compiled in. Nothing actually
    // dispatches through these today — bus enumeration is deferred —
    // but printing the list makes the gap visible in the boot log.
    arch::SerialWrite("[usb] class drivers registered: ");
    for (u64 i = 0; i < ClassDriverCount(); ++i)
    {
        if (i != 0)
            arch::SerialWrite(", ");
        arch::SerialWrite(kClassDrivers[i].name);
    }
    arch::SerialWrite("\n");
}

u64 HostControllerCount()
{
    return g_hc_count;
}

const HostControllerInfo& HostController(u64 index)
{
    KASSERT_WITH_VALUE(index < g_hc_count, "drivers/usb", "HostController index out of range", index);
    return g_hcs[index];
}

u64 ClassDriverCount()
{
    constexpr u64 n = sizeof(kClassDrivers) / sizeof(kClassDrivers[0]);
    return n;
}

const UsbClassDriver& ClassDriver(u64 index)
{
    KASSERT_WITH_VALUE(index < ClassDriverCount(), "drivers/usb", "ClassDriver index out of range", index);
    return kClassDrivers[index];
}

} // namespace customos::drivers::usb
