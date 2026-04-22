#include "usb.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"

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

bool HidProbe(u8 subclass, u8 prog_if)
{
    arch::SerialWrite("[usb-hid] probe subclass=");
    arch::SerialWriteHex(subclass);
    arch::SerialWrite(" prog_if=");
    arch::SerialWriteHex(prog_if);
    arch::SerialWrite("  (stub — not claimed)\n");
    return false;
}

bool MscProbe(u8 subclass, u8 prog_if)
{
    arch::SerialWrite("[usb-msc] probe subclass=");
    arch::SerialWriteHex(subclass);
    arch::SerialWrite(" prog_if=");
    arch::SerialWriteHex(prog_if);
    arch::SerialWrite("  (stub — not claimed)\n");
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
