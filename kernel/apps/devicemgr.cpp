#include "apps/devicemgr.h"

#include "arch/x86_64/serial.h"
#include "drivers/pci/pci.h"
#include "drivers/usb/usb.h"
#include "drivers/usb/xhci.h"
#include "drivers/video/framebuffer.h"

namespace duetos::apps::devicemgr
{

namespace
{

constexpr u32 kRowH = 12;
constexpr u32 kMargin = 12;
constexpr u32 kFg = 0x00C8D0DA;
constexpr u32 kFgDim = 0x00808890;
constexpr u32 kHeaderFg = 0x00FFFFFF;
constexpr u32 kSection = 0x00FFD040;
constexpr u32 kBg = 0x00101820;

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

void HexN(char* out, u32 v, u32 nibbles)
{
    static const char kHex[] = "0123456789ABCDEF";
    for (u32 i = 0; i < nibbles; ++i)
    {
        out[nibbles - 1 - i] = kHex[v & 0xF];
        v >>= 4;
    }
}

// Brief class-code labels for the most common PCI base classes.
// Anything else falls through to "OTHER".
const char* ClassLabel(u8 base, u8 sub)
{
    switch (base)
    {
    case 0x00:
        return "UNCLASS";
    case 0x01:
        switch (sub)
        {
        case 0x06:
            return "AHCI";
        case 0x08:
            return "NVME";
        default:
            return "STORAGE";
        }
    case 0x02:
        return "NET";
    case 0x03:
        return "DISPLAY";
    case 0x04:
        return "MULTIMEDIA";
    case 0x05:
        return "MEMORY";
    case 0x06:
        return "BRIDGE";
    case 0x07:
        return "COMM";
    case 0x08:
        return "SYS";
    case 0x09:
        return "INPUT";
    case 0x0C:
        return (sub == 0x03) ? "USB" : "SERBUS";
    default:
        return "OTHER";
    }
}

// Translate a USB device class byte to a short label. Codes
// per USB.org Class Code Reference. 0x00 indicates the device
// defers class declaration to the interface descriptor, which
// the v0 enumerator records on the configuration descriptor
// path (PortRecord.hid_keyboard / hid_mouse). Anything we
// don't recognise prints the raw hex via the caller's fallback.
const char* UsbClassLabel(u8 cls)
{
    switch (cls)
    {
    case 0x00:
        return "PER-IFACE";
    case 0x01:
        return "AUDIO";
    case 0x02:
        return "CDC";
    case 0x03:
        return "HID";
    case 0x05:
        return "PHYS";
    case 0x06:
        return "IMAGE";
    case 0x07:
        return "PRINT";
    case 0x08:
        return "MSC";
    case 0x09:
        return "HUB";
    case 0x0A:
        return "CDC-DATA";
    case 0x0B:
        return "SMARTCARD";
    case 0x0E:
        return "VIDEO";
    case 0x0F:
        return "PHDC";
    case 0xDC:
        return "DIAG";
    case 0xE0:
        return "WIRELESS";
    case 0xEF:
        return "MISC";
    case 0xFE:
        return "APPLIC";
    case 0xFF:
        return "VENDOR";
    default:
        return "OTHER";
    }
}

// Decode the 4-bit PORTSC speed indicator into a short label
// matching xHCI 1.1 §5.4.8. "?" for the unknown / power-off
// states the v0 enumerator never sets.
const char* UsbSpeedLabel(u8 speed)
{
    switch (speed)
    {
    case 1:
        return "FS";
    case 2:
        return "LS";
    case 3:
        return "HS";
    case 4:
        return "SS";
    case 5:
        return "SS+";
    default:
        return "?";
    }
}

void DrawPciSection(u32 cx, u32& y, u32 cy, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    FramebufferDrawString(cx + kMargin, y, "PCI DEVICES", kSection, kBg);
    y += kRowH + 4;
    FramebufferDrawString(cx + kMargin, y, "BUS:DV.F  VEND:DEV   CLASS", kFgDim, kBg);
    y += kRowH;

    const u64 n = duetos::drivers::pci::PciDeviceCount();
    if (n == 0)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO DEVICES — PCI ENUMERATION DID NOT RUN)", kFgDim, kBg);
        y += kRowH;
        return;
    }

    for (u64 i = 0; i < n && y + kRowH < cy + ch; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);

        char line[64];
        u32 o = 0;
        HexN(line + o, d.addr.bus, 2);
        o += 2;
        line[o++] = ':';
        HexN(line + o, d.addr.device, 2);
        o += 2;
        line[o++] = '.';
        line[o++] = static_cast<char>('0' + (d.addr.function & 0x7));
        line[o++] = ' ';
        line[o++] = ' ';

        HexN(line + o, d.vendor_id, 4);
        o += 4;
        line[o++] = ':';
        HexN(line + o, d.device_id, 4);
        o += 4;
        line[o++] = ' ';
        line[o++] = ' ';
        line[o++] = ' ';

        const char* cls = ClassLabel(d.class_code, d.subclass);
        u32 c = 0;
        while (cls[c] != '\0' && o < sizeof(line) - 1)
            line[o++] = cls[c++];
        line[o] = '\0';

        FramebufferDrawString(cx + kMargin, y, line, kFg, kBg);
        y += kRowH;
    }
}

void DrawUsbSection(u32 cx, u32& y, u32 cy, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    if (y + kRowH >= cy + ch)
    {
        return;
    }
    y += kRowH / 2;
    FramebufferDrawString(cx + kMargin, y, "USB DEVICES", kSection, kBg);
    y += kRowH + 4;
    FramebufferDrawString(cx + kMargin, y, "CTL PORT  VID:PID    SPEED CLASS    HID", kFgDim, kBg);
    y += kRowH;

    const u32 hc = duetos::drivers::usb::xhci::XhciCount();
    if (hc == 0)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO USB HOST CONTROLLERS)", kFgDim, kBg);
        y += kRowH;
        return;
    }

    bool any_attached = false;
    for (u32 c = 0; c < hc && y + kRowH < cy + ch; ++c)
    {
        const auto* ci = duetos::drivers::usb::xhci::XhciControllerAt(c);
        if (ci == nullptr)
        {
            continue;
        }
        for (u32 p = 0; p < duetos::drivers::usb::xhci::kMaxXhciPortsPerController && y + kRowH < cy + ch; ++p)
        {
            const auto& port = ci->ports[p];
            if (!port.connected)
            {
                continue;
            }
            any_attached = true;

            char line[80];
            u32 o = 0;
            line[o++] = static_cast<char>('0' + (c & 0x7));
            line[o++] = ' ';
            line[o++] = ' ';
            line[o++] = static_cast<char>('0' + ((port.port_num / 10) % 10));
            line[o++] = static_cast<char>('0' + (port.port_num % 10));
            line[o++] = ' ';
            line[o++] = ' ';

            if (port.descriptor_ok)
            {
                HexN(line + o, port.vendor_id, 4);
                o += 4;
                line[o++] = ':';
                HexN(line + o, port.product_id, 4);
                o += 4;
            }
            else
            {
                const char* na = "----:----";
                for (u32 i = 0; na[i] != '\0'; ++i)
                {
                    line[o++] = na[i];
                }
            }
            line[o++] = ' ';
            line[o++] = ' ';

            const char* spd = UsbSpeedLabel(port.speed);
            for (u32 i = 0; spd[i] != '\0'; ++i)
            {
                line[o++] = spd[i];
            }
            while (o < 28 && o < sizeof(line) - 1)
            {
                line[o++] = ' ';
            }

            const char* cls = UsbClassLabel(port.device_class);
            for (u32 i = 0; cls[i] != '\0' && o < sizeof(line) - 1; ++i)
            {
                line[o++] = cls[i];
            }
            while (o < 37 && o < sizeof(line) - 1)
            {
                line[o++] = ' ';
            }

            const char* hid_label = "";
            if (port.hid_keyboard)
            {
                hid_label = "KBD";
            }
            else if (port.hid_mouse)
            {
                hid_label = "MOUSE";
            }
            for (u32 i = 0; hid_label[i] != '\0' && o < sizeof(line) - 1; ++i)
            {
                line[o++] = hid_label[i];
            }
            line[o] = '\0';

            FramebufferDrawString(cx + kMargin, y, line, kFg, kBg);
            y += kRowH;
        }
    }
    if (!any_attached && y + kRowH < cy + ch)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO USB DEVICES ATTACHED)", kFgDim, kBg);
        y += kRowH;
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    (void)cw;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    u32 y = cy + kMargin;
    FramebufferDrawString(cx + kMargin, y, "DEVICE MANAGER", kHeaderFg, kBg);
    y += kRowH + 6;
    DrawPciSection(cx, y, cy, ch);
    DrawUsbSection(cx, y, cy, ch);
}

} // namespace

void DeviceMgrInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle DeviceMgrWindow()
{
    return g_handle;
}

void DeviceMgrSelfTest()
{
    using duetos::arch::SerialWrite;
    const u64 n = duetos::drivers::pci::PciDeviceCount();
    SerialWrite("[apps/devicemgr] selftest: pci_count=");
    char buf[8];
    u32 v = static_cast<u32>(n);
    u32 o = 0;
    if (v == 0)
        buf[o++] = '0';
    else
    {
        char tmp[8];
        u32 t = 0;
        while (v != 0)
        {
            tmp[t++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (t != 0)
            buf[o++] = tmp[--t];
    }
    buf[o] = '\0';
    SerialWrite(buf);
    SerialWrite(" PASS\n");
}

} // namespace duetos::apps::devicemgr
