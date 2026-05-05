#include "apps/devicemgr.h"

#include "arch/x86_64/serial.h"
#include "drivers/pci/pci.h"
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

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    u32 y = cy + kMargin;
    FramebufferDrawString(cx + kMargin, y, "PCI DEVICES", kHeaderFg, kBg);
    y += kRowH + 4;
    FramebufferDrawString(cx + kMargin, y, "BUS:DV.F  VEND:DEV   CLASS", kFgDim, kBg);
    y += kRowH;

    const u64 n = duetos::drivers::pci::PciDeviceCount();
    if (n == 0)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO DEVICES — PCI ENUMERATION DID NOT RUN)", kFgDim, kBg);
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
