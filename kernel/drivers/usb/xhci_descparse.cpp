/*
 * DuetOS — xHCI driver: USB descriptor parsing.
 *
 * Sibling TU. Houses the pure-logic descriptor-tree walker that
 * lifts a HID Boot Keyboard / Mouse interface (and its first
 * interrupt-IN endpoint) out of a Configuration descriptor blob.
 * No xHCI controller / Runtime / TRB state — the byte buffer comes
 * already in RAM from FetchAndParseConfig over in xhci.cpp.
 */

#include "drivers/usb/xhci_internal.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"

namespace duetos::drivers::usb::xhci::internal
{

namespace
{

void ExpectEq(u32 actual, u32 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[xhci-desc-selftest] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/usb/xhci-desc", "xHCI descriptor self-test mismatch", actual);
}

void CaptureHidReportDescriptorLength(const u8* desc, u8 len, PortRecord& port)
{
    if (desc == nullptr || len < 9)
        return;

    const u8 descriptorCount = desc[5];
    u8 off = 6;
    for (u8 i = 0; i < descriptorCount && off + 3 <= len; ++i, off = u8(off + 3))
    {
        const u8 descriptorType = desc[off];
        const u16 descriptorLength = u16(desc[off + 1]) | (u16(desc[off + 2]) << 8);
        if (descriptorType == kDescTypeReport && descriptorLength != 0)
        {
            port.hid_report_desc_length = descriptorLength;
            return;
        }
    }
}

constexpr u8 kMouseConfigDescriptor[] = {
    0x09,
    kDescTypeConfig,
    0x22,
    0x00,
    0x01,
    0x01,
    0x00,
    0xA0,
    0x32,
    0x09,
    kDescTypeInterface,
    0x03,
    0x00,
    0x01,
    kIfaceClassHid,
    kIfaceSubclassBoot,
    kIfaceProtocolMouse,
    0x00,
    0x09,
    kDescTypeHid,
    0x11,
    0x01,
    0x00,
    0x01,
    kDescTypeReport,
    0x7B,
    0x00,
    0x07,
    kDescTypeEndpoint,
    0x81,
    kEpAttrTypeInterrupt,
    0x10,
    0x00,
    0x08,
};

constexpr u8 kKeyboardThenMouseConfigDescriptor[] = {
    0x09,
    kDescTypeConfig,
    0x3B,
    0x00,
    0x02,
    0x02,
    0x00,
    0xA0,
    0x32,
    0x09,
    kDescTypeInterface,
    0x01,
    0x00,
    0x01,
    kIfaceClassHid,
    kIfaceSubclassBoot,
    kIfaceProtocolKeyboard,
    0x00,
    0x09,
    kDescTypeHid,
    0x11,
    0x01,
    0x00,
    0x01,
    kDescTypeReport,
    0x3F,
    0x00,
    0x07,
    kDescTypeEndpoint,
    0x82,
    kEpAttrTypeInterrupt,
    0x08,
    0x00,
    0x0A,
    0x09,
    kDescTypeInterface,
    0x02,
    0x00,
    0x01,
    kIfaceClassHid,
    kIfaceSubclassBoot,
    kIfaceProtocolMouse,
    0x00,
    0x09,
    kDescTypeHid,
    0x11,
    0x01,
    0x00,
    0x01,
    kDescTypeReport,
    0x65,
    0x00,
    0x07,
    kDescTypeEndpoint,
    0x83,
    kEpAttrTypeInterrupt,
    0x20,
    0x00,
    0x04,
};

} // namespace

// Walk a USB Configuration descriptor looking for the first HID
// Boot Keyboard interface and its first interrupt-IN endpoint.
// `buf[0..len)` is the wTotalLength-bytes-long descriptor tree (a
// flat stream of sub-descriptors each prefixed with {bLength,
// bDescriptorType}). Populates port fields iff a keyboard is found.
// Returns true on keyboard found.
bool ParseConfigForHidBoot(const u8* buf, u32 len, PortRecord& port)
{
    if (buf == nullptr || len < kConfigDescriptorHeaderBytes)
        return false;
    // Top-level Configuration descriptor: byte 5 = bConfigurationValue
    // (the argument we'll pass to SET_CONFIGURATION below).
    port.hid_config_value = buf[5];

    // bLength of the Config descriptor itself. Must be at least 2
    // for the inner walker's "dlen < 2 → break" guard to advance
    // past this header — if bLength is 0 or 1 we'd loop on the
    // SAME byte indefinitely, except the body's break catches that
    // too. Defensive cap.
    u32 off = buf[0]; // skip the Configuration descriptor itself
    if (off < kConfigDescriptorHeaderBytes)
        return false;
    bool in_hid_iface = false;
    while (off + 2 <= len)
    {
        const u8 dlen = buf[off];
        if (dlen < 2 || off + dlen > len)
            break;
        const u8 dtype = buf[off + 1];
        if (dtype == kDescTypeInterface && dlen >= 9)
        {
            const u8 bInterfaceNumber = buf[off + 2];
            const u8 bInterfaceClass = buf[off + 5];
            const u8 bInterfaceSubClass = buf[off + 6];
            const u8 bInterfaceProtocol = buf[off + 7];
            in_hid_iface = false;
            if (bInterfaceClass == kIfaceClassHid && bInterfaceSubClass == kIfaceSubclassBoot)
            {
                if (bInterfaceProtocol == kIfaceProtocolKeyboard && !port.hid_keyboard)
                {
                    port.hid_interface_num = bInterfaceNumber;
                    port.hid_keyboard = true;
                    in_hid_iface = true;
                }
                else if (bInterfaceProtocol == kIfaceProtocolMouse && !port.hid_mouse)
                {
                    port.hid_interface_num = bInterfaceNumber;
                    port.hid_mouse = true;
                    in_hid_iface = true;
                }
            }
        }
        else if (in_hid_iface && dtype == kDescTypeHid)
        {
            CaptureHidReportDescriptorLength(buf + off, dlen, port);
        }
        else if (in_hid_iface && dtype == kDescTypeEndpoint && dlen >= 7 && port.hid_ep_addr == 0)
        {
            const u8 bEndpointAddress = buf[off + 2];
            const u8 bmAttributes = buf[off + 3];
            const u16 wMaxPacketSize = u16(buf[off + 4]) | (u16(buf[off + 5]) << 8);
            const u8 bInterval = buf[off + 6];
            if ((bmAttributes & kEpAttrTypeMask) == kEpAttrTypeInterrupt && (bEndpointAddress & kEpAddrDirIn))
            {
                port.hid_ep_addr = bEndpointAddress;
                port.hid_ep_max_packet = wMaxPacketSize & 0x7FF;
                port.hid_ep_interval = bInterval;
            }
        }
        off += dlen;
    }
    return (port.hid_keyboard || port.hid_mouse) && port.hid_ep_addr != 0;
}

void XhciDescriptorSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/usb/xhci-desc", "XhciDescriptorSelfTest");

    {
        PortRecord port{};
        const bool ok = ParseConfigForHidBoot(kMouseConfigDescriptor, sizeof(kMouseConfigDescriptor), port);
        ExpectEq(u32(ok), 1, "mouse parse_ok");
        ExpectEq(u32(port.hid_mouse), 1, "mouse flag");
        ExpectEq(u32(port.hid_keyboard), 0, "keyboard flag clear");
        ExpectEq(u32(port.hid_interface_num), 3, "mouse iface");
        ExpectEq(u32(port.hid_ep_addr), 0x81, "mouse ep");
        ExpectEq(u32(port.hid_ep_max_packet), 0x10, "mouse max_packet");
        ExpectEq(u32(port.hid_ep_interval), 8, "mouse interval");
        ExpectEq(u32(port.hid_report_desc_length), 0x7B, "mouse report len");
    }

    {
        PortRecord port{};
        const bool ok =
            ParseConfigForHidBoot(kKeyboardThenMouseConfigDescriptor, sizeof(kKeyboardThenMouseConfigDescriptor), port);
        ExpectEq(u32(ok), 1, "keyboard-first parse_ok");
        ExpectEq(u32(port.hid_keyboard), 1, "keyboard flag");
        ExpectEq(u32(port.hid_mouse), 0, "mouse ignored after keyboard claim");
        ExpectEq(u32(port.hid_interface_num), 1, "keyboard iface");
        ExpectEq(u32(port.hid_ep_addr), 0x82, "keyboard ep");
        ExpectEq(u32(port.hid_report_desc_length), 0x3F, "keyboard report len");
    }

    arch::SerialWrite("[xhci-desc-selftest] PASS (HID boot endpoint + report descriptor length parsed)\n");
}

} // namespace duetos::drivers::usb::xhci::internal
