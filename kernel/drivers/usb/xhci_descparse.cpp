/*
 * DuetOS — xHCI driver: USB descriptor parsing.
 *
 * Sibling TU. Houses the pure-logic descriptor-tree walker that
 * lifts a HID Boot Keyboard / Mouse interface (and its first
 * interrupt-IN endpoint) out of a Configuration descriptor blob.
 * No xHCI controller / Runtime / TRB state — the byte buffer comes
 * already in RAM from FetchAndParseConfig over in xhci.cpp.
 */

#include "xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{


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

} // namespace duetos::drivers::usb::xhci::internal
