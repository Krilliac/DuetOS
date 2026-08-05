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

void CaptureHidReportDescriptorLength(const u8* desc, u8 len, HidInterfaceRecord& iface)
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
            iface.report_desc_length = descriptorLength;
            return;
        }
    }
}

// Field-by-field reset. The freestanding toolchain lowers `rec = {}`
// on an aggregate to a memset call the kernel has no definition for,
// so every field is written explicitly.
void ResetHidInterfaceRecord(HidInterfaceRecord& iface)
{
    iface.kind = HidIfaceKind::None;
    iface.interface_num = 0;
    iface.ep_addr = 0;
    iface.ep_max_packet = 0;
    iface.ep_interval = 0;
    iface.report_desc_length = 0;
    iface.bound = false;
}

// A HID interface is a boot keyboard or boot mouse iff it declares
// the Boot subclass AND the matching protocol. Everything else on
// the HID class — subclass 0 / protocol 0 gamepads, consumer-control
// blocks, digitizers — is a report-protocol CANDIDATE that only
// GET_DESCRIPTOR(Report) can classify at bring-up time.
HidIfaceKind ClassifyHidInterface(u8 subclass, u8 protocol)
{
    if (subclass == kIfaceSubclassBoot && protocol == kIfaceProtocolKeyboard)
        return HidIfaceKind::BootKeyboard;
    if (subclass == kIfaceSubclassBoot && protocol == kIfaceProtocolMouse)
        return HidIfaceKind::BootMouse;
    return HidIfaceKind::GamepadCandidate;
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

// Report-protocol gamepad: HID interface with subclass 0 /
// protocol 0 (no boot protocol). The parser must claim it as a
// gamepad CANDIDATE and still capture the endpoint + Report
// descriptor length for the bring-up path to confirm against.
constexpr u8 kGamepadConfigDescriptor[] = {
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
    0x02,
    0x00,
    0x01,
    kIfaceClassHid,
    0x00,
    0x00,
    0x00,
    0x09,
    kDescTypeHid,
    0x11,
    0x01,
    0x00,
    0x01,
    kDescTypeReport,
    0x60,
    0x00,
    0x07,
    kDescTypeEndpoint,
    0x81,
    kEpAttrTypeInterrupt,
    0x20,
    0x00,
    0x08,
};

// Composite HID device, gamepad-interface-FIRST: a non-boot HID
// interface (bInterfaceNumber 4, subclass 0 / protocol 0) precedes a
// boot keyboard interface (bInterfaceNumber 5, subclass 1 /
// protocol 1) on one device. This is the shape real gaming keyboards
// and headsets ship — the media/consumer-control interface is often
// enumerated ahead of the boot keyboard. A first-match-wins claim
// loses the keyboard entirely on this descriptor, so the parser must
// return BOTH interfaces with their own endpoints.
//
// wTotalLength = 9 (config) + 25 (iface 4 + HID + EP) + 25
//              = 59 = 0x3B.
constexpr u8 kCompositeGamepadThenKeyboardConfigDescriptor[] = {
    // Configuration descriptor.
    0x09,            // bLength
    kDescTypeConfig, // bDescriptorType
    0x3B,            // wTotalLength lo
    0x00,            // wTotalLength hi
    0x02,            // bNumInterfaces
    0x01,            // bConfigurationValue
    0x00,            // iConfiguration
    0xA0,            // bmAttributes (bus-powered, remote wakeup)
    0x32,            // bMaxPower (100 mA)
    // Interface 4 — non-boot HID (gamepad candidate).
    0x09,                 // bLength
    kDescTypeInterface,   // bDescriptorType
    0x04,                 // bInterfaceNumber
    0x00,                 // bAlternateSetting
    0x01,                 // bNumEndpoints
    kIfaceClassHid,       // bInterfaceClass
    0x00,                 // bInterfaceSubClass (not boot)
    0x00,                 // bInterfaceProtocol
    0x00,                 // iInterface
    0x09,                 // bLength (HID class descriptor)
    kDescTypeHid,         // bDescriptorType
    0x11,                 // bcdHID lo
    0x01,                 // bcdHID hi
    0x00,                 // bCountryCode
    0x01,                 // bNumDescriptors
    kDescTypeReport,      // bDescriptorType[0]
    0x90,                 // wDescriptorLength[0] lo
    0x00,                 // wDescriptorLength[0] hi
    0x07,                 // bLength (endpoint)
    kDescTypeEndpoint,    // bDescriptorType
    0x83,                 // bEndpointAddress (EP3 IN)
    kEpAttrTypeInterrupt, // bmAttributes
    0x20,                 // wMaxPacketSize lo
    0x00,                 // wMaxPacketSize hi
    0x08,                 // bInterval
    // Interface 5 — boot keyboard.
    0x09,                   // bLength
    kDescTypeInterface,     // bDescriptorType
    0x05,                   // bInterfaceNumber
    0x00,                   // bAlternateSetting
    0x01,                   // bNumEndpoints
    kIfaceClassHid,         // bInterfaceClass
    kIfaceSubclassBoot,     // bInterfaceSubClass
    kIfaceProtocolKeyboard, // bInterfaceProtocol
    0x00,                   // iInterface
    0x09,                   // bLength (HID class descriptor)
    kDescTypeHid,           // bDescriptorType
    0x11,                   // bcdHID lo
    0x01,                   // bcdHID hi
    0x00,                   // bCountryCode
    0x01,                   // bNumDescriptors
    kDescTypeReport,        // bDescriptorType[0]
    0x41,                   // wDescriptorLength[0] lo
    0x00,                   // wDescriptorLength[0] hi
    0x07,                   // bLength (endpoint)
    kDescTypeEndpoint,      // bDescriptorType
    0x81,                   // bEndpointAddress (EP1 IN)
    kEpAttrTypeInterrupt,   // bmAttributes
    0x08,                   // wMaxPacketSize lo
    0x00,                   // wMaxPacketSize hi
    0x0A,                   // bInterval
};

} // namespace

// Walk a USB Configuration descriptor collecting EVERY HID interface
// that carries a usable interrupt-IN endpoint. `buf[0..len)` is the
// wTotalLength-bytes-long descriptor tree (a flat stream of
// sub-descriptors each prefixed with {bLength, bDescriptorType}).
//
// A composite HID device — a gaming keyboard with a consumer-control
// interface, a headset with a telephony interface — presents several
// HID interfaces behind one device. Claiming only the first would
// shadow whichever interface the vendor happened to enumerate later,
// which on real hardware is routinely the boot keyboard. So each
// claimed interface gets its own record with its own endpoint;
// bring-up walks them independently.
//
// Interfaces with bAlternateSetting != 0 are skipped: we never issue
// SET_INTERFACE, so alt settings are not reachable and their
// endpoints must not be programmed. Records that ended the walk
// without an interrupt-IN endpoint are dropped — they can never feed
// reports, and leaving them in would make the aggregate flags claim
// a device the poll task cannot drive.
//
// Returns true iff at least one usable HID interface was claimed.
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

    port.hid_iface_count = 0;
    port.hid_ifaces_dropped = 0;
    port.hid_keyboard = false;
    port.hid_mouse = false;
    port.hid_gamepad = false;
    for (u8 i = 0; i < u8(kMaxHidInterfacesPerPort); ++i)
        ResetHidInterfaceRecord(port.hid_ifaces[i]);

    // Index into port.hid_ifaces of the interface the walker is
    // currently inside, or kNoIface when it is outside a HID
    // interface (or inside one the cap rejected). Every HID class
    // descriptor and endpoint descriptor that follows an interface
    // descriptor belongs to THAT interface — this cursor is what
    // keeps a composite device's endpoints attached to the right one.
    constexpr u8 kNoIface = 0xFF;
    u8 cur = kNoIface;
    while (off + 2 <= len)
    {
        const u8 dlen = buf[off];
        if (dlen < 2 || off + dlen > len)
            break;
        const u8 dtype = buf[off + 1];
        if (dtype == kDescTypeInterface && dlen >= 9)
        {
            const u8 bInterfaceNumber = buf[off + 2];
            const u8 bAlternateSetting = buf[off + 3];
            const u8 bInterfaceClass = buf[off + 5];
            const u8 bInterfaceSubClass = buf[off + 6];
            const u8 bInterfaceProtocol = buf[off + 7];
            cur = kNoIface;
            if (bInterfaceClass == kIfaceClassHid && bAlternateSetting == 0)
            {
                // A repeated interface number at alt 0 is malformed;
                // claiming it twice would program the same endpoint
                // on two records and double-count the aggregate.
                bool duplicate = false;
                for (u8 i = 0; i < port.hid_iface_count; ++i)
                {
                    if (port.hid_ifaces[i].interface_num == bInterfaceNumber)
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate)
                {
                    // Leave `cur` at kNoIface: the repeat's descriptors
                    // are ignored, the original record stands.
                }
                else if (port.hid_iface_count < u8(kMaxHidInterfacesPerPort))
                {
                    cur = port.hid_iface_count;
                    HidInterfaceRecord& rec = port.hid_ifaces[cur];
                    ResetHidInterfaceRecord(rec);
                    rec.kind = ClassifyHidInterface(bInterfaceSubClass, bInterfaceProtocol);
                    rec.interface_num = bInterfaceNumber;
                    ++port.hid_iface_count;
                }
                else
                {
                    // GAP: HID interfaces past kMaxHidInterfacesPerPort are
                    // counted and logged, not bound — revisit if hardware
                    // shows up with more than four HID interfaces per device.
                    ++port.hid_ifaces_dropped;
                }
            }
        }
        else if (cur != kNoIface && dtype == kDescTypeHid)
        {
            CaptureHidReportDescriptorLength(buf + off, dlen, port.hid_ifaces[cur]);
        }
        else if (cur != kNoIface && dtype == kDescTypeEndpoint && dlen >= 7 && port.hid_ifaces[cur].ep_addr == 0)
        {
            const u8 bEndpointAddress = buf[off + 2];
            const u8 bmAttributes = buf[off + 3];
            const u16 wMaxPacketSize = u16(buf[off + 4]) | (u16(buf[off + 5]) << 8);
            const u8 bInterval = buf[off + 6];
            if ((bmAttributes & kEpAttrTypeMask) == kEpAttrTypeInterrupt && (bEndpointAddress & kEpAddrDirIn))
            {
                HidInterfaceRecord& rec = port.hid_ifaces[cur];
                rec.ep_addr = bEndpointAddress;
                rec.ep_max_packet = wMaxPacketSize & 0x7FF;
                rec.ep_interval = bInterval;
            }
        }
        off += dlen;
    }

    // Drop interfaces that never produced an interrupt-IN endpoint.
    // They cannot be polled, and keeping them would let the aggregate
    // flags below advertise a keyboard the bring-up path would then
    // try to configure against DCI 0.
    u8 keep = 0;
    for (u8 i = 0; i < port.hid_iface_count; ++i)
    {
        if (port.hid_ifaces[i].ep_addr == 0)
            continue;
        if (keep != i)
            port.hid_ifaces[keep] = port.hid_ifaces[i];
        ++keep;
    }
    for (u8 i = keep; i < port.hid_iface_count; ++i)
        ResetHidInterfaceRecord(port.hid_ifaces[i]);
    port.hid_iface_count = keep;

    for (u8 i = 0; i < port.hid_iface_count; ++i)
    {
        switch (port.hid_ifaces[i].kind)
        {
        case HidIfaceKind::BootKeyboard:
            port.hid_keyboard = true;
            break;
        case HidIfaceKind::BootMouse:
            port.hid_mouse = true;
            break;
        case HidIfaceKind::GamepadCandidate:
            port.hid_gamepad = true;
            break;
        case HidIfaceKind::None:
            break;
        }
    }
    return port.hid_iface_count > 0;
}

void XhciDescriptorSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/usb/xhci-desc", "XhciDescriptorSelfTest");

    {
        PortRecord port{};
        const bool ok = ParseConfigForHidBoot(kMouseConfigDescriptor, sizeof(kMouseConfigDescriptor), port);
        ExpectEq(u32(ok), 1, "mouse parse_ok");
        ExpectEq(u32(port.hid_iface_count), 1, "mouse iface count");
        ExpectEq(u32(port.hid_mouse), 1, "mouse flag");
        ExpectEq(u32(port.hid_keyboard), 0, "keyboard flag clear");
        ExpectEq(u32(port.hid_ifaces[0].kind), u32(HidIfaceKind::BootMouse), "mouse kind");
        ExpectEq(u32(port.hid_ifaces[0].interface_num), 3, "mouse iface");
        ExpectEq(u32(port.hid_ifaces[0].ep_addr), 0x81, "mouse ep");
        ExpectEq(u32(port.hid_ifaces[0].ep_max_packet), 0x10, "mouse max_packet");
        ExpectEq(u32(port.hid_ifaces[0].ep_interval), 8, "mouse interval");
        ExpectEq(u32(port.hid_ifaces[0].report_desc_length), 0x7B, "mouse report len");
    }

    {
        // Composite keyboard + mouse. Both interfaces are now claimed
        // with their OWN endpoint and report-descriptor length; the
        // old first-match-wins claim kept only the keyboard.
        PortRecord port{};
        const bool ok =
            ParseConfigForHidBoot(kKeyboardThenMouseConfigDescriptor, sizeof(kKeyboardThenMouseConfigDescriptor), port);
        ExpectEq(u32(ok), 1, "keyboard-first parse_ok");
        ExpectEq(u32(port.hid_iface_count), 2, "keyboard+mouse iface count");
        ExpectEq(u32(port.hid_keyboard), 1, "keyboard flag");
        ExpectEq(u32(port.hid_mouse), 1, "mouse also claimed");
        ExpectEq(u32(port.hid_ifaces[0].kind), u32(HidIfaceKind::BootKeyboard), "iface0 kind keyboard");
        ExpectEq(u32(port.hid_ifaces[0].interface_num), 1, "keyboard iface");
        ExpectEq(u32(port.hid_ifaces[0].ep_addr), 0x82, "keyboard ep");
        ExpectEq(u32(port.hid_ifaces[0].report_desc_length), 0x3F, "keyboard report len");
        ExpectEq(u32(port.hid_ifaces[1].kind), u32(HidIfaceKind::BootMouse), "iface1 kind mouse");
        ExpectEq(u32(port.hid_ifaces[1].interface_num), 2, "mouse iface");
        ExpectEq(u32(port.hid_ifaces[1].ep_addr), 0x83, "mouse ep");
        ExpectEq(u32(port.hid_ifaces[1].ep_max_packet), 0x20, "mouse max_packet");
        ExpectEq(u32(port.hid_ifaces[1].report_desc_length), 0x65, "mouse report len");
    }

    {
        // The regression this slice closes: a non-boot HID interface
        // enumerated AHEAD of the boot keyboard. Under first-match
        // claiming the keyboard was shadowed and lost entirely.
        PortRecord port{};
        const bool ok = ParseConfigForHidBoot(kCompositeGamepadThenKeyboardConfigDescriptor,
                                              sizeof(kCompositeGamepadThenKeyboardConfigDescriptor), port);
        ExpectEq(u32(ok), 1, "composite parse_ok");
        ExpectEq(u32(port.hid_iface_count), 2, "composite iface count");
        ExpectEq(u32(port.hid_ifaces_dropped), 0, "composite none dropped");
        ExpectEq(u32(port.hid_config_value), 1, "composite config value");
        ExpectEq(u32(port.hid_gamepad), 1, "composite gamepad candidate claimed");
        ExpectEq(u32(port.hid_keyboard), 1, "composite keyboard NOT shadowed");
        ExpectEq(u32(port.hid_mouse), 0, "composite mouse flag clear");
        ExpectEq(u32(port.hid_ifaces[0].kind), u32(HidIfaceKind::GamepadCandidate), "composite iface0 kind");
        ExpectEq(u32(port.hid_ifaces[0].interface_num), 4, "composite gamepad iface");
        ExpectEq(u32(port.hid_ifaces[0].ep_addr), 0x83, "composite gamepad ep");
        ExpectEq(u32(port.hid_ifaces[0].ep_max_packet), 0x20, "composite gamepad max_packet");
        ExpectEq(u32(port.hid_ifaces[0].ep_interval), 8, "composite gamepad interval");
        ExpectEq(u32(port.hid_ifaces[0].report_desc_length), 0x90, "composite gamepad report len");
        ExpectEq(u32(port.hid_ifaces[1].kind), u32(HidIfaceKind::BootKeyboard), "composite iface1 kind");
        ExpectEq(u32(port.hid_ifaces[1].interface_num), 5, "composite keyboard iface");
        ExpectEq(u32(port.hid_ifaces[1].ep_addr), 0x81, "composite keyboard ep");
        ExpectEq(u32(port.hid_ifaces[1].ep_max_packet), 0x08, "composite keyboard max_packet");
        ExpectEq(u32(port.hid_ifaces[1].ep_interval), 0x0A, "composite keyboard interval");
        ExpectEq(u32(port.hid_ifaces[1].report_desc_length), 0x41, "composite keyboard report len");
    }

    {
        PortRecord port{};
        const bool ok = ParseConfigForHidBoot(kGamepadConfigDescriptor, sizeof(kGamepadConfigDescriptor), port);
        ExpectEq(u32(ok), 1, "gamepad parse_ok");
        ExpectEq(u32(port.hid_iface_count), 1, "gamepad iface count");
        ExpectEq(u32(port.hid_gamepad), 1, "gamepad candidate flag");
        ExpectEq(u32(port.hid_keyboard), 0, "gamepad: keyboard flag clear");
        ExpectEq(u32(port.hid_mouse), 0, "gamepad: mouse flag clear");
        ExpectEq(u32(port.hid_ifaces[0].interface_num), 2, "gamepad iface");
        ExpectEq(u32(port.hid_ifaces[0].ep_addr), 0x81, "gamepad ep");
        ExpectEq(u32(port.hid_ifaces[0].ep_max_packet), 0x20, "gamepad max_packet");
        ExpectEq(u32(port.hid_ifaces[0].ep_interval), 8, "gamepad interval");
        ExpectEq(u32(port.hid_ifaces[0].report_desc_length), 0x60, "gamepad report len");
    }

    arch::SerialWrite(
        "[xhci-desc-selftest] PASS (composite HID interfaces + endpoints + report descriptor lengths parsed)\n");
}

} // namespace duetos::drivers::usb::xhci::internal
