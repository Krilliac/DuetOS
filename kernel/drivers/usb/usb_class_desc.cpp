#include "drivers/usb/usb_class_desc.h"

#include "usbclass.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"

namespace duetos::drivers::usb
{

namespace
{

static_assert(sizeof(DuetosUsbClassEndpointSet) == sizeof(UsbClassEndpointSet),
              "Rust USB class endpoint ABI drifted from the C++ wrapper");
static_assert(alignof(DuetosUsbClassEndpointSet) == alignof(UsbClassEndpointSet),
              "Rust USB class endpoint ABI alignment drifted from the C++ wrapper");
static_assert(__builtin_offsetof(DuetosUsbClassEndpointSet, iso_out) ==
                  __builtin_offsetof(UsbClassEndpointSet, iso_out),
              "Rust USB class endpoint ABI field drifted from the C++ wrapper");
static_assert(sizeof(DuetosUsbClassSummary) == sizeof(UsbClassConfigSummary),
              "Rust USB class summary ABI drifted from the C++ wrapper");
static_assert(alignof(DuetosUsbClassSummary) == alignof(UsbClassConfigSummary),
              "Rust USB class summary ABI alignment drifted from the C++ wrapper");
static_assert(__builtin_offsetof(DuetosUsbClassSummary, bluetooth) ==
                  __builtin_offsetof(UsbClassConfigSummary, bluetooth),
              "Rust USB class summary ABI field drifted from the C++ wrapper");

void ClearSummary(UsbClassConfigSummary& out)
{
    auto* bytes = reinterpret_cast<volatile u8*>(&out);
    for (u64 i = 0; i < sizeof(out); ++i)
        bytes[i] = 0;
}

void CopyEndpointSet(const DuetosUsbClassEndpointSet& src, UsbClassEndpointSet& dst)
{
    dst.bulk_in = src.bulk_in;
    dst.bulk_out = src.bulk_out;
    dst.interrupt_in = src.interrupt_in;
    dst.interrupt_out = src.interrupt_out;
    dst.iso_in = src.iso_in;
    dst.iso_out = src.iso_out;
}

void ExpectEq(u32 actual, u32 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[usb-class-desc-selftest] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/usb/class-desc", "USB class descriptor parser self-test mismatch", actual);
}

constexpr u8 kMscConfigDescriptor[] = {
    0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32, // Config, total 32
    0x09, 0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00, // MSC SCSI BBB
    0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00,             // Bulk IN
    0x07, 0x05, 0x02, 0x02, 0x00, 0x02, 0x00,             // Bulk OUT
};

constexpr u8 kHubConfigDescriptor[] = {
    0x09, 0x02, 0x19, 0x00, 0x01, 0x01, 0x00, 0xE0, 0x00, // Config, total 25
    0x09, 0x04, 0x00, 0x00, 0x01, 0x09, 0x00, 0x00, 0x00, // Hub interface
    0x07, 0x05, 0x81, 0x03, 0x01, 0x00, 0x0C,             // Interrupt IN
};

constexpr u8 kUvcConfigDescriptor[] = {
    0x09, 0x02, 0x30, 0x00, 0x02, 0x01, 0x00, 0x80, 0xFA, // Config, total 48
    0x09, 0x04, 0x00, 0x00, 0x01, 0x0E, 0x01, 0x00, 0x00, // VideoControl
    0x07, 0x05, 0x83, 0x03, 0x10, 0x00, 0x08,             // Interrupt IN
    0x09, 0x04, 0x01, 0x00, 0x02, 0x0E, 0x02, 0x00, 0x00, // VideoStreaming
    0x07, 0x05, 0x84, 0x01, 0x00, 0x04, 0x01,             // Iso IN
    0x07, 0x05, 0x05, 0x01, 0x00, 0x04, 0x01,             // Iso OUT
};

constexpr u8 kBluetoothConfigDescriptor[] = {
    0x09, 0x02, 0x27, 0x00, 0x01, 0x01, 0x00, 0xE0, 0x32, // Config, total 39
    0x09, 0x04, 0x00, 0x00, 0x03, 0xE0, 0x01, 0x01, 0x00, // BT HCI USB
    0x07, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01,             // Interrupt IN events
    0x07, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00,             // Bulk IN ACL
    0x07, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00,             // Bulk OUT ACL
};

constexpr u8 kMalformedConfigDescriptor[] = {
    0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32, 0x09,
    0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00, 0x01, 0x05, // invalid bLength=1 for endpoint-shaped descriptor
};

} // namespace

bool UsbClassParseConfigDescriptor(const u8* buf, u32 len, UsbClassConfigSummary* out)
{
    if (out == nullptr)
        return false;

    ClearSummary(*out);

    DuetosUsbClassSummary rustSummary{};
    const bool ok = duetos_usbclass_parse_config(buf, len, &rustSummary);
    out->parse_ok = rustSummary.parse_ok;
    out->bytes_consumed = rustSummary.bytes_consumed;
    out->config_value = rustSummary.config_value;
    out->interface_count = rustSummary.interface_count;
    out->endpoint_count = rustSummary.endpoint_count;
    out->flags = rustSummary.flags;
    CopyEndpointSet(rustSummary.msc, out->msc);
    CopyEndpointSet(rustSummary.hub, out->hub);
    CopyEndpointSet(rustSummary.uvc_control, out->uvc_control);
    CopyEndpointSet(rustSummary.uvc_streaming, out->uvc_streaming);
    CopyEndpointSet(rustSummary.bluetooth, out->bluetooth);
    return ok;
}

void UsbClassDescriptorSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/usb/class-desc", "UsbClassDescriptorSelfTest");

    {
        UsbClassConfigSummary s{};
        const bool ok = UsbClassParseConfigDescriptor(kMscConfigDescriptor, sizeof(kMscConfigDescriptor), &s);
        ExpectEq(u32(ok), 1, "msc parse_ok");
        ExpectEq(s.interface_count, 1, "msc interface_count");
        ExpectEq(s.endpoint_count, 2, "msc endpoint_count");
        ExpectEq(s.flags & kUsbClassFlagMscBulkOnly, kUsbClassFlagMscBulkOnly, "msc flag");
        ExpectEq(s.msc.bulk_in, 0x81, "msc bulk_in");
        ExpectEq(s.msc.bulk_out, 0x02, "msc bulk_out");
    }
    {
        UsbClassConfigSummary s{};
        const bool ok = UsbClassParseConfigDescriptor(kHubConfigDescriptor, sizeof(kHubConfigDescriptor), &s);
        ExpectEq(u32(ok), 1, "hub parse_ok");
        ExpectEq(s.flags & kUsbClassFlagHub, kUsbClassFlagHub, "hub flag");
        ExpectEq(s.hub.interrupt_in, 0x81, "hub interrupt_in");
    }
    {
        UsbClassConfigSummary s{};
        const bool ok = UsbClassParseConfigDescriptor(kUvcConfigDescriptor, sizeof(kUvcConfigDescriptor), &s);
        ExpectEq(u32(ok), 1, "uvc parse_ok");
        ExpectEq(s.interface_count, 2, "uvc interface_count");
        ExpectEq(s.bytes_consumed, sizeof(kUvcConfigDescriptor), "uvc bytes_consumed");
        ExpectEq(s.flags & kUsbClassFlagUvcControl, kUsbClassFlagUvcControl, "uvc control flag");
        ExpectEq(s.flags & kUsbClassFlagUvcStreaming, kUsbClassFlagUvcStreaming, "uvc streaming flag");
        ExpectEq(s.uvc_control.interrupt_in, 0x83, "uvc control interrupt_in");
        ExpectEq(s.uvc_streaming.iso_in, 0x84, "uvc streaming iso_in");
        ExpectEq(s.uvc_streaming.iso_out, 0x05, "uvc streaming iso_out");
    }
    {
        UsbClassConfigSummary s{};
        const bool ok =
            UsbClassParseConfigDescriptor(kBluetoothConfigDescriptor, sizeof(kBluetoothConfigDescriptor), &s);
        ExpectEq(u32(ok), 1, "bt parse_ok");
        ExpectEq(s.flags & kUsbClassFlagBluetooth, kUsbClassFlagBluetooth, "bt flag");
        ExpectEq(s.bluetooth.interrupt_in, 0x81, "bt interrupt_in");
        ExpectEq(s.bluetooth.bulk_in, 0x82, "bt bulk_in");
        ExpectEq(s.bluetooth.bulk_out, 0x02, "bt bulk_out");
    }
    {
        UsbClassConfigSummary s{};
        const bool ok =
            UsbClassParseConfigDescriptor(kMalformedConfigDescriptor, sizeof(kMalformedConfigDescriptor), &s);
        ExpectEq(u32(ok), 0, "malformed rejected");
        ExpectEq(u32(s.parse_ok), 0, "malformed parse_ok false");
    }

    arch::SerialWrite("[usb-class-desc-selftest] PASS (MSC + hub + UVC + Bluetooth descriptors parsed)\n");
}

} // namespace duetos::drivers::usb
