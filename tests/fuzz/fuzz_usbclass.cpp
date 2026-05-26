// DuetOS — USB class-descriptor parser fuzz harness.
//
// UsbClassParseConfigDescriptor delegates byte-level parsing to
// the no_std `usbclass` Rust crate (rlib + panic=abort
// staticlib wrapper, same recipe as duetos_exfat /
// duetos_ntfs). The descriptor bytes arrive from a physical
// device's GET_DESCRIPTOR response, fully attacker-controlled
// when the peripheral is hostile (USB-killer / BadUSB / vendor
// firmware compromise). A Rust-side panic in the configuration/
// interface/endpoint walker aborts the harness so libFuzzer
// records a crash.

#include "drivers/usb/usb_class_desc.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // 4 KiB cap matches the real-world max combined-descriptor
    // size a sane device emits; larger inputs are silently
    // ignored (libFuzzer mutator handles length mutation).
    if (size > 4096)
        return 0;

    duetos::drivers::usb::UsbClassConfigSummary out{};
    (void)duetos::drivers::usb::UsbClassParseConfigDescriptor(reinterpret_cast<const duetos::u8*>(data),
                                                              static_cast<duetos::u32>(size), &out);
    return 0;
}
