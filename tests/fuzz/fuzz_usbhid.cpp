// DuetOS — USB HID report-descriptor parser fuzz harness.
//
// HidParseDescriptor + HidExtractMouseLayout both delegate
// byte-level parsing to the no_std `usbhid` Rust crate. The
// report descriptor arrives from a peripheral's HID
// GET_REPORT_DESCRIPTOR response — fully attacker-controlled
// for hostile peripherals. The harness drives both entry
// points so the collection-nesting + item-prefix walker AND
// the focused mouse-field extractor each see fuzzed input.

#include "drivers/usb/hid_descriptor.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > 4096)
        return 0;

    duetos::drivers::usb::hid::HidReportSummary summary{};
    (void)duetos::drivers::usb::hid::HidParseDescriptor(reinterpret_cast<const duetos::u8*>(data),
                                                        static_cast<duetos::u32>(size), &summary);

    duetos::drivers::usb::hid::HidMouseLayout layout{};
    (void)duetos::drivers::usb::hid::HidExtractMouseLayout(reinterpret_cast<const duetos::u8*>(data),
                                                           static_cast<duetos::u32>(size), &layout);
    return 0;
}
