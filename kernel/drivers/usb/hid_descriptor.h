#pragma once

#include "../../core/types.h"

/*
 * CustomOS — USB HID report-descriptor parser, v0.
 *
 * A HID device describes its report format with a "report
 * descriptor" — a byte string of tagged items that a driver must
 * interpret to understand the meaning of every bit in a report
 * packet. This module is the decoder: given a descriptor buffer,
 * walk it and produce a `HidReportSummary` naming the primary
 * usage (keyboard / mouse / gamepad / ...), the number of bits
 * per report, and the presence of button / axis fields.
 *
 * No host-controller dependency. The parser is a pure byte-in,
 * summary-out function — so it's reachable as soon as the USB
 * stack can deliver a descriptor, regardless of which xHCI /
 * EHCI / virtio-usb slice lands first.
 *
 * Scope (v0):
 *   - Short items only (the HID spec's long-item form is defined
 *     but never used in shipping hardware).
 *   - Top-level usage / usage page detection.
 *   - Accumulated Report Size × Report Count per Input/Output/
 *     Feature item → total report bits.
 *   - Boot-keyboard + boot-mouse descriptors recognised in a
 *     self-test.
 *
 * Not in scope:
 *   - Collection nesting (we track depth but don't emit per-
 *     collection summaries).
 *   - Per-field usage tables (a real driver would want to know
 *     "byte 2 bit 3 is KEY_CAPSLOCK" — we just count bits).
 *   - Value mapping (logical/physical min/max scaling).
 *
 * References:
 *   - USB HID 1.11 §6.2.2 "Report Descriptor"
 *   - HUT 1.4 "HID Usage Tables"
 */

namespace customos::drivers::usb::hid
{

// Common HID usage pages (subset of HUT §3). These are the
// pages a typical HID device uses at the top of its report
// descriptor.
inline constexpr u16 kUsagePageGeneric = 0x01; // Generic Desktop
inline constexpr u16 kUsagePageKeyboard = 0x07;
inline constexpr u16 kUsagePageLed = 0x08;
inline constexpr u16 kUsagePageButton = 0x09;
inline constexpr u16 kUsagePageConsumer = 0x0C;
inline constexpr u16 kUsagePageDigitizer = 0x0D;

// Common top-level Generic Desktop usages.
inline constexpr u16 kUsageGenericPointer = 0x01;
inline constexpr u16 kUsageGenericMouse = 0x02;
inline constexpr u16 kUsageGenericKeyboard = 0x06;
inline constexpr u16 kUsageGenericKeypad = 0x07;
inline constexpr u16 kUsageGenericJoystick = 0x04;
inline constexpr u16 kUsageGenericGamepad = 0x05;

// Human-readable classifier of what a top-level collection is.
enum class DeviceKind : u8
{
    Unknown = 0,
    Keyboard,
    Mouse,
    Pointer,
    Keypad,
    Joystick,
    Gamepad,
    Consumer,
    Digitizer,
    Other
};

const char* DeviceKindName(DeviceKind k);

struct HidReportSummary
{
    bool parse_ok;            // true if we walked the whole descriptor cleanly
    u32 bytes_consumed;       // bytes actually parsed before ok/error
    DeviceKind primary_kind;  // top-level usage classifier
    u16 top_usage_page;       // first usage page seen
    u16 top_usage;            // first usage seen after top_usage_page
    u32 collection_depth_max; // deepest Collection/EndCollection nesting
    u32 input_bits_total;     // sum of (report_size * report_count) over Input items
    u32 output_bits_total;    // ...over Output items
    u32 feature_bits_total;   // ...over Feature items
    u32 button_field_count;   // Input items whose usage page was Button (0x09)
    u32 report_id_count;      // # distinct Report ID values declared
};

/// Parse `buf[0..len)` as a HID report descriptor and populate
/// `*out`. The parser walks as far as it can; on a malformed
/// item it returns with `parse_ok=false` and `bytes_consumed`
/// pointing at the failure offset so callers can log it.
/// Returns `out->parse_ok`.
bool HidParseDescriptor(const u8* buf, u32 len, HidReportSummary* out);

/// Boot-time sanity test — feeds the canonical USB boot-keyboard
/// and boot-mouse descriptors through the parser and KASSERTs
/// the expected classification + bit counts. Prints PASS/FAIL on
/// COM1 and panics on mismatch.
void HidSelfTest();

} // namespace customos::drivers::usb::hid
