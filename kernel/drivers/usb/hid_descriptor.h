#pragma once

#include "util/types.h"

/*
 * DuetOS — USB HID report-descriptor parser, v0.
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

namespace duetos::drivers::usb::hid
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

// =====================================================================
// Mouse-layout extraction (high-DPI / 16-bit XY support).
//
// `HidParseDescriptor` returns aggregates only — sum-of-bits and a
// `primary_kind`. A real driver dealing with anything beyond the
// boot protocol needs to know **where** each named field (X / Y
// / wheel / button mask / report ID) lives in the report stream.
// `HidExtractMouseLayout` walks the descriptor with that lens and
// fills a `HidMouseLayout` so the input dispatcher can pull a
// 16-bit signed X out of an 8-byte report at the right bit offset.
//
// The layout is bit-addressed (not byte-addressed) because HID
// allows non-byte-aligned fields. Callers that mask + shift bits
// out of the report byte stream don't have to assume any
// particular packing.
// =====================================================================

/// Per-named-field record. `present == false` means this descriptor
/// did not declare the field in its primary mouse collection;
/// `bit_offset` / `bit_size` are then meaningless. `bit_size` is
/// always recorded in [1..32]; well-known mouse fields are 8, 12,
/// or 16 bits in shipping hardware. `is_signed` is true for
/// relative axes (X / Y / wheel / horizontal tilt — Logical
/// Minimum < 0); false for absolute fields (button bits, report
/// IDs, digitizer pressure).
struct HidMouseField
{
    bool present;
    bool is_signed;
    u8 bit_size;
    u32 bit_offset; ///< from the start of the report bit stream
};

/// Resolved mouse-report layout. `report_size_bits` is the total
/// width of the report (the sum of every Input item under the
/// primary mouse Application collection); a 4-byte report has
/// `report_size_bits == 32`. `report_id` is non-zero when the
/// device prefixes its reports with a Report ID byte; consumers
/// must skip the first byte of the report and add 8 to every
/// `bit_offset` when extracting.
struct HidMouseLayout
{
    bool valid;            ///< true iff the descriptor parsed AND a Mouse usage was found
    u8 report_id;          ///< 0 = no report ID prefix
    u32 report_size_bits;  ///< total payload bits (excluding the optional report-ID byte)
    HidMouseField buttons; ///< Button-page Input field (bit 0 = button 1, etc.)
    HidMouseField x;       ///< Generic Desktop Usage 0x30 (X)
    HidMouseField y;       ///< Generic Desktop Usage 0x31 (Y)
    HidMouseField wheel;   ///< Generic Desktop Usage 0x38 (Wheel)
    HidMouseField h_tilt;  ///< Consumer page Usage 0x238 (AC Pan / horizontal wheel)
};

/// Extract a `HidMouseLayout` from a report descriptor. Returns
/// `out->valid` on completion. Walks the descriptor twice
/// internally — once via `HidParseDescriptor` to confirm primary
/// kind == Mouse, then a focused walk to record per-field bit
/// offsets. Layouts with multiple top-level Mouse Application
/// collections only have the first one captured (matches what
/// the v0 input dispatcher consumes).
bool HidExtractMouseLayout(const u8* buf, u32 len, HidMouseLayout* out);

/// Boot-time sanity test — feeds the canonical USB boot-keyboard
/// and boot-mouse descriptors through the parser and KASSERTs
/// the expected classification + bit counts. Prints PASS/FAIL on
/// COM1 and panics on mismatch.
void HidSelfTest();

} // namespace duetos::drivers::usb::hid
