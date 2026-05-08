#include "drivers/usb/hid_descriptor.h"

#include "usbhid.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"

namespace duetos::drivers::usb::hid
{

namespace
{

static_assert(sizeof(DuetosUsbHidReportSummary) == sizeof(HidReportSummary),
              "Rust HID summary ABI drifted from the C++ wrapper");
static_assert(alignof(DuetosUsbHidReportSummary) == alignof(HidReportSummary),
              "Rust HID summary ABI alignment drifted from the C++ wrapper");
static_assert(__builtin_offsetof(DuetosUsbHidReportSummary, report_id_count) ==
                  __builtin_offsetof(HidReportSummary, report_id_count),
              "Rust HID summary ABI field drifted from the C++ wrapper");
static_assert(sizeof(DuetosUsbHidMouseField) == sizeof(HidMouseField),
              "Rust HID mouse field ABI drifted from the C++ wrapper");
static_assert(alignof(DuetosUsbHidMouseField) == alignof(HidMouseField),
              "Rust HID mouse field ABI alignment drifted from the C++ wrapper");
static_assert(__builtin_offsetof(DuetosUsbHidMouseField, bit_offset) == __builtin_offsetof(HidMouseField, bit_offset),
              "Rust HID mouse field ABI field drifted from the C++ wrapper");
static_assert(sizeof(DuetosUsbHidMouseLayout) == sizeof(HidMouseLayout),
              "Rust HID mouse layout ABI drifted from the C++ wrapper");
static_assert(alignof(DuetosUsbHidMouseLayout) == alignof(HidMouseLayout),
              "Rust HID mouse layout ABI alignment drifted from the C++ wrapper");
static_assert(__builtin_offsetof(DuetosUsbHidMouseLayout, h_tilt) == __builtin_offsetof(HidMouseLayout, h_tilt),
              "Rust HID mouse layout ABI field drifted from the C++ wrapper");

DeviceKind DeviceKindFromAbi(u8 kind)
{
    switch (kind)
    {
    case DUETOS_USBHID_KIND_KEYBOARD:
        return DeviceKind::Keyboard;
    case DUETOS_USBHID_KIND_MOUSE:
        return DeviceKind::Mouse;
    case DUETOS_USBHID_KIND_POINTER:
        return DeviceKind::Pointer;
    case DUETOS_USBHID_KIND_KEYPAD:
        return DeviceKind::Keypad;
    case DUETOS_USBHID_KIND_JOYSTICK:
        return DeviceKind::Joystick;
    case DUETOS_USBHID_KIND_GAMEPAD:
        return DeviceKind::Gamepad;
    case DUETOS_USBHID_KIND_CONSUMER:
        return DeviceKind::Consumer;
    case DUETOS_USBHID_KIND_DIGITIZER:
        return DeviceKind::Digitizer;
    case DUETOS_USBHID_KIND_OTHER:
        return DeviceKind::Other;
    default:
        return DeviceKind::Unknown;
    }
}

void ClearSummary(HidReportSummary& out)
{
    auto* bytes = reinterpret_cast<volatile u8*>(&out);
    for (u64 i = 0; i < sizeof(out); ++i)
        bytes[i] = 0;
}

void ClearLayout(HidMouseLayout& out)
{
    auto* bytes = reinterpret_cast<volatile u8*>(&out);
    for (u64 i = 0; i < sizeof(out); ++i)
        bytes[i] = 0;
}

void CopyField(const DuetosUsbHidMouseField& src, HidMouseField& dst)
{
    dst.present = src.present;
    dst.is_signed = src.is_signed;
    dst.bit_size = src.bit_size;
    dst.bit_offset = src.bit_offset;
}

} // namespace

const char* DeviceKindName(DeviceKind k)
{
    switch (k)
    {
    case DeviceKind::Keyboard:
        return "keyboard";
    case DeviceKind::Mouse:
        return "mouse";
    case DeviceKind::Pointer:
        return "pointer";
    case DeviceKind::Keypad:
        return "keypad";
    case DeviceKind::Joystick:
        return "joystick";
    case DeviceKind::Gamepad:
        return "gamepad";
    case DeviceKind::Consumer:
        return "consumer";
    case DeviceKind::Digitizer:
        return "digitizer";
    case DeviceKind::Other:
        return "other-hid";
    default:
        return "unknown-hid";
    }
}

bool HidParseDescriptor(const u8* buf, u32 len, HidReportSummary* out)
{
    if (out == nullptr)
        return false;

    ClearSummary(*out);

    DuetosUsbHidReportSummary rustSummary{};
    const bool ok = duetos_usbhid_parse_descriptor(buf, len, &rustSummary);
    out->parse_ok = rustSummary.parse_ok;
    out->bytes_consumed = rustSummary.bytes_consumed;
    out->primary_kind = DeviceKindFromAbi(rustSummary.primary_kind);
    out->top_usage_page = rustSummary.top_usage_page;
    out->top_usage = rustSummary.top_usage;
    out->collection_depth_max = rustSummary.collection_depth_max;
    out->input_bits_total = rustSummary.input_bits_total;
    out->output_bits_total = rustSummary.output_bits_total;
    out->feature_bits_total = rustSummary.feature_bits_total;
    out->button_field_count = rustSummary.button_field_count;
    out->report_id_count = rustSummary.report_id_count;
    return ok;
}

bool HidExtractMouseLayout(const u8* buf, u32 len, HidMouseLayout* out)
{
    if (out == nullptr)
        return false;

    ClearLayout(*out);

    DuetosUsbHidMouseLayout rustLayout{};
    const bool ok = duetos_usbhid_extract_mouse_layout(buf, len, &rustLayout);
    out->valid = rustLayout.valid;
    out->report_id = rustLayout.report_id;
    out->report_size_bits = rustLayout.report_size_bits;
    CopyField(rustLayout.buttons, out->buttons);
    CopyField(rustLayout.x, out->x);
    CopyField(rustLayout.y, out->y);
    CopyField(rustLayout.wheel, out->wheel);
    CopyField(rustLayout.h_tilt, out->h_tilt);
    return ok;
}

// ---------------------------------------------------------------
// Self-test.
// ---------------------------------------------------------------

namespace
{

// Canonical USB HID boot-keyboard report descriptor (USB HID 1.11
// Appendix B.1). 63 bytes. Every conforming keyboard exposes at
// least this — so it's the tightest possible round-trip test.
constexpr u8 kBootKeyboardDescriptor[] = {
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Key Codes)
    0x19, 0xE0, //   Usage Minimum (224)
    0x29, 0xE7, //   Usage Maximum (231)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Var, Abs)        <- 8 bits
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x01, //   Input (Cnst)                  <- 8 bits (reserved)
    0x95, 0x05, //   Report Count (5)
    0x75, 0x01, //   Report Size (1)
    0x05, 0x08, //   Usage Page (LEDs)
    0x19, 0x01, //   Usage Minimum (1)
    0x29, 0x05, //   Usage Maximum (5)
    0x91, 0x02, //   Output (Data, Var, Abs)       <- 5 bits
    0x95, 0x01, //   Report Count (1)
    0x75, 0x03, //   Report Size (3)
    0x91, 0x01, //   Output (Cnst)                 <- 3 bits
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x65, //   Logical Maximum (101)
    0x05, 0x07, //   Usage Page (Key Codes)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0x65, //   Usage Maximum (101)
    0x81, 0x00, //   Input (Data, Array)           <- 48 bits
    0xC0,       // End Collection
};

// Canonical USB HID boot-mouse report descriptor (USB HID 1.11
// Appendix E, adapted from §B.2). 50 bytes. Three buttons + X/Y
// relative axes.
constexpr u8 kBootMouseDescriptor[] = {
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x02, // Usage (Mouse)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x01, //   Usage (Pointer)
    0xA1, 0x00, //   Collection (Physical)
    0x05, 0x09, //     Usage Page (Button)
    0x19, 0x01, //     Usage Minimum (1)
    0x29, 0x03, //     Usage Maximum (3)
    0x15, 0x00, //     Logical Minimum (0)
    0x25, 0x01, //     Logical Maximum (1)
    0x95, 0x03, //     Report Count (3)
    0x75, 0x01, //     Report Size (1)
    0x81, 0x02, //     Input (Data, Var, Abs)      <- 3 bits buttons
    0x95, 0x01, //     Report Count (1)
    0x75, 0x05, //     Report Size (5)
    0x81, 0x01, //     Input (Cnst)                <- 5 bits padding
    0x05, 0x01, //     Usage Page (Generic Desktop)
    0x09, 0x30, //     Usage (X)
    0x09, 0x31, //     Usage (Y)
    0x15, 0x81, //     Logical Minimum (-127)
    0x25, 0x7F, //     Logical Maximum (127)
    0x75, 0x08, //     Report Size (8)
    0x95, 0x02, //     Report Count (2)
    0x81, 0x06, //     Input (Data, Var, Rel)      <- 16 bits X,Y
    0xC0,       //   End Collection
    0xC0,       // End Collection
};

void ExpectEq(u32 actual, u32 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[hid-selftest] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/usb/hid", "HID parser self-test mismatch", actual);
}

} // namespace

// Synthetic mouse descriptor with high-numbered report IDs. HID Report IDs are
// 1..255; this catches regressions where the parser only tracks a 32-bit bitset.
constexpr u8 kHighReportIdMouseDescriptor[] = {
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x02, // Usage (Mouse)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x01, //   Report ID 1
    0x09, 0x30, //   Usage (X)
    0x15, 0x81, //   Logical Minimum (-127)
    0x25, 0x7F, //   Logical Maximum (127)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x01, //   Report Count (1)
    0x81, 0x06, //   Input (Data, Var, Rel)
    0x85, 0xC8, //   Report ID 200
    0x09, 0x31, //   Usage (Y)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x01, //   Report Count (1)
    0x81, 0x06, //   Input (Data, Var, Rel)
    0x85, 0xC8, //   Duplicate Report ID 200 must not bump the count
    0x09, 0x38, //   Usage (Wheel)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x01, //   Report Count (1)
    0x81, 0x06, //   Input (Data, Var, Rel)
    0xC0,       // End Collection
};

// Synthetic high-DPI mouse report descriptor: 5 buttons + 16-bit
// signed X / Y + 8-bit signed wheel + 8-bit signed AC Pan
// (horizontal tilt). Matches the layout a typical Logitech /
// Razer gaming mouse declares once it reports outside the boot-
// protocol range. Total report = 5 button bits + 3 padding + 16
// + 16 + 8 + 8 = 56 bits = 7 bytes.
constexpr u8 kHighDpiMouseDescriptor[] = {
    0x05, 0x01,       // Usage Page (Generic Desktop)
    0x09, 0x02,       // Usage (Mouse)
    0xA1, 0x01,       // Collection (Application)
    0x09, 0x01,       //   Usage (Pointer)
    0xA1, 0x00,       //   Collection (Physical)
    0x05, 0x09,       //     Usage Page (Button)
    0x19, 0x01,       //     Usage Minimum (1)
    0x29, 0x05,       //     Usage Maximum (5)
    0x15, 0x00,       //     Logical Minimum (0)
    0x25, 0x01,       //     Logical Maximum (1)
    0x95, 0x05,       //     Report Count (5)
    0x75, 0x01,       //     Report Size (1)
    0x81, 0x02,       //     Input (Data, Var, Abs)        <- 5 button bits
    0x95, 0x01,       //     Report Count (1)
    0x75, 0x03,       //     Report Size (3)
    0x81, 0x01,       //     Input (Cnst)                  <- 3 pad bits
    0x05, 0x01,       //     Usage Page (Generic Desktop)
    0x09, 0x30,       //     Usage (X)
    0x09, 0x31,       //     Usage (Y)
    0x16, 0x01, 0x80, //     Logical Minimum (-32767)
    0x26, 0xFF, 0x7F, //     Logical Maximum (32767)
    0x75, 0x10,       //     Report Size (16)
    0x95, 0x02,       //     Report Count (2)
    0x81, 0x06,       //     Input (Data, Var, Rel)        <- 16+16 X/Y bits
    0x09, 0x38,       //     Usage (Wheel)
    0x15, 0x81,       //     Logical Minimum (-127)
    0x25, 0x7F,       //     Logical Maximum (127)
    0x75, 0x08,       //     Report Size (8)
    0x95, 0x01,       //     Report Count (1)
    0x81, 0x06,       //     Input (Data, Var, Rel)        <- 8 wheel bits
    0x05, 0x0C,       //     Usage Page (Consumer)
    0x0A, 0x38, 0x02, //     Usage (AC Pan)
    0x81, 0x06,       //     Input (Data, Var, Rel)        <- 8 horizontal tilt bits
    0xC0,             //   End Collection
    0xC0,             // End Collection
};

void HidSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/usb/hid", "HidSelfTest");

    {
        HidReportSummary s{};
        const bool ok = HidParseDescriptor(kBootKeyboardDescriptor, sizeof(kBootKeyboardDescriptor), &s);
        ExpectEq(u32(ok), 1, "keyboard parse_ok");
        ExpectEq(u32(s.primary_kind), u32(DeviceKind::Keyboard), "keyboard kind");
        ExpectEq(s.top_usage_page, kUsagePageGeneric, "keyboard top_usage_page");
        ExpectEq(s.top_usage, kUsageGenericKeyboard, "keyboard top_usage");
        // 8 modifier bits + 8 reserved + 48 keycode bits = 64 input bits.
        ExpectEq(s.input_bits_total, 64, "keyboard input_bits_total");
        // 5 LED bits + 3 padding bits = 8 output bits.
        ExpectEq(s.output_bits_total, 8, "keyboard output_bits_total");
        ExpectEq(s.collection_depth_max, 1, "keyboard collection_depth_max");
    }
    {
        HidReportSummary s{};
        const bool ok = HidParseDescriptor(kBootMouseDescriptor, sizeof(kBootMouseDescriptor), &s);
        ExpectEq(u32(ok), 1, "mouse parse_ok");
        ExpectEq(u32(s.primary_kind), u32(DeviceKind::Mouse), "mouse kind");
        ExpectEq(s.top_usage_page, kUsagePageGeneric, "mouse top_usage_page");
        ExpectEq(s.top_usage, kUsageGenericMouse, "mouse top_usage");
        // 3 buttons + 5 padding + 16 X/Y = 24 input bits.
        ExpectEq(s.input_bits_total, 24, "mouse input_bits_total");
        ExpectEq(s.output_bits_total, 0, "mouse output_bits_total");
        ExpectEq(s.collection_depth_max, 2, "mouse collection_depth_max nesting");
        ExpectEq(s.button_field_count, 1, "mouse button_field_count");
    }

    {
        HidReportSummary s{};
        const bool ok = HidParseDescriptor(kHighReportIdMouseDescriptor, sizeof(kHighReportIdMouseDescriptor), &s);
        ExpectEq(u32(ok), 1, "high-report-id parse_ok");
        ExpectEq(s.report_id_count, 2, "high-report-id distinct count");
    }

    // Layout extraction — boot mouse: 8-bit signed X/Y at offsets 8 and 16.
    {
        HidMouseLayout layout{};
        const bool ok = HidExtractMouseLayout(kBootMouseDescriptor, sizeof(kBootMouseDescriptor), &layout);
        ExpectEq(u32(ok), 1, "boot-mouse layout valid");
        ExpectEq(u32(layout.report_id), 0, "boot-mouse no report id");
        ExpectEq(layout.report_size_bits, 24, "boot-mouse report_size_bits");
        ExpectEq(u32(layout.buttons.present), 1, "boot-mouse buttons present");
        ExpectEq(u32(layout.buttons.bit_offset), 0, "boot-mouse buttons offset");
        ExpectEq(u32(layout.buttons.bit_size), 3, "boot-mouse buttons size");
        ExpectEq(u32(layout.buttons.is_signed), 0, "boot-mouse buttons unsigned");
        ExpectEq(u32(layout.x.present), 1, "boot-mouse X present");
        ExpectEq(u32(layout.x.bit_offset), 8, "boot-mouse X offset");
        ExpectEq(u32(layout.x.bit_size), 8, "boot-mouse X size");
        ExpectEq(u32(layout.x.is_signed), 1, "boot-mouse X signed");
        ExpectEq(u32(layout.y.present), 1, "boot-mouse Y present");
        ExpectEq(u32(layout.y.bit_offset), 16, "boot-mouse Y offset");
        ExpectEq(u32(layout.y.bit_size), 8, "boot-mouse Y size");
        ExpectEq(u32(layout.wheel.present), 0, "boot-mouse no wheel");
        ExpectEq(u32(layout.h_tilt.present), 0, "boot-mouse no tilt");
    }

    // Layout extraction — high-DPI mouse: 5 buttons + 16-bit X/Y +
    // 8-bit wheel + 8-bit horizontal tilt. Verifies bit offsets
    // pick up the wider X/Y window correctly.
    {
        HidMouseLayout layout{};
        const bool ok = HidExtractMouseLayout(kHighDpiMouseDescriptor, sizeof(kHighDpiMouseDescriptor), &layout);
        ExpectEq(u32(ok), 1, "highdpi layout valid");
        // 5 buttons + 3 pad + 16 + 16 + 8 + 8 = 56 bits.
        ExpectEq(layout.report_size_bits, 56, "highdpi report_size_bits");
        ExpectEq(u32(layout.buttons.present), 1, "highdpi buttons present");
        ExpectEq(u32(layout.buttons.bit_offset), 0, "highdpi buttons offset");
        ExpectEq(u32(layout.buttons.bit_size), 5, "highdpi buttons size");
        // X starts after 5 button bits + 3 padding = 8.
        ExpectEq(u32(layout.x.present), 1, "highdpi X present");
        ExpectEq(u32(layout.x.bit_offset), 8, "highdpi X offset");
        ExpectEq(u32(layout.x.bit_size), 16, "highdpi X size");
        ExpectEq(u32(layout.x.is_signed), 1, "highdpi X signed");
        // Y starts at 8 + 16 = 24.
        ExpectEq(u32(layout.y.present), 1, "highdpi Y present");
        ExpectEq(u32(layout.y.bit_offset), 24, "highdpi Y offset");
        ExpectEq(u32(layout.y.bit_size), 16, "highdpi Y size");
        // Wheel starts at 8 + 16 + 16 = 40.
        ExpectEq(u32(layout.wheel.present), 1, "highdpi wheel present");
        ExpectEq(u32(layout.wheel.bit_offset), 40, "highdpi wheel offset");
        ExpectEq(u32(layout.wheel.bit_size), 8, "highdpi wheel size");
        // AC Pan (horizontal tilt) starts at 40 + 8 = 48.
        ExpectEq(u32(layout.h_tilt.present), 1, "highdpi tilt present");
        ExpectEq(u32(layout.h_tilt.bit_offset), 48, "highdpi tilt offset");
        ExpectEq(u32(layout.h_tilt.bit_size), 8, "highdpi tilt size");
    }

    // Negative case — keyboard descriptor is not a mouse, layout
    // extraction must refuse.
    {
        HidMouseLayout layout{};
        const bool ok = HidExtractMouseLayout(kBootKeyboardDescriptor, sizeof(kBootKeyboardDescriptor), &layout);
        ExpectEq(u32(ok), 0, "keyboard layout refused");
        ExpectEq(u32(layout.valid), 0, "keyboard layout not valid");
    }

    arch::SerialWrite("[hid-selftest] PASS (boot-keyboard + boot-mouse + highdpi-mouse layout extracted)\n");
}

} // namespace duetos::drivers::usb::hid
