#include "drivers/usb/hid_descriptor.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"

namespace duetos::drivers::usb::hid
{

namespace
{

// Short-item prefix decode. See USB HID 1.11 §6.2.2.4.
//   bSize (bits 0..1):  0, 1, 2, 4   (but 3 encodes 4 bytes — decode via table)
//   bType (bits 2..3):  0 Main, 1 Global, 2 Local, 3 Reserved
//   bTag  (bits 4..7):  item-specific
inline u8 ItemSize(u8 prefix)
{
    const u8 raw = prefix & 0x03;
    return (raw == 3) ? 4 : raw;
}
inline u8 ItemType(u8 prefix)
{
    return (prefix >> 2) & 0x03;
}
inline u8 ItemTag(u8 prefix)
{
    return (prefix >> 4) & 0x0F;
}

// Item-type constants.
constexpr u8 kTypeMain = 0;
constexpr u8 kTypeGlobal = 1;
constexpr u8 kTypeLocal = 2;

// Main tags.
constexpr u8 kMainInput = 0x8;
constexpr u8 kMainOutput = 0x9;
constexpr u8 kMainFeature = 0xB;
constexpr u8 kMainCollection = 0xA;
constexpr u8 kMainEndCollection = 0xC;

// Global tags.
constexpr u8 kGlobalUsagePage = 0x0;
constexpr u8 kGlobalReportSize = 0x7;
constexpr u8 kGlobalReportId = 0x8;
constexpr u8 kGlobalReportCount = 0x9;
constexpr u8 kGlobalPush = 0xA;
constexpr u8 kGlobalPop = 0xB;

// Local tags.
constexpr u8 kLocalUsage = 0x0;

// Read a little-endian unsigned integer of `size` bytes (0, 1, 2,
// or 4). HID data values up to 4 bytes are always stored LE.
u32 ReadUData(const u8* p, u8 size)
{
    u32 r = 0;
    for (u8 i = 0; i < size; ++i)
        r |= u32(p[i]) << (i * 8);
    return r;
}

// Parser state held on the built-in "global" item stack. A real
// HID parser keeps a stack per the Push/Pop items; we keep the
// current frame + a small in-line save area.
struct GlobalState
{
    u16 usage_page;
    u32 report_size;  // bits per field
    u32 report_count; // fields per item
    u32 report_id;
};

constexpr u32 kGlobalStackMax = 4;

DeviceKind ClassifyTopUsage(u16 page, u16 usage)
{
    if (page == kUsagePageGeneric)
    {
        switch (usage)
        {
        case kUsageGenericPointer:
            return DeviceKind::Pointer;
        case kUsageGenericMouse:
            return DeviceKind::Mouse;
        case kUsageGenericKeyboard:
            return DeviceKind::Keyboard;
        case kUsageGenericKeypad:
            return DeviceKind::Keypad;
        case kUsageGenericJoystick:
            return DeviceKind::Joystick;
        case kUsageGenericGamepad:
            return DeviceKind::Gamepad;
        default:
            return DeviceKind::Other;
        }
    }
    if (page == kUsagePageConsumer)
        return DeviceKind::Consumer;
    if (page == kUsagePageDigitizer)
        return DeviceKind::Digitizer;
    if (page == kUsagePageKeyboard)
        return DeviceKind::Keyboard;
    if (page == kUsagePageButton)
        return DeviceKind::Other;
    return DeviceKind::Unknown;
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
    // Zero the output.
    auto* bytes = reinterpret_cast<volatile u8*>(out);
    for (u64 i = 0; i < sizeof(*out); ++i)
        bytes[i] = 0;

    if (buf == nullptr)
        return false;

    GlobalState gs{};
    GlobalState stack[kGlobalStackMax];
    u32 stack_depth = 0;
    u32 coll_depth = 0;
    bool saw_top_usage_page = false;
    bool saw_top_usage = false;
    u32 report_id_seen_bits = 0; // small bitmap; report IDs 1..31

    u32 off = 0;
    while (off < len)
    {
        const u8 prefix = buf[off];
        // 0xFE = long item: 1-byte size + 1-byte tag follow. Shipping
        // hardware doesn't use this; we skip it.
        if (prefix == 0xFE)
        {
            if (off + 3 > len)
                break;
            const u8 data_size = buf[off + 1];
            const u32 skip = u32(3) + data_size;
            if (off + skip > len)
                break;
            off += skip;
            continue;
        }
        const u8 data_size = ItemSize(prefix);
        if (off + 1 + data_size > len)
        {
            out->bytes_consumed = off;
            return false;
        }
        const u32 data = ReadUData(buf + off + 1, data_size);
        const u8 type = ItemType(prefix);
        const u8 tag = ItemTag(prefix);

        if (type == kTypeGlobal)
        {
            switch (tag)
            {
            case kGlobalUsagePage:
                gs.usage_page = u16(data);
                if (!saw_top_usage_page)
                {
                    out->top_usage_page = gs.usage_page;
                    saw_top_usage_page = true;
                }
                break;
            case kGlobalReportSize:
                gs.report_size = data;
                break;
            case kGlobalReportCount:
                gs.report_count = data;
                break;
            case kGlobalReportId:
                gs.report_id = data;
                if (data >= 1 && data <= 31)
                {
                    const u32 bit = 1u << (data - 1);
                    if ((report_id_seen_bits & bit) == 0)
                    {
                        report_id_seen_bits |= bit;
                        ++out->report_id_count;
                    }
                }
                break;
            case kGlobalPush:
                if (stack_depth < kGlobalStackMax)
                    stack[stack_depth++] = gs;
                break;
            case kGlobalPop:
                if (stack_depth > 0)
                    gs = stack[--stack_depth];
                break;
            default:
                break;
            }
        }
        else if (type == kTypeLocal)
        {
            if (tag == kLocalUsage)
            {
                if (!saw_top_usage)
                {
                    out->top_usage = u16(data);
                    saw_top_usage = true;
                }
            }
        }
        else if (type == kTypeMain)
        {
            switch (tag)
            {
            case kMainCollection:
                ++coll_depth;
                if (coll_depth > out->collection_depth_max)
                    out->collection_depth_max = coll_depth;
                break;
            case kMainEndCollection:
                if (coll_depth > 0)
                    --coll_depth;
                break;
            case kMainInput:
            case kMainOutput:
            case kMainFeature:
            {
                const u32 bits = gs.report_size * gs.report_count;
                // HID main-item data byte bit 0 = Constant. A Constant
                // Input is padding / filler, not a real report field —
                // it does NOT represent a usage even if the current
                // usage page is e.g. Button. Count only data (non-Cnst)
                // items as button fields.
                const bool is_constant = (data & 0x01) != 0;
                if (tag == kMainInput)
                {
                    out->input_bits_total += bits;
                    if (!is_constant && gs.usage_page == kUsagePageButton)
                        ++out->button_field_count;
                }
                else if (tag == kMainOutput)
                {
                    out->output_bits_total += bits;
                }
                else
                {
                    out->feature_bits_total += bits;
                }
                break;
            }
            default:
                break;
            }
        }
        off += 1 + data_size;
    }

    out->bytes_consumed = off;
    out->primary_kind = ClassifyTopUsage(out->top_usage_page, out->top_usage);
    // Parse is "ok" if we consumed the whole buffer AND ended with
    // a balanced collection nest.
    out->parse_ok = (off == len) && (coll_depth == 0);
    return out->parse_ok;
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
    arch::SerialWrite("[hid-selftest] PASS (boot-keyboard + boot-mouse descriptors parsed)\n");
}

} // namespace duetos::drivers::usb::hid
