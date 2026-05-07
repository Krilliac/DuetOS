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
// Mouse-layout extraction.
//
// HID descriptors declare fields in three pieces:
//   1. Global Usage Page sets the namespace.
//   2. One or more Local Usage items name the upcoming field(s).
//   3. A Main Input item commits report_count fields of report_size
//      bits each. The Local Usage list is consumed in order — the
//      first usage maps to the first sub-field, etc. After the
//      Main item the Local list is cleared (the parser must reset
//      it, per HID spec).
//
// For mice we care about a small set of well-known usages:
//   Generic Desktop (0x01):   0x30 = X, 0x31 = Y, 0x38 = Wheel
//   Button (0x09):            0x01.. = buttons (treated as a range)
//   Consumer (0x0C):          0x0238 = AC Pan (horizontal wheel)
//
// On a Constant Input item (data byte bit 0) the fields are
// padding — we still advance the bit cursor but record nothing.
// ---------------------------------------------------------------

namespace
{

// Per-field local-usage list. HID lets a single Input commit up
// to report_count fields, with usages either explicit (one
// `Usage` item per field) or implicit (Usage Min/Max declares a
// range). v0 supports the first 8 explicit usages — every
// shipping mouse uses fewer than that.
constexpr u32 kLocalUsageMax = 8;

struct LocalUsageList
{
    u8 count;
    u32 page[kLocalUsageMax];
    u32 usage[kLocalUsageMax];
};

void LocalUsageReset(LocalUsageList& l)
{
    l.count = 0;
}

void LocalUsageAppend(LocalUsageList& l, u32 page, u32 usage)
{
    if (l.count >= kLocalUsageMax)
        return;
    l.page[l.count] = page;
    l.usage[l.count] = usage;
    ++l.count;
}

// Set a HidMouseField if not already set (first occurrence wins —
// shipping mice declare X/Y once per Application collection).
void RecordField(HidMouseField& f, u32 bit_offset, u8 bit_size, bool is_signed)
{
    if (f.present)
        return;
    f.present = true;
    f.bit_offset = bit_offset;
    f.bit_size = bit_size;
    f.is_signed = is_signed;
}

constexpr u8 kLocalUsageMin = 0x1;
constexpr u8 kLocalUsageMax_Tag = 0x2;
constexpr u8 kGlobalLogicalMin = 0x1;
constexpr u8 kGlobalLogicalMax = 0x2;

} // namespace

bool HidExtractMouseLayout(const u8* buf, u32 len, HidMouseLayout* out)
{
    if (out == nullptr)
        return false;
    auto* bytes = reinterpret_cast<volatile u8*>(out);
    for (u64 i = 0; i < sizeof(*out); ++i)
        bytes[i] = 0;
    if (buf == nullptr || len == 0)
        return false;

    // Confirm the descriptor's primary classifier first — the
    // layout extractor only fires for actual mice, not for
    // pointer-only digitizers or keyboards.
    HidReportSummary summary{};
    if (!HidParseDescriptor(buf, len, &summary))
        return false;
    if (summary.primary_kind != DeviceKind::Mouse)
        return false;

    GlobalState gs{};
    GlobalState stack[kGlobalStackMax];
    u32 stack_depth = 0;

    LocalUsageList locals{};
    LocalUsageReset(locals);
    u32 usage_min_page = 0;
    bool have_usage_min = false;

    // Logical-min is signed if it's negative — HID encodes it as a
    // 32-bit value of the data-size bytes. We only track the sign
    // bit so axes can be flagged as signed.
    i32 logical_min = 0;

    bool in_mouse_collection = false;
    u32 mouse_app_depth = 0; // 0 = not yet inside; >0 = inside, levels deep
    u32 coll_depth = 0;
    u32 bit_cursor = 0;
    bool saw_top_usage_page = false;

    u32 off = 0;
    while (off < len)
    {
        const u8 prefix = buf[off];
        if (prefix == 0xFE)
        {
            if (off + 3 > len)
                break;
            const u8 ds = buf[off + 1];
            if (off + 3u + ds > len)
                break;
            off += 3u + ds;
            continue;
        }
        const u8 ds = (prefix & 0x03) == 3 ? 4 : (prefix & 0x03);
        if (off + 1u + ds > len)
            break;
        const u32 data_u = ReadUData(buf + off + 1, ds);
        // Sign-extend for 1/2/4-byte signed fields.
        i32 data_s = static_cast<i32>(data_u);
        if (ds == 1 && (data_u & 0x80))
            data_s = static_cast<i32>(data_u | 0xFFFFFF00u);
        else if (ds == 2 && (data_u & 0x8000))
            data_s = static_cast<i32>(data_u | 0xFFFF0000u);

        const u8 type = ItemType(prefix);
        const u8 tag = ItemTag(prefix);

        if (type == kTypeGlobal)
        {
            switch (tag)
            {
            case kGlobalUsagePage:
                gs.usage_page = u16(data_u);
                if (!saw_top_usage_page)
                    saw_top_usage_page = true;
                break;
            case kGlobalLogicalMin:
                logical_min = data_s;
                break;
            case kGlobalLogicalMax:
                // unused — bit_size carries the width
                break;
            case kGlobalReportSize:
                gs.report_size = data_u;
                break;
            case kGlobalReportCount:
                gs.report_count = data_u;
                break;
            case kGlobalReportId:
                gs.report_id = data_u;
                if (out->report_id == 0 && data_u != 0 && data_u <= 0xFF)
                    out->report_id = static_cast<u8>(data_u);
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
            switch (tag)
            {
            case kLocalUsage:
            {
                // 32-bit form: high half = page, low half = usage.
                u32 page = gs.usage_page;
                u32 usage = data_u;
                if (ds == 4)
                {
                    page = (data_u >> 16) & 0xFFFFu;
                    usage = data_u & 0xFFFFu;
                }
                LocalUsageAppend(locals, page, usage);
                break;
            }
            case kLocalUsageMin:
                usage_min_page = gs.usage_page;
                have_usage_min = true;
                break;
            case kLocalUsageMax_Tag:
                // The pair (UsageMin, UsageMax) declares a contiguous
                // range applied to the next Input item; we don't
                // expand the range into individual usages here, but
                // we DO use the pair to recognise the Button mask
                // when the Input item commits.
                (void)have_usage_min;
                break;
            default:
                break;
            }
        }
        else if (type == kTypeMain)
        {
            switch (tag)
            {
            case kMainCollection:
            {
                ++coll_depth;
                // Application collection (data byte == 0x01) carrying
                // a Generic-Desktop Mouse usage opens the layout
                // window. We use the most recently declared local
                // usage as the collection's usage (matches the HID
                // spec's "Usage applies to the next Main item").
                const bool app = (data_u == 0x01);
                u32 last_page = gs.usage_page;
                u32 last_usage = 0;
                if (locals.count > 0)
                {
                    last_page = locals.page[locals.count - 1];
                    last_usage = locals.usage[locals.count - 1];
                }
                if (app && last_page == kUsagePageGeneric && last_usage == kUsageGenericMouse && !in_mouse_collection)
                {
                    in_mouse_collection = true;
                    mouse_app_depth = coll_depth;
                    bit_cursor = 0;
                }
                LocalUsageReset(locals);
                have_usage_min = false;
                break;
            }
            case kMainEndCollection:
                if (in_mouse_collection && coll_depth == mouse_app_depth)
                {
                    in_mouse_collection = false;
                    mouse_app_depth = 0;
                }
                if (coll_depth > 0)
                    --coll_depth;
                LocalUsageReset(locals);
                have_usage_min = false;
                break;
            case kMainInput:
            {
                const u32 bits = gs.report_size * gs.report_count;
                const bool is_constant = (data_u & 0x01) != 0;
                if (in_mouse_collection)
                {
                    if (!is_constant && gs.report_size > 0 && gs.report_size <= 32)
                    {
                        // Per-sub-field walk. The Local Usage list
                        // (or the UsageMin/UsageMax range for buttons)
                        // determines what each report_count slot is.
                        const u32 size = gs.report_size;
                        const bool is_axis_signed = (logical_min < 0);
                        if (have_usage_min && usage_min_page == kUsagePageButton)
                        {
                            // Button bit-mask field. report_count
                            // buttons of report_size bits each (always
                            // 1-bit per button). Record as ONE field
                            // covering the whole mask; consumers extract
                            // individual bits with mask + shift.
                            RecordField(out->buttons, bit_cursor, static_cast<u8>(bits > 32 ? 32 : bits),
                                        /*is_signed=*/false);
                        }
                        else
                        {
                            // Per-explicit-usage walk.
                            for (u32 f = 0; f < gs.report_count; ++f)
                            {
                                u32 fpage = gs.usage_page;
                                u32 fuse = 0;
                                if (f < locals.count)
                                {
                                    fpage = locals.page[f];
                                    fuse = locals.usage[f];
                                }
                                else if (locals.count > 0)
                                {
                                    // HID spec: when fewer Usages than
                                    // Report Count are declared, the
                                    // last Usage applies to remaining
                                    // sub-fields.
                                    fpage = locals.page[locals.count - 1];
                                    fuse = locals.usage[locals.count - 1];
                                }
                                const u32 sub_off = bit_cursor + f * size;
                                if (fpage == kUsagePageGeneric)
                                {
                                    if (fuse == 0x30)
                                        RecordField(out->x, sub_off, static_cast<u8>(size), is_axis_signed);
                                    else if (fuse == 0x31)
                                        RecordField(out->y, sub_off, static_cast<u8>(size), is_axis_signed);
                                    else if (fuse == 0x38)
                                        RecordField(out->wheel, sub_off, static_cast<u8>(size), is_axis_signed);
                                }
                                else if (fpage == kUsagePageConsumer && fuse == 0x238)
                                {
                                    RecordField(out->h_tilt, sub_off, static_cast<u8>(size), is_axis_signed);
                                }
                            }
                        }
                    }
                    bit_cursor += bits;
                    if (out->report_size_bits < bit_cursor)
                        out->report_size_bits = bit_cursor;
                }
                LocalUsageReset(locals);
                have_usage_min = false;
                break;
            }
            case kMainOutput:
            case kMainFeature:
                LocalUsageReset(locals);
                have_usage_min = false;
                break;
            default:
                break;
            }
        }
        off += 1u + ds;
    }

    out->valid = out->x.present && out->y.present;
    return out->valid;
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
