/*
 * DuetOS -- HID gamepad state tracking + HID report layout extraction.
 *
 * See hid_gamepad.h for the design overview. This TU is the single
 * owner of the 4-slot gamepad state table and the per-slot spinlocks
 * that serialise inject vs. read.
 */

#include "drivers/input/hid_gamepad.h"
#include "drivers/usb/hid_descriptor.h"
#include "sync/spinlock.h"

#ifdef DUETOS_HOSTED_TEST
#include "host_test_helper.h"
#define GP_ASSERT(cond, msg)                                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            std::fprintf(stderr, "%s:%d: FAIL: %s\n", __FILE__, __LINE__, (msg));                                      \
            ++::duetos_host_test::failure_count();                                                                     \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)
#else
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#define GP_ASSERT(cond, msg) KASSERT(cond, "drivers/input/gamepad", msg)
#endif

namespace duetos::drivers::input
{

// ---------------------------------------------------------------
// Slot table
// ---------------------------------------------------------------

struct GamepadSlot
{
    sync::SpinLock lock;
    bool connected;
    u32 packet_number;
    GamepadState state;
    HidGamepadLayout layout;
};

static GamepadSlot g_slots[kGamepadMaxSlots];

#ifdef DUETOS_HOSTED_TEST
// Hosted builds cannot link the kernel spinlock implementation (it
// saves/restores RFLAGS.IF via arch code). The hosted test drives
// the slot table single-threaded, so the guard reduces to a plain
// ticket bump that keeps the protocol invariant (next_ticket ==
// now_serving when free) intact. Same seam idea as the RingGuard in
// ipc/message_ring.cpp, minus the atomics a threaded test would need.
class SlotGuard
{
  public:
    explicit SlotGuard(sync::SpinLock& lock) : m_lock(lock)
    {
        m_ticket = m_lock.next_ticket;
        m_lock.next_ticket = m_ticket + 1U;
        while (m_lock.now_serving != m_ticket)
        {
        }
    }
    ~SlotGuard() { m_lock.now_serving = m_ticket + 1U; }

    SlotGuard(const SlotGuard&) = delete;
    SlotGuard& operator=(const SlotGuard&) = delete;

  private:
    sync::SpinLock& m_lock;
    u32 m_ticket = 0;
};
#else
using SlotGuard = sync::SpinLockGuard;
#endif

// ---------------------------------------------------------------
// Bit extraction helpers (same algorithm as xhci_input.cpp)
// ---------------------------------------------------------------

namespace
{

u32 ExtractBitsLE(const u8* report, u32 len, u32 bit_off, u32 bits)
{
    if (report == nullptr || bits == 0 || bits > 32)
        return 0;
    u32 acc = 0;
    for (u32 i = 0; i < bits; ++i)
    {
        const u32 src_bit = bit_off + i;
        const u32 byte_off = src_bit >> 3;
        const u32 in_byte = src_bit & 7;
        if (byte_off >= len)
            break;
        const u32 b = (report[byte_off] >> in_byte) & 1u;
        acc |= b << i;
    }
    return acc;
}

i32 SignExtend(u32 value, u32 bits)
{
    if (bits == 0 || bits >= 32)
        return static_cast<i32>(value);
    const u32 mask = (1u << bits) - 1u;
    value &= mask;
    const u32 sign_bit = 1u << (bits - 1);
    if (value & sign_bit)
        return static_cast<i32>(value | ~mask);
    return static_cast<i32>(value);
}

i32 ExtractFieldValue(const u8* report, u32 len, const GamepadReportField& f)
{
    if (!f.present || f.bit_size == 0)
        return 0;
    const u32 raw = ExtractBitsLE(report, len, f.bit_offset, f.bit_size);
    return f.is_signed ? SignExtend(raw, f.bit_size) : static_cast<i32>(raw);
}

// Scale an axis value from [logical_min, logical_max] to a 16-bit
// signed range [-32768, 32767]. Handles the common 8-bit [0,255]
// and 16-bit [-32768,32767] encodings.
i16 ScaleAxis(i32 value, i32 lo, i32 hi)
{
    if (lo >= hi)
        return 0;
    // Center the value around zero
    i32 range = hi - lo;
    i32 mid = lo + range / 2;
    i32 centered = value - mid;
    // Scale to [-32768, 32767]
    i64 scaled = (static_cast<i64>(centered) * 65535) / range;
    if (scaled < -32768)
        scaled = -32768;
    if (scaled > 32767)
        scaled = 32767;
    return static_cast<i16>(scaled);
}

// Scale an axis value from [logical_min, logical_max] to [0, 255]
// for triggers.
u8 ScaleTrigger(i32 value, i32 lo, i32 hi)
{
    if (lo >= hi)
        return 0;
    i32 clamped = value;
    if (clamped < lo)
        clamped = lo;
    if (clamped > hi)
        clamped = hi;
    i32 range = hi - lo;
    u32 scaled = static_cast<u32>((clamped - lo) * 255) / static_cast<u32>(range);
    return static_cast<u8>(scaled);
}

// Map a hat switch value (0-7 = N,NE,E,SE,S,SW,W,NW; 8+ = centered)
// to d-pad button bits.
u16 HatToDpad(i32 hat_value)
{
    switch (hat_value)
    {
    case 0:
        return kGamepadDpadUp;
    case 1:
        return kGamepadDpadUp | kGamepadDpadRight;
    case 2:
        return kGamepadDpadRight;
    case 3:
        return kGamepadDpadDown | kGamepadDpadRight;
    case 4:
        return kGamepadDpadDown;
    case 5:
        return kGamepadDpadDown | kGamepadDpadLeft;
    case 6:
        return kGamepadDpadLeft;
    case 7:
        return kGamepadDpadUp | kGamepadDpadLeft;
    default:
        return 0; // centered / null
    }
}

// Map HID button indices (1-based) to XInput button bits.
// The mapping follows the most common gamepad convention:
//   Button 1  -> A       Button 2  -> B
//   Button 3  -> X       Button 4  -> Y
//   Button 5  -> LB      Button 6  -> RB
//   Button 7  -> Back    Button 8  -> Start
//   Button 9  -> L3      Button 10 -> R3
u16 ButtonBitFromIndex(u32 idx_1based)
{
    switch (idx_1based)
    {
    case 1:
        return kGamepadA;
    case 2:
        return kGamepadB;
    case 3:
        return kGamepadX;
    case 4:
        return kGamepadY;
    case 5:
        return kGamepadLeftShoulder;
    case 6:
        return kGamepadRightShoulder;
    case 7:
        return kGamepadBack;
    case 8:
        return kGamepadStart;
    case 9:
        return kGamepadLeftThumb;
    case 10:
        return kGamepadRightThumb;
    default:
        return 0;
    }
}

} // namespace

// ---------------------------------------------------------------
// Public API
// ---------------------------------------------------------------

u32 GamepadConnect(const HidGamepadLayout* layout)
{
    for (u32 i = 0; i < kGamepadMaxSlots; ++i)
    {
        SlotGuard guard(g_slots[i].lock);
        if (!g_slots[i].connected)
        {
            g_slots[i].connected = true;
            g_slots[i].packet_number = 0;
            g_slots[i].state = {};
            if (layout)
                g_slots[i].layout = *layout;
            else
                g_slots[i].layout = {};
            return i;
        }
    }
    return static_cast<u32>(-1);
}

void GamepadDisconnect(u32 slot)
{
    if (slot >= kGamepadMaxSlots)
        return;
    SlotGuard guard(g_slots[slot].lock);
    g_slots[slot].connected = false;
    g_slots[slot].state = {};
    g_slots[slot].packet_number = 0;
}

void GamepadInjectReport(u32 slot, const u8* report, u32 len)
{
    if (slot >= kGamepadMaxSlots || report == nullptr || len == 0)
        return;

    SlotGuard guard(g_slots[slot].lock);
    if (!g_slots[slot].connected)
        return;

    const HidGamepadLayout& lay = g_slots[slot].layout;
    if (!lay.valid)
        return;

    // Skip report-ID prefix byte if present
    const u8* payload = report;
    u32 payload_len = len;
    if (lay.report_id != 0)
    {
        if (len < 1 || report[0] != lay.report_id)
            return;
        ++payload;
        --payload_len;
    }

    GamepadState& s = g_slots[slot].state;

    // Axes
    if (lay.x.present)
        s.thumb_lx = ScaleAxis(ExtractFieldValue(payload, payload_len, lay.x), lay.x.logical_min, lay.x.logical_max);
    if (lay.y.present)
    {
        // Y axis is typically inverted in HID (up = negative)
        i32 raw = ExtractFieldValue(payload, payload_len, lay.y);
        s.thumb_ly = static_cast<i16>(-static_cast<i32>(ScaleAxis(raw, lay.y.logical_min, lay.y.logical_max)));
        // Clamp the -(-32768) overflow
        if (s.thumb_ly == -32768 && raw == lay.y.logical_min)
            s.thumb_ly = 32767;
    }

    // Right stick
    if (lay.rx.present)
        s.thumb_rx = ScaleAxis(ExtractFieldValue(payload, payload_len, lay.rx), lay.rx.logical_min, lay.rx.logical_max);
    else if (lay.z.present && !lay.rx.present)
    {
        // Some gamepads put right-X in Z axis
        s.thumb_rx = ScaleAxis(ExtractFieldValue(payload, payload_len, lay.z), lay.z.logical_min, lay.z.logical_max);
    }
    if (lay.ry.present)
    {
        i32 raw = ExtractFieldValue(payload, payload_len, lay.ry);
        s.thumb_ry = static_cast<i16>(-static_cast<i32>(ScaleAxis(raw, lay.ry.logical_min, lay.ry.logical_max)));
        if (s.thumb_ry == -32768 && raw == lay.ry.logical_min)
            s.thumb_ry = 32767;
    }
    else if (lay.rz.present && !lay.ry.present)
    {
        i32 raw = ExtractFieldValue(payload, payload_len, lay.rz);
        s.thumb_ry = static_cast<i16>(-static_cast<i32>(ScaleAxis(raw, lay.rz.logical_min, lay.rz.logical_max)));
        if (s.thumb_ry == -32768 && raw == lay.rz.logical_min)
            s.thumb_ry = 32767;
    }

    // Triggers -- if Z/Rz aren't consumed by sticks, use them for triggers
    if (lay.z.present && lay.rx.present)
    {
        // Z is left trigger when right-X has its own axis
        s.left_trigger =
            ScaleTrigger(ExtractFieldValue(payload, payload_len, lay.z), lay.z.logical_min, lay.z.logical_max);
    }
    if (lay.rz.present && lay.ry.present)
    {
        // Rz is right trigger when right-Y has its own axis
        s.right_trigger =
            ScaleTrigger(ExtractFieldValue(payload, payload_len, lay.rz), lay.rz.logical_min, lay.rz.logical_max);
    }

    // Buttons
    u16 btn = 0;
    if (lay.button_count > 0)
    {
        u32 count = lay.button_count;
        if (count > 16)
            count = 16;
        for (u32 i = 0; i < count; ++i)
        {
            u32 bit = ExtractBitsLE(payload, payload_len, lay.button_offset_bits + i, 1);
            if (bit)
                btn |= ButtonBitFromIndex(i + 1);
        }
    }

    // Hat switch -> d-pad
    if (lay.hat.present)
    {
        i32 hat_val = ExtractFieldValue(payload, payload_len, lay.hat);
        btn |= HatToDpad(hat_val);
    }

    s.buttons = btn;
    ++g_slots[slot].packet_number;
}

bool GamepadGetState(u32 slot, GamepadSlotState* out)
{
    if (slot >= kGamepadMaxSlots || out == nullptr)
        return false;
    SlotGuard guard(g_slots[slot].lock);
    if (!g_slots[slot].connected)
        return false;
    out->packet_number = g_slots[slot].packet_number;
    out->pad = g_slots[slot].state;
    return true;
}

bool GamepadGetCapabilities(u32 slot, GamepadCapabilities* out)
{
    if (slot >= kGamepadMaxSlots || out == nullptr)
        return false;
    SlotGuard guard(g_slots[slot].lock);
    if (!g_slots[slot].connected)
        return false;
    *out = {};
    out->type = 1;     // XINPUT_DEVTYPE_GAMEPAD
    out->sub_type = 1; // XINPUT_DEVSUBTYPE_GAMEPAD
    out->flags = 0;
    // Report which axes/buttons the layout has
    const HidGamepadLayout& lay = g_slots[slot].layout;
    GamepadState& g = out->gamepad;
    if (lay.x.present)
        g.thumb_lx = static_cast<i16>(-1);
    if (lay.y.present)
        g.thumb_ly = static_cast<i16>(-1);
    if (lay.rx.present || lay.z.present)
        g.thumb_rx = static_cast<i16>(-1);
    if (lay.ry.present || lay.rz.present)
        g.thumb_ry = static_cast<i16>(-1);
    if (lay.button_count > 0)
        g.buttons = 0xFFFF;
    return true;
}

u32 GamepadGetConnectedMask()
{
    u32 mask = 0;
    for (u32 i = 0; i < kGamepadMaxSlots; ++i)
    {
        SlotGuard guard(g_slots[i].lock);
        if (g_slots[i].connected)
            mask |= (1u << i);
    }
    return mask;
}

// ---------------------------------------------------------------
// HID report descriptor -> gamepad layout extraction
// ---------------------------------------------------------------

bool GamepadExtractLayout(const u8* desc, u32 len, HidGamepadLayout* out)
{
    using namespace duetos::drivers::usb::hid;
    if (out == nullptr)
        return false;
    *out = {};

    // First pass: verify this is a gamepad/joystick descriptor
    HidReportSummary summary{};
    if (!HidParseDescriptor(desc, len, &summary))
        return false;
    if (summary.primary_kind != DeviceKind::Gamepad && summary.primary_kind != DeviceKind::Joystick)
        return false;

    // Second pass: walk the descriptor manually to record per-field
    // bit offsets. This is a simplified walk that handles the
    // common gamepad descriptor patterns.
    u16 usage_page = 0;
    u16 usage = 0;
    u8 report_id = 0;
    i32 logical_min = 0;
    i32 logical_max = 0;
    u32 report_size = 0;
    u32 report_count = 0;
    u32 bit_offset = 0;
    u32 usage_stack[32] = {};
    u32 usage_stack_top = 0;

    u32 pos = 0;
    while (pos < len)
    {
        const u8 prefix = desc[pos];
        if (prefix == 0xFE)
            break; // long item -- not supported

        const u8 size_code = prefix & 0x03;
        const u8 item_type = (prefix >> 2) & 0x03;
        const u8 item_tag = (prefix >> 4) & 0x0F;
        u32 data_size = size_code;
        if (data_size == 3)
            data_size = 4;
        if (pos + 1 + data_size > len)
            break;

        const u8* data = &desc[pos + 1];
        u32 value = 0;
        if (data_size == 1)
            value = data[0];
        else if (data_size == 2)
            value = u32(data[0]) | (u32(data[1]) << 8);
        else if (data_size == 4)
            value = u32(data[0]) | (u32(data[1]) << 8) | (u32(data[2]) << 16) | (u32(data[3]) << 24);

        i32 svalue = static_cast<i32>(value);
        if (data_size == 1 && (value & 0x80))
            svalue = static_cast<i32>(value | 0xFFFFFF00u);
        else if (data_size == 2 && (value & 0x8000))
            svalue = static_cast<i32>(value | 0xFFFF0000u);

        // Global items (type 1)
        if (item_type == 1)
        {
            switch (item_tag)
            {
            case 0:
                usage_page = static_cast<u16>(value);
                break; // Usage Page
            case 1:
                logical_min = svalue;
                break;
            case 2:
                logical_max = svalue;
                break;
            case 3:
                break; // Physical Min
            case 4:
                break; // Physical Max
            case 7:
                report_size = value;
                break;
            case 8:
                report_id = static_cast<u8>(value);
                break;
            case 9:
                report_count = value;
                break;
            }
        }
        // Local items (type 2)
        else if (item_type == 2)
        {
            if (item_tag == 0) // Usage
            {
                if (usage_stack_top < 32)
                    usage_stack[usage_stack_top++] = value;
                usage = static_cast<u16>(value);
            }
            // Usage Min (tag 1) and Usage Max (tag 2) generate
            // a range of usages. We record the min for the button
            // field start.
            if (item_tag == 1) // Usage Minimum
            {
                usage = static_cast<u16>(value);
                usage_stack_top = 0;
            }
        }
        // Main items (type 0)
        else if (item_type == 0)
        {
            if (item_tag == 8) // Input
            {
                const bool is_constant = (value & 0x01) != 0;
                const u32 field_bits = report_size * report_count;

                if (!is_constant && usage_page == kUsagePageGeneric)
                {
                    // Walk usage stack for axis assignments
                    for (u32 i = 0; i < report_count && i < usage_stack_top; ++i)
                    {
                        u16 u = static_cast<u16>(usage_stack[i]);
                        GamepadReportField f{};
                        f.present = true;
                        f.is_signed = (logical_min < 0);
                        f.bit_size = static_cast<u8>(report_size);
                        f.bit_offset = bit_offset + i * report_size;
                        f.logical_min = logical_min;
                        f.logical_max = logical_max;

                        switch (u)
                        {
                        case 0x30:
                            out->x = f;
                            break; // X
                        case 0x31:
                            out->y = f;
                            break; // Y
                        case 0x32:
                            out->z = f;
                            break; // Z
                        case 0x33:
                            out->rx = f;
                            break; // Rx
                        case 0x34:
                            out->ry = f;
                            break; // Ry
                        case 0x35:
                            out->rz = f;
                            break; // Rz
                        case 0x39: // Hat switch
                            out->hat = f;
                            break;
                        }
                    }
                    // Single-usage case (no stack)
                    if (usage_stack_top == 0 && report_count == 1)
                    {
                        GamepadReportField f{};
                        f.present = true;
                        f.is_signed = (logical_min < 0);
                        f.bit_size = static_cast<u8>(report_size);
                        f.bit_offset = bit_offset;
                        f.logical_min = logical_min;
                        f.logical_max = logical_max;

                        switch (usage)
                        {
                        case 0x30:
                            out->x = f;
                            break;
                        case 0x31:
                            out->y = f;
                            break;
                        case 0x32:
                            out->z = f;
                            break;
                        case 0x33:
                            out->rx = f;
                            break;
                        case 0x34:
                            out->ry = f;
                            break;
                        case 0x35:
                            out->rz = f;
                            break;
                        case 0x39:
                            out->hat = f;
                            break;
                        }
                    }
                }

                if (!is_constant && usage_page == kUsagePageButton)
                {
                    out->button_offset_bits = bit_offset;
                    out->button_count = report_count;
                }

                bit_offset += field_bits;
                // Clear local state after Main item
                usage_stack_top = 0;
                usage = 0;
            }
            else if (item_tag == 10) // Collection
            {
                // nothing
            }
            else if (item_tag == 12) // End Collection
            {
                // nothing
            }
        }

        pos += 1 + data_size;
    }

    out->valid = (out->x.present || out->button_count > 0);
    out->report_id = report_id;
    out->report_size_bits = bit_offset;
    return out->valid;
}

// ---------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------

void GamepadSelfTest()
{
#ifndef DUETOS_HOSTED_TEST
    arch::SerialWrite("[gamepad-selftest] starting\n");
#endif

    // Test 1: connect / disconnect
    {
        HidGamepadLayout lay{};
        lay.valid = true;
        lay.x.present = true;
        lay.x.is_signed = true;
        lay.x.bit_size = 8;
        lay.x.bit_offset = 0;
        lay.x.logical_min = -128;
        lay.x.logical_max = 127;
        lay.button_offset_bits = 32;
        lay.button_count = 10;

        u32 s = GamepadConnect(&lay);
        GP_ASSERT(s < kGamepadMaxSlots, "connect should succeed");
        GP_ASSERT(GamepadGetConnectedMask() & (1u << s), "connected mask should include slot");
        GamepadDisconnect(s);
        GP_ASSERT(!(GamepadGetConnectedMask() & (1u << s)), "disconnected slot should be cleared");
    }

    // Test 2: inject + read round-trip
    {
        HidGamepadLayout lay{};
        lay.valid = true;
        // 8-bit X at bit 0, 8-bit Y at bit 8
        lay.x = {true, true, 8, 0, -128, 127};
        lay.y = {true, true, 8, 8, -128, 127};
        // 10 buttons at bit 32
        lay.button_offset_bits = 32;
        lay.button_count = 10;

        u32 s = GamepadConnect(&lay);
        GP_ASSERT(s < kGamepadMaxSlots, "connect for inject test");

        // Report: X=64, Y=0, padding=0x00, padding=0x00,
        //         buttons = bit 0 (A) + bit 2 (X) set
        u8 report[6] = {64, 0, 0, 0, 0x05, 0x00};
        GamepadInjectReport(s, report, 6);

        GamepadSlotState state{};
        bool ok = GamepadGetState(s, &state);
        GP_ASSERT(ok, "GetState should succeed after inject");
        GP_ASSERT(state.packet_number == 1, "packet number should be 1");
        GP_ASSERT(state.pad.thumb_lx > 0, "X=64 should map to positive thumb_lx");
        GP_ASSERT((state.pad.buttons & kGamepadA) != 0, "button 1 -> A");
        GP_ASSERT((state.pad.buttons & kGamepadX) != 0, "button 3 -> X");
        GP_ASSERT((state.pad.buttons & kGamepadB) == 0, "button 2 not set");

        GamepadDisconnect(s);
    }

    // Test 3: not-connected read fails
    {
        GamepadSlotState state{};
        bool ok = GamepadGetState(0, &state);
        // Slot 0 should be free after the above disconnect
        GP_ASSERT(!ok, "GetState on unconnected slot should fail");
    }

    // Test 4: layout extraction on a synthetic gamepad descriptor
    {
        // Minimal gamepad descriptor:
        //   Usage Page (Generic Desktop)
        //   Usage (Gamepad)
        //   Collection (Application)
        //     Usage Page (Button)
        //     Usage Minimum (1)
        //     Usage Maximum (10)
        //     Logical Minimum (0)
        //     Logical Maximum (1)
        //     Report Count (10)
        //     Report Size (1)
        //     Input (Data,Var,Abs)
        //     Report Count (1)
        //     Report Size (6)
        //     Input (Cnst)          -- padding
        //     Usage Page (Generic Desktop)
        //     Usage (X)
        //     Usage (Y)
        //     Logical Minimum (-128)
        //     Logical Maximum (127)
        //     Report Size (8)
        //     Report Count (2)
        //     Input (Data,Var,Abs)
        //   End Collection
        static const u8 desc[] = {
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x05, // Usage (Gamepad)
            0xA1, 0x01, // Collection (Application)
            0x05, 0x09, //   Usage Page (Button)
            0x19, 0x01, //   Usage Minimum (1)
            0x29, 0x0A, //   Usage Maximum (10)
            0x15, 0x00, //   Logical Minimum (0)
            0x25, 0x01, //   Logical Maximum (1)
            0x95, 0x0A, //   Report Count (10)
            0x75, 0x01, //   Report Size (1)
            0x81, 0x02, //   Input (Data,Var,Abs)
            0x95, 0x01, //   Report Count (1)
            0x75, 0x06, //   Report Size (6)
            0x81, 0x01, //   Input (Cnst) -- padding
            0x05, 0x01, //   Usage Page (Generic Desktop)
            0x09, 0x30, //   Usage (X)
            0x09, 0x31, //   Usage (Y)
            0x15, 0x80, //   Logical Minimum (-128)
            0x25, 0x7F, //   Logical Maximum (127)
            0x75, 0x08, //   Report Size (8)
            0x95, 0x02, //   Report Count (2)
            0x81, 0x02, //   Input (Data,Var,Abs)
            0xC0,       // End Collection
        };

        HidGamepadLayout lay{};
        bool ok = GamepadExtractLayout(desc, sizeof(desc), &lay);
        GP_ASSERT(ok, "layout extraction should succeed");
        GP_ASSERT(lay.valid, "layout should be valid");
        GP_ASSERT(lay.button_count == 10, "should find 10 buttons");
        GP_ASSERT(lay.button_offset_bits == 0, "buttons at bit 0");
        GP_ASSERT(lay.x.present, "X axis should be present");
        GP_ASSERT(lay.y.present, "Y axis should be present");
        GP_ASSERT(lay.x.bit_offset == 16, "X at bit 16 (after 10 btn + 6 pad)");
        GP_ASSERT(lay.y.bit_offset == 24, "Y at bit 24");
        GP_ASSERT(lay.x.bit_size == 8, "X is 8-bit");
        GP_ASSERT(lay.x.logical_min == -128, "X min -128");
        GP_ASSERT(lay.x.logical_max == 127, "X max 127");
    }

#ifndef DUETOS_HOSTED_TEST
    arch::SerialWrite("[gamepad-selftest] PASS\n");
#endif
}

} // namespace duetos::drivers::input
