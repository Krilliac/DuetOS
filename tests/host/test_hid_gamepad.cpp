// test_hid_gamepad.cpp — hosted test for kernel/drivers/input/hid_gamepad.cpp.
//
// Covers: GamepadExtractLayout on a synthetic report-protocol gamepad
// descriptor (buttons + hat + 4 signed axes), inject/read round-trip
// through the slot table, Report-ID prefix filtering, connect/
// disconnect mask behaviour, slot exhaustion, and capabilities
// reporting. Also runs the driver's own GamepadSelfTest(), whose
// hosted GP_ASSERT path feeds the same failure counter.
//
// hid_gamepad.cpp's kind check calls hid::HidParseDescriptor, whose
// production implementation lives behind the Rust usbhid staticlib.
// This test provides a minimal C++ stub (below) that classifies the
// top-level Generic Desktop usage — enough for the layout walk under
// test, without dragging the Rust toolchain into the host-test build.

#include "host_test_helper.h"

#include "drivers/input/hid_gamepad.h"
#include "drivers/usb/hid_descriptor.h"

namespace duetos::drivers::usb::hid
{

// Test stub for the Rust-backed parser. Walks short items tracking
// the current Usage Page; the first Usage seen on the Generic
// Desktop page becomes the top-level usage that drives the kind
// classification GamepadExtractLayout gates on.
bool HidParseDescriptor(const u8* buf, u32 len, HidReportSummary* out)
{
    if (out == nullptr)
        return false;
    *out = {};
    if (buf == nullptr)
        return false;

    u16 page = 0;
    u32 pos = 0;
    while (pos < len)
    {
        const u8 prefix = buf[pos];
        u32 dataSize = prefix & 0x03u;
        if (dataSize == 3)
            dataSize = 4;
        if (pos + 1 + dataSize > len)
            break;
        u32 value = 0;
        for (u32 i = 0; i < dataSize; ++i)
            value |= u32(buf[pos + 1 + i]) << (8u * i);
        const u8 itemType = (prefix >> 2) & 0x03u;
        const u8 itemTag = (prefix >> 4) & 0x0Fu;
        if (itemType == 1 && itemTag == 0)
            page = u16(value);
        else if (itemType == 2 && itemTag == 0 && out->top_usage == 0 && page == kUsagePageGeneric)
        {
            out->top_usage_page = page;
            out->top_usage = u16(value);
        }
        pos += 1 + dataSize;
    }

    out->parse_ok = true;
    switch (out->top_usage)
    {
    case kUsageGenericGamepad:
        out->primary_kind = DeviceKind::Gamepad;
        break;
    case kUsageGenericJoystick:
        out->primary_kind = DeviceKind::Joystick;
        break;
    default:
        out->primary_kind = DeviceKind::Other;
        break;
    }
    return true;
}

} // namespace duetos::drivers::usb::hid

using namespace duetos::drivers::input;
using duetos::u16;
using duetos::u32;
using duetos::u8;

namespace
{

// Report-protocol gamepad: 10 buttons @ bit 0, 6 pad bits, hat
// @ bit 16 (4 bits), 4 pad bits, then signed 8-bit X/Y/Z/Rz at
// bits 24/32/40/48. Total payload: 56 bits (7 bytes), no Report ID.
static const u8 kGamepadReportDescriptor[] = {
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x05, // Usage (Gamepad)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x09, // Usage Page (Button)
    0x19, 0x01, // Usage Minimum (1)
    0x29, 0x0A, // Usage Maximum (10)
    0x15, 0x00, // Logical Minimum (0)
    0x25, 0x01, // Logical Maximum (1)
    0x95, 0x0A, // Report Count (10)
    0x75, 0x01, // Report Size (1)
    0x81, 0x02, // Input (Data,Var,Abs) -- 10 button bits at bit 0
    0x95, 0x01, // Report Count (1)
    0x75, 0x06, // Report Size (6)
    0x81, 0x01, // Input (Const) -- 6 bits padding
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x39, // Usage (Hat switch)
    0x15, 0x00, // Logical Minimum (0)
    0x25, 0x07, // Logical Maximum (7)
    0x75, 0x04, // Report Size (4)
    0x95, 0x01, // Report Count (1)
    0x81, 0x02, // Input (Data,Var,Abs) -- hat at bit 16
    0x95, 0x01, // Report Count (1)
    0x75, 0x04, // Report Size (4)
    0x81, 0x01, // Input (Const) -- 4 bits padding
    0x09, 0x30, // Usage (X)
    0x09, 0x31, // Usage (Y)
    0x09, 0x32, // Usage (Z)
    0x09, 0x35, // Usage (Rz)
    0x15, 0x80, // Logical Minimum (-128)
    0x25, 0x7F, // Logical Maximum (127)
    0x75, 0x08, // Report Size (8)
    0x95, 0x04, // Report Count (4)
    0x81, 0x02, // Input (Data,Var,Abs) -- X@24 Y@32 Z@40 Rz@48
    0xC0        // End Collection
};

static void TestLayoutExtraction()
{
    HidGamepadLayout lay{};
    EXPECT_TRUE(GamepadExtractLayout(kGamepadReportDescriptor, sizeof(kGamepadReportDescriptor), &lay));
    EXPECT_TRUE(lay.valid);
    EXPECT_EQ(lay.report_id, 0);
    EXPECT_EQ(lay.report_size_bits, 56u);
    EXPECT_EQ(lay.button_offset_bits, 0u);
    EXPECT_EQ(lay.button_count, 10u);
    EXPECT_TRUE(lay.hat.present);
    EXPECT_EQ(lay.hat.bit_offset, 16u);
    EXPECT_EQ(lay.hat.bit_size, 4);
    EXPECT_TRUE(lay.x.present);
    EXPECT_EQ(lay.x.bit_offset, 24u);
    EXPECT_EQ(lay.x.bit_size, 8);
    EXPECT_TRUE(lay.x.is_signed);
    EXPECT_EQ(lay.x.logical_min, -128);
    EXPECT_EQ(lay.x.logical_max, 127);
    EXPECT_TRUE(lay.y.present);
    EXPECT_EQ(lay.y.bit_offset, 32u);
    EXPECT_TRUE(lay.z.present);
    EXPECT_EQ(lay.z.bit_offset, 40u);
    EXPECT_TRUE(lay.rz.present);
    EXPECT_EQ(lay.rz.bit_offset, 48u);
    EXPECT_FALSE(lay.rx.present);
    EXPECT_FALSE(lay.ry.present);
}

static void TestInjectReadRoundTrip()
{
    HidGamepadLayout lay{};
    EXPECT_TRUE(GamepadExtractLayout(kGamepadReportDescriptor, sizeof(kGamepadReportDescriptor), &lay));
    const u32 slot = GamepadConnect(&lay);
    EXPECT_TRUE(slot < kGamepadMaxSlots);
    EXPECT_TRUE((GamepadGetConnectedMask() & (1u << slot)) != 0);

    // Buttons 1 (A) + 4 (Y) in byte 0, button 9 (L3) in byte 1,
    // hat=2 (East -> D-pad right) in byte 2's low nibble, then
    // X=127, Y=-128, Z=0, Rz=0.
    const u8 report[7] = {0x09, 0x01, 0x02, 0x7F, 0x80, 0x00, 0x00};
    GamepadInjectReport(slot, report, 7);

    GamepadSlotState st{};
    EXPECT_TRUE(GamepadGetState(slot, &st));
    EXPECT_EQ(st.packet_number, 1u);
    EXPECT_TRUE((st.pad.buttons & kGamepadA) != 0);
    EXPECT_TRUE((st.pad.buttons & kGamepadY) != 0);
    EXPECT_TRUE((st.pad.buttons & kGamepadLeftThumb) != 0);
    EXPECT_TRUE((st.pad.buttons & kGamepadDpadRight) != 0);
    EXPECT_FALSE((st.pad.buttons & kGamepadB) != 0);
    EXPECT_EQ(st.pad.thumb_lx, 32767); // X=127 saturates positive
    EXPECT_EQ(st.pad.thumb_ly, 32639); // Y=-128; HID Y axis is inverted

    GamepadDisconnect(slot);
    EXPECT_FALSE((GamepadGetConnectedMask() & (1u << slot)) != 0);
    GamepadSlotState st2{};
    EXPECT_FALSE(GamepadGetState(slot, &st2));
}

static void TestReportIdPrefix()
{
    HidGamepadLayout lay{};
    lay.valid = true;
    lay.report_id = 5;
    lay.x.present = true;
    lay.x.is_signed = true;
    lay.x.bit_size = 8;
    lay.x.bit_offset = 0;
    lay.x.logical_min = -128;
    lay.x.logical_max = 127;

    const u32 slot = GamepadConnect(&lay);
    EXPECT_TRUE(slot < kGamepadMaxSlots);

    const u8 good[2] = {5, 64};
    GamepadInjectReport(slot, good, 2);
    GamepadSlotState st{};
    EXPECT_TRUE(GamepadGetState(slot, &st));
    EXPECT_EQ(st.packet_number, 1u);
    EXPECT_TRUE(st.pad.thumb_lx > 0);

    const u8 bad[2] = {6, 64}; // wrong Report ID: must be dropped
    GamepadInjectReport(slot, bad, 2);
    EXPECT_TRUE(GamepadGetState(slot, &st));
    EXPECT_EQ(st.packet_number, 1u);

    GamepadDisconnect(slot);
}

static void TestSlotExhaustionAndCapabilities()
{
    HidGamepadLayout lay{};
    lay.valid = true;
    lay.button_offset_bits = 0;
    lay.button_count = 4;
    lay.x.present = true;
    lay.x.bit_size = 8;
    lay.x.bit_offset = 8;
    lay.x.logical_min = 0;
    lay.x.logical_max = 255;

    u32 slots[4];
    for (u32 i = 0; i < 4; ++i)
    {
        slots[i] = GamepadConnect(&lay);
        EXPECT_TRUE(slots[i] < kGamepadMaxSlots);
    }
    EXPECT_EQ(GamepadGetConnectedMask(), 0xFu);
    EXPECT_EQ(GamepadConnect(&lay), static_cast<u32>(-1)); // 5th connect fails

    GamepadCapabilities caps{};
    EXPECT_TRUE(GamepadGetCapabilities(slots[0], &caps));
    EXPECT_EQ(caps.type, 1);
    EXPECT_EQ(caps.sub_type, 1);
    EXPECT_EQ(caps.gamepad.buttons, 0xFFFF);
    EXPECT_TRUE(caps.gamepad.thumb_lx != 0);

    for (u32 i = 0; i < 4; ++i)
        GamepadDisconnect(slots[i]);
    EXPECT_EQ(GamepadGetConnectedMask(), 0u);
    GamepadCapabilities caps2{};
    EXPECT_FALSE(GamepadGetCapabilities(slots[0], &caps2));
}

} // namespace

int main()
{
    // The driver's own boot self-test, routed through the hosted
    // GP_ASSERT seam (feeds the same failure counter).
    GamepadSelfTest();

    TestLayoutExtraction();
    TestInjectReadRoundTrip();
    TestReportIdPrefix();
    TestSlotExhaustionAndCapabilities();

    return duetos_host_test::finish_main("test_hid_gamepad");
}
