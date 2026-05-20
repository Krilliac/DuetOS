#include "test_main.h"
#include "input/ps2_encode.h"
#include <windows.h>

// DRIVER GROUND TRUTH (verified against kernel/drivers/input/ps2kbd.cpp,
// ps2kbd.h, ps2mouse.cpp, ps2mouse.h):
//
//   Keyboard: scan code SET 1. The kernel explicitly sends 0xF0 0x01
//   during ControllerInit() to force set 1 on the device.
//   Set-1 break = single byte (0x80 | make_byte). Extended keys carry
//   an 0xE0 prefix before the make byte; their break is 0xE0 followed
//   by (0x80 | make_byte). There is NO 0xF0 break-prefix (that is the
//   set-2 protocol).
//
//   Mouse: standard 3-BYTE protocol only. The ps2mouse driver does NOT
//   perform the IntelliMouse sample-rate knock and does NOT read 4-byte
//   packets. The `intelliMouse` parameter in MousePacket is accepted
//   for call-site symmetry but always produces a 3-byte packet.

using namespace duetos::vmm;

// ---------------------------------------------------------------------------
// Keyboard — scan set 1
// ---------------------------------------------------------------------------

TEST(set1_letter_A_make)
{
    // 'A' in scan set 1: make = 0x1E (from kKeymapLowerUS index 0x1E = 'a').
    auto mk = VkToSet1('A', true, false);
    CHECK_EQ(mk.size(), 1u);
    CHECK_EQ((int)mk[0], 0x1E);
}

TEST(set1_letter_A_break)
{
    // Set-1 break for a non-extended key: single byte 0x80 | make = 0x9E.
    auto bk = VkToSet1('A', false, false);
    CHECK_EQ(bk.size(), 1u);
    CHECK_EQ((int)bk[0], 0x9E);
}

TEST(set1_extended_key_make)
{
    // VK_RIGHT extended: kScanExtArrowRight = 0x4D (from ps2kbd.cpp).
    // Make sequence: 0xE0 0x4D.
    auto mk = VkToSet1(VK_RIGHT, true, true);
    CHECK_EQ(mk.size(), 2u);
    CHECK_EQ((int)mk[0], 0xE0);
    CHECK_EQ((int)mk[1], 0x4D);
}

TEST(set1_extended_key_break)
{
    // VK_RIGHT extended break: 0xE0 followed by (0x80 | 0x4D) = 0xCD.
    auto bk = VkToSet1(VK_RIGHT, false, true);
    CHECK_EQ(bk.size(), 2u);
    CHECK_EQ((int)bk[0], 0xE0);
    CHECK_EQ((int)bk[1], 0xCD);
}

TEST(set1_unmapped_key_returns_empty)
{
    // A key with no entry in our table must return empty.
    auto v = VkToSet1(VK_F24, true, false);
    CHECK_EQ(v.size(), 0u);
}

// ---------------------------------------------------------------------------
// Mouse — 3-byte standard protocol
// ---------------------------------------------------------------------------

TEST(mouse_packet_3byte_basic)
{
    // dx=5 right, dy=3 down (screen-space), left button.
    // byte0: always-1 (0x08) | LB (0x01) = 0x09;
    //        X_SGN (0x10) clear (dx positive);
    //        Y_SGN (0x20) set   (screen-down -> PS/2-negative Y).
    // byte1: 5.
    // byte2: (uint8_t)(-3) = 0xFD, i.e. (int8_t)p[2] == -3.
    auto p = MousePacket(5, 3, 0x1, 0, false);
    CHECK_EQ(p.size(), 3u);
    CHECK((p[0] & 0x08) != 0);   // always-1 bit
    CHECK((p[0] & 0x01) != 0);   // left button
    CHECK((p[0] & 0x02) == 0);   // right button clear
    CHECK((p[0] & 0x10) == 0);   // X_SGN clear (dx positive)
    CHECK((p[0] & 0x20) != 0);   // Y_SGN set (screen-down -> PS/2-negative)
    CHECK_EQ((int)p[1], 5);
    CHECK_EQ((int)(int8_t)p[2], -3);
}

TEST(mouse_packet_intellimouse_flag_still_3byte)
{
    // Driver is 3-byte only; intelliMouse flag must not produce a 4th byte.
    auto p = MousePacket(0, 0, 0, -1, true);
    CHECK_EQ(p.size(), 3u);
}

TEST(mouse_packet_right_button)
{
    auto p = MousePacket(0, 0, 0x2, 0, false);
    CHECK_EQ(p.size(), 3u);
    CHECK((p[0] & 0x02) != 0);  // right button set
    CHECK((p[0] & 0x01) == 0);  // left button clear
}

TEST(mouse_packet_negative_dx)
{
    // dx=-10: X_SGN bit set, byte1 = (int8_t)-10.
    auto p = MousePacket(-10, 0, 0, 0, false);
    CHECK((p[0] & 0x10) != 0);           // X_SGN set
    CHECK_EQ((int)(int8_t)p[1], -10);
    CHECK((p[0] & 0x20) == 0);           // Y_SGN clear (dy=0)
    CHECK_EQ((int)(int8_t)p[2], 0);
}
