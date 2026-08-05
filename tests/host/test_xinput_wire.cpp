// test_xinput_wire.cpp — pin the SYS_GAMEPAD_STATE wire ABI.
//
// The syscall copies a GamepadStateWire (kernel/subsystems/win32/
// input_syscall.h) into a buffer that xinput1_4.dll reads back as a
// DuetGamepadWire (userland/libs/xinput1_4/xinput_wire.h). Nothing at
// compile time forces those two declarations to agree: they live in
// different languages, different trees, and are built by different
// compilers. A field reordered on one side and not the other would
// still compile, still pass the size static_asserts both headers
// already carry, and silently hand games a thumbstick value where the
// trigger belongs.
//
// So this test compares them the only way that catches that: offset by
// offset, size by size, for every field. It also walks the round trip
// a real caller makes — kernel fills the struct, userland maps it into
// XINPUT_STATE / XINPUT_CAPABILITIES — with values chosen so a swapped
// pair of fields cannot produce the expected answer by luck.

#include "host_test_helper.h"

#include "subsystems/win32/input_syscall.h"

extern "C"
{
#include "xinput_wire.h"
}

#include <cstddef>

using duetos::subsystems::win32::GamepadStateWire;

// Both sides agree on the offset, the size, and the signedness of one
// field. Signedness matters as much as position: the thumbstick axes
// are the only signed members, and reading one as unsigned turns a
// left push into a hard right.
#define EXPECT_FIELD(kfield, ufield)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        EXPECT_EQ(offsetof(GamepadStateWire, kfield), offsetof(DuetGamepadWire, ufield));                              \
        EXPECT_EQ(sizeof(GamepadStateWire::kfield), sizeof(((DuetGamepadWire*)nullptr)->ufield));                      \
        EXPECT_EQ(static_cast<int>(decltype(GamepadStateWire::kfield)(-1) < 0),                                        \
                  static_cast<int>(static_cast<decltype(((DuetGamepadWire*)nullptr)->ufield)>(-1) < 0));               \
    } while (0)

int main()
{
    // --- Whole-struct size ------------------------------------------------
    // Each header already static_asserts its own size; this pins them to
    // each other, which neither can do alone.
    EXPECT_EQ(sizeof(GamepadStateWire), sizeof(DuetGamepadWire));
    EXPECT_EQ(sizeof(GamepadStateWire), static_cast<size_t>(DUET_XINPUT_WIRE_SIZE));

    // --- Connection state -------------------------------------------------
    EXPECT_FIELD(connected, connected);
    EXPECT_FIELD(connected_mask, connected_mask);

    // --- XINPUT_STATE image -----------------------------------------------
    EXPECT_FIELD(packet_number, packet_number);
    EXPECT_FIELD(buttons, buttons);
    EXPECT_FIELD(left_trigger, left_trigger);
    EXPECT_FIELD(right_trigger, right_trigger);
    EXPECT_FIELD(thumb_lx, thumb_lx);
    EXPECT_FIELD(thumb_ly, thumb_ly);
    EXPECT_FIELD(thumb_rx, thumb_rx);
    EXPECT_FIELD(thumb_ry, thumb_ry);

    // --- XINPUT_CAPABILITIES image ----------------------------------------
    EXPECT_FIELD(cap_type, cap_type);
    EXPECT_FIELD(cap_sub_type, cap_sub_type);
    EXPECT_FIELD(cap_flags, cap_flags);
    EXPECT_FIELD(cap_buttons, cap_buttons);
    EXPECT_FIELD(cap_left_trigger, cap_left_trigger);
    EXPECT_FIELD(cap_right_trigger, cap_right_trigger);
    EXPECT_FIELD(cap_thumb_lx, cap_thumb_lx);
    EXPECT_FIELD(cap_thumb_ly, cap_thumb_ly);
    EXPECT_FIELD(cap_thumb_rx, cap_thumb_rx);
    EXPECT_FIELD(cap_thumb_ry, cap_thumb_ry);
    EXPECT_FIELD(cap_left_motor, cap_left_motor);
    EXPECT_FIELD(cap_right_motor, cap_right_motor);
    EXPECT_FIELD(reserved, reserved);

    // --- Round trip through the real mapping helpers ----------------------
    // Fill the kernel-side struct, reinterpret the bytes as the userland
    // twin (exactly what the syscall's CopyToUser does), then run the
    // DLL's own mapping helpers over it. Every value is distinct so a
    // transposed pair shows up as a wrong number rather than a match.
    GamepadStateWire kwire{};
    kwire.connected = 1;
    kwire.connected_mask = 0x5; // slots 0 and 2
    kwire.packet_number = 0x11223344;
    kwire.buttons = 0xABCD;
    kwire.left_trigger = 0x12;
    kwire.right_trigger = 0x34;
    kwire.thumb_lx = -32768; // extremes on the signed axes: a sign
    kwire.thumb_ly = 32767;  // error flips these, a swap misplaces them
    kwire.thumb_rx = -1234;
    kwire.thumb_ry = 5678;
    kwire.cap_type = 0x01;
    kwire.cap_sub_type = 0x02;
    kwire.cap_flags = 0x0304;
    kwire.cap_buttons = 0xF0F0;
    kwire.cap_left_trigger = 0xFF;
    kwire.cap_right_trigger = 0xFE;
    kwire.cap_thumb_lx = -32768;
    kwire.cap_thumb_ly = 32767;
    kwire.cap_thumb_rx = -2;
    kwire.cap_thumb_ry = 3;
    kwire.cap_left_motor = 0x7F;
    kwire.cap_right_motor = 0x80;

    DuetGamepadWire uwire;
    __builtin_memcpy(&uwire, &kwire, sizeof(uwire));

    EXPECT_EQ(uwire.connected, 1u);
    EXPECT_EQ(uwire.connected_mask, 0x5u);
    EXPECT_EQ(uwire.packet_number, 0x11223344u);
    EXPECT_EQ(uwire.buttons, 0xABCDu);
    EXPECT_EQ(static_cast<unsigned>(uwire.left_trigger), 0x12u);
    EXPECT_EQ(static_cast<unsigned>(uwire.right_trigger), 0x34u);
    EXPECT_EQ(static_cast<int>(uwire.thumb_lx), -32768);
    EXPECT_EQ(static_cast<int>(uwire.thumb_ly), 32767);
    EXPECT_EQ(static_cast<int>(uwire.thumb_rx), -1234);
    EXPECT_EQ(static_cast<int>(uwire.thumb_ry), 5678);
    EXPECT_EQ(static_cast<unsigned>(uwire.reserved), 0u);

    DuetXInputState state;
    EXPECT_EQ(duet_xinput_wire_to_state(&uwire, &state), DUET_XINPUT_ERROR_SUCCESS);
    EXPECT_EQ(state.dwPacketNumber, 0x11223344u);
    EXPECT_EQ(state.Gamepad.wButtons, 0xABCDu);
    EXPECT_EQ(static_cast<unsigned>(state.Gamepad.bLeftTrigger), 0x12u);
    EXPECT_EQ(static_cast<unsigned>(state.Gamepad.bRightTrigger), 0x34u);
    EXPECT_EQ(static_cast<int>(state.Gamepad.sThumbLX), -32768);
    EXPECT_EQ(static_cast<int>(state.Gamepad.sThumbLY), 32767);
    EXPECT_EQ(static_cast<int>(state.Gamepad.sThumbRX), -1234);
    EXPECT_EQ(static_cast<int>(state.Gamepad.sThumbRY), 5678);

    DuetXInputCapabilities caps;
    EXPECT_EQ(duet_xinput_wire_to_capabilities(&uwire, &caps), DUET_XINPUT_ERROR_SUCCESS);
    EXPECT_EQ(static_cast<unsigned>(caps.Type), 0x01u);
    EXPECT_EQ(static_cast<unsigned>(caps.SubType), 0x02u);
    EXPECT_EQ(caps.Flags, 0x0304u);
    EXPECT_EQ(caps.Gamepad.wButtons, 0xF0F0u);
    EXPECT_EQ(static_cast<unsigned>(caps.Gamepad.bLeftTrigger), 0xFFu);
    EXPECT_EQ(static_cast<unsigned>(caps.Gamepad.bRightTrigger), 0xFEu);
    EXPECT_EQ(static_cast<int>(caps.Gamepad.sThumbLX), -32768);
    EXPECT_EQ(static_cast<int>(caps.Gamepad.sThumbRY), 3);
    // 8-bit kernel motor strength widens to XInput 16-bit as x * 257.
    EXPECT_EQ(static_cast<unsigned>(caps.Vibration.wLeftMotorSpeed), 0x7Fu * 257u);
    EXPECT_EQ(static_cast<unsigned>(caps.Vibration.wRightMotorSpeed), 0x80u * 257u);

    // --- Disconnected slot ------------------------------------------------
    // A slot with no pad is not an error: the kernel zeroes the struct
    // and sets connected = 0, which is how the DLL knows to answer
    // ERROR_DEVICE_NOT_CONNECTED instead of reporting a dead stick.
    DuetGamepadWire empty;
    __builtin_memset(&empty, 0, sizeof(empty));
    EXPECT_EQ(duet_xinput_wire_to_state(&empty, &state), DUET_XINPUT_ERROR_DEVICE_NOT_CONNECTED);
    EXPECT_EQ(duet_xinput_wire_to_capabilities(&empty, &caps), DUET_XINPUT_ERROR_DEVICE_NOT_CONNECTED);

    return duetos_host_test::finish_main("xinput_wire");
}
