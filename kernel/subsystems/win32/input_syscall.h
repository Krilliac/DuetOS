#pragma once

#include "util/types.h"

/*
 * Win32 gamepad input-syscall handler.
 *
 *   SYS_GAMEPAD_STATE (230) — rdi = slot (0..3), rsi = user pointer
 *   to a GamepadStateWire, rdx = sizeof(GamepadStateWire).
 *
 * Read-only bridge from xinput1_4.dll into the kernel HID gamepad
 * driver (kernel/drivers/input/hid_gamepad.h). The guest supplies
 * only a slot index — raw HID report data never crosses the syscall
 * boundary in either direction, so a malicious PE cannot inject
 * reports or reach driver internals through this path.
 *
 * kCapInput is gated centrally by `SyscallGate` (cap_table.def),
 * matching the sibling SYS_WIN_GET_KEYSTATE / SYS_WIN_GET_MOUSE_DELTA
 * input reads: a process missing the cap returns -1 from the gate
 * before ever reaching the handler.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

// Wire struct copied to userland by SYS_GAMEPAD_STATE. Field order
// mirrors XINPUT_STATE (packet_number + 12-byte gamepad block) and
// XINPUT_CAPABILITIES so xinput1_4.dll maps it with straight field
// copies; the userland twin lives in userland/libs/xinput1_4/
// xinput_wire.h and the host test pins the two layouts against each
// other. ABI stable from this commit — a layout change is a new
// version with a new size (the syscall rejects any other rdx).
struct GamepadStateWire
{
    u32 connected;      // 1 = queried slot has a gamepad attached
    u32 connected_mask; // bit N set = slot N connected

    // XINPUT_STATE image for the queried slot.
    u32 packet_number;
    u16 buttons;      // XINPUT_GAMEPAD_* bitmask
    u8 left_trigger;  // 0..255
    u8 right_trigger; // 0..255
    i16 thumb_lx;
    i16 thumb_ly;
    i16 thumb_rx;
    i16 thumb_ry;

    // XINPUT_CAPABILITIES image for the queried slot.
    u8 cap_type;     // XINPUT_DEVTYPE_GAMEPAD
    u8 cap_sub_type; // XINPUT_DEVSUBTYPE_GAMEPAD
    u16 cap_flags;
    u16 cap_buttons; // supported-control bitmasks (XINPUT_GAMEPAD shape)
    u8 cap_left_trigger;
    u8 cap_right_trigger;
    i16 cap_thumb_lx;
    i16 cap_thumb_ly;
    i16 cap_thumb_rx;
    i16 cap_thumb_ry;
    u8 cap_left_motor;
    u8 cap_right_motor;
    u16 reserved; // keep sizeof a multiple of 4; always 0
};
static_assert(sizeof(GamepadStateWire) == 44, "SYS_GAMEPAD_STATE wire ABI is 44 bytes");

void DoGamepadState(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
