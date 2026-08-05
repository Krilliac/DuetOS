#include "subsystems/win32/input_syscall.h"

#include "arch/x86_64/traps.h"
#include "drivers/input/hid_gamepad.h"
#include "mm/paging.h"

namespace duetos::subsystems::win32
{

// SYS_GAMEPAD_STATE — rdi = slot (0..3), rsi = user pointer to a
// GamepadStateWire, rdx = sizeof(GamepadStateWire) exactly.
//
// The snapshot is assembled in a kernel-stack staging struct first
// and copied out in one CopyToUser at the end — the compositor-style
// "stage, then copy" discipline the sibling window/GDI handlers use,
// so a mid-fill user fault can never leave a half-written buffer or
// hold driver state across a #PF fix-up.
void DoGamepadState(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::input;

    const u64 slot = frame->rdi;
    const u64 user_ptr = frame->rsi;
    const u64 user_size = frame->rdx;

    if (slot >= kGamepadMaxSlots || user_ptr == 0 || user_size != sizeof(GamepadStateWire))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    GamepadStateWire wire{};
    wire.connected_mask = GamepadGetConnectedMask();

    GamepadSlotState state{};
    GamepadCapabilities caps{};
    const u32 slot_index = static_cast<u32>(slot);
    if (GamepadGetState(slot_index, &state) && GamepadGetCapabilities(slot_index, &caps))
    {
        wire.connected = 1;
        wire.packet_number = state.packet_number;
        wire.buttons = state.pad.buttons;
        wire.left_trigger = state.pad.left_trigger;
        wire.right_trigger = state.pad.right_trigger;
        wire.thumb_lx = state.pad.thumb_lx;
        wire.thumb_ly = state.pad.thumb_ly;
        wire.thumb_rx = state.pad.thumb_rx;
        wire.thumb_ry = state.pad.thumb_ry;

        wire.cap_type = caps.type;
        wire.cap_sub_type = caps.sub_type;
        wire.cap_flags = caps.flags;
        wire.cap_buttons = caps.gamepad.buttons;
        wire.cap_left_trigger = caps.gamepad.left_trigger;
        wire.cap_right_trigger = caps.gamepad.right_trigger;
        wire.cap_thumb_lx = caps.gamepad.thumb_lx;
        wire.cap_thumb_ly = caps.gamepad.thumb_ly;
        wire.cap_thumb_rx = caps.gamepad.thumb_rx;
        wire.cap_thumb_ry = caps.gamepad.thumb_ry;
        wire.cap_left_motor = caps.left_motor;
        wire.cap_right_motor = caps.right_motor;
    }

    if (!mm::CopyToUser(reinterpret_cast<void*>(user_ptr), &wire, sizeof(wire)))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
