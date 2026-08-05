/*
 * userland/libs/xinput1_4/xinput1_4.c — DuetOS XInput 1.4.
 *
 * XInput is a flat C API (no COM). Apps poll up to 4 controller slots
 * via XInputGetState; an unconnected slot returns
 * ERROR_DEVICE_NOT_CONNECTED.
 *
 * State and capabilities are real: each call issues SYS_GAMEPAD_STATE
 * (230) with a slot index and receives a kernel snapshot of the HID
 * gamepad driver's slot (kernel/drivers/input/hid_gamepad.h) as a
 * DuetGamepadWire (xinput_wire.h). The DLL never hands the kernel raw
 * report data — the kernel is the only writer of gamepad state.
 *
 * Exports:
 *   XInputGetState, XInputSetState, XInputGetCapabilities,
 *   XInputGetBatteryInformation, XInputGetKeystroke, XInputEnable
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10280000).
 */

#include "../dx_shared.h"
#include "xinput_wire.h"

#define ERROR_SUCCESS_ 0u
#define ERROR_DEVICE_NOT_CONNECTED_ 1167u
#define ERROR_EMPTY_ 4306u

/* XINPUT_BATTERY_INFORMATION values. */
#define BATTERY_TYPE_WIRED_ 0x01u
#define BATTERY_LEVEL_FULL_ 0x03u

/* SYS_GAMEPAD_STATE = 230 — rdi = slot, rsi = wire ptr, rdx = wire
 * size. Returns 0 on success, -1 on bad slot / size / missing
 * kCapInput. */
static inline long long xi_gamepad_wire(DWORD user_index, DuetGamepadWire* wire)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)230), "D"((long long)user_index), "S"((long long)(unsigned long long)wire),
                       "d"((long long)sizeof(DuetGamepadWire))
                     : "memory");
    return rv;
}

/* Fetch the wire snapshot for a slot. Returns 1 when the syscall
 * succeeded AND the slot is connected; 0 otherwise (wire zeroed on
 * syscall failure so callers can still read connected == 0). */
static int xi_query(DWORD user_index, DuetGamepadWire* wire)
{
    dx_memzero(wire, sizeof(*wire));
    if (user_index >= DUET_XINPUT_MAX_SLOTS)
        return 0;
    if (xi_gamepad_wire(user_index, wire) != 0)
        return 0;
    return wire->connected != 0;
}

__declspec(dllexport) DWORD XInputGetState(DWORD user_index, void* state)
{
    dx_gfx_trace(6);
    DuetGamepadWire wire;
    xi_query(user_index, &wire);
    return duet_xinput_wire_to_state(&wire, (DuetXInputState*)state);
}

__declspec(dllexport) DWORD XInputGetCapabilities(DWORD user_index, DWORD flags, void* caps)
{
    (void)flags; /* XINPUT_FLAG_GAMEPAD filter — every DuetOS slot is a gamepad */
    DuetGamepadWire wire;
    xi_query(user_index, &wire);
    return duet_xinput_wire_to_capabilities(&wire, (DuetXInputCapabilities*)caps);
}

__declspec(dllexport) DWORD XInputSetState(DWORD user_index, void* vibration)
{
    (void)vibration;
    DuetGamepadWire wire;
    if (!xi_query(user_index, &wire))
        return ERROR_DEVICE_NOT_CONNECTED_;
    // STUB: no rumble output path — the HID driver has no interrupt-OUT
    // report writer yet, so the vibration request is accepted and dropped.
    return ERROR_SUCCESS_;
}

/* XINPUT_BATTERY_INFORMATION = { BYTE BatteryType; BYTE BatteryLevel; } */
__declspec(dllexport) DWORD XInputGetBatteryInformation(DWORD user_index, BYTE dev_type, void* battery)
{
    (void)dev_type;
    if (battery)
        dx_memzero(battery, 2);
    DuetGamepadWire wire;
    if (!xi_query(user_index, &wire))
        return ERROR_DEVICE_NOT_CONNECTED_;
    // GAP: USB HID gamepads are reported as wired/full — no battery
    // level plumbing in the HID driver. Revisit with wireless receivers.
    if (battery)
    {
        ((BYTE*)battery)[0] = (BYTE)BATTERY_TYPE_WIRED_;
        ((BYTE*)battery)[1] = (BYTE)BATTERY_LEVEL_FULL_;
    }
    return ERROR_SUCCESS_;
}

/* XINPUT_KEYSTROKE = 8 bytes */
__declspec(dllexport) DWORD XInputGetKeystroke(DWORD user_index, DWORD reserved, void* keystroke)
{
    (void)reserved;
    if (keystroke)
        dx_memzero(keystroke, 8);
    DuetGamepadWire wire;
    if (!xi_query(user_index, &wire))
        return ERROR_DEVICE_NOT_CONNECTED_;
    // GAP: no VK_PAD_* keystroke queue — connected pads report "no
    // keystroke pending". Revisit if a game polls keystrokes for menus.
    return ERROR_EMPTY_;
}

/* XInputEnable returns void; toggles XInput's internal "ignore input"
 * flag. */
__declspec(dllexport) void XInputEnable(BOOL enable)
{
    // GAP: the enable=FALSE "mute input while unfocused" latch is not
    // tracked — state reads stay live. Revisit when focus loss matters.
    (void)enable;
}
