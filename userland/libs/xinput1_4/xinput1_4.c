/*
 * userland/libs/xinput1_4/xinput1_4.c — DuetOS XInput 1.4 v0.
 *
 * XInput is a flat C API (no COM). Apps poll up to 4 controller slots
 * via XInputGetState; an unconnected slot returns ERROR_DEVICE_NOT_CONNECTED.
 *
 * v0 reports all four slots as not connected; capabilities/battery
 * also fail predictably. Real games gate input on the return code so
 * they handle this gracefully.
 *
 * Exports:
 *   XInputGetState, XInputSetState, XInputGetCapabilities,
 *   XInputGetBatteryInformation, XInputGetKeystroke, XInputEnable
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10280000).
 */

#include "../dx_shared.h"

/* XInput error codes — these are Win32 error DWORDs, not HRESULTs. */
#define ERROR_SUCCESS_ 0u
#define ERROR_DEVICE_NOT_CONNECTED_ 1167u
#define ERROR_NOT_SUPPORTED_ 50u

/* XINPUT_STATE = { DWORD dwPacketNumber; XINPUT_GAMEPAD Gamepad; }
 * XINPUT_GAMEPAD = { WORD wButtons, BYTE bLeftTrigger, bRightTrigger,
 *                    SHORT sThumbLX,LY,RX,RY }  = 12 bytes
 * Total: 16 bytes. Zero-fill is safe (means no input). */

__declspec(dllexport) DWORD XInputGetState(DWORD user_index, void* state)
{
    dx_gfx_trace(6);
    if (state)
        dx_memzero(state, 16);
    if (user_index >= 4)
        return ERROR_DEVICE_NOT_CONNECTED_;
    return ERROR_DEVICE_NOT_CONNECTED_;
}

__declspec(dllexport) DWORD XInputSetState(DWORD user_index, void* vibration)
{
    (void)vibration;
    if (user_index >= 4)
        return ERROR_DEVICE_NOT_CONNECTED_;
    return ERROR_DEVICE_NOT_CONNECTED_;
}

/* XINPUT_CAPABILITIES = 20 bytes (Type, SubType, Flags, Gamepad, Vibration) */
__declspec(dllexport) DWORD XInputGetCapabilities(DWORD user_index, DWORD flags, void* caps)
{
    (void)flags;
    if (caps)
        dx_memzero(caps, 20);
    if (user_index >= 4)
        return ERROR_DEVICE_NOT_CONNECTED_;
    return ERROR_DEVICE_NOT_CONNECTED_;
}

/* XINPUT_BATTERY_INFORMATION = { BYTE BatteryType; BYTE BatteryLevel; } */
__declspec(dllexport) DWORD XInputGetBatteryInformation(DWORD user_index, BYTE dev_type, void* battery)
{
    (void)dev_type;
    if (battery)
        dx_memzero(battery, 2);
    if (user_index >= 4)
        return ERROR_DEVICE_NOT_CONNECTED_;
    return ERROR_DEVICE_NOT_CONNECTED_;
}

/* XINPUT_KEYSTROKE = 8 bytes */
__declspec(dllexport) DWORD XInputGetKeystroke(DWORD user_index, DWORD reserved, void* keystroke)
{
    (void)reserved;
    if (keystroke)
        dx_memzero(keystroke, 8);
    if (user_index >= 4)
        return ERROR_DEVICE_NOT_CONNECTED_;
    return ERROR_DEVICE_NOT_CONNECTED_;
}

/* XInputEnable returns void; just toggles XInput's internal "ignore
 * input" flag. v0 has nothing to do. */
__declspec(dllexport) void XInputEnable(BOOL enable)
{
    (void)enable;
}
