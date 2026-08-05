/*
 * userland/libs/xinput1_4/xinput_wire.h
 *
 * Userland twin of the DuetOS SYS_GAMEPAD_STATE (syscall 230) wire
 * struct. The kernel twin lives in kernel/subsystems/win32/
 * input_syscall.h; the two layouts are pinned against each other by
 * tests/host/test_xinput_wire.cpp. Changing the layout requires a
 * new wire version with a new size — the kernel rejects any rdx
 * that is not exactly DUET_XINPUT_WIRE_SIZE.
 *
 * Freestanding: <stdint.h> only, byte-loop zeroing, no libc. The
 * mapping helpers are pure functions so the host test can pin the
 * wire -> XINPUT_* translation without booting a kernel.
 */

#ifndef DUETOS_XINPUT_WIRE_H
#define DUETOS_XINPUT_WIRE_H

#include <stdint.h>

#define DUET_XINPUT_MAX_SLOTS 4u
#define DUET_XINPUT_WIRE_SIZE 44u
#define DUET_XINPUT_ERROR_SUCCESS 0u
#define DUET_XINPUT_ERROR_DEVICE_NOT_CONNECTED 1167u

#if defined(__cplusplus)
#define DUET_XINPUT_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define DUET_XINPUT_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

/* XINPUT_GAMEPAD image (12 bytes). */
typedef struct DuetXInputGamepad
{
    uint16_t wButtons;
    uint8_t bLeftTrigger;
    uint8_t bRightTrigger;
    int16_t sThumbLX;
    int16_t sThumbLY;
    int16_t sThumbRX;
    int16_t sThumbRY;
} DuetXInputGamepad;
DUET_XINPUT_STATIC_ASSERT(sizeof(DuetXInputGamepad) == 12, "must match XINPUT_GAMEPAD");

/* XINPUT_STATE image (16 bytes). */
typedef struct DuetXInputState
{
    uint32_t dwPacketNumber;
    DuetXInputGamepad Gamepad;
} DuetXInputState;
DUET_XINPUT_STATIC_ASSERT(sizeof(DuetXInputState) == 16, "must match XINPUT_STATE");

/* XINPUT_VIBRATION image (4 bytes). */
typedef struct DuetXInputVibration
{
    uint16_t wLeftMotorSpeed;
    uint16_t wRightMotorSpeed;
} DuetXInputVibration;
DUET_XINPUT_STATIC_ASSERT(sizeof(DuetXInputVibration) == 4, "must match XINPUT_VIBRATION");

/* XINPUT_CAPABILITIES image (20 bytes). */
typedef struct DuetXInputCapabilities
{
    uint8_t Type;
    uint8_t SubType;
    uint16_t Flags;
    DuetXInputGamepad Gamepad;
    DuetXInputVibration Vibration;
} DuetXInputCapabilities;
DUET_XINPUT_STATIC_ASSERT(sizeof(DuetXInputCapabilities) == 20, "must match XINPUT_CAPABILITIES");

/* SYS_GAMEPAD_STATE wire snapshot (44 bytes) — kernel-owned layout. */
typedef struct DuetGamepadWire
{
    uint32_t connected;      /* 1 = queried slot has a gamepad attached */
    uint32_t connected_mask; /* bit N set = slot N connected */

    /* XINPUT_STATE image for the queried slot. */
    uint32_t packet_number;
    uint16_t buttons;
    uint8_t left_trigger;
    uint8_t right_trigger;
    int16_t thumb_lx;
    int16_t thumb_ly;
    int16_t thumb_rx;
    int16_t thumb_ry;

    /* XINPUT_CAPABILITIES image for the queried slot. */
    uint8_t cap_type;
    uint8_t cap_sub_type;
    uint16_t cap_flags;
    uint16_t cap_buttons;
    uint8_t cap_left_trigger;
    uint8_t cap_right_trigger;
    int16_t cap_thumb_lx;
    int16_t cap_thumb_ly;
    int16_t cap_thumb_rx;
    int16_t cap_thumb_ry;
    uint8_t cap_left_motor;
    uint8_t cap_right_motor;
    uint16_t reserved; /* always 0 */
} DuetGamepadWire;
DUET_XINPUT_STATIC_ASSERT(sizeof(DuetGamepadWire) == DUET_XINPUT_WIRE_SIZE, "SYS_GAMEPAD_STATE wire ABI is 44 bytes");

static inline void duet_xinput_zero_(void* p, uint32_t n)
{
    uint8_t* d = (uint8_t*)p;
    for (uint32_t i = 0; i < n; ++i)
        d[i] = 0;
}

/* wire -> XINPUT_STATE. Zeroes *out first; a disconnected slot maps
 * to ERROR_DEVICE_NOT_CONNECTED with a zeroed state. */
static inline uint32_t duet_xinput_wire_to_state(const DuetGamepadWire* w, DuetXInputState* out)
{
    if (!out)
        return DUET_XINPUT_ERROR_DEVICE_NOT_CONNECTED;
    duet_xinput_zero_(out, (uint32_t)sizeof(*out));
    if (!w || w->connected == 0)
        return DUET_XINPUT_ERROR_DEVICE_NOT_CONNECTED;

    out->dwPacketNumber = w->packet_number;
    out->Gamepad.wButtons = w->buttons;
    out->Gamepad.bLeftTrigger = w->left_trigger;
    out->Gamepad.bRightTrigger = w->right_trigger;
    out->Gamepad.sThumbLX = w->thumb_lx;
    out->Gamepad.sThumbLY = w->thumb_ly;
    out->Gamepad.sThumbRX = w->thumb_rx;
    out->Gamepad.sThumbRY = w->thumb_ry;
    return DUET_XINPUT_ERROR_SUCCESS;
}

/* wire -> XINPUT_CAPABILITIES. The kernel reports motor strengths as
 * 8-bit values; XInput speaks 16-bit, so scale 0..255 -> 0..65535
 * (x * 257 maps 0xFF to exactly 0xFFFF). */
static inline uint32_t duet_xinput_wire_to_capabilities(const DuetGamepadWire* w, DuetXInputCapabilities* out)
{
    if (!out)
        return DUET_XINPUT_ERROR_DEVICE_NOT_CONNECTED;
    duet_xinput_zero_(out, (uint32_t)sizeof(*out));
    if (!w || w->connected == 0)
        return DUET_XINPUT_ERROR_DEVICE_NOT_CONNECTED;

    out->Type = w->cap_type;
    out->SubType = w->cap_sub_type;
    out->Flags = w->cap_flags;
    out->Gamepad.wButtons = w->cap_buttons;
    out->Gamepad.bLeftTrigger = w->cap_left_trigger;
    out->Gamepad.bRightTrigger = w->cap_right_trigger;
    out->Gamepad.sThumbLX = w->cap_thumb_lx;
    out->Gamepad.sThumbLY = w->cap_thumb_ly;
    out->Gamepad.sThumbRX = w->cap_thumb_rx;
    out->Gamepad.sThumbRY = w->cap_thumb_ry;
    out->Vibration.wLeftMotorSpeed = (uint16_t)((uint16_t)w->cap_left_motor * 257u);
    out->Vibration.wRightMotorSpeed = (uint16_t)((uint16_t)w->cap_right_motor * 257u);
    return DUET_XINPUT_ERROR_SUCCESS;
}

#endif /* DUETOS_XINPUT_WIRE_H */
