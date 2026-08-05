#pragma once

#include "util/types.h"

/*
 * DuetOS -- HID gamepad state tracking.
 *
 * Tracks up to 4 gamepads (matching XInput's XUSER_MAX_COUNT).
 * Each slot holds a parsed gamepad state (buttons, triggers,
 * thumbsticks) updated from USB HID interrupt-IN reports, and
 * a monotonic packet counter so userland can detect changes.
 *
 * The state layout mirrors XInput's XINPUT_GAMEPAD (12 bytes)
 * for zero-copy into the userland DLL; DirectInput consumers
 * re-pack on their side.
 *
 * Threading: inject is called from the xHCI poll task (process
 * context, one poller per controller). Read is called from the
 * SYS_GAMEPAD_STATE syscall handler. Both paths are short and
 * serialised per-slot by a per-slot spinlock.
 *
 * HID report parsing: a gamepad's HID report descriptor tells
 * us where each axis and button lives in the variable-length
 * report. HidGamepadLayout holds the per-field bit offsets
 * extracted by GamepadExtractLayout(), analogous to the mouse
 * path's HidExtractMouseLayout().
 */

namespace duetos::drivers::input
{

inline constexpr u32 kGamepadMaxSlots = 4;

// Button bitmask -- same encoding as XINPUT_GAMEPAD.wButtons.
inline constexpr u16 kGamepadDpadUp = 0x0001;
inline constexpr u16 kGamepadDpadDown = 0x0002;
inline constexpr u16 kGamepadDpadLeft = 0x0004;
inline constexpr u16 kGamepadDpadRight = 0x0008;
inline constexpr u16 kGamepadStart = 0x0010;
inline constexpr u16 kGamepadBack = 0x0020;
inline constexpr u16 kGamepadLeftThumb = 0x0040;
inline constexpr u16 kGamepadRightThumb = 0x0080;
inline constexpr u16 kGamepadLeftShoulder = 0x0100;
inline constexpr u16 kGamepadRightShoulder = 0x0200;
inline constexpr u16 kGamepadA = 0x1000;
inline constexpr u16 kGamepadB = 0x2000;
inline constexpr u16 kGamepadX = 0x4000;
inline constexpr u16 kGamepadY = 0x8000;

// Gamepad state -- matches XINPUT_GAMEPAD layout (12 bytes).
struct GamepadState
{
    u16 buttons;      // bitmask of kGamepad* above
    u8 left_trigger;  // 0..255
    u8 right_trigger; // 0..255
    i16 thumb_lx;     // -32768..32767
    i16 thumb_ly;     // -32768..32767
    i16 thumb_rx;     // -32768..32767
    i16 thumb_ry;     // -32768..32767
};
static_assert(sizeof(GamepadState) == 12, "must match XINPUT_GAMEPAD");

// Full slot state returned by the syscall (matches XINPUT_STATE).
struct GamepadSlotState
{
    u32 packet_number;
    GamepadState pad;
};
static_assert(sizeof(GamepadSlotState) == 16, "must match XINPUT_STATE");

// Capabilities -- matches XINPUT_CAPABILITIES (20 bytes).
struct GamepadCapabilities
{
    u8 type;              // XINPUT_DEVTYPE_GAMEPAD = 1
    u8 sub_type;          // XINPUT_DEVSUBTYPE_GAMEPAD = 1
    u16 flags;            // XINPUT_CAPS_FFB_SUPPORTED = 1
    GamepadState gamepad; // supported-axis bitmask
    u8 left_motor;
    u8 right_motor;
    u8 pad_[2]; // align to 20
};
static_assert(sizeof(GamepadCapabilities) == 20, "must match XINPUT_CAPABILITIES");

// Per-field location in a HID report, same concept as HidMouseField
// in hid_descriptor.h.
struct GamepadReportField
{
    bool present;
    bool is_signed;
    u8 bit_size;
    u32 bit_offset; // from start of report payload
    i32 logical_min;
    i32 logical_max;
};

// Parsed gamepad report layout. Extracted from the HID report
// descriptor so the poll loop can pull named fields out of
// variable-width reports.
struct HidGamepadLayout
{
    bool valid;
    u8 report_id;         // 0 = no report-ID prefix
    u32 report_size_bits; // total payload bits

    // Axes -- Generic Desktop usages 0x30..0x35
    GamepadReportField x;  // left stick X (usage 0x30)
    GamepadReportField y;  // left stick Y (usage 0x31)
    GamepadReportField z;  // left trigger or right stick X (usage 0x32)
    GamepadReportField rz; // right stick Y or right trigger (usage 0x35)
    GamepadReportField rx; // right stick X (usage 0x33)
    GamepadReportField ry; // right stick Y (usage 0x34)

    // Hat switch -- Generic Desktop usage 0x39
    GamepadReportField hat;

    // Buttons -- Button page, 1-based usage IDs
    u32 button_offset_bits; // bit offset of button field start
    u32 button_count;       // number of button bits
};

// --- Public API (kernel-internal) ---

/// Register a gamepad in the next available slot. Returns the
/// slot index [0..3] on success, or (u32)-1 if all slots full.
/// `layout` is copied into the slot for report decoding.
u32 GamepadConnect(const HidGamepadLayout* layout);

/// Disconnect a gamepad by slot index. Clears state and marks
/// the slot as not connected.
void GamepadDisconnect(u32 slot);

/// Inject a raw HID report into a connected gamepad slot.
/// Decodes the report using the slot's stored layout and
/// bumps the packet counter. Called from the xHCI poll task.
void GamepadInjectReport(u32 slot, const u8* report, u32 len);

/// Read the current state of a gamepad slot. Returns true if
/// the slot is connected and the state was copied; false if
/// not connected. Thread-safe (serialised with InjectReport).
bool GamepadGetState(u32 slot, GamepadSlotState* out);

/// Query capabilities of a connected gamepad. Returns true if
/// connected.
bool GamepadGetCapabilities(u32 slot, GamepadCapabilities* out);

/// Get a bitmask of connected slots (bit N set = slot N connected).
u32 GamepadGetConnectedMask();

/// Extract a gamepad report layout from a HID report descriptor.
/// Returns `out->valid`. Analogous to HidExtractMouseLayout in
/// hid_descriptor.h.
bool GamepadExtractLayout(const u8* desc, u32 len, HidGamepadLayout* out);

/// Boot-time self-test. Verifies state packing, inject/read
/// round-trip, and layout extraction on a synthetic descriptor.
void GamepadSelfTest();

} // namespace duetos::drivers::input
