#pragma once

#include "util/types.h"

namespace duetos::net::drsh::desktop_wire
{

inline constexpr u8 kTileBlit = 0;
inline constexpr u8 kFrameStart = 1;
inline constexpr u8 kFrameEnd = 2;
inline constexpr u8 kInputKey = 3;
inline constexpr u8 kInputMouse = 4;
inline constexpr u8 kResizeAck = 5;
inline constexpr u8 kDesktopKind = 1;

struct DesktopOpenRequest
{
    u16 width; // 0 with height=0 requests native dimensions
    u16 height;
};

struct KeyInput
{
    u16 code;
    u8 modifiers;
    bool pressed;
};

/// Decode the exact desktop InputKey payload:
///   subtype(1) | code_le(2) | modifiers(1) | pressed(1)
/// Rejects malformed lengths and non-boolean pressed values so a corrupt or
/// mismatched client cannot inject shifted fields into the keyboard queue.
inline bool DecodeKeyInput(const u8* payload, u32 length, KeyInput* out)
{
    if (payload == nullptr || out == nullptr || length != 5 || payload[0] != kInputKey || payload[4] > 1)
        return false;
    out->code = static_cast<u16>(static_cast<u16>(payload[1]) | (static_cast<u16>(payload[2]) << 8));
    out->modifiers = payload[3];
    out->pressed = payload[4] != 0;
    return true;
}

/// Desktop ChannelOpen payloads are either the legacy one-byte kind or
/// kind(1) | requested_width_be(2) | requested_height_be(2).  The latter
/// lets a controller request a bounded downscaled stream before the server
/// emits its first framebuffer, avoiding a multi-megabyte native frame.
inline bool DecodeOpenRequest(const u8* payload, u32 length, DesktopOpenRequest* out)
{
    if (payload == nullptr || out == nullptr || length < 1 || payload[0] != kDesktopKind)
        return false;
    if (length == 1)
    {
        *out = DesktopOpenRequest{};
        return true;
    }
    if (length != 5)
        return false;
    const u16 width = static_cast<u16>((static_cast<u16>(payload[1]) << 8) | payload[2]);
    const u16 height = static_cast<u16>((static_cast<u16>(payload[3]) << 8) | payload[4]);
    if (width == 0 || height == 0)
        return false;
    out->width = width;
    out->height = height;
    return true;
}

inline u32 ScaleCoordinate(u32 position, u32 output_extent, u32 source_extent)
{
    if (output_extent <= 1 || source_extent <= 1)
        return 0;
    if (position >= output_extent)
        return source_extent - 1u;
    return static_cast<u32>((static_cast<u64>(position) * (source_extent - 1u)) / (output_extent - 1u));
}

inline bool FitsWireDimensions(u32 width, u32 height)
{
    return width > 0 && height > 0 && width <= 0xFFFFu && height <= 0xFFFFu;
}

inline i8 MouseDeltaStep(i32 remaining)
{
    if (remaining > 127)
        return 127;
    if (remaining < -128)
        return -128;
    return static_cast<i8>(remaining);
}

} // namespace duetos::net::drsh::desktop_wire
