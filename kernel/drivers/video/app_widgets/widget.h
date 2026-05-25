#pragma once

#include "util/types.h"

/*
 * DuetOS app widget base. CRTP template provides static polymorphism
 * without virtual dispatch or RTTI. Concrete widgets derive from
 * Widget<Self> and override the *Self variants of Paint / OnEvent.
 *
 * Storage model: value semantics, no heap, no dynamic add/remove.
 * Each app's WidgetGroup is a constinit static instance with
 * compile-time-known widget composition.
 *
 * See docs/superpowers/specs/2026-05-25-duetos-pass-d-design.md.
 */

namespace duetos::drivers::video::app_widgets
{

struct Rect
{
    u32 x = 0;
    u32 y = 0;
    u32 w = 0;
    u32 h = 0;

    constexpr bool Contains(u32 px, u32 py) const
    {
        return px >= x && py >= y && px < x + w && py < y + h;
    }
};

enum class EventKind : u8
{
    MouseDown = 0,
    MouseUp = 1,
    MouseMove = 2,
    KeyDown = 3,
    KeyUp = 4,
    FocusIn = 5,
    FocusOut = 6,
};

struct Event
{
    EventKind kind = EventKind::MouseMove;
    u32 x = 0;
    u32 y = 0;
    u32 keycode = 0;
    u32 mods = 0;
};

enum class EventResult : u8
{
    NotInterested = 0,
    Consumed = 1,
};

enum class WidgetStateFlags : u8
{
    None = 0,
    Hover = 1U << 0,
    Pressed = 1U << 1,
    Focused = 1U << 2,
    Disabled = 1U << 3,
};

constexpr WidgetStateFlags operator|(WidgetStateFlags a, WidgetStateFlags b)
{
    return static_cast<WidgetStateFlags>(static_cast<u8>(a) | static_cast<u8>(b));
}

constexpr WidgetStateFlags operator&(WidgetStateFlags a, WidgetStateFlags b)
{
    return static_cast<WidgetStateFlags>(static_cast<u8>(a) & static_cast<u8>(b));
}

constexpr bool HasFlag(WidgetStateFlags flags, WidgetStateFlags test)
{
    return (static_cast<u8>(flags) & static_cast<u8>(test)) != 0;
}

struct WidgetState
{
    WidgetStateFlags flags = WidgetStateFlags::None;
};

struct Compose; // forward — concrete type lives in compositor

template <typename Self>
struct Widget
{
    Rect bounds{};
    WidgetState state{};

    constexpr void Paint(Compose& c) const
    {
        static_cast<const Self*>(this)->PaintSelf(c);
    }

    constexpr EventResult OnEvent(const Event& e)
    {
        return static_cast<Self*>(this)->OnEventSelf(e);
    }

    constexpr void PaintSelf(Compose&) const { /* derived overrides */ }
    constexpr EventResult OnEventSelf(const Event&) { return EventResult::NotInterested; }
};

} // namespace duetos::drivers::video::app_widgets
