#include "widget.h"

#include "../../drivers/input/ps2mouse.h"
#include "cursor.h"
#include "framebuffer.h"

namespace customos::drivers::video
{

namespace
{

// Widget table. Flat array sized for boot-time widgets; grows to
// a dynamic structure once there are more than a handful on
// screen. Seven is enough for a v0 demo (one clickable button +
// room to spare).
constexpr u32 kMaxWidgets = 8;
constinit ButtonWidget g_widgets[kMaxWidgets] = {};
constinit u32 g_widget_count = 0;

// Previous left-button state for edge detection. PS/2 mouse
// packets report absolute button state, not press / release
// events — the router has to diff against the prior sample.
constinit bool g_prev_left_down = false;

bool PointInButton(const ButtonWidget& b, u32 x, u32 y)
{
    return x >= b.x && x < b.x + b.w && y >= b.y && y < b.y + b.h;
}

void PaintButton(const ButtonWidget& b)
{
    const u32 fill = b.pressed ? b.colour_pressed : b.colour_normal;
    FramebufferFillRect(b.x, b.y, b.w, b.h, fill);
    FramebufferDrawRect(b.x, b.y, b.w, b.h, b.colour_border, 2);
}

} // namespace

bool WidgetRegisterButton(const ButtonWidget& button)
{
    if (g_widget_count >= kMaxWidgets)
    {
        return false;
    }
    g_widgets[g_widget_count] = button;
    g_widgets[g_widget_count].pressed = false;
    ++g_widget_count;
    return true;
}

void WidgetDrawAll()
{
    for (u32 i = 0; i < g_widget_count; ++i)
    {
        PaintButton(g_widgets[i]);
    }
}

u32 WidgetRouteMouse(u32 cursor_x, u32 cursor_y, u8 button_mask)
{
    const bool left_down = (button_mask & drivers::input::kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_prev_left_down;
    const bool release_edge = !left_down && g_prev_left_down;
    g_prev_left_down = left_down;

    // Visual state transitions only happen on button edges; pure
    // motion over a widget doesn't repaint (no hover state yet).
    // This keeps redraws cheap and avoids flicker when dragging
    // the cursor across the widget with no button held.
    if (!press_edge && !release_edge)
    {
        return kWidgetInvalid;
    }

    for (u32 i = 0; i < g_widget_count; ++i)
    {
        ButtonWidget& b = g_widgets[i];
        if (press_edge && PointInButton(b, cursor_x, cursor_y) && !b.pressed)
        {
            b.pressed = true;
            CursorHide();
            PaintButton(b);
            CursorShow();
            return b.id;
        }
        if (release_edge && b.pressed)
        {
            // Release always clears the pressed visual, even if
            // the cursor has moved off the widget since press —
            // matches standard button semantics. A future
            // "cancellable drag" widget would diverge here.
            b.pressed = false;
            CursorHide();
            PaintButton(b);
            CursorShow();
            return b.id;
        }
    }
    return kWidgetInvalid;
}

} // namespace customos::drivers::video
