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

void WindowDraw(const WindowChrome& w)
{
    if (w.w == 0 || w.h == 0)
    {
        return;
    }

    // Client area first — the title bar draw below overwrites
    // the top strip. Painting the whole client-area colour up
    // front avoids a branch-per-row "am I inside the title?"
    // pattern.
    FramebufferFillRect(w.x, w.y, w.w, w.h, w.colour_client);

    // Title bar.
    const u32 tbh = (w.title_height == 0) ? 22 : w.title_height;
    const u32 tbh_eff = (tbh > w.h) ? w.h : tbh;
    FramebufferFillRect(w.x, w.y, w.w, tbh_eff, w.colour_title);

    // Outer border — 2-pixel dark frame over the whole window.
    FramebufferDrawRect(w.x, w.y, w.w, w.h, w.colour_border, 2);

    // Title / client divider — 1-pixel line where the title
    // bar ends. Helps the eye separate chrome from content.
    if (tbh_eff + 2 <= w.h)
    {
        FramebufferFillRect(w.x + 2, w.y + tbh_eff, w.w - 4, 1, w.colour_border);
    }

    // Close-button-ish square near top-right. Sized to fit
    // inside the title bar with 4px padding on top/bottom.
    const u32 btn_pad = 4;
    if (tbh_eff > 2 * btn_pad + 4 && w.w > tbh_eff)
    {
        const u32 btn_side = tbh_eff - 2 * btn_pad;
        const u32 btn_x = w.x + w.w - btn_side - btn_pad;
        const u32 btn_y = w.y + btn_pad;
        FramebufferFillRect(btn_x, btn_y, btn_side, btn_side, w.colour_close_btn);
        FramebufferDrawRect(btn_x, btn_y, btn_side, btn_side, w.colour_border, 1);
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
