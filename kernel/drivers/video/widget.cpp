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

u32 StringPixelWidth(const char* s)
{
    if (s == nullptr)
        return 0;
    u32 n = 0;
    while (s[n] != '\0')
    {
        ++n;
    }
    return n * 8;
}

void PaintButton(const ButtonWidget& b)
{
    const u32 fill = b.pressed ? b.colour_pressed : b.colour_normal;
    FramebufferFillRect(b.x, b.y, b.w, b.h, fill);
    FramebufferDrawRect(b.x, b.y, b.w, b.h, b.colour_border, 2);
    if (b.label != nullptr)
    {
        // Centre the label inside the button. 8x8 cell metrics,
        // rounded down so odd-pixel buttons don't wiggle by a
        // pixel between normal and pressed states.
        const u32 text_w = StringPixelWidth(b.label);
        const u32 cx = (text_w < b.w) ? b.x + (b.w - text_w) / 2 : b.x + 4;
        const u32 cy = (b.h > 8) ? b.y + (b.h - 8) / 2 : b.y + 2;
        FramebufferDrawString(cx, cy, b.label, b.colour_label, fill);
    }
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

namespace
{

struct RegisteredWindow
{
    WindowChrome chrome;
    const char* title; // caller-owned string, stored by reference
    bool alive;
    u8 _pad[7];
};

constinit RegisteredWindow g_windows[kMaxWindows] = {};
constinit u32 g_window_count = 0;

// z_order[0] = bottom of stack, z_order[count-1] = topmost. All
// entries are indices into `g_windows`. We never delete windows
// in v0, so this is append-only modulo raise-to-top moves.
constinit u32 g_z_order[kMaxWindows] = {};

bool WindowValid(WindowHandle h)
{
    return h < g_window_count && g_windows[h].alive;
}

} // namespace

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

WindowHandle WindowRegister(const WindowChrome& chrome, const char* title)
{
    if (g_window_count >= kMaxWindows)
    {
        return kWindowInvalid;
    }
    const WindowHandle h = g_window_count;
    g_windows[h].chrome = chrome;
    g_windows[h].title = title;
    g_windows[h].alive = true;
    g_z_order[g_window_count] = h;
    ++g_window_count;
    return h;
}

void WindowRaise(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return;
    }
    // Find `h` in the z-order, shift everything above it down
    // by one, place `h` at the top. O(count) — fine for tiny
    // counts; a linked list would be overkill at kMaxWindows=4.
    u32 idx = 0;
    for (; idx < g_window_count; ++idx)
    {
        if (g_z_order[idx] == h)
        {
            break;
        }
    }
    if (idx == g_window_count)
    {
        return; // not in z-order — shouldn't happen for a valid handle
    }
    if (idx + 1 == g_window_count)
    {
        return; // already topmost
    }
    for (u32 j = idx; j + 1 < g_window_count; ++j)
    {
        g_z_order[j] = g_z_order[j + 1];
    }
    g_z_order[g_window_count - 1] = h;
}

void WindowMoveTo(WindowHandle h, u32 x, u32 y)
{
    if (!WindowValid(h))
    {
        return;
    }
    const auto info = FramebufferGet();
    const u32 max_x = (info.width > g_windows[h].chrome.w) ? info.width - g_windows[h].chrome.w : 0;
    const u32 max_y = (info.height > g_windows[h].chrome.h) ? info.height - g_windows[h].chrome.h : 0;
    if (x > max_x)
        x = max_x;
    if (y > max_y)
        y = max_y;
    g_windows[h].chrome.x = x;
    g_windows[h].chrome.y = y;
}

bool WindowGetBounds(WindowHandle h, u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    if (!WindowValid(h))
    {
        return false;
    }
    const auto& c = g_windows[h].chrome;
    if (x_out)
        *x_out = c.x;
    if (y_out)
        *y_out = c.y;
    if (w_out)
        *w_out = c.w;
    if (h_out)
        *h_out = c.h;
    return true;
}

WindowHandle WindowTopmostAt(u32 x, u32 y)
{
    // Walk top-down so the first match is the visually-topmost
    // window — matches what the user expects from a click.
    for (u32 i = g_window_count; i > 0; --i)
    {
        const WindowHandle h = g_z_order[i - 1];
        if (!g_windows[h].alive)
            continue;
        const auto& c = g_windows[h].chrome;
        if (x >= c.x && x < c.x + c.w && y >= c.y && y < c.y + c.h)
        {
            return h;
        }
    }
    return kWindowInvalid;
}

bool WindowPointInTitle(WindowHandle h, u32 x, u32 y)
{
    if (!WindowValid(h))
    {
        return false;
    }
    const auto& c = g_windows[h].chrome;
    const u32 tbh = (c.title_height == 0) ? 22 : c.title_height;
    return x >= c.x && x < c.x + c.w && y >= c.y && y < c.y + tbh;
}

void WindowDrawAllOrdered()
{
    for (u32 i = 0; i < g_window_count; ++i)
    {
        const WindowHandle h = g_z_order[i];
        if (!g_windows[h].alive)
            continue;
        const auto& c = g_windows[h].chrome;
        WindowDraw(c);
        // Title text. White ink on the title-bar fill, 8-px top
        // padding + 8-px left padding so the first glyph clears
        // the 2-px outer border comfortably.
        if (g_windows[h].title != nullptr)
        {
            FramebufferDrawString(c.x + 8, c.y + 7, g_windows[h].title, 0x00FFFFFF, c.colour_title);
        }
    }
}

void DesktopCompose(u32 desktop_rgb, const char* banner)
{
    FramebufferClear(desktop_rgb);
    if (banner != nullptr)
    {
        FramebufferDrawString(16, 8, banner, 0x00FFFFFF, desktop_rgb);
    }
    WindowDrawAllOrdered();
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
