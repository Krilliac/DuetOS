#include "widget.h"

#include "../../drivers/input/ps2mouse.h"
#include "../../sched/sched.h"
#include "console.h"
#include "cursor.h"
#include "framebuffer.h"
#include "taskbar.h"

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

// Resolve a button's effective absolute bounds. When the button
// has an owning window, its stored (x, y) are offsets into that
// window; otherwise they're absolute framebuffer coordinates.
// Returns false if the button has a dead owner — caller should
// skip paint + hit-test.
bool EffectiveButtonPos(const ButtonWidget& b, u32* ax, u32* ay)
{
    if (b.owner == kWindowInvalid)
    {
        *ax = b.x;
        *ay = b.y;
        return true;
    }
    u32 wx = 0, wy = 0;
    if (!WindowGetBounds(b.owner, &wx, &wy, nullptr, nullptr))
    {
        return false;
    }
    *ax = wx + b.x;
    *ay = wy + b.y;
    return true;
}

bool PointInButton(const ButtonWidget& b, u32 x, u32 y)
{
    u32 bx = 0, by = 0;
    if (!EffectiveButtonPos(b, &bx, &by))
    {
        return false;
    }
    if (x < bx || x >= bx + b.w || y < by || y >= by + b.h)
    {
        return false;
    }
    // Window-local widgets only fire when their owner is the
    // topmost window at the click point. Stops a click that
    // visually lands on a foreground window from waking a
    // button that's hidden under that window.
    if (b.owner != kWindowInvalid)
    {
        if (WindowTopmostAt(x, y) != b.owner)
        {
            return false;
        }
    }
    return true;
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
    u32 bx = 0, by = 0;
    if (!EffectiveButtonPos(b, &bx, &by))
    {
        return; // dead owner window — skip silently
    }
    const u32 fill = b.pressed ? b.colour_pressed : b.colour_normal;
    FramebufferFillRect(bx, by, b.w, b.h, fill);
    FramebufferDrawRect(bx, by, b.w, b.h, b.colour_border, 2);
    if (b.label != nullptr)
    {
        // Centre the label inside the button. 8x8 cell metrics,
        // rounded down so odd-pixel buttons don't wiggle by a
        // pixel between normal and pressed states.
        const u32 text_w = StringPixelWidth(b.label);
        const u32 cx = (text_w < b.w) ? bx + (b.w - text_w) / 2 : bx + 4;
        const u32 cy = (b.h > 8) ? by + (b.h - 8) / 2 : by + 2;
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

// Single compositor mutex guarding every UI-side mutable: cursor
// backing, window registry, widget table, console buffer, and
// framebuffer writes. The mouse reader (drag + widget events)
// and keyboard reader (typing into the console) both acquire it
// before any Cursor* / Window* / Widget* / DesktopCompose call,
// so concurrent typing-while-dragging is race-free.
constinit customos::sched::Mutex g_compositor_mutex{};

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

bool WindowPointInCloseBox(WindowHandle h, u32 x, u32 y)
{
    if (!WindowValid(h))
    {
        return false;
    }
    const auto& c = g_windows[h].chrome;
    const u32 tbh = (c.title_height == 0) ? 22 : c.title_height;
    const u32 tbh_eff = (tbh > c.h) ? c.h : tbh;
    const u32 btn_pad = 4;
    if (tbh_eff <= 2 * btn_pad + 4 || c.w <= tbh_eff)
    {
        return false; // title bar too short for a visible close box
    }
    const u32 btn_side = tbh_eff - 2 * btn_pad;
    const u32 btn_x = c.x + c.w - btn_side - btn_pad;
    const u32 btn_y = c.y + btn_pad;
    return x >= btn_x && x < btn_x + btn_side && y >= btn_y && y < btn_y + btn_side;
}

void WindowClose(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].alive = false;
    // Leave entry in z_order — WindowDrawAllOrdered already
    // skips dead windows via the `alive` check, and compacting
    // the z-order would require touching every index stored in
    // any drag state elsewhere. Slot is "leaked" in the sense
    // that it can't be re-registered; v0 doesn't need to.
}

u32 WindowRegistryCount()
{
    return g_window_count;
}

bool WindowIsAlive(WindowHandle h)
{
    return WindowValid(h);
}

const char* WindowTitle(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return nullptr;
    }
    return g_windows[h].title;
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
        // Widgets owned by this window — layered on top of the
        // window's chrome, under any windows that stack above.
        for (u32 j = 0; j < g_widget_count; ++j)
        {
            if (g_widgets[j].owner == h)
            {
                PaintButton(g_widgets[j]);
            }
        }
    }
}

void CompositorLock()
{
    customos::sched::MutexLock(&g_compositor_mutex);
}

void CompositorUnlock()
{
    customos::sched::MutexUnlock(&g_compositor_mutex);
}

void DesktopCompose(u32 desktop_rgb, const char* banner)
{
    // Paint stack (bottom to top):
    //   1. Desktop fill
    //   2. Banner string across the top
    //   3. Framebuffer console area (under windows — windows
    //      dragged over the console occlude it, which restores
    //      when the window moves away — standard z-order feel)
    //   4. Windows in z-order
    //   5. Widgets (buttons float on top of windows for v0)
    // The cursor is not touched here — the mouse reader owns
    // CursorHide / CursorShow around this call.
    FramebufferClear(desktop_rgb);
    ConsoleRedraw();
    WindowDrawAllOrdered(); // windows + their owned widgets together in z-order
    // Freestanding widgets float on top of windows.
    for (u32 i = 0; i < g_widget_count; ++i)
    {
        if (g_widgets[i].owner == kWindowInvalid)
        {
            PaintButton(g_widgets[i]);
        }
    }
    // Taskbar is painted last so it always sits on top — matches
    // every desktop OS. The banner, if supplied, renders on the
    // desktop only in regions the taskbar doesn't cover.
    if (banner != nullptr)
    {
        FramebufferDrawString(16, 8, banner, 0x00FFFFFF, desktop_rgb);
    }
    TaskbarRedraw();
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
