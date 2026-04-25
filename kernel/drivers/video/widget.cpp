/*
 * DuetOS — desktop UI widget toolkit: implementation.
 *
 * Companion to widget.h — see there for the widget tree shape,
 * the per-widget vtable (paint / hit-test / handle-event), and
 * the catalog of built-in widgets.
 *
 * WHAT
 *   Owns every native (non-Win32-PE) UI element the desktop
 *   draws: taskbar, start menu, network flyout, file manager,
 *   notes app, calendar, clock app, calculator, theme picker,
 *   pentest GUI, login screen widgets, etc. Each widget is
 *   a struct + a vtable pointer; the compositor walks the
 *   widget tree once per frame and asks each visible widget
 *   to paint itself.
 *
 * HOW
 *   Widget tree is rooted in the desktop singleton. Layout is
 *   manual (no flex / constraint solver) — each widget knows
 *   its own absolute rect and updates it on parent-resize.
 *   Input dispatch: mouse events hit-test top-down, keyboard
 *   events go to the focused widget.
 *
 *   Theme state (colours, font metrics) is read from the
 *   theme singleton (drivers/video/theme.h) so a single
 *   `theme dark` shell command repaints every widget without
 *   per-widget knowledge.
 *
 * WHY THIS FILE IS LARGE
 *   ~30 distinct widget types, each with paint + event +
 *   layout code. Splitting per-widget would scatter the
 *   tree-walk and the theme-bind plumbing; for now they share
 *   a TU and section banners group related widgets together.
 */

#include "widget.h"

#include "../../arch/x86_64/cpu.h"
#include "../../drivers/input/ps2mouse.h"
#include "../../sched/sched.h"
#include "calendar.h"
#include "console.h"
#include "cursor.h"
#include "framebuffer.h"
#include "menu.h"
#include "netpanel.h"
#include "taskbar.h"

namespace duetos::drivers::video
{

namespace
{

// Widget table. Flat array sized for boot-time widgets; grows to
// a dynamic structure once there are more than a handful on
// screen. 32 accommodates the Calculator app's 4x4 keypad
// (16 buttons) plus reserve for another app of similar size.
constexpr u32 kMaxWidgets = 32;
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

struct WindowMsgRing
{
    WindowMsg buf[kWinMsgQueueDepth];
    u32 head; // next read
    u32 tail; // next write
    u32 count;
};

struct RegisteredWindow
{
    WindowChrome chrome;
    // Title pointer always points at `mut_title` on this same
    // struct (register-time copy from the caller's string);
    // SetWindowText overwrites the buffer in place so the
    // pointer stays stable.
    const char* title;
    char mut_title[kWindowTitleStorage];
    WindowContentFn content_fn; // nullable per-window content drawer
    void* content_cookie;
    u64 owner_pid; // 0 = kernel-owned boot window, >0 = ring-3 pid
    WindowMsgRing msgs;
    WinGdiPrim prims[kWinDisplayListDepth];
    u32 prim_count;
    u8 blit_pool[kWinBlitPoolBytes];
    u32 blit_pool_used; // bytes consumed since the last list reset
    // Per-window Win32 longs — backs SetWindowLongPtr /
    // GetWindowLongPtr for GWLP_WNDPROC, GWLP_USERDATA, and
    // two extras.
    u64 longs[kWinLongSlots];
    WindowHandle parent; // kWindowInvalid if top-level
    bool alive;
    bool visible;
    bool dirty; // set by InvalidateRect; cleared by BeginPaint / WindowDrainPaints
    u8 _pad[5];
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
constinit duetos::sched::Mutex g_compositor_mutex{};

// Global message wait queue. Any task blocked in
// SYS_WIN_GET_MSG parks here until PostMessage (or an input
// router) calls WindowMsgWakeAll. Single queue is sufficient
// for v1 — one wake broadcast per post, each blocker re-checks
// its own per-window ring. Upgrades to per-process queues when
// a workload has many concurrent message pumps.
constinit duetos::sched::WaitQueue g_msg_wq{};

// Async keyboard state — 1 bit per VK code. The kbd-reader
// toggles bits on every press/release edge before dispatching
// the event; `WindowKeyIsDown` reads the bit. Covers both raw
// ASCII chars (0x20..0x7E) and extended codes (arrows, F-keys)
// up to 255. Kernel apps don't need this — they consume events
// from the ring directly — so this table is effectively a Win32
// compat shim.
constinit u8 g_vk_state[kWindowVkStateSize / 8] = {};

// Mouse capture — one system-wide HWND that gets all mouse
// events regardless of cursor position, or kWindowInvalid when
// no capture is active.
constinit WindowHandle g_mouse_capture = kWindowInvalid;

// Keyboard focus — distinct from `g_active_window` (z-order
// topmost). Programs that want to steal input focus without
// raising to top use SetFocus vs SetActiveWindow.
constinit WindowHandle g_focus_hwnd = kWindowInvalid;

// Caret — a single global blinking rectangle. The compositor
// paints it at every DesktopCompose; the ui-ticker's 1 Hz
// compose flips `g_caret_on` between compositions to produce
// the blink.
constinit Caret g_caret = {};
constinit bool g_caret_on = false; // current blink phase

// Text clipboard — CF_TEXT only for v1. Not split per-process:
// matches Win32 in that the clipboard is a system singleton.
constinit char g_clipboard[kWindowClipboardMax] = {};
constinit u32 g_clipboard_len = 0;

// Per-process timer table. `remaining_ticks` counts down each
// scheduler tick; on zero, a WM_TIMER is posted to `hwnd` with
// wParam = timer_id, and `remaining_ticks` is reset to
// `interval_ticks`. 32 slots is enough for many simultaneous
// SetTimer callers — upgrade to a dynamic table when needed.
struct WindowTimerSlot
{
    bool in_use;
    u8 _pad[3];
    u32 timer_id;
    u64 owner_pid;
    WindowHandle hwnd;
    u32 interval_ticks;
    u32 remaining_ticks;
};
constinit WindowTimerSlot g_timers[kWindowTimersMax] = {};

// Currently-active (focused) window — the one with the brightly
// painted title bar. Follows the topmost z-order slot: WindowRaise
// sets it; WindowClose may clear it. kWindowInvalid when no
// window is active.
constinit WindowHandle g_active_window = kWindowInvalid;

// Boot-mode state. Desktop == full shell; TTY == fullscreen
// console only. Kept in widget.cpp because DesktopCompose is the
// one place that needs it, and the toggle path is a single
// function — a dedicated compositor module would be over-
// engineering at v0 scale.
constinit DisplayMode g_display_mode = DisplayMode::Desktop;

// Muted colour used for inactive windows' title bars. Chosen
// slightly darker + desaturated versus any window's own
// `colour_title`, so the active/inactive distinction reads at a
// glance without having to match each window's palette.
constexpr u32 kInactiveTitleRgb = 0x00506070;

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

namespace
{
// Sanitise + bounded-copy an ASCII title into a window's stable
// storage slot. Non-ASCII bytes become '?'. Result is always
// NUL-terminated.
void StoreTitle(RegisteredWindow& w, const char* src)
{
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < kWindowTitleStorage && src[i] != '\0'; ++i)
        {
            const char c = src[i];
            w.mut_title[i] = (c >= 0x20 && c < 0x7F) ? c : '?';
        }
    }
    w.mut_title[i] = '\0';
    w.title = w.mut_title;
}
} // namespace

WindowHandle WindowRegister(const WindowChrome& chrome, const char* title)
{
    if (g_window_count >= kMaxWindows)
    {
        return kWindowInvalid;
    }
    const WindowHandle h = g_window_count;
    g_windows[h].chrome = chrome;
    StoreTitle(g_windows[h], title);
    g_windows[h].alive = true;
    g_windows[h].visible = true;
    g_windows[h].dirty = false;
    g_windows[h].owner_pid = 0;
    g_windows[h].parent = kWindowInvalid;
    g_windows[h].msgs.head = 0;
    g_windows[h].msgs.tail = 0;
    g_windows[h].msgs.count = 0;
    g_windows[h].prim_count = 0;
    g_windows[h].blit_pool_used = 0;
    g_windows[h].content_fn = nullptr;
    g_windows[h].content_cookie = nullptr;
    for (u32 i = 0; i < kWinLongSlots; ++i)
    {
        g_windows[h].longs[i] = 0;
    }
    g_z_order[g_window_count] = h;
    ++g_window_count;
    // The latest-registered window lands on top of z-order and
    // is the obvious "just appeared" active choice. Boot-time
    // registration ends with the last window active, which is
    // what every user expects.
    g_active_window = h;
    return h;
}

void WindowRaise(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return;
    }
    // Activation tracks the raise even when the window is
    // already topmost — a click on the single-window desktop
    // still confirms focus.
    g_active_window = h;
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

WindowHandle WindowActive()
{
    return g_active_window;
}

void WindowCycleActive()
{
    // Find the handle of the currently-active window in z-order,
    // then walk forward (wrapping) until we hit a different alive
    // window. Raise it. Handles the 0- and 1-window corner cases
    // inside the loop: the first pass that finds the active
    // window tries to bump to the next, and the wrap detects
    // "no other alive windows."
    if (g_window_count == 0)
    {
        return;
    }
    // Locate the active window's index in z_order (search from
    // the top since that's where it lives).
    u32 active_idx = g_window_count;
    for (u32 i = 0; i < g_window_count; ++i)
    {
        if (g_z_order[i] == g_active_window)
        {
            active_idx = i;
            break;
        }
    }
    // Start the search one past the active slot (wrap). Walk up
    // to kMaxWindows steps; bail out if nothing else is alive.
    const u32 start = (active_idx + 1) % g_window_count;
    for (u32 step = 0; step < g_window_count; ++step)
    {
        const u32 idx = (start + step) % g_window_count;
        const WindowHandle candidate = g_z_order[idx];
        if (candidate != g_active_window && WindowValid(candidate))
        {
            WindowRaise(candidate);
            return;
        }
    }
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

void WindowSetColours(WindowHandle h, u32 border_rgb, u32 title_rgb, u32 client_rgb, u32 close_rgb)
{
    if (!WindowValid(h))
    {
        return;
    }
    auto& c = g_windows[h].chrome;
    c.colour_border = border_rgb;
    c.colour_title = title_rgb;
    c.colour_client = client_rgb;
    c.colour_close_btn = close_rgb;
}

WindowHandle WindowTopmostAt(u32 x, u32 y)
{
    // Walk top-down so the first match is the visually-topmost
    // window — matches what the user expects from a click.
    for (u32 i = g_window_count; i > 0; --i)
    {
        const WindowHandle h = g_z_order[i - 1];
        if (!g_windows[h].alive || !g_windows[h].visible)
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
    if (g_active_window == h)
    {
        // Promote the next topmost alive window, if any, so
        // activation doesn't dangle on a dead handle.
        g_active_window = kWindowInvalid;
        for (u32 i = g_window_count; i > 0; --i)
        {
            const WindowHandle candidate = g_z_order[i - 1];
            if (candidate != h && WindowValid(candidate))
            {
                g_active_window = candidate;
                break;
            }
        }
    }
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

void WindowSetContentDraw(WindowHandle h, WindowContentFn fn, void* cookie)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].content_fn = fn;
    g_windows[h].content_cookie = cookie;
}

void WindowDrawAllOrdered()
{
    for (u32 i = 0; i < g_window_count; ++i)
    {
        const WindowHandle h = g_z_order[i];
        if (!g_windows[h].alive || !g_windows[h].visible)
            continue;
        const bool is_active = (h == g_active_window);
        // Use the window's registered title colour when active,
        // a muted global grey otherwise. Copying the chrome
        // struct keeps WindowDraw's signature simple — the
        // alternative (adding an is_active parameter) would
        // ripple through every caller for one bit of state.
        WindowChrome drawn = g_windows[h].chrome;
        if (!is_active)
        {
            drawn.colour_title = kInactiveTitleRgb;
        }
        WindowDraw(drawn);
        // Title text. White ink on the title-bar fill, 8-px top
        // padding + 8-px left padding so the first glyph clears
        // the 2-px outer border comfortably.
        if (g_windows[h].title != nullptr)
        {
            FramebufferDrawString(drawn.x + 8, drawn.y + 7, g_windows[h].title, 0x00FFFFFF, drawn.colour_title);
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
        // Client-area rectangle — primitives + content_fn consume
        // it (origin is just inside the 2-px border, under the
        // title bar).
        const auto& cc = drawn;
        const u32 tbh_c = (cc.title_height == 0) ? 22 : cc.title_height;
        const u32 tbh_eff_c = (tbh_c > cc.h) ? cc.h : tbh_c;
        const u32 client_x = cc.x + 2;
        const u32 client_y = cc.y + tbh_eff_c + 2;
        const u32 client_w = (cc.w > 4) ? cc.w - 4 : 0;
        const u32 client_h = (cc.h > tbh_eff_c + 4) ? cc.h - tbh_eff_c - 4 : 0;

        // Replay GDI display list. Ring-3 PEs record primitives
        // via SYS_GDI_* syscalls; the compositor paints them here
        // on every compose. Coords are client-local; out-of-rect
        // primitives clamp to zero size.
        for (u32 p = 0; p < g_windows[h].prim_count; ++p)
        {
            const WinGdiPrim& pr = g_windows[h].prims[p];
            if (pr.kind == WinGdiPrimKind::None)
                continue;
            const i32 ax = static_cast<i32>(client_x) + pr.x;
            const i32 ay = static_cast<i32>(client_y) + pr.y;
            if (ax < 0 || ay < 0 || client_w == 0 || client_h == 0)
                continue;
            // Clamp to client rect.
            const u32 max_x = client_x + client_w;
            const u32 max_y = client_y + client_h;
            if (static_cast<u32>(ax) >= max_x || static_cast<u32>(ay) >= max_y)
                continue;
            u32 pw = static_cast<u32>(pr.w < 0 ? 0 : pr.w);
            u32 ph = static_cast<u32>(pr.h < 0 ? 0 : pr.h);
            if (static_cast<u32>(ax) + pw > max_x)
                pw = max_x - static_cast<u32>(ax);
            if (static_cast<u32>(ay) + ph > max_y)
                ph = max_y - static_cast<u32>(ay);
            switch (pr.kind)
            {
            case WinGdiPrimKind::FillRect:
                if (pw > 0 && ph > 0)
                {
                    FramebufferFillRect(static_cast<u32>(ax), static_cast<u32>(ay), pw, ph, pr.colour_rgb);
                }
                break;
            case WinGdiPrimKind::Rectangle:
                if (pw > 0 && ph > 0)
                {
                    FramebufferDrawRect(static_cast<u32>(ax), static_cast<u32>(ay), pw, ph, pr.colour_rgb, 1);
                }
                break;
            case WinGdiPrimKind::TextOut:
            {
                // TextOut has no w/h in the record; glyph width
                // is computed from the stored string. Clip by
                // trailing NUL or by remaining client-rect room.
                const u32 px = static_cast<u32>(ax);
                const u32 py = static_cast<u32>(ay);
                if (py + 8 > max_y)
                    break; // no vertical room for one 8x8 glyph row
                const u32 avail_cols = (max_x > px) ? (max_x - px) / 8 : 0;
                char clipped[kWinTextOutMax + 1];
                u32 n = 0;
                while (n < avail_cols && n < kWinTextOutMax && pr.text[n] != '\0')
                {
                    clipped[n] = pr.text[n];
                    ++n;
                }
                clipped[n] = '\0';
                if (n > 0)
                {
                    FramebufferDrawString(px, py, clipped, pr.colour_rgb, cc.colour_client);
                }
                break;
            }
            case WinGdiPrimKind::Line:
            {
                // Bresenham: (ax, ay) = start; endpoint =
                // (client_x + pr.x + pr.w, client_y + pr.y + pr.h).
                // Clamp both endpoints to the client rect rather
                // than clipping the line analytically.
                const i32 cx_max = static_cast<i32>(max_x);
                const i32 cy_max = static_cast<i32>(max_y);
                const i32 cx_min = static_cast<i32>(client_x);
                const i32 cy_min = static_cast<i32>(client_y);
                i32 x0 = ax;
                i32 y0 = ay;
                i32 x1 = ax + pr.w;
                i32 y1 = ay + pr.h;
                // Bresenham, symmetric in all 8 octants.
                const i32 dx_l = (x1 >= x0) ? (x1 - x0) : (x0 - x1);
                const i32 sx = (x1 >= x0) ? 1 : -1;
                const i32 dy_l = -((y1 >= y0) ? (y1 - y0) : (y0 - y1));
                const i32 sy = (y1 >= y0) ? 1 : -1;
                i32 err = dx_l + dy_l;
                // Safety cap on iterations so a malicious line
                // with huge coords can't spin the compositor.
                const u32 kMaxLinePixels = 4096;
                for (u32 step = 0; step < kMaxLinePixels; ++step)
                {
                    if (x0 >= cx_min && x0 < cx_max && y0 >= cy_min && y0 < cy_max)
                    {
                        FramebufferPutPixel(static_cast<u32>(x0), static_cast<u32>(y0), pr.colour_rgb);
                    }
                    if (x0 == x1 && y0 == y1)
                        break;
                    const i32 e2 = 2 * err;
                    if (e2 >= dy_l)
                    {
                        err += dy_l;
                        x0 += sx;
                    }
                    if (e2 <= dx_l)
                    {
                        err += dx_l;
                        y0 += sy;
                    }
                }
                break;
            }
            case WinGdiPrimKind::Ellipse:
            {
                // Midpoint ellipse over axis-aligned bounding
                // box (ax, ay, pw, ph). Degenerate when either
                // dimension is under 2 — fall back to a pixel /
                // line.
                if (pw < 2 || ph < 2)
                {
                    if (pw > 0 && ph > 0)
                    {
                        FramebufferPutPixel(static_cast<u32>(ax), static_cast<u32>(ay), pr.colour_rgb);
                    }
                    break;
                }
                const i32 a = static_cast<i32>(pw / 2);
                const i32 b = static_cast<i32>(ph / 2);
                const i32 xc = ax + a;
                const i32 yc = ay + b;
                const i64 a2 = static_cast<i64>(a) * a;
                const i64 b2 = static_cast<i64>(b) * b;
                auto plot4 = [&](i32 x_off, i32 y_off)
                {
                    const i32 px_pts[4] = {xc + x_off, xc - x_off, xc + x_off, xc - x_off};
                    const i32 py_pts[4] = {yc + y_off, yc + y_off, yc - y_off, yc - y_off};
                    for (u32 k = 0; k < 4; ++k)
                    {
                        if (px_pts[k] >= static_cast<i32>(client_x) && px_pts[k] < static_cast<i32>(max_x) &&
                            py_pts[k] >= static_cast<i32>(client_y) && py_pts[k] < static_cast<i32>(max_y))
                        {
                            FramebufferPutPixel(static_cast<u32>(px_pts[k]), static_cast<u32>(py_pts[k]),
                                                pr.colour_rgb);
                        }
                    }
                };
                // Region 1.
                i64 x = 0;
                i64 y = b;
                i64 d1 = b2 - a2 * b + a2 / 4;
                i64 dx = 2 * b2 * x;
                i64 dy = 2 * a2 * y;
                while (dx < dy)
                {
                    plot4(static_cast<i32>(x), static_cast<i32>(y));
                    if (d1 < 0)
                    {
                        x++;
                        dx += 2 * b2;
                        d1 += dx + b2;
                    }
                    else
                    {
                        x++;
                        y--;
                        dx += 2 * b2;
                        dy -= 2 * a2;
                        d1 += dx - dy + b2;
                    }
                }
                // Region 2.
                i64 d2 = b2 * (2 * x + 1) * (2 * x + 1) / 4 + a2 * (y - 1) * (y - 1) - a2 * b2;
                while (y >= 0)
                {
                    plot4(static_cast<i32>(x), static_cast<i32>(y));
                    if (d2 > 0)
                    {
                        y--;
                        dy -= 2 * a2;
                        d2 += a2 - dy;
                    }
                    else
                    {
                        y--;
                        x++;
                        dx += 2 * b2;
                        dy -= 2 * a2;
                        d2 += dx - dy + a2;
                    }
                }
                break;
            }
            case WinGdiPrimKind::FilledEllipse:
            {
                // Bounding-box scan with integer ellipse test:
                // (x-cx)^2 * b^2 + (y-cy)^2 * a^2 <= a^2 * b^2.
                // Surface-clipped against the window client rect.
                if (pw < 1 || ph < 1)
                    break;
                const i64 a = static_cast<i64>(pw) / 2;
                const i64 b = static_cast<i64>(ph) / 2;
                if (a == 0 || b == 0)
                    break;
                const i64 cx = static_cast<i64>(ax) + a;
                const i64 cy = static_cast<i64>(ay) + b;
                const i64 a2 = a * a;
                const i64 b2 = b * b;
                const i64 a2b2 = a2 * b2;
                i64 x0 = ax;
                i64 y0 = ay;
                i64 x1 = static_cast<i64>(ax) + pw;
                i64 y1 = static_cast<i64>(ay) + ph;
                if (x0 < static_cast<i64>(client_x))
                    x0 = static_cast<i64>(client_x);
                if (y0 < static_cast<i64>(client_y))
                    y0 = static_cast<i64>(client_y);
                if (x1 > static_cast<i64>(max_x))
                    x1 = static_cast<i64>(max_x);
                if (y1 > static_cast<i64>(max_y))
                    y1 = static_cast<i64>(max_y);
                for (i64 yy = y0; yy < y1; ++yy)
                {
                    const i64 dy = yy - cy;
                    const i64 dy2 = dy * dy;
                    for (i64 xx = x0; xx < x1; ++xx)
                    {
                        const i64 dx = xx - cx;
                        if (dx * dx * b2 + dy2 * a2 <= a2b2)
                            FramebufferPutPixel(static_cast<u32>(xx), static_cast<u32>(yy), pr.colour_rgb);
                    }
                }
                break;
            }
            case WinGdiPrimKind::Pixel:
                // Single pixel at (ax, ay). Already clipped by
                // the outer max-x/max-y guard above.
                FramebufferPutPixel(static_cast<u32>(ax), static_cast<u32>(ay), pr.colour_rgb);
                break;
            case WinGdiPrimKind::Blit:
            {
                // Source pixels live in this window's blit_pool at
                // pr.pool_off; pr.w × pr.h is the dimension. Clip
                // against the client rect before handing to
                // FramebufferBlit (which clips against the surface).
                if (pr.w <= 0 || pr.h <= 0 || pr.pool_off >= kWinBlitPoolBytes)
                    break;
                const u64 bytes = static_cast<u64>(pr.w) * static_cast<u64>(pr.h) * 4;
                if (pr.pool_off + bytes > kWinBlitPoolBytes)
                    break;
                u32 w_use = static_cast<u32>(pr.w);
                u32 h_use = static_cast<u32>(pr.h);
                if (ax < static_cast<i32>(client_x) || ay < static_cast<i32>(client_y))
                    break; // don't paint over chrome
                if (static_cast<u32>(ax) + w_use > max_x)
                    w_use = max_x - static_cast<u32>(ax);
                if (static_cast<u32>(ay) + h_use > max_y)
                    h_use = max_y - static_cast<u32>(ay);
                if (w_use == 0 || h_use == 0)
                    break;
                const auto* src = reinterpret_cast<const u32*>(g_windows[h].blit_pool + pr.pool_off);
                FramebufferBlit(static_cast<u32>(ax), static_cast<u32>(ay), src, w_use, h_use, static_cast<u32>(pr.w));
                break;
            }
            case WinGdiPrimKind::None:
                break;
            }
        }

        // Dynamic content drawer — runs after chrome + widgets
        // so live text (e.g. task-manager stats) overlays the
        // static client-area fill. Given the client rect so
        // the drawer doesn't need to know about the title bar.
        if (g_windows[h].content_fn != nullptr)
        {
            g_windows[h].content_fn(client_x, client_y, client_w, client_h, g_windows[h].content_cookie);
        }
    }
}

void CompositorLock()
{
    duetos::sched::MutexLock(&g_compositor_mutex);
}

void CompositorUnlock()
{
    duetos::sched::MutexUnlock(&g_compositor_mutex);
}

void DesktopCompose(u32 desktop_rgb, const char* banner)
{
    if (g_display_mode == DisplayMode::Tty)
    {
        // TTY mode: fullscreen console, no windows / cursor /
        // taskbar. Black background so the green-on-dark console
        // reads like a Linux VT. The caller is responsible for
        // re-anchoring the console (ConsoleSetOrigin to (0, 0)
        // or similar) before switching modes.
        FramebufferClear(0x00000000);
        ConsoleRedraw();
        return;
    }

    // Desktop paint stack (bottom to top):
    //   1. Desktop fill
    //   2. Framebuffer console (under windows — windows dragged
    //      over the console occlude it, which restores on next
    //      compose — standard z-order feel)
    //   3. Windows in z-order + their owned widgets
    //   4. Freestanding widgets (float on top of windows for v0)
    //   5. Banner (desktop-level label)
    //   6. Taskbar
    //   7. Menu (popup, on top of everything)
    // The cursor is not touched here — the mouse reader owns
    // CursorHide / CursorShow around this call.
    FramebufferClear(desktop_rgb);
    ConsoleRedraw();
    WindowDrawAllOrdered();
    for (u32 i = 0; i < g_widget_count; ++i)
    {
        if (g_widgets[i].owner == kWindowInvalid)
        {
            PaintButton(g_widgets[i]);
        }
    }
    if (banner != nullptr)
    {
        FramebufferDrawString(16, 8, banner, 0x00FFFFFF, desktop_rgb);
    }
    TaskbarRedraw();
    MenuRedraw();
    CalendarRedraw();
    NetPanelRedraw();
    // Caret — painted last so it overlays everything, including
    // the taskbar. Blink phase toggles per compose; the ui-
    // ticker's 1 Hz compose produces the blink cadence.
    if (g_caret.visible && g_caret.shown && g_caret.w > 0 && g_caret.h > 0)
    {
        g_caret_on = !g_caret_on;
        if (g_caret_on)
        {
            FramebufferFillRect(g_caret.x, g_caret.y, g_caret.w, g_caret.h, 0x00000000);
        }
    }
    // Present the freshly-composed frame. For in-place framebuffers
    // (firmware handoff, Bochs VBE) this is a no-op. For
    // virtio-gpu-backed framebuffers the hook runs
    // TRANSFER_TO_HOST_2D + RESOURCE_FLUSH so the host composites
    // our guest pixels onto the actual display surface.
    FramebufferPresent();
}

DisplayMode GetDisplayMode()
{
    return g_display_mode;
}

void SetDisplayMode(DisplayMode mode)
{
    g_display_mode = mode;
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

// --- Owner pid / message queue / display list --------------------

void WindowSetOwnerPid(WindowHandle h, u64 pid)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].owner_pid = pid;
}

u64 WindowOwnerPid(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return 0;
    }
    return g_windows[h].owner_pid;
}

namespace
{

constexpr u32 kWindowHwndBias = 1; // mirrors window_syscall.cpp kHwndBias

bool MsgRingPop(WindowMsgRing& r, WindowMsg* out)
{
    if (r.count == 0)
    {
        return false;
    }
    *out = r.buf[r.head];
    r.head = (r.head + 1) % kWinMsgQueueDepth;
    --r.count;
    return true;
}

void MsgRingPush(WindowMsgRing& r, const WindowMsg& m)
{
    if (r.count == kWinMsgQueueDepth)
    {
        // Evict oldest — standard "drop-oldest" policy for a
        // bounded input queue. Caller's syscall still reports
        // success because the message landed (the victim was
        // already stale).
        r.head = (r.head + 1) % kWinMsgQueueDepth;
        --r.count;
    }
    r.buf[r.tail] = m;
    r.tail = (r.tail + 1) % kWinMsgQueueDepth;
    ++r.count;
}

} // namespace

bool WindowPostMessage(WindowHandle h, u32 message, u64 wparam, u64 lparam)
{
    if (!WindowValid(h))
    {
        return false;
    }
    WindowMsg m{};
    m.hwnd_biased = h + kWindowHwndBias;
    m.message = message;
    m.wparam = wparam;
    m.lparam = lparam;
    MsgRingPush(g_windows[h].msgs, m);
    return true;
}

bool WindowPopMessage(WindowHandle h, WindowMsg* out)
{
    if (!WindowValid(h) || out == nullptr)
    {
        return false;
    }
    return MsgRingPop(g_windows[h].msgs, out);
}

bool WindowPeekMessage(WindowHandle h, WindowMsg* out)
{
    if (!WindowValid(h) || out == nullptr)
    {
        return false;
    }
    WindowMsgRing& r = g_windows[h].msgs;
    if (r.count == 0)
    {
        return false;
    }
    *out = r.buf[r.head];
    return true;
}

bool WindowPopMessageAny(u64 pid, WindowMsg* out)
{
    if (pid == 0 || out == nullptr)
    {
        return false;
    }
    for (u32 i = 0; i < g_window_count; ++i)
    {
        if (!g_windows[i].alive || g_windows[i].owner_pid != pid)
            continue;
        if (MsgRingPop(g_windows[i].msgs, out))
        {
            return true;
        }
    }
    return false;
}

bool WindowAnyMessagePending(u64 pid)
{
    if (pid == 0)
    {
        return false;
    }
    for (u32 i = 0; i < g_window_count; ++i)
    {
        if (g_windows[i].alive && g_windows[i].owner_pid == pid && g_windows[i].msgs.count > 0)
        {
            return true;
        }
    }
    return false;
}

u32 WindowReapByOwner(u64 pid)
{
    if (pid == 0)
    {
        return 0; // refuse to reap kernel-owned windows
    }
    u32 reaped = 0;
    for (u32 i = 0; i < g_window_count; ++i)
    {
        if (g_windows[i].alive && g_windows[i].owner_pid == pid)
        {
            WindowTimerReap(pid, static_cast<WindowHandle>(i));
            WindowClose(static_cast<WindowHandle>(i));
            ++reaped;
        }
    }
    // If the dying process held mouse capture, release it.
    if (WindowGetCapture() != kWindowInvalid && WindowOwnerPid(WindowGetCapture()) == pid)
    {
        WindowReleaseCapture();
    }
    // A process going away could have been holding a pump open
    // in a sibling thread. Wake any GetMessage blockers so they
    // re-check and either dequeue a pending WM_QUIT or exit
    // naturally when their own pid no longer owns any windows.
    if (reaped > 0)
    {
        WindowMsgWakeAll();
    }
    return reaped;
}

void WindowMsgWaitBlockTimeout(u64 timeout_ticks)
{
    (void)duetos::sched::WaitQueueBlockTimeout(&g_msg_wq, timeout_ticks);
}

void WindowMsgWakeAll()
{
    duetos::arch::Cli();
    (void)duetos::sched::WaitQueueWakeAll(&g_msg_wq);
    duetos::arch::Sti();
}

namespace
{

void CopyAsciiClamped(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < cap && src[i] != '\0'; ++i)
        {
            const char c = src[i];
            dst[i] = (c >= 0x20 && c < 0x7F) ? c : '?';
        }
    }
    dst[i] = '\0';
}

// Append a primitive, evicting oldest on overflow — mirrors
// message-ring overflow policy so long-running redrawers don't
// panic on fullness.
void PrimListAppend(RegisteredWindow& w, const WinGdiPrim& p)
{
    if (w.prim_count == kWinDisplayListDepth)
    {
        for (u32 i = 1; i < kWinDisplayListDepth; ++i)
        {
            w.prims[i - 1] = w.prims[i];
        }
        w.prim_count = kWinDisplayListDepth - 1;
    }
    w.prims[w.prim_count] = p;
    ++w.prim_count;
}

} // namespace

void WindowClientFillRect(WindowHandle h, i32 x, i32 y, i32 w, i32 hgt, u32 rgb)
{
    if (!WindowValid(h))
    {
        return;
    }
    WinGdiPrim p{};
    p.kind = WinGdiPrimKind::FillRect;
    p.x = x;
    p.y = y;
    p.w = w;
    p.h = hgt;
    p.colour_rgb = rgb;
    PrimListAppend(g_windows[h], p);
}

void WindowClientRectangle(WindowHandle h, i32 x, i32 y, i32 w, i32 hgt, u32 rgb)
{
    if (!WindowValid(h))
    {
        return;
    }
    WinGdiPrim p{};
    p.kind = WinGdiPrimKind::Rectangle;
    p.x = x;
    p.y = y;
    p.w = w;
    p.h = hgt;
    p.colour_rgb = rgb;
    PrimListAppend(g_windows[h], p);
}

void WindowClientTextOut(WindowHandle h, i32 x, i32 y, const char* text, u32 rgb)
{
    if (!WindowValid(h))
    {
        return;
    }
    WinGdiPrim p{};
    p.kind = WinGdiPrimKind::TextOut;
    p.x = x;
    p.y = y;
    p.colour_rgb = rgb;
    CopyAsciiClamped(p.text, sizeof(p.text), text);
    PrimListAppend(g_windows[h], p);
}

void WindowClientLine(WindowHandle h, i32 x, i32 y, i32 x2, i32 y2, u32 rgb)
{
    if (!WindowValid(h))
    {
        return;
    }
    WinGdiPrim p{};
    p.kind = WinGdiPrimKind::Line;
    p.x = x;
    p.y = y;
    // Encode endpoint as (w, h) deltas so the struct stays the
    // same shape as FillRect/Rectangle.
    p.w = x2 - x;
    p.h = y2 - y;
    p.colour_rgb = rgb;
    PrimListAppend(g_windows[h], p);
}

void WindowClientEllipse(WindowHandle h, i32 x, i32 y, i32 w, i32 hgt, u32 rgb)
{
    if (!WindowValid(h))
    {
        return;
    }
    WinGdiPrim p{};
    p.kind = WinGdiPrimKind::Ellipse;
    p.x = x;
    p.y = y;
    p.w = w;
    p.h = hgt;
    p.colour_rgb = rgb;
    PrimListAppend(g_windows[h], p);
}

void WindowClientFilledEllipse(WindowHandle h, i32 x, i32 y, i32 w, i32 hgt, u32 fill_rgb)
{
    if (!WindowValid(h))
    {
        return;
    }
    WinGdiPrim p{};
    p.kind = WinGdiPrimKind::FilledEllipse;
    p.x = x;
    p.y = y;
    p.w = w;
    p.h = hgt;
    p.colour_rgb = fill_rgb;
    PrimListAppend(g_windows[h], p);
}

void WindowClientPixel(WindowHandle h, i32 x, i32 y, u32 rgb)
{
    if (!WindowValid(h))
    {
        return;
    }
    WinGdiPrim p{};
    p.kind = WinGdiPrimKind::Pixel;
    p.x = x;
    p.y = y;
    p.w = 1;
    p.h = 1;
    p.colour_rgb = rgb;
    PrimListAppend(g_windows[h], p);
}

void WindowClientBitBlt(WindowHandle h, i32 dst_x, i32 dst_y, const u32* src_pixels, u32 src_w, u32 src_h)
{
    if (!WindowValid(h) || src_pixels == nullptr || src_w == 0 || src_h == 0)
    {
        return;
    }
    RegisteredWindow& w = g_windows[h];
    const u64 bytes64 = static_cast<u64>(src_w) * static_cast<u64>(src_h) * 4;
    if (bytes64 > kWinBlitPoolBytes)
    {
        return; // too large — caller should have clipped to kWinBlitMaxPx
    }
    const u32 bytes = static_cast<u32>(bytes64);
    if (w.blit_pool_used + bytes > kWinBlitPoolBytes)
    {
        // Pool full for this frame; drop — a real composite reset
        // on the next prim_count clear will reclaim space.
        return;
    }
    const u32 off = w.blit_pool_used;
    u8* dst = w.blit_pool + off;
    const u8* src = reinterpret_cast<const u8*>(src_pixels);
    for (u32 i = 0; i < bytes; ++i)
        dst[i] = src[i];
    w.blit_pool_used += bytes;

    WinGdiPrim p{};
    p.kind = WinGdiPrimKind::Blit;
    p.x = dst_x;
    p.y = dst_y;
    p.w = static_cast<i32>(src_w);
    p.h = static_cast<i32>(src_h);
    p.pool_off = off;
    PrimListAppend(w, p);
}

void WindowClearDisplayList(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].prim_count = 0;
    g_windows[h].blit_pool_used = 0;
}

bool WindowIsVisible(WindowHandle h)
{
    return WindowValid(h) && g_windows[h].visible;
}

void WindowSetVisible(WindowHandle h, bool visible)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].visible = visible;
    // If we just hid the active window, promote the next
    // visible + alive window so focus doesn't dangle on a
    // hidden slot.
    if (!visible && g_active_window == h)
    {
        g_active_window = kWindowInvalid;
        for (u32 i = g_window_count; i > 0; --i)
        {
            const WindowHandle candidate = g_z_order[i - 1];
            if (candidate != h && WindowValid(candidate) && g_windows[candidate].visible)
            {
                g_active_window = candidate;
                break;
            }
        }
    }
}

bool WindowSetTitle(WindowHandle h, const char* ascii_src)
{
    if (!WindowValid(h))
    {
        return false;
    }
    StoreTitle(g_windows[h], ascii_src);
    return true;
}

// --- Async keyboard state -----------------------------------------

void WindowInputTrackKey(u16 code, bool down)
{
    const u32 idx = code & 0xFF;
    const u32 byte = idx / 8;
    const u32 bit = idx % 8;
    if (down)
    {
        g_vk_state[byte] |= static_cast<u8>(1u << bit);
    }
    else
    {
        g_vk_state[byte] &= static_cast<u8>(~(1u << bit));
    }
}

bool WindowKeyIsDown(u16 code)
{
    const u32 idx = code & 0xFF;
    const u32 byte = idx / 8;
    const u32 bit = idx % 8;
    return (g_vk_state[byte] & (1u << bit)) != 0;
}

// --- Cursor accessors ---------------------------------------------

void WindowGetCursor(u32* x_out, u32* y_out)
{
    u32 cx = 0, cy = 0;
    CursorPosition(&cx, &cy);
    if (x_out)
        *x_out = cx;
    if (y_out)
        *y_out = cy;
}

void WindowSetCursor(u32 x, u32 y)
{
    u32 cx = 0, cy = 0;
    CursorPosition(&cx, &cy);
    const i32 dx = static_cast<i32>(x) - static_cast<i32>(cx);
    const i32 dy = static_cast<i32>(y) - static_cast<i32>(cy);
    CursorHide();
    CursorMove(static_cast<i8>((dx > 127)    ? 127
                               : (dx < -128) ? -128
                                             : dx),
               static_cast<i8>((dy > 127)    ? 127
                               : (dy < -128) ? -128
                                             : dy));
    CursorShow();
}

// --- Mouse capture ------------------------------------------------

WindowHandle WindowSetCapture(WindowHandle h)
{
    const WindowHandle prev = g_mouse_capture;
    if (h == kWindowInvalid || !WindowValid(h))
    {
        g_mouse_capture = kWindowInvalid;
    }
    else
    {
        g_mouse_capture = h;
    }
    return prev;
}

void WindowReleaseCapture()
{
    g_mouse_capture = kWindowInvalid;
}

WindowHandle WindowGetCapture()
{
    if (g_mouse_capture != kWindowInvalid && !WindowValid(g_mouse_capture))
    {
        // Capture owner died without releasing. Reset so we
        // don't keep routing to a dead slot.
        g_mouse_capture = kWindowInvalid;
    }
    return g_mouse_capture;
}

// --- Clipboard ----------------------------------------------------

void WindowClipboardSetText(const char* text)
{
    u32 i = 0;
    if (text != nullptr)
    {
        for (; i + 1 < kWindowClipboardMax && text[i] != '\0'; ++i)
        {
            const char c = text[i];
            g_clipboard[i] = (c >= 0x20 && c < 0x7F) ? c : '?';
        }
    }
    g_clipboard[i] = '\0';
    g_clipboard_len = i;
}

u32 WindowClipboardGetText(char* dst, u32 cap)
{
    if (dst == nullptr || cap == 0)
    {
        return 0;
    }
    u32 n = g_clipboard_len;
    if (n > cap - 1)
        n = cap - 1;
    for (u32 i = 0; i < n; ++i)
    {
        dst[i] = g_clipboard[i];
    }
    dst[n] = '\0';
    return n;
}

// --- Timer table --------------------------------------------------

namespace
{

// Resolve an existing (pid, hwnd, timer_id) slot index or
// `kWindowTimersMax` if none. Linear scan — N is 32.
u32 FindTimerSlot(u64 pid, WindowHandle hwnd, u32 timer_id)
{
    for (u32 i = 0; i < kWindowTimersMax; ++i)
    {
        const auto& s = g_timers[i];
        if (s.in_use && s.owner_pid == pid && s.hwnd == hwnd && s.timer_id == timer_id)
        {
            return i;
        }
    }
    return kWindowTimersMax;
}

u32 AllocTimerSlot()
{
    for (u32 i = 0; i < kWindowTimersMax; ++i)
    {
        if (!g_timers[i].in_use)
        {
            return i;
        }
    }
    return kWindowTimersMax;
}

} // namespace

bool WindowTimerSet(u64 pid, WindowHandle hwnd, u32 timer_id, u32 interval_ms)
{
    if (pid == 0 || !WindowValid(hwnd) || g_windows[hwnd].owner_pid != pid)
    {
        return false;
    }
    // Tick period is 100 Hz — 10 ms per tick. Round UP so a
    // `SetTimer(.., 15)` ticks every 2 ticks = 20 ms (Win32's
    // minimum is USER_TIMER_MINIMUM = 10 ms; we bottom out at
    // one tick).
    const u32 ticks = (interval_ms == 0) ? 1 : ((interval_ms + 9) / 10);
    u32 slot = FindTimerSlot(pid, hwnd, timer_id);
    if (slot == kWindowTimersMax)
    {
        slot = AllocTimerSlot();
        if (slot == kWindowTimersMax)
        {
            return false;
        }
        g_timers[slot].in_use = true;
        g_timers[slot].owner_pid = pid;
        g_timers[slot].hwnd = hwnd;
        g_timers[slot].timer_id = timer_id;
    }
    g_timers[slot].interval_ticks = ticks;
    g_timers[slot].remaining_ticks = ticks;
    return true;
}

bool WindowTimerKill(u64 pid, WindowHandle hwnd, u32 timer_id)
{
    const u32 slot = FindTimerSlot(pid, hwnd, timer_id);
    if (slot == kWindowTimersMax)
    {
        return false;
    }
    g_timers[slot].in_use = false;
    return true;
}

void WindowTimerReap(u64 pid, WindowHandle hwnd)
{
    for (u32 i = 0; i < kWindowTimersMax; ++i)
    {
        if (g_timers[i].in_use && g_timers[i].owner_pid == pid && g_timers[i].hwnd == hwnd)
        {
            g_timers[i].in_use = false;
        }
    }
}

void WindowTimerTick()
{
    constexpr u32 kWmTimer = 0x0113;
    bool any_posted = false;
    for (u32 i = 0; i < kWindowTimersMax; ++i)
    {
        auto& s = g_timers[i];
        if (!s.in_use)
            continue;
        if (!WindowValid(s.hwnd) || g_windows[s.hwnd].owner_pid != s.owner_pid)
        {
            // Target died out from under us — drop the timer.
            s.in_use = false;
            continue;
        }
        if (s.remaining_ticks == 0)
        {
            s.remaining_ticks = s.interval_ticks;
        }
        else
        {
            --s.remaining_ticks;
            if (s.remaining_ticks == 0)
            {
                WindowPostMessage(s.hwnd, kWmTimer, s.timer_id, 0);
                s.remaining_ticks = s.interval_ticks;
                any_posted = true;
            }
        }
    }
    if (any_posted)
    {
        WindowMsgWakeAll();
    }
}

// --- Parent / child tracking --------------------------------------

void WindowSetParent(WindowHandle h, WindowHandle parent)
{
    if (!WindowValid(h))
    {
        return;
    }
    if (parent != kWindowInvalid && !WindowValid(parent))
    {
        parent = kWindowInvalid;
    }
    g_windows[h].parent = parent;
}

WindowHandle WindowGetParent(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return kWindowInvalid;
    }
    const WindowHandle p = g_windows[h].parent;
    if (p != kWindowInvalid && !WindowValid(p))
    {
        return kWindowInvalid;
    }
    return p;
}

WindowHandle WindowGetRelated(WindowHandle h, WindowRel rel)
{
    // First / Last traverse the z-order. Next / Prev find h in
    // z-order and step by 1. Child returns the first alive
    // window whose parent is h. Owner is treated as parent in
    // v1 (we don't have a separate owner field).
    switch (rel)
    {
    case WindowRel::First:
    {
        for (u32 i = 0; i < g_window_count; ++i)
        {
            const WindowHandle w = g_z_order[i];
            if (WindowValid(w))
                return w;
        }
        return kWindowInvalid;
    }
    case WindowRel::Last:
    {
        for (u32 i = g_window_count; i > 0; --i)
        {
            const WindowHandle w = g_z_order[i - 1];
            if (WindowValid(w))
                return w;
        }
        return kWindowInvalid;
    }
    case WindowRel::Next:
    case WindowRel::Prev:
    {
        if (!WindowValid(h))
            return kWindowInvalid;
        u32 idx = g_window_count;
        for (u32 i = 0; i < g_window_count; ++i)
        {
            if (g_z_order[i] == h)
            {
                idx = i;
                break;
            }
        }
        if (idx == g_window_count)
            return kWindowInvalid;
        if (rel == WindowRel::Next)
        {
            for (u32 i = idx + 1; i < g_window_count; ++i)
            {
                if (WindowValid(g_z_order[i]))
                    return g_z_order[i];
            }
        }
        else
        {
            for (u32 i = idx; i > 0; --i)
            {
                if (WindowValid(g_z_order[i - 1]))
                    return g_z_order[i - 1];
            }
        }
        return kWindowInvalid;
    }
    case WindowRel::Child:
    {
        if (!WindowValid(h))
            return kWindowInvalid;
        for (u32 i = 0; i < g_window_count; ++i)
        {
            if (WindowValid(i) && g_windows[i].parent == h)
                return static_cast<WindowHandle>(i);
        }
        return kWindowInvalid;
    }
    case WindowRel::Owner:
        return WindowGetParent(h);
    }
    return kWindowInvalid;
}

// --- Keyboard focus -----------------------------------------------

void WindowSetFocus(WindowHandle h)
{
    constexpr u32 kWmKillFocus = 0x0008;
    constexpr u32 kWmSetFocus = 0x0007;
    const WindowHandle prev = g_focus_hwnd;
    if (h != kWindowInvalid && !WindowValid(h))
    {
        return;
    }
    if (prev == h)
    {
        return;
    }
    if (prev != kWindowInvalid && WindowValid(prev))
    {
        WindowPostMessage(prev, kWmKillFocus, static_cast<u64>(h) + 1, 0);
    }
    g_focus_hwnd = h;
    if (h != kWindowInvalid)
    {
        WindowPostMessage(h, kWmSetFocus, (prev == kWindowInvalid) ? 0 : (static_cast<u64>(prev) + 1), 0);
    }
}

WindowHandle WindowGetFocus()
{
    if (g_focus_hwnd != kWindowInvalid && !WindowValid(g_focus_hwnd))
    {
        g_focus_hwnd = kWindowInvalid;
    }
    return g_focus_hwnd;
}

// --- Caret --------------------------------------------------------

void WindowCaretCreate(WindowHandle owner, u32 w, u32 h)
{
    g_caret.owner = owner;
    g_caret.w = (w == 0) ? 1 : w;
    g_caret.h = (h == 0) ? 12 : h;
    g_caret.visible = true;
    g_caret.shown = false;
}

void WindowCaretDestroy()
{
    g_caret.visible = false;
    g_caret.shown = false;
    g_caret.owner = kWindowInvalid;
}

void WindowCaretSetPos(u32 x, u32 y)
{
    g_caret.x = x;
    g_caret.y = y;
}

void WindowCaretShow(bool shown)
{
    g_caret.shown = shown;
}

const Caret& WindowCaretGet()
{
    return g_caret;
}

// --- Per-window user-data longs + dirty region --------------------

u64 WindowGetLong(WindowHandle h, u32 index)
{
    if (!WindowValid(h) || index >= kWinLongSlots)
    {
        return 0;
    }
    return g_windows[h].longs[index];
}

u64 WindowSetLong(WindowHandle h, u32 index, u64 value)
{
    if (!WindowValid(h) || index >= kWinLongSlots)
    {
        return 0;
    }
    const u64 prev = g_windows[h].longs[index];
    g_windows[h].longs[index] = value;
    return prev;
}

void WindowInvalidate(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].dirty = true;
}

void WindowValidate(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].dirty = false;
}

bool WindowIsDirty(WindowHandle h)
{
    return WindowValid(h) && g_windows[h].dirty;
}

u32 WindowDrainPaints()
{
    constexpr u32 kWmPaint = 0x000F;
    u32 posted = 0;
    for (u32 i = 0; i < g_window_count; ++i)
    {
        if (!g_windows[i].alive || !g_windows[i].dirty)
            continue;
        if (g_windows[i].owner_pid == 0)
        {
            // Kernel-owned windows don't have PE pumps — clear
            // without posting so the flag doesn't accumulate
            // forever (the boot apps paint via content_fn on
            // every compose).
            g_windows[i].dirty = false;
            continue;
        }
        // wParam = HDC (0 in v1), lParam = dirty-rect pointer
        // (0 since whole-client dirty is the only mode). The
        // BeginPaint path on the user side will produce the HDC.
        WindowPostMessage(static_cast<WindowHandle>(i), kWmPaint, 0, 0);
        g_windows[i].dirty = false;
        ++posted;
    }
    if (posted > 0)
    {
        WindowMsgWakeAll();
    }
    return posted;
}

void WindowResizeTo(WindowHandle h, u32 w, u32 hgt)
{
    if (!WindowValid(h))
    {
        return;
    }
    const auto info = FramebufferGet();
    const u32 fb_w = info.width ? info.width : 1024;
    const u32 fb_h = info.height ? info.height : 768;
    auto& c = g_windows[h].chrome;
    if (w > 0)
    {
        if (w > fb_w)
            w = fb_w;
        if (c.x + w > fb_w)
        {
            c.x = (fb_w > w) ? fb_w - w : 0;
        }
        c.w = w;
    }
    if (hgt > 0)
    {
        if (hgt > fb_h)
            hgt = fb_h;
        if (c.y + hgt > fb_h)
        {
            c.y = (fb_h > hgt) ? fb_h - hgt : 0;
        }
        c.h = hgt;
    }
}

} // namespace duetos::drivers::video
