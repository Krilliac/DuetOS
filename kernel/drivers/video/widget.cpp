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

#include "drivers/video/widget.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/timer.h"
#include "drivers/input/ps2mouse.h"
#include "sched/sched.h"
#include "sync/lockdep.h"
#include "drivers/video/calendar.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/dialog.h"
#include "drivers/video/dnd.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/magnifier.h"
#include "drivers/video/menu.h"
#include "drivers/video/notify.h"
#include "drivers/video/shadow.h"
#include "drivers/video/ttf.h"
#include "drivers/video/ttf_raster.h"
#include "drivers/video/netpanel.h"
#include "drivers/video/taskbar.h"
#include "drivers/video/theme.h"
#include "drivers/video/tray_flyout.h"
#include "drivers/video/wallpaper.h"

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

// Saturating per-channel lighten — forward declaration of the
// helper defined further down this TU (just before WindowDraw).
// Buttons want the same "lifted top, settled bottom" gradient
// look as the rest of the chrome.
u32 LightenRgb(u32 rgb, u32 amount);

// Resolve a window's effective title-bar height: explicit
// per-window value wins; otherwise sample the active theme's
// `title_bar_height`; otherwise fall back to the historical
// 22-px default. Single source of truth — paint + hit-test
// paths both consult this so a theme switch can't desync the
// chrome and the click target.
// Pixel width of one title-bar control button (close / max /
// min). Theme.title_button_width = 0 means "derive from height"
// (the historical pre-spec behaviour: square buttons sized off
// the title bar). Otherwise the theme's value wins.
u32 EffectiveButtonWidth(u32 derived_height)
{
    const u32 from_theme = ThemeCurrent().title_button_width;
    return (from_theme != 0) ? from_theme : derived_height;
}

u32 EffectiveTitleHeight(const WindowChrome& w)
{
    if (w.title_height != 0)
        return w.title_height;
    const u32 from_theme = ThemeCurrent().title_bar_height;
    return (from_theme != 0) ? from_theme : 22u;
}

void PaintButton(const ButtonWidget& b)
{
    u32 bx = 0, by = 0;
    if (!EffectiveButtonPos(b, &bx, &by))
    {
        return; // dead owner window — skip silently
    }
    const u32 fill = b.pressed ? b.colour_pressed : b.colour_normal;
    // Vertical gradient: lifted shade at the top fading to the
    // registered fill at the bottom. Pressed buttons skip the
    // gradient (a pressed button looks "settled" without the
    // lifted highlight band) so the press transition reads
    // visibly as a state change.
    if (b.pressed)
    {
        FramebufferFillRect(bx, by, b.w, b.h, fill);
    }
    else
    {
        FramebufferFillRectGradient(bx, by, b.w, b.h, LightenRgb(fill, 22), fill);
    }
    FramebufferDrawRect(bx, by, b.w, b.h, b.colour_border, 2);
    // 1-px ridge highlight along the inside of the top edge —
    // matches the window-chrome / taskbar / popup ridge.
    if (!b.pressed && b.w > 6 && b.h > 4)
    {
        FramebufferFillRect(bx + 2, by + 2, b.w - 4, 1, LightenRgb(fill, 50));
    }
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

bool WidgetCursorOverButton(u32 cx, u32 cy)
{
    for (u32 i = 0; i < g_widget_count; ++i)
    {
        const ButtonWidget& b = g_widgets[i];
        u32 bx = 0, by = 0;
        if (!EffectiveButtonPos(b, &bx, &by))
        {
            continue;
        }
        if (cx >= bx && cx < bx + b.w && cy >= by && cy < by + b.h)
        {
            return true;
        }
    }
    return false;
}

namespace
{

// Tooltip hover state. `g_tooltip_widget` is the index of the
// widget currently under the cursor (or kWidgetInvalid). The
// timer arms when the cursor settles on a widget; if it stays
// for kTooltipArmTicks (~1s @ 100Hz), the next compose paints
// the widget's label in a small panel near the cursor.
constinit u32 g_tooltip_widget = kWidgetInvalid;
constinit u64 g_tooltip_arm_tick = 0;
constinit u32 g_tooltip_cursor_x = 0;
constinit u32 g_tooltip_cursor_y = 0;
constexpr u64 kTooltipArmTicks = 100; // ~1 second at 100Hz

u32 FindWidgetAt(u32 cx, u32 cy)
{
    for (u32 i = 0; i < g_widget_count; ++i)
    {
        const ButtonWidget& b = g_widgets[i];
        u32 bx = 0, by = 0;
        if (!EffectiveButtonPos(b, &bx, &by))
            continue;
        if (cx >= bx && cx < bx + b.w && cy >= by && cy < by + b.h)
            return i;
    }
    return kWidgetInvalid;
}

} // namespace

void WidgetTooltipTrack(u32 cx, u32 cy, u64 now_tick)
{
    const u32 hit = FindWidgetAt(cx, cy);
    if (hit != g_tooltip_widget)
    {
        g_tooltip_widget = hit;
        g_tooltip_arm_tick = now_tick;
        g_tooltip_cursor_x = cx;
        g_tooltip_cursor_y = cy;
        return;
    }
    // Same widget — refresh cursor position so the tooltip
    // anchors near where the user actually paused, not where
    // they first crossed the widget edge.
    g_tooltip_cursor_x = cx;
    g_tooltip_cursor_y = cy;
}

void WidgetTooltipRender()
{
    if (g_tooltip_widget == kWidgetInvalid || g_tooltip_widget >= g_widget_count)
        return;
    const ButtonWidget& b = g_widgets[g_tooltip_widget];
    if (b.label == nullptr)
        return;
    // Hover-time check: only render if the widget has been
    // hovered for ≥ kTooltipArmTicks. The mouse loop tracks
    // this; we read TimerTicks here to compare so a paused
    // ticker doesn't trip a tooltip.
    const u64 now = duetos::arch::TimerTicks();
    if (now - g_tooltip_arm_tick < kTooltipArmTicks)
        return;
    const u32 lw = StringPixelWidth(b.label);
    if (lw == 0)
        return;
    const u32 pad = 4;
    const u32 panel_w = lw + 2 * pad;
    const u32 panel_h = 8 + 2 * pad;
    // Anchor below the cursor by 16 px so the panel doesn't
    // sit under the pointer sprite. Clamp to the framebuffer.
    const auto fb = FramebufferGet();
    u32 px = g_tooltip_cursor_x + 12;
    u32 py = g_tooltip_cursor_y + 16;
    if (px + panel_w > fb.width)
        px = (fb.width > panel_w) ? fb.width - panel_w : 0;
    if (py + panel_h > fb.height)
        py = (fb.height > panel_h) ? fb.height - panel_h : 0;
    constexpr u32 kTipBg = 0x00FFFFD0; // pale-yellow (Win9x convention)
    constexpr u32 kTipFg = 0x00101020;
    constexpr u32 kTipBorder = 0x00606078;
    FramebufferFillRect(px, py, panel_w, panel_h, kTipBg);
    FramebufferDrawRect(px, py, panel_w, panel_h, kTipBorder, 1);
    FramebufferDrawString(px + pad, py + pad, b.label, kTipFg, kTipBg);
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
    // Duet-era optional subtitle. Empty string until
    // WindowSetSubtitle is called. Themes that don't render it
    // ignore the field; the storage is unconditional so the
    // accessor always returns a stable pointer.
    char mut_subtitle[kWindowSubtitleStorage];
    WindowContentFn content_fn; // nullable per-window content drawer
    void* content_cookie;
    WindowWheelFn wheel_fn;           // nullable per-window wheel handler
    WindowScrollbarSurface scrollbar; // most-recent scrollbar geometry
    WindowScrollSetFn scroll_fn;      // nullable scrollbar-input callback
    u64 owner_pid;                    // 0 = kernel-owned boot window, >0 = ring-3 pid
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
    // Pre-maximize bounds snapshot. Stored at WindowMaximize
    // time so WindowRestore can put the window back where it
    // was. Only meaningful when `maximized == true`.
    u32 saved_x, saved_y, saved_w, saved_h;
    // Window transition animation state. `anim_active` gates
    // the rest. `anim_post_action` runs at the moment the
    // animation lands on its final rect:
    //   0 = none — chrome stays at the target rect.
    //   1 = hide-on-complete (minimize) — at completion the
    //       rect is rolled back to `anim_start_*` so the next
    //       SW_SHOW restores to the pre-minimize geometry, and
    //       `visible` is cleared.
    // See `WindowAnimate` / `WindowAnimateStepAll` for the
    // interpolation math.
    u32 anim_start_x, anim_start_y, anim_start_w, anim_start_h;
    u32 anim_target_x, anim_target_y, anim_target_w, anim_target_h;
    u8 anim_remaining_ticks;
    u8 anim_total_ticks;
    u8 anim_ease;        // WindowAnimEase value
    u8 anim_post_action; // 0 = none, 1 = hide on completion
    bool anim_active;
    bool alive;
    bool visible;
    bool dirty;     // set by InvalidateRect; cleared by BeginPaint / WindowDrainPaints
    bool maximized; // true while WindowMaximize has been applied without a Restore
    bool pinned;    // taskbar UI hint — affects active-tab dot size
    // Per-window opacity. 0xFF = fully opaque (default). Values
    // below dim the window by alpha-blending a black overlay
    // with alpha = (0xFF - opacity) AFTER chrome / content
    // paint. Cheap fake-transparency that doesn't need a real
    // compositor backbuffer — blends toward the desktop's dark
    // ink rather than the surface beneath, but the visual
    // "fading window" cue still reads correctly.
    u8 opacity;
    // Per-window PE-requested cursor shape. When a Win32 PE app
    // calls `SetCursor(hCursor)`, the SYS_GDI_SET_CURSOR handler
    // resolves which of the caller's windows the cursor is over
    // and writes the requested shape here. The mouse-loop hit-test
    // in `boot_tasks.cpp` consults this slot before falling back
    // to its default Arrow when no kernel-owned shape rule (resize
    // band / Hand-button / Notes IBeam) matched. `requested_set`
    // gates the lookup so a window that never called SetCursor
    // doesn't accidentally pin Arrow — kernel hit-test rules
    // (Hand, IBeam, resize) still win over an explicit Arrow when
    // the slot is unset, but lose to a PE's explicit Arrow when
    // it is set. Cleared on WindowClose so a reused slot (when
    // dynamic re-use lands) doesn't carry stale state. Encoded as
    // `u8` matching `CursorShape` enum width so the field stays
    // a single byte and the surrounding `_pad` accounts for it.
    u8 requested_cursor; // CursorShape value
    bool requested_cursor_set;
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
// Tagged with `kLockClassCompositor` so lockdep records every
// edge `compositor -> (other class)` that fires across the per-
// frame walk. Compositor runs from a kernel task and never holds
// another global lock across a flush — any inversion reported
// against this class is a bug worth investigating.
constinit duetos::sched::Mutex g_compositor_mutex{
    .owner = nullptr, .waiters = {}, .class_id = duetos::sync::kLockClassCompositor};

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

// Last KeyEvent modifier bitmask. Updated by the kbd-reader
// thread after every event so peripheral consumers (wheel
// handlers, etc.) can branch on Ctrl / Shift / Alt.
constinit u8 g_modifier_state = 0;

// Double-click threshold in scheduler ticks (10 ms each).
// Default 50 ticks (~500 ms) — Windows / GTK convention.
// Read by the kernel mouse-loop DC detector on every
// press_edge so a runtime change takes effect immediately.
constinit u32 g_dbl_click_ticks = 50;

// Mouse sensitivity scale (0..255). 128 = identity. The
// mouse reader multiplies dx/dy by (scale/128) before
// feeding the cursor + apps.
constinit u8 g_mouse_sensitivity = 128;

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

// History ring for the clipboard. Each slot holds up to
// kWindowClipboardMax bytes plus a null terminator. The ring is
// front-loaded — slot 0 is the most recently displaced, slot
// kWindowClipboardHistoryDepth-1 is the oldest. New entries push
// in at slot 0 and shift older ones down; if the ring fills, the
// oldest falls off the end.
struct ClipboardHistorySlot
{
    char text[kWindowClipboardMax];
    u32 len;
    bool used;
};
constinit ClipboardHistorySlot g_clipboard_hist[kWindowClipboardHistoryDepth] = {};

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

// Show-Desktop snapshot: bitmask over `kMaxWindows` slots
// recording which windows were visible at the moment the user
// last triggered "show desktop". When `g_show_desktop_active` is
// true, the toggle is in its "windows hidden" state; the next
// trigger re-shows the marked windows. The snapshot is taken at
// activation time (not at every redraw) so windows that the user
// closes WHILE the desktop is shown don't get resurrected when
// the toggle releases.
constinit u32 g_show_desktop_mask = 0;
constinit bool g_show_desktop_active = false;

// Desktop fill colour observed on the most recent DesktopCompose
// pass. `WindowDrawAllOrdered` reads this when rounding window
// corners on the Duet theme — the punch primitive needs a "what
// colour was here before chrome" approximation, and the gradient
// mid-tone (= the raw desktop_rgb argument) is the cheapest
// reasonable answer until per-pixel sampling lands. Defaults to
// 0 so the corner-punch is a no-op before any compose pass has
// run (i.e. during the initial framebuffer self-test).
constinit u32 g_compose_desktop_rgb = 0;

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

namespace
{

// Lighten an 0x00RRGGBB colour by `amount` per channel, saturating
// at 0xFF. Used to derive the highlight shade for the top of a
// title bar gradient. Cheap saturating add — no branch on
// channel boundaries because the per-channel sums fit in u32.
u32 LightenRgb(u32 rgb, u32 amount)
{
    u32 r = ((rgb >> 16) & 0xFFU) + amount;
    u32 g = ((rgb >> 8) & 0xFFU) + amount;
    u32 b = (rgb & 0xFFU) + amount;
    if (r > 0xFFU)
        r = 0xFFU;
    if (g > 0xFFU)
        g = 0xFFU;
    if (b > 0xFFU)
        b = 0xFFU;
    return (r << 16) | (g << 8) | b;
}

// Darken sibling of LightenRgb. Saturates at 0 — channels that
// would underflow clamp to 0 instead of wrapping.
u32 DarkenRgb(u32 rgb, u32 amount)
{
    const u32 r0 = (rgb >> 16) & 0xFFU;
    const u32 g0 = (rgb >> 8) & 0xFFU;
    const u32 b0 = rgb & 0xFFU;
    const u32 r = (r0 > amount) ? r0 - amount : 0U;
    const u32 g = (g0 > amount) ? g0 - amount : 0U;
    const u32 b = (b0 > amount) ? b0 - amount : 0U;
    return (r << 16) | (g << 8) | b;
}

} // namespace

void WindowDraw(const WindowChrome& w)
{
    if (w.w == 0 || w.h == 0)
    {
        return;
    }

    const u32 tbh = EffectiveTitleHeight(w);
    const u32 tbh_eff = (tbh > w.h) ? w.h : tbh;

    // Client area paint — only the area BELOW the title bar gets
    // the opaque client fill. The title-bar strip is filled
    // separately with an alpha-blended gradient so the wallpaper
    // underneath shows through at low opacity (the Win11 Mica /
    // macOS BigSur "frosted title" idiom). Previously the entire
    // window was painted opaque first; that gave a flat-coloured
    // title with no awareness of what's behind the window.
    if (w.h > tbh_eff)
    {
        FramebufferFillRect(w.x, w.y + tbh_eff, w.w, w.h - tbh_eff, w.colour_client);
    }

    // Title bar — three-stage paint:
    //   1. Solid base fill at the title colour so the gradient
    //      below reads even when the window covers a near-black
    //      patch of wallpaper.
    //   2. Alpha-blended brighter band over the top half (the
    //      "glass shine" that simulates light catching the chrome).
    //   3. 1-pixel highlight ridge along the very top edge.
    // The 0xA0 alpha on the shine reads as "obviously chrome,
    // subtly modern" without crossing into the see-through Mica
    // look proper, which needs a per-pixel wallpaper read pass
    // (deferred — fb API is write-only today).
    const u32 title_top = LightenRgb(w.colour_title, 24);
    FramebufferFillRect(w.x, w.y, w.w, tbh_eff, w.colour_title);
    if (tbh_eff > 4)
    {
        const u32 shine_h = tbh_eff / 2;
        const u32 shine_argb = (0xA0U << 24) | (title_top & 0x00FFFFFFU);
        FramebufferBlendFill(w.x, w.y, w.w, shine_h, shine_argb);
    }
    if (tbh_eff > 0)
    {
        FramebufferFillRect(w.x + 2, w.y + 1, (w.w > 4) ? w.w - 4 : 0, 1, LightenRgb(w.colour_title, 56));
    }

    // Outer border — 2-pixel dark frame over the whole window.
    FramebufferDrawRect(w.x, w.y, w.w, w.h, w.colour_border, 2);

    // Inner client highlight: 1-pixel line just inside the
    // border at the top of the client area. Catches incoming
    // light from the title-bar gradient above and gives the
    // client a slight "recessed" feel without blowing the
    // theme's flat aesthetic.
    if (tbh_eff + 3 <= w.h && w.w > 6)
    {
        FramebufferFillRect(w.x + 3, w.y + tbh_eff + 1, w.w - 6, 1, LightenRgb(w.colour_client, 16));
    }

    // Title / client divider — 1-pixel line where the title
    // bar ends. Helps the eye separate chrome from content.
    if (tbh_eff + 2 <= w.h)
    {
        FramebufferFillRect(w.x + 2, w.y + tbh_eff, w.w - 4, 1, w.colour_border);
    }

    // Drag affordance — a centred grid of small dimples that signals
    // "this strip is a drag handle" to new users. Same idiom macOS
    // uses on its document-style title bars and KDE uses on its
    // dragger handles. Six dots in three rows × two columns, each
    // 1-px, spaced 2-px apart, painted with the title bar's brighter
    // ridge tint so they read as a tactile texture on top of the
    // gradient rather than competing with the title text.
    if (tbh_eff >= 14 && w.w > 240)
    {
        const u32 dot_rgb = LightenRgb(w.colour_title, 64);
        const u32 dimple_cols = 2;
        const u32 dimple_rows = 3;
        const u32 dimple_step = 3;
        const u32 dimple_block_w = dimple_cols * dimple_step;
        const u32 dimple_block_h = dimple_rows * dimple_step;
        const u32 dimple_x0 = w.x + (w.w - dimple_block_w) / 2;
        const u32 dimple_y0 = w.y + (tbh_eff - dimple_block_h) / 2;
        for (u32 row = 0; row < dimple_rows; ++row)
        {
            for (u32 col = 0; col < dimple_cols; ++col)
            {
                FramebufferFillRect(dimple_x0 + col * dimple_step, dimple_y0 + row * dimple_step, 1, 1, dot_rgb);
            }
        }
    }

    // Three title-bar control buttons (min / max / close), laid
    // out right-to-left from the title-bar's right edge with
    // `btn_pad` between each. Each box reuses the same square
    // geometry and shares the close button's colour for fill so
    // the trio reads as a coherent set; the close box gets the
    // distinct theme `colour_close_btn` so it's still the
    // visually loudest control. Glyphs (— / □ / X) are drawn
    // with the framebuffer's line primitive — pixel-perfect at
    // any title-bar height.
    const u32 btn_pad = 4;
    {
        const u32 btn_h = (tbh_eff > 2 * btn_pad) ? tbh_eff - 2 * btn_pad : 0;
        const u32 btn_w = EffectiveButtonWidth(btn_h);
        if (btn_h > 4 && w.w > btn_w * 3U + btn_pad * 2U)
        {
            const u32 close_x = w.x + w.w - btn_w - btn_pad;
            const u32 max_x = (close_x > btn_w + 2U) ? close_x - btn_w - 2U : close_x;
            const u32 min_x = (max_x > btn_w + 2U) ? max_x - btn_w - 2U : max_x;
            const u32 btn_y = w.y + btn_pad;

            // Use the title bar's gradient-bottom colour as the
            // hover/control fill so min + max look like part of the
            // chrome, not separate UI. The close box keeps its
            // theme-distinct red.
            //
            // Mouse-hover state: the close / max / min boxes lighten
            // toward white when the cursor is inside them, matching
            // the universal Win/macOS/GNOME "this button is hot"
            // affordance. The cursor position is sampled once per
            // recompose; per-button hit-test is a single rect
            // comparison. Close button's hover tint is also a lift
            // (rather than a Win11-red flood) so the close box stays
            // readable even under high cursor velocity.
            u32 hover_x = 0;
            u32 hover_y = 0;
            CursorPosition(&hover_x, &hover_y);
            auto inside = [&](u32 bx, u32 by) -> bool
            { return hover_x >= bx && hover_x < bx + btn_w && hover_y >= by && hover_y < by + btn_h; };
            const u32 ctrl_fill = w.colour_title;
            const u32 ctrl_fill_hot = LightenRgb(ctrl_fill, 48);
            const u32 close_fill = w.colour_close_btn;
            const u32 close_fill_hot = LightenRgb(close_fill, 48);
            FramebufferFillRect(min_x, btn_y, btn_w, btn_h, inside(min_x, btn_y) ? ctrl_fill_hot : ctrl_fill);
            FramebufferDrawRect(min_x, btn_y, btn_w, btn_h, w.colour_border, 1);
            FramebufferFillRect(max_x, btn_y, btn_w, btn_h, inside(max_x, btn_y) ? ctrl_fill_hot : ctrl_fill);
            FramebufferDrawRect(max_x, btn_y, btn_w, btn_h, w.colour_border, 1);
            FramebufferFillRect(close_x, btn_y, btn_w, btn_h, inside(close_x, btn_y) ? close_fill_hot : close_fill);
            FramebufferDrawRect(close_x, btn_y, btn_w, btn_h, w.colour_border, 1);

            // Glyph dimensions use the smaller of width/height so
            // the inner mark stays centred + symmetric whether the
            // box is square (compact themes) or wider-than-tall
            // (Duet 46-px chrome). Inset measured from the smaller
            // dim; horizontal padding centres a square glyph
            // inside the wider rectangle.
            const u32 glyph_side = (btn_w < btn_h) ? btn_w : btn_h;
            if (glyph_side >= 8)
            {
                const u32 inset = 3;
                const u32 gx_pad = (btn_w - glyph_side) / 2;
                // Minimize: a 2-px-thick horizontal bar near the
                // bottom of the box. Reads as the "_" glyph at
                // small sizes.
                FramebufferFillRect(min_x + gx_pad + inset, btn_y + btn_h - inset - 2U, glyph_side - 2U * inset, 2U,
                                    0x00FFFFFF);
                // Maximize / restore: a 1-px outlined square in
                // the centre. When already maximized, draw a
                // double-square to hint "restore" — the chrome
                // doesn't store hover state, so this is the only
                // visible distinction between max + restore.
                const u32 sq_side = glyph_side - 2U * inset;
                FramebufferDrawRect(max_x + gx_pad + inset, btn_y + inset, sq_side, sq_side, 0x00FFFFFF, 1);
                // Close: doubled diagonal X (existing chrome).
                const i32 cx0 = static_cast<i32>(close_x + gx_pad + inset);
                const i32 cy0 = static_cast<i32>(btn_y + inset);
                const i32 cx1 = static_cast<i32>(close_x + gx_pad + glyph_side - 1U - inset);
                const i32 cy1 = static_cast<i32>(btn_y + btn_h - 1U - inset);
                FramebufferDrawLine(cx0, cy0, cx1, cy1, 0x00FFFFFF);
                FramebufferDrawLine(cx0, cy1, cx1, cy0, 0x00FFFFFF);
                FramebufferDrawLine(cx0 + 1, cy0, cx1, cy1 - 1, 0x00FFFFFF);
                FramebufferDrawLine(cx0, cy1 - 1, cx1 - 1, cy0, 0x00FFFFFF);
            }
        }
    }

    // Drop shadow is painted by WindowDrawAllOrdered with depth +
    // alpha tuned for the active vs inactive state. Centralising it
    // there means every WindowDraw caller (currently only
    // WindowDrawAllOrdered) gets focus-aware depth without having
    // to thread an is_active flag down through the chrome paint.
}

void WindowPaintFocusGlow(u32 x, u32 y, u32 w, u32 h, bool is_pe_window)
{
    if (!ThemeTactilityEffective())
    {
        return;
    }
    const Theme& t = ThemeCurrent();
    if (t.focus_glow_colour == 0U)
    {
        return;
    }
    // Win32-role windows force amber regardless of theme — preserves
    // the dual-accent identity the chrome relies on to tell Win32
    // apps apart from native DuetOS apps at a glance.
    constexpr u32 kAmber = 0x00F5B73AU;
    const u32 colour = is_pe_window ? kAmber : t.focus_glow_colour;
    RenderSoftShadowWithStroke(static_cast<i32>(x), static_cast<i32>(y), w, h, 4U, 120U, colour, colour);
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

// Sibling of StoreTitle for the subtitle slot. Empty string is
// the well-defined cleared state — WindowGetSubtitle must
// always return a NUL-terminated pointer for a live window.
void StoreSubtitle(RegisteredWindow& w, const char* src)
{
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < kWindowSubtitleStorage && src[i] != '\0'; ++i)
        {
            const char c = src[i];
            w.mut_subtitle[i] = (c >= 0x20 && c < 0x7F) ? c : '?';
        }
    }
    w.mut_subtitle[i] = '\0';
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
    StoreSubtitle(g_windows[h], nullptr);
    g_windows[h].alive = true;
    g_windows[h].visible = true;
    g_windows[h].dirty = false;
    g_windows[h].opacity = 0xFF;       // fully opaque by default
    g_windows[h].requested_cursor = 0; // CursorShape::Arrow sentinel
    g_windows[h].requested_cursor_set = false;
    g_windows[h].maximized = false;
    g_windows[h].pinned = false;
    g_windows[h].saved_x = 0;
    g_windows[h].saved_y = 0;
    g_windows[h].saved_w = 0;
    g_windows[h].saved_h = 0;
    g_windows[h].anim_active = false;
    g_windows[h].anim_remaining_ticks = 0;
    g_windows[h].anim_total_ticks = 0;
    g_windows[h].anim_ease = 0;
    g_windows[h].anim_post_action = 0;
    g_windows[h].anim_start_x = 0;
    g_windows[h].anim_start_y = 0;
    g_windows[h].anim_start_w = 0;
    g_windows[h].anim_start_h = 0;
    g_windows[h].anim_target_x = 0;
    g_windows[h].anim_target_y = 0;
    g_windows[h].anim_target_w = 0;
    g_windows[h].anim_target_h = 0;
    g_windows[h].owner_pid = 0;
    g_windows[h].parent = kWindowInvalid;
    g_windows[h].msgs.head = 0;
    g_windows[h].msgs.tail = 0;
    g_windows[h].msgs.count = 0;
    g_windows[h].prim_count = 0;
    g_windows[h].blit_pool_used = 0;
    g_windows[h].content_fn = nullptr;
    g_windows[h].content_cookie = nullptr;
    g_windows[h].wheel_fn = nullptr;
    g_windows[h].scrollbar = {};
    g_windows[h].scroll_fn = nullptr;
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
    // Clamp into the framebuffer extent only when the framebuffer is
    // actually live. Pre-FramebufferInit (early boot, or headless
    // self-tests that move windows before the compositor comes up)
    // info.width/height are zero, which would otherwise force every
    // nonzero (x, y) to clamp back to the origin.
    if (FramebufferAvailable())
    {
        const auto info = FramebufferGet();
        const u32 max_x = (info.width > g_windows[h].chrome.w) ? info.width - g_windows[h].chrome.w : 0;
        const u32 max_y = (info.height > g_windows[h].chrome.h) ? info.height - g_windows[h].chrome.h : 0;
        if (x > max_x)
            x = max_x;
        if (y > max_y)
            y = max_y;
    }
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

WindowResizeEdge WindowPointInResizeEdge(WindowHandle h, u32 cx, u32 cy)
{
    if (!WindowValid(h))
        return WindowResizeEdge::None;
    const auto& w = g_windows[h].chrome;
    if (cx + kWindowResizeBorderPx < w.x || cx >= w.x + w.w + kWindowResizeBorderPx)
        return WindowResizeEdge::None;
    if (cy + kWindowResizeBorderPx < w.y || cy >= w.y + w.h + kWindowResizeBorderPx)
        return WindowResizeEdge::None;
    const bool near_top = (cy >= w.y) && (cy < w.y + kWindowResizeBorderPx);
    const bool near_bottom = (cy + kWindowResizeBorderPx >= w.y + w.h) && (cy < w.y + w.h + kWindowResizeBorderPx);
    const bool near_left = (cx >= w.x) && (cx < w.x + kWindowResizeBorderPx);
    const bool near_right = (cx + kWindowResizeBorderPx >= w.x + w.w) && (cx < w.x + w.w + kWindowResizeBorderPx);
    // Corner zones win over edges (a corner is the intersection
    // of two edge bands; the diagonal cursor is more useful than
    // the vertical fallback).
    if (near_top && near_left)
        return WindowResizeEdge::TopLeft;
    if (near_top && near_right)
        return WindowResizeEdge::TopRight;
    if (near_bottom && near_left)
        return WindowResizeEdge::BottomLeft;
    if (near_bottom && near_right)
        return WindowResizeEdge::BottomRight;
    if (near_top)
        return WindowResizeEdge::Top;
    if (near_bottom)
        return WindowResizeEdge::Bottom;
    if (near_left)
        return WindowResizeEdge::Left;
    if (near_right)
        return WindowResizeEdge::Right;
    return WindowResizeEdge::None;
}

void WindowResizeFromEdge(WindowHandle h, WindowResizeEdge edge, u32 anchor_x, u32 anchor_y, u32 anchor_w, u32 anchor_h,
                          i32 dx, i32 dy)
{
    if (!WindowValid(h) || edge == WindowResizeEdge::None)
        return;
    constexpr u32 kMinW = 80;
    constexpr u32 kMinH = 60;
    i64 nx = anchor_x;
    i64 ny = anchor_y;
    i64 nw = anchor_w;
    i64 nh = anchor_h;
    auto apply_left = [&]()
    {
        nx = static_cast<i64>(anchor_x) + dx;
        nw = static_cast<i64>(anchor_w) - dx;
        if (nw < kMinW)
        {
            nx -= (kMinW - nw);
            nw = kMinW;
        }
        if (nx < 0)
        {
            nw += nx;
            nx = 0;
        }
    };
    auto apply_right = [&]()
    {
        nw = static_cast<i64>(anchor_w) + dx;
        if (nw < kMinW)
            nw = kMinW;
    };
    auto apply_top = [&]()
    {
        ny = static_cast<i64>(anchor_y) + dy;
        nh = static_cast<i64>(anchor_h) - dy;
        if (nh < kMinH)
        {
            ny -= (kMinH - nh);
            nh = kMinH;
        }
        if (ny < 0)
        {
            nh += ny;
            ny = 0;
        }
    };
    auto apply_bottom = [&]()
    {
        nh = static_cast<i64>(anchor_h) + dy;
        if (nh < kMinH)
            nh = kMinH;
    };
    switch (edge)
    {
    case WindowResizeEdge::Left:
        apply_left();
        break;
    case WindowResizeEdge::Right:
        apply_right();
        break;
    case WindowResizeEdge::Top:
        apply_top();
        break;
    case WindowResizeEdge::Bottom:
        apply_bottom();
        break;
    case WindowResizeEdge::TopLeft:
        apply_top();
        apply_left();
        break;
    case WindowResizeEdge::TopRight:
        apply_top();
        apply_right();
        break;
    case WindowResizeEdge::BottomLeft:
        apply_bottom();
        apply_left();
        break;
    case WindowResizeEdge::BottomRight:
        apply_bottom();
        apply_right();
        break;
    default:
        return;
    }
    const auto fb_info = FramebufferGet();
    if (nx + nw > fb_info.width)
        nw = fb_info.width - nx;
    if (ny + nh > fb_info.height)
        nh = fb_info.height - ny;
    if (nw < kMinW)
        nw = kMinW;
    if (nh < kMinH)
        nh = kMinH;
    g_windows[h].chrome.x = static_cast<u32>(nx);
    g_windows[h].chrome.y = static_cast<u32>(ny);
    g_windows[h].chrome.w = static_cast<u32>(nw);
    g_windows[h].chrome.h = static_cast<u32>(nh);
    g_windows[h].maximized = false;
}

bool WindowPointInTitle(WindowHandle h, u32 x, u32 y)
{
    if (!WindowValid(h))
    {
        return false;
    }
    const auto& c = g_windows[h].chrome;
    const u32 tbh = EffectiveTitleHeight(c);
    return x >= c.x && x < c.x + c.w && y >= c.y && y < c.y + tbh;
}

bool WindowPointInCloseBox(WindowHandle h, u32 x, u32 y)
{
    if (!WindowValid(h))
    {
        return false;
    }
    const auto& c = g_windows[h].chrome;
    const u32 tbh = EffectiveTitleHeight(c);
    const u32 tbh_eff = (tbh > c.h) ? c.h : tbh;
    const u32 btn_pad = 4;
    const u32 btn_h = (tbh_eff > 2 * btn_pad) ? tbh_eff - 2 * btn_pad : 0;
    const u32 btn_w = EffectiveButtonWidth(btn_h);
    if (btn_h <= 4 || c.w <= btn_w * 3U + btn_pad * 2U)
    {
        return false; // title bar too short for the trio
    }
    const u32 btn_x = c.x + c.w - btn_w - btn_pad;
    const u32 btn_y = c.y + btn_pad;
    return x >= btn_x && x < btn_x + btn_w && y >= btn_y && y < btn_y + btn_h;
}

bool WindowPointInMaxBox(WindowHandle h, u32 x, u32 y)
{
    if (!WindowValid(h))
    {
        return false;
    }
    const auto& c = g_windows[h].chrome;
    const u32 tbh = EffectiveTitleHeight(c);
    const u32 tbh_eff = (tbh > c.h) ? c.h : tbh;
    const u32 btn_pad = 4;
    const u32 btn_h = (tbh_eff > 2 * btn_pad) ? tbh_eff - 2 * btn_pad : 0;
    const u32 btn_w = EffectiveButtonWidth(btn_h);
    if (btn_h <= 4 || c.w <= btn_w * 3U + btn_pad * 2U)
    {
        return false;
    }
    const u32 close_x = c.x + c.w - btn_w - btn_pad;
    if (close_x <= btn_w + 2U)
    {
        return false;
    }
    const u32 max_x = close_x - btn_w - 2U;
    const u32 btn_y = c.y + btn_pad;
    return x >= max_x && x < max_x + btn_w && y >= btn_y && y < btn_y + btn_h;
}

bool WindowPointInMinBox(WindowHandle h, u32 x, u32 y)
{
    if (!WindowValid(h))
    {
        return false;
    }
    const auto& c = g_windows[h].chrome;
    const u32 tbh = EffectiveTitleHeight(c);
    const u32 tbh_eff = (tbh > c.h) ? c.h : tbh;
    const u32 btn_pad = 4;
    const u32 btn_h = (tbh_eff > 2 * btn_pad) ? tbh_eff - 2 * btn_pad : 0;
    const u32 btn_w = EffectiveButtonWidth(btn_h);
    if (btn_h <= 4 || c.w <= btn_w * 3U + btn_pad * 2U)
    {
        return false;
    }
    const u32 close_x = c.x + c.w - btn_w - btn_pad;
    if (close_x <= btn_w + 2U)
    {
        return false;
    }
    const u32 max_x = close_x - btn_w - 2U;
    if (max_x <= btn_w + 2U)
    {
        return false;
    }
    const u32 min_x = max_x - btn_w - 2U;
    const u32 btn_y = c.y + btn_pad;
    return x >= min_x && x < min_x + btn_w && y >= btn_y && y < btn_y + btn_h;
}

namespace
{

// Default tween length for chrome-state transitions (min / max /
// restore / snap). 10 ticks @ 100 Hz ≈ 100 ms — perceptible as
// motion, short enough to feel snappy. Centralised so tuning is
// one edit.
constexpr u8 kWindowAnimDefaultTicks = 10;

// Minimize target rect: a small "card" centered on the taskbar
// strip the user would have clicked. Picks a per-window slot
// width so multi-window minimize animations don't visually
// collapse to the same point. The window is restored to its
// pre-anim rect on completion (visibility flips to hidden), so
// this rect is purely the "vanish into the taskbar" cue.
void MinimizeTargetRect(WindowHandle h, u32* tx, u32* ty, u32* tw, u32* th)
{
    const auto info = FramebufferGet();
    const u32 fb_w = info.width ? info.width : 1024u;
    const u32 fb_h = info.height ? info.height : 768u;
    const u32 reserve = TaskbarHeight();
    const u32 taskbar_h = (reserve != 0) ? reserve : 28u;
    // 80 x 24 card centred on the strip the click would land
    // in. `slot_stride` keeps each window's vanish point inside
    // its own visual lane on the taskbar.
    constexpr u32 kCardW = 80u;
    constexpr u32 kCardH = 24u;
    const u32 slot_stride = (kMaxWindows != 0) ? (fb_w / kMaxWindows) : kCardW;
    const u32 slot_centre = (slot_stride * h) + (slot_stride / 2u);
    const u32 card_x = (slot_centre > kCardW / 2u) ? slot_centre - (kCardW / 2u) : 0u;
    const u32 card_y = (fb_h > taskbar_h) ? fb_h - taskbar_h : 0u;
    if (tx)
        *tx = card_x;
    if (ty)
        *ty = card_y;
    if (tw)
        *tw = kCardW;
    if (th)
        *th = kCardH;
}

} // namespace

// Arm a window-rect animation. The animator writes chrome each
// 100 Hz tick from `WindowAnimateStepAll`; the chrome jumps to
// the exact target on the last step. `WindowAnimate` itself does
// NOT touch chrome — flags the caller cares about (maximized /
// visible / focus) are set by the calling op so observers
// (`WindowIsMaximized`, hit-testing) see the new state
// immediately. Skip cases:
//   - invalid handle
//   - identical source / target rect (nothing to animate)
//   - animation already in flight for `h` (don't restart mid-flight)
void WindowAnimate(WindowHandle h, u32 target_x, u32 target_y, u32 target_w, u32 target_h, u32 ticks,
                   WindowAnimEase ease)
{
    if (!WindowValid(h))
        return;
    auto& w = g_windows[h];
    if (w.anim_active)
        return; // in-flight one wins; new request dropped
    const auto& c = w.chrome;
    if (c.x == target_x && c.y == target_y && c.w == target_w && c.h == target_h)
        return; // nothing to animate — already on target
    if (ticks == 0)
    {
        // Zero-tick request degrades to a hard set; preserves the
        // primitive's contract of "after the call the rect is the
        // target" without needing a step pass.
        auto& cm = w.chrome;
        cm.x = target_x;
        cm.y = target_y;
        cm.w = target_w;
        cm.h = target_h;
        return;
    }
    if (ticks > 255u)
        ticks = 255u;
    w.anim_start_x = c.x;
    w.anim_start_y = c.y;
    w.anim_start_w = c.w;
    w.anim_start_h = c.h;
    w.anim_target_x = target_x;
    w.anim_target_y = target_y;
    w.anim_target_w = target_w;
    w.anim_target_h = target_h;
    w.anim_total_ticks = static_cast<u8>(ticks);
    w.anim_remaining_ticks = static_cast<u8>(ticks);
    w.anim_ease = static_cast<u8>(ease);
    w.anim_post_action = 0;
    w.anim_active = true;
}

bool WindowAnimateActive(WindowHandle h)
{
    return WindowValid(h) && g_windows[h].anim_active;
}

namespace
{

// Apply the per-tick interpolation for one armed window. Returns
// true iff the window's chrome was touched this tick (always
// true while `anim_active`). On the final step snaps to the
// exact target rect and runs `anim_post_action`.
//
// Math: `t = (total - remaining) / total` in [0, 1]. For ease-
// out we apply `t' = 1 - (1 - t)^2`. We stay in fixed point
// (multiply by 1024 then divide) to keep the math integer-only —
// freestanding kernel context has no FPU we can lean on.
bool WindowAnimateStepOne(RegisteredWindow& w)
{
    if (!w.anim_active)
        return false;
    // Decrement before computing `t` so the first step lands at
    // remaining = total - 1 (a non-zero `t`) and the last step
    // (remaining = 0) lands exactly on the target.
    if (w.anim_remaining_ticks > 0)
        --w.anim_remaining_ticks;
    if (w.anim_remaining_ticks == 0)
    {
        // Final step — land on the exact target rect to avoid
        // any fixed-point rounding residual.
        w.chrome.x = w.anim_target_x;
        w.chrome.y = w.anim_target_y;
        w.chrome.w = w.anim_target_w;
        w.chrome.h = w.anim_target_h;
        w.anim_active = false;
        // Post-action: minimize rolls back to the snapshot
        // rect + hides; the snapshot is the original pre-anim
        // bounds so a follow-up SW_SHOW lands the user back
        // where they were.
        if (w.anim_post_action == 1)
        {
            w.chrome.x = w.anim_start_x;
            w.chrome.y = w.anim_start_y;
            w.chrome.w = w.anim_start_w;
            w.chrome.h = w.anim_start_h;
            w.visible = false;
            w.anim_post_action = 0;
        }
        return true;
    }
    // Fixed-point interpolation. `t_q10` is t * 1024 in [0, 1024).
    // total >= 1 here because `anim_active && remaining > 0`.
    const u32 total = w.anim_total_ticks;
    const u32 elapsed = total - w.anim_remaining_ticks;
    u32 t_q10 = (elapsed * 1024u) / total;
    if (w.anim_ease == static_cast<u8>(WindowAnimEase::EaseOut))
    {
        // t' = 1 - (1 - t)^2 — quadratic ease-out. Inverse stays
        // in q10; (1 - t)^2 = inv * inv / 1024 keeps the result
        // in q10 too.
        const u32 inv = 1024u - t_q10;
        const u32 inv_sq = (inv * inv) / 1024u;
        t_q10 = 1024u - inv_sq;
    }
    auto lerp_q10 = [](u32 start, u32 target, u32 t) -> u32
    {
        // Sign-aware lerp without floats. Branch on which end
        // is larger so the intermediate subtraction stays u32.
        if (target >= start)
        {
            const u32 delta = target - start;
            return start + (delta * t) / 1024u;
        }
        const u32 delta = start - target;
        return start - (delta * t) / 1024u;
    };
    w.chrome.x = lerp_q10(w.anim_start_x, w.anim_target_x, t_q10);
    w.chrome.y = lerp_q10(w.anim_start_y, w.anim_target_y, t_q10);
    w.chrome.w = lerp_q10(w.anim_start_w, w.anim_target_w, t_q10);
    w.chrome.h = lerp_q10(w.anim_start_h, w.anim_target_h, t_q10);
    return true;
}

} // namespace

bool WindowAnimateStepAll()
{
    bool any_stepped = false;
    for (u32 i = 0; i < g_window_count; ++i)
    {
        if (!g_windows[i].alive)
            continue;
        if (WindowAnimateStepOne(g_windows[i]))
            any_stepped = true;
    }
    return any_stepped;
}

void WindowMinimize(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    // Already-hidden windows have no rect change to animate;
    // run the original de-activation path so a no-op minimize
    // doesn't leave focus stuck on a hidden window.
    if (!g_windows[h].visible)
        return;
    // Animate from current rect to a small "card" on the
    // taskbar strip. Post-action 1 rolls the chrome rect back
    // to the start bounds and clears `visible` on completion,
    // so the next ShowWindow(SW_SHOW) restores the pre-minimize
    // geometry.
    //
    // If another animation is already in flight for `h` (e.g.
    // user mashed Minimize during the Maximize tween) the new
    // request is dropped per the documented WindowAnimate
    // contract — we still hide-immediately so the user's click
    // isn't lost, and leave the in-flight animation alone (it
    // would just compete with the hide cue otherwise).
    const bool had_anim_in_flight = g_windows[h].anim_active;
    u32 tx = 0, ty = 0, tw = 0, th = 0;
    MinimizeTargetRect(h, &tx, &ty, &tw, &th);
    WindowAnimate(h, tx, ty, tw, th, kWindowAnimDefaultTicks);
    // The animation was armed by US iff there was no in-flight
    // animation at entry AND the call wasn't rejected for an
    // identical rect (anim_active goes true on a successful arm).
    const bool we_armed = !had_anim_in_flight && g_windows[h].anim_active;
    if (we_armed)
    {
        g_windows[h].anim_post_action = 1; // hide-on-complete
    }
    else
    {
        // No new animation: hide immediately so the user's
        // click registers visually even if we couldn't animate.
        g_windows[h].visible = false;
    }
    // Promote the topmost remaining alive+visible window to
    // active so keyboard input flows somewhere — same logic as
    // the pre-animation path, run immediately so input stays
    // responsive while the tween plays out.
    if (g_active_window == h)
    {
        g_active_window = kWindowInvalid;
        for (u32 i = g_window_count; i > 0; --i)
        {
            const WindowHandle cand = g_z_order[i - 1];
            if (cand != h && WindowValid(cand) && g_windows[cand].visible)
            {
                g_active_window = cand;
                break;
            }
        }
    }
}

void WindowMaximize(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    if (g_windows[h].maximized)
        return; // idempotent — preserve the original snapshot
    auto& c = g_windows[h].chrome;
    g_windows[h].saved_x = c.x;
    g_windows[h].saved_y = c.y;
    g_windows[h].saved_w = c.w;
    g_windows[h].saved_h = c.h;
    const auto info = FramebufferGet();
    // Reserve room for the taskbar at the bottom. Sample the
    // live `TaskbarHeight()` so the per-theme strip height
    // (36 px on Duet family, 28 px elsewhere) is honoured. A
    // 0 return (no taskbar) falls through to the historical
    // 28-px reserve so a no-taskbar mode still leaves a sane
    // safety margin.
    const u32 reserve = TaskbarHeight();
    const u32 reserved_for_taskbar = (reserve != 0) ? reserve : 28u;
    const u32 max_h = (info.height > reserved_for_taskbar) ? info.height - reserved_for_taskbar : info.height;
    // Flag the state-change immediately so observers
    // (`WindowIsMaximized`, the chrome max/restore glyph) see
    // the new state before the tween finishes. The animator
    // walks chrome.x/y/w/h to the target rect over ~100 ms.
    g_windows[h].maximized = true;
    WindowAnimate(h, 0u, 0u, info.width, max_h, kWindowAnimDefaultTicks);
}

void WindowRestore(WindowHandle h)
{
    if (!WindowValid(h) || !g_windows[h].maximized)
        return;
    // Flag the state-change first so observers see the restored
    // state immediately; chrome rect tweens to the saved bounds
    // over ~100 ms.
    g_windows[h].maximized = false;
    WindowAnimate(h, g_windows[h].saved_x, g_windows[h].saved_y, g_windows[h].saved_w, g_windows[h].saved_h,
                  kWindowAnimDefaultTicks);
}

bool WindowIsMaximized(WindowHandle h)
{
    return WindowValid(h) && g_windows[h].maximized;
}

namespace
{

// Compute the visible work area (framebuffer minus taskbar)
// Win-key snaps target. Single source of truth for the half-
// snap geometry — same calculation `WindowMaximize` uses for
// its full-screen reserve. A 0 taskbar height (no taskbar)
// falls back to the historical 28-px margin so a no-taskbar
// boot mode still leaves a sane safety strip.
void WorkArea(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    const auto info = FramebufferGet();
    const u32 reserve = TaskbarHeight();
    const u32 reserved = (reserve != 0) ? reserve : 28u;
    if (x_out)
        *x_out = 0;
    if (y_out)
        *y_out = 0;
    if (w_out)
        *w_out = info.width;
    if (h_out)
        *h_out = (info.height > reserved) ? info.height - reserved : info.height;
}

} // namespace

void WindowSnapLeft(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    g_windows[h].maximized = false;
    WindowAnimate(h, wa_x, wa_y, wa_w / 2u, wa_h, kWindowAnimDefaultTicks);
}

void WindowSnapRight(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    const u32 half = wa_w / 2u;
    g_windows[h].maximized = false;
    // `wa_w - half` picks up the odd column on odd-width framebuffers.
    WindowAnimate(h, wa_x + half, wa_y, wa_w - half, wa_h, kWindowAnimDefaultTicks);
}

void WindowSnapTop(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    g_windows[h].maximized = false;
    WindowAnimate(h, wa_x, wa_y, wa_w, wa_h / 2u, kWindowAnimDefaultTicks);
}

void WindowSnapBottom(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    const u32 half = wa_h / 2u;
    g_windows[h].maximized = false;
    WindowAnimate(h, wa_x, wa_y + half, wa_w, wa_h - half, kWindowAnimDefaultTicks);
}

// Quarter-screen corner snaps. Same WorkArea reserve as the
// half-snaps; the right / bottom halves pick up the odd
// row / column on odd-sized framebuffers so the four quarters
// tile exactly with no gap.
void WindowSnapTopLeft(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    g_windows[h].maximized = false;
    WindowAnimate(h, wa_x, wa_y, wa_w / 2u, wa_h / 2u, kWindowAnimDefaultTicks);
}

void WindowSnapTopRight(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    const u32 half_w = wa_w / 2u;
    g_windows[h].maximized = false;
    WindowAnimate(h, wa_x + half_w, wa_y, wa_w - half_w, wa_h / 2u, kWindowAnimDefaultTicks);
}

void WindowSnapBottomLeft(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    const u32 half_h = wa_h / 2u;
    g_windows[h].maximized = false;
    WindowAnimate(h, wa_x, wa_y + half_h, wa_w / 2u, wa_h - half_h, kWindowAnimDefaultTicks);
}

void WindowSnapBottomRight(WindowHandle h)
{
    if (!WindowValid(h))
        return;
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    const u32 half_w = wa_w / 2u;
    const u32 half_h = wa_h / 2u;
    g_windows[h].maximized = false;
    WindowAnimate(h, wa_x + half_w, wa_y + half_h, wa_w - half_w, wa_h - half_h, kWindowAnimDefaultTicks);
}

// ---------------------------------------------------------------
// Snap-zone hover preview.
//
// `g_snap_preview` is the single source of truth for "what would
// happen if the user released the drag right now." The mouse
// loop (kernel/core/boot_tasks.cpp) writes it via SnapPreviewArm
// on every drag-motion packet; DesktopCompose reads it via
// SnapPreviewArmed and paints a translucent rectangle at the
// snap target's geometry between the windows layer and the
// tooltip layer. Cleared on drag-release (by the release branch
// after committing the snap) and on Esc-during-drag.
//
// Cursor-distance hit bands (px from each screen edge):
//   - Corner: 32 × 32 box from each corner (precedence over
//     edges so a cursor 8 px from top-left resolves to TopLeft,
//     not Maximize or Left).
//   - Top edge: cursor_y <= kSnapEdgePx → Maximize.
//   - Left edge: cursor_x <= kSnapEdgePx → SnapLeft.
//   - Right edge: cursor_x >= fb.width - kSnapEdgePx → SnapRight.
//   - Bottom edge: no snap. The bottom strip is owned by the
//     taskbar's drag-snap (TaskbarBeginDrag / TaskbarEndDrag),
//     and stealing it for a window-snap would compete with the
//     existing gesture. Documented in wiki/subsystems/Compositor.md
//     "Snap Zones."
// ---------------------------------------------------------------

namespace
{

// Hit-band width / corner box edge in pixels. 32 px matches
// Win10/11's Aero snap zone, large enough that a quick drag-
// to-edge doesn't require pixel-perfect aim.
constexpr u32 kSnapEdgePx = 32;
constexpr u32 kSnapCornerPx = 32;

// Armed snap zone. Compositor-locked: the mouse loop already
// holds the compositor lock around drag motion / drag release,
// and DesktopCompose reads under the same lock, so a plain
// scalar is safe — no separate spinlock.
SnapZone g_snap_preview_zone = SnapZone::None;

// Compute the screen-space rect a given snap zone would
// produce. Mirrors the geometry inside WindowSnap* / WindowMaximize
// so the preview rectangle is pixel-identical to what the
// commit would land. `zone == None` writes zeros.
void SnapZoneRect(SnapZone zone, u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    const u32 half_w = wa_w / 2u;
    const u32 half_h = wa_h / 2u;
    u32 rx = 0, ry = 0, rw = 0, rh = 0;
    switch (zone)
    {
    case SnapZone::Maximize:
        rx = wa_x;
        ry = wa_y;
        rw = wa_w;
        rh = wa_h;
        break;
    case SnapZone::Left:
        rx = wa_x;
        ry = wa_y;
        rw = half_w;
        rh = wa_h;
        break;
    case SnapZone::Right:
        rx = wa_x + half_w;
        ry = wa_y;
        rw = wa_w - half_w;
        rh = wa_h;
        break;
    case SnapZone::TopLeft:
        rx = wa_x;
        ry = wa_y;
        rw = half_w;
        rh = half_h;
        break;
    case SnapZone::TopRight:
        rx = wa_x + half_w;
        ry = wa_y;
        rw = wa_w - half_w;
        rh = half_h;
        break;
    case SnapZone::BottomLeft:
        rx = wa_x;
        ry = wa_y + half_h;
        rw = half_w;
        rh = wa_h - half_h;
        break;
    case SnapZone::BottomRight:
        rx = wa_x + half_w;
        ry = wa_y + half_h;
        rw = wa_w - half_w;
        rh = wa_h - half_h;
        break;
    case SnapZone::None:
    default:
        break;
    }
    if (x_out)
        *x_out = rx;
    if (y_out)
        *y_out = ry;
    if (w_out)
        *w_out = rw;
    if (h_out)
        *h_out = rh;
}

// Paint the armed preview as a translucent taskbar_accent rect.
// Called from DesktopCompose between WindowDrawAllOrdered and
// the tooltip / dialog layers. The ~25% alpha (0x40) reads as
// "this is a preview, not real chrome" without washing out the
// underlying windows.
void SnapPreviewCompose()
{
    if (g_snap_preview_zone == SnapZone::None)
        return;
    u32 x = 0, y = 0, w = 0, h = 0;
    SnapZoneRect(g_snap_preview_zone, &x, &y, &w, &h);
    if (w == 0 || h == 0)
        return;
    const u32 accent_rgb = ThemeCurrent().taskbar_accent & 0x00FFFFFFu;
    // 0x40 = 25 % alpha. ARGB packing matches FramebufferBlendFill.
    const u32 argb = (0x40u << 24) | accent_rgb;
    FramebufferBlendFill(x, y, w, h, argb);

    // Tactility lift: the preview gains an accent-tinted soft halo
    // so it reads as "the window will hover here" instead of a flat
    // filled rect. The translucent body fill above already implies
    // preview-ness; the halo adds the depth cue without changing
    // the affordance. No-op when tactility is disabled at runtime
    // or off for the theme.
    if (ThemeTactilityEffective())
    {
        RenderSoftShadow(static_cast<i32>(x), static_cast<i32>(y), w, h, 16U, 100U, accent_rgb);
    }
}

} // namespace

void SnapPreviewArm(SnapZone zone)
{
    g_snap_preview_zone = zone;
}

SnapZone SnapPreviewArmed()
{
    return g_snap_preview_zone;
}

void SnapZoneGetRect(SnapZone zone, u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    SnapZoneRect(zone, x_out, y_out, w_out, h_out);
}

SnapZone SnapPreviewHitTest(u32 cursor_x, u32 cursor_y)
{
    const auto fb = FramebufferGet();
    if (fb.width == 0 || fb.height == 0)
        return SnapZone::None;
    // WorkArea bounds the bottom edge — we ignore the taskbar
    // strip for the snap-zone hit-test so a cursor parked over
    // the taskbar doesn't arm a phantom preview.
    u32 wa_x = 0, wa_y = 0, wa_w = 0, wa_h = 0;
    WorkArea(&wa_x, &wa_y, &wa_w, &wa_h);
    const u32 wa_right = wa_x + wa_w; // exclusive
    const u32 wa_bot = wa_y + wa_h;   // exclusive — clamps out the taskbar
    if (cursor_y >= wa_bot)
        return SnapZone::None;

    const bool near_top = (cursor_y - wa_y) < kSnapCornerPx;
    const bool near_left = (cursor_x - wa_x) < kSnapCornerPx;
    const bool near_right = (wa_right > kSnapCornerPx) && (cursor_x >= wa_right - kSnapCornerPx);
    const bool near_bottom = (wa_bot > kSnapCornerPx) && (cursor_y >= wa_bot - kSnapCornerPx);

    // Corners take precedence over edges. Bottom corners ARE
    // exposed (they produce the bottom-left / bottom-right
    // quarter snaps) even though the bare bottom edge isn't.
    if (near_top && near_left)
        return SnapZone::TopLeft;
    if (near_top && near_right)
        return SnapZone::TopRight;
    if (near_bottom && near_left)
        return SnapZone::BottomLeft;
    if (near_bottom && near_right)
        return SnapZone::BottomRight;

    // Edges. Top → Maximize, sides → half-snap. Bottom edge has
    // no half-snap (the taskbar drag-snap owns that strip).
    if ((cursor_y - wa_y) < kSnapEdgePx)
        return SnapZone::Maximize;
    if ((cursor_x - wa_x) < kSnapEdgePx)
        return SnapZone::Left;
    if (wa_right > kSnapEdgePx && cursor_x >= wa_right - kSnapEdgePx)
        return SnapZone::Right;
    return SnapZone::None;
}

void WindowSetOpacity(WindowHandle h, u8 opacity)
{
    if (!WindowValid(h))
        return;
    g_windows[h].opacity = opacity;
}

u8 WindowGetOpacity(WindowHandle h)
{
    if (!WindowValid(h))
        return 0xFF;
    return g_windows[h].opacity;
}

void WindowSetPinned(WindowHandle h, bool pinned)
{
    if (!WindowValid(h))
        return;
    g_windows[h].pinned = pinned;
}

bool WindowIsPinned(WindowHandle h)
{
    return WindowValid(h) && g_windows[h].pinned;
}

void WindowClose(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].alive = false;
    // Clear the PE-requested cursor shape so the next-allocated
    // window starting in this slot (if/when dynamic re-use lands)
    // doesn't observe stale state. Cheap, deterministic; the
    // mouse-loop's per-packet hit-test relies on this flag being
    // false-by-default for kernel-owned windows.
    g_windows[h].requested_cursor_set = false;
    g_windows[h].requested_cursor = 0;
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

void WindowSetWheelHandler(WindowHandle h, WindowWheelFn fn)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].wheel_fn = fn;
}

void WindowSetScrollbar(WindowHandle h, const WindowScrollbarSurface& s)
{
    if (!WindowValid(h))
        return;
    g_windows[h].scrollbar = s;
}

bool WindowGetScrollbar(WindowHandle h, WindowScrollbarSurface* out)
{
    if (!WindowValid(h) || out == nullptr)
        return false;
    if (!g_windows[h].scrollbar.present)
        return false;
    *out = g_windows[h].scrollbar;
    return true;
}

void WindowSetScrollHandler(WindowHandle h, WindowScrollSetFn fn)
{
    if (!WindowValid(h))
        return;
    g_windows[h].scroll_fn = fn;
}

void WindowDispatchScroll(WindowHandle h, u32 first)
{
    if (!WindowValid(h))
        return;
    if (g_windows[h].scroll_fn != nullptr)
    {
        g_windows[h].scroll_fn(first);
    }
}

void WindowDispatchWheel(WindowHandle h, i32 /*client_x*/, i32 /*client_y*/, i32 dz, u32 screen_x, u32 screen_y,
                         u64 mk_buttons, u8 modifiers)
{
    if (!WindowValid(h) || dz == 0)
    {
        return;
    }
    if (g_windows[h].owner_pid > 0)
    {
        // Win32 contract: high word of wparam is signed delta in
        // multiples of WHEEL_DELTA (120); low word is button mask
        // (MK_LBUTTON / MK_RBUTTON / MK_SHIFT / ...). lParam packs
        // the screen-coord click point: low word = x, high word = y.
        // Modifiers don't go into wparam — Win32 PE apps test
        // GetKeyState themselves.
        constexpr u32 kWmMouseWheel = 0x020A;
        const i32 wheel_delta = dz * 120;
        const u64 wparam = ((static_cast<u64>(static_cast<u16>(static_cast<i16>(wheel_delta))) << 16) & 0xFFFF0000U) |
                           (mk_buttons & 0xFFFFU);
        const u64 lparam = (static_cast<u64>(screen_x & 0xFFFFU)) | ((static_cast<u64>(screen_y & 0xFFFFU)) << 16);
        WindowPostMessage(h, kWmMouseWheel, wparam, lparam);
        WindowMsgWakeAll();
        return;
    }
    if (g_windows[h].wheel_fn != nullptr)
    {
        g_windows[h].wheel_fn(dz, modifiers);
    }
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
        // Focus-aware drop shadow. Painted BEFORE the chrome so the
        // window covers the inner shadow bands; only the right +
        // bottom fringe shows. The active window gets a deeper /
        // stronger cast so it visibly hovers above the desktop in
        // the macOS / Win11 idiom; inactive windows get a shallow /
        // faint cast so they recede into the surface. Single-window
        // scenes still get the active treatment regardless of the
        // focus state — there's nothing else competing for the eye.
        //
        // When the active theme advertises tactility and the runtime
        // override hasn't disabled it, route through the 9-slice
        // atlas-based RenderSoftShadow (kernel/drivers/video/shadow.h,
        // Task 5 of the chrome-tactility plan) so corners get the
        // quadratic-falloff curve instead of the strip-only fringe
        // FramebufferDropShadow paints. The shallow strip primitive
        // remains the fallback for tactility=off themes (Amber,
        // HighContrast) + the runtime `tactility off` override.
        const bool only_window = (g_window_count == 1);
        const bool deep_cast = (is_active || only_window);
        if (ThemeTactilityEffective() && ThemeCurrent().shadow_intensity_active > 0)
        {
            const Theme& t = ThemeCurrent();
            const u32 radius = deep_cast ? 24U : 16U;
            const u8 opacity = deep_cast ? t.shadow_intensity_active : t.shadow_intensity_inactive;
            if (opacity > 0)
            {
                RenderSoftShadow(static_cast<i32>(drawn.x), static_cast<i32>(drawn.y), drawn.w, drawn.h, radius,
                                 opacity, 0x000000U);
            }
        }
        else
        {
            const u32 shadow_depth = deep_cast ? 6U : 2U;
            const u8 shadow_alpha = deep_cast ? 0x88U : 0x30U;
            FramebufferDropShadow(drawn.x, drawn.y, drawn.w, drawn.h, shadow_depth, shadow_alpha);
        }
        WindowDraw(drawn);
        // Rounded-corner approximation for the Duet theme. The
        // chrome itself is painted as a rectangle; we then
        // overpaint the four corner-quadrant pixels OUTSIDE a
        // 6-px radius curve with the desktop fill colour, so
        // the visible silhouette reads as rounded. Other themes
        // keep rectangular chrome (preserves their original v0
        // look bit-for-bit).
        // All Duet-family themes (slate Duet + light + 3 accent
        // variants + classic mode) share the rounded-corner
        // punch; Classic / Slate10 / Amber stay rectangular.
        // DuetClassic uses a smaller 4-px radius to match the
        // era's chunkier proportions vs the modern variants'
        // 6-px softness.
        const ThemeId tid = ThemeCurrentId();
        if (tid == ThemeId::Duet || tid == ThemeId::DuetLight || tid == ThemeId::DuetBlue ||
            tid == ThemeId::DuetViolet || tid == ThemeId::DuetGreen)
        {
            FramebufferPunchCorners(drawn.x, drawn.y, drawn.w, drawn.h, 6U, g_compose_desktop_rgb);
        }
        else if (tid == ThemeId::DuetClassic)
        {
            FramebufferPunchCorners(drawn.x, drawn.y, drawn.w, drawn.h, 4U, g_compose_desktop_rgb);
        }
        // Title text. White ink on the title-bar fill, 8-px top
        // padding + 8-px left padding so the first glyph clears
        // the 2-px outer border comfortably. Theme.title_text_scale
        // controls the bitmap-font scale (1 = 8-px glyphs, 2 =
        // 16-px). Vertical position centres the scaled text in
        // the (also-scaled) title bar so a 16-px glyph in a
        // 30-px title bar lands at y + 7 just like the 8-px
        // glyph in a 22-px title bar.
        u32 title_pixel_w = 0;
        const u32 ttscale_raw = ThemeCurrent().title_text_scale;
        const u32 ttscale = (ttscale_raw == 0) ? 1u : ttscale_raw;
        const u32 cell_w = 8u * ttscale;
        const u32 cell_h = 8u * ttscale;
        const u32 tbh_eff_for_title = EffectiveTitleHeight(drawn);
        const u32 title_y = drawn.y + ((tbh_eff_for_title > cell_h) ? (tbh_eff_for_title - cell_h) / 2 : 0);
        if (g_windows[h].title != nullptr)
        {
            // Theme-driven font dispatch: themes that opt in to the
            // TTF path try the rasterizer first; if no chrome font is
            // registered (TtfChromeFontGet returns nullptr) the
            // bitmap font runs as the fallback. Pixel height matches
            // the existing scaled cell size so the overall chrome
            // layout is identical between the two paths.
            const bool used_ttf = (ThemeCurrent().font_kind == Theme::FontKind::Ttf) &&
                                  TtfDrawString(drawn.x + 8, title_y, g_windows[h].title, 0x00FFFFFF, cell_h);
            if (!used_ttf)
            {
                FramebufferDrawStringScaled(drawn.x + 8, title_y, g_windows[h].title, 0x00FFFFFF, drawn.colour_title,
                                            ttscale);
            }
            const char* t = g_windows[h].title;
            u32 n = 0;
            while (t[n] != '\0')
            {
                ++n;
            }
            title_pixel_w = n * cell_w;
        }
        // Subtitle slot (Duet-era "context tag"). Painted in a
        // dimmer ink immediately right of the title with a 12-px
        // gap, capped at the close-button's left edge so it never
        // collides with the chrome. The "·" separator from the
        // prototype isn't in the 8x8 font's printable range, so we
        // use a plain '|' which is.
        const char* subtitle = g_windows[h].mut_subtitle;
        if (subtitle != nullptr && subtitle[0] != '\0' && title_pixel_w > 0)
        {
            const u32 tbh_for_sub = EffectiveTitleHeight(drawn);
            const u32 btn_pad = 4;
            const u32 btn_h_for_sub = (tbh_for_sub > 2 * btn_pad) ? tbh_for_sub - 2 * btn_pad : 0;
            const u32 btn_w_for_sub = EffectiveButtonWidth(btn_h_for_sub);
            const u32 close_left =
                (drawn.w > btn_w_for_sub + btn_pad) ? drawn.x + drawn.w - btn_w_for_sub - btn_pad : drawn.x + drawn.w;
            const u32 sub_x = drawn.x + 8 + title_pixel_w + 12;
            // Only paint if there's room for at least the
            // separator + 4 glyphs before the close button.
            if (sub_x + 5 * cell_w < close_left)
            {
                // Dim ink derived from the title — a brighter
                // shade reads against dark titles, a dimmer one
                // against bright titles. We use a fixed 60%-of-
                // white blend with the title bg as the bg colour
                // so the bitmap font's anti-aliased-by-bg trick
                // still works. Brighten just enough that the
                // subtitle reads as secondary, not background.
                const u32 ink = LightenRgb(drawn.colour_title, 96);
                const u32 max_chars = (close_left - sub_x) / cell_w;
                FramebufferDrawStringScaled(sub_x, title_y, "|", ink, drawn.colour_title, ttscale);
                if (max_chars > 2)
                {
                    char clipped[kWindowSubtitleStorage];
                    u32 n = 0;
                    while (subtitle[n] != '\0' && n < kWindowSubtitleStorage - 1 && n + 2 < max_chars)
                    {
                        clipped[n] = subtitle[n];
                        ++n;
                    }
                    clipped[n] = '\0';
                    FramebufferDrawStringScaled(sub_x + 2 * cell_w, title_y, clipped, ink, drawn.colour_title, ttscale);
                }
            }
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
        const u32 tbh_c = EffectiveTitleHeight(cc);
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
            default:
                // Unknown primitive kind — skip rather than render garbage.
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

        // Subtle "out of focus" dim. The Duet spec calls for ~3%
        // dim on unfocused windows; we apply a ~10% (alpha 0x18)
        // overlay over the whole window rect AFTER chrome +
        // widgets + display-list + content_fn. Source colour is
        // the desktop background (captured into
        // `g_compose_desktop_rgb` at the top of DesktopCompose),
        // so the blend washes the window toward the desktop
        // hue — reads as "fading away" rather than the previous
        // path's "darkening toward black", which was a misleading
        // cue on light themes. With slice 1's shadow surface in
        // place this is a real read-modify-write against the
        // in-progress paint, not a read of the live MMIO.
        // Skipped in single-window scenes (every window is
        // "active enough" when there's nothing else to compete
        // with).
        if (!is_active && g_window_count > 1)
        {
            const u32 overlay = (0x18u << 24) | (g_compose_desktop_rgb & 0x00FFFFFFu);
            FramebufferBlendFill(g_windows[h].chrome.x, g_windows[h].chrome.y, g_windows[h].chrome.w,
                                     g_windows[h].chrome.h, overlay);
        }
        // Per-window opacity overlay. Lays a desktop-coloured rect
        // at alpha = (0xFF - opacity) over the whole window so
        // lower opacity values fade the window toward the desktop
        // surface. Real per-pixel transparency (seeing through the
        // window to the underlying app stack) requires per-window
        // backbuffers and is the next-tier item in the plan; this
        // is the v0 stand-in. Skipped when opacity is fully opaque
        // (the common case).
        if (g_windows[h].opacity < 0xFF)
        {
            const u32 overlay_alpha = static_cast<u32>(0xFFu - g_windows[h].opacity);
            const u32 overlay = (overlay_alpha << 24) | (g_compose_desktop_rgb & 0x00FFFFFFu);
            FramebufferBlendFill(g_windows[h].chrome.x, g_windows[h].chrome.y, g_windows[h].chrome.w,
                                     g_windows[h].chrome.h, overlay);
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
        // Push the freshly-painted console to the active backend
        // (virtio-gpu flush). Without this the host display stays
        // at whatever the GPU init painted and the user never
        // sees the TTY-mode console.
        FramebufferPresent();
        return;
    }

    // Desktop paint stack (bottom to top):
    //   1. Desktop gradient fill
    //   2. Theme wallpaper (e.g. duet-arcs on the Duet theme)
    //   3. Framebuffer console (under windows — windows dragged
    //      over the console occlude it, which restores on next
    //      compose — standard z-order feel)
    //   4. Windows in z-order + their owned widgets
    //      (each inactive window gets a 10% dim overlay)
    //   5. Freestanding widgets (float on top of windows for v0)
    //   6. Banner (desktop-level label)
    //   7. Taskbar
    //   8. Menu (popup, on top of everything)
    // The cursor is not touched here — the mouse reader owns
    // CursorHide / CursorShow around this call.
    //
    // Desktop fill: a subtle vertical gradient from a slightly-
    // lifted shade of the theme's `desktop_bg` at the top to a
    // slightly darker shade at the bottom. Reads as ambient
    // depth without competing with window chrome for attention.
    // A pure black `desktop_rgb` (used by the login / TTY-flip
    // paint) skips the gradient since lighten / darken on 0
    // produces a flat result anyway — the resulting solid
    // FramebufferClear is faster.
    // Publish the desktop-fill colour for the chrome path's
    // rounded-corner punch (Duet theme). Set unconditionally —
    // black-screen modes (login, TTY-flip) get a 0 punch which
    // is still a sensible "behind the chrome" fallback.
    g_compose_desktop_rgb = desktop_rgb;

    // Redirect this whole pass into the offscreen shadow surface so
    // alpha-blend primitives composite against the in-progress frame
    // (slice 1 of the rasterizer / compositor / shell plan). If the
    // shadow allocator is unavailable, BeginCompose silently leaves
    // the writes targeting the live framebuffer — the rest of the
    // function is unchanged either way.
    FramebufferBeginCompose();

    if (desktop_rgb == 0)
    {
        FramebufferClear(0);
    }
    else
    {
        const auto info = FramebufferGet();
        const u32 top = LightenRgb(desktop_rgb, 18);
        const u32 bot = DarkenRgb(desktop_rgb, 22);
        FramebufferFillRectGradient(0, 0, info.width, info.height, top, bot);
        // Theme-dispatched wallpaper layer (duet-arcs on the
        // Duet theme; no-op on the other three for now).
        WallpaperPaint(desktop_rgb);
    }
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
        // 1-pixel offset shadow behind the banner so the white
        // ink reads on every theme's gradient bg without a hard
        // background-fill rectangle. The shadow is painted with
        // each glyph's bg = desktop_rgb (matches the gradient
        // closely enough that the shadow doesn't show up as a
        // smear) while the foreground is pure white.
        // On themes with a 30+ px title bar (Duet family) the
        // banner renders at 2x scale so the larger chrome has a
        // proportionate banner — first concrete consumer of
        // FramebufferDrawStringScaled. Compact themes stay 1x
        // so existing layouts don't shift.
        const u32 scale = (ThemeCurrent().title_bar_height >= 30) ? 2u : 1u;
        FramebufferDrawStringScaled(17, 9, banner, 0x00000000, desktop_rgb, scale);
        FramebufferDrawStringScaled(16, 8, banner, 0x00FFFFFF, desktop_rgb, scale);
    }
    // Snap-zone hover preview — translucent target rect painted
    // after every window so the preview lays on top of normal
    // chrome but under taskbar / menus / dialogs (the user is
    // looking at the desktop snap target, not staring at a
    // covered taskbar). No-op when no zone is armed.
    SnapPreviewCompose();
    TaskbarRedraw();
    MenuRedraw();
    CalendarRedraw();
    NetPanelRedraw();
    TrayFlyoutRedraw();
    NotifyRedraw();
    MagnifierRedraw();
    // DnD ghost — paints just below the cursor during an
    // active drag. Sits under the tooltip + dialogs so a
    // hovered tooltip / open dialog doesn't get visually
    // occluded by a stale ghost.
    DndCompose();
    // Tooltip — over chrome, under modal dialogs.
    WidgetTooltipRender();
    // Modal dialog (MessageBox / InputBox) — drawn AFTER every
    // other surface so the panel + dim overlay land on top of
    // windows, taskbar, menus, notifications. The cursor is
    // still painted by the mouse reader after this returns.
    DialogCompose();
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
    // Flush the shadow surface to the live framebuffer (no-op if
    // BeginCompose fell back to direct mode).
    FramebufferEndCompose();

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

bool WindowPeekMessageAny(u64 pid, WindowMsg* out)
{
    if (pid == 0 || out == nullptr)
    {
        return false;
    }
    // Fused walk: direct field reads instead of WindowIsAlive +
    // WindowOwnerPid + WindowPeekMessage per iteration. Each of
    // those public APIs revalidates the handle; we already know
    // i < g_window_count and we're reading the live struct
    // directly.
    for (u32 i = 0; i < g_window_count; ++i)
    {
        const auto& w = g_windows[i];
        if (!w.alive || w.owner_pid != pid || w.msgs.count == 0)
            continue;
        *out = w.msgs.buf[w.msgs.head];
        return true;
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

bool WindowSetSubtitle(WindowHandle h, const char* ascii_src)
{
    if (!WindowValid(h))
    {
        return false;
    }
    StoreSubtitle(g_windows[h], ascii_src);
    return true;
}

const char* WindowGetSubtitle(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return nullptr;
    }
    return g_windows[h].mut_subtitle;
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

void WindowSetModifierState(u8 modifiers)
{
    g_modifier_state = modifiers;
}

u8 WindowModifierState()
{
    return g_modifier_state;
}

void WindowSetDoubleClickTicks(u32 ticks)
{
    // Floor + cap so a misconfigured Settings input can't make
    // DC undetectable (0 ticks) or wedge the user (a 30-second
    // threshold). 5..200 ticks ≈ 50 ms..2 s.
    if (ticks < 5)
        ticks = 5;
    if (ticks > 200)
        ticks = 200;
    g_dbl_click_ticks = ticks;
}

u32 WindowDoubleClickTicks()
{
    return g_dbl_click_ticks;
}

void WindowSetMouseSensitivity(u8 scale)
{
    g_mouse_sensitivity = scale;
}

u8 WindowMouseSensitivity()
{
    return g_mouse_sensitivity;
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

namespace
{

bool ClipboardEqual(const char* a, u32 a_len, const char* b, u32 b_len)
{
    if (a_len != b_len)
        return false;
    for (u32 i = 0; i < a_len; ++i)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

// Push the current active clipboard onto the front of the history
// ring. Dedupes against slot 0 — setting the same payload twice
// leaves the ring unchanged. Caller must hold the compositor /
// clipboard discipline (which today amounts to "called from the
// keyboard reader thread").
void ClipboardHistoryPushFront(const char* text, u32 len)
{
    if (len == 0)
        return;
    if (g_clipboard_hist[0].used && ClipboardEqual(g_clipboard_hist[0].text, g_clipboard_hist[0].len, text, len))
        return;
    // Shift slots [0..N-2] down to [1..N-1]; oldest falls off.
    for (u32 i = kWindowClipboardHistoryDepth - 1; i > 0; --i)
    {
        g_clipboard_hist[i] = g_clipboard_hist[i - 1];
    }
    auto& s = g_clipboard_hist[0];
    s.used = true;
    s.len = len;
    for (u32 i = 0; i < len; ++i)
        s.text[i] = text[i];
    s.text[len] = '\0';
}

} // namespace

void WindowClipboardSetText(const char* text)
{
    // Capture the previous content first so we can promote it to
    // history before overwriting. An empty previous slot is not
    // pushed (nothing to remember).
    char prev[kWindowClipboardMax];
    const u32 prev_len = g_clipboard_len;
    for (u32 i = 0; i < prev_len; ++i)
        prev[i] = g_clipboard[i];

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

    // Don't push if the new content is identical to the old —
    // that's just a no-op set, not a clipboard transition.
    if (!ClipboardEqual(prev, prev_len, g_clipboard, g_clipboard_len))
    {
        ClipboardHistoryPushFront(prev, prev_len);
    }
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

u32 WindowClipboardHistoryCount()
{
    u32 n = 0;
    for (u32 i = 0; i < kWindowClipboardHistoryDepth; ++i)
    {
        if (g_clipboard_hist[i].used)
            ++n;
    }
    return n;
}

u32 WindowClipboardHistoryGet(u32 idx, char* dst, u32 cap)
{
    if (dst == nullptr || cap == 0)
        return 0;
    if (idx >= kWindowClipboardHistoryDepth)
        return 0;
    const auto& s = g_clipboard_hist[idx];
    if (!s.used)
        return 0;
    u32 n = s.len;
    if (n > cap - 1)
        n = cap - 1;
    for (u32 i = 0; i < n; ++i)
        dst[i] = s.text[i];
    dst[n] = '\0';
    return n;
}

bool WindowClipboardHistoryRotate()
{
    // Rotate: active <- ring[0]; ring shifts left so older entries
    // become reachable. The displaced active is pushed onto the
    // ring front (so re-rotating cycles the most recent two).
    if (!g_clipboard_hist[0].used)
        return false;

    char old_active[kWindowClipboardMax];
    const u32 old_active_len = g_clipboard_len;
    for (u32 i = 0; i < old_active_len; ++i)
        old_active[i] = g_clipboard[i];
    old_active[old_active_len] = '\0';

    // Promote ring[0] to active.
    const u32 nl = g_clipboard_hist[0].len;
    for (u32 i = 0; i < nl; ++i)
        g_clipboard[i] = g_clipboard_hist[0].text[i];
    g_clipboard[nl] = '\0';
    g_clipboard_len = nl;

    // Shift the rest of the ring down, freeing the tail slot.
    for (u32 i = 0; i + 1 < kWindowClipboardHistoryDepth; ++i)
    {
        g_clipboard_hist[i] = g_clipboard_hist[i + 1];
    }
    auto& tail = g_clipboard_hist[kWindowClipboardHistoryDepth - 1];
    tail.used = false;
    tail.len = 0;
    tail.text[0] = '\0';

    // The displaced active goes to the new ring front so the user
    // can rotate back to it.
    if (old_active_len > 0)
    {
        ClipboardHistoryPushFront(old_active, old_active_len);
    }
    return true;
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
    default:
        return kWindowInvalid;
    }
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

bool WindowShowDesktopToggle()
{
    if (g_show_desktop_active)
    {
        // Restore phase: re-show every window in the snapshot
        // mask that's still alive. Windows the user closed
        // during the "showing desktop" interval drop off the
        // mask implicitly (their slot may still be alive but
        // we honor whatever the visible-flag logic decides;
        // restoring "visible" on a dead window is a no-op).
        for (u32 i = 0; i < g_window_count && i < 32; ++i)
        {
            if ((g_show_desktop_mask & (1u << i)) == 0)
                continue;
            if (!g_windows[i].alive)
                continue;
            g_windows[i].visible = true;
        }
        g_show_desktop_mask = 0;
        g_show_desktop_active = false;
        return false;
    }
    // Activate phase: snapshot which windows are currently
    // visible, then hide them all. The mask is bounded to 32
    // bits; if kMaxWindows ever grows past that the snapshot
    // gets truncated and the extra-slot windows stay hidden
    // until reopened — kMaxWindows is 16 today so we have
    // headroom.
    g_show_desktop_mask = 0;
    bool any_alive = false;
    for (u32 i = 0; i < g_window_count && i < 32; ++i)
    {
        if (!g_windows[i].alive)
            continue;
        any_alive = true;
        if (g_windows[i].visible)
        {
            g_show_desktop_mask |= (1u << i);
            g_windows[i].visible = false;
        }
    }
    if (!any_alive)
    {
        // Nothing to hide — leave the toggle in its inactive
        // state so the next click triggers a fresh snapshot.
        return false;
    }
    g_show_desktop_active = true;
    return true;
}

bool WindowShowDesktopActive()
{
    return g_show_desktop_active;
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

void WindowSetRequestedCursorShape(WindowHandle h, u8 shape)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].requested_cursor = shape;
    g_windows[h].requested_cursor_set = true;
}

void WindowClearRequestedCursorShape(WindowHandle h)
{
    if (!WindowValid(h))
    {
        return;
    }
    g_windows[h].requested_cursor_set = false;
    g_windows[h].requested_cursor = 0;
}

bool WindowGetRequestedCursorShape(WindowHandle h, u8* shape_out)
{
    if (!WindowValid(h) || !g_windows[h].requested_cursor_set)
    {
        return false;
    }
    if (shape_out != nullptr)
    {
        *shape_out = g_windows[h].requested_cursor;
    }
    return true;
}

} // namespace duetos::drivers::video
