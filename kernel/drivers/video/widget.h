#pragma once

#include "../../core/types.h"

/*
 * Minimal widget layer — v0.
 *
 * The simplest thing that introduces UI events to the tree: a
 * "button" is a rectangle with two colours (normal + pressed)
 * and an owner id. An event router takes {cursor_x, cursor_y,
 * button_mask} from the mouse reader, tests each registered
 * button's bounds, and transitions visual state on edges.
 *
 * Design choices that will be revisited:
 *   - Fixed-size widget table, no dynamic allocation. Boot-time
 *     widgets only. Every GUI grows this into a proper scene
 *     graph, but a flat array is correct at the point where
 *     "there are two buttons on screen at boot."
 *   - No event callbacks yet — the router returns the id of the
 *     widget that transitioned so the caller can switch on it.
 *     Wiring a function-pointer-per-widget when exactly one
 *     caller exists is premature abstraction.
 *   - Re-rendering a widget is done behind a CursorHide/Show
 *     bracket so the cursor's backing-pixel cache doesn't hold
 *     stale colours from before the repaint.
 *   - Buttons are drawn as filled rectangles with a 2-pixel
 *     outline. No rounded corners, no gradient, no text label
 *     (labels wait on the bitmap font slice).
 *
 * Context: kernel. Register widgets during boot, drive events
 * from the mouse reader thread.
 */

namespace duetos::drivers::video
{

constexpr u32 kWidgetInvalid = 0xFFFFFFFFu;

struct ButtonWidget
{
    u32 id;         // caller-assigned, returned by the router on events
    u32 x, y, w, h; // bounds in framebuffer pixels when owner=kWindowInvalid
    u32 colour_normal;
    u32 colour_pressed;
    u32 colour_border;
    u32 colour_label;  // ink colour for the label text
    const char* label; // caller-owned, nullable (skips text draw)

    // When `owner` is a valid WindowHandle, `x` / `y` are
    // interpreted as OFFSETS from the owning window's origin —
    // the button moves with its window on every drag. When
    // `owner == kWindowInvalid` (the default for zero-init),
    // `x` / `y` are absolute framebuffer coordinates and the
    // button stays put regardless of which window is on top.
    u32 owner;

    bool pressed; // current visual state
    u8 _pad[3];
};

/// Register a button. Copies the descriptor into the widget table.
/// Returns true on success, false if the table is full. The `id`
/// field is echoed back by `WidgetRouteMouse` to identify which
/// button transitioned — callers own id allocation.
bool WidgetRegisterButton(const ButtonWidget& button);

/// Paint every registered widget in registration order. Intended
/// to be called once after the desktop background fill and before
/// the cursor is rendered. Idempotent.
void WidgetDrawAll();

/// Feed a mouse state sample to the router. If any widget changes
/// visual state (press or release edge), the router returns that
/// widget's id; otherwise returns `kWidgetInvalid`. Only one
/// transition per call — callers that want to see multiple should
/// loop until the router returns kWidgetInvalid (for v0 a single
/// packet can trigger at most one transition since we only track
/// a single button bit).
u32 WidgetRouteMouse(u32 cursor_x, u32 cursor_y, u8 button_mask);

// ---------------------------------------------------------------
// Window chrome + registry.
//
// A window is a rectangle with "Windows 98-ish" chrome: outer
// dark border, coloured title bar, light client area, a close-
// button square in the top-right. Registered windows carry a
// title string (rendered via the 8x8 font) and participate in a
// z-ordered draw stack — later registrations paint on top of
// earlier ones, and `WindowRaise` moves a window to the top.
// ---------------------------------------------------------------

constexpr u32 kWindowInvalid = 0xFFFFFFFFu;
constexpr u32 kMaxWindows = 6;

using WindowHandle = u32;

struct WindowChrome
{
    u32 x, y, w, h;
    u32 colour_border;
    u32 colour_title;     // title bar fill
    u32 colour_client;    // body fill
    u32 colour_close_btn; // close-button square fill
    u32 title_height;     // pixels from top devoted to title bar
};

/// Paint one window's chrome directly (legacy one-shot path).
/// Idempotent. No-op on zero dimensions or unavailable framebuffer.
void WindowDraw(const WindowChrome& w);

/// Register a window + its title string. Returns a handle, or
/// `kWindowInvalid` if the table is full. The title pointer is
/// stored by reference — caller owns the memory and must keep it
/// alive for the window's lifetime. Newly-registered windows go
/// to the TOP of the z-order.
WindowHandle WindowRegister(const WindowChrome& chrome, const char* title);

/// Move `h` to the top of the z-order so the next draw pass
/// paints it last (i.e. on top of every other window). Also
/// sets `h` as the active window — the "raised == active"
/// coupling matches every desktop OS that doesn't have
/// focus-follows-mouse turned on. No-op if the handle is
/// invalid; safe to call when already topmost (refreshes
/// active state without re-ordering).
void WindowRaise(WindowHandle h);

/// Currently active window handle, or `kWindowInvalid` if
/// none. Active == focused for keyboard routing purposes and
/// highlighted in title-bar chrome.
WindowHandle WindowActive();

/// Cycle activation to the next alive window in z-order (wraps).
/// Also raises that window so it becomes topmost. No-op if zero
/// or one alive windows exist. Wired to Alt+Tab in the keyboard
/// reader.
void WindowCycleActive();

/// Set absolute position. Width / height / colours are unchanged.
/// Clamps so the window stays entirely within the framebuffer.
void WindowMoveTo(WindowHandle h, u32 x, u32 y);

/// Read back the current bounds. `x_out` / `y_out` / `w_out` /
/// `h_out` are populated on success; all four are nullable.
/// Returns false if the handle is invalid.
bool WindowGetBounds(WindowHandle h, u32* x_out, u32* y_out, u32* w_out, u32* h_out);

/// Update the chrome colours of an existing window in place.
/// Used by the theme module when the user cycles themes — the
/// window's bounds, title pointer, and z-order position all
/// stay; only the four chrome colours change. Caller owns the
/// follow-up DesktopCompose that paints the new palette.
/// No-op if the handle is invalid.
void WindowSetColours(WindowHandle h, u32 border_rgb, u32 title_rgb, u32 client_rgb, u32 close_rgb);

/// Return the topmost window whose bounds contain (x, y), or
/// `kWindowInvalid` if none do. Walks the z-order from top to
/// bottom — matches the visual stacking order a user expects
/// when clicking on overlapping windows.
WindowHandle WindowTopmostAt(u32 x, u32 y);

/// True iff (x, y) is inside `h`'s title bar (the strip from the
/// window's top down to `title_height` pixels).
bool WindowPointInTitle(WindowHandle h, u32 x, u32 y);

/// True iff (x, y) is inside the close-button square in the
/// top-right corner of `h`'s title bar — same geometry the
/// WindowDraw chrome paints.
bool WindowPointInCloseBox(WindowHandle h, u32 x, u32 y);

/// Mark `h` closed: the window stops drawing, stops participating
/// in hit-testing, and its widgets (buttons with owner=h) also
/// disappear. The handle stays valid — no re-use — but the slot
/// is effectively leaked for the rest of boot. A future session
/// (delete / re-register, handle pools) cleans that up.
void WindowClose(WindowHandle h);

/// Total windows ever registered — dead + alive. Handles are
/// `0 .. WindowRegistryCount() - 1`; iterate and filter by
/// `WindowIsAlive` for the live set.
u32 WindowRegistryCount();

/// True iff `h` is a valid registered slot AND the window has not
/// been closed.
bool WindowIsAlive(WindowHandle h);

/// Return the title pointer stored at registration (not copied).
/// `nullptr` if the handle is invalid or the window is dead.
const char* WindowTitle(WindowHandle h);

/// Optional content-paint callback. Invoked from
/// WindowDrawAllOrdered after the window's chrome + owned
/// widgets, receiving the client-area rectangle (everything
/// inside the border + title bar, in framebuffer coordinates).
/// Callback is responsible for NOT drawing outside the rect.
/// `nullptr` clears any previously-registered drawer. The
/// cookie is passed back unchanged.
using WindowContentFn = void (*)(u32 x, u32 y, u32 w, u32 h, void* cookie);
void WindowSetContentDraw(WindowHandle handle, WindowContentFn fn, void* cookie);

/// Paint every registered window in z-order (bottom first, top
/// last) + render the stored title string across each title bar
/// in the default ink colour. Intended as part of a full-desktop
/// repaint pass.
void WindowDrawAllOrdered();

/// Full-desktop repaint. Fills the framebuffer with `desktop_rgb`,
/// renders a banner string across the top, draws every window
/// in z-order, then paints every widget. Caller is responsible
/// for CursorHide / CursorShow around this call if the cursor
/// is currently visible — the desktop compose path does NOT
/// manage cursor save-restore itself (the cursor lives "above"
/// the desktop in the logical paint stack and the mouse reader
/// owns when to show / hide it).
void DesktopCompose(u32 desktop_rgb, const char* banner);

/// Serialise access to every GUI-side mutable data structure:
/// cursor backing, window registry, widget table, console
/// buffer, framebuffer writes. Any task touching UI state
/// (mouse reader, keyboard reader, future compositor helpers)
/// MUST bracket its work with CompositorLock / CompositorUnlock.
/// Internally a plain sched::Mutex with FIFO hand-off — safe
/// to block in task context, NEVER call from IRQ.
void CompositorLock();
void CompositorUnlock();

// ---------------------------------------------------------------
// Display mode — desktop (windows + taskbar + cursor) vs TTY
// (fullscreen console only). Single flag; DesktopCompose branches
// on it. The two modes share one framebuffer console buffer, so
// the scrollback is preserved across mode flips.
// ---------------------------------------------------------------

enum class DisplayMode : u8
{
    Desktop = 0,
    Tty = 1,
};

/// Read the current display mode.
DisplayMode GetDisplayMode();

/// Switch modes. The caller is expected to re-anchor / recolour
/// the console (ConsoleSetOrigin / ConsoleSetColours) to fit the
/// new mode, then trigger a DesktopCompose so the new layout
/// appears on screen. This function is pure state — no paint.
void SetDisplayMode(DisplayMode mode);

} // namespace duetos::drivers::video
