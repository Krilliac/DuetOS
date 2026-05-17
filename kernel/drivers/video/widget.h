#pragma once

#include "util/types.h"

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

/// Cursor-shape hit-test. True iff (cx, cy) lands inside any
/// alive button widget's bounds AND the button's owner window
/// (if any) is alive + visible. Used by the mouse loop to flip
/// the cursor sprite to `Hand` when hovering a clickable.
bool WidgetCursorOverButton(u32 cx, u32 cy);

/// Track cursor hover for tooltips. Called from the mouse loop
/// every packet; the implementation timestamps the first
/// hover-on-a-widget so a 1-second linger triggers a tooltip
/// in the next compose.
void WidgetTooltipTrack(u32 cx, u32 cy, u64 now_tick);

/// Render a tooltip if one is currently armed. Called from
/// `DesktopCompose` after every other surface paints (just
/// before the dialog overlay) so the tooltip lands above
/// chrome but below modal dialogs.
void WidgetTooltipRender();

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
// Headroom split: 6 slots for boot-time built-in apps (Calculator,
// Notepad, Task Manager, Kernel Log, Files, Clock), 10 slots for
// ring-3 windows registered via SYS_WIN_CREATE from user32.dll's
// CreateWindowExA/W bridge. 16 is a round number well under any
// real-world Win32 program's window budget and small enough that
// the kMaxWindows-sized static arrays still fit comfortably in
// .bss. A future slice replaces this with a dynamic table when
// some program legitimately needs more than 16.
constexpr u32 kMaxWindows = 16;

using WindowHandle = u32;

/// Maximum ASCII bytes stored in a window's mutable title buffer
/// (NUL included). Matches the syscall-side `kWinTitleMax` but
/// kept independent so this header has no dependency on
/// `syscall/syscall.h`.
constexpr u32 kWindowTitleStorage = 64;

/// Maximum ASCII bytes stored in a window's optional subtitle
/// buffer (NUL included). The subtitle is a Duet-era metadata
/// field — apps that opt in (Inspect: "PE32+ · x86_64", Kernel
/// Log: "/sys/klog · live") publish a one-line context string
/// next to the title. The kernel chrome path reads it lazily;
/// themes that don't render it (Classic / Slate10 / Amber)
/// simply ignore the field.
constexpr u32 kWindowSubtitleStorage = 48;

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

/// Resize-edge hit zones. `None` = not on a border; the others
/// pick which edge to drag. The hit zone is `kWindowResizeBorderPx`
/// pixels wide; corner overlaps are resolved with a vertical
/// preference (top/bottom win over left/right) — adequate for a
/// 4-edge resize without true diagonal cursors.
enum class WindowResizeEdge : u8
{
    None = 0,
    Left = 1,
    Right = 2,
    Top = 3,
    Bottom = 4,
    TopLeft = 5,
    TopRight = 6,
    BottomLeft = 7,
    BottomRight = 8,
};

/// Pixel width of the resize-detection band along each edge.
constexpr u32 kWindowResizeBorderPx = 4;

/// Hit-test (cx, cy) against `h`'s outer-border resize zones.
/// Returns the matching edge or `None`. The title bar takes
/// priority over the top edge — clicks in the title still
/// drag-to-move, not drag-to-resize.
WindowResizeEdge WindowPointInResizeEdge(WindowHandle h, u32 cx, u32 cy);

/// Read the bounds + apply a resize delta on `h`. `edge` picks
/// which side moves; `cur_x` / `cur_y` is the live cursor; the
/// caller passes the window's bounds at drag-start so the
/// resize is anchored. Clamps to a minimum 80×60 size and to
/// the framebuffer. No-op for `None`.
void WindowResizeFromEdge(WindowHandle h, WindowResizeEdge edge, u32 anchor_x, u32 anchor_y, u32 anchor_w, u32 anchor_h,
                          i32 dx, i32 dy);

/// True iff (x, y) is inside the close-button square in the
/// top-right corner of `h`'s title bar — same geometry the
/// WindowDraw chrome paints.
bool WindowPointInCloseBox(WindowHandle h, u32 x, u32 y);

/// True iff (x, y) is inside the maximize/restore button —
/// the second-from-the-right title-bar control box. Same
/// per-side padding + side as the close box.
bool WindowPointInMaxBox(WindowHandle h, u32 x, u32 y);

/// True iff (x, y) is inside the minimize button — the
/// third-from-the-right title-bar control box.
bool WindowPointInMinBox(WindowHandle h, u32 x, u32 y);

/// Hide the window (SW_HIDE-style minimize). Does NOT reap the
/// slot — the taskbar tab stays so the user can re-show via the
/// tab click. No-op if the window is already hidden or invalid.
void WindowMinimize(WindowHandle h);

/// Maximize: snapshot current bounds + expand to the full
/// framebuffer minus the taskbar strip. Idempotent — calling on
/// an already-maximized window is a no-op (the snapshot is NOT
/// overwritten). The window stays maximized until `WindowRestore`
/// or until it's resized through other means (which clears the
/// maximized flag without restoring the snapshot).
void WindowMaximize(WindowHandle h);

/// Restore the window to its pre-maximize bounds. No-op if the
/// window isn't currently maximized.
void WindowRestore(WindowHandle h);

/// True iff `h` is currently in the maximized state. False for
/// invalid handles or windows that have never been maximized.
bool WindowIsMaximized(WindowHandle h);

/// Snap `h` to the left half of the framebuffer minus the
/// taskbar reserve at the bottom. Clears the maximized flag.
/// No-op for invalid handles. Mirrors Win10's Win+Left tile.
void WindowSnapLeft(WindowHandle h);

/// Snap `h` to the right half. Mirrors Win10's Win+Right.
void WindowSnapRight(WindowHandle h);

/// Snap `h` to the top / bottom half. Mirrors Win10's Win+Up /
/// Win+Down tile chords. Together with SnapLeft / SnapRight
/// gives a complete four-direction tile keyboard surface.
void WindowSnapTop(WindowHandle h);
void WindowSnapBottom(WindowHandle h);

/// Per-window opacity, 0..255. 0xFF = fully opaque (default).
/// Lower values fade the window via a post-paint black-alpha
/// overlay — fake-transparency cue without a real compositor
/// backbuffer. No-op for invalid handles.
void WindowSetOpacity(WindowHandle h, u8 opacity);

/// Read the per-window opacity. Returns 0xFF for invalid
/// handles so callers don't accidentally treat unknown
/// windows as fully transparent.
u8 WindowGetOpacity(WindowHandle h);

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

/// Per-window mouse-wheel callback. `dz` is the signed wheel-tick
/// delta (positive = scroll up / away from user) clamped to ±8 by
/// the dispatcher. `modifiers` is a bitmask of `kKeyMod*` values
/// captured at dispatch time so handlers can branch on Ctrl+wheel
/// (typically zoom) vs. plain wheel (scroll). Native windows
/// register a handler to consume wheel motion when the cursor is
/// over their client area; PE-owned windows ignore this and
/// receive `WM_MOUSEWHEEL` via the message queue instead.
using WindowWheelFn = void (*)(i32 dz, u8 modifiers);
void WindowSetWheelHandler(WindowHandle h, WindowWheelFn fn);

/// Per-window scrollbar geometry + state, populated by the app's
/// DrawFn each compose. The kernel's mouse loop hit-tests against
/// this to enable click-on-track + drag-the-thumb without each
/// app re-implementing the geometry. `present == false` disables
/// scrollbar input routing for the window (the visual bar is
/// also skipped).
struct WindowScrollbarSurface
{
    bool present;
    u8 _pad[3];
    // Bar bounds in framebuffer coords. App computes from its
    // DrawFn's (cx, cy, cw, ch) — just before painting the bar.
    u32 x, y, w, h;
    u32 total;   // total rows of content
    u32 visible; // visible rows in the viewport
    u32 first;   // current top-row offset
};

/// Apps invoke this every compose with their current scrollbar
/// geometry. Setting present=false stashes nothing.
void WindowSetScrollbar(WindowHandle h, const WindowScrollbarSurface& s);

/// Read back the most recent scrollbar surface for `h`. Returns
/// false if none has been registered or `present == false`.
bool WindowGetScrollbar(WindowHandle h, WindowScrollbarSurface* out);

/// Notify the owning app that the user just changed the
/// scrollbar's `first` (via track click or thumb drag). Apps
/// register a callback to apply the new value to their state.
using WindowScrollSetFn = void (*)(u32 first);
void WindowSetScrollHandler(WindowHandle h, WindowScrollSetFn fn);

/// Fire the registered scroll handler. Called by the mouse-loop
/// after a hit-test resolves a new `first`.
void WindowDispatchScroll(WindowHandle h, u32 first);

/// Deliver a wheel event to `h`. Native owner → calls the
/// registered `WindowWheelFn` (no-op if none). PE owner
/// (`owner_pid > 0`) → posts `WM_MOUSEWHEEL` (0x020A) with
/// `wparam = (i16(dz * 120) << 16) | mk_buttons`,
/// `lparam = (screen_y << 16) | screen_x` per Win32 contract.
/// `client_x` / `client_y` are unused today but reserved so a
/// future scroll-zone-aware widget layer can hit-test inside the
/// client area without recomputing screen coords.
void WindowDispatchWheel(WindowHandle h, i32 client_x, i32 client_y, i32 dz, u32 screen_x, u32 screen_y, u64 mk_buttons,
                         u8 modifiers);

// ---------------------------------------------------------------
// Per-window ownership + message queue + GDI display list.
//
// Ring-3 windows registered via SYS_WIN_CREATE carry the owning
// process's pid so the process-exit reaper can close every window
// belonging to a dying process in one walk. Kernel-owned boot
// windows (Calculator, Notepad, ...) use owner_pid == 0 so the
// reaper never touches them.
//
// Each window owns a small fixed-size message ring that
// SYS_WIN_POST_MSG enqueues into and SYS_WIN_GET/PEEK_MSG
// dequeues from. Overflow drops the oldest message (standard
// finite-queue policy for input events).
//
// Each window also owns a small display list of GDI primitives —
// FillRect / TextOut / Rectangle recordings — that the compositor
// replays after chrome paint on every DesktopCompose. Display-list
// overflow drops oldest; callers that want a clean slate call
// WindowClearDisplayList first (backing WM_PAINT / InvalidateRect
// with bErase = TRUE).
// ---------------------------------------------------------------

/// Maximum messages queued per window. Oldest-dropped on overflow.
constexpr u32 kWinMsgQueueDepth = 32;

/// Maximum recorded GDI primitives per window. Oldest-dropped.
constexpr u32 kWinDisplayListDepth = 32;

/// Maximum ASCII text length stored per TextOut primitive.
constexpr u32 kWinTextOutMax = 47; // + NUL = 48

struct WindowMsg
{
    u32 hwnd_biased; // HWND as seen by user32 (biased +1)
    u32 message;     // WM_KEYDOWN / WM_CHAR / WM_CLOSE / WM_QUIT / ...
    u64 wparam;
    u64 lparam;
};

enum class WinGdiPrimKind : u8
{
    None = 0,
    FillRect,      // x,y,w,h,colour → solid fill relative to client origin
    TextOut,       // x,y,colour,text → 8x8 ASCII glyphs
    Rectangle,     // x,y,w,h,colour → 1-px outline
    Line,          // x,y,w,h,colour — (x,y) → (x+w, y+h) Bresenham line
    Ellipse,       // x,y,w,h,colour — 1-px outline, midpoint algorithm
    FilledEllipse, // x,y,w,h,colour — solid fill, integer test, no sqrt
    Pixel,         // x,y,colour — single client-local pixel
    Blit,          // x,y,w,h,pool_off → BGRA8888 rect from the window's blit pool
};

struct WinGdiPrim
{
    WinGdiPrimKind kind;
    u8 _pad[3];
    i32 x, y;
    i32 w, h; // Rectangle / FillRect / Blit: width/height; Line: dx/dy
    u32 colour_rgb;
    u32 pool_off;                  // Blit only: byte offset into RegisteredWindow::blit_pool
    char text[kWinTextOutMax + 1]; // NUL-terminated ASCII (TextOut only)
};

// Per-window staging pool for BitBlt-style pixel data. Each Blit
// primitive references a byte range inside this pool. 256 KiB
// holds 64 Ki px at 32 bpp — up to a 256×256 blit, four 128×128
// blits, or sixteen 64×64 blits. Sized to fit the dx_demo_window
// PE's 256x256 D3D back buffer in one shot. The pool resets every
// time `prim_count` resets (i.e. on every fresh frame the window
// records); see `PrimListAppend`.
inline constexpr u32 kWinBlitPoolBytes = 256 * 1024;

/// Set the owning pid on `h`. Ring-3-created windows call this
/// from the SYS_WIN_CREATE handler; boot-time windows leave it at
/// the default 0 (kernel-owned, never reaped).
void WindowSetOwnerPid(WindowHandle h, u64 pid);

/// Enqueue a message on `h`. Returns false if the handle is
/// invalid; on queue full the oldest message is evicted and the
/// call still returns true.
bool WindowPostMessage(WindowHandle h, u32 message, u64 wparam, u64 lparam);

/// Dequeue a message from `h` (FIFO). Returns false if the queue
/// is empty or the handle is invalid. Sets `*out` on success.
bool WindowPopMessage(WindowHandle h, WindowMsg* out);

/// Peek the head message without removing it. Returns false on
/// empty / invalid handle.
bool WindowPeekMessage(WindowHandle h, WindowMsg* out);

/// Pop the first pending message across ANY alive window owned
/// by `pid`. Matches Win32 GetMessage(hWnd=NULL) semantics scoped
/// to the calling process. Returns false if no queued message
/// exists across every window owned by `pid`.
bool WindowPopMessageAny(u64 pid, WindowMsg* out);

/// True iff at least one alive window owned by `pid` has a
/// non-empty message queue. Non-blocking — the caller's message
/// pump polls this, yields on false, and re-enters GetMessage.
bool WindowAnyMessagePending(u64 pid);

/// Peek (no remove) the first pending message across ANY alive
/// window owned by `pid`. Walks the window table once with
/// direct field accesses, fusing what was three nested public-API
/// calls (WindowIsAlive + WindowOwnerPid + WindowPeekMessage) per
/// iteration in the caller. Returns false if no message exists.
bool WindowPeekMessageAny(u64 pid, WindowMsg* out);

/// Close every alive window whose owner_pid matches `pid`. Called
/// from `ProcessRelease` when the last task holding a Process
/// drops its reference — guarantees that a ring-3 PE that exited
/// without DestroyWindow never leaks a compositor slot. No-op for
/// pid == 0 (would close every kernel-owned boot window).
u32 WindowReapByOwner(u64 pid);

/// Block the current task on the global message wait queue for
/// up to `timeout_ticks` (10 ms per tick). Returns when woken
/// by `WindowMsgWakeAll` OR when the timeout expires. Caller
/// must hold interrupts disabled across the "queue empty check"
/// and this call — same contract as `sched::WaitQueueBlockTimeout`.
/// Wakes are broadcast: every blocker re-checks its own queue
/// after return, so spurious wakes are expected and the caller
/// must loop. The timeout is also a safety net against a lost
/// wake landing in the narrow window between "check queue
/// empty" and "enter wait queue".
void WindowMsgWaitBlockTimeout(u64 timeout_ticks);

/// Wake every task blocked in `WindowMsgWaitBlockTimeout`.
/// Called from the PostMessage syscall and the keyboard / mouse
/// routers after appending a message. Safe from IRQ context.
void WindowMsgWakeAll();

/// Append a solid fill primitive to `h`'s display list. Coords
/// are in window-client-local pixels (origin = top-left of the
/// client area, just below the title bar). Overflow evicts the
/// oldest primitive so long-running redrawers don't leak.
void WindowClientFillRect(WindowHandle h, i32 x, i32 y, i32 w, i32 hgt, u32 rgb);

/// Append a 1-pixel rectangle outline primitive.
void WindowClientRectangle(WindowHandle h, i32 x, i32 y, i32 w, i32 hgt, u32 rgb);

/// Append a TextOut primitive. `text` is copied by value (truncated
/// to `kWinTextOutMax` ASCII bytes, non-ASCII bytes stored as '?').
void WindowClientTextOut(WindowHandle h, i32 x, i32 y, const char* text, u32 rgb);

/// Append a Bresenham line primitive from (x, y) to (x2, y2).
void WindowClientLine(WindowHandle h, i32 x, i32 y, i32 x2, i32 y2, u32 rgb);

/// Append a 1-pixel ellipse outline primitive inside the
/// bounding box (x, y, w, hgt).
void WindowClientEllipse(WindowHandle h, i32 x, i32 y, i32 w, i32 hgt, u32 rgb);

/// Append a solid-filled ellipse primitive bounded by (x, y, w, h).
/// `fill_rgb` paints the interior; outline is left to a follow-up
/// `WindowClientEllipse` call by the caller (matches the GDI
/// `Ellipse(hdc)` convention of "fill then outline").
void WindowClientFilledEllipse(WindowHandle h, i32 x, i32 y, i32 w, i32 hgt, u32 fill_rgb);

/// Append a single-pixel primitive.
void WindowClientPixel(WindowHandle h, i32 x, i32 y, u32 rgb);

/// Append a BitBlt primitive. `src_pixels` is a kernel-side pointer
/// to `src_w * src_h` BGRA8888 u32 pixels in row-major order with
/// no padding. `dst_x`/`dst_y` is the destination relative to the
/// client origin. Pixels are copied into the window's blit pool;
/// the caller's buffer can be freed immediately after the call.
/// Silently no-ops on invalid handle, zero dimensions, or a blit
/// that would exceed the remaining pool capacity for this frame.
void WindowClientBitBlt(WindowHandle h, i32 dst_x, i32 dst_y, const u32* src_pixels, u32 src_w, u32 src_h);

/// Max single-blit rect the pool can hold (in pixels). Callers that
/// accept unbounded-size BitBlt requests from user mode should clip
/// to these before issuing — anything larger is rejected by the
/// compositor and never shows.
inline constexpr u32 kWinBlitMaxPx = kWinBlitPoolBytes / 4;

/// Drop every recorded GDI primitive for `h` (WM_PAINT with
/// bErase = TRUE support).
void WindowClearDisplayList(WindowHandle h);

/// Read the owning pid — used by the keyboard router to decide
/// whether to post to the window's queue (PE-owned, pid > 0) or
/// fall through to the native shell (pid == 0).
u64 WindowOwnerPid(WindowHandle h);

// ---------------------------------------------------------------
// Visibility (SW_HIDE re-showable) + mutable title (SetWindowText)
// + sizing (MoveWindow).
//
// Newly-registered windows start visible. SW_HIDE clears the bit
// (the compositor stops drawing + hit-testing the window, but
// the slot stays alive and the HWND keeps its identity). SW_SHOW
// sets it again. Distinct from WindowClose which actually reaps
// the slot.
// ---------------------------------------------------------------

/// True iff `h` is alive AND currently visible.
bool WindowIsVisible(WindowHandle h);

/// Mark `h` as a "pinned" window. Pinning is a UI hint — the
/// kernel taskbar uses it to draw a smaller (8-px) focus dot
/// when an active pinned tab is selected, vs the 14-px dot for
/// running-but-not-pinned tabs. Native boot apps (Calculator,
/// Notes, Files, …) are typically pinned at registration; PE-
/// owned ring-3 windows default to unpinned.
void WindowSetPinned(WindowHandle h, bool pinned);

/// True iff `h` is alive AND currently marked pinned.
bool WindowIsPinned(WindowHandle h);

/// Set the visible bit. No redraw — callers trigger the next
/// DesktopCompose themselves.
void WindowSetVisible(WindowHandle h, bool visible);

/// Bounded-copy a new ASCII title into the window's arena slot.
/// Non-ASCII bytes become '?'. Returns false for invalid handle
/// or a window the kernel didn't arena-allocate for (boot
/// windows whose title lives in .rodata — refuse to mutate).
/// A successful call updates the stored title pointer's CONTENT
/// in place; the pointer itself doesn't change.
bool WindowSetTitle(WindowHandle h, const char* ascii_src);

/// Bounded-copy a new ASCII subtitle into the window's arena
/// slot. Non-ASCII bytes become '?'. The subtitle is a small
/// "context string" that future Duet-era chrome paths render
/// next to the title in a dimmer monospace ink (e.g. Inspect
/// shows "PE32+ · x86_64", Kernel Log shows "/sys/klog · live").
/// Existing themes (Classic / Slate10 / Amber) ignore the field
/// — a window without a subtitle stores an empty string and
/// renders identically to before. Pass nullptr or "" to clear.
/// Returns false for an invalid handle.
bool WindowSetSubtitle(WindowHandle h, const char* ascii_src);

/// Borrowed pointer to the window's subtitle string. Always
/// non-null while the window is alive; returns "" when no
/// subtitle has been set. Returns nullptr if the handle is
/// invalid.
const char* WindowGetSubtitle(WindowHandle h);

/// Resize in-place. Width/height are clamped against the
/// framebuffer. (0 = "don't change" for each dimension.)
void WindowResizeTo(WindowHandle h, u32 w, u32 hgt);

// ---------------------------------------------------------------
// Async input-state cache + mouse capture + text clipboard.
//
// Async keyboard state: maintained by the kbd reader via
// `WindowInputTrackKey` on every press/release edge. Backs Win32
// `GetKeyState` / `GetAsyncKeyState` — returns true iff the
// key code is currently held.
//
// Mouse capture: one HWND per system ("ownership"). When non-
// invalid, subsequent mouse-message routing targets THIS window
// regardless of the cursor position. Backs Win32 SetCapture /
// ReleaseCapture / GetCapture.
//
// Clipboard: a single bounded ASCII text buffer. Backs Win32
// SetClipboardData(CF_TEXT) / GetClipboardData(CF_TEXT) via
// the user32 wrappers.
// ---------------------------------------------------------------

constexpr u32 kWindowVkStateSize = 256;

/// Record a key press/release edge. `code` can be a raw VK /
/// char code (<256) or an extended key (arrows, F-keys). Only
/// the low 8 bits are retained; extended codes wrap but collide
/// only with keys we don't otherwise expose.
void WindowInputTrackKey(u16 code, bool down);

/// True iff `code` is currently down. Always false for codes
/// outside the tracked range.
bool WindowKeyIsDown(u16 code);

/// Cache of the last KeyEvent modifier bitmask. The kbd reader
/// publishes after every event so peripheral consumers (mouse-
/// wheel handlers, drag handlers, etc.) can branch on Ctrl /
/// Shift / Alt without scanning a key-state map.
void WindowSetModifierState(u8 modifiers);
u8 WindowModifierState();

/// Double-click threshold in scheduler ticks (10 ms each).
/// Default 50 ticks (~500 ms). The kernel mouse loop's DC
/// detector reads this on every press_edge so a runtime
/// change (Settings Mouse panel) takes effect immediately.
void WindowSetDoubleClickTicks(u32 ticks);
u32 WindowDoubleClickTicks();

/// Mouse sensitivity scale, 0..255. 128 = identity (no scale).
/// The mouse reader multiplies dx / dy by `scale / 128` before
/// feeding the cursor + apps. Below 128 dampens motion; above
/// boosts. Bypassed entirely while a modal-input or DnD
/// session is live (the user wants 1:1 cursor tracking during
/// gestures).
void WindowSetMouseSensitivity(u8 scale);
u8 WindowMouseSensitivity();

/// Current cursor position in framebuffer coordinates. Pointers
/// may be null to skip writing that axis.
void WindowGetCursor(u32* x_out, u32* y_out);

/// Move the cursor. Backing call is `CursorHide` / move /
/// `CursorShow`, all under the compositor lock owned by the
/// caller.
void WindowSetCursor(u32 x, u32 y);

/// Set the captured window. Returns the previously captured
/// handle (kWindowInvalid if none). Passing kWindowInvalid
/// releases capture (same as `WindowReleaseCapture`).
WindowHandle WindowSetCapture(WindowHandle h);

/// Release capture. No-op if no window is captured.
void WindowReleaseCapture();

/// Current captured window or kWindowInvalid.
WindowHandle WindowGetCapture();

constexpr u32 kWindowClipboardMax = 1024;
constexpr u32 kWindowClipboardHistoryDepth = 8;

/// Replace the clipboard text. `text` is copied in bounded to
/// `kWindowClipboardMax` ASCII bytes (non-ASCII stored as '?').
/// A null pointer clears the clipboard. The previous value is
/// pushed onto the history ring (deduped — setting the same text
/// twice in a row leaves the ring unchanged).
void WindowClipboardSetText(const char* text);

/// Copy current clipboard text into `dst` (cap = buffer size
/// including NUL). Returns the stored length (bytes without
/// NUL), always ≤ cap - 1 once the call returns.
u32 WindowClipboardGetText(char* dst, u32 cap);

/// History-ring depth, in entries. The ring stores up to
/// `kWindowClipboardHistoryDepth` previous clipboard payloads
/// (deduped). Index 0 is the most recently displaced, increasing
/// indices reach further back in time.
u32 WindowClipboardHistoryCount();

/// Copy entry `idx` of the history ring into `dst`. Returns the
/// stored length (bytes without NUL); 0 if `idx` is out of range
/// or the slot is empty. Does not touch the active clipboard.
u32 WindowClipboardHistoryGet(u32 idx, char* dst, u32 cap);

/// Rotate the history ring by one step: the active clipboard is
/// pushed onto the history ring (front), and entry 0 of the ring
/// is promoted to the active slot. With nothing in the ring this
/// is a no-op. Bound to Ctrl+Shift+V so the user can step backwards
/// through recent clips. Returns true iff the rotation happened.
bool WindowClipboardHistoryRotate();

// ---------------------------------------------------------------
// Per-window timer table. `SetTimer` registers (hwnd, timer_id,
// interval_ms); the kernel's timer-ticker thread posts WM_TIMER
// to the target HWND every `interval_ms`. Per-process budget is
// bounded by `kWindowTimersMax`.
// ---------------------------------------------------------------

constexpr u32 kWindowTimersMax = 32;

/// Install or update a timer. Returns true on success. `hwnd`
/// must be alive + owned by `pid` (the syscall's caller). If a
/// timer with the same (hwnd, timer_id) already exists its
/// interval is updated; otherwise a free slot is consumed.
/// Returns false if the timer table is full.
bool WindowTimerSet(u64 pid, WindowHandle hwnd, u32 timer_id, u32 interval_ms);

/// Remove a timer. Returns true on success, false if unknown.
bool WindowTimerKill(u64 pid, WindowHandle hwnd, u32 timer_id);

/// Drop all timers for a given (pid, hwnd) — called by the
/// process reaper so dead windows don't keep posting.
void WindowTimerReap(u64 pid, WindowHandle hwnd);

/// Advance every registered timer by one scheduler tick. Posts
/// WM_TIMER into the target window's queue when a timer's
/// remaining counter reaches 0 and resets it to `interval`.
/// Intended to be called from a dedicated timer-ticker thread
/// under the compositor lock.
void WindowTimerTick();

// ---------------------------------------------------------------
// Per-window user-data slot + dirty region for WM_PAINT.
//
// Win32 exposes SetWindowLongPtrA(GWLP_USERDATA, ...) /
// SetWindowLongPtrA(GWLP_WNDPROC, ...). v1 gives each window
// four 64-bit slots selectable by index — enough for
// GWLP_USERDATA (index kWinLongUserData), GWLP_WNDPROC
// (index kWinLongWndProc), and two extras.
//
// Dirty region: a single bool per window (whole-client dirty).
// InvalidateRect sets it; UpdateWindow + the mouse/kbd readers
// sample it on every pump to post WM_PAINT; EndPaint clears it.
// A real Win32 invalid-rect tracker is a future upgrade.
// ---------------------------------------------------------------

constexpr u32 kWinLongSlots = 4;
constexpr u32 kWinLongWndProc = 0;  // GWLP_WNDPROC
constexpr u32 kWinLongUserData = 1; // GWLP_USERDATA
constexpr u32 kWinLongExtra0 = 2;
constexpr u32 kWinLongExtra1 = 3;

/// Read a 64-bit per-window long. Returns 0 on bad handle or
/// out-of-range index.
u64 WindowGetLong(WindowHandle h, u32 index);

/// Write a 64-bit per-window long. Returns the previous value.
/// No-op for bad handle / index.
u64 WindowSetLong(WindowHandle h, u32 index, u64 value);

/// Mark a window's client area dirty. Next pump cycle posts
/// WM_PAINT.
void WindowInvalidate(WindowHandle h);

/// Clear the dirty bit (BeginPaint's half) without painting.
void WindowValidate(WindowHandle h);

/// True iff the window's dirty flag is set.
bool WindowIsDirty(WindowHandle h);

/// Walk every alive window; for each dirty one, post WM_PAINT
/// (wParam/lParam = 0, lParam's coords are unused in v1 since
/// we only track whole-client dirty). Then clear the dirty bit
/// per window (the PE's BeginPaint/EndPaint round-trip is the
/// canonical ack but a simple queue-side clear also keeps the
/// message from re-firing every tick). Returns the number of
/// WM_PAINTs posted.
u32 WindowDrainPaints();

/// Toggle "Show Desktop" — Win10's minimize-all + restore.
/// First call snapshots the current visibility of every alive
/// window into a backing mask and hides them all. Second call
/// re-shows only the windows that were visible at snapshot
/// time (any that were SW_HIDE'd by the user before the toggle
/// stay hidden). Returns the new state: true == "showing
/// desktop", false == "windows visible". Safe to call any time;
/// no-op if there are no alive windows.
bool WindowShowDesktopToggle();

/// Read the current Show-Desktop state without toggling. True
/// means a snapshot is pending and the windows are hidden.
bool WindowShowDesktopActive();

// ---------------------------------------------------------------
// Parent / child tracking + focus + caret.
//
// Every window has a `parent` field. Top-level windows use
// `kWindowInvalid` (no parent). The accessor preserves Win32
// semantics: newly-registered windows have no parent unless
// explicitly set.
//
// Focus: a separate HWND from the "active" window. Active
// tracks the Z-ordered topmost frame; focus tracks which
// window receives keyboard input. Edit controls that steal
// focus without raising to top use the distinction.
//
// Caret: a single global blinking rectangle. Drawn by the
// compositor at the caret's (x, y) when visible; blink is
// driven by the ui-ticker's 1 Hz compose.
// ---------------------------------------------------------------

/// Set a window's parent. Pass `kWindowInvalid` to clear.
void WindowSetParent(WindowHandle h, WindowHandle parent);

/// Read a window's parent. Returns `kWindowInvalid` if none or
/// for an invalid handle.
WindowHandle WindowGetParent(WindowHandle h);

enum class WindowRel : u32
{
    Next = 0,  // GW_HWNDNEXT (next in z-order)
    Prev = 1,  // GW_HWNDPREV
    First = 2, // GW_HWNDFIRST
    Last = 3,  // GW_HWNDLAST
    Child = 4, // GW_CHILD (first child of h)
    Owner = 5, // GW_OWNER — alias for parent in v1
};

/// Walk the relationship specified by `rel` from `h`. Returns
/// `kWindowInvalid` if no such window exists.
WindowHandle WindowGetRelated(WindowHandle h, WindowRel rel);

/// Separate focused-window tracking. Focus is the window that
/// should receive keyboard input; active is the window that's
/// Z-ordered topmost. SetFocus posts WM_KILLFOCUS to the old
/// focus and WM_SETFOCUS to the new one.
void WindowSetFocus(WindowHandle h);

/// Read the current focus, or `kWindowInvalid` if none.
WindowHandle WindowGetFocus();

// --- Caret ---
struct Caret
{
    u32 x, y;
    u32 w, h;
    bool visible;
    bool shown; // ShowCaret/HideCaret refcount > 0
    u8 _pad[2];
    WindowHandle owner;
};

/// Set the caret shape. Size defaults to 1x12 if either axis
/// is zero. Position stays at whatever it was.
void WindowCaretCreate(WindowHandle owner, u32 w, u32 h);

/// Tear the caret down. The caret stays destroyed until the
/// next CaretCreate.
void WindowCaretDestroy();

/// Move the caret to (x, y) in screen coords.
void WindowCaretSetPos(u32 x, u32 y);

/// Toggle visibility. Show/Hide in Win32 are refcounted but
/// v1 collapses to a boolean.
void WindowCaretShow(bool shown);

/// Read the caret state for the compositor's paint path.
const Caret& WindowCaretGet();

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

/// Compositor dirty signal. The 1 Hz ui-ticker only runs a full
/// `DesktopCompose` when something actually changed; an idle
/// desktop must NOT repaint every second (that full-screen
/// software recompose is the visible flicker, and the lock
/// contention against it is what makes the mouse feel slow).
///
/// `CompositorMarkDirty()` — call from any task-context site that
/// changes what the screen should show (window create/move/resize/
/// raise/close/activate, app paint via WindowInvalidate, menu /
/// dialog / notification show, theme change, input that mutates
/// UI). Cheap; idempotent; safe to over-call (worst case is one
/// extra compose). NEVER call from IRQ — UI mutation is task-only.
///
/// `CompositorTakeDirty()` — ui-ticker only: atomically reads and
/// clears the flag, returning whether a full compose is due this
/// tick. `CompositorPeriodicNeedsCompose()` reports periodic
/// animators (a visible+shown text caret) that must keep the 1 Hz
/// beat even with zero input so the caret doesn't freeze.
void CompositorMarkDirty();
bool CompositorTakeDirty();
bool CompositorPeriodicNeedsCompose();

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
