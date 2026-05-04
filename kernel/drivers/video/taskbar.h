#pragma once

#include "util/types.h"

/*
 * Taskbar — v0.
 *
 * A thin horizontal strip painted over the top (or bottom) of
 * the framebuffer as the last step of a desktop compose. Shows:
 *   - A "START" label anchored to the left edge.
 *   - A row of per-window tabs listing every live window's
 *     title, in registration order.
 *   - An "UP NNNNs" uptime counter anchored to the right edge.
 *
 * Not a widget — purely painted chrome. Tabs don't respond to
 * clicks yet; activating a window via the taskbar lands with
 * focus + minimise in a follow-up slice.
 *
 * Scope limits:
 *   - One taskbar per framebuffer. Placement fixed at init.
 *   - No clock (real wall time): uptime counter only, derived
 *     from the scheduler tick count (100 Hz).
 *   - Tabs never wrap — if window count * tab width exceeds
 *     the middle area, the overflow is clipped off the right.
 *   - No icons. Text-only tabs.
 *
 * Context: kernel. Init after FramebufferInit and the font
 * module. Redraw is called from DesktopCompose — no thread
 * concerns provided the caller holds the compositor mutex.
 */

namespace duetos::drivers::video
{

/// Position + chrome. `tab_inactive_rgb` fills idle window tabs;
/// `border_rgb` draws the 1-px top edge + tab / start outlines.
/// Passing zero for either uses a pragmatic default that matches
/// the pre-theme taskbar (dark blue-black border, slate tab fill).
void TaskbarInit(u32 y, u32 height, u32 bg_rgb, u32 fg_rgb, u32 accent_rgb, u32 tab_inactive_rgb, u32 border_rgb);

/// Update the chrome palette without moving or resizing the strip.
/// Called by the theme module so a runtime theme switch re-hues
/// the taskbar without tearing down the layout. Safe no-op if
/// the taskbar hasn't been Init'd yet.
void TaskbarSetColours(u32 bg_rgb, u32 fg_rgb, u32 accent_rgb, u32 tab_inactive_rgb, u32 border_rgb);

/// Paint the taskbar strip + its dynamic contents. Safe no-op
/// before init. Records the current tab layout so subsequent
/// `TaskbarTabAt` calls can hit-test without re-running the
/// layout.
void TaskbarRedraw();

/// Hit-test a point against the last-painted tab layout. Returns
/// the `WindowHandle` of the tab containing (x, y), or a value
/// equal to `kWindowInvalid` if none does. Caller must have
/// called `TaskbarRedraw` at least once for a valid result.
u32 TaskbarTabAt(u32 x, u32 y);

/// Whole-strip hit-test. Useful for the mouse reader's "is this
/// click on the taskbar at all?" branch.
bool TaskbarContains(u32 x, u32 y);

/// Bounds of the START anchor rectangle. Callers use this both
/// for hit-testing (click on START) and for anchoring a popup
/// (start menu opens from START's upper edge). Writes to any
/// non-null out pointer; all four may be null to skip.
void TaskbarStartBounds(u32* x, u32* y, u32* w, u32* h);

/// Live taskbar strip height in pixels — what `TaskbarInit`
/// last consumed. Returns 0 before init. Callers (e.g.
/// `WindowMaximize`) use this as the bottom-edge reserve so
/// they don't paint over the strip; the Duet family's larger
/// 36-px taskbar is automatically respected.
u32 TaskbarHeight();

/// Bounds of the clock / date widget on the right edge. Lets a
/// caller hit-test a click on the clock so it can toggle the
/// calendar popup. Populated after TaskbarRedraw.
void TaskbarClockBounds(u32* x, u32* y, u32* w, u32* h);

/// Bounds of the NETWORK tray cell ("N" badge). Used by the
/// mouse reader to hover-preview / click-toggle the network
/// flyout, similar to Windows' bottom-right Wi-Fi icon. Returns
/// w == 0 if the cell hasn't been laid out yet (TaskbarRedraw
/// must have run at least once). Anchored coordinates are
/// framebuffer-absolute.
void TaskbarNetCellBounds(u32* x, u32* y, u32* w, u32* h);

/// Bounds of the chevron-up "show hidden tray icons" button —
/// the leftmost cell of the tray on themes that paint it (Duet
/// family today). Used by the mouse reader to hover-expand and
/// click-open the tray flyout panel. Returns `w == 0` when the
/// chevron hasn't been laid out (theme doesn't paint it, or
/// `TaskbarRedraw` hasn't run yet).
void TaskbarChevronBounds(u32* x, u32* y, u32* w, u32* h);

/// Set the hover state on the chevron — the mouse reader calls
/// this every packet from its hover-poll path. The chevron
/// renders larger when hovered, mirroring the Windows tray's
/// "expand a touch on hover, expand more on click" gesture.
void TaskbarChevronSetHover(bool hovered);
bool TaskbarChevronHovered();

/// Bounds of the "Show Desktop" sliver — a thin accent rail at
/// the very right edge of the taskbar. Spec calls for a Win10-
/// style minimize-all click target; v0 paints it but the click
/// dispatcher hasn't been wired yet (STUB). Returns `w == 0` if
/// the sliver hasn't been laid out yet.
void TaskbarShowDesktopBounds(u32* x, u32* y, u32* w, u32* h);

/// Where the taskbar is anchored on the framebuffer. v0 supports
/// the two horizontal edges; left / right would need a vertical
/// layout (stacked tabs / clock pill rotated) and are deferred.
enum class TaskbarDock : u8
{
    Bottom = 0,
    Top = 1,
};

/// Set the active dock edge + immediately re-anchor the strip
/// against the current framebuffer. Cycles through Bottom -> Top
/// when called from the Ctrl+Alt+B keybind (see main.cpp's mouse
/// reader). Repaint is the caller's responsibility (typically
/// `DesktopCompose` runs again on the next frame).
void TaskbarSetDock(TaskbarDock edge);
TaskbarDock TaskbarGetDock();

/// Lock the strip in place. While locked the user can't drag the
/// taskbar (the mouse reader's "is this a drag?" check consults
/// this flag). Hotkey: Ctrl+Alt+L. Default: locked.
void TaskbarSetLocked(bool locked);
bool TaskbarIsLocked();

/// Recompute the strip's `(y, height)` from the active dock edge
/// + current framebuffer height. Idempotent. Called automatically
/// by `TaskbarRedraw` so a framebuffer rebind (virtio-gpu coming
/// online after a stale FramebufferInit returned no FB tag) does
/// not leave the taskbar pinned at the wrong y. External callers
/// can fire this after a `FramebufferRebind*` if they want the
/// new layout visible before the next compose.
void TaskbarReanchor();

/// Drag-and-snap. The mouse reader calls `BeginDrag` on a
/// mouse-down inside the taskbar strip when the strip is not
/// locked, then `EndDrag(cursor_y)` on mouse-up; the drop snaps
/// to the nearest dock edge based on `cursor_y`'s position
/// relative to the framebuffer's vertical mid-line. While a drag
/// is in progress, `IsDragging` returns true so the compose path
/// can paint a soft outline at the snap target.
void TaskbarBeginDrag();
void TaskbarEndDrag(u32 cursor_y);
bool TaskbarIsDragging();

} // namespace duetos::drivers::video
