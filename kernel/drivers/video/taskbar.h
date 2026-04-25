#pragma once

#include "../../core/types.h"

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

} // namespace duetos::drivers::video
