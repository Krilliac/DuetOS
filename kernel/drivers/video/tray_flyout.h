#pragma once

#include "util/types.h"

/*
 * Tray flyout — the small popup panel that opens when the user
 * clicks the chevron on the left of the system tray. Mirrors the
 * Win10/Win11 "show hidden icons" flyout: a compact pop-up
 * showing supplementary status rows (memory, CPU, battery, host
 * uptime) that don't earn a dedicated tray cell.
 *
 * Lifecycle is the same shape as the existing Calendar / NetPanel
 * popups:
 *
 *   - The mouse reader hit-tests the chevron via
 *     `TaskbarChevronBounds`, then calls `TrayFlyoutOpen(x, y)` on
 *     a click. The y is the chevron's top edge — the panel paints
 *     its body ABOVE that anchor, the way Windows tray flyouts
 *     hover above their icon.
 *   - The hover state is driven by `TrayFlyoutSetHover(true)` /
 *     `TrayFlyoutSetHover(false)` from the mouse reader's hover-
 *     poll path. The flag controls a subtle "lift" cue on the
 *     chevron itself + a 1-px glow on the popup if it's already
 *     open. We don't animate the popup geometry — the prototype's
 *     "expands a bit on hover" is approximated by drawing the
 *     chevron larger when the cursor is over it.
 *   - `TrayFlyoutClose()` ends the popup; called on a click
 *     outside the panel or on the chevron a second time.
 *
 * Painted from `DesktopCompose` after the menu / calendar / net
 * panel layer so the flyout reads as the topmost popup. Skipped
 * on themes that don't render the chevron (everything except the
 * Duet family today).
 *
 * Context: kernel. Caller holds `CompositorLock` across the open
 * / close / paint calls; the panel is single-instance so concurrent
 * opens just overwrite the previous anchor.
 */

namespace duetos::drivers::video
{

/// Open the flyout panel anchored at the given (x, y). The
/// implementation paints the panel ABOVE this anchor — the y
/// passed in is the top edge of the chevron (so the panel's
/// bottom edge sits flush against it). Subsequent calls just
/// re-anchor — the flyout stays single-instance.
void TrayFlyoutOpen(u32 anchor_x, u32 anchor_y);

/// Close the flyout panel. Idempotent.
void TrayFlyoutClose();

/// Whether the flyout is currently visible.
bool TrayFlyoutIsOpen();

/// Hit-test: is (x, y) inside the open panel? Returns false if
/// the panel isn't open. Used by the mouse reader to decide
/// whether a click outside dismisses the flyout.
bool TrayFlyoutContains(u32 x, u32 y);

/// Set the hover-on-chevron state. Drives the chevron's
/// "expanded" visual when the cursor is over the chevron cell —
/// approximates the prototype's "expands a bit on hover" cue
/// without animation.
void TrayFlyoutSetHover(bool hovered);
bool TrayFlyoutHovered();

/// Paint the panel into the framebuffer. No-op if not open or if
/// the framebuffer isn't available. Called by `DesktopCompose`
/// after the menu / calendar / net-panel layer.
void TrayFlyoutRedraw();

/// Update the popup's chrome to match the active theme. Called
/// by `ThemeApplyToAll` so the panel re-hues on Ctrl+Alt+Y.
void TrayFlyoutSetColours(u32 body_rgb, u32 border_rgb, u32 ink_rgb, u32 ink_dim_rgb, u32 accent_rgb, u32 accent_2_rgb);

} // namespace duetos::drivers::video
