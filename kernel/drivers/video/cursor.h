#pragma once

#include "../../core/types.h"

/*
 * Mouse cursor overlay — v0.
 *
 * Draws a movable pointer sprite on the linear framebuffer and
 * exposes a single mutation API: "the mouse moved by (dx, dy)."
 * Intended to be fed from the PS/2 mouse reader thread so the
 * cursor tracks hardware motion end-to-end.
 *
 * Mechanism: on every move, the old cursor rect is overpainted
 * with the configured desktop background colour and the new rect
 * is drawn. No save/restore of per-pixel background because v0's
 * "desktop" is a solid-colour fill — there's nothing under the
 * cursor worth preserving. When a real compositor lands, the
 * cursor migrates to a proper hardware-overlay or save/restore
 * sprite path.
 *
 * Scope limits:
 *   - Fixed-colour, fixed-size rectangular sprite (12x20). No
 *     alpha, no shaped-mask arrow. "It moves" is the test; a real
 *     arrow sprite needs a mask + pixel-level save/restore, which
 *     pulls in a dirty-rect tracker we're not ready for yet.
 *   - Desktop background is a single solid colour. Any window /
 *     widget rendered over the desktop must explicitly refresh
 *     the cursor afterwards (draw order: background → widgets →
 *     cursor last).
 *   - No hardware cursor plane. The Intel / AMD / NVIDIA GPU
 *     drivers will expose a vendor-specific cursor path later.
 *   - Not thread-safe — calls MUST come from a single task
 *     (today, the mouse-reader thread).
 *
 * Context: kernel. Init after FramebufferInit.
 */

namespace customos::drivers::video
{

/// Paint the entire framebuffer with `desktop_rgb`, remember that
/// colour as the background to restore under a moving cursor, and
/// render the initial cursor at screen centre. Safe no-op if the
/// framebuffer isn't available.
void CursorInit(u32 desktop_rgb);

/// Apply a relative motion — typically sourced from
/// Ps2MouseReadPacket. Coordinates are clamped to the surface so
/// the sprite never escapes the framebuffer. Redraws on every
/// call; callers don't need to batch.
void CursorMove(i32 dx, i32 dy);

/// Current cursor position in pixels. Useful for any higher-level
/// widget that wants to hit-test the mouse against its own bounds
/// without subscribing to packets itself.
void CursorPosition(u32* x_out, u32* y_out);

} // namespace customos::drivers::video
