#pragma once

#include "util/types.h"

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

namespace duetos::drivers::video
{

/// Remember `desktop_rgb` as the fallback "background" colour and
/// render the initial cursor sprite at screen centre. Does NOT
/// clear the framebuffer — the caller is responsible for painting
/// the desktop + any widgets first so the cursor's save-backing
/// captures them. Safe no-op if the framebuffer isn't available.
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

/// Restore the backing pixels under the cursor and mark the cursor
/// hidden. Used by widget code that wants to redraw under the
/// cursor without leaving stale backing pixels captured around the
/// edit. Must be paired with a subsequent CursorShow() — leaving
/// it hidden is a silent bug that drops mouse feedback.
void CursorHide();

/// Re-sample backing pixels at the current position and draw the
/// sprite on top. Pairs with CursorHide().
void CursorShow();

/// Update the fallback desktop-background colour the cursor uses
/// when its backing store misses (framebuffer read out of bounds).
/// Called by the theme module after a theme switch so the cursor
/// repaints over the new desktop fill rather than the old one.
void CursorSetDesktopBackground(u32 rgb);

/// Update the cursor sprite's outline + fill colours. Called by
/// the theme module so each theme's cursor matches its chrome
/// (Classic = white-on-black, Amber = bright-amber-on-black,
/// Duet = ink-on-slate-border, etc.). Both arguments are
/// `0x00RRGGBB`. The cursor is repainted at its current
/// position so the new colours appear on the next mouse event
/// without waiting for motion.
void CursorSetColours(u32 outline_rgb, u32 fill_rgb);

/// Pointer-shape variants. `Wait` is a programmatic toggle —
/// callers `CursorPushWait()` before a long operation and
/// `CursorPopWait()` after. Arrow / IBeam / Hand are picked by
/// the mouse-loop's hit-test based on what's under the cursor:
/// buttons → Hand, text-input regions → IBeam, everywhere else
/// → Arrow. ResizeNS / ResizeEW appear over window borders to
/// indicate edge-drag-to-resize. All sprites are 12×20 so the
/// backing-store allocation never moves.
enum class CursorShape : u8
{
    Arrow = 0,
    IBeam = 1,
    Hand = 2,
    Wait = 3,
    ResizeNS = 4, // ↕ over top / bottom borders
    ResizeEW = 5, // ↔ over left / right borders
};

/// Pick the active sprite. Repaints in place so the new shape
/// shows immediately without waiting for motion. No-op if `s`
/// is already the active shape.
void CursorSetShape(CursorShape s);

/// Read the current shape. Returns `Arrow` before the cursor
/// is initialised.
CursorShape CursorGetShape();

/// Push a `Wait` overlay onto the active shape. Refcounted —
/// nested CursorPushWait / CursorPopWait calls compose: the
/// shape stays Wait until the last Pop balances. The shape
/// underneath is restored on the final Pop. Used by long-
/// running code paths (screenshot save, FAT32 write) so the
/// hourglass appears for the whole operation.
void CursorPushWait();

/// Pop one Wait overlay. The cursor reverts to whatever shape
/// the hit-test was setting before the push, OR remains Wait
/// if other pushes are still outstanding.
void CursorPopWait();

} // namespace duetos::drivers::video
