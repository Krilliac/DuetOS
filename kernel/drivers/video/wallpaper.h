#pragma once

#include "util/types.h"

/*
 * Desktop wallpaper backdrop — v0.
 *
 * Painted by `DesktopCompose` between the gradient fill and the
 * first window draw, so a window dragged over the wallpaper
 * occludes it correctly and the next compose restores it.
 *
 * Currently theme-dispatched: each `ThemeId` may define its own
 * pattern, or accept the gradient-only baseline. The first slice
 * ships:
 *
 *   - Classic / Slate10 / Amber : no pattern (matches existing
 *     flat / gradient look bit-for-bit).
 *   - Duet                      : "duet-arcs" — two large
 *     interlocking outlined circles in a teal / amber pair,
 *     approximating the prototype's `--arcs` SVG backdrop.
 *
 * Scope limits intentionally narrow:
 *   - Pixel-aligned, no anti-aliasing. The framebuffer compositor
 *     has no off-screen mask yet.
 *   - No alpha-mask cache, no dirty-rect tracking — every paint
 *     re-runs the full primitive. The Duet duet-arcs paint costs
 *     O(diameter) pixel writes per frame which is trivial.
 *   - No bitmap/SVG loader. Patterns are programmatic. A real
 *     loader is Phase 7+ work.
 *
 * Context: kernel. Called from `DesktopCompose` under
 * `CompositorLock`. Safe no-op when the framebuffer isn't
 * available.
 */

namespace duetos::drivers::video
{

/// Paint the active theme's wallpaper backdrop over the
/// framebuffer. Caller has already painted the desktop fill /
/// gradient — this layers a pattern on top. `desktop_rgb` is the
/// gradient's mid-tone; the implementation derives darker /
/// lighter shades from it for any "low contrast" pattern strokes.
/// No-op if `!FramebufferAvailable()` or the active theme has no
/// pattern.
void WallpaperPaint(u32 desktop_rgb);

/// One-shot init that parses the embedded wallpaper SVG assets
/// (DuetMark, topo backdrop, syscalls grid) into static SvgImage
/// instances ready for `WallpaperPaint` to consume. Idempotent;
/// safe to call from any boot phase after `FramebufferInit`.
void WallpaperSvgInit();

} // namespace duetos::drivers::video
