#pragma once

#include "util/types.h"

/*
 * Aurora desktop backdrop — docs/aurora-theme/README.md §1 "Wallpaper".
 *
 * The design specifies a six-layer stack that the flat per-theme
 * painters in wallpaper.cpp cannot express:
 *
 *   1. linear-gradient(158deg, --bg-2, --bg-1 52%, --bg-0)
 *   2. three radial accent blobs (teal 34% / amber 22% / teal 14%)
 *   3. 60 px hairline grid, radial-masked toward the centre
 *   4. hex-dump band, diagonally masked so it fades out to the right
 *   5. counter-rotating arcs watermark
 *   6. vignette
 *
 * Layers 1-4 and 6 are static for a given (framebuffer size, palette)
 * pair, and cost ~800 k per-pixel blends to produce. Recomputing them
 * on every DesktopCompose would roughly triple the compose cost, so
 * they are generated once into a full-screen RGB cache and blitted.
 * Layer 5 rotates with the ambient-motion phase and is therefore
 * painted live by wallpaper.cpp, on top of the blit.
 *
 * Context: kernel, compositor thread only (the cache is a plain
 * global with no lock — every caller is already inside the
 * CompositorLock bracket that DesktopCompose holds).
 */

namespace duetos::drivers::video
{

/// Blit the cached Aurora base layers over the whole framebuffer,
/// regenerating the cache first if the framebuffer geometry or the
/// palette changed. Returns false when the layer could not be
/// produced (no framebuffer, or the cache allocation failed) — the
/// caller must then fall back to its flat painter so the desktop
/// never ends up unpainted.
/// `light` selects the design's light-mode token column (README
/// "Light"): a near-white gradient, dark hairlines and hex ink, and a
/// cooler, weaker vignette.
bool AuroraWallpaperPaint(u32 accent_native, u32 accent_peer, bool light);

/// Restore the cached backdrop into the four corner regions of the
/// rectangle (x, y, w, h) that fall OUTSIDE a `radius` corner arc.
///
/// This is what makes an Aurora window's corners genuinely round: the
/// chrome can paint a rounded body, but an app's content drawer fills
/// the client rect square and squares the corners straight back off.
/// Because the backdrop is a cached surface, the exact wallpaper pixels
/// under a corner can be replayed after the content lands - no flat
/// approximation, and no read-back of the compose surface (which
/// FramebufferReadPixel cannot do anyway).
///
/// GAP: replays the WALLPAPER, so a corner overlapping a lower window
/// shows wallpaper rather than that window. At an 8-px radius that is
/// ~14 px per corner; a correct fix needs per-window backbuffers.
///
/// No-op when the cache is cold.
void AuroraWallpaperRestoreCorners(u32 x, u32 y, u32 w, u32 h, u32 radius);

/// Drop the cached surface so the next AuroraWallpaperPaint call
/// regenerates it. Called on framebuffer rebind; a palette change is
/// detected automatically from the accent pair.
void AuroraWallpaperInvalidate();

} // namespace duetos::drivers::video
