#pragma once

#include "util/types.h"

/*
 * DuetOS — linear framebuffer driver, v0.
 *
 * First direct-to-pixel graphics primitive in the tree. Consumes the
 * Multiboot2 framebuffer tag (type 8) GRUB hands over on boot, maps
 * the linear framebuffer into the kernel MMIO arena, and exposes the
 * minimum ops every higher-level surface (console font rasterizer,
 * splash screen, compositor later) will need:
 *
 *   - `FramebufferInit(multiboot_info_phys)` — parses tag, validates
 *     "direct RGB" shape, MapMmios the pixel buffer. Safe to call
 *     when no tag is present: leaves the driver `Available() == false`
 *     and returns silently.
 *   - `FramebufferClear(rgb)` / `FramebufferFillRect(x, y, w, h, rgb)` /
 *     `FramebufferPutPixel(x, y, rgb)` — the classic trio; all
 *     coordinate-clipped, no panics on out-of-range.
 *   - Accessors for info the console layer needs (width in pixels,
 *     height in pixels, pitch in bytes).
 *
 * Scope limits that will be fixed in later commits:
 *   - Assumes BPP = 32 (8:8:8:8 with one reserved byte). Some real
 *     VBE modes hand back 24-bit packed, and EFI GOP sometimes
 *     reports 15 or 16 bit. Unsupported depths log + disable the
 *     driver rather than guessing.
 *   - Assumes the firmware placed red/green/blue in the classic
 *     A=24 / R=16 / G=8 / B=0 arrangement (QEMU std-vga, BGA, most
 *     Intel iGPUs). Different masks will render with swapped colour
 *     channels — visible but functional, and fixable by reading the
 *     colour-info trailer once a real machine forces the issue.
 *   - No back buffer / no double buffering. Every draw lands in the
 *     live framebuffer. Fine for boot splash + kernel panic display;
 *     the compositor will install its own off-screen buffer chain.
 *   - No dirty-rect tracking. Redraws are full-rect. The cost is
 *     a handful of MB/s at 1024x768x32, well inside the PCIe budget
 *     for the devices we care about.
 *   - No cursor / blinking text / scrolling. Those land with the
 *     framebuffer console on top of this driver.
 *
 * Context: kernel. Init runs once AFTER `PagingInit` (uses MapMmio)
 * and BEFORE any subsystem wants to draw. Drawing is IRQ-safe in
 * principle (writes to MMIO), but drawing from an IRQ handler on
 * a slow framebuffer will cause visible scheduling jitter; keep
 * draw calls in task context unless the panic path specifically
 * needs them.
 */

namespace duetos::drivers::video
{

struct FramebufferInfo
{
    void* virt; // kernel-virtual pointer into the MMIO arena
    u64 phys;   // physical base the firmware handed us
    u32 width;  // pixels
    u32 height; // pixels
    u32 pitch;  // bytes per scanline (>= width * bytes_per_pixel)
    u8 bpp;     // bits per pixel (we only support 32 today)
    u8 _pad[3];
};

/// Parse the Multiboot2 framebuffer tag from the info struct at
/// `multiboot_info_phys`, validate that it's a direct-RGB 32-bpp
/// linear framebuffer, and MapMmio the pixel buffer. Idempotent:
/// second call is a no-op. If GRUB didn't provide a tag or the tag
/// describes an unsupported mode, logs the reason to the serial
/// console and leaves the driver `Available() == false`. The
/// multiboot info phys passed here is stashed so a later
/// `FramebufferReinit` can re-locate the tag.
void FramebufferInit(uptr multiboot_info_phys);

/// Re-init using the multiboot info phys captured during the
/// first FramebufferInit call. Used by the driver fault-domain
/// registry to drive the surface through a teardown + re-init
/// without needing the boot-time multiboot pointer threaded
/// through every call site.
void FramebufferReinit();

/// Drop the active framebuffer surface so a subsequent
/// `FramebufferReinit` runs cleanly: clears Available(), zeroes
/// the cached info, drops the present-hook + compose state, and
/// resets the init-once guard. The MMIO mapping leaks (the arena
/// is a bump allocator); see FramebufferRebind for the same
/// caveat. Idempotent.
void FramebufferTeardown();

/// True if init found a usable framebuffer and drawing is permitted.
bool FramebufferAvailable();

/// Snapshot of the live framebuffer parameters. Valid for the whole
/// uptime once Init has returned; framebuffer parameters don't
/// change after boot.
FramebufferInfo FramebufferGet();

/// Fill the entire surface with `rgb` (0x00RRGGBB). No-op if
/// !Available().
void FramebufferClear(u32 rgb);

/// Write one pixel. Out-of-range coordinates silently drop — callers
/// that care are expected to clip up front. No-op if !Available().
void FramebufferPutPixel(u32 x, u32 y, u32 rgb);

/// Fill the axis-aligned rect [x, x+w) x [y, y+h) with `rgb`.
/// Clipped to the surface; passing a rect that's entirely off-screen
/// is a silent no-op. No-op if !Available().
void FramebufferFillRect(u32 x, u32 y, u32 w, u32 h, u32 rgb);

/// Draw the OUTLINE of the rect [x, x+w) x [y, y+h) with
/// `thickness` pixels of border in `rgb`. Interior is untouched.
/// Clipped; no-op on empty dimensions or !Available().
void FramebufferDrawRect(u32 x, u32 y, u32 w, u32 h, u32 rgb, u32 thickness);

/// Alpha-blend the rect [x, x+w) x [y, y+h) with `argb`. The
/// high byte of `argb` is the alpha channel (0..255); the lower
/// 24 bits are the source RGB (0xAARRGGBB layout to mirror what
/// callers already construct for `FramebufferFillRect`). The
/// blend is over the current framebuffer pixels using 8-bit
/// straight-alpha "src-over" arithmetic with /255 rounding:
///
///   out = src * alpha + dst * (255 - alpha)   (per channel)
///
/// Fast-paths alpha == 0 (no-op) and alpha == 0xFF (delegates
/// to `FramebufferFillRect`). Clipped; no-op on empty dimensions
/// or !Available().
///
/// Cost: one read + one write per covered pixel. For chrome use
/// (titlebar washes, hover tints, accent bars) the painted
/// surface is small enough that the cost is negligible. Avoid
/// blending the whole framebuffer in a hot loop.
void FramebufferFillRectAlpha(u32 x, u32 y, u32 w, u32 h, u32 argb);

/// Fill [x, x+w) x [y, y+h) with a vertical linear gradient
/// from `top_rgb` at row y to `bot_rgb` at row y+h-1. Both
/// colours are 0x00RRGGBB. Each scanline gets one interpolated
/// shade — there is no horizontal gradient, no diagonal, no
/// multi-stop. Used for focus titlebars, Start-menu header,
/// the prototype's wallpaper sky band.
///
/// Clipped; no-op on empty dimensions or !Available(). When
/// h == 1 the function devolves to `FramebufferFillRect` with
/// `top_rgb`.
void FramebufferFillRectGradient(u32 x, u32 y, u32 w, u32 h, u32 top_rgb, u32 bot_rgb);

/// Fill the axis-aligned rect [x, x+w) x [y, y+h) with `rgb`
/// using rounded corners of `radius` pixels. Radius is clamped
/// to `min(w, h) / 2` (so a square rect with radius == w/2 is a
/// circle); a radius of 0 devolves to `FramebufferFillRect`.
/// The corner curve is rendered as the largest set of pixels in
/// the corner radius-square whose squared distance to the
/// corner-arc centre is ≤ radius². Pixel-aligned, no
/// anti-aliasing — anti-aliasing is a follow-on once the
/// compositor has a real off-screen mask.
///
/// Clipped; no-op on empty dimensions or !Available().
void FramebufferFillRoundRect(u32 x, u32 y, u32 w, u32 h, u32 radius, u32 rgb);

/// Outline-only sibling of `FramebufferFillRoundRect`. Paints a
/// 1-pixel rounded-rect border in `rgb`. Same radius clamping
/// rules as the fill primitive. Interior is untouched. Used by
/// chrome paths that want a soft outline without an inner fill
/// (taskbar tab borders, button outlines).
///
/// Clipped; no-op on empty dimensions or !Available().
void FramebufferDrawRoundRect(u32 x, u32 y, u32 w, u32 h, u32 radius, u32 rgb);

/// Bresenham line from (x0, y0) to (x1, y1) inclusive in `rgb`.
/// Iterates pixels one at a time — useful for chrome details
/// (close-button "X" glyphs, accent strips, simple icons) where
/// a Manhattan-aligned filled rect would look wrong. Works for
/// every octant; coordinates are clipped per-pixel against the
/// surface so off-screen segments are silent no-ops.
///
/// Cost is O(max(|dx|, |dy|)) — one branch + one per-pixel
/// PutPixel. Bounded by `kFbMaxLinePixels` so a malicious caller
/// with insane endpoints can't spin the loop forever.
///
/// No-op if `!Available()`.
void FramebufferDrawLine(i32 x0, i32 y0, i32 x1, i32 y1, u32 rgb);

/// Midpoint-circle outline at center `(cx, cy)` with integer
/// `radius` in `rgb`. One-pixel border, eight-octant symmetric
/// plot — pixel-aligned, no anti-aliasing. Coordinates can be
/// negative; off-surface plots are silently dropped.
///
/// Degenerate radii: `0` is a single pixel at the center,
/// negative radius is a no-op. No-op if `!Available()`.
void FramebufferDrawCircle(i32 cx, i32 cy, u32 radius, u32 rgb);

/// Solid-filled circle at `(cx, cy)` of integer `radius`,
/// painted via per-row spans (one `FramebufferFillRect` per
/// scanline) using the integer test `dx² + dy² ≤ r²`. Same
/// degenerate-radius rules as `FramebufferDrawCircle`.
///
/// No-op if `!Available()`.
void FramebufferFillCircle(i32 cx, i32 cy, u32 radius, u32 rgb);

/// "Punch" the four corners of an axis-aligned rect so a chrome
/// path that already painted a rectangular surface ends up
/// looking rounded. For each of the four `radius × radius`
/// corner squares, every pixel whose squared distance to the
/// corner-arc centre is GREATER than `radius²` (i.e. lives
/// "outside" the curve) gets overpainted with `punch_rgb`. The
/// curve itself + the body interior are left untouched.
///
/// Caller is expected to pass a `punch_rgb` that visually
/// matches the surface AROUND the chrome (typically the
/// desktop's gradient mid-tone). A perfect colour match would
/// require per-pixel sampling of the underlying surface; this
/// primitive accepts a single colour as the "good enough"
/// approximation until a real compositor mask lands.
///
/// `radius == 0` is a no-op (rectangular chrome stays
/// rectangular). Radius is clamped to `min(w, h) / 2`. Clipped;
/// no-op on empty dimensions or `!Available()`.
void FramebufferPunchCorners(u32 x, u32 y, u32 w, u32 h, u32 radius, u32 punch_rgb);

/// Stroke a partial circular arc — every pixel in the
/// `[start_deg, start_deg + sweep_deg)` sector at distance
/// `radius` from `(cx, cy)`, plotted in `rgb`. Iterates `θ` in
/// 1° steps so the arc is dense enough at small radii (≤ 64 px)
/// to look continuous; larger radii will see visible gaps until
/// a per-radius step refinement lands.
///
/// `thickness` paints `thickness` concentric arcs at radii
/// `[radius - thickness/2, radius + (thickness+1)/2)` so a
/// 1-px stroke is a single arc, 2-px is `r-0` and `r+1`, 3-px
/// is `r-1`, `r`, `r+1`, etc. Pixel-aligned, no anti-aliasing.
///
/// Angles are in degrees, with 0° = positive X (3 o'clock) and
/// increasing clockwise (matching a Y-down framebuffer's
/// "counterclockwise on screen" intuition would require
/// flipping the sin sign — left as-is so the API matches an
/// SVG-style coordinate system the way the prototype's design
/// language thinks).
///
/// `sweep_deg` may be negative (sweep counter-clockwise) or
/// > 360 (multiple revolutions). Negative `radius` is a no-op.
/// No-op if `!Available()` or `thickness == 0`.
void FramebufferStrokeArc(i32 cx, i32 cy, i32 radius, i32 start_deg, i32 sweep_deg, u32 thickness, u32 rgb);

/// Path-op tag for `FramebufferStrokePath`. The op carries 0–3
/// `(x, y)` pairs depending on the tag.
enum class PathOp : u8
{
    Move = 0,  // pts[0] = new pen position; no stroke drawn
    Line = 1,  // pts[0] = endpoint; line stroked from current pen
    Cubic = 2, // pts[0] = cp1, pts[1] = cp2, pts[2] = end
    Close = 3, // straight stroke from pen to subpath start
};

struct PathPoint
{
    i32 x;
    i32 y;
};

struct PathSegment
{
    PathOp op;
    // Only the first `n` entries are meaningful, where
    // `n = OpPoints(op)`. Caller can leave the rest zeroed.
    PathPoint pts[3];
};

/// Stroke a sequence of path segments at `thickness` pixels in
/// `rgb`. Lines are walked Bresenham-style and stamped with a
/// `thickness × thickness` square at each pixel; cubic Bézier
/// segments are flattened with adaptive de Casteljau
/// subdivision (depth-capped at 8) until each leaf segment's
/// chord deviation is ≤ 1 pixel, then stroked as line segments.
/// `Close` strokes from the current pen back to the most recent
/// `Move`. A bare `Line`/`Cubic`/`Close` without a preceding
/// `Move` implicitly anchors at `(0, 0)`.
///
/// Cost is bounded by the sum of segment lengths in pixels
/// times `thickness` — fine for chrome / wallpaper geometry,
/// not intended for blitting bulk imagery.
///
/// `thickness == 0` or `count == 0` is a no-op. No-op if
/// `!Available()` or `segments == nullptr`.
void FramebufferStrokePath(const PathSegment* segments, u32 count, u32 thickness, u32 rgb);

/// Soft "drop shadow" for a window or panel. Paints a
/// `depth`-pixel-wide alpha-blended L-shape along the right
/// and bottom edges of the rect at `(x, y, w, h)`, using black
/// at `start_alpha` fading linearly to 0 at the outer edge of
/// the band. The original rect content is NOT touched — the
/// shadow lives entirely outside the rect, in the L-shaped
/// region [x+w, x+w+depth) × [y+depth, y+h+depth) ∪
/// [x+depth, x+w+depth) × [y+h, y+h+depth).
///
/// Cost: ~depth × (w + h) alpha-blended pixels. At depth=4 the
/// budget is trivial even for the desktop-sized chrome path.
/// Clipped; no-op on empty dimensions, depth==0, or !Available().
void FramebufferDropShadow(u32 x, u32 y, u32 w, u32 h, u32 depth, u8 start_alpha);

/// Copy `src_w × src_h` BGRA8888 pixels into the framebuffer at
/// `(dst_x, dst_y)`. `src` is a kernel-side pointer to a row-major
/// pixel buffer with `src_pitch_px` u32-pixels per row (allowing a
/// clipped subrect of a larger source). Out-of-range destination
/// coordinates are clipped; an entirely off-screen blit is a silent
/// no-op. No-op if `!Available()` or `src == nullptr`. The
/// compositor uses this to replay a window's recorded BitBlt
/// primitives; user code reaches it via SYS_GDI_BITBLT.
void FramebufferBlit(u32 dst_x, u32 dst_y, const u32* src, u32 src_w, u32 src_h, u32 src_pitch_px);

/// Draw one 8x8 glyph at (x, y) using the built-in bitmap font.
/// `fg` is the ink colour; `bg` is painted behind the glyph cell
/// so text appears on a clean background rather than alpha-blended.
/// Unmapped characters render as a placeholder box (see font8x8.h).
void FramebufferDrawChar(u32 x, u32 y, char ch, u32 fg, u32 bg);

/// Draw a NUL-terminated string at (x, y). Cell advance is 8 px
/// per glyph. No wrapping, no newline handling — the caller
/// controls layout. Stops at the first NUL or when the next cell
/// would exceed the framebuffer width.
void FramebufferDrawString(u32 x, u32 y, const char* text, u32 fg, u32 bg);

/// Draw `text` at (x, y) with each font pixel rendered as a
/// `scale x scale` block — integer-scaled bitmap font. `scale=1`
/// is identical to FramebufferDrawString; scale=2 produces a
/// 16x16 cell; scale=4 a 32x32 cell. Useful for chrome titles
/// at the prototype's larger sizes (14 / 18 px) without
/// shipping a full TTF rasterizer. Bilinear smoothing isn't
/// applied — pixels stay crisp, the result reads as an
/// "8-bit / chunky" font. Cell advance is 8*scale px.
///
/// Capped at scale=8 so a hostile arg can't overflow into the
/// framebuffer. Stops at NUL or when the next cell would
/// exceed framebuffer width.
void FramebufferDrawStringScaled(u32 x, u32 y, const char* text, u32 fg, u32 bg, u32 scale);

/// Pixel width of `text` rendered at scale (i.e. strlen * 8 *
/// scale, bounded). NUL-safe.
u32 StringPixelWidthScaled(const char* text, u32 scale);

/// Exercise the draw path at boot: clear to black, draw coloured
/// corner swatches + a framing rectangle. Visible proof that the
/// firmware handoff + Mmio map + pixel store all work end-to-end.
/// No-op if !Available().
void FramebufferSelfTest();

/// Re-bind the framebuffer driver to a new physical base +
/// dimensions. Called after a GPU-side mode-set (Bochs VBE,
/// future Intel/AMD/NVIDIA modeset) so the compositor paints at
/// the new resolution. MapMmios a fresh virtual alias — the old
/// mapping is leaked (arena is a bump allocator, 512 MiB wide,
/// cheap). Rejects non-32-bpp modes + insane pitches. Returns
/// false on validation failure or MMIO-arena exhaustion.
///
/// Does NOT re-initialize overlay widgets (taskbar Y position,
/// cursor/clock placement) — they stay at their boot-time
/// coordinates. Callers that care about chrome alignment need
/// to rebuild it explicitly after this call succeeds.
bool FramebufferRebind(u64 phys, u32 width, u32 height, u32 pitch, u8 bpp);

/// Rebind to an already-mapped kernel VA — the external-memory
/// variant. Unlike `FramebufferRebind` this doesn't call `MapMmio`
/// (the caller already has the VA), so it's the right primitive for
/// a framebuffer that lives in ordinary RAM (virtio-gpu backing,
/// future guest-owned double-buffer, etc.). `virt` must remain
/// valid for the lifetime of the framebuffer. Returns false on
/// invalid geometry.
bool FramebufferRebindExternal(void* virt, u64 phys, u32 width, u32 height, u32 pitch, u8 bpp);

// Present hook. A backend driver (today: virtio-gpu) can register a
// function that runs at the end of `FramebufferPresent()`; the
// compositor calls that function as the last step of every
// `DesktopCompose` pass. For in-place framebuffers (firmware
// handoff, Bochs VBE) there's nothing to do — the hook stays null
// and `FramebufferPresent()` is a no-op. For virtio-gpu the hook
// runs TRANSFER_TO_HOST_2D + RESOURCE_FLUSH so the host sees the
// new guest pixels.
using FramebufferPresentFn = void (*)();
void FramebufferSetPresentHook(FramebufferPresentFn fn);
void FramebufferPresent();

/// Begin an offscreen compose pass. While compose is active every
/// pixel-write primitive in this header (`FramebufferPutPixel`,
/// `FillRect`, `Blit`, `FillRectAlpha`, `FillRectGradient` and
/// every primitive that lowers onto them) targets a shadow buffer in
/// normal RAM instead of the live MMIO framebuffer. Reads inside
/// `FillRectAlpha` likewise read the shadow, so per-pixel
/// `src-over` blending finally composites against whatever was
/// painted earlier in the same compose pass — which is what the
/// "real compositor" calls in `widget.cpp::DesktopCompose` need to
/// do true per-window alpha instead of the post-paint black overlay
/// dim that v0 ships.
///
/// Lazy-allocates the shadow buffer (4 bytes per pixel,
/// tightly-packed pitch = `width * 4`) on first call. If the
/// physical allocator can't satisfy the request, logs the failure
/// to COM1 and stays in direct-to-MMIO mode — every primitive then
/// behaves exactly as before this change. `FramebufferComposeActive`
/// reports the resolved state.
///
/// Idempotent: a second `BeginCompose` without a matching
/// `EndCompose` is a no-op. No-op if `!Available()`.
void FramebufferBeginCompose();

/// End the offscreen compose pass started by `FramebufferBeginCompose`.
/// Copies the shadow buffer to the live framebuffer row by row
/// (handling the live framebuffer's pitch padding) so the painted
/// frame appears on screen. Does NOT call `FramebufferPresent` —
/// callers that want the virtio-gpu flush hook to fire issue a
/// `FramebufferPresent()` call after this returns. No-op if compose
/// is not active.
void FramebufferEndCompose();

/// True between matched `BeginCompose` / `EndCompose` calls AND the
/// shadow buffer is live (i.e. the allocator succeeded). False
/// otherwise — including the "compose was requested but the
/// allocator failed and we silently fell back to direct mode"
/// case, which is observable to higher layers.
bool FramebufferComposeActive();

} // namespace duetos::drivers::video
