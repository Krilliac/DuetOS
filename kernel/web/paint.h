#pragma once

/*
 * DuetOS — display-list painter (web layout output -> pixels).
 *
 * This is the consumer half of the display_list.h contract: it
 * executes a flat, paint-order `DisplayList` (produced by
 * kernel/web/layout.{h,cpp}) into actual pixels. There are two sinks:
 *
 *   - PaintToCanvas: rasterise into a caller-owned in-memory RGBA8888
 *     canvas. This is the deterministic, framebuffer-free path the
 *     self-test asserts pixels against, and the path the browser uses
 *     to compose a page off-screen before blitting.
 *   - PaintToWindow: convenience wrapper that paints onto a canvas and
 *     blits it to the kernel framebuffer at a window-content origin
 *     (so the browser's WindowSetContentDraw callback stays a one-liner).
 *
 * Capabilities (REAL):
 *   - FillRect: solid fill, alpha-blended over the canvas when a < 255.
 *   - Border:   uniform stroke on all four edges (per-edge is a layout
 *               GAP, mirrored here).
 *   - TextRun:  monospace glyphs rendered with the SAME 8x8 bitmap font
 *               (drivers/video/font8x8) the framebuffer DrawString uses,
 *               cells scaled to the run's font-size, bold = a 1px
 *               horizontal smear, colour applied; clipped to the canvas.
 *   - ImageBox: blits a decoded RGBA image (resolved + decoded by the
 *               browser, handed in via an ImageProvider callback) into
 *               the box rect with nearest-neighbour scaling; a
 *               placeholder box when no image is available.
 *
 * All drawing is clipped to the canvas and offset by `scrollY` (a
 * positive scrollY moves content UP, i.e. reveals lower content).
 *
 * Memory discipline (kernel rules): the painter writes only into the
 * caller-supplied canvas / framebuffer. It allocates nothing. Pixel
 * format is RGBA8888, byte 0 = red, matching png.h/jpeg.h output so an
 * ImageBox image can be blitted byte-for-byte.
 */

#include "util/types.h"
#include "web/display_list.h"

namespace duetos::web
{

using duetos::i32;
using duetos::u32;
using duetos::u8;

/// Fixed-cell glyph metrics for the painter. Mirrors layout's
/// TextMetrics so a run laid out at glyphW/glyphH rasterises into the
/// same cells. The painter scales the 8x8 source bitmap to glyphW x
/// glyphH (integer nearest-neighbour) per cell.
struct PaintMetrics
{
    i32 glyphW = 8;      // device-px advance per glyph cell
    i32 glyphH = 16;     // device-px cell height
    i32 baseFontPx = 16; // font-size glyphW/glyphH were measured at
};

/// A decoded image the painter can blit for an ImageBox. `rgba` points
/// at `w * h * 4` bytes in R,G,B,A order (png.h / jpeg.h output). A
/// null `rgba` means "no image available" — the painter draws a
/// placeholder box instead.
struct PaintImage
{
    const u8* rgba = nullptr;
    u32 w = 0;
    u32 h = 0;
};

/// Callback the painter invokes for each ImageBox to obtain its decoded
/// pixels. `src` is the raw <img src> attribute (NUL-terminated); the
/// callback resolves + decodes it (the browser owns that policy) and
/// returns a PaintImage (rgba==nullptr to request a placeholder).
/// `ctx` is the opaque cookie passed to PaintToCanvas.
using ImageProvider = PaintImage (*)(const char* src, u32 srcLen, void* ctx);

/// Rasterise `dl` into `canvas` (a `cw * ch` RGBA8888 buffer, R,G,B,A
/// byte order, row-major, tightly packed). Content is offset up by
/// `scrollY` device px and clipped to the canvas. `metrics` drives
/// glyph cell scaling. `images` (may be null) resolves ImageBox pixels;
/// when null every ImageBox draws a placeholder. The canvas is NOT
/// cleared first — the caller fills the background before painting.
void PaintToCanvas(const DisplayList& dl, u8* canvas, u32 cw, u32 ch, i32 scrollY, const PaintMetrics& metrics,
                   ImageProvider images, void* imagesCtx);

/// Convenience: clear an off-screen canvas to `bgRgba`, paint `dl` into
/// it (via PaintToCanvas), and blit the result to the kernel
/// framebuffer at window-content origin (dstX, dstY). `canvas` must be
/// at least `cw * ch * 4` bytes; the caller owns it (the browser keeps
/// one scratch canvas alive). Background `bgRgba` is 0xRRGGBBAA.
void PaintToWindow(const DisplayList& dl, u8* canvas, u32 cw, u32 ch, i32 scrollY, const PaintMetrics& metrics,
                   ImageProvider images, void* imagesCtx, u32 dstX, u32 dstY, u32 bgRgba);

/// Boot self-test: builds a handcrafted display list (FillRect of a
/// known colour, a TextRun, a Border, an ImageBox over a tiny decoded
/// PNG fixture), PaintToCanvas, and asserts pixels: the FillRect region
/// equals the colour; the TextRun region has non-background glyph
/// pixels; the ImageBox region matches the decoded image; out-of-canvas
/// draws are clipped. Emits `[paint-selftest] PASS (...)`; on the first
/// failed sub-check fires KBP_PROBE_V(kBootSelftestFail, <#>) and emits
/// a FAIL line. Wired via DUETOS_BOOT_SELFTEST after LayoutSelfTest.
void PaintSelfTest();

} // namespace duetos::web
