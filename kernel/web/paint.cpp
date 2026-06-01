/*
 * DuetOS — display-list painter implementation.
 *
 * Executes a paint-order DisplayList into an RGBA8888 canvas (and,
 * via PaintToWindow, onto the kernel framebuffer). See paint.h for the
 * contract. Everything here is integer-only and allocation-free; the
 * only external dependency is the 8x8 console font glyph table that the
 * framebuffer DrawString path also uses, so painted text matches the
 * rest of the desktop pixel-for-pixel at the base cell size.
 */

#include "web/paint.h"

#include "drivers/video/font8x8.h"
#include "drivers/video/framebuffer.h"

namespace duetos::web
{

namespace
{

using duetos::drivers::video::Font8x8Lookup;
using duetos::drivers::video::kGlyphHeight;
using duetos::drivers::video::kGlyphWidth;

// One canvas pixel = 4 bytes R,G,B,A. Write `c` over the pixel at
// (x, y), alpha-blending source-over when c.a < 255. Out-of-bounds
// coordinates are silently dropped (this is the clip).
void BlendPixel(u8* canvas, u32 cw, u32 ch, i32 x, i32 y, const Color& c)
{
    if (x < 0 || y < 0 || static_cast<u32>(x) >= cw || static_cast<u32>(y) >= ch)
    {
        return;
    }
    u8* p = canvas + (static_cast<u32>(y) * cw + static_cast<u32>(x)) * 4u;
    if (c.a >= 255)
    {
        p[0] = c.r;
        p[1] = c.g;
        p[2] = c.b;
        p[3] = 255;
        return;
    }
    if (c.a == 0)
    {
        return;
    }
    // source-over: out = src*a + dst*(1-a), 8-bit fixed point.
    const u32 a = c.a;
    const u32 ia = 255u - a;
    p[0] = static_cast<u8>((c.r * a + p[0] * ia + 127u) / 255u);
    p[1] = static_cast<u8>((c.g * a + p[1] * ia + 127u) / 255u);
    p[2] = static_cast<u8>((c.b * a + p[2] * ia + 127u) / 255u);
    // Accumulate coverage so stacked translucent fills approach opaque.
    p[3] = static_cast<u8>(a + (p[3] * ia + 127u) / 255u);
}

// Fill the (already scroll-adjusted, clip happens per-pixel) rect.
void FillRectCmd(u8* canvas, u32 cw, u32 ch, i32 x, i32 y, i32 w, i32 h, const Color& c)
{
    if (w <= 0 || h <= 0 || c.a == 0)
    {
        return;
    }
    for (i32 yy = 0; yy < h; ++yy)
    {
        for (i32 xx = 0; xx < w; ++xx)
        {
            BlendPixel(canvas, cw, ch, x + xx, y + yy, c);
        }
    }
}

// Uniform stroke on all four edges of {x,y,w,h} at `bw` px (mirrors the
// layout subset's single-width-all-edges border).
void BorderCmd(u8* canvas, u32 cw, u32 ch, i32 x, i32 y, i32 w, i32 h, i32 bw, const Color& c)
{
    if (bw <= 0 || w <= 0 || h <= 0 || c.a == 0)
    {
        return;
    }
    if (bw > w)
    {
        bw = w;
    }
    if (bw > h)
    {
        bw = h;
    }
    FillRectCmd(canvas, cw, ch, x, y, w, bw, c);          // top
    FillRectCmd(canvas, cw, ch, x, y + h - bw, w, bw, c); // bottom
    FillRectCmd(canvas, cw, ch, x, y, bw, h, c);          // left
    FillRectCmd(canvas, cw, ch, x + w - bw, y, bw, h, c); // right
}

// Render one 8x8 source glyph scaled into a cellW x cellH box at
// (px, py). Each lit source bit becomes a (cellW/8 x cellH/8) block via
// integer nearest-neighbour sampling, so non-multiple sizes still draw.
// `bold` smears each lit pixel one column right.
void DrawGlyph(u8* canvas, u32 cw, u32 ch, i32 px, i32 py, char gc, i32 cellW, i32 cellH, const Color& color, bool bold)
{
    const u8* glyph = Font8x8Lookup(gc);
    for (i32 dy = 0; dy < cellH; ++dy)
    {
        const u32 srcRow = (static_cast<u32>(dy) * kGlyphHeight) / static_cast<u32>(cellH);
        const u8 bits = glyph[srcRow];
        for (i32 dx = 0; dx < cellW; ++dx)
        {
            const u32 srcCol = (static_cast<u32>(dx) * kGlyphWidth) / static_cast<u32>(cellW);
            bool on = (bits & (0x80u >> srcCol)) != 0;
            if (!on && bold && srcCol > 0)
            {
                // bold: a lit pixel one source-column to the left bleeds right.
                on = (bits & (0x80u >> (srcCol - 1))) != 0;
            }
            if (on)
            {
                BlendPixel(canvas, cw, ch, px + dx, py + dy, color);
            }
        }
    }
}

// Draw a run of monospace glyphs starting at (x, y). The run's font
// size scales the base cell; runs advance by the scaled cell width.
void TextRunCmd(u8* canvas, u32 cw, u32 ch, i32 x, i32 y, const DisplayItem& it, const PaintMetrics& m)
{
    if (it.text == nullptr || it.textLen == 0)
    {
        return;
    }
    const i32 base = (m.baseFontPx > 0) ? m.baseFontPx : 16;
    i32 cellW = (m.glyphW * it.fontPx) / base;
    i32 cellH = (m.glyphH * it.fontPx) / base;
    if (cellW < 1)
    {
        cellW = 1;
    }
    if (cellH < 1)
    {
        cellH = 1;
    }
    i32 cx = x;
    for (u32 i = 0; i < it.textLen; ++i)
    {
        // Whole-cell clip: skip cells entirely off either horizontal edge.
        if (cx + cellW > 0 && cx < static_cast<i32>(cw))
        {
            DrawGlyph(canvas, cw, ch, cx, y, it.text[i], cellW, cellH, it.color, it.bold);
        }
        cx += cellW;
        if (cx >= static_cast<i32>(cw))
        {
            break; // rest of the run is off the right edge
        }
    }
}

// Blit a decoded image into {x,y,w,h} with nearest-neighbour scaling.
// Source is RGBA8888 (R,G,B,A); alpha is honoured via BlendPixel.
void ImageBlit(u8* canvas, u32 cw, u32 ch, i32 x, i32 y, i32 w, i32 h, const PaintImage& img)
{
    if (img.rgba == nullptr || img.w == 0 || img.h == 0 || w <= 0 || h <= 0)
    {
        return;
    }
    for (i32 dy = 0; dy < h; ++dy)
    {
        const u32 sy = (static_cast<u32>(dy) * img.h) / static_cast<u32>(h);
        for (i32 dx = 0; dx < w; ++dx)
        {
            const u32 sx = (static_cast<u32>(dx) * img.w) / static_cast<u32>(w);
            const u8* sp = img.rgba + (sy * img.w + sx) * 4u;
            const Color c{sp[0], sp[1], sp[2], sp[3]};
            BlendPixel(canvas, cw, ch, x + dx, y + dy, c);
        }
    }
}

// Placeholder for an <img> with no usable image: a light-gray box with
// a 1px border + a diagonal so it reads as "missing image".
void ImagePlaceholder(u8* canvas, u32 cw, u32 ch, i32 x, i32 y, i32 w, i32 h)
{
    if (w <= 0 || h <= 0)
    {
        return;
    }
    FillRectCmd(canvas, cw, ch, x, y, w, h, Color{0xE0, 0xE0, 0xE0, 255});
    BorderCmd(canvas, cw, ch, x, y, w, h, 1, Color{0x80, 0x80, 0x80, 255});
    const i32 steps = (w < h) ? w : h;
    for (i32 i = 0; i < steps; ++i)
    {
        const i32 dx = (i * (w - 1)) / (steps > 1 ? steps - 1 : 1);
        const i32 dy = (i * (h - 1)) / (steps > 1 ? steps - 1 : 1);
        BlendPixel(canvas, cw, ch, x + dx, y + dy, Color{0x80, 0x80, 0x80, 255});
    }
}

} // namespace

void PaintToCanvas(const DisplayList& dl, u8* canvas, u32 cw, u32 ch, i32 scrollY, const PaintMetrics& metrics,
                   ImageProvider images, void* imagesCtx)
{
    if (canvas == nullptr || dl.items == nullptr || cw == 0 || ch == 0)
    {
        return;
    }
    for (u32 i = 0; i < dl.count; ++i)
    {
        const DisplayItem& it = dl.items[i];
        const i32 x = it.rect.x;
        const i32 y = it.rect.y - scrollY;
        switch (it.cmd)
        {
        case DisplayCmd::FillRect:
            FillRectCmd(canvas, cw, ch, x, y, it.rect.w, it.rect.h, it.color);
            break;
        case DisplayCmd::Border:
            BorderCmd(canvas, cw, ch, x, y, it.rect.w, it.rect.h, it.borderWidth, it.color);
            break;
        case DisplayCmd::TextRun:
            TextRunCmd(canvas, cw, ch, x, y, it, metrics);
            break;
        case DisplayCmd::ImageBox:
        {
            PaintImage img{};
            if (images != nullptr)
            {
                img = images(it.src, it.srcLen, imagesCtx);
            }
            if (img.rgba != nullptr)
            {
                ImageBlit(canvas, cw, ch, x, y, it.rect.w, it.rect.h, img);
            }
            else
            {
                ImagePlaceholder(canvas, cw, ch, x, y, it.rect.w, it.rect.h);
            }
            break;
        }
        }
    }
}

void PaintToWindow(const DisplayList& dl, u8* canvas, u32 cw, u32 ch, i32 scrollY, const PaintMetrics& metrics,
                   ImageProvider images, void* imagesCtx, u32 dstX, u32 dstY, u32 bgRgba)
{
    if (canvas == nullptr || cw == 0 || ch == 0)
    {
        return;
    }
    // Clear to background (RGBA bytes from the 0xRRGGBBAA argument).
    const u8 br = static_cast<u8>((bgRgba >> 24) & 0xFF);
    const u8 bg = static_cast<u8>((bgRgba >> 16) & 0xFF);
    const u8 bb = static_cast<u8>((bgRgba >> 8) & 0xFF);
    const u8 ba = static_cast<u8>(bgRgba & 0xFF);
    for (u32 i = 0; i < cw * ch; ++i)
    {
        canvas[i * 4 + 0] = br;
        canvas[i * 4 + 1] = bg;
        canvas[i * 4 + 2] = bb;
        canvas[i * 4 + 3] = ba;
    }

    PaintToCanvas(dl, canvas, cw, ch, scrollY, metrics, images, imagesCtx);

    // Pack RGBA8888 -> the framebuffer's 0x00RRGGBB u32 per pixel and
    // blit row by row. We reuse the canvas tail-free by packing in place
    // into a u32 view? No — the framebuffer wants u32 0xRRGGBB; build a
    // small per-row scratch on the stack to avoid a second full buffer.
    constexpr u32 kRowMax = 4096;
    u32 rowbuf[kRowMax];
    const u32 rowPixels = (cw < kRowMax) ? cw : kRowMax;
    for (u32 yy = 0; yy < ch; ++yy)
    {
        const u8* src = canvas + (yy * cw) * 4u;
        for (u32 xx = 0; xx < rowPixels; ++xx)
        {
            const u8* sp = src + xx * 4u;
            rowbuf[xx] = (static_cast<u32>(sp[0]) << 16) | (static_cast<u32>(sp[1]) << 8) | static_cast<u32>(sp[2]);
        }
        duetos::drivers::video::FramebufferBlit(dstX, dstY + yy, rowbuf, rowPixels, 1, rowPixels);
    }
}

} // namespace duetos::web
