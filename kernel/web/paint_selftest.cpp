/*
 * DuetOS — boot self-test for the display-list painter.
 *
 * Builds a handcrafted display list and rasterises it into an in-memory
 * RGBA8888 canvas, then asserts PIXELS:
 *   1. a FillRect region equals the requested colour exactly;
 *   2. a TextRun region contains non-background pixels (glyphs drew);
 *   3. a Border draws on the rect's edges but not its interior;
 *   4. an ImageBox over a decoded 2x2 PNG fixture reproduces the
 *      fixture's corner colours (nearest-neighbour blit);
 *   5. a FillRect partly off-canvas is CLIPPED (no out-of-bounds write,
 *      in-bounds slice still painted).
 *
 * On success emits `[paint-selftest] PASS (...)`; on the first failed
 * sub-check fires KBP_PROBE_V(kBootSelftestFail, <#>) and emits a FAIL
 * line. Wired via DUETOS_BOOT_SELFTEST after LayoutSelfTest.
 */

#include "web/paint.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "web/png.h"

namespace duetos::web
{

namespace
{

void Fail(u32 check)
{
    arch::SerialWrite("[paint-selftest] FAIL check=");
    arch::SerialWriteHex(check);
    arch::SerialWrite("\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, check);
}

// A 2x2 RGBA PNG (colour type 6) — same fixture the PNG decoder
// self-test uses. Pixels (R,G,B,A):
//   (0,0) red    FF 00 00 FF
//   (1,0) green  00 FF 00 FF
//   (0,1) blue   00 00 FF FF
//   (1,1) white  FF FF FF 80
constexpr u8 kPng2x2Rgba[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x06, 0x00, 0x00, 0x00, 0x72, 0xB6, 0x0D, 0x24, 0x00, 0x00, 0x00,
    0x1D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x01, 0x01, 0x12, 0x00, 0xED, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00,
    0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x49, 0x49, 0x09, 0x78, 0x4B, 0xD9,
    0xCE, 0x03, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
};

// Image provider for the self-test: returns the one decoded fixture for
// any src. ctx points at the PaintImage.
PaintImage TestImages(const char* /*src*/, u32 /*srcLen*/, void* ctx)
{
    return *static_cast<const PaintImage*>(ctx);
}

const u8* PixelAt(const u8* canvas, u32 cw, u32 x, u32 y)
{
    return canvas + (y * cw + x) * 4u;
}

bool PixelEq(const u8* p, u8 r, u8 g, u8 b)
{
    return p[0] == r && p[1] == g && p[2] == b;
}

} // namespace

void PaintSelfTest()
{
    constexpr u32 kCw = 64;
    constexpr u32 kCh = 64;
    static u8 canvas[kCw * kCh * 4];

    // Clear canvas to opaque black background so glyph/non-bg checks are
    // unambiguous.
    for (u32 i = 0; i < kCw * kCh; ++i)
    {
        canvas[i * 4 + 0] = 0;
        canvas[i * 4 + 1] = 0;
        canvas[i * 4 + 2] = 0;
        canvas[i * 4 + 3] = 255;
    }

    // Decode the PNG fixture for the ImageBox.
    static u8 pngScratch[16 * 1024];
    PngArena pngArena(pngScratch, sizeof(pngScratch));
    PngImage png{};
    if (!PngDecode(kPng2x2Rgba, static_cast<u32>(sizeof(kPng2x2Rgba)), pngArena, &png))
    {
        Fail(1);
        return;
    }
    PaintImage img{png.pixels, png.width, png.height};

    // Build the display list in static storage.
    static DisplayItem items[8];
    DisplayList dl{items, 0, 8};

    // Item 0: a solid FillRect {4,4,16,16} in #3366CC opaque.
    DisplayItem fill{};
    fill.cmd = DisplayCmd::FillRect;
    fill.rect = Rect{4, 4, 16, 16};
    fill.color = Color{0x33, 0x66, 0xCC, 255};
    dl.Push(fill);

    // Item 1: a TextRun "Hi" at {4, 28} in red, base font.
    static const char kHi[] = "Hi";
    DisplayItem text{};
    text.cmd = DisplayCmd::TextRun;
    text.rect = Rect{4, 28, 16, 16};
    text.color = Color{0xFF, 0x00, 0x00, 255};
    text.text = kHi;
    text.textLen = 2;
    text.fontPx = 16;
    dl.Push(text);

    // Item 2: a Border {28, 4, 16, 16}, 2px, green.
    DisplayItem border{};
    border.cmd = DisplayCmd::Border;
    border.rect = Rect{28, 4, 16, 16};
    border.color = Color{0x00, 0xFF, 0x00, 255};
    border.borderWidth = 2;
    dl.Push(border);

    // Item 3: an ImageBox {28, 28, 16, 16} over the 2x2 fixture.
    DisplayItem image{};
    image.cmd = DisplayCmd::ImageBox;
    image.rect = Rect{28, 28, 16, 16};
    image.src = "x.png";
    image.srcLen = 5;
    dl.Push(image);

    // Item 4: a FillRect that runs off the right + bottom edge to test
    // clipping: {56, 56, 32, 32} in #112233. Only the 8x8 in-bounds
    // corner should paint; nothing past x=64/y=64.
    DisplayItem clip{};
    clip.cmd = DisplayCmd::FillRect;
    clip.rect = Rect{56, 56, 32, 32};
    clip.color = Color{0x11, 0x22, 0x33, 255};
    dl.Push(clip);

    PaintMetrics pm;
    pm.glyphW = 8;
    pm.glyphH = 16;
    pm.baseFontPx = 16;

    PaintToCanvas(dl, canvas, kCw, kCh, /*scrollY=*/0, pm, TestImages, &img);

    // --- Check 1: FillRect region is exactly #3366CC at its centre. ---
    if (!PixelEq(PixelAt(canvas, kCw, 12, 12), 0x33, 0x66, 0xCC))
    {
        Fail(2);
        return;
    }
    // ...and a pixel just outside the fill is still black background.
    if (!PixelEq(PixelAt(canvas, kCw, 2, 2), 0, 0, 0))
    {
        Fail(3);
        return;
    }

    // --- Check 2: the TextRun region has non-background (red) glyph
    // pixels. Scan the 16x16 run box for any red pixel. ---
    {
        bool foundGlyph = false;
        for (u32 yy = 28; yy < 44 && !foundGlyph; ++yy)
        {
            for (u32 xx = 4; xx < 20; ++xx)
            {
                const u8* p = PixelAt(canvas, kCw, xx, yy);
                if (p[0] == 0xFF && p[1] == 0x00 && p[2] == 0x00)
                {
                    foundGlyph = true;
                    break;
                }
            }
        }
        if (!foundGlyph)
        {
            Fail(4);
            return;
        }
    }

    // --- Check 3: the Border drew green on the top edge but the
    // interior centre stays black. ---
    if (!PixelEq(PixelAt(canvas, kCw, 35, 4), 0x00, 0xFF, 0x00))
    {
        Fail(5);
        return;
    }
    if (!PixelEq(PixelAt(canvas, kCw, 35, 11), 0, 0, 0))
    {
        Fail(6);
        return;
    }

    // --- Check 4: ImageBox reproduces the fixture corners. The 16x16
    // box maps the 2x2 image: top-left quadrant = red, top-right =
    // green, bottom-left = blue. Sample a pixel deep in each quadrant. ---
    if (!PixelEq(PixelAt(canvas, kCw, 30, 30), 0xFF, 0x00, 0x00))
    {
        Fail(7);
        return;
    }
    if (!PixelEq(PixelAt(canvas, kCw, 41, 30), 0x00, 0xFF, 0x00))
    {
        Fail(8);
        return;
    }
    if (!PixelEq(PixelAt(canvas, kCw, 30, 41), 0x00, 0x00, 0xFF))
    {
        Fail(9);
        return;
    }

    // --- Check 5: the off-canvas FillRect painted its in-bounds slice
    // (pixel at 60,60 is #112233) and nothing corrupted the very last
    // canvas pixel beyond a clean write (it's in-bounds at 63,63). ---
    if (!PixelEq(PixelAt(canvas, kCw, 60, 60), 0x11, 0x22, 0x33))
    {
        Fail(10);
        return;
    }
    if (!PixelEq(PixelAt(canvas, kCw, 63, 63), 0x11, 0x22, 0x33))
    {
        Fail(11);
        return;
    }

    // --- Check 6: scroll offset shifts content up. Repaint with
    // scrollY=4: the FillRect at world-y 4..20 now lands at canvas-y
    // 0..16, so canvas (12, 8) (= world y 12) is the fill colour. ---
    for (u32 i = 0; i < kCw * kCh; ++i)
    {
        canvas[i * 4 + 0] = 0;
        canvas[i * 4 + 1] = 0;
        canvas[i * 4 + 2] = 0;
        canvas[i * 4 + 3] = 255;
    }
    PaintToCanvas(dl, canvas, kCw, kCh, /*scrollY=*/4, pm, TestImages, &img);
    if (!PixelEq(PixelAt(canvas, kCw, 12, 8), 0x33, 0x66, 0xCC))
    {
        Fail(12);
        return;
    }

    arch::SerialWrite("[paint-selftest] PASS (fill exact, glyph pixels, border edges, image blit, "
                      "clip, scroll-offset)\n");
}

} // namespace duetos::web
