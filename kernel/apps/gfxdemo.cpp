#include "gfxdemo.h"

#include "../arch/x86_64/serial.h"
#include "../drivers/video/framebuffer.h"

namespace duetos::apps::gfxdemo
{

namespace
{

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

// 64-entry signed sine LUT: sin_lut[i] = (i32) round(127 * sin(i * 2π / 64)).
// Range is roughly -127..127. Used for:
//   - the sine-wave overlay along the window's mid-Y row,
//   - the parametric circle generator that traces the
//     concentric outline rings.
// Hand-computed at build time; no float in the kernel.
constexpr duetos::i32 kSinLut[64] = {
    0,    12,   24,   37,   48,   59,   70,   80,  89,  97,  105,  111,  117,  121,  124,  126,
    127,  126,  124,  121,  117,  111,  105,  97,  89,  80,  70,   59,   48,   37,   24,   12,
    0,    -12,  -24,  -37,  -48,  -59,  -70,  -80, -89, -97, -105, -111, -117, -121, -124, -126,
    -127, -126, -124, -121, -117, -111, -105, -97, -89, -80, -70,  -59,  -48,  -37,  -24,  -12,
};

// Cosine via phase-shifted sine LUT: cos(θ) = sin(θ + 90°).
// Index space is 0..63 (64 = 2π).
inline duetos::i32 SinIdx(duetos::u32 i)
{
    return kSinLut[i & 63];
}
inline duetos::i32 CosIdx(duetos::u32 i)
{
    return kSinLut[(i + 16) & 63];
}

constexpr duetos::u32 kTitleColour = 0x00FFFFFF;
constexpr duetos::u32 kTitleBg = 0x00000000;
constexpr duetos::u32 kSineColour = 0x00FFFF20;
constexpr duetos::u32 kRingColour[3] = {0x00FFFFFF, 0x0080FFFF, 0x00FF80FF};

// Pack an RGB byte triple into a 0x00RRGGBB pixel.
inline duetos::u32 Pack(duetos::u32 r, duetos::u32 g, duetos::u32 b)
{
    if (r > 255)
        r = 255;
    if (g > 255)
        g = 255;
    if (b > 255)
        b = 255;
    return (r << 16) | (g << 8) | b;
}

// Per-pixel colour function. (x, y) are window-relative.
// Three independent channel ramps biased so red comes from the
// horizontal axis, green from the vertical, and blue from the
// anti-diagonal. The product of two 8-step "soft tile" functions
// adds a gentle vignette texture that reads as "computed pixels"
// rather than "flat fill" without overwhelming the underlying
// gradient ramp at screenshot scale.
inline duetos::u32 GradientPixel(duetos::u32 x, duetos::u32 y, duetos::u32 cw, duetos::u32 ch)
{
    const duetos::u32 cw_ = cw ? cw : 1;
    const duetos::u32 ch_ = ch ? ch : 1;
    duetos::i32 r = static_cast<duetos::i32>((x * 255) / cw_);
    duetos::i32 g = static_cast<duetos::i32>((y * 255) / ch_);
    duetos::i32 b = static_cast<duetos::i32>(255 - (((x + y) * 255) / (cw_ + ch_)));

    // Soft 16-pixel quilt: each cell is a low-amplitude bump that
    // shifts the channel up to ±8 from the ramp value. Together
    // they read as a fine cross-hatch without losing the gradient.
    const duetos::i32 quilt = static_cast<duetos::i32>(((x >> 4) + (y >> 4)) & 1) * 8 - 4;
    r += quilt;
    g += quilt;
    b -= quilt;
    if (r < 0)
        r = 0;
    if (r > 255)
        r = 255;
    if (g < 0)
        g = 0;
    if (g > 255)
        g = 255;
    if (b < 0)
        b = 0;
    if (b > 255)
        b = 255;
    return Pack(static_cast<duetos::u32>(r), static_cast<duetos::u32>(g), static_cast<duetos::u32>(b));
}

// Draw the (filled-circle outline) by tracing 64 sample points
// around the perimeter and putting one pixel each. Cheap, no
// sqrt, no Bresenham — the LUT does all the heavy lifting.
void StrokeCircle(duetos::u32 cx, duetos::u32 cy, duetos::u32 radius, duetos::u32 colour)
{
    using duetos::drivers::video::FramebufferPutPixel;
    if (radius == 0)
        return;
    // 128 samples for visual smoothness (each LUT step is ~5.6°
    // → 128 samples = 360° with one sample every 2.8°).
    for (duetos::u32 i = 0; i < 128; ++i)
    {
        const duetos::u32 lut_idx = (i * 64) / 128; // 0..63
        const duetos::i32 dx = (CosIdx(lut_idx) * static_cast<duetos::i32>(radius)) / 127;
        const duetos::i32 dy = (SinIdx(lut_idx) * static_cast<duetos::i32>(radius)) / 127;
        const duetos::i32 px = static_cast<duetos::i32>(cx) + dx;
        const duetos::i32 py = static_cast<duetos::i32>(cy) + dy;
        if (px < 0 || py < 0)
            continue;
        FramebufferPutPixel(static_cast<duetos::u32>(px), static_cast<duetos::u32>(py), colour);
    }
}

void DrawFn(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, void*)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    using duetos::drivers::video::FramebufferPutPixel;

    if (cw == 0 || ch == 0)
        return;

    // 1) Per-pixel gradient + shimmer fill of the entire client.
    //    This is the bread-and-butter "computed pixels" pass.
    for (duetos::u32 y = 0; y < ch; ++y)
    {
        for (duetos::u32 x = 0; x < cw; ++x)
        {
            FramebufferPutPixel(cx + x, cy + y, GradientPixel(x, y, cw, ch));
        }
    }

    // 2) Three concentric rings centred on the client area.
    //    Different colours so the outline reads against the
    //    underlying gradient at every angle.
    const duetos::u32 mx = cx + cw / 2;
    const duetos::u32 my = cy + ch / 2;
    const duetos::u32 r_max = (cw < ch ? cw : ch) / 2;
    if (r_max >= 24)
    {
        StrokeCircle(mx, my, r_max - 8, kRingColour[0]);
        StrokeCircle(mx, my, (r_max * 2) / 3, kRingColour[1]);
        StrokeCircle(mx, my, r_max / 3, kRingColour[2]);
    }

    // 3) Sine-wave overlay traced left-to-right, amplitude h/4,
    //    period = client width. One pixel column per x. Bright
    //    yellow against any underlying gradient hue.
    {
        const duetos::i32 amp = static_cast<duetos::i32>(ch / 4);
        const duetos::i32 mid_y = static_cast<duetos::i32>(my);
        for (duetos::u32 x = 0; x < cw; ++x)
        {
            // Phase walks the LUT once across the full width:
            //   idx = (x * 64) / cw, so x=cw → idx=64 (one period).
            const duetos::u32 idx = (x * 64) / (cw ? cw : 1);
            const duetos::i32 dy = (SinIdx(idx) * amp) / 127;
            const duetos::i32 yp = mid_y + dy;
            if (yp < static_cast<duetos::i32>(cy) || yp >= static_cast<duetos::i32>(cy + ch))
                continue;
            FramebufferPutPixel(cx + x, static_cast<duetos::u32>(yp), kSineColour);
            // Two-pixel-thick wave so it reads cleanly at the
            // 1280x800 framebuffer scale used for screenshots.
            if (yp + 1 < static_cast<duetos::i32>(cy + ch))
                FramebufferPutPixel(cx + x, static_cast<duetos::u32>(yp + 1), kSineColour);
        }
    }

    // 4) Title strip — one row of 8x8 glyphs centred horizontally
    //    near the top of the client area, with a black ground so
    //    the text reads against any gradient hue.
    {
        const char kTitle[] = "DUETOS GFX DEMO - NATIVE PIXEL RENDER";
        const duetos::u32 nch = sizeof(kTitle) - 1;
        const duetos::u32 text_w = nch * 8;
        const duetos::u32 text_h = 10;
        if (cw > text_w + 8 && ch > text_h + 8)
        {
            const duetos::u32 strip_x = cx + (cw - text_w) / 2 - 4;
            const duetos::u32 strip_y = cy + 6;
            FramebufferFillRect(strip_x, strip_y, text_w + 8, text_h, kTitleBg);
            FramebufferDrawString(cx + (cw - text_w) / 2, strip_y + 1, kTitle, kTitleColour, kTitleBg);
        }
    }

    // 5) Subtitle strip — line two, smaller. Same chrome.
    {
        const char kSub[] = "FRAMEBUFFER + DIRECTX V0 PIPELINE";
        const duetos::u32 nch = sizeof(kSub) - 1;
        const duetos::u32 text_w = nch * 8;
        const duetos::u32 text_h = 10;
        if (cw > text_w + 8 && ch > text_h + 24)
        {
            const duetos::u32 strip_x = cx + (cw - text_w) / 2 - 4;
            const duetos::u32 strip_y = cy + 22;
            FramebufferFillRect(strip_x, strip_y, text_w + 8, text_h, kTitleBg);
            FramebufferDrawString(cx + (cw - text_w) / 2, strip_y + 1, kSub, kRingColour[1], kTitleBg);
        }
    }
}

} // namespace

void GfxDemoInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle GfxDemoWindow()
{
    return g_handle;
}

void GfxDemoSelfTest()
{
    using duetos::arch::SerialWrite;
    bool pass = true;
    // Spot-check the sine LUT: sin(0)=0, sin(π/2)=127, sin(π)=0, sin(3π/2)=-127.
    if (kSinLut[0] != 0)
        pass = false;
    if (kSinLut[16] != 127)
        pass = false;
    if (kSinLut[32] != 0)
        pass = false;
    if (kSinLut[48] != -127)
        pass = false;
    // CosIdx(0) == sin(π/2) == 127; CosIdx(16) == sin(π) == 0.
    if (CosIdx(0) != 127)
        pass = false;
    if (CosIdx(16) != 0)
        pass = false;
    // Pack saturates correctly.
    if (Pack(300, 0, 0) != 0x00FF0000)
        pass = false;
    SerialWrite(pass ? "[gfxdemo] self-test OK (sin LUT + Pack saturation)\n" : "[gfxdemo] self-test FAILED\n");
}

} // namespace duetos::apps::gfxdemo
