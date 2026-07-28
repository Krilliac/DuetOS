#include "drivers/video/wallpaper_aurora.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/blend_math.h"
#include "drivers/video/font8x8.h"
#include "drivers/video/framebuffer.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"

namespace duetos::drivers::video
{

namespace
{

// ----- Design tokens (docs/aurora-theme/README.md "Dark (default)") --
//
// Only the backdrop's own tokens live here; the accent pair is passed
// in so an accent-variant palette (DuetBlue / DuetViolet / DuetGreen)
// recolours the blobs without a second token table.
struct Palette
{
    u32 bg0, bg1, bg2;
    u32 hairline;        // --line, pre-opacity
    u8 hairline_alpha;   // --line alpha * layer opacity
    u32 ink2;            // hex-dump band ink
    u32 vignette;        // --vignette colour
    u8 vignette_alpha;   // --vignette alpha
};

constexpr Palette kDark = {
    0x0004060A, 0x00080C12, 0x000E141D, 0x00FFFFFF, 13, 0x00A7B3C2, 0x00000000, 56,
};

constexpr Palette kLight = {
    0x00DFE5EE, 0x00EAEEF4, 0x00F2F5F9, 0x00091426, 13, 0x004B5765, 0x00182C50, 31,
};

// Q12 fixed point is used for every normalised coordinate below:
// 4096 == 1.0. Chosen so a squared distance still fits comfortably in
// 32 bits (4096^2 == 2^24) and the whole generator stays integer-only.
constexpr i32 kOne = 4096;

// Linear interpolation between two packed 0x00RRGGBB colours.
// `t` is Q12 and is clamped by the caller.
u32 LerpRgb(u32 a, u32 b, i32 t)
{
    const i32 it = kOne - t;
    const u32 r = static_cast<u32>((((a >> 16) & 0xFF) * it + ((b >> 16) & 0xFF) * t) >> 12);
    const u32 g = static_cast<u32>((((a >> 8) & 0xFF) * it + ((b >> 8) & 0xFF) * t) >> 12);
    const u32 bl = static_cast<u32>(((a & 0xFF) * it + (b & 0xFF) * t) >> 12);
    return (r << 16) | (g << 8) | bl;
}

// Squared normalised distance from (x, y) to an ellipse centred at
// (cx, cy) with radii (rx, ry), in Q12. 0 at the centre, 4096 on the
// ellipse boundary. Saturates rather than overflowing for far pixels.
i32 EllipseD2(i32 x, i32 y, i32 cx, i32 cy, i32 rx, i32 ry)
{
    if (rx <= 0 || ry <= 0)
    {
        return kOne;
    }
    const i64 dx = (static_cast<i64>(x - cx) * kOne) / rx;
    const i64 dy = (static_cast<i64>(y - cy) * kOne) / ry;
    const i64 d2 = ((dx * dx) + (dy * dy)) >> 12;
    return (d2 > 4 * kOne) ? 4 * kOne : static_cast<i32>(d2);
}

// ----- Cache -------------------------------------------------------

constinit u32* g_cache = nullptr;
constinit u64 g_cache_frames = 0;
constinit u32 g_cache_w = 0;
constinit u32 g_cache_h = 0;
constinit u32 g_cache_accent = 0;
constinit u32 g_cache_peer = 0;
constinit bool g_cache_light = false;
constinit bool g_cache_valid = false;

// Blend `src` at `alpha` over the cache pixel at (x, y). Bounds are
// the caller's responsibility — every loop below is already clipped
// to [0, w) x [0, h).
inline void CacheBlend(u32 x, u32 y, u32 src, u32 alpha)
{
    if (alpha == 0)
    {
        return;
    }
    u32* p = &g_cache[static_cast<u64>(y) * g_cache_w + x];
    *p = BlendOver(*p, src, static_cast<u8>(alpha > 255 ? 255 : alpha));
}

// ----- Layer 1: the 158-degree base gradient -----------------------
//
// CSS gradient angles run clockwise from "up", so 158 degrees points
// down and slightly right: (sin 158, -cos 158) = (0.3746, 0.9272).
// The stops are --bg-2 at 0 %, --bg-1 at 52 % and --bg-0 at 100 %.
void PaintBaseGradient(u32 w, u32 h, const Palette& pal)
{
    // Projection onto the gradient axis, scaled by 1024 so the whole
    // span fits an i32 without a divide in the inner loop.
    const i64 span = (static_cast<i64>(w) * 374) + (static_cast<i64>(h) * 927);
    if (span == 0)
    {
        return;
    }
    for (u32 y = 0; y < h; ++y)
    {
        const i64 row = static_cast<i64>(y) * 927;
        u32* dst = &g_cache[static_cast<u64>(y) * w];
        for (u32 x = 0; x < w; ++x)
        {
            const i64 proj = row + (static_cast<i64>(x) * 374);
            const i32 t = static_cast<i32>((proj * kOne) / span);
            // 52 % of 4096 == 2130.
            dst[x] = (t < 2130) ? LerpRgb(pal.bg2, pal.bg1, (t * kOne) / 2130)
                                : LerpRgb(pal.bg1, pal.bg0, ((t - 2130) * kOne) / (kOne - 2130));
        }
    }
}

// ----- Layer 2: the aurora blobs -----------------------------------
//
// Each blob is a radial gradient that reaches `peak` alpha at its
// centre and zero on the ellipse boundary. `peak` runs hotter than the
// design's literal .34 / .22 / .14: the squared falloff concentrates
// the wash into the middle third of the ellipse, so matching the CSS
// alpha at the centre is what actually matches the CSS *appearance*
// over the same area. The design blurs the layer
// by 10 px; a squared falloff (1 - d^2)^2 produces the same soft
// shoulder without a separate blur pass.
void PaintBlob(u32 w, u32 h, u32 rgb, u32 cx_pct, u32 cy_pct, u32 rx_pct, u32 ry_pct, u32 peak)
{
    const i32 cx = static_cast<i32>((w * cx_pct) / 100);
    const i32 cy = static_cast<i32>((h * cy_pct) / 100);
    const i32 rx = static_cast<i32>((w * rx_pct) / 100);
    const i32 ry = static_cast<i32>((h * ry_pct) / 100);
    const i32 x0 = (cx - rx > 0) ? cx - rx : 0;
    const i32 y0 = (cy - ry > 0) ? cy - ry : 0;
    const i32 x1 = (cx + rx < static_cast<i32>(w)) ? cx + rx : static_cast<i32>(w);
    const i32 y1 = (cy + ry < static_cast<i32>(h)) ? cy + ry : static_cast<i32>(h);
    for (i32 y = y0; y < y1; ++y)
    {
        for (i32 x = x0; x < x1; ++x)
        {
            const i32 d2 = EllipseD2(x, y, cx, cy, rx, ry);
            if (d2 >= kOne)
            {
                continue;
            }
            const i64 f = kOne - d2;               // Q12, 1.0 at the centre
            const i64 falloff = (f * f) >> 12;     // squared shoulder
            const u32 a = static_cast<u32>((static_cast<i64>(peak) * falloff) >> 12);
            CacheBlend(static_cast<u32>(x), static_cast<u32>(y), rgb, a);
        }
    }
}

// ----- Layer 3: the hairline grid ----------------------------------
//
// 60 px at the 1920 design canvas; 32 px here so the cell count reads
// the same at 1024 wide. --line is white at 10 %, the layer sits at
// 50 % opacity, and a radial mask (80 % x 70 % at 50 % / 45 %) fades
// it out toward the screen edges.
void PaintGrid(u32 w, u32 h, const Palette& pal)
{
    constexpr u32 kStep = 32;
    const u32 kLineAlpha = pal.hairline_alpha; // --line alpha * layer opacity
    const i32 cx = static_cast<i32>(w / 2);
    const i32 cy = static_cast<i32>((h * 45) / 100);
    const i32 rx = static_cast<i32>((w * 80) / 200);
    const i32 ry = static_cast<i32>((h * 70) / 200);
    auto mask = [&](i32 x, i32 y) -> u32
    {
        const i32 d2 = EllipseD2(x, y, cx, cy, rx, ry);
        if (d2 >= kOne)
        {
            return 0;
        }
        return static_cast<u32>((static_cast<i64>(kLineAlpha) * (kOne - d2)) >> 12);
    };
    for (u32 y = 0; y < h; y += kStep)
    {
        for (u32 x = 0; x < w; ++x)
        {
            CacheBlend(x, y, pal.hairline, mask(static_cast<i32>(x), static_cast<i32>(y)));
        }
    }
    for (u32 x = 0; x < w; x += kStep)
    {
        for (u32 y = 0; y < h; ++y)
        {
            CacheBlend(x, y, pal.hairline, mask(static_cast<i32>(x), static_cast<i32>(y)));
        }
    }
}

// ----- Layer 4: the hex-dump band ----------------------------------
//
// Rows are `<offset 8 hex>: <bytes>` with the byte stream generated by
// the design's LCG, `((r * 40 + c) * 1103515245 + 12345) & 0xff`, so
// the pattern is bit-identical to the reference render. 24 bytes per
// row rather than the design's 40: the 8x8 chrome font is 8 px wide
// where JetBrains Mono at 12 px is ~7, and 40 bytes would run off a
// 1024-px framebuffer.
void PaintHexBand(u32 w, u32 h, const Palette& pal)
{
    constexpr u32 kBytesPerRow = 24;
    constexpr u32 kRows = 16;
    constexpr u32 kLineHeight = 14;
    constexpr u32 kBaseAlpha = 33; // 0.13 * 255
    const u32 origin_x = 24;
    const u32 origin_y = (h * 26) / 100;
    if (origin_y + kRows * kLineHeight >= h)
    {
        return;
    }
    // mask-image: linear-gradient(105deg, #000 0%, transparent 46%).
    // 105 degrees clockwise from "up" is (0.966, 0.259).
    const i64 mask_span = ((static_cast<i64>(w) * 966) + (static_cast<i64>(h) * 259)) / 1000;
    const i64 mask_end = (mask_span * 46) / 100;

    static const char kHex[] = "0123456789abcdef";
    char line[8 + 2 + kBytesPerRow * 3 + 1];

    for (u32 r = 0; r < kRows; ++r)
    {
        const u32 offset = r * kBytesPerRow;
        u32 o = 0;
        for (i32 nib = 7; nib >= 0; --nib)
        {
            line[o++] = kHex[(offset >> (nib * 4)) & 0xF];
        }
        line[o++] = ':';
        for (u32 c = 0; c < kBytesPerRow; ++c)
        {
            const u32 v = ((r * 40 + c) * 1103515245u + 12345u) & 0xFFu;
            line[o++] = ' ';
            line[o++] = kHex[v >> 4];
            line[o++] = kHex[v & 0xF];
        }
        line[o] = '\0';

        const u32 row_y = origin_y + r * kLineHeight;
        for (u32 i = 0; line[i] != '\0'; ++i)
        {
            const u8* glyph = Font8x8Lookup(line[i]);
            const u32 gx = origin_x + i * kGlyphWidth;
            if (gx + kGlyphWidth >= w)
            {
                break;
            }
            for (u32 gy = 0; gy < kGlyphHeight; ++gy)
            {
                const u8 bits = glyph[gy];
                for (u32 bx = 0; bx < kGlyphWidth; ++bx)
                {
                    if ((bits & (0x80u >> bx)) == 0)
                    {
                        continue;
                    }
                    const u32 px = gx + bx;
                    const u32 py = row_y + gy;
                    const i64 proj = ((static_cast<i64>(px) * 966) + (static_cast<i64>(py) * 259)) / 1000;
                    if (proj >= mask_end)
                    {
                        continue;
                    }
                    const u32 a = static_cast<u32>((kBaseAlpha * (mask_end - proj)) / mask_end);
                    CacheBlend(px, py, pal.ink2, a);
                }
            }
        }
    }
}

// ----- Layer 6: the vignette ---------------------------------------
//
// radial-gradient(120% 100% at 50% 50%, transparent 40%, --vignette).
void PaintVignette(u32 w, u32 h, const Palette& pal)
{
    const u32 kVignetteAlpha = pal.vignette_alpha;
    const i32 cx = static_cast<i32>(w / 2);
    const i32 cy = static_cast<i32>(h / 2);
    const i32 rx = static_cast<i32>((w * 120) / 200);
    const i32 ry = static_cast<i32>(h / 2);
    // The stop runs from 40 % to 100 % of the radius; comparing
    // squared distances keeps the loop free of a square root, at the
    // cost of a slightly steeper ramp than the CSS original.
    constexpr i32 kInner = (kOne * 16) / 100; // 0.40^2
    for (u32 y = 0; y < h; ++y)
    {
        for (u32 x = 0; x < w; ++x)
        {
            const i32 d2 = EllipseD2(static_cast<i32>(x), static_cast<i32>(y), cx, cy, rx, ry);
            if (d2 <= kInner)
            {
                continue;
            }
            const i32 clamped = (d2 > kOne) ? kOne : d2;
            const u32 a = static_cast<u32>((static_cast<i64>(kVignetteAlpha) * (clamped - kInner)) / (kOne - kInner));
            CacheBlend(x, y, pal.vignette, a);
        }
    }
}

bool EnsureCache(u32 w, u32 h, u32 accent, u32 peer, bool light)
{
    if (g_cache != nullptr && g_cache_w == w && g_cache_h == h && g_cache_accent == accent && g_cache_peer == peer &&
        g_cache_light == light && g_cache_valid)
    {
        return true;
    }

    if (g_cache != nullptr && (g_cache_w != w || g_cache_h != h))
    {
        // Geometry changed under us (framebuffer rebind). The frame
        // allocator has no partial-release path for a contiguous run
        // of a different size, so release and re-acquire.
        mm::FreeContiguousFrames(mm::VirtToPhys(g_cache), g_cache_frames);
        g_cache = nullptr;
        g_cache_frames = 0;
    }

    if (g_cache == nullptr)
    {
        const u64 bytes = static_cast<u64>(w) * 4ULL * h;
        const u64 frames = (bytes + (mm::kPageSize - 1ULL)) >> mm::kPageSizeLog2;
        auto phys = mm::AllocateContiguousFrames(frames);
        if (!phys)
        {
            arch::SerialWrite("[video/aurora] backdrop cache alloc failed - flat wallpaper stands\n");
            return false;
        }
        g_cache = static_cast<u32*>(mm::PhysToVirt(phys.value()));
        g_cache_frames = frames;
    }

    g_cache_w = w;
    g_cache_h = h;
    g_cache_accent = accent;
    g_cache_peer = peer;
    g_cache_light = light;

    const Palette& pal = light ? kLight : kDark;
    PaintBaseGradient(w, h, pal);
    // README §1 layer 2: 46% 44% at 74% 20% accent 34%,
    //                    42% 40% at 16% 86% accent-2 22%,
    //                    34% 32% at 22% 14% accent 14%.
    PaintBlob(w, h, accent, 74, 20, 46, 44, 120);
    PaintBlob(w, h, peer, 16, 86, 42, 40, 105);
    PaintBlob(w, h, accent, 22, 14, 34, 32, 48);
    PaintGrid(w, h, pal);
    PaintHexBand(w, h, pal);
    PaintVignette(w, h, pal);

    g_cache_valid = true;
    arch::SerialWrite("[video/aurora] backdrop cache built\n");
    return true;
}

} // namespace

bool AuroraWallpaperPaint(u32 accent_native, u32 accent_peer, bool light)
{
    if (!FramebufferAvailable())
    {
        return false;
    }
    const auto info = FramebufferGet();
    if (info.width == 0 || info.height == 0)
    {
        return false;
    }
    if (!EnsureCache(info.width, info.height, accent_native & 0x00FFFFFFu, accent_peer & 0x00FFFFFFu, light))
    {
        return false;
    }
    FramebufferBlit(0, 0, g_cache, info.width, info.height, info.width);
    return true;
}

void AuroraWallpaperInvalidate()
{
    g_cache_valid = false;
}

} // namespace duetos::drivers::video
