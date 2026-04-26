#include "gfxdemo_modes.h"

#include "../drivers/video/framebuffer.h"

namespace duetos::apps::gfxdemo
{

namespace
{

// ---------------------------------------------------------------
// 256-entry signed sine LUT in Q15. Hand-generated at build time.
// Values mirror sin(2π * i / 256) * 32767, rounded to nearest.
// Symmetry note: only the first quarter is materialised; the rest
// is reflected at lookup time. This keeps the LUT inside L1 even
// alongside the renderers' own working sets.
// ---------------------------------------------------------------
constexpr duetos::i32 kSinQuarter[65] = {
    0,     804,   1608,  2410,  3212,  4011,  4808,  5602,  6393,  7179,  7962,  8739,  9512,
    10278, 11039, 11793, 12539, 13279, 14010, 14732, 15446, 16151, 16846, 17530, 18204, 18868,
    19519, 20159, 20787, 21403, 22005, 22594, 23170, 23731, 24279, 24811, 25329, 25832, 26319,
    26790, 27245, 27683, 28105, 28510, 28898, 29268, 29621, 29956, 30273, 30571, 30852, 31113,
    31356, 31580, 31785, 31971, 32137, 32285, 32412, 32521, 32609, 32678, 32728, 32757, 32767,
};

duetos::i32 SinFromQuarter(duetos::u32 idx)
{
    idx &= 255;
    if (idx < 64)
        return kSinQuarter[idx];
    if (idx < 128)
        return kSinQuarter[128 - idx];
    if (idx < 192)
        return -kSinQuarter[idx - 128];
    return -kSinQuarter[256 - idx];
}

inline duetos::u32 Pack(duetos::i32 r, duetos::i32 g, duetos::i32 b)
{
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
    return (static_cast<duetos::u32>(r) << 16) | (static_cast<duetos::u32>(g) << 8) | static_cast<duetos::u32>(b);
}

// HSV-ish palette via three phase-shifted sines. `t` is a 0..255
// position along the hue ring. Used by Plasma + Mandelbrot for
// banded shading.
duetos::u32 PaletteHueQ8(duetos::u32 t)
{
    const duetos::i32 r = (SinFromQuarter(t) >> 8) + 128;
    const duetos::i32 g = (SinFromQuarter(t + 85) >> 8) + 128;
    const duetos::i32 b = (SinFromQuarter(t + 170) >> 8) + 128;
    return Pack(r, g, b);
}

// ---------------------------------------------------------------
// Mode-local state.
// ---------------------------------------------------------------

constexpr duetos::u32 kParticleCount = 64;
struct Particle
{
    duetos::i32 x_q16;
    duetos::i32 y_q16;
    duetos::i32 vx_q16;
    duetos::i32 vy_q16;
    duetos::u32 colour;
    duetos::u8 life; // remaining frames before respawn
    duetos::u8 _pad[3];
};
constinit Particle g_particles[kParticleCount] = {};

constexpr duetos::u32 kStarCount = 96;
struct Star
{
    duetos::i32 x; // -512..512 logical units
    duetos::i32 y; // -512..512 logical units
    duetos::u32 z; // 1..1024, smaller = closer
};
constinit Star g_stars[kStarCount] = {};

// Coarse fire grid — 64 columns x 40 rows, scaled up by integer
// blocks in the renderer. 40 rows is enough that the heat-source
// row at the bottom + a tall plume both fit comfortably in even
// the smallest demo window.
constexpr duetos::u32 kFireCols = 64;
constexpr duetos::u32 kFireRows = 40;
constinit duetos::u8 g_fire[kFireRows * kFireCols] = {};
constinit duetos::u32 g_fire_seed = 0xC001CAFEu;

// Cube — 8 vertices in 16.16, 12 edges as index pairs.
constexpr duetos::i32 kQ16_one = 1 << 16;
constexpr duetos::i32 kCubeVerts[8][3] = {
    {-kQ16_one, -kQ16_one, -kQ16_one}, {kQ16_one, -kQ16_one, -kQ16_one}, {kQ16_one, kQ16_one, -kQ16_one},
    {-kQ16_one, kQ16_one, -kQ16_one},  {-kQ16_one, -kQ16_one, kQ16_one}, {kQ16_one, -kQ16_one, kQ16_one},
    {kQ16_one, kQ16_one, kQ16_one},    {-kQ16_one, kQ16_one, kQ16_one},
};
constexpr duetos::u8 kCubeEdges[12][2] = {
    {0, 1}, {1, 2}, {2, 3}, {3, 0}, // back face
    {4, 5}, {5, 6}, {6, 7}, {7, 4}, // front face
    {0, 4}, {1, 5}, {2, 6}, {3, 7}, // connecting edges
};

} // namespace

// ---------------------------------------------------------------
// Public helpers.
// ---------------------------------------------------------------

duetos::i32 SinQ15(duetos::u32 idx)
{
    return SinFromQuarter(idx);
}

duetos::i32 CosQ15(duetos::u32 idx)
{
    return SinFromQuarter(idx + 64);
}

duetos::i32 FxMul(duetos::i32 a, duetos::i32 b)
{
    const duetos::i64 prod = static_cast<duetos::i64>(a) * static_cast<duetos::i64>(b);
    const duetos::i64 shifted = prod >> 16;
    if (shifted > 0x7FFFFFFFLL)
        return 0x7FFFFFFF;
    if (shifted < -0x7FFFFFFFLL - 1)
        return -0x7FFFFFFF - 1;
    return static_cast<duetos::i32>(shifted);
}

duetos::u32 PrngNext(duetos::u32* state)
{
    duetos::u32 z = (*state += 0x9E3779B9u);
    z = (z ^ (z >> 16)) * 0x85EBCA6Bu;
    z = (z ^ (z >> 13)) * 0xC2B2AE35u;
    z = z ^ (z >> 16);
    return z;
}

duetos::u32 MandelbrotEscape(duetos::i32 cx_q18, duetos::i32 cy_q18, duetos::u32 iter_max)
{
    duetos::i32 zx = 0;
    duetos::i32 zy = 0;
    // Bailout |z|^2 > 4 in Q18: 4 << 36 = 0x4000000000.
    constexpr duetos::i64 kBailQ36 = 4LL << 36;
    for (duetos::u32 i = 0; i < iter_max; ++i)
    {
        const duetos::i64 zx2 = static_cast<duetos::i64>(zx) * static_cast<duetos::i64>(zx);
        const duetos::i64 zy2 = static_cast<duetos::i64>(zy) * static_cast<duetos::i64>(zy);
        if (zx2 + zy2 > kBailQ36)
            return i;
        const duetos::i64 zxy = static_cast<duetos::i64>(zx) * static_cast<duetos::i64>(zy);
        const duetos::i32 new_zx = static_cast<duetos::i32>((zx2 - zy2) >> 18) + cx_q18;
        const duetos::i32 new_zy = static_cast<duetos::i32>((zxy >> 17)) + cy_q18; // 2*zxy >> 18
        zx = new_zx;
        zy = new_zy;
    }
    return iter_max;
}

// ---------------------------------------------------------------
// Reset hooks.
// ---------------------------------------------------------------

void ResetParticles(duetos::u32 seed)
{
    duetos::u32 s = seed ? seed : 0xDEADBEEFu;
    for (duetos::u32 i = 0; i < kParticleCount; ++i)
    {
        const duetos::u32 r1 = PrngNext(&s);
        const duetos::u32 r2 = PrngNext(&s);
        Particle& p = g_particles[i];
        p.x_q16 = static_cast<duetos::i32>((r1 & 0xFFFF) << 8); // 0..255 in Q16
        p.y_q16 = static_cast<duetos::i32>((r2 & 0xFFFF) << 8); // 0..255 in Q16
        p.vx_q16 = static_cast<duetos::i32>((static_cast<duetos::i32>(r1 >> 16) & 0x1FFF) - 0x1000) << 4;
        p.vy_q16 = static_cast<duetos::i32>((static_cast<duetos::i32>(r2 >> 16) & 0x0FFF) - 0x0800) << 4;
        const duetos::u32 hue = (r1 ^ r2) & 0xFF;
        p.colour = PaletteHueQ8(hue);
        p.life = static_cast<duetos::u8>(40 + (r2 & 0x7F));
    }
}

void ResetStarfield(duetos::u32 seed)
{
    duetos::u32 s = seed ? seed : 0xCAFEF00Du;
    for (duetos::u32 i = 0; i < kStarCount; ++i)
    {
        const duetos::u32 r1 = PrngNext(&s);
        const duetos::u32 r2 = PrngNext(&s);
        Star& st = g_stars[i];
        st.x = static_cast<duetos::i32>(r1 & 0x3FF) - 512;
        st.y = static_cast<duetos::i32>(r2 & 0x3FF) - 512;
        st.z = 1 + (r1 >> 10) % 1024;
    }
}

void ResetFire(duetos::u32 seed)
{
    g_fire_seed = seed ? seed : 0xC001CAFEu;
    for (duetos::u32 i = 0; i < kFireRows * kFireCols; ++i)
        g_fire[i] = 0;
}

// ---------------------------------------------------------------
// Renderers.
// ---------------------------------------------------------------

void RenderPlasma(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame)
{
    using duetos::drivers::video::FramebufferPutPixel;
    const duetos::u32 t = frame * 3;
    for (duetos::u32 y = 0; y < ch; ++y)
    {
        const duetos::u32 ya = y + (t >> 1);
        for (duetos::u32 x = 0; x < cw; ++x)
        {
            const duetos::u32 xa = x + t;
            // Four-sin sum; scaled so the result lives in the
            // 0..255 hue ring.
            duetos::i32 v = 0;
            v += SinFromQuarter(xa);
            v += SinFromQuarter(ya);
            v += SinFromQuarter((xa + ya) >> 1);
            v += SinFromQuarter((xa - ya + 256) >> 1);
            // Each SinFromQuarter is +/-32767 so v is +/-131068.
            // Map to 0..255 hue.
            const duetos::u32 hue = static_cast<duetos::u32>((v + 131072) >> 10) & 0xFF;
            FramebufferPutPixel(cx + x, cy + y, PaletteHueQ8(hue));
        }
    }
}

void RenderMandelbrot(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame)
{
    using duetos::drivers::video::FramebufferFillRect;
    if (cw == 0 || ch == 0)
        return;
    // Animated zoom: span shrinks slowly, oscillating around a
    // visually interesting region. Centre is fixed at (-0.7, 0).
    // Span in Q18: starts at 3.0 << 18, breathes ±33%.
    const duetos::i32 base_span = 3 << 18;
    const duetos::i32 osc = (SinQ15(frame * 4) >> 4);                            // ±2048
    const duetos::i32 span_q18 = base_span - (base_span / 4) * (osc / 2048) / 1; // breath
    const duetos::i32 cx0_q18 = -((7 << 18) / 10);                               // -0.7
    const duetos::i32 cy0_q18 = 0;
    // Coarse 4-pixel tiles to keep per-frame iteration count
    // manageable on the 1 Hz draw budget.
    constexpr duetos::u32 kTile = 4;
    const duetos::u32 iter_max = 18;
    for (duetos::u32 ty = 0; ty < ch; ty += kTile)
    {
        for (duetos::u32 tx = 0; tx < cw; tx += kTile)
        {
            // Map tile centre to complex plane.
            const duetos::i64 px = static_cast<duetos::i64>(tx + kTile / 2);
            const duetos::i64 py = static_cast<duetos::i64>(ty + kTile / 2);
            const duetos::i32 c_re = cx0_q18 + static_cast<duetos::i32>((px * span_q18) / cw - span_q18 / 2);
            const duetos::i32 c_im = cy0_q18 + static_cast<duetos::i32>((py * span_q18) / ch - span_q18 / 2);
            const duetos::u32 it = MandelbrotEscape(c_re, c_im, iter_max);
            duetos::u32 colour;
            if (it >= iter_max)
            {
                colour = 0x00000000;
            }
            else
            {
                const duetos::u32 hue = ((it * 14) + frame * 6) & 0xFF;
                colour = PaletteHueQ8(hue);
            }
            const duetos::u32 fw = (tx + kTile <= cw) ? kTile : (cw - tx);
            const duetos::u32 fh = (ty + kTile <= ch) ? kTile : (ch - ty);
            FramebufferFillRect(cx + tx, cy + ty, fw, fh, colour);
        }
    }
}

void RenderCube(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame)
{
    using duetos::drivers::video::FramebufferFillRect;
    using duetos::drivers::video::FramebufferPutPixel;
    if (cw == 0 || ch == 0)
        return;
    // Background — dark blue so wireframe edges read clearly.
    FramebufferFillRect(cx, cy, cw, ch, 0x00080820);

    const duetos::u32 ax = (frame * 5) & 0xFF;
    const duetos::u32 ay = (frame * 3) & 0xFF;
    const duetos::u32 az = (frame * 2) & 0xFF;

    // 16.16 sin/cos. SinQ15 returns Q15 → shift to Q16 by <<1.
    const duetos::i32 sx = SinQ15(ax) << 1;
    const duetos::i32 cxr = CosQ15(ax) << 1;
    const duetos::i32 sy = SinQ15(ay) << 1;
    const duetos::i32 cyr = CosQ15(ay) << 1;
    const duetos::i32 sz = SinQ15(az) << 1;
    const duetos::i32 czr = CosQ15(az) << 1;

    duetos::i32 px[8], py[8];
    bool valid[8];

    const duetos::i32 cam_z = 4 << 16; // 4.0 in Q16
    const duetos::i32 focal = 2 << 16; // 2.0 in Q16
    const duetos::i32 half_w = static_cast<duetos::i32>(cw / 2);
    const duetos::i32 half_h = static_cast<duetos::i32>(ch / 2);
    const duetos::i32 screen_scale = static_cast<duetos::i32>((cw < ch ? cw : ch) / 4);

    for (duetos::u32 i = 0; i < 8; ++i)
    {
        duetos::i32 x = kCubeVerts[i][0];
        duetos::i32 y = kCubeVerts[i][1];
        duetos::i32 z = kCubeVerts[i][2];
        // Rotate around X.
        const duetos::i32 y1 = FxMul(y, cxr) - FxMul(z, sx);
        const duetos::i32 z1 = FxMul(y, sx) + FxMul(z, cxr);
        y = y1;
        z = z1;
        // Rotate around Y.
        const duetos::i32 x2 = FxMul(x, cyr) + FxMul(z, sy);
        const duetos::i32 z2 = -FxMul(x, sy) + FxMul(z, cyr);
        x = x2;
        z = z2;
        // Rotate around Z.
        const duetos::i32 x3 = FxMul(x, czr) - FxMul(y, sz);
        const duetos::i32 y3 = FxMul(x, sz) + FxMul(y, czr);
        x = x3;
        y = y3;
        // Translate into camera space.
        const duetos::i32 zc = z + cam_z;
        if (zc <= (1 << 14))
        {
            valid[i] = false;
            px[i] = py[i] = 0;
            continue;
        }
        // Perspective divide: x' = focal * x / zc.
        const duetos::i64 sx_q16 = (static_cast<duetos::i64>(focal) * x) / zc;
        const duetos::i64 sy_q16 = (static_cast<duetos::i64>(focal) * y) / zc;
        // Scale and offset to screen.
        px[i] = half_w + static_cast<duetos::i32>((sx_q16 * screen_scale) >> 16);
        py[i] = half_h + static_cast<duetos::i32>((sy_q16 * screen_scale) >> 16);
        valid[i] = true;
    }

    auto draw_line = [cx, cy, cw, ch](duetos::i32 x0, duetos::i32 y0, duetos::i32 x1, duetos::i32 y1, duetos::u32 col)
    {
        // Bresenham, clipped to client rect.
        duetos::i32 dx = x1 - x0;
        if (dx < 0)
            dx = -dx;
        duetos::i32 dy = y1 - y0;
        if (dy < 0)
            dy = -dy;
        const duetos::i32 sx_step = (x0 < x1) ? 1 : -1;
        const duetos::i32 sy_step = (y0 < y1) ? 1 : -1;
        duetos::i32 err = dx - dy;
        duetos::i32 x = x0;
        duetos::i32 y = y0;
        const duetos::i32 max_steps = dx + dy + 4; // safety bound
        for (duetos::i32 step = 0; step < max_steps; ++step)
        {
            if (x >= 0 && y >= 0 && static_cast<duetos::u32>(x) < cw && static_cast<duetos::u32>(y) < ch)
                FramebufferPutPixel(cx + static_cast<duetos::u32>(x), cy + static_cast<duetos::u32>(y), col);
            if (x == x1 && y == y1)
                break;
            const duetos::i32 e2 = err << 1;
            if (e2 > -dy)
            {
                err -= dy;
                x += sx_step;
            }
            if (e2 < dx)
            {
                err += dx;
                y += sy_step;
            }
        }
    };

    constexpr duetos::u32 kEdgeCol = 0x0080FFC0;
    for (duetos::u32 e = 0; e < 12; ++e)
    {
        const duetos::u8 a = kCubeEdges[e][0];
        const duetos::u8 b = kCubeEdges[e][1];
        if (!valid[a] || !valid[b])
            continue;
        draw_line(px[a], py[a], px[b], py[b], kEdgeCol);
    }

    // Vertex dots — slightly brighter so corners read clearly.
    for (duetos::u32 i = 0; i < 8; ++i)
    {
        if (!valid[i])
            continue;
        for (duetos::i32 dy = -1; dy <= 1; ++dy)
        {
            for (duetos::i32 dx = -1; dx <= 1; ++dx)
            {
                const duetos::i32 vx = px[i] + dx;
                const duetos::i32 vy = py[i] + dy;
                if (vx >= 0 && vy >= 0 && static_cast<duetos::u32>(vx) < cw && static_cast<duetos::u32>(vy) < ch)
                    FramebufferPutPixel(cx + static_cast<duetos::u32>(vx), cy + static_cast<duetos::u32>(vy),
                                        0x00FFFFFF);
            }
        }
    }
}

void RenderParticles(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame)
{
    using duetos::drivers::video::FramebufferFillRect;
    using duetos::drivers::video::FramebufferPutPixel;
    if (cw == 0 || ch == 0)
        return;
    // Fade-to-black background — a darker rect each frame gives
    // the particles a soft motion-trail look without needing a
    // back buffer.
    FramebufferFillRect(cx, cy, cw, ch, 0x00100808);

    const duetos::i32 width_q16 = static_cast<duetos::i32>(cw) << 16;
    const duetos::i32 height_q16 = static_cast<duetos::i32>(ch) << 16;
    const duetos::i32 gravity_q16 = 0x2000; // 0.125 px/frame²

    duetos::u32 reseed = 0xACE10001u + frame;
    for (duetos::u32 i = 0; i < kParticleCount; ++i)
    {
        Particle& p = g_particles[i];
        // Step.
        p.vy_q16 += gravity_q16;
        p.x_q16 += p.vx_q16;
        p.y_q16 += p.vy_q16;
        // Wall bounce.
        if (p.x_q16 < 0)
        {
            p.x_q16 = -p.x_q16;
            p.vx_q16 = -p.vx_q16;
        }
        else if (p.x_q16 >= width_q16)
        {
            p.x_q16 = (width_q16 << 1) - p.x_q16 - 1;
            p.vx_q16 = -p.vx_q16;
        }
        if (p.y_q16 < 0)
        {
            p.y_q16 = -p.y_q16;
            p.vy_q16 = -p.vy_q16;
        }
        else if (p.y_q16 >= height_q16)
        {
            p.y_q16 = (height_q16 << 1) - p.y_q16 - 1;
            // Lossy bounce so they settle. >>2 keeps half-life
            // small without floats.
            p.vy_q16 = -((p.vy_q16 * 3) >> 2);
            p.vx_q16 = (p.vx_q16 * 7) >> 3;
        }
        // Lifetime.
        if (p.life == 0)
        {
            const duetos::u32 r1 = PrngNext(&reseed);
            const duetos::u32 r2 = PrngNext(&reseed);
            p.x_q16 = static_cast<duetos::i32>((r1 % cw) << 16);
            p.y_q16 = 0;
            p.vx_q16 = (static_cast<duetos::i32>(r1 >> 16) & 0x1FFF) - 0x1000;
            p.vy_q16 = -(static_cast<duetos::i32>(r2 & 0x3FFF));
            p.colour = PaletteHueQ8(r2 & 0xFF);
            p.life = static_cast<duetos::u8>(40 + (r1 & 0x7F));
        }
        else
        {
            --p.life;
        }
        const duetos::i32 ix = p.x_q16 >> 16;
        const duetos::i32 iy = p.y_q16 >> 16;
        if (ix < 0 || iy < 0 || static_cast<duetos::u32>(ix) >= cw || static_cast<duetos::u32>(iy) >= ch)
            continue;
        // Draw a 2x2 dot for visibility.
        for (duetos::i32 dy = 0; dy < 2; ++dy)
        {
            for (duetos::i32 dx = 0; dx < 2; ++dx)
            {
                const duetos::i32 sx = ix + dx;
                const duetos::i32 sy = iy + dy;
                if (sx >= 0 && sy >= 0 && static_cast<duetos::u32>(sx) < cw && static_cast<duetos::u32>(sy) < ch)
                    FramebufferPutPixel(cx + static_cast<duetos::u32>(sx), cy + static_cast<duetos::u32>(sy), p.colour);
            }
        }
    }
}

void RenderStarfield(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame)
{
    using duetos::drivers::video::FramebufferFillRect;
    using duetos::drivers::video::FramebufferPutPixel;
    if (cw == 0 || ch == 0)
        return;
    FramebufferFillRect(cx, cy, cw, ch, 0x00000008);
    const duetos::i32 half_w = static_cast<duetos::i32>(cw / 2);
    const duetos::i32 half_h = static_cast<duetos::i32>(ch / 2);
    const duetos::i32 focal = 192; // arbitrary — tuned visually
    duetos::u32 reseed = 0xBAD1DE5u + frame;
    for (duetos::u32 i = 0; i < kStarCount; ++i)
    {
        Star& st = g_stars[i];
        // March toward camera.
        if (st.z <= 4)
        {
            const duetos::u32 r1 = PrngNext(&reseed);
            const duetos::u32 r2 = PrngNext(&reseed);
            st.x = static_cast<duetos::i32>(r1 & 0x3FF) - 512;
            st.y = static_cast<duetos::i32>(r2 & 0x3FF) - 512;
            st.z = 600 + (r1 >> 10) % 400;
            continue;
        }
        st.z -= 4;
        const duetos::i32 sx = half_w + (st.x * focal) / static_cast<duetos::i32>(st.z);
        const duetos::i32 sy = half_h + (st.y * focal) / static_cast<duetos::i32>(st.z);
        if (sx < 0 || sy < 0 || static_cast<duetos::u32>(sx) >= cw || static_cast<duetos::u32>(sy) >= ch)
            continue;
        // Brighter when closer.
        const duetos::u32 brightness = 255 - (st.z >> 2);
        const duetos::u32 b = brightness > 255 ? 255 : brightness;
        const duetos::u32 col = (b << 16) | (b << 8) | b;
        FramebufferPutPixel(cx + static_cast<duetos::u32>(sx), cy + static_cast<duetos::u32>(sy), col);
        // Streak — one extra pixel toward the centre to suggest
        // motion blur. Cheap, no extra LUT.
        if (st.z < 200)
        {
            const duetos::i32 dx = (sx > half_w) ? -1 : (sx < half_w ? 1 : 0);
            const duetos::i32 dy = (sy > half_h) ? -1 : (sy < half_h ? 1 : 0);
            const duetos::i32 tx = sx + dx;
            const duetos::i32 ty = sy + dy;
            if (tx >= 0 && ty >= 0 && static_cast<duetos::u32>(tx) < cw && static_cast<duetos::u32>(ty) < ch)
                FramebufferPutPixel(cx + static_cast<duetos::u32>(tx), cy + static_cast<duetos::u32>(ty), col);
        }
    }
}

void RenderFire(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame)
{
    using duetos::drivers::video::FramebufferFillRect;
    if (cw == 0 || ch == 0)
        return;
    (void)frame;
    // Seed bottom row with random heat.
    const duetos::u32 last_row = (kFireRows - 1) * kFireCols;
    for (duetos::u32 x = 0; x < kFireCols; ++x)
    {
        const duetos::u32 r = PrngNext(&g_fire_seed);
        g_fire[last_row + x] = static_cast<duetos::u8>((r & 0x3F) ? 200 + (r & 0x3F) : 0);
    }
    // Diffuse upward: each cell averages the three below it minus
    // a small decay. Wraparound at the X edges keeps the plume
    // from collapsing into a corner.
    for (duetos::u32 y = 0; y + 1 < kFireRows; ++y)
    {
        const duetos::u32 row_off = y * kFireCols;
        const duetos::u32 below_off = (y + 1) * kFireCols;
        for (duetos::u32 x = 0; x < kFireCols; ++x)
        {
            const duetos::u32 xl = (x == 0) ? kFireCols - 1 : x - 1;
            const duetos::u32 xr = (x + 1 == kFireCols) ? 0 : x + 1;
            const duetos::u32 sum = static_cast<duetos::u32>(g_fire[below_off + xl]) +
                                    static_cast<duetos::u32>(g_fire[below_off + x]) +
                                    static_cast<duetos::u32>(g_fire[below_off + xr]);
            const duetos::u32 avg = sum / 3;
            const duetos::u32 decay = 2 + (PrngNext(&g_fire_seed) & 3);
            g_fire[row_off + x] = (avg > decay) ? static_cast<duetos::u8>(avg - decay) : 0;
        }
    }
    // Render: each cell maps to a (block_w x block_h) framebuffer
    // rect. Heat -> palette via three colour ramps.
    const duetos::u32 block_w = (cw + kFireCols - 1) / kFireCols;
    const duetos::u32 block_h = (ch + kFireRows - 1) / kFireRows;
    for (duetos::u32 y = 0; y < kFireRows; ++y)
    {
        const duetos::u32 fy = (y * ch) / kFireRows;
        const duetos::u32 row_off = y * kFireCols;
        for (duetos::u32 x = 0; x < kFireCols; ++x)
        {
            const duetos::u32 fx = (x * cw) / kFireCols;
            const duetos::u32 h = g_fire[row_off + x];
            duetos::u32 r, g, b;
            if (h < 64)
            {
                r = h * 4;
                g = 0;
                b = 0;
            }
            else if (h < 160)
            {
                r = 255;
                g = (h - 64) * 2;
                b = 0;
            }
            else
            {
                r = 255;
                g = 200 + ((h - 160) >> 1);
                b = (h - 160) * 2;
            }
            const duetos::u32 col =
                Pack(static_cast<duetos::i32>(r), static_cast<duetos::i32>(g), static_cast<duetos::i32>(b));
            const duetos::u32 fw = (fx + block_w <= cw) ? block_w : (cw - fx);
            const duetos::u32 fh = (fy + block_h <= ch) ? block_h : (ch - fy);
            FramebufferFillRect(cx + fx, cy + fy, fw, fh, col);
        }
    }
}

} // namespace duetos::apps::gfxdemo
