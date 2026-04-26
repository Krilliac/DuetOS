#include "gfxdemo.h"
#include "gfxdemo_modes.h"

#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../drivers/video/framebuffer.h"

namespace duetos::apps::gfxdemo
{

namespace
{

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;
constinit Mode g_mode = Mode::Plasma;
constinit duetos::u32 g_frame = 0;
constinit duetos::u32 g_seed = 0x12345678u;
constinit bool g_auto_cycle = true;
constinit duetos::u32 g_mode_frames = 0;
// Auto-cycle period: 12 frames at the 1 Hz ui-ticker == 12 s per
// effect. Long enough to read each one before the next snaps in.
constexpr duetos::u32 kAutoCyclePeriod = 12;

const char* ModeName(Mode m)
{
    switch (m)
    {
    case Mode::Plasma:
        return "PLASMA";
    case Mode::Mandelbrot:
        return "MANDELBROT";
    case Mode::Cube:
        return "WIRECUBE";
    case Mode::Particles:
        return "PARTICLES";
    case Mode::Starfield:
        return "STARFIELD";
    case Mode::Fire:
        return "FIRE";
    case Mode::Count:
    default:
        return "?";
    }
}

void ResetAllModeState()
{
    ResetParticles(g_seed ^ 0xA1A1A1A1u);
    ResetStarfield(g_seed ^ 0xB2B2B2B2u);
    ResetFire(g_seed ^ 0xC3C3C3C3u);
}

void DispatchRender(Mode m, duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame)
{
    switch (m)
    {
    case Mode::Plasma:
        RenderPlasma(cx, cy, cw, ch, frame);
        break;
    case Mode::Mandelbrot:
        RenderMandelbrot(cx, cy, cw, ch, frame);
        break;
    case Mode::Cube:
        RenderCube(cx, cy, cw, ch, frame);
        break;
    case Mode::Particles:
        RenderParticles(cx, cy, cw, ch, frame);
        break;
    case Mode::Starfield:
        RenderStarfield(cx, cy, cw, ch, frame);
        break;
    case Mode::Fire:
        RenderFire(cx, cy, cw, ch, frame);
        break;
    case Mode::Count:
        break;
    }
}

// Format a u32 as zero-padded decimal of the given width into
// `out` (which must hold width + 1 bytes for the NUL).
void FmtU32Pad(duetos::u32 v, char* out, duetos::u32 width)
{
    for (duetos::u32 i = 0; i < width; ++i)
        out[width - 1 - i] = static_cast<char>('0' + (v % 10)), v /= 10;
    out[width] = '\0';
}

// Append `src` (NUL-terminated) into `dst` starting at offset
// `*pos`, bounded by `cap` (size including final NUL). Updates
// `*pos`. Truncates silently if needed.
void StrAppend(char* dst, duetos::u32 cap, duetos::u32* pos, const char* src)
{
    while (*src != '\0' && *pos + 1 < cap)
    {
        dst[(*pos)++] = *src++;
    }
    dst[*pos] = '\0';
}

void DrawHud(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    if (cw < 80 || ch < 24)
        return;

    constexpr duetos::u32 kStripH = 11;
    constexpr duetos::u32 kBg = 0x00000000;
    constexpr duetos::u32 kFg = 0x00FFFFFF;

    // Top strip: mode name + indicator.
    char top[64];
    duetos::u32 pos = 0;
    StrAppend(top, sizeof(top), &pos, "MODE ");
    char num[2] = {static_cast<char>('0' + static_cast<duetos::u32>(g_mode)), '\0'};
    StrAppend(top, sizeof(top), &pos, num);
    StrAppend(top, sizeof(top), &pos, "/");
    char count[2] = {static_cast<char>('0' + static_cast<duetos::u32>(Mode::Count) - 1), '\0'};
    (void)count;
    StrAppend(top, sizeof(top), &pos, "5 ");
    StrAppend(top, sizeof(top), &pos, ModeName(g_mode));
    if (g_auto_cycle)
        StrAppend(top, sizeof(top), &pos, " [AUTO]");
    else
        StrAppend(top, sizeof(top), &pos, " [HOLD]");
    duetos::u32 top_w = pos * 8;
    if (top_w + 12 > cw)
        top_w = (cw > 12) ? cw - 12 : cw;
    FramebufferFillRect(cx + 4, cy + 2, top_w + 8, kStripH, kBg);
    FramebufferDrawString(cx + 8, cy + 3, top, kFg, kBg);

    // Bottom strip: frame counter + uptime.
    char bot[64];
    pos = 0;
    StrAppend(bot, sizeof(bot), &pos, "F:");
    char fbuf[8];
    FmtU32Pad(g_frame % 100000, fbuf, 5);
    StrAppend(bot, sizeof(bot), &pos, fbuf);
    StrAppend(bot, sizeof(bot), &pos, "  T:");
    const duetos::u64 ticks_now = duetos::arch::TimerTicks();
    // 100 Hz scheduler tick → seconds = ticks / 100.
    const duetos::u64 secs = ticks_now / 100;
    char sbuf[8];
    FmtU32Pad(static_cast<duetos::u32>(secs % 100000), sbuf, 5);
    StrAppend(bot, sizeof(bot), &pos, sbuf);
    StrAppend(bot, sizeof(bot), &pos, "S  KEYS:0-5,N,P,A,R");
    duetos::u32 bot_w = pos * 8;
    if (bot_w + 12 > cw)
        bot_w = (cw > 12) ? cw - 12 : cw;
    const duetos::u32 bot_y = (ch >= kStripH + 4) ? cy + ch - kStripH - 2 : cy + ch - kStripH;
    FramebufferFillRect(cx + 4, bot_y, bot_w + 8, kStripH, kBg);
    FramebufferDrawString(cx + 8, bot_y + 1, bot, kFg, kBg);
}

void DrawFn(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, void*)
{
    if (cw == 0 || ch == 0)
        return;

    DispatchRender(g_mode, cx, cy, cw, ch, g_frame);
    DrawHud(cx, cy, cw, ch);

    ++g_frame;
    if (g_auto_cycle)
    {
        ++g_mode_frames;
        if (g_mode_frames >= kAutoCyclePeriod)
        {
            g_mode_frames = 0;
            const duetos::u32 next = (static_cast<duetos::u32>(g_mode) + 1) % static_cast<duetos::u32>(Mode::Count);
            g_mode = static_cast<Mode>(next);
        }
    }
}

} // namespace

void GfxDemoInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    g_mode = Mode::Plasma;
    g_frame = 0;
    g_mode_frames = 0;
    g_auto_cycle = true;
    g_seed = 0x12345678u;
    ResetAllModeState();
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle GfxDemoWindow()
{
    return g_handle;
}

bool GfxDemoFeedChar(char c)
{
    if (c >= '0' && c < '0' + static_cast<int>(Mode::Count))
    {
        g_mode = static_cast<Mode>(static_cast<duetos::u32>(c - '0'));
        g_mode_frames = 0;
        return true;
    }
    if (c == 'n' || c == 'N' || c == ' ')
    {
        const duetos::u32 next = (static_cast<duetos::u32>(g_mode) + 1) % static_cast<duetos::u32>(Mode::Count);
        g_mode = static_cast<Mode>(next);
        g_mode_frames = 0;
        return true;
    }
    if (c == 'p' || c == 'P')
    {
        const duetos::u32 cur = static_cast<duetos::u32>(g_mode);
        const duetos::u32 prev = (cur == 0) ? static_cast<duetos::u32>(Mode::Count) - 1 : cur - 1;
        g_mode = static_cast<Mode>(prev);
        g_mode_frames = 0;
        return true;
    }
    if (c == 'a' || c == 'A')
    {
        g_auto_cycle = !g_auto_cycle;
        g_mode_frames = 0;
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        // Mix the frame counter into the new seed so successive
        // resets land on different layouts.
        g_seed = (g_seed * 1664525u + 1013904223u) ^ g_frame;
        ResetAllModeState();
        return true;
    }
    return false;
}

void GfxDemoSelfTest()
{
    using duetos::arch::SerialWrite;
    bool pass = true;

    // Sin LUT spot checks: SinQ15(0) == 0, SinQ15(64) == 32767,
    // SinQ15(128) == 0, SinQ15(192) == -32767.
    if (SinQ15(0) != 0)
        pass = false;
    if (SinQ15(64) != 32767)
        pass = false;
    if (SinQ15(128) != 0)
        pass = false;
    if (SinQ15(192) != -32767)
        pass = false;
    // Cos shift: CosQ15(0) == 32767, CosQ15(64) == 0.
    if (CosQ15(0) != 32767)
        pass = false;
    if (CosQ15(64) != 0)
        pass = false;
    // Wraparound symmetry.
    if (SinQ15(256) != SinQ15(0))
        pass = false;
    if (SinQ15(257) != SinQ15(1))
        pass = false;

    // FxMul: 1.0 (0x10000) * 1.0 == 1.0.
    if (FxMul(0x10000, 0x10000) != 0x10000)
        pass = false;
    // 0.5 * 0.5 == 0.25.
    if (FxMul(0x8000, 0x8000) != 0x4000)
        pass = false;
    // -1.0 * 1.0 == -1.0.
    if (FxMul(-0x10000, 0x10000) != -0x10000)
        pass = false;

    // PRNG determinism: same seed → same first sample.
    {
        duetos::u32 s1 = 1234;
        duetos::u32 s2 = 1234;
        if (PrngNext(&s1) != PrngNext(&s2))
            pass = false;
        // Different seed → different sample (high-probability check).
        duetos::u32 s3 = 1235;
        if (PrngNext(&s2) == PrngNext(&s3))
            pass = false;
    }

    // Mandelbrot escape — origin (0, 0) stays bounded for
    // arbitrary iter_max. Point (1.0, 0.0) escapes very quickly.
    if (MandelbrotEscape(0, 0, 32) != 32)
        pass = false;
    if (MandelbrotEscape(1 << 18, 0, 32) >= 4)
        pass = false;
    // (-1, 0) is in the period-2 bulb — bounded.
    if (MandelbrotEscape(-(1 << 18), 0, 32) != 32)
        pass = false;

    SerialWrite(pass ? "[gfxdemo] self-test OK (sin LUT, FxMul, PRNG, Mandelbrot)\n" : "[gfxdemo] self-test FAILED\n");
}

} // namespace duetos::apps::gfxdemo
