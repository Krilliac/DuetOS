#include "drivers/video/magnifier.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

namespace
{

constinit bool g_active = false;

// Inset geometry. 200×150 output → 100×75 source at 2× zoom.
constexpr u32 kInsetW = 200;
constexpr u32 kInsetH = 150;
constexpr u32 kSrcW = kInsetW / 2;
constexpr u32 kSrcH = kInsetH / 2;
constexpr u32 kInsetMargin = 12;
constexpr u32 kBorderThick = 2;

} // namespace

bool MagnifierToggle()
{
    g_active = !g_active;
    return g_active;
}

bool MagnifierIsActive()
{
    return g_active;
}

void MagnifierRedraw()
{
    if (!g_active)
    {
        return;
    }
    const auto fb = FramebufferGet();
    if (fb.virt == nullptr || fb.width < kInsetW + 2 * kInsetMargin || fb.height < kInsetH + 2 * kInsetMargin)
    {
        return;
    }

    u32 cx = 0, cy = 0;
    CursorPosition(&cx, &cy);

    // Source region centered on the cursor, clipped to the
    // framebuffer. If the cursor is near an edge, the source
    // window slides so the magnifier still shows kSrcW × kSrcH
    // pixels — matches macOS / Windows magnifier behaviour at
    // edges (no truncated zoom).
    i32 sx0 = static_cast<i32>(cx) - static_cast<i32>(kSrcW / 2);
    i32 sy0 = static_cast<i32>(cy) - static_cast<i32>(kSrcH / 2);
    if (sx0 < 0)
    {
        sx0 = 0;
    }
    if (sy0 < 0)
    {
        sy0 = 0;
    }
    if (static_cast<u32>(sx0) + kSrcW > fb.width)
    {
        sx0 = static_cast<i32>(fb.width - kSrcW);
    }
    if (static_cast<u32>(sy0) + kSrcH > fb.height)
    {
        sy0 = static_cast<i32>(fb.height - kSrcH);
    }

    // Inset position: top-right with a margin. Avoid overlapping
    // the source region — when the cursor is in the top-right
    // quadrant, drop the inset to the bottom-right instead.
    const bool cursor_in_topright = (cx > fb.width / 2) && (cy < fb.height / 2);
    const u32 inset_x = fb.width - kInsetW - kInsetMargin;
    const u32 inset_y = cursor_in_topright ? (fb.height - kInsetH - kInsetMargin) : kInsetMargin;

    // Border + clear so we don't bleed into adjacent chrome.
    const auto& th = ThemeCurrent();
    FramebufferDrawRect(inset_x - kBorderThick, inset_y - kBorderThick, kInsetW + 2 * kBorderThick,
                        kInsetH + 2 * kBorderThick, th.window_border, kBorderThick);

    // 2x nearest-neighbour blit. Each source pixel becomes a 2x2
    // block. We read directly from fb.virt to avoid accumulating
    // round-trips through FramebufferPutPixel.
    const u8* src_base = static_cast<const u8*>(fb.virt);
    // FramebufferInfo.bpp is bits-per-pixel; we only support 32-bit.
    constexpr u32 bpp = 4;
    if (fb.bpp != 32)
    {
        // Non-32bpp framebuffers exist (15/16bpp on some VBE
        // modes). v0 magnifier supports the canonical 32bpp path
        // only — bail with a coloured corner so the failure is
        // visible without panicking.
        FramebufferFillRect(inset_x, inset_y, kInsetW, kInsetH, 0x00FF00FF);
        return;
    }
    for (u32 sy = 0; sy < kSrcH; ++sy)
    {
        const u32 src_y = static_cast<u32>(sy0) + sy;
        const u8* row = src_base + src_y * fb.pitch + static_cast<u32>(sx0) * bpp;
        for (u32 sx = 0; sx < kSrcW; ++sx)
        {
            const u32 px = *reinterpret_cast<const u32*>(row + sx * bpp);
            // Paint a 2×2 block. Inline puts to dodge the per-pixel
            // dispatch overhead of FramebufferPutPixel on the inner
            // loop's ~30k iterations per frame.
            const u32 dx = inset_x + sx * 2;
            const u32 dy = inset_y + sy * 2;
            FramebufferPutPixel(dx, dy, px);
            FramebufferPutPixel(dx + 1, dy, px);
            FramebufferPutPixel(dx, dy + 1, px);
            FramebufferPutPixel(dx + 1, dy + 1, px);
        }
    }
}

void MagnifierSelfTest()
{
    using duetos::arch::SerialWrite;
    bool ok = true;
    const bool save = g_active;

    g_active = false;
    ok = ok && !MagnifierIsActive();

    const bool t1 = MagnifierToggle();
    ok = ok && t1;
    ok = ok && MagnifierIsActive();

    const bool t2 = MagnifierToggle();
    ok = ok && !t2;
    ok = ok && !MagnifierIsActive();

    g_active = save;
    SerialWrite(ok ? "[magnifier] self-test OK\n" : "[magnifier] self-test FAILED\n");
}

} // namespace duetos::drivers::video
