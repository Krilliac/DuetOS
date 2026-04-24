#include "cursor.h"

#include "framebuffer.h"

namespace customos::drivers::video
{

namespace
{

// Shaped-mask arrow sprite. 12 columns x 20 rows; '#' = opaque
// white, '.' = opaque black (outline), ' ' = transparent (the
// background pixel shows through). Classic NW-pointing arrow
// silhouette — the shape every Windows / X11 / macOS cursor
// converges on.
constexpr u32 kCursorWidth = 12;
constexpr u32 kCursorHeight = 20;

// Pixel kinds. Packed 2 bits per pixel would save space but the
// full byte-per-pixel form survives easy editing — 240 bytes of
// .rodata isn't worth compressing.
enum : u8
{
    kPxTransparent = 0,
    kPxOutline = 1, // drawn as black
    kPxFill = 2,    // drawn as white
};

// clang-format off
constinit const u8 kCursorMask[kCursorHeight][kCursorWidth] = {
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // row 0  #
    {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, //        ##
    {1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, //        #.#
    {1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0}, //        #..#
    {1, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0},
    {1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0},
    {1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0}, // widest
    {1, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1}, // elbow — tail starts
    {1, 2, 2, 2, 1, 2, 2, 1, 0, 0, 0, 0},
    {1, 2, 2, 1, 1, 2, 2, 1, 0, 0, 0, 0},
    {1, 2, 1, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {1, 1, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0},
    {1, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};
// clang-format on

constexpr u32 kColourOutline = 0x00000000;
constexpr u32 kColourFill = 0x00FFFFFF;

constinit u32 g_x = 0;
constinit u32 g_y = 0;
constinit u32 g_desktop_rgb = 0;
constinit bool g_ready = false;

// Per-pixel save/restore buffer. The cursor can land on top of any
// pixels (desktop fill today, widgets tomorrow), so "erase by
// painting the desktop colour" stops working the moment something
// non-desktop is under the cursor. Keeping 12x20 = 240 u32s in
// .bss costs nothing and makes the cursor work correctly over any
// future painted content.
constinit u32 g_backing[kCursorHeight][kCursorWidth] = {};
constinit bool g_backing_valid = false;

// Clamp a signed addition of `delta` to `value` into [0, max).
// Required because mouse dx / dy can be much larger than the
// screen (rapid flick) or negative past the origin (cursor at
// x=0, move left).
u32 ClampMove(u32 value, i32 delta, u32 max)
{
    const i64 sum = static_cast<i64>(value) + delta;
    if (sum < 0)
    {
        return 0;
    }
    if (static_cast<u64>(sum) >= max)
    {
        return (max == 0) ? 0 : max - 1;
    }
    return static_cast<u32>(sum);
}

u32 FramebufferReadPixel(u32 x, u32 y)
{
    const auto info = FramebufferGet();
    if (info.virt == nullptr || x >= info.width || y >= info.height)
    {
        return g_desktop_rgb;
    }
    const auto* row =
        reinterpret_cast<const volatile u32*>(reinterpret_cast<const u8*>(info.virt) + static_cast<u64>(y) * info.pitch);
    return row[x];
}

// Save every pixel the cursor sprite covers so a later RestoreAt
// can put them back exactly — even if a widget painted under the
// cursor between move events. Only samples pixels the mask will
// actually overwrite; fully-transparent pixels are skipped.
void SaveAt(u32 x, u32 y)
{
    for (u32 yi = 0; yi < kCursorHeight; ++yi)
    {
        for (u32 xi = 0; xi < kCursorWidth; ++xi)
        {
            if (kCursorMask[yi][xi] == kPxTransparent)
            {
                continue;
            }
            g_backing[yi][xi] = FramebufferReadPixel(x + xi, y + yi);
        }
    }
    g_backing_valid = true;
}

void RestoreAt(u32 x, u32 y)
{
    if (!g_backing_valid)
    {
        return;
    }
    for (u32 yi = 0; yi < kCursorHeight; ++yi)
    {
        for (u32 xi = 0; xi < kCursorWidth; ++xi)
        {
            if (kCursorMask[yi][xi] == kPxTransparent)
            {
                continue;
            }
            FramebufferPutPixel(x + xi, y + yi, g_backing[yi][xi]);
        }
    }
}

void DrawAt(u32 x, u32 y)
{
    for (u32 yi = 0; yi < kCursorHeight; ++yi)
    {
        for (u32 xi = 0; xi < kCursorWidth; ++xi)
        {
            const u8 kind = kCursorMask[yi][xi];
            if (kind == kPxTransparent)
            {
                continue;
            }
            const u32 rgb = (kind == kPxOutline) ? kColourOutline : kColourFill;
            FramebufferPutPixel(x + xi, y + yi, rgb);
        }
    }
}

} // namespace

void CursorInit(u32 desktop_rgb)
{
    if (!FramebufferAvailable())
    {
        return;
    }
    const auto info = FramebufferGet();

    // Remember desktop colour for any later "restore under cursor"
    // that falls back to a flat fill (widget-less regions). Do NOT
    // clear the framebuffer here — callers may already have painted
    // desktop chrome + widgets before invoking this, and we must
    // render on top rather than wipe.
    g_desktop_rgb = desktop_rgb;

    // Centre the cursor. Guard against a framebuffer smaller than
    // the cursor sprite — clamp the starting position so the draw
    // still fits, even if only one row/column is visible.
    const u32 cx = (info.width > kCursorWidth) ? (info.width - kCursorWidth) / 2 : 0;
    const u32 cy = (info.height > kCursorHeight) ? (info.height - kCursorHeight) / 2 : 0;
    g_x = cx;
    g_y = cy;

    SaveAt(g_x, g_y);
    DrawAt(g_x, g_y);
    g_ready = true;
}

void CursorMove(i32 dx, i32 dy)
{
    if (!g_ready)
    {
        return;
    }
    const auto info = FramebufferGet();
    const u32 x_max = (info.width > kCursorWidth) ? info.width - kCursorWidth : 1;
    const u32 y_max = (info.height > kCursorHeight) ? info.height - kCursorHeight : 1;

    const u32 new_x = ClampMove(g_x, dx, x_max);
    const u32 new_y = ClampMove(g_y, dy, y_max);
    if (new_x == g_x && new_y == g_y)
    {
        return;
    }
    RestoreAt(g_x, g_y);
    g_x = new_x;
    g_y = new_y;
    SaveAt(g_x, g_y);
    DrawAt(g_x, g_y);
}

void CursorPosition(u32* x_out, u32* y_out)
{
    if (x_out != nullptr)
    {
        *x_out = g_x;
    }
    if (y_out != nullptr)
    {
        *y_out = g_y;
    }
}

void CursorHide()
{
    if (!g_ready)
    {
        return;
    }
    RestoreAt(g_x, g_y);
    g_ready = false;
    // Leave backing_valid true — it's just stale, but the next
    // SaveAt from CursorShow replaces it before it's read.
}

void CursorShow()
{
    if (g_ready)
    {
        return; // already visible
    }
    if (!FramebufferAvailable())
    {
        return;
    }
    SaveAt(g_x, g_y);
    DrawAt(g_x, g_y);
    g_ready = true;
}

void CursorSetDesktopBackground(u32 rgb)
{
    g_desktop_rgb = rgb;
}

} // namespace customos::drivers::video
