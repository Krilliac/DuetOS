#include "cursor.h"

#include "framebuffer.h"

namespace customos::drivers::video
{

namespace
{

// Cursor sprite — a solid rectangle in v0. Size tuned so the sprite
// is visible at 1024x768 without dominating the screen; 12x20 is
// roughly the ratio of a classic arrow cursor.
constexpr u32 kCursorWidth = 12;
constexpr u32 kCursorHeight = 20;

// Bright cyan/white — high-contrast against both the dark-teal
// default desktop and any future window chrome. The inverse of
// typical Windows cursor, but the point is visibility at boot.
constexpr u32 kCursorColour = 0x00FFFFFF;

constinit u32 g_x = 0;
constinit u32 g_y = 0;
constinit u32 g_desktop_rgb = 0;
constinit bool g_ready = false;

void EraseAt(u32 x, u32 y)
{
    FramebufferFillRect(x, y, kCursorWidth, kCursorHeight, g_desktop_rgb);
}

void DrawAt(u32 x, u32 y)
{
    // A simple arrow-ish silhouette inside the bounding box. Top-
    // left triangle filled, with a two-pixel border. Cheap to
    // render, visibly cursor-shaped at a glance without needing
    // a mask.
    for (u32 yi = 0; yi < kCursorHeight; ++yi)
    {
        // Row `yi` has `width - (yi * width / height)` pixels of
        // cursor fill, counted from the left. Gives a diagonal
        // right-edge that slopes from (width, 0) at the top to
        // (0, height) at the bottom — the classic NW-pointing
        // arrow-ish shape without a proper bitmap mask.
        const u32 fill = kCursorWidth - (yi * kCursorWidth) / kCursorHeight;
        FramebufferFillRect(x, y + yi, fill, 1, kCursorColour);
    }
}

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

} // namespace

void CursorInit(u32 desktop_rgb)
{
    if (!FramebufferAvailable())
    {
        return;
    }
    const auto info = FramebufferGet();

    g_desktop_rgb = desktop_rgb;
    FramebufferClear(desktop_rgb);

    // Centre the cursor. Guard against a framebuffer smaller than
    // the cursor sprite — clamp the starting position so the draw
    // still fits, even if only one row/column is visible.
    const u32 cx = (info.width > kCursorWidth) ? (info.width - kCursorWidth) / 2 : 0;
    const u32 cy = (info.height > kCursorHeight) ? (info.height - kCursorHeight) / 2 : 0;
    g_x = cx;
    g_y = cy;

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
    EraseAt(g_x, g_y);
    g_x = new_x;
    g_y = new_y;
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

} // namespace customos::drivers::video
