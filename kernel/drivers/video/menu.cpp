#include "drivers/video/menu.h"

#include "drivers/video/framebuffer.h"

namespace duetos::drivers::video
{

namespace
{

constexpr u32 kMaxItems = 8;
constexpr u32 kRowHeight = 22;
constexpr u32 kMenuWidth = 240;
constexpr u32 kPaddingX = 8;
constexpr u32 kTextOffsetY = 7;

constinit MenuItem g_items[kMaxItems] = {};
constinit u32 g_item_count = 0;
constinit u32 g_anchor_x = 0;
constinit u32 g_anchor_y = 0;
constinit u32 g_context = 0;
constinit bool g_open = false;

// Theme-driven chrome palette. Defaults match the original
// hardcoded slate/blue look so a kernel that never calls
// MenuSetColours sees the v0 menu unchanged. ThemeApplyToAll
// rewrites these per-theme.
constinit u32 g_body_rgb = 0x00303848;
constinit u32 g_border_rgb = 0x00101828;
constinit u32 g_ink_rgb = 0x00FFFFFF;
constinit u32 g_accent_rgb = 0x00406090;

u32 PanelHeight()
{
    return g_item_count * kRowHeight + 4; // 2-px border top+bottom
}

} // namespace

void MenuSetColours(u32 body_rgb, u32 border_rgb, u32 ink_rgb, u32 accent_rgb)
{
    g_body_rgb = body_rgb;
    g_border_rgb = border_rgb;
    g_ink_rgb = ink_rgb;
    g_accent_rgb = accent_rgb;
}

void MenuOpen(const MenuItem* items, u32 count, u32 ax, u32 ay, u32 context)
{
    if (items == nullptr || count == 0)
    {
        g_open = false;
        return;
    }
    if (count > kMaxItems)
    {
        count = kMaxItems;
    }
    for (u32 i = 0; i < count; ++i)
    {
        g_items[i] = items[i];
    }
    g_item_count = count;
    g_anchor_x = ax;
    g_anchor_y = ay;
    g_context = context;
    g_open = true;
}

u32 MenuContext()
{
    return g_context;
}

void MenuClose()
{
    g_open = false;
}

bool MenuIsOpen()
{
    return g_open;
}

// Lighten an 0x00RRGGBB colour by `amount` per channel, saturating
// at 0xFF. Inline duplicate of the helper in widget.cpp / taskbar.cpp;
// each TU keeps its own copy so the menu doesn't pull in a tree
// of headers.
namespace
{
u32 LightenRgb(u32 rgb, u32 amount)
{
    u32 r = ((rgb >> 16) & 0xFFU) + amount;
    u32 g = ((rgb >> 8) & 0xFFU) + amount;
    u32 b = (rgb & 0xFFU) + amount;
    if (r > 0xFFU)
        r = 0xFFU;
    if (g > 0xFFU)
        g = 0xFFU;
    if (b > 0xFFU)
        b = 0xFFU;
    return (r << 16) | (g << 8) | b;
}
} // namespace

void MenuRedraw()
{
    if (!g_open || g_item_count == 0)
    {
        return;
    }
    // Anchor is the upper-left corner of the menu panel.
    const u32 h = PanelHeight();

    // Soft drop shadow first so the panel reads as raised over
    // the taskbar / desktop. Same depth + alpha as window chrome
    // for visual consistency.
    FramebufferDropShadow(g_anchor_x, g_anchor_y, kMenuWidth, h, 4, 0x60);

    // Subtle vertical gradient on the body so the menu has the
    // same lifted-from-the-surface feel as the chrome / taskbar.
    // Top is a brighter shade of the body, bottom is the body
    // itself — preserves the theme's chosen body hue.
    FramebufferFillRectGradient(g_anchor_x, g_anchor_y, kMenuWidth, h, LightenRgb(g_body_rgb, 14), g_body_rgb);
    // 1-pixel accent strip down the left edge — a Win10-style
    // "active surface" cue that uses the theme's accent colour.
    FramebufferFillRect(g_anchor_x, g_anchor_y, 2, h, g_accent_rgb);
    // 1-pixel highlight along the very top of the panel inside
    // the border, matching window-chrome's title-bar ridge.
    if (kMenuWidth > 4)
    {
        FramebufferFillRect(g_anchor_x + 2, g_anchor_y + 1, kMenuWidth - 4, 1, LightenRgb(g_body_rgb, 36));
    }
    FramebufferDrawRect(g_anchor_x, g_anchor_y, kMenuWidth, h, g_border_rgb, 1);

    for (u32 i = 0; i < g_item_count; ++i)
    {
        const u32 row_y = g_anchor_y + 2 + i * kRowHeight;
        if (g_items[i].label != nullptr)
        {
            FramebufferDrawString(g_anchor_x + kPaddingX, row_y + kTextOffsetY, g_items[i].label, g_ink_rgb,
                                  g_body_rgb);
        }
        // Thin separator between items — half-strength border ink.
        if (i + 1 < g_item_count)
        {
            FramebufferFillRect(g_anchor_x + 2, row_y + kRowHeight - 1, kMenuWidth - 4, 1,
                                LightenRgb(g_border_rgb, 28));
        }
    }
}

u32 MenuItemAt(u32 x, u32 y)
{
    if (!g_open || g_item_count == 0)
    {
        return 0;
    }
    if (x < g_anchor_x || x >= g_anchor_x + kMenuWidth)
    {
        return 0;
    }
    if (y < g_anchor_y + 2)
    {
        return 0;
    }
    const u32 row = (y - (g_anchor_y + 2)) / kRowHeight;
    if (row >= g_item_count)
    {
        return 0;
    }
    return g_items[row].action_id;
}

u32 MenuPanelHeight()
{
    return PanelHeight();
}

bool MenuContains(u32 x, u32 y)
{
    if (!g_open || g_item_count == 0)
    {
        return false;
    }
    return x >= g_anchor_x && x < g_anchor_x + kMenuWidth && y >= g_anchor_y && y < g_anchor_y + PanelHeight();
}

} // namespace duetos::drivers::video
