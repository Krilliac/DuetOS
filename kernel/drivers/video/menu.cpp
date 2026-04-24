#include "menu.h"

#include "framebuffer.h"

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

u32 PanelHeight()
{
    return g_item_count * kRowHeight + 4; // 2-px border top+bottom
}

} // namespace

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

void MenuRedraw()
{
    if (!g_open || g_item_count == 0)
    {
        return;
    }
    // Anchor is the upper-left corner of the menu panel.
    const u32 h = PanelHeight();
    // Darker body fill than the taskbar, with a dark outline
    // for definition. Text renders over the body.
    const u32 body_rgb = 0x00303848;
    const u32 border_rgb = 0x00101828;
    const u32 item_text = 0x00FFFFFF;

    FramebufferFillRect(g_anchor_x, g_anchor_y, kMenuWidth, h, body_rgb);
    FramebufferDrawRect(g_anchor_x, g_anchor_y, kMenuWidth, h, border_rgb, 2);

    for (u32 i = 0; i < g_item_count; ++i)
    {
        const u32 row_y = g_anchor_y + 2 + i * kRowHeight;
        if (g_items[i].label != nullptr)
        {
            FramebufferDrawString(g_anchor_x + kPaddingX, row_y + kTextOffsetY, g_items[i].label, item_text, body_rgb);
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
