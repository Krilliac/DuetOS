#include "drivers/video/menu.h"

#include "drivers/input/ps2kbd.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

namespace
{

// Alias of the public cap (kept local for the brevity of the
// hot-path indices below). Changing the cap goes in menu.h.
constexpr u32 kMaxItems = kMenuMaxItemsPerPanel;
constexpr u32 kRowHeight = 22;
constexpr u32 kMenuWidth = 240;
constexpr u32 kPaddingX = 8;
constexpr u32 kTextOffsetY = 7;
constexpr u32 kChevronInset = 14; // distance from right edge for the submenu '>' glyph

struct Panel
{
    MenuItem items[kMaxItems];
    u32 count;
    u32 anchor_x;
    u32 anchor_y;
    i32 hovered_row; // -1 = none
};

constinit Panel g_panels[kMenuMaxStack] = {};
constinit u32 g_panel_depth = 0; // 0 = closed; otherwise number of open panels
constinit u32 g_context = 0;

// Theme-driven chrome palette. Defaults match the original
// hardcoded slate/blue look so a kernel that never calls
// MenuSetColours sees the menu unchanged.
constinit u32 g_body_rgb = 0x00303848;
constinit u32 g_border_rgb = 0x00101828;
constinit u32 g_ink_rgb = 0x00FFFFFF;
constinit u32 g_accent_rgb = 0x00406090;

u32 PanelHeightFor(u32 count)
{
    return count * kRowHeight + 4; // 2-px border top+bottom
}

// Lighten an 0x00RRGGBB colour by `amount` per channel, saturating
// at 0xFF. Inline duplicate of the helper in widget.cpp / taskbar.cpp;
// each TU keeps its own copy so the menu doesn't pull in a tree
// of headers.
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

// Average two channels, used for the "disabled" greyed text colour.
u32 BlendRgb(u32 a, u32 b)
{
    u32 ar = (a >> 16) & 0xFFU;
    u32 ag = (a >> 8) & 0xFFU;
    u32 ab = a & 0xFFU;
    u32 br = (b >> 16) & 0xFFU;
    u32 bg = (b >> 8) & 0xFFU;
    u32 bb = b & 0xFFU;
    return (((ar + br) >> 1) << 16) | (((ag + bg) >> 1) << 8) | ((ab + bb) >> 1);
}

bool ItemIsActivatable(const MenuItem& m)
{
    if ((m.flags & kMenuItemFlagDisabled) != 0)
        return false;
    if ((m.flags & kMenuItemFlagSeparator) != 0)
        return false;
    if (m.label == nullptr)
        return false;
    return true;
}

i32 PanelAt(u32 x, u32 y)
{
    // Walk from topmost down so deeper panels win on overlap.
    for (i32 i = static_cast<i32>(g_panel_depth) - 1; i >= 0; --i)
    {
        const Panel& p = g_panels[i];
        const u32 h = PanelHeightFor(p.count);
        if (x >= p.anchor_x && x < p.anchor_x + kMenuWidth && y >= p.anchor_y && y < p.anchor_y + h)
            return i;
    }
    return -1;
}

i32 RowInPanel(const Panel& p, u32 y)
{
    if (y < p.anchor_y + 2)
        return -1;
    const u32 row = (y - (p.anchor_y + 2)) / kRowHeight;
    if (row >= p.count)
        return -1;
    return static_cast<i32>(row);
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
        g_panel_depth = 0;
        return;
    }
    if (count > kMaxItems)
        count = kMaxItems;
    Panel& root = g_panels[0];
    for (u32 i = 0; i < count; ++i)
        root.items[i] = items[i];
    root.count = count;
    root.anchor_x = ax;
    root.anchor_y = ay;
    root.hovered_row = -1;
    g_panel_depth = 1;
    g_context = context;
}

void MenuOpenSubmenu(u32 row)
{
    if (g_panel_depth == 0 || g_panel_depth >= kMenuMaxStack)
        return;
    Panel& parent = g_panels[g_panel_depth - 1];
    if (row >= parent.count)
        return;
    const MenuItem& item = parent.items[row];
    if ((item.flags & kMenuItemFlagSubmenu) == 0 || item.submenu == nullptr || item.submenu_count == 0)
        return;

    u32 count = item.submenu_count;
    if (count > kMaxItems)
        count = kMaxItems;

    Panel& child = g_panels[g_panel_depth];
    for (u32 i = 0; i < count; ++i)
        child.items[i] = item.submenu[i];
    child.count = count;
    // Anchor child to the right edge of the parent row, clamped
    // to the framebuffer.
    const FramebufferInfo fb = FramebufferGet();
    u32 cx = parent.anchor_x + kMenuWidth;
    if (fb.width >= kMenuWidth && cx + kMenuWidth > fb.width)
        cx = fb.width - kMenuWidth;
    u32 cy = parent.anchor_y + 2 + row * kRowHeight;
    const u32 child_h = PanelHeightFor(count);
    if (fb.height >= child_h && cy + child_h > fb.height)
        cy = fb.height - child_h;
    child.anchor_x = cx;
    child.anchor_y = cy;
    child.hovered_row = -1;
    ++g_panel_depth;
}

bool MenuPopSubmenu()
{
    if (g_panel_depth <= 1)
        return false;
    --g_panel_depth;
    return true;
}

u32 MenuStackDepth()
{
    return g_panel_depth;
}

u32 MenuContext()
{
    return g_context;
}

void MenuClose()
{
    g_panel_depth = 0;
    g_context = 0;
}

bool MenuIsOpen()
{
    return g_panel_depth > 0;
}

void MenuRedraw()
{
    if (g_panel_depth == 0)
        return;

    const u32 disabled_rgb = BlendRgb(g_ink_rgb, g_body_rgb);
    const u32 separator_rgb = LightenRgb(g_border_rgb, 28);
    const u32 hover_rgb = g_accent_rgb;
    const u32 hover_ink_rgb = 0x00FFFFFF;

    // Paint low-to-high so child panels visually overlay their
    // parents.
    for (u32 pi = 0; pi < g_panel_depth; ++pi)
    {
        const Panel& p = g_panels[pi];
        const u32 h = PanelHeightFor(p.count);

        // Atlas-based panel shadow when the theme supports tactility;
        // FramebufferDropShadow remains the strip-based fallback so
        // tactility=off themes (Amber, HighContrast) + the runtime
        // override stay bit-for-bit identical. Radius 12 is slightly
        // smaller than the active window shadow (24) since menu
        // panels are smaller surfaces — keeps the depth read
        // proportional.
        const u8 atlas_opacity =
            ThemeTactilityEffective() ? ThemeIntensityEffective(ThemeCurrent().shadow_intensity_active) : u8{0};
        if (atlas_opacity > 0)
        {
            RenderSoftShadow(static_cast<i32>(p.anchor_x), static_cast<i32>(p.anchor_y), kMenuWidth, h, 12U,
                             atlas_opacity, 0x00000000U);
        }
        else
        {
            FramebufferDropShadow(p.anchor_x, p.anchor_y, kMenuWidth, h, 4, 0x60);
        }
        FramebufferFillRectGradient(p.anchor_x, p.anchor_y, kMenuWidth, h, LightenRgb(g_body_rgb, 14), g_body_rgb);
        FramebufferFillRect(p.anchor_x, p.anchor_y, 2, h, g_accent_rgb);
        if (kMenuWidth > 4)
        {
            FramebufferFillRect(p.anchor_x + 2, p.anchor_y + 1, kMenuWidth - 4, 1, LightenRgb(g_body_rgb, 36));
        }
        FramebufferDrawRect(p.anchor_x, p.anchor_y, kMenuWidth, h, g_border_rgb, 1);

        for (u32 i = 0; i < p.count; ++i)
        {
            const MenuItem& it = p.items[i];
            const u32 row_y = p.anchor_y + 2 + i * kRowHeight;
            const bool is_separator = (it.flags & kMenuItemFlagSeparator) != 0;
            const bool is_disabled = (it.flags & kMenuItemFlagDisabled) != 0;
            const bool is_checked = (it.flags & kMenuItemFlagChecked) != 0;
            const bool has_submenu = (it.flags & kMenuItemFlagSubmenu) != 0;
            const bool is_hovered =
                !is_separator && !is_disabled && p.hovered_row >= 0 && static_cast<u32>(p.hovered_row) == i;

            if (is_separator)
            {
                // Draw a thin centered line; no body, no text.
                FramebufferFillRect(p.anchor_x + 8, row_y + kRowHeight / 2, kMenuWidth - 16, 1, separator_rgb);
                continue;
            }

            // Hover background: paints the row in the accent colour
            // before the text. Leaves the 2-px left accent stripe.
            if (is_hovered && kMenuWidth > 4)
            {
                FramebufferFillRect(p.anchor_x + 2, row_y, kMenuWidth - 4, kRowHeight, hover_rgb);
            }

            const u32 ink = is_disabled ? disabled_rgb : (is_hovered ? hover_ink_rgb : g_ink_rgb);
            const u32 bg = is_hovered ? hover_rgb : g_body_rgb;

            // Checkmark glyph for radio-style checked items —
            // rendered as a leading '*' so we don't have to ship a
            // new glyph; visible cue beats dictionary purity.
            u32 text_x = p.anchor_x + kPaddingX;
            if (is_checked)
            {
                ChromeTextDraw(ChromeTextRole::Body, text_x, row_y + kTextOffsetY, "*", ink, bg);
                text_x += ChromeTextMeasure(ChromeTextRole::Body, "*");
            }

            if (it.label != nullptr)
            {
                ChromeTextDraw(ChromeTextRole::Body, text_x, row_y + kTextOffsetY, it.label, ink, bg);
            }

            // Submenu chevron in the row's right gutter.
            if (has_submenu && kMenuWidth > kChevronInset)
            {
                ChromeTextDraw(ChromeTextRole::Body, p.anchor_x + kMenuWidth - kChevronInset, row_y + kTextOffsetY, ">",
                               ink, bg);
            }

            // Separator line between rows — half-strength border.
            if (i + 1 < p.count && !((p.items[i + 1].flags & kMenuItemFlagSeparator) != 0))
            {
                FramebufferFillRect(p.anchor_x + 2, row_y + kRowHeight - 1, kMenuWidth - 4, 1, separator_rgb);
            }
        }
    }
}

u32 MenuItemAt(u32 x, u32 y)
{
    if (g_panel_depth == 0)
        return 0;
    const i32 pi = PanelAt(x, y);
    if (pi < 0)
        return 0;
    const Panel& p = g_panels[pi];
    const i32 row = RowInPanel(p, y);
    if (row < 0)
        return 0;
    if (!ItemIsActivatable(p.items[row]))
        return 0;
    // A submenu row clicks open the submenu; it doesn't fire an
    // action_id directly. Caller (mouse reader) checks panel via
    // MenuTrackHoverAt + click-vs-submenu separately if it cares;
    // for now activating a submenu row from MenuItemAt opens the
    // child panel and returns 0 so the dispatcher does nothing.
    if ((p.items[row].flags & kMenuItemFlagSubmenu) != 0)
    {
        // Only auto-open if this is the topmost panel (clicking on
        // a deeper row should retreat first; but v0 is tolerant).
        if (static_cast<u32>(pi) == g_panel_depth - 1)
            MenuOpenSubmenu(static_cast<u32>(row));
        return 0;
    }
    return p.items[row].action_id;
}

bool MenuContains(u32 x, u32 y)
{
    if (g_panel_depth == 0)
        return false;
    return PanelAt(x, y) >= 0;
}

// Fold the whole open stack's highlight state into one value.
// Any change here means the menu paints a different row somewhere,
// so the caller must recompose; an unchanged value means the
// motion was visually inert for the menu. depth is included so an
// open/close of a submenu also counts as a change.
// File-local: internal linkage (the TU's other helpers live in the
// anonymous namespace above, which closed before the public API
// block; `static` keeps this symbol from leaking the same way).
static u64 HoverSignature()
{
    u64 sig = g_panel_depth;
    for (u32 i = 0; i < kMenuMaxStack; ++i)
    {
        // +1 so the -1 "no hover" sentinel stays distinct from row 0.
        sig = (sig << 8) | static_cast<u8>(g_panels[i].hovered_row + 1);
    }
    return sig;
}

bool MenuTrackHoverAt(u32 x, u32 y)
{
    if (g_panel_depth == 0)
        return false;
    const u64 before = HoverSignature();
    const i32 pi = PanelAt(x, y);
    if (pi < 0)
    {
        // Cursor outside every panel: clear hover on topmost.
        g_panels[g_panel_depth - 1].hovered_row = -1;
    }
    else
    {
        Panel& p = g_panels[pi];
        const i32 row = RowInPanel(p, y);
        // Clear hover for a miss or a non-activatable (separator /
        // disabled) row; otherwise land the hover on `row`.
        p.hovered_row = (row < 0 || !ItemIsActivatable(p.items[row])) ? -1 : row;
    }
    return HoverSignature() != before;
}

void MenuSetHover(i32 panel, i32 row)
{
    if (g_panel_depth == 0)
        return;
    if (panel < 0)
    {
        g_panels[g_panel_depth - 1].hovered_row = -1;
        return;
    }
    if (static_cast<u32>(panel) >= g_panel_depth)
        return;
    g_panels[panel].hovered_row = row;
}

void MenuMoveHover(int dy)
{
    if (g_panel_depth == 0)
        return;
    Panel& p = g_panels[g_panel_depth - 1];
    if (p.count == 0)
        return;
    const int n = static_cast<int>(p.count);
    int row = p.hovered_row;
    if (row < 0)
        row = (dy >= 0) ? -1 : n; // first step lands on first/last item
    // Try up to n steps to find a non-separator, non-disabled row.
    for (int step = 0; step < n; ++step)
    {
        row = (row + dy) % n;
        if (row < 0)
            row += n;
        if (ItemIsActivatable(p.items[row]))
        {
            p.hovered_row = row;
            return;
        }
    }
    // No activatable rows; leave hover as-is.
}

u32 MenuActivateHover()
{
    if (g_panel_depth == 0)
        return 0;
    Panel& p = g_panels[g_panel_depth - 1];
    if (p.hovered_row < 0)
        return 0;
    const u32 row = static_cast<u32>(p.hovered_row);
    if (row >= p.count)
        return 0;
    const MenuItem& it = p.items[row];
    if (!ItemIsActivatable(it))
        return 0;
    if ((it.flags & kMenuItemFlagSubmenu) != 0)
    {
        MenuOpenSubmenu(row);
        return 0;
    }
    return it.action_id;
}

u32 MenuFeedKey(u16 key_code)
{
    if (g_panel_depth == 0)
        return 0;
    using duetos::drivers::input::kKeyArrowDown;
    using duetos::drivers::input::kKeyArrowLeft;
    using duetos::drivers::input::kKeyArrowRight;
    using duetos::drivers::input::kKeyArrowUp;
    using duetos::drivers::input::kKeyEnter;
    using duetos::drivers::input::kKeyEsc;
    switch (key_code)
    {
    case kKeyArrowDown:
        MenuMoveHover(1);
        return 0;
    case kKeyArrowUp:
        MenuMoveHover(-1);
        return 0;
    case kKeyArrowRight:
    {
        Panel& p = g_panels[g_panel_depth - 1];
        if (p.hovered_row >= 0 && static_cast<u32>(p.hovered_row) < p.count &&
            (p.items[p.hovered_row].flags & kMenuItemFlagSubmenu) != 0)
        {
            MenuOpenSubmenu(static_cast<u32>(p.hovered_row));
        }
        return 0;
    }
    case kKeyArrowLeft:
        if (!MenuPopSubmenu())
            MenuClose();
        return 0;
    case kKeyEsc:
        MenuClose();
        return 0;
    case kKeyEnter:
        return MenuActivateHover();
    default:
        return 0;
    }
}

u32 MenuPanelHeight()
{
    if (g_panel_depth == 0)
        return 0;
    return PanelHeightFor(g_panels[g_panel_depth - 1].count);
}

} // namespace duetos::drivers::video
