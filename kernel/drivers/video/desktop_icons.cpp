#include "drivers/video/desktop_icons.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

namespace
{

struct Icon
{
    const char* label;
    IconGlyph glyph;
    WindowHandle target;
};

// Fixed capacity — the grid wraps into extra columns, so this is the only
// ceiling on how many destinations the desktop can surface.
constexpr u32 kMaxIcons = 16;
Icon g_icons[kMaxIcons] = {};
u32 g_icon_count = 0;
int g_hover = -1; // index of the hovered icon, or -1

// Grid layout. Icons fill the left column top-to-bottom, then wrap into
// the next column once they'd reach the taskbar.
constexpr u32 kTopY = 24;
constexpr u32 kColX0 = 20;
constexpr u32 kColStride = 96;
constexpr u32 kRowPitch = 92;
constexpr u32 kCellW = 84;
constexpr u32 kCellH = 84;
constexpr u32 kTileW = 56;
constexpr u32 kTileH = 56;
constexpr u32 kBottomReserve = 52;

// 0x00RRGGBB, matching the rest of the chrome.
constexpr u32 kWhite = 0x00FFFFFFu;
constexpr u32 kDark = 0x001A222Cu; // screens / recesses inside a glyph
constexpr u32 kTileBorder = 0x00101418u;
constexpr u32 kLabelChip = 0x00141A20u;
constexpr u32 kTermGreen = 0x0050E060u;
constexpr u32 kPaperRed = 0x00C04848u;

void IconCell(u32 index, u32* out_x, u32* out_y)
{
    const FramebufferInfo fb = FramebufferGet();
    const u32 usable = (fb.height > kTopY + kBottomReserve) ? (fb.height - kTopY - kBottomReserve) : kRowPitch;
    u32 rows = usable / kRowPitch;
    if (rows == 0)
    {
        rows = 1;
    }
    *out_x = kColX0 + (index / rows) * kColStride;
    *out_y = kTopY + (index % rows) * kRowPitch;
}

// Draw the iconographic glyph for `kind` inside the kTileW x kTileH tile
// at (tx, ty). `fg` is the stroke colour (white); `accent` is the tile
// fill (used where the glyph wants the tile colour to show through).
void DrawGlyph(IconGlyph kind, u32 tx, u32 ty, u32 fg, u32 accent)
{
    const u32 m = 12;
    const u32 ox = tx + m;
    const u32 oy = ty + m;
    const u32 s = kTileW - 2 * m; // 32
    const i32 cx = static_cast<i32>(tx + kTileW / 2);
    const i32 cy = static_cast<i32>(ty + kTileH / 2);

    switch (kind)
    {
    case IconGlyph::Computer:
    {
        const u32 mh = s * 2 / 3;
        FramebufferFillRoundRect(ox, oy, s, mh, 3, fg);
        FramebufferFillRect(ox + 3, oy + 3, s - 6, mh - 6, kDark);
        FramebufferFillRect(ox + s / 2 - 2, oy + mh, 4, 6, fg);
        FramebufferFillRect(ox + s / 2 - 8, oy + mh + 6, 16, 3, fg);
        break;
    }
    case IconGlyph::Browser:
    {
        const i32 r = static_cast<i32>(s / 2);
        FramebufferFillCircle(cx, cy, static_cast<u32>(r), fg);
        FramebufferDrawCircle(cx, cy, static_cast<u32>(r), accent);
        FramebufferDrawLine(cx, cy - r, cx, cy + r, accent);
        FramebufferDrawLine(cx - r, cy, cx + r, cy, accent);
        FramebufferDrawLine(cx - r + 3, cy - r / 2, cx + r - 3, cy - r / 2, accent);
        FramebufferDrawLine(cx - r + 3, cy + r / 2, cx + r - 3, cy + r / 2, accent);
        break;
    }
    case IconGlyph::Terminal:
    {
        FramebufferFillRoundRect(ox, oy, s, s, 3, kDark);
        FramebufferDrawLine(static_cast<i32>(ox + 6), static_cast<i32>(oy + 7), static_cast<i32>(ox + 13),
                            static_cast<i32>(oy + s / 2), kTermGreen);
        FramebufferDrawLine(static_cast<i32>(ox + 13), static_cast<i32>(oy + s / 2), static_cast<i32>(ox + 6),
                            static_cast<i32>(oy + s - 7), kTermGreen);
        FramebufferFillRect(ox + 15, oy + s - 11, 10, 3, kTermGreen);
        break;
    }
    case IconGlyph::Calculator:
    {
        FramebufferFillRoundRect(ox, oy, s, s, 3, fg);
        FramebufferFillRect(ox + 3, oy + 3, s - 6, s / 4, kDark);
        const u32 by = oy + s / 4 + 5;
        for (u32 r = 0; r < 3; ++r)
        {
            for (u32 c = 0; c < 3; ++c)
            {
                FramebufferFillRect(ox + 4 + c * 8, by + r * 6, 5, 4, accent);
            }
        }
        break;
    }
    case IconGlyph::Notepad:
    {
        const u32 pw = s * 5 / 6;
        FramebufferFillRect(ox, oy, pw, s, fg);
        for (u32 i = 1; i <= 4; ++i)
        {
            FramebufferDrawLine(static_cast<i32>(ox + 5), static_cast<i32>(oy + i * 6), static_cast<i32>(ox + pw - 4),
                                static_cast<i32>(oy + i * 6), accent);
        }
        FramebufferFillRect(ox, oy, 3, s, kPaperRed);
        break;
    }
    case IconGlyph::Settings:
    {
        const u32 r = s / 2 - 1;
        // Eight teeth around the rim (unit directions scaled to r).
        const i32 dirs[8][2] = {{0, -7}, {5, -5}, {7, 0}, {5, 5}, {0, 7}, {-5, 5}, {-7, 0}, {-5, -5}};
        for (auto& d : dirs)
        {
            const i32 tcx = cx + d[0] * static_cast<i32>(r) / 7;
            const i32 tcy = cy + d[1] * static_cast<i32>(r) / 7;
            FramebufferFillRect(static_cast<u32>(tcx - 2), static_cast<u32>(tcy - 2), 5, 5, fg);
        }
        FramebufferFillCircle(cx, cy, r - 1, fg);
        FramebufferFillCircle(cx, cy, r * 2 / 5, kDark);
        break;
    }
    case IconGlyph::DeviceMgr:
    {
        FramebufferFillRect(ox + 4, oy + 4, s - 8, s - 8, fg);
        FramebufferFillRect(ox + 8, oy + 8, s - 16, s - 16, kDark);
        for (u32 i = 0; i < 3; ++i)
        {
            FramebufferFillRect(ox + 8 + i * 8, oy, 3, 4, fg);
            FramebufferFillRect(ox + 8 + i * 8, oy + s - 4, 3, 4, fg);
            FramebufferFillRect(ox, oy + 8 + i * 8, 4, 3, fg);
            FramebufferFillRect(ox + s - 4, oy + 8 + i * 8, 4, 3, fg);
        }
        break;
    }
    case IconGlyph::Trash:
    {
        FramebufferFillRect(ox + s / 2 - 3, oy, 6, 3, fg);     // handle
        FramebufferFillRect(ox, oy + 3, s, 4, fg);             // lid
        FramebufferFillRect(ox + 3, oy + 8, s - 6, s - 9, fg); // body
        FramebufferDrawLine(static_cast<i32>(ox + s / 3), static_cast<i32>(oy + 11), static_cast<i32>(ox + s / 3),
                            static_cast<i32>(oy + s - 3), accent);
        FramebufferDrawLine(static_cast<i32>(ox + 2 * s / 3), static_cast<i32>(oy + 11),
                            static_cast<i32>(ox + 2 * s / 3), static_cast<i32>(oy + s - 3), accent);
        break;
    }
    case IconGlyph::Help:
    {
        FramebufferFillCircle(cx, cy, s / 2 - 1, fg);
        const u32 qw = ChromeTextMeasure(ChromeTextRole::Title, "?");
        const u32 qh = ChromeTextRoleHeight(ChromeTextRole::Title);
        ChromeTextDraw(ChromeTextRole::Title, static_cast<u32>(cx) - qw / 2, static_cast<u32>(cy) - qh / 2, "?", accent,
                       fg, ChromeTextWeight::Bold);
        break;
    }
    }
}

} // namespace

void DesktopIconRegister(const char* label, IconGlyph glyph, WindowHandle target)
{
    if (g_icon_count >= kMaxIcons || label == nullptr || target == kWindowInvalid)
    {
        return;
    }
    g_icons[g_icon_count] = Icon{label, glyph, target};
    ++g_icon_count;
}

bool DesktopIconSetHover(int index)
{
    if (index >= static_cast<int>(g_icon_count))
    {
        index = -1;
    }
    if (index == g_hover)
    {
        return false;
    }
    g_hover = index;
    return true;
}

void DesktopIconsPaint()
{
    const u32 accent = ThemeCurrent().taskbar_accent;
    for (u32 i = 0; i < g_icon_count; ++i)
    {
        u32 cell_x = 0, cell_y = 0;
        IconCell(i, &cell_x, &cell_y);

        // Hover wash behind the whole cell.
        if (static_cast<int>(i) == g_hover)
        {
            FramebufferFillRoundRect(cell_x, cell_y - 2, kCellW, kCellH, 6, 0x002A3442u);
        }

        const u32 tile_x = cell_x + (kCellW - kTileW) / 2u;
        const u32 tile_y = cell_y + 2u;

        FramebufferFillRect(tile_x - 1u, tile_y - 1u, kTileW + 2u, kTileH + 2u, kTileBorder);
        FramebufferFillRect(tile_x, tile_y, kTileW, kTileH, accent);
        DrawGlyph(g_icons[i].glyph, tile_x, tile_y, kWhite, accent);

        const u32 lw = ChromeTextMeasure(ChromeTextRole::Caption, g_icons[i].label);
        const u32 lx = cell_x + (kCellW > lw ? (kCellW - lw) / 2u : 0u);
        const u32 ly = tile_y + kTileH + 4u;
        ChromeTextDraw(ChromeTextRole::Caption, lx, ly, g_icons[i].label, kWhite, kLabelChip, ChromeTextWeight::Bold);
    }
}

int DesktopIconHitTest(u32 x, u32 y)
{
    for (u32 i = 0; i < g_icon_count; ++i)
    {
        u32 cell_x = 0, cell_y = 0;
        IconCell(i, &cell_x, &cell_y);
        if (x >= cell_x && x < cell_x + kCellW && y >= cell_y && y < cell_y + kCellH)
        {
            return static_cast<int>(i);
        }
    }
    return -1;
}

void DesktopIconActivate(int index)
{
    if (index < 0 || static_cast<u32>(index) >= g_icon_count)
    {
        return;
    }
    const WindowHandle target = g_icons[static_cast<u32>(index)].target;
    if (target == kWindowInvalid)
    {
        return;
    }
    WindowSetVisible(target, true);
    WindowRaise(target);
}

u32 DesktopIconCount()
{
    return g_icon_count;
}

void DesktopIconsSelfTest()
{
    bool ok = true;
    for (u32 i = 0; i < g_icon_count; ++i)
    {
        u32 cell_x = 0, cell_y = 0;
        IconCell(i, &cell_x, &cell_y);
        if (DesktopIconHitTest(cell_x + kCellW / 2u, cell_y + kCellH / 2u) != static_cast<int>(i))
        {
            ok = false;
        }
    }
    if (DesktopIconHitTest(5000u, 5000u) != -1)
    {
        ok = false;
    }
    duetos::arch::SerialWrite(ok ? "[desktop-icons] selftest PASS (" : "[desktop-icons] selftest FAIL (");
    duetos::arch::SerialWriteHex(g_icon_count);
    duetos::arch::SerialWrite(" icons)\n");
}

} // namespace duetos::drivers::video
