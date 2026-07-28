#include "drivers/video/desktop_icons.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/blend_math.h"
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
constexpr u32 kBottomReserve = 52;

// 0x00RRGGBB, matching the rest of the chrome.
constexpr u32 kWhite = 0x00FFFFFFu;
constexpr u32 kDark = 0x001A222Cu; // screens / recesses inside a glyph
constexpr u32 kTileBorder = 0x00101418u;
constexpr u32 kLabelChip = 0x00141A20u;
constexpr u32 kTermGreen = 0x0050E060u;
constexpr u32 kPaperRed = 0x00C04848u;

// Aurora tile metrics — docs/aurora-theme/README.md §1 "Desktop icon",
// scaled to the 1024x768 column of IMPLEMENTATION.md §7 (52 -> 40 px
// tile, radius 14 -> 10).
constexpr u32 kAuroraTile = 40;
constexpr u32 kAuroraRadius = 10;

u32 IsqrtU32(u32 v)
{
    u32 r = 0;
    while ((r + 1) * (r + 1) <= v)
    {
        ++r;
    }
    return r;
}

// Horizontal inset of a rounded rectangle's row `row` (0-based from the
// top of an `h`-tall box with corner radius `radius`). Rows in the
// straight middle return 0.
u32 RoundInset(u32 row, u32 h, u32 radius)
{
    u32 dy = 0;
    if (row < radius)
    {
        dy = radius - row;
    }
    else if (row >= h - radius)
    {
        dy = row - (h - radius) + 1;
    }
    else
    {
        return 0;
    }
    if (dy > radius)
    {
        dy = radius;
    }
    return radius - IsqrtU32(radius * radius - dy * dy);
}

// Blend a rounded rectangle filled with a vertical alpha ramp of `rgb`,
// from `a_top` at the first row to `a_bot` at the last. This is the one
// primitive the Aurora icon tile needs that the framebuffer doesn't
// already have: FillRoundRect is opaque, BlendFill is square, and the
// design's tile is both rounded AND translucent so the wallpaper's glow
// reads through it.
void BlendRoundRectVGradient(u32 x, u32 y, u32 w, u32 h, u32 radius, u32 rgb, u32 a_top, u32 a_bot)
{
    if (w == 0 || h == 0)
    {
        return;
    }
    for (u32 row = 0; row < h; ++row)
    {
        const u32 inset = RoundInset(row, h, radius);
        if (2 * inset >= w)
        {
            continue;
        }
        const u32 a = a_top - ((a_top - a_bot) * row) / h;
        FramebufferBlendFill(x + inset, y + row, w - 2 * inset, 1, (a << 24) | (rgb & 0x00FFFFFFu));
    }
}

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
void DrawGlyph(IconGlyph kind, u32 tx, u32 ty, u32 tile, u32 fg, u32 accent)
{
    // Every glyph below is hand-plotted against a 32-px art box (the
    // original 56-px tile's 12-px margin), so the box stays 32 on any
    // tile that can hold it and the margin absorbs the difference.
    // Rescaling the plots instead would mean re-tuning nine glyphs.
    const u32 s = (tile > 36) ? 32 : tile - 4;
    const u32 m = (tile - s) / 2;
    const u32 ox = tx + m;
    const u32 oy = ty + m;
    const i32 cx = static_cast<i32>(tx + tile / 2);
    const i32 cy = static_cast<i32>(ty + tile / 2);

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

        // Aurora tile (README §1 "Desktop icon"): a rounded, translucent
        // accent wash with a gloss dome on the upper half, an accent
        // border, and the glyph stroked in the accent rather than a
        // white-on-solid-accent chip. Palettes that don't ship the
        // Aurora vocabulary (surface_radius == 0) keep the flat tile.
        const bool aurora = ThemeCurrent().surface_radius != 0 && ThemeTactilityEffective();
        const u32 tile_side = aurora ? kAuroraTile : kTileW;
        const u32 tile_x = cell_x + (kCellW - tile_side) / 2u;
        const u32 tile_y = cell_y + 2u;

        if (aurora)
        {
            // linear-gradient(160deg, accent 30%, accent 8%) -> 77..20.
            BlendRoundRectVGradient(tile_x, tile_y, tile_side, tile_side, kAuroraRadius, accent, 77u, 20u);
            // Gloss dome: white .30 -> .06 at 44 %, gone by 52 %.
            const u32 dome_h = (tile_side * 52u) / 100u;
            BlendRoundRectVGradient(tile_x, tile_y, tile_side, dome_h, kAuroraRadius, kWhite, 76u, 8u);
            // Border at accent 38 %. DrawRoundRect has no alpha form, so
            // the stroke is pre-blended against the theme's desktop
            // ground — the tiles always sit on the wallpaper's darkest
            // band, where that ground is within a step or two of truth.
            FramebufferDrawRoundRect(tile_x, tile_y, tile_side, tile_side, kAuroraRadius,
                                     BlendOver(ThemeCurrent().desktop_bg, accent, 97));
            DrawGlyph(g_icons[i].glyph, tile_x, tile_y, tile_side, accent, kDark);
        }
        else
        {
            FramebufferFillRect(tile_x - 1u, tile_y - 1u, tile_side + 2u, tile_side + 2u, kTileBorder);
            FramebufferFillRect(tile_x, tile_y, tile_side, tile_side, accent);
            DrawGlyph(g_icons[i].glyph, tile_x, tile_y, tile_side, kWhite, accent);
        }

        const u32 lw = ChromeTextMeasure(ChromeTextRole::Caption, g_icons[i].label);
        const u32 lx = cell_x + (kCellW > lw ? (kCellW - lw) / 2u : 0u);
        const u32 ly = tile_y + tile_side + 6u;
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

WindowHandle DesktopIconWindow(int index)
{
    if (index < 0 || static_cast<u32>(index) >= g_icon_count)
        return kWindowInvalid;
    return g_icons[static_cast<u32>(index)].target;
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
