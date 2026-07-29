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

// Grid layout. docs/aurora-theme/README.md §1 specifies a 2-column grid
// of cells at the top-left, filled left-to-right; the reference desktop
// reads Task Manager / Kernel Log across the top row and Inspect / Files
// across the second. Column-major filling — which is what this used to
// do — put the second icon UNDER the first, which is the layout of a
// nine-item Windows-style column, not of the design's 2x2 block.
constexpr u32 kTopY = 24;
constexpr u32 kColX0 = 20;
constexpr u32 kColStride = 96;
constexpr u32 kRowPitch = 92;
constexpr u32 kCellW = 84;
constexpr u32 kCellH = 84;
constexpr u32 kTileW = 56;
constexpr u32 kBottomReserve = 52;
constexpr u32 kGridCols = 2;

// Longest label the paint pass will render before truncating. 20 covers
// every registered label with room to spare; the cell-width clamp below
// is what actually decides where the text stops.
constexpr u32 kMaxLabel = 20;

// 0x00RRGGBB, matching the rest of the chrome.
constexpr u32 kWhite = 0x00FFFFFFu;
constexpr u32 kTileBorder = 0x00101418u;
constexpr u32 kLabelChip = 0x00141A20u;

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

// Row-major over kGridCols columns. If that many rows would run past the
// taskbar reserve the grid widens instead — the count is data (a future
// slice can register more destinations) and running icons off the bottom
// of the screen is worse than a wider block.
void IconCell(u32 index, u32* out_x, u32* out_y)
{
    const FramebufferInfo fb = FramebufferGet();
    const u32 usable = (fb.height > kTopY + kBottomReserve) ? (fb.height - kTopY - kBottomReserve) : kRowPitch;
    u32 rows_that_fit = usable / kRowPitch;
    if (rows_that_fit == 0)
    {
        rows_that_fit = 1;
    }
    u32 cols = kGridCols;
    while (cols < kMaxIcons && (g_icon_count + cols - 1) / cols > rows_that_fit)
    {
        ++cols;
    }
    *out_x = kColX0 + (index % cols) * kColStride;
    *out_y = kTopY + (index / cols) * kRowPitch;
}

// Draw the iconographic glyph for `kind` inside the `tile`-square tile at
// (tx, ty). `fg` is the stroke colour — the accent under Aurora, white on
// the flat palettes.
//
// README §1 calls for a 24-px stroke glyph on a 52-px tile — a light,
// outlined mark, not a filled silhouette. The plots below are stroked for
// that reason: on the Aurora tile the glyph is accent-on-translucent, and
// a solid shape at that size fills the tile and loses its identity. That
// is also why there is no second "recess" colour any more: none of the
// four marks has an interior that needs to read as a hole.
void DrawGlyph(IconGlyph kind, u32 tx, u32 ty, u32 tile, u32 fg)
{
    // Art box: the design's 24-px glyph on a 52-px tile is a ~46 % inset,
    // so the box tracks the tile rather than staying a fixed 32 px — the
    // Aurora tile is 40 px here and a fixed box would overflow it.
    const u32 s = (tile * 22u) / 40u * 2u > tile - 8u ? tile - 8u : (tile * 22u) / 40u * 2u;
    const u32 ox = tx + (tile - s) / 2u;
    const u32 oy = ty + (tile - s) / 2u;
    const u32 right = ox + s - 1;
    const u32 bottom = oy + s - 1;

    switch (kind)
    {
    case IconGlyph::TaskManager:
    {
        // Four ascending columns on a baseline — the same silhouette the
        // taskbar's TaskManager glyph uses, so the desktop launcher and
        // the running app's button read as the same app.
        FramebufferFillRect(ox, bottom, s, 2, fg);
        const u32 bar_w = s / 6u;
        const u32 gap = (s - 4u * bar_w) / 3u;
        for (u32 i = 0; i < 4; ++i)
        {
            const u32 h = (s * (3u + 2u * i)) / 12u;
            FramebufferFillRect(ox + i * (bar_w + gap), bottom - h, bar_w, h, fg);
        }
        break;
    }
    case IconGlyph::KernelLog:
    {
        // Console frame with a title rule and three log lines of
        // decreasing length.
        FramebufferDrawRoundRect(ox, oy, s, s, 3, fg);
        FramebufferFillRect(ox + 2, oy + s / 4u, s - 4u, 1, fg);
        for (u32 i = 0; i < 3; ++i)
        {
            const u32 len = (s - 8u) - i * (s / 8u);
            FramebufferFillRect(ox + 4, oy + s / 4u + 4u + i * (s / 6u), len, 2, fg);
        }
        break;
    }
    case IconGlyph::Inspect:
    {
        // Magnifier over a short code column — the design's Inspect is a
        // binary/disassembly reader, so the lens sits on text, not on a
        // bare circle.
        for (u32 i = 0; i < 3; ++i)
        {
            FramebufferFillRect(ox, oy + i * (s / 5u), (s / 2u) - i * 2u, 2, fg);
        }
        const i32 lens_r = static_cast<i32>(s / 4u);
        const i32 lens_cx = static_cast<i32>(ox + (s * 3u) / 5u);
        const i32 lens_cy = static_cast<i32>(oy + (s * 3u) / 5u);
        FramebufferDrawCircle(lens_cx, lens_cy, static_cast<u32>(lens_r), fg);
        FramebufferDrawCircle(lens_cx, lens_cy, static_cast<u32>(lens_r) - 1u, fg);
        FramebufferDrawLine(lens_cx + (lens_r * 3) / 4, lens_cy + (lens_r * 3) / 4, static_cast<i32>(right),
                            static_cast<i32>(bottom), fg);
        break;
    }
    case IconGlyph::Files:
    {
        // Folder: a raised tab over an outlined body.
        const u32 tab_h = s / 6u;
        FramebufferFillRect(ox, oy + tab_h, (s * 2u) / 5u, 2, fg);
        FramebufferFillRect(ox, oy + tab_h, 2, 2, fg);
        FramebufferDrawRoundRect(ox, oy + tab_h + 2u, s, s - tab_h - 2u, 3, fg);
        FramebufferFillRect(ox + 2, oy + tab_h + 2u + (s / 5u), s - 4u, 1, fg);
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
            DrawGlyph(g_icons[i].glyph, tile_x, tile_y, tile_side, accent);
        }
        else
        {
            FramebufferFillRect(tile_x - 1u, tile_y - 1u, tile_side + 2u, tile_side + 2u, kTileBorder);
            FramebufferFillRect(tile_x, tile_y, tile_side, tile_side, accent);
            DrawGlyph(g_icons[i].glyph, tile_x, tile_y, tile_side, kWhite);
        }

        // Labels are truncated to the cell rather than being allowed to
        // run past it. The proportional TTF caption fits "Task Manager"
        // inside 84 px; the fixed 8-px bitmap caption the flat palettes
        // use does not, and an untruncated label ran straight into the
        // next column's.
        char label[kMaxLabel];
        u32 n = 0;
        while (n + 1u < kMaxLabel && g_icons[i].label[n] != '\0')
        {
            label[n] = g_icons[i].label[n];
            ++n;
        }
        label[n] = '\0';
        while (n > 1u && ChromeTextMeasure(ChromeTextRole::Caption, label) > kCellW)
        {
            label[--n] = '\0';
        }
        const u32 lw = ChromeTextMeasure(ChromeTextRole::Caption, label);
        const u32 lx = cell_x + (kCellW > lw ? (kCellW - lw) / 2u : 0u);
        const u32 ly = tile_y + tile_side + 6u;
        ChromeTextDraw(ChromeTextRole::Caption, lx, ly, label, kWhite, kLabelChip, ChromeTextWeight::Bold);
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
