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
    const char* glyph;
    WindowHandle target;
};

// Fixed capacity — the desktop holds the handful of canonical
// destinations (Computer, Browser, Terminal, Calculator, Notepad,
// Settings, Device Manager, Trash, Help). The grid wraps into extra
// columns, so this is the only ceiling.
constexpr u32 kMaxIcons = 16;
Icon g_icons[kMaxIcons] = {};
u32 g_icon_count = 0;

// Grid layout. Icons fill the left column top-to-bottom, then wrap into
// the next column once they'd reach the taskbar. Each icon occupies a
// kCellW x kCellH cell; a kTileW x kTileH glyph tile sits centred at the
// top with the label centred beneath it.
constexpr u32 kTopY = 24;
constexpr u32 kColX0 = 20;
constexpr u32 kColStride = 96; // column pitch (cell + gutter)
constexpr u32 kRowPitch = 92;  // row pitch (cell + gutter)
constexpr u32 kCellW = 84;
constexpr u32 kCellH = 84;
constexpr u32 kTileW = 56;
constexpr u32 kTileH = 56;
constexpr u32 kBottomReserve = 52; // keep clear of the taskbar at the bottom

// 0x00RRGGBB, matching the rest of the chrome (see login.cpp).
constexpr u32 kWhite = 0x00FFFFFFu;
constexpr u32 kTileBorder = 0x00101418u; // near-black 1px frame
constexpr u32 kLabelChip = 0x00141A20u;  // dark chip behind the label for contrast

// Resolve an icon index to its top-left cell origin, wrapping columns to
// stay above the taskbar. Reads the live framebuffer height so the grid
// adapts to the boot resolution.
void IconCell(u32 index, u32* out_x, u32* out_y)
{
    const FramebufferInfo fb = FramebufferGet();
    const u32 usable = (fb.height > kTopY + kBottomReserve) ? (fb.height - kTopY - kBottomReserve) : kRowPitch;
    u32 rows = usable / kRowPitch;
    if (rows == 0)
    {
        rows = 1;
    }
    const u32 col = index / rows;
    const u32 row = index % rows;
    *out_x = kColX0 + col * kColStride;
    *out_y = kTopY + row * kRowPitch;
}

} // namespace

void DesktopIconRegister(const char* label, const char* glyph, WindowHandle target)
{
    if (g_icon_count >= kMaxIcons || label == nullptr || glyph == nullptr || target == kWindowInvalid)
    {
        return;
    }
    g_icons[g_icon_count] = Icon{label, glyph, target};
    ++g_icon_count;
}

void DesktopIconsPaint()
{
    const u32 accent = ThemeCurrent().taskbar_accent;
    for (u32 i = 0; i < g_icon_count; ++i)
    {
        u32 cell_x = 0, cell_y = 0;
        IconCell(i, &cell_x, &cell_y);
        const u32 tile_x = cell_x + (kCellW - kTileW) / 2u;
        const u32 tile_y = cell_y + 2u;

        // 1px dark frame, then the accent tile inside it.
        FramebufferFillRect(tile_x - 1u, tile_y - 1u, kTileW + 2u, kTileH + 2u, kTileBorder);
        FramebufferFillRect(tile_x, tile_y, kTileW, kTileH, accent);

        // Glyph centred in the tile (bg == accent so it blends).
        const u32 gw = ChromeTextMeasure(ChromeTextRole::Title, g_icons[i].glyph);
        const u32 gh = ChromeTextRoleHeight(ChromeTextRole::Title);
        const u32 gx = tile_x + (kTileW > gw ? (kTileW - gw) / 2u : 2u);
        const u32 gy = tile_y + (kTileH > gh ? (kTileH - gh) / 2u : 2u);
        ChromeTextDraw(ChromeTextRole::Title, gx, gy, g_icons[i].glyph, kWhite, accent, ChromeTextWeight::Bold);

        // Label centred under the tile on a dark chip so it stays legible
        // over the gradient wallpaper.
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
    // A point well off the grid must hit nothing.
    if (DesktopIconHitTest(5000u, 5000u) != -1)
    {
        ok = false;
    }
    duetos::arch::SerialWrite(ok ? "[desktop-icons] selftest PASS (" : "[desktop-icons] selftest FAIL (");
    duetos::arch::SerialWriteHex(g_icon_count);
    duetos::arch::SerialWrite(" icons)\n");
}

} // namespace duetos::drivers::video
