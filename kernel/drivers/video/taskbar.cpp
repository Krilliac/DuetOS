#include "drivers/video/taskbar.h"

#include "arch/x86_64/rtc.h"
#include "drivers/net/net.h"
#include "drivers/power/power.h"
#include "mm/frame_allocator.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "subsystems/audio/audio_backend.h"
#include "drivers/video/blend_math.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"

namespace duetos::drivers::video
{

namespace
{

constinit u32 g_y = 0;
constinit u32 g_h = 0;

// Painted strip rect on the x axis. On a classic full-width strip
// these are `0` and the framebuffer width. Under the Aurora island
// layout (Theme::taskbar_island) the strip becomes a centred,
// content-width, rounded surface inset from every screen edge, and
// every anchor in the redraw path — START, tabs, tray, time card,
// show-desktop rail — measures from these instead of from the
// framebuffer edges. Recomputed by TaskbarReanchor.
constinit u32 g_bar_x = 0;
constinit u32 g_bar_w = 0;
// Radius the island body was last painted with; 0 for the classic
// strip. Cached so the hit-test and the body paint agree.
constinit u32 g_bar_radius = 0;
constinit u32 g_bg = 0x00202020;
constinit u32 g_fg = 0x00FFFFFF;
constinit u32 g_accent = 0x00406080;
constinit u32 g_tab_inactive = 0x00303848;
constinit u32 g_border = 0x00101828;
constinit bool g_ready = false;

// Dock + lock + drag state. Default: docked at the bottom + locked
// (matches the project's pre-dock-API behaviour). The reanchor
// helper recomputes `g_y` from these whenever the framebuffer
// dimensions are known to be valid.
constinit TaskbarDock g_dock = TaskbarDock::Bottom;
constinit bool g_locked = true;
constinit bool g_dragging = false;

// Cached clock-widget bounds (recomputed every redraw). Exposed
// via TaskbarClockBounds for the mouse reader's calendar-toggle.
constinit u32 g_clock_x = 0;
constinit u32 g_clock_y = 0;
constinit u32 g_clock_w = 0;
constinit u32 g_clock_h = 0;

// Cached NET tray cell bounds — exposed via TaskbarNetCellBounds for
// the mouse reader to hover-preview / click-toggle the network
// flyout. Recomputed every redraw because the tray lays out right-
// to-left and the date width can shift the entire tray when the
// month name changes glyph count.
constinit u32 g_net_cell_x = 0;
constinit u32 g_net_cell_y = 0;
constinit u32 g_net_cell_w = 0;
constinit u32 g_net_cell_h = 0;

// Cached volume (speaker) tray cell bounds — exposed via
// TaskbarVolumeBounds so the mouse reader can click-toggle the volume
// flyout. Same right-to-left recompute caveat as the NET cell.
constinit u32 g_vol_cell_x = 0;
constinit u32 g_vol_cell_y = 0;
constinit u32 g_vol_cell_w = 0;
constinit u32 g_vol_cell_h = 0;

// "Show Desktop" sliver bounds — exposed via
// `TaskbarShowDesktopBounds`. Updated every redraw; remains 0
// until the strip has been Init'd + Redrawn at least once.
constinit u32 g_show_desktop_x = 0;
constinit u32 g_show_desktop_y = 0;
constinit u32 g_show_desktop_w = 0;
constinit u32 g_show_desktop_h = 0;

// Chevron-up "show hidden icons" button — the leftmost tray
// cell on Duet-family themes. Bounds are exposed for the mouse
// reader's hover + click handlers; `g_chevron_hover` carries the
// "cursor is currently over me" flag so the redraw can paint a
// larger glyph (the prototype's "expand a bit on hover" cue).
constinit u32 g_chevron_x = 0;
constinit u32 g_chevron_y = 0;
constinit u32 g_chevron_w = 0;
constinit u32 g_chevron_h = 0;
constinit bool g_chevron_hover = false;

// Cached search-pill bounds — exposed via TaskbarSearchBounds so the
// mouse reader can route a click into the Start menu. Zero-width when
// the active layout paints no search pill (any non-island theme).
constinit u32 g_search_x = 0;
constinit u32 g_search_y = 0;
constinit u32 g_search_w = 0;
constinit u32 g_search_h = 0;

// Last-painted app-button layout. Updated by TaskbarRedraw; consumed by
// TaskbarTabAt. Capacity has to cover the island's pinned launchers PLUS
// the running windows that aren't pinned, so it is deliberately larger
// than either set alone.
constexpr u32 kMaxTabs = 12;
struct TabSlot
{
    u32 x, y, w, h;
    u32 window; // WindowHandle, or 0xFFFFFFFF for empty
};
constinit TabSlot g_tabs[kMaxTabs] = {};
constinit u32 g_tab_count = 0;

// Vertically centre a row of 8-px glyphs inside the taskbar.
u32 TextRowY()
{
    return (g_h > 8) ? g_y + (g_h - 8) / 2 : g_y + 2;
}

// Is the active theme a Duet-family palette? Several layout
// decisions (DuetMark on START, the CPU/FPS pill, the reserve that
// pays for it) key off this. Single definition so a new Duet
// variant can't light up in one place and stay dark in another —
// the whitelist-incompleteness shape CLAUDE.md warns about.
bool IsDuetFamily(ThemeId id)
{
    return id == ThemeId::Duet || id == ThemeId::DuetLight || id == ThemeId::DuetBlue || id == ThemeId::DuetViolet ||
           id == ThemeId::DuetGreen || id == ThemeId::DuetClassic;
}

// START button + tab metrics. Shared by the paint pass and by the
// island's content-width measurement, which has to agree with the
// paint pass exactly or the rightmost cell falls off the surface.
constexpr u32 kStartW = 88;
constexpr u32 kStartGap = 16;
constexpr u32 kEdgePad = 4;
constexpr u32 kTabW = 170;
constexpr u32 kTabGap = 4;

// Aurora island metrics (docs/aurora-theme/README.md §10, scaled by
// IMPLEMENTATION.md §7's 1024x768 column). On the island the tabs stop
// being title-text slots and become fixed square icon buttons with a
// running/focused indicator pill underneath, and START drops its
// "DUET" label so the arcs mark stands alone. Both changes are what
// take the island from a 98 %-wide strip to the design's centred pill:
// the width is content-derived, so 170-px text tabs made "content"
// mean "the whole screen".
constexpr u32 kIslandStartW = 44;
constexpr u32 kIslandStartGap = 12;
constexpr u32 kIconTabW = 36;
constexpr u32 kIconTabGap = 6;
constexpr u32 kIconTabGlyph = 16;
constexpr u32 kPillH = 3;
constexpr u32 kPillRunW = 8;
constexpr u32 kPillFocusW = 16;

// Search pill (design §10: 250 x 40 at 1920, so 132 x 22 on the
// IMPLEMENTATION.md §7 1024 column). It sits between START and the app
// buttons and is the island's widest single cell.
constexpr u32 kSearchW = 132;
constexpr u32 kSearchH = 22;
constexpr u32 kSearchRadius = 10;
constexpr u32 kSearchGap = 12;

// Pinned launchers, in the order the island paints them: the shell's own
// surfaces — diagnostics, files, shell, settings.
//
// Design §10 pins NINE app buttons. That is a 1920 figure and it does
// not survive the scale down. Type does not scale below 11 px
// (IMPLEMENTATION.md §7), so the text-bearing cells on the right —
// "CPU nn%", "60.0 FPS", the clock and the date — keep their 1920
// widths while everything around them halves; the right-hand reserve is
// therefore a much larger share of a 1024 island than of a 1920 one.
// Nine buttons measured 86 % of the framebuffer, which is the
// near-full-width strip the island exists to avoid (see the Compositor
// wiki's "island's first landing"); five lands at ~69 %, against the
// reference's 65 %.
//
// Every entry must resolve through ThemeRoleWindow to a real registered
// window; a role whose window never got registered is skipped at paint
// time rather than painting a button that does nothing.
constexpr ThemeRole kPinnedRoles[] = {
    ThemeRole::TaskManager, ThemeRole::LogView, ThemeRole::Files, ThemeRole::Terminal, ThemeRole::Settings,
};
constexpr u32 kPinnedCount = sizeof(kPinnedRoles) / sizeof(kPinnedRoles[0]);

// Show-desktop rail: the rightmost cell of the strip. Hoisted out of
// the paint block because the time card has to anchor LEFT of it —
// both used to measure back from the same right edge, so the rail
// painted over the last few pixels of the date row.
constexpr u32 kRailW = 4;
constexpr u32 kRailGap = 4;

// Horizontal room the right-hand cluster needs: time card + tray
// icons + chevron + (Duet only) the CPU/FPS pill + the show-desktop
// rail + the gaps between them. Sized so tabs never get clipped by
// the rightmost paint pass.
//
//   Duet family: pill (~180) + tray (~100) + time (~80) +
//                rail (~6) + gaps (~30) = ~400
//   Other themes: tray (~70) + time (~80) + rail (~6) +
//                 gaps (~14) = ~170
u32 RightReserve()
{
    const ThemeId id = ThemeCurrentId();
    // DuetClassic keeps the Duet identity but not the pill — it is
    // deliberately absent from the pill list below.
    const bool pill = id == ThemeId::Duet || id == ThemeId::DuetLight || id == ThemeId::DuetBlue ||
                      id == ThemeId::DuetViolet || id == ThemeId::DuetGreen;
    // Under the island the cells pack tighter than on a full-width
    // strip: stats pill ~110 + tray ~54 + clock ~56 + rail 6 + gaps ~24.
    // Measuring the strip's looser 400 there is what left a dead gap
    // between the last app button and the stats pill.
    if (pill && ThemeCurrent().taskbar_island && ThemeTactilityEffective())
        return 270u;
    return pill ? 400u : 180u;
}

// The app buttons this pass will paint, left to right.
//
// Classic strip: running windows only — the strip has always meant
// "what's on screen", and its 170-px text tabs have no room for
// launchers that aren't running.
//
// Island (design §10): the pinned launchers first, whether or not they
// are running, then any running window not already covered by one. That
// is what makes the row a superbar rather than a task list — the design
// shows app buttons on an empty desktop, and the indicator pill under
// each button is what encodes running / focused / neither.
//
// Both the island's content-width measurement and the paint pass call
// this, so the two cannot disagree about how many cells to reserve.
u32 BuildButtonRoster(WindowHandle* out, u32 cap)
{
    const bool island = ThemeCurrent().taskbar_island && ThemeTactilityEffective();
    u32 n = 0;
    if (island)
    {
        for (u32 i = 0; i < kPinnedCount && n < cap; ++i)
        {
            const WindowHandle h = ThemeRoleWindow(kPinnedRoles[i]);
            if (h != kWindowInvalid && WindowIsAlive(h))
            {
                out[n++] = h;
            }
        }
    }
    const u32 count = WindowRegistryCount();
    for (u32 i = 0; i < count && n < cap; ++i)
    {
        const WindowHandle h = i;
        if (!WindowIsAlive(h) || !WindowIsVisible(h))
        {
            continue;
        }
        bool already = false;
        for (u32 j = 0; j < n; ++j)
        {
            if (out[j] == h)
            {
                already = true;
                break;
            }
        }
        if (!already)
        {
            out[n++] = h;
        }
    }
    return n;
}

// Cell count only — for the width measurement, which doesn't need the
// handles themselves.
u32 ButtonCount()
{
    WindowHandle roster[kMaxTabs] = {};
    return BuildButtonRoster(roster, kMaxTabs);
}

// Lighten an 0x00RRGGBB colour by `amount` per channel, saturating
// at 0xFF. Used to derive the highlight shade for the top of
// gradient bands (taskbar strip, START button, active tab).
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

// Paint a 10×10 app glyph for a taskbar tab. Each ThemeRole gets
// a distinctive silhouette assembled from the framebuffer's
// rect/line primitives — no glyph asset pipeline needed at v0.
// Untagged windows (handle has no role registered) get a neutral
// square placeholder so the tab layout stays uniform whether or
// not the window is a registered native app. The glyph is drawn
// from origin (gx, gy) in `size` × `size` pixels with `ink` over
// the tab's fill (`bg`).
void DrawTaskbarGlyph(u32 gx, u32 gy, u32 size, u32 ink, u32 bg, bool have_role, ThemeRole role)
{
    (void)bg;
    if (!have_role)
    {
        FramebufferDrawRect(gx + 1, gy + 1, size - 2, size - 2, ink, 1);
        FramebufferFillRect(gx + size / 2 - 1, gy + size / 2 - 1, 2, 2, ink);
        return;
    }
    const u32 right = gx + size - 1;
    const u32 bottom = gy + size - 1;
    switch (role)
    {
    case ThemeRole::Calculator:
        // Display strip on top + a 2×2 keypad grid.
        FramebufferFillRect(gx, gy, size, 2, ink);
        FramebufferDrawRect(gx, gy + 3, size, size - 3, ink, 1);
        FramebufferFillRect(gx + size / 2, gy + 4, 1, size - 4, ink);
        FramebufferFillRect(gx + 1, gy + 3 + (size - 3) / 2, size - 2, 1, ink);
        break;
    case ThemeRole::Notes:
        // Page with three ruled rows.
        FramebufferDrawRect(gx, gy, size, size, ink, 1);
        FramebufferFillRect(gx + 2, gy + 3, size - 4, 1, ink);
        FramebufferFillRect(gx + 2, gy + 5, size - 4, 1, ink);
        FramebufferFillRect(gx + 2, gy + 7, size - 5, 1, ink);
        break;
    case ThemeRole::TaskManager:
        // Bar chart: three ascending columns.
        FramebufferFillRect(gx + 1, gy + size - 4, 2, 3, ink);
        FramebufferFillRect(gx + 4, gy + size - 6, 2, 5, ink);
        FramebufferFillRect(gx + 7, gy + size - 9, 2, 8, ink);
        break;
    case ThemeRole::LogView:
        // Console with three text lines.
        FramebufferDrawRect(gx, gy, size, size, ink, 1);
        FramebufferFillRect(gx + 2, gy + 2, 4, 1, ink);
        FramebufferFillRect(gx + 2, gy + 4, 6, 1, ink);
        FramebufferFillRect(gx + 2, gy + 6, 5, 1, ink);
        break;
    case ThemeRole::Files:
        // Folder silhouette: tab on top, body below.
        FramebufferFillRect(gx, gy + 2, 4, 1, ink);
        FramebufferDrawRect(gx, gy + 3, size, size - 3, ink, 1);
        break;
    case ThemeRole::Clock:
        // Circle with two hands.
        FramebufferStrokeArc(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + size / 2),
                             static_cast<i32>(size / 2 - 1), 0, 360, 1U, ink);
        FramebufferDrawLine(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + size / 2),
                            static_cast<i32>(gx + size / 2), static_cast<i32>(gy + 2), ink);
        FramebufferDrawLine(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + size / 2),
                            static_cast<i32>(gx + size - 2), static_cast<i32>(gy + size / 2), ink);
        break;
    case ThemeRole::GfxDemo:
        // Triangle in a frame — the universal "graphics demo" sign.
        FramebufferDrawRect(gx, gy, size, size, ink, 1);
        FramebufferDrawLine(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + 2), static_cast<i32>(gx + 2),
                            static_cast<i32>(bottom - 2), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 2), static_cast<i32>(bottom - 2), static_cast<i32>(right - 2),
                            static_cast<i32>(bottom - 2), ink);
        FramebufferDrawLine(static_cast<i32>(right - 2), static_cast<i32>(bottom - 2), static_cast<i32>(gx + size / 2),
                            static_cast<i32>(gy + 2), ink);
        break;
    case ThemeRole::Settings:
        // Gear-suggesting diamond at centre.
        FramebufferDrawLine(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + 1), static_cast<i32>(right - 1),
                            static_cast<i32>(gy + size / 2), ink);
        FramebufferDrawLine(static_cast<i32>(right - 1), static_cast<i32>(gy + size / 2),
                            static_cast<i32>(gx + size / 2), static_cast<i32>(bottom - 1), ink);
        FramebufferDrawLine(static_cast<i32>(gx + size / 2), static_cast<i32>(bottom - 1), static_cast<i32>(gx + 1),
                            static_cast<i32>(gy + size / 2), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 1), static_cast<i32>(gy + size / 2), static_cast<i32>(gx + size / 2),
                            static_cast<i32>(gy + 1), ink);
        FramebufferFillRect(gx + size / 2 - 1, gy + size / 2 - 1, 2, 2, ink);
        break;
    case ThemeRole::ImageView:
        // Frame with a sun-and-mountain silhouette.
        FramebufferDrawRect(gx, gy, size, size, ink, 1);
        FramebufferStrokeArc(static_cast<i32>(gx + 3), static_cast<i32>(gy + 3), 1, 0, 360, 1U, ink);
        FramebufferDrawLine(static_cast<i32>(gx + 1), static_cast<i32>(bottom - 1), static_cast<i32>(gx + 4),
                            static_cast<i32>(gy + size / 2), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 4), static_cast<i32>(gy + size / 2), static_cast<i32>(right - 1),
                            static_cast<i32>(bottom - 1), ink);
        break;
    case ThemeRole::About:
        // Lower-case "i".
        FramebufferDrawRect(gx + 1, gy + 1, size - 2, size - 2, ink, 1);
        FramebufferFillRect(gx + size / 2, gy + 2, 1, 1, ink);
        FramebufferFillRect(gx + size / 2, gy + 4, 1, size - 6, ink);
        break;
    case ThemeRole::Help:
        // Question mark.
        FramebufferStrokeArc(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + 3), 2, 0, 270, 1U, ink);
        FramebufferDrawLine(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + 5), static_cast<i32>(gx + size / 2),
                            static_cast<i32>(bottom - 3), ink);
        FramebufferFillRect(gx + size / 2, bottom - 1, 1, 1, ink);
        break;
    case ThemeRole::Browser:
        // Globe outline.
        FramebufferStrokeArc(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + size / 2),
                             static_cast<i32>(size / 2 - 1), 0, 360, 1U, ink);
        FramebufferDrawLine(static_cast<i32>(gx + 1), static_cast<i32>(gy + size / 2), static_cast<i32>(right - 1),
                            static_cast<i32>(gy + size / 2), ink);
        FramebufferDrawLine(static_cast<i32>(gx + size / 2), static_cast<i32>(gy + 1), static_cast<i32>(gx + size / 2),
                            static_cast<i32>(bottom - 1), ink);
        break;
    case ThemeRole::Calendar:
        // Grid layout with a header strip.
        FramebufferDrawRect(gx, gy, size, size, ink, 1);
        FramebufferFillRect(gx + 1, gy + 1, size - 2, 1, ink);
        FramebufferFillRect(gx + 1, gy + 5, size - 2, 1, ink);
        FramebufferFillRect(gx + size / 2, gy + 3, 1, size - 4, ink);
        break;
    case ThemeRole::NotifyCenter:
        // Bell silhouette.
        FramebufferDrawLine(static_cast<i32>(gx + 2), static_cast<i32>(bottom - 2), static_cast<i32>(right - 2),
                            static_cast<i32>(bottom - 2), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 2), static_cast<i32>(bottom - 2), static_cast<i32>(gx + 3),
                            static_cast<i32>(gy + 3), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 3), static_cast<i32>(gy + 3), static_cast<i32>(right - 3),
                            static_cast<i32>(gy + 3), ink);
        FramebufferDrawLine(static_cast<i32>(right - 3), static_cast<i32>(gy + 3), static_cast<i32>(right - 2),
                            static_cast<i32>(bottom - 2), ink);
        FramebufferFillRect(gx + size / 2, bottom - 1, 1, 1, ink);
        break;
    case ThemeRole::Sysmon:
        // EKG-like line graph.
        FramebufferDrawRect(gx, gy + 1, size, size - 2, ink, 1);
        FramebufferDrawLine(static_cast<i32>(gx + 1), static_cast<i32>(gy + 6), static_cast<i32>(gx + 3),
                            static_cast<i32>(gy + 6), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 3), static_cast<i32>(gy + 6), static_cast<i32>(gx + 4),
                            static_cast<i32>(gy + 3), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 4), static_cast<i32>(gy + 3), static_cast<i32>(gx + 5),
                            static_cast<i32>(gy + 8), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 5), static_cast<i32>(gy + 8), static_cast<i32>(gx + 6),
                            static_cast<i32>(gy + 5), ink);
        FramebufferDrawLine(static_cast<i32>(gx + 6), static_cast<i32>(gy + 5), static_cast<i32>(right - 1),
                            static_cast<i32>(gy + 5), ink);
        break;
    case ThemeRole::HexView:
        // Two columns of nibble dots.
        for (u32 r = 0; r < 4; ++r)
        {
            FramebufferFillRect(gx + 2, gy + 1 + r * 2, 1, 1, ink);
            FramebufferFillRect(gx + 4, gy + 1 + r * 2, 1, 1, ink);
            FramebufferFillRect(gx + 7, gy + 1 + r * 2, 1, 1, ink);
            FramebufferFillRect(gx + 9, gy + 1 + r * 2, 1, 1, ink);
        }
        break;
    case ThemeRole::CharMap:
        // Grid of squares (a 3×3 sample of glyph cells).
        for (u32 r = 0; r < 3; ++r)
        {
            for (u32 c = 0; c < 3; ++c)
            {
                FramebufferDrawRect(gx + 1 + c * 3, gy + 1 + r * 3, 2, 2, ink, 1);
            }
        }
        break;
    case ThemeRole::Terminal:
        // Box with a single ">_" prompt glyph sketched inside.
        FramebufferDrawRect(gx + 1, gy + 1, size - 2, size - 2, ink, 1);
        // ">"
        FramebufferFillRect(gx + 3, gy + 4, 1, 1, ink);
        FramebufferFillRect(gx + 4, gy + 5, 1, 1, ink);
        FramebufferFillRect(gx + 3, gy + 6, 1, 1, ink);
        // "_" cursor
        FramebufferFillRect(gx + 6, gy + 7, 3, 1, ink);
        break;
    default:
        FramebufferDrawRect(gx + 1, gy + 1, size - 2, size - 2, ink, 1);
        break;
    }
}

} // namespace

void TaskbarInit(u32 y, u32 height, u32 bg_rgb, u32 fg_rgb, u32 accent_rgb, u32 tab_inactive_rgb, u32 border_rgb)
{
    g_y = y;
    g_h = height;
    g_bg = bg_rgb;
    g_fg = fg_rgb;
    g_accent = accent_rgb;
    g_tab_inactive = tab_inactive_rgb;
    g_border = border_rgb;
    g_ready = true;
}

void TaskbarSetColours(u32 bg_rgb, u32 fg_rgb, u32 accent_rgb, u32 tab_inactive_rgb, u32 border_rgb)
{
    g_bg = bg_rgb;
    g_fg = fg_rgb;
    g_accent = accent_rgb;
    g_tab_inactive = tab_inactive_rgb;
    g_border = border_rgb;
}

void TaskbarReanchor()
{
    if (!g_ready || !FramebufferAvailable())
        return;
    const auto info = FramebufferGet();
    if (info.height == 0 || g_h == 0)
        return;

    // Aurora island layout: the strip lifts off the screen edge and
    // becomes a centred, content-width, rounded surface. Only defined
    // for the two horizontal docks — there is no left/right dock in
    // v0, so no fallback is needed here (see taskbar.h).
    const Theme& theme = ThemeCurrent();
    const u32 inset = (theme.taskbar_island && ThemeTactilityEffective()) ? theme.taskbar_inset : 0U;

    if (g_dock == TaskbarDock::Top)
        g_y = inset;
    else
        g_y = (info.height > g_h + inset) ? info.height - g_h - inset : 0;

    if (inset == 0)
    {
        g_bar_x = 0;
        g_bar_w = info.width;
        g_bar_radius = 0;
        return;
    }

    // Content width: left pad + START + gap + search pill + gap + the
    // app buttons that will actually paint + the right-hand cluster +
    // right pad. Clamped to the framebuffer minus an inset on each side,
    // so a desktop with many windows degrades to a near-full-width
    // island rather than running off the screen.
    // The rounded corners eat into the first and last `radius`
    // columns, so the content pad has to clear them or the START
    // button and the time card get sliced by the curve.
    const u32 pad = kEdgePad + theme.surface_radius;
    const u32 tabs_w = ButtonCount() * (kIconTabW + kIconTabGap);
    const u32 content = 2 * pad + kIslandStartW + kIslandStartGap + kSearchW + kSearchGap + tabs_w + RightReserve();
    const u32 max_w = (info.width > 2 * inset) ? info.width - 2 * inset : info.width;
    const u32 w = (content < max_w) ? content : max_w;

    g_bar_w = w;
    g_bar_x = (info.width > w) ? (info.width - w) / 2 : 0;
    g_bar_radius = theme.surface_radius;
}

void TaskbarSetDock(TaskbarDock edge)
{
    g_dock = edge;
    TaskbarReanchor();
}

TaskbarDock TaskbarGetDock()
{
    return g_dock;
}

void TaskbarSetLocked(bool locked)
{
    g_locked = locked;
    if (locked && g_dragging)
        g_dragging = false;
}

bool TaskbarIsLocked()
{
    return g_locked;
}

void TaskbarBeginDrag()
{
    if (g_locked || !g_ready)
        return;
    g_dragging = true;
}

void TaskbarEndDrag(u32 cursor_y)
{
    if (!g_dragging)
        return;
    g_dragging = false;
    if (!FramebufferAvailable())
        return;
    const auto info = FramebufferGet();
    // Snap to the nearest horizontal edge: above mid-line -> Top,
    // below -> Bottom. Drop on the current edge is a no-op.
    const TaskbarDock target = (cursor_y * 2u < info.height) ? TaskbarDock::Top : TaskbarDock::Bottom;
    if (target != g_dock)
        TaskbarSetDock(target);
}

bool TaskbarIsDragging()
{
    return g_dragging;
}

void TaskbarRedraw()
{
    if (!g_ready || !FramebufferAvailable())
    {
        return;
    }
    // Always reanchor before painting — handles the case where the
    // framebuffer was rebound (virtio-gpu coming online after a
    // stale FramebufferInit) AFTER TaskbarInit set g_y from the
    // pre-rebind dimensions.
    TaskbarReanchor();
    const auto info = FramebufferGet();
    // Every anchor below measures from the painted strip rect, not
    // from the framebuffer edges: under the Aurora island layout the
    // strip is a centred, inset surface and the desktop shows either
    // side of it. `g_bar_w == 0` only happens if a caller painted
    // before the first reanchor; fall back to full width.
    const u32 bar_x = g_bar_x;
    const u32 bar_w = (g_bar_w != 0) ? g_bar_w : info.width;
    const u32 bar_right = bar_x + bar_w;
    const u32 bar_radius = g_bar_radius;
    // Left / right content pad. On a full-width strip the chrome sits
    // 4 px off the framebuffer edge; on an island it must additionally
    // clear the corner curve. `bar_content_right` is the right-hand
    // anchor every right-aligned cell measures back from.
    const u32 bar_pad = kEdgePad + bar_radius;
    const u32 bar_content_right = (bar_w > 2 * bar_pad) ? bar_right - bar_pad : bar_right;

    // Tactility lift: a faint 6-px shadow bleeds upward from the
    // strip's top edge so the taskbar reads as a piece of chrome
    // floating above the desktop instead of a coloured stripe
    // pasted onto the bottom edge. Half the active shadow intensity
    // — the strip already commands attention via its accent border,
    // we just want depth, not weight. No-op for tactility=off
    // themes / runtime override + when the strip is already at the
    // top edge (g_y < 6).
    if (ThemeTactilityEffective() && g_y >= 6U)
    {
        const u8 base = ThemeIntensityEffective(ThemeCurrent().shadow_intensity_active);
        const u8 opacity = static_cast<u8>(base / 2U);
        if (opacity > 0)
        {
            RenderSoftShadow(static_cast<i32>(bar_x), static_cast<i32>(g_y) - 6, bar_w, 6U, 8U, opacity, 0x00000000U);
        }
    }

    // Background strip with a subtle vertical gradient: a slightly
    // lifted shade at the top fades into the registered taskbar bg
    // at the bottom. Reads as a coherent toolbar surface rather
    // than a flat coloured stripe. Keep the lift small so themes
    // that picked a near-black bg still read as near-black.
    //
    // Under the island layout the body is a rounded surface instead:
    // FillRoundRect leaves the corner pixels alone, so the desktop
    // shows through them without needing a punch colour that only
    // approximates the wallpaper. The gradient is traded for a flat
    // fill plus the Aurora specular below — there is no rounded
    // gradient primitive, and painting a square gradient first would
    // put four hard corners back on the surface.
    if (bar_radius > 0)
    {
        FramebufferFillRoundRect(bar_x, g_y, bar_w, g_h, bar_radius, g_bg);
        FramebufferDrawRoundRect(bar_x, g_y, bar_w, g_h, bar_radius, g_border);
    }
    else
    {
        FramebufferFillRectGradient(bar_x, g_y, bar_w, g_h, LightenRgb(g_bg, 12), g_bg);
    }

    // Top-edge treatment. The classic strip paints a 1-px accent line
    // ("the taskbar starts here"). The island already reads as a
    // separate surface thanks to its shadow and radius, so it takes
    // the Aurora specular instead: a white wash decaying across the
    // upper half with a hard terminator at the midpoint, plus a sheen
    // hairline along the very top. Both are inset by the radius so
    // they never spill into a corner that was left unpainted.
    if (bar_radius == 0)
    {
        FramebufferFillRect(bar_x, g_y, bar_w, 1, g_accent);
    }
    else if (bar_w > 2 * bar_radius)
    {
        const Theme& theme = ThemeCurrent();
        const u32 wash_x = bar_x + bar_radius;
        const u32 wash_w = bar_w - 2 * bar_radius;
        const u8 gloss = ThemeIntensityEffective(theme.gloss_alpha);
        const u32 band_h = g_h / 2;
        for (u32 row = 0; row < band_h && gloss > 0; ++row)
        {
            const u32 top = gloss;
            const u32 bottom = top / 4U;
            const u32 a = top - ((top - bottom) * row) / band_h;
            FramebufferBlendFill(wash_x, g_y + row, wash_w, 1U, (a << 24) | 0x00FFFFFFU);
        }
        const u8 sheen = ThemeIntensityEffective(theme.sheen_alpha);
        if (sheen > 0)
        {
            FramebufferBlendFill(wash_x, g_y, wash_w, 1U, (static_cast<u32>(sheen) << 24) | 0x00FFFFFFU);
        }
    }

    const u32 text_y = TextRowY();

    // "START" anchor on the left. Clicking it opens the start
    // menu via the mouse reader's TaskbarStartBounds hit-test.
    // Rounded fill + matching outline so it reads as an affordance
    // rather than a coloured rectangle. A 2-px highlight strip on
    // the top edge gives it a subtle raised look matching the
    // window-chrome highlight band.
    const bool island = bar_radius > 0;
    const u32 start_w = island ? kIslandStartW : kStartW;
    const u32 start_radius = island ? 10U : 4U;
    const u32 start_x = bar_x + bar_pad;
    const u32 start_h = (g_h > 8) ? g_h - 8 : g_h;
    FramebufferFillRoundRect(start_x, g_y + 4, start_w, start_h, start_radius, g_accent);
    FramebufferDrawRoundRect(start_x, g_y + 4, start_w, start_h, start_radius, g_border);
    if (start_h > 4)
    {
        FramebufferFillRect(start_x + start_radius, g_y + 5, start_w - 2 * start_radius, 1, LightenRgb(g_accent, 40));
    }
    // On the Duet theme the START button paints the DuetMark — two
    // interlocking rings (teal + amber) glyphing the dual-ABI
    // story — followed by the word "DUET". Other themes keep the
    // five-letter "START" label since they don't carry the duet
    // narrative. The simplified DuetMark uses two outlined circles
    // rather than the prototype's partial-arc strokes; partial-arc
    // rasterization is a follow-on once a proper path stroker
    // lands in the framebuffer.
    const bool is_duet_family = IsDuetFamily(ThemeCurrentId());
    if (is_duet_family && island)
    {
        // Island START is icon-only (design §10: 56x52 tile carrying a
        // 26 px arcs mark). Dropping the word buys 44 px of island.
        const i32 ring_cy = static_cast<i32>(g_y + g_h / 2);
        const i32 mark_cx = static_cast<i32>(start_x + start_w / 2);
        constexpr i32 kArcSweep = 189;
        constexpr u32 kAmberMark = 0x00F0B040;
        FramebufferStrokeArc(mark_cx - 4, ring_cy, 7, -30, kArcSweep, 2U, g_accent);
        FramebufferStrokeArc(mark_cx + 4, ring_cy, 7, 150, kArcSweep, 2U, kAmberMark);
    }
    else if (is_duet_family)
    {
        // "DUET" label width comes from the chrome-text dispatcher
        // so the DuetMark centring stays correct under TTF themes
        // where the advance differs from the bitmap's 4 * 8.
        const u32 mark_label_w = ChromeTextMeasure(ChromeTextRole::Body, "DUET");
        constexpr u32 mark_diameter = 14;
        constexpr u32 mark_overlap = 6; // shared horizontal overlap between rings
        const u32 mark_total_w = 2 * mark_diameter - mark_overlap + 6 + mark_label_w;
        const u32 mark_origin_x = start_x + (start_w - mark_total_w) / 2;
        const i32 ring_cy = static_cast<i32>(g_y + g_h / 2);
        const i32 ring_a_cx = static_cast<i32>(mark_origin_x + mark_diameter / 2);
        const i32 ring_b_cx = static_cast<i32>(mark_origin_x + mark_diameter - mark_overlap + mark_diameter / 2);
        constexpr u32 ring_r = mark_diameter / 2;
        // Teal accent (matches Duet's `--accent`). Drawing the ring
        // twice — once at radius r, once at radius r-1 — gives a
        // 2-pixel stroke without a separate stroke primitive.
        // Primary ring: the active theme's accent (teal on slate
        // Duet, blue on DuetBlue, violet on DuetViolet, etc.) so
        // each variant's brand colour reads in the START glyph.
        // Secondary ring: amber across all variants — the "second
        // ABI" ink the duet narrative is built around.
        //
        // Partial-arc geometry — matches the prototype's DuetMark
        // (`docs/duet-theme/prototype/`): each ring is a ~189°
        // sweep (52% of the full circle), with the two arcs
        // rotated 180° apart so the open ends face away from
        // each other. Stroke thickness 2 keeps the ring visible
        // on the active-tab gradient + the inactive dim overlay.
        constexpr u32 kAmber = 0x00F0B040;
        const u32 primary_ring = g_accent;
        constexpr i32 kArcSweep = 189;
        FramebufferStrokeArc(ring_a_cx, ring_cy, static_cast<i32>(ring_r), -30, kArcSweep, 2U, primary_ring);
        FramebufferStrokeArc(ring_b_cx, ring_cy, static_cast<i32>(ring_r), 150, kArcSweep, 2U, kAmber);
        // Label sits right of the rings.
        const u32 label_x = mark_origin_x + 2 * mark_diameter - mark_overlap + 6;
        ChromeTextDraw(ChromeTextRole::Body, label_x, text_y, "DUET", g_fg, g_accent);
    }
    else
    {
        // Use g_border (the darkest theme amber/grey) as the START
        // label ink so it stays readable when g_fg and g_accent are
        // close in hue — amber's palette in particular puts both
        // values in the same amber band and the label was invisible
        // against the button. Width comes from the chrome-text
        // dispatcher so the label stays centred under TTF themes.
        const u32 start_label_w = ChromeTextMeasure(ChromeTextRole::Body, "START");
        const u32 start_label_x = start_x + ((start_w > start_label_w) ? (start_w - start_label_w) / 2 : 0);
        ChromeTextDraw(ChromeTextRole::Body, start_label_x, text_y, "START", g_border, g_accent);
    }

    // Search pill (design §10), between START and the app buttons. Only
    // the island layout has room for it; the classic strip's 170-px text
    // tabs already fill the middle.
    //
    // GAP: the pill is a launcher affordance, not a query box — clicking
    // it opens the Start menu (routed via TaskbarSearchBounds in
    // boot_tasks). There is no free-text index to search yet, so it
    // deliberately accepts no typed input and shows no results. Revisit
    // when the Start menu grows its own §11 search field, which is where
    // a real query would be typed.
    g_search_x = 0;
    g_search_y = 0;
    g_search_w = 0;
    g_search_h = 0;
    if (island)
    {
        const u32 sx = start_x + start_w + kIslandStartGap;
        const u32 sh = (g_h > kSearchH) ? kSearchH : g_h;
        const u32 sy = g_y + (g_h - sh) / 2;
        // Sheer well rather than an opaque chip — the pill has to read as
        // an inset in the island's glass, the way the design's
        // rgba(0,0,0,.22) fill does over a blurred surface.
        FramebufferBlendFill(sx, sy, kSearchW, sh, (72U << 24) | 0x00000000U);
        FramebufferDrawRoundRect(sx, sy, kSearchW, sh, kSearchRadius, g_border);

        // Magnifier: a two-pass circle for a 2-px stroke plus a handle,
        // matching the desktop Inspect glyph's construction.
        const i32 lens_cx = static_cast<i32>(sx + 12);
        const i32 lens_cy = static_cast<i32>(sy + sh / 2);
        FramebufferDrawCircle(lens_cx, lens_cy, 4U, g_fg);
        FramebufferDrawLine(lens_cx + 3, lens_cy + 3, lens_cx + 6, lens_cy + 6, g_fg);

        // Placeholder ink is deliberately dimmer than g_fg: this is a
        // prompt, not a value the user entered.
        ChromeTextDraw(ChromeTextRole::Caption, sx + 24, text_y, "Search", g_tab_inactive, g_bg);

        g_search_x = sx;
        g_search_y = sy;
        g_search_w = kSearchW;
        g_search_h = sh;
    }

    // App buttons. On the island this is the pinned launcher row plus
    // any running window that isn't pinned (BuildButtonRoster); on the
    // classic strip it stays a running-windows-only task list. Advance x
    // with a small gap between cells, and clip when we'd overflow the
    // right-side cluster reserve.
    const u32 tab_w = island ? kIconTabW : kTabW;
    const u32 tab_gap = island ? kIconTabGap : kTabGap;
    // Reserve space on the right for the cluster of widgets that
    // sits beyond the tabs — time card + tray icons + chevron +
    // (Duet only) the CPU/FPS pill. Sized so tabs never get
    // clipped by the rightmost paint pass.
    //
    //   Duet family: pill (~180) + tray (~100) + time (~80) +
    //                rail (~6) + gaps (~30) = ~400
    //   Other themes: tray (~70) + time (~80) + rail (~6) +
    //                 gaps (~14) = ~170
    const u32 right_reserve = RightReserve();
    u32 tab_x = start_x + start_w + (island ? kIslandStartGap + kSearchW + kSearchGap : kStartGap);
    const u32 tabs_right_limit =
        (bar_content_right > bar_x + right_reserve) ? bar_content_right - right_reserve : bar_content_right;

    g_tab_count = 0;
    WindowHandle roster[kMaxTabs] = {};
    const u32 count = BuildButtonRoster(roster, kMaxTabs);
    for (u32 i = 0; i < count; ++i)
    {
        const WindowHandle h = roster[i];
        // A pinned launcher that isn't on screen still gets a button —
        // that's what makes the island a superbar. `running` drives the
        // indicator pill below, so "pinned but closed" reads as a bare
        // button with no pill under it.
        const bool running = WindowIsVisible(h);
        if (tab_x + tab_w > tabs_right_limit)
        {
            break; // ran out of middle — overflow unshown in v0
        }
        const bool is_active = running && (h == WindowActive());
        // Active tab uses the taskbar's accent colour so the
        // focused window reads at a glance — matches the window-
        // chrome active/inactive distinction. Rounded fill +
        // outline match the START button so the tray reads as
        // a coherent set of affordances rather than mismatched
        // styles. Active tabs get a vertical gradient — same
        // "lifted top" idiom as the window chrome — so the focused
        // tab visibly pops out of the strip; inactive tabs stay
        // flat to recede into the surface.
        const u32 tab_bg = is_active ? g_accent : g_tab_inactive;
        const u32 tab_h_eff = island ? kIconTabW : g_h - 8;
        const u32 tab_y = island ? g_y + 3 : g_y + 4;
        if (island)
        {
            // Aurora icon button (design 10): 52x52 at 1920, 36x36
            // here, radius 14 -> 10. Focused buttons take an accent
            // wash + accent border + accent glyph; everything else
            // stays sheer so the island reads as one surface.
            constexpr u32 kIconRadius = 10;
            if (is_active)
            {
                FramebufferBlendFill(tab_x, tab_y, tab_h_eff, tab_h_eff, (46U << 24) | (g_accent & 0x00FFFFFFU));
                FramebufferDrawRoundRect(tab_x, tab_y, tab_h_eff, tab_h_eff, kIconRadius, g_accent);
            }
            else
            {
                u32 cursor_x = 0;
                u32 cursor_y = 0;
                CursorPosition(&cursor_x, &cursor_y);
                const bool hovered = cursor_x >= tab_x && cursor_x < tab_x + tab_h_eff && cursor_y >= tab_y &&
                                     cursor_y < tab_y + tab_h_eff;
                if (hovered && ThemeTactilityEffective())
                {
                    const u8 hover_alpha = ThemeIntensityEffective(ThemeCurrent().hover_lift_alpha);
                    FramebufferBlendFill(tab_x, tab_y, tab_h_eff, tab_h_eff, ScaleAlpha(0x1AFFFFFFU, hover_alpha));
                }
            }
            ThemeRole role{};
            const bool have_role = ThemeRoleForWindow(h, &role);
            const u32 glyph_x = tab_x + (tab_h_eff - kIconTabGlyph) / 2;
            const u32 glyph_y = tab_y + (tab_h_eff - kIconTabGlyph) / 2;
            DrawTaskbarGlyph(glyph_x, glyph_y, kIconTabGlyph, is_active ? g_accent : g_fg, tab_bg, have_role, role);

            // Indicator pill: 10 px running / 22 px focused at 1920,
            // scaled here. The focused pill gets a 1-px accent halo in
            // place of the design's 10-px CSS glow - the framebuffer
            // has no blur primitive, and a hard halo still separates
            // "focused" from "running" at a glance. A pinned launcher
            // that isn't running gets NO pill: the absence is the third
            // state, and painting one would claim the app is open.
            if (running)
            {
                const u32 pill_w = is_active ? kPillFocusW : kPillRunW;
                const u32 pill_x = tab_x + (tab_h_eff - pill_w) / 2;
                const u32 pill_y = g_y + g_h - kPillH - 2;
                const u32 pill_rgb = is_active ? g_accent : g_tab_inactive;
                if (is_active && pill_x >= 1)
                {
                    FramebufferBlendFill(pill_x - 1, pill_y - 1, pill_w + 2, kPillH + 2,
                                         (90U << 24) | (g_accent & 0x00FFFFFFU));
                }
                FramebufferFillRect(pill_x, pill_y, pill_w, kPillH, pill_rgb);
            }
        }
        else
        {
            constexpr u32 tab_radius = 3;
            const u32 legacy_h = g_h - 8;
            if (is_active)
            {
                FramebufferFillRectGradient(tab_x, g_y + 4, tab_w, legacy_h, LightenRgb(g_accent, 32), g_accent);
            }
            else
            {
                FramebufferFillRoundRect(tab_x, g_y + 4, tab_w, legacy_h, tab_radius, tab_bg);
            }
            FramebufferDrawRoundRect(tab_x, g_y + 4, tab_w, legacy_h, tab_radius, g_border);

            // Tactility lift: per-tab hover overlay + faint ambient
            // shadow. Cursor-position hit-test mirrors the titlebar
            // control buttons' inline `inside()` lambda (widget.cpp
            // L748). No press-overlay yet — per-tab pressed state
            // isn't tracked at paint time (the mouse loop transitions
            // straight from press to dispatch); a future input-state
            // refactor that surfaces per-widget pressed-bits will
            // light it up. Skip the lift for the active tab — its
            // accent gradient already reads as elevated.
            if (!is_active && ThemeTactilityEffective())
            {
                const u8 hover_alpha = ThemeIntensityEffective(ThemeCurrent().hover_lift_alpha);
                if (hover_alpha > 0)
                {
                    u32 cursor_x = 0;
                    u32 cursor_y = 0;
                    CursorPosition(&cursor_x, &cursor_y);
                    const bool hovered = cursor_x >= tab_x && cursor_x < tab_x + tab_w && cursor_y >= g_y + 4 &&
                                         cursor_y < g_y + 4 + legacy_h;
                    if (hovered)
                    {
                        const u32 wash = ScaleAlpha(0x1AFFFFFFU, hover_alpha);
                        FramebufferBlendFill(tab_x, g_y + 4, tab_w, legacy_h, wash);
                        const u8 shadow_base = ThemeIntensityEffective(ThemeCurrent().shadow_intensity_active);
                        RenderSoftShadow(static_cast<i32>(tab_x), static_cast<i32>(g_y + 4), tab_w, legacy_h, 8U,
                                         static_cast<u8>(shadow_base / 2U), 0x00000000U);
                    }
                }
            }
            // 1-px highlight ridge across the top edge of the active
            // tab. Matches the window-chrome highlight band so the
            // tab reads as a small piece of chrome lifted off the strip.
            if (is_active && tab_w > 2 * tab_radius)
            {
                FramebufferFillRect(tab_x + tab_radius, g_y + 5, tab_w - 2 * tab_radius, 1, LightenRgb(g_accent, 56));
            }
            // Focus dot under the active tab. Per the spec the dot
            // is 14 px wide for running-but-not-pinned active apps
            // and 8 px wide for pinned-and-active apps — the size
            // difference encodes "session-bound vs always-here"
            // without adding ink.
            if (is_active && legacy_h > 4)
            {
                const bool pinned = WindowIsPinned(h);
                const u32 dot_w = pinned ? 8U : 14U;
                constexpr u32 dot_h = 2;
                const u32 strip_rgb = LightenRgb(g_accent, 56);
                const u32 dot_x = tab_x + (tab_w - dot_w) / 2;
                const u32 dot_y = g_y + g_h - 4 - dot_h;
                FramebufferFillRect(dot_x, dot_y, dot_w, dot_h, strip_rgb);
            }
            // Per-role app glyph in the tab's left gutter, before the
            // title text. Gives each running app a visual identity beyond
            // the truncated bitmap title — the same affordance the Win11
            // taskbar / macOS Dock / GNOME panel have. Glyphs are drawn
            // with the framebuffer's existing primitives (no SVG / TTF
            // dependency at boot), 10×10 px so they fit comfortably
            // inside the 20-px tab height without competing with the
            // title text's 8×8 cell. Untagged windows (ring-3 PEs that
            // skip ThemeRegisterWindow) get a neutral square placeholder.
            const u32 glyph_x = tab_x + 6;
            const u32 glyph_y = g_y + (g_h - 10) / 2;
            constexpr u32 kGlyphSize = 10;
            const u32 glyph_ink = g_fg;
            ThemeRole role{};
            const bool have_role = ThemeRoleForWindow(h, &role);
            DrawTaskbarGlyph(glyph_x, glyph_y, kGlyphSize, glyph_ink, tab_bg, have_role, role);
            const u32 text_x = tab_x + 6 + kGlyphSize + 6;
            const char* title = WindowTitle(h);
            if (title != nullptr)
            {
                // Pass C: tab labels through the unified chrome-text
                // dispatcher. The active tab renders bold to reinforce
                // the focus signal already carried by the accent
                // gradient + focus dot; inactive tabs stay regular.
                // Tab slot width is a fixed 170 px (kGlyphSize + label
                // run + padding) so labels are truncated to fit rather
                // than sizing-to-fit — the slot rect doubles as the
                // hit rect, so click-targeting is decoupled from the
                // rendered label width.
                ChromeTextDraw(ChromeTextRole::Body, text_x, text_y, title, g_fg, tab_bg,
                               is_active ? ChromeTextWeight::Bold : ChromeTextWeight::Regular);
            }
        }

        // Record the slot so subsequent hit-tests can map a
        // click back to a window without re-running the layout.
        if (g_tab_count < kMaxTabs)
        {
            g_tabs[g_tab_count].x = tab_x;
            g_tabs[g_tab_count].y = island ? g_y + 3 : g_y + 4;
            g_tabs[g_tab_count].w = tab_w;
            g_tabs[g_tab_count].h = island ? kIconTabW : g_h - 8;
            g_tabs[g_tab_count].window = h;
            ++g_tab_count;
        }
        tab_x += tab_w + tab_gap;
    }

    // --- Right edge: system tray + date + clock + uptime. ---
    //
    // Layout right-to-left from the framebuffer's right edge —
    // new widgets land left of existing ones without shifting
    // the clock:
    //
    //   [ ...tabs ... ]  [pill]  [chev][icons]   HH:MM
    //                                            DDD M/D
    //
    // The clock + date form a vertically-stacked block (Win10
    // tray convention) so the right-edge cluster is half as wide
    // as a single-line "HH:MM:SS  WWW DD MMM YYYY" run. The old
    // "UP NNNNs" uptime counter has moved into the chevron-flyout
    // panel — it's a developer-grade reading, not a glanceable
    // chrome cell.
    //
    // Clock bounds are captured into g_clock_* so the mouse reader
    // can toggle the calendar popup on click.

    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);

    // HH:MM (no seconds — they don't survive the 1 Hz compose
    // pump cleanly anyway, and Win10 / macOS both drop them).
    char clk[6];
    clk[0] = char('0' + rtc.hour / 10);
    clk[1] = char('0' + rtc.hour % 10);
    clk[2] = ':';
    clk[3] = char('0' + rtc.minute / 10);
    clk[4] = char('0' + rtc.minute % 10);
    clk[5] = '\0';
    // Pass C: width comes from the chrome-text dispatcher so the
    // calendar hit-rect tracks whichever font path the active theme
    // selected (TTF Title vs scaled bitmap). Falling back to the
    // raw 5*8 bitmap math would leave the hit-rect undersized on
    // TTF themes the moment the clock rendered wider than 40 px.
    const u32 clk_text_w = ChromeTextMeasure(ChromeTextRole::Title, clk);

    // Date row underneath: "WWW M/D" (e.g. "MON 5/4"). Compact —
    // 7 chars × 8 px = 56 px, less than the clock above so the
    // block reads as a stacked time card.
    static const char* kWd[7] = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"};
    u32 wy = rtc.year;
    u32 wm = rtc.month;
    const u32 wd_day = rtc.day;
    if (wm < 1 || wm > 12)
        wm = 1;
    if (wm < 3)
    {
        wm += 12;
        --wy;
    }
    const u32 K = wy % 100;
    const u32 J = wy / 100;
    const u32 h_zeller = (wd_day + (13 * (wm + 1)) / 5 + K + K / 4 + J / 4 + 5 * J) % 7;
    const u32 dow = (h_zeller + 6) % 7;
    char date[12];
    u32 d_off = 0;
    date[d_off++] = kWd[dow][0];
    date[d_off++] = kWd[dow][1];
    date[d_off++] = kWd[dow][2];
    date[d_off++] = ' ';
    if (rtc.month >= 10)
    {
        date[d_off++] = char('0' + rtc.month / 10);
    }
    date[d_off++] = char('0' + rtc.month % 10);
    date[d_off++] = '/';
    if (rtc.day >= 10)
    {
        date[d_off++] = char('0' + rtc.day / 10);
    }
    date[d_off++] = char('0' + rtc.day % 10);
    date[d_off] = '\0';
    // Pass C: same rationale as clk_text_w — measure under the
    // active theme's Caption font so the block hit-rect stays
    // accurate when the date rendered width diverges from bitmap
    // `d_off * 8`.
    const u32 date_text_w = ChromeTextMeasure(ChromeTextRole::Caption, date);

    // Block geometry: take the wider of the two rows + 12 px right
    // inset, anchored to the framebuffer's right edge.
    const u32 block_text_w = (clk_text_w > date_text_w) ? clk_text_w : date_text_w;
    const u32 block_w = block_text_w + 12;
    // Anchor left of the show-desktop rail, not of the strip edge:
    // the rail is painted last and would otherwise overwrite the
    // right-hand few pixels of the date row.
    const u32 cluster_right =
        (bar_content_right > bar_x + kRailW + kRailGap) ? bar_content_right - kRailW - kRailGap : bar_content_right;
    const u32 block_x = (cluster_right > bar_x + block_w) ? cluster_right - block_w : bar_x;
    // Two-row stack inside the taskbar height — top row above the
    // strip's vertical centre, bottom row below.
    const u32 row_top_y = g_y + (g_h / 2) - 8;
    const u32 row_bot_y = g_y + (g_h / 2) + 1;
    // Right-align each row inside the block.
    const u32 clk_x = block_x + (block_text_w - clk_text_w);
    const u32 date_x = block_x + (block_text_w - date_text_w);
    // Pass C: clock numerals run at Title weight (matches window
    // titlebars + modal titles — the most prominent chrome text
    // role), date underneath uses Caption (the chrome's smallest
    // role, reserved for hints/status/timestamps).
    ChromeTextDraw(ChromeTextRole::Title, clk_x, row_top_y, clk, g_fg, g_bg);
    ChromeTextDraw(ChromeTextRole::Caption, date_x, row_bot_y, date, g_fg, g_bg);

    // Publish a whole-cell hit-test rect around the stacked block
    // so a click anywhere in the time card opens the calendar.
    g_clock_x = (block_x >= 4) ? block_x - 4 : 0;
    g_clock_y = g_y + 4;
    g_clock_w = block_w + 4;
    g_clock_h = (g_h > 8) ? g_h - 8 : g_h;

    // --- System tray: left of the date. Compact icon cells laid
    // out right-to-left, ending with a chevron-up overflow button
    // on Duet-family themes. Replaces the original M/C/N letter
    // cells with proper stroked icons (Wi-Fi, volume, battery)
    // and a status dot in the cell's bottom-right corner.
    //
    // Cell metric: 22 px square, 4 px gap. Each icon paints a
    // 14-px stroke glyph centered inside the cell; the status
    // dot is a 3-px filled square in the bottom-right pinning
    // the cell's contextual colour without flooding the body.
    constexpr u32 tray_cell = 22;
    constexpr u32 tray_gap = 4;
    const u32 tray_y = g_y + (g_h > tray_cell ? (g_h - tray_cell) / 2 : 0);
    // Tray sits to the LEFT of the time card. Anchor the
    // rightmost tray cell against the time card's left edge.
    u32 tray_right = (block_x > tray_gap + 4) ? block_x - tray_gap : 0;

    // Reset cached cell bounds; we re-publish only the cells that
    // actually got placed on this redraw (e.g. NET cell skipped
    // entirely if the strip ran out of horizontal room).
    g_net_cell_x = g_net_cell_y = g_net_cell_w = g_net_cell_h = 0;
    g_vol_cell_x = g_vol_cell_y = g_vol_cell_w = g_vol_cell_h = 0;
    g_chevron_x = g_chevron_y = g_chevron_w = g_chevron_h = 0;

    // --- Icon-drawing helpers. Each takes the (x, y) origin of
    // the 14-px glyph area + an ink colour, and strokes the icon
    // with framebuffer primitives. Sized so the glyph reads at
    // 14 px. All have a 4-px margin inside the 22-px cell.
    constexpr u32 kGlyph = 14;

    // Wi-Fi: three stacked partial arcs above a tiny dot at the
    // bottom centre. Sweep is 100° centred at -90° so the arc
    // opens upward (matching standard Wi-Fi glyphs).
    auto draw_wifi = [&](u32 ox, u32 oy, u32 ink)
    {
        const i32 cx = static_cast<i32>(ox + kGlyph / 2);
        const i32 cy = static_cast<i32>(oy + kGlyph - 2);
        FramebufferStrokeArc(cx, cy, 6, -140, 100, 1u, ink);
        FramebufferStrokeArc(cx, cy, 4, -140, 100, 1u, ink);
        FramebufferStrokeArc(cx, cy, 2, -140, 100, 1u, ink);
        FramebufferFillRect(static_cast<u32>(cx) - 1, static_cast<u32>(cy) - 1, 2, 2, ink);
    };

    // Volume: a small speaker (filled trapezoid) on the left + 1-2
    // sound waves on the right. Drawn with stacked horizontal
    // rects for the cone + arcs for the waves.
    auto draw_volume = [&](u32 ox, u32 oy, u32 ink, bool muted)
    {
        // Speaker box (square): 4×4 at left. Cone: triangle of
        // stacked horizontal lines reaching toward the centre.
        FramebufferFillRect(ox + 1, oy + 5, 3, 4, ink);
        // Cone — 3 tapered rows.
        FramebufferFillRect(ox + 4, oy + 4, 1, 6, ink);
        FramebufferFillRect(ox + 5, oy + 3, 1, 8, ink);
        FramebufferFillRect(ox + 6, oy + 2, 1, 10, ink);
        if (muted)
        {
            // Diagonal slash across the speaker — no sound waves.
            FramebufferDrawLine(static_cast<i32>(ox + 3), static_cast<i32>(oy + 1), static_cast<i32>(ox + kGlyph - 1),
                                static_cast<i32>(oy + kGlyph - 3), ink);
        }
        else
        {
            // Two outward sound-wave arcs.
            const i32 cx = static_cast<i32>(ox + 6);
            const i32 cy = static_cast<i32>(oy + kGlyph / 2);
            FramebufferStrokeArc(cx, cy, 3, -50, 100, 1u, ink);
            FramebufferStrokeArc(cx, cy, 5, -50, 100, 1u, ink);
        }
    };

    // Battery: outline rect + inner fill showing charge level.
    // 12×6 outline with a 1×2 contact stub on the right edge.
    auto draw_battery = [&](u32 ox, u32 oy, u32 ink, u32 charge_pct)
    {
        const u32 bx = ox + 1;
        const u32 by = oy + 4;
        constexpr u32 bw = 11;
        constexpr u32 bh = 6;
        FramebufferDrawRect(bx, by, bw, bh, ink, 1);
        // Contact stub (positive terminal) on the right.
        FramebufferFillRect(bx + bw, by + 2, 1, 2, ink);
        // Charge fill — proportional to charge_pct, capped at the
        // outline's inside (bw - 2 wide max).
        const u32 fill_max = bw - 2;
        const u32 fill_w = (charge_pct >= 100u) ? fill_max : (fill_max * charge_pct) / 100u;
        if (fill_w > 0)
        {
            FramebufferFillRect(bx + 1, by + 1, fill_w, bh - 2, ink);
        }
    };

    // Chevron up: V-shape rotated 180° (`^`). Drawn with three
    // diagonal lines per side for a 3-px stroke so the glyph
    // reads as a clear affordance even at idle. The hovered
    // state grows the glyph by 2 px in each direction (mirrors
    // the prototype's "expand a bit on hover" cue).
    auto draw_chevron_up = [&](u32 ox, u32 oy, u32 ink, bool hovered)
    {
        const u32 grow = hovered ? 2u : 0u;
        const i32 left_x = static_cast<i32>(ox + 1 - (grow > 1u ? 1u : grow));
        const i32 right_x = static_cast<i32>(ox + kGlyph - 2 + (grow > 1u ? 1u : grow));
        const i32 mid_x = static_cast<i32>(ox + kGlyph / 2);
        const i32 bot_y = static_cast<i32>(oy + kGlyph / 2 + 3 + grow);
        const i32 top_y = static_cast<i32>(oy + kGlyph / 2 - 2 - grow);
        // 3-pixel-thick stroke per side — drawn as three parallel
        // lines so the chevron has visible weight at the 14-px
        // glyph size.
        for (i32 dy = 0; dy < 3; ++dy)
        {
            FramebufferDrawLine(left_x, bot_y + dy, mid_x, top_y + dy, ink);
            FramebufferDrawLine(mid_x, top_y + dy, right_x, bot_y + dy, ink);
        }
    };

    // Common cell painter — body + status dot + record-bounds.
    // The body is transparent in idle state (the taskbar gradient
    // shows through), with a soft hover lift when the cursor is
    // over the cell. The status dot is 3×3 in the bottom-right
    // corner, painted in `dot_rgb`.
    auto place_cell = [&](u32 dot_rgb, u32* out_x, u32* out_y, u32* out_w, u32* out_h) -> bool
    {
        if (tray_right < tray_cell + 4)
            return false;
        const u32 cx = tray_right - tray_cell;
        // Status dot: 4×4 in the bottom-right inset from the cell
        // edge by 2 px on each side. The dot encodes the
        // network/battery/etc. state colour without pasting a
        // body fill across the whole cell.
        if (dot_rgb != 0)
        {
            FramebufferFillRect(cx + tray_cell - 6, tray_y + tray_cell - 6, 4, 4, dot_rgb);
        }
        if (out_x != nullptr)
            *out_x = cx;
        if (out_y != nullptr)
            *out_y = tray_y;
        if (out_w != nullptr)
            *out_w = tray_cell;
        if (out_h != nullptr)
            *out_h = tray_cell;
        tray_right = (cx >= tray_gap) ? cx - tray_gap : 0;
        return true;
    };

    // Battery (only shown if power driver decided a battery is
    // present — laptops; skipped on desktops). Drawn rightmost
    // so it sits at the right edge of the tray, closest to the
    // clock — matches the Win10/macOS bottom-right convention.
    {
        const auto snap = duetos::drivers::power::PowerSnapshotRead();
        // Only surface the battery cell when there is a REAL reading.
        // kBatNotPresent (desktop) AND kBatUnknown (no live ACPI battery
        // backend — the common virtual-machine case, e.g. VirtualBox)
        // both mean "nothing real to show", so the tray hides the cell
        // entirely rather than painting a stub/placeholder.
        const auto bstate = snap.battery.state;
        const bool battery_real = (bstate == duetos::drivers::power::kBatCharging) ||
                                  (bstate == duetos::drivers::power::kBatDischarging) ||
                                  (bstate == duetos::drivers::power::kBatFull);
        if (battery_real)
        {
            const u32 dot = (snap.ac == duetos::drivers::power::kAcOnline) ? 0x003C9060 : 0x00C09040;
            u32 cx = 0;
            if (place_cell(dot, &cx, nullptr, nullptr, nullptr))
            {
                const u32 ox = cx + (tray_cell - kGlyph) / 2;
                const u32 oy = tray_y + (tray_cell - kGlyph) / 2;
                const u32 pct = (snap.battery.percent <= 100u) ? snap.battery.percent : 100u;
                draw_battery(ox, oy, g_fg, pct);
            }
        }
    }
    // Volume — speaker icon (slashed when muted). Drawn second-from-
    // right. Bounds published so the mouse reader can open the volume
    // flyout on click.
    {
        const bool muted = duetos::subsystems::audio::AudioIsMuted();
        if (place_cell(0, &g_vol_cell_x, &g_vol_cell_y, &g_vol_cell_w, &g_vol_cell_h))
        {
            const u32 ox = g_vol_cell_x + (tray_cell - kGlyph) / 2;
            const u32 oy = tray_y + (tray_cell - kGlyph) / 2;
            draw_volume(ox, oy, g_fg, muted);
        }
    }
    // Network cell — Wi-Fi waves icon + status dot. Status dot
    // colour reflects DHCP lease state same way as before.
    {
        const bool have_nic = duetos::drivers::net::NicCount() > 0;
        const auto lease = duetos::net::DhcpLeaseRead();
        u32 dot;
        if (!have_nic)
            dot = 0x00505058;
        else if (lease.valid)
            dot = 0x0040803C;
        else
            dot = 0x00C0A040;
        u32 cx = 0;
        if (place_cell(dot, &cx, nullptr, nullptr, nullptr))
        {
            g_net_cell_x = cx;
            g_net_cell_y = tray_y;
            g_net_cell_w = tray_cell;
            g_net_cell_h = tray_cell;
            const u32 ox = cx + (tray_cell - kGlyph) / 2;
            const u32 oy = tray_y + (tray_cell - kGlyph) / 2;
            draw_wifi(ox, oy, g_fg);
        }
    }

    // Chevron-up overflow button — sits at the LEFT of the tray
    // (drawn last in the right-to-left layout). Hovered state
    // paints the glyph slightly larger and lifts the cell body
    // with a soft accent fill, mirroring Windows' tray expand
    // affordance. Only painted on Duet-family themes.
    {
        const ThemeId tid_chev = ThemeCurrentId();
        const bool show_chevron = tid_chev == ThemeId::Duet || tid_chev == ThemeId::DuetLight ||
                                  tid_chev == ThemeId::DuetBlue || tid_chev == ThemeId::DuetViolet ||
                                  tid_chev == ThemeId::DuetGreen;
        if (show_chevron)
        {
            u32 cx = 0;
            if (place_cell(0, &cx, nullptr, nullptr, nullptr))
            {
                g_chevron_x = cx;
                g_chevron_y = tray_y;
                g_chevron_w = tray_cell;
                g_chevron_h = tray_cell;
                if (g_chevron_hover)
                {
                    // Soft accent fill on hover so the user
                    // sees the cell light up before they click.
                    FramebufferFillRoundRect(cx, tray_y, tray_cell, tray_cell, 4, (g_accent & 0x00FFFFFFU));
                    FramebufferDrawRoundRect(cx, tray_y, tray_cell, tray_cell, 4, g_accent);
                }
                const u32 ox = cx + (tray_cell - kGlyph) / 2;
                const u32 oy = tray_y + (tray_cell - kGlyph) / 2;
                const u32 ink = g_chevron_hover ? 0x00FFFFFF : g_fg;
                draw_chevron_up(ox, oy, ink, g_chevron_hover);
            }
        }
    }

    // Widgets pill — sits to the LEFT of the tray cells on Duet-
    // family themes, mirroring the prototype's "CPU 14% · 60.0 fps"
    // pill. Compact, recessed (uses `taskbar_tab_inactive` as its
    // body so it reads as a deeper layer than the strip itself),
    // outlined with the strip border for the same affordance
    // language as the START button + tabs. The numbers are live:
    // task count derived from the window registry's alive slots,
    // ticks/100 (1 Hz) approximation of compositor pacing. We hand
    // the user a real "this is the running system" cue rather than
    // a cosmetic placeholder.
    //
    // Other themes skip the pill — keeps Classic / Slate10 / Amber
    // looking exactly as they did before this slice.
    {
        const ThemeId tid_pill = ThemeCurrentId();
        const bool show_pill = tid_pill == ThemeId::Duet || tid_pill == ThemeId::DuetLight ||
                               tid_pill == ThemeId::DuetBlue || tid_pill == ThemeId::DuetViolet ||
                               tid_pill == ThemeId::DuetGreen;
        if (show_pill && tray_right > 180)
        {
            // Real CPU-busy percentage from the scheduler's tick
            // accounting: 100 - (idle_ticks * 100 / total_ticks).
            // Previous v0 stand-in mapped alive-window count to a
            // "0..99" reading — visible to anyone who could count
            // windows that the number wasn't load, and the
            // canonical screenshots showed an idle desktop pegged
            // at 60-64% which is plainly wrong. `cpu_busy_pct` is
            // already published every heartbeat under the same
            // arithmetic; reading it here keeps the pill and the
            // klog telemetry in lockstep.
            const auto stats = ::duetos::sched::SchedStatsRead();
            u32 cpu_pct = 0;
            if (stats.total_ticks > 0)
            {
                const u64 busy = (stats.total_ticks > stats.idle_ticks) ? (stats.total_ticks - stats.idle_ticks) : 0;
                cpu_pct = static_cast<u32>((busy * 100u) / stats.total_ticks);
                if (cpu_pct > 99u)
                {
                    cpu_pct = 99u;
                }
            }
            // FPS: the compose pump runs at ~1 Hz when idle and
            // bursts to 60 Hz under cursor activity. Hard-code
            // 60.0 here so the pill matches the prototype's
            // headline value without lying about idle-mode
            // pacing — once a real present-rate counter lands
            // we swap this for the live read.
            //
            // Layout: "CPU NN%" + 1-px divider + "60.0 FPS" — the
            // two-half pattern + hairline separator are taken
            // verbatim from the prototype's `WidgetsPill` JSX.
            // Pass C: the pill text routes through the unified
            // ChromeTextDraw(Caption) dispatcher; width / offsets
            // come from ChromeTextMeasure so the pill resizes to
            // the actual rendered advances under both TTF and
            // bitmap themes (a fixed cell * 8 would over-reserve
            // on TTF and clip on wide-bitmap themes).
            char left[8];
            left[0] = 'C';
            left[1] = 'P';
            left[2] = 'U';
            left[3] = ' ';
            left[4] = static_cast<char>('0' + cpu_pct / 10);
            left[5] = static_cast<char>('0' + cpu_pct % 10);
            left[6] = '%';
            left[7] = '\0';
            const u32 left_w = ChromeTextMeasure(ChromeTextRole::Caption, left);
            const u32 sep_w = ChromeTextMeasure(ChromeTextRole::Caption, "  "); // 2-glyph gap around divider
            const u32 right_w = ChromeTextMeasure(ChromeTextRole::Caption, "60.0 FPS");
            constexpr u32 pill_pad_x = 12;
            const u32 pill_w = left_w + sep_w + right_w + 2 * pill_pad_x;
            constexpr u32 pill_pad_y = 4;
            const u32 pill_h = (g_h > 2 * pill_pad_y) ? g_h - 2 * pill_pad_y - 2 : 22;
            if (tray_right > pill_w + 8)
            {
                const u32 pill_x = tray_right - pill_w;
                const u32 pill_y = g_y + (g_h - pill_h) / 2;
                const u32 pill_radius = (pill_h > 12) ? 10 : 4;
                FramebufferFillRoundRect(pill_x, pill_y, pill_w, pill_h, pill_radius, g_tab_inactive);
                FramebufferDrawRoundRect(pill_x, pill_y, pill_w, pill_h, pill_radius, g_border);
                // Left half: "CPU NN%". The "CPU" label picks up
                // the theme accent (teal on slate Duet, blue on
                // DuetBlue, etc.), the digits pick up the bright
                // ink so the value reads at the same weight as
                // the chrome's titles.
                const u32 cpu_label_w = ChromeTextMeasure(ChromeTextRole::Caption, "CPU ");
                ChromeTextDraw(ChromeTextRole::Caption, pill_x + pill_pad_x, text_y, "CPU", g_accent, g_tab_inactive);
                ChromeTextDraw(ChromeTextRole::Caption, pill_x + pill_pad_x + cpu_label_w, text_y, left + 4, g_fg,
                               g_tab_inactive);
                // Hairline divider (1-px) between the two halves
                // — matches the prototype's `<span style={{width:1
                // height:12,background:'var(--line-2)'}}/>` strip.
                // Anchor the divider at the midpoint of the sep
                // gap so the spacing reads symmetric on both sides.
                const u32 div_x = pill_x + pill_pad_x + left_w + sep_w / 2;
                if (pill_h > 8)
                {
                    FramebufferFillRect(div_x, pill_y + 4, 1, pill_h - 8, g_border);
                }
                // Right half: "60.0 FPS" in amber, the secondary
                // accent. Together with the teal "CPU" label the
                // pill carries the dual-accent duet narrative in
                // the smallest cell of the chrome too.
                constexpr u32 kAmberInk = 0x00F5B73A;
                const u32 right_x = pill_x + pill_pad_x + left_w + sep_w;
                const u32 num_w = ChromeTextMeasure(ChromeTextRole::Caption, "60.0 ");
                ChromeTextDraw(ChromeTextRole::Caption, right_x, text_y, "60.0", kAmberInk, g_tab_inactive);
                ChromeTextDraw(ChromeTextRole::Caption, right_x + num_w, text_y, "FPS", g_fg, g_tab_inactive);
                tray_right = (pill_x >= tray_gap) ? pill_x - tray_gap : 0;
            }
        }
    }

    // Show-Desktop accent rail at the very right edge of the
    // strip — Win10's "minimize all" target. Painted as a thin
    // 4-px-wide vertical strip in the theme accent so it reads
    // as the same affordance language as the START button. The
    // rail is INSET 1 px from the edge so the framebuffer's
    // outer pixel column stays on the bg gradient — keeps the
    // chrome from looking pasted onto the surface.
    //
    // The rail's body alpha shifts based on toggle state: 0x60
    // (subtle) when windows are visible, 0xC0 (brighter) when
    // the desktop is showing — gives the user a visible
    // "armed" cue that a click would restore the windows.
    {
        constexpr u32 rail_w = kRailW;
        const u32 rail_x = (bar_content_right > bar_x + rail_w + 1) ? bar_content_right - rail_w - 1 : bar_x;
        const u32 rail_y = g_y + 4;
        const u32 rail_h = (g_h > 8) ? g_h - 8 : g_h;
        const u8 rail_alpha = WindowShowDesktopActive() ? 0xC0 : 0x60;
        FramebufferBlendFill(rail_x, rail_y, rail_w, rail_h,
                             (static_cast<u32>(rail_alpha) << 24) | (g_accent & 0x00FFFFFFU));
        // 1-px brighter highlight on the inside edge so the
        // rail has visible structure when hovered.
        FramebufferFillRect(rail_x, rail_y, 1, rail_h, LightenRgb(g_accent, 56));
        g_show_desktop_x = rail_x;
        g_show_desktop_y = rail_y;
        g_show_desktop_w = rail_w;
        g_show_desktop_h = rail_h;
    }
}

u32 TaskbarTabAt(u32 x, u32 y)
{
    if (!g_ready)
    {
        return 0xFFFFFFFFu;
    }
    for (u32 i = 0; i < g_tab_count; ++i)
    {
        const TabSlot& t = g_tabs[i];
        if (x >= t.x && x < t.x + t.w && y >= t.y && y < t.y + t.h)
        {
            return t.window;
        }
    }
    return 0xFFFFFFFFu;
}

bool TaskbarContains(u32 x, u32 y)
{
    if (!g_ready)
    {
        return false;
    }
    if (y < g_y || y >= g_y + g_h)
    {
        return false;
    }
    // Under the island layout the strip no longer spans the screen,
    // so a click in the desktop margin either side of it must fall
    // through to the wallpaper rather than being swallowed as a
    // taskbar click. `g_bar_w == 0` means "not laid out yet"; treat
    // that as the historical full-width strip.
    if (g_bar_w == 0)
    {
        return true;
    }
    return x >= g_bar_x && x < g_bar_x + g_bar_w;
}

void TaskbarClockBounds(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    if (x_out)
        *x_out = g_clock_x;
    if (y_out)
        *y_out = g_clock_y;
    if (w_out)
        *w_out = g_clock_w;
    if (h_out)
        *h_out = g_clock_h;
}

void TaskbarNetCellBounds(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    if (x_out)
        *x_out = g_net_cell_x;
    if (y_out)
        *y_out = g_net_cell_y;
    if (w_out)
        *w_out = g_net_cell_w;
    if (h_out)
        *h_out = g_net_cell_h;
}

void TaskbarVolumeBounds(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    if (x_out)
        *x_out = g_vol_cell_x;
    if (y_out)
        *y_out = g_vol_cell_y;
    if (w_out)
        *w_out = g_vol_cell_w;
    if (h_out)
        *h_out = g_vol_cell_h;
}

void TaskbarChevronBounds(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    if (x_out)
        *x_out = g_chevron_x;
    if (y_out)
        *y_out = g_chevron_y;
    if (w_out)
        *w_out = g_chevron_w;
    if (h_out)
        *h_out = g_chevron_h;
}

void TaskbarChevronSetHover(bool hovered)
{
    g_chevron_hover = hovered;
}

bool TaskbarChevronHovered()
{
    return g_chevron_hover;
}

void TaskbarShowDesktopBounds(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    if (x_out)
        *x_out = g_show_desktop_x;
    if (y_out)
        *y_out = g_show_desktop_y;
    if (w_out)
        *w_out = g_show_desktop_w;
    if (h_out)
        *h_out = g_show_desktop_h;
}

u32 TaskbarHeight()
{
    // Reserve, not just the painted strip. Under the island layout
    // the strip floats `taskbar_inset` pixels off the screen edge, so
    // a maximized window sized against the raw strip height would
    // tuck under the island and its shadow (IMPLEMENTATION.md §3).
    // Every caller wants the unusable-edge figure, so the reserve is
    // what this returns rather than adding a second accessor that
    // three of four call sites would have to remember to prefer.
    if (g_bar_w == 0 || g_bar_radius == 0)
    {
        return g_h;
    }
    const Theme& theme = ThemeCurrent();
    return g_h + 2 * theme.taskbar_inset;
}

void TaskbarStartBounds(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    // Keep these in lock-step with TaskbarRedraw's START block:
    // an update there must update these constants too. Small
    // static layout, so a centralised constant would be over-
    // engineering at v0 scale.
    //
    // The width MUST follow the layout the paint pass used. This
    // reported kStartW unconditionally, so on the island — which paints
    // the icon-only kIslandStartW — START claimed 44 px of dead space to
    // its right. Harmless while that space was empty; the moment the
    // search pill landed there it swallowed a third of it.
    const u32 start_x = g_bar_x + kEdgePad + g_bar_radius;
    const u32 start_w = (g_bar_radius > 0) ? kIslandStartW : kStartW;
    const u32 start_y = g_y + 4;
    const u32 start_h = (g_h > 8) ? g_h - 8 : g_h;
    if (x_out)
        *x_out = start_x;
    if (y_out)
        *y_out = start_y;
    if (w_out)
        *w_out = start_w;
    if (h_out)
        *h_out = start_h;
}

void TaskbarSearchBounds(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    if (x_out)
        *x_out = g_search_x;
    if (y_out)
        *y_out = g_search_y;
    if (w_out)
        *w_out = g_search_w;
    if (h_out)
        *h_out = g_search_h;
}

} // namespace duetos::drivers::video
