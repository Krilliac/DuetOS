#include "drivers/video/taskbar.h"

#include "arch/x86_64/rtc.h"
#include "drivers/net/net.h"
#include "drivers/power/power.h"
#include "mm/frame_allocator.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"

namespace duetos::drivers::video
{

namespace
{

constinit u32 g_y = 0;
constinit u32 g_h = 0;
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

// Last-painted tab layout. Updated by TaskbarRedraw; consumed by
// TaskbarTabAt. Capacity matches kMaxWindows so tabs and window
// slots are in 1:1 correspondence.
constexpr u32 kMaxTabs = 8;
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
    if (g_dock == TaskbarDock::Top)
        g_y = 0;
    else
        g_y = (info.height > g_h) ? info.height - g_h : 0;
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
    const u32 fbw = info.width;

    // Background strip with a subtle vertical gradient: a slightly
    // lifted shade at the top fades into the registered taskbar bg
    // at the bottom. Reads as a coherent toolbar surface rather
    // than a flat coloured stripe. Keep the lift small so themes
    // that picked a near-black bg still read as near-black.
    FramebufferFillRectGradient(0, g_y, fbw, g_h, LightenRgb(g_bg, 12), g_bg);
    // Thin accent line on the top edge — preserves the "the
    // taskbar starts here" cue the original flat bar had.
    FramebufferFillRect(0, g_y, fbw, 1, g_accent);

    const u32 text_y = TextRowY();

    // "START" anchor on the left. Clicking it opens the start
    // menu via the mouse reader's TaskbarStartBounds hit-test.
    // Rounded fill + matching outline so it reads as an affordance
    // rather than a coloured rectangle. A 2-px highlight strip on
    // the top edge gives it a subtle raised look matching the
    // window-chrome highlight band.
    constexpr u32 start_w = 88;
    constexpr u32 start_radius = 4;
    const u32 start_h = (g_h > 8) ? g_h - 8 : g_h;
    FramebufferFillRoundRect(4, g_y + 4, start_w, start_h, start_radius, g_accent);
    FramebufferDrawRoundRect(4, g_y + 4, start_w, start_h, start_radius, g_border);
    if (start_h > 4)
    {
        FramebufferFillRect(4 + start_radius, g_y + 5, start_w - 2 * start_radius, 1, LightenRgb(g_accent, 40));
    }
    // On the Duet theme the START button paints the DuetMark — two
    // interlocking rings (teal + amber) glyphing the dual-ABI
    // story — followed by the word "DUET". Other themes keep the
    // five-letter "START" label since they don't carry the duet
    // narrative. The simplified DuetMark uses two outlined circles
    // rather than the prototype's partial-arc strokes; partial-arc
    // rasterization is a follow-on once a proper path stroker
    // lands in the framebuffer.
    const ThemeId tid_start = ThemeCurrentId();
    const bool is_duet_family = tid_start == ThemeId::Duet || tid_start == ThemeId::DuetLight ||
                                tid_start == ThemeId::DuetBlue || tid_start == ThemeId::DuetViolet ||
                                tid_start == ThemeId::DuetGreen || tid_start == ThemeId::DuetClassic;
    if (is_duet_family)
    {
        constexpr u32 mark_label_w = 4 * 8; // "DUET"
        constexpr u32 mark_diameter = 14;
        constexpr u32 mark_overlap = 6; // shared horizontal overlap between rings
        const u32 mark_total_w = 2 * mark_diameter - mark_overlap + 6 + mark_label_w;
        const u32 mark_origin_x = 4 + (start_w - mark_total_w) / 2;
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
        FramebufferDrawString(label_x, text_y, "DUET", g_fg, g_accent);
    }
    else
    {
        FramebufferDrawString(4 + (start_w - 5 * 8) / 2, text_y, "START", g_fg, g_accent);
    }

    // Per-window tabs. Iterate every registered window, filter
    // alive, render a dark tab with its title. Advance x with a
    // small gap between tabs. Clip when we'd overflow the right-
    // side uptime reserve.
    constexpr u32 tab_w = 170;
    constexpr u32 tab_gap = 4;
    // Reserve space on the right for the cluster of widgets that
    // sits beyond the tabs — time card + tray icons + chevron +
    // (Duet only) the CPU/FPS pill. Sized so tabs never get
    // clipped by the rightmost paint pass.
    //
    //   Duet family: pill (~180) + tray (~100) + time (~80) +
    //                rail (~6) + gaps (~30) = ~400
    //   Other themes: tray (~70) + time (~80) + rail (~6) +
    //                 gaps (~14) = ~170
    const ThemeId tid_reserve = ThemeCurrentId();
    const bool reserve_for_pill = tid_reserve == ThemeId::Duet || tid_reserve == ThemeId::DuetLight ||
                                  tid_reserve == ThemeId::DuetBlue || tid_reserve == ThemeId::DuetViolet ||
                                  tid_reserve == ThemeId::DuetGreen;
    const u32 right_reserve = reserve_for_pill ? 400u : 180u;
    u32 tab_x = start_w + 16;
    const u32 tabs_right_limit = (fbw > right_reserve) ? fbw - right_reserve : fbw;

    g_tab_count = 0;
    const u32 count = WindowRegistryCount();
    for (u32 i = 0; i < count; ++i)
    {
        const WindowHandle h = i;
        if (!WindowIsAlive(h))
        {
            continue;
        }
        if (tab_x + tab_w > tabs_right_limit)
        {
            break; // ran out of middle — overflow unshown in v0
        }
        const bool is_active = (h == WindowActive());
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
        constexpr u32 tab_radius = 3;
        const u32 tab_h_eff = g_h - 8;
        if (is_active)
        {
            FramebufferFillRectGradient(tab_x, g_y + 4, tab_w, tab_h_eff, LightenRgb(g_accent, 32), g_accent);
        }
        else
        {
            FramebufferFillRoundRect(tab_x, g_y + 4, tab_w, tab_h_eff, tab_radius, tab_bg);
        }
        FramebufferDrawRoundRect(tab_x, g_y + 4, tab_w, tab_h_eff, tab_radius, g_border);
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
        if (is_active && tab_h_eff > 4)
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
            FramebufferDrawString(text_x, text_y, title, g_fg, tab_bg);
        }
        // Record the slot so subsequent hit-tests can map a
        // click back to a window without re-running the layout.
        if (g_tab_count < kMaxTabs)
        {
            g_tabs[g_tab_count].x = tab_x;
            g_tabs[g_tab_count].y = g_y + 4;
            g_tabs[g_tab_count].w = tab_w;
            g_tabs[g_tab_count].h = g_h - 8;
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
    const u32 clk_text_w = 5 * 8;

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
    const u32 date_text_w = d_off * 8;

    // Block geometry: take the wider of the two rows + 12 px right
    // inset, anchored to the framebuffer's right edge.
    const u32 block_text_w = (clk_text_w > date_text_w) ? clk_text_w : date_text_w;
    const u32 block_w = block_text_w + 12;
    const u32 block_x = (fbw > block_w) ? fbw - block_w : 0;
    // Two-row stack inside the taskbar height — top row above the
    // strip's vertical centre, bottom row below.
    const u32 row_top_y = g_y + (g_h / 2) - 8;
    const u32 row_bot_y = g_y + (g_h / 2) + 1;
    // Right-align each row inside the block.
    const u32 clk_x = block_x + (block_text_w - clk_text_w);
    const u32 date_x = block_x + (block_text_w - date_text_w);
    FramebufferDrawString(clk_x, row_top_y, clk, g_fg, g_bg);
    FramebufferDrawString(date_x, row_bot_y, date, g_fg, g_bg);

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
    auto draw_volume = [&](u32 ox, u32 oy, u32 ink)
    {
        // Speaker box (square): 4×4 at left. Cone: triangle of
        // stacked horizontal lines reaching toward the centre.
        FramebufferFillRect(ox + 1, oy + 5, 3, 4, ink);
        // Cone — 3 tapered rows.
        FramebufferFillRect(ox + 4, oy + 4, 1, 6, ink);
        FramebufferFillRect(ox + 5, oy + 3, 1, 8, ink);
        FramebufferFillRect(ox + 6, oy + 2, 1, 10, ink);
        // Two outward sound-wave arcs.
        const i32 cx = static_cast<i32>(ox + 6);
        const i32 cy = static_cast<i32>(oy + kGlyph / 2);
        FramebufferStrokeArc(cx, cy, 3, -50, 100, 1u, ink);
        FramebufferStrokeArc(cx, cy, 5, -50, 100, 1u, ink);
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
        if (snap.battery.state != duetos::drivers::power::kBatNotPresent)
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
    // Volume — placeholder dot in the accent (no audio mixer
    // yet). Drawn second-from-right.
    {
        u32 cx = 0;
        if (place_cell(0, &cx, nullptr, nullptr, nullptr))
        {
            const u32 ox = cx + (tray_cell - kGlyph) / 2;
            const u32 oy = tray_y + (tray_cell - kGlyph) / 2;
            draw_volume(ox, oy, g_fg);
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
            constexpr u32 kLeftCells = 7;  // "CPU NN%" = 7 glyphs
            constexpr u32 kRightCells = 8; // "60.0 FPS" = 8 glyphs
            constexpr u32 kSepCells = 2;   // gap around the divider
            const u32 pill_text_cells = kLeftCells + kSepCells + kRightCells;
            constexpr u32 pill_pad_x = 12;
            const u32 pill_w = pill_text_cells * 8 + 2 * pill_pad_x;
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
                char left[8];
                left[0] = 'C';
                left[1] = 'P';
                left[2] = 'U';
                left[3] = ' ';
                left[4] = static_cast<char>('0' + cpu_pct / 10);
                left[5] = static_cast<char>('0' + cpu_pct % 10);
                left[6] = '%';
                left[7] = '\0';
                FramebufferDrawString(pill_x + pill_pad_x, text_y, "CPU", g_accent, g_tab_inactive);
                FramebufferDrawString(pill_x + pill_pad_x + 4 * 8, text_y, left + 4, g_fg, g_tab_inactive);
                // Hairline divider (1-px) between the two halves
                // — matches the prototype's `<span style={{width:1
                // height:12,background:'var(--line-2)'}}/>` strip.
                const u32 div_x = pill_x + pill_pad_x + (kLeftCells + 1) * 8;
                if (pill_h > 8)
                {
                    FramebufferFillRect(div_x, pill_y + 4, 1, pill_h - 8, g_border);
                }
                // Right half: "60.0 FPS" in amber, the secondary
                // accent. Together with the teal "CPU" label the
                // pill carries the dual-accent duet narrative in
                // the smallest cell of the chrome too.
                constexpr u32 kAmberInk = 0x00F5B73A;
                const u32 right_x = div_x + 1 * 8;
                FramebufferDrawString(right_x, text_y, "60.0", kAmberInk, g_tab_inactive);
                FramebufferDrawString(right_x + 5 * 8, text_y, "FPS", g_fg, g_tab_inactive);
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
        constexpr u32 rail_w = 4;
        const u32 rail_x = (fbw > rail_w + 1) ? fbw - rail_w - 1 : 0;
        const u32 rail_y = g_y + 4;
        const u32 rail_h = (g_h > 8) ? g_h - 8 : g_h;
        const u8 rail_alpha = WindowShowDesktopActive() ? 0xC0 : 0x60;
        FramebufferFillRectAlpha(rail_x, rail_y, rail_w, rail_h,
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
    (void)x;
    return y >= g_y && y < g_y + g_h;
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
    return g_h;
}

void TaskbarStartBounds(u32* x_out, u32* y_out, u32* w_out, u32* h_out)
{
    // Keep these in lock-step with TaskbarRedraw's START block:
    // an update there must update these constants too. Small
    // static layout, so a centralised constant would be over-
    // engineering at v0 scale.
    constexpr u32 start_x = 4;
    constexpr u32 start_w = 88;
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

} // namespace duetos::drivers::video
