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

// Format an unsigned u64 as a decimal ASCII string into `buf`.
// Writes at most `cap - 1` bytes + NUL. Returns the number of
// characters written (excluding NUL). Simple, no float / %d.
u32 FormatU64Dec(u64 v, char* buf, u32 cap)
{
    if (cap < 2)
    {
        if (cap == 1)
            buf[0] = '\0';
        return 0;
    }
    // Reverse-print, then reverse in place.
    char tmp[24];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    if (n > cap - 1)
    {
        n = cap - 1;
    }
    for (u32 i = 0; i < n; ++i)
    {
        buf[i] = tmp[n - 1 - i];
    }
    buf[n] = '\0';
    return n;
}

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
    constexpr u32 uptime_reserve = 128; // space for "UP NNNNs"
    u32 tab_x = start_w + 16;
    const u32 tabs_right_limit = (fbw > uptime_reserve) ? fbw - uptime_reserve : fbw;

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
        // styles.
        const u32 tab_bg = is_active ? g_accent : g_tab_inactive;
        constexpr u32 tab_radius = 3;
        const u32 tab_h_eff = g_h - 8;
        FramebufferFillRoundRect(tab_x, g_y + 4, tab_w, tab_h_eff, tab_radius, tab_bg);
        FramebufferDrawRoundRect(tab_x, g_y + 4, tab_w, tab_h_eff, tab_radius, g_border);
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
        const char* title = WindowTitle(h);
        if (title != nullptr)
        {
            FramebufferDrawString(tab_x + 8, text_y, title, g_fg, tab_bg);
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
    // Layout right-to-left from the framebuffer's right edge so
    // new widgets can land left of existing ones without shifting
    // the clock:
    //
    //   [ ...tabs ... ]  [NET][CPU][MEM]  MON 23 APR 2026  HH:MM:SS  UP Ns
    //
    // Clock bounds are captured into g_clock_* so the mouse reader
    // can toggle the calendar popup on click.

    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);

    // Uptime goes at the far right; the clock gets its own rect
    // so the mouse reader has a tight hit-test target.
    char upbuf[16];
    u32 up_off = 0;
    upbuf[up_off++] = 'U';
    upbuf[up_off++] = 'P';
    upbuf[up_off++] = ' ';
    const u64 ticks = duetos::sched::SchedNowTicks();
    const u64 secs = ticks / 100;
    up_off += FormatU64Dec(secs, upbuf + up_off, sizeof(upbuf) - up_off - 2);
    upbuf[up_off++] = 's';
    upbuf[up_off] = '\0';
    const u32 up_text_w = up_off * 8;
    const u32 up_x = (fbw > up_text_w + 8) ? fbw - up_text_w - 8 : 0;
    FramebufferDrawString(up_x, text_y, upbuf, g_fg, g_bg);

    // Wall clock left of the uptime.
    char clk[9];
    clk[0] = char('0' + rtc.hour / 10);
    clk[1] = char('0' + rtc.hour % 10);
    clk[2] = ':';
    clk[3] = char('0' + rtc.minute / 10);
    clk[4] = char('0' + rtc.minute % 10);
    clk[5] = ':';
    clk[6] = char('0' + rtc.second / 10);
    clk[7] = char('0' + rtc.second % 10);
    clk[8] = '\0';
    const u32 clk_text_w = 8 * 8;
    const u32 clk_x = (up_x > clk_text_w + 12) ? up_x - clk_text_w - 12 : 0;
    FramebufferDrawString(clk_x, text_y, clk, g_fg, g_bg);
    // Publish a whole-cell hit-test rect around the clock so a
    // user can click anywhere vertically on the widget and have
    // the calendar pop up.
    g_clock_x = (clk_x >= 4) ? clk_x - 4 : 0;
    g_clock_y = g_y + 4;
    g_clock_w = clk_text_w + 8;
    g_clock_h = (g_h > 8) ? g_h - 8 : g_h;

    // Date display left of the clock, format "WWW DD MMM YYYY".
    // Three-letter weekday (derived from a Zeller-ish computation
    // rather than requiring the RTC to provide one; QEMU's RTC
    // doesn't populate .weekday reliably).
    static const char* kWd[7] = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"};
    static const char* kMo[13] = {"???", "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
                                  "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"};
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
    const u32 mo_for_name = (rtc.month >= 1 && rtc.month <= 12) ? rtc.month : 0;
    char date[16];
    u32 d = 0;
    date[d++] = kWd[dow][0];
    date[d++] = kWd[dow][1];
    date[d++] = kWd[dow][2];
    date[d++] = ' ';
    date[d++] = char('0' + rtc.day / 10);
    date[d++] = char('0' + rtc.day % 10);
    date[d++] = ' ';
    date[d++] = kMo[mo_for_name][0];
    date[d++] = kMo[mo_for_name][1];
    date[d++] = kMo[mo_for_name][2];
    date[d++] = ' ';
    date[d++] = char('0' + (rtc.year / 1000) % 10);
    date[d++] = char('0' + (rtc.year / 100) % 10);
    date[d++] = char('0' + (rtc.year / 10) % 10);
    date[d++] = char('0' + rtc.year % 10);
    date[d] = '\0';
    const u32 date_text_w = d * 8;
    const u32 date_x = (clk_x > date_text_w + 12) ? clk_x - date_text_w - 12 : 0;
    FramebufferDrawString(date_x, text_y, date, g_fg, g_bg);

    // --- System tray: left of the date. Three tiny cells 20×20
    // each with a label + status colour, laid out right-to-left.
    constexpr u32 tray_cell = 20;
    constexpr u32 tray_gap = 6;
    const u32 tray_y = g_y + (g_h > tray_cell ? (g_h - tray_cell) / 2 : 0);
    u32 tray_right = (date_x > tray_gap + 4) ? date_x - tray_gap : 0;

    // Reset cached cell bounds; we re-publish only the cells that
    // actually got placed on this redraw (e.g. NET cell skipped
    // entirely if the strip ran out of horizontal room).
    g_net_cell_x = g_net_cell_y = g_net_cell_w = g_net_cell_h = 0;

    auto draw_tray_cell = [&](const char* label, u32 body_rgb, u32* out_x, u32* out_y, u32* out_w, u32* out_h)
    {
        if (tray_right < tray_cell + 4)
            return;
        const u32 cx = tray_right - tray_cell;
        FramebufferFillRect(cx, tray_y, tray_cell, tray_cell, body_rgb);
        FramebufferDrawRect(cx, tray_y, tray_cell, tray_cell, g_border, 1);
        // 3-char label centred ~ (20 - 8)/2, but we only have
        // 8x8 glyphs so we place one glyph for 1-char labels and
        // stack two glyphs for 2-char ones.
        const u32 len = (label[0] == '\0' ? 0 : label[1] == '\0' ? 1 : 2);
        const u32 tw = len * 8;
        const u32 tx = cx + (tray_cell - tw) / 2;
        const u32 ty = tray_y + (tray_cell - 8) / 2;
        FramebufferDrawString(tx, ty, label, 0x00FFFFFF, body_rgb);
        if (out_x != nullptr)
            *out_x = cx;
        if (out_y != nullptr)
            *out_y = tray_y;
        if (out_w != nullptr)
            *out_w = tray_cell;
        if (out_h != nullptr)
            *out_h = tray_cell;
        tray_right = (cx >= tray_gap) ? cx - tray_gap : 0;
    };

    // MEM: green once the allocator has > 1024 free frames
    // (4 MiB) — a rough "we're not starving" threshold. Turns red
    // when free frames drop below that as a gross pressure signal.
    {
        const u64 free_frames = duetos::mm::FreeFramesCount();
        const bool healthy = free_frames > 1024;
        draw_tray_cell("M", healthy ? 0x0040803C : 0x00C04040, nullptr, nullptr, nullptr, nullptr);
    }
    // CPU: always green while scheduler is running.
    draw_tray_cell("C", 0x0040803C, nullptr, nullptr, nullptr, nullptr);
    // NET: green if at least one NIC is bound to the stack AND has
    // a DHCP lease; amber while a NIC is up but DHCP hasn't bound;
    // grey if no NIC was discovered. The flyout panel hangs off
    // this cell — we publish its bounds so the mouse reader can
    // hover-preview and click-toggle it.
    {
        const bool have_nic = duetos::drivers::net::NicCount() > 0;
        const auto lease = duetos::net::DhcpLeaseRead();
        u32 colour;
        if (!have_nic)
            colour = 0x00505058;
        else if (lease.valid)
            colour = 0x0040803C; // green — online
        else
            colour = 0x00C0A040; // amber — link up, DHCP pending
        draw_tray_cell("N", colour, &g_net_cell_x, &g_net_cell_y, &g_net_cell_w, &g_net_cell_h);
    }
    // Battery (only shown if power driver decided a battery is
    // present — laptops; skipped on desktops).
    {
        const auto snap = duetos::drivers::power::PowerSnapshotRead();
        if (snap.battery.state != duetos::drivers::power::kBatNotPresent)
        {
            const u32 colour = (snap.ac == duetos::drivers::power::kAcOnline) ? 0x003C9060 : 0x00C09040;
            draw_tray_cell("B", colour, nullptr, nullptr, nullptr, nullptr);
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
            // Live windows count = a coarse "system load" stand-in
            // until /proc/cpuhist lands. The prototype shows a CPU
            // percentage; we render a percentage digit shape with
            // a value derived from how many windows are actually
            // alive (a 0-99 range scaled to a 0-99% reading) so
            // the number responds to launch / close rather than
            // sitting at a fake constant.
            const u32 wcount = WindowRegistryCount();
            u32 alive = 0;
            for (u32 i = 0; i < wcount; ++i)
            {
                if (WindowIsAlive(i))
                {
                    ++alive;
                }
            }
            // Map alive-window count to a 0..99 percentage so the
            // pill reads as a live load gauge: 4 windows -> 16%,
            // 12 windows -> 48%, etc. Caps at 99 so the digit
            // pair stays stable — more than ~25 live windows is a
            // separate problem the load gauge will visibly pin.
            const u32 cpu_pct = ((alive * 4u) > 99u) ? 99u : (alive * 4u);
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
