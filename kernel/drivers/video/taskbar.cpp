#include "taskbar.h"

#include "../../arch/x86_64/rtc.h"
#include "../../drivers/net/net.h"
#include "../../drivers/power/power.h"
#include "../../mm/frame_allocator.h"
#include "../../sched/sched.h"
#include "framebuffer.h"
#include "widget.h"

namespace customos::drivers::video
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

// Cached clock-widget bounds (recomputed every redraw). Exposed
// via TaskbarClockBounds for the mouse reader's calendar-toggle.
constinit u32 g_clock_x = 0;
constinit u32 g_clock_y = 0;
constinit u32 g_clock_w = 0;
constinit u32 g_clock_h = 0;

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

void TaskbarRedraw()
{
    if (!g_ready || !FramebufferAvailable())
    {
        return;
    }
    const auto info = FramebufferGet();
    const u32 fbw = info.width;

    // Background strip + thin accent line at top for visual
    // separation from the desktop.
    FramebufferFillRect(0, g_y, fbw, g_h, g_bg);
    FramebufferFillRect(0, g_y, fbw, 1, g_accent);

    const u32 text_y = TextRowY();

    // "START" anchor on the left. Clicking it opens the start
    // menu via the mouse reader's TaskbarStartBounds hit-test.
    constexpr u32 start_w = 88;
    FramebufferFillRect(4, g_y + 4, start_w, g_h - 8, g_accent);
    FramebufferDrawRect(4, g_y + 4, start_w, g_h - 8, g_border, 1);
    FramebufferDrawString(4 + (start_w - 5 * 8) / 2, text_y, "START", g_fg, g_accent);

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
        // chrome active/inactive distinction.
        const u32 tab_bg = is_active ? g_accent : g_tab_inactive;
        FramebufferFillRect(tab_x, g_y + 4, tab_w, g_h - 8, tab_bg);
        FramebufferDrawRect(tab_x, g_y + 4, tab_w, g_h - 8, g_border, 1);
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

    customos::arch::RtcTime rtc{};
    customos::arch::RtcRead(&rtc);

    // Uptime goes at the far right; the clock gets its own rect
    // so the mouse reader has a tight hit-test target.
    char upbuf[16];
    u32 up_off = 0;
    upbuf[up_off++] = 'U';
    upbuf[up_off++] = 'P';
    upbuf[up_off++] = ' ';
    const u64 ticks = customos::sched::SchedNowTicks();
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

    auto draw_tray_cell = [&](const char* label, u32 body_rgb)
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
        tray_right = (cx >= tray_gap) ? cx - tray_gap : 0;
    };

    // MEM: green once the allocator has > 1024 free frames
    // (4 MiB) — a rough "we're not starving" threshold. Turns red
    // when free frames drop below that as a gross pressure signal.
    {
        const u64 free_frames = customos::mm::FreeFramesCount();
        const bool healthy = free_frames > 1024;
        draw_tray_cell("M", healthy ? 0x0040803C : 0x00C04040);
    }
    // CPU: always green while scheduler is running.
    draw_tray_cell("C", 0x0040803C);
    // NET: green if at least one NIC was discovered.
    {
        const bool have_nic = customos::drivers::net::NicCount() > 0;
        draw_tray_cell("N", have_nic ? 0x0040803C : 0x00505058);
    }
    // Battery (only shown if power driver decided a battery is
    // present — laptops; skipped on desktops).
    {
        const auto snap = customos::drivers::power::PowerSnapshotRead();
        if (snap.battery.state != customos::drivers::power::kBatNotPresent)
        {
            const u32 colour = (snap.ac == customos::drivers::power::kAcOnline) ? 0x003C9060 : 0x00C09040;
            draw_tray_cell("B", colour);
        }
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

} // namespace customos::drivers::video
