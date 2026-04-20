#include "taskbar.h"

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
constinit bool g_ready = false;

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

void TaskbarInit(u32 y, u32 height, u32 bg_rgb, u32 fg_rgb, u32 accent_rgb)
{
    g_y = y;
    g_h = height;
    g_bg = bg_rgb;
    g_fg = fg_rgb;
    g_accent = accent_rgb;
    g_ready = true;
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

    // "START"-style anchor on the left. No click action yet — it's
    // a visual cue that this is a taskbar, not just a coloured band.
    constexpr u32 start_w = 88;
    FramebufferFillRect(4, g_y + 4, start_w, g_h - 8, g_accent);
    FramebufferDrawRect(4, g_y + 4, start_w, g_h - 8, 0x00101828, 1);
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
        const u32 tab_bg = 0x00303848;
        FramebufferFillRect(tab_x, g_y + 4, tab_w, g_h - 8, tab_bg);
        FramebufferDrawRect(tab_x, g_y + 4, tab_w, g_h - 8, 0x00101828, 1);
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

    // Right-anchored uptime. 100 Hz scheduler tick → seconds.
    const u64 ticks = customos::sched::SchedNowTicks();
    const u64 secs = ticks / 100;
    char buf[24];
    // Build "UP " + decimal + "s" in place to keep the font table
    // honest (no %u helper in kernel C++).
    buf[0] = 'U';
    buf[1] = 'P';
    buf[2] = ' ';
    const u32 n = FormatU64Dec(secs, buf + 3, sizeof(buf) - 5);
    buf[3 + n] = 'S';
    buf[3 + n + 1] = '\0';
    const u32 text_w = (3 + n + 1) * 8;
    const u32 text_x = (fbw > text_w + 8) ? fbw - text_w - 8 : 0;
    FramebufferDrawString(text_x, text_y, buf, g_fg, g_bg);
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

} // namespace customos::drivers::video
