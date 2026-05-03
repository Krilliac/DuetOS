#include "apps/calendar.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::apps::calendar
{

namespace
{

using duetos::drivers::video::FramebufferDrawRect;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::ThemeRole;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kCellW = 36;
constexpr u32 kCellH = 26;
constexpr u32 kCols = 7;
constexpr u32 kGridRows = 6;
constexpr u32 kHeaderH = 26;
constexpr u32 kWeekdayH = 16;
constexpr u32 kFooterH = 14;
constexpr u32 kMargin = 8;

constexpr const char* kMonthNames[13] = {
    "???",  "JANUARY", "FEBRUARY",  "MARCH",   "APRIL",    "MAY",      "JUNE",
    "JULY", "AUGUST",  "SEPTEMBER", "OCTOBER", "NOVEMBER", "DECEMBER",
};

constexpr const char* kWeekdayInitials[7] = {"S", "M", "T", "W", "T", "F", "S"};

// Zeller's congruence — file-local copy. The drivers/video/calendar
// popup has its own copy; both are tiny and refusing the dependency
// avoids reaching into the popup module's internals.
u32 DayOfWeek(u32 year, u32 month, u32 day)
{
    if (month < 3)
    {
        month += 12;
        --year;
    }
    const u32 K = year % 100;
    const u32 J = year / 100;
    const u32 h = (day + (13 * (month + 1)) / 5 + K + K / 4 + J / 4 + 5 * J) % 7;
    return (h + 6) % 7; // 0=Sun..6=Sat
}

u32 DaysInMonth(u32 year, u32 month)
{
    switch (month)
    {
    case 1:
    case 3:
    case 5:
    case 7:
    case 8:
    case 10:
    case 12:
        return 31;
    case 4:
    case 6:
    case 9:
    case 11:
        return 30;
    case 2:
    {
        const bool leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        return leap ? 29 : 28;
    }
    default:
        return 0;
    }
}

// Step the displayed year/month by `delta` months. delta may be
// negative (encoded by callers as a signed expression normalised
// here). Wraps year on Jan/Dec boundaries.
void Step(u32& year, u32& month, i32 delta)
{
    // 32-bit arithmetic in a wide accumulator to dodge underflow.
    i64 m = i64(month) + delta - 1;
    i64 dy = m / 12;
    i64 mo = m % 12;
    if (mo < 0)
    {
        mo += 12;
        --dy;
    }
    const i64 ny = i64(year) + dy;
    if (ny < 1)
    {
        year = 1;
        month = 1;
        return;
    }
    if (ny > 9999)
    {
        year = 9999;
        month = 12;
        return;
    }
    year = u32(ny);
    month = u32(mo) + 1;
}

void FormatU16Dec4(char* out, u32 v)
{
    out[0] = char('0' + (v / 1000) % 10);
    out[1] = char('0' + (v / 100) % 10);
    out[2] = char('0' + (v / 10) % 10);
    out[3] = char('0' + v % 10);
    out[4] = '\0';
}

void FormatDayDec(char* out, u32 d, u32& width)
{
    if (d >= 10)
    {
        out[0] = char('0' + (d / 10) % 10);
        out[1] = char('0' + d % 10);
        out[2] = '\0';
        width = 16;
    }
    else
    {
        out[0] = char('0' + d);
        out[1] = '\0';
        width = 8;
    }
}

struct State
{
    WindowHandle handle;
    u32 view_year;
    u32 view_month;
    bool initialised;
};

constinit State g_state = {kWindowInvalid, 2026, 1, false};

// Pull current RTC date into view_year / view_month if the user
// hasn't navigated yet. Called on every paint so the live month is
// always shown until a key is pressed.
void RefreshFromRtcIfFresh()
{
    if (g_state.initialised)
        return;
    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);
    if (rtc.month >= 1 && rtc.month <= 12 && rtc.year >= 1 && rtc.year <= 9999)
    {
        g_state.view_year = rtc.year;
        g_state.view_month = rtc.month;
    }
}

void ResetToToday()
{
    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);
    if (rtc.month >= 1 && rtc.month <= 12)
    {
        g_state.view_year = rtc.year;
        g_state.view_month = rtc.month;
    }
    g_state.initialised = false; // resume tracking the live RTC
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    RefreshFromRtcIfFresh();

    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::Calendar)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 header_bg = th.role_title[static_cast<u32>(ThemeRole::Calendar)];
    const u32 today_accent = th.taskbar_accent;
    const u32 select_dim = th.taskbar_tab_inactive;

    FramebufferFillRect(cx, cy, cw, ch, bg);

    const u32 grid_w = kCols * kCellW;
    const u32 grid_h = kGridRows * kCellH;
    const u32 panel_w = grid_w + 2 * kMargin;
    const u32 panel_h = kHeaderH + kWeekdayH + grid_h + kFooterH + 2 * kMargin;

    if (cw < panel_w + 4 || ch < panel_h + 4)
    {
        FramebufferDrawString(cx + 4, cy + 4, "(WINDOW TOO SMALL)", dim, bg);
        return;
    }

    const u32 ox = cx + (cw - panel_w) / 2;
    const u32 oy = cy + (ch - panel_h) / 2;

    // Header: month + year, centred. Width = "SEPTEMBER 9999" =
    // 14 glyphs × 8 px = 112 px.
    FramebufferFillRect(ox, oy, panel_w, kHeaderH, header_bg);
    {
        char title[24];
        u32 o = 0;
        const char* mn =
            (g_state.view_month >= 1 && g_state.view_month <= 12) ? kMonthNames[g_state.view_month] : "???";
        for (u32 i = 0; mn[i] != '\0' && o + 1 < sizeof(title); ++i)
            title[o++] = mn[i];
        title[o++] = ' ';
        char ybuf[5];
        FormatU16Dec4(ybuf, g_state.view_year);
        for (u32 i = 0; ybuf[i] != '\0' && o + 1 < sizeof(title); ++i)
            title[o++] = ybuf[i];
        title[o] = '\0';
        const u32 title_w = o * 8;
        const u32 tx = ox + (panel_w > title_w ? (panel_w - title_w) / 2 : 0);
        const u32 ty = oy + (kHeaderH - 8) / 2;
        FramebufferDrawString(tx, ty, title, dim, header_bg);
    }

    // Weekday row: SMTWTFS. Each cell is centred under the column.
    {
        const u32 wy = oy + kHeaderH + (kWeekdayH - 8) / 2;
        for (u32 c = 0; c < kCols; ++c)
        {
            const u32 col_x = ox + kMargin + c * kCellW;
            const u32 wx = col_x + (kCellW - 8) / 2;
            FramebufferDrawString(wx, wy, kWeekdayInitials[c], dim, bg);
        }
    }

    // Day grid.
    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);
    const u32 today_year = rtc.year;
    const u32 today_month = rtc.month;
    const u32 today_day = rtc.day;

    const u32 first_dow = DayOfWeek(g_state.view_year, g_state.view_month, 1);
    const u32 month_days = DaysInMonth(g_state.view_year, g_state.view_month);

    // Previous month's tail to fill the leading cells.
    u32 prev_year = g_state.view_year;
    u32 prev_month = g_state.view_month;
    Step(prev_year, prev_month, -1);
    const u32 prev_days = DaysInMonth(prev_year, prev_month);

    const u32 grid_origin_y = oy + kHeaderH + kWeekdayH;
    const u32 grid_origin_x = ox + kMargin;

    for (u32 r = 0; r < kGridRows; ++r)
    {
        for (u32 c = 0; c < kCols; ++c)
        {
            const u32 cell_x = grid_origin_x + c * kCellW;
            const u32 cell_y = grid_origin_y + r * kCellH;

            // Compute the day number this cell shows.
            const i32 ord = i32(r * kCols + c) - i32(first_dow);
            u32 day = 0;
            bool current_month = true;
            u32 cell_year = g_state.view_year;
            u32 cell_month = g_state.view_month;
            if (ord < 0)
            {
                day = u32(i32(prev_days) + ord + 1);
                current_month = false;
                cell_year = prev_year;
                cell_month = prev_month;
            }
            else if (ord >= i32(month_days))
            {
                day = u32(ord - i32(month_days) + 1);
                current_month = false;
                cell_year = g_state.view_year;
                cell_month = g_state.view_month;
                Step(cell_year, cell_month, +1);
            }
            else
            {
                day = u32(ord) + 1;
            }

            const bool is_today = (cell_year == today_year && cell_month == today_month && day == today_day);

            if (is_today)
            {
                FramebufferFillRect(cell_x + 2, cell_y + 2, kCellW - 4, kCellH - 4, today_accent);
            }
            else if (current_month && (c == 0 || c == 6))
            {
                // Faint weekend highlight on the current month so
                // weekends stand out from weekdays.
                FramebufferFillRect(cell_x + 2, cell_y + 2, kCellW - 4, kCellH - 4, select_dim);
            }

            char dbuf[3];
            u32 dw = 0;
            FormatDayDec(dbuf, day, dw);
            const u32 dx = cell_x + (kCellW - dw) / 2;
            const u32 dy = cell_y + (kCellH - 8) / 2;
            const u32 inkbg = is_today ? today_accent : (current_month && (c == 0 || c == 6) ? select_dim : bg);
            const u32 inkfg = current_month ? fg : dim;
            FramebufferDrawString(dx, dy, dbuf, inkfg, inkbg);
        }
    }

    // 1-px frame around the grid for visual lock-in.
    FramebufferDrawRect(grid_origin_x, grid_origin_y, grid_w, grid_h, dim, 1);

    // Footer hint.
    {
        const u32 fy = oy + kHeaderH + kWeekdayH + grid_h + (kFooterH - 8) / 2 + 2;
        FramebufferDrawString(ox + kMargin, fy, "[ ] MONTH   { } YEAR   T TODAY", dim, bg);
    }
}

} // namespace

void CalendarInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.initialised = false;
    g_state.view_year = 2026;
    g_state.view_month = 1;
    WindowSetContentDraw(handle, DrawFn, nullptr);
}

bool CalendarFeedChar(char c)
{
    if (c == '[')
    {
        Step(g_state.view_year, g_state.view_month, -1);
        g_state.initialised = true;
        return true;
    }
    if (c == ']')
    {
        Step(g_state.view_year, g_state.view_month, +1);
        g_state.initialised = true;
        return true;
    }
    if (c == '{')
    {
        Step(g_state.view_year, g_state.view_month, -12);
        g_state.initialised = true;
        return true;
    }
    if (c == '}')
    {
        Step(g_state.view_year, g_state.view_month, +12);
        g_state.initialised = true;
        return true;
    }
    if (c == 'T' || c == 't')
    {
        ResetToToday();
        return true;
    }
    return false;
}

bool CalendarFeedArrow(u16 keycode)
{
    using duetos::drivers::input::kKeyArrowDown;
    using duetos::drivers::input::kKeyArrowLeft;
    using duetos::drivers::input::kKeyArrowRight;
    using duetos::drivers::input::kKeyArrowUp;
    if (keycode == kKeyArrowLeft)
    {
        Step(g_state.view_year, g_state.view_month, -1);
        g_state.initialised = true;
        return true;
    }
    if (keycode == kKeyArrowRight)
    {
        Step(g_state.view_year, g_state.view_month, +1);
        g_state.initialised = true;
        return true;
    }
    if (keycode == kKeyArrowUp)
    {
        Step(g_state.view_year, g_state.view_month, -12);
        g_state.initialised = true;
        return true;
    }
    if (keycode == kKeyArrowDown)
    {
        Step(g_state.view_year, g_state.view_month, +12);
        g_state.initialised = true;
        return true;
    }
    return false;
}

WindowHandle CalendarWindow()
{
    return g_state.handle;
}

void CalendarSelfTest()
{
    using duetos::arch::SerialWrite;
    bool pass = true;

    // 1) Zeller's congruence reference points.
    // Friday 2026-05-01 — DOW=5.
    if (DayOfWeek(2026, 5, 1) != 5)
        pass = false;
    // Sunday 2000-01-01 — DOW=6 in Zeller (Saturday is 6 in our remap... let's check)
    // 2000-01-01 was a Saturday. In our 0=Sun..6=Sat mapping, Sat == 6.
    if (DayOfWeek(2000, 1, 1) != 6)
        pass = false;
    // 2024-02-29 (leap) was a Thursday — DOW=4.
    if (DayOfWeek(2024, 2, 29) != 4)
        pass = false;

    // 2) DaysInMonth coverage.
    if (DaysInMonth(2026, 1) != 31)
        pass = false;
    if (DaysInMonth(2026, 2) != 28)
        pass = false; // not a leap year
    if (DaysInMonth(2024, 2) != 29)
        pass = false; // leap (div 4, not 100)
    if (DaysInMonth(2000, 2) != 29)
        pass = false; // leap (div 400)
    if (DaysInMonth(1900, 2) != 28)
        pass = false; // not leap (div 100, not 400)
    if (DaysInMonth(2026, 4) != 30)
        pass = false;
    if (DaysInMonth(2026, 13) != 0)
        pass = false; // out of range

    // 3) Step navigation across year boundaries.
    {
        u32 y = 2026, m = 1;
        Step(y, m, -1);
        if (y != 2025 || m != 12)
            pass = false;
    }
    {
        u32 y = 2026, m = 12;
        Step(y, m, +1);
        if (y != 2027 || m != 1)
            pass = false;
    }
    {
        u32 y = 2026, m = 6;
        Step(y, m, +12);
        if (y != 2027 || m != 6)
            pass = false;
    }
    {
        u32 y = 2026, m = 6;
        Step(y, m, -12);
        if (y != 2025 || m != 6)
            pass = false;
    }
    {
        u32 y = 2026, m = 1;
        Step(y, m, -25); // back 25 months
        if (y != 2023 || m != 12)
            pass = false;
    }

    // 4) Step clamps year at 1 / 9999.
    {
        u32 y = 1, m = 1;
        Step(y, m, -1);
        if (y != 1 || m != 1)
            pass = false;
    }
    {
        u32 y = 9999, m = 12;
        Step(y, m, +1);
        if (y != 9999 || m != 12)
            pass = false;
    }

    SerialWrite(pass ? "[calendar] self-test OK (zeller + days + step)\n" : "[calendar] self-test FAILED\n");
}

} // namespace duetos::apps::calendar
