#include "drivers/video/calendar.h"

#include "arch/x86_64/rtc.h"
#include "drivers/video/framebuffer.h"

namespace duetos::drivers::video
{

namespace
{

// Panel geometry. 7 columns × (header + weekday-row + 6 rows),
// 22 px per row, 26 px per column — keeps day numbers legible at
// the 8x8 font's native width. Popup is a touch wider than the
// start menu so the 7-column grid doesn't look cramped.
constexpr u32 kCellW = 26;
constexpr u32 kCellH = 22;
constexpr u32 kCols = 7;
constexpr u32 kGridRows = 6;
constexpr u32 kMargin = 6;
constexpr u32 kHeaderH = 26; // month + year
constexpr u32 kWeekdayH = 18;

constexpr u32 kPanelW = kMargin * 2 + kCellW * kCols;
constexpr u32 kPanelH = kMargin * 2 + kHeaderH + kWeekdayH + kCellH * kGridRows;

// Theme-driven chrome palette. Defaults match the original
// hardcoded slate-blue look so a kernel that never calls
// CalendarSetColours sees the v0 popup unchanged. ThemeApplyToAll
// rewrites these per-theme.
constinit u32 g_body_rgb = 0x00303848;
constinit u32 g_border_rgb = 0x00101828;
constinit u32 g_header_rgb = 0x00406090;
constinit u32 g_ink_rgb = 0x00FFFFFF;

// Semantic indicators — kept hardcoded across themes since
// "today" / "other-month dim" carry meaning independent of palette.
constexpr u32 kTodayRgb = 0x0054C06A; // accent green for today
constexpr u32 kDimRgb = 0x00707884;

// Saturating per-channel lighten — file-local copy of the helper
// in widget.cpp / taskbar.cpp / menu.cpp.
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

constinit bool g_open = false;
constinit u32 g_ax = 0;
constinit u32 g_ay = 0;

const char* kMonthNames[13] = {
    "???", "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
};

// Zeller's congruence, normal-form variant: return 0=Sun..6=Sat
// for a given Gregorian (year, month, day). month must be 1..12.
u32 DayOfWeek(u32 year, u32 month, u32 day)
{
    // Shift Jan/Feb into months 13/14 of the previous year so
    // February's length lines up naturally.
    if (month < 3)
    {
        month += 12;
        --year;
    }
    const u32 K = year % 100;
    const u32 J = year / 100;
    // h: 0 = Sat, 1 = Sun, ..., 6 = Fri
    const u32 h = (day + (13 * (month + 1)) / 5 + K + K / 4 + J / 4 + 5 * J) % 7;
    // Re-map to 0=Sun..6=Sat.
    return (h + 6) % 7;
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

void FormatU16Dec(char* out, u16 v)
{
    // 4-digit year with leading zeros.
    out[0] = char('0' + (v / 1000) % 10);
    out[1] = char('0' + (v / 100) % 10);
    out[2] = char('0' + (v / 10) % 10);
    out[3] = char('0' + v % 10);
    out[4] = '\0';
}

} // namespace

void CalendarSetColours(u32 body_rgb, u32 border_rgb, u32 header_rgb, u32 ink_rgb)
{
    g_body_rgb = body_rgb;
    g_border_rgb = border_rgb;
    g_header_rgb = header_rgb;
    g_ink_rgb = ink_rgb;
}

void CalendarOpen(u32 ax, u32 ay)
{
    g_ax = ax;
    g_ay = ay;
    g_open = true;
}

void CalendarClose()
{
    g_open = false;
}

bool CalendarIsOpen()
{
    return g_open;
}

u32 CalendarPanelWidth()
{
    return kPanelW;
}

u32 CalendarPanelHeight()
{
    return kPanelH;
}

void CalendarRedraw()
{
    if (!g_open)
        return;

    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);

    u32 year = rtc.year;
    u32 month = rtc.month;
    u32 today = rtc.day;
    if (month < 1 || month > 12)
    {
        month = 1;
        today = 0;
    }

    // Drop shadow first so the popup reads as raised — same depth
    // + alpha as window chrome / start menu for visual consistency.
    FramebufferDropShadow(g_ax, g_ay, kPanelW, kPanelH, 4, 0x60);

    // Body: subtle vertical gradient from a lifted shade of the
    // theme body to the body itself. Matches the menu / taskbar
    // chrome polish.
    FramebufferFillRectGradient(g_ax, g_ay, kPanelW, kPanelH, LightenRgb(g_body_rgb, 14), g_body_rgb);
    // 1-px highlight ridge along the inside of the top border.
    if (kPanelW > 4)
    {
        FramebufferFillRect(g_ax + 2, g_ay + 1, kPanelW - 4, 1, LightenRgb(g_body_rgb, 36));
    }
    FramebufferDrawRect(g_ax, g_ay, kPanelW, kPanelH, g_border_rgb, 1);

    // Header: coloured bar + "MMM YYYY" centred.
    FramebufferFillRect(g_ax + kMargin, g_ay + kMargin, kPanelW - kMargin * 2, kHeaderH, g_header_rgb);
    char ybuf[5];
    FormatU16Dec(ybuf, u16(year));
    // "APR 2026" = 8 glyphs × 8 px = 64 px.
    char title[9];
    title[0] = kMonthNames[month][0];
    title[1] = kMonthNames[month][1];
    title[2] = kMonthNames[month][2];
    title[3] = ' ';
    title[4] = ybuf[0];
    title[5] = ybuf[1];
    title[6] = ybuf[2];
    title[7] = ybuf[3];
    title[8] = '\0';
    const u32 title_w = 8 * 8;
    const u32 title_x = g_ax + (kPanelW - title_w) / 2;
    const u32 title_y = g_ay + kMargin + (kHeaderH - 8) / 2;
    FramebufferDrawString(title_x, title_y, title, g_ink_rgb, g_header_rgb);

    // Weekday initials row.
    const char* kWeek = "SMTWTFS";
    const u32 week_y = g_ay + kMargin + kHeaderH;
    for (u32 c = 0; c < kCols; ++c)
    {
        char one[2];
        one[0] = kWeek[c];
        one[1] = '\0';
        const u32 cx = g_ax + kMargin + c * kCellW + (kCellW - 8) / 2;
        const u32 cy = week_y + (kWeekdayH - 8) / 2;
        FramebufferDrawString(cx, cy, one, kDimRgb, g_body_rgb);
    }

    // Grid.
    const u32 first_dow = DayOfWeek(year, month, 1);
    const u32 days = DaysInMonth(year, month);
    const u32 grid_top = week_y + kWeekdayH;
    for (u32 r = 0; r < kGridRows; ++r)
    {
        for (u32 c = 0; c < kCols; ++c)
        {
            const u32 slot = r * kCols + c;
            if (slot < first_dow || slot >= first_dow + days)
                continue;
            const u32 day = slot - first_dow + 1;
            const u32 cx = g_ax + kMargin + c * kCellW;
            const u32 cy = grid_top + r * kCellH;
            const bool is_today = (day == today);
            if (is_today)
                FramebufferFillRect(cx + 1, cy + 1, kCellW - 2, kCellH - 2, kTodayRgb);

            // Two-char right-aligned day number.
            char buf[3];
            if (day < 10)
            {
                buf[0] = ' ';
                buf[1] = char('0' + day);
            }
            else
            {
                buf[0] = char('0' + day / 10);
                buf[1] = char('0' + day % 10);
            }
            buf[2] = '\0';
            const u32 text_x = cx + (kCellW - 16) / 2;
            const u32 text_y = cy + (kCellH - 8) / 2;
            FramebufferDrawString(text_x, text_y, buf, g_ink_rgb, is_today ? kTodayRgb : g_body_rgb);
        }
    }
}

bool CalendarContains(u32 x, u32 y)
{
    if (!g_open)
        return false;
    return x >= g_ax && x < g_ax + kPanelW && y >= g_ay && y < g_ay + kPanelH;
}

} // namespace duetos::drivers::video
