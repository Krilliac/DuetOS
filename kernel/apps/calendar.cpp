#include "apps/calendar.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/dialog.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "fs/fat32.h"
#include "util/datetime.h"

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
using duetos::util::IsoWeekDate;
using duetos::util::IsoYearWeek;

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
    // User-selected day. `sel_year` == 0 means "no selection".
    // The selection survives view changes — paging months still
    // remembers what day the user clicked.
    u32 sel_year;
    u32 sel_month;
    u32 sel_day;
};

constinit State g_state = {kWindowInvalid, 2026, 1, false, 0, 0, 0};

// In-RAM event store. Each entry pins an event to a specific
// date. v0 has no persistence — events vanish at reboot. The
// kMaxEvents / kEventTextCap caps come from the public header
// so callers (the dialog flow in main.cpp) can size buffers
// against them.
struct StoredEvent
{
    u32 year;
    u8 month;
    u8 day;
    u8 _pad[2];
    char text[kEventTextCap + 1]; // NUL-terminated
};

constinit StoredEvent g_events[kMaxEvents] = {};
constinit u32 g_event_count = 0;

bool ValidDate(u32 year, u8 month, u8 day)
{
    if (month < 1 || month > 12 || day < 1 || day > 31)
        return false;
    // Cheap upper-bound check — month-day validity is fully
    // covered by the calendar's existing DaysInMonth helper at
    // the renderer; the events store doesn't need to re-derive
    // leap-year semantics. Year > 0 also rejects the "no
    // selection" sentinel value.
    if (year == 0)
        return false;
    return true;
}

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
        char title[40];
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
        // ISO week-of-year for the first day of the displayed month.
        // ISO weeks straddle calendar-year boundaries, so the printed
        // year is iso.year (which can be view_year-1 in early January
        // or view_year+1 in late December — see ISO 8601:2019 §4.4.4).
        if (g_state.view_month >= 1 && g_state.view_month <= 12)
        {
            const IsoWeekDate iso = IsoYearWeek(i32(g_state.view_year), u8(g_state.view_month), 1);
            if (iso.week >= 1 && iso.week <= 53 && o + 8 < sizeof(title))
            {
                const char sep[6] = {' ', '-', ' ', 'W', 'k', ' '};
                for (u32 i = 0; i < sizeof(sep) && o + 1 < sizeof(title); ++i)
                    title[o++] = sep[i];
                if (iso.week >= 10)
                    title[o++] = char('0' + (iso.week / 10));
                title[o++] = char('0' + (iso.week % 10));
            }
        }
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
            const bool is_selected = (g_state.sel_year != 0) && (cell_year == g_state.sel_year) &&
                                     (cell_month == g_state.sel_month) && (day == g_state.sel_day);

            if (is_selected)
            {
                // Selection: outlined fill in the theme accent so
                // it reads distinctly from the today-highlight.
                FramebufferFillRect(cell_x + 2, cell_y + 2, kCellW - 4, kCellH - 4, today_accent);
                FramebufferDrawRect(cell_x + 1, cell_y + 1, kCellW - 2, kCellH - 2, fg, 1);
            }
            else if (is_today)
            {
                FramebufferFillRect(cell_x + 2, cell_y + 2, kCellW - 4, kCellH - 4, today_accent);
            }
            else if (current_month && (c == 0 || c == 6))
            {
                FramebufferFillRect(cell_x + 2, cell_y + 2, kCellW - 4, kCellH - 4, select_dim);
            }

            char dbuf[3];
            u32 dw = 0;
            FormatDayDec(dbuf, day, dw);
            const u32 dx = cell_x + (kCellW - dw) / 2;
            const u32 dy = cell_y + (kCellH - 8) / 2;
            const u32 inkbg =
                (is_selected || is_today) ? today_accent : (current_month && (c == 0 || c == 6) ? select_dim : bg);
            const u32 inkfg = current_month ? fg : dim;
            FramebufferDrawString(dx, dy, dbuf, inkfg, inkbg);

            // Event indicator: 3x3 dot in the bottom-right of
            // the cell when the date has at least one event.
            // Skipped on cells from adjacent months — keeps the
            // indicator anchored to the visually-active month.
            if (current_month && CalendarHasEvent(cell_year, static_cast<u8>(cell_month), static_cast<u8>(day)))
            {
                const u32 dot_x = cell_x + kCellW - 6;
                const u32 dot_y = cell_y + kCellH - 6;
                // Use the foreground colour for visibility — the
                // selection / today highlights already shift the
                // cell background, so a pure-fg dot stands out
                // against either tone.
                FramebufferFillRect(dot_x, dot_y, 3, 3, fg);
            }
        }
    }

    // 1-px frame around the grid for visual lock-in.
    FramebufferDrawRect(grid_origin_x, grid_origin_y, grid_w, grid_h, dim, 1);

    // Footer hint + selected-date event preview when applicable.
    {
        const u32 fy = oy + kHeaderH + kWeekdayH + grid_h + (kFooterH - 8) / 2 + 2;
        char ev_buf[kEventTextCap + 1] = {};
        const bool has_ev =
            (g_state.sel_year != 0) && CalendarFirstEventText(g_state.sel_year, static_cast<u8>(g_state.sel_month),
                                                              static_cast<u8>(g_state.sel_day), ev_buf, sizeof(ev_buf));
        if (has_ev)
        {
            // Show the first event's text on the footer row,
            // prefixed with a small "*" to make it visually
            // distinct from the static binding hint.
            char line[kEventTextCap + 8];
            u32 o = 0;
            const char* lead = "* ";
            while (*lead != '\0' && o + 1 < sizeof(line))
                line[o++] = *lead++;
            for (u32 i = 0; ev_buf[i] != '\0' && o + 1 < sizeof(line); ++i)
                line[o++] = ev_buf[i];
            line[o] = '\0';
            FramebufferDrawString(ox + kMargin, fy, line, fg, bg);
        }
        else
        {
            FramebufferDrawString(ox + kMargin, fy, "[ ] MONTH  { } YEAR  T TODAY  ENTER ADD  DEL REMOVE", dim, bg);
        }
    }
}

} // namespace

bool CalendarOnClick(duetos::u32 cx, duetos::u32 cy)
{
    using duetos::drivers::video::WindowGetBounds;
    if (g_state.handle == kWindowInvalid)
        return false;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return false;
    // Mirror DrawFn's geometry. Window chrome eats 22 px title +
    // 2 px borders (the same constants the chrome path uses).
    constexpr duetos::u32 kTitle = 22;
    constexpr duetos::u32 kBorder = 2;
    if (wh < kTitle + 2 * kBorder)
        return false;
    const duetos::u32 client_x = wx + kBorder;
    const duetos::u32 client_y = wy + kTitle + kBorder;
    const duetos::u32 client_w = (ww > 2 * kBorder) ? ww - 2 * kBorder : 0;
    const duetos::u32 client_h = (wh > kTitle + 2 * kBorder) ? wh - kTitle - 2 * kBorder : 0;
    const duetos::u32 grid_w = kCols * kCellW;
    const duetos::u32 grid_h = kGridRows * kCellH;
    const duetos::u32 panel_w = grid_w + 2 * kMargin;
    const duetos::u32 panel_h = kHeaderH + kWeekdayH + grid_h + kFooterH + 2 * kMargin;
    if (client_w < panel_w + 4 || client_h < panel_h + 4)
        return false;
    const duetos::u32 ox = client_x + (client_w - panel_w) / 2;
    const duetos::u32 oy = client_y + (client_h - panel_h) / 2;
    const duetos::u32 grid_origin_x = ox + kMargin;
    const duetos::u32 grid_origin_y = oy + kHeaderH + kWeekdayH;
    if (cx < grid_origin_x || cx >= grid_origin_x + grid_w)
        return false;
    if (cy < grid_origin_y || cy >= grid_origin_y + grid_h)
        return false;
    const duetos::u32 r = (cy - grid_origin_y) / kCellH;
    const duetos::u32 c = (cx - grid_origin_x) / kCellW;
    // Re-derive the cell's (year, month, day) using the same
    // ord arithmetic DrawFn uses.
    const duetos::u32 first_dow = DayOfWeek(g_state.view_year, g_state.view_month, 1);
    const duetos::u32 month_days = DaysInMonth(g_state.view_year, g_state.view_month);
    duetos::u32 prev_year = g_state.view_year;
    duetos::u32 prev_month = g_state.view_month;
    Step(prev_year, prev_month, -1);
    const duetos::u32 prev_days = DaysInMonth(prev_year, prev_month);
    const duetos::i32 ord = duetos::i32(r * kCols + c) - duetos::i32(first_dow);
    duetos::u32 day = 0;
    duetos::u32 cell_year = g_state.view_year;
    duetos::u32 cell_month = g_state.view_month;
    if (ord < 0)
    {
        day = duetos::u32(duetos::i32(prev_days) + ord + 1);
        cell_year = prev_year;
        cell_month = prev_month;
    }
    else if (ord >= duetos::i32(month_days))
    {
        day = duetos::u32(ord - duetos::i32(month_days) + 1);
        cell_year = g_state.view_year;
        cell_month = g_state.view_month;
        Step(cell_year, cell_month, +1);
    }
    else
    {
        day = duetos::u32(ord) + 1;
    }
    g_state.sel_year = cell_year;
    g_state.sel_month = cell_month;
    g_state.sel_day = day;
    duetos::arch::SerialWrite("[calendar] click select day=");
    duetos::arch::SerialWriteHex(day);
    duetos::arch::SerialWrite(" month=");
    duetos::arch::SerialWriteHex(cell_month);
    duetos::arch::SerialWrite(" year=");
    duetos::arch::SerialWriteHex(cell_year);
    duetos::arch::SerialWrite("\n");
    return true;
}

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
    if (static_cast<u8>(c) == 0x0A) // Enter — add event for active date
    {
        duetos::drivers::video::InputBoxOpen(
            "ADD EVENT", "Event text:", "",
            [](duetos::drivers::video::DialogResult r, const char* text, void*)
            {
                if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr || text[0] == '\0')
                    return;
                const bool ok = CalendarAddEventForSelected(text);
                duetos::drivers::video::NotifyShow(ok ? "calendar: event added" : "calendar: event store full");
            },
            nullptr);
        return true;
    }
    if (static_cast<u8>(c) == 0x7F || static_cast<u8>(c) == 0x08) // Delete / Backspace
    {
        const u32 n = CalendarRemoveEventsForSelected();
        if (n > 0)
            duetos::drivers::video::NotifyShow("calendar: event removed");
        return true;
    }
    return false;
}

// Step the active selection by `days` days. If no selection is
// set, seeds it from today's RTC date. Wraps month / year on
// boundaries; the displayed view follows so the cell is always
// visible. Used by the Shift+arrow day-navigation path.
void StepSelectionByDays(i32 days)
{
    u32 y;
    u8 m;
    u8 d;
    if (g_state.sel_year == 0)
    {
        duetos::arch::RtcTime rtc{};
        duetos::arch::RtcRead(&rtc);
        y = rtc.year;
        m = rtc.month;
        d = rtc.day;
    }
    else
    {
        y = g_state.sel_year;
        m = static_cast<u8>(g_state.sel_month);
        d = static_cast<u8>(g_state.sel_day);
    }
    // Apply the delta in calendar-correct steps. Forward and
    // backward use the same loop so the wrap rules are shared.
    while (days > 0)
    {
        const u32 m_days = DaysInMonth(y, m);
        if (d < m_days)
        {
            ++d;
        }
        else
        {
            d = 1;
            if (m < 12)
            {
                ++m;
            }
            else
            {
                m = 1;
                if (y < 9999)
                    ++y;
            }
        }
        --days;
    }
    while (days < 0)
    {
        if (d > 1)
        {
            --d;
        }
        else
        {
            if (m > 1)
            {
                --m;
            }
            else
            {
                m = 12;
                if (y > 1)
                    --y;
            }
            d = static_cast<u8>(DaysInMonth(y, m));
        }
        ++days;
    }
    g_state.sel_year = y;
    g_state.sel_month = m;
    g_state.sel_day = d;
    g_state.view_year = y;
    g_state.view_month = m;
    g_state.initialised = true;
}

bool CalendarFeedArrow(u16 keycode, u8 modifiers)
{
    using duetos::drivers::input::kKeyArrowDown;
    using duetos::drivers::input::kKeyArrowLeft;
    using duetos::drivers::input::kKeyArrowRight;
    using duetos::drivers::input::kKeyArrowUp;
    using duetos::drivers::input::kKeyModShift;
    using duetos::drivers::input::kKeyPageDown;
    using duetos::drivers::input::kKeyPageUp;
    const bool shift = (modifiers & kKeyModShift) != 0;
    // Shift+arrows = day-cell navigation (matches macOS
    // Calendar). Plain arrows keep their original month / year
    // step semantics so existing muscle memory is preserved.
    if (shift)
    {
        if (keycode == kKeyArrowLeft)
        {
            StepSelectionByDays(-1);
            return true;
        }
        if (keycode == kKeyArrowRight)
        {
            StepSelectionByDays(+1);
            return true;
        }
        if (keycode == kKeyArrowUp)
        {
            StepSelectionByDays(-7);
            return true;
        }
        if (keycode == kKeyArrowDown)
        {
            StepSelectionByDays(+7);
            return true;
        }
    }
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
    // Up/Down and PageUp/PageDown both step a year. PageUp/Dn
    // matches calendar-app muscle memory; Up/Dn matches v0's
    // existing binding so neither breaks for current users.
    if (keycode == kKeyArrowUp || keycode == kKeyPageUp)
    {
        Step(g_state.view_year, g_state.view_month, -12);
        g_state.initialised = true;
        return true;
    }
    if (keycode == kKeyArrowDown || keycode == kKeyPageDown)
    {
        Step(g_state.view_year, g_state.view_month, +12);
        g_state.initialised = true;
        return true;
    }
    if (keycode == duetos::drivers::input::kKeyDelete)
    {
        const u32 n = CalendarRemoveEventsForSelected();
        if (n > 0)
            duetos::drivers::video::NotifyShow("calendar: event removed");
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

    // Event store round-trip: add 3 events, query, remove,
    // verify the table is back to the pre-test count.
    const u32 saved_event_count = g_event_count;
    g_event_count = 0;
    if (!CalendarAddEvent(2026, 5, 7, "DENTIST"))
        pass = false;
    if (!CalendarAddEvent(2026, 5, 14, "TAXES"))
        pass = false;
    if (!CalendarAddEvent(2026, 5, 7, "MEETING")) // 2nd event same day
        pass = false;
    if (!CalendarHasEvent(2026, 5, 7) || !CalendarHasEvent(2026, 5, 14))
        pass = false;
    if (CalendarHasEvent(2026, 5, 8))
        pass = false;
    char ebuf[kEventTextCap + 1];
    if (!CalendarFirstEventText(2026, 5, 7, ebuf, sizeof(ebuf)))
        pass = false;
    // First event on 5/7 should be "DENTIST" — order of insertion
    // is preserved by CalendarAddEvent's append-only contract.
    if (ebuf[0] != 'D' || ebuf[1] != 'E' || ebuf[2] != 'N')
        pass = false;
    const u32 removed = CalendarRemoveEvents(2026, 5, 7);
    if (removed != 2 || CalendarHasEvent(2026, 5, 7))
        pass = false;
    CalendarRemoveEvents(2026, 5, 14);
    if (g_event_count != 0)
        pass = false;
    g_event_count = saved_event_count;
    SerialWrite(pass ? "[calendar] self-test OK (zeller + days + step + events)\n" : "[calendar] self-test FAILED\n");
}

bool CalendarAddEvent(u32 year, u8 month, u8 day, const char* text)
{
    if (!ValidDate(year, month, day) || text == nullptr || text[0] == '\0')
        return false;
    if (g_event_count >= kMaxEvents)
        return false;
    StoredEvent& e = g_events[g_event_count++];
    e.year = year;
    e.month = month;
    e.day = day;
    u32 i = 0;
    for (; i < kEventTextCap && text[i] != '\0'; ++i)
        e.text[i] = text[i];
    e.text[i] = '\0';
    return true;
}

u32 CalendarRemoveEvents(u32 year, u8 month, u8 day)
{
    if (!ValidDate(year, month, day))
        return 0;
    u32 removed = 0;
    u32 j = 0;
    for (u32 i = 0; i < g_event_count; ++i)
    {
        const StoredEvent& e = g_events[i];
        if (e.year == year && e.month == month && e.day == day)
        {
            ++removed;
            continue;
        }
        if (j != i)
            g_events[j] = e;
        ++j;
    }
    g_event_count = j;
    return removed;
}

bool CalendarHasEvent(u32 year, u8 month, u8 day)
{
    if (!ValidDate(year, month, day))
        return false;
    for (u32 i = 0; i < g_event_count; ++i)
    {
        const StoredEvent& e = g_events[i];
        if (e.year == year && e.month == month && e.day == day)
            return true;
    }
    return false;
}

bool CalendarFirstEventText(u32 year, u8 month, u8 day, char* out, u32 cap)
{
    if (out == nullptr || cap == 0 || cap < kEventTextCap + 1)
        return false;
    if (!ValidDate(year, month, day))
        return false;
    for (u32 i = 0; i < g_event_count; ++i)
    {
        const StoredEvent& e = g_events[i];
        if (e.year == year && e.month == month && e.day == day)
        {
            u32 k = 0;
            for (; k < kEventTextCap && e.text[k] != '\0'; ++k)
                out[k] = e.text[k];
            out[k] = '\0';
            return true;
        }
    }
    return false;
}

bool CalendarSelection(u32* year, u8* month, u8* day)
{
    if (year)
        *year = 0;
    if (month)
        *month = 0;
    if (day)
        *day = 0;
    if (g_state.sel_year == 0)
        return false;
    if (year)
        *year = g_state.sel_year;
    if (month)
        *month = static_cast<u8>(g_state.sel_month);
    if (day)
        *day = static_cast<u8>(g_state.sel_day);
    return true;
}

// Helper: derive (year, month, day) for the "active" date —
// either the user's selection, or today's RTC date as a fallback.
void ActiveDate(u32* y, u8* m, u8* d)
{
    if (g_state.sel_year != 0)
    {
        *y = g_state.sel_year;
        *m = static_cast<u8>(g_state.sel_month);
        *d = static_cast<u8>(g_state.sel_day);
        return;
    }
    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);
    *y = rtc.year;
    *m = rtc.month;
    *d = rtc.day;
}

bool CalendarAddEventForSelected(const char* text)
{
    u32 y;
    u8 m, d;
    ActiveDate(&y, &m, &d);
    return CalendarAddEvent(y, m, d, text);
}

u32 CalendarRemoveEventsForSelected()
{
    u32 y;
    u8 m, d;
    ActiveDate(&y, &m, &d);
    return CalendarRemoveEvents(y, m, d);
}

u32 CalendarEventCount()
{
    return g_event_count;
}

bool CalendarEventAt(u32 index, u32* year, u8* month, u8* day, char* text_out, u32 text_cap)
{
    if (index >= g_event_count)
        return false;
    const StoredEvent& e = g_events[index];
    if (year)
        *year = e.year;
    if (month)
        *month = e.month;
    if (day)
        *day = e.day;
    if (text_out != nullptr && text_cap > 0)
    {
        u32 i = 0;
        for (; i + 1 < text_cap && i < kEventTextCap && e.text[i] != '\0'; ++i)
            text_out[i] = e.text[i];
        text_out[i] = '\0';
    }
    return true;
}

namespace
{

// Persistence path on the FAT32 root volume. 8.3 form to keep
// the LFN-emission path off this slice's surface; mirrors the
// convention NOTES.TXT uses.
constexpr const char kSaveFile[] = "CALENDAR.TXT";
constexpr const char kTmpFile[] = "CALENDAR.TMP";
// One-line buffer size: "YYYY-MM-DD\t" + kEventTextCap + "\n" + "\0".
constexpr u32 kLineMax = 4 + 1 + 2 + 1 + 2 + 1 + kEventTextCap + 2;
// Whole-file buffer: kMaxEvents * kLineMax with a small safety pad.
constexpr u32 kFileBufCap = kMaxEvents * (kLineMax + 1) + 16;

void EmitU32(char* out, u32& o, u32 cap, u32 v, u32 width)
{
    char tmp[12];
    u32 n = 0;
    if (v == 0)
        tmp[n++] = '0';
    else
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    while (n < width && n < sizeof(tmp))
        tmp[n++] = '0';
    while (n > 0 && o + 1 < cap)
        out[o++] = tmp[--n];
}

bool ParseU32(const char* s, u32 len, u32& out)
{
    if (len == 0)
        return false;
    u32 v = 0;
    for (u32 i = 0; i < len; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + static_cast<u32>(s[i] - '0');
    }
    out = v;
    return true;
}

} // namespace

bool CalendarSave()
{
    namespace fat = duetos::fs::fat32;
    using duetos::arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[calendar] save: no FAT32 volume mounted\n");
        return false;
    }
    // Serialise to a single byte-buffer first, then ship via the
    // atomic create-tmp + rename path that NotesSave uses.
    char buf[kFileBufCap];
    u32 o = 0;
    for (u32 i = 0; i < g_event_count; ++i)
    {
        const StoredEvent& e = g_events[i];
        if (o + kLineMax >= sizeof(buf))
            break; // hard cap — leave the rest for next save
        EmitU32(buf, o, sizeof(buf), e.year, 4);
        if (o + 1 < sizeof(buf))
            buf[o++] = '-';
        EmitU32(buf, o, sizeof(buf), e.month, 2);
        if (o + 1 < sizeof(buf))
            buf[o++] = '-';
        EmitU32(buf, o, sizeof(buf), e.day, 2);
        if (o + 1 < sizeof(buf))
            buf[o++] = '\t';
        for (u32 k = 0; k < kEventTextCap && e.text[k] != '\0' && o + 1 < sizeof(buf); ++k)
            buf[o++] = e.text[k];
        if (o + 1 < sizeof(buf))
            buf[o++] = '\n';
    }
    // Drop a stale CALENDAR.TMP so the create succeeds.
    fat::DirEntry tmp_existing;
    if (fat::Fat32LookupPath(v, kTmpFile, &tmp_existing))
        fat::Fat32DeleteAtPath(v, kTmpFile);
    if (fat::Fat32CreateAtPath(v, kTmpFile, buf, o) < 0)
    {
        SerialWrite("[calendar] save: create CALENDAR.TMP failed\n");
        return false;
    }
    fat::DirEntry existing;
    if (fat::Fat32LookupPath(v, kSaveFile, &existing))
    {
        if (!fat::Fat32DeleteAtPath(v, kSaveFile))
        {
            SerialWrite("[calendar] save: delete-existing failed; CALENDAR.TMP retained\n");
            return false;
        }
    }
    if (!fat::Fat32RenameAtPath(v, kTmpFile, kSaveFile))
    {
        SerialWrite("[calendar] save: rename failed\n");
        return false;
    }
    SerialWrite("[calendar] save: CALENDAR.TXT written (atomic via CALENDAR.TMP)\n");
    return true;
}

bool CalendarLoad()
{
    namespace fat = duetos::fs::fat32;
    using duetos::arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[calendar] load: no FAT32 volume mounted\n");
        return false;
    }
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, kSaveFile, &e))
    {
        SerialWrite("[calendar] load: CALENDAR.TXT not found\n");
        return false;
    }
    if (e.attributes & 0x10)
        return false;
    char buf[kFileBufCap];
    const u64 cap = (e.size_bytes < sizeof(buf)) ? e.size_bytes : sizeof(buf);
    const i64 n = fat::Fat32ReadFile(v, &e, buf, cap);
    if (n < 0)
    {
        SerialWrite("[calendar] load: read failed\n");
        return false;
    }
    g_event_count = 0;
    u32 i = 0;
    while (i < static_cast<u32>(n))
    {
        // Find end-of-line.
        u32 lend = i;
        while (lend < static_cast<u32>(n) && buf[lend] != '\n')
            ++lend;
        // Parse "YYYY-MM-DD\tTEXT".
        if (lend - i >= 11 && buf[i + 4] == '-' && buf[i + 7] == '-' && buf[i + 10] == '\t')
        {
            u32 yy = 0, mm = 0, dd = 0;
            const bool ok = ParseU32(buf + i, 4, yy) && ParseU32(buf + i + 5, 2, mm) && ParseU32(buf + i + 8, 2, dd);
            if (ok && ValidDate(yy, static_cast<u8>(mm), static_cast<u8>(dd)))
            {
                char text[kEventTextCap + 1];
                u32 t = 0;
                u32 src = i + 11;
                while (src < lend && t < kEventTextCap)
                    text[t++] = buf[src++];
                text[t] = '\0';
                CalendarAddEvent(yy, static_cast<u8>(mm), static_cast<u8>(dd), text);
            }
        }
        // Advance past the newline (or end-of-buffer).
        i = (lend < static_cast<u32>(n)) ? lend + 1 : lend;
    }
    SerialWrite("[calendar] load: CALENDAR.TXT applied\n");
    return true;
}

void CalendarPersistSelfTest()
{
    namespace fat = duetos::fs::fat32;
    using duetos::arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[calendar] persist self-test SKIP (no FAT32)\n");
        return;
    }
    fat::DirEntry existing;
    if (fat::Fat32LookupPath(v, kSaveFile, &existing))
    {
        SerialWrite("[calendar] persist self-test SKIP (CALENDAR.TXT exists)\n");
        return;
    }
    // Snapshot live state so the test never destroys it.
    StoredEvent saved[kMaxEvents];
    const u32 saved_count = g_event_count;
    for (u32 i = 0; i < saved_count; ++i)
        saved[i] = g_events[i];

    g_event_count = 0;
    bool pass = true;
    if (!CalendarAddEvent(2026, 5, 7, "PERSIST_TEST"))
        pass = false;
    if (!CalendarSave())
        pass = false;
    g_event_count = 0;
    if (pass && !CalendarLoad())
        pass = false;
    if (pass && (g_event_count != 1 || !CalendarHasEvent(2026, 5, 7)))
        pass = false;
    char tbuf[kEventTextCap + 1] = {};
    if (pass && !CalendarFirstEventText(2026, 5, 7, tbuf, sizeof(tbuf)))
        pass = false;
    if (pass && (tbuf[0] != 'P' || tbuf[1] != 'E' || tbuf[2] != 'R'))
        pass = false;

    // Cleanup: drop the test file + restore the live table.
    fat::Fat32DeleteAtPath(v, kSaveFile);
    g_event_count = saved_count;
    for (u32 i = 0; i < saved_count; ++i)
        g_events[i] = saved[i];

    SerialWrite(pass ? "[calendar] persist self-test OK (round-trip)\n" : "[calendar] persist self-test FAILED\n");
}

} // namespace duetos::apps::calendar
