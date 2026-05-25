#include "apps/settings.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/dialog.h"
#include "drivers/video/notify.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/theme.h"
#include "time/timezone.h"

namespace duetos::apps::settings
{

namespace
{

void Append2(char* out, u32* o, u32 v)
{
    out[(*o)++] = static_cast<char>('0' + (v / 10));
    out[(*o)++] = static_cast<char>('0' + (v % 10));
}

void Append4(char* out, u32* o, u32 v)
{
    out[(*o)++] = static_cast<char>('0' + (v / 1000));
    out[(*o)++] = static_cast<char>('0' + (v / 100) % 10);
    out[(*o)++] = static_cast<char>('0' + (v / 10) % 10);
    out[(*o)++] = static_cast<char>('0' + v % 10);
}

void AppendStr(char* out, u32 cap, u32* o, const char* s)
{
    while (*s != '\0' && *o + 1 < cap)
        out[(*o)++] = *s++;
}

void AppendSignedDec(char* out, u32 cap, u32* o, i32 v)
{
    if (v < 0)
    {
        if (*o + 1 < cap)
            out[(*o)++] = '-';
        v = -v;
    }
    char tmp[12];
    u32 n = 0;
    if (v == 0)
        tmp[n++] = '0';
    while (v > 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n > 0 && *o + 1 < cap)
        out[(*o)++] = tmp[--n];
}

void Draw(u32 x, u32 y, u32 w, u32 h)
{
    using duetos::drivers::video::ChromeTextDraw;
    using duetos::drivers::video::ChromeTextRole;
    using duetos::drivers::video::ChromeTextWeight;
    const auto& th = duetos::drivers::video::ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    if (w < 8 * 24 || h < 8 * 8)
        return;

    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);
    char line[80];
    u32 o = 0;

    // Section header — Title + Bold so "DATE & TIME" reads as the
    // panel's hero label rather than a row.
    ChromeTextDraw(ChromeTextRole::Title, x, y, "DATE & TIME", fg, bg, ChromeTextWeight::Bold);

    o = 0;
    AppendStr(line, sizeof(line), &o, "RTC (UTC): ");
    Append4(line, &o, rtc.year);
    line[o++] = '-';
    Append2(line, &o, rtc.month);
    line[o++] = '-';
    Append2(line, &o, rtc.day);
    line[o++] = ' ';
    Append2(line, &o, rtc.hour);
    line[o++] = ':';
    Append2(line, &o, rtc.minute);
    line[o++] = ':';
    Append2(line, &o, rtc.second);
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 14, line, fg, bg);

    const i32 off = duetos::time::TimezoneOffsetMinutes();
    o = 0;
    AppendStr(line, sizeof(line), &o, "TIMEZONE OFFSET: ");
    AppendSignedDec(line, sizeof(line), &o, off);
    AppendStr(line, sizeof(line), &o, " min (");
    AppendSignedDec(line, sizeof(line), &o, off / 60);
    AppendStr(line, sizeof(line), &o, "h ");
    AppendSignedDec(line, sizeof(line), &o, (off >= 0 ? off : -off) % 60);
    AppendStr(line, sizeof(line), &o, "m)");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 30, line, fg, bg);

    // Hint lines — Caption role for the key-shortcut help below the readouts.
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 50, "[ : -1 hour    ] : +1 hour", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 62, ", : -15 min    . : +15 min", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 74, "Z : reset to UTC", dim, bg);

    ChromeTextDraw(ChromeTextRole::Caption, x, y + 96, "S : SET RTC (UTC) — opens YYYY-MM-DD HH:MM:SS prompt", dim, bg);
}

// Trim leading whitespace + parse "YYYY-MM-DD HH:MM:SS" or
// "YYYY-MM-DD HH:MM" (seconds default to 0). Returns true on
// successful parse with all six fields populated; false on
// any malformed input.
bool ParseDateTime(const char* text, duetos::arch::RtcTime* out)
{
    if (text == nullptr || out == nullptr)
        return false;
    auto digit = [](char c) -> int { return (c >= '0' && c <= '9') ? c - '0' : -1; };
    u32 i = 0;
    while (text[i] == ' ' || text[i] == '\t')
        ++i;
    auto take_n = [&](u32 n, u32* val) -> bool
    {
        u32 v = 0;
        for (u32 k = 0; k < n; ++k)
        {
            const int d = digit(text[i + k]);
            if (d < 0)
                return false;
            v = v * 10 + static_cast<u32>(d);
        }
        i += n;
        *val = v;
        return true;
    };
    u32 y4 = 0, mo = 0, da = 0, hr = 0, mi = 0, se = 0;
    if (!take_n(4, &y4))
        return false;
    if (text[i++] != '-')
        return false;
    if (!take_n(2, &mo))
        return false;
    if (text[i++] != '-')
        return false;
    if (!take_n(2, &da))
        return false;
    if (text[i++] != ' ')
        return false;
    if (!take_n(2, &hr))
        return false;
    if (text[i++] != ':')
        return false;
    if (!take_n(2, &mi))
        return false;
    if (text[i] == ':')
    {
        ++i;
        if (!take_n(2, &se))
            return false;
    }
    if (y4 < 2000 || y4 > 2099 || mo < 1 || mo > 12 || da < 1 || da > 31 || hr > 23 || mi > 59 || se > 59)
        return false;
    out->year = static_cast<u16>(y4);
    out->month = static_cast<u8>(mo);
    out->day = static_cast<u8>(da);
    out->hour = static_cast<u8>(hr);
    out->minute = static_cast<u8>(mi);
    out->second = static_cast<u8>(se);
    return true;
}

void OnRtcSetResult(duetos::drivers::video::DialogResult r, const char* text, void* /*user*/)
{
    if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr)
        return;
    duetos::arch::RtcTime t{};
    if (!ParseDateTime(text, &t))
    {
        duetos::drivers::video::NotifyShow("rtc: bad format (use YYYY-MM-DD HH:MM:SS)");
        duetos::drivers::video::SoundCueError();
        return;
    }
    if (!duetos::arch::RtcWrite(&t))
    {
        duetos::drivers::video::NotifyShow("rtc: write rejected");
        duetos::drivers::video::SoundCueError();
        return;
    }
    duetos::drivers::video::NotifyShow("rtc: set");
    duetos::arch::SerialWrite("[settings] rtc set ok\n");
}

bool Key(char c)
{
    using duetos::time::SetTimezoneOffsetMinutes;
    using duetos::time::TimezoneOffsetMinutes;
    if (c == '[')
    {
        SetTimezoneOffsetMinutes(TimezoneOffsetMinutes() - 60);
        duetos::drivers::video::NotifyShow("timezone -1h");
        return true;
    }
    if (c == ']')
    {
        SetTimezoneOffsetMinutes(TimezoneOffsetMinutes() + 60);
        duetos::drivers::video::NotifyShow("timezone +1h");
        return true;
    }
    if (c == ',')
    {
        SetTimezoneOffsetMinutes(TimezoneOffsetMinutes() - 15);
        duetos::drivers::video::NotifyShow("timezone -15m");
        return true;
    }
    if (c == '.')
    {
        SetTimezoneOffsetMinutes(TimezoneOffsetMinutes() + 15);
        duetos::drivers::video::NotifyShow("timezone +15m");
        return true;
    }
    if (c == 'z' || c == 'Z')
    {
        SetTimezoneOffsetMinutes(0);
        duetos::drivers::video::NotifyShow("timezone reset to UTC");
        return true;
    }
    if (c == 's' || c == 'S')
    {
        // Pre-fill the InputBox with the current RTC reading
        // so the user can edit one field without retyping the
        // whole stamp. ISO-8601 form, space-separated.
        duetos::arch::RtcTime now{};
        duetos::arch::RtcRead(&now);
        char buf[24];
        u32 o = 0;
        auto put2 = [&](u32 v)
        {
            buf[o++] = static_cast<char>('0' + (v / 10) % 10);
            buf[o++] = static_cast<char>('0' + v % 10);
        };
        buf[o++] = static_cast<char>('0' + (now.year / 1000));
        buf[o++] = static_cast<char>('0' + (now.year / 100) % 10);
        buf[o++] = static_cast<char>('0' + (now.year / 10) % 10);
        buf[o++] = static_cast<char>('0' + now.year % 10);
        buf[o++] = '-';
        put2(now.month);
        buf[o++] = '-';
        put2(now.day);
        buf[o++] = ' ';
        put2(now.hour);
        buf[o++] = ':';
        put2(now.minute);
        buf[o++] = ':';
        put2(now.second);
        buf[o] = '\0';
        duetos::drivers::video::InputBoxOpen("SET RTC (UTC)", "Enter YYYY-MM-DD HH:MM:SS:", buf, OnRtcSetResult,
                                             nullptr);
        return true;
    }
    return false;
}

} // namespace

void SettingsDateTimeInit()
{
    SettingsRegisterPanel(Panel::DateTime, Draw, Key);
}

} // namespace duetos::apps::settings
