#include "apps/settings.h"

#include "arch/x86_64/rtc.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
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
    using duetos::drivers::video::FramebufferDrawString;
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

    FramebufferDrawString(x, y, "DATE & TIME", fg, bg);

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
    FramebufferDrawString(x, y + 14, line, fg, bg);

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
    FramebufferDrawString(x, y + 30, line, fg, bg);

    FramebufferDrawString(x, y + 50, "[ : -1 hour    ] : +1 hour", dim, bg);
    FramebufferDrawString(x, y + 62, ", : -15 min    . : +15 min", dim, bg);
    FramebufferDrawString(x, y + 74, "Z : reset to UTC", dim, bg);

    FramebufferDrawString(x, y + 96, "(RTC programming via shell `time set` for now)", dim, bg);
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
    return false;
}

} // namespace

void SettingsDateTimeInit()
{
    SettingsRegisterPanel(Panel::DateTime, Draw, Key);
}

} // namespace duetos::apps::settings
