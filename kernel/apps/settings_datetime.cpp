#include "apps/settings.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/dialog.h"
#include "drivers/video/notify.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/theme.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "time/timezone.h"

namespace duetos::apps::settings
{

namespace
{

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// ---------------------------------------------------------------
// Pass D chrome: DATE & TIME panel. Three AppLabels stand the
// canonical hero / readout-line / hint-line chrome up behind the
// existing key-driven panel. The two data-bearing rows (RTC line +
// timezone-offset line) stay as raw ChromeTextDraw because their
// text mutates every paint via RtcRead / TimezoneOffsetMinutes —
// AppLabel.text is a `const char*` and we want the buffer to be
// re-composed inside Draw without leaning on a separate static
// composer per row.
//
// Composition (back-to-front declaration order):
//   - AppLabel  Title   — "DATE & TIME" hero header
//   - AppLabel  Caption — "S : SET RTC (UTC) ..." footer hint
//
// The intermediate Body rows and the [/]/,/./Z hint lines stay
// carve-out raw paint because they're heterogeneous (live values
// + multi-key cheat-sheet rows) and would each need their own
// composer buffer for ~zero readability gain.

constinit char g_dt_header[16] = "DATE & TIME";
constinit char g_dt_footer[64] = "S:set RTC  N:NTP sync  [/]:-/+1h  ,/.:+-15m  Z:UTC";

// NTP auto-sync flag — persisted in SESSION.CFG (datetime.ntp).
// When true pressing N issues one NTP query against the well-known
// pool address and writes the result to the RTC. When false the
// flag is stored but no automatic sync fires; a future background
// sync task would check this flag.
// NOTE: The NTP client (net/stack.h NetNtpQuery) exists and is
// wired; this flag gates whether N triggers a live query+RTC write.
constinit bool g_ntp_enabled = false;

// Last NTP sync status string for display.
constinit char g_ntp_status[40] = "NTP: OFF";

constinit auto g_settings_datetime = MakeWidgetGroup(AppLabel{}, AppLabel{});

constinit bool g_settings_datetime_bound = false;
constinit bool g_settings_datetime_self_test_passed = false;

AppLabel& DtHeader()
{
    return g_settings_datetime.chain.head;
}
AppLabel& DtFooter()
{
    return g_settings_datetime.chain.tail.head;
}

void BindSettingsDateTimeOnce()
{
    if (g_settings_datetime_bound)
        return;
    g_settings_datetime_bound = true;

    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    AppLabel& h = DtHeader();
    h.text = g_dt_header;
    h.role = ChromeTextRole::Title;
    h.weight = ChromeTextWeight::Bold;
    h.fg_rgb = fg;
    h.bg_rgb = bg;
    h.align_left = true;

    AppLabel& f = DtFooter();
    f.text = g_dt_footer;
    f.role = ChromeTextRole::Caption;
    f.weight = ChromeTextWeight::Regular;
    f.fg_rgb = dim;
    f.bg_rgb = bg;
    f.align_left = true;
}

// Re-anchor the header / footer to the supplied sub-panel content
// rect. Called from Draw before PaintAll so the labels track the
// live layout. The header sits at the top; the footer pins to the
// bottom of the rect.
void RebindSettingsDateTimeBounds(u32 x, u32 y, u32 w, u32 h)
{
    constexpr u32 kHeaderH = 14U;
    constexpr u32 kFooterH = 12U;
    DtHeader().bounds = Rect{x, y, w, kHeaderH};
    const u32 fy = (h > kFooterH) ? y + h - kFooterH : y;
    DtFooter().bounds = Rect{x, fy, w, kFooterH};
}

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
    const auto& th = duetos::drivers::video::ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    if (w < 8 * 24 || h < 8 * 8)
        return;

    // Pass D chrome: anchor + paint the header + footer labels.
    BindSettingsDateTimeOnce();
    RebindSettingsDateTimeBounds(x, y, w, h);
    Compose ctx{};
    g_settings_datetime.PaintAll(ctx);

    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);
    char line[80];
    u32 o = 0;

    // Raw paint — live-data rows + multi-key hint lines. AppLabel
    // stores text by pointer; these buffers refresh every Draw so
    // carve-out raw paint is the simpler shape.
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

    // NTP auto-sync row — shows toggle state; N key toggles + triggers.
    ChromeTextDraw(ChromeTextRole::Body, x, y + 46, g_ntp_status, fg, bg);

    // Hint lines — Caption role for the key-shortcut help below the readouts.
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 62, "[ : -1 hour    ] : +1 hour", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 74, ", : -15 min    . : +15 min", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 86, "Z : reset to UTC", dim, bg);
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
    if (c == 'n' || c == 'N')
    {
        // Toggle NTP auto-sync. When toggled ON, fire one NTP query
        // against the well-known Google time server and apply the
        // result to the RTC. When toggled OFF the flag is cleared
        // and persisted; no sync fires.
        g_ntp_enabled = !g_ntp_enabled;
        if (g_ntp_enabled)
        {
            // Well-known Google time server — same as the shell `ntp` command.
            duetos::net::Ipv4Address srv{{216, 239, 35, 0}};
            AppendStr(g_ntp_status, sizeof(g_ntp_status), nullptr, ""); // unused; direct write below
            // Update status to "querying" immediately so the panel
            // shows activity on the next frame.
            g_ntp_status[0] = 'N';
            g_ntp_status[1] = 'T';
            g_ntp_status[2] = 'P';
            g_ntp_status[3] = ':';
            g_ntp_status[4] = ' ';
            g_ntp_status[5] = 'O';
            g_ntp_status[6] = 'N';
            g_ntp_status[7] = ' ';
            g_ntp_status[8] = '(';
            g_ntp_status[9] = 'q';
            g_ntp_status[10] = 'u';
            g_ntp_status[11] = 'e';
            g_ntp_status[12] = 'r';
            g_ntp_status[13] = 'y';
            g_ntp_status[14] = 'i';
            g_ntp_status[15] = 'n';
            g_ntp_status[16] = 'g';
            g_ntp_status[17] = '.';
            g_ntp_status[18] = '.';
            g_ntp_status[19] = '.';
            g_ntp_status[20] = '\0';
            duetos::drivers::video::NotifyShow("NTP: querying...");
            const bool sent = duetos::net::NetNtpQuery(/*iface_index=*/0, srv);
            if (!sent)
            {
                // ARP miss / iface not bound — record but don't crash.
                g_ntp_status[8] = 'n';
                g_ntp_status[9] = 'o';
                g_ntp_status[10] = ' ';
                g_ntp_status[11] = 'r';
                g_ntp_status[12] = 'o';
                g_ntp_status[13] = 'u';
                g_ntp_status[14] = 't';
                g_ntp_status[15] = 'e';
                g_ntp_status[16] = ')';
                g_ntp_status[17] = '\0';
                duetos::drivers::video::NotifyShow("NTP: no route to server");
            }
            else
            {
                // Poll briefly — up to ~1 s in 10 ms steps. The
                // settings panel runs on the UI tick; we poll
                // inline so the RTC is updated before we return.
                // This is a bounded busy-wait (100 x 1 tick = ~1 s);
                // acceptable for a user-initiated one-shot sync.
                for (u32 i = 0; i < 100; ++i)
                {
                    duetos::sched::SchedSleepTicks(1);
                    const auto r = duetos::net::NetNtpResultRead();
                    if (r.synced)
                    {
                        // Convert unix_secs → RTC fields.
                        // unix_secs is seconds since 1970-01-01.
                        // We compute a rough UTC decomposition:
                        // year/month/day via Gregorian math,
                        // time-of-day via modulo.
                        const u64 secs = r.unix_secs;
                        const u64 tod = secs % 86400u;
                        const u8 hr = static_cast<u8>(tod / 3600u);
                        const u8 mn = static_cast<u8>((tod / 60u) % 60u);
                        const u8 sc = static_cast<u8>(tod % 60u);
                        // Days since epoch.
                        u32 days = static_cast<u32>(secs / 86400u);
                        // Gregorian year/month/day from days since 1970-01-01.
                        // Algorithm: civil_from_days (Howard Hinnant).
                        const i32 z = static_cast<i32>(days) + 719468;
                        const i32 era = (z >= 0 ? z : z - 146096) / 146097;
                        const u32 doe = static_cast<u32>(z - era * 146097);
                        const u32 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
                        const u32 y = static_cast<u32>(yoe) + static_cast<u32>(era) * 400u;
                        const u32 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
                        const u32 mp = (5 * doy + 2) / 153;
                        const u8 d = static_cast<u8>(doy - (153 * mp + 2) / 5 + 1);
                        const u8 m = static_cast<u8>(mp < 10 ? mp + 3 : mp - 9);
                        const u16 yr = static_cast<u16>(y + (m <= 2 ? 1 : 0));

                        duetos::arch::RtcTime t{};
                        t.year = yr;
                        t.month = m;
                        t.day = d;
                        t.hour = hr;
                        t.minute = mn;
                        t.second = sc;
                        if (duetos::arch::RtcWrite(&t))
                        {
                            // Update status: "NTP: ON (synced HH:MM:SS)"
                            u32 so = 0;
                            auto cs = [&](char ch)
                            {
                                if (so + 1 < sizeof(g_ntp_status))
                                    g_ntp_status[so++] = ch;
                            };
                            cs('N');
                            cs('T');
                            cs('P');
                            cs(':');
                            cs(' ');
                            cs('O');
                            cs('N');
                            cs(' ');
                            cs('(');
                            cs('s');
                            cs('y');
                            cs('n');
                            cs('c');
                            cs('e');
                            cs('d');
                            cs(' ');
                            cs(static_cast<char>('0' + hr / 10));
                            cs(static_cast<char>('0' + hr % 10));
                            cs(':');
                            cs(static_cast<char>('0' + mn / 10));
                            cs(static_cast<char>('0' + mn % 10));
                            cs(':');
                            cs(static_cast<char>('0' + sc / 10));
                            cs(static_cast<char>('0' + sc % 10));
                            cs(' ');
                            cs('U');
                            cs('T');
                            cs('C');
                            cs(')');
                            g_ntp_status[so] = '\0';
                            duetos::drivers::video::NotifyShow("NTP: RTC synced");
                            duetos::arch::SerialWrite("[settings-datetime] NTP sync ok\n");
                        }
                        else
                        {
                            g_ntp_status[8] = 'r';
                            g_ntp_status[9] = 't';
                            g_ntp_status[10] = 'c';
                            g_ntp_status[11] = ' ';
                            g_ntp_status[12] = 'e';
                            g_ntp_status[13] = 'r';
                            g_ntp_status[14] = 'r';
                            g_ntp_status[15] = ')';
                            g_ntp_status[16] = '\0';
                            duetos::drivers::video::NotifyShow("NTP: RTC write failed");
                        }
                        break;
                    }
                }
                // If still not synced after poll window, status already says "querying".
                const auto r2 = duetos::net::NetNtpResultRead();
                if (!r2.synced)
                {
                    g_ntp_status[8] = 't';
                    g_ntp_status[9] = 'i';
                    g_ntp_status[10] = 'm';
                    g_ntp_status[11] = 'e';
                    g_ntp_status[12] = 'o';
                    g_ntp_status[13] = 'u';
                    g_ntp_status[14] = 't';
                    g_ntp_status[15] = ')';
                    g_ntp_status[16] = '\0';
                    duetos::drivers::video::NotifyShow("NTP: no response (timeout)");
                }
            }
        }
        else
        {
            // Toggled OFF — update display string.
            g_ntp_status[0] = 'N';
            g_ntp_status[1] = 'T';
            g_ntp_status[2] = 'P';
            g_ntp_status[3] = ':';
            g_ntp_status[4] = ' ';
            g_ntp_status[5] = 'O';
            g_ntp_status[6] = 'F';
            g_ntp_status[7] = 'F';
            g_ntp_status[8] = '\0';
            duetos::drivers::video::NotifyShow("NTP: disabled");
        }
        return true;
    }
    return false;
}

} // namespace

void SettingsDateTimeInit()
{
    SettingsRegisterPanel(Panel::DateTime, Draw, Key);
}

void SettingsDateTimeSelfTest()
{
    using duetos::arch::SerialWrite;
    bool ok = true;

    // Pass D chrome: bind + rebind only. Skipping PaintAll because
    // under TTF themes (duet*) AppLabel::PaintSelf routes into
    // TtfDrawString -> CompositeCoverage -> FramebufferBlendFill at
    // the synthetic (0,0) origin and races the compositor lock
    // before the WM is online (silent boot halt). The bind + rebind
    // + buffer-non-empty + label-bound checks below validate the
    // chrome contract without painting. The live Draw() path
    // exercises paint when the settings shell composes us.
    BindSettingsDateTimeOnce();
    RebindSettingsDateTimeBounds(0U, 0U, 256U, 160U);

    if (g_dt_header[0] == '\0' || g_dt_footer[0] == '\0')
        ok = false;
    if (DtHeader().text == nullptr || DtFooter().text == nullptr)
        ok = false;

    g_settings_datetime_self_test_passed = ok;
    SerialWrite(ok ? "[settings-datetime-selftest] PASS\n" : "[settings-datetime-selftest] FAIL\n");
}

bool SettingsDateTimeSelfTestPassed()
{
    return g_settings_datetime_self_test_passed;
}

bool DateTimeNtpEnabled()
{
    return g_ntp_enabled;
}

void DateTimeSetNtpEnabled(bool enabled)
{
    g_ntp_enabled = enabled;
    // Sync the display string to match the stored flag without
    // firing a live query — this path is called by SessionRestoreApply
    // at boot before the NIC is up.
    if (!enabled)
    {
        g_ntp_status[0] = 'N';
        g_ntp_status[1] = 'T';
        g_ntp_status[2] = 'P';
        g_ntp_status[3] = ':';
        g_ntp_status[4] = ' ';
        g_ntp_status[5] = 'O';
        g_ntp_status[6] = 'F';
        g_ntp_status[7] = 'F';
        g_ntp_status[8] = '\0';
    }
    else
    {
        g_ntp_status[0] = 'N';
        g_ntp_status[1] = 'T';
        g_ntp_status[2] = 'P';
        g_ntp_status[3] = ':';
        g_ntp_status[4] = ' ';
        g_ntp_status[5] = 'O';
        g_ntp_status[6] = 'N';
        g_ntp_status[7] = ' ';
        g_ntp_status[8] = '(';
        g_ntp_status[9] = 'n';
        g_ntp_status[10] = 'o';
        g_ntp_status[11] = 't';
        g_ntp_status[12] = ' ';
        g_ntp_status[13] = 'y';
        g_ntp_status[14] = 'e';
        g_ntp_status[15] = 't';
        g_ntp_status[16] = ' ';
        g_ntp_status[17] = 's';
        g_ntp_status[18] = 'y';
        g_ntp_status[19] = 'n';
        g_ntp_status[20] = 'c';
        g_ntp_status[21] = 'e';
        g_ntp_status[22] = 'd';
        g_ntp_status[23] = ')';
        g_ntp_status[24] = '\0';
    }
}

} // namespace duetos::apps::settings
