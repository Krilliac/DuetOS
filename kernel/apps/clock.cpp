#include "apps/clock.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "drivers/video/dialog.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"

namespace duetos::apps::clock
{

namespace
{

// 7-segment digit geometry. Each digit is drawn in a kDigitW x
// kDigitH rectangle consisting of up to 7 segments:
//
//      aaa          bit 0 = a (top)
//     f   b         bit 1 = b (top right)
//     f   b         bit 2 = c (bottom right)
//      ggg          bit 3 = d (bottom)
//     e   c         bit 4 = e (bottom left)
//     e   c         bit 5 = f (top left)
//      ddd          bit 6 = g (middle)
constexpr u32 kDigitW = 24;
constexpr u32 kDigitH = 40;
constexpr u32 kSegT = 3; // segment thickness

// Segment masks per digit 0-9.
constexpr u8 kDigitMask[10] = {
    /* 0 */ 0x3F, // abcdef
    /* 1 */ 0x06, // bc
    /* 2 */ 0x5B, // abdeg
    /* 3 */ 0x4F, // abcdg
    /* 4 */ 0x66, // bcfg
    /* 5 */ 0x6D, // acdfg
    /* 6 */ 0x7D, // acdefg
    /* 7 */ 0x07, // abc
    /* 8 */ 0x7F, // abcdefg
    /* 9 */ 0x6F, // abcdfg
};

constexpr u32 kColonW = 8;   // width reserved for a ":" glyph
constexpr u32 kGap = 4;      // gap between digits / separators
constexpr u32 kMarginX = 16; // left inset from window client edge
constexpr u32 kMarginY = 16; // top inset

// Colours chosen for a retro-LED look against the client's
// dark background. kSegOn = glowing green; kSegOff = dim
// trace so "8888" shows every inactive segment faintly.
constexpr u32 kSegOn = 0x0020FF40;
constexpr u32 kSegOff = 0x00102818;
constexpr u32 kBg = 0x00081008;

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

// Mode toggle cycled via Tab.
//   Clock     — wall-clock HH:MM:SS from RTC.
//   Stopwatch — elapsed-time counter driven by arch::TimerTicks
//               (10 ms per tick at the kernel's 100 Hz rate).
//   Alarm     — fires NotifyShow when the live RTC matches a
//               user-set HH:MM. 'S' opens an InputBox for the
//               target time; 'A' arms / disarms.
//   Timer     — countdown from a user-set duration in seconds.
//               'S' to set, Space to start / pause, R to reset.
//               NotifyShow fires when the countdown reaches 0.
enum class Mode : u8
{
    Clock = 0,
    Stopwatch = 1,
    Alarm = 2,
    Timer = 3,
};

constinit Mode g_mode = Mode::Clock;
// Stopwatch state. `accumulated_ticks` holds run time captured
// across past start/stop cycles; while `running` is true, the
// live display adds (now - run_start_tick) on top.
constinit bool g_sw_running = false;
constinit u64 g_sw_run_start_tick = 0;
constinit u64 g_sw_accumulated_ticks = 0;
// Alarm state. `armed` gates the per-frame trigger; `triggered`
// becomes true once and the user has to disarm to re-arm.
constinit bool g_alarm_armed = false;
constinit bool g_alarm_triggered = false;
constinit u8 g_alarm_hour = 7;
constinit u8 g_alarm_minute = 0;
// Timer state. `duration_ticks` is the configured countdown;
// `remaining_ticks` is how much is left when the timer is
// running; `run_start_tick` is when the live run began.
constinit u64 g_timer_duration_ticks = 60 * 100; // 60 s default
constinit u64 g_timer_remaining_ticks = 60 * 100;
constinit u64 g_timer_run_start_tick = 0;
constinit bool g_timer_running = false;
constinit bool g_timer_fired = false;

// Paint one segment of a digit. `x` / `y` is the digit's
// top-left. `on` chooses colour.
void PaintSegment(u32 x, u32 y, u8 seg, bool on)
{
    using duetos::drivers::video::FramebufferFillRect;
    const u32 c = on ? kSegOn : kSegOff;
    switch (seg)
    {
    case 0: // a — top
        FramebufferFillRect(x + kSegT, y, kDigitW - 2 * kSegT, kSegT, c);
        break;
    case 1: // b — top right
        FramebufferFillRect(x + kDigitW - kSegT, y + kSegT, kSegT, (kDigitH - 3 * kSegT) / 2, c);
        break;
    case 2: // c — bottom right
        FramebufferFillRect(x + kDigitW - kSegT, y + kDigitH / 2 + kSegT / 2, kSegT, (kDigitH - 3 * kSegT) / 2, c);
        break;
    case 3: // d — bottom
        FramebufferFillRect(x + kSegT, y + kDigitH - kSegT, kDigitW - 2 * kSegT, kSegT, c);
        break;
    case 4: // e — bottom left
        FramebufferFillRect(x, y + kDigitH / 2 + kSegT / 2, kSegT, (kDigitH - 3 * kSegT) / 2, c);
        break;
    case 5: // f — top left
        FramebufferFillRect(x, y + kSegT, kSegT, (kDigitH - 3 * kSegT) / 2, c);
        break;
    case 6: // g — middle
        FramebufferFillRect(x + kSegT, y + (kDigitH - kSegT) / 2, kDigitW - 2 * kSegT, kSegT, c);
        break;
    default:
        break;
    }
}

void PaintDigit(u32 x, u32 y, u8 value)
{
    // Unknown digits paint as all-off (dim "8"-ghost shape).
    const u8 mask = (value < 10) ? kDigitMask[value] : 0;
    for (u8 s = 0; s < 7; ++s)
    {
        const bool on = (mask & (1u << s)) != 0;
        PaintSegment(x, y, s, on);
    }
}

void PaintColon(u32 x, u32 y)
{
    using duetos::drivers::video::FramebufferFillRect;
    // Two small squares at vertical thirds of the digit height.
    const u32 sz = kSegT + 1;
    const u32 cx = x + (kColonW - sz) / 2;
    const u32 y1 = y + kDigitH / 3 - sz / 2;
    const u32 y2 = y + 2 * kDigitH / 3 - sz / 2;
    FramebufferFillRect(cx, y1, sz, sz, kSegOn);
    FramebufferFillRect(cx, y2, sz, sz, kSegOn);
}

// Live stopwatch elapsed in ticks (running + accumulated). Each
// tick is 10 ms at the kernel's 100 Hz scheduler rate.
u64 StopwatchElapsedTicks()
{
    u64 elapsed = g_sw_accumulated_ticks;
    if (g_sw_running)
    {
        const u64 now = duetos::arch::TimerTicks();
        if (now >= g_sw_run_start_tick)
            elapsed += now - g_sw_run_start_tick;
    }
    return elapsed;
}

// Live timer remaining-ticks. While running, subtracts elapsed
// since the last start. Saturates at zero so the digit format
// never underflows.
u64 TimerRemainingTicks()
{
    if (!g_timer_running)
        return g_timer_remaining_ticks;
    const u64 now = duetos::arch::TimerTicks();
    const u64 elapsed = (now >= g_timer_run_start_tick) ? (now - g_timer_run_start_tick) : 0;
    if (elapsed >= g_timer_remaining_ticks)
        return 0;
    return g_timer_remaining_ticks - elapsed;
}

// Per-frame trigger checks. Called from DrawFn at 1 Hz cadence.
// Alarm fires when the live RTC matches the armed HH:MM and we
// haven't already triggered this minute. Timer fires once when
// the countdown reaches zero.
void CheckAlarmTrigger()
{
    if (!g_alarm_armed)
        return;
    duetos::arch::RtcTime rtc{};
    duetos::arch::RtcRead(&rtc);
    const bool match = (rtc.hour == g_alarm_hour) && (rtc.minute == g_alarm_minute);
    if (match && !g_alarm_triggered)
    {
        g_alarm_triggered = true;
        char msg[40];
        u32 o = 0;
        const char* lead = "ALARM ";
        for (u32 i = 0; lead[i] != '\0' && o + 1 < sizeof(msg); ++i)
            msg[o++] = lead[i];
        msg[o++] = static_cast<char>('0' + (g_alarm_hour / 10));
        msg[o++] = static_cast<char>('0' + (g_alarm_hour % 10));
        msg[o++] = ':';
        msg[o++] = static_cast<char>('0' + (g_alarm_minute / 10));
        msg[o++] = static_cast<char>('0' + (g_alarm_minute % 10));
        msg[o] = '\0';
        duetos::drivers::video::NotifyShow(msg);
    }
    if (!match)
    {
        g_alarm_triggered = false;
    }
}

void CheckTimerTrigger()
{
    if (!g_timer_running || g_timer_fired)
        return;
    if (TimerRemainingTicks() == 0)
    {
        g_timer_fired = true;
        g_timer_running = false;
        // Bake the elapsed back into the stored remaining so a
        // restart from this point doesn't misread.
        g_timer_remaining_ticks = 0;
        duetos::drivers::video::NotifyShow("TIMER ZERO");
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    // Per-frame trigger checks. 1 Hz cadence is the worst case —
    // alarm matches a whole minute window, timer countdown
    // resolution is 10 ms and we test against zero.
    CheckAlarmTrigger();
    CheckTimerTrigger();
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    u8 digits[6] = {0, 0, 0, 0, 0, 0};
    if (g_mode == Mode::Clock)
    {
        duetos::arch::RtcTime rtc{};
        duetos::arch::RtcRead(&rtc);
        digits[0] = static_cast<u8>(rtc.hour / 10);
        digits[1] = static_cast<u8>(rtc.hour % 10);
        digits[2] = static_cast<u8>(rtc.minute / 10);
        digits[3] = static_cast<u8>(rtc.minute % 10);
        digits[4] = static_cast<u8>(rtc.second / 10);
        digits[5] = static_cast<u8>(rtc.second % 10);
    }
    else if (g_mode == Mode::Stopwatch)
    {
        const u64 ticks = StopwatchElapsedTicks();
        const u64 total_seconds = ticks / 100;
        const u64 hr = (total_seconds / 3600) % 100;
        const u64 mn = (total_seconds / 60) % 60;
        const u64 sc = total_seconds % 60;
        digits[0] = static_cast<u8>(hr / 10);
        digits[1] = static_cast<u8>(hr % 10);
        digits[2] = static_cast<u8>(mn / 10);
        digits[3] = static_cast<u8>(mn % 10);
        digits[4] = static_cast<u8>(sc / 10);
        digits[5] = static_cast<u8>(sc % 10);
    }
    else if (g_mode == Mode::Alarm)
    {
        // HH : MM : -- (seconds dimmed off — alarm is a HH:MM
        // target, the seconds slot reads as a static "--").
        digits[0] = g_alarm_hour / 10;
        digits[1] = g_alarm_hour % 10;
        digits[2] = g_alarm_minute / 10;
        digits[3] = g_alarm_minute % 10;
        digits[4] = 10; // sentinel -> "8"-ghost
        digits[5] = 10;
    }
    else // Timer
    {
        const u64 ticks = TimerRemainingTicks();
        const u64 total_seconds = ticks / 100;
        const u64 hr = (total_seconds / 3600) % 100;
        const u64 mn = (total_seconds / 60) % 60;
        const u64 sc = total_seconds % 60;
        digits[0] = static_cast<u8>(hr / 10);
        digits[1] = static_cast<u8>(hr % 10);
        digits[2] = static_cast<u8>(mn / 10);
        digits[3] = static_cast<u8>(mn % 10);
        digits[4] = static_cast<u8>(sc / 10);
        digits[5] = static_cast<u8>(sc % 10);
    }

    const u32 row_w = 6 * kDigitW + 2 * kColonW + 7 * kGap;
    // Centre the row horizontally if the window is wider, else
    // clip at kMarginX. `ch` is used only to centre vertically
    // when there's spare height above/below the digit row.
    u32 x = (cw > row_w + 2 * kMarginX) ? cx + (cw - row_w) / 2 : cx + kMarginX;
    const u32 y = (ch > kDigitH + 2 * kMarginY) ? cy + (ch - kDigitH - 16) / 2 : cy + kMarginY;

    // HH : MM : SS
    for (u32 g = 0; g < 6; ++g)
    {
        PaintDigit(x, y, digits[g]);
        x += kDigitW + kGap;
        if (g == 1 || g == 3)
        {
            PaintColon(x, y);
            x += kColonW + kGap;
        }
    }

    // Footer: in Clock mode, paint date + year. In Stopwatch
    // mode, paint mode label + run/stop hint + centisecond
    // counter.
    if (ch >= kDigitH + 2 * kMarginY + 12)
    {
        char line[40];
        u32 o = 0;
        if (g_mode == Mode::Clock)
        {
            duetos::arch::RtcTime rtc{};
            duetos::arch::RtcRead(&rtc);
            line[o++] = static_cast<char>('0' + (rtc.day / 10));
            line[o++] = static_cast<char>('0' + (rtc.day % 10));
            line[o++] = '/';
            line[o++] = static_cast<char>('0' + (rtc.month / 10));
            line[o++] = static_cast<char>('0' + (rtc.month % 10));
            line[o++] = '/';
            const u32 y_div_1000 = rtc.year / 1000;
            const u32 y_div_100 = (rtc.year / 100) % 10;
            const u32 y_div_10 = (rtc.year / 10) % 10;
            const u32 y_mod_10 = rtc.year % 10;
            line[o++] = static_cast<char>('0' + y_div_1000);
            line[o++] = static_cast<char>('0' + y_div_100);
            line[o++] = static_cast<char>('0' + y_div_10);
            line[o++] = static_cast<char>('0' + y_mod_10);
            line[o++] = ' ';
            line[o++] = '|';
            line[o++] = ' ';
            line[o++] = 'T';
            line[o++] = 'A';
            line[o++] = 'B';
            line[o++] = ':';
            line[o++] = 'S';
            line[o++] = 'W';
        }
        else if (g_mode == Mode::Stopwatch)
        {
            const u64 ticks = StopwatchElapsedTicks();
            const u64 cs = (ticks % 100); // centiseconds
            const char* lead = g_sw_running ? "STOPWATCH .RUN " : "STOPWATCH .STOP";
            for (u32 i = 0; lead[i] != '\0' && o + 1 < sizeof(line); ++i)
                line[o++] = lead[i];
            line[o++] = ' ';
            line[o++] = '.';
            line[o++] = static_cast<char>('0' + (cs / 10));
            line[o++] = static_cast<char>('0' + (cs % 10));
            line[o++] = ' ';
            line[o++] = '|';
            line[o++] = ' ';
            const char* hint = "SPACE:RUN R:RESET TAB:NEXT";
            for (u32 i = 0; hint[i] != '\0' && o + 1 < sizeof(line); ++i)
                line[o++] = hint[i];
        }
        else if (g_mode == Mode::Alarm)
        {
            const char* lead = g_alarm_armed ? "ALARM .ARMED " : "ALARM .IDLE  ";
            for (u32 i = 0; lead[i] != '\0' && o + 1 < sizeof(line); ++i)
                line[o++] = lead[i];
            line[o++] = ' ';
            line[o++] = '|';
            line[o++] = ' ';
            const char* hint = "S:SET A:ARM TAB:NEXT";
            for (u32 i = 0; hint[i] != '\0' && o + 1 < sizeof(line); ++i)
                line[o++] = hint[i];
        }
        else // Timer
        {
            const char* lead = g_timer_running ? "TIMER .RUN  " : (g_timer_fired ? "TIMER .ZERO " : "TIMER .IDLE ");
            for (u32 i = 0; lead[i] != '\0' && o + 1 < sizeof(line); ++i)
                line[o++] = lead[i];
            line[o++] = ' ';
            line[o++] = '|';
            line[o++] = ' ';
            const char* hint = "S:SET SPC:RUN R:RESET TAB:NEXT";
            for (u32 i = 0; hint[i] != '\0' && o + 1 < sizeof(line); ++i)
                line[o++] = hint[i];
        }
        line[o] = '\0';
        const u32 text_w = o * 8;
        const u32 text_x = (cw > text_w) ? cx + (cw - text_w) / 2 : cx;
        const u32 text_y = y + kDigitH + 6;
        FramebufferDrawString(text_x, text_y, line, kSegOn, kBg);
    }
}

} // namespace

void ClockInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle ClockWindow()
{
    return g_handle;
}

// Pause running state on mode change so the Stopwatch / Timer
// don't keep counting invisibly while the user is on Clock /
// Alarm. Restart requires an explicit Space.
void PauseStopwatchIfRunning()
{
    if (g_sw_running)
    {
        const u64 now = duetos::arch::TimerTicks();
        if (now >= g_sw_run_start_tick)
            g_sw_accumulated_ticks += now - g_sw_run_start_tick;
        g_sw_running = false;
    }
}

void PauseTimerIfRunning()
{
    if (!g_timer_running)
        return;
    const u64 now = duetos::arch::TimerTicks();
    const u64 elapsed = (now >= g_timer_run_start_tick) ? (now - g_timer_run_start_tick) : 0;
    if (elapsed >= g_timer_remaining_ticks)
        g_timer_remaining_ticks = 0;
    else
        g_timer_remaining_ticks -= elapsed;
    g_timer_running = false;
}

// InputBox callback for "set alarm time": accepts "HH:MM" and
// stores the parsed values. Validates the format; nonsense
// strings notify and leave state unchanged.
void OnAlarmSetResult(duetos::drivers::video::DialogResult r, const char* text, void* /*user*/)
{
    if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr)
        return;
    u32 h = 0;
    u32 m = 0;
    u32 i = 0;
    while (text[i] >= '0' && text[i] <= '9')
    {
        h = h * 10 + static_cast<u32>(text[i] - '0');
        ++i;
    }
    if (text[i] != ':')
    {
        duetos::drivers::video::NotifyShow("alarm: expect HH:MM");
        return;
    }
    ++i;
    while (text[i] >= '0' && text[i] <= '9')
    {
        m = m * 10 + static_cast<u32>(text[i] - '0');
        ++i;
    }
    if (h >= 24 || m >= 60)
    {
        duetos::drivers::video::NotifyShow("alarm: out of range");
        return;
    }
    g_alarm_hour = static_cast<u8>(h);
    g_alarm_minute = static_cast<u8>(m);
    g_alarm_triggered = false;
}

void OnTimerSetResult(duetos::drivers::video::DialogResult r, const char* text, void* /*user*/)
{
    if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr)
        return;
    u32 secs = 0;
    for (u32 i = 0; text[i] != '\0'; ++i)
    {
        if (text[i] < '0' || text[i] > '9')
        {
            duetos::drivers::video::NotifyShow("timer: digits only");
            return;
        }
        secs = secs * 10 + static_cast<u32>(text[i] - '0');
        if (secs > 24 * 3600)
        {
            duetos::drivers::video::NotifyShow("timer: max 24h");
            return;
        }
    }
    g_timer_duration_ticks = static_cast<u64>(secs) * 100u;
    g_timer_remaining_ticks = g_timer_duration_ticks;
    g_timer_running = false;
    g_timer_fired = false;
}

bool ClockFeedChar(char c)
{
    if (c == '\t')
    {
        // Cycle Clock -> Stopwatch -> Alarm -> Timer -> Clock.
        // Pause anything that was counting before swapping.
        PauseStopwatchIfRunning();
        PauseTimerIfRunning();
        switch (g_mode)
        {
        case Mode::Clock:
            g_mode = Mode::Stopwatch;
            break;
        case Mode::Stopwatch:
            g_mode = Mode::Alarm;
            break;
        case Mode::Alarm:
            g_mode = Mode::Timer;
            break;
        case Mode::Timer:
        default:
            g_mode = Mode::Clock;
            break;
        }
        return true;
    }
    if (g_mode == Mode::Stopwatch)
    {
        if (c == ' ')
        {
            if (g_sw_running)
            {
                const u64 now = duetos::arch::TimerTicks();
                if (now >= g_sw_run_start_tick)
                    g_sw_accumulated_ticks += now - g_sw_run_start_tick;
                g_sw_running = false;
            }
            else
            {
                g_sw_run_start_tick = duetos::arch::TimerTicks();
                g_sw_running = true;
            }
            return true;
        }
        if (c == 'r' || c == 'R')
        {
            g_sw_running = false;
            g_sw_accumulated_ticks = 0;
            g_sw_run_start_tick = 0;
            return true;
        }
        return false;
    }
    if (g_mode == Mode::Alarm)
    {
        if (c == 's' || c == 'S')
        {
            char buf[8];
            u32 o = 0;
            buf[o++] = static_cast<char>('0' + (g_alarm_hour / 10));
            buf[o++] = static_cast<char>('0' + (g_alarm_hour % 10));
            buf[o++] = ':';
            buf[o++] = static_cast<char>('0' + (g_alarm_minute / 10));
            buf[o++] = static_cast<char>('0' + (g_alarm_minute % 10));
            buf[o] = '\0';
            duetos::drivers::video::InputBoxOpen("ALARM", "Set time HH:MM:", buf, OnAlarmSetResult, nullptr);
            return true;
        }
        if (c == 'a' || c == 'A')
        {
            g_alarm_armed = !g_alarm_armed;
            g_alarm_triggered = false;
            duetos::drivers::video::NotifyShow(g_alarm_armed ? "alarm armed" : "alarm disarmed");
            return true;
        }
        return false;
    }
    if (g_mode == Mode::Timer)
    {
        if (c == 's' || c == 'S')
        {
            char buf[12];
            u32 o = 0;
            const u64 secs = g_timer_duration_ticks / 100;
            // Render seconds in decimal — buf cap of 11 digits +
            // NUL covers up to ~99 999 999 999 seconds.
            if (secs == 0)
            {
                buf[o++] = '0';
            }
            else
            {
                char tmp[12];
                u32 n = 0;
                u64 v = secs;
                while (v > 0 && n < sizeof(tmp))
                {
                    tmp[n++] = static_cast<char>('0' + (v % 10));
                    v /= 10;
                }
                while (n > 0)
                {
                    buf[o++] = tmp[--n];
                }
            }
            buf[o] = '\0';
            duetos::drivers::video::InputBoxOpen("TIMER", "Set seconds:", buf, OnTimerSetResult, nullptr);
            return true;
        }
        if (c == ' ')
        {
            if (g_timer_running)
            {
                PauseTimerIfRunning();
            }
            else
            {
                if (g_timer_remaining_ticks == 0)
                    g_timer_remaining_ticks = g_timer_duration_ticks;
                if (g_timer_remaining_ticks > 0)
                {
                    g_timer_run_start_tick = duetos::arch::TimerTicks();
                    g_timer_running = true;
                    g_timer_fired = false;
                }
            }
            return true;
        }
        if (c == 'r' || c == 'R')
        {
            g_timer_running = false;
            g_timer_fired = false;
            g_timer_remaining_ticks = g_timer_duration_ticks;
            return true;
        }
        return false;
    }
    return false;
}

void ClockSelfTest()
{
    using duetos::arch::SerialWrite;
    bool pass = true;
    // Every digit 0-9 should resolve to a non-zero mask.
    for (u32 d = 0; d < 10; ++d)
    {
        if (kDigitMask[d] == 0)
        {
            pass = false;
            break;
        }
    }
    // Digit '8' lights all seven segments — canonical full-on
    // test for a 7-segment display. Its mask must be 0x7F.
    if (kDigitMask[8] != 0x7F)
        pass = false;
    // Row width must fit in a reasonable window (<= 400 px);
    // if the geometry constants drift out of proportion the
    // clock window would be unrenderable.
    const u32 row_w = 6 * kDigitW + 2 * kColonW + 7 * kGap;
    if (row_w >= 400)
        pass = false;
    SerialWrite(pass ? "[clock] self-test OK (digit mask + row fit)\n" : "[clock] self-test FAILED\n");
}

} // namespace duetos::apps::clock
