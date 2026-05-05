#include "apps/clock.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "drivers/video/framebuffer.h"

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

// Mode toggle. Clock = wall-clock HH:MM:SS from RTC.
// Stopwatch = elapsed-time counter driven by arch::TimerTicks
// (10 ms per tick at the kernel's 100 Hz scheduler rate).
enum class Mode : u8
{
    Clock = 0,
    Stopwatch = 1,
};

constinit Mode g_mode = Mode::Clock;
// Stopwatch state. `accumulated_ticks` holds run time captured
// across past start/stop cycles; while `running` is true, the
// live display adds (now - run_start_tick) on top.
constinit bool g_sw_running = false;
constinit u64 g_sw_run_start_tick = 0;
constinit u64 g_sw_accumulated_ticks = 0;

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

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    // Solid background — keeps the previous frame's glow from
    // leaking through on the inactive-segment colour.
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
    else // Stopwatch
    {
        const u64 ticks = StopwatchElapsedTicks();
        // 100 ticks per second. Display HH:MM:SS — sub-second
        // precision is shown in the footer to keep the digit
        // row stable.
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
        else
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
            const char* hint = "SPACE:RUN R:RESET TAB:CLK";
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

bool ClockFeedChar(char c)
{
    if (c == '\t')
    {
        // Mode toggle. Pause the stopwatch if it was running so
        // entering Clock mode doesn't keep accumulating time
        // invisibly. Resume on next Space — explicit-only.
        if (g_mode == Mode::Stopwatch && g_sw_running)
        {
            const u64 now = duetos::arch::TimerTicks();
            if (now >= g_sw_run_start_tick)
                g_sw_accumulated_ticks += now - g_sw_run_start_tick;
            g_sw_running = false;
        }
        g_mode = (g_mode == Mode::Clock) ? Mode::Stopwatch : Mode::Clock;
        return true;
    }
    if (g_mode != Mode::Stopwatch)
        return false;
    if (c == ' ')
    {
        // Toggle run / stop. On stop, fold the live elapsed
        // into accumulated. On start, take a fresh tick anchor.
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
