#include "apps/clock.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/dialog.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/sound_cue.h"

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

constexpr u32 kColonW = 8; // width reserved for a ":" glyph
constexpr u32 kGap = 4;    // gap between digits / separators

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

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 4 AppButton entries (CLOCK
// / STOP / ALRM / TIMR — one per Mode) + 1 AppLabel footer that
// carries the per-mode status / hint line. The 4 toolbar buttons
// duplicate the Tab-cycle keyboard shortcut so the chrome stays
// discoverable without forcing fresh users to memorise that
// Tab cycles modes.
//
// Carve-outs that stay raw paint:
//   - LED-style 7-segment digit face (HH:MM:SS row). This is the
//     app's intentional personality — each digit is composed of
//     up to 7 filled rectangles in retro-LED green against a
//     dark background. AppButton's uniform fg/bg/label model
//     can't reproduce the per-segment on/off ghosting or the
//     two-square colon glyph. The face paints inside the band
//     DrawFn carves out below the toolbar and above the footer
//     label.
//
// Layout: toolbar (kClockToolbarH = 22) at the top of the
// client area, then the LED digit face centred in the middle
// band, then a footer AppLabel along the bottom. Status text
// content is per-mode (see RefreshFooterText) and re-composed
// each frame from the live mode + run/armed/fired flags.

constexpr u32 kClockToolbarH = 22U;
constexpr u32 kClockToolbarBtnW = 48U;
constexpr u32 kClockToolbarBtnH = 18U;
constexpr u32 kClockToolbarBtnGap = 4U;
constexpr u32 kClockToolbarPadX = 4U;
constexpr u32 kClockToolbarPadY = 2U;
constexpr u32 kClockModeBtnCount = 4U;
constexpr u32 kClockFooterH = 12U;

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppToolbar;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::EventResult;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// AppLabel stores text by pointer so the buffer must outlive
// every Paint. DrawFn re-renders it each frame via
// RefreshClockFooter.
constinit char g_clock_footer_text[64] = {};

// Forward decls for the toolbar click trampolines (defined
// below; they have to live above the constinit g_clock that
// captures them by function-pointer value).
void ClickClockMode();
void ClickStopwatchMode();
void ClickAlarmMode();
void ClickTimerMode();

// Toolbar (back), then 4 mode-toggle AppButtons (CLOCK / STOP /
// ALRM / TIMR), then 1 AppLabel footer. Reverse declaration
// order is dispatch order — buttons get first refusal on clicks.
constinit auto g_clock = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppLabel{});

constinit bool g_clock_bound = false;
constinit bool g_clock_prev_left_down = false;
constinit bool g_clock_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to each mode button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 4 buttons -> 1
// label).
AppButton* ClockModeButton(u32 i)
{
    auto& a = g_clock.chain.tail; // toolbar -> btn[0]
    auto& b = a.tail;             // btn[0]   -> btn[1]
    auto& c = b.tail;             // btn[1]   -> btn[2]
    auto& d = c.tail;             // btn[2]   -> btn[3]
    AppButton* btns[kClockModeBtnCount] = {&a.head, &b.head, &c.head, &d.head};
    return btns[i];
}

// AppLabel accessor — footer sits at chain position 5 (zero-
// indexed) after the 1 toolbar + 4 buttons.
AppLabel& ClockFooterLabel()
{
    return g_clock.chain.tail.tail.tail.tail.tail.head;
}

void BindClockOnce()
{
    if (g_clock_bound)
        return;
    g_clock_bound = true;

    auto& toolbar = g_clock.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    static const char* const kClockModeLabels[kClockModeBtnCount] = {"CLOCK", "STOP", "ALRM", "TIMR"};
    using ClickFn = void (*)();
    static constexpr ClickFn kClockModeClicks[kClockModeBtnCount] = {ClickClockMode, ClickStopwatchMode, ClickAlarmMode,
                                                                     ClickTimerMode};
    for (u32 i = 0; i < kClockModeBtnCount; ++i)
    {
        AppButton* btn = ClockModeButton(i);
        btn->label = kClockModeLabels[i];
        btn->on_click = kClockModeClicks[i];
        btn->weight = ChromeTextWeight::Regular;
        btn->bg_rgb = 0; // theme role default
        btn->fg_rgb = 0x00101828U;
    }

    auto& footer = ClockFooterLabel();
    footer.text = g_clock_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = kSegOn;
    footer.bg_rgb = kBg;
    footer.align_left = false;
}

// Re-anchor the toolbar + buttons + footer to the live client
// rect. Called from DrawFn before PaintAll and from
// ClockMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindClockBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_clock.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kClockToolbarH};

    for (u32 i = 0; i < kClockModeBtnCount; ++i)
    {
        const u32 bx = cx + kClockToolbarPadX + i * (kClockToolbarBtnW + kClockToolbarBtnGap);
        ClockModeButton(i)->bounds = Rect{bx, cy + kClockToolbarPadY, kClockToolbarBtnW, kClockToolbarBtnH};
    }

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kClockFooterH) ? cy + ch - kClockFooterH : cy;
    const u32 fw = (cw > 4U) ? cw - 4U : cw;
    ClockFooterLabel().bounds = Rect{cx + 2U, fy, fw, kClockFooterH};
}

// Re-compose g_clock_footer_text from live state. Per-mode
// status (RUN/IDLE/ARMED/etc.) + hint, mirroring the legacy
// inline footer build in DrawFn.
void RefreshClockFooter()
{
    u32 o = 0;
    auto append = [&](const char* s)
    {
        for (u32 i = 0; s[i] != '\0' && o + 1 < sizeof(g_clock_footer_text); ++i)
            g_clock_footer_text[o++] = s[i];
    };
    if (g_mode == Mode::Clock)
    {
        append("CLOCK | TAB:NEXT MODE");
    }
    else if (g_mode == Mode::Stopwatch)
    {
        append(g_sw_running ? "STOP .RUN | SPC:RUN R:RESET" : "STOP .IDLE | SPC:RUN R:RESET");
    }
    else if (g_mode == Mode::Alarm)
    {
        append(g_alarm_armed ? "ALRM .ARMED | S:SET A:ARM" : "ALRM .IDLE | S:SET A:ARM");
    }
    else // Timer
    {
        append(g_timer_running
                   ? "TIMR .RUN | S:SET SPC:RUN R:RESET"
                   : (g_timer_fired ? "TIMR .ZERO | S:SET SPC:RUN R:RESET" : "TIMR .IDLE | S:SET SPC:RUN R:RESET"));
    }
    g_clock_footer_text[o] = '\0';
}

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
        duetos::drivers::video::SoundCueAlarm();
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
        duetos::drivers::video::SoundCueAlarm();
    }
}

// Paint the LED 7-segment digit face (HH:MM:SS) inside the band
// DrawFn reserves between the toolbar and the footer label. This
// is the carve-out: the digits aren't a uniform-fill / uniform-
// label widget, so they stay raw FramebufferFillRect paint via
// PaintDigit / PaintColon.
void PaintLedFace(u32 cx, u32 cy, u32 cw, u32 ch)
{
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
    // Centre the row horizontally if the band is wider, else
    // clip at the left margin. Vertical centring inside the
    // band when there's spare height; otherwise top-anchor with
    // a small inset.
    u32 x = (cw > row_w) ? cx + (cw - row_w) / 2 : cx + 2U;
    const u32 y = (ch > kDigitH) ? cy + (ch - kDigitH) / 2 : cy;

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
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferFillRect;
    // Per-frame trigger checks. 1 Hz cadence is the worst case —
    // alarm matches a whole minute window, timer countdown
    // resolution is 10 ms and we test against zero.
    CheckAlarmTrigger();
    CheckTimerTrigger();
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    // Pass D chrome: re-anchor + refresh + paint the toolbar +
    // mode buttons + footer label. The LED face (carve-out)
    // paints inside the band between the toolbar and the footer.
    BindClockOnce();
    RefreshClockFooter();
    RebindClockBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_clock.PaintAll(compose_ctx);

    // LED face band — between the toolbar at the top and the
    // footer AppLabel at the bottom.
    const u32 top_band = kClockToolbarH;
    const u32 bot_band = kClockFooterH;
    const u32 face_x = cx;
    const u32 face_y = cy + top_band;
    const u32 face_w = cw;
    const u32 face_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (face_h > 0)
    {
        PaintLedFace(face_x, face_y, face_w, face_h);
    }
}

// Local copies of the Pause* helpers. The non-anonymous-namespace
// PauseStopwatchIfRunning / PauseTimerIfRunning are the public
// entry points (still called from ClockFeedChar's Tab branch);
// the click trampolines need the same behaviour but live inside
// the anonymous namespace where the forward-decl ordering vs.
// constinit g_clock would otherwise force a layering shuffle.
void PauseSwInternal()
{
    if (g_sw_running)
    {
        const u64 now = duetos::arch::TimerTicks();
        if (now >= g_sw_run_start_tick)
            g_sw_accumulated_ticks += now - g_sw_run_start_tick;
        g_sw_running = false;
    }
}

void PauseTimerInternal()
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

// ----- Pass D click trampolines --------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_clock above captures each one by function-pointer value. Each
// click sets the corresponding Mode and pauses anything that was
// counting — mirrors the Tab-cycle's "pause running state on
// mode change" discipline so a fresh user can click straight to
// CLOCK / STOP / ALRM / TIMR without remembering the Tab key.

void ClickClockMode()
{
    PauseSwInternal();
    PauseTimerInternal();
    g_mode = Mode::Clock;
}

void ClickStopwatchMode()
{
    PauseSwInternal();
    PauseTimerInternal();
    g_mode = Mode::Stopwatch;
}

void ClickAlarmMode()
{
    PauseSwInternal();
    PauseTimerInternal();
    g_mode = Mode::Alarm;
}

void ClickTimerMode()
{
    PauseSwInternal();
    PauseTimerInternal();
    g_mode = Mode::Timer;
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
// Alarm. Restart requires an explicit Space. Delegated to the
// anonymous-namespace internal helpers so the click trampolines
// (Pass D) and the keyboard Tab path share one implementation.
void PauseStopwatchIfRunning()
{
    PauseSwInternal();
}

void PauseTimerIfRunning()
{
    PauseTimerInternal();
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

    // Pass D: drive a synthetic click on the TIMR toolbar
    // button via the WidgetGroup dispatch chain. ClickTimerMode
    // sets g_mode = Mode::Timer (and pauses any running
    // counters); the test verifies the dispatch path is wired
    // end-to-end AND that the click mutates the view state.
    // Restore g_mode after.
    const Mode saved_mode = g_mode;
    BindClockOnce();
    // Anchor the toolbar at (0, 22, 240, 88) — same shape
    // boot_bringup.cpp registers the live Clock window with
    // (240x110 minus 22 px title bar). TIMR is mode index 3.
    RebindClockBounds(0U, 22U, 240U, 88U);
    g_mode = Mode::Clock;
    constexpr u32 kTimerIdx = 3U;
    const u32 nx = kClockToolbarPadX + kTimerIdx * (kClockToolbarBtnW + kClockToolbarBtnGap) + kClockToolbarBtnW / 2U;
    const u32 ny = 22U + kClockToolbarPadY + kClockToolbarBtnH / 2U;
    const Event n_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    const Event n_down{EventKind::MouseDown, nx, ny, 0U, 0U};
    const Event n_up{EventKind::MouseUp, nx, ny, 0U, 0U};
    if (g_clock.DispatchEvent(n_move) != EventResult::Consumed)
        pass = false;
    if (g_clock.DispatchEvent(n_down) != EventResult::Consumed)
        pass = false;
    if (g_clock.DispatchEvent(n_up) != EventResult::Consumed)
        pass = false;
    if (g_mode != Mode::Timer)
        pass = false;

    // Footer composer must produce non-empty text after a
    // refresh.
    RefreshClockFooter();
    if (g_clock_footer_text[0] == '\0')
        pass = false;

    // Restore pre-test state so the live UI is unchanged when
    // the umbrella selftest returns.
    g_mode = saved_mode;

    g_clock_self_test_passed = pass;
    if (pass)
    {
        SerialWrite("[clock] self-test OK (digit mask + row fit + widget-click)\n");
        SerialWrite("[clock-selftest] PASS\n");
    }
    else
    {
        SerialWrite("[clock] self-test FAILED\n");
        SerialWrite("[clock-selftest] FAIL\n");
    }
}

bool ClockSelfTestPassed()
{
    return g_clock_self_test_passed;
}

void ClockMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_handle == duetos::drivers::video::kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the
    // same frame RebindClockBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindClockOnce();
    RebindClockBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_clock_prev_left_down;
    const bool release_edge = !left_down && g_clock_prev_left_down;
    g_clock_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_clock.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the LED digit face below the toolbar has
        // no per-pixel click semantics in v0 — the dispatch
        // path's hit-test naturally short-circuits when the
        // click misses the toolbar bounds. MouseDown still
        // fires for the toolbar's Pressed-state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_clock.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside
        // the toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_clock.DispatchEvent(u);
    }
}

} // namespace duetos::apps::clock
