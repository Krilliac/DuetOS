#include "drivers/video/desktop_gadgets.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/render_stats.h"
#include "drivers/video/taskbar.h"
#include "drivers/video/theme.h"
#include "mm/frame_allocator.h"
#include "sched/sched.h"
#include "sched/sched_sample_ring.h"

namespace duetos::drivers::video
{

namespace
{

// Gadget column metrics. docs/aurora-theme/README.md §1 puts the column
// at right:44 top:44 with width 300 on the 1920 canvas;
// IMPLEMENTATION.md §7 scales the column to 220 at 1024. The panel
// height is not in the table — 88 is what the reference's clock panel
// measures once the type stops scaling at 11 px.
constexpr u32 kColW = 220;
constexpr u32 kEdgeInset = 24;
constexpr u32 kClockH = 88;
constexpr u32 kPanelGap = 12;
constexpr u32 kKernelH = 126;
constexpr u32 kAbiH = 92;
constexpr u32 kColumnH = kClockH + kPanelGap + kKernelH + kPanelGap + kAbiH;
constexpr u32 kPadX = 16;
constexpr u32 kDialR = 18;
constexpr u32 kKernelSparkW = 46;
constexpr u32 kKernelSparkH = 18;

constinit RenderFpsWindow g_gadget_fps_window{};

// Sine of 6*k degrees in Q10, k = 0..15 (0..90 degrees). A minute hand
// needs 60 distinct directions, so a 12-entry hour table won't do; the
// quadrant table plus reflection covers all 60 in 16 constants.
constexpr i32 kSinQ10[16] = {0, 107, 213, 316, 417, 512, 602, 685, 761, 828, 887, 935, 974, 1002, 1018, 1024};

// sin(6*k degrees), k = 0..59, Q10.
i32 Sin60(u32 k)
{
    k %= 60U;
    if (k <= 15U)
        return kSinQ10[k];
    if (k <= 30U)
        return kSinQ10[30U - k];
    if (k <= 45U)
        return -kSinQ10[k - 30U];
    return -kSinQ10[60U - k];
}

i32 Cos60(u32 k)
{
    return Sin60(k + 15U);
}

// Draw a clock hand from the dial centre to `len` pixels out, pointing
// at position `pos` on a 60-step dial where 0 is straight up and the
// count runs clockwise.
void DrawHand(i32 cx, i32 cy, u32 pos, i32 len, u32 rgb)
{
    const i32 ex = cx + (len * Sin60(pos)) / 1024;
    const i32 ey = cy - (len * Cos60(pos)) / 1024;
    FramebufferDrawLine(cx, cy, ex, ey, rgb);
}

// Append `s` to `dst` at `*at`, stopping before `cap - 1`. Returns
// nothing; `*at` advances by however much actually fit.
void Append(char* dst, u32* at, u32 cap, const char* s)
{
    while (*s != '\0' && *at + 1U < cap)
    {
        dst[(*at)++] = *s++;
    }
    dst[*at] = '\0';
}

void AppendU32(char* dst, u32* at, u32 cap, u32 v)
{
    char tmp[12];
    u32 n = 0;
    do
    {
        tmp[n++] = static_cast<char>('0' + (v % 10U));
        v /= 10U;
    } while (v != 0 && n < sizeof(tmp));
    while (n > 0 && *at + 1U < cap)
    {
        dst[(*at)++] = tmp[--n];
    }
    dst[*at] = '\0';
}

void AppendU64(char* dst, u32* at, u32 cap, u64 v)
{
    char tmp[21];
    u32 n = 0;
    do
    {
        tmp[n++] = static_cast<char>('0' + (v % 10U));
        v /= 10U;
    } while (v != 0 && n < sizeof(tmp));
    while (n > 0 && *at + 1U < cap)
    {
        dst[(*at)++] = tmp[--n];
    }
    dst[*at] = '\0';
}

void FormatU64(char* dst, u32 cap, u64 v)
{
    u32 at = 0;
    dst[0] = '\0';
    AppendU64(dst, &at, cap, v);
}

void FormatCpuPct(char* dst, u32 cap, u32 pct)
{
    if (cap == 0)
    {
        return;
    }
    if (pct > 99U)
    {
        pct = 99U;
    }
    u32 at = 0;
    if (pct >= 10U && at + 1U < cap)
    {
        dst[at++] = static_cast<char>('0' + pct / 10U);
    }
    if (at + 1U < cap)
    {
        dst[at++] = static_cast<char>('0' + pct % 10U);
    }
    if (at + 1U < cap)
    {
        dst[at++] = '%';
    }
    dst[at] = '\0';
}

void FormatFps(char* dst, u32 cap, RenderFps fps)
{
    if (cap == 0)
    {
        return;
    }
    if (!fps.valid)
    {
        u32 at = 0;
        Append(dst, &at, cap, "--.-");
        return;
    }
    u32 whole = fps.fps_x10 / 10U;
    const u32 frac = fps.fps_x10 % 10U;
    u32 at = 0;
    if (whole >= 100U && at + 1U < cap)
    {
        dst[at++] = static_cast<char>('0' + whole / 100U);
        whole %= 100U;
    }
    if (whole >= 10U && at + 1U < cap)
    {
        dst[at++] = static_cast<char>('0' + whole / 10U);
    }
    if (at + 1U < cap)
    {
        dst[at++] = static_cast<char>('0' + whole % 10U);
    }
    if (at + 1U < cap)
    {
        dst[at++] = '.';
    }
    if (at + 1U < cap)
    {
        dst[at++] = static_cast<char>('0' + frac);
    }
    dst[at] = '\0';
}

void DrawGlassPanel(u32 x, u32 y, u32 w, u32 h, const Theme& theme)
{
    const u32 radius = theme.surface_radius;
    FramebufferBlendRoundRect(x, y, w, h, radius, (theme.glass_alpha << 24) | (theme.taskbar_bg & 0x00FFFFFFU));
    FramebufferDrawRoundRect(x, y, w, h, radius, theme.taskbar_border);
    if (w > 2U * radius)
    {
        FramebufferBlendFill(x + radius, y + 1U, w - 2U * radius, 1U, (theme.sheen_alpha << 24) | 0x00FFFFFFU);
    }
}

void DrawMetricRow(u32 x, u32 y, const char* label, const char* value, const Theme& theme, u32 value_ink)
{
    constexpr u32 kLabelW = 58;
    ChromeTextDraw(ChromeTextRole::Caption, x, y, label, theme.taskbar_tab_inactive, theme.taskbar_bg);
    ChromeTextDraw(ChromeTextRole::Caption, x + kLabelW, y, value, value_ink, theme.taskbar_bg);
}

void DrawCpuSparkline(u32 x, u32 y, u32 w, u32 h, const sched::SchedStatsSampleSnapshot& samples, u32 ink, u32 dim)
{
    if (w == 0 || h == 0)
    {
        return;
    }
    FramebufferFillRect(x, y + h - 1U, w, 1U, dim);
    const u32 count = (samples.count > w) ? w : samples.count;
    const u32 left_pad = w - count;
    for (u32 i = 0; i < count; ++i)
    {
        const auto& s = samples.samples[samples.count - count + i];
        const u32 pct = s.valid ? s.cpu_busy_pct : 0U;
        u32 bar_h = (pct * (h - 1U) + 99U) / 100U;
        if (bar_h == 0)
        {
            bar_h = 1U;
        }
        FramebufferFillRect(x + left_pad + i, y + h - bar_h, 1U, bar_h, ink);
    }
}

// Zeller's congruence — same derivation as the taskbar's date row.
// Returns 0 = Sunday.
u32 DayOfWeek(u32 year, u32 month, u32 day)
{
    if (month < 1U || month > 12U)
        month = 1U;
    if (month < 3U)
    {
        month += 12U;
        --year;
    }
    const u32 k = year % 100U;
    const u32 j = year / 100U;
    const u32 h = (day + (13U * (month + 1U)) / 5U + k + k / 4U + j / 4U + 5U * j) % 7U;
    return (h + 6U) % 7U;
}

// Top-left of the gadget column, and whether it fits at all. The column
// has to clear the taskbar's reserve at the bottom; on a framebuffer too
// narrow or short to hold it the gadget simply doesn't paint.
bool ColumnOrigin(u32* out_x, u32* out_y)
{
    const FramebufferInfo fb = FramebufferGet();
    if (fb.width < kColW + 2U * kEdgeInset)
    {
        return false;
    }
    const u32 bottom_limit = (fb.height > TaskbarHeight()) ? fb.height - TaskbarHeight() : 0U;
    if (kEdgeInset + kColumnH >= bottom_limit)
    {
        return false;
    }
    *out_x = fb.width - kEdgeInset - kColW;
    *out_y = kEdgeInset;
    return true;
}

} // namespace

void DesktopGadgetsPaint()
{
    const Theme& theme = ThemeCurrent();
    // No glass vocabulary, no gadget: on a flat palette this would be an
    // opaque slab sitting on the wallpaper, which is worse than absent.
    if (theme.surface_radius == 0 || !ThemeTactilityEffective())
    {
        return;
    }
    u32 px = 0;
    u32 py = 0;
    if (!ColumnOrigin(&px, &py))
    {
        return;
    }

    const u32 accent = theme.taskbar_accent;
    const u32 radius = theme.surface_radius;

    // Glass body + border + the 1-px sheen along the top edge, mirroring
    // the taskbar island so the two surfaces read as the same material.
    FramebufferBlendRoundRect(px, py, kColW, kClockH, radius,
                              (theme.glass_alpha << 24) | (theme.taskbar_bg & 0x00FFFFFFU));
    FramebufferDrawRoundRect(px, py, kColW, kClockH, radius, theme.taskbar_border);
    if (kColW > 2U * radius)
    {
        FramebufferBlendFill(px + radius, py + 1U, kColW - 2U * radius, 1U, (theme.sheen_alpha << 24) | 0x00FFFFFFU);
    }

    arch::RtcTime rtc{};
    arch::RtcRead(&rtc);

    // "HH:MM" at Title weight, the panel's dominant figure.
    char clk[6];
    clk[0] = static_cast<char>('0' + rtc.hour / 10U);
    clk[1] = static_cast<char>('0' + rtc.hour % 10U);
    clk[2] = ':';
    clk[3] = static_cast<char>('0' + rtc.minute / 10U);
    clk[4] = static_cast<char>('0' + rtc.minute % 10U);
    clk[5] = '\0';
    const u32 clk_h = ChromeTextRoleHeight(ChromeTextRole::Title);
    const u32 clk_y = py + kClockH / 2U - clk_h;
    ChromeTextDraw(ChromeTextRole::Title, px + kPadX, clk_y, clk, theme.taskbar_fg, theme.taskbar_bg,
                   ChromeTextWeight::Bold);

    // "Tuesday, July 28" underneath, in the muted inactive ink — the
    // date is context for the time, not a second headline.
    static const char* const kWeekday[7] = {"Sunday",   "Monday", "Tuesday", "Wednesday",
                                            "Thursday", "Friday", "Saturday"};
    static const char* const kMonth[12] = {"January", "February", "March",     "April",   "May",      "June",
                                           "July",    "August",   "September", "October", "November", "December"};
    char date[32];
    u32 at = 0;
    date[0] = '\0';
    Append(date, &at, sizeof(date), kWeekday[DayOfWeek(rtc.year, rtc.month, rtc.day) % 7U]);
    Append(date, &at, sizeof(date), ", ");
    Append(date, &at, sizeof(date), kMonth[((rtc.month >= 1U && rtc.month <= 12U) ? rtc.month : 1U) - 1U]);
    Append(date, &at, sizeof(date), " ");
    AppendU32(date, &at, sizeof(date), rtc.day);
    ChromeTextDraw(ChromeTextRole::Caption, px + kPadX, clk_y + clk_h + 6U, date, theme.taskbar_tab_inactive,
                   theme.taskbar_bg);

    // Analogue dial on the right: rim, hour hand, minute hand, and a
    // glowing accent hub. There is no second hand — the compose pump
    // runs at 1 Hz at best, so a second hand would lie about how fresh
    // the reading is.
    const i32 dcx = static_cast<i32>(px + kColW - kPadX - kDialR);
    const i32 dcy = static_cast<i32>(py + kClockH / 2U);
    FramebufferDrawCircle(dcx, dcy, kDialR, theme.taskbar_tab_inactive);
    for (u32 tick = 0; tick < 12U; ++tick)
    {
        const i32 tx = dcx + (static_cast<i32>(kDialR - 3U) * Sin60(tick * 5U)) / 1024;
        const i32 ty = dcy - (static_cast<i32>(kDialR - 3U) * Cos60(tick * 5U)) / 1024;
        FramebufferFillRect(static_cast<u32>(tx), static_cast<u32>(ty), 1U, 1U, theme.taskbar_tab_inactive);
    }
    // Hour hand advances with the minutes, so 07:30 points half past
    // seven rather than snapping to the hour mark.
    const u32 hour_pos = ((rtc.hour % 12U) * 5U + rtc.minute / 12U) % 60U;
    DrawHand(dcx, dcy, hour_pos, static_cast<i32>(kDialR) - 9, theme.taskbar_fg);
    DrawHand(dcx, dcy, rtc.minute % 60U, static_cast<i32>(kDialR) - 5, theme.taskbar_fg);
    FramebufferBlendFill(static_cast<u32>(dcx) - 2U, static_cast<u32>(dcy) - 2U, 5U, 5U,
                         (110U << 24) | (accent & 0x00FFFFFFU));
    FramebufferFillRect(static_cast<u32>(dcx) - 1U, static_cast<u32>(dcy) - 1U, 2U, 2U, accent);

    sched::SchedStatsSampleSnapshot samples{};
    sched::SchedStatsSampleSnapshotRead(&samples);
    const sched::SchedStatsSample* latest = (samples.count != 0 && samples.samples[samples.count - 1U].valid)
                                                ? &samples.samples[samples.count - 1U]
                                                : nullptr;
    const u32 cpu_pct = (latest != nullptr) ? latest->cpu_busy_pct : 0U;
    const u32 live = (latest != nullptr) ? latest->tasks_live : 0U;
    const u32 sleeping = (latest != nullptr) ? latest->tasks_sleeping : 0U;
    const u32 blocked = (latest != nullptr) ? latest->tasks_blocked : 0U;
    const u64 ctxsw = (latest != nullptr) ? latest->context_switches : 0U;
    const u32 native = (latest != nullptr) ? latest->native_processes : 0U;
    const u32 win32 = (latest != nullptr) ? latest->win32_processes : 0U;
    const u32 linux = (latest != nullptr) ? latest->linux_processes : 0U;
    const u32 peer_accent = (theme.accent_peer != 0) ? theme.accent_peer : 0x00F5B73A;

    const u32 kernel_y = py + kClockH + kPanelGap;
    DrawGlassPanel(px, kernel_y, kColW, kKernelH, theme);
    ChromeTextDraw(ChromeTextRole::Caption, px + kPadX, kernel_y + 10U, "Kernel", accent, theme.taskbar_bg,
                   ChromeTextWeight::Bold);
    DrawCpuSparkline(px + kPadX, kernel_y + 31U, kKernelSparkW, kKernelSparkH, samples, accent, theme.taskbar_border);

    char cpu_val[8];
    char live_val[16];
    char sleep_val[16];
    char block_val[16];
    char ctx_val[22];
    char fps_val[8];
    FormatCpuPct(cpu_val, sizeof(cpu_val), cpu_pct);
    FormatU64(live_val, sizeof(live_val), live);
    FormatU64(sleep_val, sizeof(sleep_val), sleeping);
    FormatU64(block_val, sizeof(block_val), blocked);
    FormatU64(ctx_val, sizeof(ctx_val), ctxsw);
    const RenderFps fps =
        RenderFpsSample(g_gadget_fps_window, arch::TimerTicks(), static_cast<u32>(arch::kTickFrequencyHz));
    FormatFps(fps_val, sizeof(fps_val), fps);

    const u32 row_step = ChromeTextRoleHeight(ChromeTextRole::Caption) + 3U;
    u32 row_y = kernel_y + 54U;
    DrawMetricRow(px + kPadX, row_y, "cpu", cpu_val, theme, theme.taskbar_fg);
    row_y += row_step;
    DrawMetricRow(px + kPadX, row_y, "live", live_val, theme, theme.taskbar_fg);
    row_y += row_step;
    DrawMetricRow(px + kPadX, row_y, "sleep", sleep_val, theme, theme.taskbar_fg);
    row_y += row_step;
    DrawMetricRow(px + kPadX, row_y, "block", block_val, theme, theme.taskbar_fg);
    row_y += row_step;
    DrawMetricRow(px + kPadX, row_y, "ctx", ctx_val, theme, theme.taskbar_fg);
    ChromeTextDraw(ChromeTextRole::Caption, px + kPadX + 118U, kernel_y + 32U, fps_val, peer_accent, theme.taskbar_bg);
    ChromeTextDraw(ChromeTextRole::Caption,
                   px + kPadX + 118U + ChromeTextMeasure(ChromeTextRole::Caption, fps_val) +
                       ChromeTextMeasure(ChromeTextRole::Caption, " "),
                   kernel_y + 32U, "FPS", theme.taskbar_fg, theme.taskbar_bg);

    const u32 abi_y = kernel_y + kKernelH + kPanelGap;
    DrawGlassPanel(px, abi_y, kColW, kAbiH, theme);
    ChromeTextDraw(ChromeTextRole::Caption, px + kPadX, abi_y + 10U, "ABI peers", peer_accent, theme.taskbar_bg,
                   ChromeTextWeight::Bold);

    char native_val[16];
    char win32_val[16];
    char linux_val[16];
    char total_val[16];
    FormatU64(native_val, sizeof(native_val), native);
    FormatU64(win32_val, sizeof(win32_val), win32);
    FormatU64(linux_val, sizeof(linux_val), linux);
    FormatU64(total_val, sizeof(total_val), native + win32 + linux);
    row_y = abi_y + 31U;
    DrawMetricRow(px + kPadX, row_y, "native", native_val, theme, accent);
    row_y += row_step;
    DrawMetricRow(px + kPadX, row_y, "win32", win32_val, theme, peer_accent);
    row_y += row_step;
    DrawMetricRow(px + kPadX, row_y, "linux", linux_val, theme, theme.taskbar_fg);
    row_y += row_step;
    DrawMetricRow(px + kPadX, row_y, "total", total_val, theme, theme.taskbar_fg);
}

void DesktopGadgetsSelfTest()
{
    const FramebufferInfo fb = FramebufferGet();
    u32 px = 0;
    u32 py = 0;
    bool ok = true;
    if (ColumnOrigin(&px, &py))
    {
        // Fully on screen horizontally, and clear of the taskbar reserve.
        if (px + kColW > fb.width)
            ok = false;
        if (py + kColumnH > fb.height - TaskbarHeight())
            ok = false;
    }
    arch::SerialWrite(ok ? "[desktop-gadgets] selftest PASS\n" : "[desktop-gadgets] selftest FAIL\n");
}

} // namespace duetos::drivers::video
