#include "apps/settings.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "drivers/gpu/dpms.h"
#include "drivers/gpu/modeset.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"

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
// Pass D chrome: DISPLAY panel. Header (Title Bold) + footer
// (Caption hint band) AppLabels stand the canonical hero / hint
// chrome up; the four data-bearing rows (resolution, pitch,
// DPMS state, transitions) and the four B/W/Y/U hint lines stay
// raw paint because their content is live-data + key-driven and
// composes better in-line than as separate AppLabels with their
// own static composer buffers.

constinit char g_disp_header[16] = "DISPLAY";
constinit char g_disp_footer[64] = "B:BLANK  W:WAKE  Y:STANDBY  U:SUSPEND";

constinit auto g_settings_display = MakeWidgetGroup(AppLabel{}, AppLabel{});

constinit bool g_settings_display_bound = false;
constinit bool g_settings_display_self_test_passed = false;

// ---------------------------------------------------------------
// Resolution selector + revert-timeout state (F-029).
//
// `g_sel` is the highlighted mode in the modeset list. `Apply`
// switches to it and arms a confirm window: if the user doesn't
// press K (keep) within kRevertSeconds, the next Draw() pass
// auto-reverts to the resolution that was live before Apply. This
// is the rubric's safety net — a mode that renders garbage (or an
// input-routing surprise) self-heals without the user being able
// to confirm a screen they can't see.

constexpr u64 kRevertSeconds = 10;

// Selected list index (0..DisplayModeCount()-1). Initialised lazily
// to the live mode on first Draw so the highlight starts on "current".
constinit u32 g_sel = 0;
constinit bool g_sel_init = false;

// Pending-confirm state. While `g_pending`, a revert is armed for
// `g_revert_deadline_ticks` and the previous geometry is stashed.
constinit bool g_pending = false;
constinit u64 g_revert_deadline_ticks = 0;
constinit u32 g_prev_w = 0;
constinit u32 g_prev_h = 0;

// Seconds remaining until auto-revert, clamped to [0, kRevertSeconds].
u64 RevertSecondsLeft()
{
    if (!g_pending)
        return 0;
    const u64 now = ::duetos::arch::TimerTicks();
    if (now >= g_revert_deadline_ticks)
        return 0;
    const u64 ticks_left = g_revert_deadline_ticks - now;
    return (ticks_left + ::duetos::arch::kTickFrequencyHz - 1) / ::duetos::arch::kTickFrequencyHz;
}

AppLabel& DspHeader()
{
    return g_settings_display.chain.head;
}
AppLabel& DspFooter()
{
    return g_settings_display.chain.tail.head;
}

void BindSettingsDisplayOnce()
{
    if (g_settings_display_bound)
        return;
    g_settings_display_bound = true;

    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    AppLabel& h = DspHeader();
    h.text = g_disp_header;
    h.role = ChromeTextRole::Title;
    h.weight = ChromeTextWeight::Bold;
    h.fg_rgb = fg;
    h.bg_rgb = bg;
    h.align_left = true;

    AppLabel& f = DspFooter();
    f.text = g_disp_footer;
    f.role = ChromeTextRole::Caption;
    f.weight = ChromeTextWeight::Regular;
    f.fg_rgb = dim;
    f.bg_rgb = bg;
    f.align_left = true;
}

void RebindSettingsDisplayBounds(u32 x, u32 y, u32 w, u32 h)
{
    constexpr u32 kHeaderH = 14U;
    constexpr u32 kFooterH = 12U;
    DspHeader().bounds = Rect{x, y, w, kHeaderH};
    const u32 fy = (h > kFooterH) ? y + h - kFooterH : y;
    DspFooter().bounds = Rect{x, fy, w, kFooterH};
}

// Decimal-render `v` into `out` at offset `*o`, capped at
// `cap - 1` chars.
void AppendDec(char* out, u32 cap, u32* o, u64 v)
{
    char tmp[24];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    while (n > 0 && *o + 1 < cap)
    {
        out[(*o)++] = tmp[--n];
    }
}

void AppendStr(char* out, u32 cap, u32* o, const char* s)
{
    while (*s != '\0' && *o + 1 < cap)
    {
        out[(*o)++] = *s++;
    }
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

    // Pass D chrome: anchor + paint header + footer labels.
    BindSettingsDisplayOnce();
    RebindSettingsDisplayBounds(x, y, w, h);
    Compose ctx{};
    g_settings_display.PaintAll(ctx);

    const auto fb = duetos::drivers::video::FramebufferGet();
    char line[80];
    u32 o = 0;
    AppendStr(line, sizeof(line), &o, "RESOLUTION: ");
    AppendDec(line, sizeof(line), &o, fb.width);
    AppendStr(line, sizeof(line), &o, " x ");
    AppendDec(line, sizeof(line), &o, fb.height);
    AppendStr(line, sizeof(line), &o, " @ ");
    AppendDec(line, sizeof(line), &o, fb.bpp);
    AppendStr(line, sizeof(line), &o, " bpp");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 14, line, fg, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "PITCH: ");
    AppendDec(line, sizeof(line), &o, fb.pitch);
    AppendStr(line, sizeof(line), &o, " bytes");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 26, line, dim, bg);

    // Resolution selector (F-029). The actual auto-revert modeset is
    // driven by SettingsDisplayRevertTick() from the UiTicker OUTSIDE
    // the compose pass (rebinding the FB mid-compose is unsafe); here
    // we only render the live state + countdown.
    using duetos::drivers::gpu::DisplayCurrentModeIndex;
    using duetos::drivers::gpu::DisplayModeAt;
    using duetos::drivers::gpu::DisplayModeCount;
    using duetos::drivers::gpu::DisplayModesetAvailable;

    if (!g_sel_init)
    {
        const u32 ci = DisplayCurrentModeIndex();
        g_sel = (ci < DisplayModeCount()) ? ci : 0;
        g_sel_init = true;
    }

    const u32 sel_y = y + 44;
    if (DisplayModesetAvailable())
    {
        ChromeTextDraw(ChromeTextRole::Body, x, sel_y, "RESOLUTION (,/. select  M apply):", fg, bg);
        const u32 cur_idx = DisplayCurrentModeIndex();
        for (u32 i = 0; i < DisplayModeCount(); ++i)
        {
            const auto& m = DisplayModeAt(i);
            o = 0;
            // Marker column: '>' selected, '*' currently-live mode.
            AppendStr(line, sizeof(line), &o, (i == g_sel) ? "> " : "  ");
            AppendStr(line, sizeof(line), &o, m.label);
            if (i == cur_idx)
                AppendStr(line, sizeof(line), &o, "   (current)");
            line[o] = '\0';
            const u32 row_fg = (i == g_sel) ? fg : dim;
            ChromeTextDraw(ChromeTextRole::Body, x + 8, sel_y + 14 + i * 12, line, row_fg, bg);
        }

        // Confirm / revert countdown banner while a mode is pending.
        const u32 after_list = sel_y + 14 + DisplayModeCount() * 12 + 4;
        if (g_pending)
        {
            o = 0;
            AppendStr(line, sizeof(line), &o, "KEEP THIS MODE? press K  (auto-revert in ");
            AppendDec(line, sizeof(line), &o, RevertSecondsLeft());
            AppendStr(line, sizeof(line), &o, "s)");
            line[o] = '\0';
            ChromeTextDraw(ChromeTextRole::Body, x, after_list, line, fg, bg);
        }
        else
        {
            ChromeTextDraw(ChromeTextRole::Caption, x, after_list, "M: APPLY SELECTED  K: KEEP (confirm)  ,/.: SELECT",
                           dim, bg);
        }
    }
    else
    {
        ChromeTextDraw(ChromeTextRole::Caption, x, sel_y, "RESOLUTION: fixed (no re-programmable display backend)", dim,
                       bg);
    }

    o = 0;
    AppendStr(line, sizeof(line), &o, "DPMS: ");
    AppendStr(line, sizeof(line), &o, duetos::drivers::gpu::DpmsStateName(duetos::drivers::gpu::DpmsGet()));
    AppendStr(line, sizeof(line), &o, "  (B blank / W wake / Y standby / U suspend)");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Caption, x, y + h - 24, line, dim, bg);
}

bool Key(char c)
{
    using duetos::drivers::gpu::DisplayCurrentModeIndex;
    using duetos::drivers::gpu::DisplayModeAt;
    using duetos::drivers::gpu::DisplayModeCount;
    using duetos::drivers::gpu::DisplayModesetAvailable;
    using duetos::drivers::gpu::DisplaySetMode;
    using duetos::drivers::gpu::DpmsSetState;
    using duetos::drivers::gpu::DpmsState;

    // Resolution selector controls (F-029). Only active when a
    // re-programmable backend (virtio-gpu) owns the framebuffer.
    if (DisplayModesetAvailable())
    {
        if (!g_sel_init)
        {
            const u32 ci = DisplayCurrentModeIndex();
            g_sel = (ci < DisplayModeCount()) ? ci : 0;
            g_sel_init = true;
        }
        // ',' / '<' previous mode; '.' / '>' next mode.
        if (c == ',' || c == '<')
        {
            g_sel = (g_sel == 0) ? DisplayModeCount() - 1 : g_sel - 1;
            return true;
        }
        if (c == '.' || c == '>')
        {
            g_sel = (g_sel + 1) % DisplayModeCount();
            return true;
        }
        // 'M' applies the selected mode + arms the confirm window.
        if (c == 'm' || c == 'M')
        {
            const auto fb = duetos::drivers::video::FramebufferGet();
            const auto& m = DisplayModeAt(g_sel);
            if (m.width == fb.width && m.height == fb.height)
            {
                duetos::drivers::video::NotifyShow("already at that resolution");
                return true;
            }
            // Stash the live geometry so a lapsed confirm reverts to
            // it, THEN switch. If the switch fails the old mode is
            // still live (reset-scanout is allocation-safe).
            g_prev_w = fb.width;
            g_prev_h = fb.height;
            if (DisplaySetMode(m.width, m.height))
            {
                g_pending = true;
                g_revert_deadline_ticks =
                    ::duetos::arch::TimerTicks() + kRevertSeconds * ::duetos::arch::kTickFrequencyHz;
                duetos::drivers::video::NotifyShow("resolution applied — press K to keep");
            }
            else
            {
                duetos::drivers::video::NotifyShow("resolution change failed");
            }
            return true;
        }
        // 'K' confirms (keep) the pending mode, disarming the revert.
        if (c == 'k' || c == 'K')
        {
            if (g_pending)
            {
                g_pending = false;
                g_sel = DisplayCurrentModeIndex();
                if (g_sel >= DisplayModeCount())
                    g_sel = 0;
                duetos::drivers::video::NotifyShow("resolution kept");
            }
            return true;
        }
    }

    if (c == 'b' || c == 'B')
    {
        DpmsSetState(DpmsState::Off);
        duetos::drivers::video::NotifyShow("monitor sleep (DPMS Off)");
        return true;
    }
    if (c == 'w' || c == 'W')
    {
        DpmsSetState(DpmsState::On);
        duetos::drivers::video::NotifyShow("monitor wake");
        return true;
    }
    if (c == 'y' || c == 'Y')
    {
        DpmsSetState(DpmsState::Standby);
        duetos::drivers::video::NotifyShow("monitor standby");
        return true;
    }
    if (c == 'u' || c == 'U')
    {
        DpmsSetState(DpmsState::Suspend);
        duetos::drivers::video::NotifyShow("monitor suspend");
        return true;
    }
    return false;
}

} // namespace

void SettingsDisplayInit()
{
    SettingsRegisterPanel(Panel::Display, Draw, Key);
}

void SettingsDisplaySelfTest()
{
    using duetos::arch::SerialWrite;
    bool ok = true;

    // Pass D chrome: bind + rebind only. Skipping PaintAll because
    // under TTF themes (duet*) AppLabel::PaintSelf routes into
    // TtfDrawString -> CompositeCoverage -> FramebufferBlendFill at
    // the synthetic (0,0) origin and races the compositor lock
    // before the WM is online (silent boot halt). The live Draw()
    // path exercises paint when the settings shell composes us.
    BindSettingsDisplayOnce();
    RebindSettingsDisplayBounds(0U, 0U, 256U, 160U);

    if (g_disp_header[0] == '\0' || g_disp_footer[0] == '\0')
        ok = false;
    if (DspHeader().text == nullptr || DspFooter().text == nullptr)
        ok = false;

    g_settings_display_self_test_passed = ok;
    SerialWrite(ok ? "[settings-display-selftest] PASS\n" : "[settings-display-selftest] FAIL\n");
}

bool SettingsDisplaySelfTestPassed()
{
    return g_settings_display_self_test_passed;
}

bool SettingsDisplayRevertTick()
{
    if (!g_pending)
        return false;
    if (::duetos::arch::TimerTicks() < g_revert_deadline_ticks)
        return false;
    // Confirm window lapsed without a Keep — revert to the previous
    // geometry. The caller guarantees we're OUTSIDE a compose pass +
    // hold the compositor lock, so the FB rebind + compose-buffer
    // drop inside DisplaySetMode are safe.
    g_pending = false;
    if (duetos::drivers::gpu::DisplaySetMode(g_prev_w, g_prev_h))
    {
        g_sel = duetos::drivers::gpu::DisplayCurrentModeIndex();
        if (g_sel >= duetos::drivers::gpu::DisplayModeCount())
            g_sel = 0;
        duetos::drivers::video::NotifyShow("resolution reverted (not confirmed)");
        return true;
    }
    return false;
}

} // namespace duetos::apps::settings
