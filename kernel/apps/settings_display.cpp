#include "apps/settings.h"

#include "arch/x86_64/serial.h"
#include "drivers/gpu/dpms.h"
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

    o = 0;
    AppendStr(line, sizeof(line), &o, "DPMS STATE: ");
    AppendStr(line, sizeof(line), &o, duetos::drivers::gpu::DpmsStateName(duetos::drivers::gpu::DpmsGet()));
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 44, line, fg, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "TRANSITIONS: ");
    AppendDec(line, sizeof(line), &o, duetos::drivers::gpu::DpmsTransitionCount());
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 56, line, dim, bg);

    // Hint lines — Caption role for key-shortcut help under the readouts.
    // The bottom-pinned AppLabel footer carries the canonical one-liner;
    // the four expanded rows here document the long-form effect of each
    // key for a user who hasn't memorised the abbreviations.
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 80, "B: BLANK MONITOR (DPMS Off)", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 92, "W: WAKE MONITOR (DPMS On)", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 104, "Y: STANDBY (H-sync off)", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 116, "U: SUSPEND (V-sync off)", dim, bg);
}

bool Key(char c)
{
    using duetos::drivers::gpu::DpmsSetState;
    using duetos::drivers::gpu::DpmsState;
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

} // namespace duetos::apps::settings
