#include "apps/settings.h"

#include "drivers/gpu/dpms.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"

namespace duetos::apps::settings
{

namespace
{

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
    using duetos::drivers::video::ChromeTextRole;
    using duetos::drivers::video::ChromeTextWeight;
    const auto& th = duetos::drivers::video::ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    if (w < 8 * 24 || h < 8 * 8)
        return;
    // Section header — Title + Bold for the panel's hero label.
    ChromeTextDraw(ChromeTextRole::Title, x, y, "DISPLAY", fg, bg, ChromeTextWeight::Bold);
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

} // namespace duetos::apps::settings
