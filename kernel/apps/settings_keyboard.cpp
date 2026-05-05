#include "apps/settings.h"

#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"

namespace duetos::apps::settings
{

namespace
{

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
        out[(*o)++] = tmp[--n];
}

void AppendStr(char* out, u32 cap, u32* o, const char* s)
{
    while (*s != '\0' && *o + 1 < cap)
        out[(*o)++] = *s++;
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
    FramebufferDrawString(x, y, "KEYBOARD", fg, bg);
    FramebufferDrawString(x, y + 14, "LAYOUT: US (hardcoded)", dim, bg);
    FramebufferDrawString(x, y + 26, "REPEAT: PS/2 hardware default", dim, bg);

    // Live diagnostics — counters from the PS/2 driver.
    const auto stats = duetos::drivers::input::Ps2KeyboardStats();
    char line[80];
    u32 o = 0;
    AppendStr(line, sizeof(line), &o, "IRQS: ");
    AppendDec(line, sizeof(line), &o, stats.irqs_seen);
    line[o] = '\0';
    FramebufferDrawString(x, y + 46, line, fg, bg);
    o = 0;
    AppendStr(line, sizeof(line), &o, "BYTES BUFFERED: ");
    AppendDec(line, sizeof(line), &o, stats.bytes_buffered);
    line[o] = '\0';
    FramebufferDrawString(x, y + 58, line, dim, bg);
    o = 0;
    AppendStr(line, sizeof(line), &o, "BYTES DROPPED: ");
    AppendDec(line, sizeof(line), &o, stats.bytes_dropped);
    line[o] = '\0';
    FramebufferDrawString(x, y + 70, line, dim, bg);

    // Async modifier readout.
    const u8 mods = duetos::drivers::video::WindowModifierState();
    o = 0;
    AppendStr(line, sizeof(line), &o, "MODIFIERS:");
    if ((mods & duetos::drivers::input::kKeyModShift) != 0)
        AppendStr(line, sizeof(line), &o, " SHIFT");
    if ((mods & duetos::drivers::input::kKeyModCtrl) != 0)
        AppendStr(line, sizeof(line), &o, " CTRL");
    if ((mods & duetos::drivers::input::kKeyModAlt) != 0)
        AppendStr(line, sizeof(line), &o, " ALT");
    if ((mods & duetos::drivers::input::kKeyModCapsLock) != 0)
        AppendStr(line, sizeof(line), &o, " CAPS");
    if (mods == 0)
        AppendStr(line, sizeof(line), &o, " (none)");
    line[o] = '\0';
    FramebufferDrawString(x, y + 90, line, fg, bg);

    FramebufferDrawString(x, y + 110, "(layout / repeat config: future slice)", dim, bg);
}

bool Key(char /*c*/)
{
    return false;
}

} // namespace

void SettingsKeyboardInit()
{
    SettingsRegisterPanel(Panel::Keyboard, Draw, Key);
}

} // namespace duetos::apps::settings
