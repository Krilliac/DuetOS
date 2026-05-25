#include "apps/settings.h"

#include "drivers/input/ps2kbd.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"

namespace duetos::apps::settings
{

// Cached typematic indices so the panel can render the
// current values + so successive +/- key presses step from a
// known anchor. Defaults match the BIOS-set typematic the
// PS/2 controller comes up with on most hardware. Lifted out
// of the anonymous namespace so KeyboardTypematic{Rate,Delay}Idx
// + KeyboardSetTypematicIdx can read/write them — those are the
// hooks SessionRestoreApply / SessionRestoreSave use to round-
// trip these values through SESSION.CFG.
constinit u8 g_rate_idx = 0xB; // ~10.9 Hz — comfortable
constinit u8 g_delay_idx = 1;  // 500 ms

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
    ChromeTextDraw(ChromeTextRole::Title, x, y, "KEYBOARD", fg, bg, ChromeTextWeight::Bold);
    ChromeTextDraw(ChromeTextRole::Body, x, y + 14, "LAYOUT: US (hardcoded)", dim, bg);
    ChromeTextDraw(ChromeTextRole::Body, x, y + 26, "REPEAT: PS/2 hardware default", dim, bg);

    // Live diagnostics — counters from the PS/2 driver.
    const auto stats = duetos::drivers::input::Ps2KeyboardStats();
    char line[80];
    u32 o = 0;
    AppendStr(line, sizeof(line), &o, "IRQS: ");
    AppendDec(line, sizeof(line), &o, stats.irqs_seen);
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 46, line, fg, bg);
    o = 0;
    AppendStr(line, sizeof(line), &o, "BYTES BUFFERED: ");
    AppendDec(line, sizeof(line), &o, stats.bytes_buffered);
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 58, line, dim, bg);
    o = 0;
    AppendStr(line, sizeof(line), &o, "BYTES DROPPED: ");
    AppendDec(line, sizeof(line), &o, stats.bytes_dropped);
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 70, line, dim, bg);

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
    ChromeTextDraw(ChromeTextRole::Body, x, y + 90, line, fg, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "REPEAT RATE IDX: ");
    AppendDec(line, sizeof(line), &o, g_rate_idx);
    AppendStr(line, sizeof(line), &o, " (lower = faster, 0..31)");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 106, line, fg, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "REPEAT DELAY IDX: ");
    AppendDec(line, sizeof(line), &o, g_delay_idx);
    static const char* kDelayMs[4] = {"250 ms", "500 ms", "750 ms", "1000 ms"};
    AppendStr(line, sizeof(line), &o, " (");
    AppendStr(line, sizeof(line), &o, kDelayMs[g_delay_idx & 0x3]);
    AppendStr(line, sizeof(line), &o, ")");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 118, line, fg, bg);

    // Hint lines — Caption role for key-shortcut help.
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 134, "F : faster repeat   S : slower repeat", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 146, "D : longer delay    Q : shorter delay", dim, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "ACTIVE LAYOUT: ");
    switch (duetos::drivers::input::Ps2KeyboardLayout())
    {
    case duetos::drivers::input::KeyboardLayout::US:
        AppendStr(line, sizeof(line), &o, "US QWERTY");
        break;
    case duetos::drivers::input::KeyboardLayout::UK:
        AppendStr(line, sizeof(line), &o, "UK QWERTY");
        break;
    case duetos::drivers::input::KeyboardLayout::Dvorak:
        AppendStr(line, sizeof(line), &o, "DVORAK SIMPLIFIED");
        break;
    case duetos::drivers::input::KeyboardLayout::DE:
        AppendStr(line, sizeof(line), &o, "DE QWERTZ (ASCII subset)");
        break;
    case duetos::drivers::input::KeyboardLayout::FR:
        AppendStr(line, sizeof(line), &o, "FR AZERTY (ASCII subset)");
        break;
    case duetos::drivers::input::KeyboardLayout::Colemak:
        AppendStr(line, sizeof(line), &o, "COLEMAK");
        break;
    }
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 162, line, fg, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 174,
                   "1:US  2:UK  3:DVORAK  4:DE  5:FR  6:COLEMAK", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 186,
                   "(DE/FR diacritics: ASCII fallback for now)", dim, bg);
}

bool Key(char c)
{
    auto apply = []()
    {
        if (duetos::drivers::input::Ps2KeyboardSetTypematic(g_rate_idx, g_delay_idx))
        {
            duetos::drivers::video::NotifyShow("typematic updated");
        }
        else
        {
            duetos::drivers::video::NotifyShow("typematic write rejected");
        }
    };
    if (c == 'f' || c == 'F')
    {
        if (g_rate_idx > 0)
            --g_rate_idx;
        apply();
        return true;
    }
    if (c == 's' || c == 'S')
    {
        if (g_rate_idx < 31)
            ++g_rate_idx;
        apply();
        return true;
    }
    if (c == 'd' || c == 'D')
    {
        if (g_delay_idx < 3)
            ++g_delay_idx;
        apply();
        return true;
    }
    if (c == 'q' || c == 'Q')
    {
        if (g_delay_idx > 0)
            --g_delay_idx;
        apply();
        return true;
    }
    using duetos::drivers::input::KeyboardLayout;
    using duetos::drivers::input::Ps2KeyboardSetLayout;
    if (c == '1')
    {
        Ps2KeyboardSetLayout(KeyboardLayout::US);
        duetos::drivers::video::NotifyShow("layout: US QWERTY");
        return true;
    }
    if (c == '2')
    {
        Ps2KeyboardSetLayout(KeyboardLayout::UK);
        duetos::drivers::video::NotifyShow("layout: UK QWERTY");
        return true;
    }
    if (c == '3')
    {
        Ps2KeyboardSetLayout(KeyboardLayout::Dvorak);
        duetos::drivers::video::NotifyShow("layout: Dvorak");
        return true;
    }
    if (c == '4')
    {
        Ps2KeyboardSetLayout(KeyboardLayout::DE);
        duetos::drivers::video::NotifyShow("layout: DE QWERTZ");
        return true;
    }
    if (c == '5')
    {
        Ps2KeyboardSetLayout(KeyboardLayout::FR);
        duetos::drivers::video::NotifyShow("layout: FR AZERTY");
        return true;
    }
    if (c == '6')
    {
        Ps2KeyboardSetLayout(KeyboardLayout::Colemak);
        duetos::drivers::video::NotifyShow("layout: Colemak");
        return true;
    }
    return false;
}

} // namespace

void SettingsKeyboardInit()
{
    SettingsRegisterPanel(Panel::Keyboard, Draw, Key);
}

u8 KeyboardTypematicRateIdx()
{
    return g_rate_idx;
}

u8 KeyboardTypematicDelayIdx()
{
    return g_delay_idx;
}

void KeyboardSetTypematicIdx(u8 rate, u8 delay)
{
    if (rate > 31)
        rate = 31;
    if (delay > 3)
        delay = 3;
    g_rate_idx = rate;
    g_delay_idx = delay;
    duetos::drivers::input::Ps2KeyboardSetTypematic(g_rate_idx, g_delay_idx);
}

} // namespace duetos::apps::settings
