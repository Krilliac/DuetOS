#include "apps/settings.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/cursor.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"

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
// Pass D chrome: MOUSE panel. Header (Title Bold) + footer
// (Caption hint band) AppLabels. All live readouts (cursor
// position, active shape name, dbl-click threshold, sensitivity)
// + the multi-key shape menu + the bottom hint trio stay raw
// paint because they recompose every paint via CursorPosition /
// CursorGetShape / WindowDoubleClickTicks / WindowMouseSensitivity.

constinit char g_mse_header[16] = "MOUSE";
constinit char g_mse_footer[64] = "1-9:shape  [/]:dbl-click  -/=:sens  B:swap  0:reset";

constinit auto g_settings_mouse = MakeWidgetGroup(AppLabel{}, AppLabel{});

constinit bool g_settings_mouse_bound = false;
constinit bool g_settings_mouse_self_test_passed = false;

AppLabel& MseHeader()
{
    return g_settings_mouse.chain.head;
}
AppLabel& MseFooter()
{
    return g_settings_mouse.chain.tail.head;
}

void BindSettingsMouseOnce()
{
    if (g_settings_mouse_bound)
        return;
    g_settings_mouse_bound = true;

    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    AppLabel& h = MseHeader();
    h.text = g_mse_header;
    h.role = ChromeTextRole::Title;
    h.weight = ChromeTextWeight::Bold;
    h.fg_rgb = fg;
    h.bg_rgb = bg;
    h.align_left = true;

    AppLabel& f = MseFooter();
    f.text = g_mse_footer;
    f.role = ChromeTextRole::Caption;
    f.weight = ChromeTextWeight::Regular;
    f.fg_rgb = dim;
    f.bg_rgb = bg;
    f.align_left = true;
}

void RebindSettingsMouseBounds(u32 x, u32 y, u32 w, u32 h)
{
    constexpr u32 kHeaderH = 14U;
    constexpr u32 kFooterH = 12U;
    MseHeader().bounds = Rect{x, y, w, kHeaderH};
    const u32 fy = (h > kFooterH) ? y + h - kFooterH : y;
    MseFooter().bounds = Rect{x, fy, w, kFooterH};
}

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

const char* CursorShapeName(duetos::drivers::video::CursorShape s)
{
    using duetos::drivers::video::CursorShape;
    switch (s)
    {
    case CursorShape::IBeam:
        return "IBEAM";
    case CursorShape::Hand:
        return "HAND";
    case CursorShape::Wait:
        return "WAIT";
    case CursorShape::ResizeNS:
        return "RESIZE-NS";
    case CursorShape::ResizeEW:
        return "RESIZE-EW";
    case CursorShape::ResizeNESW:
        return "RESIZE-NESW";
    case CursorShape::ResizeNWSE:
        return "RESIZE-NWSE";
    case CursorShape::Arrow:
    default:
        return "ARROW";
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
    BindSettingsMouseOnce();
    RebindSettingsMouseBounds(x, y, w, h);
    Compose ctx{};
    g_settings_mouse.PaintAll(ctx);

    ChromeTextDraw(ChromeTextRole::Body, x, y + 14, "DRIVER: PS/2 + xHCI HID (auto)", dim, bg);

    duetos::u32 cx = 0, cy = 0;
    duetos::drivers::video::CursorPosition(&cx, &cy);
    char line[80];
    u32 o = 0;
    AppendStr(line, sizeof(line), &o, "CURSOR: (");
    AppendDec(line, sizeof(line), &o, cx);
    AppendStr(line, sizeof(line), &o, ", ");
    AppendDec(line, sizeof(line), &o, cy);
    AppendStr(line, sizeof(line), &o, ")");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 30, line, fg, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "ACTIVE SHAPE: ");
    AppendStr(line, sizeof(line), &o, CursorShapeName(duetos::drivers::video::CursorGetShape()));
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 42, line, fg, bg);

    // Cursor-shape menu — Body for the section label, Caption for the
    // key-shortcut lines below it.
    ChromeTextDraw(ChromeTextRole::Body, x, y + 60, "TEST CURSOR SHAPES:", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 72, "1: IBEAM   2: HAND   3: WAIT", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 84, "4: RESIZE-NS  5: RESIZE-EW", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 96, "6: RESIZE-NESW  7: RESIZE-NWSE  9: ARROW", dim, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "DBL-CLICK THRESHOLD: ");
    AppendDec(line, sizeof(line), &o, duetos::drivers::video::WindowDoubleClickTicks() * 10u);
    AppendStr(line, sizeof(line), &o, " ms");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 116, line, fg, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "SENSITIVITY: ");
    AppendDec(line, sizeof(line), &o, duetos::drivers::video::WindowMouseSensitivity());
    AppendStr(line, sizeof(line), &o, " / 128 (identity = 128)");
    line[o] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 128, line, fg, bg);

    // Button-swap row — shows current state; B key toggles.
    const bool swapped = duetos::drivers::video::WindowMouseButtonSwap();
    ChromeTextDraw(ChromeTextRole::Body, x, y + 142,
                   swapped ? "BUTTON SWAP: ON  (right=primary)" : "BUTTON SWAP: OFF (left=primary)", fg, bg);

    // Hint lines — Caption role for key-shortcut help.
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 158, "[ : DC -50ms     ] : DC +50ms", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 170, "- : SENS -16     = : SENS +16", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 182, "B : SWAP buttons     0 : RESET", dim, bg);
}

bool Key(char c)
{
    using duetos::drivers::video::CursorSetShape;
    using duetos::drivers::video::CursorShape;
    switch (c)
    {
    case '1':
        CursorSetShape(CursorShape::IBeam);
        duetos::drivers::video::NotifyShow("cursor: IBeam");
        return true;
    case '2':
        CursorSetShape(CursorShape::Hand);
        duetos::drivers::video::NotifyShow("cursor: Hand");
        return true;
    case '3':
        CursorSetShape(CursorShape::Wait);
        duetos::drivers::video::NotifyShow("cursor: Wait");
        return true;
    case '4':
        CursorSetShape(CursorShape::ResizeNS);
        duetos::drivers::video::NotifyShow("cursor: ResizeNS");
        return true;
    case '5':
        CursorSetShape(CursorShape::ResizeEW);
        duetos::drivers::video::NotifyShow("cursor: ResizeEW");
        return true;
    case '6':
        CursorSetShape(CursorShape::ResizeNESW);
        duetos::drivers::video::NotifyShow("cursor: ResizeNESW");
        return true;
    case '7':
        CursorSetShape(CursorShape::ResizeNWSE);
        duetos::drivers::video::NotifyShow("cursor: ResizeNWSE");
        return true;
    case '9':
        CursorSetShape(CursorShape::Arrow);
        duetos::drivers::video::NotifyShow("cursor: Arrow");
        return true;
    case '[':
    {
        const u32 cur = duetos::drivers::video::WindowDoubleClickTicks();
        duetos::drivers::video::WindowSetDoubleClickTicks((cur >= 5) ? cur - 5 : 5);
        duetos::drivers::video::NotifyShow("dbl-click threshold -50ms");
        return true;
    }
    case ']':
    {
        duetos::drivers::video::WindowSetDoubleClickTicks(duetos::drivers::video::WindowDoubleClickTicks() + 5);
        duetos::drivers::video::NotifyShow("dbl-click threshold +50ms");
        return true;
    }
    case '-':
    {
        const u8 cur = duetos::drivers::video::WindowMouseSensitivity();
        const u8 nxt = (cur > 16) ? static_cast<u8>(cur - 16) : 16;
        duetos::drivers::video::WindowSetMouseSensitivity(nxt);
        duetos::drivers::video::NotifyShow("sensitivity -");
        return true;
    }
    case '=':
    case '+':
    {
        const u32 cur = duetos::drivers::video::WindowMouseSensitivity();
        const u32 nxt = (cur + 16 > 255) ? 255 : cur + 16;
        duetos::drivers::video::WindowSetMouseSensitivity(static_cast<u8>(nxt));
        duetos::drivers::video::NotifyShow("sensitivity +");
        return true;
    }
    case 'b':
    case 'B':
    {
        const bool now = !duetos::drivers::video::WindowMouseButtonSwap();
        duetos::drivers::video::WindowSetMouseButtonSwap(now);
        duetos::drivers::video::NotifyShow(now ? "button swap: ON" : "button swap: OFF");
        return true;
    }
    case '0':
        duetos::drivers::video::WindowSetDoubleClickTicks(50);
        duetos::drivers::video::WindowSetMouseSensitivity(128);
        duetos::drivers::video::WindowSetMouseButtonSwap(false);
        duetos::drivers::video::NotifyShow("mouse: defaults restored");
        return true;
    default:
        return false;
    }
}

} // namespace

void SettingsMouseInit()
{
    SettingsRegisterPanel(Panel::Mouse, Draw, Key);
}

void SettingsMouseSelfTest()
{
    using duetos::arch::SerialWrite;
    bool ok = true;

    // Pass D chrome: bind + rebind only. Skipping PaintAll because
    // under TTF themes (duet*) AppLabel::PaintSelf routes into
    // TtfDrawString -> CompositeCoverage -> FramebufferBlendFill at
    // the synthetic (0,0) origin and races the compositor lock
    // before the WM is online (silent boot halt). The live Draw()
    // path exercises paint when the settings shell composes us.
    BindSettingsMouseOnce();
    RebindSettingsMouseBounds(0U, 0U, 256U, 200U);

    if (g_mse_header[0] == '\0' || g_mse_footer[0] == '\0')
        ok = false;
    if (MseHeader().text == nullptr || MseFooter().text == nullptr)
        ok = false;

    g_settings_mouse_self_test_passed = ok;
    SerialWrite(ok ? "[settings-mouse-selftest] PASS\n" : "[settings-mouse-selftest] FAIL\n");
}

bool SettingsMouseSelfTestPassed()
{
    return g_settings_mouse_self_test_passed;
}

} // namespace duetos::apps::settings
