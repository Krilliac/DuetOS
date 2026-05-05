#include "apps/settings.h"

#include "drivers/input/ps2mouse.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"

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
    using duetos::drivers::video::FramebufferDrawString;
    const auto& th = duetos::drivers::video::ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    if (w < 8 * 24 || h < 8 * 8)
        return;
    FramebufferDrawString(x, y, "MOUSE", fg, bg);
    FramebufferDrawString(x, y + 14, "DRIVER: PS/2 + xHCI HID (auto)", dim, bg);

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
    FramebufferDrawString(x, y + 30, line, fg, bg);

    o = 0;
    AppendStr(line, sizeof(line), &o, "ACTIVE SHAPE: ");
    AppendStr(line, sizeof(line), &o, CursorShapeName(duetos::drivers::video::CursorGetShape()));
    line[o] = '\0';
    FramebufferDrawString(x, y + 42, line, fg, bg);

    FramebufferDrawString(x, y + 60, "TEST CURSOR SHAPES:", dim, bg);
    FramebufferDrawString(x, y + 72, "1: IBEAM   2: HAND   3: WAIT", dim, bg);
    FramebufferDrawString(x, y + 84, "4: RESIZE-NS  5: RESIZE-EW", dim, bg);
    FramebufferDrawString(x, y + 96, "6: RESIZE-NESW  7: RESIZE-NWSE  9: ARROW", dim, bg);

    FramebufferDrawString(x, y + 116, "(double-click ms / sensitivity: future slice)", dim, bg);
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
    default:
        return false;
    }
}

} // namespace

void SettingsMouseInit()
{
    SettingsRegisterPanel(Panel::Mouse, Draw, Key);
}

} // namespace duetos::apps::settings
