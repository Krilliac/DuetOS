#include "apps/settings.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"

namespace duetos::apps::settings
{

using duetos::drivers::video::ButtonWidget;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeApplyToAll;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::ThemeCurrentId;
using duetos::drivers::video::ThemeCycle;
using duetos::drivers::video::ThemeId;
using duetos::drivers::video::ThemeIdName;
using duetos::drivers::video::ThemeSet;
using duetos::drivers::video::WindowActive;
using duetos::drivers::video::WindowGetOpacity;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowIsAlive;
using duetos::drivers::video::WindowSetOpacity;

namespace
{

// Per-button dispatch — index = id - kIdBase. The labels live in
// .rodata so we can hand the pointer straight to the widget layer
// (it expects caller-owned strings).
struct Action
{
    const char* label;
    void (*fn)();
};

// Active-window opacity step matches the Ctrl+Alt+, / Ctrl+Alt+.
// chord step. Lower bound 64 (anything below renders chrome
// unreadable); upper bound 255 (fully opaque).
constexpr u8 kOpacityStep = 32;
constexpr u8 kOpacityMin = 64;

void DoThemePrev()
{
    // ThemeCycle only advances forward, so step kCount-1 times.
    const u32 n = static_cast<u32>(ThemeId::kCount);
    for (u32 i = 0; i + 1 < n; ++i)
    {
        ThemeCycle();
    }
    ThemeApplyToAll();
}

void DoThemeNext()
{
    ThemeCycle();
    ThemeApplyToAll();
}

void DoOpacityDown()
{
    const auto active = WindowActive();
    if (active == kWindowInvalid || !WindowIsAlive(active))
    {
        return;
    }
    const u8 cur = WindowGetOpacity(active);
    const u8 next = (cur > kOpacityMin + kOpacityStep) ? static_cast<u8>(cur - kOpacityStep) : kOpacityMin;
    WindowSetOpacity(active, next);
}

void DoOpacityUp()
{
    const auto active = WindowActive();
    if (active == kWindowInvalid || !WindowIsAlive(active))
    {
        return;
    }
    const u8 cur = WindowGetOpacity(active);
    const u8 next = (cur > 0xFFu - kOpacityStep) ? 0xFFu : static_cast<u8>(cur + kOpacityStep);
    WindowSetOpacity(active, next);
}

void DoHighContrast()
{
    ThemeSet(ThemeId::HighContrast);
    ThemeApplyToAll();
}

void DoDefault()
{
    ThemeSet(ThemeId::Classic);
    ThemeApplyToAll();
    const auto active = WindowActive();
    if (active != kWindowInvalid && WindowIsAlive(active))
    {
        WindowSetOpacity(active, 0xFFu);
    }
}

constexpr Action kActions[kIdCount] = {
    {"THEME PREV", DoThemePrev}, {"THEME NEXT", DoThemeNext},    {"OPACITY -", DoOpacityDown},
    {"OPACITY +", DoOpacityUp},  {"HIGH CTRST", DoHighContrast}, {"DEFAULT", DoDefault},
};

struct State
{
    WindowHandle handle;
};

constinit State g_state = {kWindowInvalid};

// Layout constants.
constexpr u32 kBtnX = 8;
constexpr u32 kBtnY = 8;
constexpr u32 kBtnW = 92;
constexpr u32 kBtnH = 22;
constexpr u32 kBtnGap = 4;
constexpr u32 kReadoutX = 112; // right of the button column

// 0..9 -> '0'..'9'; >=10 wraps to '?'. Used by the wall-clock readout.
constexpr char Digit(u32 v)
{
    return (v < 10) ? static_cast<char>('0' + v) : '?';
}

// Format "HH:MM:SS YYYY-MM-DD" into a fixed 20-byte buffer (NUL).
void FormatRtc(const arch::RtcTime& t, char out[20])
{
    out[0] = Digit(t.hour / 10);
    out[1] = Digit(t.hour % 10);
    out[2] = ':';
    out[3] = Digit(t.minute / 10);
    out[4] = Digit(t.minute % 10);
    out[5] = ':';
    out[6] = Digit(t.second / 10);
    out[7] = Digit(t.second % 10);
    out[8] = ' ';
    const u16 yr = t.year;
    out[9] = Digit((yr / 1000) % 10);
    out[10] = Digit((yr / 100) % 10);
    out[11] = Digit((yr / 10) % 10);
    out[12] = Digit(yr % 10);
    out[13] = '-';
    out[14] = Digit(t.month / 10);
    out[15] = Digit(t.month % 10);
    out[16] = '-';
    out[17] = Digit(t.day / 10);
    out[18] = Digit(t.day % 10);
    out[19] = '\0';
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    if (cw < kReadoutX + 32 || ch < 80)
    {
        return; // window too small; readout pane has nothing to paint
    }
    const auto& th = ThemeCurrent();
    const u32 ink_fg = th.console_fg;
    const u32 ink_bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];

    // Section header.
    const u32 hdr_y = cy + 6;
    FramebufferDrawString(cx + kReadoutX, hdr_y, "SETTINGS", ink_fg, ink_bg);

    // Theme readout: "THEME: <name>"
    u32 y = hdr_y + 16;
    FramebufferDrawString(cx + kReadoutX, y, "THEME:", ink_fg, ink_bg);
    const char* name = ThemeIdName(ThemeCurrentId());
    FramebufferDrawString(cx + kReadoutX + 8 * 7, y, (name != nullptr) ? name : "?", ink_fg, ink_bg);

    // Opacity readout: "OPACITY: <hex>"
    y += 12;
    FramebufferDrawString(cx + kReadoutX, y, "OPACITY:", ink_fg, ink_bg);
    const auto active = WindowActive();
    if (active != kWindowInvalid && WindowIsAlive(active))
    {
        const u8 op = WindowGetOpacity(active);
        char hex[5] = {'0', 'x', 0, 0, 0};
        constexpr char kHex[] = "0123456789ABCDEF";
        hex[2] = kHex[(op >> 4) & 0xF];
        hex[3] = kHex[op & 0xF];
        FramebufferDrawString(cx + kReadoutX + 8 * 9, y, hex, ink_fg, ink_bg);
    }
    else
    {
        FramebufferDrawString(cx + kReadoutX + 8 * 9, y, "(no win)", ink_fg, ink_bg);
    }

    // Wall clock — refreshed on every paint via RtcRead.
    y += 16;
    FramebufferDrawString(cx + kReadoutX, y, "TIME:", ink_fg, ink_bg);
    arch::RtcTime t{};
    arch::RtcRead(&t);
    char buf[20];
    FormatRtc(t, buf);
    FramebufferDrawString(cx + kReadoutX, y + 12, buf, ink_fg, ink_bg);

    // About line.
    y += 30;
    FramebufferDrawString(cx + kReadoutX, y, "DUETOS v0", ink_fg, ink_bg);
    FramebufferDrawString(cx + kReadoutX, y + 12, "BUILD: HEAD", ink_fg, ink_bg);
}

bool DispatchById(u32 id)
{
    if (id < kIdBase || id >= kIdBase + kIdCount)
    {
        return false;
    }
    const u32 idx = id - kIdBase;
    if (kActions[idx].fn != nullptr)
    {
        kActions[idx].fn();
    }
    return true;
}

bool DispatchByChar(char c)
{
    switch (c)
    {
    case 't':
    case 'T':
        DoThemeNext();
        return true;
    case 'h':
    case 'H':
        DoHighContrast();
        return true;
    case '-':
    case '_':
        DoOpacityDown();
        return true;
    case '+':
    case '=':
        DoOpacityUp();
        return true;
    case '0':
        DoDefault();
        return true;
    default:
        return false;
    }
}

} // namespace

void SettingsInit(WindowHandle handle)
{
    g_state.handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);

    // Six buttons stacked vertically along the left of the panel.
    const auto& th = ThemeCurrent();
    const u32 normal = th.taskbar_tab_inactive;
    const u32 pressed = th.taskbar_accent;
    const u32 border = th.window_border;
    const u32 label_ink = th.banner_fg;
    for (u32 i = 0; i < kIdCount; ++i)
    {
        ButtonWidget b{};
        b.id = kIdBase + i;
        b.owner = handle;
        b.x = kBtnX;
        b.y = kBtnY + i * (kBtnH + kBtnGap);
        b.w = kBtnW;
        b.h = kBtnH;
        b.colour_normal = normal;
        b.colour_pressed = pressed;
        b.colour_border = border;
        b.colour_label = label_ink;
        b.label = kActions[i].label;
        duetos::drivers::video::WidgetRegisterButton(b);
    }
}

WindowHandle SettingsWindow()
{
    return g_state.handle;
}

bool SettingsOnWidgetEvent(u32 id)
{
    return DispatchById(id);
}

bool SettingsFeedChar(char c)
{
    return DispatchByChar(c);
}

void SettingsSelfTest()
{
    using duetos::arch::SerialWrite;

    // Verify char dispatch covers every documented key. We don't
    // assert side effects on the live theme/opacity state — those
    // are observed externally. Just ensure dispatch returns true
    // for the documented chars and false otherwise.
    bool ok = true;
    ok = ok && DispatchByChar('t');
    ok = ok && DispatchByChar('h');
    ok = ok && DispatchByChar('-');
    ok = ok && DispatchByChar('+');
    ok = ok && DispatchByChar('0');
    ok = ok && !DispatchByChar('z');

    // Verify cycle round-trips: ThemeCycle 9 times returns to the
    // same id. The DoThemeNext path goes through the same code
    // path the next-button click takes.
    const auto start = ThemeCurrentId();
    for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
    {
        DoThemeNext();
    }
    ok = ok && (ThemeCurrentId() == start);

    // Verify id dispatch range gates correctly.
    ok = ok && !DispatchById(kIdBase - 1);
    ok = ok && !DispatchById(kIdBase + kIdCount);
    ok = ok && DispatchById(kIdBase);

    // Restore start theme so the live desktop is unchanged.
    ThemeSet(start);
    ThemeApplyToAll();

    SerialWrite(ok ? "[settings] self-test OK\n" : "[settings] self-test FAILED\n");
}

} // namespace duetos::apps::settings
