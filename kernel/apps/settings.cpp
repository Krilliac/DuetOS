#include "apps/settings.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/gpu/dpms.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "core/session_restore.h"
#include "power/reboot.h"
#include "security/auth.h"
#include "security/login.h"
#include "time/timezone.h"

namespace duetos::apps::settings
{

using duetos::drivers::video::ButtonWidget;
using duetos::drivers::video::ChromeTextDraw;
using duetos::drivers::video::ChromeTextMeasure;
using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
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

// Sub-panel registry. Indexed by Panel enum value. Each slot
// is populated by SettingsRegisterPanel from the panel's own
// .cpp; the General panel is handled inline in DrawFn /
// SettingsFeedChar so it doesn't register here.
struct PanelSlot
{
    PanelDrawFn draw;
    PanelKeyFn key;
};
constinit PanelSlot g_panels[static_cast<u32>(Panel::kCount)] = {};
constinit Panel g_active_panel = Panel::General;

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

void DoLogOut()
{
    // Persist theme + window positions before the gate goes up
    // so the next login lands in the same layout the user left.
    duetos::core::SessionRestoreSave();
    duetos::core::AuthLogout();
    duetos::core::LoginStart(duetos::core::LoginMode::Gui);
}

void DoTzDown()
{
    duetos::time::TimezoneStep(false);
}

void DoTzUp()
{
    duetos::time::TimezoneStep(true);
}

[[noreturn]] void DoShutdown()
{
    // Persist theme + window positions before the firmware-level
    // shutdown — same discipline as DoLogOut. If S5 honours the
    // request the buffer hits FAT before the chip cuts power; if
    // not, we fall through to Halt and the caller's last known
    // session is still on disk.
    duetos::core::SessionRestoreSave();
    duetos::drivers::video::NotifyShow("shutting down...");
    duetos::arch::SerialWrite("[settings] user invoked shutdown\n");
    // Move the DPMS state machine to Off so any registered driver
    // hook (e.g. eDP power-down on real GPUs, once one is wired)
    // gets the chance to drop power before ACPI shutdown. On v0
    // there is no driver hook so this is bookkeeper-only — the
    // recorded state still matches the user's request, which makes
    // the inspect-shell history coherent.
    duetos::drivers::gpu::DpmsSetState(duetos::drivers::gpu::DpmsState::Off);
    duetos::acpi::AcpiShutdown();
    duetos::arch::Halt();
}

[[noreturn]] void DoReboot()
{
    duetos::core::SessionRestoreSave();
    duetos::drivers::video::NotifyShow("rebooting...");
    duetos::arch::SerialWrite("[settings] user invoked reboot\n");
    // Reboot transitions through Standby → Off so a future driver
    // hook can implement a graceful blank then full power-down. The
    // bookkeeper-only path is identical to DoShutdown for now.
    duetos::drivers::gpu::DpmsSetState(duetos::drivers::gpu::DpmsState::Standby);
    duetos::drivers::gpu::DpmsSetState(duetos::drivers::gpu::DpmsState::Off);
    duetos::core::KernelReboot();
}

// Settings actions are nullary; the [[noreturn]] shutdown / reboot
// helpers don't fit that signature. Wrap them in tiny shims so the
// dispatch table can hold a uniform `void()` pointer. The shim is
// itself [[noreturn]] but the table entry doesn't need to advertise
// that — callers just invoke and never come back.
void DoShutdownShim()
{
    DoShutdown();
}

void DoRebootShim()
{
    DoReboot();
}

constexpr Action kActions[kIdCount] = {
    {"THEME PREV", DoThemePrev},
    {"THEME NEXT", DoThemeNext},
    {"OPACITY -", DoOpacityDown},
    {"OPACITY +", DoOpacityUp},
    {"HIGH CTRST", DoHighContrast},
    {"DEFAULT", DoDefault},
    {"LOG OUT", DoLogOut},
    {"TZ -", DoTzDown},
    {"TZ +", DoTzUp},
    {"REBOOT", DoRebootShim},
    {"SHUTDOWN", DoShutdownShim},
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

// ---- Pass D chrome: AppToolbar tab strip + 6 sub-panel buttons
// (GEN/DSP/SND/KBD/MSE/DT) + AppLabel status footer at the top of
// the readout column (cx + kReadoutX onward). The 11 left-column
// action buttons (THEME PREV/NEXT, OPACITY -/+, etc.) stay on the
// legacy WidgetRegisterButton path — their kIdBase..kIdBase+11 ID
// range is load-bearing for the boot-time DispatchById hit-test.
// The readout content (theme/opacity/wall clock/users) stays raw
// paint — heterogeneous Body-role rows with measured value
// columns AppLabel can't compose without losing alignment. The
// Pass D win here is making the panel-switcher discoverable
// (click instead of memorising 1..5 number-key shortcuts).

constexpr u32 kTabStripH = 22U;
constexpr u32 kTabBtnW = 38U;
constexpr u32 kTabBtnH = 18U;
constexpr u32 kTabBtnGap = 4U;
constexpr u32 kTabPadX = 4U;
constexpr u32 kTabPadY = 2U;
constexpr u32 kFooterBandH = 12U;
constexpr u32 kFooterPadX = 4U;

// Six tab buttons — one per Panel enum value. Order matches the
// '0'..'5' panel-switcher number keys so on-screen order aligns
// with the keyboard shortcuts.
constexpr u32 kTabBtnCount = static_cast<u32>(Panel::kCount);
static_assert(kTabBtnCount == 6, "Update kTabLabels / kTabClicks if Panel::kCount changes");

// AppLabel stores text by pointer so the buffer must outlive
// every Paint. Composed by RefreshSettingsFooter() before
// PaintAll fires.
constinit char g_footer_text[96] = {};

// Pass D umbrella result + mouse-state edge detector for
// SettingsMouseInput. The legacy DispatchById path stays the
// source of truth for the 11 left-column action buttons; this
// edge detector only drives the new tab-strip widget chain.
constinit bool g_self_test_passed = false;
constinit bool g_prev_left_down = false;

// Forward-declared click trampolines — AppButton::on_click is a
// plain `void (*)()` so the constinit g_settings below captures
// them by function-pointer value.
void ClickTabGeneral();
void ClickTabDisplay();
void ClickTabSound();
void ClickTabKeyboard();
void ClickTabMouse();
void ClickTabDateTime();

using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppToolbar;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::EventResult;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// Toolbar (back), then 6 tab AppButtons in panel order, then
// footer AppLabel (overlays the bottom hint band). Reverse
// declaration order is dispatch order — tab buttons get first
// refusal on clicks.
constinit auto g_settings =
    MakeWidgetGroup(AppToolbar{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{},
                    AppLabel{});

constinit bool g_settings_bound = false;

// Walk the recursive WidgetChain by hand to grab a stable pointer
// to each tab button. Chain order matches the MakeWidgetGroup
// argument list (toolbar -> 6 buttons -> label).
AppButton* TabButton(u32 i)
{
    auto& a = g_settings.chain.tail; // toolbar -> btn[0]
    auto& b = a.tail;                // btn[0] -> btn[1]
    auto& c2 = b.tail;               // btn[1] -> btn[2]
    auto& d = c2.tail;               // btn[2] -> btn[3]
    auto& e = d.tail;                // btn[3] -> btn[4]
    auto& f = e.tail;                // btn[4] -> btn[5]
    AppButton* btns[kTabBtnCount] = {&a.head, &b.head, &c2.head, &d.head, &e.head, &f.head};
    return btns[i];
}

void BindSettingsOnce()
{
    if (g_settings_bound)
        return;
    g_settings_bound = true;

    auto& toolbar = g_settings.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    static const char* const kTabLabels[kTabBtnCount] = {"GEN", "DSP", "SND", "KBD", "MSE", "DT"};
    using ClickFn = void (*)();
    static constexpr ClickFn kTabClicks[kTabBtnCount] = {ClickTabGeneral, ClickTabDisplay, ClickTabSound,
                                                         ClickTabKeyboard, ClickTabMouse,  ClickTabDateTime};
    for (u32 i = 0; i < kTabBtnCount; ++i)
    {
        AppButton* btn = TabButton(i);
        btn->label = kTabLabels[i];
        btn->on_click = kTabClicks[i];
        btn->weight = ChromeTextWeight::Regular;
        btn->bg_rgb = 0; // theme role default
        btn->fg_rgb = 0x00101828U;
    }

    auto& label = g_settings.chain.tail.tail.tail.tail.tail.tail.tail.head;
    label.text = g_footer_text;
    label.role = ChromeTextRole::Caption;
    label.weight = ChromeTextWeight::Regular;
    label.fg_rgb = 0x00181828U;
    label.bg_rgb = 0x00C8C8B8U; // status band tone
    label.align_left = true;
}

// Re-anchor the toolbar + tab buttons + footer label to the live
// window's client rect. Called from DrawFn before PaintAll and
// from SettingsMouseInput before DispatchEvent so hit-tests +
// visuals stay consistent across window moves / resizes. The tab
// strip lives at the top of the readout area (cx + kReadoutX) so
// the 11 left-column action buttons are unaffected; the footer
// spans the full client width as a status hint.
void RebindSettingsBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    const u32 strip_x = (cw > kReadoutX) ? cx + kReadoutX : cx;
    const u32 strip_w = (cw > kReadoutX) ? cw - kReadoutX : 0;
    auto& toolbar = g_settings.chain.head;
    toolbar.bounds = Rect{strip_x, cy, strip_w, kTabStripH};

    for (u32 i = 0; i < kTabBtnCount; ++i)
    {
        const u32 bx = strip_x + kTabPadX + i * (kTabBtnW + kTabBtnGap);
        TabButton(i)->bounds = Rect{bx, cy + kTabPadY, kTabBtnW, kTabBtnH};
        // Bold the active tab so the visual selection state is
        // unambiguous (legacy UX had no distinction at all).
        TabButton(i)->weight =
            (static_cast<u32>(g_active_panel) == i) ? ChromeTextWeight::Bold : ChromeTextWeight::Regular;
    }

    auto& label = g_settings.chain.tail.tail.tail.tail.tail.tail.tail.head;
    const u32 fy = (ch > kFooterBandH) ? cy + ch - kFooterBandH : cy;
    const u32 fw = (cw > 2U * kFooterPadX) ? cw - 2U * kFooterPadX : cw;
    label.bounds = Rect{cx + kFooterPadX, fy, fw, kFooterBandH};
}

// Append `s` (NUL-terminated) onto `dst` at offset `*o`, capped at
// `cap - 1` bytes. Mirrors the Files / Taskman footer helpers.
void FooterAppend(char* dst, u32 cap, u32* o, const char* s)
{
    while (*s != '\0' && *o + 1 < cap)
    {
        dst[(*o)++] = *s++;
    }
}

// Re-compose g_footer_text from the active panel. Called from
// DrawFn before PaintAll so the AppLabel sees the current frame's
// text. Replaces the legacy raw-paint hint at the top of the
// readout area.
void RefreshSettingsFooter()
{
    u32 o = 0;
    g_footer_text[0] = '\0';
    FooterAppend(g_footer_text, sizeof(g_footer_text), &o, "0:GEN 1:DSP 2:SND 3:KBD 4:MSE 5:DT  (active=");
    static const char* const kShortName[kTabBtnCount] = {"GEN", "DSP", "SND", "KBD", "MSE", "DT"};
    const u32 idx = static_cast<u32>(g_active_panel);
    FooterAppend(g_footer_text, sizeof(g_footer_text), &o, (idx < kTabBtnCount) ? kShortName[idx] : "?");
    FooterAppend(g_footer_text, sizeof(g_footer_text), &o, ")");
    if (o < sizeof(g_footer_text))
        g_footer_text[o] = '\0';
    else
        g_footer_text[sizeof(g_footer_text) - 1] = '\0';
}

// Click trampolines — each one sets the active panel directly,
// matching the SettingsFeedChar '0'..'5' branch.
void ClickTabGeneral()
{
    g_active_panel = Panel::General;
}
void ClickTabDisplay()
{
    g_active_panel = Panel::Display;
}
void ClickTabSound()
{
    g_active_panel = Panel::Sound;
}
void ClickTabKeyboard()
{
    g_active_panel = Panel::Keyboard;
}
void ClickTabMouse()
{
    g_active_panel = Panel::Mouse;
}
void ClickTabDateTime()
{
    g_active_panel = Panel::DateTime;
}

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

    // Pass D chrome: refresh the footer text from the live panel,
    // re-anchor the tab strip + footer label to the current client
    // rect, and paint the WidgetGroup. The active tab gets a Bold
    // weight via RebindSettingsBounds so the visual selection
    // state is unambiguous.
    BindSettingsOnce();
    RefreshSettingsFooter();
    RebindSettingsBounds(cx, cy, cw, ch);
    Compose ctx{};
    g_settings.PaintAll(ctx);

    // Sub-panel dispatch. When a non-General panel is active
    // and registered, render its content into the readout area
    // — below the tab strip carved out by RebindSettingsBounds
    // and above the AppLabel footer band — and skip the
    // General-panel body below.
    if (g_active_panel != Panel::General)
    {
        const PanelSlot& s = g_panels[static_cast<u32>(g_active_panel)];
        if (s.draw != nullptr)
        {
            // Readout area = right of buttons, below the tab strip,
            // above the footer band. Matches the same vertical
            // budget the General-panel rows below claim.
            const u32 sx = cx + kReadoutX;
            const u32 sy = cy + kTabStripH + 2;
            const u32 sw = (cw > kReadoutX) ? cw - kReadoutX - 4 : 0;
            const u32 reserve = kTabStripH + 2 + kFooterBandH + 4;
            const u32 sh = (ch > reserve) ? ch - reserve : 0;
            s.draw(sx, sy, sw, sh);
            return;
        }
        // Fallthrough — placeholder text when a panel slot is
        // empty. The real panel populates via SettingsRegisterPanel
        // from its own .cpp. Caption role — diagnostic placeholder,
        // not a section header.
        ChromeTextDraw(ChromeTextRole::Caption, cx + kReadoutX, cy + kTabStripH + 12,
                       "(panel not registered yet)", th.banner_fg, ink_bg);
        return;
    }

    // Section header — Title + Bold so "SETTINGS" reads as the
    // window's hero label rather than a row. Offset below the
    // Pass D tab strip the AppToolbar carved out at the top of
    // the readout area.
    const u32 hdr_y = cy + kTabStripH + 4;
    ChromeTextDraw(ChromeTextRole::Title, cx + kReadoutX, hdr_y, "SETTINGS", ink_fg, ink_bg, ChromeTextWeight::Bold);

    // Theme readout: "THEME: <name>" — Body role for both label and
    // value. Value column derived from ChromeTextMeasure so variable-
    // width TTF doesn't collide with the label; collapses to the
    // prior fixed-grid spacing (label + space) under the bitmap path.
    u32 y = hdr_y + 16;
    ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX, y, "THEME:", ink_fg, ink_bg);
    const char* name = ThemeIdName(ThemeCurrentId());
    const u32 theme_label_w = ChromeTextMeasure(ChromeTextRole::Body, "THEME: ");
    ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX + theme_label_w, y, (name != nullptr) ? name : "?", ink_fg,
                   ink_bg);

    // Opacity readout: "OPACITY: <hex>" — same Body role + measured
    // value column as the THEME row.
    y += 12;
    ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX, y, "OPACITY:", ink_fg, ink_bg);
    const u32 opacity_label_w = ChromeTextMeasure(ChromeTextRole::Body, "OPACITY: ");
    const auto active = WindowActive();
    if (active != kWindowInvalid && WindowIsAlive(active))
    {
        const u8 op = WindowGetOpacity(active);
        char hex[5] = {'0', 'x', 0, 0, 0};
        constexpr char kHex[] = "0123456789ABCDEF";
        hex[2] = kHex[(op >> 4) & 0xF];
        hex[3] = kHex[op & 0xF];
        ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX + opacity_label_w, y, hex, ink_fg, ink_bg);
    }
    else
    {
        ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX + opacity_label_w, y, "(no win)", ink_fg, ink_bg);
    }

    // Wall clock — refreshed on every paint via RtcRead. UTC line
    // first, then a LOCAL line that applies the live timezone
    // offset, then an offset readout. Each row is 12 px tall. Both
    // label and value use Body role; "UTC:  " (with trailing spaces)
    // is measured to derive the value column so the digits don't
    // collide under TTF.
    y += 16;
    arch::RtcTime t{};
    arch::RtcRead(&t);
    char utc_buf[20];
    FormatRtc(t, utc_buf);
    const u32 clock_label_w = ChromeTextMeasure(ChromeTextRole::Body, "UTC:  ");
    ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX, y, "UTC:  ", ink_fg, ink_bg);
    ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX + clock_label_w, y, utc_buf, ink_fg, ink_bg);
    y += 12;

    const i32 off_min = duetos::time::TimezoneOffsetMinutes();
    arch::RtcTime local = t;
    {
        i32 total_min = static_cast<i32>(local.hour) * 60 + static_cast<i32>(local.minute) + off_min;
        while (total_min < 0)
        {
            total_min += 1440;
        }
        while (total_min >= 1440)
        {
            total_min -= 1440;
        }
        local.hour = static_cast<u8>(total_min / 60);
        local.minute = static_cast<u8>(total_min % 60);
    }
    char local_buf[20];
    FormatRtc(local, local_buf);
    ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX, y, "LOCAL:", ink_fg, ink_bg);
    // Reuses the same six-char prefix column as the UTC line so the
    // two timestamps stack visually under any chrome font.
    ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX + clock_label_w, y, local_buf, ink_fg, ink_bg);
    y += 12;

    char tz[12] = {'T', 'Z', ':', ' ', ' ', ' ', '+', '0', '0', ':', '0', 0};
    {
        i32 m = off_min;
        if (m < 0)
        {
            tz[6] = '-';
            m = -m;
        }
        const u32 hh = static_cast<u32>(m) / 60;
        const u32 mm = static_cast<u32>(m) % 60;
        tz[7] = Digit(hh / 10);
        tz[8] = Digit(hh % 10);
        tz[10] = Digit(mm / 10);
        // Append trailing minute digit, terminate.
        char buf[14];
        for (u32 i = 0; i < 11; ++i)
        {
            buf[i] = tz[i];
        }
        buf[11] = Digit(mm % 10);
        buf[12] = '\0';
        // Full "TZ:    +HH:MM" line as one Body-role paint — the
        // label and value share the same buffer so we keep the
        // original single-call shape.
        ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX, y, buf, ink_fg, ink_bg);
    }
    y += 16;

    // Users readout — shows the live account table + the currently
    // signed-in identity. Read-only. Section label as Body (USERS:
    // is a row header, not a window title).
    ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX, y, "USERS:", ink_fg, ink_bg);
    const u32 count = duetos::core::AuthAccountCount();
    for (u32 i = 0; i < count && i < 4; ++i)
    {
        duetos::core::AccountView v{};
        if (!duetos::core::AuthAccountAt(i, &v) || v.username == nullptr)
        {
            continue;
        }
        const char* role = "GUEST";
        switch (v.role)
        {
        case duetos::core::AuthRole::Admin:
            role = "ADMIN";
            break;
        case duetos::core::AuthRole::User:
            role = "USER ";
            break;
        case duetos::core::AuthRole::Guest:
            role = "GUEST";
            break;
        }
        char line[40];
        u32 li = 0;
        const char* w = v.username;
        while (*w != '\0' && li < 16)
        {
            line[li++] = *w++;
        }
        while (li < 18)
        {
            line[li++] = ' ';
        }
        for (u32 ri = 0; role[ri] != '\0' && li < sizeof(line) - 1; ++ri)
        {
            line[li++] = role[ri];
        }
        line[li] = '\0';
        // Per-user row — Body role. The 8 px left indent keeps the
        // username column under the "USERS:" header above; that
        // visual offset is independent of the chrome font width.
        ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX + 8, y + 12 * (i + 1), line, ink_fg, ink_bg);
    }
    if (count == 0)
    {
        ChromeTextDraw(ChromeTextRole::Body, cx + kReadoutX + 8, y + 12, "(none)", ink_fg, ink_bg);
    }
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

    // Sub-panel installers — each settings_<panel>.cpp registers
    // its draw + key callbacks with the framework. A panel that
    // hasn't shipped yet is a missing-symbol link error rather
    // than a silent placeholder; that's the right tradeoff —
    // catching the missing wiring at link time.
    SettingsDisplayInit();
    SettingsSoundInit();
    SettingsKeyboardInit();
    SettingsMouseInit();
    SettingsDateTimeInit();
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
    // Panel-switcher number keys take priority. '0' switches
    // back to the General panel; '1'..'5' route to Display /
    // Sound / Keyboard / Mouse / Date-Time. The General
    // panel's existing chars ('t' / 'h' / '-' / '+' / '0')
    // overlap on '0' — but '0' has the same semantics in
    // both contexts ("reset to default") so the alias is
    // intentional.
    if (c >= '0' && c <= '5')
    {
        const u32 idx = static_cast<u32>(c - '0');
        if (idx < static_cast<u32>(Panel::kCount))
        {
            g_active_panel = static_cast<Panel>(idx);
        }
        // Don't return here — '0' should still reach the
        // General-panel reset action. Other digits are
        // panel-only keystrokes.
        if (c != '0')
            return true;
    }
    if (g_active_panel != Panel::General)
    {
        const PanelKeyFn fn = g_panels[static_cast<u32>(g_active_panel)].key;
        if (fn != nullptr && fn(c))
            return true;
        // Fall through to General handling for unhandled keys
        // — keeps Theme cycle / opacity always reachable.
    }
    return DispatchByChar(c);
}

Panel SettingsActivePanel()
{
    return g_active_panel;
}

void SettingsSetActivePanel(Panel p)
{
    if (static_cast<u32>(p) < static_cast<u32>(Panel::kCount))
        g_active_panel = p;
}

void SettingsRegisterPanel(Panel p, PanelDrawFn draw, PanelKeyFn key)
{
    const u32 idx = static_cast<u32>(p);
    if (idx >= static_cast<u32>(Panel::kCount))
        return;
    g_panels[idx].draw = draw;
    g_panels[idx].key = key;
}

void SettingsSelfTest()
{
    using duetos::arch::SerialWrite;

    // Capture the live theme BEFORE any dispatch so the restore
    // at the bottom puts it back faithfully. The `'h'` (high-
    // contrast) and `'0'` (default = Classic) dispatches and the
    // explicit DispatchById path all mutate g_current as a side
    // effect; capturing `start` after them would silently leave
    // the desktop on whichever theme the last dispatch happened
    // to set — which is what made every kernel cmdline
    // `theme=…` boot land on Classic regardless of the boot
    // selection (the boot self-test fires AFTER cmdline-driven
    // ThemeSet but before the user can ever interact).
    const auto start = ThemeCurrentId();

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
    const auto cycle_start = ThemeCurrentId();
    for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
    {
        DoThemeNext();
    }
    ok = ok && (ThemeCurrentId() == cycle_start);

    // Verify id dispatch range gates correctly.
    ok = ok && !DispatchById(kIdBase - 1);
    ok = ok && !DispatchById(kIdBase + kIdCount);
    ok = ok && DispatchById(kIdBase);

    // Restore the boot-time theme so the live desktop is
    // unchanged. ThemeApplyToAll re-publishes the palette into
    // every chrome owner that may have re-coloured during the
    // test dispatches above.
    ThemeSet(start);
    ThemeApplyToAll();

    // Pass D: drive a synthetic click on the DSP tab button via
    // the WidgetGroup dispatch chain. Each tab trampoline just
    // flips g_active_panel directly, so the test verifies the
    // dispatch path is wired end-to-end AND that the click
    // actually mutates the active-panel state. Save / restore the
    // panel so the live desktop is unchanged when the test
    // returns.
    const Panel saved_panel = g_active_panel;
    BindSettingsOnce();
    // Anchor the tab strip at (0, 22, 380, 318) — same shape
    // boot_bringup.cpp registers the live Settings window with
    // (380x340 minus 22 px title bar). The DSP tab is index 1.
    RebindSettingsBounds(0U, 22U, 380U, 318U);
    g_active_panel = Panel::General;
    const u32 dx = kReadoutX + kTabPadX + 1U * (kTabBtnW + kTabBtnGap) + kTabBtnW / 2U;
    const u32 dy = 22U + kTabPadY + kTabBtnH / 2U;
    const Event d_move{EventKind::MouseMove, dx, dy, 0U, 0U};
    const Event d_down{EventKind::MouseDown, dx, dy, 0U, 0U};
    const Event d_up{EventKind::MouseUp, dx, dy, 0U, 0U};
    ok = ok && (g_settings.DispatchEvent(d_move) == EventResult::Consumed);
    ok = ok && (g_settings.DispatchEvent(d_down) == EventResult::Consumed);
    ok = ok && (g_settings.DispatchEvent(d_up) == EventResult::Consumed);
    ok = ok && (g_active_panel == Panel::Display);

    // Footer-text composer must produce non-empty text for any
    // panel. Mutating g_active_panel here is fine — restored
    // below as part of saved_panel.
    RefreshSettingsFooter();
    ok = ok && (g_footer_text[0] != '\0');

    g_active_panel = saved_panel;

    g_self_test_passed = ok;
    if (ok)
    {
        SerialWrite("[settings] self-test OK (dispatch, theme-cycle, tab-click, footer-refresh)\n");
        SerialWrite("[settings-selftest] PASS\n");
    }
    else
    {
        SerialWrite("[settings] self-test FAILED\n");
        SerialWrite("[settings-selftest] FAIL\n");
    }
}

bool SettingsSelfTestPassed()
{
    return g_self_test_passed;
}

void SettingsMouseInput(u32 cx, u32 cy, u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == kWindowInvalid)
        return;
    u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it.
    // RebindSettingsBounds works in client-relative coords so the
    // widget dispatch path needs cursor coords in the same frame.
    constexpr u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const u32 client_y = wy + kTitleH;
    const u32 client_h = wh - kTitleH;
    BindSettingsOnce();
    RebindSettingsBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_prev_left_down;
    const bool release_edge = !left_down && g_prev_left_down;
    g_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_settings.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_settings.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // tab strip and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_settings.DispatchEvent(u);
    }
}

} // namespace duetos::apps::settings
