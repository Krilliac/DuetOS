#include "apps/settings.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/gpu/dpms.h"
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
    // Panel-switcher hint at the very top: lists the number-key
    // shortcuts so a fresh user can find sub-panels without
    // reading the wiki. Caption role — small navigation hint, not
    // the panel's primary content.
    ChromeTextDraw(ChromeTextRole::Caption, cx + kReadoutX, cy + 2, "0:GEN 1:DSP 2:SND 3:KBD 4:MSE 5:DT", th.banner_fg,
                   ink_bg);
    // Sub-panel dispatch. When a non-General panel is active
    // and registered, render its content into the readout area
    // (everything to the right of the button column) and skip
    // the General-panel body below.
    if (g_active_panel != Panel::General)
    {
        const PanelSlot& s = g_panels[static_cast<u32>(g_active_panel)];
        if (s.draw != nullptr)
        {
            // Readout area = right of buttons, below the
            // panel-switcher hint, above the bottom edge.
            constexpr u32 kSubTop = 14;
            const u32 sx = cx + kReadoutX;
            const u32 sy = cy + kSubTop;
            const u32 sw = (cw > kReadoutX) ? cw - kReadoutX - 4 : 0;
            const u32 sh = (ch > kSubTop + 4) ? ch - kSubTop - 4 : 0;
            s.draw(sx, sy, sw, sh);
            return;
        }
        // Fallthrough — placeholder text when a panel slot is
        // empty. The real panel populates via SettingsRegisterPanel
        // from its own .cpp. Caption role — diagnostic placeholder,
        // not a section header.
        ChromeTextDraw(ChromeTextRole::Caption, cx + kReadoutX, cy + 24, "(panel not registered yet)", th.banner_fg,
                       ink_bg);
        return;
    }

    // Section header — Title + Bold so "SETTINGS" reads as the
    // window's hero label rather than a row.
    const u32 hdr_y = cy + 6;
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

    SerialWrite(ok ? "[settings] self-test OK\n" : "[settings] self-test FAILED\n");
}

} // namespace duetos::apps::settings
