/*
 * DuetOS — login gate: implementation.
 *
 * Companion to login.h — see there for the two UI flavours
 * (Tty / Gui), v0 scope limits, and integration with the auth
 * subsystem.
 *
 * WHAT
 *   Two parallel UIs sharing one auth back-end. The keyboard
 *   thread routes every key into `LoginFeedKey` while the gate
 *   is active; the gate dispatches to the active mode's
 *   per-key handler.
 *
 * HOW
 *   Per-mode helpers cluster in their own banners
 *   (`// === TTY mode`, `// === GUI mode`). Field state is held
 *   in a small struct of (buf, len, cursor); ClearField /
 *   FieldAppend / FieldBackspace are the building blocks for
 *   both modes.
 *
 *   Auth call goes through the auth.h interface — login itself
 *   doesn't touch credential storage.
 */

#include "security/login.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/console.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/widget.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "security/auth.h"
#include "time/tick.h"

namespace duetos::core
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;
using duetos::drivers::video::FramebufferDrawRect;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferDropShadow;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::FramebufferFillRectGradient;
using duetos::drivers::video::FramebufferGet;

namespace
{

constexpr u32 kFieldMax = kAuthNameMax; // both name and pw buffers share the cap

enum class Field : u8
{
    Username = 0,
    Password = 1,
};

struct State
{
    bool active;
    LoginMode mode;
    Field focus;
    char username[kFieldMax];
    char password[kFieldMax];
    u32 username_len;
    u32 password_len;
    const char* status; // non-null string shown beneath the form
    u32 attempts;

    // Lock-screen same-user-only policy. When `locked` is true the
    // gate is up because LoginLock fired (vs. LoginStart on a fresh
    // boot or LoginReopen after a logout). `locked_user` holds the
    // username that was active at lock time so the unlock path can
    // refuse credentials for any other account. Cleared on
    // successful unlock and on LoginReopen.
    bool locked;
    char locked_user[kFieldMax];
};

constinit State g_login = {};

// Colours used by the GUI login screen. The top-to-bottom teal
// gradient matches the desktop mode so the transition from
// login → desktop is visually continuous.
constexpr u32 kBgTop = 0x00204868;
constexpr u32 kBgBottom = 0x00101828;
constexpr u32 kPanel = 0x00E0E0D8;
constexpr u32 kPanelBorder = 0x00101828;
constexpr u32 kTitleBar = 0x00205080;
constexpr u32 kTitleText = 0x00FFFFFF;
constexpr u32 kFieldBg = 0x00FFFFFF;
constexpr u32 kFieldFocusBg = 0x00FFF8C0;
constexpr u32 kFieldBorder = 0x00404040;
constexpr u32 kFieldText = 0x00101010;
constexpr u32 kLabelText = 0x00101010;
constexpr u32 kHint = 0x00606060;
constexpr u32 kStatusError = 0x00801010;

void ClearField(char* buf, u32* len)
{
    buf[0] = '\0';
    *len = 0;
}

bool LockedSameUser(const char* submitted)
{
    if (!g_login.locked)
    {
        return true;
    }
    const char* a = g_login.locked_user;
    const char* b = submitted;
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == *b;
}

void CopyName(char* dst, const char* src, u32 cap)
{
    if (cap == 0)
    {
        return;
    }
    u32 i = 0;
    while (i + 1 < cap && src[i] != '\0')
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

void FieldAppend(char* buf, u32* len, char c)
{
    if (*len + 1 >= kFieldMax)
    {
        return;
    }
    buf[*len] = c;
    ++(*len);
    buf[*len] = '\0';
}

void FieldBackspace(char* buf, u32* len)
{
    if (*len == 0)
    {
        return;
    }
    --(*len);
    buf[*len] = '\0';
}

// ---------------------------------------------------------------
// TTY login UI — drawn into the framebuffer console so the same
// scrollback machinery the shell uses handles scroll / redraw.
// ---------------------------------------------------------------

void TtyPrintBanner()
{
    ConsoleWriteln("");
    ConsoleWriteln("================================");
    ConsoleWriteln("  DUETOS LOGIN");
    ConsoleWriteln("================================");
    ConsoleWriteln("  DEFAULTS: admin / admin");
    ConsoleWriteln("            guest / (empty)");
    ConsoleWriteln("");
    ConsoleWrite("USERNAME: ");
}

void TtyPromptPassword()
{
    ConsoleWrite("PASSWORD: ");
}

void TtyFeedChar(char c)
{
    if (g_login.focus == Field::Username)
    {
        FieldAppend(g_login.username, &g_login.username_len, c);
        ConsoleWriteChar(c);
    }
    else
    {
        FieldAppend(g_login.password, &g_login.password_len, c);
        ConsoleWriteChar('*');
    }
}

void TtyBackspace()
{
    if (g_login.focus == Field::Username)
    {
        if (g_login.username_len == 0)
        {
            return;
        }
        FieldBackspace(g_login.username, &g_login.username_len);
        ConsoleWriteChar('\b');
    }
    else
    {
        if (g_login.password_len == 0)
        {
            return;
        }
        FieldBackspace(g_login.password, &g_login.password_len);
        ConsoleWriteChar('\b');
    }
}

bool TtySubmit()
{
    if (g_login.focus == Field::Username)
    {
        if (g_login.username_len == 0)
        {
            ConsoleWriteln("");
            ConsoleWrite("USERNAME: ");
            return true;
        }
        ConsoleWriteln("");
        g_login.focus = Field::Password;
        TtyPromptPassword();
        return true;
    }
    // password field — try to authenticate
    ConsoleWriteln("");
    if (!LockedSameUser(g_login.username))
    {
        ++g_login.attempts;
        ConsoleWrite("LOCKED FOR USER: ");
        ConsoleWriteln(g_login.locked_user);
        ConsoleWriteln("UNLOCK REQUIRES THE SAME USER. LOG OUT TO SWITCH USERS.");
        ConsoleWriteln("");
        ClearField(g_login.username, &g_login.username_len);
        ClearField(g_login.password, &g_login.password_len);
        g_login.focus = Field::Username;
        ConsoleWrite("USERNAME: ");
        KLOG_WARN("login", "tty unlock attempted for different user");
        return true;
    }
    if (AuthLogin(g_login.username, g_login.password))
    {
        ConsoleWrite("WELCOME, ");
        ConsoleWriteln(g_login.username);
        ConsoleWriteln("");
        ClearField(g_login.username, &g_login.username_len);
        ClearField(g_login.password, &g_login.password_len);
        g_login.active = false;
        g_login.focus = Field::Username;
        g_login.locked = false;
        g_login.locked_user[0] = '\0';
        KLOG_INFO("login", "tty session opened");
        return false;
    }
    ++g_login.attempts;
    ConsoleWriteln("LOGIN FAILED.");
    ConsoleWriteln("");
    ClearField(g_login.username, &g_login.username_len);
    ClearField(g_login.password, &g_login.password_len);
    g_login.focus = Field::Username;
    ConsoleWrite("USERNAME: ");
    KLOG_WARN("login", "tty auth failed");
    return true;
}

// ---------------------------------------------------------------
// GUI login UI — painted directly to the framebuffer. Sized from
// the live framebuffer dimensions so it centres on any resolution.
// ---------------------------------------------------------------

struct GuiLayout
{
    u32 fb_w, fb_h;
    u32 panel_x, panel_y, panel_w, panel_h;
    u32 title_h;
    u32 user_x, user_y, user_w, user_h;
    u32 pass_x, pass_y, pass_w, pass_h;
    u32 hint_y;
    u32 status_y;
};

GuiLayout ComputeLayout()
{
    const auto fb = FramebufferGet();
    GuiLayout l = {};
    l.fb_w = fb.width;
    l.fb_h = fb.height;
    l.panel_w = 440;
    l.panel_h = 220;
    if (l.panel_w > l.fb_w)
    {
        l.panel_w = l.fb_w;
    }
    if (l.panel_h > l.fb_h)
    {
        l.panel_h = l.fb_h;
    }
    l.panel_x = (l.fb_w - l.panel_w) / 2;
    l.panel_y = (l.fb_h - l.panel_h) / 2;
    l.title_h = 28;
    const u32 field_w = 260;
    const u32 field_h = 22;
    const u32 field_x = l.panel_x + 140;
    l.user_x = field_x;
    l.user_y = l.panel_y + l.title_h + 24;
    l.user_w = field_w;
    l.user_h = field_h;
    l.pass_x = field_x;
    l.pass_y = l.user_y + field_h + 14;
    l.pass_w = field_w;
    l.pass_h = field_h;
    l.status_y = l.pass_y + field_h + 18;
    l.hint_y = l.panel_y + l.panel_h - 14;
    return l;
}

// Saturating per-channel lighten — file-local copy.
u32 LightenRgb(u32 rgb, u32 amount)
{
    u32 r = ((rgb >> 16) & 0xFFU) + amount;
    u32 g = ((rgb >> 8) & 0xFFU) + amount;
    u32 b = (rgb & 0xFFU) + amount;
    if (r > 0xFFU)
        r = 0xFFU;
    if (g > 0xFFU)
        g = 0xFFU;
    if (b > 0xFFU)
        b = 0xFFU;
    return (r << 16) | (g << 8) | b;
}

void DrawBackground(const GuiLayout& l)
{
    // Smooth full-height vertical gradient. Replaces the previous
    // two-stripe approximation now that the framebuffer ships
    // FillRectGradient — the same primitive the desktop compose
    // uses, so the login → desktop transition reads as continuous
    // colour rather than a band hand-off.
    FramebufferFillRectGradient(0, 0, l.fb_w, l.fb_h, kBgTop, kBgBottom);
    // Top banner text.
    FramebufferDrawString(16, 12, "DUETOS", 0x00FFFFFF, kBgTop);
    FramebufferDrawString(l.fb_w - 8 * 9, 12, "LOGIN v0", 0x00C0D0E0, kBgTop);
}

void DrawPanel(const GuiLayout& l)
{
    // Drop shadow first so the panel reads as raised relative to
    // the gradient bg. Same depth + alpha as the desktop chrome.
    FramebufferDropShadow(l.panel_x, l.panel_y, l.panel_w, l.panel_h, 5, 0x70);

    // Body fill + 1-px outer border (was 2-px slab).
    FramebufferFillRect(l.panel_x, l.panel_y, l.panel_w, l.panel_h, kPanel);
    FramebufferDrawRect(l.panel_x, l.panel_y, l.panel_w, l.panel_h, kPanelBorder, 1);

    // Title bar with a vertical gradient + a 1-px ridge highlight
    // along its top edge. Same chrome language as window titles.
    FramebufferFillRectGradient(l.panel_x, l.panel_y, l.panel_w, l.title_h, LightenRgb(kTitleBar, 24), kTitleBar);
    if (l.panel_w > 4)
    {
        FramebufferFillRect(l.panel_x + 2, l.panel_y + 1, l.panel_w - 4, 1, LightenRgb(kTitleBar, 56));
    }
    // 1-pixel divider where the title bar meets the panel body —
    // matches the window-chrome divider.
    if (l.panel_h > l.title_h + 2)
    {
        FramebufferFillRect(l.panel_x + 2, l.panel_y + l.title_h, l.panel_w - 4, 1, kPanelBorder);
    }

    FramebufferDrawString(l.panel_x + 10, l.panel_y + 10, "WELCOME TO DUETOS", kTitleText, kTitleBar);
}

void DrawField(u32 x, u32 y, u32 w, u32 h, const char* text, u32 len, bool mask, bool focus)
{
    const u32 bg = focus ? kFieldFocusBg : kFieldBg;
    FramebufferFillRect(x, y, w, h, bg);
    FramebufferDrawRect(x, y, w, h, kFieldBorder, 1);
    // Draw text inside with a small left inset. Mask shows stars
    // for password. 8-pixel glyph cells.
    const u32 inset_x = x + 4;
    const u32 inset_y = y + (h - 8) / 2;
    const u32 max_chars = (w - 8) / 8;
    const u32 shown = (len > max_chars) ? max_chars : len;
    if (mask)
    {
        char stars[kFieldMax];
        for (u32 i = 0; i < shown; ++i)
        {
            stars[i] = '*';
        }
        stars[shown] = '\0';
        FramebufferDrawString(inset_x, inset_y, stars, kFieldText, bg);
    }
    else
    {
        // Local NUL-terminated copy of the shown prefix.
        char buf[kFieldMax];
        for (u32 i = 0; i < shown; ++i)
        {
            buf[i] = text[i];
        }
        buf[shown] = '\0';
        FramebufferDrawString(inset_x, inset_y, buf, kFieldText, bg);
    }
    if (focus)
    {
        const u32 caret_x = inset_x + shown * 8;
        if (caret_x + 8 < x + w)
        {
            FramebufferFillRect(caret_x, inset_y, 8, 2, kFieldText);
        }
    }
}

void GuiRepaint()
{
    const GuiLayout l = ComputeLayout();
    DrawBackground(l);
    DrawPanel(l);

    FramebufferDrawString(l.panel_x + 24, l.user_y + 6, "USERNAME:", kLabelText, kPanel);
    FramebufferDrawString(l.panel_x + 24, l.pass_y + 6, "PASSWORD:", kLabelText, kPanel);

    DrawField(l.user_x, l.user_y, l.user_w, l.user_h, g_login.username, g_login.username_len, false,
              g_login.focus == Field::Username);
    DrawField(l.pass_x, l.pass_y, l.pass_w, l.pass_h, g_login.password, g_login.password_len, true,
              g_login.focus == Field::Password);

    const char* status = g_login.status;
    if (status != nullptr && status[0] != '\0')
    {
        FramebufferDrawString(l.panel_x + 24, l.status_y, status, kStatusError, kPanel);
    }

    FramebufferDrawString(l.panel_x + 24, l.hint_y, "TAB TO SWITCH FIELD   ENTER TO LOG IN", kHint, kPanel);

    const u32 y_hint = l.fb_h - 22;
    FramebufferDrawString(16, y_hint, "DEFAULT ACCOUNTS: ADMIN/ADMIN  GUEST/(EMPTY)", 0x00C0D0E0, kBgBottom);

    // Push the freshly-painted login surface to the active backend
    // (virtio-gpu TRANSFER_TO_HOST_2D + RESOURCE_FLUSH; no-op for
    // direct firmware-handoff framebuffers). Without this the
    // virtio-gpu host display stays at whatever the GPU init painted
    // and the user never sees the login chrome.
    drivers::video::FramebufferPresent();
}

bool GuiTrySubmit()
{
    g_login.status = nullptr;
    if (g_login.username_len == 0)
    {
        g_login.status = "ENTER A USERNAME";
        GuiRepaint();
        return true;
    }
    if (!LockedSameUser(g_login.username))
    {
        ++g_login.attempts;
        g_login.status = "LOCKED — USE THE SAME USER OR LOG OUT TO SWITCH";
        duetos::arch::SerialWrite("[login] gui unlock attempted for different user; locked_user=\"");
        duetos::arch::SerialWrite(g_login.locked_user);
        duetos::arch::SerialWrite("\"\n");
        GuiRepaint();
        return true;
    }
    if (AuthLogin(g_login.username, g_login.password))
    {
        ClearField(g_login.username, &g_login.username_len);
        ClearField(g_login.password, &g_login.password_len);
        g_login.active = false;
        g_login.focus = Field::Username;
        g_login.status = nullptr;
        g_login.locked = false;
        g_login.locked_user[0] = '\0';
        KLOG_INFO("login", "gui session opened");
        return false;
    }
    ++g_login.attempts;
    g_login.status = "LOGIN FAILED - CHECK USERNAME / PASSWORD";
    // Emit the submitted username + password length on serial for
    // operator forensics (password VALUE never logged). Matches
    // the audit trail any sane login daemon writes after a bad
    // attempt.
    duetos::arch::SerialWrite("[login-debug] submitted username=\"");
    duetos::arch::SerialWrite(g_login.username);
    duetos::arch::SerialWrite("\" password_len=");
    duetos::arch::SerialWriteHex(g_login.password_len);
    duetos::arch::SerialWrite("\n");
    // Clear BOTH fields and reset focus to Username on a failed
    // attempt. Retaining the username caused two real problems:
    //   1. The next submit inherited the old username with a new
    //      password typed into the wrong field, producing
    //      confusing failures for an honest user who mis-typed
    //      and wanted to start fresh.
    //   2. An attacker with brief console access could observe
    //      the last-attempted username of whoever just left —
    //      a minor but real info leak.
    // Fresh-blank state is the only policy that avoids both.
    ClearField(g_login.username, &g_login.username_len);
    ClearField(g_login.password, &g_login.password_len);
    g_login.focus = Field::Username;
    GuiRepaint();
    KLOG_WARN("login", "gui auth failed");
    return true;
}

bool GuiFeedKey(u16 code)
{
    using duetos::drivers::input::kKeyBackspace;
    using duetos::drivers::input::kKeyEnter;
    using duetos::drivers::input::kKeyTab;

    if (code == kKeyTab)
    {
        g_login.focus = (g_login.focus == Field::Username) ? Field::Password : Field::Username;
        GuiRepaint();
        return true;
    }
    if (code == kKeyEnter)
    {
        if (g_login.focus == Field::Username && g_login.password_len == 0)
        {
            // Convention borrowed from XP welcome — Enter on the
            // username field advances to password unless that
            // field already has content the user wants submitted.
            g_login.focus = Field::Password;
            GuiRepaint();
            return true;
        }
        return GuiTrySubmit();
    }
    if (code == kKeyBackspace)
    {
        if (g_login.focus == Field::Username)
        {
            FieldBackspace(g_login.username, &g_login.username_len);
        }
        else
        {
            FieldBackspace(g_login.password, &g_login.password_len);
        }
        GuiRepaint();
        return true;
    }
    if (code >= 0x20 && code <= 0x7E)
    {
        const char c = static_cast<char>(code);
        if (g_login.focus == Field::Username)
        {
            FieldAppend(g_login.username, &g_login.username_len, c);
        }
        else
        {
            FieldAppend(g_login.password, &g_login.password_len, c);
        }
        GuiRepaint();
        return true;
    }
    return true;
}

} // namespace

void LoginStart(LoginMode mode)
{
    g_login.active = true;
    g_login.mode = mode;
    g_login.focus = Field::Username;
    ClearField(g_login.username, &g_login.username_len);
    ClearField(g_login.password, &g_login.password_len);
    g_login.status = nullptr;
    g_login.attempts = 0;
    if (mode == LoginMode::Gui)
    {
        GuiRepaint();
        KLOG_INFO("login", "gate up (gui)");
    }
    else
    {
        TtyPrintBanner();
        KLOG_INFO("login", "gate up (tty)");
    }
}

bool LoginIsActive()
{
    return g_login.active;
}

LoginMode LoginCurrentMode()
{
    return g_login.mode;
}

bool LoginFeedKey(u16 code)
{
    if (!g_login.active)
    {
        return false;
    }
    if (g_login.mode == LoginMode::Gui)
    {
        return GuiFeedKey(code);
    }

    using duetos::drivers::input::kKeyBackspace;
    using duetos::drivers::input::kKeyEnter;
    using duetos::drivers::input::kKeyTab;
    if (code == kKeyEnter)
    {
        return TtySubmit();
    }
    if (code == kKeyBackspace)
    {
        TtyBackspace();
        return true;
    }
    if (code == kKeyTab)
    {
        // Tab on the TTY login is a convenience: skip the current
        // field (submit it as-is) to move focus forward.
        return TtySubmit();
    }
    if (code >= 0x20 && code <= 0x7E)
    {
        TtyFeedChar(static_cast<char>(code));
    }
    return true;
}

void LoginRepaint()
{
    if (!g_login.active)
    {
        return;
    }
    if (g_login.mode == LoginMode::Gui)
    {
        GuiRepaint();
    }
    // TTY login re-uses the console's own redraw path from
    // DesktopCompose; no dedicated work needed here.
}

void LoginReopen()
{
    AuthLogout();
    const LoginMode mode = g_login.mode;
    ClearField(g_login.username, &g_login.username_len);
    ClearField(g_login.password, &g_login.password_len);
    g_login.status = nullptr;
    g_login.focus = Field::Username;
    // A full logout drops the lock policy — the next user is
    // free to log in. Lock policy only fires after an explicit
    // LoginLock call.
    g_login.locked = false;
    g_login.locked_user[0] = '\0';
    LoginStart(mode);
}

void LoginLock()
{
    // Same as LoginReopen minus the AuthLogout — the session
    // stays valid under the hood, the gate just intercepts kbd
    // until credentials are re-entered. Capture the active user
    // so the unlock submit path can refuse credentials for any
    // other account (Windows-style same-user lock policy). If
    // no session is active when LoginLock fires (programmer
    // error — locking an empty desktop), fall back to a regular
    // login gate without the same-user constraint so the box
    // doesn't become unreachable.
    const LoginMode mode = g_login.mode;
    const char* active = AuthCurrentUserName();
    if (active != nullptr && active[0] != '\0')
    {
        g_login.locked = true;
        CopyName(g_login.locked_user, active, kFieldMax);
    }
    else
    {
        g_login.locked = false;
        g_login.locked_user[0] = '\0';
    }
    ClearField(g_login.username, &g_login.username_len);
    ClearField(g_login.password, &g_login.password_len);
    g_login.status = nullptr;
    g_login.focus = Field::Username;
    LoginStart(mode);
    if (g_login.locked)
    {
        KLOG_INFO_S("login", "screen locked (same-user-only)", "user", g_login.locked_user);
    }
    else
    {
        KLOG_WARN("login", "LoginLock with no active session — no same-user constraint");
    }
}

// ---------------------------------------------------------------
// Idle-timeout auto-lock.
// ---------------------------------------------------------------

namespace
{

// Default threshold: 600 seconds == 10 minutes. Matches the
// Windows / GNOME default. 0 disables auto-lock entirely.
constexpr u32 kDefaultIdleSeconds = 600;
constexpr u32 kSchedulerHz = 100;
constexpr u64 kIdleCheckIntervalTicks = kSchedulerHz; // 1 s

constinit u64 g_input_last_activity_ticks = 0;
constinit u32 g_idle_threshold_secs = kDefaultIdleSeconds;
constinit bool g_idle_task_started = false;

bool IdleLockCheckAt(u64 now_ticks)
{
    const u32 threshold = g_idle_threshold_secs;
    if (threshold == 0)
    {
        return false; // auto-lock disabled
    }
    if (LoginIsActive())
    {
        return false; // gate already up
    }
    if (!AuthIsAuthenticated())
    {
        return false; // nobody logged in to lock against
    }
    const u64 last = g_input_last_activity_ticks;
    if (now_ticks <= last)
    {
        return false;
    }
    const u64 elapsed_ticks = now_ticks - last;
    const u64 threshold_ticks = u64(threshold) * kSchedulerHz;
    if (elapsed_ticks < threshold_ticks)
    {
        return false;
    }
    KLOG_INFO_V("login", "idle-lock threshold crossed; locking", elapsed_ticks);
    duetos::drivers::video::CompositorLock();
    LoginLock();
    duetos::drivers::video::CompositorUnlock();
    return true;
}

void IdleLockTask(void* /*arg*/)
{
    for (;;)
    {
        ::duetos::sched::SchedSleepTicks(kIdleCheckIntervalTicks);
        IdleLockCheckAt(::duetos::time::TickCount());
    }
}

} // namespace

void InputActivityStamp()
{
    g_input_last_activity_ticks = ::duetos::time::TickCount();
}

u64 InputLastActivityTicks()
{
    return g_input_last_activity_ticks;
}

void IdleLockSetThresholdSeconds(u32 seconds)
{
    g_idle_threshold_secs = seconds;
    KLOG_INFO_V("login", "idle-lock threshold set (seconds)", seconds);
}

u32 IdleLockThresholdSeconds()
{
    return g_idle_threshold_secs;
}

void IdleLockTaskStart()
{
    if (g_idle_task_started)
    {
        return;
    }
    g_idle_task_started = true;
    // Stamp once so the first idle window starts now rather than
    // counting from 0. The task itself wakes once a second; the
    // watch is cheap enough to coexist with other 1Hz consumers.
    InputActivityStamp();
    ::duetos::sched::SchedCreate(IdleLockTask, nullptr, "idle-lock");
}

bool IdleLockCheckOnce()
{
    return IdleLockCheckAt(::duetos::time::TickCount());
}

namespace
{

void IdleExpect(bool cond, const char* what)
{
    if (!cond)
    {
        KLOG_WARN("login", what);
    }
}

} // namespace

void IdleLockSelfTest()
{
    KLOG_TRACE_SCOPE("login", "IdleLockSelfTest");

    // Threshold accessor round-trips.
    const u32 saved = IdleLockThresholdSeconds();
    IdleLockSetThresholdSeconds(60);
    IdleExpect(IdleLockThresholdSeconds() == 60, "threshold round-trip");
    IdleLockSetThresholdSeconds(0);
    IdleExpect(IdleLockThresholdSeconds() == 0, "threshold zero round-trip");
    IdleLockSetThresholdSeconds(saved);

    // Activity stamp is monotonic.
    const u64 t0 = InputLastActivityTicks();
    InputActivityStamp();
    const u64 t1 = InputLastActivityTicks();
    IdleExpect(t1 >= t0, "stamp monotonic");

    // Synthetic "way past threshold" timestamp without an active
    // session — should NOT fire (no session to lock against).
    // This run is at boot before any login, so the path
    // short-circuits cleanly.
    g_input_last_activity_ticks = 1; // ancient
    const u32 t = IdleLockThresholdSeconds();
    const u64 huge_now = u64(t + 1000) * kSchedulerHz + 100;
    const bool fired = IdleLockCheckAt(huge_now);
    IdleExpect(!fired, "no auto-lock without active session");

    // Re-stamp so the watcher's first real check has a fresh
    // window.
    InputActivityStamp();
    KLOG_INFO("login", "idle-lock self-test ok");
}

} // namespace duetos::core
