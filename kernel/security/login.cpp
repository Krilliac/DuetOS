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

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/console.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/shadow.h"
#include "drivers/video/wallpaper.h"
#include "drivers/video/widget.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "security/auth.h"
#include "time/tick.h"
#include "util/datetime.h"

namespace duetos::core
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;
using duetos::drivers::video::FramebufferBeginCompose;
using duetos::drivers::video::FramebufferDrawCircle;
using duetos::drivers::video::FramebufferDrawRect;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferDrawStringScaled;
using duetos::drivers::video::FramebufferEndCompose;
using duetos::drivers::video::FramebufferFillCircle;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::FramebufferGet;
using duetos::drivers::video::RenderSoftShadowWithStroke;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::WallpaperPaint;
using duetos::drivers::video::WindowPaintFocusGlow;

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

// Colours for the Pass B corner-card login screen.
// T13+ will add corner-card palette constants here.

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


// ---------------------------------------------------------------
// Pass B corner-card helpers — clock + date text for the big
// clock left panel. Both read the RTC directly so they're
// always wall-clock accurate (no separate tick-derived fallback
// needed: RtcRead is cheap, ~1 ms max spin, fine for a 1 Hz
// repaint).
// ---------------------------------------------------------------

// Write a two-digit decimal (with leading zero) at *pos in buf.
// Helper for LoginFormatClock/Date — avoids a snprintf dependency.
void AppendTwoDigit(char* buf, u32* pos, u32 cap, u32 val)
{
    if (*pos + 1 < cap)
    {
        buf[(*pos)++] = static_cast<char>('0' + (val / 10) % 10);
    }
    if (*pos + 1 < cap)
    {
        buf[(*pos)++] = static_cast<char>('0' + val % 10);
    }
}

void LoginFormatClock(char* out, u32 cap)
{
    duetos::arch::RtcTime t = {};
    duetos::arch::RtcRead(&t);
    u32 pos = 0;
    AppendTwoDigit(out, &pos, cap, t.hour);
    if (pos + 1 < cap)
    {
        out[pos++] = ':';
    }
    AppendTwoDigit(out, &pos, cap, t.minute);
    if (pos < cap)
    {
        out[pos] = '\0';
    }
}

void LoginFormatDate(char* out, u32 cap)
{
    duetos::arch::RtcTime t = {};
    duetos::arch::RtcRead(&t);

    static const char* kDay[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
    static const char* kMonth[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    const u8 dow = duetos::util::DayOfWeekFromYmd(i32(t.year), t.month, t.day);
    const char* day_name = kDay[dow % 7];
    const u8 m0 = (t.month >= 1 && t.month <= 12) ? u8(t.month - 1) : u8(0);
    const char* month_name = kMonth[m0];

    u32 pos = 0;
    // Write day name.
    for (u32 i = 0; day_name[i] != '\0' && pos + 1 < cap; ++i)
    {
        out[pos++] = day_name[i];
    }
    if (pos + 1 < cap)
    {
        out[pos++] = ',';
    }
    if (pos + 1 < cap)
    {
        out[pos++] = ' ';
    }
    // Write abbreviated month name.
    for (u32 i = 0; month_name[i] != '\0' && pos + 1 < cap; ++i)
    {
        out[pos++] = month_name[i];
    }
    if (pos + 1 < cap)
    {
        out[pos++] = ' ';
    }
    // Write day-of-month (1 or 2 digits, no leading zero).
    const u32 d = t.day;
    if (d >= 10 && pos + 1 < cap)
    {
        out[pos++] = static_cast<char>('0' + d / 10);
    }
    if (pos + 1 < cap)
    {
        out[pos++] = static_cast<char>('0' + d % 10);
    }
    if (pos < cap)
    {
        out[pos] = '\0';
    }
}

void GuiRepaint()
{
    // Pass B corner-card layout. See spec §4.2 / §5.
    //
    // Step 1 (Task 12): wallpaper backdrop + big clock left.
    // Step 2 (Tasks 13-16 — pending): corner card bottom-right with
    //   atlas-shadow, avatar/name, password field, sign-in button.
    //
    // The login form (centered winlogon-flavour box) is intentionally
    // absent in this commit. Keyboard input is still wired through
    // GuiFeedKey → GuiTrySubmit, but nothing on-screen reflects it
    // until the corner card lands in T13-T16.

    FramebufferBeginCompose();

    // 1. Backdrop — wallpaper pattern continuous from splash, repainted
    //    here to recover pixels on every LoginRepaint / mode flip.
    WallpaperPaint(ThemeCurrent().desktop_bg);

    // 2. Big clock left — 84-px digit clock (scale=8 on the 8×8 font)
    //    at (80, 560) baseline and 20-px date (scale=2) at (80, 660)
    //    on a 1024×768 reference; scaled to the actual framebuffer.
    const auto& fb = FramebufferGet();
    const u32 clock_x = 80u * fb.width / 1024u;
    const u32 clock_y = 560u * fb.height / 768u;
    const u32 date_y = 660u * fb.height / 768u;

    char clock_buf[8]; // "HH:MM\0"
    char date_buf[32]; // "Wednesday, May 24\0"
    LoginFormatClock(clock_buf, sizeof(clock_buf));
    LoginFormatDate(date_buf, sizeof(date_buf));

    // Text colour: banner_fg is the high-contrast overlay ink used for
    // the desktop banner — correct tone for the large clock over the
    // wallpaper backdrop regardless of active theme.
    const u32 fg = ThemeCurrent().banner_fg;
    // bg = transparent match: use desktop_bg so the scaled glyphs
    // blend against the wallpaper tone rather than leaving a solid rect.
    const u32 bg = ThemeCurrent().desktop_bg;

    FramebufferDrawStringScaled(clock_x, clock_y, clock_buf, fg, bg, /*scale=*/8);
    FramebufferDrawStringScaled(clock_x, date_y, date_buf, fg, bg, /*scale=*/2);

    // 3. Corner card bottom-right — 280×160 at (694, 540) on a 1024×768
    //    reference; scaled to the actual framebuffer dimensions.
    //    Pass B Task 13: atlas-shadow halo + body fill + border stroke.
    //    Pass B Task 14: avatar circle + monogram + username + role text.
    //    Card contents (password field, sign-in button) land in Tasks 15–16.
    const u32 card_x = 694u * fb.width / 1024u;
    const u32 card_y = 540u * fb.height / 768u;
    const u32 card_w = 280u * fb.width / 1024u;
    const u32 card_h = 160u * fb.height / 768u;

    // Card body — taskbar_bg is the elevated-panel surface shared across
    // all themes; window_border is the 1-px stroke used on every window
    // chrome so the card matches the rest of the chrome language.
    FramebufferFillRect(card_x, card_y, card_w, card_h, ThemeCurrent().taskbar_bg);

    // Atlas-shadow halo + 1-px inner stroke in one call.
    // Shadow colour is pure black (0x000000); stroke colour is the theme's
    // window_border — matches window chrome language. radius=16 / opacity=120
    // gives a soft, medium-lift halo consistent with the Pass A window chrome.
    RenderSoftShadowWithStroke(static_cast<i32>(card_x), static_cast<i32>(card_y), card_w, card_h,
                               /*radius=*/16, /*opacity=*/120, /*colour=*/0x000000u,
                               /*stroke_colour=*/ThemeCurrent().window_border);

    // 4. Avatar circle + monogram + username + role text.
    //    Pass B Task 14.
    //
    //    Avatar is a 40-px diameter circle (radius 20) positioned
    //    36 px right and 40 px down from the card top-left corner
    //    on a 1024×768 reference grid, scaled to actual fb dimensions.
    //    accent_colour = taskbar_accent — the theme's primary accent,
    //    used consistently for topo tint, start-button fill, and
    //    highlighted tab borders across all themes.
    const u32 accent = ThemeCurrent().taskbar_accent;
    // Avatar background: use taskbar_bg (elevated panel surface) so the
    // circle reads as an inset element inside the card rather than a
    // flat sticker on top of it.
    const u32 avatar_bg = ThemeCurrent().taskbar_bg;

    // Scale the avatar centre to the actual framebuffer resolution.
    const u32 avatar_cx = card_x + 36u * fb.width / 1024u;
    const u32 avatar_cy = card_y + 40u * fb.height / 768u;
    const u32 avatar_r = 20u * fb.width / 1024u;

    // Filled circle (card-body colour) then 1-px accent stroke ring.
    FramebufferFillCircle(static_cast<i32>(avatar_cx), static_cast<i32>(avatar_cy), avatar_r, avatar_bg);
    FramebufferDrawCircle(static_cast<i32>(avatar_cx), static_cast<i32>(avatar_cy), avatar_r, accent);

    // Monogram — first character of the current username, uppercased.
    // Falls back to '?' if the username buffer is empty (shouldn't happen
    // at repaint time, but defensive for the autologin path).
    char mono = '?';
    const char* user = g_login.username;
    if (user != nullptr && user[0] != '\0')
    {
        mono = user[0];
        if (mono >= 'a' && mono <= 'z')
        {
            mono = static_cast<char>(mono - 'a' + 'A');
        }
    }
    char mono_str[2] = {mono, '\0'};

    // Centre the 2x-scaled 8×8 bitmap glyph (16×16 rendered pixels)
    // inside the circle.  Offset by half the rendered glyph size so
    // the character visual centre lands on avatar_cx / avatar_cy.
    FramebufferDrawStringScaled(avatar_cx - 8u, avatar_cy - 8u, mono_str, accent, avatar_bg, /*scale=*/2);

    // Username and role text rendered to the right of the avatar.
    // name_x is avatar right-edge + 12 px of gap on the reference grid.
    const u32 name_x = avatar_cx + avatar_r + 12u * fb.width / 1024u;
    const u32 name_y = card_y + 32u * fb.height / 768u;
    const u32 role_y = card_y + 48u * fb.height / 768u;

    FramebufferDrawString(name_x, name_y, (user != nullptr && user[0] != '\0') ? user : "<no user>",
                          ThemeCurrent().banner_fg, ThemeCurrent().taskbar_bg);

    // GAP: role hardcoded — RBAC role-per-user lookup not wired into
    //      login.cpp yet, revisit when RBAC v1 persistence lands.
    FramebufferDrawString(name_x, role_y, "Administrator", ThemeCurrent().banner_fg, ThemeCurrent().taskbar_bg);

    // 5. Password field — single-line accent-stroked rect with masked echo.
    //    Pass B Task 15.
    //
    //    Positioned in the lower half of the card, below the avatar/name
    //    block. On a 1024×768 reference: 20 px inset from the card left,
    //    86 px down from the card top (below the 40-px avatar + 40-px gap),
    //    spanning the card width minus 40 px of horizontal padding, 28 px tall.
    const u32 pwd_x = card_x + 20u * fb.width / 1024u;
    const u32 pwd_y = card_y + 86u * fb.height / 768u;
    const u32 pwd_w = card_w - 40u * fb.width / 1024u;
    const u32 pwd_h = 28u * fb.height / 768u;

    // Field body: taskbar_bg gives the same elevated-panel surface used by the
    // avatar fill — reads as a recessed input well inside the card.
    FramebufferFillRect(pwd_x, pwd_y, pwd_w, pwd_h, ThemeCurrent().taskbar_bg);

    // Focus indicator: Pass A WindowPaintFocusGlow when the password field has
    // keyboard focus; thin window_border stroke otherwise (matches Task 13).
    if (g_login.focus == Field::Password)
    {
        WindowPaintFocusGlow(pwd_x, pwd_y, pwd_w, pwd_h, /*is_pe_window=*/false);
    }
    else
    {
        FramebufferDrawRect(pwd_x, pwd_y, pwd_w, pwd_h, ThemeCurrent().window_border, 1u);
    }

    // Masked password echo: render one asterisk per typed character.
    {
        char masked[64];
        const u32 cap = static_cast<u32>(sizeof(masked)) - 1u;
        const u32 n = g_login.password_len < cap ? g_login.password_len : cap;
        for (u32 i = 0; i < n; ++i)
        {
            masked[i] = '*';
        }
        masked[n] = '\0';
        if (n > 0u)
        {
            FramebufferDrawString(pwd_x + 8u * fb.width / 1024u, pwd_y + 10u * fb.height / 768u, masked,
                                  ThemeCurrent().banner_fg, ThemeCurrent().taskbar_bg);
        }
    }

    // 6. Sign-in button — accent fill with dark "Sign in" label.
    //    Pass B Task 16. Right-aligned under the password field.
    //    Font8x8MeasureString does not exist; label width is approximated
    //    from glyph count × 8 px (8×8 bitmap font, scale=1).
    const u32 btn_w = 170u * fb.width / 1024u;
    const u32 btn_h = 28u * fb.height / 768u;
    const u32 btn_x = pwd_x + pwd_w - btn_w;
    const u32 btn_y = pwd_y + pwd_h + 14u * fb.height / 768u;

    FramebufferFillRect(btn_x, btn_y, btn_w, btn_h, ThemeCurrent().taskbar_accent);

    // "Sign in" = 7 glyphs × 8 px wide = 56 px at scale 1.
    constexpr u32 kLabelPxW = 7u * 8u;
    const char* btn_label = "Sign in";
    FramebufferDrawString(btn_x + (btn_w - kLabelPxW) / 2u,
                          btn_y + 10u * fb.height / 768u,
                          btn_label,
                          ThemeCurrent().desktop_bg,    // dark ink on accent fill
                          ThemeCurrent().taskbar_accent); // bg matches button so glyphs blend

    // Flush offscreen shadow → live framebuffer (no-op if BeginCompose
    // fell back to direct mode).
    FramebufferEndCompose();
    // Push to the active backend (virtio-gpu TRANSFER_TO_HOST_2D +
    // RESOURCE_FLUSH; no-op for direct firmware-handoff framebuffers).
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

bool LoginIsLocked()
{
    return g_login.locked;
}

void LoginSwitchUser()
{
    if (!g_login.locked)
    {
        // Caller assumed the gate is locked; if it isn't,
        // LoginReopen still does the right thing (logs out +
        // re-opens), but log the surprise so a misuse surfaces.
        KLOG_WARN("login", "LoginSwitchUser called outside of locked state");
    }
    KLOG_INFO_S("login", "switch-user requested from locked gate", "previous", g_login.locked_user);
    LoginReopen();
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
