#include "theme.h"

#include "console.h"
#include "cursor.h"
#include "taskbar.h"
#include "widget.h"

namespace duetos::drivers::video
{

namespace
{

// Ascii-lower. No locale awareness needed — theme names are fixed.
constexpr char ToLower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

bool StrEqCi(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != '\0' && *b != '\0')
    {
        if (ToLower(*a) != ToLower(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

// ---------------------------------------------------------------
// Theme palettes.
//
// Colours are stored as 0x00RRGGBB (the framebuffer uses the top
// byte for padding). Each Theme is a compile-time aggregate so
// the whole table sits in .rodata.
//
// Classic preserves the exact values the first GUI slice used,
// bit-for-bit, so a user who never touches the theme hotkey sees
// the same desktop that shipped with the initial compositor.
//
// Slate10 mixes the Windows 10 desktop language (dark chrome,
// bright single-colour accent, flat rectangles, red close-btn)
// with Unreal Engine's Slate UI (deep charcoal panels, amber-ish
// highlights, minimal borders) — the "where are Notes and where
// is the clock" distinction is carried by title-bar hue rather
// than client-fill hue, so most client areas land on the same
// dark Slate panel colour.
// ---------------------------------------------------------------

constexpr Theme kClassic = {
    .name = "classic",

    .desktop_bg = 0x00204868,
    .banner_fg = 0x00FFFFFF,

    .taskbar_bg = 0x00202838,
    .taskbar_fg = 0x00FFFFFF,
    .taskbar_accent = 0x00406090,
    .taskbar_tab_inactive = 0x00303848,
    .taskbar_border = 0x00101828,

    .window_border = 0x00101828,
    .window_close = 0x00E04020,

    .role_title =
        {
            0x00205080, // Calculator
            0x00306838, // Notes
            0x00803020, // TaskManager
            0x00407080, // LogView
            0x00606020, // Files
            0x00203040, // Clock
        },
    .role_client =
        {
            0x00101828, // Calculator — dark blue-black
            0x00E0E0D8, // Notes      — cream (the only light client)
            0x00101828, // TaskManager
            0x00101020, // LogView
            0x00101828, // Files
            0x00081008, // Clock
        },

    .console_fg = 0x0080F088,
    .console_bg = 0x00181028,
};

constexpr Theme kSlate10 = {
    .name = "slate10",

    // Desktop: deep Slate charcoal with a faint blue cast so the
    // windows read as "panels on a dark surface" rather than
    // "black screen with popups."
    .desktop_bg = 0x001F1F28,
    .banner_fg = 0x00DDDDE2,

    // Taskbar: Win10-style near-black strip with a single bright
    // blue accent (start + active tab). Inactive tabs are a
    // half-step lighter than the strip so they read without a
    // border. The border constant is used for the thin top-edge
    // line; 0 renders as black in the framebuffer, which is what
    // Slate does for its divider lines.
    .taskbar_bg = 0x0017171C,
    .taskbar_fg = 0x00F0F0F0,
    .taskbar_accent = 0x000078D7, // Win10 system blue
    .taskbar_tab_inactive = 0x002D2D33,
    .taskbar_border = 0x00000000,

    // Windows: minimal dark-slate border, Win10-red close button.
    .window_border = 0x002D2D33,
    .window_close = 0x00E81123, // Win10 close-button red

    .role_title =
        {
            0x000078D7, // Calculator   — Win10 blue (primary accent)
            0x00C5860B, // Notes        — Unreal Slate amber
            0x00B52525, // TaskManager  — dark red
            0x00008CBA, // LogView      — VSCode-ish teal
            0x008B6914, // Files        — dark amber / goldenrod
            0x002D2D33, // Clock        — flat dark slate
        },
    .role_client =
        {
            0x00252529, // Calculator
            0x00F3F3F3, // Notes — light panel, like Win10 apps
            0x00252529, // TaskManager
            0x001A1A20, // LogView — deepest Slate so log colours pop
            0x00252529, // Files
            0x00101014, // Clock — near-black so 7-seg reads bright
        },

    .console_fg = 0x00D4D4D4, // VSCode default editor ink
    .console_bg = 0x001A1A20, // Slate panel
};

const Theme* const kThemes[static_cast<u32>(ThemeId::kCount)] = {
    &kClassic,
    &kSlate10,
};

// ---------------------------------------------------------------
// Live state. A single theme id + a handle-per-role table. The
// handle table is populated by main.cpp during boot after each
// WindowRegister returns; subsequent theme switches walk it to
// re-chrome every live window in one pass.
// ---------------------------------------------------------------

constinit ThemeId g_current = ThemeId::Classic;
constinit WindowHandle g_role_window[static_cast<u32>(ThemeRole::kCount)] = {
    kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid,
};

} // namespace

const Theme& ThemeCurrent()
{
    return *kThemes[static_cast<u32>(g_current)];
}

ThemeId ThemeCurrentId()
{
    return g_current;
}

void ThemeSet(ThemeId id)
{
    if (static_cast<u32>(id) >= static_cast<u32>(ThemeId::kCount))
    {
        return;
    }
    g_current = id;
}

void ThemeCycle()
{
    const u32 next = (static_cast<u32>(g_current) + 1) % static_cast<u32>(ThemeId::kCount);
    g_current = static_cast<ThemeId>(next);
}

bool ThemeIdFromName(const char* s, ThemeId* out)
{
    if (s == nullptr || out == nullptr)
        return false;
    for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
    {
        if (StrEqCi(s, kThemes[i]->name))
        {
            *out = static_cast<ThemeId>(i);
            return true;
        }
    }
    return false;
}

const char* ThemeIdName(ThemeId id)
{
    if (static_cast<u32>(id) >= static_cast<u32>(ThemeId::kCount))
        return "unknown";
    return kThemes[static_cast<u32>(id)]->name;
}

void ThemeRegisterWindow(ThemeRole role, WindowHandle h)
{
    const u32 idx = static_cast<u32>(role);
    if (idx >= static_cast<u32>(ThemeRole::kCount))
        return;
    g_role_window[idx] = h;
}

void ThemeApplyToAll()
{
    const Theme& t = ThemeCurrent();

    // Windows: each registered role gets its chrome re-published.
    for (u32 i = 0; i < static_cast<u32>(ThemeRole::kCount); ++i)
    {
        const WindowHandle h = g_role_window[i];
        if (h == kWindowInvalid || !WindowIsAlive(h))
            continue;
        WindowSetColours(h, t.window_border, t.role_title[i], t.role_client[i], t.window_close);
    }

    // Taskbar colours + console ink / bg + cursor backing all get
    // refreshed. The caller triggers DesktopCompose afterwards —
    // these calls only update state, they don't paint.
    TaskbarSetColours(t.taskbar_bg, t.taskbar_fg, t.taskbar_accent, t.taskbar_tab_inactive, t.taskbar_border);
    ConsoleSetColours(t.console_fg, t.console_bg);
    CursorSetDesktopBackground(t.desktop_bg);
}

} // namespace duetos::drivers::video
