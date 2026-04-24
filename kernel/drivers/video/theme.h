#pragma once

#include "../../core/types.h"
#include "widget.h"

/*
 * Desktop theming, v0.
 *
 * A theme is a flat palette of 32-bit ARGB (really 0x00RRGGBB —
 * the framebuffer driver discards the alpha byte) colours keyed
 * by role. Every piece of desktop chrome that previously held a
 * hardcoded colour now samples its value from the active theme:
 *
 *   - desktop fill / banner ink          (DesktopCompose)
 *   - taskbar strip, start-button fill,
 *     active / inactive tab fills, the
 *     thin top-edge border line          (taskbar.cpp)
 *   - each app window's title bar,
 *     client fill, border, close-btn     (main.cpp, via ThemeRoleChrome)
 *   - framebuffer console ink + bg       (main.cpp, via ConsoleSetColours)
 *
 * Two themes ship today:
 *
 *   - Classic : the teal / slate blue palette the first GUI slice
 *               hardcoded (preserved bit-for-bit so a user who
 *               doesn't touch anything sees exactly what they saw
 *               before themes existed).
 *   - Slate10 : a Windows 10 × Unreal Engine "Slate" UI hybrid.
 *               Dark charcoal / slate desktop, flat Win10-blue
 *               accent, Slate-amber highlight on notes, Win10-red
 *               close button. Title bars stay role-coloured so
 *               individual apps are still distinguishable at a
 *               glance, just in a much flatter / darker register.
 *
 * Switching themes is a runtime operation (Ctrl+Alt+Y cycles, or
 * `theme=slate10` / `theme=classic` on the kernel cmdline picks
 * at boot). ThemeApplyToAll re-publishes every chrome colour
 * into the window registry + taskbar + console + cursor backing,
 * then the caller triggers a DesktopCompose to paint the result.
 *
 * Context: kernel. Not thread-safe on its own — the switch path
 * is called from the keyboard-reader thread inside a
 * CompositorLock bracket. No ring-3 exposure yet (no syscall).
 */

namespace customos::drivers::video
{

enum class ThemeId : u8
{
    Classic = 0,
    Slate10 = 1,
    kCount = 2,
};

/// Stable role tag for each application window whose chrome is
/// themed. Ordering is arbitrary — callers register a window
/// against a role at boot and the theme module consults the
/// current palette when painting. New apps extend this enum;
/// tables in theme.cpp must be extended in lock-step.
enum class ThemeRole : u8
{
    Calculator = 0,
    Notes = 1,
    TaskManager = 2,
    LogView = 3,
    Files = 4,
    Clock = 5,
    kCount = 6,
};

struct Theme
{
    const char* name;

    // Desktop chrome
    u32 desktop_bg;
    u32 banner_fg;

    // Taskbar
    u32 taskbar_bg;
    u32 taskbar_fg;
    u32 taskbar_accent;       // start button + active tab fill
    u32 taskbar_tab_inactive; // idle tab fill
    u32 taskbar_border;       // 1-px top edge + tab / start outlines

    // Windows — shared across all roles
    u32 window_border;
    u32 window_close;

    // Per-role title + client — indexed by ThemeRole
    u32 role_title[static_cast<u32>(ThemeRole::kCount)];
    u32 role_client[static_cast<u32>(ThemeRole::kCount)];

    // Framebuffer console
    u32 console_fg;
    u32 console_bg;
};

/// Read-only snapshot of the active theme. Valid for as long as
/// no ThemeSet call races with the read (callers in the keyboard
/// reader hold CompositorLock across the whole repaint; callers
/// that just want to sample a colour at init time run before any
/// theme-switch hotkey is armed).
const Theme& ThemeCurrent();

/// Id of the active theme.
ThemeId ThemeCurrentId();

/// Switch the active theme. Does NOT repaint — call ThemeApplyToAll
/// afterwards to publish the new colours into the window registry,
/// taskbar, console, and cursor backing.
void ThemeSet(ThemeId id);

/// Convenience: advance to the next theme (wraps). Same caveat
/// as ThemeSet re: repaint.
void ThemeCycle();

/// Map a theme name ("classic" / "slate10") to an id. Matching is
/// case-insensitive. Returns false + leaves `out` untouched if
/// the string is unknown.
bool ThemeIdFromName(const char* s, ThemeId* out);

/// Human-readable name for an id ("classic", "slate10", "unknown").
const char* ThemeIdName(ThemeId id);

/// Register a window handle against a role so ThemeApplyToAll
/// knows which window to re-chrome when the theme changes. The
/// handle must be valid (WindowIsAlive == true) at call time.
/// Re-registering the same role overwrites the previous handle.
/// Passing kWindowInvalid clears the slot.
void ThemeRegisterWindow(ThemeRole role, WindowHandle h);

/// Re-publish every themed colour into the live UI:
///   - every registered window's chrome (border, title, client,
///     close button)
///   - the taskbar bg / fg / accent / tab-inactive / border
///   - the console foreground + background
///   - the cursor-backing's "desktop fallback" colour
/// Caller is responsible for calling DesktopCompose afterwards
/// to paint the result. Safe to call before any window has been
/// registered (no-ops the window loop).
void ThemeApplyToAll();

} // namespace customos::drivers::video
