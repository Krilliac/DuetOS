#pragma once

#include "drivers/video/widget.h" // WindowHandle
#include "util/types.h"

/*
 * DuetOS desktop icons — clickable shortcuts on the desktop wallpaper.
 *
 * Every other desktop OS surfaces its common destinations (This PC /
 * drives, the file manager, the trash, a browser) as icons on the bare
 * desktop. DuetOS already HAS these as windowed apps (kernel/apps/{files,
 * browser,devicemgr,terminal,settings}.cpp), reachable only from the
 * Start menu. This module puts a column of icons on the desktop surface
 * so a double-click raises the bound app — the affordance a first-time
 * user reaches for before they discover the Start menu.
 *
 * Model: a fixed, boot-populated array of {label, glyph, target window}.
 * The launch target is a WindowHandle (not a ThemeRole) because two of
 * the surfaced apps — Device Manager and the Files/trash view — have no
 * ThemeRole; boot_bringup registers each icon right where it created the
 * window, so the handle is always in scope.
 *
 * Draw order: icons paint in DesktopCompose AFTER the wallpaper/console
 * and BEFORE the window list, so an open window correctly covers them.
 * The input task only activates an icon when no window sits under the
 * cursor, so a covered icon is never clickable.
 *
 * Context: kernel. Registration happens once at boot (single-threaded);
 * Paint runs on the compositor, HitTest/Activate on the input task. The
 * array is immutable after boot, so the cross-thread read needs no lock.
 */

namespace duetos::drivers::video
{

/// Which iconographic glyph a desktop icon paints in its tile. Each is
/// drawn from framebuffer primitives (rounded rects / circles / lines) —
/// see DrawGlyph in desktop_icons.cpp.
enum class IconGlyph : u8
{
    Computer,   // monitor + stand
    Browser,    // globe with meridians
    Terminal,   // dark screen + prompt
    Calculator, // body + display + keypad
    Notepad,    // ruled page
    Settings,   // cog/gear
    DeviceMgr,  // chip with pins
    Trash,      // bin with lid
    Help,       // disc with "?"
};

/// Register a desktop icon bound to `target`. `label` is shown beneath the
/// tile; `glyph` selects the iconographic drawing inside it. Auto-laid-out
/// top-to-bottom (wrapping into columns) in registration order. Silently
/// ignored past the fixed capacity or when `target` is kWindowInvalid.
void DesktopIconRegister(const char* label, IconGlyph glyph, WindowHandle target);

/// Set which icon (if any) is highlighted as hovered; pass -1 for none.
/// Returns true if the hovered icon actually changed — the caller uses
/// that to recompose only on a change (never per mouse packet), so the
/// hover highlight stays responsive without the per-packet repaint that
/// previously caused mouse lag.
bool DesktopIconSetHover(int index);

/// Paint every registered icon onto the current framebuffer. Call from
/// DesktopCompose between the wallpaper and the window list.
void DesktopIconsPaint();

/// Return the index of the icon whose cell contains (x, y), or -1 if the
/// point is not over any icon.
int DesktopIconHitTest(u32 x, u32 y);

/// Show + raise the window bound to icon `index`. No-op for an
/// out-of-range index or an invalid bound handle.
void DesktopIconActivate(int index);

/// Number of icons registered so far (for diagnostics / self-test).
u32 DesktopIconCount();

/// Return the WindowHandle bound to icon `index`, or kWindowInvalid for an
/// out-of-range index. Callers use this to post-hoc dispatch on which app
/// was just activated (e.g. auto-focus the URL bar when the browser opens).
WindowHandle DesktopIconWindow(int index);

/// Boot self-test: pure layout math — verifies hit-testing the centre of
/// each registered icon's cell returns that icon and a far-off point
/// returns none. Emits a greppable PASS/FAIL sentinel; never panics
/// (a layout regression is a UI bug, not a reason to halt the box).
/// Call AFTER the DesktopIconRegister calls in boot_bringup.
void DesktopIconsSelfTest();

} // namespace duetos::drivers::video
