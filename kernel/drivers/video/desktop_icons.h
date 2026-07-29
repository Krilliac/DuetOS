#pragma once

#include "drivers/video/widget.h" // WindowHandle
#include "util/types.h"

/*
 * DuetOS desktop icons — clickable shortcuts on the desktop wallpaper.
 *
 * The desktop surfaces the four launchers docs/aurora-theme/README.md §1
 * puts there — Task Manager, Kernel Log, Inspect, Files — in a 2-column
 * grid, so a double-click raises the bound app. These are DuetOS's own
 * diagnostic and file surfaces, not a mirror of another OS's shell
 * furniture; the Start menu carries the complete app list.
 *
 * Model: a fixed, boot-populated array of {label, glyph, target window}.
 * The launch target is a WindowHandle (not a ThemeRole) because not every
 * surfaced app has a ThemeRole — the debugger behind "Inspect" registers
 * its own window; boot_bringup registers each icon right where it created
 * or resolved the window, so the handle is always in scope.
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
/// see DrawGlyph in desktop_icons.cpp. The set is exactly the four
/// launchers docs/aurora-theme/README.md §1 puts on the desktop; the
/// Start menu remains the complete app list.
enum class IconGlyph : u8
{
    TaskManager, // ascending bar chart
    KernelLog,   // console frame + log lines
    Inspect,     // magnifier over a code column
    Files,       // folder with a raised tab
};

/// Register a desktop icon bound to `target`. `label` is shown beneath the
/// tile; `glyph` selects the iconographic drawing inside it. Auto-laid-out
/// left-to-right across two columns in registration order, wrapping into
/// further columns only if the rows would run into the taskbar. Silently
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

/// Boot self-test: pure layout math — verifies hit-testing the centre of
/// each registered icon's cell returns that icon and a far-off point
/// returns none. Emits a greppable PASS/FAIL sentinel; never panics
/// (a layout regression is a UI bug, not a reason to halt the box).
/// Call AFTER the DesktopIconRegister calls in boot_bringup.
void DesktopIconsSelfTest();

} // namespace duetos::drivers::video
