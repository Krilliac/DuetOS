#pragma once

#include "../../core/types.h"

/*
 * Pop-up menu primitive — v0.
 *
 * The classic Windows-style start menu: a vertical stack of
 * text items in a framed panel, anchored to a screen point
 * (typically the START button's upper-left corner). Opens on
 * demand, closes on item click or click-outside. Stores a small
 * table of (label, action_id) entries the caller seeds at init.
 *
 * Scope limits:
 *   - Single menu instance. A future slice may support
 *     contextual sub-menus or right-click popup menus via a
 *     small menu-handle table.
 *   - Fixed item count + width + row height. No icons, no
 *     separators, no shortcut hints.
 *   - No keyboard navigation (arrow keys to highlight, Enter
 *     to fire). Mouse-driven only.
 *   - No hover highlight — items paint in one state.
 *
 * Context: kernel. Render from DesktopCompose (after taskbar);
 * dispatch mouse events from the mouse reader thread.
 */

namespace customos::drivers::video
{

struct MenuItem
{
    const char* label;
    u32 action_id;
};

/// Open the menu with `items` as its content and `context` as
/// an opaque u32 the dispatcher can read back via `MenuContext()`.
/// Typical use: pass a target window handle so a "Close" item
/// knows what to close. Labels + items array must outlive the
/// open state — v0 uses static const arrays. Safe to call when
/// already open (swaps contents in place).
void MenuOpen(const MenuItem* items, u32 count, u32 ax, u32 ay, u32 context = 0);

/// Ambient context set by MenuOpen. Read by the dispatcher to
/// resolve `action_id`s that depend on a target (window handle,
/// taskbar slot, etc.). Defaults to 0 when the menu is closed.
u32 MenuContext();

/// Mark the menu closed. Safe any time.
void MenuClose();

/// True iff the menu is currently open.
bool MenuIsOpen();

/// Paint the menu, if open. Called from DesktopCompose AFTER
/// taskbar so the menu always sits on top of everything,
/// including the bar it opened from.
void MenuRedraw();

/// Hit-test against the last-painted item layout. Returns the
/// action_id of the item under (x, y), or 0 if none. A zero
/// action_id is reserved for "nothing" — callers seed non-zero
/// ids.
u32 MenuItemAt(u32 x, u32 y);

/// Whole-panel hit-test — lets the mouse reader detect
/// click-outside-to-close cleanly.
bool MenuContains(u32 x, u32 y);

/// Height in pixels the menu will paint at, given the items
/// passed in the most recent `MenuOpen`. Useful for callers
/// that need to anchor the menu to the bottom of a button
/// (popup grows upward).
u32 MenuPanelHeight();

} // namespace customos::drivers::video
