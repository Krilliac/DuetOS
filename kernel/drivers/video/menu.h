#pragma once

#include "util/types.h"

/*
 * Pop-up menu primitive.
 *
 * Vertical stack of text items in a framed panel anchored to a
 * screen point. Drives both the START menu and the right-click
 * desktop / window / system / file context menus.
 *
 * Capabilities:
 *   - Up to kMenuMaxStack nested panels (root + 3 submenus).
 *   - Hover highlight tracked via MenuTrackHoverAt or MenuSetHover.
 *   - Keyboard navigation via MenuFeedKey: Up/Down move highlight,
 *     Right opens a submenu, Left/Esc closes one panel, Enter
 *     activates the hovered item (returns its action_id).
 *   - Per-item flags: disabled (greyed + non-clickable), checked
 *     (radio glyph), separator (1-px line, no row body), submenu
 *     (right-pointing chevron + nested panel on activation).
 *
 * Scope limits:
 *   - Single global instance (one menu open at a time).
 *   - Fixed item count + width + row height per panel.
 *   - No icons. No keyboard accelerators / underlined letters.
 *
 * Context: kernel. Render from DesktopCompose (after taskbar) so
 * the menu always sits on top. Dispatch from the mouse-reader
 * thread under the compositor lock.
 */

namespace duetos::drivers::video
{

constexpr u32 kMenuItemFlagDisabled = 1u << 0;
constexpr u32 kMenuItemFlagChecked = 1u << 1;
constexpr u32 kMenuItemFlagSubmenu = 1u << 2;
constexpr u32 kMenuItemFlagSeparator = 1u << 3;

/// Maximum panel-stack depth. Root panel + up to (kMenuMaxStack-1)
/// nested submenus. Sized small because deep menus are user-hostile;
/// the kernel rejects deeper opens.
constexpr u32 kMenuMaxStack = 4;

struct MenuItem
{
    const char* label;       // nullptr OK if separator flag set
    u32 action_id;           // 0 = unused; activate returns 0 for a no-op row
    u32 flags;               // bitmask of kMenuItemFlag*
    const MenuItem* submenu; // nullable; only consulted when flags has Submenu bit
    u32 submenu_count;       // count for the submenu array
};

/// Update the menu's chrome palette. Called by the theme module
/// so a runtime theme switch re-hues the popup. Every parameter is
/// written unconditionally. Safe before any open / first paint.
void MenuSetColours(u32 body_rgb, u32 border_rgb, u32 ink_rgb, u32 accent_rgb);

/// Open the root panel with `items` as its content and `context`
/// as an opaque u32 the dispatcher can read back via `MenuContext()`.
/// Resets any submenu stack. Labels + items array must outlive the
/// open state — callers use static const arrays. Safe to call when
/// already open (replaces the stack with a fresh root).
void MenuOpen(const MenuItem* items, u32 count, u32 ax, u32 ay, u32 context = 0);

/// Push a new panel as a child of the topmost panel's row `row`.
/// No-op if `row` lacks the Submenu flag, has no submenu pointer,
/// or the stack is already at kMenuMaxStack. Anchors the child
/// panel to the right edge of the parent row, clamped to the
/// framebuffer width.
void MenuOpenSubmenu(u32 row);

/// Pop the topmost panel (a submenu). Returns true if a panel was
/// popped, false if the stack is at the root (in which case the
/// menu remains open). Caller decides whether to MenuClose().
bool MenuPopSubmenu();

/// Stack depth: 0 when closed, 1 when only the root is open, 2..
/// when submenus are stacked. Bounded by kMenuMaxStack.
u32 MenuStackDepth();

/// Ambient context set by MenuOpen. Read by the dispatcher to
/// resolve action_ids that depend on a target. Defaults to 0 when
/// closed.
u32 MenuContext();

/// Mark every panel closed. Safe any time.
void MenuClose();

/// True iff at least one panel is open.
bool MenuIsOpen();

/// Paint every open panel, low-to-high. Called from DesktopCompose
/// AFTER taskbar so the menu sits on top of everything.
void MenuRedraw();

/// Hit-test the topmost panel only and return the action_id of
/// the item under (x, y), or 0 if none. Disabled and separator
/// items return 0. Preserved for callers that just want a click
/// dispatch on the currently focused panel.
u32 MenuItemAt(u32 x, u32 y);

/// Whole-stack hit-test: true iff (x, y) is inside any open panel.
/// Lets the mouse reader detect click-outside-to-close.
bool MenuContains(u32 x, u32 y);

/// Update the hover state for the panel under (x, y). If the
/// cursor is inside a panel deeper in the stack than the topmost
/// open one, intermediate panels stay open (caller can use
/// MenuPopSubmenu to retreat). If the cursor is outside every
/// panel, the topmost panel's hover is cleared. Idempotent.
void MenuTrackHoverAt(u32 x, u32 y);

/// Direct hover poke. `panel` is a stack index (0 = root); -1
/// clears the hover on the topmost panel. `row` is the row index
/// within that panel; -1 clears the hover on that panel.
void MenuSetHover(i32 panel, i32 row);

/// Move the hovered row on the topmost panel by `dy` (typically
/// ±1). Wraps at the panel ends. Skips disabled items and
/// separators. No-op when the menu is closed.
void MenuMoveHover(int dy);

/// Activate the row currently hovered on the topmost panel.
/// Returns the action_id of that row (0 if no row hovered, the
/// row is disabled, a separator, or has a submenu — in the
/// submenu case the call opens it instead and returns 0). Caller
/// dispatches on a non-zero return.
u32 MenuActivateHover();

/// Feed a keyboard event into the menu. Recognised codes:
///   kKeyArrowDown / kKeyArrowUp  → MenuMoveHover(±1)
///   kKeyEnter                    → MenuActivateHover; caller reads return via MenuActivateHover separately
///   kKeyEscape (0x1B)            → MenuClose() (always closes the whole menu)
///   kKeyArrowRight               → MenuOpenSubmenu(hovered_row)
///   kKeyArrowLeft                → MenuPopSubmenu (or MenuClose at root)
/// Anything else: no-op. The dispatcher decides what to do with
/// the activation result; this function does not call the action
/// dispatcher (which lives in main.cpp).
/// Returns the action_id if the key produced an activation (Enter
/// on a non-submenu, non-disabled, non-separator row), else 0.
u32 MenuFeedKey(u16 key_code);

/// Height in pixels the topmost panel will paint at. Useful for
/// callers anchoring the menu to the bottom of a button (popup
/// grows upward).
u32 MenuPanelHeight();

} // namespace duetos::drivers::video
