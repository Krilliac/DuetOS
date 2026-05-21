#pragma once

#include "util/types.h"
#include "drivers/video/widget.h"

/*
 * DuetOS File Browser — v0.
 *
 * Lists the children of the ramfs trusted root in a scrollable
 * column. Each row shows:
 *
 *     [D] subdirname/
 *     [F] filename      1234 bytes
 *
 * A highlighted row tracks the current selection. Arrow keys
 * (Up / Down) move the selection; Enter descends into a
 * directory; Backspace (or 'b') ascends to the parent. The
 * browser keeps a small path stack so Backspace pops reliably.
 *
 * Scope limits (v0):
 *   - Read-only. No create / delete / rename — the ramfs is
 *     itself read-only, so there's no backend for mutation.
 *   - No file preview. Enter on a file prints its size + name
 *     to the serial log; a content-viewer is a future app.
 *   - Fixed depth cap (kMaxDepth). Deeply nested trees overflow
 *     and refuse further descent.
 *
 * Context: kernel. All mutation happens under the compositor
 * lock, same discipline as Notes and Calculator.
 */

namespace duetos::apps::files
{

/// Install the File Browser on `handle`. Sets the content-draw
/// callback, loads the trusted root's children as the initial
/// listing, prints a boot-time self-test confirming at least
/// one child was discovered.
void FilesInit(duetos::drivers::video::WindowHandle handle);

/// Promote the default mode to FAT32 disk view once a volume
/// becomes available. Called from main.cpp after `Fat32Probe`
/// succeeds (FilesInit runs before the probe so its own check
/// always sees `Fat32Volume(0) == nullptr`). No-op if the user
/// has already switched modes or there is still no volume.
void FilesPromoteToDisk();

/// Handle of the Files window.
duetos::drivers::video::WindowHandle FilesWindow();

/// Keyboard handler. Consumes:
///   - Enter           — descend into the selected directory,
///                       log the selected file's size.
///   - Backspace / 'b' — ascend to parent.
///   - 'j' / Arrow Dn  — move selection down.
///   - 'k' / Arrow Up  — move selection up.
/// Returns true iff consumed.
bool FilesFeedChar(char c);

/// Arrow key handler. Called from kbd-reader for codes that
/// aren't plain ASCII (kKeyArrowUp / kKeyArrowDown). Returns
/// true iff consumed.
bool FilesFeedArrow(bool up);

/// Home / End / PageUp / PageDown handler for the active list.
/// `code` is a VK navigation key (kKeyHome / kKeyEnd /
/// kKeyPageUp / kKeyPageDown). Returns true iff consumed.
bool FilesFeedListKey(duetos::u16 code);

/// One-shot self-test: verifies the root has at least one
/// child and that Enter on a directory updates the listing
/// to that directory's children. Prints PASS/FAIL to COM1.
void FilesSelfTest();

/// Map cursor (cx, cy) in screen coordinates to a row index in
/// the current FAT32 listing. Returns -1 if the cursor is not
/// over a row (over the title bar, header, scrollbar, or outside
/// the window). Mirrors the row geometry in DrawFat32 — keep them
/// in sync if the layout changes.
duetos::i32 FilesRowAt(duetos::u32 cx, duetos::u32 cy);

/// Right-click handler. Each Files mode opens a menu tuned to its
/// backing store:
///   FAT32  — rich per-row menu (Open / Rename / Delete /
///            Properties / Refresh / New File / New Folder).
///   DuetFS — shared generic browse menu (Open / Properties /
///            Refresh).
///   Trash  — Open / Restore / Delete Forever / Properties /
///            Refresh. Open notifies "restore to open" (GAP: the
///            openers look up by name in root); Delete Forever
///            shares the X-keybind Y-confirm prompt.
///   Ramfs  — Open / Delete (disabled) / Properties / Refresh.
///            Delete is shown disabled because the trusted ramfs
///            is constinit / .rodata.
/// Always returns true for the non-FAT views. Caller must not be
/// holding the compositor lock when invoking — the menu itself
/// doesn't touch it, but the caller's surrounding flow does.
bool FilesOnRightClick(duetos::u32 cx, duetos::u32 cy);

/// Mouse-wheel handler. `dz > 0` (wheel up) steps the selection
/// toward row 0; `dz < 0` (wheel down) steps it toward the
/// listing tail. Equivalent to repeated FilesFeedArrow calls.
/// Registered as the Files window's WindowWheelFn at
/// FilesInit time.
void FilesOnWheel(duetos::i32 dz, duetos::u8 modifiers);

/// Mouse double-click handler. If `cx`/`cy` resolves to a row,
/// opens that row: directories descend (when supported),
/// `.TXT` opens in Notes, `.BMP/.PNG/.TGA` opens in ImageView.
/// Returns true iff the click was consumed.
bool FilesOnDoubleClick(duetos::u32 cx, duetos::u32 cy);

/// Begin a DnD drag of the currently-selected row. Called by
/// the kbd-reader on Ctrl+D when Files is focused. Returns
/// true on success (DnD started); false if no selection / no
/// FAT32 mode / a drag is already live.
bool FilesBeginDragSelection();

/// Dispatch a Files-app context-menu action. Called from the
/// shared menu dispatcher in main.cpp once the menu fires. The
/// action ids span 30..39 (FAT32 + generic non-FAT verbs) and
/// 44..47 (Trash extended + ramfs delete); ctx is the row index
/// captured at MenuOpen time. See files.cpp for the per-id table.
void FilesDispatchContextAction(duetos::u32 action, duetos::u32 ctx);

} // namespace duetos::apps::files
