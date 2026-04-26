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

/// One-shot self-test: verifies the root has at least one
/// child and that Enter on a directory updates the listing
/// to that directory's children. Prints PASS/FAIL to COM1.
void FilesSelfTest();

} // namespace duetos::apps::files
