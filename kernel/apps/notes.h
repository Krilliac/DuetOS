#pragma once

#include "util/types.h"
#include "drivers/video/widget.h"

/*
 * DuetOS Notes — v1.
 *
 * The first user-facing application in the tree. A simple
 * notepad: a ring-free linear text buffer, a content-draw
 * callback the window system invokes during DesktopCompose,
 * and keyboard-feed entry points the kbd-reader thread calls
 * when the notes window is active.
 *
 * v1 adds a cursor model: insertion happens at a tracked
 * position, arrow keys move the cursor, Home/End jump to
 * line edges, Delete removes the char to the right of the
 * cursor. v0's append-only discipline is gone — the caret
 * is now authoritative.
 *
 * Scope limits:
 *   - Single document. No save/load — there is no persistent
 *     storage yet.
 *   - Printable ASCII (0x20..0x7E), Enter, Backspace, Delete,
 *     arrow keys, Home, End. No selection, no clipboard, no
 *     undo.
 *   - Hard buffer cap (kNotesBufCap). Inputs past the cap
 *     are dropped silently — a ring would be wrong for a
 *     notes app (oldest content is not less important than
 *     newest).
 *   - Draw path wraps at the column count derived from the
 *     window's client width (mid-word, no hyphenation).
 *   - Arrow Up / Down move by LOGICAL lines (delimited by
 *     '\n'), not visual wrap lines. The caller's column
 *     within the logical line is preserved when the target
 *     line is long enough, clamped otherwise.
 *
 * Context: kernel. All state mutated under CompositorLock —
 * NotesFeedChar / NotesFeedKey are invoked with the lock held
 * by kbd-reader, and the draw callback is invoked under the
 * same lock by DesktopCompose. No reentrancy concerns.
 */

namespace duetos::apps::notes
{

/// Install the content-draw callback on `handle` and seed the
/// buffer with a short greeting. Called once at boot after the
/// notes window is registered.
void NotesInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the notes window, or `kWindowInvalid` until Init.
/// Used by the keyboard router to decide when to redirect keys
/// from the shell into the notes buffer.
duetos::drivers::video::WindowHandle NotesWindow();

/// Feed one character into the notes buffer. Accepts printable
/// ASCII (0x20-0x7E), newline (0x0A), and backspace (0x08).
/// Inserts at the cursor position; Backspace deletes the char
/// immediately to the left of the cursor. Returns true iff the
/// character was consumed.
///
/// MUST be called with the compositor lock held.
bool NotesFeedChar(char c);

/// Feed a non-ASCII key (arrows, Home, End, Delete) into the
/// notes buffer. `keycode` is one of the kKey* values from
/// `drivers/input/ps2kbd.h`. Returns true iff the key was
/// consumed (i.e. matched a navigation binding).
///
/// MUST be called with the compositor lock held.
bool NotesFeedKey(duetos::u16 keycode);

/// One-shot self-test: exercises insert / backspace / delete
/// and every navigation binding on a scratch state, asserts
/// each step, then restores the pre-test buffer. Prints one
/// PASS/FAIL line to COM1. Safe to call after NotesInit.
void NotesSelfTest();

} // namespace duetos::apps::notes
