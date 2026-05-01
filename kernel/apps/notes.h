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
 *   - Single document. Save / load round-trip lives at
 *     `NOTES.TXT` on the FAT32 root volume (Ctrl+S / Ctrl+O,
 *     wired in `kernel/core/main.cpp`); v0 has no journaling
 *     and no atomic-rename, so a power loss mid-save can
 *     truncate the file. Documented as a // GAP in
 *     notes_persist.cpp.
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

/// Copy the entire buffer contents to the kernel clipboard
/// (`WindowClipboardSetText`). Truncates at the clipboard cap
/// — no separate selection model in v0, so "copy" always means
/// "copy everything". Returns the number of bytes published.
duetos::u32 NotesCopyToClipboard();

/// Insert the current kernel clipboard text at the cursor,
/// expanding the buffer in place. Newlines and printable ASCII
/// are accepted; anything else is dropped. Caller holds the
/// compositor lock. Returns the number of bytes inserted.
duetos::u32 NotesPasteFromClipboard();

/// Persist the current buffer to the FAT32 root volume as
/// `NOTES.TXT`. Existing content is replaced (delete-then-
/// create — non-atomic; v0 has no journaling). Returns true
/// on success. Returns false and leaves on-disk state alone if
/// no FAT32 volume is mounted.
///
/// Caller MUST hold the compositor lock — the buffer is read
/// directly without a copy.
bool NotesSave();

/// Replace the current buffer with the contents of `NOTES.TXT`
/// from the FAT32 root volume. Bytes outside printable ASCII
/// + newline are dropped (mirrors NotesPasteFromClipboard).
/// Cursor lands at end-of-buffer. Returns true on success;
/// false if there's no FAT32 volume, no NOTES.TXT, or read
/// I/O fails. The live buffer is untouched on failure.
///
/// Caller MUST hold the compositor lock.
bool NotesLoad();

/// One-shot self-test: exercises insert / backspace / delete
/// and every navigation binding on a scratch state, asserts
/// each step, then restores the pre-test buffer. Prints one
/// PASS/FAIL line to COM1. Safe to call after NotesInit.
void NotesSelfTest();

/// Round-trip self-test for NotesSave / NotesLoad. Plants a
/// known marker into a scratch buffer, saves, clears, loads,
/// and verifies the bytes match. Cleans up the test file at
/// the end. Skipped silently if no FAT32 volume is mounted or
/// if `NOTES.TXT` already exists on disk (so a real save isn't
/// trampled). Prints one PASS / FAIL / SKIP line to COM1.
void NotesPersistSelfTest();

} // namespace duetos::apps::notes
